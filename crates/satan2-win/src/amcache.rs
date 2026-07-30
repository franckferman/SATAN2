// amcache.rs — wipe Amcache.hve and AppCompatCache (ShimCache)
//
// Amcache.hve: C:\Windows\AppCompat\Programs\Amcache.hve
//   Registry hive (offline) recording every executed binary:
//   SHA1 hash, path, size, compile timestamp, last-modified time.
//   Also: RecentFileCache.bcf on Windows 8.x (same dir).
//
// ShimCache (AppCompatCache):
//   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
//   Value "AppCompatCache" — binary blob, last ~1024 executed binaries.
//   Written to the registry at system shutdown; in-memory state is lost on
//   hard power-off so clearing the persisted value stops recovery across reboots.
//
// Strategy:
//   1. Disable Application Experience scheduled tasks (stop re-population)
//   2. Wipe Amcache.hve + transaction logs + RecentFileCache.bcf
//   3. Delete AppCompatCache registry value

use std::fs;
use std::path::Path;
use std::process::Command;
use std::ptr;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Debug, Default)]
pub struct AmcacheStats {
    pub files_deleted: u32,
    pub bytes_freed: u64,
    pub shimcache_cleared: bool,
    pub errors: u32,
}

fn disable_appcompat_tasks() {
    for task in &[
        r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        r"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        r"\Microsoft\Windows\Application Experience\StartupAppTask",
        r"\Microsoft\Windows\Application Experience\AitAgent",
    ] {
        let _ = Command::new("schtasks")
            .args(["/Change", "/TN", task, "/Disable"])
            .output();
    }
    // Stop the Application Experience service
    let _ = Command::new("sc").args(["stop", "AeLookupSvc"]).output();
}

fn wipe_amcache_files(stats: &mut AmcacheStats, verbose: bool) {
    let base = r"C:\Windows\AppCompat\Programs";
    for name in &[
        "Amcache.hve",
        "Amcache.hve.LOG1",
        "Amcache.hve.LOG2",
        "Amcache.hve.blf",
        "Amcache.hve.regtrans-ms",
        "RecentFileCache.bcf",
        "RecentFileCache.bcf.LOG1",
        "RecentFileCache.bcf.LOG2",
    ] {
        let path = format!("{}\\{}", base, name);
        let p = Path::new(&path);
        if !p.exists() {
            continue;
        }

        let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        match fs::remove_file(p) {
            Ok(()) => {
                if verbose {
                    eprintln!("[+] amcache: deleted {}", path);
                }
                stats.files_deleted += 1;
                stats.bytes_freed += size;
            }
            Err(e) => {
                eprintln!("[!] amcache: {}: {}", path, e);
                stats.errors += 1;
            }
        }
    }
}

fn clear_shimcache(stats: &mut AmcacheStats, verbose: bool) {
    let key = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
    let key_w = wide(key);
    let mut hkey = ptr::null_mut();

    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_w.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if rc != ERROR_SUCCESS {
        eprintln!("[!] amcache: ShimCache key open failed (rc={})", rc);
        stats.errors += 1;
        return;
    }

    let val_w = wide("AppCompatCache");
    let rc = unsafe { RegDeleteValueW(hkey, val_w.as_ptr()) };
    unsafe { RegCloseKey(hkey) };

    if rc == ERROR_SUCCESS {
        if verbose {
            eprintln!("[+] amcache: AppCompatCache registry value deleted");
        }
        stats.shimcache_cleared = true;
    } else {
        eprintln!(
            "[!] amcache: AppCompatCache delete failed (rc={}) — may require SYSTEM",
            rc
        );
        stats.errors += 1;
    }
}

fn wipe_pca_files(stats: &mut AmcacheStats, verbose: bool) {
    // PCA (Program Compatibility Assistant) — Win11 22H2+
    // Records every executable launched via Explorer with UTC timestamp.
    // High forensic value: persists after binary deletion.
    let pca_base = r"C:\Windows\appcompat\pca";
    for name in &[
        "PcaAppLaunchDic.txt",
        "PcaGeneralDb0.txt",
        "PcaGeneralDb1.txt",
        "PcaAppLaunchDic.txt.bak",
    ] {
        let path = format!("{}\\{}", pca_base, name);
        let p = Path::new(&path);
        if !p.exists() {
            continue;
        }
        let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        match fs::remove_file(p) {
            Ok(()) => {
                if verbose {
                    eprintln!("[+] amcache: deleted PCA artifact {}", path);
                }
                stats.files_deleted += 1;
                stats.bytes_freed += size;
            }
            Err(_) => {
                // PCA files may be locked — truncate as fallback
                if let Ok(f) = fs::OpenOptions::new().write(true).open(p) {
                    let _ = f.set_len(0);
                    stats.files_deleted += 1;
                    if verbose {
                        eprintln!("[+] amcache: truncated PCA artifact {}", path);
                    }
                } else {
                    stats.errors += 1;
                }
            }
        }
    }
}

pub fn wipe_amcache(verbose: bool) -> AmcacheStats {
    let mut stats = AmcacheStats::default();

    disable_appcompat_tasks();
    wipe_amcache_files(&mut stats, verbose);
    wipe_pca_files(&mut stats, verbose);
    clear_shimcache(&mut stats, verbose);

    eprintln!(
        "[+] amcache: {} file(s) ({} MiB), shimcache={}, {} error(s)",
        stats.files_deleted,
        stats.bytes_freed >> 20,
        stats.shimcache_cleared,
        stats.errors
    );
    stats
}
