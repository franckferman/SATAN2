/*
 * registry.rs — Registry artifact removal
 *
 * Key forensic artifacts in the registry:
 *
 *  UserAssist (HKCU):   encoded GUI execution history (ROT-13 names + run count)
 *  ShimCache  (HKLM):   AppCompatCache — all executed PE paths + timestamps
 *  Amcache    (file):   C:\Windows\AppCompat\Programs\Amcache.hve — SHA1 + metadata
 *  RecentDocs (HKCU):   recently opened files per extension
 *  RunMRU     (HKCU):   Run dialog history
 *  TypedURLs  (HKCU):   IE/Edge typed URLs
 *  BAM        (HKLM):   Background Activity Monitor — last exec time per binary
 *  MuiCache   (HKCU):   application display names (populated on first run)
 *  WordWheelQuery:      Explorer search history
 */

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::System::Registry::*;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

// ── Delete all values under a key ────────────────────────────────────────────

unsafe fn clear_key_values(root: HKEY, subkey: &str) -> u32 {
    let path = to_wide(subkey);
    let mut hkey: HKEY = std::ptr::null_mut();

    let r = RegOpenKeyExW(
        root,
        path.as_ptr(),
        0,
        KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
        &mut hkey,
    );
    if r != 0 {
        return 0;
    }

    let mut deleted = 0u32;
    loop {
        let mut name = vec![0u16; 16384];
        let mut name_len = name.len() as u32;

        // Always enumerate index 0 — after deletion the next value shifts down
        let r = RegEnumValueW(
            hkey,
            0,
            name.as_mut_ptr(),
            &mut name_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        if r != 0 {
            break;
        }

        let r = RegDeleteValueW(hkey, name.as_ptr());
        if r == 0 {
            deleted += 1;
        } else {
            break;
        }
    }

    RegFlushKey(hkey);
    RegCloseKey(hkey);
    deleted
}

// ── Delete a registry key and all subkeys ─────────────────────────────────────

unsafe fn delete_key_recursive(root: HKEY, subkey: &str) -> bool {
    let path = to_wide(subkey);
    RegDeleteTreeW(root, path.as_ptr()) == 0
}

// ── UserAssist ────────────────────────────────────────────────────────────────

pub fn clear_userassist() -> u32 {
    // Two known GUIDs for UserAssist under HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
    let guids = [
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count",
    ];
    let mut total = 0u32;
    for key in &guids {
        total += unsafe { clear_key_values(HKEY_CURRENT_USER, key) };
    }
    eprintln!("[+] registry: UserAssist — {} entry/entries cleared", total);
    total
}

// ── ShimCache / AppCompatCache ────────────────────────────────────────────────

pub fn clear_shimcache() -> bool {
    // Delete and recreate the AppCompatCache value — kernel rebuilds on reboot
    let path = to_wide(r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache");
    let val = to_wide("AppCompatCache");

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let r = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
            &mut hkey,
        );
        if r != 0 {
            return false;
        }

        let r = RegDeleteValueW(hkey, val.as_ptr());
        RegFlushKey(hkey);
        RegCloseKey(hkey);
        if r == 0 {
            eprintln!("[+] registry: ShimCache cleared");
            true
        } else {
            false
        }
    }
}

// ── RecentDocs ────────────────────────────────────────────────────────────────

pub fn clear_recentdocs() -> bool {
    let r = unsafe {
        delete_key_recursive(
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        )
    };
    eprintln!(
        "[+] registry: RecentDocs {}",
        if r { "cleared" } else { "failed" }
    );
    r
}

// ── RunMRU ────────────────────────────────────────────────────────────────────

pub fn clear_runmru() -> u32 {
    let n = unsafe {
        clear_key_values(
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        )
    };
    eprintln!("[+] registry: RunMRU — {} entry/entries cleared", n);
    n
}

// ── TypedURLs ─────────────────────────────────────────────────────────────────

pub fn clear_typed_urls() -> u32 {
    let n = unsafe {
        clear_key_values(
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Internet Explorer\TypedURLs",
        )
    };
    eprintln!("[+] registry: TypedURLs — {} entry/entries cleared", n);
    n
}

// ── BAM (Background Activity Monitor) — Windows 10+ ──────────────────────────

pub fn clear_bam() -> bool {
    // BAM stores last execution time per binary under user SID subkeys
    let r = unsafe {
        delete_key_recursive(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        )
    };
    eprintln!(
        "[+] registry: BAM {}",
        if r { "cleared" } else { "failed/not present" }
    );
    r
}

// ── MUICache ──────────────────────────────────────────────────────────────────

pub fn clear_muicache() -> u32 {
    let n = unsafe {
        clear_key_values(
            HKEY_CURRENT_USER,
            r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        )
    };
    eprintln!("[+] registry: MUICache — {} entry/entries cleared", n);
    n
}

// ── WordWheelQuery (Explorer search history) ──────────────────────────────────

pub fn clear_wordwheelquery() -> u32 {
    let n = unsafe {
        clear_key_values(
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
        )
    };
    eprintln!("[+] registry: WordWheelQuery — {} entry/entries cleared", n);
    n
}

// ── Amcache.hve (file, not registry API) ─────────────────────────────────────

pub fn wipe_amcache() -> bool {
    // Amcache.hve is locked by the system. We can try to stop and restart
    // the apphelp service, but the simplest approach is to truncate it.
    let path = r"C:\Windows\AppCompat\Programs\Amcache.hve";
    match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => {
            if f.set_len(0).is_ok() {
                eprintln!("[+] registry: Amcache.hve truncated");
                return true;
            }
            eprintln!("[!] registry: Amcache.hve truncate failed (file locked)");
            false
        }
        Err(e) => {
            eprintln!("[!] registry: Amcache.hve open failed: {}", e);
            false
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct RegistryStats {
    pub userassist_cleared: u32,
    pub shimcache_cleared: bool,
    pub bam_cleared: bool,
    pub other_cleared: u32,
    pub errors: u32,
}

pub fn clean_registry(verbose: bool) -> RegistryStats {
    let mut stats = RegistryStats::default();

    // Bind the results first: these fields are write-only (callers only read
    // `.errors`), so struct-literal init would trip dead_code, while a direct
    // assignment right after `Default::default()` trips field_reassign_with_default.
    let userassist_cleared = clear_userassist();
    let shimcache_cleared = clear_shimcache();
    stats.userassist_cleared = userassist_cleared;
    stats.shimcache_cleared = shimcache_cleared;
    clear_recentdocs();
    stats.other_cleared += clear_runmru();
    stats.other_cleared += clear_typed_urls();
    stats.bam_cleared = clear_bam();
    stats.other_cleared += clear_muicache();
    stats.other_cleared += clear_wordwheelquery();
    wipe_amcache();

    if verbose {
        eprintln!("[+] registry: clean complete");
    }
    stats
}
