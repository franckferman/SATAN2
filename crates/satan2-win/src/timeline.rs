/*
 * timeline.rs — Windows Activity History and Clipboard artifact removal
 *
 * Windows Timeline (Activity History):
 *   C:\Users\*\AppData\Local\ConnectedDevicesPlatform\L.<locale>\ActivitiesCache.db
 *   SQLite database: records app launches, file opens, URLs, search queries
 *   with timestamps going back 30 days by default.
 *
 * Also covered by the cdp_dir (ConnectedDevicesPlatform):
 *   - ActivitiesCache.db-wal, ActivitiesCache.db-shm
 *   - Other CDPGlobalSettings*.bin files
 *
 * Clipboard History (Windows 10 v1809+):
 *   C:\Users\*\AppData\Local\Microsoft\Windows\Clipboard\
 *   Contains the last N clipboard entries (text, images) in .dat files.
 *   Only populated if "Clipboard history" is enabled in Settings.
 *
 * Windows Search history (search box):
 *   Already handled by win_search.rs for the UWP component.
 *
 * Disable Timeline via registry (optional):
 *   HKLM\SOFTWARE\Policies\Microsoft\Windows\System
 *     EnableActivityFeed = 0
 *     PublishUserActivities = 0
 *     UploadUserActivities = 0
 */

use std::fs;
use std::io::Write;
use std::path::Path;
use walkdir::WalkDir;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
    REG_OPTION_NON_VOLATILE,
};

#[derive(Debug, Default)]
pub struct TimelineStats {
    pub db_wiped: u32,
    pub clipboard_wiped: u32,
    pub files_deleted: u32,
    pub bytes_freed: u64,
    pub timeline_disabled: bool,
    pub errors: u32,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn overwrite_and_delete(path: &Path, stats: &mut TimelineStats) {
    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    if size > 0 {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; 65536];
            let mut done = 0u64;
            while done < size {
                let n = ((size - done) as usize).min(zeros.len());
                let _ = f.write_all(&zeros[..n]);
                done += n as u64;
            }
        }
    }

    match fs::remove_file(path) {
        Ok(()) => {
            stats.files_deleted += 1;
            stats.bytes_freed += size;
        }
        Err(e) => {
            if e.raw_os_error() != Some(32) {
                eprintln!("[!] timeline: {}: {}", path.display(), e);
                stats.errors += 1;
            }
        }
    }
}

fn delete_dir_tree(path: &Path, stats: &mut TimelineStats) {
    for entry in WalkDir::new(path)
        .follow_links(false)
        .contents_first(true)
        .into_iter()
        .flatten()
    {
        let p = entry.path();
        if entry.file_type().is_file() {
            let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            match fs::remove_file(p) {
                Ok(()) => {
                    stats.files_deleted += 1;
                    stats.bytes_freed += size;
                }
                Err(_) => {
                    stats.errors += 1;
                }
            }
        } else {
            let _ = fs::remove_dir(p);
        }
    }
}

fn wipe_activity_cache(cdp_dir: &Path, stats: &mut TimelineStats, verbose: bool) {
    if !cdp_dir.exists() {
        return;
    }

    // L.<locale> subdirectories contain the SQLite databases
    for entry in fs::read_dir(cdp_dir).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let ns = name.to_string_lossy();
        if !ns.starts_with("L.") {
            continue;
        }

        let locale_dir = entry.path();
        for db_name in &[
            "ActivitiesCache.db",
            "ActivitiesCache.db-wal",
            "ActivitiesCache.db-shm",
        ] {
            let db = locale_dir.join(db_name);
            if db.exists() {
                if verbose {
                    eprintln!("[*] timeline: {}", db.display());
                }
                overwrite_and_delete(&db, stats);
                stats.db_wiped += 1;
            }
        }
    }
}

fn wipe_clipboard_dir(clipboard_dir: &Path, stats: &mut TimelineStats, verbose: bool) {
    if !clipboard_dir.exists() {
        return;
    }
    if verbose {
        eprintln!("[*] timeline: clipboard: {}", clipboard_dir.display());
    }
    let n_before = stats.files_deleted;
    delete_dir_tree(clipboard_dir, stats);
    let n = stats.files_deleted - n_before;
    if n > 0 {
        stats.clipboard_wiped += 1;
    }
}

fn disable_timeline_gpo() -> bool {
    let key = "SOFTWARE\\Policies\\Microsoft\\Windows\\System";
    let key_w = wide(key);
    let mut hkey: HKEY = std::ptr::null_mut();
    let mut disp = 0u32;

    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key_w.as_ptr(),
            0,
            std::ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut hkey,
            &mut disp,
        )
    };
    if rc != ERROR_SUCCESS {
        return false;
    }

    let mut ok = true;
    for value in &[
        "EnableActivityFeed",
        "PublishUserActivities",
        "UploadUserActivities",
    ] {
        let vw = wide(value);
        let data = 0u32.to_le_bytes();
        let rc = unsafe { RegSetValueExW(hkey, vw.as_ptr(), 0, 4, data.as_ptr(), 4) };
        if rc != ERROR_SUCCESS {
            ok = false;
        }
    }
    unsafe { RegCloseKey(hkey) };
    ok
}

pub fn wipe_timeline(disable_feed: bool, verbose: bool) -> TimelineStats {
    let mut stats = TimelineStats::default();

    let users = match fs::read_dir(r"C:\Users") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[!] timeline: {}", e);
            return stats;
        }
    };

    for user in users.flatten() {
        let home = user.path();
        if !home.is_dir() {
            continue;
        }

        // Activity cache
        let cdp = home.join(r"AppData\Local\ConnectedDevicesPlatform");
        wipe_activity_cache(&cdp, &mut stats, verbose);

        // Clipboard history
        let clip = home.join(r"AppData\Local\Microsoft\Windows\Clipboard");
        wipe_clipboard_dir(&clip, &mut stats, verbose);
    }

    // Optionally disable via Group Policy registry keys
    if disable_feed {
        stats.timeline_disabled = disable_timeline_gpo();
        if stats.timeline_disabled {
            eprintln!("[+] timeline: Activity Feed disabled via GPO registry keys");
        } else {
            eprintln!("[!] timeline: failed to set GPO registry keys");
            stats.errors += 1;
        }
    }

    eprintln!(
        "[+] timeline: {} DB(s) wiped, {} clipboard(s) wiped, {} file(s) ({} MiB), {} error(s)",
        stats.db_wiped,
        stats.clipboard_wiped,
        stats.files_deleted,
        stats.bytes_freed >> 20,
        stats.errors
    );
    stats
}
