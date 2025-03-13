#![cfg(target_os = "windows")]
/*
 * recycle_bin.rs — Recycle Bin wiping
 *
 * Files in the Recycle Bin are stored in C:\$Recycle.Bin\<SID>\
 * Each deleted file has two entries:
 *   $RXXXXXX.<ext>  — actual file content
 *   $IXXXXXX.<ext>  — metadata (original path, deletion time, file size)
 *
 * The $I file is a forensic goldmine: it records the original full path
 * and deletion timestamp.
 *
 * Primary approach: SHEmptyRecycleBinW (Shell32) — cleanest
 * Fallback: direct deletion of $R* and $I* files
 */

use windows_sys::Win32::UI::Shell::SHEmptyRecycleBinW;
use std::fs;
use glob::glob;

#[derive(Debug, Default)]
pub struct RecycleBinStats {
    pub files_deleted: u32,
    pub bytes_freed:   u64,
    pub errors:        u32,
}

/// Use Shell API to empty the recycle bin (all drives, no confirm, no sound).
fn shell_empty_recycle_bin() -> bool {
    const SHERB_NOCONFIRMATION: u32 = 0x00000001;
    const SHERB_NOPROGRESSUI:   u32 = 0x00000002;
    const SHERB_NOSOUND:        u32 = 0x00000004;

    let flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND;
    let r = unsafe { SHEmptyRecycleBinW(0, std::ptr::null(), flags) };
    r == 0 // S_OK
}

/// Fallback: walk all $Recycle.Bin directories and delete $R/$I files.
fn direct_empty_recycle_bin(stats: &mut RecycleBinStats) {
    // Iterate all drive letters
    for drive in b'A'..=b'Z' {
        let base = format!("{}:\\$Recycle.Bin", drive as char);
        if !std::path::Path::new(&base).exists() { continue; }

        for pattern in &[
            format!(r"{}\*\$R*", base),
            format!(r"{}\*\$I*", base),
        ] {
            if let Ok(entries) = glob(pattern) {
                for e in entries.flatten() {
                    let path = e.to_str().unwrap_or("");
                    if let Ok(meta) = fs::metadata(path) {
                        stats.bytes_freed += meta.len();
                    }
                    match fs::remove_file(path) {
                        Ok(()) => { stats.files_deleted += 1; }
                        Err(e2) => {
                            eprintln!("[!] recycle_bin: {}: {}", path, e2);
                            stats.errors += 1;
                        }
                    }
                }
            }
        }
    }
}

pub fn wipe_recycle_bin(verbose: bool) -> RecycleBinStats {
    let mut stats = RecycleBinStats::default();

    if shell_empty_recycle_bin() {
        eprintln!("[+] recycle_bin: emptied via SHEmptyRecycleBinW");
        // Stats not available from Shell API
        stats.files_deleted = 1; // sentinel
    } else {
        if verbose { eprintln!("[*] recycle_bin: Shell API failed, using direct deletion"); }
        direct_empty_recycle_bin(&mut stats);
        eprintln!("[+] recycle_bin: {} file(s) deleted, {} KiB freed, {} error(s)",
            stats.files_deleted, stats.bytes_freed >> 10, stats.errors);
    }

    stats
}
