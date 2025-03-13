#![cfg(target_os = "windows")]
/*
 * prefetch.rs — Prefetch file removal
 *
 * C:\Windows\Prefetch\*.pf contains one file per launched executable:
 *   <EXE_NAME>-<HASH>.pf
 * Each .pf records: execution timestamps (up to 8 runs), file paths
 * accessed, volumes used. Primary artifact for execution evidence.
 *
 * Also covers:
 *  - ReadyBoost cache (same dir, *.db)
 *  - SysMain / Superfetch memory hints (not directly accessible, but
 *    disabling the service prevents future collection)
 */

use std::fs;
use glob::glob;
use std::process::Command;

#[derive(Debug, Default)]
pub struct PrefetchStats {
    pub files_deleted: u32,
    pub bytes_freed:   u64,
    pub errors:        u32,
}

fn delete_file(path: &str, stats: &mut PrefetchStats) {
    match fs::metadata(path) {
        Ok(m) => { stats.bytes_freed += m.len(); }
        Err(_) => {}
    }
    match fs::remove_file(path) {
        Ok(()) => { stats.files_deleted += 1; }
        Err(e) => {
            eprintln!("[!] prefetch: remove {}: {}", path, e);
            stats.errors += 1;
        }
    }
}

pub fn wipe_prefetch(verbose: bool) -> PrefetchStats {
    let mut stats = PrefetchStats::default();
    let prefetch_dir = r"C:\Windows\Prefetch";

    for pattern in &[
        format!(r"{}\*.pf",  prefetch_dir),
        format!(r"{}\*.db",  prefetch_dir),
        format!(r"{}\*.tmp", prefetch_dir),
    ] {
        if let Ok(entries) = glob(pattern) {
            for e in entries.flatten() {
                let p = e.to_str().unwrap_or("");
                if verbose { eprintln!("[*] prefetch: deleting {}", p); }
                delete_file(p, &mut stats);
            }
        }
    }

    eprintln!("[+] prefetch: {} file(s) deleted, {} KiB freed, {} error(s)",
        stats.files_deleted, stats.bytes_freed >> 10, stats.errors);
    stats
}

/// Disable SysMain (Superfetch) service to prevent future prefetch recording.
pub fn disable_sysmain() -> bool {
    Command::new("sc")
        .args(["config", "SysMain", "start=", "disabled"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
