#![cfg(target_os = "windows")]
/*
 * lnk_jumplists.rs — LNK shortcut and JumpList removal
 *
 * LNK files (%APPDATA%\Microsoft\Windows\Recent\*.lnk):
 *   Created automatically when a file is opened. Contains: target path,
 *   MAC times, volume serial number, NetBIOS name, file size.
 *
 * JumpLists (%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\ and
 *            CustomDestinations\):
 *   Per-application recently accessed files list, stored in OLE compound
 *   document format. Very rich forensic source.
 *
 * Also covers: Desktop shortcuts, Start Menu recent items.
 */

use std::fs;
use std::env;
use glob::glob;

#[derive(Debug, Default)]
pub struct LnkStats {
    pub lnk_deleted:       u32,
    pub jumplist_deleted:  u32,
    pub bytes_freed:       u64,
    pub errors:            u32,
}

fn delete_glob(pattern: &str, stats: &mut LnkStats, is_jumplist: bool) {
    if let Ok(entries) = glob(pattern) {
        for e in entries.flatten() {
            let path = e.to_str().unwrap_or("");
            if let Ok(meta) = fs::metadata(path) {
                stats.bytes_freed += meta.len();
            }
            match fs::remove_file(path) {
                Ok(()) => {
                    if is_jumplist { stats.jumplist_deleted += 1; }
                    else           { stats.lnk_deleted += 1; }
                }
                Err(e2) => {
                    eprintln!("[!] lnk: remove {}: {}", path, e2);
                    stats.errors += 1;
                }
            }
        }
    }
}

pub fn wipe_lnk_jumplists(verbose: bool) -> LnkStats {
    let mut stats = LnkStats::default();

    let appdata = env::var("APPDATA").unwrap_or_else(|_| String::from(r"C:\Users\Default\AppData\Roaming"));
    let recent  = format!(r"{}\Microsoft\Windows\Recent", appdata);

    // LNK files
    delete_glob(&format!(r"{}\*.lnk", recent), &mut stats, false);

    // AutomaticDestinations (JumpLists created by Windows)
    delete_glob(
        &format!(r"{}\AutomaticDestinations\*.automaticDestinations-ms", recent),
        &mut stats, true,
    );

    // CustomDestinations (JumpLists created by apps)
    delete_glob(
        &format!(r"{}\CustomDestinations\*.customDestinations-ms", recent),
        &mut stats, true,
    );

    // Windows Explorer Quick Access (pinned folders)
    let local = env::var("LOCALAPPDATA").unwrap_or_default();
    if !local.is_empty() {
        delete_glob(
            &format!(r"{}\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms", local),
            &mut stats, true,
        );
    }

    if verbose {
        eprintln!("[+] lnk: {} LNK + {} JumpList file(s) deleted, {} KiB freed",
            stats.lnk_deleted, stats.jumplist_deleted, stats.bytes_freed >> 10);
    }
    stats
}
