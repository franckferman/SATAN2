/*
 * thumbcache.rs — Thumbnail cache and icon cache removal
 *
 * Windows Explorer generates thumbnail previews and caches them in:
 *   %LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db
 *   %LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_*.db
 *
 * These databases contain actual image thumbnails — a forensic examiner
 * can recover images of files that no longer exist on disk.
 *
 * The databases are locked by Explorer. We must kill Explorer before deletion
 * and restart it after, or use Volume Shadow Copies to access the files.
 *
 * Strategy:
 *   1. taskkill /F /IM explorer.exe
 *   2. Delete thumbcache_*.db + iconcache_*.db
 *   3. Restart explorer.exe
 */

use glob::glob;
use std::env;
use std::fs;
use std::process::Command;

#[derive(Debug, Default)]
pub struct ThumbcacheStats {
    pub files_deleted: u32,
    pub bytes_freed: u64,
    pub errors: u32,
}

fn kill_explorer() -> bool {
    Command::new("taskkill")
        .args(["/F", "/IM", "explorer.exe"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn start_explorer() {
    let _ = Command::new("explorer.exe").spawn();
}

pub fn wipe_thumbcache(verbose: bool) -> ThumbcacheStats {
    let mut stats = ThumbcacheStats::default();

    let localappdata = env::var("LOCALAPPDATA").unwrap_or_else(|_| {
        format!(
            r"C:\Users\{}\AppData\Local",
            env::var("USERNAME").unwrap_or_else(|_| "Default".into())
        )
    });

    let explorer_dir = format!(r"{}\Microsoft\Windows\Explorer", localappdata);

    if verbose {
        eprintln!("[*] thumbcache: killing explorer.exe...");
    }
    let explorer_killed = kill_explorer();

    // Small delay to let Explorer release file handles
    if explorer_killed {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    for pattern in &[
        format!(r"{}\thumbcache_*.db", explorer_dir),
        format!(r"{}\iconcache_*.db", explorer_dir),
    ] {
        if let Ok(entries) = glob(pattern) {
            for e in entries.flatten() {
                let path = e.to_str().unwrap_or("");
                if let Ok(meta) = fs::metadata(path) {
                    stats.bytes_freed += meta.len();
                }
                match fs::remove_file(path) {
                    Ok(()) => {
                        if verbose {
                            eprintln!("[+] thumbcache: deleted {}", path);
                        }
                        stats.files_deleted += 1;
                    }
                    Err(e2) => {
                        eprintln!("[!] thumbcache: {}: {}", path, e2);
                        stats.errors += 1;
                    }
                }
            }
        }
    }

    if explorer_killed {
        if verbose {
            eprintln!("[*] thumbcache: restarting explorer.exe...");
        }
        start_explorer();
    }

    eprintln!(
        "[+] thumbcache: {} file(s) deleted, {} MiB freed, {} error(s)",
        stats.files_deleted,
        stats.bytes_freed >> 20,
        stats.errors
    );
    stats
}
