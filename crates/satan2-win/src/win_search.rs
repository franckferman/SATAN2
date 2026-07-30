/*
 * win_search.rs — Windows Search index removal
 *
 * Windows Search (WSearch service) maintains an ESE database at:
 *   C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
 *
 * The index records:
 *   - Every file path ever indexed (including deleted files)
 *   - File content snippets (plain text extracted from Office/PDF/etc.)
 *   - Timestamps of when files were accessed / created
 *   - Application usage and search query history
 *
 * This is a rich forensic source — investigators routinely pull it to
 * reconstruct attacker file activity without needing the files themselves.
 *
 * GatherLogs/ also contains incremental crawl logs.
 *
 * Strategy:
 *   1. Stop WSearch service
 *   2. Zero-overwrite Windows.edb (ESE checksum corruption)
 *   3. Delete the entire Search\Data\Applications\Windows\ directory tree
 *   4. Restart WSearch (rebuilds from scratch — clean state)
 *
 * The additional SearchApp search history (Cortana/Search box queries) lives in:
 *   C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
 *   (handled by lnk_jumplists.rs) and in the IndexedDB of SearchApp.exe UWP.
 *
 * UWP SearchApp data:
 *   C:\Users\*\AppData\Local\Packages\Microsoft.Windows.Search_*\LocalState\
 */

use std::fs;
use std::io::Write;
use std::process::Command;
use walkdir::WalkDir;

const WSEARCH_SERVICE: &str = "WSearch";
const SEARCH_DATA_DIR: &str = r"C:\ProgramData\Microsoft\Search\Data\Applications\Windows";
const SEARCH_DB: &str = r"C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb";

#[derive(Debug, Default)]
pub struct WinSearchStats {
    pub db_wiped: bool,
    pub files_deleted: u32,
    pub bytes_freed: u64,
    pub uwp_cleared: u32,
    pub errors: u32,
}

fn service_stop(name: &str) -> bool {
    Command::new("net")
        .args(["stop", name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn service_start(name: &str) -> bool {
    Command::new("net")
        .args(["start", name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn overwrite_and_delete(path: &str, stats: &mut WinSearchStats) {
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
            eprintln!("[!] win_search: remove {}: {}", path, e);
            stats.errors += 1;
        }
    }
}

fn delete_dir_tree(dir: &str, stats: &mut WinSearchStats) {
    if !std::path::Path::new(dir).exists() {
        return;
    }
    for entry in WalkDir::new(dir)
        .follow_links(false)
        .contents_first(true)
        .into_iter()
        .flatten()
    {
        let path = entry.path();
        if entry.file_type().is_file() {
            let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            match fs::remove_file(path) {
                Ok(()) => {
                    stats.files_deleted += 1;
                    stats.bytes_freed += size;
                }
                Err(e) => {
                    if e.raw_os_error() != Some(32) {
                        eprintln!("[!] win_search: {}: {}", path.display(), e);
                        stats.errors += 1;
                    }
                }
            }
        } else if entry.file_type().is_dir() {
            let _ = fs::remove_dir(path);
        }
    }
}

fn wipe_uwp_search(stats: &mut WinSearchStats) {
    let users_dir = r"C:\Users";
    let users = match fs::read_dir(users_dir) {
        Ok(d) => d,
        Err(_) => return,
    };
    for user in users.flatten() {
        let pkg_dir = format!(r"{}\AppData\Local\Packages", user.path().display());
        let pkgs = match fs::read_dir(&pkg_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for pkg in pkgs.flatten() {
            let name = pkg.file_name();
            let name_str = name.to_string_lossy();
            // Microsoft.Windows.Search_ prefix covers all locale variants
            if name_str.starts_with("Microsoft.Windows.Search_") {
                let local = format!(r"{}\LocalState", pkg.path().display());
                let n_before = stats.files_deleted;
                delete_dir_tree(&local, stats);
                if stats.files_deleted > n_before {
                    eprintln!(
                        "[+] win_search: UWP search data cleared for {}",
                        user.path().display()
                    );
                    stats.uwp_cleared += 1;
                }
            }
        }
    }
}

pub fn wipe_win_search(verbose: bool) -> WinSearchStats {
    let mut stats = WinSearchStats::default();

    eprintln!("[*] win_search: stopping {} service...", WSEARCH_SERVICE);
    if !service_stop(WSEARCH_SERVICE) {
        eprintln!(
            "[!] win_search: failed to stop {} (may not be running)",
            WSEARCH_SERVICE
        );
    }

    // Brief wait for service to release DB handle
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Zero-overwrite and delete Windows.edb (Win10 ESE format)
    if std::path::Path::new(SEARCH_DB).exists() {
        if verbose {
            eprintln!("[*] win_search: overwriting {}", SEARCH_DB);
        }
        overwrite_and_delete(SEARCH_DB, &mut stats);
        stats.db_wiped = true;
        eprintln!("[+] win_search: Windows.edb wiped");
    } else {
        eprintln!("[*] win_search: Windows.edb not found");
    }

    // Win11 SQLite search databases (replace Windows.edb on Win11)
    for db_name in &[
        "Windows-gather.db",
        "Windows.db",
        "Windows-gather.db-wal",
        "Windows.db-wal",
        "Windows-gather.db-shm",
        "Windows.db-shm",
    ] {
        let db_path = format!(r"{}\{}", SEARCH_DATA_DIR, db_name);
        if std::path::Path::new(&db_path).exists() {
            if verbose {
                eprintln!("[*] win_search: removing {} (Win11 SQLite)", db_name);
            }
            overwrite_and_delete(&db_path, &mut stats);
            stats.db_wiped = true;
        }
    }

    // Delete the full directory tree (GatherLogs/, etc.)
    if verbose {
        eprintln!("[*] win_search: deleting {}", SEARCH_DATA_DIR);
    }
    delete_dir_tree(SEARCH_DATA_DIR, &mut stats);

    // Wipe UWP SearchApp local state
    wipe_uwp_search(&mut stats);

    // Restart service — rebuilds clean index
    eprintln!("[*] win_search: restarting {} service...", WSEARCH_SERVICE);
    if !service_start(WSEARCH_SERVICE) {
        eprintln!(
            "[!] win_search: failed to restart {} (non-fatal)",
            WSEARCH_SERVICE
        );
    }

    eprintln!(
        "[+] win_search: {} file(s) deleted, {} MiB freed, {} error(s)",
        stats.files_deleted,
        stats.bytes_freed >> 20,
        stats.errors
    );
    stats
}
