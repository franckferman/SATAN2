/*
 * tmpfs.rs — Wipe volatile and temporary file areas
 *
 * Targets:
 *  /tmp                              world-writable temp files
 *  /dev/shm                          shared memory objects (mmap'd secrets)
 *  /run/user/<uid>/                  XDG runtime dir (sockets, tokens)
 *  /var/lib/systemd/coredump/        core dumps (may contain process memory)
 *  /var/crash/                       Ubuntu crash reports
 *  /tmp/.ICE-unix, /tmp/.X11-unix    socket dirs (skip — active sockets)
 *
 * Strategy: recursively delete all regular files. Directories and sockets
 * are left in place (removing a directory used as a socket parent breaks
 * running processes).
 *
 * For coredumps: overwrite before deletion (they contain raw memory).
 */

use std::fs;
use std::path::Path;

use walkdir::WalkDir;

use crate::Result;

#[derive(Debug, Default)]
pub struct TmpfsStats {
    pub files_deleted: u64,
    pub bytes_freed: u64,
    pub cores_wiped: u32,
    pub errors: u32,
}

// ── Overwrite a file before deletion ─────────────────────────────────────────

fn secure_delete(path: &str, stats: &mut TmpfsStats) {
    if let Ok(meta) = fs::metadata(path) {
        let size = meta.len();
        // Overwrite core dumps and large files before removing
        if size > 0 && (path.contains("coredump") || path.contains(".crash") || size > 1024 * 1024)
        {
            let _ = crate::secure_zero_file(path);
            if path.contains("coredump") || path.contains("/var/crash") {
                stats.cores_wiped += 1;
            }
        }
        stats.bytes_freed += size;
    }
    match fs::remove_file(path) {
        Ok(()) => {
            stats.files_deleted += 1;
        }
        Err(e) => {
            eprintln!("[!] tmpfs: remove {}: {}", path, e);
            stats.errors += 1;
        }
    }
}

// ── Walk a directory and delete all regular files ─────────────────────────────

fn wipe_dir(dir: &str, stats: &mut TmpfsStats) {
    if !Path::new(dir).exists() {
        return;
    }
    eprintln!("[*] tmpfs: wiping {}...", dir);

    let walker = WalkDir::new(dir).follow_links(false).contents_first(true);

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                stats.errors += 1;
                continue;
            }
        };

        if entry.file_type().is_file() {
            secure_delete(entry.path().to_str().unwrap_or(""), stats);
        }
    }
}

// ── /run/user/<uid>/ ──────────────────────────────────────────────────────────

fn wipe_xdg_runtime(stats: &mut TmpfsStats) {
    let uid = unsafe { libc::getuid() };
    let path = format!("/run/user/{}", uid);

    if Path::new(&path).exists() {
        // Only delete regular files — sockets/pipes break running processes
        if let Ok(rd) = fs::read_dir(&path) {
            for entry in rd.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_file() {
                        secure_delete(entry.path().to_str().unwrap_or(""), stats);
                    }
                }
            }
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn wipe_tmp_areas(stats: &mut TmpfsStats) -> Result<()> {
    wipe_dir("/tmp", stats);
    wipe_dir("/dev/shm", stats);
    wipe_dir("/var/lib/systemd/coredump", stats);
    wipe_dir("/var/crash", stats);
    wipe_xdg_runtime(stats);

    eprintln!(
        "[+] tmpfs: {} file(s) deleted, {} MiB freed, {} core(s) wiped, {} error(s)",
        stats.files_deleted,
        stats.bytes_freed >> 20,
        stats.cores_wiped,
        stats.errors
    );
    Ok(())
}
