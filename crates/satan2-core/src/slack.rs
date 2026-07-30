/*
 * slack.rs — Cluster tip and free space wiping
 *
 * Cluster tip: space between file EOF and end of its last allocated block.
 * Free space:  fill all unallocated blocks with a temp file, then delete it.
 */

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::time::Instant;

use walkdir::WalkDir;

use crate::Result;

const FREE_WIPE_CHUNK: usize = 4 * 1024 * 1024; // 4 MiB

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SlackStats {
    pub files_processed: u64,
    pub files_with_slack: u64,
    pub bytes_wiped: u64,
    pub errors: u64,
}

// ── libc wrappers ─────────────────────────────────────────────────────────────

fn lstat_size(path: &str) -> Option<(u64, u64)> {
    let path_c = std::ffi::CString::new(path).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::lstat(path_c.as_ptr(), &mut st) };
    if r < 0 {
        return None;
    }
    Some((st.st_size as u64, st.st_blocks as u64 * 512))
}

fn statfs_bsize(path: &str) -> u64 {
    let path_c = match std::ffi::CString::new(path) {
        Ok(c) => c,
        Err(_) => return 4096,
    };
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statfs(path_c.as_ptr(), &mut sfs) };
    if r < 0 || sfs.f_bsize <= 0 {
        return 4096;
    }
    sfs.f_bsize as u64
}

fn statfs_free(path: &str) -> u64 {
    let path_c = match std::ffi::CString::new(path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statfs(path_c.as_ptr(), &mut sfs) };
    if r < 0 {
        return 0;
    }
    sfs.f_bavail * sfs.f_bsize as u64
}

// ── Single-file cluster tip wipe ──────────────────────────────────────────────

pub fn slack_wipe_file(path: &str, stats: &mut SlackStats) -> Result<()> {
    let (file_size, alloc_bytes) = match lstat_size(path) {
        Some(v) => v,
        None => {
            stats.errors += 1;
            return Ok(());
        }
    };

    if file_size == 0 {
        stats.files_processed += 1;
        return Ok(());
    }

    // Skip sparse files (allocated < logical size)
    if alloc_bytes < file_size {
        stats.files_processed += 1;
        return Ok(());
    }

    let blk_size = statfs_bsize(path);
    let tail_used = file_size % blk_size;
    if tail_used == 0 {
        stats.files_processed += 1;
        return Ok(());
    }

    let slack_len = blk_size - tail_used;

    let mut f = match OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => {
            stats.files_processed += 1;
            stats.errors += 1;
            return Ok(());
        }
    };

    if f.seek(SeekFrom::Start(file_size)).is_err() {
        stats.errors += 1;
        return Ok(());
    }

    let zeros = vec![0u8; slack_len as usize];
    if f.write_all(&zeros).is_err() {
        stats.errors += 1;
        return Ok(());
    }

    unsafe { libc::fsync(f.as_raw_fd()) };

    // Truncate back to original size — zeros remain in the slack region
    if f.set_len(file_size).is_err() {
        stats.errors += 1;
        return Ok(());
    }

    unsafe { libc::fsync(f.as_raw_fd()) };

    stats.files_processed += 1;
    stats.files_with_slack += 1;
    stats.bytes_wiped += slack_len;
    Ok(())
}

// ── Recursive directory walk ──────────────────────────────────────────────────

pub fn slack_wipe_dir(path: &str, recursive: bool, stats: &mut SlackStats) -> Result<()> {
    let p = std::path::Path::new(path);

    if !p.is_dir() {
        return slack_wipe_file(path, stats);
    }

    eprintln!("[*] slack: scanning {}...", path);

    if !recursive {
        for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.metadata().map(|m| m.is_file()).unwrap_or(false) {
                let _ = slack_wipe_file(entry.path().to_str().unwrap_or(""), stats);
            }
        }
        return Ok(());
    }

    let walker = WalkDir::new(path).follow_links(false);

    for entry in walker {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().is_file() {
            continue;
        }

        let ep = entry.path().to_str().unwrap_or("");
        let _ = slack_wipe_file(ep, stats);

        if stats.files_processed.is_multiple_of(50_000) && stats.files_processed > 0 {
            eprint!(
                "\r[>] slack: {} files, {} MiB wiped",
                stats.files_processed,
                stats.bytes_wiped >> 20
            );
        }
    }

    eprintln!(
        "\r[+] slack: {} files, {} with slack, {} MiB, {} error(s)",
        stats.files_processed,
        stats.files_with_slack,
        stats.bytes_wiped >> 20,
        stats.errors
    );
    Ok(())
}

// ── Free space wipe ───────────────────────────────────────────────────────────

pub fn slack_wipe_free(mountpoint: &str, stats: &mut SlackStats) -> Result<()> {
    let free = statfs_free(mountpoint);
    eprintln!(
        "[*] slack_wipe_free: ~{} MiB free on {}",
        free >> 20,
        mountpoint
    );

    // mkstemp equivalent using libc
    let template = format!("{}/{}XXXXXX", mountpoint, ".satan2_freewipe_");
    let mut tmp_cstr = template.into_bytes();
    tmp_cstr.push(0);

    let fd = unsafe { libc::mkstemp(tmp_cstr.as_mut_ptr() as *mut libc::c_char) };
    if fd < 0 {
        return Err(format!("mkstemp failed: errno={}", unsafe {
            *libc::__errno_location()
        }));
    }

    // Unlink immediately — file stays open, disappears from dir now
    unsafe {
        let path_ptr = tmp_cstr.as_ptr() as *const libc::c_char;
        libc::unlink(path_ptr);
    }

    let zeros = vec![0u8; FREE_WIPE_CHUNK];
    let mut total_written: u64 = 0;
    let t0 = Instant::now();

    loop {
        let w = unsafe { libc::write(fd, zeros.as_ptr() as *const libc::c_void, FREE_WIPE_CHUNK) };

        if w < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::ENOSPC {
                break;
            }
            if errno == libc::EINTR {
                continue;
            }
            unsafe { libc::close(fd) };
            stats.errors += 1;
            return Err(format!("write error: errno={}", errno));
        }

        total_written += w as u64;
        if let Some(s) = stats.bytes_wiped.checked_add(w as u64) {
            stats.bytes_wiped = s;
        }

        let elapsed = t0.elapsed().as_secs_f64();
        let mbs = total_written as f64 / (1024.0 * 1024.0) / elapsed.max(0.001);
        eprint!(
            "\r[>] free wipe: {} MiB  {:.1} MiB/s  ",
            total_written >> 20,
            mbs
        );
    }

    unsafe {
        libc::fsync(fd);
        libc::close(fd);
    }

    eprintln!(
        "\n[+] slack_wipe_free: {} MiB of free space zeroed",
        total_written >> 20
    );
    Ok(())
}
