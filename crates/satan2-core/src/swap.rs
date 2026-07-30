/*
 * swap.rs — Wipe swap partitions and swap files
 *
 * Swap space holds plaintext memory pages that may contain secrets,
 * session keys, decrypted data, or command history. It is NOT wiped
 * on shutdown by default.
 *
 * Strategy:
 *   1. Read /proc/swaps to discover active swap areas
 *   2. swapoff(path) — kernel stops using it for new pages
 *   3. Overwrite the full area with random data
 *      (for partitions: O_DIRECT write; for files: regular write)
 *   4. swapon(path, priority) — optional re-enable
 *
 * Note: swapoff requires CAP_SYS_ADMIN. Pages in active use are
 * paged back in before swapoff completes — the area is empty after.
 */

use crate::{fill_random, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};

// swapon(2) priority flags — not exposed by the libc crate
const SWAP_FLAG_PREFER: libc::c_int = 0x8000;
const SWAP_FLAG_PRIO_MASK: libc::c_int = 0x7fff;
const SWAP_FLAG_PRIO_SHIFT: libc::c_int = 0;

const WIPE_CHUNK: usize = 4 * 1024 * 1024; // 4 MiB

#[derive(Debug)]
pub struct SwapEntry {
    pub path: String,
    pub kind: String, // "partition" or "file"
    pub size_kb: u64,
    pub priority: i32,
}

pub fn list_swap() -> Result<Vec<SwapEntry>> {
    let f = File::open("/proc/swaps").map_err(|e| e.to_string())?;
    let mut entries = Vec::new();

    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if i == 0 {
            continue;
        } // skip header

        let mut parts = line.split_whitespace();
        let path = parts.next().unwrap_or("").to_string();
        let kind = parts.next().unwrap_or("").to_string();
        let size_kb: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let _used_kb: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let priority: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(-1);

        if !path.is_empty() {
            entries.push(SwapEntry {
                path,
                kind,
                size_kb,
                priority,
            });
        }
    }
    Ok(entries)
}

fn wipe_area(path: &str, size_bytes: u64, is_partition: bool) -> Result<()> {
    let mut buf = vec![0u8; WIPE_CHUNK];

    let mut f = if is_partition {
        // O_DIRECT for block devices
        let flags = libc::O_WRONLY | libc::O_DIRECT | libc::O_SYNC;
        let path_c = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
        let fd = unsafe { libc::open(path_c.as_ptr(), flags) };
        if fd < 0 {
            return Err(format!("open {}: errno={}", path, unsafe {
                *libc::__errno_location()
            }));
        }
        // Wrap fd in a File-like for write operations
        unsafe {
            use std::os::unix::io::FromRawFd;
            std::fs::File::from_raw_fd(fd)
        }
    } else {
        OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| format!("open {}: {}", path, e))?
    };

    let mut written = 0u64;
    while written < size_bytes {
        let chunk = WIPE_CHUNK.min((size_bytes - written) as usize);
        // Align to 512 for O_DIRECT
        let chunk = if is_partition {
            chunk & !(512 - 1)
        } else {
            chunk
        };
        if chunk == 0 {
            break;
        }

        fill_random(&mut buf[..chunk]);

        f.write_all(&buf[..chunk])
            .map_err(|e| format!("write to {}: {}", path, e))?;

        written += chunk as u64;
        eprint!(
            "\r[>] swap wipe {}: {}/{} MiB",
            path,
            written >> 20,
            size_bytes >> 20
        );
    }
    eprintln!();
    Ok(())
}

pub fn wipe_swap_entry(entry: &SwapEntry, reenable: bool) -> Result<()> {
    eprintln!(
        "[*] swap: disabling {} ({}KB)...",
        entry.path, entry.size_kb
    );

    let path_c = std::ffi::CString::new(entry.path.as_str()).map_err(|e| e.to_string())?;

    let r = unsafe { libc::swapoff(path_c.as_ptr()) };
    if r < 0 {
        return Err(format!("swapoff {}: errno={}", entry.path, unsafe {
            *libc::__errno_location()
        }));
    }

    eprintln!("[*] swap: wiping {}...", entry.path);
    let size_bytes = entry.size_kb * 1024;
    let is_partition = entry.kind.contains("partition");

    wipe_area(&entry.path, size_bytes, is_partition)?;

    if reenable {
        let flags =
            SWAP_FLAG_PREFER | ((entry.priority & SWAP_FLAG_PRIO_MASK) << SWAP_FLAG_PRIO_SHIFT);
        let r = unsafe { libc::swapon(path_c.as_ptr(), flags) };
        if r < 0 {
            eprintln!("[!] swapon {} failed: errno={}", entry.path, unsafe {
                *libc::__errno_location()
            });
        } else {
            eprintln!("[+] swap: re-enabled {}", entry.path);
        }
    }

    eprintln!("[+] swap: {} wiped", entry.path);
    Ok(())
}

pub fn wipe_all_swap(reenable: bool) -> Result<()> {
    let entries = list_swap()?;
    if entries.is_empty() {
        eprintln!("[*] swap: no active swap areas found");
        return Ok(());
    }

    for entry in &entries {
        if let Err(e) = wipe_swap_entry(entry, reenable) {
            eprintln!("[!] swap wipe {}: {}", entry.path, e);
        }
    }
    Ok(())
}
