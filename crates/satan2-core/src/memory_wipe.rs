// RAM purge via mmap(MAP_ANONYMOUS) fill + munmap, then drop_caches.
// mmap returns MAP_FAILED on OOM — safe, no panic/abort.

use std::fs;
use std::io::Write;

pub struct MemoryWipeStats {
    pub bytes_zeroed:  u64,
    pub cache_dropped: bool,
    pub errors:        u32,
}

fn drop_caches() -> bool {
    // sync before dropping to avoid flushing dirty data as zeros
    unsafe { libc::sync() };
    match fs::OpenOptions::new().write(true).open("/proc/sys/vm/drop_caches") {
        Ok(mut f) => f.write_all(b"3\n").is_ok(),
        Err(_)    => false,
    }
}

fn fill_free_memory(verbose: bool) -> u64 {
    const CHUNK: usize = 64 * 1024 * 1024; // 64 MiB slabs
    const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB cap to avoid total OOM

    let mut total = 0u64;
    let mut slabs: Vec<(*mut libc::c_void, usize)> = Vec::new();

    unsafe {
        loop {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                CHUNK,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED { break; }

            // Explicit zero-fill with volatile writes forces page allocation
            libc::memset(ptr, 0, CHUNK);
            let p8 = ptr as *mut u8;
            for i in (0..CHUNK).step_by(4096) {
                std::ptr::write_volatile(p8.add(i), 0u8);
            }

            total += CHUNK as u64;
            slabs.push((ptr, CHUNK));

            if verbose && slabs.len() % 8 == 0 {
                eprintln!("[*] memory-wipe: {} MiB zeroed", total / 1_048_576);
            }
            if total >= MAX_BYTES { break; }
        }

        // Release: pages are returned to OS as zero-filled
        for (ptr, len) in slabs {
            libc::munmap(ptr, len);
        }
    }

    total
}

pub fn wipe_memory(verbose: bool) -> MemoryWipeStats {
    let mut s = MemoryWipeStats { bytes_zeroed: 0, cache_dropped: false, errors: 0 };

    s.cache_dropped = drop_caches();
    if verbose {
        if s.cache_dropped { eprintln!("[+] memory-wipe: page cache dropped"); }
        else               { eprintln!("[!] memory-wipe: drop_caches failed (root required)"); }
    }

    if verbose { eprintln!("[*] memory-wipe: filling free RAM (2 GiB cap)..."); }
    s.bytes_zeroed = fill_free_memory(verbose);

    // Second drop after releasing our slabs
    drop_caches();

    if verbose {
        eprintln!("[+] memory-wipe: {} MiB zeroed and released", s.bytes_zeroed / 1_048_576);
    }
    s
}
