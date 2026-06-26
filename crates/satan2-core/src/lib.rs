pub mod exif_forge;
pub mod trap_archive;
pub mod stego_honey;
pub mod nvme;
pub mod ata;
pub mod wipe;
pub mod fs_kill;
pub mod meta;
pub mod slack;
pub mod log_poison;
pub mod swap;
pub mod net_clean;
pub mod auditd;
pub mod ssh_clean;
pub mod trim;
pub mod tmpfs;
pub mod opsec_linux;

#[cfg(target_os = "linux")]
pub mod browser_linux;
#[cfg(target_os = "linux")]
pub mod pkg_logs;
#[cfg(target_os = "linux")]
pub mod log_forge;
#[cfg(target_os = "linux")]
pub mod pkg_forge;
#[cfg(target_os = "linux")]
pub mod ssh_forge;
#[cfg(target_os = "linux")]
pub mod browser_forge;
#[cfg(target_os = "linux")]
pub mod forge_wtmp;
#[cfg(target_os = "linux")]
pub mod forge_journal;
#[cfg(target_os = "linux")]
pub mod secure_delete;
#[cfg(target_os = "linux")]
pub mod memory_wipe;
#[cfg(target_os = "linux")]
pub mod proc_clean;
#[cfg(target_os = "linux")]
pub mod docker_cover;
#[cfg(target_os = "linux")]
pub mod self_audit;
#[cfg(target_os = "linux")]
pub mod lastlog_forge;

pub type Result<T> = std::result::Result<T, String>;

pub const fn iowr(ty: u8, nr: u8, size: usize) -> libc::c_ulong {
    (3 << 30) | ((size as libc::c_ulong) << 16) | ((ty as libc::c_ulong) << 8) | (nr as libc::c_ulong)
}

pub const fn iow(ty: u8, nr: u8, size: usize) -> libc::c_ulong {
    (1 << 30) | ((size as libc::c_ulong) << 16) | ((ty as libc::c_ulong) << 8) | (nr as libc::c_ulong)
}

/// Zero a memory slice without the compiler optimizing it away.
pub fn secure_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// Overwrite a file with zeros and truncate to 0.
pub fn secure_zero_file(path: &str) -> Result<()> {
    use std::io::Write;

    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let size = meta.len();

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;

    if size > 0 {
        let buf = vec![0u8; 4096];
        let mut done = 0u64;
        while done < size {
            let n = ((size - done) as usize).min(4096);
            f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            done += n as u64;
        }
    }
    f.set_len(0).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn fill_random(buf: &mut [u8]) {
    let mut p = buf.as_mut_ptr();
    let mut rem = buf.len();
    while rem > 0 {
        let r = unsafe { libc::getrandom(p as *mut libc::c_void, rem, 0) };
        if r > 0 {
            unsafe { p = p.add(r as usize) };
            rem -= r as usize;
        }
    }
}

pub fn rand_u32() -> u32 {
    let mut v = 0u32;
    fill_random(unsafe { std::slice::from_raw_parts_mut(&mut v as *mut u32 as *mut u8, 4) });
    v
}
