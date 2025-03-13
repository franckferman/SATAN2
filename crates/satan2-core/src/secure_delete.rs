// Multi-pass secure file deletion (per-file).
// Passes: 0xFF → zeros → random → truncate → unlink.

use std::fs::{self, OpenOptions};
use std::io::{Seek, Write};
use std::path::Path;

#[derive(Default)]
pub struct SecureDeleteStats {
    pub files_deleted: u32,
    pub bytes_wiped:   u64,
    pub errors:        u32,
}

fn random_buf(buf: &mut [u8]) {
    let mut off = 0usize;
    let mut rem = buf.len();
    while rem > 0 {
        let r = unsafe {
            libc::getrandom(buf.as_mut_ptr().add(off) as *mut libc::c_void, rem, 0)
        };
        if r > 0 { off += r as usize; rem -= r as usize; }
    }
}

pub fn secure_delete_file(path: &str, passes: u32) -> Result<u64, String> {
    let meta = fs::metadata(path).map_err(|e| format!("{}: {}", path, e))?;
    let size = meta.len();
    if size == 0 {
        fs::remove_file(path).map_err(|e| e.to_string())?;
        return Ok(0);
    }

    let n = passes.max(3);
    let mut f = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;

    let chunk = 65536usize;
    let mut buf = vec![0u8; chunk];

    for pass in 0..n {
        f.seek(std::io::SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut remaining = size;
        while remaining > 0 {
            let n_bytes = remaining.min(chunk as u64) as usize;
            match pass % 3 {
                0 => { for b in &mut buf[..n_bytes] { *b = 0xFF; } }
                1 => { for b in &mut buf[..n_bytes] { *b = 0x00; } }
                _ => { random_buf(&mut buf[..n_bytes]); }
            }
            f.write_all(&buf[..n_bytes]).map_err(|e| e.to_string())?;
            remaining -= n_bytes as u64;
        }
        f.flush().map_err(|e| e.to_string())?;
        unsafe { libc::fsync(std::os::unix::io::AsRawFd::as_raw_fd(&f)); }
    }

    // Final random pass
    f.seek(std::io::SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut remaining = size;
    while remaining > 0 {
        let n_bytes = remaining.min(chunk as u64) as usize;
        random_buf(&mut buf[..n_bytes]);
        f.write_all(&buf[..n_bytes]).map_err(|e| e.to_string())?;
        remaining -= n_bytes as u64;
    }
    f.flush().map_err(|e| e.to_string())?;
    unsafe { libc::fsync(std::os::unix::io::AsRawFd::as_raw_fd(&f)); }

    f.set_len(0).map_err(|e| e.to_string())?;
    drop(f);
    fs::remove_file(path).map_err(|e| format!("unlink {}: {}", path, e))?;
    Ok(size)
}

fn secure_delete_dir_inner(dir: &Path, passes: u32, verbose: bool, s: &mut SecureDeleteStats) {
    let entries = match fs::read_dir(dir) {
        Ok(e)  => e,
        Err(_) => { s.errors += 1; return; }
    };
    let mut subdirs: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_symlink() { continue; }
        if p.is_dir() { subdirs.push(p); }
        else if p.is_file() {
            let ps = p.to_string_lossy().to_string();
            match secure_delete_file(&ps, passes) {
                Ok(b)  => { s.bytes_wiped += b; s.files_deleted += 1;
                            if verbose { eprintln!("[+] secure-delete: {}", ps); } }
                Err(e) => { s.errors += 1;
                            if verbose { eprintln!("[!] secure-delete: {}", e); } }
            }
        }
    }
    for sub in subdirs {
        secure_delete_dir_inner(&sub, passes, verbose, s);
        let _ = fs::remove_dir(&sub);
    }
}

pub fn secure_delete_dir(dir: &str, passes: u32, verbose: bool) -> SecureDeleteStats {
    let mut s = SecureDeleteStats::default();
    secure_delete_dir_inner(Path::new(dir), passes, verbose, &mut s);
    s
}

pub fn secure_delete_targets(targets: &[String], passes: u32, verbose: bool) -> SecureDeleteStats {
    let mut s = SecureDeleteStats::default();
    for t in targets {
        let p = Path::new(t);
        if p.is_dir() {
            let ds = secure_delete_dir(t, passes, verbose);
            s.files_deleted += ds.files_deleted;
            s.bytes_wiped   += ds.bytes_wiped;
            s.errors        += ds.errors;
            let _ = fs::remove_dir_all(t);
        } else if p.is_file() {
            match secure_delete_file(t, passes) {
                Ok(b)  => { s.bytes_wiped += b; s.files_deleted += 1;
                            if verbose { eprintln!("[+] secure-delete: {}", t); } }
                Err(e) => { s.errors += 1;
                            if verbose { eprintln!("[!] secure-delete: {}", e); } }
            }
        }
    }
    s
}
