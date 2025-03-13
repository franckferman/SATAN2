// High-level operations: encrypt files, directories, devices, containers, secure wipe.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::algo::Engine;
use crate::container::{fill_random, open, write_sector, SECTOR_SIZE};
use crate::header::{AlgoId, CvHeader, DATA_OFFSET, SALT_LEN};
use crate::kdf::{derive_keys, split_keys};
use crate::xts::{Aes256Cipher, Xts};

pub use crate::header::AlgoId as Algorithm;

// ─── internal helpers ────────────────────────────────────────────────────────

/// Build a fresh container header + encrypted header region, write salt + enc_hdr to `f`.
/// Returns the Engine built from the embedded master keys and the CvHeader.
fn write_container_header(
    f: &mut File,
    data_size: u64,
    algo: AlgoId,
    passphrase: &[u8],
    kdf_iters: u32,
) -> Result<(CvHeader, Engine), String> {
    use zeroize::Zeroizing;

    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;

    let km = derive_keys(passphrase, &salt, kdf_iters);
    let (hk1, hk2, _dk1, _dk2, _ck1, _ck2) = split_keys(&km);

    let mut master_key  = Zeroizing::new([0u8; 64]);
    let mut cascade_key = Zeroizing::new([0u8; 64]);
    fill_random(master_key.as_mut())?;
    fill_random(cascade_key.as_mut())?;

    let hdr = CvHeader {
        algo,
        kdf_iters,
        volume_size: data_size,
        master_key:  *master_key,
        cascade_key: *cascade_key,
    };

    let engine = Engine::from_keys(algo, &hdr.master_key, &hdr.cascade_key);

    let mut hdr_buf = hdr.serialize();
    let xts: Xts<Aes256Cipher> = Xts {
        data_cipher:  Aes256Cipher::new(hk1),
        tweak_cipher: Aes256Cipher::new(hk2),
    };
    xts.encrypt_sector(0, &mut hdr_buf);

    f.write_all(&salt).map_err(|e| e.to_string())?;
    f.write_all(&hdr_buf).map_err(|e| e.to_string())?;

    Ok((hdr, engine))
}

/// Encrypt `data` (arbitrary length, padded to next multiple of SECTOR_SIZE) and stream to `f`.
/// Writes sectors sequentially starting at `start_sector`.
/// Returns number of sectors written.
fn stream_encrypt_to_file(
    f: &mut File,
    engine: &Engine,
    data: &mut dyn Read,
    data_len: u64,
    start_sector: u64,
) -> Result<u64, String> {
    let padded = align_up(data_len, SECTOR_SIZE as u64);
    let n_sectors = padded / SECTOR_SIZE as u64;
    let mut buf = vec![0u8; SECTOR_SIZE];
    let mut sector = start_sector;
    let mut remaining = data_len;

    while remaining > 0 {
        let to_read = remaining.min(SECTOR_SIZE as u64) as usize;
        buf.fill(0);
        data.read_exact(&mut buf[..to_read]).map_err(|e| e.to_string())?;
        remaining -= to_read as u64;

        let arr: &mut [u8; SECTOR_SIZE] = buf.as_mut_slice().try_into().unwrap();
        engine.encrypt_sector(sector, arr);
        f.write_all(arr).map_err(|e| e.to_string())?;
        sector += 1;
    }

    Ok(n_sectors)
}

#[inline]
fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) / align * align
}

// ─── public API ──────────────────────────────────────────────────────────────

/// Create an empty container of `size` bytes (data region).
pub fn create_container(
    path: &str,
    size: u64,
    algo: Algorithm,
    passphrase: &[u8],
    kdf_iters: u32,
    verbose: bool,
) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("create {}: {}", path, e))?;

    write_container_header(&mut f, size, algo, passphrase, kdf_iters)?;

    // Write zero-filled, XTS-encrypted data region
    let zero = vec![0u8; SECTOR_SIZE];
    let n_sectors = align_up(size, SECTOR_SIZE as u64) / SECTOR_SIZE as u64;
    // Re-open the engine from the header we just wrote
    drop(f);
    let (hdr, engine, mut f2) = open(path, passphrase)?;
    let _ = &hdr;

    for s in 0..n_sectors {
        write_sector(&mut f2, &engine, s, zero.as_slice().try_into().unwrap())?;
        if verbose && s % 2048 == 0 {
            let pct = s * 100 / n_sectors.max(1);
            eprintln!("  create_container: {}%", pct);
        }
    }
    f2.flush().map_err(|e| e.to_string())?;
    if verbose {
        eprintln!("  create_container: done ({} bytes)", size);
    }
    Ok(())
}

/// Encrypt a single file into a new SATAN2CV container.
/// Returns the number of plaintext bytes written.
pub fn encrypt_file(
    src: &str,
    dst: &str,
    algo: Algorithm,
    passphrase: &[u8],
    kdf_iters: u32,
) -> Result<u64, String> {
    let src_meta = std::fs::metadata(src).map_err(|e| format!("stat {}: {}", src, e))?;
    let data_len = src_meta.len();
    let padded = align_up(data_len, SECTOR_SIZE as u64);

    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)
        .map_err(|e| format!("create {}: {}", dst, e))?;

    let (_hdr, engine) = write_container_header(&mut out, data_len, algo, passphrase, kdf_iters)?;

    let mut src_f = File::open(src).map_err(|e| format!("open {}: {}", src, e))?;
    stream_encrypt_to_file(&mut out, &engine, &mut src_f, data_len, 0)?;
    out.flush().map_err(|e| e.to_string())?;

    let _ = padded;
    Ok(data_len)
}

/// Encrypt an entire directory tree into a container using a simple inline tar format.
/// Format per file: [path_len: u16 LE][path: UTF-8][size: u64 LE][data: bytes]
/// Directory entries: path ends with '/', size = 0.
/// Terminates with path_len = 0.
pub fn encrypt_dir(
    src: &str,
    dst: &str,
    algo: Algorithm,
    passphrase: &[u8],
    kdf_iters: u32,
) -> Result<u64, String> {
    // First pass: collect all files and compute total stream size
    let mut entries: Vec<(String, u64)> = Vec::new(); // (relative_path, size)
    collect_dir(src, src, &mut entries)?;

    let mut stream_len: u64 = 0;
    for (path, size) in &entries {
        let pb = path.as_bytes();
        stream_len += 2 + pb.len() as u64 + 8 + *size;
    }
    stream_len += 2; // terminator

    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)
        .map_err(|e| format!("create {}: {}", dst, e))?;

    let (_hdr, engine) = write_container_header(&mut out, stream_len, algo, passphrase, kdf_iters)?;

    // Build a synthetic readable stream from the directory
    let mut pipe = DirStream::new(src, entries)?;
    stream_encrypt_to_file(&mut out, &engine, &mut pipe, stream_len, 0)?;
    out.flush().map_err(|e| e.to_string())?;

    Ok(stream_len)
}

/// Recursively collect (relative_path, file_size) for all entries under `base`.
fn collect_dir(base: &str, dir: &str, out: &mut Vec<(String, u64)>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("readdir {}: {}", dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let rel = path
            .strip_prefix(base)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();

        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if meta.is_dir() {
            // Directory entry
            out.push((format!("{}/", rel), 0));
            collect_dir(base, path.to_str().unwrap_or(dir), out)?;
        } else if meta.is_file() {
            out.push((rel, meta.len()));
        }
        // Ignore symlinks and other special files
    }
    Ok(())
}

/// A Read impl that sequences the inline-tar stream for a directory.
struct DirStream {
    base:     String,
    entries:  Vec<(String, u64)>,
    idx:      usize,
    state:    DirStreamState,
    cur_file: Option<File>,
    cur_rem:  u64,
}

enum DirStreamState {
    Header(Vec<u8>, usize), // pending header bytes + position
    Data,
    Terminator([u8; 2], usize),
    Done,
}

impl DirStream {
    fn new(base: &str, entries: Vec<(String, u64)>) -> Result<Self, String> {
        Ok(DirStream {
            base:     base.to_string(),
            entries,
            idx:      0,
            state:    DirStreamState::Header(Vec::new(), 0),
            cur_file: None,
            cur_rem:  0,
        })
    }
}

impl Read for DirStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match &mut self.state {
                DirStreamState::Header(ref hdr_bytes, ref mut pos) => {
                    if hdr_bytes.is_empty() {
                        // Build next header
                        if self.idx >= self.entries.len() {
                            // Write terminator
                            self.state = DirStreamState::Terminator([0u8; 2], 0);
                            continue;
                        }
                        let (path, size) = &self.entries[self.idx];
                        let pb = path.as_bytes();
                        let mut h = Vec::with_capacity(2 + pb.len() + 8);
                        h.extend_from_slice(&(pb.len() as u16).to_le_bytes());
                        h.extend_from_slice(pb);
                        h.extend_from_slice(&size.to_le_bytes());
                        self.cur_rem = *size;
                        if *size > 0 {
                            let full_path = format!("{}/{}", self.base, path);
                            self.cur_file = Some(
                                File::open(&full_path)
                                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
                            );
                        } else {
                            self.cur_file = None;
                        }
                        self.idx += 1;
                        *pos = 0;
                        *self = DirStream {
                            base: self.base.clone(),
                            entries: std::mem::take(&mut self.entries),
                            idx: self.idx,
                            state: DirStreamState::Header(h, 0),
                            cur_file: self.cur_file.take(),
                            cur_rem: self.cur_rem,
                        };
                        continue;
                    }

                    let avail = hdr_bytes.len() - *pos;
                    let n = avail.min(buf.len());
                    buf[..n].copy_from_slice(&hdr_bytes[*pos..*pos + n]);
                    *pos += n;
                    if *pos >= hdr_bytes.len() {
                        // Transition to data state
                        self.state = DirStreamState::Data;
                    }
                    return Ok(n);
                }
                DirStreamState::Data => {
                    if self.cur_rem == 0 {
                        // Start next entry header
                        self.state = DirStreamState::Header(Vec::new(), 0);
                        continue;
                    }
                    if let Some(ref mut f) = self.cur_file {
                        let to_read = (self.cur_rem as usize).min(buf.len());
                        let n = f.read(&mut buf[..to_read])?;
                        if n == 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "file shorter than expected",
                            ));
                        }
                        self.cur_rem -= n as u64;
                        return Ok(n);
                    } else {
                        self.state = DirStreamState::Header(Vec::new(), 0);
                        continue;
                    }
                }
                DirStreamState::Terminator(ref term, ref mut pos) => {
                    let avail = 2 - *pos;
                    let n = avail.min(buf.len());
                    buf[..n].copy_from_slice(&term[*pos..*pos + n]);
                    *pos += n;
                    if *pos >= 2 {
                        self.state = DirStreamState::Done;
                    }
                    return Ok(n);
                }
                DirStreamState::Done => return Ok(0),
            }
        }
    }
}

/// Decrypt a container back to a flat file.
/// Returns the number of plaintext bytes written.
pub fn decrypt_container(src: &str, dst: &str, passphrase: &[u8]) -> Result<u64, String> {
    let (hdr, engine, mut f) = open(src, passphrase)?;
    let data_len = hdr.volume_size;
    let n_sectors = align_up(data_len, SECTOR_SIZE as u64) / SECTOR_SIZE as u64;

    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)
        .map_err(|e| format!("create {}: {}", dst, e))?;

    let mut buf = [0u8; SECTOR_SIZE];
    let mut written = 0u64;

    for sector in 0..n_sectors {
        let offset = DATA_OFFSET + sector * SECTOR_SIZE as u64;
        f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
        f.read_exact(&mut buf).map_err(|e| e.to_string())?;
        engine.decrypt_sector(sector, &mut buf);

        let to_write = (data_len - written).min(SECTOR_SIZE as u64) as usize;
        out.write_all(&buf[..to_write]).map_err(|e| e.to_string())?;
        written += to_write as u64;
    }

    out.flush().map_err(|e| e.to_string())?;
    Ok(written)
}

/// Encrypt a block device in-place (Linux only).
/// Reads the device in 1 MB chunks, encrypts sector by sector, writes back.
/// The SATAN2CV header is written at the very beginning (first 4608 bytes).
#[cfg(unix)]
pub fn encrypt_device(
    dev: &str,
    algo: Algorithm,
    passphrase: &[u8],
    kdf_iters: u32,
    verbose: bool,
) -> Result<(), String> {
    use libc::{O_DIRECT, O_RDWR};
    use std::os::unix::fs::OpenOptionsExt;

    // Open with O_DIRECT for aligned I/O on raw block devices
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(O_RDWR | O_DIRECT)
        .open(dev)
        .map_err(|e| format!("open {}: {}", dev, e))?;

    // Detect device size via seek-to-end
    let dev_size = f.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;

    if dev_size <= DATA_OFFSET {
        return Err(format!("device too small: {} bytes", dev_size));
    }

    let data_size = dev_size - DATA_OFFSET;

    // Read existing data after the header region, encrypt, write back
    // First, build the header in memory
    use zeroize::Zeroizing;
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    let km = derive_keys(passphrase, &salt, kdf_iters);
    let (hk1, hk2, _dk1, _dk2, _ck1, _ck2) = split_keys(&km);
    let mut master_key  = Zeroizing::new([0u8; 64]);
    let mut cascade_key = Zeroizing::new([0u8; 64]);
    fill_random(master_key.as_mut())?;
    fill_random(cascade_key.as_mut())?;

    let hdr = CvHeader {
        algo,
        kdf_iters,
        volume_size: data_size,
        master_key:  *master_key,
        cascade_key: *cascade_key,
    };
    let engine = Engine::from_keys(algo, &hdr.master_key, &hdr.cascade_key);

    let mut hdr_buf = hdr.serialize();
    let xts_hdr: Xts<Aes256Cipher> = Xts {
        data_cipher:  Aes256Cipher::new(hk1),
        tweak_cipher: Aes256Cipher::new(hk2),
    };
    xts_hdr.encrypt_sector(0, &mut hdr_buf);

    // Chunk size: 1 MB aligned to SECTOR_SIZE
    const CHUNK_SECTORS: usize = 2048; // 1 MB
    const CHUNK_SIZE: usize = CHUNK_SECTORS * SECTOR_SIZE;

    let n_sectors = data_size / SECTOR_SIZE as u64;
    let mut sector = 0u64;

    // Allocate aligned buffer (O_DIRECT requires 512-byte alignment)
    // Use Vec with explicit capacity so it is heap-allocated aligned to at least 8 bytes.
    // For O_DIRECT the kernel needs 512-byte alignment; we over-allocate and align manually.
    let mut raw_buf = vec![0u8; CHUNK_SIZE + 4096];
    let align_offset = {
        let ptr = raw_buf.as_ptr() as usize;
        (512 - (ptr % 512)) % 512
    };
    let chunk_buf = &mut raw_buf[align_offset..align_offset + CHUNK_SIZE];

    while sector < n_sectors {
        let this_chunk = (n_sectors - sector).min(CHUNK_SECTORS as u64) as usize;
        let this_bytes = this_chunk * SECTOR_SIZE;

        let file_offset = DATA_OFFSET + sector * SECTOR_SIZE as u64;
        f.seek(SeekFrom::Start(file_offset)).map_err(|e| e.to_string())?;
        f.read_exact(&mut chunk_buf[..this_bytes]).map_err(|e| e.to_string())?;

        for i in 0..this_chunk {
            let slice = &mut chunk_buf[i * SECTOR_SIZE..(i + 1) * SECTOR_SIZE];
            engine.encrypt_sector(sector + i as u64, slice);
        }

        f.seek(SeekFrom::Start(file_offset)).map_err(|e| e.to_string())?;
        f.write_all(&chunk_buf[..this_bytes]).map_err(|e| e.to_string())?;

        sector += this_chunk as u64;

        if verbose && sector % (n_sectors / 20).max(1) == 0 {
            eprintln!("  encrypt_device: {}%", sector * 100 / n_sectors);
        }
    }

    // Finally write the header (overwrites the first 4608 bytes)
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    f.write_all(&salt).map_err(|e| e.to_string())?;
    f.write_all(&hdr_buf).map_err(|e| e.to_string())?;
    f.flush().map_err(|e| e.to_string())?;

    if verbose {
        eprintln!("  encrypt_device: done");
    }
    Ok(())
}

/// Wipe `path` with random bytes, then truncate and remove.
fn wipe_file(path: &str) -> Result<(), String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let size = meta.len() as usize;

    if size > 0 {
        let mut f = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| format!("wipe open {}: {}", path, e))?;

        // Three passes: random, zeros, random
        let mut chunk = vec![0u8; 65536.min(size)];
        for pass in 0..3u32 {
            f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut remaining = size;
            while remaining > 0 {
                let n = remaining.min(chunk.len());
                if pass % 2 == 0 {
                    fill_random(&mut chunk[..n])?;
                } else {
                    chunk[..n].fill(0);
                }
                f.write_all(&chunk[..n]).map_err(|e| e.to_string())?;
                remaining -= n;
            }
            f.flush().map_err(|e| e.to_string())?;
        }
    }

    std::fs::remove_file(path).map_err(|e| format!("remove {}: {}", path, e))?;
    Ok(())
}

/// Encrypt a list of files/directories into a single container, then securely wipe the sources.
pub fn destroy_and_encrypt(
    src_paths: &[&str],
    dst_container: &str,
    algo: Algorithm,
    passphrase: &[u8],
    kdf_iters: u32,
) -> Result<u64, String> {
    // Step 1: compute total stream size (inline-tar format for all sources)
    let mut all_entries: Vec<(String, u64)> = Vec::new();
    for &src in src_paths {
        let meta = std::fs::metadata(src).map_err(|e| format!("stat {}: {}", src, e))?;
        if meta.is_file() {
            // Use the basename as the path
            let name = std::path::Path::new(src)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| src.to_string());
            all_entries.push((name, meta.len()));
        } else if meta.is_dir() {
            // Prefix all paths with the directory name
            let dirname = std::path::Path::new(src)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| src.to_string());
            let before = all_entries.len();
            collect_dir(src, src, &mut all_entries)?;
            // Prepend dirname to each new entry
            for e in &mut all_entries[before..] {
                e.0 = format!("{}/{}", dirname, e.0);
            }
        }
    }

    let mut stream_len: u64 = 0;
    for (path, size) in &all_entries {
        stream_len += 2 + path.len() as u64 + 8 + *size;
    }
    stream_len += 2; // terminator

    // Step 2: build container
    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst_container)
        .map_err(|e| format!("create {}: {}", dst_container, e))?;

    // Resolve actual base dirs per source path for DirStream
    // Since all_entries are already (rel_path, size), we need a combined stream.
    // Use a simple flat approach: re-derive the base per entry.
    let (_hdr, engine) =
        write_container_header(&mut out, stream_len, algo, passphrase, kdf_iters)?;

    // Build a unified stream using a combined base of "/"
    // Actually entries already have their full paths built. We need the real FS paths.
    // Rebuild entries with FS paths for reading.
    let mut fs_entries: Vec<(String, String, u64)> = Vec::new(); // (stream_path, fs_path, size)
    for &src in src_paths {
        let meta = std::fs::metadata(src).map_err(|e| e.to_string())?;
        if meta.is_file() {
            let name = std::path::Path::new(src)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| src.to_string());
            fs_entries.push((name, src.to_string(), meta.len()));
        } else if meta.is_dir() {
            let dirname = std::path::Path::new(src)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| src.to_string());
            collect_fs_entries(src, src, &dirname, &mut fs_entries)?;
        }
    }

    let mut pipe = FlatStream::new(fs_entries)?;
    stream_encrypt_to_file(&mut out, &engine, &mut pipe, stream_len, 0)?;
    out.flush().map_err(|e| e.to_string())?;

    // Step 3: wipe sources
    for &src in src_paths {
        let meta = std::fs::metadata(src).map_err(|e| e.to_string())?;
        if meta.is_file() {
            wipe_file(src)?;
        } else if meta.is_dir() {
            wipe_dir_recursive(src)?;
        }
    }

    Ok(stream_len)
}

/// Recursively collect (stream_path, fs_path, size) under `dir` with prefix `prefix`.
fn collect_fs_entries(
    base: &str,
    dir: &str,
    prefix: &str,
    out: &mut Vec<(String, String, u64)>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("readdir {}: {}", dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stream_path = format!("{}/{}", prefix, name);
        let fs_path = path.to_string_lossy().into_owned();
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if meta.is_dir() {
            out.push((format!("{}/", stream_path), fs_path.clone(), 0));
            collect_fs_entries(base, &fs_path, &stream_path, out)?;
        } else if meta.is_file() {
            out.push((stream_path, fs_path, meta.len()));
        }
    }
    Ok(())
}

/// Wipe all files in a directory recursively, then remove the directory.
fn wipe_dir_recursive(dir: &str) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        let p = path.to_str().unwrap_or("");
        if meta.is_dir() {
            wipe_dir_recursive(p)?;
        } else if meta.is_file() {
            wipe_file(p)?;
        }
    }
    std::fs::remove_dir(dir).map_err(|e| format!("rmdir {}: {}", dir, e))?;
    Ok(())
}

/// A Read impl that sequences a flat list of (stream_path, fs_path, size) as inline-tar.
struct FlatStream {
    entries:  Vec<(String, String, u64)>, // (stream_path, fs_path, size)
    idx:      usize,
    hdr_buf:  Vec<u8>,
    hdr_pos:  usize,
    cur_file: Option<File>,
    cur_rem:  u64,
    done:     bool,
    term_pos: usize,
}

impl FlatStream {
    fn new(entries: Vec<(String, String, u64)>) -> Result<Self, String> {
        Ok(FlatStream {
            entries,
            idx:      0,
            hdr_buf:  Vec::new(),
            hdr_pos:  0,
            cur_file: None,
            cur_rem:  0,
            done:     false,
            term_pos: 0,
        })
    }

    fn load_next_header(&mut self) -> std::io::Result<bool> {
        if self.idx >= self.entries.len() {
            return Ok(false);
        }
        let (stream_path, fs_path, size) = &self.entries[self.idx];
        let pb = stream_path.as_bytes();
        let mut h = Vec::with_capacity(2 + pb.len() + 8);
        h.extend_from_slice(&(pb.len() as u16).to_le_bytes());
        h.extend_from_slice(pb);
        h.extend_from_slice(&size.to_le_bytes());
        self.hdr_buf = h;
        self.hdr_pos = 0;
        self.cur_rem = *size;
        if *size > 0 {
            self.cur_file = Some(
                File::open(fs_path)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?,
            );
        } else {
            self.cur_file = None;
        }
        self.idx += 1;
        Ok(true)
    }
}

impl Read for FlatStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }

        loop {
            // Emit header bytes first
            if self.hdr_pos < self.hdr_buf.len() {
                let avail = self.hdr_buf.len() - self.hdr_pos;
                let n = avail.min(buf.len());
                buf[..n].copy_from_slice(&self.hdr_buf[self.hdr_pos..self.hdr_pos + n]);
                self.hdr_pos += n;
                return Ok(n);
            }

            // Emit file data
            if self.cur_rem > 0 {
                if let Some(ref mut f) = self.cur_file {
                    let to_read = (self.cur_rem as usize).min(buf.len());
                    let n = f.read(&mut buf[..to_read])?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "truncated file",
                        ));
                    }
                    self.cur_rem -= n as u64;
                    return Ok(n);
                }
            }

            // Load next entry
            if !self.load_next_header()? {
                // Write terminator
                let term = [0u8; 2];
                let n = (2 - self.term_pos).min(buf.len());
                buf[..n].copy_from_slice(&term[self.term_pos..self.term_pos + n]);
                self.term_pos += n;
                if self.term_pos >= 2 {
                    self.done = true;
                }
                return Ok(n);
            }
        }
    }
}

