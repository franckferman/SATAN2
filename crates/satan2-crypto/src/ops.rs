// High-level operations: encrypt files, directories, devices, containers, secure wipe.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::algo::Engine;
use crate::container::{fill_random, generate_salt, open, write_sector, SECTOR_SIZE};
use crate::header::{AlgoId, CvHeader, DATA_OFFSET};
use crate::kdf::{derive_keys, split_keys};
use crate::xts::{Aes256Cipher, Xts};

pub use crate::header::AlgoId as Algorithm;

/// One layer of a nested (containers-inside-containers) encryption.
/// The passphrase is zeroized on drop.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Layer {
    pub algo: Algorithm,
    pub passphrase: Vec<u8>,
}

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

    let salt = generate_salt(kdf_iters)?;

    let km = derive_keys(passphrase, &salt, kdf_iters);
    let (hk1, hk2, _dk1, _dk2, _ck1, _ck2) = split_keys(&km);

    let mut master_key = Zeroizing::new([0u8; 64]);
    let mut cascade_key = Zeroizing::new([0u8; 64]);
    fill_random(master_key.as_mut())?;
    fill_random(cascade_key.as_mut())?;

    let hdr = CvHeader {
        algo,
        kdf_iters,
        volume_size: data_size,
        master_key: *master_key,
        cascade_key: *cascade_key,
    };

    let engine = Engine::from_keys(algo, &hdr.master_key, &hdr.cascade_key);

    let mut hdr_buf = hdr.serialize();
    let xts: Xts<Aes256Cipher> = Xts {
        data_cipher: Aes256Cipher::new(hk1),
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
        data.read_exact(&mut buf[..to_read])
            .map_err(|e| e.to_string())?;
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
    v.div_ceil(align) * align
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

    // Write zero-filled, XTS-encrypted data region.
    // Reuse the engine + write handle from the header write: the File returned
    // by open() is read-only, so re-opening it for sector writes would fail.
    let (_hdr, engine) = write_container_header(&mut f, size, algo, passphrase, kdf_iters)?;
    let zero = vec![0u8; SECTOR_SIZE];
    let n_sectors = align_up(size, SECTOR_SIZE as u64) / SECTOR_SIZE as u64;

    for s in 0..n_sectors {
        write_sector(&mut f, &engine, s, zero.as_slice().try_into().unwrap())?;
        if verbose && s % 2048 == 0 {
            let pct = s * 100 / n_sectors.max(1);
            eprintln!("  create_container: {}%", pct);
        }
    }
    f.flush().map_err(|e| e.to_string())?;
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
    base: String,
    entries: Vec<(String, u64)>,
    idx: usize,
    state: DirStreamState,
    cur_file: Option<File>,
    cur_rem: u64,
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
            base: base.to_string(),
            entries,
            idx: 0,
            state: DirStreamState::Header(Vec::new(), 0),
            cur_file: None,
            cur_rem: 0,
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
                            self.cur_file =
                                Some(File::open(&full_path).map_err(std::io::Error::other)?);
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
    decrypt_container_impl(src, dst, passphrase, None)
}

/// Shared decrypt implementation. When `expect_algo` is given, the algorithm
/// recorded in the decrypted header must match — used by `decrypt_layers` to
/// catch wrong layer order with a clear error.
fn decrypt_container_impl(
    src: &str,
    dst: &str,
    passphrase: &[u8],
    expect_algo: Option<AlgoId>,
) -> Result<u64, String> {
    let (hdr, engine, mut f) = open(src, passphrase)?;
    if let Some(algo) = expect_algo {
        if hdr.algo != algo {
            return Err(format!(
                "{}: layer algorithm mismatch — container is {:?}, expected {:?} \
                 (wrong layer order or algorithm)",
                src, hdr.algo, algo
            ));
        }
    }
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

// ─── nested multi-layer encryption ───────────────────────────────────────────
//
// Nesting is honest and simple: each layer is a full, standalone SATAN2CV
// container. Layer 1 (innermost) encrypts the source file; layer 2 encrypts
// the layer-1 container file; and so on. Decrypting the outer layer therefore
// yields the inner container file — this composes naturally with the existing
// format because a container is just a file. Every layer has its own
// algorithm, salt, master keys and passphrase. Supported targets: files only
// (directory/device sources would need a different final unpack step on the
// decrypt side).

/// Path for an intermediate layer container inside the system temp dir.
/// Intermediate files always hold fully-encrypted containers (never
/// plaintext) and are removed as soon as the next layer is written.
fn temp_layer_path(idx: usize) -> std::path::PathBuf {
    let mut rnd = [0u8; 8];
    let suffix = match fill_random(&mut rnd) {
        Ok(()) => rnd.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        Err(_) => "fallback".to_string(),
    };
    std::env::temp_dir().join(format!(
        "satan2-layer-{}-{}-{}.cv",
        std::process::id(),
        idx,
        suffix
    ))
}

/// Encrypt a file with multiple nested layers.
/// `layers[0]` is the innermost layer (applied to `src` first); the last
/// entry is the outermost layer, whose container lands in `dst`.
/// Returns the size of the original plaintext in bytes.
pub fn encrypt_layers(
    src: &str,
    dst: &str,
    layers: &[Layer],
    kdf_iters: u32,
) -> Result<u64, String> {
    if layers.is_empty() {
        return Err("encrypt_layers: at least one layer is required".into());
    }

    let mut tmp_paths: Vec<std::path::PathBuf> = Vec::new();
    let result = (|| {
        let mut cur_src = src.to_string();
        for (i, layer) in layers.iter().enumerate() {
            let out = if i == layers.len() - 1 {
                dst.to_string()
            } else {
                let t = temp_layer_path(i);
                tmp_paths.push(t.clone());
                t.to_string_lossy().into_owned()
            };
            encrypt_file(&cur_src, &out, layer.algo, &layer.passphrase, kdf_iters)
                .map_err(|e| format!("layer {} ({:?}): {}", i + 1, layer.algo, e))?;
            cur_src = out;
        }
        std::fs::metadata(src)
            .map(|m| m.len())
            .map_err(|e| format!("stat {}: {}", src, e))
    })();

    for t in &tmp_paths {
        std::fs::remove_file(t).ok();
    }
    result
}

/// Decrypt a file produced by `encrypt_layers`.
/// `layers` must be given in the same order as for encryption (innermost
/// first); decryption walks them in reverse, peeling the outermost layer
/// first. Each layer's algorithm is verified against the decrypted header,
/// so a wrong layer order fails with a clear error. Returns the size of the
/// recovered plaintext in bytes.
pub fn decrypt_layers(src: &str, dst: &str, layers: &[Layer]) -> Result<u64, String> {
    if layers.is_empty() {
        return Err("decrypt_layers: at least one layer is required".into());
    }

    let mut tmp_paths: Vec<std::path::PathBuf> = Vec::new();
    let result = (|| {
        let mut cur_src = src.to_string();
        let mut written = 0u64;
        for (i, layer) in layers.iter().enumerate().rev() {
            let out = if i == 0 {
                dst.to_string()
            } else {
                let t = temp_layer_path(i);
                tmp_paths.push(t.clone());
                t.to_string_lossy().into_owned()
            };
            written = decrypt_container_impl(&cur_src, &out, &layer.passphrase, Some(layer.algo))
                .map_err(|e| format!("layer {} ({:?}): {}", i + 1, layer.algo, e))?;
            cur_src = out;
        }
        Ok(written)
    })();

    for t in &tmp_paths {
        std::fs::remove_file(t).ok();
    }
    result
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
    let salt = generate_salt(kdf_iters)?;
    let km = derive_keys(passphrase, &salt, kdf_iters);
    let (hk1, hk2, _dk1, _dk2, _ck1, _ck2) = split_keys(&km);
    let mut master_key = Zeroizing::new([0u8; 64]);
    let mut cascade_key = Zeroizing::new([0u8; 64]);
    fill_random(master_key.as_mut())?;
    fill_random(cascade_key.as_mut())?;

    let hdr = CvHeader {
        algo,
        kdf_iters,
        volume_size: data_size,
        master_key: *master_key,
        cascade_key: *cascade_key,
    };
    let engine = Engine::from_keys(algo, &hdr.master_key, &hdr.cascade_key);

    let mut hdr_buf = hdr.serialize();
    let xts_hdr: Xts<Aes256Cipher> = Xts {
        data_cipher: Aes256Cipher::new(hk1),
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
        f.seek(SeekFrom::Start(file_offset))
            .map_err(|e| e.to_string())?;
        f.read_exact(&mut chunk_buf[..this_bytes])
            .map_err(|e| e.to_string())?;

        for i in 0..this_chunk {
            let slice = &mut chunk_buf[i * SECTOR_SIZE..(i + 1) * SECTOR_SIZE];
            engine.encrypt_sector(sector + i as u64, slice);
        }

        f.seek(SeekFrom::Start(file_offset))
            .map_err(|e| e.to_string())?;
        f.write_all(&chunk_buf[..this_bytes])
            .map_err(|e| e.to_string())?;

        sector += this_chunk as u64;

        if verbose && sector.is_multiple_of((n_sectors / 20).max(1)) {
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
    let (_hdr, engine) = write_container_header(&mut out, stream_len, algo, passphrase, kdf_iters)?;

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
#[allow(clippy::only_used_in_recursion)] // `base` is part of the recursive walk contract
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
    entries: Vec<(String, String, u64)>, // (stream_path, fs_path, size)
    idx: usize,
    hdr_buf: Vec<u8>,
    hdr_pos: usize,
    cur_file: Option<File>,
    cur_rem: u64,
    done: bool,
    term_pos: usize,
}

impl FlatStream {
    fn new(entries: Vec<(String, String, u64)>) -> Result<Self, String> {
        Ok(FlatStream {
            entries,
            idx: 0,
            hdr_buf: Vec::new(),
            hdr_pos: 0,
            cur_file: None,
            cur_rem: 0,
            done: false,
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
            self.cur_file =
                Some(File::open(fs_path).map_err(|e| std::io::Error::other(e.to_string()))?);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::read_sector;
    use crate::extract::extract_dir;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "satan2-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const ALL_ALGOS: [Algorithm; 5] = [
        AlgoId::Aes256,
        AlgoId::Twofish256,
        AlgoId::Camellia256,
        AlgoId::AesTwofish,
        AlgoId::Kuznyechik,
    ];

    const ITERS: u32 = 1000; // low for test speed; also exercises non-default iters
    const PASS: &[u8] = b"correct horse battery staple";

    fn pseudo_random(len: usize, seed: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        let mut s = seed;
        while v.len() < len {
            s = s.wrapping_mul(167).wrapping_add(61);
            v.push(s);
        }
        v
    }

    /// encrypt_file → decrypt_container must reproduce the input for every algorithm.
    #[test]
    fn file_roundtrip_all_algos() {
        let dir = tmpdir("ops-file-roundtrip");
        let data = pseudo_random(10_003, 7); // odd size, spans 20 sectors
        let src = dir.join("plain.bin");
        std::fs::write(&src, &data).unwrap();

        for algo in ALL_ALGOS {
            let cv = dir.join(format!("{:?}.cv", algo));
            let out = dir.join(format!("{:?}.out", algo));
            let n = encrypt_file(
                src.to_str().unwrap(),
                cv.to_str().unwrap(),
                algo,
                PASS,
                ITERS,
            )
            .unwrap_or_else(|e| panic!("encrypt_file {:?}: {}", algo, e));
            assert_eq!(n, data.len() as u64);

            let m = decrypt_container(cv.to_str().unwrap(), out.to_str().unwrap(), PASS)
                .unwrap_or_else(|e| panic!("decrypt_container {:?}: {}", algo, e));
            assert_eq!(m, data.len() as u64);
            assert_eq!(
                std::fs::read(&out).unwrap(),
                data,
                "roundtrip mismatch for {:?}",
                algo
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Edge sizes: empty file, 1 byte, exactly one sector.
    #[test]
    fn file_roundtrip_edge_sizes() {
        let dir = tmpdir("ops-file-edges");
        for len in [0usize, 1, 512] {
            let data = pseudo_random(len, 3);
            let src = dir.join(format!("in-{}", len));
            let cv = dir.join(format!("c-{}.cv", len));
            let out = dir.join(format!("out-{}", len));
            std::fs::write(&src, &data).unwrap();
            encrypt_file(
                src.to_str().unwrap(),
                cv.to_str().unwrap(),
                AlgoId::Aes256,
                PASS,
                ITERS,
            )
            .unwrap();
            decrypt_container(cv.to_str().unwrap(), out.to_str().unwrap(), PASS).unwrap();
            assert_eq!(std::fs::read(&out).unwrap(), data, "size {} mismatch", len);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let dir = tmpdir("ops-wrongpass");
        let src = dir.join("plain.bin");
        let cv = dir.join("c.cv");
        let out = dir.join("out.bin");
        std::fs::write(&src, b"secret data").unwrap();
        encrypt_file(
            src.to_str().unwrap(),
            cv.to_str().unwrap(),
            AlgoId::Aes256,
            PASS,
            ITERS,
        )
        .unwrap();
        assert!(decrypt_container(cv.to_str().unwrap(), out.to_str().unwrap(), b"WRONG").is_err());
        assert!(extract_dir(
            cv.to_str().unwrap(),
            dir.join("x").to_str().unwrap(),
            b"WRONG"
        )
        .is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// XTS has no MAC: a flipped ciphertext byte must change the decrypted output.
    #[test]
    fn tamper_changes_decrypted_output() {
        let dir = tmpdir("ops-tamper");
        let data = pseudo_random(2048, 11);
        let src = dir.join("plain.bin");
        let cv = dir.join("c.cv");
        let out = dir.join("out.bin");
        std::fs::write(&src, &data).unwrap();
        encrypt_file(
            src.to_str().unwrap(),
            cv.to_str().unwrap(),
            AlgoId::Aes256,
            PASS,
            ITERS,
        )
        .unwrap();

        let mut raw = std::fs::read(&cv).unwrap();
        raw[DATA_OFFSET as usize + 100] ^= 0x01;
        std::fs::write(&cv, &raw).unwrap();

        decrypt_container(cv.to_str().unwrap(), out.to_str().unwrap(), PASS).unwrap();
        assert_ne!(
            std::fs::read(&out).unwrap(),
            data,
            "tampered container decrypted to the original plaintext"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Build a small nested tree: a.txt, sub/b.txt, sub/deep/c.txt
    fn build_tree(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let files = vec![
            ("a.txt".to_string(), b"alpha".to_vec()),
            ("sub/b.txt".to_string(), pseudo_random(1500, 5)),
            ("sub/deep/c.txt".to_string(), pseudo_random(42, 9)),
        ];
        std::fs::create_dir_all(root.join("sub/deep")).unwrap();
        for (rel, content) in &files {
            std::fs::write(root.join(rel), content).unwrap();
        }
        files
    }

    /// encrypt_dir → extract_dir must preserve relative paths and contents.
    #[test]
    fn dir_roundtrip_all_algos() {
        let dir = tmpdir("ops-dir-roundtrip");
        let src_tree = dir.join("tree");
        std::fs::create_dir_all(&src_tree).unwrap();
        let files = build_tree(&src_tree);

        for algo in ALL_ALGOS {
            let cv = dir.join(format!("{:?}.cv", algo));
            let dst = dir.join(format!("out-{:?}", algo));
            encrypt_dir(
                src_tree.to_str().unwrap(),
                cv.to_str().unwrap(),
                algo,
                PASS,
                ITERS,
            )
            .unwrap_or_else(|e| panic!("encrypt_dir {:?}: {}", algo, e));

            extract_dir(cv.to_str().unwrap(), dst.to_str().unwrap(), PASS)
                .unwrap_or_else(|e| panic!("extract_dir {:?}: {}", algo, e));

            for (rel, content) in &files {
                let extracted = std::fs::read(dst.join(rel))
                    .unwrap_or_else(|e| panic!("{:?}: read {}: {}", algo, rel, e));
                assert_eq!(
                    &extracted, content,
                    "{:?}: content mismatch for {}",
                    algo, rel
                );
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// create_container must produce a valid container whose data region
    /// decrypts to zeros (this also guards the read-only-handle regression).
    #[test]
    fn create_container_zeroed_region() {
        let dir = tmpdir("ops-create-container");
        let cv = dir.join("c.cv");
        let ps = cv.to_str().unwrap();
        create_container(ps, 4096, AlgoId::Aes256, PASS, ITERS, false).unwrap();

        let (hdr, engine, mut f) = open(ps, PASS).unwrap();
        assert_eq!(hdr.volume_size, 4096);
        assert_eq!(hdr.kdf_iters, ITERS);
        let mut buf = [1u8; SECTOR_SIZE];
        for sector in 0..8 {
            read_sector(&mut f, &engine, sector, &mut buf).unwrap();
            assert_eq!(buf, [0u8; SECTOR_SIZE], "sector {} not zeroed", sector);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// destroy_and_encrypt: sources are wiped after archiving; container extracts cleanly.
    #[test]
    fn destroy_and_encrypt_roundtrip_and_wipe() {
        let dir = tmpdir("ops-destroy");
        let file_src = dir.join("single.txt");
        std::fs::write(&file_src, b"gone soon").unwrap();
        let tree = dir.join("mydir");
        std::fs::create_dir_all(&tree).unwrap();
        let files = build_tree(&tree);

        let cv = dir.join("vault.cv");
        let srcs = [file_src.to_str().unwrap(), tree.to_str().unwrap()];
        destroy_and_encrypt(&srcs, cv.to_str().unwrap(), AlgoId::Aes256, PASS, ITERS).unwrap();

        // Sources wiped
        assert!(!file_src.exists(), "source file not wiped");
        assert!(!tree.exists(), "source dir not wiped");

        // Extract and verify (paths are prefixed with the basename)
        let dst = dir.join("extracted");
        extract_dir(cv.to_str().unwrap(), dst.to_str().unwrap(), PASS).unwrap();
        assert_eq!(std::fs::read(dst.join("single.txt")).unwrap(), b"gone soon");
        for (rel, content) in &files {
            let extracted = std::fs::read(dst.join("mydir").join(rel)).unwrap();
            assert_eq!(&extracted, content, "content mismatch for {}", rel);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── nested multi-layer encryption ────────────────────────────────────────

    fn layer(algo: Algorithm, pass: &[u8]) -> Layer {
        Layer {
            algo,
            passphrase: pass.to_vec(),
        }
    }

    const PASS1: &[u8] = b"inner layer passphrase";
    const PASS2: &[u8] = b"middle layer passphrase";
    const PASS3: &[u8] = b"outer layer passphrase";

    /// 2-layer roundtrip with different algorithms and passphrases per layer.
    #[test]
    fn layers_two_roundtrip_different_algos() {
        let dir = tmpdir("ops-layers-2");
        let data = pseudo_random(5001, 13);
        let src = dir.join("plain.bin");
        let cv = dir.join("nested.cv");
        let out = dir.join("out.bin");
        std::fs::write(&src, &data).unwrap();

        let layers = [
            layer(AlgoId::Aes256, PASS1),
            layer(AlgoId::Twofish256, PASS2),
        ];
        let n =
            encrypt_layers(src.to_str().unwrap(), cv.to_str().unwrap(), &layers, ITERS).unwrap();
        assert_eq!(n, data.len() as u64);

        // The outer container must decrypt (with the outer passphrase) to a
        // valid inner container — this proves containers nest naturally.
        let inner = dir.join("inner.cv");
        decrypt_container(cv.to_str().unwrap(), inner.to_str().unwrap(), PASS2).unwrap();
        let (hdr, _e, _f) = open(inner.to_str().unwrap(), PASS1).unwrap();
        assert_eq!(hdr.algo, AlgoId::Aes256);
        assert_eq!(hdr.volume_size, data.len() as u64);

        let layers = [
            layer(AlgoId::Aes256, PASS1),
            layer(AlgoId::Twofish256, PASS2),
        ];
        let m = decrypt_layers(cv.to_str().unwrap(), out.to_str().unwrap(), &layers).unwrap();
        assert_eq!(m, data.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), data);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 3-layer roundtrip, three different algorithms and passphrases.
    #[test]
    fn layers_three_roundtrip_different_algos() {
        let dir = tmpdir("ops-layers-3");
        let data = pseudo_random(12_345, 21);
        let src = dir.join("plain.bin");
        let cv = dir.join("nested.cv");
        let out = dir.join("out.bin");
        std::fs::write(&src, &data).unwrap();

        let mk = || {
            [
                layer(AlgoId::Camellia256, PASS1),
                layer(AlgoId::Kuznyechik, PASS2),
                layer(AlgoId::AesTwofish, PASS3),
            ]
        };
        encrypt_layers(src.to_str().unwrap(), cv.to_str().unwrap(), &mk(), ITERS).unwrap();

        // Peel the outer layer manually: it must yield a valid 2-layer container.
        let mid = dir.join("mid.cv");
        decrypt_container(cv.to_str().unwrap(), mid.to_str().unwrap(), PASS3).unwrap();
        let (hdr, _e, _f) = open(mid.to_str().unwrap(), PASS2).unwrap();
        assert_eq!(hdr.algo, AlgoId::Kuznyechik);

        let m = decrypt_layers(cv.to_str().unwrap(), out.to_str().unwrap(), &mk()).unwrap();
        assert_eq!(m, data.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), data);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Layers supplied in the wrong order must fail decryption.
    #[test]
    fn layers_wrong_order_fails() {
        let dir = tmpdir("ops-layers-order");
        let src = dir.join("plain.bin");
        let cv = dir.join("nested.cv");
        let out = dir.join("out.bin");
        std::fs::write(&src, b"order matters").unwrap();

        let layers = [
            layer(AlgoId::Aes256, PASS1),
            layer(AlgoId::Twofish256, PASS2),
        ];
        encrypt_layers(src.to_str().unwrap(), cv.to_str().unwrap(), &layers, ITERS).unwrap();

        // Swapped layer order: outer layer tried with the inner passphrase.
        let swapped = [
            layer(AlgoId::Twofish256, PASS2),
            layer(AlgoId::Aes256, PASS1),
        ];
        assert!(decrypt_layers(cv.to_str().unwrap(), out.to_str().unwrap(), &swapped).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A wrong passphrase on any layer (outer or inner) must fail decryption.
    #[test]
    fn layers_wrong_passphrase_any_layer_fails() {
        let dir = tmpdir("ops-layers-wrongpass");
        let src = dir.join("plain.bin");
        let cv = dir.join("nested.cv");
        std::fs::write(&src, b"secret").unwrap();

        let layers = [
            layer(AlgoId::Aes256, PASS1),
            layer(AlgoId::Camellia256, PASS2),
        ];
        encrypt_layers(src.to_str().unwrap(), cv.to_str().unwrap(), &layers, ITERS).unwrap();

        // Wrong outer passphrase.
        let bad_outer = [
            layer(AlgoId::Aes256, PASS1),
            layer(AlgoId::Camellia256, b"WRONG"),
        ];
        assert!(decrypt_layers(
            cv.to_str().unwrap(),
            dir.join("o1").to_str().unwrap(),
            &bad_outer
        )
        .is_err());

        // Correct outer, wrong inner passphrase.
        let bad_inner = [
            layer(AlgoId::Aes256, b"WRONG"),
            layer(AlgoId::Camellia256, PASS2),
        ];
        assert!(decrypt_layers(
            cv.to_str().unwrap(),
            dir.join("o2").to_str().unwrap(),
            &bad_inner
        )
        .is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Tampering with the outer layer's data region must be detected: the
    /// peeled "inner container" is garbage, so the inner open fails.
    #[test]
    fn layers_tamper_outer_detected() {
        let dir = tmpdir("ops-layers-tamper");
        let data = pseudo_random(4096, 31);
        let src = dir.join("plain.bin");
        let cv = dir.join("nested.cv");
        let out = dir.join("out.bin");
        std::fs::write(&src, &data).unwrap();

        let layers = [
            layer(AlgoId::Aes256, PASS1),
            layer(AlgoId::Twofish256, PASS2),
        ];
        encrypt_layers(src.to_str().unwrap(), cv.to_str().unwrap(), &layers, ITERS).unwrap();

        // Flip a byte in the outer data region — this lands inside the inner
        // container's salt/header area, so inner decryption must fail.
        let mut raw = std::fs::read(&cv).unwrap();
        raw[DATA_OFFSET as usize + 100] ^= 0x01;
        std::fs::write(&cv, &raw).unwrap();

        let layers = [
            layer(AlgoId::Aes256, PASS1),
            layer(AlgoId::Twofish256, PASS2),
        ];
        assert!(decrypt_layers(cv.to_str().unwrap(), out.to_str().unwrap(), &layers).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A single layer must behave exactly like encrypt_file/decrypt_container.
    #[test]
    fn layers_single_layer_roundtrip() {
        let dir = tmpdir("ops-layers-1");
        let data = pseudo_random(777, 41);
        let src = dir.join("plain.bin");
        let cv = dir.join("one.cv");
        let out = dir.join("out.bin");
        std::fs::write(&src, &data).unwrap();

        let layers = [layer(AlgoId::Kuznyechik, PASS1)];
        encrypt_layers(src.to_str().unwrap(), cv.to_str().unwrap(), &layers, ITERS).unwrap();
        decrypt_layers(cv.to_str().unwrap(), out.to_str().unwrap(), &layers).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), data);

        // And it is a plain container, openable with decrypt_container.
        decrypt_container(
            cv.to_str().unwrap(),
            dir.join("o2").to_str().unwrap(),
            PASS1,
        )
        .unwrap();
        assert_eq!(std::fs::read(dir.join("o2")).unwrap(), data);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Empty layer lists are rejected.
    #[test]
    fn layers_empty_rejected() {
        let dir = tmpdir("ops-layers-empty");
        let src = dir.join("plain.bin");
        std::fs::write(&src, b"x").unwrap();
        assert!(encrypt_layers(
            src.to_str().unwrap(),
            dir.join("c").to_str().unwrap(),
            &[],
            ITERS
        )
        .is_err());
        assert!(
            decrypt_layers(src.to_str().unwrap(), dir.join("o").to_str().unwrap(), &[]).is_err()
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
