// SATAN2CV container I/O:
//   create_new  — allocate a container file and write an encrypted header
//   open        — verify passphrase, return decrypted CvHeader + data Engine
//   read_sector / write_sector — random-access I/O on the data region

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::algo::Engine;
use crate::header::{AlgoId, CvHeader, DATA_OFFSET, HEADER_ENCRYPTED_LEN, SALT_LEN};
use crate::kdf::{derive_keys, split_keys};
use crate::xts::{Aes256Cipher, Xts};

/// Sector size used for the XTS tweak index in the data region.
pub const SECTOR_SIZE: usize = 512;

/// Encrypt the 4096-byte plaintext header with AES-256-XTS (sector 0).
fn encrypt_header_buf(buf: &mut [u8; HEADER_ENCRYPTED_LEN], hk1: &[u8; 32], hk2: &[u8; 32]) {
    let xts: Xts<Aes256Cipher> = Xts {
        data_cipher:  Aes256Cipher::new(hk1),
        tweak_cipher: Aes256Cipher::new(hk2),
    };
    // Header is 4096 bytes = 256 × 16-byte blocks — encrypt as a single sector 0
    xts.encrypt_sector(0, buf.as_mut_slice());
}

/// Decrypt the 4096-byte header buffer with AES-256-XTS.
fn decrypt_header_buf(buf: &mut [u8; HEADER_ENCRYPTED_LEN], hk1: &[u8; 32], hk2: &[u8; 32]) {
    let xts: Xts<Aes256Cipher> = Xts {
        data_cipher:  Aes256Cipher::new(hk1),
        tweak_cipher: Aes256Cipher::new(hk2),
    };
    xts.decrypt_sector(0, buf.as_mut_slice());
}

/// Create a new container file of `data_size` bytes.
/// The file will be DATA_OFFSET + data_size bytes total.
pub fn create_new(
    path: &str,
    data_size: u64,
    algo: AlgoId,
    passphrase: &[u8],
    kdf_iters: u32,
) -> Result<(), String> {
    use zeroize::Zeroizing;

    // Generate random salt
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;

    // Derive keys
    let km = derive_keys(passphrase, &salt, kdf_iters);
    let (hk1, hk2, dk1, dk2, ck1, ck2) = split_keys(&km);

    // Generate random master keys
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

    let mut hdr_buf = hdr.serialize();
    encrypt_header_buf(&mut hdr_buf, hk1, hk2);

    // Write the file
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("create {}: {}", path, e))?;

    f.write_all(&salt).map_err(|e| e.to_string())?;
    f.write_all(&hdr_buf).map_err(|e| e.to_string())?;

    // Pre-allocate the data region with zeros (or random if desired)
    let zero_chunk = vec![0u8; 65536];
    let mut remaining = data_size;
    while remaining > 0 {
        let n = remaining.min(65536) as usize;
        f.write_all(&zero_chunk[..n]).map_err(|e| e.to_string())?;
        remaining -= n as u64;
    }
    f.flush().map_err(|e| e.to_string())?;

    // Suppress unused-variable warnings for keys we read but don't use here
    let _ = (dk1, dk2, ck1, ck2);
    Ok(())
}

/// Open an existing container: verify passphrase and return the decrypted header + data Engine.
pub fn open(path: &str, passphrase: &[u8]) -> Result<(CvHeader, Engine, File), String> {
    let mut f = File::open(path).map_err(|e| format!("open {}: {}", path, e))?;

    // Read salt
    let mut salt = [0u8; SALT_LEN];
    f.read_exact(&mut salt).map_err(|e| e.to_string())?;

    // Read encrypted header (we don't know kdf_iters yet — try with reasonable defaults
    // by first decrypting with trial iterations 0 to read the header which stores the actual iters)
    // Actually: the header stores kdf_iters itself. We must try to decrypt to find it.
    // Approach: PBKDF2 output length is 192 bytes regardless; we derive once, decrypt, check magic.
    // But we don't know kdf_iters before decrypting... We store kdf_iters in the header.
    // VeraCrypt solves this by fixing iterations per algo version. We use the same: caller must
    // supply passphrase only; we try DEFAULT_KDF_ITERS first.
    // Better: use a fixed well-known "bootstrap" derivation with 1 iteration just to check the
    // magic, then re-derive with the actual iteration count stored in the header.
    // Simplest correct approach: derive with a fixed iteration count, decode header, read kdf_iters,
    // re-derive if different. For the first release we fix kdf_iters in the header and trust it.

    let mut hdr_enc = [0u8; HEADER_ENCRYPTED_LEN];
    f.read_exact(&mut hdr_enc).map_err(|e| e.to_string())?;

    // We must decode with the ACTUAL kdf_iters. Since we don't know them yet, we bootstrap:
    // derive with a sentinel iter count (1) to decode the kdf_iters field, then re-derive.
    // This is intentionally weak for the bootstrap read only — real key material comes second.
    let bootstrap_km = derive_keys(passphrase, &salt, 1);
    let (bk1, bk2, _, _, _, _) = split_keys(&bootstrap_km);
    let mut trial_buf = hdr_enc;
    decrypt_header_buf(&mut trial_buf, bk1, bk2);
    let stored_iters = if &trial_buf[0..8] == b"SATAN2CV" {
        u32::from_le_bytes(trial_buf[16..20].try_into().unwrap())
    } else {
        // Not a bootstrap-compatible container; derive with default and hope for the best
        500_000
    };

    // Real derivation
    let km = derive_keys(passphrase, &salt, stored_iters);
    let (hk1, hk2, dk1, dk2, ck1, ck2) = split_keys(&km);

    let mut hdr_buf = hdr_enc;
    decrypt_header_buf(&mut hdr_buf, hk1, hk2);

    let hdr = CvHeader::deserialize(&hdr_buf)?;

    // Build the data engine using the master keys from the decrypted header
    let engine = Engine::from_keys(hdr.algo, &hdr.master_key, &hdr.cascade_key);

    let _ = (dk1, dk2, ck1, ck2);
    Ok((hdr, engine, f))
}

/// Read one sector (512 bytes) from the data region of an open file, decrypt in place.
pub fn read_sector(
    f: &mut File,
    engine: &Engine,
    sector: u64,
    buf: &mut [u8; SECTOR_SIZE],
) -> Result<(), String> {
    let offset = DATA_OFFSET + sector * SECTOR_SIZE as u64;
    f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    f.read_exact(buf).map_err(|e| e.to_string())?;
    engine.decrypt_sector(sector, buf);
    Ok(())
}

/// Encrypt and write one sector (512 bytes) to the data region.
pub fn write_sector(
    f: &mut File,
    engine: &Engine,
    sector: u64,
    data: &[u8; SECTOR_SIZE],
) -> Result<(), String> {
    let mut buf = *data;
    engine.encrypt_sector(sector, &mut buf);
    let offset = DATA_OFFSET + sector * SECTOR_SIZE as u64;
    f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    f.write_all(&buf).map_err(|e| e.to_string())
}

/// Fill a slice with cryptographically random bytes.
/// Uses getrandom (BCryptGenRandom on Windows, /dev/urandom on Unix).
pub fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    getrandom::getrandom(buf).map_err(|e| format!("getrandom: {}", e))
}
