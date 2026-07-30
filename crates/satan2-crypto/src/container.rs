// SATAN2CV container I/O:
//   create_new  — allocate a container file and write an encrypted header
//   open        — verify passphrase, return decrypted CvHeader + data Engine
//   read_sector / write_sector — random-access I/O on the data region

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::algo::Engine;
use crate::header::{
    AlgoId, CvHeader, DATA_OFFSET, HEADER_ENCRYPTED_LEN, SALT_ITERS_OFFSET, SALT_LEN,
};
use crate::kdf::{derive_keys, split_keys};
use crate::xts::{Aes256Cipher, Xts};

/// Sector size used for the XTS tweak index in the data region.
pub const SECTOR_SIZE: usize = 512;

/// Historic fallback iteration count for containers written before the
/// iteration count was embedded in the salt region.
const LEGACY_KDF_ITERS: u32 = 500_000;
/// Upper sanity bound for a plausible iteration count read from disk.
const MAX_PLAUSIBLE_ITERS: u32 = 100_000_000;

/// Generate a fresh KDF salt with the iteration count embedded in its last
/// 4 bytes (LE u32). The full 512 bytes are fed to the KDF as salt.
pub fn generate_salt(kdf_iters: u32) -> Result<[u8; SALT_LEN], String> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    salt[SALT_ITERS_OFFSET..].copy_from_slice(&kdf_iters.to_le_bytes());
    Ok(salt)
}

/// Recover the KDF iteration count embedded in the salt region.
/// Legacy containers have fully random salt, so implausible values
/// (0 or absurdly large) fall back to the historic default.
pub fn iters_from_salt(salt: &[u8; SALT_LEN]) -> u32 {
    let v = u32::from_le_bytes(salt[SALT_ITERS_OFFSET..].try_into().unwrap());
    if v == 0 || v > MAX_PLAUSIBLE_ITERS {
        LEGACY_KDF_ITERS
    } else {
        v
    }
}

/// Encrypt the 4096-byte plaintext header with AES-256-XTS (sector 0).
fn encrypt_header_buf(buf: &mut [u8; HEADER_ENCRYPTED_LEN], hk1: &[u8; 32], hk2: &[u8; 32]) {
    let xts: Xts<Aes256Cipher> = Xts {
        data_cipher: Aes256Cipher::new(hk1),
        tweak_cipher: Aes256Cipher::new(hk2),
    };
    // Header is 4096 bytes = 256 × 16-byte blocks — encrypt as a single sector 0
    xts.encrypt_sector(0, buf.as_mut_slice());
}

/// Decrypt the 4096-byte header buffer with AES-256-XTS.
fn decrypt_header_buf(buf: &mut [u8; HEADER_ENCRYPTED_LEN], hk1: &[u8; 32], hk2: &[u8; 32]) {
    let xts: Xts<Aes256Cipher> = Xts {
        data_cipher: Aes256Cipher::new(hk1),
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

    // Generate random salt with the iteration count embedded in its last 4 bytes
    let salt = generate_salt(kdf_iters)?;

    // Derive keys
    let km = derive_keys(passphrase, &salt, kdf_iters);
    let (hk1, hk2, dk1, dk2, ck1, ck2) = split_keys(&km);

    // Generate random master keys
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

    // Read salt; the KDF iteration count is embedded in its last 4 bytes.
    let mut salt = [0u8; SALT_LEN];
    f.read_exact(&mut salt).map_err(|e| e.to_string())?;
    let kdf_iters = iters_from_salt(&salt);

    let mut hdr_enc = [0u8; HEADER_ENCRYPTED_LEN];
    f.read_exact(&mut hdr_enc).map_err(|e| e.to_string())?;

    let km = derive_keys(passphrase, &salt, kdf_iters);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::AlgoId;

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

    const ALL_ALGOS: [AlgoId; 5] = [
        AlgoId::Aes256,
        AlgoId::Twofish256,
        AlgoId::Camellia256,
        AlgoId::AesTwofish,
        AlgoId::Kuznyechik,
    ];

    #[test]
    fn create_open_roundtrip_all_algos() {
        let dir = tmpdir("container-roundtrip");
        for algo in ALL_ALGOS {
            let path = dir.join(format!("{:?}.cv", algo));
            let ps = path.to_str().unwrap();
            create_new(ps, 4096, algo, b"test-pass", 1000).unwrap();
            let (hdr, _engine, _f) = open(ps, b"test-pass").unwrap();
            assert_eq!(hdr.algo, algo);
            assert_eq!(hdr.kdf_iters, 1000);
            assert_eq!(hdr.volume_size, 4096);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Containers created with a non-default iteration count must still open.
    /// (The CLI defaults to 300_000, not 500_000.)
    #[test]
    fn non_default_kdf_iters_roundtrip() {
        let dir = tmpdir("container-iters");
        for iters in [1u32, 1000, 300_000] {
            let path = dir.join(format!("iters-{}.cv", iters));
            let ps = path.to_str().unwrap();
            create_new(ps, 1024, AlgoId::Aes256, b"test-pass", iters).unwrap();
            let (hdr, _e, _f) = open(ps, b"test-pass")
                .unwrap_or_else(|e| panic!("open failed for kdf_iters={}: {}", iters, e));
            assert_eq!(hdr.kdf_iters, iters);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let dir = tmpdir("container-wrongpass");
        let path = dir.join("c.cv");
        let ps = path.to_str().unwrap();
        create_new(ps, 1024, AlgoId::Aes256, b"right-pass", 1000).unwrap();
        let err = open(ps, b"wrong-pass").err().unwrap();
        assert!(err.contains("magic"), "unexpected error: {}", err);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Helper: open() returns a read-only File; sector writes need an rw handle.
    fn rw_handle(path: &std::path::Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    #[test]
    fn write_read_sector_roundtrip() {
        let dir = tmpdir("container-sectors");
        let path = dir.join("c.cv");
        let ps = path.to_str().unwrap();
        create_new(ps, 4096, AlgoId::Aes256, b"test-pass", 1000).unwrap();
        let (_hdr, engine, _f) = open(ps, b"test-pass").unwrap();
        let mut wf = rw_handle(&path);

        let s0: [u8; SECTOR_SIZE] = [0x5A; SECTOR_SIZE];
        let mut s1 = [0u8; SECTOR_SIZE];
        for (i, b) in s1.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }

        write_sector(&mut wf, &engine, 0, &s0).unwrap();
        write_sector(&mut wf, &engine, 1, &s1).unwrap();

        let mut back0 = [0u8; SECTOR_SIZE];
        let mut back1 = [0u8; SECTOR_SIZE];
        read_sector(&mut wf, &engine, 0, &mut back0).unwrap();
        read_sector(&mut wf, &engine, 1, &mut back1).unwrap();
        assert_eq!(back0, s0);
        assert_eq!(back1, s1);

        // Untouched sector: create_new leaves raw zeros on disk (not encrypted
        // zeros), so it must NOT decrypt to zeros — and must differ from s0.
        let mut back2 = [0u8; SECTOR_SIZE];
        read_sector(&mut wf, &engine, 2, &mut back2).unwrap();
        assert_ne!(back2, [0u8; SECTOR_SIZE]);
        assert_ne!(back2, s0);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// On-disk ciphertext must not equal plaintext, and tampering with the
    /// data region must change what read_sector returns.
    #[test]
    fn data_region_is_encrypted_and_tamper_evident() {
        let dir = tmpdir("container-tamper");
        let path = dir.join("c.cv");
        let ps = path.to_str().unwrap();
        create_new(ps, 4096, AlgoId::Twofish256, b"test-pass", 1000).unwrap();
        let (_hdr, engine, _f) = open(ps, b"test-pass").unwrap();
        let mut wf = rw_handle(&path);

        let plain: [u8; SECTOR_SIZE] = [0x42; SECTOR_SIZE];
        write_sector(&mut wf, &engine, 0, &plain).unwrap();
        wf.flush().unwrap();

        // Raw bytes on disk must not be the plaintext.
        let raw = std::fs::read(ps).unwrap();
        let on_disk = &raw[DATA_OFFSET as usize..DATA_OFFSET as usize + SECTOR_SIZE];
        assert_ne!(on_disk, &plain[..], "sector stored in cleartext!");

        // Flip one ciphertext byte on disk; decrypted sector must change.
        let mut before = [0u8; SECTOR_SIZE];
        read_sector(&mut wf, &engine, 0, &mut before).unwrap();
        drop(wf);

        let mut raw = std::fs::read(ps).unwrap();
        raw[DATA_OFFSET as usize + 100] ^= 0x01;
        std::fs::write(ps, &raw).unwrap();

        let (_h2, engine2, mut f2) = open(ps, b"test-pass").unwrap();
        let mut after = [0u8; SECTOR_SIZE];
        read_sector(&mut f2, &engine2, 0, &mut after).unwrap();
        assert_eq!(before, plain, "pre-tamper readback wrong");
        assert_ne!(
            after, plain,
            "tampered ciphertext decrypted to original plaintext"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn salt_embeds_kdf_iters() {
        let salt = generate_salt(300_000).unwrap();
        assert_eq!(iters_from_salt(&salt), 300_000);
        // The random part (first 508 bytes) must differ between generations.
        let salt2 = generate_salt(300_000).unwrap();
        assert_ne!(&salt[..SALT_ITERS_OFFSET], &salt2[..SALT_ITERS_OFFSET]);
    }

    #[test]
    fn iters_from_salt_legacy_fallback() {
        // All-zero salt region → iter count 0 → legacy default.
        assert_eq!(iters_from_salt(&[0u8; SALT_LEN]), LEGACY_KDF_ITERS);
        // Garbage (fully random legacy salt) → implausibly large → legacy default.
        let mut salt = [0u8; SALT_LEN];
        salt[SALT_ITERS_OFFSET..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(iters_from_salt(&salt), LEGACY_KDF_ITERS);
    }
}
