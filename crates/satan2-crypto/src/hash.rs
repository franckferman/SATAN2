// hash.rs — cryptographic hashing of files and byte slices
// Supported: SHA-256, SHA-512, BLAKE2b-512, SHA3-256, SHA3-512

use std::fs::File;
use std::io::{BufReader, Read};

use blake2::Blake2b512;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

const BUF_SIZE: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgo {
    Sha256,
    Sha512,
    Blake2b512,
    Sha3_256,
    Sha3_512,
}

/// Format bytes as a lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
            s
        })
}

/// Hash a file with the specified algorithm; returns raw digest bytes.
pub fn hash_file(path: &str, algo: HashAlgo) -> Result<Vec<u8>, String> {
    match algo {
        HashAlgo::Sha256 => hash_stream::<Sha256>(path),
        HashAlgo::Sha512 => hash_stream::<Sha512>(path),
        HashAlgo::Blake2b512 => hash_stream::<Blake2b512>(path),
        HashAlgo::Sha3_256 => hash_stream::<Sha3_256>(path),
        HashAlgo::Sha3_512 => hash_stream::<Sha3_512>(path),
    }
}

/// Hash an in-memory byte slice.
pub fn hash_bytes(data: &[u8], algo: HashAlgo) -> Vec<u8> {
    match algo {
        HashAlgo::Sha256 => {
            use sha2::Digest;
            Sha256::digest(data).to_vec()
        }
        HashAlgo::Sha512 => {
            use sha2::Digest;
            Sha512::digest(data).to_vec()
        }
        HashAlgo::Blake2b512 => {
            use blake2::Digest;
            Blake2b512::digest(data).to_vec()
        }
        HashAlgo::Sha3_256 => {
            use sha3::Digest;
            Sha3_256::digest(data).to_vec()
        }
        HashAlgo::Sha3_512 => {
            use sha3::Digest;
            Sha3_512::digest(data).to_vec()
        }
    }
}

// Generic streaming helper — works for any RustCrypto Digest impl.
fn hash_stream<D>(path: &str) -> Result<Vec<u8>, String>
where
    D: sha2::digest::Digest,
{
    let f = File::open(path).map_err(|e| format!("open '{}': {}", path, e))?;
    let mut reader = BufReader::with_capacity(BUF_SIZE, f);
    let mut h = D::new();
    let mut buf = [0u8; BUF_SIZE];

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("read '{}': {}", path, e))?;
        if n == 0 {
            break;
        }
        sha2::digest::Digest::update(&mut h, &buf[..n]);
    }

    Ok(sha2::digest::Digest::finalize(h).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // Well-known NIST / reference digests for "abc" and the empty string.

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            to_hex(&hash_bytes(b"abc", HashAlgo::Sha256)),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            to_hex(&hash_bytes(b"", HashAlgo::Sha256)),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha512_vectors() {
        assert_eq!(
            to_hex(&hash_bytes(b"abc", HashAlgo::Sha512)),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            to_hex(&hash_bytes(b"", HashAlgo::Sha512)),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn blake2b512_vectors() {
        assert_eq!(
            to_hex(&hash_bytes(b"abc", HashAlgo::Blake2b512)),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            to_hex(&hash_bytes(b"", HashAlgo::Blake2b512)),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    #[test]
    fn sha3_256_vectors() {
        assert_eq!(
            to_hex(&hash_bytes(b"abc", HashAlgo::Sha3_256)),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            to_hex(&hash_bytes(b"", HashAlgo::Sha3_256)),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn sha3_512_vectors() {
        assert_eq!(
            to_hex(&hash_bytes(b"abc", HashAlgo::Sha3_512)),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        assert_eq!(
            to_hex(&hash_bytes(b"", HashAlgo::Sha3_512)),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn digest_lengths() {
        assert_eq!(hash_bytes(b"x", HashAlgo::Sha256).len(), 32);
        assert_eq!(hash_bytes(b"x", HashAlgo::Sha512).len(), 64);
        assert_eq!(hash_bytes(b"x", HashAlgo::Blake2b512).len(), 64);
        assert_eq!(hash_bytes(b"x", HashAlgo::Sha3_256).len(), 32);
        assert_eq!(hash_bytes(b"x", HashAlgo::Sha3_512).len(), 64);
    }

    #[test]
    fn hash_file_matches_hash_bytes() {
        let dir = tmpdir("hash-file");
        let path = dir.join("data.bin");
        // Larger than the 64 KiB streaming buffer to cross chunk boundaries.
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();

        for algo in [
            HashAlgo::Sha256,
            HashAlgo::Sha512,
            HashAlgo::Blake2b512,
            HashAlgo::Sha3_256,
            HashAlgo::Sha3_512,
        ] {
            let from_file = hash_file(path.to_str().unwrap(), algo).unwrap();
            let from_mem = hash_bytes(&data, algo);
            assert_eq!(
                from_file, from_mem,
                "hash_file/hash_bytes mismatch for {:?}",
                algo
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hash_file_missing_file_errors() {
        assert!(hash_file("/nonexistent/satan2-no-such-file", HashAlgo::Sha256).is_err());
    }

    #[test]
    fn to_hex_formatting() {
        assert_eq!(to_hex(&[0x00, 0x0F, 0xAB, 0xFF]), "000fabff");
        assert_eq!(to_hex(&[]), "");
    }
}
