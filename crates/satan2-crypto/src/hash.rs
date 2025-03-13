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
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    })
}

/// Hash a file with the specified algorithm; returns raw digest bytes.
pub fn hash_file(path: &str, algo: HashAlgo) -> Result<Vec<u8>, String> {
    match algo {
        HashAlgo::Sha256    => hash_stream::<Sha256>(path),
        HashAlgo::Sha512    => hash_stream::<Sha512>(path),
        HashAlgo::Blake2b512 => hash_stream::<Blake2b512>(path),
        HashAlgo::Sha3_256  => hash_stream::<Sha3_256>(path),
        HashAlgo::Sha3_512  => hash_stream::<Sha3_512>(path),
    }
}

/// Hash an in-memory byte slice.
pub fn hash_bytes(data: &[u8], algo: HashAlgo) -> Vec<u8> {
    match algo {
        HashAlgo::Sha256     => { use sha2::Digest; Sha256::digest(data).to_vec() }
        HashAlgo::Sha512     => { use sha2::Digest; Sha512::digest(data).to_vec() }
        HashAlgo::Blake2b512 => { use blake2::Digest; Blake2b512::digest(data).to_vec() }
        HashAlgo::Sha3_256   => { use sha3::Digest; Sha3_256::digest(data).to_vec() }
        HashAlgo::Sha3_512   => { use sha3::Digest; Sha3_512::digest(data).to_vec() }
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
        let n = reader.read(&mut buf).map_err(|e| format!("read '{}': {}", path, e))?;
        if n == 0 { break; }
        sha2::digest::Digest::update(&mut h, &buf[..n]);
    }

    Ok(sha2::digest::Digest::finalize(h).to_vec())
}
