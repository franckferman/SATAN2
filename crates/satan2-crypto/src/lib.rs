// satan2-crypto — VeraCrypt-style encryption engine for SATAN2
// Provides: XTS mode, AES/Twofish/Camellia/Kuznyechik, PBKDF2-based KDF,
//           SATAN2CV container format, file/dir/device encryption, hashing.

pub mod algo;
pub mod container;
pub mod extract;
pub mod hash;
pub mod header;
pub mod kdf;
pub mod kuznyechik;
pub mod ops;
pub mod xts;

pub use extract::extract_dir;
pub use hash::{hash_bytes, hash_file, to_hex, HashAlgo};
pub use header::AlgoId;
pub use ops::{decrypt_layers, encrypt_layers, Algorithm, Layer};
