// Key derivation using PBKDF2-HMAC-SHA512
// Returns 192 bytes:
//   [0..32]   header encryption key K1 (AES-256 for header)
//   [32..64]  header tweak key K2
//   [64..96]  data cipher key K1
//   [96..128] data cipher tweak key K2
//   [128..160] cascade key K1 (second algo)
//   [160..192] cascade key K2 (second algo tweak)

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use zeroize::Zeroizing;

/// Derive 192 bytes of keying material from a passphrase and 512-byte salt.
/// Uses PBKDF2-HMAC-SHA512 with the given iteration count.
pub fn derive_keys(passphrase: &[u8], salt: &[u8; 512], iterations: u32) -> Zeroizing<[u8; 192]> {
    let mut out = Zeroizing::new([0u8; 192]);
    pbkdf2::<Hmac<Sha512>>(passphrase, salt.as_ref(), iterations, out.as_mut())
        .expect("PBKDF2 length is valid");
    out
}

/// Split the 192-byte key material into typed slices.
/// Returns (header_k1, header_k2, data_k1, data_k2, cascade_k1, cascade_k2).
pub fn split_keys(km: &[u8; 192]) -> (&[u8; 32], &[u8; 32], &[u8; 32], &[u8; 32], &[u8; 32], &[u8; 32]) {
    let hk1: &[u8; 32] = km[0..32].try_into().unwrap();
    let hk2: &[u8; 32] = km[32..64].try_into().unwrap();
    let dk1: &[u8; 32] = km[64..96].try_into().unwrap();
    let dk2: &[u8; 32] = km[96..128].try_into().unwrap();
    let ck1: &[u8; 32] = km[128..160].try_into().unwrap();
    let ck2: &[u8; 32] = km[160..192].try_into().unwrap();
    (hk1, hk2, dk1, dk2, ck1, ck2)
}
