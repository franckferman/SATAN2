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
#[allow(clippy::type_complexity)] // a 6-tuple of fixed key slices is the clearest signature here
pub fn split_keys(
    km: &[u8; 192],
) -> (
    &[u8; 32],
    &[u8; 32],
    &[u8; 32],
    &[u8; 32],
    &[u8; 32],
    &[u8; 32],
) {
    let hk1: &[u8; 32] = km[0..32].try_into().unwrap();
    let hk2: &[u8; 32] = km[32..64].try_into().unwrap();
    let dk1: &[u8; 32] = km[64..96].try_into().unwrap();
    let dk2: &[u8; 32] = km[96..128].try_into().unwrap();
    let ck1: &[u8; 32] = km[128..160].try_into().unwrap();
    let ck2: &[u8; 32] = km[160..192].try_into().unwrap();
    (hk1, hk2, dk1, dk2, ck1, ck2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt(byte: u8) -> [u8; 512] {
        [byte; 512]
    }

    #[test]
    fn output_length_is_192() {
        let km = derive_keys(b"passphrase", &salt(0x01), 1000);
        assert_eq!(km.len(), 192);
    }

    #[test]
    fn deterministic_same_inputs() {
        let a = derive_keys(b"hunter2", &salt(0xAB), 1000);
        let b = derive_keys(b"hunter2", &salt(0xAB), 1000);
        assert_eq!(
            a, b,
            "same passphrase + salt + iterations must derive the same key"
        );
    }

    #[test]
    fn different_salt_different_key() {
        let a = derive_keys(b"hunter2", &salt(0x01), 1000);
        let b = derive_keys(b"hunter2", &salt(0x02), 1000);
        assert_ne!(a, b);
    }

    #[test]
    fn different_passphrase_different_key() {
        let a = derive_keys(b"hunter2", &salt(0x01), 1000);
        let b = derive_keys(b"hunter3", &salt(0x01), 1000);
        assert_ne!(a, b);
    }

    #[test]
    fn different_iterations_different_key() {
        let a = derive_keys(b"hunter2", &salt(0x01), 1000);
        let b = derive_keys(b"hunter2", &salt(0x01), 2000);
        assert_ne!(a, b);
    }

    #[test]
    fn split_keys_covers_all_192_bytes() {
        let km = derive_keys(b"hunter2", &salt(0x77), 1000);
        let (hk1, hk2, dk1, dk2, ck1, ck2) = split_keys(&km);
        let mut reassembled = Vec::new();
        for part in [hk1, hk2, dk1, dk2, ck1, ck2] {
            reassembled.extend_from_slice(part);
        }
        assert_eq!(reassembled.as_slice(), km.as_slice());
        // The six sub-keys should be pairwise distinct for real KDF output.
        let parts: [&[u8; 32]; 6] = [hk1, hk2, dk1, dk2, ck1, ck2];
        for i in 0..6 {
            for j in (i + 1)..6 {
                assert_ne!(parts[i], parts[j], "sub-keys {} and {} must differ", i, j);
            }
        }
    }
}
