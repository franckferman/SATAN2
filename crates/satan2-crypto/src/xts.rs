// XTS mode implementation from scratch (IEEE 1619-2007)
// Supports any block cipher with 128-bit blocks via the XtsCipher trait.

use aes::Aes256;
use camellia::Camellia256;
use cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use twofish::Twofish;

/// GF(2^128) multiply by x — primitive polynomial x^128+x^7+x^2+x+1
/// Input/output in little-endian (byte 0 is the least significant).
#[inline]
fn gf_mul_x(v: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let carry = v[15] >> 7;
    // Left shift the entire 128-bit value by 1 bit (LE order: shift towards higher index)
    for i in (1..16).rev() {
        out[i] = (v[i] << 1) | (v[i - 1] >> 7);
    }
    out[0] = v[0] << 1;
    // If carry bit was set, XOR with the field polynomial's low bits
    if carry != 0 {
        out[0] ^= 0x87;
    }
    out
}

/// XOR two 16-byte blocks in place: dst ^= src
#[inline]
fn xor16(dst: &mut [u8; 16], src: &[u8; 16]) {
    for i in 0..16 {
        dst[i] ^= src[i];
    }
}

/// Trait for 128-bit block ciphers used inside XTS
pub trait XtsCipher {
    fn encrypt_block_raw(&self, block: &mut [u8; 16]);
    fn decrypt_block_raw(&self, block: &mut [u8; 16]);
}

/// XTS wrapper: holds a data cipher and a tweak cipher (both with independent keys)
pub struct Xts<C: XtsCipher> {
    pub data_cipher:  C,
    pub tweak_cipher: C,
}

impl<C: XtsCipher> Xts<C> {
    /// Encrypt `data` interpreted as a sequence of 512-byte sectors.
    /// `sector_index` is the logical sector number (used as the tweak).
    /// Data length must be a multiple of 16.
    pub fn encrypt_sector(&self, sector_index: u64, data: &mut [u8]) {
        assert!(data.len() % 16 == 0, "XTS data must be a multiple of 16 bytes");

        // Build initial tweak: sector_index as 128-bit LE
        let mut tweak = [0u8; 16];
        let idx_bytes = sector_index.to_le_bytes();
        tweak[..8].copy_from_slice(&idx_bytes);
        // Encrypt the tweak with the tweak key
        self.tweak_cipher.encrypt_block_raw(&mut tweak);

        for chunk in data.chunks_exact_mut(16) {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            xor16(&mut block, &tweak);
            self.data_cipher.encrypt_block_raw(&mut block);
            xor16(&mut block, &tweak);
            chunk.copy_from_slice(&block);
            tweak = gf_mul_x(&tweak);
        }
    }

    /// Decrypt `data` for the given sector.
    pub fn decrypt_sector(&self, sector_index: u64, data: &mut [u8]) {
        assert!(data.len() % 16 == 0, "XTS data must be a multiple of 16 bytes");

        let mut tweak = [0u8; 16];
        let idx_bytes = sector_index.to_le_bytes();
        tweak[..8].copy_from_slice(&idx_bytes);
        self.tweak_cipher.encrypt_block_raw(&mut tweak);

        for chunk in data.chunks_exact_mut(16) {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            xor16(&mut block, &tweak);
            self.data_cipher.decrypt_block_raw(&mut block);
            xor16(&mut block, &tweak);
            chunk.copy_from_slice(&block);
            tweak = gf_mul_x(&tweak);
        }
    }
}

// ─── XtsCipher implementations ───────────────────────────────────────────────

/// AES-256 wrapper
pub struct Aes256Cipher {
    enc: Aes256,
    dec: Aes256,
}

impl Aes256Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        use cipher::generic_array::GenericArray;
        let k = GenericArray::from_slice(key);
        Aes256Cipher {
            enc: Aes256::new(k),
            dec: Aes256::new(k),
        }
    }
}

impl XtsCipher for Aes256Cipher {
    fn encrypt_block_raw(&self, block: &mut [u8; 16]) {
        use cipher::generic_array::GenericArray;
        let mut b = GenericArray::from_mut_slice(block);
        self.enc.encrypt_block(&mut b);
    }
    fn decrypt_block_raw(&self, block: &mut [u8; 16]) {
        use cipher::generic_array::GenericArray;
        let mut b = GenericArray::from_mut_slice(block);
        self.dec.decrypt_block(&mut b);
    }
}

/// Twofish-256 wrapper
pub struct TwofishCipher {
    inner: Twofish,
}

impl TwofishCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        use cipher::generic_array::GenericArray;
        let k = GenericArray::from_slice(key);
        TwofishCipher { inner: Twofish::new(k) }
    }
}

impl XtsCipher for TwofishCipher {
    fn encrypt_block_raw(&self, block: &mut [u8; 16]) {
        use cipher::generic_array::GenericArray;
        let mut b = GenericArray::from_mut_slice(block);
        self.inner.encrypt_block(&mut b);
    }
    fn decrypt_block_raw(&self, block: &mut [u8; 16]) {
        use cipher::generic_array::GenericArray;
        let mut b = GenericArray::from_mut_slice(block);
        self.inner.decrypt_block(&mut b);
    }
}

/// Camellia-256 wrapper
pub struct CamelliaCipher {
    enc: Camellia256,
    dec: Camellia256,
}

impl CamelliaCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        use cipher::generic_array::GenericArray;
        let k = GenericArray::from_slice(key);
        CamelliaCipher {
            enc: Camellia256::new(k),
            dec: Camellia256::new(k),
        }
    }
}

impl XtsCipher for CamelliaCipher {
    fn encrypt_block_raw(&self, block: &mut [u8; 16]) {
        use cipher::generic_array::GenericArray;
        let mut b = GenericArray::from_mut_slice(block);
        self.enc.encrypt_block(&mut b);
    }
    fn decrypt_block_raw(&self, block: &mut [u8; 16]) {
        use cipher::generic_array::GenericArray;
        let mut b = GenericArray::from_mut_slice(block);
        self.dec.decrypt_block(&mut b);
    }
}

/// Cascade: AES-256 outer + Twofish-256 inner (encrypt: AES then Twofish, decrypt: inverse)
pub struct CascadeAesTwofish {
    aes:      Aes256Cipher,
    twofish:  TwofishCipher,
    // For tweak cipher slot we need two independent pairings
    // The struct is generic so we use it directly in the Xts wrapper.
}

impl CascadeAesTwofish {
    pub fn new(key_aes: &[u8; 32], key_tf: &[u8; 32]) -> Self {
        CascadeAesTwofish {
            aes:     Aes256Cipher::new(key_aes),
            twofish: TwofishCipher::new(key_tf),
        }
    }
}

impl XtsCipher for CascadeAesTwofish {
    fn encrypt_block_raw(&self, block: &mut [u8; 16]) {
        // Encrypt with Twofish first, then AES (innermost first)
        self.twofish.encrypt_block_raw(block);
        self.aes.encrypt_block_raw(block);
    }
    fn decrypt_block_raw(&self, block: &mut [u8; 16]) {
        self.aes.decrypt_block_raw(block);
        self.twofish.decrypt_block_raw(block);
    }
}
