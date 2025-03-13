// SATAN2CV container header format
// Offset 0:    512 bytes  — random salt for KDF
// Offset 512:  4096 bytes — encrypted header (AES-256-XTS with keys derived from salt+passphrase)
// Offset 4608: N bytes    — data region encrypted in XTS with the master key

use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN:        usize = 512;
pub const HEADER_ENCRYPTED_LEN: usize = 4096;
pub const DATA_OFFSET:     u64   = (SALT_LEN + HEADER_ENCRYPTED_LEN) as u64;
pub const CV_MAGIC:        &[u8; 8] = b"SATAN2CV";
pub const CV_VERSION:      u16   = 1;

/// Algorithm identifier stored in the header
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgoId {
    Aes256     = 0,
    Twofish256 = 1,
    Camellia256= 2,
    AesTwofish = 3,  // cascade: AES outer + Twofish inner
    Kuznyechik = 4,
}

impl TryFrom<u8> for AlgoId {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(AlgoId::Aes256),
            1 => Ok(AlgoId::Twofish256),
            2 => Ok(AlgoId::Camellia256),
            3 => Ok(AlgoId::AesTwofish),
            4 => Ok(AlgoId::Kuznyechik),
            _ => Err(format!("unknown algo id: {}", v)),
        }
    }
}

/// Plaintext header — fits inside the 4096-byte encrypted region.
/// Sensitive fields are zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CvHeader {
    pub algo:        AlgoId,
    pub kdf_iters:   u32,
    pub volume_size: u64,
    /// K1[0..32] + K2[32..64] for the data XTS cipher
    pub master_key:  [u8; 64],
    /// Second algo keys for cascade (AES-Twofish)
    pub cascade_key: [u8; 64],
}

impl CvHeader {
    /// Serialize to a 4096-byte buffer (zero-padded, with magic + version).
    pub fn serialize(&self) -> [u8; HEADER_ENCRYPTED_LEN] {
        let mut buf = [0u8; HEADER_ENCRYPTED_LEN];
        buf[0..8].copy_from_slice(CV_MAGIC);
        buf[8..10].copy_from_slice(&CV_VERSION.to_le_bytes());
        buf[10] = self.algo as u8;
        // bytes 11..15 are padding (0)
        buf[16..20].copy_from_slice(&self.kdf_iters.to_le_bytes());
        buf[20..28].copy_from_slice(&self.volume_size.to_le_bytes());
        buf[28..92].copy_from_slice(&self.master_key);
        buf[92..156].copy_from_slice(&self.cascade_key);
        // rest is random-looking due to encryption, here it's zero — caller adds entropy before encrypting
        buf
    }

    /// Deserialize from a 4096-byte plaintext buffer.
    pub fn deserialize(buf: &[u8; HEADER_ENCRYPTED_LEN]) -> Result<Self, String> {
        if &buf[0..8] != CV_MAGIC {
            return Err("bad magic — wrong passphrase or corrupt container".into());
        }
        let version = u16::from_le_bytes([buf[8], buf[9]]);
        if version != CV_VERSION {
            return Err(format!("unsupported container version {}", version));
        }
        let algo = AlgoId::try_from(buf[10])?;
        let kdf_iters = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let volume_size = u64::from_le_bytes(buf[20..28].try_into().unwrap());
        let mut master_key = [0u8; 64];
        master_key.copy_from_slice(&buf[28..92]);
        let mut cascade_key = [0u8; 64];
        cascade_key.copy_from_slice(&buf[92..156]);
        Ok(CvHeader { algo, kdf_iters, volume_size, master_key, cascade_key })
    }
}

// Implement Zeroize for AlgoId manually (it's a u8 enum)
impl Zeroize for AlgoId {
    fn zeroize(&mut self) {
        *self = AlgoId::Aes256;
    }
}
