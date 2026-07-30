// SATAN2CV container header format
// Offset 0:    512 bytes  — KDF salt; the last 4 bytes (508..512) hold the
//                           PBKDF2 iteration count as a plaintext LE u32,
//                           the first 508 bytes are random.
// Offset 512:  4096 bytes — encrypted header (AES-256-XTS with keys derived from salt+passphrase)
// Offset 4608: N bytes    — data region encrypted in XTS with the master key

use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 512;
/// Offset within the salt region of the plaintext LE u32 PBKDF2 iteration count.
pub const SALT_ITERS_OFFSET: usize = SALT_LEN - 4;
pub const HEADER_ENCRYPTED_LEN: usize = 4096;
pub const DATA_OFFSET: u64 = (SALT_LEN + HEADER_ENCRYPTED_LEN) as u64;
pub const CV_MAGIC: &[u8; 8] = b"SATAN2CV";
pub const CV_VERSION: u16 = 1;

/// Algorithm identifier stored in the header
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgoId {
    Aes256 = 0,
    Twofish256 = 1,
    Camellia256 = 2,
    AesTwofish = 3, // cascade: AES outer + Twofish inner
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
    pub algo: AlgoId,
    pub kdf_iters: u32,
    pub volume_size: u64,
    /// K1[0..32] + K2[32..64] for the data XTS cipher
    pub master_key: [u8; 64],
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
        Ok(CvHeader {
            algo,
            kdf_iters,
            volume_size,
            master_key,
            cascade_key,
        })
    }
}

// Implement Zeroize for AlgoId manually (it's a u8 enum)
impl Zeroize for AlgoId {
    fn zeroize(&mut self) {
        *self = AlgoId::Aes256;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> CvHeader {
        CvHeader {
            algo: AlgoId::Camellia256,
            kdf_iters: 123_456,
            volume_size: 0x1122_3344_5566_7788,
            master_key: [0xAA; 64],
            cascade_key: [0xBB; 64],
        }
    }

    #[test]
    fn serialize_layout() {
        let buf = sample_header().serialize();
        assert_eq!(&buf[0..8], CV_MAGIC, "magic at offset 0");
        assert_eq!(
            u16::from_le_bytes([buf[8], buf[9]]),
            CV_VERSION,
            "version at offset 8"
        );
        assert_eq!(buf[10], AlgoId::Camellia256 as u8, "algo id at offset 10");
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 123_456);
        assert_eq!(
            u64::from_le_bytes(buf[20..28].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
        assert_eq!(&buf[28..92], &[0xAA; 64], "master key at offset 28");
        assert_eq!(&buf[92..156], &[0xBB; 64], "cascade key at offset 92");
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        for algo in [
            AlgoId::Aes256,
            AlgoId::Twofish256,
            AlgoId::Camellia256,
            AlgoId::AesTwofish,
            AlgoId::Kuznyechik,
        ] {
            let hdr = CvHeader {
                algo,
                ..sample_header()
            };
            let buf = hdr.serialize();
            let back = CvHeader::deserialize(&buf).unwrap();
            assert_eq!(back.algo, algo);
            assert_eq!(back.kdf_iters, hdr.kdf_iters);
            assert_eq!(back.volume_size, hdr.volume_size);
            assert_eq!(back.master_key, hdr.master_key);
            assert_eq!(back.cascade_key, hdr.cascade_key);
        }
    }

    #[test]
    fn deserialize_rejects_bad_magic() {
        let mut buf = sample_header().serialize();
        buf[0] = b'X';
        let err = CvHeader::deserialize(&buf).err().unwrap();
        assert!(err.contains("magic"), "unexpected error: {}", err);
    }

    #[test]
    fn deserialize_rejects_bad_version() {
        let mut buf = sample_header().serialize();
        buf[8..10].copy_from_slice(&99u16.to_le_bytes());
        let err = CvHeader::deserialize(&buf).err().unwrap();
        assert!(err.contains("version"), "unexpected error: {}", err);
    }

    #[test]
    fn deserialize_rejects_unknown_algo() {
        let mut buf = sample_header().serialize();
        buf[10] = 200;
        assert!(CvHeader::deserialize(&buf).is_err());
    }

    #[test]
    fn algo_id_try_from() {
        assert_eq!(AlgoId::try_from(0).unwrap(), AlgoId::Aes256);
        assert_eq!(AlgoId::try_from(1).unwrap(), AlgoId::Twofish256);
        assert_eq!(AlgoId::try_from(2).unwrap(), AlgoId::Camellia256);
        assert_eq!(AlgoId::try_from(3).unwrap(), AlgoId::AesTwofish);
        assert_eq!(AlgoId::try_from(4).unwrap(), AlgoId::Kuznyechik);
        assert!(AlgoId::try_from(5).is_err());
        assert!(AlgoId::try_from(255).is_err());
    }
}
