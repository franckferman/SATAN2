// Algorithm dispatch: builds the correct Xts<C> engine from key material and an AlgoId.
// Wraps the variant-specific constructors behind a common encrypt/decrypt interface.

use crate::header::AlgoId;
use crate::kuznyechik::Kuznyechik;
use crate::xts::{
    Aes256Cipher, CamelliaCipher, CascadeAesTwofish, TwofishCipher, Xts,
};

/// Unified cipher engine that dispatches to the correct XTS variant at runtime.
pub enum Engine {
    Aes(Xts<Aes256Cipher>),
    Twofish(Xts<TwofishCipher>),
    Camellia(Xts<CamelliaCipher>),
    Cascade(Xts<CascadeAesTwofish>),
    Kuznyechik(Xts<Kuznyechik>),
}

impl Engine {
    /// Build an engine from the master_key (64 bytes: data_k1 + data_k2)
    /// and optional cascade_key (64 bytes) for the AesTwofish cascade.
    pub fn from_keys(algo: AlgoId, master_key: &[u8; 64], cascade_key: &[u8; 64]) -> Self {
        let k1: &[u8; 32] = master_key[0..32].try_into().unwrap();
        let k2: &[u8; 32] = master_key[32..64].try_into().unwrap();

        match algo {
            AlgoId::Aes256 => Engine::Aes(Xts {
                data_cipher:  Aes256Cipher::new(k1),
                tweak_cipher: Aes256Cipher::new(k2),
            }),
            AlgoId::Twofish256 => Engine::Twofish(Xts {
                data_cipher:  TwofishCipher::new(k1),
                tweak_cipher: TwofishCipher::new(k2),
            }),
            AlgoId::Camellia256 => Engine::Camellia(Xts {
                data_cipher:  CamelliaCipher::new(k1),
                tweak_cipher: CamelliaCipher::new(k2),
            }),
            AlgoId::AesTwofish => {
                // cascade_key: ck1[0..32] for Twofish data, ck2[32..64] for Twofish tweak
                let ck1: &[u8; 32] = cascade_key[0..32].try_into().unwrap();
                let ck2: &[u8; 32] = cascade_key[32..64].try_into().unwrap();
                Engine::Cascade(Xts {
                    data_cipher:  CascadeAesTwofish::new(k1, ck1),
                    tweak_cipher: CascadeAesTwofish::new(k2, ck2),
                })
            }
            AlgoId::Kuznyechik => Engine::Kuznyechik(Xts {
                data_cipher:  Kuznyechik::new(k1),
                tweak_cipher: Kuznyechik::new(k2),
            }),
        }
    }

    pub fn encrypt_sector(&self, sector: u64, data: &mut [u8]) {
        match self {
            Engine::Aes(x)        => x.encrypt_sector(sector, data),
            Engine::Twofish(x)    => x.encrypt_sector(sector, data),
            Engine::Camellia(x)   => x.encrypt_sector(sector, data),
            Engine::Cascade(x)    => x.encrypt_sector(sector, data),
            Engine::Kuznyechik(x) => x.encrypt_sector(sector, data),
        }
    }

    pub fn decrypt_sector(&self, sector: u64, data: &mut [u8]) {
        match self {
            Engine::Aes(x)        => x.decrypt_sector(sector, data),
            Engine::Twofish(x)    => x.decrypt_sector(sector, data),
            Engine::Camellia(x)   => x.decrypt_sector(sector, data),
            Engine::Cascade(x)    => x.decrypt_sector(sector, data),
            Engine::Kuznyechik(x) => x.decrypt_sector(sector, data),
        }
    }
}

// XtsCipher for Kuznyechik is implemented in kuznyechik.rs
