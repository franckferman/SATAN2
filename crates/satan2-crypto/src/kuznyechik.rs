// Kuznyechik (Grasshopper) block cipher — GOST R 34.12-2015
// 128-bit block, 256-bit key, 10 rounds
// Tables taken verbatim from the official GOST specification.

/// Forward S-box (pi) — GOST R 34.12-2015, section 5.1.1
/// (verified against the official test vectors of the standard)
#[rustfmt::skip]
const PI: [u8; 256] = [
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
    0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
    0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
    0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
    0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
    0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
    0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
    0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
    0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
    0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
    0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
    0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
    0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
    0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
    0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
    0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
    0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6,
];

/// Inverse S-box, derived from PI at compile time so the two can never
/// drift apart (the previous hand-written table did not match PI).
const fn invert_sbox(pi: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        inv[pi[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

const PI_INV: [u8; 256] = invert_sbox(&PI);

// Linear transform coefficients — GF(2^8) with polynomial x^8+x^7+x^6+x+1 (0xC3)
// Row of the L matrix: [148,32,133,16,194,192,1,251,1,192,194,16,133,32,148,1]
#[rustfmt::skip]
const L_COEFFS: [u8; 16] = [
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
];

/// Multiply in GF(2^8) with modulus 0xC3 (x^8+x^7+x^6+x+1)
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0xC3;
        }
        b >>= 1;
    }
    result
}

/// R transform: one application of the LFSR on a 128-bit block (as 16 bytes, little-endian lane order)
/// The LFSR output byte is XOR of L_COEFFS[i] * state[i] for i in 0..16,
/// then the block is shifted right by 1 byte and the result is placed in position 0.
fn r_transform(block: &mut [u8; 16]) {
    let mut l = 0u8;
    for i in 0..16 {
        l ^= gf_mul(block[i], L_COEFFS[i]);
    }
    // shift right (toward higher index), place l at index 15 -> actually:
    // R shifts the vector: a_{15}|a_{14}|...|a_0  -> l(a)|a_{15}|...|a_1
    // In our byte layout block[0] = a_0, block[15] = a_{15}
    // After R: block[0]=l, block[i]=old block[i-1] for i in 1..16
    let tmp = *block;
    block[0] = l;
    block[1..16].copy_from_slice(&tmp[0..15]);
}

/// Inverse R transform
fn r_inv_transform(block: &mut [u8; 16]) {
    // R maps a_15|...|a_0 -> l(a)|a_15|...|a_1, so the inverse recovers
    // a_i = b_{i-1} for i in 1..16 and a_0 = b_15 XOR (sum of k_i * a_i, i>=1)
    // (k_0 = 1, so a_0 drops out of the LFSR feedback).
    // In our byte layout block[0] = a_15 ... block[15] = a_0:
    // shift left first, then block[15] = old block[0] XOR LFSR(block[0..15]).
    let tmp = *block;
    block[0..15].copy_from_slice(&tmp[1..16]);
    let mut l = 0u8;
    for i in 0..15 {
        l ^= gf_mul(block[i], L_COEFFS[i]);
    }
    block[15] = tmp[0] ^ l;
}

/// L transform: apply R 16 times
fn l_transform(block: &mut [u8; 16]) {
    for _ in 0..16 {
        r_transform(block);
    }
}

/// Inverse L transform
fn l_inv_transform(block: &mut [u8; 16]) {
    for _ in 0..16 {
        r_inv_transform(block);
    }
}

/// S transform: apply PI to each byte
fn s_transform(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        *b = PI[*b as usize];
    }
}

/// Inverse S transform
fn s_inv_transform(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        *b = PI_INV[*b as usize];
    }
}

/// X transform: XOR with round key
fn x_transform(block: &mut [u8; 16], key: &[u8; 16]) {
    for i in 0..16 {
        block[i] ^= key[i];
    }
}

/// LSX = L(S(X(k, a)))
fn lsx(block: &mut [u8; 16], key: &[u8; 16]) {
    x_transform(block, key);
    s_transform(block);
    l_transform(block);
}

/// F function used in key schedule:  F[k](a1,a0) = (LSX(k,a1) XOR a0, a1)
fn f_func(k: &[u8; 16], a1: &mut [u8; 16], a0: &mut [u8; 16]) {
    let mut tmp = *a1;
    lsx(&mut tmp, k);
    for i in 0..16 {
        tmp[i] ^= a0[i];
    }
    *a0 = *a1;
    *a1 = tmp;
}

// Iteration constants C[i] = L(i) for i = 1..32
// We compute them lazily. Actually let's precompute in the key schedule.
fn iteration_constant(n: usize) -> [u8; 16] {
    // C_i = L(Vec_128(i)) where Vec_128(i) is i encoded as a 128-bit
    // little-endian integer, i.e. a_0 = i and a_1..a_15 = 0.
    // In our byte layout block[0] = a_15 ... block[15] = a_0, so block[15] = i.
    let mut block = [0u8; 16];
    block[15] = n as u8;
    l_transform(&mut block);
    block
}

/// Kuznyechik cipher struct holding 10 round keys (each 16 bytes)
pub struct Kuznyechik {
    round_keys: [[u8; 16]; 10],
}

impl Kuznyechik {
    /// Create from a 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        let mut rk = [[0u8; 16]; 10];

        // Split key into two 128-bit halves
        let mut kr0 = [0u8; 16];
        let mut kr1 = [0u8; 16];
        kr0.copy_from_slice(&key[0..16]);
        kr1.copy_from_slice(&key[16..32]);

        rk[0] = kr0;
        rk[1] = kr1;

        // Key schedule: generate 10 round keys using the F function
        // Round keys are produced in pairs: (K_{2i}, K_{2i+1}) from (K_{2i-2}, K_{2i-1})
        // using 8 iterations of F with constants C_1..C_8 per pair
        let mut a1 = kr0;
        let mut a0 = kr1;

        let mut key_idx = 2;
        let mut const_idx = 1usize;

        while key_idx < 10 {
            // 8 rounds of F to produce next pair
            for _ in 0..8 {
                let c = iteration_constant(const_idx);
                f_func(&c, &mut a1, &mut a0);
                const_idx += 1;
            }
            rk[key_idx] = a1;
            rk[key_idx + 1] = a0;
            key_idx += 2;
        }

        Kuznyechik { round_keys: rk }
    }

    /// Encrypt a 16-byte block in place
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        // Rounds 1..9: LSX
        for i in 0..9 {
            lsx(block, &self.round_keys[i]);
        }
        // Round 10 (final): only X
        x_transform(block, &self.round_keys[9]);
    }

    /// Decrypt a 16-byte block in place
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        // Reverse: X then inverse L, inverse S, inverse X for each round
        x_transform(block, &self.round_keys[9]);
        for i in (0..9).rev() {
            l_inv_transform(block);
            s_inv_transform(block);
            x_transform(block, &self.round_keys[i]);
        }
    }
}

impl crate::xts::XtsCipher for Kuznyechik {
    fn encrypt_block_raw(&self, block: &mut [u8; 16]) {
        self.encrypt_block(block);
    }
    fn decrypt_block_raw(&self, block: &mut [u8; 16]) {
        self.decrypt_block(block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Official test vector from GOST R 34.12-2015 (section 7.1.2 example).
    #[test]
    fn gost_official_vector() {
        let key_bytes =
            from_hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        let pt_bytes = from_hex("1122334455667700ffeeddccbbaa9988");
        let ct_bytes = from_hex("7f679d90bebc24305a468d42b9d4edcd");

        let kuz = Kuznyechik::new(&key);

        let mut block = [0u8; 16];
        block.copy_from_slice(&pt_bytes);
        kuz.encrypt_block(&mut block);
        assert_eq!(
            block.to_vec(),
            ct_bytes,
            "encryption mismatch vs GOST vector"
        );

        kuz.decrypt_block(&mut block);
        assert_eq!(
            block.to_vec(),
            pt_bytes,
            "decryption mismatch vs GOST vector"
        );
    }

    /// R and R_inv must be exact inverses on arbitrary states.
    #[test]
    fn r_transform_inverse() {
        let original: [u8; 16] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
            0x99, 0x88,
        ];
        let mut b = original;
        r_transform(&mut b);
        r_inv_transform(&mut b);
        assert_eq!(b, original);
        // and the other order as well
        r_inv_transform(&mut b);
        r_transform(&mut b);
        assert_eq!(b, original);
    }

    /// L and L_inv must be exact inverses.
    #[test]
    fn l_transform_inverse() {
        let original = [0xA5u8; 16];
        let mut b = original;
        l_transform(&mut b);
        assert_ne!(b, original);
        l_inv_transform(&mut b);
        assert_eq!(b, original);
    }

    /// S and S_inv must be exact inverses over the full byte range.
    #[test]
    fn s_box_inverse() {
        for v in 0..=255u8 {
            assert_eq!(PI_INV[PI[v as usize] as usize], v);
        }
    }

    #[test]
    fn roundtrip() {
        let key = [0xABu8; 32];
        let kuz = Kuznyechik::new(&key);
        let original = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let mut block = original;
        kuz.encrypt_block(&mut block);
        assert_ne!(block, original);
        kuz.decrypt_block(&mut block);
        assert_eq!(block, original);
    }

    /// Roundtrip over several distinct keys and plaintexts.
    #[test]
    fn roundtrip_multi() {
        for k in 0..8u8 {
            let mut key = [0u8; 32];
            for (i, b) in key.iter_mut().enumerate() {
                *b = k.wrapping_mul(31).wrapping_add(i as u8);
            }
            let kuz = Kuznyechik::new(&key);
            for p in 0..8u8 {
                let mut block = [0u8; 16];
                for (i, b) in block.iter_mut().enumerate() {
                    *b = p.wrapping_mul(17).wrapping_add(i as u8);
                }
                let original = block;
                kuz.encrypt_block(&mut block);
                assert_ne!(block, original);
                kuz.decrypt_block(&mut block);
                assert_eq!(block, original);
            }
        }
    }
}
