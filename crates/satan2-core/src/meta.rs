/*
 * meta.rs — Timestamp scrambling, file signature masking, xattr removal
 *
 * ctime cannot be set directly (kernel updates it on any metadata write).
 * We set atime + mtime via utimensat(). ctime ends up as "now" — unavoidable
 * without kernel patches or mounting with noatime.
 */

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use walkdir::WalkDir;

use crate::{fill_random, rand_u32, Result};

// ── Timestamp strategy ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum TsStrategy {
    RandomPlausible, // 2000-01-01 to 2024-01-01
    RandomFull,      // full i64 range
    Epoch,           // Unix epoch 0
    Clone,           // copy from reference file
}

const TS_PLAUSIBLE_MIN: i64 = 946_684_800;  // 2000-01-01
const TS_PLAUSIBLE_MAX: i64 = 1_704_067_200; // 2024-01-01

fn random_ts(strategy: TsStrategy) -> i64 {
    match strategy {
        TsStrategy::RandomPlausible => {
            let range = (TS_PLAUSIBLE_MAX - TS_PLAUSIBLE_MIN) as u64;
            TS_PLAUSIBLE_MIN + (rand_u32() as u64 % range) as i64
        }
        TsStrategy::RandomFull => rand_u32() as i64,
        TsStrategy::Epoch      => 0,
        TsStrategy::Clone      => unreachable!(),
    }
}

pub fn meta_scramble_timestamps(path: &str, strategy: TsStrategy, ref_path: Option<&str>) -> Result<()> {
    let (atime_sec, mtime_sec) = if let TsStrategy::Clone = strategy {
        let rp = ref_path.ok_or("TS_CLONE requires a reference path")?;
        let meta = std::fs::metadata(rp).map_err(|e| e.to_string())?;
        use std::os::unix::fs::MetadataExt;
        (meta.atime(), meta.mtime())
    } else {
        (random_ts(strategy), random_ts(strategy))
    };

    let times = [
        libc::timespec { tv_sec: atime_sec, tv_nsec: 0 },
        libc::timespec { tv_sec: mtime_sec, tv_nsec: 0 },
    ];

    let path_c = CString::new(path).map_err(|e| e.to_string())?;
    let r = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path_c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };

    if r < 0 {
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::EPERM { return Ok(()); } // silently skip immutable/proc files
        return Err(format!("utimensat {}: errno={}", path, errno));
    }
    Ok(())
}

// ── Extended attributes ───────────────────────────────────────────────────────

pub fn meta_clear_xattrs(path: &str) -> Result<()> {
    let path_c = CString::new(path).map_err(|e| e.to_string())?;

    // Get list size
    let list_size = unsafe {
        libc::llistxattr(path_c.as_ptr(), std::ptr::null_mut(), 0)
    };
    if list_size <= 0 { return Ok(()); }

    let mut list = vec![0u8; list_size as usize];
    let r = unsafe {
        libc::llistxattr(path_c.as_ptr(), list.as_mut_ptr() as *mut libc::c_char, list.len())
    };
    if r <= 0 { return Ok(()); }

    // Each attribute name is NUL-terminated in the list
    let mut pos = 0usize;
    while pos < r as usize {
        let end = list[pos..].iter().position(|&b| b == 0).unwrap_or(r as usize - pos);
        if end == 0 { pos += 1; continue; }

        let name = CString::new(&list[pos..pos + end]).map_err(|e| e.to_string())?;
        unsafe { libc::lremovexattr(path_c.as_ptr(), name.as_ptr()) };
        pos += end + 1;
    }
    Ok(())
}

// ── File signature masking ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum SigStrategy {
    Zero,
    Random,
}

struct SigEntry {
    name:   &'static str,
    offset: usize,
    magic:  &'static [u8],
}

static SIG_TABLE: &[SigEntry] = &[
    SigEntry { name: "PDF",      offset: 0,    magic: b"%PDF"              },
    SigEntry { name: "OLE2",     offset: 0,    magic: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" },
    SigEntry { name: "ZIP",      offset: 0,    magic: b"PK\x03\x04"        },
    SigEntry { name: "GZIP",     offset: 0,    magic: b"\x1F\x8B"          },
    SigEntry { name: "BZIP2",    offset: 0,    magic: b"BZh"               },
    SigEntry { name: "XZ",       offset: 0,    magic: b"\xFD7zXZ\x00"      },
    SigEntry { name: "7ZIP",     offset: 0,    magic: b"7z\xBC\xAF\x27\x1C"},
    SigEntry { name: "RAR4",     offset: 0,    magic: b"Rar!\x1A\x07\x00"  },
    SigEntry { name: "RAR5",     offset: 0,    magic: b"Rar!\x1A\x07\x01\x00" },
    SigEntry { name: "JPEG",     offset: 0,    magic: b"\xFF\xD8\xFF"       },
    SigEntry { name: "PNG",      offset: 0,    magic: b"\x89PNG\r\n\x1A\n" },
    SigEntry { name: "GIF87",    offset: 0,    magic: b"GIF87a"            },
    SigEntry { name: "GIF89",    offset: 0,    magic: b"GIF89a"            },
    SigEntry { name: "BMP",      offset: 0,    magic: b"BM"                },
    SigEntry { name: "TIFF-LE",  offset: 0,    magic: b"II\x2A\x00"        },
    SigEntry { name: "TIFF-BE",  offset: 0,    magic: b"MM\x00\x2A"        },
    SigEntry { name: "ELF",      offset: 0,    magic: b"\x7FELF"           },
    SigEntry { name: "PE/MZ",    offset: 0,    magic: b"MZ"                },
    SigEntry { name: "SQLite",   offset: 0,    magic: b"SQLite format 3\x00" },
    SigEntry { name: "PCAP",     offset: 0,    magic: b"\xD4\xC3\xB2\xA1" },
    SigEntry { name: "PCAPNG",   offset: 0,    magic: b"\x0A\x0D\x0D\x0A" },
    SigEntry { name: "EVTX",     offset: 0,    magic: b"ElfFile\x00"       },
    SigEntry { name: "REGF",     offset: 0,    magic: b"regf"              },
    SigEntry { name: "LNK",      offset: 0,    magic: b"\x4C\x00\x00\x00\x01\x14\x02\x00" },
    SigEntry { name: "EXT4-SB",  offset: 1080, magic: b"\x53\xEF"          },
];

fn mask_zip_eocd(f: &mut File, file_size: u64) -> bool {
    // Search backwards for PK\x05\x06 (End of Central Directory)
    let search_len = file_size.min(65536 + 22) as usize;
    let search_start = file_size.saturating_sub(search_len as u64);

    if f.seek(SeekFrom::Start(search_start)).is_err() { return false; }
    let mut buf = vec![0u8; search_len];
    if f.read_exact(&mut buf).is_err() { return false; }

    for i in (0..buf.len().saturating_sub(4)).rev() {
        if &buf[i..i+4] == b"PK\x05\x06" {
            let eocd_offset = search_start + i as u64;
            if f.seek(SeekFrom::Start(eocd_offset)).is_ok() {
                let _ = f.write_all(&[0u8; 4]);
            }
            return true;
        }
    }
    false
}

pub fn meta_mask_signature(path: &str, strategy: SigStrategy) -> Result<()> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;

    let file_size = f.metadata().map_err(|e| e.to_string())?.len();

    // Read probe buffer (up to 2 KiB covers all signature offsets in the table)
    let probe_len = (file_size as usize).min(2048);
    let mut probe = vec![0u8; probe_len];
    f.read_exact(&mut probe).map_err(|e| e.to_string())?;

    let mut matched = false;
    let mut is_zip = false;

    for sig in SIG_TABLE {
        let end = sig.offset + sig.magic.len();
        if end > probe.len() { continue; }
        if &probe[sig.offset..end] != sig.magic { continue; }

        matched = true;
        if sig.name == "ZIP" { is_zip = true; }

        let mask: Vec<u8> = match strategy {
            SigStrategy::Zero   => vec![0u8; sig.magic.len()],
            SigStrategy::Random => {
                let mut v = vec![0u8; sig.magic.len()];
                fill_random(&mut v);
                v
            }
        };

        f.seek(SeekFrom::Start(sig.offset as u64)).map_err(|e| e.to_string())?;
        f.write_all(&mask).map_err(|e| e.to_string())?;
    }

    // For ZIP: also destroy the End of Central Directory record
    if is_zip {
        mask_zip_eocd(&mut f, file_size);
    }

    if matched {
        f.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ── Options ───────────────────────────────────────────────────────────────────

pub struct MetaOpts {
    pub do_timestamps: bool,
    pub do_sig_mask:   bool,
    pub do_xattrs:     bool,
    pub recursive:     bool,
    pub ts_strategy:   TsStrategy,
    pub ts_clone_ref:  Option<String>,
    pub sig_strategy:  SigStrategy,
    pub verbose:       bool,
}

// ── Process single path or walk tree ─────────────────────────────────────────

fn process_one(path: &str, opts: &MetaOpts) -> Result<()> {
    if opts.do_sig_mask {
        // Only regular files for signature masking
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.is_file() {
                let _ = meta_mask_signature(path, opts.sig_strategy);
            }
        }
    }

    if opts.do_xattrs {
        let _ = meta_clear_xattrs(path);
    }

    if opts.do_timestamps {
        let ref_path = opts.ts_clone_ref.as_deref();
        let _ = meta_scramble_timestamps(path, opts.ts_strategy, ref_path);
    }

    Ok(())
}

pub fn meta_process(path: &str, opts: &MetaOpts) -> Result<()> {
    let p = Path::new(path);

    if !opts.recursive || !p.is_dir() {
        return process_one(path, opts);
    }

    // Recursive walk, contents_first (post-order) so directory timestamps
    // are set after all children — otherwise child writes update parent mtime.
    let walker = WalkDir::new(path)
        .follow_links(false)
        .contents_first(true);

    for entry in walker {
        let entry = entry.map_err(|e| e.to_string())?;
        process_one(entry.path().to_str().unwrap_or(""), opts)?;
    }

    Ok(())
}
