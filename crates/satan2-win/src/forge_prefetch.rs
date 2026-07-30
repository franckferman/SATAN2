// Create fake Windows Prefetch files (.pf) in C:\Windows\Prefetch\.
//
// Win10/11 use MAM-compressed v30 format:
//   [4D 41 4D 04][decompressed_size u32 LE][RtlCompressBuffer XPRESS-Huffman payload]
// RtlCompressBuffer is called dynamically from ntdll (not exposed by windows-sys).
// Falls back to uncompressed v23 if ntdll symbols are unavailable.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self {
        Lcg(seed as u64 ^ 0xdead_beef_1234_abcd)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + (self.next() % (hi - lo))
    }
}

// ── Prefetch hash algorithm ───────────────────────────────────────────────────
// Hsieh SuperFastHash variant used by Windows Prefetch system

fn prefetch_hash(path: &str) -> u32 {
    let upper_w: Vec<u16> = path.to_uppercase().encode_utf16().collect();
    let mut hash: u64 = 0x314B5A4B;
    for &wc in &upper_w {
        hash = hash.wrapping_mul(37).wrapping_add(wc as u64);
    }
    (hash & 0xFFFF_FFFF) as u32
}

// ── MAM compression (Win8+ Prefetch wrapper) ──────────────────────────────────
//
// MAM file layout:
//   Bytes 0-2  : 0x4D 0x41 0x4D  ("MAM")
//   Byte  3    : 0x04             (algorithm = XPRESS Huffman)
//   Bytes 4-7  : decompressed size (u32 LE)
//   Bytes 8+   : RtlCompressBuffer output (XPRESS Huffman)

const MAM_ALGO: u8 = 0x04;
// COMPRESSION_FORMAT_XPRESS_HUFF (0x0004) | COMPRESSION_ENGINE_MAXIMUM (0x0100)
const XPRESS_HUFF_MAX: u16 = 0x0104;

type FnGetWorkspaceSize = unsafe extern "system" fn(
    CompressionFormatAndEngine: u16,
    CompressWorkSpaceSize: *mut u32,
    FragmentWorkSpaceSize: *mut u32,
) -> i32;

type FnCompressBuffer = unsafe extern "system" fn(
    CompressionFormatAndEngine: u16,
    UncompressedBuffer: *const u8,
    UncompressedBufferSize: u32,
    CompressedBuffer: *mut u8,
    CompressedBufferSize: u32,
    UncompressedChunkSize: u32,
    FinalCompressedSize: *mut u32,
    WorkSpace: *mut core::ffi::c_void,
) -> i32;

fn compress_mam(raw: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hmod = LoadLibraryW(ntdll_w.as_ptr());
        if hmod.is_null() {
            return None;
        }

        // GetProcAddress returns FARPROC = Option<unsafe extern "system" fn() -> isize>
        let gws_raw = GetProcAddress(hmod, c"RtlGetCompressionWorkSpaceSize".as_ptr().cast())?;
        let cmp_raw = GetProcAddress(hmod, c"RtlCompressBuffer".as_ptr().cast())?;

        let get_ws: FnGetWorkspaceSize = std::mem::transmute(gws_raw);
        let compress: FnCompressBuffer = std::mem::transmute(cmp_raw);

        let mut ws_size: u32 = 0;
        let mut frag_size: u32 = 0;
        // NTSTATUS 0 = STATUS_SUCCESS
        if get_ws(XPRESS_HUFF_MAX, &mut ws_size, &mut frag_size) != 0 {
            return None;
        }

        let mut workspace = vec![0u8; ws_size as usize];
        // Allocate 2× + slack; XPRESS-Huff can expand small incompressible inputs
        let out_cap = (raw.len() as u32).saturating_mul(2).saturating_add(4096);
        let mut compressed = vec![0u8; out_cap as usize];
        let mut final_size: u32 = 0;

        let status = compress(
            XPRESS_HUFF_MAX,
            raw.as_ptr(),
            raw.len() as u32,
            compressed.as_mut_ptr(),
            out_cap,
            4096, // standard chunk size for Prefetch MAM
            &mut final_size,
            workspace.as_mut_ptr() as *mut core::ffi::c_void,
        );
        if status != 0 {
            return None;
        }
        compressed.truncate(final_size as usize);

        // Build MAM wrapper: 4-byte magic+algo, 4-byte decompressed size, payload
        let mut out = Vec::with_capacity(8 + compressed.len());
        out.extend_from_slice(&[0x4D, 0x41, 0x4D, MAM_ALGO]); // "MAM\x04"
        out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        out.extend_from_slice(&compressed);
        Some(out)
    }
}

// ── Prefetch file builder ─────────────────────────────────────────────────────

// Prefetch header layout (common to v23 and v30):
//   0x00  Version (DWORD)         = 23 or 30
//   0x04  Signature "SCCA" (4B)
//   0x08  Unknown (DWORD)         = 0x0F000000
//   0x0C  File size (DWORD)       — total bytes (decompressed size for v30 inside MAM)
//   0x10  Exe name (char[60] — 30 UTF-16LE wide chars, zero-padded)
//   0x4C  Prefetch hash (DWORD)
//   0x50  Unknown flags (DWORD)   = 0
// Total: 84 bytes
//
// Section header table (32 bytes at offset 84):
//   section A offset/count, B offset/count, C offset/size, D offset/count

fn build_pf_inner(
    exe_name: &str,
    exe_path: &str,
    run_count: u32,
    last_run_ts: u64,
    version: u32,
) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let hash = prefetch_hash(exe_path);

    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(b"SCCA");
    buf.extend_from_slice(&0x0F000000u32.to_le_bytes());
    let size_offset = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes()); // file size — patched at end

    // Exe name: 30 UTF-16LE wide chars (60 bytes), zero-padded
    let name_upper = exe_name.to_uppercase();
    let wchars: Vec<u16> = name_upper.encode_utf16().take(29).collect();
    for &wc in &wchars {
        buf.extend_from_slice(&wc.to_le_bytes());
    }
    for _ in 0..(30 - wchars.len()) {
        buf.extend_from_slice(&0u16.to_le_bytes());
    }

    buf.extend_from_slice(&hash.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags

    // Section header (32 bytes at offset 84)
    let section_a_off = 116u32;
    let section_a_cnt = 1u32;
    let section_b_off = section_a_off + 36;
    let section_b_cnt = 1u32;
    let section_c_off = section_b_off + 12;
    let paths_bytes = build_paths_section(exe_path);
    let section_c_sz = paths_bytes.len() as u32;
    let section_d_off = section_c_off + section_c_sz;
    let section_d_cnt = 1u32;

    buf.extend_from_slice(&section_a_off.to_le_bytes());
    buf.extend_from_slice(&section_a_cnt.to_le_bytes());
    buf.extend_from_slice(&section_b_off.to_le_bytes());
    buf.extend_from_slice(&section_b_cnt.to_le_bytes());
    buf.extend_from_slice(&section_c_off.to_le_bytes());
    buf.extend_from_slice(&section_c_sz.to_le_bytes());
    buf.extend_from_slice(&section_d_off.to_le_bytes());
    buf.extend_from_slice(&section_d_cnt.to_le_bytes());

    // Section A: file metrics (36 bytes per entry)
    buf.extend_from_slice(&0u32.to_le_bytes()); // start_time
    buf.extend_from_slice(&10u32.to_le_bytes()); // duration ms
    buf.extend_from_slice(&10u32.to_le_bytes()); // avg_duration
    buf.extend_from_slice(&0u32.to_le_bytes()); // filename offset in section C
    let path_wchars = (exe_path.encode_utf16().count() + 1) as u32;
    buf.extend_from_slice(&path_wchars.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags
    buf.extend_from_slice(&0u64.to_le_bytes()); // file_ref

    // Section B: trace chains (12 bytes per entry)
    buf.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // next = none
    buf.extend_from_slice(&1u32.to_le_bytes()); // block load count
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags/duration

    // Section C: referenced filenames (UTF-16LE, null-terminated)
    buf.extend_from_slice(&paths_bytes);

    // Section D: volume info (104-byte fixed entry + device path UTF-16LE)
    let vol_path = r"\DEVICE\HARDDISKVOLUME2";
    let vol_wchars: Vec<u16> = vol_path.encode_utf16().collect();
    let vol_path_offset = 104u32; // offset from section D start to path data
    buf.extend_from_slice(&vol_path_offset.to_le_bytes());
    buf.extend_from_slice(&(vol_wchars.len() as u32 + 1).to_le_bytes());
    buf.extend_from_slice(&last_run_ts.to_le_bytes()); // FILETIME as volume creation time
    buf.extend_from_slice(&0xAB1234CDu32.to_le_bytes()); // fake serial number
    buf.extend_from_slice(&0u32.to_le_bytes()); // file_refs offset
    buf.extend_from_slice(&0u32.to_le_bytes()); // file_refs size
    buf.extend_from_slice(&0u32.to_le_bytes()); // dir strings offset
    buf.extend_from_slice(&1u32.to_le_bytes()); // dir strings count
    buf.extend_from_slice(&[0u8; 28]); // unknown
    for &wc in &vol_wchars {
        buf.extend_from_slice(&wc.to_le_bytes());
    }
    buf.extend_from_slice(&[0u8; 2]); // null terminator

    // Run count + last run timestamp (section D extended area, v23/v30 compatible)
    buf.extend_from_slice(&run_count.to_le_bytes());
    buf.extend_from_slice(&last_run_ts.to_le_bytes());

    let total_size = buf.len() as u32;
    buf[size_offset..size_offset + 4].copy_from_slice(&total_size.to_le_bytes());
    buf
}

fn build_paths_section(path: &str) -> Vec<u8> {
    let upper = path.to_uppercase();
    let wchars: Vec<u16> = upper.encode_utf16().collect();
    let mut sec = Vec::new();
    for &wc in &wchars {
        sec.extend_from_slice(&wc.to_le_bytes());
    }
    sec.extend_from_slice(&0u16.to_le_bytes());
    sec
}

fn unix_to_filetime(unix_ts: i64) -> u64 {
    ((unix_ts + 11_644_473_600i64) as u64) * 10_000_000
}

// ── Fake executables ──────────────────────────────────────────────────────────

const FAKE_EXES: &[(&str, &str)] = &[
    (
        "CHROME.EXE",
        r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES (X86)\GOOGLE\CHROME\APPLICATION\CHROME.EXE",
    ),
    (
        "FIREFOX.EXE",
        r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES\MOZILLA FIREFOX\FIREFOX.EXE",
    ),
    (
        "OUTLOOK.EXE",
        r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES\MICROSOFT OFFICE\ROOT\OFFICE16\OUTLOOK.EXE",
    ),
    (
        "WINWORD.EXE",
        r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES\MICROSOFT OFFICE\ROOT\OFFICE16\WINWORD.EXE",
    ),
    (
        "EXCEL.EXE",
        r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES\MICROSOFT OFFICE\ROOT\OFFICE16\EXCEL.EXE",
    ),
    (
        "POWERPNT.EXE",
        r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES\MICROSOFT OFFICE\ROOT\OFFICE16\POWERPNT.EXE",
    ),
    (
        "TEAMS.EXE",
        r"\DEVICE\HARDDISKVOLUME2\USERS\USER\APPDATA\LOCAL\MICROSOFT\TEAMS\CURRENT\TEAMS.EXE",
    ),
    (
        "EXPLORER.EXE",
        r"\DEVICE\HARDDISKVOLUME2\WINDOWS\EXPLORER.EXE",
    ),
    (
        "MSPAINT.EXE",
        r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\MSPAINT.EXE",
    ),
    (
        "NOTEPAD.EXE",
        r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NOTEPAD.EXE",
    ),
    (
        "POWERSHELL.EXE",
        r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE",
    ),
    (
        "MSIEXEC.EXE",
        r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\MSIEXEC.EXE",
    ),
    (
        "WUAUCLT.EXE",
        r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\WUAUCLT.EXE",
    ),
    (
        "SVCHOST.EXE",
        r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\SVCHOST.EXE",
    ),
    (
        "ONEDRIVE.EXE",
        r"\DEVICE\HARDDISKVOLUME2\USERS\USER\APPDATA\LOCAL\MICROSOFT\ONEDRIVE\ONEDRIVE.EXE",
    ),
    (
        "SKYPE.EXE",
        r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES (X86)\MICROSOFT\SKYPE FOR DESKTOP\SKYPE.EXE",
    ),
    (
        "ACROBAT.EXE",
        r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES\ADOBE\ACROBAT DC\ACROBAT\ACROBAT.EXE",
    ),
    (
        "SLACK.EXE",
        r"\DEVICE\HARDDISKVOLUME2\USERS\USER\APPDATA\LOCAL\SLACK\SLACK.EXE",
    ),
    (
        "CODE.EXE",
        r"\DEVICE\HARDDISKVOLUME2\USERS\USER\APPDATA\LOCAL\PROGRAMS\MICROSOFT VS CODE\CODE.EXE",
    ),
    (
        "WINZIP32.EXE",
        r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES\WINZIP\WINZIP32.EXE",
    ),
];

// ── Public API ────────────────────────────────────────────────────────────────

pub struct PrefetchForgeOpts {
    pub n_files: u32,
    pub ts_base: i64,
    pub verbose: bool,
}

#[derive(Default)]
pub struct PrefetchForgeStats {
    pub files_written: u32,
    pub mam_compressed: u32, // files written in v30 MAM format
    pub errors: u32,
}

pub fn forge_prefetch(opts: &PrefetchForgeOpts) -> PrefetchForgeStats {
    let mut s = PrefetchForgeStats::default();
    let mut lcg = Lcg::new(opts.ts_base);

    let pf_dir = PathBuf::from(r"C:\Windows\Prefetch");
    if !pf_dir.exists() {
        if let Err(e) = fs::create_dir_all(&pf_dir) {
            if opts.verbose {
                eprintln!("[!] forge-prefetch: create dir: {}", e);
            }
            s.errors += 1;
            return s;
        }
    }

    let n = opts.n_files.min(FAKE_EXES.len() as u32) as usize;
    for &(exe_name, exe_path) in FAKE_EXES.iter().take(n) {
        let run_count = lcg.range(3, 200) as u32;
        let offset_secs = lcg.range(0, 86_400) as i64;
        let last_run_ts = unix_to_filetime(opts.ts_base - offset_secs);
        let hash_val = prefetch_hash(exe_path);

        // Try v30 MAM first; fall back to v23 uncompressed when ntdll symbols fail
        let (pf_data, is_mam) = {
            let raw_v30 = build_pf_inner(exe_name, exe_path, run_count, last_run_ts, 30);
            match compress_mam(&raw_v30) {
                Some(mam) => (mam, true),
                None => (
                    build_pf_inner(exe_name, exe_path, run_count, last_run_ts, 23),
                    false,
                ),
            }
        };

        // Filename: EXENAME-HASHVALUE.pf (hash uppercase hex, no .EXE in base name)
        let base = &exe_name[..exe_name.len() - 4];
        let pf_name = format!("{}-{:08X}.pf", base, hash_val);
        let pf_path = pf_dir.join(&pf_name);

        match fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&pf_path)
        {
            Ok(mut f) => match f.write_all(&pf_data) {
                Ok(_) => {
                    s.files_written += 1;
                    if is_mam {
                        s.mam_compressed += 1;
                    }
                    if opts.verbose {
                        eprintln!(
                            "[+] forge-prefetch: wrote {:?} ({})",
                            pf_path,
                            if is_mam { "v30 MAM" } else { "v23 fallback" }
                        );
                    }
                }
                Err(e) => {
                    s.errors += 1;
                    if opts.verbose {
                        eprintln!("[!] forge-prefetch: write {:?}: {}", pf_path, e);
                    }
                }
            },
            Err(e) => {
                s.errors += 1;
                if opts.verbose {
                    eprintln!("[!] forge-prefetch: open {:?}: {}", pf_path, e);
                }
            }
        }
    }
    s
}
