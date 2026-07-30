// Create fake Windows LNK (Shell Link) files in %APPDATA%\Microsoft\Windows\Recent\.
// Format: MS-SHLLINK v1 — header + StringData (no IDList to keep size minimal).
// Forensic tools parse LNK timestamps and target paths for timeline reconstruction.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self {
        Lcg(seed as u64 ^ 0x1e7c_0ffe_e000_0000)
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

// Windows FILETIME: 100-ns intervals since 1601-01-01
fn unix_to_filetime(ts: i64) -> u64 {
    ((ts + 11_644_473_600) * 10_000_000) as u64
}

// ── LNK binary builder ────────────────────────────────────────────────────────
//
// [MS-SHLLINK] 2.1 — Shell Link Header (76 bytes):
//   0x00  HeaderSize (DWORD)      = 0x4C
//   0x04  LinkCLSID (16 bytes)    = {00021401-0000-0000-C000-000000000046}
//   0x14  LinkFlags (DWORD)
//   0x18  FileAttributes (DWORD)
//   0x1C  CreationTime (FILETIME = 8 bytes)
//   0x24  AccessTime (FILETIME)
//   0x2C  WriteTime (FILETIME)
//   0x34  FileSize (DWORD)
//   0x38  IconIndex (DWORD)
//   0x3C  ShowCommand (DWORD)
//   0x40  HotKey (WORD)
//   0x42  Reserved1 (WORD)
//   0x44  Reserved2 (DWORD)
//   0x48  Reserved3 (DWORD)
//   Total: 0x4C = 76 bytes
//
// StringData (section 2.4):
//   For each set flag (in order: NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON):
//     CountCharacters (WORD)
//     String (WCHAR[CountCharacters]) — no null terminator, IsUnicode flag set

// LinkFlags relevant bits:
//   Bit 3  HasRelativePath    (0x08)
//   Bit 4  HasWorkingDir      (0x10)
//   Bit 7  IsUnicode          (0x80)
const LINK_FLAGS: u32 = 0x98; // HasRelativePath | HasWorkingDir | IsUnicode

// {00021401-0000-0000-C000-000000000046} in little-endian byte order
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, // Data1 = 0x00021401 (LE)
    0x00, 0x00, // Data2 = 0x0000 (LE)
    0x00, 0x00, // Data3 = 0x0000 (LE)
    0xC0, 0x00, // Data4[0..1]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x46, // Data4[2..7]
];

fn write_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn write_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_string_data(buf: &mut Vec<u8>, s: &str) {
    let wchars: Vec<u16> = s.encode_utf16().collect();
    write_u16_le(buf, wchars.len() as u16);
    for &wc in &wchars {
        write_u16_le(buf, wc);
    }
}

fn build_lnk(
    target: &str,
    working_dir: &str,
    ts_create: i64,
    ts_access: i64,
    ts_write: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // Header
    write_u32_le(&mut buf, 0x4C); // HeaderSize
    buf.extend_from_slice(&LINK_CLSID); // LinkCLSID
    write_u32_le(&mut buf, LINK_FLAGS); // LinkFlags
    write_u32_le(&mut buf, 0x00000020); // FileAttributes = FILE_ATTRIBUTE_ARCHIVE
    write_u64_le(&mut buf, unix_to_filetime(ts_create)); // CreationTime
    write_u64_le(&mut buf, unix_to_filetime(ts_access)); // AccessTime
    write_u64_le(&mut buf, unix_to_filetime(ts_write)); // WriteTime
    write_u32_le(&mut buf, 0); // FileSize
    write_u32_le(&mut buf, 0); // IconIndex
    write_u32_le(&mut buf, 1); // ShowCommand = SW_SHOWNORMAL
    write_u16_le(&mut buf, 0); // HotKey
    write_u16_le(&mut buf, 0); // Reserved1
    write_u32_le(&mut buf, 0); // Reserved2
    write_u32_le(&mut buf, 0); // Reserved3

    // StringData: RelativePath (HasRelativePath bit 3)
    write_string_data(&mut buf, target);
    // StringData: WorkingDir (HasWorkingDir bit 4)
    write_string_data(&mut buf, working_dir);

    buf
}

// ── Fake LNK targets ─────────────────────────────────────────────────────────

const FAKE_LINKS: &[(&str, &str, &str)] = &[
    // (target_path, working_dir, lnk_name)
    (
        r"C:\Users\user\Documents\Q4_Report_2025.xlsx",
        r"C:\Users\user\Documents",
        "Q4_Report_2025.xlsx.lnk",
    ),
    (
        r"C:\Users\user\Documents\Budget_2026.xlsx",
        r"C:\Users\user\Documents",
        "Budget_2026.xlsx.lnk",
    ),
    (
        r"C:\Users\user\Downloads\setup_chrome_installer.exe",
        r"C:\Users\user\Downloads",
        "setup_chrome_installer.exe.lnk",
    ),
    (
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        r"C:\Users\user\Documents",
        "WINWORD.EXE.lnk",
    ),
    (
        r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
        r"C:\Users\user\Documents",
        "EXCEL.EXE.lnk",
    ),
    (
        r"C:\Users\user\Desktop\Notes.txt",
        r"C:\Users\user\Desktop",
        "Notes.txt.lnk",
    ),
    (
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32",
        "cmd.exe.lnk",
    ),
    (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0",
        "powershell.exe.lnk",
    ),
    (
        r"C:\Users\user\Downloads\VLC-3.0.20-win64.exe",
        r"C:\Users\user\Downloads",
        "VLC-3.0.20-win64.exe.lnk",
    ),
    (
        r"C:\Program Files\7-Zip\7zFM.exe",
        r"C:\Program Files\7-Zip",
        "7zFM.exe.lnk",
    ),
    (
        r"C:\Users\user\Documents\Presentations\Q1_Kickoff.pptx",
        r"C:\Users\user\Documents\Presentations",
        "Q1_Kickoff.pptx.lnk",
    ),
    (
        r"C:\Users\user\Pictures\vacation_2025.jpg",
        r"C:\Users\user\Pictures",
        "vacation_2025.jpg.lnk",
    ),
    (
        r"C:\Users\user\Documents\contracts\NDA_signed.pdf",
        r"C:\Users\user\Documents\contracts",
        "NDA_signed.pdf.lnk",
    ),
    (
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Slack\Slack.lnk",
        r"C:\Users\user\AppData\Local\slack",
        "Slack.lnk",
    ),
    (
        r"C:\Users\user\AppData\Local\Programs\Microsoft VS Code\Code.exe",
        r"C:\Users\user",
        "Code.exe.lnk",
    ),
    (
        r"C:\Users\user\Documents\server_list.txt",
        r"C:\Users\user\Documents",
        "server_list.txt.lnk",
    ),
    (
        r"C:\Windows\System32\mmc.exe",
        r"C:\Windows\System32",
        "mmc.exe.lnk",
    ),
    (
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files\Wireshark",
        "Wireshark.exe.lnk",
    ),
    (
        r"C:\Users\user\Documents\logs_analysis.py",
        r"C:\Users\user\Documents",
        "logs_analysis.py.lnk",
    ),
    (
        r"C:\Users\user\Downloads\AnyDesk.exe",
        r"C:\Users\user\Downloads",
        "AnyDesk.exe.lnk",
    ),
];

// ── Public API ────────────────────────────────────────────────────────────────

pub struct LnkForgeOpts {
    pub n_files: u32,
    pub ts_base: i64,
    pub verbose: bool,
}

#[derive(Default)]
pub struct LnkForgeStats {
    pub files_written: u32,
    pub errors: u32,
}

pub fn forge_lnk(opts: &LnkForgeOpts) -> LnkForgeStats {
    let mut s = LnkForgeStats::default();
    let mut lcg = Lcg::new(opts.ts_base);

    // Find Recent folder for all user profiles
    let users_dir = PathBuf::from(r"C:\Users");
    let user_dirs: Vec<PathBuf> = if users_dir.is_dir() {
        fs::read_dir(&users_dir)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect()
    } else {
        std::env::var("USERPROFILE")
            .ok()
            .into_iter()
            .map(PathBuf::from)
            .collect()
    };

    for user_dir in &user_dirs {
        let recent = user_dir.join(r"AppData\Roaming\Microsoft\Windows\Recent");
        if !recent.exists() {
            continue;
        }

        let n = opts.n_files.min(FAKE_LINKS.len() as u32) as usize;
        for &(target, working_dir, lnk_name) in FAKE_LINKS.iter().take(n) {
            let offset = lcg.range(0, 604_800) as i64; // up to 7 days back
            let ts_write = opts.ts_base - offset;
            let ts_access = ts_write + lcg.range(0, 3600) as i64;
            let ts_create = ts_write - lcg.range(3600, 86_400) as i64;

            let lnk_data = build_lnk(target, working_dir, ts_create, ts_access, ts_write);
            let out_path = recent.join(lnk_name);

            match fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&out_path)
            {
                Ok(mut f) => {
                    if f.write_all(&lnk_data).is_ok() {
                        s.files_written += 1;
                        if opts.verbose {
                            eprintln!("[+] forge-lnk: wrote {:?}", out_path);
                        }
                    } else {
                        s.errors += 1;
                    }
                }
                Err(e) => {
                    s.errors += 1;
                    if opts.verbose {
                        eprintln!("[!] forge-lnk: {:?}: {}", out_path, e);
                    }
                }
            }
        }
    }
    s
}
