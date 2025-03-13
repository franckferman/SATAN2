use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Registry::*;

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self { Lcg(seed as u64 ^ 0xc0ffee_dead_0000_beef) }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005)
                       .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 { lo + (self.next() % (hi - lo)) }
    fn pick<'a, T>(&mut self, s: &'a [T]) -> &'a T { &s[(self.next() as usize) % s.len()] }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// ROT13-encode the value name (UserAssist obfuscation).
fn rot13(s: &str) -> String {
    s.chars().map(|c| match c {
        'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
        'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
        _ => c,
    }).collect()
}

/// Convert Unix epoch to Windows FILETIME (100-ns intervals since 1601-01-01).
fn unix_to_filetime(ts: i64) -> u64 {
    ((ts + 11_644_473_600i64) as u64).saturating_mul(10_000_000)
}

/// Build the 24-byte binary payload for a UserAssist registry entry.
fn ua_entry_bytes(run_count: u32, focus_count: u32, focus_ms: u32, ts: i64) -> [u8; 24] {
    let mut b = [0u8; 24];
    // offset 0: DWORD padding (always 0)
    b[4..8].copy_from_slice(&run_count.to_le_bytes());
    b[8..12].copy_from_slice(&focus_count.to_le_bytes());
    b[12..16].copy_from_slice(&focus_ms.to_le_bytes());
    b[16..24].copy_from_slice(&unix_to_filetime(ts).to_le_bytes());
    b
}

// ── Constants ─────────────────────────────────────────────────────────────────

// UserAssist GUIDs (both application paths and shortcut targets are tracked)
const UA_GUIDS: &[&str] = &[
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}",
];

const FAKE_EXES: &[&str] = &[
    "C:\\Windows\\explorer.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Windows\\System32\\mmc.exe",
    "C:\\Windows\\System32\\taskmgr.exe",
    "C:\\Windows\\System32\\regedit.exe",
    "C:\\Windows\\System32\\mstsc.exe",
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Windows\\System32\\control.exe",
    "C:\\Windows\\System32\\certmgr.msc",
    "C:\\Windows\\System32\\eventvwr.msc",
    "C:\\Windows\\System32\\compmgmt.msc",
    "C:\\Windows\\System32\\secpol.msc",
    "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\ONENOTE.EXE",
    "C:\\Program Files (x86)\\Notepad++\\notepad++.exe",
    "C:\\Program Files\\PuTTY\\putty.exe",
    "C:\\Program Files\\WinRAR\\WinRAR.exe",
    "C:\\Program Files\\7-Zip\\7zFM.exe",
    "C:\\Program Files\\Git\\git-bash.exe",
    "C:\\Program Files\\Microsoft VS Code\\Code.exe",
    "C:\\Program Files\\Wireshark\\Wireshark.exe",
];

// ── Public API ────────────────────────────────────────────────────────────────

pub struct UserAssistForgeStats {
    pub entries_written: u32,
    pub errors:          u32,
}

/// Write fake UserAssist execution-count entries to HKCU.
/// ts_base: reference Unix timestamp (entries are scattered in the past week).
pub fn forge_userassist(ts_base: i64, verbose: bool) -> UserAssistForgeStats {
    let mut s   = UserAssistForgeStats { entries_written: 0, errors: 0 };
    let mut lcg = Lcg::new(ts_base);

    for &guid in UA_GUIDS {
        let key_path = format!(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{}\\Count",
            guid
        );
        let kp_w = wstr(&key_path);
        let mut hkey: HKEY = 0;
        let mut disposition: u32 = 0;

        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                kp_w.as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                null(),
                &mut hkey,
                &mut disposition,
            )
        };

        if rc != 0 {
            s.errors += 1;
            if verbose { eprintln!("[!] forge-ua: RegCreateKeyEx {}: {}", guid, rc); }
            continue;
        }

        // Write a subset of FAKE_EXES per GUID to keep it realistic
        let n_exe = lcg.range(10, FAKE_EXES.len() as u64) as usize;
        for i in 0..n_exe {
            let exe        = FAKE_EXES[i % FAKE_EXES.len()];
            let val_name   = rot13(exe);
            let val_name_w = wstr(&val_name);
            let run_count  = lcg.range(3, 80) as u32;
            let foc_count  = run_count + lcg.range(0, run_count as u64) as u32;
            let foc_ms     = lcg.range(15_000, 900_000) as u32;
            let ts_last    = ts_base - lcg.range(0, 7 * 86_400) as i64;
            let data       = ua_entry_bytes(run_count, foc_count, foc_ms, ts_last);

            let ret = unsafe {
                RegSetValueExW(
                    hkey,
                    val_name_w.as_ptr(),
                    0,
                    REG_BINARY,
                    data.as_ptr(),
                    data.len() as u32,
                )
            };

            if ret == 0 {
                s.entries_written += 1;
                if verbose { eprintln!("[+] forge-ua: {} (run={})", exe, run_count); }
            } else {
                s.errors += 1;
                if verbose { eprintln!("[!] forge-ua: RegSetValueEx {}: {}", exe, ret); }
            }
        }

        unsafe { RegCloseKey(hkey) };
    }

    s
}
