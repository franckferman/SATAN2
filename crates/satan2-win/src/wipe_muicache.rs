// Wipe (and optionally forge) the MUI Cache registry artifact.
//
// MUI Cache records every executable that has displayed a window on this system,
// along with the file description string. Persists independently of Prefetch/Amcache.
// IR teams use it to identify executables run by a user even after other artifacts
// are wiped, because it's rarely targeted by cleanup tools.
//
// Registry path (per-user):
//   HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
//
// Each value: name = full path to .exe, data = REG_SZ file description
//
// For all users: HKEY_USERS\{SID}\Software\Classes\...

use std::ptr;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW,
    RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_OPTION_NON_VOLATILE, REG_SZ,
};

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self {
        Lcg(seed as u64 ^ 0xfeed_face_cafe_1234)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct MuiCacheStats {
    pub values_deleted: u32,
    pub values_forged: u32,
    pub errors: u32,
}

const MUI_CACHE_PATH: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

fn open_muicache_key(access: u32) -> Option<HKEY> {
    let path_w = to_wide(MUI_CACHE_PATH);
    let mut hkey: HKEY = ptr::null_mut();

    let ret = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path_w.as_ptr(), 0, access, &mut hkey) };
    if ret == ERROR_SUCCESS {
        Some(hkey)
    } else {
        None
    }
}

// ── Wipe ──────────────────────────────────────────────────────────────────────

pub fn wipe_muicache(verbose: bool) -> MuiCacheStats {
    let mut s = MuiCacheStats::default();

    let hkey = match open_muicache_key(KEY_ALL_ACCESS) {
        Some(k) => k,
        None => {
            if verbose {
                eprintln!("[!] wipe-muicache: failed to open key");
            }
            s.errors += 1;
            return s;
        }
    };

    // Enumerate all value names, then delete them
    let mut value_count: u32 = 0;
    let mut max_name: u32 = 0;
    unsafe {
        RegQueryInfoKeyW(
            hkey,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut value_count,
            &mut max_name,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
    }

    let max_name = (max_name + 1) as usize;
    let mut names: Vec<String> = Vec::new();

    for i in 0..value_count {
        let mut name_buf = vec![0u16; max_name];
        let mut name_len = max_name as u32;
        let ret = unsafe {
            RegEnumValueW(
                hkey,
                i,
                name_buf.as_mut_ptr(),
                &mut name_len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ret == ERROR_SUCCESS {
            names.push(wide_to_string(&name_buf[..name_len as usize]));
        }
    }

    for name in &names {
        // Skip internal MUI keys (ApplicationCompany, etc.)
        if !name.ends_with(".exe")
            && !name.ends_with(".exe.FriendlyAppName")
            && !name.ends_with(".exe.ApplicationCompany")
        {
            continue;
        }

        let name_w = to_wide(name);
        let ret = unsafe { RegDeleteValueW(hkey, name_w.as_ptr()) };
        if ret == ERROR_SUCCESS {
            s.values_deleted += 1;
            if verbose {
                eprintln!("[+] wipe-muicache: deleted '{}'", name);
            }
        } else {
            s.errors += 1;
        }
    }

    unsafe { RegCloseKey(hkey) };
    s
}

// ── Forge ─────────────────────────────────────────────────────────────────────

const FAKE_MUI_ENTRIES: &[(&str, &str)] = &[
    (r"C:\Windows\System32\cmd.exe", "Windows Command Processor"),
    (r"C:\Windows\System32\notepad.exe", "Notepad"),
    (
        r"C:\Windows\System32\mmc.exe",
        "Microsoft Management Console",
    ),
    (r"C:\Windows\System32\taskmgr.exe", "Task Manager"),
    (r"C:\Windows\System32\regedit.exe", "Registry Editor"),
    (r"C:\Windows\System32\msiexec.exe", "Windows Installer"),
    (r"C:\Windows\System32\explorer.exe", "Windows Explorer"),
    (r"C:\Windows\System32\control.exe", "Control Panel"),
    (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "Google Chrome",
    ),
    (r"C:\Program Files\Mozilla Firefox\firefox.exe", "Firefox"),
    (
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "Microsoft Word",
    ),
    (
        r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
        "Microsoft Excel",
    ),
    (
        r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        "Microsoft Outlook",
    ),
    (r"C:\Program Files\7-Zip\7zFM.exe", "7-Zip File Manager"),
    (r"C:\Program Files\Wireshark\Wireshark.exe", "Wireshark"),
    (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "Windows PowerShell",
    ),
];

pub fn forge_muicache(n_entries: u32, verbose: bool) -> MuiCacheStats {
    let mut s = MuiCacheStats::default();

    let path_w = to_wide(MUI_CACHE_PATH);
    let mut hkey: HKEY = ptr::null_mut();
    let mut disposition: u32 = 0;

    let ret = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            path_w.as_ptr(),
            0,
            ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            ptr::null(),
            &mut hkey,
            &mut disposition,
        )
    };
    if ret != ERROR_SUCCESS {
        s.errors += 1;
        return s;
    }

    let mut lcg = Lcg::new(n_entries as i64 * 1234567);
    let n = (n_entries as usize).min(FAKE_MUI_ENTRIES.len());

    for &(path, desc) in FAKE_MUI_ENTRIES.iter().take(n) {
        let _ = lcg.next(); // consume for variation

        // Write FriendlyAppName variant
        let name_friendly = format!("{}.FriendlyAppName", path);
        let name_w = to_wide(&name_friendly);
        let desc_w: Vec<u16> = desc.encode_utf16().chain(std::iter::once(0)).collect();
        let data_bytes = desc_w.len() * 2;

        let ret = unsafe {
            RegSetValueExW(
                hkey,
                name_w.as_ptr(),
                0,
                REG_SZ,
                desc_w.as_ptr() as *const u8,
                data_bytes as u32,
            )
        };
        if ret == ERROR_SUCCESS {
            s.values_forged += 1;
            if verbose {
                eprintln!("[+] forge-muicache: {} = {}", path, desc);
            }
        } else {
            s.errors += 1;
        }
    }

    unsafe { RegCloseKey(hkey) };
    s
}
