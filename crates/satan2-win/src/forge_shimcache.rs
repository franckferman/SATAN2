// Inject fake entries into Windows AppCompatCache (ShimCache).
// Registry value: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
// Value name: AppCompatCache (REG_BINARY)
// Format: Win10 1607+ binary layout (entry_size, data_size, FILETIME, path_len, path[]).

use std::ptr;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_ALL_ACCESS, REG_BINARY, REG_OPTION_NON_VOLATILE,
};

// Windows FILETIME: 100-ns intervals since 1601-01-01
fn unix_to_filetime(ts: i64) -> u64 {
    ((ts + 11_644_473_600) * 10_000_000) as u64
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self {
        Lcg(seed as u64 ^ 0xcafe_babe_5678_90ab)
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

// ── Registry access ───────────────────────────────────────────────────────────

const APPCACHE_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
const APPCACHE_VALUE: &str = "AppCompatCache";

fn open_or_create_key() -> Option<HKEY> {
    let key_w = to_wide(APPCACHE_KEY);
    let mut hkey: HKEY = ptr::null_mut();
    let mut disposition: u32 = 0;
    let ret = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key_w.as_ptr(),
            0,
            ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            ptr::null(),
            &mut hkey,
            &mut disposition,
        )
    };
    if ret == ERROR_SUCCESS {
        Some(hkey)
    } else {
        None
    }
}

fn read_existing_value(hkey: HKEY) -> Option<Vec<u8>> {
    let name_w = to_wide(APPCACHE_VALUE);
    let mut data_size: u32 = 0;
    let mut reg_type: u32 = 0;

    // First call: get size
    let ret = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            ptr::null_mut(),
            &mut reg_type,
            ptr::null_mut(),
            &mut data_size,
        )
    };
    if ret != ERROR_SUCCESS || data_size == 0 {
        return None;
    }

    let mut buf = vec![0u8; data_size as usize];
    let ret = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            ptr::null_mut(),
            &mut reg_type,
            buf.as_mut_ptr(),
            &mut data_size,
        )
    };
    if ret == ERROR_SUCCESS {
        Some(buf)
    } else {
        None
    }
}

fn write_value(hkey: HKEY, data: &[u8]) -> bool {
    let name_w = to_wide(APPCACHE_VALUE);
    let ret = unsafe {
        RegSetValueExW(
            hkey,
            name_w.as_ptr(),
            0,
            REG_BINARY,
            data.as_ptr(),
            data.len() as u32,
        )
    };
    ret == ERROR_SUCCESS
}

// ── AppCompatCache binary format ──────────────────────────────────────────────
//
// Win10 1607+ layout (from open-source parser research):
//
// Header (48 bytes):
//   DWORD signature    (0x00000030 for most Win10 builds)
//   BYTE  padding[44]  (zeros)
//
// Entries (variable, follows header immediately):
//   DWORD entry_size   (total size of this entry including this field)
//   DWORD data_size    (bytes of appended data blob)
//   QWORD last_mod     (FILETIME of last modification)
//   WORD  path_len     (bytes, not chars)
//   WCHAR path[path_len/2]  (UTF-16LE, no null terminator)
//   BYTE  data[data_size]

const APPCACHE_SIGNATURE: u32 = 0x00000030;
const HEADER_SIZE: usize = 48;

fn build_entry(path: &str, last_mod: i64) -> Vec<u8> {
    let wpath: Vec<u16> = path.encode_utf16().collect();
    let path_bytes = (wpath.len() * 2) as u16;
    let data_size: u32 = 0;
    // entry_size = sizeof(entry_size) + sizeof(data_size) + sizeof(last_mod) + sizeof(path_len)
    //            + path_bytes + data_size
    let entry_size = (4 + 4 + 8 + 2 + path_bytes as usize) as u32;

    let mut e = Vec::with_capacity(entry_size as usize);
    e.extend_from_slice(&entry_size.to_le_bytes());
    e.extend_from_slice(&data_size.to_le_bytes());
    e.extend_from_slice(&unix_to_filetime(last_mod).to_le_bytes());
    e.extend_from_slice(&path_bytes.to_le_bytes());
    for &wc in &wpath {
        e.extend_from_slice(&wc.to_le_bytes());
    }
    e
}

fn build_header(existing: Option<&[u8]>) -> Vec<u8> {
    let mut h = vec![0u8; HEADER_SIZE];
    // Detect signature from existing value, fall back to 0x30
    let sig = existing
        .filter(|e| e.len() >= 4)
        .map(|e| u32::from_le_bytes([e[0], e[1], e[2], e[3]]))
        .unwrap_or(APPCACHE_SIGNATURE);
    h[0..4].copy_from_slice(&sig.to_le_bytes());
    h
}

// ── Fake executable paths ─────────────────────────────────────────────────────

const FAKE_PATHS: &[&str] = &[
    r"\??\C:\Windows\System32\svchost.exe",
    r"\??\C:\Windows\System32\services.exe",
    r"\??\C:\Windows\System32\lsass.exe",
    r"\??\C:\Windows\System32\winlogon.exe",
    r"\??\C:\Windows\explorer.exe",
    r"\??\C:\Windows\System32\cmd.exe",
    r"\??\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"\??\C:\Windows\System32\msiexec.exe",
    r"\??\C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"\??\C:\Program Files\Mozilla Firefox\firefox.exe",
    r"\??\C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"\??\C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    r"\??\C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    r"\??\C:\Users\user\AppData\Local\Microsoft\Teams\current\Teams.exe",
    r"\??\C:\Users\user\AppData\Local\Slack\slack.exe",
    r"\??\C:\Program Files\7-Zip\7z.exe",
    r"\??\C:\Program Files\WinRAR\WinRAR.exe",
    r"\??\C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
    r"\??\C:\Windows\System32\notepad.exe",
    r"\??\C:\Windows\System32\taskmgr.exe",
    r"\??\C:\Windows\System32\mmc.exe",
    r"\??\C:\Windows\System32\regedit.exe",
    r"\??\C:\Windows\SysWOW64\rundll32.exe",
    r"\??\C:\Windows\System32\werfault.exe",
    r"\??\C:\Windows\System32\wbem\WmiPrvSE.exe",
];

// ── Public API ────────────────────────────────────────────────────────────────

pub struct ShimcacheForgeOpts {
    pub n_entries: u32,
    pub ts_base: i64,
    pub verbose: bool,
}

#[derive(Default)]
pub struct ShimcacheForgeStats {
    pub entries_injected: u32,
    pub errors: u32,
}

pub fn forge_shimcache(opts: &ShimcacheForgeOpts) -> ShimcacheForgeStats {
    let mut s = ShimcacheForgeStats::default();
    let mut lcg = Lcg::new(opts.ts_base);

    let hkey = match open_or_create_key() {
        Some(k) => k,
        None => {
            if opts.verbose {
                eprintln!("[!] forge-shimcache: failed to open registry key");
            }
            s.errors += 1;
            return s;
        }
    };

    // Read existing value to preserve its header signature and existing entries
    let existing = read_existing_value(hkey);
    let header = build_header(existing.as_deref());

    // Build fake entries (most recent first = prepended)
    let n = opts.n_entries.min(FAKE_PATHS.len() as u32) as usize;
    let mut new_entries: Vec<u8> = Vec::new();
    for &path in FAKE_PATHS.iter().take(n) {
        let offset = lcg.range(0, 30 * 86_400) as i64; // up to 30 days back
        let last_mod = opts.ts_base - offset;
        new_entries.extend_from_slice(&build_entry(path, last_mod));
        s.entries_injected += 1;
    }

    // Assemble: header + new fake entries + existing entries (skip existing header)
    let mut value = header;
    value.extend_from_slice(&new_entries);
    if let Some(ref existing_data) = existing {
        if existing_data.len() > HEADER_SIZE {
            value.extend_from_slice(&existing_data[HEADER_SIZE..]);
        }
    }

    if write_value(hkey, &value) {
        if opts.verbose {
            eprintln!(
                "[+] forge-shimcache: {} entries injected ({} bytes total)",
                s.entries_injected,
                value.len()
            );
        }
    } else {
        s.errors += 1;
        if opts.verbose {
            eprintln!("[!] forge-shimcache: failed to write registry value");
        }
    }

    unsafe { RegCloseKey(hkey) };
    s
}
