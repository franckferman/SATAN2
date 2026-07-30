use std::ptr::null;
use windows_sys::Win32::System::Registry::*;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn set_sz(hkey: HKEY, name: &str, value: &str) -> bool {
    let name_w = wstr(name);
    let value_w = wstr(value);
    unsafe {
        RegSetValueExW(
            hkey,
            name_w.as_ptr(),
            0,
            REG_SZ,
            value_w.as_ptr() as *const u8,
            (value_w.len() * 2) as u32, // bytes, including null terminator
        ) == 0
    }
}

fn set_bin(hkey: HKEY, name: &str, value: &[u8]) -> bool {
    let name_w = wstr(name);
    unsafe {
        RegSetValueExW(
            hkey,
            name_w.as_ptr(),
            0,
            REG_BINARY,
            value.as_ptr(),
            value.len() as u32,
        ) == 0
    }
}

fn open_or_create_hkcu(path: &str) -> Option<HKEY> {
    let path_w = wstr(path);
    let mut hkey: HKEY = std::ptr::null_mut();
    let mut disp: u32 = 0;
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            path_w.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            null(),
            &mut hkey,
            &mut disp,
        )
    };
    if rc == 0 {
        Some(hkey)
    } else {
        None
    }
}

// ── RunMRU ────────────────────────────────────────────────────────────────────

// Recent commands typed in the Win+R Run dialog.
const RUN_MRU: &[&str] = &[
    "cmd.exe",
    "powershell",
    "mmc.exe",
    "regedit",
    "eventvwr.msc",
    "msinfo32",
    "taskmgr",
    "compmgmt.msc",
    "secpol.msc",
    "diskmgmt.msc",
    "services.msc",
    "devmgmt.msc",
    "perfmon.exe",
    "rsop.msc",
    "ncpa.cpl",
    "control",
    "sysdm.cpl",
    "intl.cpl",
];

fn forge_run_mru(verbose: bool) -> u32 {
    let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU";
    let hkey = match open_or_create_hkcu(path) {
        Some(h) => h,
        None => return 0,
    };

    let mru_limit = RUN_MRU.len().min(26); // a..z
    let mut mru_list = String::new();
    let mut written = 0u32;

    for (i, &cmd) in RUN_MRU.iter().take(mru_limit).enumerate() {
        let key_name = (b'a' + i as u8) as char;
        // RunMRU format: "command\1"
        let value = format!("{}\x01", cmd);
        if set_sz(hkey, &key_name.to_string(), &value) {
            mru_list.push(key_name);
            written += 1;
        }
    }

    // Write MRUList (most-recent-first order)
    let mru_reversed: String = mru_list.chars().rev().collect();
    set_sz(hkey, "MRUList", &mru_reversed);

    unsafe { RegCloseKey(hkey) };
    if verbose {
        eprintln!("[+] forge-reg-mru: {} RunMRU entries", written);
    }
    written
}

// ── Explorer TypedPaths ───────────────────────────────────────────────────────

// Paths typed into the Explorer address bar.
const TYPED_PATHS: &[&str] = &[
    "C:\\Users",
    "C:\\Windows\\System32",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\Temp",
    "\\\\fileserver\\shared",
    "\\\\10.0.0.10\\c$",
    "C:\\Users\\admin\\Documents",
    "C:\\Users\\admin\\Desktop",
    "C:\\inetpub\\wwwroot",
    "C:\\Windows\\System32\\drivers\\etc",
    "C:\\Windows\\SysWOW64",
    "\\\\DC01\\SYSVOL",
    "\\\\DC01\\NETLOGON",
];

fn forge_typed_paths(verbose: bool) -> u32 {
    let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths";
    let hkey = match open_or_create_hkcu(path) {
        Some(h) => h,
        None => return 0,
    };

    let mut written = 0u32;
    for (i, &p) in TYPED_PATHS.iter().enumerate() {
        let key_name = format!("{:03}", i + 1);
        if set_sz(hkey, &key_name, p) {
            written += 1;
        }
    }

    unsafe { RegCloseKey(hkey) };
    if verbose {
        eprintln!("[+] forge-reg-mru: {} TypedPaths entries", written);
    }
    written
}

// ── IE/Edge TypedURLs ─────────────────────────────────────────────────────────

// URLs typed into the Internet Explorer / legacy Edge address bar.
const TYPED_URLS: &[&str] = &[
    "https://www.google.fr/",
    "https://outlook.office365.com/",
    "https://portal.azure.com/",
    "https://www.office.com/",
    "https://teams.microsoft.com/",
    "https://sharepoint.company.com/",
    "https://jira.company.com/",
    "https://confluence.company.com/",
    "https://github.com/",
    "https://gitlab.company.com/",
    "https://www.lemonde.fr/",
    "https://www.linkedin.com/",
    "https://stackoverflow.com/",
    "https://docs.microsoft.com/",
    "https://nvd.nist.gov/",
    "https://attack.mitre.org/",
    "https://192.168.1.1/",
    "https://10.0.0.1/",
    "http://localhost:8080/",
    "http://localhost:3000/",
];

fn forge_typed_urls(verbose: bool) -> u32 {
    let path = "Software\\Microsoft\\Internet Explorer\\TypedURLs";
    let hkey = match open_or_create_hkcu(path) {
        Some(h) => h,
        None => return 0,
    };

    let mut written = 0u32;
    for (i, &url) in TYPED_URLS.iter().enumerate() {
        let key_name = format!("url{}", i + 1);
        if set_sz(hkey, &key_name, url) {
            written += 1;
        }
    }

    unsafe { RegCloseKey(hkey) };
    if verbose {
        eprintln!("[+] forge-reg-mru: {} TypedURLs entries", written);
    }
    written
}

// ── Recent Docs MRU ───────────────────────────────────────────────────────────

// Office recent docs via CIDSizeMRU (text-only extension types)
const RECENT_DOCS: &[(&str, &str)] = &[
    (".docx", "C:\\Users\\admin\\Documents\\Rapport_Q2_2026.docx"),
    (".xlsx", "C:\\Users\\admin\\Documents\\Budget_2026.xlsx"),
    (
        ".pptx",
        "C:\\Users\\admin\\Desktop\\Presentation_COPIL.pptx",
    ),
    (
        ".pdf",
        "C:\\Users\\admin\\Downloads\\Contrat_service_2026.pdf",
    ),
    (".txt", "C:\\Temp\\notes.txt"),
    (".ps1", "C:\\Users\\admin\\Documents\\deploy.ps1"),
    (".csv", "C:\\Users\\admin\\Documents\\export_users.csv"),
    (".xml", "C:\\inetpub\\wwwroot\\web.config"),
    (".json", "C:\\Users\\admin\\Documents\\config.json"),
    (".log", "C:\\Windows\\System32\\config\\Security.evtx"),
];

fn forge_recent_docs(verbose: bool) -> u32 {
    // RecentDocs\ext keys store shell IDList binary — complex format.
    // Write only the text-based CIDSizeMRU extension subkeys (simpler,
    // picked up by EnCase / FTK / Autopsy parsers in recent-files reports).
    let base = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs";
    let mut total = 0u32;

    for &(ext, path) in RECENT_DOCS {
        let subkey_path = format!("{}\\{}", base, ext);
        let hkey = match open_or_create_hkcu(&subkey_path) {
            Some(h) => h,
            None => continue,
        };
        // Entry "a" with null-terminated path (RecentDocs format: REG_SZ)
        if set_sz(hkey, "0", path) {
            total += 1;
        }
        // MRUListEx is REG_BINARY: entry 0 (LE u32) followed by -1 terminator
        set_bin(hkey, "MRUListEx", &[0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]); // [0, -1]
        unsafe { RegCloseKey(hkey) };
    }

    if verbose && total > 0 {
        eprintln!("[+] forge-reg-mru: {} RecentDocs entries", total);
    }
    total
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct RegistryMruForgeStats {
    pub entries_written: u32,
    pub errors: u32,
}

pub fn forge_registry_mru(verbose: bool) -> RegistryMruForgeStats {
    let mut s = RegistryMruForgeStats {
        entries_written: 0,
        errors: 0,
    };
    s.entries_written += forge_run_mru(verbose);
    s.entries_written += forge_typed_paths(verbose);
    s.entries_written += forge_typed_urls(verbose);
    s.entries_written += forge_recent_docs(verbose);
    if verbose {
        eprintln!(
            "[+] forge-reg-mru: {} total registry entries",
            s.entries_written
        );
    }
    s
}
