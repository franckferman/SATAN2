/*
 * rdp.rs — RDP (Remote Desktop Protocol) artifact removal
 *
 * Artifacts created by mstsc.exe (RDP client):
 *
 * 1. Registry MRU (recently connected servers):
 *    HKCU\Software\Microsoft\Terminal Server Client\Default\
 *      MRU0..MRU9  — last 10 servers
 *    HKCU\Software\Microsoft\Terminal Server Client\Servers\<hostname>\
 *      UsernameHint — stored username
 *
 * 2. Default.rdp file:
 *    %USERPROFILE%\Documents\Default.rdp  — saved connection settings
 *
 * 3. Bitmap cache (client-side image cache of the RDP session):
 *    %LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\
 *      bcache*.bmc, cache*.bin
 *
 * 4. Windows Credential Manager (stored RDP passwords):
 *    Via cmdkey.exe: cmdkey /list   then cmdkey /delete:TERMSRV/<host>
 *    Also in: %APPDATA%\Microsoft\Credentials\  (encrypted blobs)
 *
 * 5. RDP event logs (cleared by event_log.rs):
 *    Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
 *    Microsoft-Windows-TerminalServices-RDPClient/Operational
 *    Security (4624, 4625 logon events)
 */

use std::fs;
use std::process::Command;
use walkdir::WalkDir;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteKeyW, RegDeleteValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
    KEY_ALL_ACCESS,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

const MRU_KEY: &str = "Software\\Microsoft\\Terminal Server Client\\Default";
const SERVERS_KEY: &str = "Software\\Microsoft\\Terminal Server Client\\Servers";

unsafe fn delete_key_tree(root: windows_sys::Win32::System::Registry::HKEY, subkey: &str) -> bool {
    let w = wide(subkey);
    RegDeleteKeyW(root, w.as_ptr()) == ERROR_SUCCESS
}

unsafe fn delete_value(
    root: windows_sys::Win32::System::Registry::HKEY,
    subkey: &str,
    value: &str,
) -> bool {
    let mut hkey: HKEY = std::ptr::null_mut();
    let sk = wide(subkey);
    let rc = RegOpenKeyExW(root, sk.as_ptr(), 0, KEY_ALL_ACCESS, &mut hkey);
    if rc != ERROR_SUCCESS {
        return false;
    }

    let vw = wide(value);
    let rc = RegDeleteValueW(hkey, vw.as_ptr());
    RegCloseKey(hkey);
    rc == ERROR_SUCCESS
}

fn clear_rdp_mru() -> u32 {
    let mut cleared = 0u32;
    for i in 0..10u32 {
        let value = format!("MRU{}", i);
        if unsafe { delete_value(HKEY_CURRENT_USER, MRU_KEY, &value) } {
            cleared += 1;
        }
    }
    if cleared > 0 {
        eprintln!(
            "[+] rdp: cleared {} MRU entries from Client\\Default",
            cleared
        );
    }
    cleared
}

fn clear_rdp_servers() -> u32 {
    // List server subkeys then delete each
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY, KEY_READ,
    };

    let mut hkey: HKEY = std::ptr::null_mut();
    let sk = wide(SERVERS_KEY);
    let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, sk.as_ptr(), 0, KEY_READ, &mut hkey) };
    if rc != ERROR_SUCCESS {
        return 0;
    }

    let mut names: Vec<String> = Vec::new();
    let mut idx = 0u32;
    loop {
        let mut buf = vec![0u16; 512];
        let mut len = buf.len() as u32;
        let rc = unsafe {
            RegEnumKeyExW(
                hkey,
                idx,
                buf.as_mut_ptr(),
                &mut len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            break;
        }
        let name = String::from_utf16_lossy(&buf[..len as usize]);
        names.push(name);
        idx += 1;
    }
    unsafe { RegCloseKey(hkey) };

    let mut deleted = 0u32;
    for name in &names {
        let full = format!("{}\\{}", SERVERS_KEY, name);
        if unsafe { delete_key_tree(HKEY_CURRENT_USER, &full) } {
            deleted += 1;
        }
    }
    if deleted > 0 {
        eprintln!(
            "[+] rdp: deleted {} server entries from Client\\Servers",
            deleted
        );
    }
    deleted
}

fn delete_bitmap_cache(user_home: &str, stats: &mut RdpStats) {
    let cache_dir = format!(
        r"{}\AppData\Local\Microsoft\Terminal Server Client\Cache",
        user_home
    );
    let path = std::path::Path::new(&cache_dir);
    if !path.exists() {
        return;
    }

    for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let size = fs::metadata(entry.path()).map(|m| m.len()).unwrap_or(0);
        match fs::remove_file(entry.path()) {
            Ok(()) => {
                stats.files_deleted += 1;
                stats.bytes_freed += size;
            }
            Err(e) => {
                eprintln!("[!] rdp: {}: {}", entry.path().display(), e);
                stats.errors += 1;
            }
        }
    }
}

fn delete_credentials(user_home: &str, stats: &mut RdpStats) {
    // Encrypted credential blobs
    let creds_dir = format!(r"{}\AppData\Roaming\Microsoft\Credentials", user_home);
    let local_creds_dir = format!(r"{}\AppData\Local\Microsoft\Credentials", user_home);

    for dir in &[creds_dir.as_str(), local_creds_dir.as_str()] {
        let p = std::path::Path::new(dir);
        if !p.exists() {
            continue;
        }
        for entry in WalkDir::new(p).follow_links(false).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let size = fs::metadata(entry.path()).map(|m| m.len()).unwrap_or(0);
            match fs::remove_file(entry.path()) {
                Ok(()) => {
                    stats.files_deleted += 1;
                    stats.bytes_freed += size;
                }
                Err(_) => {
                    stats.errors += 1;
                } // encrypted blobs may be locked by LSASS
            }
        }
    }

    // cmdkey: remove TERMSRV/* entries
    let _ = Command::new("cmdkey").args(["/delete:TERMSRV/*"]).status();
}

#[derive(Debug, Default)]
pub struct RdpStats {
    pub mru_cleared: u32,
    pub servers_cleared: u32,
    pub files_deleted: u32,
    pub bytes_freed: u64,
    pub errors: u32,
}

pub fn wipe_rdp_artifacts(verbose: bool) -> RdpStats {
    // Registry MRU (per-user — affects the currently running user's hive)
    let mut stats = RdpStats {
        mru_cleared: clear_rdp_mru(),
        servers_cleared: clear_rdp_servers(),
        ..Default::default()
    };

    let users = match fs::read_dir(r"C:\Users") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[!] rdp: C:\\Users: {}", e);
            return stats;
        }
    };

    for user in users.flatten() {
        let home = user.path();
        if !home.is_dir() {
            continue;
        }
        let home_str = home.to_string_lossy();

        // Default.rdp
        let rdp_file = format!(r"{}\Documents\Default.rdp", home_str);
        if std::path::Path::new(&rdp_file).exists() {
            match fs::remove_file(&rdp_file) {
                Ok(()) => {
                    if verbose {
                        eprintln!("[+] rdp: deleted {}", rdp_file);
                    }
                    stats.files_deleted += 1;
                }
                Err(e) => {
                    eprintln!("[!] rdp: {}: {}", rdp_file, e);
                    stats.errors += 1;
                }
            }
        }

        // Bitmap cache
        delete_bitmap_cache(&home_str, &mut stats);

        // Credential blobs
        delete_credentials(&home_str, &mut stats);
    }

    eprintln!(
        "[+] rdp: MRU={} servers={} files={} ({} MiB) errors={}",
        stats.mru_cleared,
        stats.servers_cleared,
        stats.files_deleted,
        stats.bytes_freed >> 20,
        stats.errors
    );
    stats
}
