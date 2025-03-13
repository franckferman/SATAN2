#![cfg(target_os = "windows")]
// userassist.rs — wipe Windows UserAssist registry entries
//
// UserAssist: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\
//   Multiple GUID subkeys, each with a "Count" sub-key recording every application
//   and shortcut executed by the user. Key names are ROT13-encoded.
//   Data per entry: execution count + FILETIME of last run.
//
// Strategy for current user:    delete Count subkeys directly from HKCU.
// Strategy for other users:     load their NTUSER.DAT via RegLoadKeyW into
//                                HKEY_USERS\<temp_name>, delete Count subkeys, unload.
//                                Requires SeBackupPrivilege + SeRestorePrivilege
//                                (already enabled by privilege::enable_backup_restore()).

use std::fs;
use std::ptr;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteKeyExW, RegEnumKeyExW, RegLoadKeyW, RegOpenKeyExW,
    RegUnLoadKeyW, HKEY_CURRENT_USER, HKEY_USERS, KEY_ALL_ACCESS, KEY_READ,
    KEY_WOW64_64KEY,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

const UA_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

#[derive(Debug, Default)]
pub struct UserAssistStats {
    pub keys_deleted:   u32,
    pub users_cleaned:  u32,
    pub errors:         u32,
}

/// Enumerate subkey names under an open registry key handle.
unsafe fn enum_subkeys(hkey: windows_sys::Win32::System::Registry::HKEY) -> Vec<String> {
    let mut names = Vec::new();
    let mut idx = 0u32;
    loop {
        let mut buf = vec![0u16; 512];
        let mut len = buf.len() as u32;
        let rc = RegEnumKeyExW(
            hkey, idx, buf.as_mut_ptr(), &mut len,
            ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
        );
        if rc != ERROR_SUCCESS as i32 { break; }
        names.push(String::from_utf16_lossy(&buf[..len as usize]));
        idx += 1;
    }
    names
}

/// Delete a registry key. Tries direct delete first; if the key has children,
/// enumerates and recurses.
unsafe fn delete_key_tree(
    root: windows_sys::Win32::System::Registry::HKEY,
    subkey: &str,
) -> bool {
    let w = wide(subkey);
    let rc = RegDeleteKeyExW(root, w.as_ptr(), KEY_WOW64_64KEY, 0);
    if rc == ERROR_SUCCESS as i32 { return true; }

    // Open and recurse into children
    let mut hkey = 0isize;
    let w2 = wide(subkey);
    let rc = RegOpenKeyExW(root, w2.as_ptr(), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &mut hkey);
    if rc != ERROR_SUCCESS as i32 { return false; }

    let children = enum_subkeys(hkey);
    RegCloseKey(hkey);

    let mut ok = true;
    for child in &children {
        let full = format!("{}\\{}", subkey, child);
        if !delete_key_tree(root, &full) { ok = false; }
    }

    let w3 = wide(subkey);
    RegDeleteKeyExW(root, w3.as_ptr(), KEY_WOW64_64KEY, 0) == ERROR_SUCCESS as i32 && ok
}

/// Wipe all UserAssist Count subkeys in the hive accessible via `root`.
fn wipe_ua_in_hive(
    root: windows_sys::Win32::System::Registry::HKEY,
    stats: &mut UserAssistStats,
    verbose: bool,
) {
    let ua_w = wide(UA_KEY);
    let mut hkey = 0isize;

    let rc = unsafe {
        RegOpenKeyExW(root, ua_w.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut hkey)
    };
    if rc != ERROR_SUCCESS as i32 { return; } // key absent — nothing to do

    // Collect GUID subkey names (e.g. {CEBFF5CD-ACE2-4F4F-9178-9926F41749EA})
    let guids = unsafe { enum_subkeys(hkey) };
    unsafe { RegCloseKey(hkey) };

    for guid in &guids {
        let count_path = format!("{}\\{}\\Count", UA_KEY, guid);
        if unsafe { delete_key_tree(root, &count_path) } {
            if verbose { eprintln!("[+] userassist: deleted {}", count_path); }
            stats.keys_deleted += 1;
        } else {
            stats.errors += 1;
        }
    }
}

pub fn wipe_userassist(verbose: bool) -> UserAssistStats {
    let mut stats = UserAssistStats::default();

    // Current user — directly available via HKCU
    wipe_ua_in_hive(HKEY_CURRENT_USER, &mut stats, verbose);
    stats.users_cleaned += 1;

    // Other users — load NTUSER.DAT for users not currently logged in
    let users = match fs::read_dir(r"C:\Users") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[!] userassist: C:\\Users: {}", e);
            return stats;
        }
    };

    for (i, user_entry) in users.flatten().enumerate() {
        let home = user_entry.path();
        if !home.is_dir() { continue; }

        let ntuser_dat = home.join("NTUSER.DAT");
        if !ntuser_dat.exists() { continue; }

        let hive_name  = format!("S2_UA_{}", i);
        let hive_name_w = wide(&hive_name);
        let dat_path_w  = wide(&ntuser_dat.to_string_lossy());

        // RegLoadKey requires SeRestorePrivilege + SeBackupPrivilege (enabled in main)
        let rc = unsafe { RegLoadKeyW(HKEY_USERS, hive_name_w.as_ptr(), dat_path_w.as_ptr()) };
        if rc != ERROR_SUCCESS as i32 {
            // User is probably currently logged in — their HKCU is already covered above
            continue;
        }

        // Open the temporarily loaded hive
        let sub_w = wide(&hive_name);
        let mut h_loaded = 0isize;
        let rc = unsafe {
            RegOpenKeyExW(HKEY_USERS, sub_w.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut h_loaded)
        };
        if rc == ERROR_SUCCESS as i32 {
            wipe_ua_in_hive(h_loaded, &mut stats, verbose);
            unsafe { RegCloseKey(h_loaded) };
            stats.users_cleaned += 1;
        }

        let hive_w2 = wide(&hive_name);
        unsafe { RegUnLoadKeyW(HKEY_USERS, hive_w2.as_ptr()) };
    }

    eprintln!("[+] userassist: {} key(s) deleted, {} user(s) cleaned, {} error(s)",
        stats.keys_deleted, stats.users_cleaned, stats.errors);
    stats
}
