/*
 * hiberfil.rs — Hibernation file and pagefile artifact removal
 *
 * hiberfil.sys  (~RAM-size compressed snapshot of physical memory at hibernate).
 *               Deleted immediately by: powercfg /hibernate off
 *
 * pagefile.sys  (kernel paging file — plaintext process memory, registry hives,
 *               decrypted secrets). Locked by the OS at runtime.
 *               Options:
 *                 1. ClearPageFileAtShutdown = 1  → OS zeros it on next shutdown
 *                 2. Disable pagefile entirely     → no persistence across reboots
 *                    (requires reboot to take effect; may impact stability)
 *               We set option 1 by default; option 2 if --disable-pagefile is passed.
 *
 * Both require SeShutdownPrivilege / admin rights.
 */

use std::fs;
use std::process::Command;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
};

const MEMMAN_KEY: &str = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";

// ── Hiberfil ─────────────────────────────────────────────────────────────────

fn disable_hibernation() -> bool {
    Command::new("powercfg")
        .args(["/hibernate", "off"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn hiberfil_exists() -> bool {
    std::path::Path::new(r"C:\hiberfil.sys").exists()
}

// ── Pagefile registry helpers ─────────────────────────────────────────────────

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn set_dword(subkey: &str, value: &str, data: u32) -> bool {
    let mut hkey: HKEY = std::ptr::null_mut();
    let sub_w = wide(subkey);
    let val_w = wide(value);

    let rc = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        sub_w.as_ptr(),
        0,
        KEY_SET_VALUE,
        &mut hkey,
    );
    if rc != ERROR_SUCCESS {
        return false;
    }

    let bytes = data.to_le_bytes();
    let rc = RegSetValueExW(
        hkey,
        val_w.as_ptr(),
        0,
        4, // REG_DWORD
        bytes.as_ptr(),
        4,
    );
    RegCloseKey(hkey);
    rc == ERROR_SUCCESS
}

fn set_clear_pagefile_at_shutdown(enable: bool) -> bool {
    unsafe { set_dword(MEMMAN_KEY, "ClearPageFileAtShutdown", enable as u32) }
}

fn disable_pagefile() -> bool {
    // Set PagingFiles to empty string — takes effect on next reboot
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
    };

    let sub_w = wide(MEMMAN_KEY);
    let val_w = wide("PagingFiles");
    let empty: Vec<u16> = vec![0u16]; // empty multi-sz

    let mut hkey: HKEY = std::ptr::null_mut();
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            sub_w.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if rc != ERROR_SUCCESS {
        return false;
    }

    let rc = unsafe {
        RegSetValueExW(
            hkey,
            val_w.as_ptr(),
            0,
            7, // REG_MULTI_SZ
            empty.as_ptr() as *const u8,
            (empty.len() * 2) as u32,
        )
    };
    unsafe { RegCloseKey(hkey) };
    rc == ERROR_SUCCESS
}

// ── Public ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct HiberfilStats {
    pub hiberfile_disabled: bool,
    pub hiberfile_existed: bool,
    pub pagefile_clear_set: bool,
    pub pagefile_disabled: bool,
    pub errors: u32,
}

pub fn wipe_hiberfil(disable_pf: bool, verbose: bool) -> HiberfilStats {
    let mut s = HiberfilStats {
        hiberfile_existed: hiberfil_exists(),
        ..Default::default()
    };

    // Hibernation
    if verbose {
        eprintln!("[*] hiberfil: hiberfil.sys exists: {}", s.hiberfile_existed);
    }

    s.hiberfile_disabled = disable_hibernation();
    if s.hiberfile_disabled {
        eprintln!("[+] hiberfil: hibernation disabled (hiberfil.sys deleted by powercfg)");
    } else {
        eprintln!("[!] hiberfil: powercfg /hibernate off failed");
        s.errors += 1;
        // Fallback: try direct deletion (usually locked, but worth trying)
        if s.hiberfile_existed {
            let _ = fs::remove_file(r"C:\hiberfil.sys");
        }
    }

    // Pagefile — ClearPageFileAtShutdown
    s.pagefile_clear_set = set_clear_pagefile_at_shutdown(true);
    if s.pagefile_clear_set {
        eprintln!("[+] hiberfil: ClearPageFileAtShutdown = 1 (will zero pagefile on shutdown)");
    } else {
        eprintln!("[!] hiberfil: failed to set ClearPageFileAtShutdown");
        s.errors += 1;
    }

    // Optional: disable pagefile entirely
    if disable_pf {
        s.pagefile_disabled = disable_pagefile();
        if s.pagefile_disabled {
            eprintln!("[+] hiberfil: pagefile disabled (effective on next reboot)");
        } else {
            eprintln!("[!] hiberfil: failed to disable pagefile");
            s.errors += 1;
        }
    }

    s
}
