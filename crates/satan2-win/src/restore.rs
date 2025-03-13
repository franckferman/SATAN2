#![cfg(target_os = "windows")]

/*
 * System Restore Points — WMI root\default, class SystemRestore.
 * Deletion: SRRemoveRestorePoint(dwSequenceNumber) from SrClient.dll.
 */

use windows_sys::Win32::{
    Foundation::*,
    System::{
        Com::*,
        Ole::*,
        Variant::*,
        Wmi::*,
        LibraryLoader::*,
    },
};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

type SRRemoveRestorePointFn = unsafe extern "system" fn(dwRPNum: u32) -> BOOL;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

unsafe fn bstr(s: &str) -> BSTR {
    SysAllocString(to_wide(s).as_ptr())
}

unsafe fn bstr_to_string(b: BSTR) -> String {
    if b.is_null() { return String::new(); }
    let len = SysStringLen(b) as usize;
    String::from_utf16_lossy(std::slice::from_raw_parts(b, len))
}

pub fn delete_all(verbose: bool) -> Result<u32, String> {
    // Load SrClient.dll for SRRemoveRestorePoint
    let lib_name = to_wide("SrClient.dll");
    let hlib = unsafe { LoadLibraryW(lib_name.as_ptr()) };
    if hlib == 0 {
        return Err("SrClient.dll not found — System Restore may be disabled".into());
    }

    let fn_name = b"SRRemoveRestorePoint\0";
    let fn_ptr = unsafe { GetProcAddress(hlib, fn_name.as_ptr()) };
    if fn_ptr.is_none() {
        unsafe { FreeLibrary(hlib) };
        return Err("SRRemoveRestorePoint not found in SrClient.dll".into());
    }
    let sr_remove: SRRemoveRestorePointFn = unsafe { std::mem::transmute(fn_ptr.unwrap()) };

    // Enumerate via WMI root\default, class SystemRestore
    let restore_points = enumerate_restore_points(verbose)?;
    let mut deleted = 0u32;

    for seq_num in restore_points {
        let ok = unsafe { sr_remove(seq_num) };
        if ok != 0 {
            deleted += 1;
            if verbose { eprintln!("[+] Deleted restore point #{}", seq_num); }
        } else {
            eprintln!("[!] SRRemoveRestorePoint({}) failed", seq_num);
        }
    }

    unsafe { FreeLibrary(hlib) };
    Ok(deleted)
}

fn enumerate_restore_points(verbose: bool) -> Result<Vec<u32>, String> {
    unsafe {
        let hr = CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED);
        if hr < 0 && hr != 0x00000001i32 { /* S_FALSE */ }

        // CLSID_WbemLocator
        let clsid: GUID = GUID {
            data1: 0x4590F811,
            data2: 0x1D3A,
            data3: 0x11D0,
            data4: [0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24],
        };

        let mut locator: *mut IWbemLocator = std::ptr::null_mut();
        let hr = CoCreateInstance(
            &clsid, std::ptr::null_mut(), CLSCTX_INPROC_SERVER,
            &IWbemLocator::IID, &mut locator as *mut _ as *mut _,
        );
        if hr < 0 { return Err(format!("CoCreateInstance: 0x{:x}", hr as u32)); }

        let ns = bstr("ROOT\\DEFAULT");
        let mut services: *mut IWbemServices = std::ptr::null_mut();
        let hr = (*locator).ConnectServer(
            ns, std::ptr::null_mut(), std::ptr::null_mut(),
            std::ptr::null_mut(), 0, std::ptr::null_mut(),
            std::ptr::null_mut(), &mut services,
        );
        SysFreeString(ns);
        (*locator).Release();
        if hr < 0 { return Err(format!("ConnectServer ROOT\\DEFAULT: 0x{:x}", hr as u32)); }

        let query = bstr("SELECT * FROM SystemRestore");
        let lang  = bstr("WQL");
        let mut enumerator: *mut IEnumWbemClassObject = std::ptr::null_mut();
        let hr = (*services).ExecQuery(
            lang, query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            std::ptr::null_mut(), &mut enumerator,
        );
        SysFreeString(query);
        SysFreeString(lang);

        if hr < 0 {
            (*services).Release();
            return Err(format!("ExecQuery SystemRestore: 0x{:x}", hr as u32));
        }

        let mut seq_nums = Vec::new();

        loop {
            let mut obj: *mut IWbemClassObject = std::ptr::null_mut();
            let mut returned = 0u32;
            let hr = (*enumerator).Next(WBEM_INFINITE, 1, &mut obj, &mut returned);
            if hr < 0 || returned == 0 { break; }

            let prop = bstr("SequenceNumber");
            let mut var: VARIANT = std::mem::zeroed();
            let hr = (*obj).Get(prop, 0, &mut var, std::ptr::null_mut(), std::ptr::null_mut());
            SysFreeString(prop);

            if hr >= 0 && var.Anonymous.Anonymous.vt == VT_I4 as u16 {
                let seq = var.Anonymous.Anonymous.Anonymous.lVal as u32;
                if verbose { eprintln!("  restore point #{}  desc={}", seq,
                    get_str_prop_inner(obj, "Description")); }
                seq_nums.push(seq);
            }
            VariantClear(&mut var);
            (*obj).Release();
        }

        (*enumerator).Release();
        (*services).Release();
        CoUninitialize();
        Ok(seq_nums)
    }
}

unsafe fn get_str_prop_inner(obj: *mut IWbemClassObject, prop: &str) -> String {
    let prop_w = bstr(prop);
    let mut var: VARIANT = std::mem::zeroed();
    let hr = (*obj).Get(prop_w, 0, &mut var, std::ptr::null_mut(), std::ptr::null_mut());
    SysFreeString(prop_w);
    if hr < 0 { return String::new(); }
    let s = if var.Anonymous.Anonymous.vt == VT_BSTR as u16 {
        bstr_to_string(var.Anonymous.Anonymous.Anonymous.bstrVal)
    } else { String::new() };
    VariantClear(&mut var);
    s
}
