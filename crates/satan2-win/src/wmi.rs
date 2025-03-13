/*
 * wmi.rs — VSS operations via WMI (Win32_ShadowCopy)
 *
 * COM stack:
 *   CoInitializeEx(COINIT_MULTITHREADED)
 *   CoCreateInstance(CLSID_WbemLocator, IWbemLocator)
 *   IWbemLocator::ConnectServer("root\\cimv2") → IWbemServices
 *   IWbemServices::ExecQuery("SELECT * FROM Win32_ShadowCopy") → IEnumWbemClassObject
 *   IEnumWbemClassObject::Next → IWbemClassObject
 *   IWbemClassObject::Get("__PATH") → VARIANT (object path for DeleteInstance)
 *   IWbemServices::DeleteInstance(path) → delete
 *
 * Shadow creation uses Win32_ShadowCopy::Create (static method via IWbemServices::ExecMethod).
 */

#![cfg(target_os = "windows")]

use windows_sys::core::GUID;
use windows_sys::Win32::{
    Foundation::*,
    System::{
        Com::*,
        Ole::*,
        Variant::*,
        Wmi::*,
    },
};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

pub struct ShadowInfo {
    pub id:           String,
    pub volume:       String,
    pub install_date: String,
    pub obj_path:     String,
}

// ── Wide string helpers ───────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

unsafe fn bstr(s: &str) -> BSTR {
    let w = to_wide(s);
    SysAllocString(w.as_ptr())
}

unsafe fn bstr_to_string(b: BSTR) -> String {
    if b.is_null() { return String::new(); }
    let len = SysStringLen(b) as usize;
    let slice = std::slice::from_raw_parts(b, len);
    String::from_utf16_lossy(slice)
}

// ── COM guard ─────────────────────────────────────────────────────────────────

struct ComGuard;

impl ComGuard {
    unsafe fn init() -> Result<Self, String> {
        let hr = CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED);
        // S_FALSE means already initialized — that's fine
        if hr < 0 && hr != 0x00000001i32 /* S_FALSE */ {
            return Err(format!("CoInitializeEx failed: 0x{:08x}", hr as u32));
        }
        // Set COM security blanket for WMI access
        let _ = CoInitializeSecurity(
            std::ptr::null_mut(),
            -1,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            std::ptr::null_mut(),
            EOAC_NONE,
            std::ptr::null_mut(),
        );
        Ok(ComGuard)
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

// ── WMI connection ────────────────────────────────────────────────────────────

// CLSID_WbemLocator  = {4590F811-1D3A-11D0-891F-00AA004B2E24}
const CLSID_WBEM_LOCATOR: GUID = GUID {
    data1: 0x4590F811,
    data2: 0x1D3A,
    data3: 0x11D0,
    data4: [0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24],
};

unsafe fn connect_wmi() -> Result<*mut IWbemServices, String> {
    let mut locator: *mut IWbemLocator = std::ptr::null_mut();
    let hr = CoCreateInstance(
        &CLSID_WBEM_LOCATOR,
        std::ptr::null_mut(),
        CLSCTX_INPROC_SERVER,
        &IWbemLocator::IID,
        &mut locator as *mut _ as *mut _,
    );
    if hr < 0 {
        return Err(format!("CoCreateInstance(WbemLocator): 0x{:08x}", hr as u32));
    }

    let namespace = bstr("ROOT\\CIMV2");
    let mut services: *mut IWbemServices = std::ptr::null_mut();

    let hr = (*locator).ConnectServer(
        namespace,
        std::ptr::null_mut(), // user
        std::ptr::null_mut(), // password
        std::ptr::null_mut(), // locale
        0,
        std::ptr::null_mut(), // authority
        std::ptr::null_mut(), // ctx
        &mut services,
    );
    SysFreeString(namespace);
    (*locator).Release();

    if hr < 0 {
        return Err(format!("ConnectServer: 0x{:08x}", hr as u32));
    }

    // Set impersonation on the proxy
    CoSetProxyBlanket(
        services as *mut _,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        std::ptr::null_mut(),
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        std::ptr::null_mut(),
        EOAC_NONE,
    );

    Ok(services)
}

// ── Property extraction from IWbemClassObject ─────────────────────────────────

unsafe fn get_str_prop(obj: *mut IWbemClassObject, prop: &str) -> String {
    let prop_w = bstr(prop);
    let mut var: VARIANT = std::mem::zeroed();
    let hr = (*obj).Get(prop_w, 0, &mut var, std::ptr::null_mut(), std::ptr::null_mut());
    SysFreeString(prop_w);
    if hr < 0 { return String::new(); }

    let s = if var.Anonymous.Anonymous.vt == VT_BSTR as u16 {
        bstr_to_string(var.Anonymous.Anonymous.Anonymous.bstrVal)
    } else {
        String::new()
    };
    VariantClear(&mut var);
    s
}

// ── Parse Win32_ShadowCopy InstallDate (WMI datetime string) ─────────────────

fn parse_wmi_datetime(s: &str) -> i64 {
    // Format: "YYYYMMDDHHmmss.mmmmmm+OOO"
    if s.len() < 14 { return 0; }
    let year:  i32 = s[0..4].parse().unwrap_or(1970);
    let month: u32 = s[4..6].parse().unwrap_or(1);
    let day:   u32 = s[6..8].parse().unwrap_or(1);
    let hour:  u32 = s[8..10].parse().unwrap_or(0);
    let min:   u32 = s[10..12].parse().unwrap_or(0);
    let sec:   u32 = s[12..14].parse().unwrap_or(0);

    // Rough Unix timestamp (ignores DST/TZ — sufficient for comparison)
    let days_since_epoch = days_from_ymd(year, month, day);
    days_since_epoch * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64
}

fn days_from_ymd(y: i32, m: u32, d: u32) -> i64 {
    // Rata Die algorithm
    let y = y as i64 - if m <= 2 { 1 } else { 0 };
    let m = m as i64 + if m <= 2 { 9 } else { -3 };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * m + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn list_shadows(verbose: bool) -> Result<Vec<ShadowInfo>, String> {
    unsafe {
        let _com = ComGuard::init()?;
        let services = connect_wmi()?;

        let query = bstr("SELECT * FROM Win32_ShadowCopy");
        let lang  = bstr("WQL");
        let mut enumerator: *mut IEnumWbemClassObject = std::ptr::null_mut();

        let hr = (*services).ExecQuery(
            lang, query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            std::ptr::null_mut(),
            &mut enumerator,
        );
        SysFreeString(query);
        SysFreeString(lang);

        if hr < 0 {
            (*services).Release();
            return Err(format!("ExecQuery: 0x{:08x}", hr as u32));
        }

        let mut shadows = Vec::new();

        loop {
            let mut obj: *mut IWbemClassObject = std::ptr::null_mut();
            let mut returned = 0u32;
            let hr = (*enumerator).Next(WBEM_INFINITE, 1, &mut obj, &mut returned);
            if hr < 0 || returned == 0 { break; }

            let id           = get_str_prop(obj, "ID");
            let volume       = get_str_prop(obj, "VolumeName");
            let install_date = get_str_prop(obj, "InstallDate");
            let obj_path     = get_str_prop(obj, "__PATH");

            if verbose {
                eprintln!("  shadow: {} vol={} date={}", id, volume, install_date);
            }

            shadows.push(ShadowInfo { id, volume, install_date, obj_path });
            (*obj).Release();
        }

        (*enumerator).Release();
        (*services).Release();
        Ok(shadows)
    }
}

pub fn delete_shadows(volume: Option<&str>, after_unix: Option<i64>, verbose: bool) -> Result<u32, String> {
    let shadows = list_shadows(verbose)?;

    unsafe {
        let _com = ComGuard::init()?;
        let services = connect_wmi()?;
        let mut deleted = 0u32;

        for s in shadows {
            // Volume filter
            if let Some(vol) = volume {
                if !s.volume.to_lowercase().contains(&vol.to_lowercase()) { continue; }
            }

            // Timestamp filter (COVER mode)
            if let Some(after) = after_unix {
                let ts = parse_wmi_datetime(&s.install_date);
                if ts <= after { continue; }
            }

            let path = bstr(&s.obj_path);
            let hr = (*services).DeleteInstance(path, 0, std::ptr::null_mut(), std::ptr::null_mut());
            SysFreeString(path);

            if hr >= 0 {
                deleted += 1;
                if verbose { eprintln!("[+] Deleted shadow: {}", s.id); }
            } else {
                eprintln!("[!] DeleteInstance failed for {}: 0x{:08x}", s.id, hr as u32);
            }
        }

        (*services).Release();
        Ok(deleted)
    }
}

pub fn create_shadow(volume: &str) -> Result<String, String> {
    unsafe {
        let _com = ComGuard::init()?;
        let services = connect_wmi()?;

        let class_name = bstr("Win32_ShadowCopy");
        let method_name = bstr("Create");

        let mut class_def: *mut IWbemClassObject = std::ptr::null_mut();
        (*services).GetObject(
            class_name, 0, std::ptr::null_mut(),
            &mut class_def, std::ptr::null_mut()
        );

        let mut in_params_def: *mut IWbemClassObject = std::ptr::null_mut();
        (*class_def).GetMethod(method_name, 0, &mut in_params_def, std::ptr::null_mut());
        (*class_def).Release();

        let mut in_params: *mut IWbemClassObject = std::ptr::null_mut();
        (*in_params_def).SpawnInstance(0, &mut in_params);
        (*in_params_def).Release();

        // Set Volume parameter
        let vol_name = bstr("Volume");
        let vol_path = format!("{}\\", volume.trim_end_matches('\\'));
        let vol_bstr = bstr(&vol_path);
        let mut var: VARIANT = std::mem::zeroed();
        var.Anonymous.Anonymous.vt = VT_BSTR as u16;
        var.Anonymous.Anonymous.Anonymous.bstrVal = vol_bstr;
        (*in_params).Put(vol_name, 0, &var, 0);
        SysFreeString(vol_name);
        SysFreeString(vol_bstr);

        // Set Context parameter
        let ctx_name = bstr("Context");
        let ctx_val  = bstr("ClientAccessible");
        let mut var2: VARIANT = std::mem::zeroed();
        var2.Anonymous.Anonymous.vt = VT_BSTR as u16;
        var2.Anonymous.Anonymous.Anonymous.bstrVal = ctx_val;
        (*in_params).Put(ctx_name, 0, &var2, 0);
        SysFreeString(ctx_name);
        SysFreeString(ctx_val);

        let mut out_params: *mut IWbemClassObject = std::ptr::null_mut();
        let hr = (*services).ExecMethod(
            class_name, method_name, 0,
            std::ptr::null_mut(),
            in_params,
            &mut out_params,
            std::ptr::null_mut(),
        );
        SysFreeString(class_name);
        SysFreeString(method_name);
        (*in_params).Release();
        (*services).Release();

        if hr < 0 {
            return Err(format!("ExecMethod(Create): 0x{:08x}", hr as u32));
        }

        let shadow_id = get_str_prop(out_params, "ShadowID");
        (*out_params).Release();
        Ok(shadow_id)
    }
}
