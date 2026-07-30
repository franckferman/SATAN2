use std::ptr::{null, null_mut};
use windows_sys::Win32::System::EventLog::*;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn write_event(source: &str, ev_type: u16, category: u16, event_id: u32, msg: &str) -> bool {
    let src_w = wstr(source);
    unsafe {
        let h = RegisterEventSourceW(null(), src_w.as_ptr());
        if h.is_null() {
            return false;
        }

        let msg_w = wstr(msg);
        let ptrs: [*const u16; 1] = [msg_w.as_ptr()];

        let ok = ReportEventW(
            h,
            ev_type,
            category,
            event_id,
            null_mut(), // lpUserSid
            1,          // wNumStrings
            0,          // dwDataSize
            ptrs.as_ptr(),
            null(), // lpRawData
        );

        DeregisterEventSource(h);
        ok != 0
    }
}

// ── Event templates ───────────────────────────────────────────────────────────

// MsiInstaller events (Application log, event 1033 = installation completed)
const MSI_PRODUCTS: &[&str] = &[
    "Microsoft Visual C++ 2022 Redistributable (x64) - 14.40.33810",
    "Microsoft Visual C++ 2022 Redistributable (x86) - 14.40.33810",
    "Microsoft .NET Framework 4.8.1",
    "Microsoft .NET Runtime 8.0.5",
    "Microsoft ASP.NET Core 8.0.5 - Shared Framework",
    "7-Zip 24.05 (x64)",
    "Git version 2.45.2",
    "Notepad++ (64-bit x64)",
    "Python 3.12.3 (64-bit)",
    "Node.js 20.13.1",
    "OpenSSL 3.3.0 Light (64-bit)",
    "PuTTY release 0.81 (64-bit)",
    "WinRAR 7.00 (64 bit)",
    "Microsoft Edge WebView2 Runtime",
    "Microsoft OneDrive",
    "Microsoft Teams Machine-Wide Installer",
];

// Application error events (event 1000 — application crash)
const APP_CRASHES: &[(&str, &str)] = &[
    ("chrome.exe", "6adc727d"),
    ("svchost.exe", "c0000005"),
    ("RuntimeBroker.exe", "c0000005"),
    ("SearchUI.exe", "c000001d"),
    ("ShellExperienceHost.exe", "c0000409"),
    ("msedge.exe", "80000003"),
];

// ESENT events (very common Application log noise)
const ESENT_MSGS: &[&str] = &[
    "svchost (808) SYSTEM: The database engine created a new database (2, C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb). (Time=0 seconds)",
    "svchost (808) SRUJet: The database engine is initiating recovery steps.",
    "svchost (1128) TILEREPOSITORYS-1-5-18: The database engine has successfully completed recovery steps.",
    "svchost (1780) TILEREPOSITORYS-1-5-21-000000001-000000002-000000003-1001: The database engine is initiating recovery steps.",
    "svchost (2544) SRUM: The database engine started a new instance (0). (Time=0 seconds)",
];

// Security-SPP events (Software Protection Platform — licensing)
const SPP_MSGS: &[&str] = &[
    "The Software Protection service has completed licensing status check.",
    "Offline downlevel migration succeeded.",
    "Successfully scheduled Software Protection service for re-start at 2122-01-01T00:00:00Z.",
];

// ── Public API ────────────────────────────────────────────────────────────────

pub struct EventLogForgeStats {
    pub events_written: u32,
    pub errors: u32,
}

pub fn forge_event_log(verbose: bool) -> EventLogForgeStats {
    let mut s = EventLogForgeStats {
        events_written: 0,
        errors: 0,
    };

    // ── MsiInstaller — software installation events ───────────────────────────
    for product in MSI_PRODUCTS {
        let msg = format!(
            "Product: {} -- Installation completed successfully.",
            product
        );
        // EventID 1033, category 0, Information
        if write_event("MsiInstaller", EVENTLOG_INFORMATION_TYPE, 0, 1033, &msg) {
            s.events_written += 1;
            if verbose {
                eprintln!("[+] forge-evtlog: MsiInstaller → {}", product);
            }
        } else {
            s.errors += 1;
            if verbose {
                eprintln!("[!] forge-evtlog: MsiInstaller failed for {}", product);
            }
        }
    }

    // ── Application Error — crash events ─────────────────────────────────────
    for (exe, exc_code) in APP_CRASHES {
        let msg = format!(
            "Faulting application name: {}, version: 0.0.0.0, time stamp: 0x00000000\n\
             Faulting module name: ntdll.dll, version: 10.0.22621.3447, time stamp: 0xf3b8d2a4\n\
             Exception code: 0x{}\n\
             Fault offset: 0x00000001403c7d90\n\
             Faulting process id: 0x{:04x}\n\
             Faulting application start time: 0x01da0000deadbeef\n\
             Faulting application path: C:\\Windows\\System32\\{}",
            exe,
            exc_code,
            (0x1000u32 + (exe.len() as u32 * 7) % 0xe000),
            exe
        );
        if write_event("Application Error", EVENTLOG_ERROR_TYPE, 100, 1000, &msg) {
            s.events_written += 1;
            if verbose {
                eprintln!("[+] forge-evtlog: AppError → {}", exe);
            }
        } else {
            s.errors += 1;
        }
    }

    // ── ESENT — common database engine noise ──────────────────────────────────
    for &msg in ESENT_MSGS {
        if write_event("ESENT", EVENTLOG_INFORMATION_TYPE, 1, 102, msg) {
            s.events_written += 1;
            if verbose {
                eprintln!("[+] forge-evtlog: ESENT event");
            }
        } else {
            s.errors += 1;
        }
    }

    // ── Security-SPP — licensing (very common on Win10/11) ───────────────────
    for &msg in SPP_MSGS {
        if write_event("Security-SPP", EVENTLOG_INFORMATION_TYPE, 0, 16394, msg) {
            s.events_written += 1;
            if verbose {
                eprintln!("[+] forge-evtlog: Security-SPP");
            }
        } else {
            s.errors += 1;
        }
    }

    if verbose {
        eprintln!(
            "[+] forge-evtlog: {} events written, {} errors",
            s.events_written, s.errors
        );
    }
    s
}
