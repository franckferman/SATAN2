/*
 * etw.rs — ETW traces and Windows Error Reporting removal
 *
 * ETW (Event Tracing for Windows) session logs:
 *   C:\Windows\System32\WDI\LogFiles\*.etl
 *   C:\Windows\Logs\WindowsUpdate\*.etl
 *   C:\ProgramData\Microsoft\Windows\WER\  (crash reports)
 *   C:\Users\*\AppData\Local\Microsoft\Windows\WER\
 *   C:\Windows\System32\WER\
 *
 * WER (Windows Error Reporting) crash dumps contain full process memory
 * and mini-dumps — extremely rich forensic sources.
 *
 * Circular kernel logger (PerfDisk, etc.) at:
 *   C:\Windows\System32\LogFiles\WMI\*.etl
 *
 * Note: active ETL sessions are memory-mapped. We can stop collection
 * via logman but cannot delete the active session file while it's mapped.
 * We target archived/completed ETL files only.
 */

use std::fs;
use std::process::Command;
use walkdir::WalkDir;

#[derive(Debug, Default)]
pub struct EtwStats {
    pub etl_deleted: u32,
    pub wer_deleted: u32,
    pub bytes_freed: u64,
    pub errors: u32,
}

fn delete_dir_contents(dir: &str, ext_filter: Option<&str>, stats: &mut EtwStats, is_wer: bool) {
    if !std::path::Path::new(dir).exists() {
        return;
    }

    for entry in WalkDir::new(dir).follow_links(false).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path().to_str().unwrap_or("");

        if let Some(ext) = ext_filter {
            if !path.ends_with(ext) {
                continue;
            }
        }

        if let Ok(meta) = fs::metadata(path) {
            stats.bytes_freed += meta.len();
        }

        match fs::remove_file(path) {
            Ok(()) => {
                if is_wer {
                    stats.wer_deleted += 1;
                } else {
                    stats.etl_deleted += 1;
                }
            }
            Err(e) => {
                // File in use — skip silently (active ETL session)
                if e.raw_os_error() != Some(32) {
                    // ERROR_SHARING_VIOLATION
                    eprintln!("[!] etw: remove {}: {}", path, e);
                    stats.errors += 1;
                }
            }
        }
    }
}

/// Stop non-essential ETW data collectors via logman.
fn stop_etw_collectors() {
    let collectors = ["DiagLog", "WiFiSession", "ReadyBoot"];
    for c in &collectors {
        let _ = Command::new("logman").args(["stop", c, "-ets"]).status();
    }
}

pub fn wipe_etw(verbose: bool) -> EtwStats {
    let mut stats = EtwStats::default();

    stop_etw_collectors();

    // ETL files
    let etl_dirs = [
        r"C:\Windows\System32\LogFiles\WMI",
        r"C:\Windows\System32\WDI\LogFiles",
        r"C:\Windows\Logs\WindowsUpdate",
        r"C:\Windows\Logs\CBS",
        r"C:\Windows\INF", // setupapi.log
    ];
    for dir in &etl_dirs {
        if verbose {
            eprintln!("[*] etw: cleaning {}", dir);
        }
        delete_dir_contents(dir, Some(".etl"), &mut stats, false);
    }

    // WER crash reports (system-wide)
    let wer_dirs = [
        r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
        r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
        r"C:\Windows\System32\WER",
    ];
    for dir in &wer_dirs {
        if verbose {
            eprintln!("[*] etw: clearing WER {}", dir);
        }
        delete_dir_contents(dir, None, &mut stats, true);
    }

    // Per-user WER
    if let Ok(users) = fs::read_dir(r"C:\Users") {
        for user in users.flatten() {
            let wer = format!(
                r"{}\AppData\Local\Microsoft\Windows\WER",
                user.path().display()
            );
            delete_dir_contents(&wer, None, &mut stats, true);
        }
    }

    // setupapi.log (device installation history)
    let _ = fs::remove_file(r"C:\Windows\INF\setupapi.dev.log");
    let _ = fs::remove_file(r"C:\Windows\INF\setupapi.setup.log");

    eprintln!(
        "[+] etw: {} ETL + {} WER file(s) deleted, {} MiB freed, {} error(s)",
        stats.etl_deleted,
        stats.wer_deleted,
        stats.bytes_freed >> 20,
        stats.errors
    );
    stats
}
