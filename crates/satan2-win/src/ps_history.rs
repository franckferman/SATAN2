/*
 * ps_history.rs — PowerShell command history removal
 *
 * PSReadLine (default in PS 5.1+) saves history to:
 *   %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
 *
 * Also covers Windows PowerShell ISE history and VS Code terminal history.
 */

use std::env;
use std::fs;

#[derive(Debug, Default)]
pub struct PsHistoryStats {
    pub files_wiped: u32,
    pub errors: u32,
}

fn wipe_file(path: &str, stats: &mut PsHistoryStats) {
    if !std::path::Path::new(path).exists() {
        return;
    }

    match fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => {
            if f.set_len(0).is_ok() {
                stats.files_wiped += 1;
                eprintln!("[+] ps_history: wiped {}", path);
            } else {
                eprintln!("[!] ps_history: truncate failed: {}", path);
                stats.errors += 1;
            }
        }
        Err(e) => {
            eprintln!("[!] ps_history: open {}: {}", path, e);
            stats.errors += 1;
        }
    }
}

pub fn wipe_ps_history(verbose: bool) -> PsHistoryStats {
    let mut stats = PsHistoryStats::default();

    let appdata = env::var("APPDATA").unwrap_or_else(|_| {
        format!(
            r"C:\Users\{}\AppData\Roaming",
            env::var("USERNAME").unwrap_or_else(|_| "Default".into())
        )
    });

    let paths = [
        format!(
            r"{}\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            appdata
        ),
        // PowerShell ISE
        format!(
            r"{}\Microsoft\Windows\PowerShell\ISE\ISEHistory.ps1",
            appdata
        ),
    ];

    for path in &paths {
        if verbose {
            eprintln!("[*] ps_history: checking {}", path);
        }
        wipe_file(path, &mut stats);
    }

    // Also check all user profiles for multi-user systems
    let users_base = r"C:\Users";
    if let Ok(rd) = fs::read_dir(users_base) {
        for entry in rd.flatten() {
            let user_path = entry.path().to_str().unwrap_or("").to_string();
            let hist = format!(
                r"{}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
                user_path
            );
            if hist.contains("Default") || hist.contains("Public") {
                continue;
            }
            wipe_file(&hist, &mut stats);
        }
    }

    eprintln!(
        "[+] ps_history: {} file(s) wiped, {} error(s)",
        stats.files_wiped, stats.errors
    );
    stats
}
