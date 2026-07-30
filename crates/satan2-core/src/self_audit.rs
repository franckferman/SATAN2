// Post-cleanup audit: enumerate residual forensic artifacts that could identify
// attacker activity. Returns a structured list for reporting or further cleanup.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub category: &'static str,
    pub path: String,
    pub description: String,
    pub severity: u8, // 1=low, 2=medium, 3=high
}

fn check_file_nonempty(
    findings: &mut Vec<AuditFinding>,
    path: &str,
    category: &'static str,
    description: &str,
    severity: u8,
) {
    if let Ok(m) = fs::metadata(path) {
        if m.len() > 0 {
            findings.push(AuditFinding {
                category,
                path: path.to_string(),
                description: format!("{} ({} bytes)", description, m.len()),
                severity,
            });
        }
    }
}

fn check_dir_nonempty(
    findings: &mut Vec<AuditFinding>,
    path: &str,
    category: &'static str,
    description: &str,
    severity: u8,
) {
    let p = Path::new(path);
    if !p.is_dir() {
        return;
    }
    let has_files = fs::read_dir(p)
        .ok()
        .map(|mut r| r.next().is_some())
        .unwrap_or(false);
    if has_files {
        findings.push(AuditFinding {
            category,
            path: path.to_string(),
            description: description.to_string(),
            severity,
        });
    }
}

fn check_wtmp_has_records(findings: &mut Vec<AuditFinding>) {
    const UTMP_SIZE: u64 = 384;
    if let Ok(m) = fs::metadata("/var/log/wtmp") {
        let records = m.len() / UTMP_SIZE;
        if records > 0 {
            findings.push(AuditFinding {
                category: "wtmp",
                path: "/var/log/wtmp".to_string(),
                description: format!("{} login records (readable via `last`)", records),
                severity: 3,
            });
        }
    }
}

fn check_browser_history(findings: &mut Vec<AuditFinding>, home: &Path) {
    // Firefox
    let ff = home.join(".mozilla/firefox");
    if ff.is_dir() {
        if let Ok(rd) = fs::read_dir(&ff) {
            for entry in rd.flatten() {
                let places = entry.path().join("places.sqlite");
                if places.exists() {
                    if let Ok(m) = fs::metadata(&places) {
                        if m.len() > 8192 {
                            findings.push(AuditFinding {
                                category: "browser",
                                path: places.to_string_lossy().to_string(),
                                description: format!("Firefox history ({} bytes)", m.len()),
                                severity: 2,
                            });
                        }
                    }
                }
            }
        }
    }
    // Chromium / Chrome
    for browser in &[
        "chromium",
        "google-chrome",
        "google-chrome-stable",
        "brave-browser",
    ] {
        let h = home.join(".config").join(browser).join("Default/History");
        if let Ok(m) = fs::metadata(&h) {
            if m.len() > 8192 {
                findings.push(AuditFinding {
                    category: "browser",
                    path: h.to_string_lossy().to_string(),
                    description: format!("{} history ({} bytes)", browser, m.len()),
                    severity: 2,
                });
            }
        }
    }
}

fn check_ssh_keys(findings: &mut Vec<AuditFinding>, home: &Path) {
    let ssh = home.join(".ssh");
    if !ssh.is_dir() {
        return;
    }
    for name in &["id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"] {
        let key = ssh.join(name);
        if key.exists() {
            findings.push(AuditFinding {
                category: "ssh",
                path: key.to_string_lossy().to_string(),
                description: format!("Private SSH key: {} (identifies user)", name),
                severity: 3,
            });
        }
    }
    check_file_nonempty(
        findings,
        &ssh.join("known_hosts").to_string_lossy(),
        "ssh",
        "known_hosts reveals target hosts",
        2,
    );
}

fn check_package_logs(findings: &mut Vec<AuditFinding>) {
    let dpkg = "/var/log/dpkg.log";
    if let Ok(c) = fs::read_to_string(dpkg) {
        if c.len() > 200 {
            findings.push(AuditFinding {
                category: "pkg-logs",
                path: dpkg.to_string(),
                description: format!("dpkg log has {} bytes of install history", c.len()),
                severity: 2,
            });
        }
    }
    check_file_nonempty(
        findings,
        "/var/log/apt/history.log",
        "pkg-logs",
        "apt history log present",
        2,
    );
    check_file_nonempty(
        findings,
        "/var/log/pacman.log",
        "pkg-logs",
        "pacman log present",
        2,
    );
}

fn check_running_processes(findings: &mut Vec<AuditFinding>) {
    // Check if any suspicious shell sessions are visible in /proc
    let suspicious = &[
        "nc",
        "ncat",
        "nmap",
        "metasploit",
        "msfconsole",
        "mimikatz",
        "bloodhound",
        "crackmapexec",
    ];
    if let Ok(rd) = fs::read_dir("/proc") {
        for entry in rd.flatten() {
            let p = entry.path().join("cmdline");
            if let Ok(cmd) = fs::read_to_string(&p) {
                let cmd_lower = cmd.to_lowercase();
                for &kw in suspicious {
                    if cmd_lower.contains(kw) {
                        findings.push(AuditFinding {
                            category: "process",
                            path: entry.path().to_string_lossy().to_string(),
                            description: format!(
                                "Potentially suspicious process: cmdline contains '{}'",
                                kw
                            ),
                            severity: 3,
                        });
                        break;
                    }
                }
            }
        }
    }
}

fn check_cron(findings: &mut Vec<AuditFinding>) {
    check_dir_nonempty(
        findings,
        "/etc/cron.d",
        "persistence",
        "/etc/cron.d entries present (check for backdoors)",
        2,
    );
    for f in &[
        "/etc/crontab",
        "/var/spool/cron/root",
        "/var/spool/cron/crontabs/root",
    ] {
        check_file_nonempty(
            findings,
            f,
            "persistence",
            "root crontab has entries — potential persistence",
            2,
        );
    }
}

fn home_dirs() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    if let Ok(c) = fs::read_to_string("/etc/passwd") {
        for line in c.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 {
                let p = PathBuf::from(parts[5]);
                if p.exists() && p != std::path::Path::new("/") {
                    homes.push(p);
                }
            }
        }
    }
    homes
}

pub fn audit_artifacts(verbose: bool) -> Vec<AuditFinding> {
    let mut f: Vec<AuditFinding> = Vec::new();

    // ── Auth / access logs ────────────────────────────────────────────────────
    for path in &[
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/audit/audit.log",
    ] {
        check_file_nonempty(&mut f, path, "auth-logs", "Auth log has content", 3);
    }
    for path in &["/var/log/syslog", "/var/log/messages"] {
        check_file_nonempty(&mut f, path, "syslog", "System log has content", 2);
    }

    // ── wtmp / utmp / login records ──────────────────────────────────────────
    check_wtmp_has_records(&mut f);
    check_file_nonempty(
        &mut f,
        "/var/log/lastlog",
        "wtmp",
        "lastlog records last login per user",
        2,
    );
    check_file_nonempty(
        &mut f,
        "/var/log/btmp",
        "wtmp",
        "btmp records failed login attempts (readable via `lastb`)",
        2,
    );
    check_file_nonempty(
        &mut f,
        "/var/log/faillog",
        "wtmp",
        "faillog PAM per-UID failure counters",
        1,
    );
    check_file_nonempty(
        &mut f,
        "/var/lib/wtmpdb/wtmpdb.db",
        "wtmp",
        "wtmpdb SQLite login DB (Debian 13+)",
        2,
    );

    // ── Package manager logs ──────────────────────────────────────────────────
    check_package_logs(&mut f);

    // ── Per-user artifacts ────────────────────────────────────────────────────
    for home in home_dirs() {
        let h = home.to_string_lossy().to_string();

        check_file_nonempty(
            &mut f,
            &format!("{}/.bash_history", h),
            "shell-history",
            "Bash history has commands",
            3,
        );
        check_file_nonempty(
            &mut f,
            &format!("{}/.zsh_history", h),
            "shell-history",
            "Zsh history has commands",
            3,
        );
        check_file_nonempty(
            &mut f,
            &format!("{}/.local/share/recently-used.xbel", h),
            "recent-files",
            "GNOME recent-files list present",
            2,
        );

        check_browser_history(&mut f, &home);
        check_ssh_keys(&mut f, &home);

        // Docker client credentials
        check_file_nonempty(
            &mut f,
            &format!("{}/.docker/config.json", h),
            "docker",
            "Docker client config may contain credentials",
            2,
        );

        // GNOME Tracker (search index recording all accessed file paths)
        check_dir_nonempty(
            &mut f,
            &format!("{}/.local/share/tracker", h),
            "tracker",
            "GNOME Tracker index present (accessed file paths)",
            1,
        );
        check_dir_nonempty(
            &mut f,
            &format!("{}/.local/share/tracker3", h),
            "tracker",
            "GNOME Tracker3 index present",
            1,
        );
        check_dir_nonempty(
            &mut f,
            &format!("{}/.local/share/gvfs-metadata", h),
            "tracker",
            "GNOME gvfs-metadata present (file access metadata per path)",
            1,
        );
    }

    // ── Process traces ────────────────────────────────────────────────────────
    check_running_processes(&mut f);

    // ── Cron / persistence ────────────────────────────────────────────────────
    check_cron(&mut f);

    // ── Swap ─────────────────────────────────────────────────────────────────
    if let Ok(swaps) = fs::read_to_string("/proc/swaps") {
        if swaps.lines().count() > 1 {
            f.push(AuditFinding {
                category: "swap",
                path: "/proc/swaps".to_string(),
                description: "Swap is active — memory artifacts may persist on disk".to_string(),
                severity: 2,
            });
        }
    }

    // ── Journal ───────────────────────────────────────────────────────────────
    check_dir_nonempty(
        &mut f,
        "/var/log/journal",
        "journal",
        "Persistent systemd journal present",
        2,
    );

    // ── Kernel / daemon logs ──────────────────────────────────────────────────
    check_file_nonempty(
        &mut f,
        "/var/log/kern.log",
        "kernel",
        "kern.log has content (USB events, module loads, network events)",
        2,
    );
    check_file_nonempty(
        &mut f,
        "/var/log/dmesg",
        "kernel",
        "dmesg snapshot present",
        1,
    );
    check_file_nonempty(
        &mut f,
        "/var/log/daemon.log",
        "syslog",
        "daemon.log records background service events",
        1,
    );

    // ── Web server logs ───────────────────────────────────────────────────────
    for path in &[
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
    ] {
        check_file_nonempty(
            &mut f,
            path,
            "web-logs",
            "Web server log has content (HTTP requests, client IPs)",
            2,
        );
    }

    // ── Service logs (FTP / DB) ───────────────────────────────────────────────
    for path in &[
        "/var/log/xferlog",
        "/var/log/vsftpd.log",
        "/var/log/pureftp.log",
    ] {
        check_file_nonempty(&mut f, path, "ftp-logs", "FTP transfer log present", 2);
    }
    for path in &[
        "/var/log/mysql.log",
        "/var/log/mysqld.log",
        "/var/log/mysql/error.log",
    ] {
        check_file_nonempty(&mut f, path, "db-logs", "MySQL/MariaDB log present", 1);
    }

    // ── NetworkManager connection profiles ────────────────────────────────────
    check_dir_nonempty(
        &mut f,
        "/etc/NetworkManager/system-connections",
        "network",
        "NetworkManager profiles present (WiFi credentials + connection history)",
        3,
    );

    if verbose {
        eprintln!("[+] self-audit: {} findings", f.len());
        for finding in &f {
            eprintln!(
                "  [{}] ({}) {} — {}",
                match finding.severity {
                    3 => "HIGH",
                    2 => "MED",
                    _ => "LOW",
                },
                finding.category,
                finding.path,
                finding.description
            );
        }
    }
    f
}
