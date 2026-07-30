/*
 * opsec_linux.rs — Linux nolog/opsec mode: prevent trace generation before it happens
 *
 * This module configures the machine to minimize forensic evidence generation at the
 * system level.  Focus is on prevention (volatile storage, disabled logging subsystems)
 * rather than destruction after the fact.
 *
 * Operations applied by apply_opsec_linux():
 *  1. journald volatile   — redirect journal to RAM only (lost on reboot)
 *  2. HISTSIZE=0 global   — disable shell history for root and all home users
 *  3. auditd silent       — disable Linux Audit subsystem at runtime and on boot
 *  4. sysctl hardening    — restrict dmesg, null core pattern, minimize swap
 *  5. Core dumps off      — PAM limits + systemd coredump config
 *  6. tmpfs /tmp          — ensure /tmp lives in RAM, persist in fstab
 *  7. rsyslog blocked     — drop all messages before any forwarding/writing rule
 *  8. SSH no logging      — force sshd LogLevel QUIET
 *  9. Cron cleanup        — hourly wipe of residual history and log files
 *
 * Backups: patched files are saved as <path>.s2bak before modification.
 * revert_opsec_linux() restores all backups and removes created files.
 *
 * Requires root (CAP_SYS_ADMIN, CAP_AUDIT_CONTROL).
 */

use std::fs;
use std::path::Path;
use std::process::Command;

use glob::glob;

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct OpsecLinuxStats {
    /// journald configured to use volatile (RAM-only) storage
    pub journald_volatile: bool,
    /// HISTFILE/HISTSIZE disabled system-wide
    pub histfile_disabled: bool,
    /// Linux Audit subsystem disabled at runtime
    pub audit_disabled: bool,
    /// Number of sysctl knobs successfully written/applied
    pub sysctl_applied: u32,
    /// Core dump generation disabled (PAM + systemd)
    pub coredump_disabled: bool,
    /// /tmp is currently backed by a tmpfs
    pub tmp_is_tmpfs: bool,
    /// rsyslog configured to drop all messages
    pub rsyslog_blocked: bool,
    /// sshd configured with LogLevel QUIET
    pub ssh_quiet: bool,
    /// Number of non-fatal errors encountered
    pub errors: u32,
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Copy <path> to <path>.s2bak before patching it.
/// Skips if the backup already exists (idempotent) or if the source does not exist.
fn backup_file(path: &str) {
    let bak = format!("{}.s2bak", path);
    if !Path::new(&bak).exists() && Path::new(path).exists() {
        let _ = fs::copy(path, &bak);
    }
}

/// Append `content` to `path` only when `marker` is not already present anywhere in the file.
/// Creates the file if it does not exist.  Returns true on success.
fn append_if_absent(path: &str, marker: &str, content: &str) -> bool {
    let existing = fs::read_to_string(path).unwrap_or_default();
    if existing.contains(marker) {
        return true; // Already patched — do not duplicate
    }
    backup_file(path);
    // Ensure there is exactly one blank separator before the injected block
    let sep = if existing.ends_with('\n') || existing.is_empty() {
        ""
    } else {
        "\n"
    };
    let new = format!("{}{}{}", existing, sep, content);
    fs::write(path, new).is_ok()
}

/// Run a process and return true when it exits with status 0.
fn run_cmd(prog: &str, args: &[&str]) -> bool {
    Command::new(prog)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Return true when the named systemd unit is in the "active" state.
fn service_active(name: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── 1. journald volatile ──────────────────────────────────────────────────────

const JOURNALD_CONF: &str = "/etc/systemd/journald.conf";

fn apply_journald_volatile(verbose: bool, stats: &mut OpsecLinuxStats) {
    let content = fs::read_to_string(JOURNALD_CONF).unwrap_or_else(|_| "[Journal]\n".to_string());

    if content.contains("Storage=volatile") {
        if verbose {
            eprintln!("[*] journald: already Storage=volatile, skipping");
        }
        stats.journald_volatile = true;
        return;
    }

    backup_file(JOURNALD_CONF);

    // Replace any existing Storage= directive (commented or not); remember whether we found one.
    let mut replaced = false;
    let new_lines: Vec<String> = content
        .lines()
        .map(|line| {
            let t = line.trim();
            if t.starts_with("Storage=") || t.starts_with("#Storage=") {
                replaced = true;
                "Storage=volatile".to_string()
            } else {
                line.to_string()
            }
        })
        .collect();

    let mut new_content = new_lines.join("\n");
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }

    // No Storage= directive found: inject it right after [Journal].
    // If [Journal] is missing too, append the whole section.
    if !replaced {
        if new_content.contains("[Journal]") {
            new_content = new_content.replacen("[Journal]", "[Journal]\nStorage=volatile", 1);
        } else {
            new_content.push_str("\n[Journal]\nStorage=volatile\n");
        }
    }

    match fs::write(JOURNALD_CONF, &new_content) {
        Ok(()) => {
            if verbose {
                eprintln!("[+] journald: set Storage=volatile in {}", JOURNALD_CONF);
            }
            if run_cmd("systemctl", &["restart", "systemd-journald"]) {
                if verbose {
                    eprintln!("[+] journald: systemd-journald restarted");
                }
            } else {
                if verbose {
                    eprintln!("[!] journald: restart failed (config was still written)");
                }
                stats.errors += 1;
            }
            stats.journald_volatile = true;
        }
        Err(e) => {
            if verbose {
                eprintln!(
                    "[!] journald: write {}: {} — trying tmpfs fallback",
                    JOURNALD_CONF, e
                );
            }
            stats.errors += 1;
            // Fallback: mount a tmpfs directly over /var/log/journal so new entries land in RAM.
            apply_journal_tmpfs_fallback(verbose, stats);
        }
    }
}

/// Mount a tmpfs on /var/log/journal so journal data never hits persistent storage.
fn apply_journal_tmpfs_fallback(verbose: bool, stats: &mut OpsecLinuxStats) {
    let _ = fs::create_dir_all("/var/log/journal");

    let rc = unsafe {
        libc::mount(
            c"tmpfs".as_ptr() as *const libc::c_char,
            c"/var/log/journal".as_ptr() as *const libc::c_char,
            c"tmpfs".as_ptr() as *const libc::c_char,
            libc::MS_NOSUID | libc::MS_NODEV,
            c"mode=0755,size=64m".as_ptr() as *const libc::c_void,
        )
    };

    if rc == 0 {
        if verbose {
            eprintln!("[+] journald: tmpfs mounted on /var/log/journal (fallback)");
        }
        stats.journald_volatile = true;
        let _ = run_cmd("systemctl", &["restart", "systemd-journald"]);
    } else {
        let errno = unsafe { *libc::__errno_location() };
        if verbose {
            eprintln!(
                "[!] journald: tmpfs fallback mount failed (errno {})",
                errno
            );
        }
        stats.errors += 1;
    }
}

// ── 2. HISTSIZE=0 global ──────────────────────────────────────────────────────

// Marker string used to detect whether we already patched a bashrc/profile file.
const HIST_MARKER: &str = "satan2: disable shell history";

// Content written to the profile.d dropin (sourced by all login shells).
const NO_HISTORY_PROFILE: &str = "\
# satan2: disable shell history for all users
unset HISTFILE
export HISTSIZE=0
export HISTFILESIZE=0
export HISTCONTROL=ignorealldups
";

// Block appended to bashrc files for interactive non-login shells.
const NO_HISTORY_BLOCK: &str = "\n\
# satan2: disable shell history\n\
unset HISTFILE\n\
export HISTSIZE=0\n\
export HISTFILESIZE=0\n\
export HISTCONTROL=ignorealldups\n";

fn apply_histsize_zero(verbose: bool, stats: &mut OpsecLinuxStats) {
    // Write a profile.d dropin — picked up by all POSIX login shells.
    match fs::write("/etc/profile.d/no_history.sh", NO_HISTORY_PROFILE) {
        Ok(()) => {
            if verbose {
                eprintln!("[+] history: wrote /etc/profile.d/no_history.sh");
            }
        }
        Err(e) => {
            if verbose {
                eprintln!("[!] history: write /etc/profile.d/no_history.sh: {}", e);
            }
            stats.errors += 1;
        }
    }

    // Patch /etc/bash.bashrc (interactive non-login shells, Debian/Ubuntu layout).
    if Path::new("/etc/bash.bashrc").exists() {
        if append_if_absent("/etc/bash.bashrc", HIST_MARKER, NO_HISTORY_BLOCK) {
            if verbose {
                eprintln!("[+] history: patched /etc/bash.bashrc");
            }
        } else {
            if verbose {
                eprintln!("[!] history: /etc/bash.bashrc patch failed");
            }
            stats.errors += 1;
        }
    }

    // Patch /root/.bashrc.
    if Path::new("/root/.bashrc").exists() {
        if append_if_absent("/root/.bashrc", HIST_MARKER, NO_HISTORY_BLOCK) {
            if verbose {
                eprintln!("[+] history: patched /root/.bashrc");
            }
        } else {
            if verbose {
                eprintln!("[!] history: /root/.bashrc patch failed");
            }
            stats.errors += 1;
        }
    }

    // Patch every /home/*/.bashrc found on the system.
    if let Ok(entries) = glob("/home/*/.bashrc") {
        for entry in entries.flatten() {
            let p = match entry.to_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            if append_if_absent(&p, HIST_MARKER, NO_HISTORY_BLOCK) {
                if verbose {
                    eprintln!("[+] history: patched {}", p);
                }
            } else {
                if verbose {
                    eprintln!("[!] history: patch failed: {}", p);
                }
                stats.errors += 1;
            }
        }
    }

    stats.histfile_disabled = true;
}

// ── 3. auditd silent ─────────────────────────────────────────────────────────

const AUDIT_RULES_PATH: &str = "/etc/audit/rules.d/opsec.rules";
const AUDIT_RULES_CONTENT: &str = "\
# satan2: persistently disable auditing at boot
-e 0
";

fn apply_audit_silent(verbose: bool, stats: &mut OpsecLinuxStats) {
    // Disable at runtime — no new audit records from this point forward.
    if run_cmd("auditctl", &["-e", "0"]) {
        if verbose {
            eprintln!("[+] audit: auditctl -e 0 applied");
        }
        stats.audit_disabled = true;
    } else {
        if verbose {
            eprintln!("[!] audit: auditctl -e 0 failed (not installed or no CAP_AUDIT_CONTROL)");
        }
        stats.errors += 1;
    }

    // Prevent auditd from starting on next boot.
    if !run_cmd("systemctl", &["disable", "--now", "auditd"]) {
        // Not critical — auditd may be absent or managed differently.
        if verbose {
            eprintln!(
                "[*] audit: systemctl disable auditd skipped (not found or already disabled)"
            );
        }
    } else if verbose {
        eprintln!("[+] audit: auditd systemd unit disabled");
    }

    // Persist -e 0 via audit rules so it survives auditd restarts.
    let rules_dir = Path::new("/etc/audit/rules.d");
    if rules_dir.exists() || fs::create_dir_all(rules_dir).is_ok() {
        match fs::write(AUDIT_RULES_PATH, AUDIT_RULES_CONTENT) {
            Ok(()) => {
                if verbose {
                    eprintln!("[+] audit: persistent rule written to {}", AUDIT_RULES_PATH);
                }
            }
            Err(e) => {
                if verbose {
                    eprintln!("[!] audit: write {}: {}", AUDIT_RULES_PATH, e);
                }
                stats.errors += 1;
            }
        }
    }
}

// ── 4. sysctl hardening ───────────────────────────────────────────────────────

const SYSCTL_CONF_PATH: &str = "/etc/sysctl.d/99-satan2-opsec.conf";

// Base knobs — these are safe on every kernel without optional modules.
const SYSCTL_BASE: &str = "\
# satan2: anti-trace sysctl hardening
# Restrict /proc/kmsg and dmesg(8) to CAP_SYSLOG (effectively root-only)
kernel.dmesg_restrict = 1
# Route core dumps to /dev/null so they are never written to disk
kernel.core_pattern = /dev/null
# PID suffix in core file names is moot with the null pattern above
kernel.core_uses_pid = 0
# Disable core dumps for setuid/setgid executables
fs.suid_dumpable = 0
# Minimize swap usage — keep sensitive pages in RAM rather than on disk
vm.swappiness = 0
";

// Optional line appended only when the nf_conntrack module is loaded.
const SYSCTL_CONNTRACK: &str = "\
# Silence conntrack log spam for invalid packets (nf_conntrack module loaded)
net.netfilter.nf_conntrack_log_invalid = 0
";

fn apply_sysctl_hardening(verbose: bool, stats: &mut OpsecLinuxStats) {
    let _ = fs::create_dir_all("/etc/sysctl.d");

    // Include the conntrack knob only when the corresponding sysfs entry exists.
    let mut content = SYSCTL_BASE.to_string();
    if Path::new("/proc/sys/net/netfilter/nf_conntrack_log_invalid").exists() {
        content.push_str(SYSCTL_CONNTRACK);
    }

    match fs::write(SYSCTL_CONF_PATH, &content) {
        Ok(()) => {
            if verbose {
                eprintln!("[+] sysctl: wrote {}", SYSCTL_CONF_PATH);
            }
            // Count non-blank, non-comment lines as the number of knobs.
            let n: u32 = content
                .lines()
                .filter(|l| {
                    let t = l.trim();
                    !t.is_empty() && !t.starts_with('#')
                })
                .count() as u32;

            if run_cmd("sysctl", &["-p", SYSCTL_CONF_PATH]) {
                if verbose {
                    eprintln!("[+] sysctl: applied {} knob(s)", n);
                }
            } else {
                if verbose {
                    eprintln!("[!] sysctl: sysctl -p returned non-zero (file still written for next boot)");
                }
                stats.errors += 1;
            }
            stats.sysctl_applied = n;
        }
        Err(e) => {
            if verbose {
                eprintln!("[!] sysctl: write {}: {}", SYSCTL_CONF_PATH, e);
            }
            stats.errors += 1;
        }
    }
}

// ── 5. Core dumps off ─────────────────────────────────────────────────────────

const LIMITS_CONF_PATH: &str = "/etc/security/limits.d/no-core.conf";
const LIMITS_CONF_CONTENT: &str = "\
# satan2: disable core dumps for all users via PAM limits
* hard core 0
* soft core 0
";

const COREDUMP_CONF_DIR: &str = "/etc/systemd/coredump.conf.d";
const COREDUMP_CONF_PATH: &str = "/etc/systemd/coredump.conf.d/opsec.conf";
const COREDUMP_CONF_CONTENT: &str = "\
[Coredump]
# satan2: discard all core dumps immediately
Storage=none
ProcessSizeMax=0
";

fn apply_coredump_disabled(verbose: bool, stats: &mut OpsecLinuxStats) {
    // PAM hard/soft limits — effective for new sessions after login.
    let _ = fs::create_dir_all("/etc/security/limits.d");
    match fs::write(LIMITS_CONF_PATH, LIMITS_CONF_CONTENT) {
        Ok(()) => {
            if verbose {
                eprintln!("[+] coredump: wrote PAM limits to {}", LIMITS_CONF_PATH);
            }
        }
        Err(e) => {
            if verbose {
                eprintln!("[!] coredump: write {}: {}", LIMITS_CONF_PATH, e);
            }
            stats.errors += 1;
        }
    }

    // systemd-coredump override — suppresses coredump processing by PID 1.
    let _ = fs::create_dir_all(COREDUMP_CONF_DIR);
    match fs::write(COREDUMP_CONF_PATH, COREDUMP_CONF_CONTENT) {
        Ok(()) => {
            if verbose {
                eprintln!(
                    "[+] coredump: wrote systemd config to {}",
                    COREDUMP_CONF_PATH
                );
            }
            stats.coredump_disabled = true;
        }
        Err(e) => {
            if verbose {
                eprintln!("[!] coredump: write {}: {}", COREDUMP_CONF_PATH, e);
            }
            stats.errors += 1;
        }
    }

    // Tell systemd to re-read unit files so the coredump.conf.d drop-in takes effect.
    let _ = run_cmd("systemctl", &["daemon-reexec"]);
}

// ── 6. tmpfs /tmp ─────────────────────────────────────────────────────────────

const FSTAB_PATH: &str = "/etc/fstab";
// Marker used to detect an existing /tmp tmpfs entry in fstab.
const FSTAB_MARKER: &str = "tmpfs /tmp";
// The fstab line to add if none is present.
const FSTAB_TMP_ENTRY: &str = "\n\
# satan2: /tmp on tmpfs (volatile, lost on reboot)\n\
tmpfs\t/tmp\ttmpfs\tdefaults,nosuid,nodev,mode=1777\t0 0\n";

/// Parse /proc/mounts and return true when /tmp is backed by a tmpfs.
fn tmp_is_tmpfs() -> bool {
    fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .any(|line| {
            let mut f = line.split_whitespace();
            // Format: device mount_point fstype ...
            let _dev = f.next().unwrap_or("");
            let mp = f.next().unwrap_or("");
            let fstype = f.next().unwrap_or("");
            mp == "/tmp" && fstype == "tmpfs"
        })
}

fn apply_tmpfs_tmp(verbose: bool, stats: &mut OpsecLinuxStats) {
    if tmp_is_tmpfs() {
        if verbose {
            eprintln!("[*] tmpfs/tmp: /tmp is already a tmpfs");
        }
        stats.tmp_is_tmpfs = true;
    } else {
        // Mount a tmpfs over /tmp at runtime.
        let rc = unsafe {
            libc::mount(
                c"tmpfs".as_ptr() as *const libc::c_char,
                c"/tmp".as_ptr() as *const libc::c_char,
                c"tmpfs".as_ptr() as *const libc::c_char,
                libc::MS_NOSUID | libc::MS_NODEV,
                c"mode=1777".as_ptr() as *const libc::c_void,
            )
        };

        if rc == 0 {
            if verbose {
                eprintln!("[+] tmpfs/tmp: tmpfs mounted on /tmp");
            }
            stats.tmp_is_tmpfs = true;
        } else {
            let errno = unsafe { *libc::__errno_location() };
            if verbose {
                eprintln!("[!] tmpfs/tmp: mount failed (errno {})", errno);
            }
            stats.errors += 1;
        }
    }

    // Persist the entry in /etc/fstab so it survives reboots.
    if append_if_absent(FSTAB_PATH, FSTAB_MARKER, FSTAB_TMP_ENTRY) {
        if verbose {
            eprintln!("[+] tmpfs/tmp: fstab entry ensured");
        }
    } else {
        if verbose {
            eprintln!("[!] tmpfs/tmp: fstab patch failed");
        }
        stats.errors += 1;
    }
}

// ── 7. rsyslog blocked ────────────────────────────────────────────────────────

const RSYSLOG_OPSEC_PATH: &str = "/etc/rsyslog.d/00-satan2-opsec.conf";
// Prefix "00-" ensures this file is included before any other drop-in,
// so the "stop" action drops every message before any forwarding/writing rule.
// The RainerScript "stop" action requires rsyslog >= 7.x (all modern distros).
const RSYSLOG_OPSEC_CONTENT: &str = "\
# satan2: drop all log messages before any other rsyslog rule is evaluated
# Loaded first (00- prefix) to intercept everything.
*.* stop
";

fn apply_rsyslog_blocked(verbose: bool, stats: &mut OpsecLinuxStats) {
    // Only act when rsyslog is present; skip silently if the config dir is missing.
    if !Path::new("/etc/rsyslog.d").exists() {
        if verbose {
            eprintln!("[*] rsyslog: /etc/rsyslog.d not found, skipping");
        }
        return;
    }

    match fs::write(RSYSLOG_OPSEC_PATH, RSYSLOG_OPSEC_CONTENT) {
        Ok(()) => {
            if verbose {
                eprintln!("[+] rsyslog: wrote {}", RSYSLOG_OPSEC_PATH);
            }
            // Restart rsyslog to pick up the new config (if it is running).
            if service_active("rsyslog") {
                if run_cmd("systemctl", &["restart", "rsyslog"]) {
                    if verbose {
                        eprintln!("[+] rsyslog: service restarted");
                    }
                } else {
                    if verbose {
                        eprintln!("[!] rsyslog: restart failed");
                    }
                    stats.errors += 1;
                }
            }
            stats.rsyslog_blocked = true;
        }
        Err(e) => {
            if verbose {
                eprintln!("[!] rsyslog: write {}: {}", RSYSLOG_OPSEC_PATH, e);
            }
            stats.errors += 1;
        }
    }
}

// ── 8. SSH no logging ─────────────────────────────────────────────────────────

const SSHD_CONFIG_PATH: &str = "/etc/ssh/sshd_config";
// Marker used to detect whether the config already has LogLevel QUIET.
const SSHD_QUIET_MARKER: &str = "LogLevel QUIET";

fn apply_ssh_quiet(verbose: bool, stats: &mut OpsecLinuxStats) {
    if !Path::new(SSHD_CONFIG_PATH).exists() {
        if verbose {
            eprintln!("[*] ssh: {} not found, skipping", SSHD_CONFIG_PATH);
        }
        return;
    }

    let content = match fs::read_to_string(SSHD_CONFIG_PATH) {
        Ok(c) => c,
        Err(e) => {
            if verbose {
                eprintln!("[!] ssh: read {}: {}", SSHD_CONFIG_PATH, e);
            }
            stats.errors += 1;
            return;
        }
    };

    if content.contains(SSHD_QUIET_MARKER) {
        if verbose {
            eprintln!("[*] ssh: already LogLevel QUIET");
        }
        stats.ssh_quiet = true;
        return;
    }

    backup_file(SSHD_CONFIG_PATH);

    // Replace any existing LogLevel directive (active or commented) in-place.
    let mut replaced = false;
    let new_lines: Vec<String> = content
        .lines()
        .map(|line| {
            let t = line.trim();
            if t.starts_with("LogLevel") || t.starts_with("#LogLevel") {
                replaced = true;
                "LogLevel QUIET".to_string()
            } else {
                line.to_string()
            }
        })
        .collect();

    let mut new_content = new_lines.join("\n");
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }

    // No existing LogLevel line: append one at the end.
    if !replaced {
        new_content.push_str("\n# satan2: suppress SSH logging\nLogLevel QUIET\n");
    }

    match fs::write(SSHD_CONFIG_PATH, &new_content) {
        Ok(()) => {
            if verbose {
                eprintln!("[+] ssh: LogLevel QUIET written to {}", SSHD_CONFIG_PATH);
            }
            // Restart whichever sshd service is currently active.
            for svc in &["sshd", "ssh", "openssh-server"] {
                if service_active(svc) {
                    if run_cmd("systemctl", &["restart", svc]) {
                        if verbose {
                            eprintln!("[+] ssh: {} restarted", svc);
                        }
                    } else {
                        if verbose {
                            eprintln!("[!] ssh: {} restart failed", svc);
                        }
                        stats.errors += 1;
                    }
                    break;
                }
            }
            stats.ssh_quiet = true;
        }
        Err(e) => {
            if verbose {
                eprintln!("[!] ssh: write {}: {}", SSHD_CONFIG_PATH, e);
            }
            stats.errors += 1;
        }
    }
}

// ── 9. Cron cleanup ───────────────────────────────────────────────────────────

const CRON_OPSEC_PATH: &str = "/etc/cron.d/opsec_cleanup";
// Single cron entry (all on one line) that truncates common history files
// and flushes journal data every hour.  Runs as root.
const CRON_OPSEC_CONTENT: &str =
    "# satan2: hourly trace cleanup — wipe history files and flush journal\n\
0 * * * * root \
find /root /home -maxdepth 2 -name '.bash_history'   -exec truncate -s 0 {} \\; 2>/dev/null; \
find /root /home -maxdepth 2 -name '.zsh_history'    -exec truncate -s 0 {} \\; 2>/dev/null; \
find /root /home -maxdepth 2 -name '.python_history' -exec truncate -s 0 {} \\; 2>/dev/null; \
journalctl --flush --rotate --vacuum-size=1 >/dev/null 2>&1\n";

fn apply_cron_cleanup(verbose: bool, stats: &mut OpsecLinuxStats) {
    if !Path::new("/etc/cron.d").exists() {
        if verbose {
            eprintln!("[*] cron: /etc/cron.d not found, skipping");
        }
        return;
    }

    match fs::write(CRON_OPSEC_PATH, CRON_OPSEC_CONTENT) {
        Ok(()) => {
            if verbose {
                eprintln!(
                    "[+] cron: hourly cleanup job written to {}",
                    CRON_OPSEC_PATH
                );
            }
        }
        Err(e) => {
            if verbose {
                eprintln!("[!] cron: write {}: {}", CRON_OPSEC_PATH, e);
            }
            stats.errors += 1;
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Apply all nolog/opsec configurations on a Linux system.
///
/// Each sub-operation is best-effort: failures increment `stats.errors` but do
/// not abort the remaining operations.  Call `revert_opsec_linux()` to undo.
///
/// Returns an `OpsecLinuxStats` struct describing the outcome of each operation.
pub fn apply_opsec_linux(verbose: bool) -> OpsecLinuxStats {
    let mut stats = OpsecLinuxStats::default();

    if verbose {
        eprintln!("[*] opsec_linux: entering nolog/opsec mode...");
    }

    apply_journald_volatile(verbose, &mut stats);
    apply_histsize_zero(verbose, &mut stats);
    apply_audit_silent(verbose, &mut stats);
    apply_sysctl_hardening(verbose, &mut stats);
    apply_coredump_disabled(verbose, &mut stats);
    apply_tmpfs_tmp(verbose, &mut stats);
    apply_rsyslog_blocked(verbose, &mut stats);
    apply_ssh_quiet(verbose, &mut stats);
    apply_cron_cleanup(verbose, &mut stats);

    if verbose {
        eprintln!("[+] opsec_linux: done — {} error(s)", stats.errors);
        eprintln!("    journald_volatile : {}", stats.journald_volatile);
        eprintln!("    histfile_disabled : {}", stats.histfile_disabled);
        eprintln!("    audit_disabled    : {}", stats.audit_disabled);
        eprintln!("    sysctl_applied    : {}", stats.sysctl_applied);
        eprintln!("    coredump_disabled : {}", stats.coredump_disabled);
        eprintln!("    tmp_is_tmpfs      : {}", stats.tmp_is_tmpfs);
        eprintln!("    rsyslog_blocked   : {}", stats.rsyslog_blocked);
        eprintln!("    ssh_quiet         : {}", stats.ssh_quiet);
    }

    stats
}

/// Revert all opsec configurations by restoring .s2bak backup files and
/// removing files that were newly created by apply_opsec_linux().
///
/// After restoring, relevant services are restarted to pick up the original config.
pub fn revert_opsec_linux(verbose: bool) {
    if verbose {
        eprintln!("[*] opsec_linux: reverting to pre-opsec state...");
    }

    // ── Restore files that were patched in-place ───────────────────────────────
    let patched = [
        JOURNALD_CONF,
        "/etc/bash.bashrc",
        "/root/.bashrc",
        SSHD_CONFIG_PATH,
        FSTAB_PATH,
    ];

    for path in &patched {
        let bak = format!("{}.s2bak", path);
        if Path::new(&bak).exists() {
            match fs::copy(&bak, path) {
                Ok(_) => {
                    if verbose {
                        eprintln!("[+] revert: restored {}", path);
                    }
                    let _ = fs::remove_file(&bak);
                }
                Err(e) => {
                    if verbose {
                        eprintln!("[!] revert: restore {}: {}", path, e);
                    }
                }
            }
        }
    }

    // Restore per-user bashrc backups from /home/*/.bashrc.s2bak.
    if let Ok(entries) = glob("/home/*/.bashrc.s2bak") {
        for entry in entries.flatten() {
            let bak_path = entry.to_str().unwrap_or("").to_string();
            // Strip the ".s2bak" suffix to recover the original path.
            let orig_path = bak_path.trim_end_matches(".s2bak").to_string();
            match fs::copy(&bak_path, &orig_path) {
                Ok(_) => {
                    if verbose {
                        eprintln!("[+] revert: restored {}", orig_path);
                    }
                    let _ = fs::remove_file(&bak_path);
                }
                Err(e) => {
                    if verbose {
                        eprintln!("[!] revert: restore {}: {}", orig_path, e);
                    }
                }
            }
        }
    }

    // ── Remove files that were newly created by apply_opsec_linux() ───────────
    let created = [
        "/etc/profile.d/no_history.sh",
        AUDIT_RULES_PATH,
        SYSCTL_CONF_PATH,
        LIMITS_CONF_PATH,
        COREDUMP_CONF_PATH,
        RSYSLOG_OPSEC_PATH,
        CRON_OPSEC_PATH,
    ];

    for path in &created {
        if Path::new(path).exists() {
            match fs::remove_file(path) {
                Ok(()) => {
                    if verbose {
                        eprintln!("[+] revert: removed {}", path);
                    }
                }
                Err(e) => {
                    if verbose {
                        eprintln!("[!] revert: remove {}: {}", path, e);
                    }
                }
            }
        }
    }

    // ── Re-enable and restart affected services ────────────────────────────────

    // Restore journald configuration and restart the service.
    let _ = run_cmd("systemctl", &["restart", "systemd-journald"]);

    // Re-enable auditd and restore runtime audit state.
    let _ = run_cmd("systemctl", &["enable", "auditd"]);
    let _ = run_cmd("auditctl", &["-e", "1"]);

    // Re-apply all sysctl settings from remaining drop-in files (our file was deleted above).
    let _ = run_cmd("sysctl", &["--system"]);

    // Restart rsyslog if it is active so it picks up the restored config.
    if service_active("rsyslog") {
        let _ = run_cmd("systemctl", &["restart", "rsyslog"]);
    }

    // Restart whichever sshd service is running.
    for svc in &["sshd", "ssh", "openssh-server"] {
        if service_active(svc) {
            let _ = run_cmd("systemctl", &["restart", svc]);
            break;
        }
    }

    if verbose {
        eprintln!("[+] opsec_linux: revert complete");
    }
}
