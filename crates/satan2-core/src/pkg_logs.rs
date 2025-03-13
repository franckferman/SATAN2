#[cfg(target_os = "linux")]
// pkg_logs.rs — wipe package manager logs and caches
//
// Covered:
//   Debian/Ubuntu  — dpkg, apt (log + list cache + deb archive cache)
//   RHEL/CentOS    — yum, dnf, dnf5 (logs + history databases)
//   Arch Linux     — pacman (log + pkg cache)
//   openSUSE/SLES  — zypper / zypp
//   Snap           — syslog contains snap install records
//   Per-user       — pip, npm, gem (Ruby), cargo registry, Go module cache

use std::fs;
use std::path::Path;
use glob::glob;

#[derive(Debug, Default)]
pub struct PkgLogsStats {
    pub files_wiped:  u32,
    pub dirs_cleared: u32,
    pub bytes_freed:  u64,
    pub errors:       u32,
}

fn remove_file(path: &str, stats: &mut PkgLogsStats, verbose: bool) {
    let p = Path::new(path);
    if !p.exists() { return; }
    let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    match fs::remove_file(p) {
        Ok(()) => {
            if verbose { eprintln!("[*] pkg-logs: rm {}", path); }
            stats.files_wiped += 1;
            stats.bytes_freed += size;
        }
        Err(e) => { eprintln!("[!] pkg-logs: {}: {}", path, e); stats.errors += 1; }
    }
}

fn remove_glob(pattern: &str, stats: &mut PkgLogsStats, verbose: bool) {
    for entry in glob(pattern).into_iter().flatten().flatten() {
        remove_file(&entry.to_string_lossy(), stats, verbose);
    }
}

fn truncate_file(path: &str, stats: &mut PkgLogsStats, verbose: bool) {
    let p = Path::new(path);
    if !p.exists() { return; }
    let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    match fs::OpenOptions::new().write(true).open(p).and_then(|f| f.set_len(0)) {
        Ok(()) => {
            if verbose { eprintln!("[*] pkg-logs: truncated {}", path); }
            stats.files_wiped += 1;
            stats.bytes_freed += size;
        }
        Err(e) => { eprintln!("[!] pkg-logs: truncate {}: {}", path, e); stats.errors += 1; }
    }
}

fn remove_dir(path: &str, stats: &mut PkgLogsStats, verbose: bool) {
    let p = Path::new(path);
    if !p.is_dir() { return; }
    match fs::remove_dir_all(p) {
        Ok(()) => {
            if verbose { eprintln!("[*] pkg-logs: rmdir {}", path); }
            stats.dirs_cleared += 1;
        }
        Err(e) => { eprintln!("[!] pkg-logs: rmdir {}: {}", path, e); stats.errors += 1; }
    }
}

pub fn wipe_pkg_logs(verbose: bool) -> PkgLogsStats {
    let mut stats = PkgLogsStats::default();

    // ── Debian / Ubuntu ───────────────────────────────────────────────────────
    remove_glob("/var/log/dpkg.log*",          &mut stats, verbose);
    remove_glob("/var/log/apt/history.log*",   &mut stats, verbose);
    remove_glob("/var/log/apt/term.log*",      &mut stats, verbose);
    remove_file("/var/log/apt/eipp.log.xz",    &mut stats, verbose);
    // Downloaded packages cache (shows what was installed)
    remove_dir("/var/cache/apt/archives",      &mut stats, verbose);
    // Package list cache (reveals what was searched / updated)
    remove_dir("/var/lib/apt/lists",           &mut stats, verbose);

    // ── RHEL / CentOS / Fedora ────────────────────────────────────────────────
    remove_glob("/var/log/yum.log*",           &mut stats, verbose);
    remove_glob("/var/log/dnf.log*",           &mut stats, verbose);
    remove_glob("/var/log/dnf.librepo.log*",   &mut stats, verbose);
    remove_glob("/var/log/dnf.rpm.log*",       &mut stats, verbose);
    remove_glob("/var/log/dnf5.log*",          &mut stats, verbose);
    // DNF transaction history DB (records all installs/upgrades with timestamps)
    remove_dir("/var/lib/dnf/history",         &mut stats, verbose);
    remove_dir("/var/lib/yum/history",         &mut stats, verbose);
    // DNF cache
    remove_dir("/var/cache/dnf",               &mut stats, verbose);
    remove_dir("/var/cache/yum",               &mut stats, verbose);

    // ── Arch Linux ────────────────────────────────────────────────────────────
    truncate_file("/var/log/pacman.log",       &mut stats, verbose);
    // Package download cache
    remove_dir("/var/cache/pacman/pkg",        &mut stats, verbose);

    // ── openSUSE / SLES ───────────────────────────────────────────────────────
    remove_glob("/var/log/zypper.log*",        &mut stats, verbose);
    remove_glob("/var/log/zypp/history*",      &mut stats, verbose);

    // ── Per-user package managers ─────────────────────────────────────────────
    let homes = user_home_dirs();
    for home in &homes {
        // pip logs
        remove_glob(&format!("{}/.local/share/pip/*.log", home), &mut stats, verbose);
        remove_glob(&format!("{}/.pip/*.log",              home), &mut stats, verbose);
        // pip cache (contains hashes / filenames of downloaded packages)
        remove_dir(&format!("{}/.cache/pip",               home), &mut stats, verbose);

        // npm install logs
        remove_dir(&format!("{}/.npm/_logs",               home), &mut stats, verbose);
        // npm cache
        remove_dir(&format!("{}/.npm/_cacache",            home), &mut stats, verbose);

        // gem logs
        remove_glob(&format!("{}/.gem/*.log",              home), &mut stats, verbose);

        // cargo registry cache — filenames reveal downloaded crates
        remove_dir(&format!("{}/.cargo/registry/cache",    home), &mut stats, verbose);
        remove_dir(&format!("{}/.cargo/registry/src",      home), &mut stats, verbose);

        // Go module cache
        remove_dir(&format!("{}/.cache/go/pkg/mod/cache",  home), &mut stats, verbose);

        // snap store cache
        remove_dir(&format!("{}/.cache/snapd",             home), &mut stats, verbose);
    }

    eprintln!("[+] pkg-logs: {} file(s) ({} MiB), {} dir(s), {} error(s)",
        stats.files_wiped, stats.bytes_freed >> 20,
        stats.dirs_cleared, stats.errors);
    stats
}

fn user_home_dirs() -> Vec<String> {
    let mut dirs = Vec::new();
    if Path::new("/root").is_dir() { dirs.push("/root".to_string()); }
    if let Ok(entries) = fs::read_dir("/home") {
        for e in entries.flatten() {
            if e.path().is_dir() {
                dirs.push(e.path().to_string_lossy().into_owned());
            }
        }
    }
    dirs
}
