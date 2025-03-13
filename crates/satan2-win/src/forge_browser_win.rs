// Inject fake browsing history into Windows browser SQLite databases.
// Covers: Chrome, Edge, Brave (Chromium-based) and Firefox.
// Uses the same schema logic as the Linux browser_forge — different path resolution only.

#![cfg(target_os = "windows")]

use rusqlite::{Connection, params};
use std::fs;
use std::path::PathBuf;

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self { Lcg(seed as u64 ^ 0xb0bb_1e50_face_cafe) }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005)
                       .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 { lo + (self.next() % (hi - lo)) }
    fn pick<'a, T>(&mut self, s: &'a [T]) -> &'a T { &s[(self.next() as usize) % s.len()] }
}

// ── URL pool ──────────────────────────────────────────────────────────────────

const URL_POOL: &[(&str, &str)] = &[
    ("https://github.com",              "GitHub · Where the world builds software"),
    ("https://stackoverflow.com",       "Stack Overflow - Where Developers Learn"),
    ("https://docs.microsoft.com",      "Microsoft Docs"),
    ("https://outlook.office.com",      "Outlook"),
    ("https://teams.microsoft.com",     "Microsoft Teams"),
    ("https://portal.azure.com",        "Microsoft Azure"),
    ("https://www.google.com",          "Google"),
    ("https://google.com/search?q=csv+parsing+python", "csv parsing python - Google Search"),
    ("https://stackoverflow.com/questions/2081586",    "Python split string - Stack Overflow"),
    ("https://docs.python.org/3/library/csv.html",     "csv — Python Docs"),
    ("https://www.youtube.com",         "YouTube"),
    ("https://mail.google.com",         "Gmail"),
    ("https://calendar.google.com",     "Google Calendar"),
    ("https://drive.google.com",        "Google Drive"),
    ("https://www.wikipedia.org",       "Wikipedia"),
    ("https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol", "HTTP - Wikipedia"),
    ("https://news.ycombinator.com",    "Hacker News"),
    ("https://reddit.com/r/sysadmin",   "r/sysadmin - Reddit"),
    ("https://twitter.com",             "X (Twitter)"),
    ("https://linkedin.com",            "LinkedIn"),
    ("https://npmjs.com",               "npm"),
    ("https://crates.io",               "crates.io"),
    ("https://docs.rs",                 "Docs.rs"),
    ("https://devblogs.microsoft.com",  "Microsoft Dev Blogs"),
    ("https://learn.microsoft.com",     "Microsoft Learn"),
    ("https://hub.docker.com",          "Docker Hub"),
    ("https://grafana.com",             "Grafana"),
    ("https://prometheus.io",           "Prometheus"),
    ("https://kubernetes.io/docs",      "Kubernetes Docs"),
    ("https://aws.amazon.com/console",  "AWS Management Console"),
];

// ── SQLite helpers ────────────────────────────────────────────────────────────

// Chrome FILETIME: microseconds since 1601-01-01 00:00:00 UTC
fn chrome_ts(unix_ts: i64) -> i64 { (unix_ts + 11_644_473_600) * 1_000_000 }

// Firefox PRTime: microseconds since Unix epoch
fn ff_ts(unix_ts: i64) -> i64 { unix_ts * 1_000_000 }

fn fnv1a_u64(url: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in url.bytes() { h ^= b as u64; h = h.wrapping_mul(0x100_0000_01b3); }
    h
}

fn ensure_chrome_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS meta (key LONGVARCHAR NOT NULL UNIQUE,value LONGVARCHAR);
        INSERT OR IGNORE INTO meta VALUES ('version','52');
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY,url LONGVARCHAR NOT NULL,
            title LONGVARCHAR DEFAULT '',visit_count INTEGER DEFAULT 0,
            typed_count INTEGER DEFAULT 0,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS visits (
            id INTEGER PRIMARY KEY,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,
            from_visit INTEGER DEFAULT 0,transition INTEGER DEFAULT 0,segment_id INTEGER DEFAULT 0,
            visit_duration INTEGER DEFAULT 0);
    ")
}

fn ensure_firefox_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS moz_meta (key TEXT PRIMARY KEY,value NOT NULL);
        INSERT OR IGNORE INTO moz_meta VALUES ('schema_incompatible_version','57');
        INSERT OR IGNORE INTO moz_meta VALUES ('schema_version','78');
        CREATE TABLE IF NOT EXISTS moz_places (
            id INTEGER PRIMARY KEY,url LONGVARCHAR,title LONGVARCHAR,
            rev_host LONGVARCHAR,visit_count INTEGER DEFAULT 0,
            hidden INTEGER DEFAULT 0,typed INTEGER DEFAULT 0,
            frecency INTEGER DEFAULT -1,last_visit_date INTEGER,guid TEXT,
            foreign_count INTEGER DEFAULT 0,url_hash INTEGER DEFAULT 0,
            description TEXT,preview_image_url TEXT,origin_id INTEGER,
            site_name TEXT);
        CREATE TABLE IF NOT EXISTS moz_historyvisits (
            id INTEGER PRIMARY KEY,from_visit INTEGER,place_id INTEGER,
            visit_date INTEGER,visit_type INTEGER,session INTEGER);
    ")
}

fn rev_host(url: &str) -> String {
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url);
    let reversed: String = host.chars().rev().collect();
    format!("{}.", reversed)
}

fn inject_chrome(conn: &Connection, url: &str, title: &str, ts: i64, count: u64) -> bool {
    let ts_chrome = chrome_ts(ts);
    let uid: i64 = conn
        .query_row(
            "SELECT id FROM urls WHERE url=?1",
            params![url],
            |r| r.get(0),
        )
        .or_else(|_| {
            conn.execute(
                "INSERT INTO urls(url,title,visit_count,last_visit_time) VALUES(?1,?2,?3,?4)",
                params![url, title, count, ts_chrome],
            ).ok();
            conn.query_row("SELECT id FROM urls WHERE url=?1", params![url], |r| r.get(0))
        })
        .unwrap_or(-1);
    if uid < 0 { return false; }
    conn.execute(
        "INSERT INTO visits(url,visit_time,transition) VALUES(?1,?2,?3)",
        params![uid, ts_chrome, 0x00800001i64],
    ).is_ok()
}

fn inject_firefox(conn: &Connection, url: &str, title: &str, ts: i64, count: u64) -> bool {
    let ts_ff   = ff_ts(ts);
    let hash    = fnv1a_u64(url) as i64;
    let rev     = rev_host(url);
    let pid: i64 = conn
        .query_row("SELECT id FROM moz_places WHERE url=?1", params![url], |r| r.get(0))
        .or_else(|_| {
            conn.execute(
                "INSERT INTO moz_places(url,title,rev_host,visit_count,last_visit_date,url_hash) \
                 VALUES(?1,?2,?3,?4,?5,?6)",
                params![url, title, rev, count, ts_ff, hash],
            ).ok();
            conn.query_row("SELECT id FROM moz_places WHERE url=?1", params![url], |r| r.get(0))
        })
        .unwrap_or(-1);
    if pid < 0 { return false; }
    conn.execute(
        "INSERT INTO moz_historyvisits(place_id,visit_date,visit_type) VALUES(?1,?2,1)",
        params![pid, ts_ff],
    ).is_ok()
}

// ── Path discovery ────────────────────────────────────────────────────────────

fn user_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let users = PathBuf::from(r"C:\Users");
    if users.is_dir() {
        if let Ok(rd) = fs::read_dir(&users) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() { dirs.push(p); }
            }
        }
    }
    if dirs.is_empty() {
        // Fallback: only current user via env vars
        if let Ok(v) = std::env::var("USERPROFILE") { dirs.push(PathBuf::from(v)); }
    }
    dirs
}

fn chromium_db_paths(user: &PathBuf) -> Vec<PathBuf> {
    let local = user.join("AppData").join("Local");
    let candidates = [
        local.join(r"Google\Chrome\User Data\Default\History"),
        local.join(r"Microsoft\Edge\User Data\Default\History"),
        local.join(r"BraveSoftware\Brave-Browser\User Data\Default\History"),
        local.join(r"Chromium\User Data\Default\History"),
        local.join(r"Opera Software\Opera Stable\History"),
    ];
    candidates.into_iter().filter(|p| {
        p.parent().map(|d| d.exists()).unwrap_or(false)
    }).collect()
}

fn firefox_db_paths(user: &PathBuf) -> Vec<PathBuf> {
    let roaming = user.join("AppData").join("Roaming");
    let profiles_dir = roaming.join(r"Mozilla\Firefox\Profiles");
    let mut dbs = Vec::new();
    if let Ok(rd) = fs::read_dir(&profiles_dir) {
        for entry in rd.flatten() {
            let db = entry.path().join("places.sqlite");
            if entry.path().is_dir() { dbs.push(db); }
        }
    }
    dbs
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct BrowserWinForgeOpts {
    pub n_entries: u32,
    pub ts_start:  i64,
    pub ts_end:    i64,
    pub verbose:   bool,
}

#[derive(Default)]
pub struct BrowserWinForgeStats {
    pub chrome_entries:  u32,
    pub firefox_entries: u32,
    pub dbs_touched:     u32,
    pub errors:          u32,
}

pub fn forge_browser_win(opts: &BrowserWinForgeOpts) -> BrowserWinForgeStats {
    let mut s   = BrowserWinForgeStats::default();
    let mut lcg = Lcg::new(opts.ts_start ^ opts.n_entries as i64);
    let window  = (opts.ts_end - opts.ts_start).max(1);
    let step    = window / opts.n_entries.max(1) as i64;

    for user in user_dirs() {
        // Chromium-based browsers
        for db_path in chromium_db_paths(&user) {
            let conn = match Connection::open(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    if opts.verbose { eprintln!("[!] forge-browser-win: {:?}: {}", db_path, e); }
                    s.errors += 1;
                    continue;
                }
            };
            if ensure_chrome_schema(&conn).is_err() { s.errors += 1; continue; }
            let mut ok = 0u32;
            for i in 0..opts.n_entries {
                let ts    = opts.ts_start + i as i64 * step + lcg.range(0, step.min(3600) as u64) as i64;
                let count = lcg.range(1, 20);
                let (url, title) = lcg.pick(URL_POOL);
                if inject_chrome(&conn, url, title, ts, count) { ok += 1; }
            }
            s.chrome_entries += ok;
            s.dbs_touched    += 1;
            if opts.verbose {
                eprintln!("[+] forge-browser-win: {} entries → {:?}", ok, db_path);
            }
        }

        // Firefox
        for db_path in firefox_db_paths(&user) {
            let conn = match Connection::open(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    if opts.verbose { eprintln!("[!] forge-browser-win: {:?}: {}", db_path, e); }
                    s.errors += 1;
                    continue;
                }
            };
            if ensure_firefox_schema(&conn).is_err() { s.errors += 1; continue; }
            let mut ok = 0u32;
            for i in 0..opts.n_entries {
                let ts    = opts.ts_start + i as i64 * step + lcg.range(0, step.min(3600) as u64) as i64;
                let count = lcg.range(1, 10);
                let (url, title) = lcg.pick(URL_POOL);
                if inject_firefox(&conn, url, title, ts, count) { ok += 1; }
            }
            s.firefox_entries += ok;
            s.dbs_touched     += 1;
            if opts.verbose {
                eprintln!("[+] forge-browser-win: {} Firefox entries → {:?}", ok, db_path);
            }
        }
    }
    s
}
