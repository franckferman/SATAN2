use std::path::{Path, PathBuf};
use rusqlite::{Connection, params};

pub struct BrowserForgeOpts {
    pub n_urls:       u32,
    pub ts_start:     i64,
    pub ts_end:       i64,
    /// Override a specific profile directory or SQLite file
    pub profile_path: Option<String>,
    pub verbose:      bool,
}

#[derive(Default)]
pub struct BrowserForgeStats {
    pub urls_injected: u32,
    pub dbs_touched:   u32,
    pub errors:        u32,
}

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self { Lcg(seed as u64 ^ 0xb2_0b_0b_00_cafe_1234) }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005)
                       .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 { lo + (self.next() % (hi - lo)) }
    fn pick<'a, T>(&mut self, s: &'a [T]) -> &'a T { &s[(self.next() as usize) % s.len()] }

    fn guid(&mut self) -> String {
        // 12-char URL-safe base64 (Firefox GUID format)
        const A: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        (0..12).map(|_| A[(self.next() % 64) as usize] as char).collect()
    }
}

// ── URL pool ──────────────────────────────────────────────────────────────────

const URL_POOL: &[(&str, &str)] = &[
    ("https://www.google.fr/search?q=linux+systemd+journald",   "linux systemd journald - Google"),
    ("https://www.google.fr/search?q=nginx+reverse+proxy+config","nginx reverse proxy config - Google"),
    ("https://stackoverflow.com/questions/tagged/python3",       "Python3 Questions - Stack Overflow"),
    ("https://stackoverflow.com/questions/tagged/bash",          "Bash Questions - Stack Overflow"),
    ("https://github.com/trending",                              "Trending repositories on GitHub today"),
    ("https://github.com/ansible/ansible",                       "ansible/ansible: Ansible is a radically simple IT automation platform"),
    ("https://docs.ansible.com/ansible/latest/",                 "Ansible Documentation — Ansible Community"),
    ("https://kubernetes.io/docs/home/",                         "Kubernetes Documentation"),
    ("https://docs.docker.com/",                                 "Docker Documentation"),
    ("https://docs.microsoft.com/en-us/azure/",                  "Azure Documentation - Microsoft"),
    ("https://developer.mozilla.org/en-US/docs/Web/HTTP/",       "HTTP — MDN Web Docs"),
    ("https://www.lemonde.fr/",                                  "Le Monde - Actualités et Infos en France"),
    ("https://www.lefigaro.fr/",                                 "Le Figaro - Actualité en direct et informations"),
    ("https://news.ycombinator.com/",                            "Hacker News"),
    ("https://reddit.com/r/sysadmin",                            "r/sysadmin - reddit"),
    ("https://reddit.com/r/netsec",                              "r/netsec - reddit"),
    ("https://www.youtube.com/",                                 "YouTube"),
    ("https://outlook.office365.com/mail/inbox",                 "Inbox - Outlook"),
    ("https://mail.google.com/mail/u/0/#inbox",                  "Inbox - Gmail"),
    ("https://fr.wikipedia.org/wiki/Linux",                      "Linux — Wikipédia"),
    ("https://fr.wikipedia.org/wiki/Python_(langage)",           "Python (langage) — Wikipédia"),
    ("https://www.nginx.com/resources/wiki/",                    "NGINX Resources Wiki"),
    ("https://pypi.org/",                                        "PyPI · The Python Package Index"),
    ("https://mvnrepository.com/",                               "Maven Repository: Search/Browse/Explore"),
    ("https://npmjs.com/",                                       "npm"),
    ("https://www.amazon.fr/",                                   "Amazon.fr : bons prix, livraison rapide"),
    ("https://www.leboncoin.fr/",                                "leboncoin - petites annonces gratuites"),
    ("https://www.linkedin.com/feed/",                           "LinkedIn"),
    ("https://www.man7.org/linux/man-pages/man1/",               "Linux man-pages"),
    ("https://www.kernel.org/",                                  "The Linux Kernel Archives"),
    ("https://security.debian.org/",                             "Debian Security"),
    ("https://nvd.nist.gov/",                                    "NVD - National Vulnerability Database"),
    ("https://attack.mitre.org/",                                "MITRE ATT&CK®"),
    ("https://www.virustotal.com/gui/home/upload",               "VirusTotal"),
    ("https://www.shodan.io/",                                   "Shodan"),
    ("https://cve.mitre.org/cve/search_cve_list.html",          "CVE - Search CVE List"),
    ("https://portswigger.net/web-security",                     "Web Security Academy: Free Online Training"),
    ("https://book.hacktricks.xyz/",                             "HackTricks"),
    ("https://gtfobins.github.io/",                              "GTFOBins"),
    ("https://lolbas-project.github.io/",                        "LOLBAS"),
    ("https://www.exploit-db.com/",                              "Exploit Database - Exploits for Penetration Testers"),
    ("https://www.metasploit.com/",                              "Metasploit | Penetration Testing Software"),
];

// ── Timestamp converters ──────────────────────────────────────────────────────

/// Firefox stores timestamps as microseconds since Unix epoch (PRTime)
fn to_firefox_ts(unix: i64) -> i64 { unix * 1_000_000 }

/// Chromium stores timestamps as microseconds since 1601-01-01
fn to_chrome_ts(unix: i64) -> i64 { (unix + 11_644_473_600) * 1_000_000 }

// ── URL utilities ─────────────────────────────────────────────────────────────

/// FNV-1a hash of the URL string (Firefox uses a 64-bit hash for fast dedup)
fn fnv1a_url_hash(url: &str) -> i64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in url.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0001_0000_01b3);
    }
    h as i64
}

/// Firefox rev_host: reverse the hostname, append a trailing dot.
fn rev_host(url: &str) -> String {
    let stripped = url.trim_start_matches("https://").trim_start_matches("http://");
    let host = stripped.split('/').next().unwrap_or("")
                       .split(':').next().unwrap_or("");
    let mut r: String = host.chars().rev().collect();
    r.push('.');
    r
}

// ── Schema setup ──────────────────────────────────────────────────────────────

/// Ensure the minimum tables exist for forensic history injection (Firefox)
fn ensure_firefox_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS moz_places (
            id               INTEGER PRIMARY KEY,
            url              LONGVARCHAR NOT NULL,
            title            LONGVARCHAR,
            rev_host         LONGVARCHAR NOT NULL,
            visit_count      INTEGER  DEFAULT 0  NOT NULL,
            hidden           INTEGER  DEFAULT 0  NOT NULL,
            typed            INTEGER  DEFAULT 0  NOT NULL,
            frecency         INTEGER  DEFAULT -1 NOT NULL,
            last_visit_date  INTEGER,
            guid             TEXT,
            foreign_count    INTEGER  DEFAULT 0  NOT NULL,
            url_hash         INTEGER  DEFAULT 0  NOT NULL,
            description      TEXT,
            preview_image_url TEXT,
            site_name        TEXT
        );
        CREATE TABLE IF NOT EXISTS moz_historyvisits (
            id               INTEGER PRIMARY KEY,
            from_visit       INTEGER DEFAULT NULL,
            place_id         INTEGER NOT NULL,
            visit_date       INTEGER NOT NULL,
            visit_type       INTEGER NOT NULL,
            session          INTEGER DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS moz_meta (
            key   TEXT PRIMARY KEY,
            value NOT NULL
        );
        INSERT OR IGNORE INTO moz_meta (key, value) VALUES ('origin_frecency_count', 0);
        INSERT OR IGNORE INTO moz_meta (key, value) VALUES ('places-schema-version', 78);
    ")
}

/// Ensure the minimum tables exist for Chromium history injection
fn ensure_chrome_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS urls (
            id              INTEGER PRIMARY KEY,
            url             LONGVARCHAR NOT NULL,
            title           LONGVARCHAR DEFAULT '',
            visit_count     INTEGER DEFAULT 0 NOT NULL,
            typed_count     INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL,
            hidden          INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE IF NOT EXISTS visits (
            id              INTEGER PRIMARY KEY,
            url             INTEGER NOT NULL,
            visit_time      INTEGER NOT NULL,
            from_visit      INTEGER DEFAULT 0,
            transition      INTEGER DEFAULT 0,
            segment_id      INTEGER DEFAULT 0,
            visit_duration  INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS meta (
            key   LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY,
            value LONGVARCHAR
        );
        INSERT OR IGNORE INTO meta (key, value) VALUES ('version', '52');
        INSERT OR IGNORE INTO meta (key, value) VALUES ('last_compatible_version', '16');
    ")
}

// ── Injectors ─────────────────────────────────────────────────────────────────

fn inject_firefox(
    db_path: &Path,
    opts: &BrowserForgeOpts,
    lcg: &mut Lcg,
    s: &mut BrowserForgeStats,
) {
    let conn = match Connection::open(db_path) {
        Ok(c)  => c,
        Err(e) => {
            s.errors += 1;
            if opts.verbose { eprintln!("[!] forge-browser (FF): open {:?}: {}", db_path, e); }
            return;
        }
    };

    if let Err(e) = ensure_firefox_schema(&conn) {
        s.errors += 1;
        if opts.verbose { eprintln!("[!] forge-browser (FF): schema {:?}: {}", db_path, e); }
        return;
    }

    let window = (opts.ts_end - opts.ts_start).max(1);
    let step   = window / opts.n_urls.max(1) as i64;
    let mut injected = 0u32;

    for i in 0..opts.n_urls {
        let (url, title) = lcg.pick(URL_POOL);
        let ts_unix      = opts.ts_start + i as i64 * step + lcg.range(0, step.min(60) as u64) as i64;
        let ts_ff        = to_firefox_ts(ts_unix);
        let vh           = fnv1a_url_hash(url);
        let rh           = rev_host(url);
        let guid         = lcg.guid();
        let v_count      = lcg.range(1, 20) as i64;

        // Insert or update place
        let place_id: i64 = match conn.query_row(
            "INSERT OR IGNORE INTO moz_places (url, title, rev_host, visit_count, typed, frecency, last_visit_date, guid, url_hash)
             VALUES (?1, ?2, ?3, ?4, 0, 100, ?5, ?6, ?7)
             RETURNING id",
            params![url, title, rh, v_count, ts_ff, guid, vh],
            |row| row.get(0),
        ) {
            Ok(id) => id,
            Err(_) => {
                // Row already existed — fetch its id
                match conn.query_row(
                    "SELECT id FROM moz_places WHERE url = ?1",
                    params![url],
                    |row| row.get(0),
                ) {
                    Ok(id) => id,
                    Err(_) => { s.errors += 1; continue; }
                }
            }
        };

        // Insert visit record
        if conn.execute(
            "INSERT INTO moz_historyvisits (place_id, visit_date, visit_type, session)
             VALUES (?1, ?2, 1, ?3)",
            params![place_id, ts_ff, lcg.range(1, 50) as i64],
        ).is_ok() {
            injected += 1;
        }
    }

    s.urls_injected += injected;
    s.dbs_touched   += 1;
    if opts.verbose { eprintln!("[+] forge-browser (FF): {} URLs → {:?}", injected, db_path); }
}

fn inject_chromium(
    db_path: &Path,
    opts: &BrowserForgeOpts,
    lcg: &mut Lcg,
    s: &mut BrowserForgeStats,
) {
    let conn = match Connection::open(db_path) {
        Ok(c)  => c,
        Err(e) => {
            s.errors += 1;
            if opts.verbose { eprintln!("[!] forge-browser (CR): open {:?}: {}", db_path, e); }
            return;
        }
    };

    if let Err(e) = ensure_chrome_schema(&conn) {
        s.errors += 1;
        if opts.verbose { eprintln!("[!] forge-browser (CR): schema {:?}: {}", db_path, e); }
        return;
    }

    let window = (opts.ts_end - opts.ts_start).max(1);
    let step   = window / opts.n_urls.max(1) as i64;
    let mut injected = 0u32;

    for i in 0..opts.n_urls {
        let (url, title) = lcg.pick(URL_POOL);
        let ts_unix  = opts.ts_start + i as i64 * step + lcg.range(0, step.min(60) as u64) as i64;
        let ts_chrome = to_chrome_ts(ts_unix);
        let v_count   = lcg.range(1, 15) as i64;

        let url_id: i64 = match conn.query_row(
            "INSERT OR IGNORE INTO urls (url, title, visit_count, typed_count, last_visit_time, hidden)
             VALUES (?1, ?2, ?3, 0, ?4, 0)
             RETURNING id",
            params![url, title, v_count, ts_chrome],
            |row| row.get(0),
        ) {
            Ok(id) => id,
            Err(_) => match conn.query_row(
                "SELECT id FROM urls WHERE url = ?1", params![url], |row| row.get(0),
            ) {
                Ok(id) => id,
                Err(_) => { s.errors += 1; continue; }
            },
        };

        let transition = 0x00800001i64; // CHAIN_END | LINK — typical for clicked links
        if conn.execute(
            "INSERT INTO visits (url, visit_time, transition) VALUES (?1, ?2, ?3)",
            params![url_id, ts_chrome, transition],
        ).is_ok() {
            injected += 1;
        }
    }

    s.urls_injected += injected;
    s.dbs_touched   += 1;
    if opts.verbose { eprintln!("[+] forge-browser (CR): {} URLs → {:?}", injected, db_path); }
}

// ── Profile discovery ─────────────────────────────────────────────────────────

fn firefox_places_dbs(home: &Path) -> Vec<PathBuf> {
    let prof_dir = home.join(".mozilla/firefox");
    let mut out  = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&prof_dir) {
        for e in rd.flatten() {
            let p = e.path().join("places.sqlite");
            if p.exists() { out.push(p); }
        }
    }
    out
}

const CHROMIUM_PROFILE_DIRS: &[&str] = &[
    ".config/google-chrome",
    ".config/chromium",
    ".config/brave-browser",
    ".config/microsoft-edge",
    ".config/vivaldi",
    ".config/opera",
];

const CHROMIUM_PROFILE_NAMES: &[&str] = &[
    "Default", "Profile 1", "Profile 2", "Guest Profile",
];

fn chromium_history_dbs(home: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in CHROMIUM_PROFILE_DIRS {
        for prof in CHROMIUM_PROFILE_NAMES {
            let db = home.join(dir).join(prof).join("History");
            if db.exists() { out.push(db); }
        }
    }
    out
}

fn collect_home_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let root = PathBuf::from("/root");
    if root.exists() { dirs.push(root); }
    if let Ok(rd) = std::fs::read_dir("/home") {
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) { dirs.push(e.path()); }
        }
    }
    dirs
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn forge_browser_history(opts: &BrowserForgeOpts) -> BrowserForgeStats {
    let mut s   = BrowserForgeStats::default();
    let mut lcg = Lcg::new(opts.ts_start ^ opts.n_urls as i64);

    // Override: caller pointed at a specific file
    if let Some(ref path) = opts.profile_path {
        let p = Path::new(path);
        // Heuristic: if filename contains "places" → Firefox, otherwise Chromium
        if p.file_name().and_then(|n| n.to_str()).map(|n| n.contains("places")).unwrap_or(false) {
            inject_firefox(p, opts, &mut lcg, &mut s);
        } else {
            inject_chromium(p, opts, &mut lcg, &mut s);
        }
        return s;
    }

    // Auto-discover profiles in all home dirs
    for home in collect_home_dirs() {
        for db in firefox_places_dbs(&home) {
            inject_firefox(&db, opts, &mut lcg, &mut s);
        }
        for db in chromium_history_dbs(&home) {
            inject_chromium(&db, opts, &mut lcg, &mut s);
        }
    }

    s
}
