use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub struct PkgForgeOpts {
    pub n_packages: u32,
    pub ts_start:   i64,
    pub ts_end:     i64,
    pub verbose:    bool,
}

#[derive(Default)]
pub struct PkgForgeStats {
    pub lines_written: u64,
    pub files_touched: u32,
    pub errors:        u32,
}

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self { Lcg(seed as u64 ^ 0x1234_abcd_5678_ef00) }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005)
                       .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 { lo + (self.next() % (hi - lo)) }
    fn pick<'a, T>(&mut self, s: &'a [T]) -> &'a T { &s[(self.next() as usize) % s.len()] }
}

// ── Timestamp helpers ─────────────────────────────────────────────────────────

fn epoch_to_dpkg_ts(ts: i64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&ts, &mut tm) };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec)
}

fn epoch_to_apt_ts(ts: i64) -> String {
    // apt/history.log uses: "2026-06-25  14:32:15"
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&ts, &mut tm) };
    format!("{:04}-{:02}-{:02}  {:02}:{:02}:{:02}",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec)
}

fn epoch_to_pacman_ts(ts: i64) -> String {
    // pacman.log: [2026-06-25T14:32:15+0200]
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&ts, &mut tm) };
    let tz_off = tm.tm_gmtoff / 60; // minutes
    let tz_h   = tz_off / 60;
    let tz_m   = (tz_off % 60).abs();
    format!("[{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{:+03}{:02}]",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec, tz_h, tz_m)
}

// ── Package pools ─────────────────────────────────────────────────────────────

const DEB_PKGS: &[(&str, &str)] = &[
    ("curl",           "7.81.0-1ubuntu1.20"),
    ("wget",           "1.21.2-2ubuntu1.1"),
    ("vim",            "2:8.2.3995-1ubuntu2.20"),
    ("git",            "1:2.34.1-1ubuntu1.12"),
    ("htop",           "3.0.5-7build2"),
    ("tmux",           "3.2a-4build1"),
    ("python3",        "3.10.6-1~22.04.1"),
    ("python3-pip",    "22.0.2+dfsg-1ubuntu0.4"),
    ("build-essential","12.9ubuntu3"),
    ("make",           "4.3-4.1build1"),
    ("gcc",            "4:11.2.0-1ubuntu1"),
    ("openssl",        "3.0.2-0ubuntu1.18"),
    ("libssl-dev",     "3.0.2-0ubuntu1.18"),
    ("net-tools",      "1.60+git20181103.0eebece-1ubuntu5"),
    ("nmap",           "7.91+dfsg1+really7.80+dfsg1-2build2"),
    ("tcpdump",        "4.99.1-3ubuntu0.2"),
    ("strace",         "5.16-0ubuntu3"),
    ("gdb",            "12.1-0ubuntu1~22.04.2"),
    ("nginx",          "1.18.0-6ubuntu14.4"),
    ("jq",             "1.6-2.1ubuntu3"),
    ("unzip",          "6.0-26ubuntu3.2"),
    ("rsync",          "3.2.7-0ubuntu0.22.04.2"),
    ("screen",         "4.9.0-1"),
    ("fail2ban",       "0.11.2-6"),
    ("ufw",            "0.36.1-4ubuntu0.1"),
    ("docker.io",      "20.10.21-0ubuntu1~22.04.3"),
    ("postgresql-client","14+238"),
    ("redis-tools",    "5:6.0.16-1ubuntu1"),
    ("golang-go",      "2:1.18.1-1ubuntu1.1"),
    ("rustc",          "1.75.0+dfsg0ubuntu1~bpo0-0ubuntu0.22.04"),
];

const ARCH_PKGS: &[(&str, &str)] = &[
    ("base-devel",   "1-1"),
    ("git",          "2.44.0-1"),
    ("curl",         "8.6.0-1"),
    ("wget",         "1.21.4-1"),
    ("vim",          "9.1.0121-1"),
    ("neovim",       "0.9.5-3"),
    ("htop",         "3.3.0-1"),
    ("tmux",         "3.4-1"),
    ("python",       "3.12.2-1"),
    ("python-pip",   "24.0-1"),
    ("go",           "2:1.22.1-1"),
    ("rust",         "1:1.77.0-2"),
    ("nodejs",       "21.7.1-1"),
    ("npm",          "10.5.0-1"),
    ("nmap",         "7.95-1"),
    ("tcpdump",      "4.99.4-1"),
    ("strace",       "6.8-1"),
    ("gdb",          "14.2-1"),
    ("nginx",        "1.25.4-1"),
    ("docker",       "1:25.0.3-1"),
    ("kubectl",      "1.29.2-1"),
    ("terraform",    "1.7.4-1"),
    ("ansible",      "9.3.0-1"),
    ("redis",        "7.2.4-1"),
    ("postgresql",   "16.2-1"),
];

const RPM_PKGS: &[(&str, &str)] = &[
    ("curl",          "7.76.1-26.el9_3.2"),
    ("wget",          "1.21.1-8.el9"),
    ("vim-enhanced",  "8.2.2637-20.el9_1"),
    ("git",           "2.43.0-1.el9"),
    ("tmux",          "3.2a-4.el9"),
    ("python3",       "3.9.18-3.el9_3.1"),
    ("python3-pip",   "21.3.1-1.el9"),
    ("gcc",           "11.4.1-3.el9"),
    ("make",          "4.3-7.el9"),
    ("openssl",       "3.0.7-25.el9_3"),
    ("nmap",          "7.91-11.el9"),
    ("tcpdump",       "4.99.0-7.el9"),
    ("strace",        "5.18-2.el9"),
    ("gdb",           "10.2-11.el9"),
    ("nginx",         "1.20.1-14.el9_2.1"),
    ("jq",            "1.6-16.el9"),
    ("rsync",         "3.1.3-19.el9_3"),
    ("fail2ban",      "1.0.2-4.el9"),
    ("firewalld",     "1.3.4-1.el9"),
    ("docker-ce",     "25.0.3-1.el9"),
    ("golang",        "1.21.8-1.el9"),
    ("rust",          "1.75.0-2.el9"),
];

// ── Debian/Ubuntu generators ──────────────────────────────────────────────────

fn gen_dpkg_lines(pkg: &str, ver: &str, ts: i64, arch: &str) -> Vec<String> {
    let t = epoch_to_dpkg_ts(ts);
    vec![
        format!("{} status half-installed {}:{} {}", t, pkg, arch, ver),
        format!("{} status unpacked {}:{} {}",       t, pkg, arch, ver),
        format!("{} configure {}:{} {} <none>",       t, pkg, arch, ver),
        format!("{} status installed {}:{} {}",       t, pkg, arch, ver),
    ]
}

fn gen_apt_history_block(pkg: &str, ver: &str, ts_start: i64, ts_end: i64) -> Vec<String> {
    vec![
        format!("Start-Date: {}", epoch_to_apt_ts(ts_start)),
        format!("Commandline: apt-get install -y {}", pkg),
        "Requested-By: root (0)".to_string(),
        format!("Install: {}:amd64 ({})", pkg, ver),
        format!("End-Date: {}", epoch_to_apt_ts(ts_end)),
        "".to_string(),
    ]
}

// ── Arch generator ────────────────────────────────────────────────────────────

fn gen_pacman_lines(pkg: &str, ver: &str, ts: i64, lcg: &mut Lcg) -> Vec<String> {
    let t_start = epoch_to_pacman_ts(ts);
    let t_end   = epoch_to_pacman_ts(ts + lcg.range(5, 60) as i64);
    vec![
        format!("{} [PACMAN] Running 'pacman -S --noconfirm {}'", t_start, pkg),
        format!("{} [ALPM] transaction started",                    t_start),
        format!("{} [ALPM] installed {} ({})",                      t_start, pkg, ver),
        format!("{} [ALPM] transaction completed",                  t_end),
    ]
}

// ── RPM/DNF generator ─────────────────────────────────────────────────────────

fn gen_dnf_lines(pkg: &str, ver: &str, ts: i64) -> Vec<String> {
    let t = epoch_to_dpkg_ts(ts); // same ISO-ish format
    vec![
        format!("{} INFO  dnf:  {} Install  {}-1.x86_64", t, pkg, ver),
        format!("{} INFO  dnf:  Transaction finished.",    t),
    ]
}

// ── I/O helper ────────────────────────────────────────────────────────────────

fn append_lines(path: &str, lines: &[String]) -> Result<usize, String> {
    if let Some(p) = Path::new(path).parent() {
        if !p.as_os_str().is_empty() { let _ = std::fs::create_dir_all(p); }
    }
    let mut f = OpenOptions::new()
        .append(true).create(true).open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;
    let mut n = 0;
    for l in lines { writeln!(f, "{}", l).map_err(|e| e.to_string())?; n += 1; }
    Ok(n)
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn forge_pkg_logs(opts: &PkgForgeOpts) -> PkgForgeStats {
    let mut s   = PkgForgeStats::default();
    let mut lcg = Lcg::new(opts.ts_start ^ opts.n_packages as i64 * 7);
    let window  = (opts.ts_end - opts.ts_start).max(1);
    let step    = window / opts.n_packages.max(1) as i64;

    // ── Debian/Ubuntu ─────────────────────────────────────────────────────────
    if Path::new("/var/log/dpkg.log").parent().map(|d| d.exists()).unwrap_or(false)
       || Path::new("/var/log/dpkg.log").exists() {
        let mut dpkg_lines: Vec<String> = Vec::new();
        let mut apt_lines:  Vec<String> = Vec::new();

        for i in 0..opts.n_packages {
            let (pkg, ver) = lcg.pick(DEB_PKGS);
            let ts = opts.ts_start + i as i64 * step + lcg.range(0, step.min(30) as u64) as i64;
            dpkg_lines.extend(gen_dpkg_lines(pkg, ver, ts, "amd64"));
            apt_lines.extend(gen_apt_history_block(pkg, ver, ts, ts + lcg.range(2, 15) as i64));
        }

        for (path, lines) in [("/var/log/dpkg.log", &dpkg_lines),
                               ("/var/log/apt/history.log", &apt_lines)] {
            if let Some(p) = Path::new(path).parent() { let _ = std::fs::create_dir_all(p); }
            match append_lines(path, lines) {
                Ok(n)  => { s.lines_written += n as u64; s.files_touched += 1;
                            if opts.verbose { eprintln!("[+] forge-pkg: {} lines → {}", n, path); } }
                Err(e) => { s.errors += 1;
                            if opts.verbose { eprintln!("[!] forge-pkg: {}", e); } }
            }
        }
    }

    // ── Arch Linux ────────────────────────────────────────────────────────────
    if Path::new("/var/log/pacman.log").exists()
       || Path::new("/var/log/pacman.log").parent().map(|d| d.exists()).unwrap_or(false) {
        let mut lines: Vec<String> = Vec::new();
        for i in 0..opts.n_packages {
            let (pkg, ver) = lcg.pick(ARCH_PKGS);
            let ts = opts.ts_start + i as i64 * step;
            lines.extend(gen_pacman_lines(pkg, ver, ts, &mut lcg));
        }
        match append_lines("/var/log/pacman.log", &lines) {
            Ok(n)  => { s.lines_written += n as u64; s.files_touched += 1;
                        if opts.verbose { eprintln!("[+] forge-pkg: {} lines → /var/log/pacman.log", n); } }
            Err(e) => { s.errors += 1;
                        if opts.verbose { eprintln!("[!] forge-pkg pacman: {}", e); } }
        }
    }

    // ── RHEL/Fedora ───────────────────────────────────────────────────────────
    let dnf_candidates = ["/var/log/dnf.log", "/var/log/yum.log"];
    for dnf_path in &dnf_candidates {
        if Path::new(dnf_path).exists()
           || Path::new(dnf_path).parent().map(|d| d.exists()).unwrap_or(false) {
            let mut lines: Vec<String> = Vec::new();
            for i in 0..opts.n_packages {
                let (pkg, ver) = lcg.pick(RPM_PKGS);
                let ts = opts.ts_start + i as i64 * step;
                lines.extend(gen_dnf_lines(pkg, ver, ts));
            }
            match append_lines(dnf_path, &lines) {
                Ok(n)  => { s.lines_written += n as u64; s.files_touched += 1;
                            if opts.verbose { eprintln!("[+] forge-pkg: {} lines → {}", n, dnf_path); } }
                Err(e) => { s.errors += 1;
                            if opts.verbose { eprintln!("[!] forge-pkg dnf: {}", e); } }
            }
        }
    }

    // ── Per-user pip history ──────────────────────────────────────────────────
    const PIP_PKGS: &[&str] = &[
        "requests", "numpy", "pandas", "flask", "fastapi", "pydantic",
        "httpx", "boto3", "paramiko", "cryptography", "pycryptodome",
        "sqlalchemy", "alembic", "celery", "redis", "pytest", "black",
    ];
    let home_base = Path::new("/home");
    if home_base.exists() {
        if let Ok(rd) = std::fs::read_dir(home_base) {
            for entry in rd.flatten() {
                let pip_log = entry.path().join(".local/share/pip/pip.log");
                let n_pip   = lcg.range(3, 12) as usize;
                let mut lines: Vec<String> = Vec::new();
                for _ in 0..n_pip {
                    let pkg = lcg.pick(PIP_PKGS);
                    lines.push(format!("VERBOSE: Found existing installation: {} 0.0.0", pkg));
                    lines.push(format!("VERBOSE: Uninstalling {} 0.0.0:", pkg));
                    lines.push(format!("INFO: Successfully installed {}-2.31.0", pkg));
                }
                if let Some(p) = pip_log.parent() { let _ = std::fs::create_dir_all(p); }
                if let Ok(mut f) = OpenOptions::new().append(true).create(true)
                                         .open(&pip_log) {
                    for l in &lines { let _ = writeln!(f, "{}", l); }
                    s.lines_written += lines.len() as u64;
                    s.files_touched += 1;
                }
            }
        }
    }

    s
}
