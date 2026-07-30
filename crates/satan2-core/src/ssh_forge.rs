use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct SshForgeOpts {
    /// Specific host:port entries to add (port optional, default 22)
    pub hosts: Vec<String>,
    /// Number of random plausible hosts to generate
    pub n_random: u32,
    /// Limit to specific home dirs; empty = all home dirs
    pub user_homes: Vec<String>,
    pub verbose: bool,
}

#[derive(Default)]
pub struct SshForgeStats {
    pub entries_added: u32,
    pub files_touched: u32,
    pub errors: u32,
}

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: u32) -> Self {
        Lcg(seed as u64 ^ 0xfeed_face_dead_beef)
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
    fn b64char(&mut self) -> char {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        A[(self.next() % 64) as usize] as char
    }
    fn b64(&mut self, n: usize) -> String {
        (0..n).map(|_| self.b64char()).collect()
    }
    fn pick<'a, T>(&mut self, s: &'a [T]) -> &'a T {
        &s[(self.next() as usize) % s.len()]
    }
}

// ── Key type prefixes ─────────────────────────────────────────────────────────
// These are the correct base64 prefixes for each key type (encoding the
// length-prefixed algorithm name per RFC 4253 §6.6).

const RSA_PREFIX: &str = "AAAAB3NzaC1yc2E"; // "\x00\x00\x00\x07ssh-rsa"
const ECDSA_PREFIX: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY"; // ecdsa-sha2-nistp256
const ED25519_PREFIX: &str = "AAAAC3NzaC1lZDI1NTE5"; // "\x00\x00\x00\x0bssh-ed25519"

// Total base64 lengths (includes prefix):
// RSA-2048:       372 chars
// ECDSA-nistp256: 140 chars
// Ed25519:         68 chars

#[derive(Clone, Copy)]
enum KeyType {
    Rsa,
    Ecdsa,
    Ed25519,
}

fn gen_key(kt: KeyType, lcg: &mut Lcg) -> String {
    match kt {
        KeyType::Rsa => format!("{}{}", RSA_PREFIX, lcg.b64(372 - RSA_PREFIX.len())),
        KeyType::Ecdsa => format!("{}{}", ECDSA_PREFIX, lcg.b64(140 - ECDSA_PREFIX.len())),
        KeyType::Ed25519 => format!("{}{}", ED25519_PREFIX, lcg.b64(68 - ED25519_PREFIX.len())),
    }
}

fn key_type_str(kt: KeyType) -> &'static str {
    match kt {
        KeyType::Rsa => "ssh-rsa",
        KeyType::Ecdsa => "ecdsa-sha2-nistp256",
        KeyType::Ed25519 => "ssh-ed25519",
    }
}

// ── Plausible random hosts ────────────────────────────────────────────────────

const FAKE_DOMAINS: &[&str] = &[
    "git.internal.corp",
    "ci.internal.corp",
    "jenkins.internal.corp",
    "bastion.internal.corp",
    "db01.internal.corp",
    "db02.internal.corp",
    "web01.internal.corp",
    "web02.internal.corp",
    "monitoring.internal.corp",
    "backup.internal.corp",
    "vpn.internal.corp",
    "ldap.internal.corp",
    "smtp.internal.corp",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
];

const RFC1918_PREFIXES: &[&str] = &[
    "10.0.0.",
    "10.0.1.",
    "10.0.2.",
    "10.10.0.",
    "10.10.1.",
    "172.16.0.",
    "172.16.1.",
    "172.17.0.",
    "192.168.0.",
    "192.168.1.",
    "192.168.10.",
];

fn gen_random_host(lcg: &mut Lcg) -> String {
    if lcg.range(0, 2) == 0 {
        // Domain name
        lcg.pick(FAKE_DOMAINS).to_string()
    } else {
        // RFC1918 IP
        format!("{}{}", lcg.pick(RFC1918_PREFIXES), lcg.range(1, 254))
    }
}

// ── known_hosts line builder ──────────────────────────────────────────────────

fn known_hosts_line(host: &str, kt: KeyType, lcg: &mut Lcg) -> String {
    let key = gen_key(kt, lcg);
    format!("{} {} {}", host, key_type_str(kt), key)
}

/// Pick key type with realistic distribution: ed25519 > ecdsa > rsa.
fn pick_key_type(lcg: &mut Lcg) -> KeyType {
    match lcg.range(0, 10) {
        0..=4 => KeyType::Ed25519,
        5..=7 => KeyType::Ecdsa,
        _ => KeyType::Rsa,
    }
}

// ── Home dir enumeration ──────────────────────────────────────────────────────

fn collect_home_dirs(filter: &[String]) -> Vec<PathBuf> {
    if !filter.is_empty() {
        return filter.iter().map(PathBuf::from).collect();
    }
    let mut dirs: Vec<PathBuf> = Vec::new();
    // /root
    let root = PathBuf::from("/root");
    if root.exists() {
        dirs.push(root);
    }
    // /home/*
    if let Ok(rd) = std::fs::read_dir("/home") {
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                dirs.push(e.path());
            }
        }
    }
    dirs
}

// ── Write helper ──────────────────────────────────────────────────────────────

fn append_known_hosts(kh_path: &Path, lines: &[String]) -> Result<usize, String> {
    if let Some(p) = kh_path.parent() {
        if !p.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(p);
        }
    }
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open(kh_path)
        .map_err(|e| format!("open {:?}: {}", kh_path, e))?;
    let mut n = 0;
    for l in lines {
        writeln!(f, "{}", l).map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn forge_ssh(opts: &SshForgeOpts) -> SshForgeStats {
    let mut s = SshForgeStats::default();
    let mut lcg = Lcg::new(opts.n_random ^ 0x1234);

    // Build the list of known_hosts lines to inject
    let mut lines: Vec<String> = Vec::new();

    // User-specified hosts
    for h in &opts.hosts {
        let kt = pick_key_type(&mut lcg);
        lines.push(known_hosts_line(h, kt, &mut lcg));
        // Ed25519 entries are common alongside RSA in real known_hosts
        if lcg.range(0, 3) == 0 {
            lines.push(known_hosts_line(h, KeyType::Rsa, &mut lcg));
        }
    }

    // Random hosts
    for _ in 0..opts.n_random {
        let h = gen_random_host(&mut lcg);
        let kt = pick_key_type(&mut lcg);
        lines.push(known_hosts_line(&h, kt, &mut lcg));
    }

    if lines.is_empty() {
        return s;
    }

    // Write to each home dir's .ssh/known_hosts
    let homes = collect_home_dirs(&opts.user_homes);
    for home in &homes {
        let kh = home.join(".ssh/known_hosts");
        match append_known_hosts(&kh, &lines) {
            Ok(n) => {
                s.entries_added += n as u32;
                s.files_touched += 1;
                if opts.verbose {
                    eprintln!("[+] forge-ssh: {} entries → {:?}", n, kh);
                }
            }
            Err(e) => {
                s.errors += 1;
                if opts.verbose {
                    eprintln!("[!] forge-ssh: {}", e);
                }
            }
        }
    }

    s
}
