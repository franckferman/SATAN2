// Inject fake entries into systemd journal via the native journald socket protocol.
// Messages are sent as datagrams to /run/systemd/journal/socket with KEY=VALUE\n fields.
// Only non-trusted fields (without _ prefix) are accepted from external senders.

use std::os::unix::io::RawFd;
use std::path::Path;

pub struct JournalForgeOpts {
    pub fake_ip: String,
    pub fake_user: String,
    pub n_entries: u32,
    pub ts_start: i64,
    pub ts_end: i64,
    pub verbose: bool,
}

#[derive(Default)]
pub struct JournalForgeStats {
    pub entries_sent: u32,
    pub errors: u32,
}

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: i64) -> Self {
        Lcg(seed as u64 ^ 0xf00d_cafe_1234_5678)
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

    fn b64_string(&mut self, n: usize) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        (0..n)
            .map(|_| A[(self.next() % 64) as usize] as char)
            .collect()
    }
}

// ── Journald socket ───────────────────────────────────────────────────────────

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

fn open_journal_socket() -> Option<RawFd> {
    if !Path::new(JOURNAL_SOCKET).exists() {
        return None;
    }
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return None;
        }

        let path_bytes = JOURNAL_SOCKET.as_bytes();
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as u16;
        let copy_len = path_bytes.len().min(addr.sun_path.len() - 1);
        for (i, &b) in path_bytes[..copy_len].iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }

        // sun_family (sa_family_t = u16) is 2 bytes; sun_path starts at offset 2
        let addr_len = (2usize + copy_len + 1) as libc::socklen_t;

        if libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            addr_len,
        ) < 0
        {
            libc::close(fd);
            return None;
        }
        Some(fd)
    }
}

fn send_journal_entry(fd: RawFd, msg: &str) -> bool {
    let bytes = msg.as_bytes();
    unsafe { libc::send(fd, bytes.as_ptr() as *const libc::c_void, bytes.len(), 0) >= 0 }
}

// ── Message templates ─────────────────────────────────────────────────────────

fn mk_ssh_accept(user: &str, ip: &str, port: u64, pid: u64, fp: &str) -> String {
    format!(
        "PRIORITY=6\nSYSLOG_FACILITY=10\nSYSLOG_IDENTIFIER=sshd\nSYSLOG_PID={}\n\
         MESSAGE=Accepted publickey for {} from {} port {} ssh2: RSA {}\n",
        pid, user, ip, port, fp
    )
}

fn mk_pam_session_open(user: &str, pid: u64) -> String {
    format!(
        "PRIORITY=6\nSYSLOG_FACILITY=10\nSYSLOG_IDENTIFIER=sshd\nSYSLOG_PID={}\n\
         MESSAGE=pam_unix(sshd:session): session opened for user {} by (uid=0)\n",
        pid, user
    )
}

fn mk_pam_session_close(user: &str, pid: u64) -> String {
    format!(
        "PRIORITY=6\nSYSLOG_FACILITY=10\nSYSLOG_IDENTIFIER=sshd\nSYSLOG_PID={}\n\
         MESSAGE=pam_unix(sshd:session): session closed for user {}\n",
        pid, user
    )
}

fn mk_ssh_disconnect(user: &str, ip: &str, port: u64, pid: u64) -> String {
    format!(
        "PRIORITY=6\nSYSLOG_FACILITY=10\nSYSLOG_IDENTIFIER=sshd\nSYSLOG_PID={}\n\
         MESSAGE=Disconnected from user {} {} port {}\n",
        pid, user, ip, port
    )
}

fn mk_sudo(user: &str, cmd: &str, pid: u64) -> String {
    format!(
        "PRIORITY=6\nSYSLOG_FACILITY=10\nSYSLOG_IDENTIFIER=sudo\nSYSLOG_PID={}\n\
         MESSAGE={} : TTY=pts/0 ; PWD=/home/{} ; USER=root ; COMMAND={}\n",
        pid, user, user, cmd
    )
}

fn mk_systemd_service(unit: &str, state: &str) -> String {
    format!(
        "PRIORITY=6\nSYSLOG_FACILITY=3\nSYSLOG_IDENTIFIER=systemd\nSYSLOG_PID=1\n\
         MESSAGE={}.service: {}\n",
        unit, state
    )
}

const SUDO_CMDS: &[&str] = &[
    "/usr/bin/apt-get update",
    "/usr/sbin/service nginx restart",
    "/bin/systemctl restart ssh",
    "/usr/bin/journalctl -n 100",
    "/usr/bin/find / -name '*.conf' 2>/dev/null",
];

const SERVICES: &[&str] = &[
    "nginx",
    "rsyslog",
    "cron",
    "ntp",
    "snapd",
    "udisksd",
    "networkd-dispatcher",
];

// ── Public API ────────────────────────────────────────────────────────────────

pub fn forge_journal(opts: &JournalForgeOpts) -> JournalForgeStats {
    let mut s = JournalForgeStats::default();
    let mut lcg = Lcg::new(opts.ts_start ^ opts.n_entries as i64);

    let fd = match open_journal_socket() {
        Some(f) => f,
        None => {
            if opts.verbose {
                eprintln!("[!] forge-journal: {} not available", JOURNAL_SOCKET);
            }
            s.errors += 1;
            return s;
        }
    };

    let window = (opts.ts_end - opts.ts_start).max(1);
    let step = window / opts.n_entries.max(1) as i64;

    for i in 0..opts.n_entries {
        let _ts = opts.ts_start + i as i64 * step + lcg.range(0, step.min(60) as u64) as i64;
        let pid = lcg.range(1_000, 65_000);
        let port = lcg.range(49_152, 65_535);
        let fp = format!("SHA256:{}", lcg.b64_string(43));

        let msgs = [
            mk_ssh_accept(&opts.fake_user, &opts.fake_ip, port, pid, &fp),
            mk_pam_session_open(&opts.fake_user, pid),
        ];

        for m in &msgs {
            if send_journal_entry(fd, m) {
                s.entries_sent += 1;
            } else {
                s.errors += 1;
            }
        }

        // Interleave sudo / service events
        if lcg.range(0, 3) < 2 {
            let cmd = lcg.pick(SUDO_CMDS);
            let m = mk_sudo(&opts.fake_user, cmd, lcg.range(1_000, 65_000));
            if send_journal_entry(fd, &m) {
                s.entries_sent += 1;
            } else {
                s.errors += 1;
            }
        }

        if i % 3 == 0 {
            let svc = lcg.pick(SERVICES);
            let m = mk_systemd_service(svc, "Reloading");
            if send_journal_entry(fd, &m) {
                s.entries_sent += 1;
            } else {
                s.errors += 1;
            }
        }

        // Close session
        let close_msgs = [
            mk_ssh_disconnect(&opts.fake_user, &opts.fake_ip, port, pid),
            mk_pam_session_close(&opts.fake_user, pid),
        ];
        for m in &close_msgs {
            if send_journal_entry(fd, m) {
                s.entries_sent += 1;
            } else {
                s.errors += 1;
            }
        }
    }

    unsafe { libc::close(fd) };
    if opts.verbose {
        eprintln!("[+] forge-journal: {} entries sent", s.entries_sent);
    }
    s
}
