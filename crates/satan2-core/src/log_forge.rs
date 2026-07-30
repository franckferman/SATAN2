use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub struct LogForgeOpts {
    pub fake_ip: String,
    pub fake_user: String,
    pub n_sessions: u32,
    pub ts_start: i64,
    pub ts_end: i64,
    pub fake_hostname: Option<String>,
    pub do_auth: bool,
    pub do_syslog: bool,
    pub bash_history_paths: Vec<String>,
    pub verbose: bool,
}

#[derive(Default)]
pub struct LogForgeStats {
    pub lines_written: u64,
    pub files_touched: u32,
    pub errors: u32,
}

// ── LCG PRNG ─────────────────────────────────────────────────────────────────

struct Lcg(u64);

impl Lcg {
    fn new(seed: i64) -> Self {
        Lcg(seed as u64 ^ 0xdeadbeef_cafe1234)
    }

    fn next(&mut self) -> u64 {
        // Knuth LCG with 64-bit constants (Numerical Recipes)
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + (self.next() % (hi - lo))
    }

    fn pick<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        &slice[(self.next() as usize) % slice.len()]
    }

    fn b64_char(&mut self) -> char {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        A[(self.next() % 64) as usize] as char
    }

    fn b64_string(&mut self, n: usize) -> String {
        (0..n).map(|_| self.b64_char()).collect()
    }

    fn pid(&mut self) -> u32 {
        self.range(1_000, 65_000) as u32
    }
}

// ── Timestamp helpers ─────────────────────────────────────────────────────────

fn epoch_to_syslog_ts(ts: i64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&ts, &mut tm) };
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mo = months[(tm.tm_mon as usize).min(11)];
    format!(
        "{} {:2} {:02}:{:02}:{:02}",
        mo, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec
    )
}

fn get_hostname() -> String {
    let mut buf = [0u8; 256];
    unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, 255) };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(0);
    String::from_utf8_lossy(&buf[..end]).to_string()
}

// ── Entry generators ──────────────────────────────────────────────────────────

fn rsa_fingerprint(lcg: &mut Lcg) -> String {
    format!("SHA256:{}", lcg.b64_string(43))
}

/// Full SSH session: accept → pam open → [sudo] → disconnect → pam close
fn gen_ssh_session(
    host: &str,
    user: &str,
    ip: &str,
    ts_open: i64,
    ts_close: i64,
    lcg: &mut Lcg,
) -> Vec<String> {
    let pid = lcg.pid();
    let port = lcg.range(49_152, 65_535);
    let session = lcg.range(1, 300);
    let uid = lcg.range(1_000, 9_999);
    let fp = rsa_fingerprint(lcg);
    let t_o = epoch_to_syslog_ts(ts_open);
    let t_c = epoch_to_syslog_ts(ts_close);
    vec![
        format!(
            "{} {} sshd[{}]: Accepted publickey for {} from {} port {} ssh2: RSA {}",
            t_o, host, pid, user, ip, port, fp
        ),
        format!(
            "{} {} sshd[{}]: pam_unix(sshd:session): session opened for user {}(uid={}) by (uid=0)",
            t_o, host, pid, user, uid
        ),
        format!(
            "{} {} systemd-logind[1]: New session {} of user {}.",
            t_o, host, session, user
        ),
        format!(
            "{} {} sshd[{}]: Disconnected from user {} {} port {}",
            t_c, host, pid, user, ip, port
        ),
        format!(
            "{} {} sshd[{}]: pam_unix(sshd:session): session closed for user {}",
            t_c, host, pid, user
        ),
        format!(
            "{} {} systemd-logind[1]: Session {} logged out. Waiting for processes to exit.",
            t_c, host, session
        ),
    ]
}

const SUDO_CMDS: &[&str] = &[
    "/usr/bin/apt-get update",
    "/usr/bin/apt-get upgrade -y",
    "/usr/sbin/service nginx restart",
    "/bin/systemctl restart ssh",
    "/usr/bin/tail -f /var/log/syslog",
    "/usr/bin/find / -name '*.conf' 2>/dev/null",
    "/usr/bin/journalctl -u nginx --since today",
    "/usr/sbin/ufw status",
    "/usr/bin/netstat -tlnp",
    "/usr/bin/ss -tlnp",
    "/usr/sbin/logrotate -f /etc/logrotate.conf",
    "/usr/bin/passwd root",
];

fn gen_sudo_event(host: &str, user: &str, ts: i64, cmd: &str, lcg: &mut Lcg) -> Vec<String> {
    let pid = lcg.pid();
    let uid = lcg.range(1_000, 9_999);
    let pts = lcg.range(0, 5);
    let t = epoch_to_syslog_ts(ts);
    let t2 = epoch_to_syslog_ts(ts + lcg.range(2, 60) as i64);
    vec![
        format!("{} {} sudo[{}]:   {} : TTY=pts/{} ; PWD=/home/{} ; USER=root ; COMMAND={}",
            t, host, pid, user, pts, user, cmd),
        format!("{} {} sudo[{}]: pam_unix(sudo:session): session opened for user root(uid=0) by {}(uid={})",
            t, host, pid, user, uid),
        format!("{} {} sudo: pam_unix(sudo:session): session closed for user root",
            t2, host),
    ]
}

fn gen_cron_events(host: &str, ts: i64) -> Vec<String> {
    vec![
        format!("{} {} CRON[{}]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
            epoch_to_syslog_ts(ts), host, 10_000u32 + (ts % 10_000) as u32),
        format!("{} {} CRON[{}]: (root) CMD (/usr/sbin/logrotate /etc/logrotate.conf)",
            epoch_to_syslog_ts(ts + 60), host, 10_001u32 + (ts % 10_000) as u32),
    ]
}

const SERVICES: &[&str] = &[
    "nginx",
    "rsyslog",
    "networkd-dispatcher",
    "snapd",
    "udisksd",
    "cron",
    "ntp",
    "unattended-upgrades",
];

fn gen_syslog_events(host: &str, ts: i64, lcg: &mut Lcg) -> Vec<String> {
    let svc = lcg.pick(SERVICES);
    let uptime_secs = lcg.range(100, 999_999);
    vec![
        format!("{} {} systemd[1]: Started {}.service.",
            epoch_to_syslog_ts(ts), host, svc),
        format!("{} {} kernel: [{}] EXT4-fs (sda1): re-mounted. Opts: (null). Quota mode: none.",
            epoch_to_syslog_ts(ts + 1), host, uptime_secs),
        format!("{} {} NetworkManager[{}]: <info>  [{}] device (eth0): Activation: Stage 5 of 5 (IP Configure Commit) complete",
            epoch_to_syslog_ts(ts + 2), host, lcg.pid(), ts),
    ]
}

// ── Bash history ──────────────────────────────────────────────────────────────

const BASH_CMDS: &[&str] = &[
    "ls -la",
    "ls -la /etc/",
    "pwd",
    "whoami",
    "id",
    "ps aux | grep -v grep",
    "df -h",
    "free -m",
    "uptime",
    "w",
    "last | head -20",
    "cat /etc/hostname",
    "cat /etc/os-release",
    "ip addr show",
    "ip route show",
    "ss -tlnp",
    "netstat -tlnp 2>/dev/null || ss -tlnp",
    "systemctl status",
    "systemctl list-units --type=service --state=running",
    "journalctl -n 100",
    "journalctl -u nginx -n 50",
    "find /tmp -maxdepth 1 -ls 2>/dev/null",
    "ls /var/log/",
    "uname -a",
    "env | sort | head -40",
    "history | tail -30",
    "cat /proc/cpuinfo | grep 'model name' | head -1",
    "lsblk",
    "mount | grep -v tmpfs",
    "crontab -l 2>/dev/null",
    "sudo apt-get update -y",
    "sudo apt-get upgrade -y",
    "sudo systemctl restart nginx",
    "curl -s https://ifconfig.me",
    "ping -c 4 8.8.8.8",
    "dig google.com",
    "nslookup google.com",
    "vim /etc/hosts",
    "nano /etc/resolv.conf",
    "grep -r 'error' /var/log/nginx/ 2>/dev/null | tail -20",
    "tail -f /var/log/syslog",
    "tail -100 /var/log/auth.log",
    "git status",
    "git log --oneline -20",
    "git pull",
    "python3 --version",
    "pip3 list | head -20",
    "docker ps 2>/dev/null",
    "kubectl get pods 2>/dev/null",
    "tar -czf /tmp/backup.tar.gz /etc/ 2>/dev/null",
    "rsync -avz /var/www/ /backups/www/",
    "scp config.tar.gz user@192.168.1.100:/backups/",
    "ssh-keygen -t ed25519 -C 'admin@$(hostname)' -f ~/.ssh/id_ed25519 -N ''",
    "openssl req -new -x509 -key /etc/ssl/private/nginx.key -out /etc/ssl/certs/nginx.crt -days 365",
    "iptables -L -v -n",
    "ufw status verbose",
    "fail2ban-client status",
    "top -bn1 | head -20",
    "htop",
    "iotop -obn 3",
    "strace -p $(pgrep nginx | head -1) 2>&1 | head -30",
];

// ── I/O helper ────────────────────────────────────────────────────────────────

fn append_lines(path: &str, lines: &[String]) -> Result<usize, String> {
    // Create parent directory if it doesn't exist (best-effort)
    if let Some(p) = Path::new(path).parent() {
        if !p.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(p);
        }
    }
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;
    let mut n = 0;
    for l in lines {
        writeln!(f, "{}", l).map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn forge_logs(opts: &LogForgeOpts) -> LogForgeStats {
    let mut s = LogForgeStats::default();
    let mut lcg = Lcg::new(opts.ts_start ^ opts.n_sessions as i64);
    let host = opts.fake_hostname.clone().unwrap_or_else(get_hostname);
    let window = (opts.ts_end - opts.ts_start).max(1);
    let step = window / opts.n_sessions.max(1) as i64;

    // ── Auth log ──────────────────────────────────────────────────────────────
    if opts.do_auth {
        let candidates = ["/var/log/auth.log", "/var/log/secure"];
        let path = candidates
            .iter()
            .find(|p| {
                Path::new(p).exists() || Path::new(p).parent().map(|d| d.exists()).unwrap_or(false)
            })
            .copied()
            .unwrap_or("/var/log/auth.log");

        let mut lines: Vec<String> = Vec::new();
        for i in 0..opts.n_sessions {
            let ts_open =
                opts.ts_start + i as i64 * step + lcg.range(0, step.min(120) as u64) as i64;
            let dur = lcg.range(120, 3_600) as i64;
            let ts_close = (ts_open + dur).min(opts.ts_end);

            lines.extend(gen_ssh_session(
                &host,
                &opts.fake_user,
                &opts.fake_ip,
                ts_open,
                ts_close,
                &mut lcg,
            ));

            if lcg.range(0, 3) < 2 {
                let ts_sudo = ts_open + lcg.range(30, dur.min(1_800) as u64) as i64;
                let cmd = lcg.pick(SUDO_CMDS);
                lines.extend(gen_sudo_event(
                    &host,
                    &opts.fake_user,
                    ts_sudo,
                    cmd,
                    &mut lcg,
                ));
            }
        }

        match append_lines(path, &lines) {
            Ok(n) => {
                s.lines_written += n as u64;
                s.files_touched += 1;
                if opts.verbose {
                    eprintln!("[+] forge-log auth: {} lines → {}", n, path);
                }
            }
            Err(e) => {
                s.errors += 1;
                if opts.verbose {
                    eprintln!("[!] forge-log auth: {}", e);
                }
            }
        }
    }

    // ── Syslog ────────────────────────────────────────────────────────────────
    if opts.do_syslog {
        let candidates = ["/var/log/syslog", "/var/log/messages"];
        let path = candidates
            .iter()
            .find(|p| {
                Path::new(p).exists() || Path::new(p).parent().map(|d| d.exists()).unwrap_or(false)
            })
            .copied()
            .unwrap_or("/var/log/syslog");

        let mut lines: Vec<String> = Vec::new();
        for i in 0..opts.n_sessions {
            let ts = opts.ts_start + i as i64 * step;
            lines.extend(gen_syslog_events(&host, ts, &mut lcg));
            if i % 4 == 0 {
                lines.extend(gen_cron_events(&host, ts));
            }
        }

        match append_lines(path, &lines) {
            Ok(n) => {
                s.lines_written += n as u64;
                s.files_touched += 1;
                if opts.verbose {
                    eprintln!("[+] forge-log syslog: {} lines → {}", n, path);
                }
            }
            Err(e) => {
                s.errors += 1;
                if opts.verbose {
                    eprintln!("[!] forge-log syslog: {}", e);
                }
            }
        }
    }

    // ── Bash history ──────────────────────────────────────────────────────────
    for hist_path in &opts.bash_history_paths {
        let n_cmds = lcg.range(15, 60) as usize;
        let lines: Vec<String> = (0..n_cmds)
            .map(|_| lcg.pick(BASH_CMDS).to_string())
            .collect();
        match append_lines(hist_path, &lines) {
            Ok(n) => {
                s.lines_written += n as u64;
                s.files_touched += 1;
                if opts.verbose {
                    eprintln!("[+] forge-log bash_history: {} lines → {}", n, hist_path);
                }
            }
            Err(e) => {
                s.errors += 1;
                if opts.verbose {
                    eprintln!("[!] forge-log bash_history: {}", e);
                }
            }
        }
    }

    s
}
