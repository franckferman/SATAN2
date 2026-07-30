#![allow(non_snake_case)]

// Non-Windows stub so `cargo check` on Linux does not fail on a missing main.
#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("[!] satan2_win is Windows-only.");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
mod amcache;
#[cfg(target_os = "windows")]
mod browser_history;
#[cfg(target_os = "windows")]
mod defender;
#[cfg(target_os = "windows")]
mod etw;
#[cfg(target_os = "windows")]
mod event_log;
#[cfg(target_os = "windows")]
mod forge_browser_win;
#[cfg(target_os = "windows")]
mod forge_event_log;
#[cfg(target_os = "windows")]
mod forge_lnk;
#[cfg(target_os = "windows")]
mod forge_prefetch;
#[cfg(target_os = "windows")]
mod forge_registry_mru;
#[cfg(target_os = "windows")]
mod forge_shimcache;
#[cfg(target_os = "windows")]
mod forge_userassist;
#[cfg(target_os = "windows")]
mod hiberfil;
#[cfg(target_os = "windows")]
mod lnk_jumplists;
#[cfg(target_os = "windows")]
mod ntfs;
#[cfg(target_os = "windows")]
mod opsec_win;
#[cfg(target_os = "windows")]
mod prefetch;
#[cfg(target_os = "windows")]
mod privilege;
#[cfg(target_os = "windows")]
mod ps_history;
#[cfg(target_os = "windows")]
mod rdp;
#[cfg(target_os = "windows")]
mod recycle_bin;
#[cfg(target_os = "windows")]
mod registry;
#[cfg(target_os = "windows")]
mod restore;
#[cfg(target_os = "windows")]
mod schtasks;
#[cfg(target_os = "windows")]
mod service;
#[cfg(target_os = "windows")]
mod srum;
#[cfg(target_os = "windows")]
mod thumbcache;
#[cfg(target_os = "windows")]
mod timeline;
#[cfg(target_os = "windows")]
mod userassist;
#[cfg(target_os = "windows")]
mod vssadmin;
#[cfg(target_os = "windows")]
mod win_search;
#[cfg(target_os = "windows")]
mod wipe_bam;
#[cfg(target_os = "windows")]
mod wipe_bits;
#[cfg(target_os = "windows")]
mod wipe_muicache;
#[cfg(target_os = "windows")]
mod wmi;

#[cfg(target_os = "windows")]
use std::env;
#[cfg(target_os = "windows")]
use std::process;

#[cfg(target_os = "windows")]
use satan2_crypto::{
    extract_dir,
    hash::{hash_file, to_hex, HashAlgo},
    ops::{
        create_container, decrypt_container, destroy_and_encrypt, encrypt_dir, encrypt_file,
        encrypt_layers, Layer,
    },
    Algorithm,
};

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
#[derive(Debug, Default, PartialEq)]
enum Mode {
    #[default]
    DestroyAll,
    CoverAll,
    Vss,
    EventLog,
    Prefetch,
    Registry,
    PsHistory,
    Lnk,
    RecycleBin,
    Defender,
    Thumbcache,
    Srum,
    Etw,
    Hiberfil,
    WinSearch,
    Browser,
    Schtasks,
    Rdp,
    Timeline,
    Opsec,
    OpsecRevert,
    Amcache,
    UserAssist,
    // Forensic cleanup
    WipeBam,
    ForgeBam,
    WipeBits,
    WipeMuiCache,
    WipeUsnJrnl,
    // Forge (plant plausible artifacts)
    ForgeUserAssist,
    ForgeEventLog,
    ForgeRegistryMru,
    ForgeBrowserWin,
    ForgePrefetch,
    ForgeLnk,
    ForgeShimcache,
    ForgeMuiCache,
    ForgeAll,
    // Crypto
    CreateContainer,
    EncryptFile,
    EncryptDir,
    EncryptLayers,
    Decrypt,
    Extract,
    DestroyAndEncrypt,
    Hash,
    List,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct Opts {
    mode: Mode,
    verbose: bool,
    dry_run: bool,
    json: bool,
    // VSS
    vss_volume: Option<String>,
    vss_after: Option<i64>,
    vss_decoy: bool,
    restore_points: bool,
    no_fallback: bool,
    // Storage
    disable_pf: bool,
    // Crypto shared
    input: Option<String>,
    output: Option<String>,
    algo_str: String,
    kdf_iters: u32,
    pass_env: String,
    size_mib: u64,
    sources: Vec<String>,
    layer_algos: Vec<String>, // repeated --layer <algo>, innermost first
    hash_algo: String,
    // Forge
    ts_forge: i64,
    n_forge: u32, // entry/file count for forge subcommands
}

#[cfg(target_os = "windows")]
impl Default for Opts {
    fn default() -> Self {
        Opts {
            mode: Mode::default(),
            verbose: false,
            dry_run: false,
            json: false,
            vss_volume: None,
            vss_after: None,
            vss_decoy: false,
            restore_points: false,
            no_fallback: false,
            disable_pf: false,
            input: None,
            output: None,
            algo_str: "aes".to_string(),
            kdf_iters: 300_000,
            pass_env: "SATAN2_PASS".to_string(),
            size_mib: 100,
            sources: Vec::new(),
            layer_algos: Vec::new(),
            hash_algo: "sha256".to_string(),
            ts_forge: 0, // 0 = current time at dispatch
            n_forge: 20,
        }
    }
}

#[cfg(target_os = "windows")]
fn usage() -> ! {
    eprintln!("satan2_win — Windows counter-forensics + encryption

DESTROY / COVER:
  destroy-all    Run all DESTROY modules
  cover-all      Run all COVER modules

FORENSIC ARTIFACT CLEANUP:
  vss            VSS shadow copy operations
  event-log      Clear Windows Event Logs
  prefetch       Delete Prefetch files
  registry       Clean registry artifacts
  ps-history     Wipe PowerShell history
  lnk            Delete LNK + JumpLists
  recycle-bin    Empty Recycle Bin
  defender       Clear Defender history/quarantine
  thumbcache     Delete thumbnail caches
  srum           Wipe SRUM database
  etw            Delete ETW traces + WER reports
  hiberfil       Disable hibernation + configure pagefile wipe
  win-search     Wipe Windows Search index (Windows.edb)
  browser        Wipe browser history (Chrome/Edge/Firefox/…)
  schtasks       Delete non-Microsoft scheduled tasks
  rdp            Remove RDP MRU, bitmap cache, credentials
  timeline       Wipe Windows Activity History + Clipboard
  amcache        Wipe Amcache.hve + AppCompatCache (ShimCache)
  user-assist    Wipe UserAssist registry entries (executed programs)

OPSEC:
  opsec          Apply OPSEC hardening (nolog/stealth mode)
  opsec-revert   Undo OPSEC hardening

FORGE (plant plausible artifacts — counter-forensics):
  forge-userassist   Inject fake executed-program records into UserAssist registry
  forge-event-log    Write fake MsiInstaller/AppError/ESENT events to Application log
  forge-registry-mru Add fake RunMRU / TypedPaths / TypedURLs / RecentDocs entries
  forge-browser-win  Inject fake history into Chrome/Edge/Firefox SQLite databases
  forge-prefetch     Create fake Prefetch files (.pf) in C:\\Windows\\Prefetch\\
  forge-lnk          Create fake LNK files in %%APPDATA%%\\Microsoft\\Windows\\Recent\\
  forge-shimcache    Inject fake entries into AppCompatCache (ShimCache)
  forge-bam          Inject fake BAM execution entries for current user SID
  forge-muicache     Inject fake MUI Cache entries (executed exe descriptions)
  forge-all          Run ALL forge modules  [--ts-forge <unix_ts>]

FORENSIC CLEANUP (targeted):
  wipe-bam           Delete BAM/DAM registry keys (execution timestamps)
  wipe-bits          Stop BITS service and delete BITS job database
  wipe-muicache      Delete MUI Cache entries (executed executables)
  wipe-usn           Delete $UsnJrnl on all accessible NTFS volumes

ENCRYPTION (SATAN2CV):
  create-container   Create new encrypted container  [--output] [--size-mib] [--algo] [--kdf-iters] [--pass-env]
  encrypt-file       Encrypt file to container       [--input] [--output] [--algo] [--kdf-iters] [--pass-env]
  encrypt-dir        Encrypt directory to container  [--input] [--output] [--algo] [--kdf-iters] [--pass-env]
  encrypt-layers     Encrypt file with N nested layers [--input] [--output] --layer <algo> [--layer <algo>]... [--kdf-iters] [--pass-env]
                     (innermost layer first; decrypt by N sequential 'decrypt' runs, outermost passphrase first)
  decrypt            Decrypt container to file       [--input] [--output] [--pass-env]
  extract            Extract dir-container to dir    [--input] [--output] [--pass-env]
  destroy-and-encrypt  Encrypt + wipe sources        [--source <path>]... [--output] [--algo] [--kdf-iters] [--pass-env]
  hash               Hash a file                     <path> [--hash-algo sha256|sha512|blake2b|sha3-256|sha3-512]

  Algos: aes (default) | twofish | camellia | cascade | kuznyechik
  Passphrase: set SATAN2_PASS env var (or use --pass-env to name the var);
  for encrypt-layers, layer i uses <PASS_ENV>_<i> (e.g. SATAN2_PASS_1..N)

MISC:
  list-vss       List VSS shadow copies

OPTIONS:
  --volume <X:>      VSS: target volume
  --after <ts>       VSS: only shadows after Unix timestamp
  --decoy            VSS: create decoy shadow after deletion
  --restore-pts      VSS: also wipe restore points
  --no-fallback      VSS: skip vssadmin.exe fallback
  --disable-pf       hiberfil: disable pagefile entirely (needs reboot)
  --verbose
  --dry-run          Print what would execute and skip execution (exit 0).
                     No module implements a native preview, so NOTHING is run.
                     list-vss and hash are read-only and still execute.
  --json             After execution, emit one JSON summary line on stdout:
                     {{\"module\":\"<mode>\",\"ok\":<bool>,\"errors\":<n>}}

Unknown arguments are rejected: a clear error is printed and the process
exits non-zero (nothing is executed).
");
    process::exit(1);
}

#[cfg(target_os = "windows")]
fn parse() -> Opts {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    let mut o = Opts::default();
    let mut i = 1usize;

    // Global flags may also appear before the mode.
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => {
                o.dry_run = true;
                i += 1;
            }
            "--json" => {
                o.json = true;
                i += 1;
            }
            _ => break,
        }
    }
    if i >= args.len() {
        usage();
    }

    o.mode = match args[i].as_str() {
        "destroy-all" => Mode::DestroyAll,
        "cover-all" => Mode::CoverAll,
        "opsec" => Mode::Opsec,
        "opsec-revert" => Mode::OpsecRevert,
        "vss" => Mode::Vss,
        "event-log" => Mode::EventLog,
        "prefetch" => Mode::Prefetch,
        "registry" => Mode::Registry,
        "ps-history" => Mode::PsHistory,
        "lnk" => Mode::Lnk,
        "recycle-bin" => Mode::RecycleBin,
        "defender" => Mode::Defender,
        "thumbcache" => Mode::Thumbcache,
        "srum" => Mode::Srum,
        "etw" => Mode::Etw,
        "hiberfil" => Mode::Hiberfil,
        "win-search" => Mode::WinSearch,
        "browser" => Mode::Browser,
        "schtasks" => Mode::Schtasks,
        "rdp" => Mode::Rdp,
        "timeline" => Mode::Timeline,
        "amcache" => Mode::Amcache,
        "user-assist" => Mode::UserAssist,
        "forge-userassist" => Mode::ForgeUserAssist,
        "forge-event-log" => Mode::ForgeEventLog,
        "forge-registry-mru" => Mode::ForgeRegistryMru,
        "forge-browser-win" => Mode::ForgeBrowserWin,
        "forge-prefetch" => Mode::ForgePrefetch,
        "forge-lnk" => Mode::ForgeLnk,
        "forge-shimcache" => Mode::ForgeShimcache,
        "wipe-bam" => Mode::WipeBam,
        "forge-bam" => Mode::ForgeBam,
        "wipe-bits" => Mode::WipeBits,
        "wipe-muicache" => Mode::WipeMuiCache,
        "forge-muicache" => Mode::ForgeMuiCache,
        "wipe-usn" => Mode::WipeUsnJrnl,
        "forge-all" => Mode::ForgeAll,
        "create-container" => Mode::CreateContainer,
        "encrypt-file" => Mode::EncryptFile,
        "encrypt-dir" => Mode::EncryptDir,
        "encrypt-layers" => Mode::EncryptLayers,
        "decrypt" => Mode::Decrypt,
        "extract" => Mode::Extract,
        "destroy-and-encrypt" => Mode::DestroyAndEncrypt,
        "hash" => {
            // hash takes a positional file path after the subcommand
            i += 1;
            if let Some(path) = args.get(i) {
                o.input = Some(path.clone());
                i += 1;
            }
            Mode::Hash
        }
        "list-vss" => Mode::List,
        _ => usage(),
    };
    if o.mode != Mode::Hash {
        i += 1;
    }

    while i < args.len() {
        match args[i].as_str() {
            "--volume" => {
                i += 1;
                o.vss_volume = args.get(i).cloned();
            }
            "--after" => {
                i += 1;
                o.vss_after = args.get(i).and_then(|s| s.parse().ok());
            }
            "--decoy" => o.vss_decoy = true,
            "--restore-pts" => o.restore_points = true,
            "--no-fallback" => o.no_fallback = true,
            "--disable-pf" => o.disable_pf = true,
            "--verbose" => o.verbose = true,
            // Crypto flags
            "--input" => {
                i += 1;
                o.input = args.get(i).cloned();
            }
            "--output" => {
                i += 1;
                o.output = args.get(i).cloned();
            }
            "--algo" => {
                i += 1;
                if let Some(a) = args.get(i) {
                    o.algo_str = a.clone();
                }
            }
            "--kdf-iters" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) {
                    o.kdf_iters = v;
                }
            }
            "--pass-env" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    o.pass_env = v.clone();
                }
            }
            "--size-mib" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) {
                    o.size_mib = v;
                }
            }
            "--source" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    o.sources.push(v.clone());
                }
            }
            "--layer" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    o.layer_algos.push(v.clone());
                }
            }
            "--hash-algo" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    o.hash_algo = v.clone();
                }
            }
            "--ts-forge" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) {
                    o.ts_forge = v;
                }
            }
            "--n-forge" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) {
                    o.n_forge = v;
                }
            }
            "--dry-run" => o.dry_run = true,
            "--json" => o.json = true,
            // NOTE: values of the known flags above are consumed inside their
            // own arms (i += 1), so they never reach this arm.
            unknown => {
                eprintln!("[!] unknown argument: {}", unknown);
                eprintln!("[*] run satan2_win without arguments for usage");
                process::exit(2);
            }
        }
        i += 1;
    }
    o
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn win_algo(s: &str) -> Algorithm {
    match s {
        "twofish" => Algorithm::Twofish256,
        "camellia" => Algorithm::Camellia256,
        "cascade" => Algorithm::AesTwofish,
        "kuznyechik" => Algorithm::Kuznyechik,
        _ => Algorithm::Aes256,
    }
}

#[cfg(target_os = "windows")]
fn win_hash_algo(s: &str) -> HashAlgo {
    match s {
        "sha512" => HashAlgo::Sha512,
        "blake2b" => HashAlgo::Blake2b512,
        "sha3-256" => HashAlgo::Sha3_256,
        "sha3-512" => HashAlgo::Sha3_512,
        _ => HashAlgo::Sha256,
    }
}

#[cfg(target_os = "windows")]
fn win_passphrase(pass_env: &str) -> Vec<u8> {
    match env::var(pass_env) {
        Ok(s) if !s.is_empty() => s.into_bytes(),
        _ => {
            // Visible prompt fallback (no echo suppression without Console API)
            eprint!("[?] {} not set — passphrase (visible): ", pass_env);
            use std::io::BufRead;
            let mut line = String::new();
            let _ = std::io::BufReader::new(std::io::stdin()).read_line(&mut line);
            let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
            if trimmed.is_empty() {
                eprintln!("[!] empty passphrase — aborting");
                process::exit(1);
            }
            trimmed.into_bytes()
        }
    }
}

// ── Orchestration ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn run_destroy_all(opts: &Opts) -> u64 {
    let mut errors: u64 = 0;
    eprintln!("[*] DESTROY ALL — Windows");

    eprintln!("\n[*] == VSS ==");
    match wmi::delete_shadows(None, None, opts.verbose) {
        Ok(n) => eprintln!("[+] VSS: {} shadow(s) deleted", n),
        Err(e) => {
            eprintln!("[!] VSS WMI: {} — trying vssadmin", e);
            if vssadmin::delete_all(None).is_err() {
                errors += 1;
            }
        }
    }
    if opts.restore_points && restore::delete_all(opts.verbose).is_err() {
        errors += 1;
    }

    eprintln!("\n[*] == Event Logs ==");
    errors += event_log::clear_all_event_logs(opts.verbose).failed as u64;

    eprintln!("\n[*] == Prefetch ==");
    errors += prefetch::wipe_prefetch(opts.verbose).errors as u64;

    eprintln!("\n[*] == Registry ==");
    errors += registry::clean_registry(opts.verbose).errors as u64;

    eprintln!("\n[*] == PowerShell History ==");
    errors += ps_history::wipe_ps_history(opts.verbose).errors as u64;

    eprintln!("\n[*] == LNK / JumpLists ==");
    errors += lnk_jumplists::wipe_lnk_jumplists(opts.verbose).errors as u64;

    eprintln!("\n[*] == Recycle Bin ==");
    errors += recycle_bin::wipe_recycle_bin(opts.verbose).errors as u64;

    eprintln!("\n[*] == Windows Defender ==");
    errors += defender::wipe_defender_artifacts(opts.verbose).errors as u64;

    eprintln!("\n[*] == Thumbcache ==");
    errors += thumbcache::wipe_thumbcache(opts.verbose).errors as u64;

    eprintln!("\n[*] == SRUM ==");
    errors += srum::wipe_srum(opts.verbose).error.is_some() as u64;

    eprintln!("\n[*] == ETW / WER ==");
    errors += etw::wipe_etw(opts.verbose).errors as u64;

    eprintln!("\n[*] == Hiberfil / Pagefile ==");
    errors += hiberfil::wipe_hiberfil(opts.disable_pf, opts.verbose).errors as u64;

    eprintln!("\n[*] == Windows Search ==");
    errors += win_search::wipe_win_search(opts.verbose).errors as u64;

    eprintln!("\n[*] == Browser History ==");
    errors += browser_history::wipe_browser_history(opts.verbose).errors as u64;

    eprintln!("\n[*] == Scheduled Tasks ==");
    errors += schtasks::wipe_scheduled_tasks(&[], true, opts.verbose).errors as u64;

    eprintln!("\n[*] == RDP Artifacts ==");
    errors += rdp::wipe_rdp_artifacts(opts.verbose).errors as u64;

    eprintln!("\n[*] == Timeline / Clipboard ==");
    errors += timeline::wipe_timeline(true, opts.verbose).errors as u64;

    eprintln!("\n[*] == Amcache / ShimCache ==");
    errors += amcache::wipe_amcache(opts.verbose).errors as u64;

    eprintln!("\n[*] == UserAssist ==");
    errors += userassist::wipe_userassist(opts.verbose).errors as u64;

    eprintln!("\n[*] == BAM/DAM ==");
    let bam = wipe_bam::wipe_bam(opts.verbose);
    eprintln!(
        "[+] bam: {} keys deleted, {} errors",
        bam.keys_deleted, bam.errors
    );
    errors += bam.errors as u64;

    eprintln!("\n[*] == MUI Cache ==");
    let mc = wipe_muicache::wipe_muicache(opts.verbose);
    eprintln!(
        "[+] muicache: {} values deleted, {} errors",
        mc.values_deleted, mc.errors
    );
    errors += mc.errors as u64;

    eprintln!("\n[*] == BITS Database ==");
    let bits = wipe_bits::wipe_bits(true, opts.verbose);
    eprintln!(
        "[+] bits: {} files removed, {} errors",
        bits.files_removed, bits.errors
    );
    errors += bits.errors as u64;

    eprintln!("\n[*] == NTFS $UsnJrnl ==");
    let usn = ntfs::wipe_usn_journal(opts.verbose);
    eprintln!(
        "[+] ntfs: {} journal(s) deleted, {} errors",
        usn.journals_deleted, usn.errors
    );
    errors += usn.errors as u64;

    if errors == 0 {
        eprintln!("\n[+] DESTROY ALL complete.");
    } else {
        eprintln!("\n[!] DESTROY ALL finished with {} error(s).", errors);
    }
    errors
}

#[cfg(target_os = "windows")]
fn current_unix_ts() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn run_forge_all(opts: &Opts) -> u64 {
    let mut errors: u64 = 0;
    let ts = if opts.ts_forge != 0 {
        opts.ts_forge
    } else {
        current_unix_ts()
    };
    eprintln!("[*] FORGE ALL — Windows (ts={})", ts);

    eprintln!("\n[*] == Forge UserAssist ==");
    let ua = forge_userassist::forge_userassist(ts, opts.verbose);
    eprintln!(
        "[+] forge-ua: {} entries, {} errors",
        ua.entries_written, ua.errors
    );
    errors += ua.errors as u64;

    eprintln!("\n[*] == Forge EventLog ==");
    let ev = forge_event_log::forge_event_log(opts.verbose);
    eprintln!(
        "[+] forge-evtlog: {} events, {} errors",
        ev.events_written, ev.errors
    );
    errors += ev.errors as u64;

    eprintln!("\n[*] == Forge Registry MRU ==");
    let rm = forge_registry_mru::forge_registry_mru(opts.verbose);
    eprintln!(
        "[+] forge-reg-mru: {} entries, {} errors",
        rm.entries_written, rm.errors
    );
    errors += rm.errors as u64;

    eprintln!("\n[*] == Forge Browser (Windows) ==");
    let bw = forge_browser_win::forge_browser_win(&forge_browser_win::BrowserWinForgeOpts {
        n_entries: opts.n_forge.max(20),
        ts_start: ts - 259_200,
        ts_end: ts,
        verbose: opts.verbose,
    });
    eprintln!(
        "[+] forge-browser-win: chrome={}, firefox={}, dbs={}",
        bw.chrome_entries, bw.firefox_entries, bw.dbs_touched
    );
    errors += bw.errors as u64;

    eprintln!("\n[*] == Forge Prefetch ==");
    let pf = forge_prefetch::forge_prefetch(&forge_prefetch::PrefetchForgeOpts {
        n_files: opts.n_forge.clamp(10, 20),
        ts_base: ts,
        verbose: opts.verbose,
    });
    eprintln!(
        "[+] forge-prefetch: {} files, {} errors",
        pf.files_written, pf.errors
    );
    errors += pf.errors as u64;

    eprintln!("\n[*] == Forge LNK ==");
    let lnk = forge_lnk::forge_lnk(&forge_lnk::LnkForgeOpts {
        n_files: opts.n_forge.clamp(10, 20),
        ts_base: ts,
        verbose: opts.verbose,
    });
    eprintln!(
        "[+] forge-lnk: {} files, {} errors",
        lnk.files_written, lnk.errors
    );
    errors += lnk.errors as u64;

    eprintln!("\n[*] == Forge ShimCache ==");
    let sc = forge_shimcache::forge_shimcache(&forge_shimcache::ShimcacheForgeOpts {
        n_entries: opts.n_forge.max(20),
        ts_base: ts,
        verbose: opts.verbose,
    });
    eprintln!(
        "[+] forge-shimcache: {} entries, {} errors",
        sc.entries_injected, sc.errors
    );
    errors += sc.errors as u64;

    eprintln!("\n[*] == Forge BAM ==");
    let bam = wipe_bam::forge_bam(ts - 7 * 86_400, ts, opts.n_forge.min(17), opts.verbose);
    eprintln!(
        "[+] forge-bam: {} entries, {} errors",
        bam.entries_forged, bam.errors
    );
    errors += bam.errors as u64;

    eprintln!("\n[*] == Forge MUI Cache ==");
    let mc = wipe_muicache::forge_muicache(opts.n_forge.min(16), opts.verbose);
    eprintln!(
        "[+] forge-muicache: {} values, {} errors",
        mc.values_forged, mc.errors
    );
    errors += mc.errors as u64;

    if errors == 0 {
        eprintln!("\n[+] FORGE ALL complete.");
    } else {
        eprintln!("\n[!] FORGE ALL finished with {} error(s).", errors);
    }
    errors
}

#[cfg(target_os = "windows")]
fn run_cover_all(opts: &Opts) -> u64 {
    let mut errors: u64 = 0;
    eprintln!("[*] COVER ALL — Windows");

    match wmi::delete_shadows(opts.vss_volume.as_deref(), opts.vss_after, opts.verbose) {
        Ok(n) => eprintln!("[+] VSS: {} shadow(s) deleted", n),
        Err(e) => {
            eprintln!("[!] VSS: {}", e);
            errors += 1;
        }
    }
    if opts.vss_decoy {
        let vol = opts.vss_volume.as_deref().unwrap_or("C:");
        match wmi::create_shadow(vol) {
            Ok(id) => eprintln!("[+] VSS: decoy shadow: {}", id),
            Err(e) => {
                eprintln!("[!] VSS decoy: {}", e);
                errors += 1;
            }
        }
    }

    errors += event_log::clear_all_event_logs(opts.verbose).failed as u64;
    errors += ps_history::wipe_ps_history(opts.verbose).errors as u64;
    errors += lnk_jumplists::wipe_lnk_jumplists(opts.verbose).errors as u64;
    errors += registry::clean_registry(opts.verbose).errors as u64;

    if errors == 0 {
        eprintln!("[+] COVER ALL complete.");
    } else {
        eprintln!("[!] COVER ALL finished with {} error(s).", errors);
    }
    errors
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn mode_name(mode: &Mode) -> &'static str {
    match mode {
        Mode::DestroyAll => "destroy-all",
        Mode::CoverAll => "cover-all",
        Mode::Vss => "vss",
        Mode::EventLog => "event-log",
        Mode::Prefetch => "prefetch",
        Mode::Registry => "registry",
        Mode::PsHistory => "ps-history",
        Mode::Lnk => "lnk",
        Mode::RecycleBin => "recycle-bin",
        Mode::Defender => "defender",
        Mode::Thumbcache => "thumbcache",
        Mode::Srum => "srum",
        Mode::Etw => "etw",
        Mode::Hiberfil => "hiberfil",
        Mode::WinSearch => "win-search",
        Mode::Browser => "browser",
        Mode::Schtasks => "schtasks",
        Mode::Rdp => "rdp",
        Mode::Timeline => "timeline",
        Mode::Opsec => "opsec",
        Mode::OpsecRevert => "opsec-revert",
        Mode::Amcache => "amcache",
        Mode::UserAssist => "user-assist",
        Mode::WipeBam => "wipe-bam",
        Mode::ForgeBam => "forge-bam",
        Mode::WipeBits => "wipe-bits",
        Mode::WipeMuiCache => "wipe-muicache",
        Mode::WipeUsnJrnl => "wipe-usn",
        Mode::ForgeUserAssist => "forge-userassist",
        Mode::ForgeEventLog => "forge-event-log",
        Mode::ForgeRegistryMru => "forge-registry-mru",
        Mode::ForgeBrowserWin => "forge-browser-win",
        Mode::ForgePrefetch => "forge-prefetch",
        Mode::ForgeLnk => "forge-lnk",
        Mode::ForgeShimcache => "forge-shimcache",
        Mode::ForgeMuiCache => "forge-muicache",
        Mode::ForgeAll => "forge-all",
        Mode::CreateContainer => "create-container",
        Mode::EncryptFile => "encrypt-file",
        Mode::EncryptDir => "encrypt-dir",
        Mode::EncryptLayers => "encrypt-layers",
        Mode::Decrypt => "decrypt",
        Mode::Extract => "extract",
        Mode::DestroyAndEncrypt => "destroy-and-encrypt",
        Mode::Hash => "hash",
        Mode::List => "list-vss",
    }
}

#[cfg(target_os = "windows")]
fn main() {
    let opts = parse();

    privilege::enable_backup_restore().unwrap_or_else(|e| {
        eprintln!("[!] Privilege: {} (continuing)", e);
    });

    // --dry-run: no module in this crate implements a native preview, so we
    // report what would run and skip execution entirely. list-vss and hash
    // are read-only, so they still execute under --dry-run.
    if opts.dry_run && !matches!(opts.mode, Mode::List | Mode::Hash) {
        eprintln!("[*] dry-run: would execute {}", mode_name(&opts.mode));
        if opts.json {
            println!(
                "{{\"dry_run\":true,\"module\":\"{}\",\"ok\":true}}",
                mode_name(&opts.mode)
            );
        }
        return;
    }

    let errors: u64 = match opts.mode {
        Mode::DestroyAll => run_destroy_all(&opts),
        Mode::CoverAll => run_cover_all(&opts),

        Mode::List => match wmi::list_shadows(opts.verbose) {
            Ok(s) if s.is_empty() => {
                println!("[*] No shadow copies.");
                0
            }
            Ok(s) => {
                for sh in s {
                    println!("  {} vol={} date={}", sh.id, sh.volume, sh.install_date);
                }
                0
            }
            Err(e) => {
                eprintln!("[!] {}", e);
                1
            }
        },

        Mode::Vss => {
            let mut errors: u64 = 0;
            match wmi::delete_shadows(opts.vss_volume.as_deref(), opts.vss_after, opts.verbose) {
                Ok(n) => eprintln!("[+] VSS: {} deleted", n),
                Err(e) => {
                    if !opts.no_fallback {
                        if vssadmin::delete_all(opts.vss_volume.as_deref()).is_err() {
                            errors += 1;
                        }
                    } else {
                        eprintln!("[!] {}", e);
                        errors += 1;
                    }
                }
            }
            // Disable the VSS service so shadows are not re-created
            if let Err(e) = service::disable_vss() {
                if opts.verbose {
                    eprintln!("[!] VSS service disable: {}", e);
                }
            }
            if opts.restore_points && restore::delete_all(opts.verbose).is_err() {
                errors += 1;
            }
            errors
        }

        Mode::EventLog => event_log::clear_all_event_logs(opts.verbose).failed as u64,
        Mode::Prefetch => prefetch::wipe_prefetch(opts.verbose).errors as u64,
        Mode::Registry => registry::clean_registry(opts.verbose).errors as u64,
        Mode::PsHistory => ps_history::wipe_ps_history(opts.verbose).errors as u64,
        Mode::Lnk => lnk_jumplists::wipe_lnk_jumplists(opts.verbose).errors as u64,
        Mode::RecycleBin => recycle_bin::wipe_recycle_bin(opts.verbose).errors as u64,
        Mode::Defender => defender::wipe_defender_artifacts(opts.verbose).errors as u64,
        Mode::Thumbcache => thumbcache::wipe_thumbcache(opts.verbose).errors as u64,
        Mode::Srum => srum::wipe_srum(opts.verbose).error.is_some() as u64,
        Mode::Etw => etw::wipe_etw(opts.verbose).errors as u64,
        Mode::Hiberfil => hiberfil::wipe_hiberfil(opts.disable_pf, opts.verbose).errors as u64,
        Mode::WinSearch => win_search::wipe_win_search(opts.verbose).errors as u64,
        Mode::Browser => browser_history::wipe_browser_history(opts.verbose).errors as u64,
        Mode::Schtasks => schtasks::wipe_scheduled_tasks(&[], true, opts.verbose).errors as u64,
        Mode::Rdp => rdp::wipe_rdp_artifacts(opts.verbose).errors as u64,
        Mode::Timeline => timeline::wipe_timeline(opts.disable_pf, opts.verbose).errors as u64,
        Mode::Opsec => opsec_win::apply_opsec_win(opts.verbose).errors as u64,
        Mode::OpsecRevert => {
            opsec_win::revert_opsec_win(opts.verbose);
            0
        }
        Mode::Amcache => amcache::wipe_amcache(opts.verbose).errors as u64,
        Mode::UserAssist => userassist::wipe_userassist(opts.verbose).errors as u64,

        // ── Forge ─────────────────────────────────────────────────────────────
        Mode::ForgeUserAssist => {
            let ts = if opts.ts_forge != 0 {
                opts.ts_forge
            } else {
                current_unix_ts()
            };
            let r = forge_userassist::forge_userassist(ts, opts.verbose);
            eprintln!(
                "[+] forge-ua: {} entries, {} errors",
                r.entries_written, r.errors
            );
            r.errors as u64
        }
        Mode::ForgeEventLog => {
            let r = forge_event_log::forge_event_log(opts.verbose);
            eprintln!(
                "[+] forge-evtlog: {} events, {} errors",
                r.events_written, r.errors
            );
            r.errors as u64
        }
        Mode::ForgeRegistryMru => {
            let r = forge_registry_mru::forge_registry_mru(opts.verbose);
            eprintln!(
                "[+] forge-reg-mru: {} entries, {} errors",
                r.entries_written, r.errors
            );
            r.errors as u64
        }
        Mode::ForgeBrowserWin => {
            let ts = if opts.ts_forge != 0 {
                opts.ts_forge
            } else {
                current_unix_ts()
            };
            let r = forge_browser_win::forge_browser_win(&forge_browser_win::BrowserWinForgeOpts {
                n_entries: opts.n_forge.max(20),
                ts_start: ts - 259_200,
                ts_end: ts,
                verbose: opts.verbose,
            });
            eprintln!(
                "[+] forge-browser-win: chrome={}, firefox={}, dbs={}, errors={}",
                r.chrome_entries, r.firefox_entries, r.dbs_touched, r.errors
            );
            r.errors as u64
        }
        Mode::ForgePrefetch => {
            let ts = if opts.ts_forge != 0 {
                opts.ts_forge
            } else {
                current_unix_ts()
            };
            let r = forge_prefetch::forge_prefetch(&forge_prefetch::PrefetchForgeOpts {
                n_files: opts.n_forge.clamp(10, 20),
                ts_base: ts,
                verbose: opts.verbose,
            });
            eprintln!(
                "[+] forge-prefetch: {} files, {} errors",
                r.files_written, r.errors
            );
            r.errors as u64
        }
        Mode::ForgeLnk => {
            let ts = if opts.ts_forge != 0 {
                opts.ts_forge
            } else {
                current_unix_ts()
            };
            let r = forge_lnk::forge_lnk(&forge_lnk::LnkForgeOpts {
                n_files: opts.n_forge.clamp(10, 20),
                ts_base: ts,
                verbose: opts.verbose,
            });
            eprintln!(
                "[+] forge-lnk: {} files, {} errors",
                r.files_written, r.errors
            );
            r.errors as u64
        }
        Mode::ForgeShimcache => {
            let ts = if opts.ts_forge != 0 {
                opts.ts_forge
            } else {
                current_unix_ts()
            };
            let r = forge_shimcache::forge_shimcache(&forge_shimcache::ShimcacheForgeOpts {
                n_entries: opts.n_forge.max(20),
                ts_base: ts,
                verbose: opts.verbose,
            });
            eprintln!(
                "[+] forge-shimcache: {} entries, {} errors",
                r.entries_injected, r.errors
            );
            r.errors as u64
        }
        Mode::WipeBam => {
            let r = wipe_bam::wipe_bam(opts.verbose);
            eprintln!(
                "[+] wipe-bam: {} keys deleted, {} errors",
                r.keys_deleted, r.errors
            );
            r.errors as u64
        }
        Mode::ForgeBam => {
            let ts = if opts.ts_forge != 0 {
                opts.ts_forge
            } else {
                current_unix_ts()
            };
            let r = wipe_bam::forge_bam(ts - 7 * 86_400, ts, opts.n_forge.min(17), opts.verbose);
            eprintln!(
                "[+] forge-bam: {} entries, {} errors",
                r.entries_forged, r.errors
            );
            r.errors as u64
        }
        Mode::WipeBits => {
            let r = wipe_bits::wipe_bits(true, opts.verbose);
            eprintln!(
                "[+] wipe-bits: {} files removed, service_stopped={}, {} errors",
                r.files_removed, r.service_stopped, r.errors
            );
            r.errors as u64
        }
        Mode::WipeMuiCache => {
            let r = wipe_muicache::wipe_muicache(opts.verbose);
            eprintln!(
                "[+] wipe-muicache: {} values deleted, {} errors",
                r.values_deleted, r.errors
            );
            r.errors as u64
        }
        Mode::ForgeMuiCache => {
            let r = wipe_muicache::forge_muicache(opts.n_forge.min(16), opts.verbose);
            eprintln!(
                "[+] forge-muicache: {} values written, {} errors",
                r.values_forged, r.errors
            );
            r.errors as u64
        }
        Mode::WipeUsnJrnl => {
            let r = ntfs::wipe_usn_journal(opts.verbose);
            eprintln!(
                "[+] wipe-usn: {} journal(s) deleted, {} errors",
                r.journals_deleted, r.errors
            );
            r.errors as u64
        }
        Mode::ForgeAll => run_forge_all(&opts),

        // ── Crypto ────────────────────────────────────────────────────────────
        Mode::CreateContainer => {
            let out = opts.output.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --output required");
                process::exit(1);
            });
            let pass = win_passphrase(&opts.pass_env);
            let size = opts.size_mib * 1024 * 1024;
            eprintln!(
                "[*] create-container: {} ({} MiB, {})",
                out, opts.size_mib, opts.algo_str
            );
            match create_container(
                out,
                size,
                win_algo(&opts.algo_str),
                &pass,
                opts.kdf_iters,
                opts.verbose,
            ) {
                Ok(()) => {
                    eprintln!("[+] create-container: done");
                    0
                }
                Err(e) => {
                    eprintln!("[!] create-container: {}", e);
                    1
                }
            }
        }

        Mode::EncryptFile => {
            let inp = opts.input.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --input required");
                process::exit(1);
            });
            let out = opts.output.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --output required");
                process::exit(1);
            });
            let pass = win_passphrase(&opts.pass_env);
            eprintln!("[*] encrypt-file: {} → {}", inp, out);
            match encrypt_file(inp, out, win_algo(&opts.algo_str), &pass, opts.kdf_iters) {
                Ok(b) => {
                    eprintln!("[+] encrypt-file: {} bytes", b);
                    0
                }
                Err(e) => {
                    eprintln!("[!] encrypt-file: {}", e);
                    1
                }
            }
        }

        Mode::EncryptDir => {
            let inp = opts.input.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --input required");
                process::exit(1);
            });
            let out = opts.output.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --output required");
                process::exit(1);
            });
            let pass = win_passphrase(&opts.pass_env);
            eprintln!("[*] encrypt-dir: {} → {}", inp, out);
            match encrypt_dir(inp, out, win_algo(&opts.algo_str), &pass, opts.kdf_iters) {
                Ok(b) => {
                    eprintln!("[+] encrypt-dir: {} bytes", b);
                    0
                }
                Err(e) => {
                    eprintln!("[!] encrypt-dir: {}", e);
                    1
                }
            }
        }

        Mode::EncryptLayers => {
            let inp = opts.input.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --input required");
                process::exit(1);
            });
            let out = opts.output.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --output required");
                process::exit(1);
            });
            if opts.layer_algos.len() < 2 {
                eprintln!("[!] encrypt-layers: specify at least 2 --layer flags (use encrypt-file for a single layer)");
                process::exit(1);
            }
            let mut layers: Vec<Layer> = Vec::with_capacity(opts.layer_algos.len());
            for (i, a) in opts.layer_algos.iter().enumerate() {
                // Passphrase for layer i+1: SATAN2_PASS_<i+1>; layer 1 falls
                // back to the base --pass-env var (default SATAN2_PASS).
                let indexed = format!("{}_{}", opts.pass_env, i + 1);
                let pass = match env::var(&indexed) {
                    Ok(s) if !s.is_empty() => s.into_bytes(),
                    _ if i == 0 => win_passphrase(&opts.pass_env),
                    _ => win_passphrase(&indexed),
                };
                layers.push(Layer {
                    algo: win_algo(a),
                    passphrase: pass,
                });
            }
            eprintln!(
                "[*] encrypt-layers: {} → {} ({} layers, innermost→outermost)",
                inp,
                out,
                layers.len()
            );
            match encrypt_layers(inp, out, &layers, opts.kdf_iters) {
                Ok(b) => {
                    eprintln!("[+] encrypt-layers: {} plaintext bytes", b);
                    0
                }
                Err(e) => {
                    eprintln!("[!] encrypt-layers: {}", e);
                    1
                }
            }
        }

        Mode::Decrypt => {
            let inp = opts.input.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --input required");
                process::exit(1);
            });
            let out = opts.output.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --output required");
                process::exit(1);
            });
            let pass = win_passphrase(&opts.pass_env);
            eprintln!("[*] decrypt: {} → {}", inp, out);
            match decrypt_container(inp, out, &pass) {
                Ok(b) => {
                    eprintln!("[+] decrypt: {} bytes", b);
                    0
                }
                Err(e) => {
                    eprintln!("[!] decrypt: {}", e);
                    1
                }
            }
        }

        Mode::Extract => {
            let inp = opts.input.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --input required");
                process::exit(1);
            });
            let out = opts.output.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --output required");
                process::exit(1);
            });
            let pass = win_passphrase(&opts.pass_env);
            eprintln!("[*] extract: {} → {}/", inp, out);
            match extract_dir(inp, out, &pass) {
                Ok(b) => {
                    eprintln!("[+] extract: {} bytes", b);
                    0
                }
                Err(e) => {
                    eprintln!("[!] extract: {}", e);
                    1
                }
            }
        }

        Mode::DestroyAndEncrypt => {
            if opts.sources.is_empty() {
                eprintln!("[!] --source required");
                process::exit(1);
            }
            let out = opts.output.as_deref().unwrap_or_else(|| {
                eprintln!("[!] --output required");
                process::exit(1);
            });
            let pass = win_passphrase(&opts.pass_env);
            let srcs: Vec<&str> = opts.sources.iter().map(String::as_str).collect();
            eprintln!(
                "[*] destroy-and-encrypt: {} source(s) → {}",
                srcs.len(),
                out
            );
            match destroy_and_encrypt(&srcs, out, win_algo(&opts.algo_str), &pass, opts.kdf_iters) {
                Ok(b) => {
                    eprintln!("[+] destroy-and-encrypt: {} bytes, sources wiped", b);
                    0
                }
                Err(e) => {
                    eprintln!("[!] destroy-and-encrypt: {}", e);
                    1
                }
            }
        }

        Mode::Hash => {
            let path = opts.input.as_deref().unwrap_or_else(|| {
                eprintln!("[!] file path required after 'hash'");
                process::exit(1);
            });
            let halgo = win_hash_algo(&opts.hash_algo);
            match hash_file(path, halgo) {
                Ok(digest) => {
                    println!("{}  {}", to_hex(&digest), path);
                    0
                }
                Err(e) => {
                    eprintln!("[!] hash: {}", e);
                    1
                }
            }
        }
    };

    if opts.json {
        println!(
            "{{\"module\":\"{}\",\"ok\":{},\"errors\":{}}}",
            mode_name(&opts.mode),
            errors == 0,
            errors
        );
    }

    if errors != 0 {
        process::exit(1);
    }
}
