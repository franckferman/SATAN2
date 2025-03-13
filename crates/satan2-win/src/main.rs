#![allow(non_snake_case)]

// Non-Windows stub so `cargo check` on Linux does not fail on a missing main.
#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("[!] satan2_win is Windows-only.");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
mod wmi;
#[cfg(target_os = "windows")]
mod vssadmin;
#[cfg(target_os = "windows")]
mod service;
#[cfg(target_os = "windows")]
mod restore;
#[cfg(target_os = "windows")]
mod privilege;
#[cfg(target_os = "windows")]
mod event_log;
#[cfg(target_os = "windows")]
mod prefetch;
#[cfg(target_os = "windows")]
mod registry;
#[cfg(target_os = "windows")]
mod ps_history;
#[cfg(target_os = "windows")]
mod lnk_jumplists;
#[cfg(target_os = "windows")]
mod recycle_bin;
#[cfg(target_os = "windows")]
mod defender;
#[cfg(target_os = "windows")]
mod thumbcache;
#[cfg(target_os = "windows")]
mod srum;
#[cfg(target_os = "windows")]
mod etw;
#[cfg(target_os = "windows")]
mod hiberfil;
#[cfg(target_os = "windows")]
mod win_search;
#[cfg(target_os = "windows")]
mod browser_history;
#[cfg(target_os = "windows")]
mod schtasks;
#[cfg(target_os = "windows")]
mod rdp;
#[cfg(target_os = "windows")]
mod timeline;
#[cfg(target_os = "windows")]
mod opsec_win;
#[cfg(target_os = "windows")]
mod amcache;
#[cfg(target_os = "windows")]
mod userassist;
#[cfg(target_os = "windows")]
mod forge_userassist;
#[cfg(target_os = "windows")]
mod forge_event_log;
#[cfg(target_os = "windows")]
mod forge_registry_mru;
#[cfg(target_os = "windows")]
mod forge_browser_win;
#[cfg(target_os = "windows")]
mod forge_prefetch;
#[cfg(target_os = "windows")]
mod forge_lnk;
#[cfg(target_os = "windows")]
mod forge_shimcache;
#[cfg(target_os = "windows")]
mod wipe_bam;
#[cfg(target_os = "windows")]
mod wipe_bits;
#[cfg(target_os = "windows")]
mod wipe_muicache;
#[cfg(target_os = "windows")]
mod ntfs;

#[cfg(target_os = "windows")]
use std::env;
#[cfg(target_os = "windows")]
use std::process;

#[cfg(target_os = "windows")]
use satan2_crypto::{
    ops::{create_container, encrypt_file, encrypt_dir, decrypt_container, destroy_and_encrypt},
    hash::{hash_file, to_hex, HashAlgo},
    extract_dir,
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
    Decrypt,
    Extract,
    DestroyAndEncrypt,
    Hash,
    List,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct Opts {
    mode:            Mode,
    verbose:         bool,
    // VSS
    vss_volume:      Option<String>,
    vss_after:       Option<i64>,
    vss_decoy:       bool,
    restore_points:  bool,
    no_fallback:     bool,
    // Storage
    disable_pf:      bool,
    // Crypto shared
    input:           Option<String>,
    output:          Option<String>,
    algo_str:        String,
    kdf_iters:       u32,
    pass_env:        String,
    size_mib:        u64,
    sources:         Vec<String>,
    hash_algo:       String,
    // Forge
    ts_forge:        i64,
    n_forge:         u32, // entry/file count for forge subcommands
}

#[cfg(target_os = "windows")]
impl Default for Opts {
    fn default() -> Self {
        Opts {
            mode:           Mode::default(),
            verbose:        false,
            vss_volume:     None,
            vss_after:      None,
            vss_decoy:      false,
            restore_points: false,
            no_fallback:    false,
            disable_pf:     false,
            input:          None,
            output:         None,
            algo_str:       "aes".to_string(),
            kdf_iters:      300_000,
            pass_env:       "SATAN2_PASS".to_string(),
            size_mib:       100,
            sources:        Vec::new(),
            hash_algo:      "sha256".to_string(),
            ts_forge:       0, // 0 = current time at dispatch
            n_forge:        20,
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
  decrypt            Decrypt container to file       [--input] [--output] [--pass-env]
  extract            Extract dir-container to dir    [--input] [--output] [--pass-env]
  destroy-and-encrypt  Encrypt + wipe sources        [--source <path>]... [--output] [--algo] [--kdf-iters] [--pass-env]
  hash               Hash a file                     <path> [--hash-algo sha256|sha512|blake2b|sha3-256|sha3-512]

  Algos: aes (default) | twofish | camellia | cascade | kuznyechik
  Passphrase: set SATAN2_PASS env var (or use --pass-env to name the var)

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
");
    process::exit(1);
}

#[cfg(target_os = "windows")]
fn parse() -> Opts {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { usage(); }

    let mut o = Opts::default();
    let mut i = 1usize;

    o.mode = match args[i].as_str() {
        "destroy-all"        => Mode::DestroyAll,
        "cover-all"          => Mode::CoverAll,
        "opsec"              => Mode::Opsec,
        "opsec-revert"       => Mode::OpsecRevert,
        "vss"                => Mode::Vss,
        "event-log"          => Mode::EventLog,
        "prefetch"           => Mode::Prefetch,
        "registry"           => Mode::Registry,
        "ps-history"         => Mode::PsHistory,
        "lnk"                => Mode::Lnk,
        "recycle-bin"        => Mode::RecycleBin,
        "defender"           => Mode::Defender,
        "thumbcache"         => Mode::Thumbcache,
        "srum"               => Mode::Srum,
        "etw"                => Mode::Etw,
        "hiberfil"           => Mode::Hiberfil,
        "win-search"         => Mode::WinSearch,
        "browser"            => Mode::Browser,
        "schtasks"           => Mode::Schtasks,
        "rdp"                => Mode::Rdp,
        "timeline"           => Mode::Timeline,
        "amcache"              => Mode::Amcache,
        "user-assist"          => Mode::UserAssist,
        "forge-userassist"     => Mode::ForgeUserAssist,
        "forge-event-log"      => Mode::ForgeEventLog,
        "forge-registry-mru"   => Mode::ForgeRegistryMru,
        "forge-browser-win"    => Mode::ForgeBrowserWin,
        "forge-prefetch"       => Mode::ForgePrefetch,
        "forge-lnk"            => Mode::ForgeLnk,
        "forge-shimcache"      => Mode::ForgeShimcache,
        "wipe-bam"             => Mode::WipeBam,
        "forge-bam"            => Mode::ForgeBam,
        "wipe-bits"            => Mode::WipeBits,
        "wipe-muicache"        => Mode::WipeMuiCache,
        "forge-muicache"       => Mode::ForgeMuiCache,
        "wipe-usn"             => Mode::WipeUsnJrnl,
        "forge-all"            => Mode::ForgeAll,
        "create-container"     => Mode::CreateContainer,
        "encrypt-file"       => Mode::EncryptFile,
        "encrypt-dir"        => Mode::EncryptDir,
        "decrypt"            => Mode::Decrypt,
        "extract"            => Mode::Extract,
        "destroy-and-encrypt"=> Mode::DestroyAndEncrypt,
        "hash"               => {
            // hash takes a positional file path after the subcommand
            i += 1;
            if let Some(path) = args.get(i) {
                o.input = Some(path.clone());
                i += 1;
            }
            Mode::Hash
        }
        "list-vss"           => Mode::List,
        _                    => usage(),
    };
    if o.mode != Mode::Hash { i += 1; }

    while i < args.len() {
        match args[i].as_str() {
            "--volume"      => { i += 1; o.vss_volume = args.get(i).cloned(); }
            "--after"       => { i += 1; o.vss_after = args.get(i).and_then(|s| s.parse().ok()); }
            "--decoy"       => o.vss_decoy      = true,
            "--restore-pts" => o.restore_points = true,
            "--no-fallback" => o.no_fallback    = true,
            "--disable-pf"  => o.disable_pf     = true,
            "--verbose"     => o.verbose        = true,
            // Crypto flags
            "--input"       => { i += 1; o.input      = args.get(i).cloned(); }
            "--output"      => { i += 1; o.output     = args.get(i).cloned(); }
            "--algo"        => { i += 1; if let Some(a) = args.get(i) { o.algo_str = a.clone(); } }
            "--kdf-iters"   => { i += 1; if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) { o.kdf_iters = v; } }
            "--pass-env"    => { i += 1; if let Some(v) = args.get(i) { o.pass_env = v.clone(); } }
            "--size-mib"    => { i += 1; if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) { o.size_mib = v; } }
            "--source"      => { i += 1; if let Some(v) = args.get(i) { o.sources.push(v.clone()); } }
            "--hash-algo"   => { i += 1; if let Some(v) = args.get(i) { o.hash_algo = v.clone(); } }
            "--ts-forge"    => { i += 1; if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) { o.ts_forge = v; } }
            "--n-forge"     => { i += 1; if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) { o.n_forge = v; } }
            _               => {}
        }
        i += 1;
    }
    o
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn win_algo(s: &str) -> Algorithm {
    match s {
        "twofish"    => Algorithm::Twofish256,
        "camellia"   => Algorithm::Camellia256,
        "cascade"    => Algorithm::AesTwofish,
        "kuznyechik" => Algorithm::Kuznyechik,
        _            => Algorithm::Aes256,
    }
}

#[cfg(target_os = "windows")]
fn win_hash_algo(s: &str) -> HashAlgo {
    match s {
        "sha512"   => HashAlgo::Sha512,
        "blake2b"  => HashAlgo::Blake2b512,
        "sha3-256" => HashAlgo::Sha3_256,
        "sha3-512" => HashAlgo::Sha3_512,
        _          => HashAlgo::Sha256,
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
fn run_destroy_all(opts: &Opts) {
    eprintln!("[*] DESTROY ALL — Windows");

    eprintln!("\n[*] == VSS ==");
    match wmi::delete_shadows(None, None, opts.verbose) {
        Ok(n)  => eprintln!("[+] VSS: {} shadow(s) deleted", n),
        Err(e) => {
            eprintln!("[!] VSS WMI: {} — trying vssadmin", e);
            let _ = vssadmin::delete_all(None);
        }
    }
    if opts.restore_points { let _ = restore::delete_all(opts.verbose); }

    eprintln!("\n[*] == Event Logs ==");
    event_log::clear_all_event_logs(opts.verbose);

    eprintln!("\n[*] == Prefetch ==");
    prefetch::wipe_prefetch(opts.verbose);

    eprintln!("\n[*] == Registry ==");
    registry::clean_registry(opts.verbose);

    eprintln!("\n[*] == PowerShell History ==");
    ps_history::wipe_ps_history(opts.verbose);

    eprintln!("\n[*] == LNK / JumpLists ==");
    lnk_jumplists::wipe_lnk_jumplists(opts.verbose);

    eprintln!("\n[*] == Recycle Bin ==");
    recycle_bin::wipe_recycle_bin(opts.verbose);

    eprintln!("\n[*] == Windows Defender ==");
    defender::wipe_defender_artifacts(opts.verbose);

    eprintln!("\n[*] == Thumbcache ==");
    thumbcache::wipe_thumbcache(opts.verbose);

    eprintln!("\n[*] == SRUM ==");
    srum::wipe_srum(opts.verbose);

    eprintln!("\n[*] == ETW / WER ==");
    etw::wipe_etw(opts.verbose);

    eprintln!("\n[*] == Hiberfil / Pagefile ==");
    hiberfil::wipe_hiberfil(opts.disable_pf, opts.verbose);

    eprintln!("\n[*] == Windows Search ==");
    win_search::wipe_win_search(opts.verbose);

    eprintln!("\n[*] == Browser History ==");
    browser_history::wipe_browser_history(opts.verbose);

    eprintln!("\n[*] == Scheduled Tasks ==");
    schtasks::wipe_scheduled_tasks(&[], true, opts.verbose);

    eprintln!("\n[*] == RDP Artifacts ==");
    rdp::wipe_rdp_artifacts(opts.verbose);

    eprintln!("\n[*] == Timeline / Clipboard ==");
    timeline::wipe_timeline(true, opts.verbose);

    eprintln!("\n[*] == Amcache / ShimCache ==");
    amcache::wipe_amcache(opts.verbose);

    eprintln!("\n[*] == UserAssist ==");
    userassist::wipe_userassist(opts.verbose);

    eprintln!("\n[*] == BAM/DAM ==");
    let bam = wipe_bam::wipe_bam(opts.verbose);
    eprintln!("[+] bam: {} keys deleted, {} errors", bam.keys_deleted, bam.errors);

    eprintln!("\n[*] == MUI Cache ==");
    let mc = wipe_muicache::wipe_muicache(opts.verbose);
    eprintln!("[+] muicache: {} values deleted, {} errors", mc.values_deleted, mc.errors);

    eprintln!("\n[*] == BITS Database ==");
    let bits = wipe_bits::wipe_bits(true, opts.verbose);
    eprintln!("[+] bits: {} files removed, {} errors", bits.files_removed, bits.errors);

    eprintln!("\n[*] == NTFS $UsnJrnl ==");
    let usn = ntfs::wipe_usn_journal(opts.verbose);
    eprintln!("[+] ntfs: {} journal(s) deleted, {} errors", usn.journals_deleted, usn.errors);

    eprintln!("\n[+] DESTROY ALL complete.");
}

#[cfg(target_os = "windows")]
fn current_unix_ts() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn run_forge_all(opts: &Opts) {
    let ts = if opts.ts_forge != 0 { opts.ts_forge } else { current_unix_ts() };
    eprintln!("[*] FORGE ALL — Windows (ts={})", ts);

    eprintln!("\n[*] == Forge UserAssist ==");
    let ua = forge_userassist::forge_userassist(ts, opts.verbose);
    eprintln!("[+] forge-ua: {} entries, {} errors", ua.entries_written, ua.errors);

    eprintln!("\n[*] == Forge EventLog ==");
    let ev = forge_event_log::forge_event_log(opts.verbose);
    eprintln!("[+] forge-evtlog: {} events, {} errors", ev.events_written, ev.errors);

    eprintln!("\n[*] == Forge Registry MRU ==");
    let rm = forge_registry_mru::forge_registry_mru(opts.verbose);
    eprintln!("[+] forge-reg-mru: {} entries, {} errors", rm.entries_written, rm.errors);

    eprintln!("\n[*] == Forge Browser (Windows) ==");
    let bw = forge_browser_win::forge_browser_win(&forge_browser_win::BrowserWinForgeOpts {
        n_entries: opts.n_forge.max(20),
        ts_start:  ts - 259_200,
        ts_end:    ts,
        verbose:   opts.verbose,
    });
    eprintln!("[+] forge-browser-win: chrome={}, firefox={}, dbs={}", bw.chrome_entries, bw.firefox_entries, bw.dbs_touched);

    eprintln!("\n[*] == Forge Prefetch ==");
    let pf = forge_prefetch::forge_prefetch(&forge_prefetch::PrefetchForgeOpts {
        n_files:  opts.n_forge.min(20).max(10),
        ts_base:  ts,
        verbose:  opts.verbose,
    });
    eprintln!("[+] forge-prefetch: {} files, {} errors", pf.files_written, pf.errors);

    eprintln!("\n[*] == Forge LNK ==");
    let lnk = forge_lnk::forge_lnk(&forge_lnk::LnkForgeOpts {
        n_files: opts.n_forge.min(20).max(10),
        ts_base: ts,
        verbose: opts.verbose,
    });
    eprintln!("[+] forge-lnk: {} files, {} errors", lnk.files_written, lnk.errors);

    eprintln!("\n[*] == Forge ShimCache ==");
    let sc = forge_shimcache::forge_shimcache(&forge_shimcache::ShimcacheForgeOpts {
        n_entries: opts.n_forge.max(20),
        ts_base:   ts,
        verbose:   opts.verbose,
    });
    eprintln!("[+] forge-shimcache: {} entries, {} errors", sc.entries_injected, sc.errors);

    eprintln!("\n[*] == Forge BAM ==");
    let bam = wipe_bam::forge_bam(ts - 7 * 86_400, ts, opts.n_forge.min(17), opts.verbose);
    eprintln!("[+] forge-bam: {} entries, {} errors", bam.entries_forged, bam.errors);

    eprintln!("\n[*] == Forge MUI Cache ==");
    let mc = wipe_muicache::forge_muicache(opts.n_forge.min(16), opts.verbose);
    eprintln!("[+] forge-muicache: {} values, {} errors", mc.values_forged, mc.errors);

    eprintln!("\n[+] FORGE ALL complete.");
}

#[cfg(target_os = "windows")]
fn run_cover_all(opts: &Opts) {
    eprintln!("[*] COVER ALL — Windows");

    match wmi::delete_shadows(opts.vss_volume.as_deref(), opts.vss_after, opts.verbose) {
        Ok(n)  => eprintln!("[+] VSS: {} shadow(s) deleted", n),
        Err(e) => eprintln!("[!] VSS: {}", e),
    }
    if opts.vss_decoy {
        let vol = opts.vss_volume.as_deref().unwrap_or("C:");
        match wmi::create_shadow(vol) {
            Ok(id) => eprintln!("[+] VSS: decoy shadow: {}", id),
            Err(e) => eprintln!("[!] VSS decoy: {}", e),
        }
    }

    event_log::clear_all_event_logs(opts.verbose);
    ps_history::wipe_ps_history(opts.verbose);
    lnk_jumplists::wipe_lnk_jumplists(opts.verbose);
    registry::clean_registry(opts.verbose);

    eprintln!("[+] COVER ALL complete.");
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn main() {
    let opts = parse();

    privilege::enable_backup_restore().unwrap_or_else(|e| {
        eprintln!("[!] Privilege: {} (continuing)", e);
    });

    match opts.mode {
        Mode::DestroyAll  => run_destroy_all(&opts),
        Mode::CoverAll    => run_cover_all(&opts),

        Mode::List => {
            match wmi::list_shadows(opts.verbose) {
                Ok(s) if s.is_empty() => println!("[*] No shadow copies."),
                Ok(s) => for sh in s { println!("  {} vol={} date={}", sh.id, sh.volume, sh.install_date); }
                Err(e) => eprintln!("[!] {}", e),
            }
        }

        Mode::Vss => {
            match wmi::delete_shadows(opts.vss_volume.as_deref(), opts.vss_after, opts.verbose) {
                Ok(n)  => eprintln!("[+] VSS: {} deleted", n),
                Err(e) => {
                    if !opts.no_fallback { let _ = vssadmin::delete_all(opts.vss_volume.as_deref()); }
                    else { eprintln!("[!] {}", e); }
                }
            }
            if opts.restore_points { let _ = restore::delete_all(opts.verbose); }
        }

        Mode::EventLog   => { event_log::clear_all_event_logs(opts.verbose); }
        Mode::Prefetch   => { prefetch::wipe_prefetch(opts.verbose); }
        Mode::Registry   => { registry::clean_registry(opts.verbose); }
        Mode::PsHistory  => { ps_history::wipe_ps_history(opts.verbose); }
        Mode::Lnk        => { lnk_jumplists::wipe_lnk_jumplists(opts.verbose); }
        Mode::RecycleBin => { recycle_bin::wipe_recycle_bin(opts.verbose); }
        Mode::Defender   => { defender::wipe_defender_artifacts(opts.verbose); }
        Mode::Thumbcache => { thumbcache::wipe_thumbcache(opts.verbose); }
        Mode::Srum       => { srum::wipe_srum(opts.verbose); }
        Mode::Etw        => { etw::wipe_etw(opts.verbose); }
        Mode::Hiberfil   => { hiberfil::wipe_hiberfil(opts.disable_pf, opts.verbose); }
        Mode::WinSearch  => { win_search::wipe_win_search(opts.verbose); }
        Mode::Browser    => { browser_history::wipe_browser_history(opts.verbose); }
        Mode::Schtasks   => { schtasks::wipe_scheduled_tasks(&[], true, opts.verbose); }
        Mode::Rdp        => { rdp::wipe_rdp_artifacts(opts.verbose); }
        Mode::Timeline   => { timeline::wipe_timeline(opts.disable_pf, opts.verbose); }
        Mode::Opsec      => { opsec_win::apply_opsec_win(opts.verbose); }
        Mode::OpsecRevert => { opsec_win::revert_opsec_win(opts.verbose); }
        Mode::Amcache    => { amcache::wipe_amcache(opts.verbose); }
        Mode::UserAssist => { userassist::wipe_userassist(opts.verbose); }

        // ── Forge ─────────────────────────────────────────────────────────────

        Mode::ForgeUserAssist => {
            let ts = if opts.ts_forge != 0 { opts.ts_forge } else { current_unix_ts() };
            let r = forge_userassist::forge_userassist(ts, opts.verbose);
            eprintln!("[+] forge-ua: {} entries, {} errors", r.entries_written, r.errors);
        }
        Mode::ForgeEventLog => {
            let r = forge_event_log::forge_event_log(opts.verbose);
            eprintln!("[+] forge-evtlog: {} events, {} errors", r.events_written, r.errors);
        }
        Mode::ForgeRegistryMru => {
            let r = forge_registry_mru::forge_registry_mru(opts.verbose);
            eprintln!("[+] forge-reg-mru: {} entries, {} errors", r.entries_written, r.errors);
        }
        Mode::ForgeBrowserWin => {
            let ts = if opts.ts_forge != 0 { opts.ts_forge } else { current_unix_ts() };
            let r = forge_browser_win::forge_browser_win(&forge_browser_win::BrowserWinForgeOpts {
                n_entries: opts.n_forge.max(20),
                ts_start:  ts - 259_200,
                ts_end:    ts,
                verbose:   opts.verbose,
            });
            eprintln!("[+] forge-browser-win: chrome={}, firefox={}, dbs={}, errors={}",
                r.chrome_entries, r.firefox_entries, r.dbs_touched, r.errors);
        }
        Mode::ForgePrefetch => {
            let ts = if opts.ts_forge != 0 { opts.ts_forge } else { current_unix_ts() };
            let r = forge_prefetch::forge_prefetch(&forge_prefetch::PrefetchForgeOpts {
                n_files: opts.n_forge.min(20).max(10),
                ts_base: ts,
                verbose: opts.verbose,
            });
            eprintln!("[+] forge-prefetch: {} files, {} errors", r.files_written, r.errors);
        }
        Mode::ForgeLnk => {
            let ts = if opts.ts_forge != 0 { opts.ts_forge } else { current_unix_ts() };
            let r = forge_lnk::forge_lnk(&forge_lnk::LnkForgeOpts {
                n_files: opts.n_forge.min(20).max(10),
                ts_base: ts,
                verbose: opts.verbose,
            });
            eprintln!("[+] forge-lnk: {} files, {} errors", r.files_written, r.errors);
        }
        Mode::ForgeShimcache => {
            let ts = if opts.ts_forge != 0 { opts.ts_forge } else { current_unix_ts() };
            let r = forge_shimcache::forge_shimcache(&forge_shimcache::ShimcacheForgeOpts {
                n_entries: opts.n_forge.max(20),
                ts_base:   ts,
                verbose:   opts.verbose,
            });
            eprintln!("[+] forge-shimcache: {} entries, {} errors", r.entries_injected, r.errors);
        }
        Mode::WipeBam => {
            let r = wipe_bam::wipe_bam(opts.verbose);
            eprintln!("[+] wipe-bam: {} keys deleted, {} errors", r.keys_deleted, r.errors);
        }
        Mode::ForgeBam => {
            let ts = if opts.ts_forge != 0 { opts.ts_forge } else { current_unix_ts() };
            let r = wipe_bam::forge_bam(ts - 7 * 86_400, ts, opts.n_forge.min(17), opts.verbose);
            eprintln!("[+] forge-bam: {} entries, {} errors", r.entries_forged, r.errors);
        }
        Mode::WipeBits => {
            let r = wipe_bits::wipe_bits(true, opts.verbose);
            eprintln!("[+] wipe-bits: {} files removed, service_stopped={}, {} errors",
                r.files_removed, r.service_stopped, r.errors);
        }
        Mode::WipeMuiCache => {
            let r = wipe_muicache::wipe_muicache(opts.verbose);
            eprintln!("[+] wipe-muicache: {} values deleted, {} errors", r.values_deleted, r.errors);
        }
        Mode::ForgeMuiCache => {
            let r = wipe_muicache::forge_muicache(opts.n_forge.min(16), opts.verbose);
            eprintln!("[+] forge-muicache: {} values written, {} errors", r.values_forged, r.errors);
        }
        Mode::WipeUsnJrnl => {
            let r = ntfs::wipe_usn_journal(opts.verbose);
            eprintln!("[+] wipe-usn: {} journal(s) deleted, {} errors", r.journals_deleted, r.errors);
        }
        Mode::ForgeAll => { run_forge_all(&opts); }

        // ── Crypto ────────────────────────────────────────────────────────────

        Mode::CreateContainer => {
            let out = opts.output.as_deref().unwrap_or_else(|| { eprintln!("[!] --output required"); process::exit(1); });
            let pass = win_passphrase(&opts.pass_env);
            let size = opts.size_mib * 1024 * 1024;
            eprintln!("[*] create-container: {} ({} MiB, {})", out, opts.size_mib, opts.algo_str);
            match create_container(out, size, win_algo(&opts.algo_str), &pass, opts.kdf_iters, opts.verbose) {
                Ok(())  => eprintln!("[+] create-container: done"),
                Err(e)  => eprintln!("[!] create-container: {}", e),
            }
        }

        Mode::EncryptFile => {
            let inp = opts.input.as_deref().unwrap_or_else(|| { eprintln!("[!] --input required"); process::exit(1); });
            let out = opts.output.as_deref().unwrap_or_else(|| { eprintln!("[!] --output required"); process::exit(1); });
            let pass = win_passphrase(&opts.pass_env);
            eprintln!("[*] encrypt-file: {} → {}", inp, out);
            match encrypt_file(inp, out, win_algo(&opts.algo_str), &pass, opts.kdf_iters) {
                Ok(b)  => eprintln!("[+] encrypt-file: {} bytes", b),
                Err(e) => eprintln!("[!] encrypt-file: {}", e),
            }
        }

        Mode::EncryptDir => {
            let inp = opts.input.as_deref().unwrap_or_else(|| { eprintln!("[!] --input required"); process::exit(1); });
            let out = opts.output.as_deref().unwrap_or_else(|| { eprintln!("[!] --output required"); process::exit(1); });
            let pass = win_passphrase(&opts.pass_env);
            eprintln!("[*] encrypt-dir: {} → {}", inp, out);
            match encrypt_dir(inp, out, win_algo(&opts.algo_str), &pass, opts.kdf_iters) {
                Ok(b)  => eprintln!("[+] encrypt-dir: {} bytes", b),
                Err(e) => eprintln!("[!] encrypt-dir: {}", e),
            }
        }

        Mode::Decrypt => {
            let inp = opts.input.as_deref().unwrap_or_else(|| { eprintln!("[!] --input required"); process::exit(1); });
            let out = opts.output.as_deref().unwrap_or_else(|| { eprintln!("[!] --output required"); process::exit(1); });
            let pass = win_passphrase(&opts.pass_env);
            eprintln!("[*] decrypt: {} → {}", inp, out);
            match decrypt_container(inp, out, &pass) {
                Ok(b)  => eprintln!("[+] decrypt: {} bytes", b),
                Err(e) => eprintln!("[!] decrypt: {}", e),
            }
        }

        Mode::Extract => {
            let inp = opts.input.as_deref().unwrap_or_else(|| { eprintln!("[!] --input required"); process::exit(1); });
            let out = opts.output.as_deref().unwrap_or_else(|| { eprintln!("[!] --output required"); process::exit(1); });
            let pass = win_passphrase(&opts.pass_env);
            eprintln!("[*] extract: {} → {}/", inp, out);
            match extract_dir(inp, out, &pass) {
                Ok(b)  => eprintln!("[+] extract: {} bytes", b),
                Err(e) => eprintln!("[!] extract: {}", e),
            }
        }

        Mode::DestroyAndEncrypt => {
            if opts.sources.is_empty() { eprintln!("[!] --source required"); process::exit(1); }
            let out = opts.output.as_deref().unwrap_or_else(|| { eprintln!("[!] --output required"); process::exit(1); });
            let pass = win_passphrase(&opts.pass_env);
            let srcs: Vec<&str> = opts.sources.iter().map(String::as_str).collect();
            eprintln!("[*] destroy-and-encrypt: {} source(s) → {}", srcs.len(), out);
            match destroy_and_encrypt(&srcs, out, win_algo(&opts.algo_str), &pass, opts.kdf_iters) {
                Ok(b)  => eprintln!("[+] destroy-and-encrypt: {} bytes, sources wiped", b),
                Err(e) => eprintln!("[!] destroy-and-encrypt: {}", e),
            }
        }

        Mode::Hash => {
            let path = opts.input.as_deref().unwrap_or_else(|| { eprintln!("[!] file path required after 'hash'"); process::exit(1); });
            let halgo = win_hash_algo(&opts.hash_algo);
            match hash_file(path, halgo) {
                Ok(digest) => println!("{}  {}", to_hex(&digest), path),
                Err(e)     => eprintln!("[!] hash: {}", e),
            }
        }
    }
}
