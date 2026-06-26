<div id="top" align="center">

[![Contributors][contributors-shield]](https://github.com/franckferman/SATAN2/graphs/contributors)
[![Forks][forks-shield]](https://github.com/franckferman/SATAN2/network/members)
[![Stargazers][stars-shield]](https://github.com/franckferman/SATAN2/stargazers)
[![Issues][issues-shield]](https://github.com/franckferman/SATAN2/issues)
[![License][license-shield]](https://github.com/franckferman/SATAN2/blob/stable/LICENSE)
[![Rust][rust-shield]](https://www.rust-lang.org/)

<br />

<h1 align="center">☢️ SATAN2</h1>
<h3 align="center"><em>Secure Anti-Forensics and Total Annihilation of iNformation</em></h3>

<p align="center">
  Advanced counter-forensics framework — multi-pass wiping, nested encryption,<br>
  filesystem implosion, forensic artifact forgery, embedded metadata poisoning,<br>
  and misdirection payloads designed to exhaust and mislead incident-response analysis.<br>
  <strong>Cross-platform. Modular. Uncompromising.</strong>
</p>

<br />

</div>

---

## Table of Contents

<details open>
<summary><strong>Expand / Collapse</strong></summary>

1. [Philosophy](#philosophy)
2. [Architecture](#architecture)
3. [Implemented Features](#implemented-features)
   - [Destruction & Wiping](#destruction--wiping)
   - [Encryption](#encryption)
   - [Linux — Forensic Artifact Cleanup & Forgery](#linux--forensic-artifact-cleanup--forgery)
   - [Windows — Forensic Artifact Cleanup & Forgery](#windows--forensic-artifact-cleanup--forgery)
4. [Planned Features](#planned-features)
   - [Embedded File Metadata Poisoning](#embedded-file-metadata-poisoning)
   - [Compression Traps & Archive Bombs](#compression-traps--archive-bombs)
   - [Steganography Honey Injection](#steganography-honey-injection)
   - [Other Planned Techniques](#other-planned-techniques)
5. [Build](#build)
6. [Usage](#usage)
   - [Linux CLI](#linux-cli-satan2_cli)
   - [Windows CLI](#windows-cli-satan2_win)
7. [Threat Model & Detection Notes](#threat-model--detection-notes)
8. [License](#license)
9. [Contact](#contact)

</details>

---

## Philosophy

> Pressing *Delete* leaves a body. SATAN2 buries it, burns the grave, poisons the soil, and plants false witnesses.

SATAN2 is a modular counter-forensics framework for security professionals, Red Teams, and privacy advocates operating under authorised engagements. It combines four independent pillars:

| Pillar | Goal |
|--------|------|
| **Destroy** | Eliminate data at the hardware, filesystem, and block level — past any recovery threshold |
| **Encrypt** | Wrap survivors in multi-layer nested encryption so remaining fragments yield nothing |
| **Erase** | Wipe OS-level forensic artefacts (logs, registry, journals, browser state, memory) |
| **Deceive** | Plant synthetic artefacts and misdirection payloads to exhaust and mislead analysts |

SATAN2 does not slow forensic analysts — it makes their findings false.

---

## Architecture

```
satan2/
├── crates/
│   ├── satan2-crypto/    # Encryption engine (AES/Twofish/Camellia/Kuznyechik XTS, nested containers)
│   ├── satan2-core/      # Linux counter-forensics (wiping, artifact cleanup, forgery, disk ops)
│   ├── satan2-win/       # Windows counter-forensics (registry, NTFS, event logs, Win artifacts)
│   └── satan2-cli/       # Linux CLI entry point (clap-based, wraps satan2-core + satan2-crypto)
├── docs/
│   └── website/          # GitHub Pages landing site
└── .github/
    └── workflows/        # CI/CD pipelines
```

**Platform targets:**
- `satan2-cli` → Linux (x86-64, ARM64)
- `satan2_win.exe` → Windows 10/11 x86-64

No Python, no shell scripts, no external runtime dependencies beyond OS-provided utilities (`fsutil`, `vssadmin`, `sc`, `schtasks` on Windows).

---

## Implemented Features

### Destruction & Wiping

| Feature | Module | Notes |
|---------|--------|-------|
| **Multi-pass shredding** | `secure_delete.rs` | 0xFF → 0x00 → random → truncate → unlink; DoD 5220.22-M / Gutmann / Schneier-compatible |
| **ATA Secure Erase** | `ata.rs` | SECURITY ERASE UNIT + Enhanced Secure Erase via HDPARM ioctls; detects frozen state |
| **NVMe Secure Erase** | `nvme.rs` | Format NVM command (NVMe 1.2+); Crypto Erase (SES=2) when supported |
| **TRIM / Discard** | `trim.rs` | BLKDISCARD ioctl for SSD free-space reclaim |
| **Filesystem implosion** | `fs_kill.rs` | GPT primary+backup headers & entry arrays; MBR (512 B); ext4 primary+backup superblocks (sparse groups 1, 3^n, 5^n, 7^n); XFS AG superblocks; Btrfs superblocks at 64 K / 64 M / 256 G / 1 P offsets |
| **Cluster tip & slack space wipe** | `slack.rs` | Per-file cluster-tip zeroing via truncate/fallocate; free-space fill-and-delete to wipe unallocated blocks |
| **Swap wipe** | `swap.rs` | Zero-fill active swap partitions and swap files via direct block I/O |
| **RAM / memory wipe** | `memory_wipe.rs` | mlock + overwrite of heap buffers; /proc/self/mem zeroing |
| **tmpfs cleanup** | `tmpfs.rs` | Wipe and unmount tmpfs mounts; RAM-backed temporary directories |
| **Volume Shadow Copy deletion** | `vssadmin.rs` (Win) | `vssadmin delete shadows /all /quiet`; removes all VSS snapshots |

---

### Encryption

| Feature | Detail |
|---------|--------|
| **Algorithms** | AES-256, Twofish-256, Camellia-256, Kuznyechik-256 (GOST R 34.12-2015) |
| **Block mode** | XTS (IEEE 1619) — sector-aligned disk encryption |
| **Key derivation** | PBKDF2-HMAC-SHA3-512; configurable iterations |
| **Hash** | SHA2-256/512, SHA3-256/512, Blake2b-512, HMAC variants |
| **Multi-layer nested encryption** | `container.rs` — triple-pass encrypt → overwrite → re-encrypt; independent key + algorithm per layer |
| **Container format** | `SATAN2CV` — 4 KB encrypted authenticated header, sector-addressable data region |

---

### Linux — Forensic Artifact Cleanup & Forgery

#### Authentication & Access Logs

| Feature | Module |
|---------|--------|
| Wipe `/var/log/auth.log`, `/var/log/secure`, `/var/log/audit/audit.log` | `proc_clean.rs` |
| Wipe `/var/log/syslog`, `/var/log/messages`, `/var/log/kern.log` | `proc_clean.rs` |
| Wipe & forge `wtmp` / `utmp` (fake login records — `last` shows clean history) | `forge_wtmp.rs` |
| Wipe & forge `/var/log/lastlog` (per-UID login timestamp, sparse binary format) | `lastlog_forge.rs` |
| Wipe `wtmpdb` (Debian 13+ SQLite replacement for wtmp) | `proc_clean.rs` |
| Wipe & inject entries into systemd journal via `/run/systemd/journal/socket` | `forge_journal.rs` |
| auditd log cleanup | `auditd.rs` |

#### System & Package Logs

| Feature | Module |
|---------|--------|
| Package log cleanup (dpkg, apt history, pacman) | `pkg_logs.rs` |
| Package log forging (synthetic install events) | `pkg_forge.rs` |
| Log file poisoning — inject synthetic noise entries to exhaust analyst time | `log_poison.rs` |
| Log file forging — replace entries with plausible synthetic history | `log_forge.rs` |
| NetworkManager connection profile cleanup (WiFi credentials + history) | `proc_clean.rs` |

#### Timestamps & File Metadata

| Feature | Module |
|---------|--------|
| **MACE timestamp scrambling** — `utimensat()` with strategies: random-plausible (2000–2024), random-full, epoch, clone-from-reference | `meta.rs` |
| **File signature masking** — overwrite magic bytes / file headers to break carving | `meta.rs` |
| Extended attribute removal (SELinux labels, POSIX capabilities, user metadata) | `meta.rs` |

#### Browser & User Activity

| Feature | Module |
|---------|--------|
| Browser cleanup: Chrome, Chromium, Brave, Firefox, Opera — History, Cookies, Cache, LevelDB, IndexedDB, Sync Data, Extension State, GCM Store, AutofillStrikeDatabase | `browser_linux.rs` |
| Browser artifact forge — synthetic history, fake site visits | `browser_forge.rs` |
| Shell history wipe (bash, zsh, fish, ksh) | `proc_clean.rs` |
| GNOME recent-files (`recently-used.xbel`) | `proc_clean.rs` |
| GNOME Tracker / Tracker3 / gvfs-metadata wipe | `proc_clean.rs` |
| GNOME keyring cleanup | `proc_clean.rs` |

#### Infrastructure & Persistence

| Feature | Module |
|---------|--------|
| SSH key cleanup + `known_hosts` wipe | `ssh_clean.rs` |
| SSH key & config forging (plausible fake key material) | `ssh_forge.rs` |
| Docker trace cleanup (build cache, container logs, image metadata) | `docker_cover.rs` |
| Network artifact cleanup (ARP cache, DNS cache, connection tables) | `net_clean.rs` |

#### Audit & Verification

| Feature | Module |
|---------|--------|
| **Post-cleanup self-audit** — enumerate residual forensic artefacts with severity scoring | `self_audit.rs` |

---

### Windows — Forensic Artifact Cleanup & Forgery

#### Execution Traces

| Feature | Module |
|---------|--------|
| Prefetch wipe (`C:\Windows\Prefetch\`) | `prefetch.rs` |
| **Fake Prefetch files** — v30 MAM format (XPRESS Huffman via `ntdll!RtlCompressBuffer`), correct Hsieh hash, plausible run counts; accepted natively by Win10/11 Sysmain | `forge_prefetch.rs` |
| ShimCache (AppCompatCache) wipe | `amcache.rs` |
| **Fake ShimCache entries** — binary blob injection with correct v10 header signature, FILETIME, path | `forge_shimcache.rs` |
| Amcache.hve wipe + transaction logs + RecentFileCache.bcf; disables Application Experience tasks | `amcache.rs` |
| PCA artifact cleanup (Win11 22H2+) — `PcaAppLaunchDic.txt`, `PcaGeneralDb*.txt` | `amcache.rs` |
| BAM / DAM wipe (`bam\State\UserSettings\{SID}\`) | `wipe_bam.rs` |
| **Fake BAM entries** — FILETIME + 8-byte padding per value, plausible exe paths | `wipe_bam.rs` |
| UserAssist wipe (ROT-13 encoded GUID subkeys, run counts, focus time) | `userassist.rs` |
| **Fake UserAssist entries** — ROT-13 encoded paths, plausible FILETIME + focus counts | `forge_userassist.rs` |
| MUI Cache wipe + forge (`FriendlyAppName` values per exe path) | `wipe_muicache.rs` |

#### Event Logs

| Feature | Module |
|---------|--------|
| Windows Event Log wipe — clears all channels via `EvtClearLog` | `event_log.rs` |
| **Fake Event Log entries** — synthetic EVTX records for Security, System, Application, PowerShell/Operational | `forge_event_log.rs` |

#### Registry & NTFS

| Feature | Module |
|---------|--------|
| Registry MRU cleanup — Run/RunMRU, RecentDocs, OpenSaveMRU, TypedPaths, Comdlg32 | `registry.rs` |
| **Fake registry MRU** — plausible typed paths, recent document names | `forge_registry_mru.rs` |
| **$UsnJrnl wipe** — `fsutil usn deletejournal /D /N` on all fixed volumes | `ntfs.rs` |
| BITS queue cleanup — stops service, removes `qmgr.db` / `qmgr0.dat` / `qmgr1.dat` | `wipe_bits.rs` |
| Recycle Bin wipe | `recycle_bin.rs` |
| Thumbnail cache wipe | `thumbcache.rs` |
| Windows Timeline wipe (`ActivitiesCache.db`) | `timeline.rs` |
| Hibernation file wipe — `powercfg /h off` + zero-fill | `hiberfil.rs` |

#### Search & Indexing

| Feature | Module |
|---------|--------|
| Windows Search wipe — stops WSearch, overwrites `Windows.edb` (Win10 ESE), `Windows-gather.db` / `Windows.db` + WAL/SHM (Win11 SQLite); clears GatherLogs + UWP SearchApp data | `win_search.rs` |

#### Browser & User Activity

| Feature | Module |
|---------|--------|
| Browser history cleanup (IE / Legacy Edge / Chrome / Firefox) | `browser_history.rs` |
| Fake browser history injection | `forge_browser_win.rs` |
| LNK / JumpList wipe (`Recent\`, `AutomaticDestinations\`, `CustomDestinations\`) | `lnk_jumplists.rs` |
| **Fake LNK files** — full Shell Link binary format, correct timestamps | `forge_lnk.rs` |
| PowerShell history wipe (`ConsoleHost_history.txt` for all users) | `ps_history.rs` |
| RDP artifact cleanup (MRU, bitmap cache, terminal server client keys) | `rdp.rs` |

#### System Infrastructure

| Feature | Module |
|---------|--------|
| SRUM database wipe — `SRUDB.dat` (network usage, app execution, energy) | `srum.rs` |
| Windows Defender log cleanup | `defender.rs` |
| ETW session cleanup | `etw.rs` |
| Scheduled tasks artifact cleanup | `schtasks.rs` |
| WMI repository cleanup | `wmi.rs` |
| System Restore point deletion | `restore.rs` |

---

## Implemented: Deception Modules

### Embedded File Metadata Poisoning — `exif_forge.rs`

> Forensic tools extract metadata embedded *inside* files — independent of filesystem timestamps, MFT records, or registry state. A carved JPEG recovered from unallocated space still carries its EXIF data.

Pure-Rust implementation — no `exiftool` dependency.

| File Type | Implemented |
|-----------|-------------|
| **JPEG** | Full TIFF-LE EXIF segment: IFD0 + ExifIFD + GPS IFD. Fields: Make, Model, Software, Artist, DateTime, DateTimeOriginal, ISO, ExposureTime, FNumber, FocalLength, PixelXDimension, PixelYDimension, GPSLatitude, GPSLongitude, GPSMapDatum |
| **PDF** | `/Info` dictionary injected before `%%EOF`: Author, Creator, Producer, CreationDate, ModDate |
| **MP4 / MOV** | `mvhd` creation/modification timestamps (v0 + v1), `©too` encoder atom via `udta` |

---

### Compression Traps & Archive Bombs — `trap_archive.rs`

> Decoy archives designed to crash, hang, or exhaust forensic parsing tools.

| Trap Type | Mechanism | Effect |
|-----------|-----------|--------|
| **Nested ZIP bomb** | N layers × W inner ZIPs, innermost = DEFLATE-compressed zeros; claims `W^N × leaf_size` bytes | `binwalk`, `autopsy` carvers OOM on extraction |
| **Oversized ZIP** | CDR declares multi-GB uncompressed sizes; actual data = a few bytes | Naive parsers allocate and OOM before reading content |
| **Bad CRC** | Valid structure, wrong CRC32 in CDR | Strict extractors reject; loose ones silently corrupt evidence |
| **Truncated data** | Local file data shorter than stated compressed size | Partial-read crash in streaming extractors |
| **Corrupt signature** | PK local header signature overwritten | Parser bails at first entry, may not scan CDR |
| **Infinite recurse** | EOCD CDR offset points to EOCD itself | Self-referential parse loop |

---

### Steganography Honey Injection — `stego_honey.rs`

> Plant fake hidden messages inside media files. An analyst who finds steganographic content spends hours decoding content that carries no operational value.

| Carrier | Method | Fake payload |
|---------|--------|--------------|
| **JPEG** | Append after EOI (`FF D9`) with fake `OUTGUESS13` magic header | Seeded fake PEM private key block |
| **PNG** | Inject `tEXt` chunk (keyword `steganography`) + `zTXt` chunk with fake zlib header | Base64-encoded noise |
| **WAV** | LSB of 16-bit PCM audio samples; encodes payload length + payload bits | Fake PEM block seeded per file |
| **Any format** | Raw trailer append with caller-specified tool signature | Arbitrary payload |

`generate_honey_payload(seed, size)` — generates PEM-header-framed base64 noise that looks like credential material to automated scanners.

`inject_directory_honey(dir, seed, size)` — traverse directory and inject into all JPEG/PNG/WAV files found.

---

## Planned Techniques

| Technique | Notes |
|-----------|-------|
| Partition scheme obfuscation | Ghost partitions, misleading GPT signatures |
| Misaligned sector wiping | Sub-512-byte granularity writes to evade hardware-level imagers |
| Volume Shadow Copy poisoning | Structurally valid but content-corrupted VSS snapshots |
| Unicode filename injection | RTLO characters, MAX_PATH bypass to crash forensic parsers |
| Cross-linked file fragments | Inode cross-links to prevent fragment reassembly during carving |
| Bad sector simulation | Mark LBA ranges as reallocated to block carving |
| Disk surface noise generation | PRNG fill of free blocks to defeat entropy-based carving |
| MSIX Virtual Registry Hive cleanup | `%LocalAppData%\Packages\*\SystemAppData\Helium\` |

---

## Build

### Prerequisites

```bash
# Rust 1.75+
rustup update stable

# Cross-compile target (Windows from Linux)
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64   # Debian/Ubuntu
```

### Compile

```bash
# Workspace check (fast, all platforms)
cargo check --workspace

# Linux binary
cargo build --release -p satan2-cli

# Windows binary (cross-compile from Linux)
cargo build --release -p satan2-win --target x86_64-pc-windows-gnu
```

---

## Usage

### Linux CLI (`satan2-cli`)

```
SATAN2 — Secure Anti-Forensics and Total Annihilation of iNformation

COMMANDS:
  Destruction:
    secure-delete <PATH>            Multi-pass wipe (0xFF → 0x00 → rand → unlink)
    ata-erase <DEV>                 ATA Secure Erase (requires unfrozen drive)
    nvme-erase <DEV>                NVMe Format NVM (Crypto Erase when available)
    fs-kill <DEV>                   Filesystem implosion (GPT/MBR + superblocks)
    wipe-slack <PATH>               Cluster tip + free-space wipe
    wipe-swap                       Zero-fill all active swap

  Encryption:
    encrypt <FILE>                  Encrypt into SATAN2CV container
    decrypt <FILE>                  Decrypt SATAN2CV container
    encrypt-layers <FILE>           Triple-layer nested encryption

  Timestamps & Metadata:
    timestomp <PATH> [--strategy random-plausible|random-full|epoch|clone --ref <REF>]
    mask-signature <FILE>           Overwrite file magic bytes
    strip-xattr <PATH>              Remove all extended attributes recursively

  Linux Forensics:
    wipe-logs                       Wipe auth.log, syslog, kern.log, audit.log
    wipe-wtmp                       Wipe /var/log/wtmp + utmp
    forge-wtmp --ts-start <TS> --ts-end <TS>
    wipe-lastlog                    Wipe /var/log/lastlog (all UIDs)
    forge-lastlog --ts-start <TS> --ts-end <TS>
    wipe-journal                    Vacuum systemd journal
    forge-journal --ts-start <TS> --ts-end <TS>
    wipe-browser                    Wipe Chrome/Chromium/Firefox/Brave/Opera
    wipe-shell-history              Wipe bash/zsh/fish history (all users)
    wipe-ssh                        Wipe SSH keys and known_hosts
    wipe-docker                     Wipe Docker build cache and logs
    wipe-pkglogs                    Wipe dpkg/apt/pacman logs
    poison-logs                     Inject noise entries into system logs
    forge-logs                      Replace entries with synthetic plausible history
    audit                           Post-cleanup residual artifact report

OPTIONS:
  --verbose, -v                     Verbose output
```

**Examples:**

```bash
# Secure-delete a file
satan2 secure-delete /home/user/evidence.zip -v

# Forge 30 days of fake login history
satan2 forge-wtmp --ts-start 1745107200 --ts-end 1748736000

# Timestomp all files in a directory to plausible 2020–2023 range
satan2 timestomp /opt/tools --strategy random-plausible

# Full sequence
satan2 wipe-logs && satan2 wipe-journal && satan2 wipe-browser \
  && satan2 wipe-wtmp && satan2 wipe-shell-history && satan2 audit
```

---

### Windows CLI (`satan2_win.exe`)

```
SATAN2 Windows — counter-forensics toolkit

COMMANDS:
  Destruction:
    wipe-vss                        Delete all Volume Shadow Copy snapshots
    wipe-usn [--vol C:]             Wipe $UsnJrnl (default: all fixed volumes)
    wipe-bits                       Remove BITS job database
    wipe-hiberfile                  Disable hibernation + wipe hiberfil.sys

  Event Logs:
    wipe-evtlog                     Clear all Event Log channels
    forge-evtlog --ts-start <TS> --ts-end <TS>

  Execution Artifacts:
    wipe-prefetch                   Delete all .pf files
    forge-prefetch --n <N> --ts-base <TS>   [v30 MAM, correct Hsieh hash]
    wipe-shimcache                  Delete AppCompatCache value
    forge-shimcache --n <N> --ts-base <TS>
    wipe-amcache                    Delete Amcache.hve + PCA artifacts
    wipe-bam / forge-bam --n <N> --ts-start <TS> --ts-end <TS>
    wipe-userassist / forge-userassist --n <N> --ts-base <TS>
    wipe-muicache / forge-muicache --n <N>

  Registry:
    wipe-registry                   Clean MRU keys
    forge-registry --n <N> --ts-base <TS>

  Browser & User:
    wipe-browser                    Wipe IE/Edge/Chrome/Firefox history
    forge-browser --n <N> --ts-base <TS>
    wipe-lnk                        Wipe Recent + JumpLists
    forge-lnk --n <N> --ts-base <TS>
    wipe-ps-history                 PowerShell history (all users)
    wipe-rdp                        RDP MRU + bitmap cache
    wipe-timeline / wipe-thumbcache

  System:
    wipe-search                     Windows Search index (ESE + SQLite)
    wipe-srum                       SRUM database
    wipe-defender / wipe-wmi / wipe-schtasks

  One-shot:
    destroy-all                     Run all wipe operations
    forge-all --ts-start <TS> --ts-end <TS>   Plant full fake activity trail

OPTIONS:
  --verbose, -v
```

**Examples:**

```powershell
# Full wipe
.\satan2_win.exe destroy-all --verbose

# Plant fake activity trail for 30 days before 2025-06-01
.\satan2_win.exe forge-all --ts-start 1745107200 --ts-end 1748736000

# Fake forensic trail: Prefetch + ShimCache + BAM
.\satan2_win.exe forge-prefetch --n 15 --ts-base 1748736000
.\satan2_win.exe forge-shimcache --n 20 --ts-base 1748736000
.\satan2_win.exe forge-bam --n 10 --ts-start 1745107200 --ts-end 1748736000
```

> **Privilege:** Most operations require `NT AUTHORITY\SYSTEM` or high-integrity Administrator.

---

## Threat Model & Detection Notes

| SATAN2 Action | Residual Trace | Defender Mitigation |
|---------------|----------------|---------------------|
| `wipe-usn` | EventID 3079 (NTFS driver), Sysmon EID 1 on `fsutil.exe` | Alert on `fsutil usn deletejournal` |
| `wipe-evtlog` | EID 1102 / 104 (Security / System log cleared) | Forward EID 1102 to SIEM before clearing |
| `wipe-vss` | EID 524, Sysmon on `vssadmin.exe` | Alert on `vssadmin delete shadows` |
| `ata-erase` / `nvme-erase` | None (hardware-level) | Pre-seizure disk imaging; SMART logs |
| `forge-journal` | Injection via socket bypasses FSS architecturally | Enable FSS + baseline comparison |
| `forge-shimcache` | Modified `AppCompatCache` binary blob | AppCompatCacheParser baseline diff |
| `forge-prefetch` (v30 MAM) | Structurally valid .pf; MFT `$STANDARD_INFORMATION` timestamps may differ from `$FILE_NAME` | `$SI.Created < $FN.Created` → timestomp detection |
| Steganography honey injection | Files flagged by stego detectors | StegDetect / zsteg output is intentionally noisy |
| Compression trap archives | Carving tools may crash or hang | Timeout and OOM limits on forensic parsing pipelines |

---

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

> Intended for authorised security testing, Red Team engagements, and privacy research. Usage against systems or data you do not own or have explicit written authorisation to test is illegal and outside the scope of this project.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

<p align="right">(<a href="#top">Back to top</a>)</p>

---

[contributors-shield]: https://img.shields.io/github/contributors/franckferman/SATAN2.svg?style=for-the-badge
[forks-shield]: https://img.shields.io/github/forks/franckferman/SATAN2.svg?style=for-the-badge
[stars-shield]: https://img.shields.io/github/stars/franckferman/SATAN2.svg?style=for-the-badge
[issues-shield]: https://img.shields.io/github/issues/franckferman/SATAN2.svg?style=for-the-badge
[license-shield]: https://img.shields.io/github/license/franckferman/SATAN2.svg?style=for-the-badge
[rust-shield]: https://img.shields.io/badge/Rust-1.75+-ce422b?style=for-the-badge&logo=rust&logoColor=white
[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=white
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=0077B5
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=1DA1F2
