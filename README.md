<div id="top" align="center">

<img src="docs/github/graphical_resources/Logo-without_background-SATAN2_Cleaner.png" alt="SATAN2 logo" width="220">

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
   - [Deception Modules](#deception-modules)
4. [Planned Techniques](#planned-techniques)
5. [Build](#build)
6. [Testing & CI](#testing--ci)
7. [Usage](#usage)
   - [Linux CLI (`satan2`)](#linux-cli-satan2)
   - [Windows CLI (`satan2_win`)](#windows-cli-satan2_win)
8. [Threat Model & Detection Notes](#threat-model--detection-notes)
9. [License](#license)
10. [Contact](#contact)

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
- `satan2` → Linux (x86-64, ARM64)
- `satan2_win.exe` → Windows 10/11 x86-64

No Python, no shell scripts, no external runtime dependencies beyond OS-provided utilities (`vssadmin`, `wevtutil` on Windows).

---

## Implemented Features

### Destruction & Wiping

| Feature | Module | Notes |
|---------|--------|-------|
| **Multi-pass secure file deletion** | `secure_delete.rs` | 0xFF → 0x00 → random (cycled, min 3 passes) → truncate → unlink |
| **Multi-pass device wipe** | `wipe.rs` | Random / DoD 5220.22-M / Schneier / Gutmann; optional verify pass |
| **ATA Secure Erase** | `ata.rs` | SECURITY ERASE UNIT via SG_IO passthrough; detects frozen state (Word 128) |
| **NVMe secure erase** | `nvme.rs` | Sanitize (Crypto Erase / Block Erase / Overwrite) and Format NVM; TCG OPAL is detected but Revert/PSID is **not** implemented — falls back to Sanitize |
| **TRIM** | `trim.rs` | FITRIM ioctl issued on all mounted writable filesystems |
| **Filesystem implosion** | `fs_kill.rs` | Partition tables (GPT primary+backup, MBR) and filesystem superblocks (ext4 primary+backups, XFS AGs, Btrfs) |
| **Cluster tip & slack space wipe** | `slack.rs` | Per-file cluster-tip zeroing; free-space fill-and-delete to wipe unallocated blocks |
| **Swap wipe** | `swap.rs` | Zero-fill swap partitions and swap files; optional re-enable |
| **RAM wipe** | `memory_wipe.rs` | Anonymous `mmap` zero-fill of free RAM (2 GiB cap) + `drop_caches` |
| **tmpfs cleanup** | `tmpfs.rs` | Clear `/tmp`, `/dev/shm`, core dumps, crash dirs |
| **Volume Shadow Copy deletion** | `vssadmin.rs` (Win) | `vssadmin delete shadows`; volume filter, timestamp filter, decoy shadow, restore-point wipe |

---

### Encryption

| Feature | Detail |
|---------|--------|
| **Algorithms** | AES-256, Twofish-256, Camellia-256, Kuznyechik (GOST R 34.12-2015 — validated against the official test vectors of the standard), AES-256+Twofish-256 cascade |
| **Block mode** | XTS (IEEE 1619) — sector-aligned, tweakable encryption |
| **Key derivation** | PBKDF2-HMAC-SHA512 (SHA-2 family); configurable iterations (default 300,000) |
| **Hashing** | SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b-512 |
| **Multi-layer nested encryption** | `ops.rs` — `encrypt_layers`: containers-inside-containers; **one full `SATAN2CV` container per layer**, each with its own algorithm, salt, keys and passphrase |
| **Container format** | `SATAN2CV` — magic + 512-byte salt region + 4 KB encrypted header, sector-addressable data region |
| **Device encryption** | In-place block-device encryption (irreversible) |

---

### Linux — Forensic Artifact Cleanup & Forgery

#### Logs & Audit

| Feature | Module |
|---------|--------|
| Log sanitize / misdirect — cover (needle:replacement scrubbing) or destroy mode across auth.log, syslog, wtmp, bash history, systemd journal, arbitrary extra files | `log_poison.rs` |
| auditd disable + audit log overwrite (optional re-enable) | `auditd.rs` |
| Wipe & forge `wtmp` / `utmp` (binary `struct utmp` format — fake login sessions) | `forge_wtmp.rs` |
| Wipe & forge `/var/log/lastlog` (per-UID last-login timestamps) | `lastlog_forge.rs` |
| Inject fake entries into the systemd journal via `/run/systemd/journal/socket` | `forge_journal.rs` |
| Forge auth.log / syslog / bash_history (fake SSH sessions, sudo events, cron entries) | `log_forge.rs` |
| Package log cleanup (dpkg/apt/yum/dnf/pacman/zypper + pip/npm/gem caches) | `pkg_logs.rs` |
| Package log forging (synthetic install events) | `pkg_forge.rs` |

#### Timestamps & File Metadata

| Feature | Module |
|---------|--------|
| **MACE timestamp scrambling** — strategies: random-plausible, random-full, epoch, clone-from-reference | `meta.rs` |
| **Targeted timestomping** — set atime+mtime to an exact epoch or ISO-8601 timestamp | `meta.rs` |
| **File signature masking** — overwrite magic bytes to break carving | `meta.rs` |
| Extended attribute removal | `meta.rs` |

#### Browser, Shell & User Activity

| Feature | Module |
|---------|--------|
| Browser cleanup: Firefox, Chrome, Chromium, Brave, Edge, Opera | `browser_linux.rs` |
| Browser artifact forge — fake URLs into Firefox `places.sqlite` and Chromium History | `browser_forge.rs` |
| Process-trace cleanup: `recently-used.xbel`, thumbnails, session errors, shell history | `proc_clean.rs` |

#### Network, SSH & Infrastructure

| Feature | Module |
|---------|--------|
| SSH cleanup — selective `known_hosts` host removal or full `.ssh` destruction (keys, config) | `ssh_clean.rs` |
| SSH forge — inject fake host-key entries into `known_hosts` | `ssh_forge.rs` |
| Network artifact cleanup — ARP cache, conntrack table, DNS resolver cache | `net_clean.rs` |
| Docker trace cleanup — container logs, client credentials, build cache | `docker_cover.rs` |
| OPSEC hardening (nolog/stealth mode) + revert | `opsec_linux.rs` |

#### Audit & Verification

| Feature | Module |
|---------|--------|
| **Post-cleanup self-audit** — enumerate residual forensic artefacts (optional JSON findings) | `self_audit.rs` |

---

### Windows — Forensic Artifact Cleanup & Forgery

#### Execution Traces

| Feature | Module |
|---------|--------|
| Prefetch wipe (`C:\Windows\Prefetch\`) | `prefetch.rs` |
| **Fake Prefetch files** — Win10/11 v30 MAM format (XPRESS Huffman via `ntdll!RtlCompressBuffer`), correct Hsieh hash | `forge_prefetch.rs` |
| ShimCache / Amcache wipe (`AppCompatCache`, `Amcache.hve`) | `amcache.rs` |
| **Fake ShimCache entries** — Win10 1607+ binary layout, correct header signature, FILETIME, path | `forge_shimcache.rs` |
| BAM / DAM wipe (`bam\State\UserSettings\{SID}\`) | `wipe_bam.rs` |
| **Fake BAM entries** — plausible execution FILETIMEs for the current user SID | `wipe_bam.rs` |
| UserAssist wipe (ROT-13 encoded run-count records) | `userassist.rs` |
| **Fake UserAssist entries** | `forge_userassist.rs` |
| MUI Cache wipe + forge (executed-exe descriptions) | `wipe_muicache.rs` |

#### Event Logs

| Feature | Module |
|---------|--------|
| Event Log wipe — all channels via `wevtutil cl`, `ClearEventLogW` fallback | `event_log.rs` |
| **Fake Event Log entries** — synthetic MsiInstaller / Application Error / ESENT events in the Application log | `forge_event_log.rs` |

#### Registry & NTFS

| Feature | Module |
|---------|--------|
| Registry MRU cleanup — RunMRU, RecentDocs, TypedPaths, etc. | `registry.rs` |
| **Fake registry MRU** — RunMRU / TypedPaths / TypedURLs / RecentDocs | `forge_registry_mru.rs` |
| **$UsnJrnl wipe** — delete the USN journal on all accessible NTFS volumes | `ntfs.rs` |
| BITS queue cleanup — stop service, delete job database | `wipe_bits.rs` |
| Recycle Bin wipe | `recycle_bin.rs` |
| Thumbnail cache wipe | `thumbcache.rs` |
| Windows Timeline wipe (Activity History + Clipboard) | `timeline.rs` |
| Hibernation file wipe — disable hibernation, optional full pagefile disable | `hiberfil.rs` |

#### Search & Indexing

| Feature | Module |
|---------|--------|
| Windows Search index wipe (`Windows.edb`) | `win_search.rs` |
| SRUM database wipe (`SRUDB.dat`) | `srum.rs` |

#### Browser & User Activity

| Feature | Module |
|---------|--------|
| Browser history cleanup (Chrome / Edge / Firefox / …) | `browser_history.rs` |
| Fake browser history injection (SQLite) | `forge_browser_win.rs` |
| LNK / JumpList wipe (`Recent\`, `AutomaticDestinations\`) | `lnk_jumplists.rs` |
| **Fake LNK files** — Shell Link binary format | `forge_lnk.rs` |
| PowerShell history wipe | `ps_history.rs` |
| RDP artifact cleanup (MRU, bitmap cache, credentials) | `rdp.rs` |

#### System Infrastructure

| Feature | Module |
|---------|--------|
| Windows Defender history / quarantine cleanup | `defender.rs` |
| ETW trace + WER report cleanup | `etw.rs` |
| Scheduled task cleanup (non-Microsoft tasks) | `schtasks.rs` |
| WMI repository cleanup | `wmi.rs` |
| System Restore point deletion | `restore.rs` |
| OPSEC hardening (nolog/stealth mode) + revert | `opsec_win.rs` |

---

### Deception Modules

#### Embedded File Metadata Poisoning — `exif_forge.rs`

> Forensic tools extract metadata embedded *inside* files — independent of filesystem timestamps, MFT records, or registry state. A carved JPEG recovered from unallocated space still carries its EXIF data.

Pure-Rust implementation — no `exiftool` dependency. Format auto-detected from extension.

| File Type | Implemented |
|-----------|-------------|
| **JPEG** | Full TIFF-LE EXIF segment: IFD0 + ExifIFD + GPS IFD. Fields: Make, Model, Software, Artist, DateTime, DateTimeOriginal, ISO, FocalLength, PixelXDimension, PixelYDimension, GPSLatitude, GPSLongitude |
| **PDF** | `/Info` dictionary: Author, Creator, Producer, Title, CreationDate, ModDate |
| **MP4 / MOV** | `mvhd` creation/modification timestamps, `©too` encoder atom |

#### Compression Traps & Archive Bombs — `trap_archive.rs`

> Decoy archives designed to crash, hang, or exhaust forensic parsing tools.

| Trap Type | Mechanism | Effect |
|-----------|-----------|--------|
| **Nested ZIP bomb** | `--layers` × `--width` inner ZIPs, innermost = compressed zeros | Recursive extractors OOM |
| **Oversized ZIP** | CDR declares multi-GiB uncompressed sizes; actual data = a few bytes | Naive parsers allocate and OOM before reading content |
| **Bad CRC** | Valid structure, wrong CRC32 | Strict extractors reject; loose ones silently corrupt evidence |
| **Truncated data** | Local file data shorter than stated compressed size | Partial-read crash in streaming extractors |
| **Corrupt signature** | PK local header signature overwritten | Parser bails at first entry |
| **Infinite recurse** | EOCD CDR offset points to EOCD itself | Self-referential parse loop |

#### Steganography Honey Injection — `stego_honey.rs`

> Plant fake hidden messages inside media files. An analyst who finds steganographic content spends hours decoding content that carries no operational value.

| Carrier | Method | Fake payload |
|---------|--------|--------------|
| **JPEG** | Append after EOI (`FF D9`) with fake tool signature | PEM-header-framed base64 noise (credential-looking) |
| **PNG** | Inject `tEXt` / `zTXt` chunks | Base64-encoded noise |
| **WAV** | LSB of 16-bit PCM samples | Fake PEM block, seeded per file |
| **Any format** | Raw trailer append with caller-specified tool signature (`--tool-sig`) | Arbitrary payload |

Directories are processed recursively (depth ≤ 3); payload size and PRNG seed are configurable.

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

Everything goes through the `Makefile` (`make help` lists all targets).

### Prerequisites

```bash
# Rust stable
rustup update stable

# Cross-compile prerequisites (only needed for the matching targets)
rustup target add x86_64-pc-windows-gnu          # Windows
sudo apt install gcc-mingw-w64-x86-64            # Windows linker
sudo apt install gcc-aarch64-linux-gnu           # ARM64 linker
```

### Targets

| Target | Output |
|--------|--------|
| `make build` | Dev build (unoptimised, with symbols) |
| `make release` | Release — Linux x86-64 (glibc) → `target/release/satan2` |
| `make musl` | Static release — Linux x86-64 (musl, no libc dep) |
| `make arm64` | Release — Linux ARM64 (cross) |
| `make windows` | Release — Windows x86-64 (cross, MinGW) → `target/x86_64-pc-windows-gnu/release/satan2_win.exe` |
| `make all` | All of the above |
| `make stealth` | LTO + `panic=abort` + full strip (UPX if available) — minimal footprint |
| `make hardened` | RELRO + CFP + debuginfo strip |

### Polymorphic builds

```bash
make poly          # 3 variants
make poly-n N=10   # N variants
```

Each variant embeds a unique 64-bit build nonce (compiled in via `SATAN2_BUILD_NONCE`), so every binary has a distinct hash with identical behaviour — useful to prevent cross-correlation of operator copies by hash. Variants land in `dist/poly/` and the target prints how many unique hashes were produced.

### Quality, packaging, release

| Target | Action |
|--------|--------|
| `make check` / `make test` | `cargo check` / `cargo test --workspace` |
| `make fmt` / `make clippy` | `cargo fmt --all` / `cargo clippy --workspace --tests -- -D warnings` |
| `make audit` / `make fix` | `cargo audit` / `cargo fix` + fmt |
| `make strip` / `make dist` | Strip binaries / build versioned archives + `SHA256SUMS` in `dist/` |
| `make install` / `make uninstall` | Install / remove `/usr/local/bin/satan2` |
| `make tag V=1.2.0` | Create + push `v1.2.0` → triggers the release CI |
| `make clean` / `make distclean` | `cargo clean` / also remove `dist/` |

Cross targets are guarded: if `rustup` is available the target is installed automatically; without `rustup`, the Makefile checks for an already-installed target and fails with an actionable message instead of a raw `rustc` error.

---

## Testing & CI

- **106 tests** pass (`cargo test --workspace`): 43 in `satan2-core`, 63 in `satan2-crypto` — including the official GOST R 34.12-2015 test vectors for Kuznyechik.
- `cargo clippy --workspace --tests -- -D warnings` is clean and enforced.
- **`.github/workflows/ci.yml`** — `fmt --check` + clippy (`-D warnings`) + full test suite on every push and PR.
- **`.github/workflows/release.yml`** — on `v*` tags, a test+clippy gate must pass before a 4-platform matrix builds and publishes release artifacts: linux-x86_64, linux-x86_64-musl, linux-arm64, windows-x86_64.
- **`.github/workflows/static.yml`** — deploys `docs/website` to GitHub Pages.

---

## Usage

### Linux CLI (`satan2`)

47 subcommands (clap). Global flags, accepted by every subcommand:

```
--dry-run   Print what would be done without performing any action
--json      Emit a JSON report to stdout after execution
```

#### Orchestration

```
satan2 destroy-all [--device <DEV>] [--reenable-audit]
satan2 cover-all [--replace "needle:replacement"...] [--hosts <HOST>...]
```

`destroy-all` chains: disable audit → logs → meta → slack → net → swap → tmpfs → trim, then optionally nukes a block device (NVMe/ATA auto-detected). `cover-all` chains: log cover → ssh → net → disable audit.

#### OPSEC

```
satan2 opsec                 # apply hardening — run BEFORE activity
satan2 opsec-revert          # undo it
```

#### Destruction & storage

```
satan2 secure-delete <PATH>... [--passes N]        # default 7, min 3
satan2 wipe <DEVICE> [--algo random|dod|schneier|gutmann] [--verify]
satan2 ata-erase <DEVICE>
satan2 nvme-erase <DEVICE>
satan2 kill-pt <DEVICE>                            # GPT + MBR
satan2 kill-fs <DEVICE>                            # ext4 / XFS / Btrfs superblocks
satan2 swap [--reenable]
satan2 trim                                        # FITRIM on all mounted writable fs
satan2 memory-wipe                                 # mmap zero-fill + drop_caches
satan2 tmpfs
```

#### Filesystem metadata

```
satan2 meta <PATH> [--recursive] [--ts random-plausible|random-full|epoch|clone]
            [--ts-ref <REF>] [--sig-mask] [--xattrs]
satan2 timestomp <PATH> <TS>                       # epoch or YYYY-MM-DDTHH:MM:SS
satan2 slack [--dir <DIR> [--recursive]] [--free <MOUNTPOINT>]
```

#### Logs & audit

```
satan2 log-poison [--mode cover|destroy] [--replace "needle:replacement"...]
                  [--auth] [--syslog] [--wtmp] [--history] [--journal]
                  [--extra <FILE>...]
satan2 auditd [--reenable]
satan2 forge-log [--fake-ip IP] [--fake-user USER] [--n-sessions N]
                 [--ts-start TS] [--ts-end TS] [--fake-hostname NAME]
                 [--auth] [--syslog] [--bash]
satan2 forge-journal [--fake-ip IP] [--fake-user USER] [--n-entries N]
                     [--ts-start TS] [--ts-end TS]
satan2 forge-wtmp [--fake-ip IP] [--fake-user USER] [--n-sessions N]
                  [--ts-start TS] [--ts-end TS]
satan2 wipe-lastlog
satan2 forge-lastlog [--ts-start TS] [--ts-end TS]
```

#### Network & SSH

```
satan2 net-clean
satan2 ssh-clean [--hosts <HOST>...] [--destroy-all] [--wipe-keys] [--wipe-config]
satan2 forge-ssh [--hosts <HOST>...] [--n-random N] [--home <DIR>...]
```

#### Artifact cleanup

```
satan2 browser-linux       # Firefox, Chrome, Chromium, Brave, Edge, Opera
satan2 pkg-logs            # dpkg/apt/yum/dnf/pacman/zypper + pip/npm/gem caches
satan2 proc-clean          # recently-used.xbel, thumbnails, session errors
satan2 docker-cover        # container logs, client credentials, build cache
```

#### Forgery (plant plausible artifacts)

```
satan2 forge-pkg-logs [--n-packages N] [--ts-start TS] [--ts-end TS]
satan2 forge-browser [--n-urls N] [--ts-start TS] [--ts-end TS] [--profile <FILE>]
satan2 forge-all [--fake-ip IP] [--fake-user USER] [--n N] [--ts-start TS] [--ts-end TS]
```

`forge-all` runs every forge module in one shot: log + pkg + ssh + browser + wtmp + journal.

#### Deception

```
satan2 exif-forge <FILE.(jpg|pdf|mp4)> [--make ...] [--model ...] [--software ...]
                  [--artist ...] [--datetime "YYYY:MM:DD HH:MM:SS"]
                  [--gps-lat D] [--gps-lon D] [--no-gps] [--iso N]
                  [--focal-length N] [--pixel-x N] [--pixel-y N]
                  [--pdf-author ...] [--pdf-creator ...] [--pdf-producer ...]
                  [--pdf-title ...] [--pdf-created TS] [--pdf-modified TS]
                  [--mp4-encoder ...] [--mp4-ts-create N] [--mp4-ts-modify N]
satan2 trap-archive <OUTPUT> [--variant nested-bomb|oversized|malformed]
                    [--layers N] [--width N] [--leaf-size-mib N]
                    [--claimed-gb N] [--malform bad-crc|truncated-data|corrupt-signature|infinite-recurse]
satan2 stego-honey <PATH> [--seed N] [--payload-size N] [--tool-sig SIG]
```

#### Encryption (SATAN2CV)

```
satan2 create-container <OUTPUT> [--size-mib N] [--algo ALGO] [--kdf-iters N] [--pass-env VAR]
satan2 encrypt-file <IN> <OUT> [--algo ALGO] [--kdf-iters N] [--pass-env VAR]
satan2 encrypt-dir <IN> <OUT> [--algo ALGO] [--kdf-iters N] [--pass-env VAR]
satan2 decrypt <IN> <OUT> [--pass-env VAR]
satan2 extract <IN> <OUT_DIR> [--pass-env VAR]
satan2 encrypt-layers <IN> <OUT> --layer <ALGO> --layer <ALGO> [--layer <ALGO>]...
                      [--kdf-iters N] [--pass-env VAR]
satan2 encrypt-device <DEVICE> [--algo ALGO] [--kdf-iters N] [--pass-env VAR]
satan2 destroy-and-encrypt <PATH>... --output <OUT> [--algo ALGO] [--kdf-iters N] [--pass-env VAR]
```

Algorithms: `aes` (default), `twofish`, `camellia`, `cascade` (AES-256 + Twofish-256), `kuznyechik`. Passphrases come from `$SATAN2_PASS` (or `--pass-env VAR`); if unset, a no-echo terminal prompt is used. For `encrypt-layers`, layer *i* reads `<PASS_ENV>_<i>` (`SATAN2_PASS_1..N`; layer 1 falls back to `<PASS_ENV>`); layers are applied **innermost first** in flag order (minimum 2). Decryption peels the onion: N sequential `decrypt` runs, **outermost passphrase first**.

#### Audit & hashing

```
satan2 self-audit [--findings-json]
satan2 hash <PATH> [--algo sha256|sha512|blake2b|sha3-256|sha3-512]
```

**Examples:**

```bash
# Preview the full destruction chain without touching anything
satan2 destroy-all --dry-run

# Full wipe, then firmware-erase the system NVMe at the end
sudo satan2 destroy-all --device /dev/nvme0n1

# Cover your tracks: scrub your real IP from the logs, drop a host from known_hosts
sudo satan2 cover-all --replace "203.0.113.10:10.0.0.1" --hosts bastion.corp.internal

# DoD wipe with verification
sudo satan2 wipe /dev/sdb --algo dod --verify

# Scramble a directory tree: plausible timestamps, masked signatures, stripped xattrs
satan2 meta /opt/tools --recursive --ts random-plausible --sig-mask --xattrs

# Clone timestamps from an innocuous system file
satan2 meta ./report.pdf --ts clone --ts-ref /etc/hostname

# Targeted timestomp
satan2 timestomp ./payload 2023-11-07T09:42:18

# Plant 30 days of fake logins
sudo satan2 forge-wtmp --fake-user jdoe --n-sessions 8 --ts-start 1745107200 --ts-end 1748736000

# Plant a full fake activity trail in one shot
sudo satan2 forge-all --fake-ip 10.0.0.1 --fake-user jdoe --n 10

# Forge camera EXIF with GPS on a JPEG
satan2 exif-forge ./photo.jpg --make "Canon" --model "Canon EOS R5" \
  --gps-lat 51.5074 --gps-lon=-0.1278   # negative values need the = form

# Nested ZIP bomb: 4 layers × 10 archives, 10 MiB leaves
satan2 trap-archive ./decoy.zip --variant nested-bomb --layers 4 --width 10

# Honey-inject every JPEG/PNG/WAV under a directory
satan2 stego-honey ./media --payload-size 1024

# Two-layer nested encryption (innermost first: aes, then twofish)
SATAN2_PASS_1='inner-secret' SATAN2_PASS_2='outer-secret' \
  satan2 encrypt-layers ./plans.txt ./plans.s2cv --layer aes --layer twofish

# Peel it back: outermost passphrase first
SATAN2_PASS='outer-secret' satan2 decrypt ./plans.s2cv ./layer1.s2cv
SATAN2_PASS='inner-secret' satan2 decrypt ./layer1.s2cv ./plans.txt

# Encrypt sources, then 3-pass wipe the originals
SATAN2_PASS='s3cret' satan2 destroy-and-encrypt ./docs ./keys --output ./vault.s2cv

# Post-cleanup residual check, machine-readable
satan2 self-audit --findings-json
```

---

### Windows CLI (`satan2_win`)

46 modes, hand-rolled parser. Global flags (accepted before or after the mode):

```
--dry-run   Print what would execute and skip execution (exit 0).
            list-vss and hash are read-only and still execute.
--json      After execution, emit {"module":"<mode>","ok":<bool>,"errors":<n>} on stdout.
--verbose
```

Unknown arguments are rejected with a clear error and exit code 2 — nothing is executed. Failures exit non-zero.

#### Orchestration & OPSEC

```
satan2_win destroy-all       # all DESTROY modules
satan2_win cover-all         # all COVER modules
satan2_win opsec             # apply hardening (nolog/stealth)
satan2_win opsec-revert
```

#### Forensic artifact cleanup

```
satan2_win vss [--volume X:] [--after <unix_ts>] [--decoy] [--restore-pts] [--no-fallback]
satan2_win list-vss
satan2_win event-log         # all channels (wevtutil, ClearEventLog fallback)
satan2_win prefetch
satan2_win registry          # MRU keys
satan2_win ps-history
satan2_win lnk               # Recent + JumpLists
satan2_win recycle-bin
satan2_win defender
satan2_win thumbcache
satan2_win srum
satan2_win etw               # ETW traces + WER reports
satan2_win hiberfil [--disable-pf]
satan2_win win-search        # Windows.edb
satan2_win browser           # Chrome / Edge / Firefox / …
satan2_win schtasks          # non-Microsoft scheduled tasks
satan2_win rdp               # MRU, bitmap cache, credentials
satan2_win timeline          # Activity History + Clipboard
satan2_win amcache           # Amcache.hve + ShimCache
satan2_win user-assist
satan2_win wipe-bam          # BAM/DAM execution timestamps
satan2_win wipe-bits         # stop BITS, delete job database
satan2_win wipe-muicache
satan2_win wipe-usn          # $UsnJrnl on all accessible NTFS volumes
```

#### Forge (plant plausible artifacts)

```
satan2_win forge-userassist [--n-forge N] [--ts-forge <unix_ts>]
satan2_win forge-event-log
satan2_win forge-registry-mru [--n-forge N] [--ts-forge <unix_ts>]
satan2_win forge-browser-win [--n-forge N] [--ts-forge <unix_ts>]
satan2_win forge-prefetch [--n-forge N] [--ts-forge <unix_ts>]
satan2_win forge-lnk [--n-forge N] [--ts-forge <unix_ts>]
satan2_win forge-shimcache [--n-forge N] [--ts-forge <unix_ts>]
satan2_win forge-bam [--n-forge N] [--ts-forge <unix_ts>]
satan2_win forge-muicache [--n-forge N]
satan2_win forge-all [--n-forge N] [--ts-forge <unix_ts>]
```

`--n-forge` sets the entry/file count (default 20); `--ts-forge` sets the base timestamp (default: current time at dispatch).

#### Encryption (SATAN2CV)

```
satan2_win create-container --output <OUT> [--size-mib N] [--algo ALGO] [--kdf-iters N] [--pass-env VAR]
satan2_win encrypt-file --input <IN> --output <OUT> [--algo ALGO] [--kdf-iters N] [--pass-env VAR]
satan2_win encrypt-dir --input <IN> --output <OUT> [--algo ALGO] [--kdf-iters N] [--pass-env VAR]
satan2_win encrypt-layers --input <IN> --output <OUT> --layer <ALGO> --layer <ALGO> [--layer <ALGO>]...
                          [--kdf-iters N] [--pass-env VAR]
satan2_win decrypt --input <IN> --output <OUT> [--pass-env VAR]
satan2_win extract --input <IN> --output <DIR> [--pass-env VAR]
satan2_win destroy-and-encrypt --source <PATH>... --output <OUT> [--algo ALGO] [--kdf-iters N] [--pass-env VAR]
satan2_win hash <PATH> [--hash-algo sha256|sha512|blake2b|sha3-256|sha3-512]
```

Same container format and semantics as the Linux CLI: algorithms `aes` (default) / `twofish` / `camellia` / `cascade` / `kuznyechik`; passphrase from `SATAN2_PASS` (or `--pass-env`), layer *i* of `encrypt-layers` from `<PASS_ENV>_<i>`; decrypt with N sequential `decrypt` runs, outermost first.

**Examples:**

```powershell
# Dry-run the full destroy chain — prints, executes nothing
.\satan2_win.exe --dry-run destroy-all

# Full wipe with a machine-readable summary
.\satan2_win.exe destroy-all --verbose --json

# Delete shadow copies and restore points, plant a decoy shadow
.\satan2_win.exe vss --restore-pts --decoy

# Plant a full fake activity trail anchored at a base timestamp
.\satan2_win.exe forge-all --ts-forge 1748736000 --n-forge 15

# Fake execution trail: Prefetch (v30 MAM) + ShimCache + BAM
.\satan2_win.exe forge-prefetch --n-forge 15 --ts-forge 1748736000
.\satan2_win.exe forge-shimcache --n-forge 20 --ts-forge 1748736000
.\satan2_win.exe forge-bam --n-forge 10 --ts-forge 1748736000

# Two-layer nested encryption
$env:SATAN2_PASS_1='inner-secret'; $env:SATAN2_PASS_2='outer-secret'
.\satan2_win.exe encrypt-layers --input .\plans.txt --output .\plans.s2cv --layer aes --layer twofish

# Hash evidence before destruction
.\satan2_win.exe hash .\disk.img --hash-algo sha3-512
```

> **Privilege:** Most operations require `NT AUTHORITY\SYSTEM` or high-integrity Administrator.

---

## Threat Model & Detection Notes

| SATAN2 Action | Residual Trace | Defender Mitigation |
|---------------|----------------|---------------------|
| `wipe-usn` (Win) | USN journal deletion events, Sysmon EID 1 on journal tools | Alert on USN journal deletion |
| `event-log` (Win) | EID 1102 / 104 (Security / System log cleared) | Forward EID 1102 to SIEM before clearing |
| `vss` (Win) | VSS deletion events, Sysmon on `vssadmin.exe` | Alert on `vssadmin delete shadows` |
| `ata-erase` / `nvme-erase` (Linux) | None (hardware-level) | Pre-seizure disk imaging; SMART logs |
| `forge-journal` (Linux) | Injection via `/run/systemd/journal/socket` bypasses FSS architecturally | Enable FSS + baseline comparison |
| `forge-shimcache` (Win) | Modified `AppCompatCache` binary blob | AppCompatCacheParser baseline diff |
| `forge-prefetch` (Win) | Structurally valid v30 .pf; MFT `$STANDARD_INFORMATION` timestamps may differ from `$FILE_NAME` | `$SI.Created < $FN.Created` → timestomp detection |
| `stego-honey` (Linux) | Files flagged by stego detectors | StegDetect / zsteg output is intentionally noisy |
| `trap-archive` (Linux) | Carving tools may crash or hang | Timeout and OOM limits on forensic parsing pipelines |

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
