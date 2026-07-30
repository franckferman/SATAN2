# SATAN2 — Competitive Comparison

> **Scope:** anti-forensics / log-cleaning tools available as of 2026.
> Tools compared: **covermyass** (sundowndev, Go), **hidemylogs** (franckferman, Rust),
> **raider** (ADBeveridge, C+GTK4).
> *LastLog-Audit (franckferman, Python) is a read-only DFIR auditor — not a cleaner.*

Legend: ✅ implemented · ❌ absent · ⚠️ partial · — N/A

---

## 1 — Architecture

| | SATAN2 | covermyass | hidemylogs | raider |
|---|:---:|:---:|:---:|:---:|
| Language | Rust | Go | Rust | C |
| Memory safety | ✅ | ✅ | ✅ | ❌ |
| Static binary (musl) | ✅ | ✅ | ✅ | ❌ (Flatpak) |
| Headless / scriptable | ✅ | ✅ | ✅ | ❌ GUI only |
| Linux | ✅ | ✅ | ✅ | ✅ |
| Windows | ✅ | ❌ | ❌ | ❌ |
| ARM64 support | ✅ | ⚠️ | ✅ | ❌ |
| Polymorphic builds (defeat hash AV) | ✅ | ❌ | ✅ | ❌ |
| Multi-arch release CI | ✅ | ✅ | ✅ | ✅ |

---

## 2 — Linux Log Coverage

| | SATAN2 | covermyass | hidemylogs | raider |
|---|:---:|:---:|:---:|:---:|
| auth.log / secure | ✅ | ✅ | ❌ | ❌ |
| wtmp (binary) — truncate | ✅ | ✅ | ✅ | ❌ |
| wtmp — **selective record wipe** (by IP/user/time) | ✅ | ❌ | ✅ | ❌ |
| btmp + rotations | ✅ | ✅ | ✅ | ❌ |
| lastlog — truncate | ✅ | ✅ | ✅ | ❌ |
| lastlog — **per-UID zero/forge** | ✅ | ❌ | ✅ | ❌ |
| faillog | ✅ | ✅ | ❌ | ❌ |
| kern.log | ✅ | ❌ | ❌ | ❌ |
| daemon.log + rotations | ✅ | ✅ | ❌ | ❌ |
| dmesg / dmesg.old | ✅ | ✅ | ❌ | ❌ |
| syslog / messages | ✅ | ✅ | ❌ | ❌ |
| systemd journal (persistent) | ✅ (forge+detect) | ❌ | ❌ | ❌ |
| auditd log / rules | ✅ | ❌ | ❌ | ❌ |
| Package manager logs (dpkg/apt/pacman) | ✅ | ❌ | ❌ | ❌ |
| Web server logs — Apache2 / httpd / Nginx | ✅ | ✅ | ❌ | ❌ |
| FTP logs (xferlog / vsftpd / pureftp) | ✅ | ✅ | ❌ | ❌ |
| MySQL / MariaDB logs | ✅ | ✅ | ❌ | ❌ |
| Mail logs (Debian/RHEL/Plesk) | ✅ | ⚠️ | ❌ | ❌ |
| wtmpdb SQLite (Debian 13+) | ✅ | ❌ | ❌ | ❌ |
| **Log rotation glob** (.1, .2.gz, …) | ✅ | ❌ | ❌ | ❌ |

---

## 3 — Per-User Desktop Artifacts

| | SATAN2 | covermyass | hidemylogs | raider |
|---|:---:|:---:|:---:|:---:|
| bash / zsh / fish history | ✅ | ✅ (bash) | ❌ | ❌ |
| Python / Node.js REPL history | ✅ | ✅ (node) | ❌ | ❌ |
| Vim / Neovim / less history | ✅ | ❌ | ❌ | ❌ |
| GNOME recently-used.xbel | ✅ | ❌ | ❌ | ❌ |
| GNOME Tracker search index | ✅ | ❌ | ❌ | ❌ |
| GNOME gvfs-metadata | ✅ | ❌ | ❌ | ❌ |
| Thumbnail caches | ✅ | ❌ | ❌ | ❌ |
| Browser history (Firefox / Chromium) | ✅ | ❌ | ❌ | ❌ |
| pip / npm cache + logs | ✅ | ❌ | ❌ | ❌ |
| dconf database (GNOME activity) | ✅ | ❌ | ❌ | ❌ |
| GTK bookmarks | ✅ | ❌ | ❌ | ❌ |
| NetworkManager profiles (WiFi creds) | ⚠️ ² | ❌ | ❌ | ❌ |
| X11 / ICE lock files in /tmp | ✅ | ❌ | ❌ | ❌ |
| /dev/shm cleanup | ✅ | ❌ | ❌ | ❌ |
| SSH known_hosts + key audit | ✅ | ❌ | ❌ | ❌ |
| Docker client credentials | ✅ | ❌ | ❌ | ❌ |

² NetworkManager profiles are flagged by the self-audit module but not wiped.

---

## 4 — Active Forgery / Counter-Forensics Deception

*Inject plausible fake entries to achieve deniability — absent from all competitors.*

| | SATAN2 | covermyass | hidemylogs | raider |
|---|:---:|:---:|:---:|:---:|
| Forge wtmp (fake USER+DEAD sessions) | ✅ | ❌ | ❌ | ❌ |
| Forge lastlog per-UID (ts + tty + host) | ✅ | ❌ | ✅ | ❌ |
| Forge auth.log (SSH sessions + PAM + sudo) | ✅ | ❌ | ❌ | ❌ |
| Forge syslog (service events, cron, kernel) | ✅ | ❌ | ❌ | ❌ |
| Forge bash history (plausible admin commands) | ✅ | ❌ | ❌ | ❌ |
| Forge systemd journal (via journald socket) | ✅ | ❌ | ❌ | ❌ |
| Forge SSH known_hosts | ✅ | ❌ | ❌ | ❌ |
| Forge package history (dpkg / pacman logs) | ✅ | ❌ | ❌ | ❌ |
| Forge browser history | ✅ | ❌ | ❌ | ❌ |

---

## 5 — Windows Forensics Coverage

*Unique to SATAN2 — no competitor touches Windows.*

| | SATAN2 | covermyass | hidemylogs | raider |
|---|:---:|:---:|:---:|:---:|
| Prefetch forge (v23 + v30 MAM/XPRESS-Huffman) | ✅ | ❌ | ❌ | ❌ |
| LNK (.lnk) forge | ✅ | ❌ | ❌ | ❌ |
| Shimcache forge | ✅ | ❌ | ❌ | ❌ |
| Event Log wipe + forge | ✅ | ❌ | ❌ | ❌ |
| Registry MRU forge | ✅ | ❌ | ❌ | ❌ |
| UserAssist forge (GUI execution evidence) | ✅ | ❌ | ❌ | ❌ |
| AmCache wipe | ✅ | ❌ | ❌ | ❌ |
| Windows Search index wipe | ✅ | ❌ | ❌ | ❌ |
| BAM / DAM wipe (Background Activity Monitor) | ✅ | ❌ | ❌ | ❌ |
| BITS wipe (transfer artifacts) | ✅ | ❌ | ❌ | ❌ |
| MUI cache wipe | ✅ | ❌ | ❌ | ❌ |
| NTFS artifact manipulation | ✅ | ❌ | ❌ | ❌ |
| VSS shadow copy removal | ✅ | ❌ | ❌ | ❌ |
| RDP history cleanup | ✅ | ❌ | ❌ | ❌ |
| Windows Timeline wipe | ✅ | ❌ | ❌ | ❌ |
| Thumbcache wipe | ✅ | ❌ | ❌ | ❌ |
| SRUM wipe (CPU/network usage history) | ✅ | ❌ | ❌ | ❌ |
| Recycle Bin cleanup | ✅ | ❌ | ❌ | ❌ |
| Scheduled tasks cleanup | ✅ | ❌ | ❌ | ❌ |
| WMI forensic artifacts | ✅ | ❌ | ❌ | ❌ |
| Hibernate file wipe | ✅ | ❌ | ❌ | ❌ |
| PowerShell history | ✅ | ❌ | ❌ | ❌ |
| ETW session manipulation | ✅ | ❌ | ❌ | ❌ |
| Windows Defender history + quarantine wipe | ✅ | ❌ | ❌ | ❌ |

---

## 6 — Storage / Disk-Level Wiping

| | SATAN2 | covermyass | hidemylogs | raider |
|---|:---:|:---:|:---:|:---:|
| Single random pass (NIST 800-88) | ✅ | ❌ | ❌ | ❌ |
| DoD 5220.22-M (3-pass) | ✅ | ❌ | ❌ | ❌ |
| Schneier 7-pass | ✅ | ❌ | ❌ | ❌ |
| Gutmann 35-pass | ✅ | ❌ | ❌ | ❌ |
| O_DIRECT (bypass page cache) | ✅ | ❌ | ❌ | ❌ |
| fsync per pass | ✅ | ❌ | ❌ | ❌ (!) |
| Post-wipe verify pass | ✅ | ❌ | ❌ | ❌ |
| NVMe Sanitize / Format NVM | ✅ ¹ | ❌ | ❌ | ❌ |
| ATA Secure Erase | ✅ | ❌ | ❌ | ❌ |
| SSD TRIM-based wipe | ✅ | ❌ | ❌ | ❌ |
| RAM purge (mmap fill + drop_caches) | ✅ | ❌ | ❌ | ❌ |
| Swap wipe | ✅ | ❌ | ❌ | ❌ |
| Volatile area wipe (/tmp, /dev/shm, coredumps) | ✅ | ❌ | ❌ | ❌ |

¹ TCG OPAL is detected but Revert/PSID is **not** implemented — SATAN2 falls back to
NVMe Sanitize (crypto / block / overwrite erase) or Format NVM with secure-erase.

---

## 7 — Prevention Mode (proactive, before evidence is created)

*Unique to SATAN2.*

| | SATAN2 | covermyass | hidemylogs | raider |
|---|:---:|:---:|:---:|:---:|
| journald → volatile (RAM-only, lost on reboot) | ✅ | ❌ | ❌ | ❌ |
| HISTSIZE=0 / HISTFILE=/dev/null system-wide | ✅ | ❌ | ❌ | ❌ |
| auditd disabled at runtime + boot | ✅ | ❌ | ❌ | ❌ |
| sysctl: restrict dmesg, null core pattern | ✅ | ❌ | ❌ | ❌ |
| Core dumps disabled (PAM + systemd) | ✅ | ❌ | ❌ | ❌ |
| rsyslog rules — drop all before writing | ✅ | ❌ | ❌ | ❌ |
| SSH LogLevel QUIET | ✅ | ❌ | ❌ | ❌ |
| Cron-based hourly cleanup | ✅ | ❌ | ❌ | ❌ |

---

## 8 — OPSEC / Build Hardening

| | SATAN2 | covermyass | hidemylogs | raider |
|---|:---:|:---:|:---:|:---:|
| Timestamp scrambling on cleaned files (utimensat) | ✅ | ❌ | ❌ | ❌ |
| **Timestamp preservation** (restore atime/mtime after truncate — defeats FIM) | ✅ | ❌ | ✅ | ❌ |
| Extended attribute (xattr) removal | ✅ | ❌ | ❌ | ❌ |
| File signature masking (magic byte patch) | ✅ | ❌ | ❌ | ❌ |
| Polymorphic builds (random nonce → unique SHA256) | ✅ | ❌ | ✅ | ❌ |
| LTO + panic=abort + full strip (stealth mode) | ✅ | — | ✅ | ❌ |
| Docker forensic artifact coverage | ✅ | ❌ | ❌ | ❌ |
| Workspace test suite | ✅ 106 tests ³ | — | — | — |
| Official GOST vectors (Kuznyechik, GOST R 34.12-2015) | ✅ | — | — | — |

³ competitor test coverage not assessed.

---

## 9 — Self-Audit / Post-Op Assessment

*Unique to SATAN2.*

| | SATAN2 | covermyass | hidemylogs | raider |
|---|:---:|:---:|:---:|:---:|
| Residual artifact enumeration | ✅ | ❌ | ❌ | ❌ |
| Severity scoring (LOW / MED / HIGH) | ✅ | ❌ | ❌ | ❌ |
| Auth log / wtmp / btmp / faillog check | ✅ | ❌ | ❌ | ❌ |
| Web / FTP / DB log check | ✅ | ❌ | ❌ | ❌ |
| Browser history check | ✅ | ❌ | ❌ | ❌ |
| SSH key / known_hosts check | ✅ | ❌ | ❌ | ❌ |
| GNOME Tracker / gvfs check | ✅ | ❌ | ❌ | ❌ |
| NetworkManager profile check | ✅ | ❌ | ❌ | ❌ |
| Swap activity detection | ✅ | ❌ | ❌ | ❌ |
| Suspicious process detection | ✅ | ❌ | ❌ | ❌ |
| Cron / persistence check | ✅ | ❌ | ❌ | ❌ |
| Package manager log check | ✅ | ❌ | ❌ | ❌ |

---

## Summary

| Dimension | SATAN2 | covermyass | hidemylogs | raider |
|---|:---:|:---:|:---:|:---:|
| **Linux log cleanup** | ✅ full | ✅ basic | ⚠️ wtmp/lastlog only | ❌ |
| **Log rotation coverage** | ✅ glob | ❌ | ❌ | ❌ |
| **Per-user desktop artifacts** | ✅ 16 targets ² | ❌ | ❌ | ❌ |
| **Active forgery / deception** | ✅ 9 vectors | ❌ | ⚠️ lastlog only | ❌ |
| **Windows forensics** | ✅ 25 modules | ❌ | ❌ | ❌ |
| **Storage / disk wipe** | ✅ DoD/Gutmann/NVMe | ❌ | ❌ | ⚠️ no fsync |
| **Prevention mode** | ✅ 8 controls | ❌ | ❌ | ❌ |
| **OPSEC build hardening** | ✅ | ❌ | ⚠️ partial | ❌ |
| **Self-audit module** | ✅ | ❌ | ❌ | ❌ |

SATAN2 is the only tool in this space that covers all nine dimensions simultaneously.
covermyass covers basic Linux log cleanup. hidemylogs excels at precise binary-format
manipulation of wtmp/lastlog. raider is a generic GUI file shredder with no forensic
awareness. None of the three operates on Windows, forges realistic decoy evidence,
or includes a self-assessment module.
