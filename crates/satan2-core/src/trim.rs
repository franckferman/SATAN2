/*
 * trim.rs — FITRIM ioctl: discard free blocks on mounted filesystems
 *
 * On SSDs, deleted file data remains in NAND cells until the firmware
 * erases those cells (either proactively or on reuse). FITRIM tells the
 * filesystem to enumerate all free (unallocated) blocks and issue a
 * TRIM/DISCARD command to the device, allowing the firmware to erase them.
 *
 * This is complementary to software wiping: wipe.rs covers allocated
 * blocks by overwriting them; trim.rs covers the unallocated pool.
 *
 * Requires: root + filesystem mounted with discard support
 *           (or at least the driver accepting FITRIM even without mount-time discard)
 *
 * ioctl: FITRIM = _IOWR('X', 121, struct fstrim_range) = 0xC018_5879
 * Applied to: an open file descriptor on the mount point directory.
 */

use std::fs;
use std::io::BufRead;
use std::os::unix::io::AsRawFd;

use crate::Result;

const FITRIM: libc::c_ulong = 0xC018_5879;

// Must match kernel struct fstrim_range
#[repr(C)]
struct FstrimRange {
    start:  u64, // byte offset to start trimming
    len:    u64, // number of bytes to trim (u64::MAX = whole device)
    minlen: u64, // minimum extent size to discard (0 = any size)
}

// Filesystems that support FITRIM
static TRIMMABLE_FS: &[&str] = &[
    "ext4", "xfs", "btrfs", "f2fs", "exfat", "vfat", "ntfs",
];

fn is_trimmable(fstype: &str) -> bool {
    TRIMMABLE_FS.contains(&fstype)
}

// ── Parse /proc/mounts ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct MountEntry {
    pub device:     String,
    pub mountpoint: String,
    pub fstype:     String,
}

pub fn list_mounts() -> Result<Vec<MountEntry>> {
    let f = std::fs::File::open("/proc/mounts").map_err(|e| e.to_string())?;
    let mut entries = Vec::new();

    for line in std::io::BufReader::new(f).lines() {
        let line = line.map_err(|e| e.to_string())?;
        let mut parts = line.split_whitespace();
        let device     = parts.next().unwrap_or("").to_string();
        let mountpoint = parts.next().unwrap_or("").to_string();
        let fstype     = parts.next().unwrap_or("").to_string();

        // Skip pseudo-filesystems
        if device.starts_with("none") || device == "tmpfs" || device == "proc"
            || device == "sysfs" || device == "devtmpfs" || device == "cgroup"
            || device == "cgroup2" || device == "pstore" || device == "bpf"
            || device == "securityfs" || mountpoint == "/dev"
        {
            continue;
        }

        if !mountpoint.is_empty() && !fstype.is_empty() {
            entries.push(MountEntry { device, mountpoint, fstype });
        }
    }
    Ok(entries)
}

// ── FITRIM ────────────────────────────────────────────────────────────────────

pub fn fitrim_mountpoint(mountpoint: &str) -> Result<u64> {
    let dir = fs::File::open(mountpoint)
        .map_err(|e| format!("open {}: {}", mountpoint, e))?;

    let mut range = FstrimRange {
        start:  0,
        len:    u64::MAX,
        minlen: 0,
    };

    let r = unsafe {
        libc::ioctl(dir.as_raw_fd(), FITRIM, &mut range as *mut FstrimRange)
    };

    if r < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(format!("FITRIM on {}: errno={}", mountpoint, errno));
    }

    // range.len is updated by kernel to bytes actually discarded
    Ok(range.len)
}

// ── Public API ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct TrimStats {
    pub mounts_trimmed: u32,
    pub bytes_discarded: u64,
    pub errors: u32,
}

pub fn trim_all_mounts(stats: &mut TrimStats) -> Result<()> {
    let mounts = list_mounts()?;

    for mount in &mounts {
        if !is_trimmable(&mount.fstype) { continue; }

        eprintln!("[*] trim: {} ({}) on {}",
            mount.device, mount.fstype, mount.mountpoint);

        match fitrim_mountpoint(&mount.mountpoint) {
            Ok(bytes) => {
                eprintln!("[+] trim: {} MiB discarded on {}", bytes >> 20, mount.mountpoint);
                stats.mounts_trimmed  += 1;
                stats.bytes_discarded += bytes;
            }
            Err(e) => {
                // EOPNOTSUPP is common on HDDs or VMs — not a real error
                let errno = e.split('=').last().and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
                if errno == libc::EOPNOTSUPP || errno == libc::ENOTTY {
                    eprintln!("[*] trim: {} not supported (HDD or no discard)", mount.mountpoint);
                } else {
                    eprintln!("[!] trim: {}: {}", mount.mountpoint, e);
                    stats.errors += 1;
                }
            }
        }
    }

    eprintln!("[+] trim: {} mount(s) trimmed, {} MiB discarded, {} error(s)",
        stats.mounts_trimmed, stats.bytes_discarded >> 20, stats.errors);
    Ok(())
}
