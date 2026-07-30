/*
 * ata.rs — ATA Secure Erase via SG_IO ATA-16 passthrough
 *
 * Sequence: SET FEATURES (password) → SECURITY ERASE PREPARE → SECURITY ERASE UNIT
 * Requires: drive not frozen (Word 128 bit 3 == 0)
 * Frozen workaround: echo mem > /sys/power/state  (S3 suspend unfreezes on resume)
 */

use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

use crate::{fill_random, secure_zero, Result};

// ── SG_IO ─────────────────────────────────────────────────────────────────────

const SG_IO: libc::c_ulong = 0x2285;
const SG_DXFER_NONE: i32 = -1;
const SG_DXFER_FROM_DEV: i32 = -3;
const SG_DXFER_TO_DEV: i32 = -2;

// ATA-16 passthrough CDB (16 bytes, opcode 0x85)
const ATA16_OPCODE: u8 = 0x85;

// Protocol values in CDB[1] bits [4:1]
const ATA16_PROTO_NON_DATA: u8 = 3 << 1;
const ATA16_PROTO_PIO_IN: u8 = 4 << 1;
const ATA16_PROTO_PIO_OUT: u8 = 5 << 1;

// T_DIR | BYT_BLOK | T_LENGTH=2 (sector count in CDB[6])
const ATA16_TFLAGS_PIO_IN: u8 = (1 << 4) | (1 << 3) | 2;
const ATA16_TFLAGS_PIO_OUT: u8 = (1 << 3) | 2; // T_DIR=0 (out), BYT_BLOK, T_LENGTH=2

// ATA commands
const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_SECURITY_SET_PASSWORD: u8 = 0xF1;
const ATA_CMD_SECURITY_ERASE_PREPARE: u8 = 0xF3;
const ATA_CMD_SECURITY_ERASE_UNIT: u8 = 0xF4;

// Security Status (Word 128) bit masks
const ATA_SEC_SUPPORTED: u16 = 1 << 0;
const ATA_SEC_ENABLED: u16 = 1 << 1;
const ATA_SEC_LOCKED: u16 = 1 << 2;
const ATA_SEC_FROZEN: u16 = 1 << 3;
const ATA_SEC_COUNT_EXPIRED: u16 = 1 << 4;
const ATA_SEC_ENHANCED_SUPPORTED: u16 = 1 << 5;

// ── SgIoHdr ──────────────────────────────────────────────────────────────────

// Mirrors struct sg_io_hdr from <scsi/sg.h>
#[repr(C)]
struct SgIoHdr {
    interface_id: i32,
    dxfer_direction: i32,
    cmd_len: u8,
    mx_sb_len: u8,
    iovec_count: u16,
    dxfer_len: u32,
    dxferp: *mut libc::c_void,
    cmdp: *const u8,
    sbp: *mut u8,
    timeout: u32,
    flags: u32,
    pack_id: i32,
    usr_ptr: *mut libc::c_void,
    status: u8,
    masked_status: u8,
    msg_status: u8,
    sb_len_wr: u8,
    host_status: u16,
    driver_status: u16,
    resid: i32,
    duration: u32,
    info: u32,
}

// SgIoHdr contains raw pointers — only used single-threaded in unsafe blocks.
unsafe impl Send for SgIoHdr {}

// ── ATA passthrough ───────────────────────────────────────────────────────────

struct AtaCmd {
    fd: libc::c_int,
    cdb: [u8; 16],
    data: Option<*mut u8>,
    data_len: usize,
    direction: i32,
    timeout_s: u32,
}

fn ata_do(cmd: &mut AtaCmd) -> Result<()> {
    let mut sense = [0u8; 64];

    let hdr = SgIoHdr {
        interface_id: b'S' as i32,
        dxfer_direction: cmd.direction,
        cmd_len: 16,
        mx_sb_len: sense.len() as u8,
        iovec_count: 0,
        dxfer_len: cmd.data_len as u32,
        dxferp: cmd
            .data
            .map(|p| p as *mut libc::c_void)
            .unwrap_or(std::ptr::null_mut()),
        cmdp: cmd.cdb.as_ptr(),
        sbp: sense.as_mut_ptr(),
        timeout: cmd.timeout_s * 1000,
        flags: 0,
        pack_id: 0,
        usr_ptr: std::ptr::null_mut(),
        status: 0,
        masked_status: 0,
        msg_status: 0,
        sb_len_wr: 0,
        host_status: 0,
        driver_status: 0,
        resid: 0,
        duration: 0,
        info: 0,
    };

    let r = unsafe { libc::ioctl(cmd.fd, SG_IO, &hdr as *const SgIoHdr) };
    if r < 0 {
        return Err(format!("SG_IO ioctl failed: errno={}", unsafe {
            *libc::__errno_location()
        }));
    }
    if hdr.status != 0 {
        return Err(format!("ATA command failed: status=0x{:02x}", hdr.status));
    }
    Ok(())
}

// ── IDENTIFY DEVICE ───────────────────────────────────────────────────────────

fn ata_identify(fd: libc::c_int) -> Result<[u16; 256]> {
    let mut buf = [0u8; 512];
    let mut cdb = [0u8; 16];
    cdb[0] = ATA16_OPCODE;
    cdb[1] = ATA16_PROTO_PIO_IN;
    cdb[2] = ATA16_TFLAGS_PIO_IN;
    cdb[6] = 1; // sector count = 1
    cdb[14] = ATA_CMD_IDENTIFY;

    let mut cmd = AtaCmd {
        fd,
        cdb,
        data: Some(buf.as_mut_ptr()),
        data_len: 512,
        direction: SG_DXFER_FROM_DEV,
        timeout_s: 30,
    };
    ata_do(&mut cmd)?;

    let mut words = [0u16; 256];
    for i in 0..256 {
        words[i] = u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]]);
    }
    Ok(words)
}

// ── Security status ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AtaSecurityCaps {
    pub supported: bool,
    pub enabled: bool,
    pub locked: bool,
    pub frozen: bool,
    pub count_expired: bool,
    pub enhanced_supported: bool,
    pub enhanced_erase_min: u16,
    pub normal_erase_min: u16,
    pub model: String,
}

fn detect_security(fd: libc::c_int) -> Result<AtaSecurityCaps> {
    let words = ata_identify(fd)?;
    let w128 = words[128];

    // Model: words 27–46, each word = 2 ASCII bytes, big-endian per word
    let mut model = String::with_capacity(41);
    for w in &words[27..47] {
        model.push((w >> 8) as u8 as char);
        model.push((w & 0xFF) as u8 as char);
    }
    let model = model.trim().to_string();

    Ok(AtaSecurityCaps {
        supported: w128 & ATA_SEC_SUPPORTED != 0,
        enabled: w128 & ATA_SEC_ENABLED != 0,
        locked: w128 & ATA_SEC_LOCKED != 0,
        frozen: w128 & ATA_SEC_FROZEN != 0,
        count_expired: w128 & ATA_SEC_COUNT_EXPIRED != 0,
        enhanced_supported: w128 & ATA_SEC_ENHANCED_SUPPORTED != 0,
        // Words 89/90: units of 2 minutes, 0xFFFE = "maximum"
        enhanced_erase_min: words[89].wrapping_mul(2),
        normal_erase_min: words[90].wrapping_mul(2),
        model,
    })
}

// ── ATA Security command helpers ──────────────────────────────────────────────

fn ata_security_set_password(fd: libc::c_int, password: &[u8; 32]) -> Result<()> {
    // SET PASSWORD data block: 512 bytes
    // Word 0: bit 0 = user (0) / master (1), bit 8 = security level
    // Words 1–16: password (32 bytes)
    let mut buf = [0u8; 512];
    buf[0] = 0; // user password, security level high
    buf[2..34].copy_from_slice(password);

    let mut cdb = [0u8; 16];
    cdb[0] = ATA16_OPCODE;
    cdb[1] = ATA16_PROTO_PIO_OUT;
    cdb[2] = ATA16_TFLAGS_PIO_OUT;
    cdb[6] = 1;
    cdb[14] = ATA_CMD_SECURITY_SET_PASSWORD;

    let mut cmd = AtaCmd {
        fd,
        cdb,
        data: Some(buf.as_mut_ptr()),
        data_len: 512,
        direction: SG_DXFER_TO_DEV,
        timeout_s: 30,
    };
    ata_do(&mut cmd)
}

fn ata_security_erase_prepare(fd: libc::c_int) -> Result<()> {
    let mut cdb = [0u8; 16];
    cdb[0] = ATA16_OPCODE;
    cdb[1] = ATA16_PROTO_NON_DATA;
    cdb[2] = 0;
    cdb[14] = ATA_CMD_SECURITY_ERASE_PREPARE;

    let mut cmd = AtaCmd {
        fd,
        cdb,
        data: None,
        data_len: 0,
        direction: SG_DXFER_NONE,
        timeout_s: 30,
    };
    ata_do(&mut cmd)
}

fn ata_security_erase_unit(
    fd: libc::c_int,
    password: &[u8; 32],
    enhanced: bool,
    timeout_s: u32,
) -> Result<()> {
    let mut buf = [0u8; 512];
    buf[0] = if enhanced { 0x02 } else { 0x00 };
    buf[2..34].copy_from_slice(password);

    let mut cdb = [0u8; 16];
    cdb[0] = ATA16_OPCODE;
    cdb[1] = ATA16_PROTO_PIO_OUT;
    cdb[2] = ATA16_TFLAGS_PIO_OUT;
    cdb[6] = 1;
    cdb[14] = ATA_CMD_SECURITY_ERASE_UNIT;

    let mut cmd = AtaCmd {
        fd,
        cdb,
        data: Some(buf.as_mut_ptr()),
        data_len: 512,
        direction: SG_DXFER_TO_DEV,
        timeout_s,
    };
    ata_do(&mut cmd)
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn ata_secure_erase(dev_path: &str) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .map_err(|e| format!("open {}: {}", dev_path, e))?;
    let fd = file.as_raw_fd();

    let caps = detect_security(fd)?;
    eprintln!("[*] ATA model: {}", caps.model);
    eprintln!(
        "[*] Security: supported={} enabled={} locked={} frozen={}",
        caps.supported, caps.enabled, caps.locked, caps.frozen
    );

    if !caps.supported {
        return Err(format!(
            "{}: ATA Security Feature Set not supported",
            dev_path
        ));
    }

    if caps.frozen {
        return Err("Drive is security-frozen (BIOS SECURITY FREEZE LOCK).\n\
             Workaround: echo mem > /sys/power/state  (S3 suspend unfreezes on resume)\n\
             Then re-run this command."
            .into());
    }

    if caps.count_expired {
        return Err("Security password attempt count expired — drive is locked out".into());
    }

    let enhanced = caps.enhanced_supported;
    let erase_minutes = if enhanced {
        caps.enhanced_erase_min
    } else {
        caps.normal_erase_min
    };

    // 2× drive estimate, minimum 4 hours
    let timeout_s = std::cmp::max(erase_minutes as u64 * 2 * 60, 4 * 3600) as u32;
    eprintln!(
        "[*] Erase timeout: {}s ({}min estimate, enhanced={})",
        timeout_s, erase_minutes, enhanced
    );

    // Random password: if process is killed, no one knows the password
    let mut password = [0u8; 32];
    fill_random(&mut password);

    eprintln!("[*] Step 1/3: SET PASSWORD...");
    ata_security_set_password(fd, &password)?;

    eprintln!("[*] Step 2/3: SECURITY ERASE PREPARE...");
    ata_security_erase_prepare(fd)?;

    eprintln!("[*] Step 3/3: SECURITY ERASE UNIT (this blocks until done)...");
    let result = ata_security_erase_unit(fd, &password, enhanced, timeout_s);

    // Zero password regardless of outcome
    secure_zero(&mut password);

    result?;

    // Verify: re-read security status
    let caps2 = detect_security(fd)?;
    if caps2.enabled {
        eprintln!("[!] Warning: security still shows enabled post-erase");
    } else {
        eprintln!("[+] ATA Secure Erase completed — security disabled");
    }

    Ok(())
}
