/*
 * nvme.rs — NVMe firmware-level erase via Linux ioctl
 *
 * Fallback chain: CES → BES → OWS → Format SES=2 → Format SES=1 → warn
 */

use std::fs::{self, File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::{fill_random, iowr, Result};

// ── NVMe ioctl ────────────────────────────────────────────────────────────────

#[repr(C)]
struct NvmePassthruCmd {
    opcode:       u8,
    flags:        u8,
    rsvd1:        u16,
    nsid:         u32,
    cdw2:         u32,
    cdw3:         u32,
    metadata:     u64,
    addr:         u64,
    metadata_len: u32,
    data_len:     u32,
    cdw10:        u32,
    cdw11:        u32,
    cdw12:        u32,
    cdw13:        u32,
    cdw14:        u32,
    cdw15:        u32,
    timeout_ms:   u32,
    result:       u32,
}

const NVME_IOCTL_ADMIN_CMD: libc::c_ulong =
    iowr(b'N', 0x41, std::mem::size_of::<NvmePassthruCmd>());

// SANICAP bits (Identify Controller, offset 0x200)
const NVME_SANICAP_BES: u32 = 1 << 0; // Block Erase Sanitize
const NVME_SANICAP_OWS: u32 = 1 << 1; // Overwrite Sanitize
const NVME_SANICAP_CES: u32 = 1 << 2; // Crypto Erase Sanitize

// Sanitize action codes (CDW10 bits [2:0])
const NVME_SANACT_BLOCK_ERASE:  u32 = 2;
const NVME_SANACT_OVERWRITE:    u32 = 3;
const NVME_SANACT_CRYPTO_ERASE: u32 = 4;

// Format NVM SES field (CDW10 bits [11:9])
const NVME_FORMAT_SES_NONE:      u32 = 0 << 9;
const NVME_FORMAT_SES_USER_DATA: u32 = 1 << 9;
const NVME_FORMAT_SES_CRYPTO:    u32 = 2 << 9;

// Admin command opcodes
const NVME_ADM_CMD_IDENTIFY: u8 = 0x06;
const NVME_ADM_CMD_SANITIZE: u8 = 0x84;
const NVME_ADM_CMD_FORMAT:   u8 = 0x80;

// ── NVMe status decoding ──────────────────────────────────────────────────────

fn nvme_sct(result: u32) -> u32 { (result >> 9) & 0x7 }
fn nvme_sc(result: u32)  -> u32 { result & 0xFF }

// ── Low-level passthrough ─────────────────────────────────────────────────────

unsafe fn do_admin_cmd(fd: libc::c_int, cmd: &mut NvmePassthruCmd) -> std::result::Result<(), String> {
    let r = libc::ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd as *mut NvmePassthruCmd);
    if r == 0 {
        return Ok(());
    }
    let errno = *libc::__errno_location();
    if errno == libc::EIO && cmd.result != 0 {
        return Err(format!(
            "NVMe error: SCT={} SC=0x{:02x}",
            nvme_sct(cmd.result), nvme_sc(cmd.result)
        ));
    }
    Err(format!("ioctl NVME_IOCTL_ADMIN_CMD failed: errno={}", errno))
}

// ── Identify Controller ───────────────────────────────────────────────────────

fn identify_controller(fd: libc::c_int) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let mut cmd = NvmePassthruCmd {
        opcode:   NVME_ADM_CMD_IDENTIFY,
        nsid:     0,
        addr:     buf.as_mut_ptr() as u64,
        data_len: 4096,
        cdw10:    1, // CNS=1: Identify Controller
        ..unsafe { std::mem::zeroed() }
    };
    unsafe { do_admin_cmd(fd, &mut cmd) }?;
    Ok(buf)
}

// ── SANICAP ───────────────────────────────────────────────────────────────────

pub fn nvme_get_sanicap(fd: libc::c_int) -> Result<u32> {
    let buf = identify_controller(fd)?;
    // SANICAP is at offset 0x200 (bytes 512–515)
    let sanicap = u32::from_le_bytes([buf[0x200], buf[0x201], buf[0x202], buf[0x203]]);
    Ok(sanicap)
}

// ── Sanitize command ──────────────────────────────────────────────────────────

pub fn nvme_sanitize(fd: libc::c_int, sanact: u32) -> Result<()> {
    let mut cmd = NvmePassthruCmd {
        opcode: NVME_ADM_CMD_SANITIZE,
        cdw10:  sanact,
        ..unsafe { std::mem::zeroed() }
    };
    unsafe { do_admin_cmd(fd, &mut cmd) }
}

// ── Sanitize log page polling ─────────────────────────────────────────────────

pub fn nvme_wait_sanitize(fd: libc::c_int) -> Result<()> {
    let mut log = vec![0u8; 512];

    loop {
        let mut cmd = NvmePassthruCmd {
            opcode:   0x02, // Get Log Page
            nsid:     0xFFFF_FFFF,
            addr:     log.as_mut_ptr() as u64,
            data_len: 512,
            cdw10:    0x0081 | (((512 / 4 - 1) as u32) << 16), // LID=0x81, NUMDL
            ..unsafe { std::mem::zeroed() }
        };

        match unsafe { do_admin_cmd(fd, &mut cmd) } {
            Err(e) if e.contains("SC=0x") => {
                // Log page temporarily unavailable during sanitize — normal
                thread::sleep(Duration::from_secs(2));
                continue;
            }
            Err(e) => return Err(e),
            Ok(()) => {}
        }

        // SPROG (word 0) + SSTAT (word 1)
        let sstat = u16::from_le_bytes([log[2], log[3]]);
        let status = sstat & 0x7; // bits [2:0]

        match status {
            1 => {
                // In progress — SPROG gives 0–65535 completion
                let sprog = u16::from_le_bytes([log[0], log[1]]);
                eprint!("\r[>] NVMe sanitize: {:.1}%  ", sprog as f32 / 655.35);
                thread::sleep(Duration::from_secs(2));
            }
            2 => {
                eprintln!("\n[+] NVMe sanitize: completed successfully");
                return Ok(());
            }
            3 => return Err("NVMe sanitize: completed with errors".into()),
            _ => {
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

// ── Format NVM ────────────────────────────────────────────────────────────────

pub fn nvme_format_ses(fd: libc::c_int, ses: u32) -> Result<()> {
    // Read current LBAF from namespace 1
    let mut ns_buf = vec![0u8; 4096];
    let mut id_cmd = NvmePassthruCmd {
        opcode:   NVME_ADM_CMD_IDENTIFY,
        nsid:     0xFFFF_FFFF,
        addr:     ns_buf.as_mut_ptr() as u64,
        data_len: 4096,
        cdw10:    0, // CNS=0: Identify Namespace
        ..unsafe { std::mem::zeroed() }
    };

    if unsafe { do_admin_cmd(fd, &mut id_cmd) }.is_err() {
        id_cmd.nsid = 1;
        unsafe { do_admin_cmd(fd, &mut id_cmd) }?;
    }

    let flbas = ns_buf[26] & 0x0F; // current LBAF index
    let cdw10 = ses | (flbas as u32) | NVME_FORMAT_SES_NONE;

    let mut fmt_cmd = NvmePassthruCmd {
        opcode:     NVME_ADM_CMD_FORMAT,
        nsid:       0xFFFF_FFFF,
        cdw10:      cdw10,
        timeout_ms: 600_000,
        ..unsafe { std::mem::zeroed() }
    };

    if unsafe { do_admin_cmd(fd, &mut fmt_cmd) }.is_err() {
        fmt_cmd.nsid = 1;
        unsafe { do_admin_cmd(fd, &mut fmt_cmd) }?;
    }
    Ok(())
}

// ── USB bridge detection ──────────────────────────────────────────────────────

fn is_usb_bridge(dev: &str) -> bool {
    let devname = Path::new(dev).file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let syslink = format!("/sys/block/{}/device/../../../subsystem", devname);
    match fs::read_link(&syslink) {
        Ok(target) => target.to_string_lossy().contains("usb"),
        Err(_) => false,
    }
}

// ── OPAL detection (Security Send/Receive capability) ────────────────────────

fn has_opal(fd: libc::c_int) -> bool {
    let buf = match identify_controller(fd) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // OACS field at offset 0x0100, bit 3 = Security Send/Receive
    let oacs = u16::from_le_bytes([buf[0x100], buf[0x101]]);
    (oacs & (1 << 3)) != 0
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct NvmeDev {
    file: File,
}

impl NvmeDev {
    pub fn open(path: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("open {}: {}", path, e))?;
        Ok(NvmeDev { file })
    }

    pub fn fd(&self) -> libc::c_int {
        self.file.as_raw_fd()
    }

    /// Full fallback chain: CES → BES → OWS → Format SES=2 → SES=1 → warn
    pub fn secure_erase(dev_path: &str) -> Result<()> {
        if is_usb_bridge(dev_path) {
            return Err(format!(
                "{}: USB bridge detected — NVMe commands not forwarded by most bridges",
                dev_path
            ));
        }

        let dev = Self::open(dev_path)?;
        let fd = dev.fd();

        let sanicap = nvme_get_sanicap(fd)?;
        eprintln!("[*] NVMe SANICAP: BES={} OWS={} CES={}",
            (sanicap & NVME_SANICAP_BES) != 0,
            (sanicap & NVME_SANICAP_OWS) != 0,
            (sanicap & NVME_SANICAP_CES) != 0,
        );

        if has_opal(fd) {
            eprintln!("[*] TCG OPAL detected — TCG Revert preferred but not implemented; continuing with Sanitize");
        }

        // CES
        if sanicap & NVME_SANICAP_CES != 0 {
            eprintln!("[*] Issuing Sanitize (Crypto Erase)...");
            if nvme_sanitize(fd, NVME_SANACT_CRYPTO_ERASE).is_ok() {
                thread::sleep(Duration::from_millis(500));
                return nvme_wait_sanitize(fd);
            }
            eprintln!("[!] CES rejected, trying BES");
        }

        // BES
        if sanicap & NVME_SANICAP_BES != 0 {
            eprintln!("[*] Issuing Sanitize (Block Erase)...");
            if nvme_sanitize(fd, NVME_SANACT_BLOCK_ERASE).is_ok() {
                thread::sleep(Duration::from_millis(500));
                return nvme_wait_sanitize(fd);
            }
            eprintln!("[!] BES rejected, trying OWS");
        }

        // OWS — fill CDW11 with random 32-bit pattern
        if sanicap & NVME_SANICAP_OWS != 0 {
            eprintln!("[*] Issuing Sanitize (Overwrite, 1 pass)...");
            let pattern = rand_u32_local();
            let act = NVME_SANACT_OVERWRITE | (1 << 4); // OWPASS=1
            let mut cmd = NvmePassthruCmd {
                opcode: NVME_ADM_CMD_SANITIZE,
                cdw10:  act,
                cdw11:  pattern,
                ..unsafe { std::mem::zeroed() }
            };
            if unsafe { do_admin_cmd(fd, &mut cmd) }.is_ok() {
                thread::sleep(Duration::from_millis(500));
                return nvme_wait_sanitize(fd);
            }
            eprintln!("[!] OWS rejected, trying Format SES=2");
        }

        // Format SES=2 (crypto erase via Format NVM)
        eprintln!("[*] Trying Format NVM with SES=2 (crypto)...");
        if nvme_format_ses(fd, NVME_FORMAT_SES_CRYPTO).is_ok() {
            eprintln!("[+] Format NVM SES=2 succeeded");
            return Ok(());
        }

        // Format SES=1 (user data erase)
        eprintln!("[*] Trying Format NVM with SES=1 (user data erase)...");
        if nvme_format_ses(fd, NVME_FORMAT_SES_USER_DATA).is_ok() {
            eprintln!("[+] Format NVM SES=1 succeeded");
            return Ok(());
        }

        Err(format!(
            "{}: firmware supports no sanitize method — use software wipe as fallback",
            dev_path
        ))
    }
}

fn rand_u32_local() -> u32 {
    let mut v = [0u8; 4];
    fill_random(&mut v);
    u32::from_le_bytes(v)
}
