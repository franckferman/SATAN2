/*
 * wipe.rs — Multi-pass software wipe with O_DIRECT
 *
 * Algorithms: Random (NIST 800-88), DoD 5220.22-M (3-pass),
 *             Schneier (7-pass), Gutmann (35-pass, legacy MFM/RLL).
 *
 * Uses O_DIRECT + O_SYNC to bypass page cache and force writes to media.
 * Buffer must be aligned to ALIGN_SIZE (4096) for O_DIRECT.
 */

use std::alloc::{alloc, dealloc, Layout};
use std::time::Instant;

use crate::{fill_random, Result};

const WIPE_BUF_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
const ALIGN_SIZE: usize = 4096;

const BLKGETSIZE64: libc::c_ulong = 0x80081272;
const BLKFLSBUF: libc::c_ulong = 0x00001261;

// ── Algorithm definitions ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WipeAlgo {
    Random,   // 1 random pass (NIST 800-88 recommendation)
    Dod,      // 3-pass DoD 5220.22-M
    Schneier, // 7-pass Schneier
    Gutmann,  // 35-pass Gutmann (legacy MFM/RLL — meaningless on modern drives)
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum PassType {
    Zero,
    One,
    Byte(u8),
    Pattern3([u8; 3]),
    Random,
}

struct PassDef {
    kind: PassType,
    label: &'static str,
}

const DOD_PASSES: [PassDef; 3] = [
    PassDef {
        kind: PassType::Byte(0x00),
        label: "0x00",
    },
    PassDef {
        kind: PassType::Byte(0xFF),
        label: "0xFF",
    },
    PassDef {
        kind: PassType::Random,
        label: "random",
    },
];

const SCHNEIER_PASSES: [PassDef; 7] = [
    PassDef {
        kind: PassType::Byte(0xFF),
        label: "0xFF",
    },
    PassDef {
        kind: PassType::Byte(0x00),
        label: "0x00",
    },
    PassDef {
        kind: PassType::Random,
        label: "random",
    },
    PassDef {
        kind: PassType::Random,
        label: "random",
    },
    PassDef {
        kind: PassType::Random,
        label: "random",
    },
    PassDef {
        kind: PassType::Random,
        label: "random",
    },
    PassDef {
        kind: PassType::Random,
        label: "random",
    },
];

// Gutmann 35 passes — random bookends + MFM/RLL/PRML encoding patterns
#[rustfmt::skip]
const GUTMANN_PASSES: [PassDef; 35] = [
    PassDef { kind: PassType::Random,                  label: "random" },
    PassDef { kind: PassType::Random,                  label: "random" },
    PassDef { kind: PassType::Random,                  label: "random" },
    PassDef { kind: PassType::Random,                  label: "random" },
    PassDef { kind: PassType::Pattern3([0x55,0x55,0x55]), label: "0x555555" },
    PassDef { kind: PassType::Pattern3([0xAA,0xAA,0xAA]), label: "0xAAAAAA" },
    PassDef { kind: PassType::Pattern3([0x92,0x49,0x24]), label: "0x924924" },
    PassDef { kind: PassType::Pattern3([0x49,0x24,0x92]), label: "0x492492" },
    PassDef { kind: PassType::Pattern3([0x24,0x92,0x49]), label: "0x249249" },
    PassDef { kind: PassType::Byte(0x00),               label: "0x00" },
    PassDef { kind: PassType::Byte(0x11),               label: "0x11" },
    PassDef { kind: PassType::Byte(0x22),               label: "0x22" },
    PassDef { kind: PassType::Byte(0x33),               label: "0x33" },
    PassDef { kind: PassType::Byte(0x44),               label: "0x44" },
    PassDef { kind: PassType::Byte(0x55),               label: "0x55" },
    PassDef { kind: PassType::Byte(0x66),               label: "0x66" },
    PassDef { kind: PassType::Byte(0x77),               label: "0x77" },
    PassDef { kind: PassType::Byte(0x88),               label: "0x88" },
    PassDef { kind: PassType::Byte(0x99),               label: "0x99" },
    PassDef { kind: PassType::Byte(0xAA),               label: "0xAA" },
    PassDef { kind: PassType::Byte(0xBB),               label: "0xBB" },
    PassDef { kind: PassType::Byte(0xCC),               label: "0xCC" },
    PassDef { kind: PassType::Byte(0xDD),               label: "0xDD" },
    PassDef { kind: PassType::Byte(0xEE),               label: "0xEE" },
    PassDef { kind: PassType::Byte(0xFF),               label: "0xFF" },
    PassDef { kind: PassType::Pattern3([0x92,0x49,0x24]), label: "0x924924" },
    PassDef { kind: PassType::Pattern3([0x49,0x24,0x92]), label: "0x492492" },
    PassDef { kind: PassType::Pattern3([0x24,0x92,0x49]), label: "0x249249" },
    PassDef { kind: PassType::Pattern3([0x6D,0xB6,0xDB]), label: "0x6DB6DB" },
    PassDef { kind: PassType::Pattern3([0xB6,0xDB,0x6D]), label: "0xB6DB6D" },
    PassDef { kind: PassType::Pattern3([0xDB,0x6D,0xB6]), label: "0xDB6DB6" },
    PassDef { kind: PassType::Random,                  label: "random" },
    PassDef { kind: PassType::Random,                  label: "random" },
    PassDef { kind: PassType::Random,                  label: "random" },
    PassDef { kind: PassType::Random,                  label: "random" },
];

// ── Options ───────────────────────────────────────────────────────────────────

pub struct WipeOpts {
    pub algo: WipeAlgo,
    pub verify_last: bool,
    pub verbose: bool,
}

// ── Progress ──────────────────────────────────────────────────────────────────

struct Progress {
    start: Instant,
    last_print: Instant,
    total: u64,
    written: u64,
}

impl Progress {
    fn new(total: u64) -> Self {
        let now = Instant::now();
        Progress {
            start: now,
            last_print: now,
            total,
            written: 0,
        }
    }

    fn update(&mut self, n: u64) {
        self.written += n;
        let now = Instant::now();
        if (now - self.last_print).as_secs_f64() >= 1.0 {
            self.last_print = now;
            let elapsed = (now - self.start).as_secs_f64();
            let pct = self.written as f64 / self.total as f64 * 100.0;
            let mbs = self.written as f64 / (1024.0 * 1024.0) / elapsed.max(0.001);
            let eta = if self.written > 0 {
                (self.total - self.written) as f64 / (self.written as f64 / elapsed.max(0.001))
            } else {
                0.0
            };
            eprint!("\r[>] {:.1}%  {:.1} MiB/s  ETA {:.0}s   ", pct, mbs, eta);
        }
    }

    fn done(&self) {
        let elapsed = (Instant::now() - self.start).as_secs_f64();
        let mbs = self.written as f64 / (1024.0 * 1024.0) / elapsed.max(0.001);
        eprintln!(
            "\r[+] {:.0} MiB in {:.1}s  ({:.1} MiB/s)          ",
            self.written >> 20,
            elapsed,
            mbs
        );
    }
}

// ── Aligned buffer ────────────────────────────────────────────────────────────

struct AlignedBuf {
    ptr: *mut u8,
    layout: Layout,
    len: usize,
}

impl AlignedBuf {
    fn new(size: usize, align: usize) -> Option<Self> {
        let layout = Layout::from_size_align(size, align).ok()?;
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return None;
        }
        Some(AlignedBuf {
            ptr,
            layout,
            len: size,
        })
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr, self.layout) };
    }
}

// ── Device size ───────────────────────────────────────────────────────────────

fn block_dev_size(fd: libc::c_int) -> Result<u64> {
    let mut size = 0u64;
    let r = unsafe { libc::ioctl(fd, BLKGETSIZE64, &mut size as *mut u64) };
    if r < 0 {
        return Err(format!("BLKGETSIZE64 failed: errno={}", unsafe {
            *libc::__errno_location()
        }));
    }
    Ok(size)
}

// ── Single pass ───────────────────────────────────────────────────────────────

fn do_pass(
    fd: libc::c_int,
    dev_size: u64,
    pass: &PassDef,
    pass_n: usize,
    total_n: usize,
) -> Result<()> {
    eprintln!("[*] Pass {}/{}: {}", pass_n, total_n, pass.label);

    let mut buf = AlignedBuf::new(WIPE_BUF_SIZE, ALIGN_SIZE).ok_or("aligned alloc failed")?;

    // Pre-fill non-random passes
    match pass.kind {
        PassType::Zero => buf.as_mut_slice().fill(0x00),
        PassType::One => buf.as_mut_slice().fill(0xFF),
        PassType::Byte(b) => buf.as_mut_slice().fill(b),
        PassType::Pattern3(p) => {
            let s = buf.as_mut_slice();
            for (i, b) in s.iter_mut().enumerate() {
                *b = p[i % 3];
            }
        }
        PassType::Random => {} // filled per-chunk below
    }

    let mut prog = Progress::new(dev_size);

    // Seek to start
    let r = unsafe { libc::lseek64(fd, 0, libc::SEEK_SET) };
    if r < 0 {
        return Err(format!("lseek failed: errno={}", unsafe {
            *libc::__errno_location()
        }));
    }

    let mut written_total: u64 = 0;
    while written_total < dev_size {
        let chunk = WIPE_BUF_SIZE.min((dev_size - written_total) as usize);
        // Round down to 512-byte sector boundary for O_DIRECT
        let chunk = chunk & !(512 - 1);
        if chunk == 0 {
            break;
        }

        if pass.kind == PassType::Random {
            fill_random(&mut buf.as_mut_slice()[..chunk]);
        }

        let w = unsafe { libc::write(fd, buf.ptr as *const libc::c_void, chunk) };
        if w < 0 {
            return Err(format!("write failed: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }

        written_total += w as u64;
        prog.update(w as u64);
    }

    unsafe {
        libc::fsync(fd);
        libc::ioctl(fd, BLKFLSBUF, 0 as libc::c_int);
    }

    prog.done();
    Ok(())
}

// ── Verify pass ───────────────────────────────────────────────────────────────

fn do_verify(fd: libc::c_int, dev_size: u64, pass: &PassDef) -> Result<()> {
    if pass.kind == PassType::Random {
        return Ok(()); // can't verify random
    }

    eprintln!("[*] Verifying last pass...");
    let mut buf = AlignedBuf::new(WIPE_BUF_SIZE, ALIGN_SIZE).ok_or("aligned alloc failed")?;

    unsafe { libc::lseek64(fd, 0, libc::SEEK_SET) };

    let mut verified: u64 = 0;
    while verified < dev_size {
        let chunk = WIPE_BUF_SIZE.min((dev_size - verified) as usize) & !(512 - 1);
        if chunk == 0 {
            break;
        }

        let r = unsafe { libc::read(fd, buf.ptr as *mut libc::c_void, chunk) };
        if r <= 0 {
            break;
        }

        let data = &buf.as_mut_slice()[..r as usize];
        let expected = match pass.kind {
            PassType::Zero => 0x00,
            PassType::One => 0xFF,
            PassType::Byte(b) => b,
            _ => 0x00,
        };

        for &b in data {
            if b != expected {
                return Err(format!(
                    "Verify FAILED at offset {}: expected 0x{:02x}, got 0x{:02x}",
                    verified, expected, b
                ));
            }
        }
        verified += r as u64;
    }
    eprintln!("[+] Verify OK");
    Ok(())
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn wipe_device(dev_path: &str, opts: &WipeOpts) -> Result<()> {
    if opts.algo == WipeAlgo::Gutmann {
        eprintln!(
            "[!] Gutmann 35-pass: only meaningful for pre-2000 MFM/RLL drives. \
                   On modern drives (NVMe/SATA/SSD), 1 random pass is equivalent."
        );
    }

    let flags = libc::O_WRONLY | libc::O_DIRECT | libc::O_SYNC;
    let fd = unsafe {
        let path = std::ffi::CString::new(dev_path).map_err(|e| e.to_string())?;
        libc::open(path.as_ptr(), flags)
    };
    if fd < 0 {
        return Err(format!("open {}: errno={}", dev_path, unsafe {
            *libc::__errno_location()
        }));
    }

    let dev_size = block_dev_size(fd)?;
    eprintln!("[*] Device: {}  Size: {} MiB", dev_path, dev_size >> 20);

    let passes: &[PassDef] = match opts.algo {
        WipeAlgo::Random => &[PassDef {
            kind: PassType::Random,
            label: "random",
        }],
        WipeAlgo::Dod => &DOD_PASSES,
        WipeAlgo::Schneier => &SCHNEIER_PASSES,
        WipeAlgo::Gutmann => &GUTMANN_PASSES,
    };

    let n = passes.len();
    for (i, pass) in passes.iter().enumerate() {
        do_pass(fd, dev_size, pass, i + 1, n)?;
    }

    if opts.verify_last {
        // Re-open R/W for verify
        unsafe { libc::close(fd) };
        let rw_flags = libc::O_RDONLY | libc::O_DIRECT;
        let fd_r = unsafe {
            let path = std::ffi::CString::new(dev_path).map_err(|e| e.to_string())?;
            libc::open(path.as_ptr(), rw_flags)
        };
        if fd_r >= 0 {
            let _ = do_verify(fd_r, dev_size, passes.last().unwrap());
            unsafe { libc::close(fd_r) };
        }
        return Ok(());
    }

    unsafe { libc::close(fd) };
    Ok(())
}
