#![cfg(target_os = "windows")]
/*
 * srum.rs — System Resource Usage Monitor database removal
 *
 * SRUM (srudb.dat) is an ESE (Extensible Storage Engine) database at:
 *   C:\Windows\System32\sru\SRUDB.dat
 *
 * It records every 60 minutes:
 *  - Network usage per application (bytes sent/received, interface used)
 *  - CPU/memory/disk usage per process
 *  - Energy consumption per process
 *  - Connected network profiles (SSIDs, domains)
 *
 * This is one of the richest forensic artifacts on Windows 10/11 —
 * an examiner can reconstruct months of network and process activity.
 *
 * The database is locked by the SRU (System Resource Usage) service.
 * Strategy:
 *   1. Stop the SRU service
 *   2. Overwrite and delete SRUDB.dat
 *   3. Restart the service (Windows will recreate the DB)
 *
 * Also covers: SRUM-DUMP2 won't find anything if we wipe the ESE file.
 */

use std::fs;
use std::process::Command;

const SRUDB_PATH: &str = r"C:\Windows\System32\sru\SRUDB.dat";
const SRU_SERVICE: &str = "srum";

fn service_control(service: &str, action: &str) -> bool {
    Command::new("sc")
        .args(["stop", service])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    Command::new("net")
        .args([action, service])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn overwrite_and_delete(path: &str) -> Result<u64, String> {
    use std::io::Write;

    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    let size = meta.len();

    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;

    // Overwrite with zeros (ESE checksum mismatch → DB unusable even if recovered)
    let buf = vec![0u8; 65536];
    let mut done = 0u64;
    while done < size {
        let n = ((size - done) as usize).min(buf.len());
        f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        done += n as u64;
    }
    drop(f);

    fs::remove_file(path).map_err(|e| format!("remove {}: {}", path, e))?;
    Ok(size)
}

#[derive(Debug, Default)]
pub struct SrumStats {
    pub wiped:      bool,
    pub bytes_freed: u64,
    pub error:      Option<String>,
}

pub fn wipe_srum(verbose: bool) -> SrumStats {
    let mut stats = SrumStats::default();

    if !std::path::Path::new(SRUDB_PATH).exists() {
        eprintln!("[*] srum: SRUDB.dat not found (not a Windows 10/11 system?)");
        return stats;
    }

    eprintln!("[*] srum: stopping {} service...", SRU_SERVICE);
    service_control(SRU_SERVICE, "stop");

    // Brief wait for service to release DB handle
    std::thread::sleep(std::time::Duration::from_secs(2));

    match overwrite_and_delete(SRUDB_PATH) {
        Ok(bytes) => {
            stats.wiped      = true;
            stats.bytes_freed = bytes;
            eprintln!("[+] srum: SRUDB.dat wiped and deleted ({} MiB)", bytes >> 20);
        }
        Err(e) => {
            eprintln!("[!] srum: {}", e);
            stats.error = Some(e);
        }
    }

    // Restart — Windows recreates an empty SRUDB.dat
    eprintln!("[*] srum: restarting {} service...", SRU_SERVICE);
    service_control(SRU_SERVICE, "start");

    stats
}
