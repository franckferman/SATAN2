#![cfg(target_os = "windows")]
/*
 * schtasks.rs — Scheduled task artifact cleanup
 *
 * Windows stores task definitions as XML files in:
 *   C:\Windows\System32\Tasks\   (32/64-bit tasks)
 *   C:\Windows\SysWOW64\Tasks\   (WOW64 tasks, mirror)
 *
 * The Task Scheduler service (Schedule) maintains the runtime state.
 * XML files persist independently — readable even offline.
 *
 * Strategy for DESTROY mode:
 *   - Enumerate C:\Windows\System32\Tasks\
 *   - Skip known Microsoft/ and Windows/ subtrees (avoid breaking the OS)
 *   - Zero-overwrite + delete remaining XML files (attacker persistence artifacts)
 *
 * Strategy for targeted cleanup:
 *   - Accept a list of task names/paths and call schtasks /delete /f on each
 *
 * Detection / Forensics note:
 *   - The Task Scheduler event log (Microsoft-Windows-TaskScheduler/Operational)
 *     is cleared by event_log.rs — it logs task creation/execution.
 *   - The Security event log (4698: A scheduled task was created) is also cleared.
 */

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

const TASKS_DIR:     &str = r"C:\Windows\System32\Tasks";
const TASKS_WOW_DIR: &str = r"C:\Windows\SysWOW64\Tasks";

// Microsoft-owned task subtrees — do NOT touch these
const MS_PREFIXES: &[&str] = &[
    "Microsoft\\",
    "Microsoft/",
];

fn is_microsoft_task(path: &Path, base: &Path) -> bool {
    if let Ok(rel) = path.strip_prefix(base) {
        let rel_str = rel.to_string_lossy();
        return MS_PREFIXES.iter().any(|p| rel_str.starts_with(p));
    }
    false
}

fn overwrite_and_delete(path: &Path, stats: &mut SchtasksStats) {
    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    if size > 0 {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; 4096];
            let mut done = 0u64;
            while done < size {
                let n = ((size - done) as usize).min(zeros.len());
                let _ = f.write_all(&zeros[..n]);
                done += n as u64;
            }
        }
    }

    match fs::remove_file(path) {
        Ok(()) => {
            stats.xml_deleted += 1;
            stats.bytes_freed += size;
        }
        Err(e) => {
            eprintln!("[!] schtasks: remove {}: {}", path.display(), e);
            stats.errors += 1;
        }
    }
}

#[derive(Debug, Default)]
pub struct SchtasksStats {
    pub xml_deleted:    u32,
    pub tasks_deleted:  u32,
    pub bytes_freed:    u64,
    pub errors:         u32,
}

/// Delete a specific task by name via schtasks.exe.
pub fn delete_task(task_name: &str, stats: &mut SchtasksStats) {
    let ok = Command::new("schtasks")
        .args(["/delete", "/tn", task_name, "/f"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if ok {
        stats.tasks_deleted += 1;
        eprintln!("[+] schtasks: deleted task: {}", task_name);
    } else {
        eprintln!("[!] schtasks: failed to delete task: {}", task_name);
        stats.errors += 1;
    }
}

/// Wipe all non-Microsoft task XML files.
fn wipe_tasks_dir(dir: &str, stats: &mut SchtasksStats, verbose: bool) {
    let base = Path::new(dir);
    if !base.exists() { return; }

    for entry in WalkDir::new(base).follow_links(false).into_iter().flatten() {
        if !entry.file_type().is_file() { continue; }

        let path = entry.path();

        // Skip XML files that belong to Microsoft subtrees
        if is_microsoft_task(path, base) { continue; }

        if verbose { eprintln!("[*] schtasks: wiping {}", path.display()); }
        overwrite_and_delete(path, stats);
    }
}

pub fn wipe_scheduled_tasks(task_names: &[&str], destroy_all: bool, verbose: bool) -> SchtasksStats {
    let mut stats = SchtasksStats::default();

    // Targeted: delete specific tasks by name via API
    for name in task_names {
        delete_task(name, &mut stats);
    }

    if destroy_all {
        if verbose { eprintln!("[*] schtasks: wiping non-Microsoft tasks in {}", TASKS_DIR); }
        wipe_tasks_dir(TASKS_DIR, &mut stats, verbose);
        wipe_tasks_dir(TASKS_WOW_DIR, &mut stats, verbose);
    }

    eprintln!("[+] schtasks: {} XML(s) deleted, {} task(s) via API, {} MiB, {} error(s)",
        stats.xml_deleted, stats.tasks_deleted, stats.bytes_freed >> 20, stats.errors);
    stats
}
