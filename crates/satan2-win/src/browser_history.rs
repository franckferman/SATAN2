/*
 * browser_history.rs — Browser artifact removal
 *
 * Chrome / Chromium / Edge (all Chromium-based):
 *   %LOCALAPPDATA%\<vendor>\<product>\User Data\<profile>\
 *     History, History-journal          — URL visits, search terms
 *     Cookies, Cookies-journal          — session cookies
 *     Login Data, Login Data-journal    — saved credentials
 *     Web Data                          — autofill, search engines
 *     Sessions\                         — current/previous sessions
 *     Cache\, Code Cache\               — disk cache
 *     Network\                          — DNS/socket state
 *     Top Sites                         — new tab thumbnails
 *
 * Firefox / Waterfox / LibreWolf:
 *   %APPDATA%\Mozilla\Firefox\Profiles\*.default*\
 *     places.sqlite[,-wal,-shm]         — history + bookmarks
 *     cookies.sqlite[,-wal,-shm]        — cookies
 *     formhistory.sqlite                — form autofill
 *     sessionstore.jsonlz4              — active session
 *     datareporting\                    — telemetry
 *
 * All SQLite files: we zero-overwrite then delete (WAL files too).
 * No selective removal — WAL + shm make partial cleaning unreliable.
 */

use std::fs;
use std::io::Write;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Default)]
pub struct BrowserStats {
    pub profiles_cleaned: u32,
    pub files_deleted: u32,
    pub bytes_freed: u64,
    pub errors: u32,
}

// Chromium profile database files to wipe
const CHROMIUM_DB_FILES: &[&str] = &[
    "History",
    "History-journal",
    "Cookies",
    "Cookies-journal",
    "Login Data",
    "Login Data-journal",
    "Web Data",
    "Top Sites",
    "Favicons",
    "Network Action Predictor",
    "Visited Links",
    "Origin Bound Certs",
];

// Firefox/Gecko SQLite files to wipe
const GECKO_DB_FILES: &[&str] = &[
    "places.sqlite",
    "places.sqlite-wal",
    "places.sqlite-shm",
    "cookies.sqlite",
    "cookies.sqlite-wal",
    "cookies.sqlite-shm",
    "formhistory.sqlite",
    "content-prefs.sqlite",
    "permissions.sqlite",
    "storage.sqlite",
    "webappsstore.sqlite",
    "sessionCheckpoints.json",
    "sessionstore.jsonlz4",
    "sessionstore-backups",
];

fn overwrite_and_delete(path: &Path, stats: &mut BrowserStats) {
    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    if size > 0 {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; 65536];
            let mut done = 0u64;
            while done < size {
                let n = ((size - done) as usize).min(zeros.len());
                if f.write_all(&zeros[..n]).is_err() {
                    break;
                }
                done += n as u64;
            }
        }
    }

    match fs::remove_file(path) {
        Ok(()) => {
            stats.files_deleted += 1;
            stats.bytes_freed += size;
        }
        Err(e) => {
            if e.raw_os_error() != Some(32) {
                // ignore ERROR_SHARING_VIOLATION (open tab)
                eprintln!("[!] browser: remove {}: {}", path.display(), e);
                stats.errors += 1;
            }
        }
    }
}

fn delete_dir(path: &Path, stats: &mut BrowserStats) {
    if !path.exists() {
        return;
    }
    for entry in WalkDir::new(path)
        .follow_links(false)
        .contents_first(true)
        .into_iter()
        .flatten()
    {
        let p = entry.path();
        if entry.file_type().is_file() {
            let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            match fs::remove_file(p) {
                Ok(()) => {
                    stats.files_deleted += 1;
                    stats.bytes_freed += size;
                }
                Err(e) => {
                    if e.raw_os_error() != Some(32) {
                        eprintln!("[!] browser: rm {}: {}", p.display(), e);
                        stats.errors += 1;
                    }
                }
            }
        } else {
            let _ = fs::remove_dir(p);
        }
    }
}

// ── Chromium-based ────────────────────────────────────────────────────────────

fn clean_chromium_profile(profile_dir: &Path, stats: &mut BrowserStats) {
    // Named DB files
    for name in CHROMIUM_DB_FILES {
        let p = profile_dir.join(name);
        if p.exists() {
            overwrite_and_delete(&p, stats);
        }
    }

    // Session files directory
    let sessions = profile_dir.join("Sessions");
    if sessions.exists() {
        delete_dir(&sessions, stats);
    }

    // Cache directories
    for cache in &[
        "Cache",
        "Code Cache",
        "GPUCache",
        "ShaderCache",
        "Network",
        "File System",
        "IndexedDB",
        "databases",
    ] {
        let d = profile_dir.join(cache);
        if d.exists() {
            delete_dir(&d, stats);
        }
    }
}

fn clean_chromium_vendor(vendor_dir: &Path, verbose: bool, stats: &mut BrowserStats) {
    if !vendor_dir.exists() {
        return;
    }

    let user_data = vendor_dir.join("User Data");
    if !user_data.exists() {
        return;
    }

    // Profiles: Default, Profile 1, Profile 2, ...
    let entries = match fs::read_dir(&user_data) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let ns = name.to_string_lossy();
        if ns == "Default" || ns.starts_with("Profile ") || ns.starts_with("Guest ") {
            if verbose {
                eprintln!("[*] browser: chromium profile: {}", entry.path().display());
            }
            clean_chromium_profile(&entry.path(), stats);
            stats.profiles_cleaned += 1;
        }
    }
}

// ── Firefox / Gecko ───────────────────────────────────────────────────────────

fn clean_gecko_profile(profile_dir: &Path, verbose: bool, stats: &mut BrowserStats) {
    if verbose {
        eprintln!("[*] browser: gecko profile: {}", profile_dir.display());
    }

    for name in GECKO_DB_FILES {
        let p = profile_dir.join(name);
        if p.exists() {
            overwrite_and_delete(&p, stats);
        }
    }

    // Telemetry / crash reports
    for sub in &[
        "datareporting",
        "crashes",
        "sessionstore-backups",
        "storage",
        "thumbnails",
    ] {
        let d = profile_dir.join(sub);
        if d.exists() {
            delete_dir(&d, stats);
        }
    }

    stats.profiles_cleaned += 1;
}

fn clean_gecko_vendor(
    appdata_roaming: &str,
    vendor: &str,
    product: &str,
    verbose: bool,
    stats: &mut BrowserStats,
) {
    let profiles_dir = format!(r"{}\{}\{}\Profiles", appdata_roaming, vendor, product);
    let profiles_dir = Path::new(&profiles_dir);
    if !profiles_dir.exists() {
        return;
    }

    for entry in fs::read_dir(profiles_dir).into_iter().flatten().flatten() {
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            clean_gecko_profile(&entry.path(), verbose, stats);
        }
    }
}

// ── Public ────────────────────────────────────────────────────────────────────

pub fn wipe_browser_history(verbose: bool) -> BrowserStats {
    let mut stats = BrowserStats::default();

    let users = match fs::read_dir(r"C:\Users") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[!] browser: C:\\Users: {}", e);
            return stats;
        }
    };

    for user in users.flatten() {
        let home = user.path();
        if !home.is_dir() {
            continue;
        }

        let local_appdata = format!(r"{}\AppData\Local", home.display());
        let roaming_appdata = format!(r"{}\AppData\Roaming", home.display());

        // Chromium-based browsers
        let chromium_vendors: &[(&str, &str)] = &[
            (r"Google\Chrome", "Chrome"),
            (r"Google\Chrome Beta", "Chrome Beta"),
            (r"Google\Chrome SxS", "Chrome Canary"),
            (r"Microsoft\Edge", "Edge"),
            (r"BraveSoftware\Brave-Browser", "Brave"),
            (r"Chromium", "Chromium"),
            (r"Vivaldi", "Vivaldi"),
            (r"Opera Software\Opera Stable", "Opera"),
        ];
        for (rel, name) in chromium_vendors {
            let dir = format!(r"{}\{}", local_appdata, rel);
            let p = Path::new(&dir);
            if p.exists() {
                if verbose {
                    eprintln!("[*] browser: {} for {}", name, home.display());
                }
                clean_chromium_vendor(p, verbose, &mut stats);
            }
        }

        // Gecko browsers
        let gecko_browsers: &[(&str, &str)] = &[
            ("Mozilla", "Firefox"),
            ("Mozilla", "FirefoxESR"),
            ("Waterfox", "Waterfox"),
            ("LibreWolf", "LibreWolf"),
            ("Pale Moon", "Pale Moon"),
        ];
        for (vendor, product) in gecko_browsers {
            clean_gecko_vendor(&roaming_appdata, vendor, product, verbose, &mut stats);
        }

        // Internet Explorer / Legacy Edge — index.dat and WebCacheV01.dat
        let ie_cache = format!(
            r"{}\Microsoft\Windows\WebCache\WebCacheV01.dat",
            local_appdata
        );
        if Path::new(&ie_cache).exists() {
            overwrite_and_delete(Path::new(&ie_cache), &mut stats);
        }
    }

    eprintln!(
        "[+] browser: {} profile(s), {} file(s) deleted, {} MiB freed, {} error(s)",
        stats.profiles_cleaned,
        stats.files_deleted,
        stats.bytes_freed >> 20,
        stats.errors
    );
    stats
}
