// browser_linux.rs — wipe browser history / cache artifacts on Linux
//
// Covered:
//   Firefox / Librewolf — ~/.mozilla/firefox/<profile>/ and ~/.librewolf/<profile>/
//   Chrome             — ~/.config/google-chrome/<profile>/
//   Chromium           — ~/.config/chromium/<profile>/
//   Brave              — ~/.config/BraveSoftware/Brave-Browser/<profile>/
//   Microsoft Edge     — ~/.config/microsoft-edge/<profile>/
//   Opera              — ~/.config/opera/<profile>/
//   Vivaldi            — ~/.config/vivaldi/<profile>/
//   Snap variants      — ~/snap/firefox/common/.mozilla/firefox/
//                        ~/snap/chromium/common/chromium/<profile>/
//
// Per-profile targets are wiped file by file (not dir-removed) so the profile
// directory itself survives and the browser doesn't prompt to recreate it.

use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Default)]
pub struct BrowserLinuxStats {
    pub profiles_wiped: u32,
    pub files_deleted: u64,
    pub bytes_freed: u64,
    pub errors: u32,
}

// Files/dirs to wipe inside a Firefox/Librewolf profile directory
const FIREFOX_TARGETS: &[&str] = &[
    "places.sqlite",
    "places.sqlite-wal",
    "places.sqlite-shm",
    "cookies.sqlite",
    "cookies.sqlite-wal",
    "cookies.sqlite-shm",
    "formhistory.sqlite",
    "downloads.sqlite",
    "favicons.sqlite",
    "sessionstore.jsonlz4",
    "sessionstore-backups", // directory
    "storage",              // directory
    "cache2",               // directory
    "startupCache",         // directory
    "thumbnails",           // directory
    "webappsstore.sqlite",
    "chromeappstore.sqlite",
];

// Files/dirs to wipe inside a Chromium-family profile directory
const CHROMIUM_TARGETS: &[&str] = &[
    "History",
    "History-journal",
    "Cookies",
    "Cookies-journal",
    "Web Data",
    "Web Data-journal",
    "Login Data",
    "Login Data-journal",
    "Media History",
    "Media History-journal",
    "Network Persistent State",
    "Visited Links",
    "Last Session",
    "Last Tabs",
    "Current Session",
    "Current Tabs",
    "Cache",                  // directory
    "GPUCache",               // directory
    "ShaderCache",            // directory
    "Code Cache",             // directory
    "blob_storage",           // directory
    "Session Storage",        // directory — LevelDB, stores session tokens
    "Local Storage",          // directory — LevelDB, stores localStorage data
    "IndexedDB",              // directory — LevelDB, stores structured DB data
    "Extension State",        // directory — LevelDB, extension key-value store
    "Sync Data",              // directory — LevelDB, sync metadata
    "AutofillStrikeDatabase", // directory — LevelDB
    "GCM Store",              // directory — LevelDB, push subscription metadata
];

fn wipe_path(path: &Path, stats: &mut BrowserLinuxStats) {
    if path.is_file() {
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if fs::remove_file(path).is_ok() {
            stats.files_deleted += 1;
            stats.bytes_freed += size;
        } else {
            stats.errors += 1;
        }
    } else if path.is_dir() {
        // Walk directory tree collecting files, then remove
        for entry in WalkDir::new(path)
            .follow_links(false)
            .contents_first(true)
            .into_iter()
            .flatten()
        {
            let p = entry.path();
            if entry.file_type().is_file() {
                let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                if fs::remove_file(p).is_ok() {
                    stats.files_deleted += 1;
                    stats.bytes_freed += size;
                } else {
                    stats.errors += 1;
                }
            } else {
                let _ = fs::remove_dir(p);
            }
        }
    }
}

fn wipe_firefox_dir(profiles_root: &Path, stats: &mut BrowserLinuxStats, verbose: bool) {
    if !profiles_root.exists() {
        return;
    }

    let entries = match fs::read_dir(profiles_root) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let profile = entry.path();
        if !profile.is_dir() {
            continue;
        }

        // Heuristic: Firefox profile dirs contain places.sqlite or prefs.js
        let is_profile =
            profile.join("places.sqlite").exists() || profile.join("prefs.js").exists();
        if !is_profile {
            continue;
        }

        if verbose {
            eprintln!("[*] browser-linux: firefox profile: {}", profile.display());
        }

        for target in FIREFOX_TARGETS {
            wipe_path(&profile.join(target), stats);
        }
        stats.profiles_wiped += 1;
    }
}

fn wipe_chromium_dir(browser_root: &Path, stats: &mut BrowserLinuxStats, verbose: bool) {
    if !browser_root.exists() {
        return;
    }

    let entries = match fs::read_dir(browser_root) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let profile = entry.path();
        if !profile.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let ns = name.to_string_lossy();
        // Chromium profile dirs: "Default", "Profile 1", "Profile 2", "Guest Profile"
        let is_profile =
            ns == "Default" || ns.starts_with("Profile ") || ns.starts_with("Guest Profile");
        if !is_profile {
            continue;
        }

        if verbose {
            eprintln!("[*] browser-linux: chromium profile: {}", profile.display());
        }

        for target in CHROMIUM_TARGETS {
            wipe_path(&profile.join(target), stats);
        }
        stats.profiles_wiped += 1;
    }
}

fn home_dirs() -> Vec<String> {
    let mut dirs = Vec::new();
    // Always try /root
    if Path::new("/root").is_dir() {
        dirs.push("/root".to_string());
    }
    // Enumerate /home/*
    if let Ok(entries) = fs::read_dir("/home") {
        for e in entries.flatten() {
            if e.path().is_dir() {
                dirs.push(e.path().to_string_lossy().into_owned());
            }
        }
    }
    // Also include the invoking user's home if not root
    if unsafe { libc::getuid() } != 0 {
        if let Ok(h) = std::env::var("HOME") {
            if !dirs.contains(&h) {
                dirs.push(h);
            }
        }
    }
    dirs
}

pub fn wipe_browser_history_linux(verbose: bool) -> BrowserLinuxStats {
    let mut stats = BrowserLinuxStats::default();

    for home in home_dirs() {
        let home = Path::new(&home);

        // Firefox + Librewolf
        wipe_firefox_dir(&home.join(".mozilla/firefox"), &mut stats, verbose);
        wipe_firefox_dir(&home.join(".librewolf"), &mut stats, verbose);

        // Snap-packaged Firefox
        wipe_firefox_dir(
            &home.join("snap/firefox/common/.mozilla/firefox"),
            &mut stats,
            verbose,
        );

        let config = home.join(".config");

        // Chromium-family browsers
        for subdir in &[
            "google-chrome",
            "chromium",
            "BraveSoftware/Brave-Browser",
            "microsoft-edge",
            "opera",
            "vivaldi",
        ] {
            wipe_chromium_dir(&config.join(subdir), &mut stats, verbose);
        }

        // Snap-packaged Chromium
        wipe_chromium_dir(
            &home.join("snap/chromium/common/chromium"),
            &mut stats,
            verbose,
        );

        // Flatpak browser dirs under XDG data home
        let xdg = home.join(".var/app");
        for (app_id, kind, subpath) in &[
            ("org.mozilla.firefox", "ff", ".mozilla/firefox"),
            ("org.chromium.Chromium", "cr", ".config/chromium"),
            (
                "com.brave.Browser",
                "cr",
                ".config/BraveSoftware/Brave-Browser",
            ),
            ("com.google.Chrome", "cr", ".config/google-chrome"),
            ("com.microsoft.Edge", "cr", ".config/microsoft-edge"),
            ("com.opera.Opera", "cr", ".config/opera"),
        ] {
            let base = xdg.join(app_id).join(subpath);
            if *kind == "ff" {
                wipe_firefox_dir(&base, &mut stats, verbose);
            } else {
                wipe_chromium_dir(&base, &mut stats, verbose);
            }
        }
    }

    eprintln!(
        "[+] browser-linux: {} profile(s) wiped, {} file(s) ({} MiB), {} error(s)",
        stats.profiles_wiped,
        stats.files_deleted,
        stats.bytes_freed >> 20,
        stats.errors
    );
    stats
}
