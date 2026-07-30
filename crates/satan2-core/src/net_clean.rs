/*
 * net_clean.rs — Network artifact removal
 *
 * Targets:
 *  - ARP/NDP neighbor cache  (kernel table of IP→MAC mappings)
 *  - Connection tracking table (netfilter conntrack — stores all seen flows)
 *  - DNS resolver cache       (systemd-resolved, nscd, dnsmasq)
 *  - /proc/net/arp            (read-only view, cleared via ip/sysctl)
 *
 * Most operations require CAP_NET_ADMIN.
 */

use std::fs;
use std::process::Command;

// crate::Result not needed here

#[derive(Debug, Default)]
pub struct NetCleanStats {
    pub arp_flushed: bool,
    pub conntrack_flushed: bool,
    pub dns_flushed: bool,
    pub errors: u32,
}

// ── ARP / NDP neighbor cache ──────────────────────────────────────────────────

fn flush_arp_iproute() -> bool {
    // ip neigh flush all  — works for both IPv4 ARP and IPv6 NDP
    Command::new("ip")
        .args(["neigh", "flush", "all"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn flush_arp_sysctl() {
    // Reduce gc_stale_time to 1s — entries expire almost immediately
    for path in &[
        "/proc/sys/net/ipv4/neigh/default/gc_stale_time",
        "/proc/sys/net/ipv6/neigh/default/gc_stale_time",
    ] {
        let _ = fs::write(path, "1\n");
    }
}

pub fn flush_arp(stats: &mut NetCleanStats) {
    if flush_arp_iproute() {
        eprintln!("[+] net: ARP/NDP cache flushed (ip neigh flush all)");
        stats.arp_flushed = true;
    } else {
        // Fallback: accelerate expiry via sysctl
        flush_arp_sysctl();
        eprintln!("[*] net: ARP gc_stale_time set to 1s (ip not available)");
        stats.arp_flushed = true;
    }
}

// ── Connection tracking ───────────────────────────────────────────────────────

fn flush_conntrack_tool() -> bool {
    // conntrack -F flushes all tracked connections
    Command::new("conntrack")
        .args(["-F"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn flush_conntrack_proc() -> bool {
    // Direct write to the conntrack table clear interface
    for path in &[
        "/proc/net/nf_conntrack",
        "/proc/sys/net/netfilter/nf_conntrack_count",
    ] {
        if std::path::Path::new(path).exists() {
            // Writing to nf_conntrack flushes on some kernels
            let _ = fs::write("/proc/sys/net/netfilter/nf_conntrack_max", "0");
            let _ = fs::write("/proc/sys/net/netfilter/nf_conntrack_max", "65536");
            return true;
        }
    }
    false
}

pub fn flush_conntrack(stats: &mut NetCleanStats) {
    if flush_conntrack_tool() {
        eprintln!("[+] net: conntrack table flushed");
        stats.conntrack_flushed = true;
    } else if flush_conntrack_proc() {
        eprintln!("[*] net: conntrack max cycled (conntrack tool not available)");
        stats.conntrack_flushed = true;
    } else {
        eprintln!("[*] net: conntrack flush skipped (module not loaded or no permission)");
        stats.errors += 1;
    }
}

// ── DNS cache ─────────────────────────────────────────────────────────────────

fn flush_systemd_resolved() -> bool {
    Command::new("systemd-resolve")
        .args(["--flush-caches"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn flush_nscd() -> bool {
    Command::new("nscd")
        .args(["-i", "hosts"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn flush_dnsmasq() -> bool {
    // Send SIGHUP to dnsmasq to flush its cache
    if let Ok(output) = Command::new("pidof").arg("dnsmasq").output() {
        let pid_str = String::from_utf8_lossy(&output.stdout);
        if let Some(pid) = pid_str
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<i32>().ok())
        {
            return unsafe { libc::kill(pid, libc::SIGHUP) } == 0;
        }
    }
    false
}

pub fn flush_dns_cache(stats: &mut NetCleanStats) {
    let mut flushed = false;

    if flush_systemd_resolved() {
        eprintln!("[+] net: systemd-resolved cache flushed");
        flushed = true;
    }
    if flush_nscd() {
        eprintln!("[+] net: nscd hosts cache flushed");
        flushed = true;
    }
    if flush_dnsmasq() {
        eprintln!("[+] net: dnsmasq cache flushed (SIGHUP)");
        flushed = true;
    }

    if flushed {
        stats.dns_flushed = true;
    } else {
        eprintln!("[*] net: no DNS resolver found to flush (resolved/nscd/dnsmasq)");
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn net_clean_all(stats: &mut NetCleanStats) {
    flush_arp(stats);
    flush_conntrack(stats);
    flush_dns_cache(stats);

    eprintln!(
        "[+] net_clean: arp={} conntrack={} dns={}",
        stats.arp_flushed, stats.conntrack_flushed, stats.dns_flushed
    );
}
