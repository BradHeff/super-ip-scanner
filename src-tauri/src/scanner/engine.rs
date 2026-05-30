//! Orchestrates a scan: parses the target spec, enumerates IPs,
//! fans out concurrent probes (ARP + ICMP + TCP + hostname resolution),
//! and streams results to the frontend via a Tauri channel.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::scanner::arp;
use crate::scanner::hostname::HostnameResolver;
use crate::scanner::icmp::Pinger;
use crate::scanner::tcp;
use crate::scanner::types::{HostResult, HostStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// CIDR (e.g. `192.168.1.0/24`) or a single IP / range (`192.168.1.1-50`).
    pub target: String,
    /// Optional source IP — picks an interface for ARP.
    #[serde(default)]
    pub source_ip: Option<String>,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_timeout_ms")]
    pub probe_timeout_ms: u64,
    #[serde(default = "default_true")]
    pub use_arp: bool,
    #[serde(default = "default_true")]
    pub use_icmp: bool,
    #[serde(default = "default_true")]
    pub use_tcp_probe: bool,
    #[serde(default = "default_true")]
    pub resolve_hostnames: bool,
    /// Extra TCP ports to probe in addition to the defaults.
    #[serde(default)]
    pub tcp_ports: Vec<u16>,
}

fn default_concurrency() -> usize { 256 }
fn default_timeout_ms() -> u64 { 1000 }
fn default_true() -> bool { true }

/// Tiny built-in OUI → vendor map covering common devices. Full IEEE OUI lookup is a
/// post-MVP enhancement (consider re-adding the `mac_oui` crate once the API stabilizes).
fn lookup_oui_vendor(mac: &str) -> Option<String> {
    let prefix = mac.get(..8)?.to_ascii_uppercase().replace('-', ":");
    let name = match prefix.as_str() {
        "00:50:56" | "00:0C:29" | "00:05:69" | "00:1C:14" => "VMware",
        "08:00:27" => "VirtualBox",
        "00:15:5D" => "Microsoft (Hyper-V)",
        "B8:27:EB" | "DC:A6:32" | "E4:5F:01" | "D8:3A:DD" => "Raspberry Pi",
        "F0:18:98" | "3C:22:FB" | "A4:83:E7" | "00:1F:5B" => "Apple",
        "60:8B:0E" | "FC:FB:FB" | "00:14:22" => "Cisco",
        "C8:3A:35" | "70:4D:7B" | "94:FB:B2" => "Tenda",
        "00:1D:7E" | "00:24:01" | "9C:5C:8E" => "ASUS",
        "00:0F:B5" | "00:1B:2F" => "Netgear",
        "1C:69:7A" | "D4:6E:0E" => "Elitegroup",
        _ => return None,
    };
    Some(name.to_string())
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ScanEvent {
    Started { total: usize, target: String },
    HostUpdate { host: HostResult },
    Progress { scanned: usize, alive: usize },
    // u64 ms is plenty (≈584 million years) and avoids u128 JSON serialization quirks.
    Finished { scanned: usize, alive: usize, elapsed_ms: u64 },
    Error { message: String },
}

pub struct ScanHandle {
    cancel: CancellationToken,
}

impl ScanHandle {
    pub fn cancel(self) {
        self.cancel.cancel();
    }
}

pub fn start(options: ScanOptions, channel: Channel<ScanEvent>) -> Result<ScanHandle> {
    let cancel = CancellationToken::new();
    let cancel_child = cancel.clone();

    tokio::spawn(async move {
        if let Err(e) = run_scan(options, channel.clone(), cancel_child).await {
            let _ = channel.send(ScanEvent::Error { message: e.to_string() });
        }
    });

    Ok(ScanHandle { cancel })
}

fn parse_targets(spec: &str) -> Result<Vec<Ipv4Addr>> {
    let spec = spec.trim();
    // CIDR
    if let Ok(net) = Ipv4Net::from_str(spec) {
        return Ok(net.hosts().collect());
    }
    // Range a.b.c.d-e or a.b.c.d-a.b.c.e
    if let Some((lo, hi)) = spec.split_once('-') {
        let lo: Ipv4Addr = lo.trim().parse().context("invalid range start")?;
        let hi: Ipv4Addr = if hi.contains('.') {
            hi.trim().parse().context("invalid range end")?
        } else {
            let last: u8 = hi.trim().parse().context("invalid range end byte")?;
            let oct = lo.octets();
            Ipv4Addr::new(oct[0], oct[1], oct[2], last)
        };
        let (lo_u, hi_u) = (u32::from(lo), u32::from(hi));
        if hi_u < lo_u {
            return Err(anyhow!("range end < start"));
        }
        return Ok((lo_u..=hi_u).map(Ipv4Addr::from).collect());
    }
    // Single IP
    let ip: Ipv4Addr = spec.parse().context("invalid target")?;
    Ok(vec![ip])
}

async fn run_scan(
    options: ScanOptions,
    channel: Channel<ScanEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    let started = std::time::Instant::now();
    let timeout = Duration::from_millis(options.probe_timeout_ms);
    let targets = parse_targets(&options.target)?;
    let total = targets.len();

    let _ = channel.send(ScanEvent::Started {
        total,
        target: options.target.clone(),
    });

    // Initialize shared resources
    let pinger = Arc::new(Pinger::new().context("failed to init ICMP pinger — on Linux, the binary needs CAP_NET_RAW (sudo setcap cap_net_raw+ep ./super-ip-scanner) or be run as root")?);
    let resolver = Arc::new(HostnameResolver::new(timeout)?);

    // ARP sweep (local subnet only — needs a source IP on the same L2 segment)
    let mut arp_map = std::collections::HashMap::new();
    if options.use_arp {
        if let Some(src) = options.source_ip.as_ref().and_then(|s| s.parse::<Ipv4Addr>().ok()) {
            let arp_targets: Vec<Ipv4Addr> = targets.iter().copied().filter(|&t| t != src).collect();
            match arp::sweep(src, arp_targets, Duration::from_millis(800)).await {
                Ok(map) => arp_map = map,
                Err(e) => tracing::warn!("ARP sweep failed: {e}"),
            }
        }
    }

    // Per-host probing
    let extra_ports: Vec<u16> = options.tcp_ports.clone();
    let mut ports: Vec<u16> = tcp::COMMON_PROBE_PORTS.to_vec();
    ports.extend(extra_ports);
    ports.sort_unstable();
    ports.dedup();
    let ports = Arc::new(ports);

    let sem = Arc::new(Semaphore::new(options.concurrency));
    let mut futs = FuturesUnordered::new();

    let scanned = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let alive = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for (i, ip) in targets.iter().copied().enumerate() {
        let permit_owner = sem.clone();
        let pinger = pinger.clone();
        let resolver = resolver.clone();
        let ports = ports.clone();
        let cancel = cancel.clone();
        let arp_mac = arp_map.get(&ip).cloned();
        let channel = channel.clone();
        let scanned = scanned.clone();
        let alive = alive.clone();
        let opts = options.clone();

        futs.push(async move {
            if cancel.is_cancelled() {
                return;
            }
            let _permit = match permit_owner.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };

            let mut host = HostResult::new(ip.to_string());

            // ARP hit?
            if let Some(mac) = arp_mac {
                host.status = HostStatus::Alive;
                host.via.push("arp".into());
                host.vendor = lookup_oui_vendor(&mac);
                host.mac = Some(mac);
            }

            // ICMP
            if opts.use_icmp {
                let ident: u16 = ((i as u16).wrapping_add(1)) | 0x8000;
                if let Some(rtt) = pinger.ping(IpAddr::V4(ip), timeout, ident).await {
                    host.status = HostStatus::Alive;
                    host.rtt_ms = Some(rtt);
                    host.via.push("icmp".into());
                }
            }

            // TCP probe (also a liveness signal — firewalled hosts may respond)
            if opts.use_tcp_probe {
                let open = tcp::scan_ports(IpAddr::V4(ip), &ports, timeout).await;
                if !open.is_empty() {
                    host.status = HostStatus::Alive;
                    if !host.via.contains(&"tcp".to_string()) {
                        host.via.push("tcp".into());
                    }
                }
                host.open_ports = open;
            }

            // Hostname resolution — only for alive hosts to avoid wasted DNS load.
            if opts.resolve_hostnames && host.status == HostStatus::Alive {
                host.hostname = resolver.resolve(IpAddr::V4(ip)).await;
            }

            if host.status == HostStatus::Alive {
                alive.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                host.status = HostStatus::Dead;
            }
            let n = scanned.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

            let _ = channel.send(ScanEvent::HostUpdate { host });
            if n % 16 == 0 || n == total {
                let _ = channel.send(ScanEvent::Progress {
                    scanned: n,
                    alive: alive.load(std::sync::atomic::Ordering::Relaxed),
                });
            }
        });
    }

    while futs.next().await.is_some() {
        if cancel.is_cancelled() {
            break;
        }
    }

    let _ = channel.send(ScanEvent::Finished {
        scanned: scanned.load(std::sync::atomic::Ordering::Relaxed),
        alive: alive.load(std::sync::atomic::Ordering::Relaxed),
        elapsed_ms: started.elapsed().as_millis() as u64,
    });

    Ok(())
}
