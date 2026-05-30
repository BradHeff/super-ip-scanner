//! ARP-based host discovery for the local subnet.
//!
//! Two backends share a single async API:
//! - **Windows**: `SendARP` from `iphlpapi.dll` — no Npcap/WinPcap dependency. The OS
//!   sends the ARP request on our behalf and waits for a reply, then returns the MAC.
//!   Each call blocks the calling thread, so we fan them out across the tokio blocking pool.
//! - **Unix**: raw `pnet` datalink channel — we build the L2 frame ourselves and read
//!   replies off the same socket. Requires `CAP_NET_RAW` (or root).
//!
//! Both honour an outer timeout. The Windows API caps at its own internal ~3 s timeout
//! per call; we limit overall scan length with `tokio::time::timeout` on the sweep.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;

/// Performs an ARP sweep across the given target IPs. Returns IP→MAC map (lowercase, colon-separated).
pub async fn sweep(
    src_ip: Ipv4Addr,
    targets: Vec<Ipv4Addr>,
    duration: Duration,
) -> Result<HashMap<Ipv4Addr, String>> {
    platform::sweep(src_ip, targets, duration).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows: SendARP fan-out
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(windows)]
mod platform {
    use super::*;
    use futures::stream::{FuturesUnordered, StreamExt};
    use windows::Win32::NetworkManagement::IpHelper::SendARP;

    fn mac_to_string(b: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }

    fn send_arp_once(dest: Ipv4Addr, src: Ipv4Addr) -> Option<String> {
        // SendARP expects network-byte-order IPs.
        let dest_n = u32::from_ne_bytes(dest.octets());
        let src_n = u32::from_ne_bytes(src.octets());
        let mut mac_buf = [0u32; 2];
        let mut len: u32 = 6;
        let result =
            unsafe { SendARP(dest_n, src_n, mac_buf.as_mut_ptr() as *mut _, &mut len) };
        if result == 0 && len >= 6 {
            let bytes: [u8; 8] = unsafe { std::mem::transmute(mac_buf) };
            let mut out = [0u8; 6];
            out.copy_from_slice(&bytes[..6]);
            // SendARP returns 00:00:00:00:00:00 in odd cases — treat as miss.
            if out.iter().all(|&b| b == 0) {
                return None;
            }
            Some(mac_to_string(&out))
        } else {
            None
        }
    }

    pub async fn sweep(
        src_ip: Ipv4Addr,
        targets: Vec<Ipv4Addr>,
        duration: Duration,
    ) -> Result<HashMap<Ipv4Addr, String>> {
        let mut futs = FuturesUnordered::new();
        for target in targets {
            futs.push(tokio::task::spawn_blocking(move || {
                (target, send_arp_once(target, src_ip))
            }));
        }
        let mut out = HashMap::new();
        let sweep_fut = async {
            while let Some(res) = futs.next().await {
                if let Ok((ip, Some(mac))) = res {
                    out.insert(ip, mac);
                }
            }
        };
        let _ = tokio::time::timeout(duration.saturating_add(Duration::from_secs(2)), sweep_fut).await;
        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unix: raw datalink with pnet
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(unix)]
mod platform {
    use super::*;
    use anyhow::anyhow;
    use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::{MutablePacket, Packet};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn build_arp_request(src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> [u8; 42] {
        let mut buf = [0u8; 42];
        {
            let mut eth = MutableEthernetPacket::new(&mut buf[..]).unwrap();
            eth.set_destination(MacAddr::broadcast());
            eth.set_source(src_mac);
            eth.set_ethertype(EtherTypes::Arp);
            let payload = eth.payload_mut();
            let mut arp = MutableArpPacket::new(payload).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Request);
            arp.set_sender_hw_addr(src_mac);
            arp.set_sender_proto_addr(src_ip);
            arp.set_target_hw_addr(MacAddr::zero());
            arp.set_target_proto_addr(target_ip);
        }
        buf
    }

    fn find_interface(src_ip: Ipv4Addr) -> Option<NetworkInterface> {
        datalink::interfaces().into_iter().find(|i| {
            i.ips.iter().any(|n| match n.ip() {
                std::net::IpAddr::V4(v4) => v4 == src_ip,
                _ => false,
            })
        })
    }

    pub async fn sweep(
        src_ip: Ipv4Addr,
        targets: Vec<Ipv4Addr>,
        duration: Duration,
    ) -> Result<HashMap<Ipv4Addr, String>> {
        let iface = find_interface(src_ip)
            .ok_or_else(|| anyhow!("no datalink interface matches source IP {src_ip}"))?;
        let src_mac = iface
            .mac
            .ok_or_else(|| anyhow!("interface {} has no MAC", iface.name))?;

        let results: Arc<Mutex<HashMap<Ipv4Addr, String>>> = Arc::new(Mutex::new(HashMap::new()));
        let results_writer = results.clone();

        let iface_clone = iface.clone();
        let handle = tokio::task::spawn_blocking(move || -> Result<()> {
            let (mut tx, mut rx) = match datalink::channel(&iface_clone, Default::default())? {
                Channel::Ethernet(tx, rx) => (tx, rx),
                _ => return Err(anyhow!("unsupported datalink channel")),
            };

            for target in &targets {
                let frame = build_arp_request(src_mac, src_ip, *target);
                tx.send_to(&frame, None)
                    .ok_or_else(|| anyhow!("send_to returned None"))??;
            }

            let deadline = std::time::Instant::now() + duration;
            while std::time::Instant::now() < deadline {
                match rx.next() {
                    Ok(packet) => {
                        let Some(eth) = EthernetPacket::new(packet) else { continue };
                        if eth.get_ethertype() != EtherTypes::Arp {
                            continue;
                        }
                        let Some(arp) = ArpPacket::new(eth.payload()) else { continue };
                        if arp.get_operation() != ArpOperations::Reply {
                            continue;
                        }
                        let ip = arp.get_sender_proto_addr();
                        let mac = arp.get_sender_hw_addr().to_string();
                        if let Ok(mut g) = results_writer.try_lock() {
                            g.insert(ip, mac);
                        }
                    }
                    Err(_) => break,
                }
            }
            Ok(())
        });

        let _ = handle.await?;
        let final_map = std::mem::take(&mut *results.lock().await);
        Ok(final_map)
    }
}
