//! Multi-source hostname resolution.
//!
//! Order of attempts (each guarded by a short timeout, first hit wins):
//!  1. **OS-level reverse lookup** (`getnameinfo`) — on Windows this walks the full
//!     resolver chain: DNS → NetBT/WINS cache → LMHOSTS. Catches Windows hosts that
//!     hickory's pure-DNS path misses.
//!  2. **Hickory reverse DNS** — explicit PTR query against the configured resolvers.
//!     Useful when the OS resolver is misconfigured but DNS itself works.
//!  3. **NBNS (NetBIOS Name Service)** — direct UDP/137 NBSTAT query. This is what
//!     surfaces Windows hostnames on networks with no PTR records.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace};

pub struct HostnameResolver {
    dns: Arc<TokioAsyncResolver>,
    timeout: Duration,
}

impl HostnameResolver {
    pub fn new(timeout: Duration) -> anyhow::Result<Self> {
        #[cfg(any(unix, windows))]
        let dns = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        });
        #[cfg(not(any(unix, windows)))]
        let dns = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self { dns: Arc::new(dns), timeout })
    }

    /// Race all four resolvers in parallel. First non-empty result wins; the rest are
    /// cancelled. Whole call caps at ~`self.timeout` (one round of timeouts).
    /// `biased` makes priority deterministic when several finish in the same tick:
    /// OS > DNS > NBNS > mDNS (OS usually has the richest answer when it has one).
    pub async fn resolve(&self, ip: IpAddr) -> Option<String> {
        let t = self.timeout;
        let dns = self.dns.clone();

        let result: Option<(&'static str, String)> = if let IpAddr::V4(v4) = ip {
            tokio::select! {
                biased;
                Some(name) = os_reverse(ip, t)                  => Some(("os",   name)),
                Some(name) = hickory_reverse(dns.clone(), ip, t)=> Some(("dns",  name)),
                Some(name) = nbns_query(v4, t)                  => Some(("nbns", name)),
                Some(name) = mdns_reverse_query(v4, t)          => Some(("mdns", name)),
                else => None,
            }
        } else {
            tokio::select! {
                biased;
                Some(name) = os_reverse(ip, t)                  => Some(("os",  name)),
                Some(name) = hickory_reverse(dns.clone(), ip, t)=> Some(("dns", name)),
                else => None,
            }
        };

        match result {
            Some((via, name)) => {
                trace!("{ip} → {name} ({via})");
                Some(name)
            }
            None => {
                debug!("{ip} → no hostname (all sources empty)");
                None
            }
        }
    }
}

/// `getnameinfo` runs on the blocking pool because it's a sync libc call. The
/// `timeout` cancels our await; the blocking thread may keep running briefly
/// (acceptable — pool is large and these calls eventually finish).
async fn os_reverse(ip: IpAddr, t: Duration) -> Option<String> {
    let fut = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok());
    match timeout(t, fut).await.ok()? {
        Ok(Some(name)) if !name.is_empty() && name != ip.to_string() => Some(name),
        _ => None,
    }
}

async fn hickory_reverse(
    dns: Arc<TokioAsyncResolver>,
    ip: IpAddr,
    t: Duration,
) -> Option<String> {
    let fut = dns.reverse_lookup(ip);
    match timeout(t, fut).await.ok()? {
        Ok(resp) => resp
            .into_iter()
            .next()
            .map(|n| n.to_utf8().trim_end_matches('.').to_string())
            .filter(|s| !s.is_empty()),
        Err(_) => None,
    }
}

/// NetBIOS Name Service (NBNS) NBSTAT query against UDP 137.
/// Wire format is hand-rolled — there is no good Rust crate.
pub async fn nbns_query(ip: std::net::Ipv4Addr, t: Duration) -> Option<String> {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            debug!("nbns: bind failed: {e}");
            return None;
        }
    };
    let dest = SocketAddr::new(IpAddr::V4(ip), 137);

    let tx_id: u16 = rand::random();
    let mut pkt = Vec::with_capacity(50);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // standard unicast query
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    pkt.push(0x20); // name length
    // '*' (0x2A) → "CK"; NULL (0x00) → "AA" × 15
    pkt.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    pkt.push(0x00); // root
    pkt.extend_from_slice(&0x0021u16.to_be_bytes()); // QTYPE = NBSTAT
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS = IN

    if let Err(e) = socket.send_to(&pkt, dest).await {
        debug!("nbns {ip}: send failed: {e}");
        return None;
    }

    let mut buf = [0u8; 1024];
    let recv = match timeout(t, socket.recv_from(&mut buf)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            debug!("nbns {ip}: recv failed: {e}");
            return None;
        }
        Err(_) => {
            trace!("nbns {ip}: timeout");
            return None;
        }
    };
    let (n, from) = recv;
    if from.ip() != IpAddr::V4(ip) {
        trace!("nbns {ip}: response from unexpected address {from}");
        return None;
    }
    trace!("nbns {ip}: {n} bytes recv");
    parse_nbstat_response(&buf[..n])
}

/// Unicast mDNS reverse PTR query against UDP/5353 on the host directly.
/// Per RFC 6762 §5.5 — modern Bonjour/Avahi stacks answer direct unicast queries.
/// Catches Apple devices, most Linux desktops, and Bonjour-aware IoT gear.
pub async fn mdns_reverse_query(ip: std::net::Ipv4Addr, t: Duration) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let dest = SocketAddr::new(IpAddr::V4(ip), 5353);

    let oct = ip.octets();
    let qname = format!("{}.{}.{}.{}.in-addr.arpa", oct[3], oct[2], oct[1], oct[0]);

    let tx_id: u16 = rand::random();
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // standard query
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in qname.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&0x000Cu16.to_be_bytes()); // QTYPE = PTR
    pkt.extend_from_slice(&0x8001u16.to_be_bytes()); // QCLASS = IN | unicast-response

    if let Err(e) = socket.send_to(&pkt, dest).await {
        debug!("mdns {ip}: send failed: {e}");
        return None;
    }

    let mut buf = [0u8; 1500];
    let recv = match timeout(t, socket.recv_from(&mut buf)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            debug!("mdns {ip}: recv failed: {e}");
            return None;
        }
        Err(_) => {
            trace!("mdns {ip}: timeout");
            return None;
        }
    };
    let (n, from) = recv;
    if from.ip() != IpAddr::V4(ip) {
        return None;
    }
    parse_dns_ptr_response(&buf[..n])
}

/// Minimal DNS message parser — finds the first PTR answer's RDATA and decodes
/// the (possibly compressed) name. Handles the common Bonjour reply shape.
fn parse_dns_ptr_response(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(data, pos)?;
        pos = pos.checked_add(4)?; // QTYPE + QCLASS
    }
    for _ in 0..ancount {
        pos = skip_name(data, pos)?;
        if pos + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > data.len() {
            return None;
        }
        if rtype == 0x000C {
            // PTR record — RDATA is a domain name. Strip trailing `.local.`/`.` to be
            // friendly in the UI; keep the rest intact (e.g. `printer.local`).
            let name = read_name(data, pos)?;
            let cleaned = name.trim_end_matches('.').to_string();
            return Some(cleaned);
        }
        pos += rdlength;
    }
    None
}

fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    let mut hops = 0;
    loop {
        if pos >= data.len() || hops > 32 {
            return None;
        }
        let b = data[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            return Some(pos + 2); // pointer is always terminal
        }
        pos += 1 + (b as usize);
        hops += 1;
    }
}

fn read_name(data: &[u8], start: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut pos = start;
    let mut hops = 0;
    loop {
        if pos >= data.len() || hops > 32 {
            return None;
        }
        let b = data[pos];
        if b == 0 {
            break;
        }
        if b & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let next = (((b as usize) & 0x3F) << 8) | (data[pos + 1] as usize);
            if next >= data.len() {
                return None;
            }
            pos = next;
            hops += 1;
            continue;
        }
        let len = b as usize;
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

/// Parse an NBSTAT response. Tolerates both compressed and uncompressed answer names.
fn parse_nbstat_response(data: &[u8]) -> Option<String> {
    // Header is 12 bytes; after that comes the answer RR.
    if data.len() < 13 {
        return None;
    }
    let mut pos = 12;

    // Skip the answer name. Either a compression pointer (2 bytes, first byte 0xC0)
    // or a series of labels terminated by 0x00. Standard NBSTAT replies usually use
    // the uncompressed 34-byte form.
    if data[pos] & 0xC0 == 0xC0 {
        pos += 2;
    } else {
        while pos < data.len() && data[pos] != 0 {
            let len = data[pos] as usize;
            pos += 1 + len;
            if pos >= data.len() {
                return None;
            }
        }
        pos += 1; // skip the 0x00 terminator
    }

    // type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes; then NUM_NAMES(1).
    if pos + 11 > data.len() {
        return None;
    }
    pos += 10;
    let num_names = data[pos] as usize;
    pos += 1;

    if num_names == 0 || pos + num_names * 18 > data.len() {
        return None;
    }

    // First unique (non-group) name with the workstation/server suffix (0x00) is the
    // machine name shown in Network Neighborhood. Skip group entries and other types.
    for _ in 0..num_names {
        let raw = &data[pos..pos + 15];
        let name_type = data[pos + 15];
        let flags = u16::from_be_bytes([data[pos + 16], data[pos + 17]]);
        pos += 18;
        let is_group = flags & 0x8000 != 0;
        if name_type == 0x00 && !is_group {
            let name = String::from_utf8_lossy(raw)
                .trim_end_matches('\0')
                .trim()
                .to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}
