use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

/// Common ports used both for liveness probing and to enrich host info.
pub const COMMON_PROBE_PORTS: &[u16] = &[80, 443, 22, 445, 3389, 139, 21, 8080];

pub async fn probe_port(ip: IpAddr, port: u16, t: Duration) -> bool {
    let addr = SocketAddr::new(ip, port);
    matches!(timeout(t, TcpStream::connect(addr)).await, Ok(Ok(_)))
}

/// Returns the list of open ports out of `ports`, scanned concurrently.
pub async fn scan_ports(ip: IpAddr, ports: &[u16], t: Duration) -> Vec<u16> {
    use futures::stream::{FuturesUnordered, StreamExt};
    let mut futs = FuturesUnordered::new();
    for &p in ports {
        futs.push(async move {
            if probe_port(ip, p, t).await {
                Some(p)
            } else {
                None
            }
        });
    }
    let mut open = Vec::new();
    while let Some(r) = futs.next().await {
        if let Some(p) = r {
            open.push(p);
        }
    }
    open.sort_unstable();
    open
}
