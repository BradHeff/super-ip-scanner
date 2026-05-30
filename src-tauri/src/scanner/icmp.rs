use std::net::IpAddr;
use std::time::Duration;

use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, ICMP};

pub struct Pinger {
    client_v4: Client,
}

impl Pinger {
    pub fn new() -> anyhow::Result<Self> {
        let config_v4 = Config::builder().kind(ICMP::V4).build();
        let client_v4 = Client::new(&config_v4)?;
        Ok(Self { client_v4 })
    }

    /// Sends a single ICMP echo and waits up to `timeout` for a reply.
    /// Returns `Some(rtt_ms)` on success.
    pub async fn ping(&self, ip: IpAddr, timeout: Duration, ident: u16) -> Option<f64> {
        let client = match ip {
            IpAddr::V4(_) => &self.client_v4,
            IpAddr::V6(_) => return None, // v6 unsupported for now
        };
        let payload = [0u8; 32];
        let mut pinger = client.pinger(ip, PingIdentifier(ident)).await;
        pinger.timeout(timeout);
        match pinger.ping(PingSequence(0), &payload).await {
            Ok((IcmpPacket::V4(_), dur)) => Some(dur.as_secs_f64() * 1000.0),
            _ => None,
        }
    }
}
