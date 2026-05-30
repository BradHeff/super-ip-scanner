use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    Alive,
    Dead,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: String,
    pub status: HostStatus,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub rtt_ms: Option<f64>,
    pub open_ports: Vec<u16>,
    /// Method that flagged the host alive: "arp" | "icmp" | "tcp" | "nbns" | "mdns"
    pub via: Vec<String>,
}

impl HostResult {
    pub fn new(ip: String) -> Self {
        Self {
            ip,
            status: HostStatus::Unknown,
            hostname: None,
            mac: None,
            vendor: None,
            rtt_ms: None,
            open_ports: Vec::new(),
            via: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetIface {
    pub name: String,
    pub description: String,
    pub mac: Option<String>,
    pub ipv4: Vec<String>,
    pub is_loopback: bool,
    pub is_up: bool,
}
