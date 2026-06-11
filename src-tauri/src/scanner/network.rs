use std::net::IpAddr;

use anyhow::Result;

use crate::commands::DetectedSubnet;
use crate::scanner::types::NetIface;

pub fn list_interfaces() -> Result<Vec<NetIface>> {
    let mut out = Vec::new();
    for ifc in default_net::get_interfaces() {
        let ipv4 = ifc
            .ipv4
            .iter()
            .map(|n| n.addr.to_string())
            .collect::<Vec<_>>();
        out.push(NetIface {
            name: ifc.name.clone(),
            description: ifc.friendly_name.clone().unwrap_or_else(|| ifc.name.clone()),
            mac: ifc.mac_addr.map(|m| m.to_string()),
            ipv4,
            is_loopback: ifc.ipv4.iter().any(|n| n.addr.is_loopback()),
            is_up: ifc.flags & 1 != 0, // IFF_UP
        });
    }
    Ok(out)
}

/// Detect the user's most likely local subnets — non-loopback, IPv4, with a default gateway.
pub fn detect_local_subnets() -> Result<Vec<DetectedSubnet>> {
    let mut out = Vec::new();
    for ifc in default_net::get_interfaces() {
        for n in &ifc.ipv4 {
            let addr = n.addr;
            if addr.is_loopback() || addr.is_link_local() || addr.is_unspecified() {
                continue;
            }
            // Build CIDR from prefix length
            let prefix = n.prefix_len;
            let cidr = format!("{}/{}", addr, prefix);
            let gateway = ifc
                .gateway
                .as_ref()
                .and_then(|g| match g.ip_addr {
                    IpAddr::V4(v4) => Some(v4.to_string()),
                    _ => None,
                });
            out.push(DetectedSubnet {
                iface_name: ifc.friendly_name.clone().unwrap_or_else(|| ifc.name.clone()),
                cidr,
                gateway,
            });
        }
    }
    Ok(out)
}
