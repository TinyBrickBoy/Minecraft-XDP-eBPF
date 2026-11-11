//! Userspace side of the unused address drop (see xdp/unused.h).

use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::Pod;
use aya::maps::{Array, MapData, PerCpuHashMap};
use log::{info, warn};

use crate::addr::Net;
use crate::config::{Config, parse_cidr};

/// Userspace mirror of `struct unused_network`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UnusedNetwork {
    addr: u32,
    mask: u32,
    valid: u32,
    pad: u32,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for UnusedNetwork {}

impl UnusedNetwork {
    /// A network as address/mask in network byte order (shared by
    /// unused_networks and ratelimit_networks).
    pub fn new(addr: std::net::Ipv4Addr, len: u8) -> Self {
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        Self { addr: (u32::from(addr) & mask).to_be(), mask: mask.to_be(), valid: 1, pad: 0 }
    }
}

/// The array slots for a network list. The kernel stops at the first empty
/// slot, so skipped (IPv6) entries must not leave gaps.
pub fn network_slots(section: &str, networks: &[String]) -> Result<Vec<UnusedNetwork>> {
    let mut slots = Vec::new();
    for network in networks {
        let Net { addr: IpAddr::V4(addr), len } = parse_cidr(network)? else {
            warn!("{section} networks: IPv6 network '{network}' ignored, IPv6 not supported yet");
            continue;
        };
        slots.push(UnusedNetwork::new(addr, len));
    }
    Ok(slots)
}

/// Userspace mirror of `struct unused_stats`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UnusedStats {
    pub packets: u64,
    pub bytes: u64,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for UnusedStats {}

/// Destination address (network byte order) -> per cpu statistics.
pub type StatsMap = PerCpuHashMap<MapData, u32, UnusedStats>;

pub fn addr(key: u32) -> Ipv4Addr {
    Ipv4Addr::from(key.to_ne_bytes())
}

/// Writes the configured networks into the kernel. Returns the statistics
/// map when the drop is enabled.
pub fn setup(ebpf: &mut Ebpf, config: &Config) -> Result<Option<StatsMap>> {
    if !config.unused.enabled {
        return Ok(None);
    }
    let mut networks: Array<MapData, UnusedNetwork> = Array::try_from(
        ebpf.take_map("unused_networks")
            .context("can't take map 'unused_networks'")?,
    )?;
    for (index, slot) in network_slots("[unused]", &config.unused.networks)?.iter().enumerate() {
        networks.set(index as u32, *slot, 0)?;
    }
    info!(
        "Dropping traffic to unrouted addresses of {:?}",
        config.unused.networks
    );
    let stats = PerCpuHashMap::try_from(
        ebpf.take_map("unused_stats")
            .context("can't take map 'unused_stats'")?,
    )?;
    Ok(Some(stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_ipv6_networks_leave_no_gap() {
        let nets = ["2001:db8::/48".to_string(), "10.0.0.0/24".to_string()];
        let slots = network_slots("[test]", &nets).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].valid, 1);
        assert_eq!(slots[0].addr, u32::from(Ipv4Addr::new(10, 0, 0, 0)).to_be());
    }
}
