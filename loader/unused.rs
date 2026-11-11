//! Userspace side of the unused address drop (see xdp/unused.h).

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::Pod;
use aya::maps::{Array, MapData, PerCpuHashMap};
use log::info;

use crate::addr::{Addr6, Net};
use crate::config::{Config, parse_cidr};

/// Userspace mirror of `struct unused_network`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UnusedNetwork {
    pub addr: Addr6,
    pub mask: Addr6,
    valid: u32,
    pad: u32,
}
// SAFETY: repr(C) struct of plain integers without padding (16 + 16 + 4 + 4).
unsafe impl Pod for UnusedNetwork {}

impl UnusedNetwork {
    /// A network as masked address + mask (shared by unused_networks and
    /// ratelimit_networks).
    pub fn new(net: &Net) -> Self {
        Self { addr: net.addr6(), mask: net.mask6(), valid: 1, pad: 0 }
    }
}

/// The array slots for a network list, dense: the kernel stops at the first
/// empty slot.
pub fn network_slots(_section: &str, networks: &[String]) -> Result<Vec<UnusedNetwork>> {
    networks.iter().map(|network| Ok(UnusedNetwork::new(&parse_cidr(network)?))).collect()
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

/// Destination address -> per cpu statistics.
pub type StatsMap = PerCpuHashMap<MapData, Addr6, UnusedStats>;

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
    fn unused_network_layout() {
        assert_eq!(std::mem::size_of::<UnusedNetwork>(), 40);
        let n = UnusedNetwork::new(&parse_cidr("10.1.2.3/24").unwrap());
        assert_eq!(n.addr.to_string(), "10.1.2.0");
        assert_eq!(n.mask.0[..12], [0xff; 12]);
        assert_eq!(n.mask.0[12..], [0xff, 0xff, 0xff, 0]);
        let n = UnusedNetwork::new(&parse_cidr("2001:db8::/32").unwrap());
        assert_eq!(n.mask.0[..4], [0xff; 4]);
        assert_eq!(n.mask.0[4..], [0; 12]);
    }

    #[test]
    fn mixed_networks_fill_dense_slots() {
        let nets = ["2001:db8::/48".to_string(), "10.0.0.0/24".to_string()];
        let slots = network_slots("[test]", &nets).unwrap();
        assert_eq!(slots.len(), 2);
        assert!(slots.iter().all(|s| s.valid == 1));
        assert_eq!(slots[0].addr.to_string(), "2001:db8::");
        assert_eq!(slots[1].addr.to_string(), "10.0.0.0");
    }
}
