//! Userspace side of the unused address drop (see xdp/unused.h).

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::Pod;
use aya::maps::{Array, MapData, PerCpuHashMap};
use log::info;

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
    for (index, network) in config.unused.networks.iter().enumerate() {
        let (addr, len) = parse_cidr(network)?;
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        let entry = UnusedNetwork {
            addr: (u32::from(addr) & mask).to_be(),
            mask: mask.to_be(),
            valid: 1,
            pad: 0,
        };
        networks.set(index as u32, entry, 0)?;
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
