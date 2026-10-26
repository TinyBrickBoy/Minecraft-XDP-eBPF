//! Userspace side of the source blocklist and the per source rate limit
//! (see xdp/blocklist.h).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::Pod;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray};
use log::{info, warn};

use crate::config::{Config, ProtectionMode, parse_cidr};
use crate::shutdown::Shutdown;
use crate::unused::UnusedNetwork;

/// Userspace mirror of `struct ban`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Ban {
    pub until_ns: u64,
    pub since_ns: u64,
    pub rate: u64,
    pub dropped: u64,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for Ban {}

/// Userspace mirror of `struct block_stats`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct BlockStats {
    pub blocklist_packets: u64,
    pub blocklist_bytes: u64,
    pub banned_packets: u64,
    pub banned_bytes: u64,
    pub bans: u64,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for BlockStats {}

/// Userspace mirror of `struct source_stats`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct SourceStats {
    pub packets: u64,
    pub bytes: u64,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for SourceStats {}

pub type BanMap = BpfHashMap<MapData, u32, Ban>;
pub type SourceMap = aya::maps::PerCpuHashMap<MapData, u32, SourceStats>;
pub type StatsMap = PerCpuArray<MapData, BlockStats>;

/// What the metrics need from this module.
pub struct Handles {
    pub sources: SourceMap,
    pub bans: BanMap,
    pub stats: StatsMap,
    pub entries: Arc<std::sync::atomic::AtomicUsize>,
}

fn key_of(net: (Ipv4Addr, u8)) -> Key<u32> {
    let (addr, len) = net;
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Key::new(len as u32, (u32::from(addr) & mask).to_be())
}

/// Parses blocklist lines: one address or prefix per line, `#` comments.
/// Invalid lines are reported and skipped, they never block everything.
pub fn parse_list(text: &str, origin: &str) -> HashSet<(Ipv4Addr, u8)> {
    let mut out = HashSet::new();
    for (no, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match parse_cidr(line) {
            Ok((addr, len)) => {
                let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
                out.insert((Ipv4Addr::from(u32::from(addr) & mask), len));
            }
            Err(e) => warn!("{origin}:{}: ignoring invalid entry '{line}': {e:#}", no + 1),
        }
    }
    out
}

/// Fills the rate limit networks and allowlist, starts the thread that keeps
/// the blocklist map in sync with the config and the blocklist file, and
/// returns the maps the metrics read.
pub fn setup(ebpf: &mut Ebpf, config: &Config, shutdown: &Arc<Shutdown>) -> Result<(Option<Handles>, Option<JoinHandle<()>>)> {
    let rl = &config.ratelimit;
    if rl.mode != ProtectionMode::Off {
        if rl.networks.len() > 8 {
            anyhow::bail!("[ratelimit] supports at most 8 networks");
        }
        let mut networks: Array<MapData, UnusedNetwork> = Array::try_from(
            ebpf.take_map("ratelimit_networks").context("can't take map 'ratelimit_networks'")?,
        )?;
        for (index, network) in rl.networks.iter().enumerate() {
            let (addr, len) = parse_cidr(network)?;
            networks.set(index as u32, UnusedNetwork::new(addr, len), 0)?;
        }
        let mut allow: LpmTrie<MapData, u32, u8> = LpmTrie::try_from(
            ebpf.take_map("ratelimit_allow").context("can't take map 'ratelimit_allow'")?,
        )?;
        for entry in &rl.allow {
            allow.insert(&key_of(parse_cidr(entry)?), 1, 0)?;
        }
        info!(
            "Rate limit ({:?}): > {} packets/s per source to {:?} -> ban for {} s, {} allowlisted",
            rl.mode, rl.pps, rl.networks, rl.ban_secs, rl.allow.len()
        );
    }

    let entries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut thread = None;
    if config.blocklist.enabled {
        let map: LpmTrie<MapData, u32, u8> =
            LpmTrie::try_from(ebpf.take_map("blocklist").context("can't take map 'blocklist'")?)?;
        let size: Array<MapData, u64> =
            Array::try_from(ebpf.take_map("blocklist_size").context("can't take map 'blocklist_size'")?)?;
        let static_entries = parse_list(&config.blocklist.entries.join("\n"), "[blocklist] entries");
        let file = PathBuf::from(&config.blocklist.file);
        let interval = Duration::from_secs(config.blocklist.reload_secs);
        let (shutdown, entries) = (shutdown.clone(), entries.clone());
        thread = Some(thread::Builder::new().name("blocklist".into()).spawn(move || {
            sync_loop(map, size, static_entries, file, interval, entries, shutdown)
        })?);
    }

    let bans = BpfHashMap::try_from(ebpf.take_map("ratelimit_bans").context("can't take map 'ratelimit_bans'")?)?;
    let stats = PerCpuArray::try_from(ebpf.take_map("block_stats").context("can't take map 'block_stats'")?)?;
    let sources = aya::maps::PerCpuHashMap::try_from(
        ebpf.take_map("blocked_sources").context("can't take map 'blocked_sources'")?,
    )?;
    Ok((Some(Handles { sources, bans, stats, entries }), thread))
}

/// Re-reads the blocklist file whenever it changes and applies the difference.
fn sync_loop(
    mut map: LpmTrie<MapData, u32, u8>,
    mut size: Array<MapData, u64>,
    static_entries: HashSet<(Ipv4Addr, u8)>,
    file: PathBuf,
    interval: Duration,
    entries: Arc<std::sync::atomic::AtomicUsize>,
    shutdown: Arc<Shutdown>,
) {
    let mut current: HashSet<(Ipv4Addr, u8)> = HashSet::new();
    let mut last_mtime: Option<SystemTime> = None;
    let mut first = true;
    loop {
        let mtime = std::fs::metadata(&file).and_then(|m| m.modified()).ok();
        if first || mtime != last_mtime {
            first = false;
            last_mtime = mtime;
            let mut wanted = static_entries.clone();
            match std::fs::read_to_string(&file) {
                Ok(text) => wanted.extend(parse_list(&text, &file.display().to_string())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!("Can't read blocklist {}: {e}", file.display()),
            }
            let (mut added, mut removed) = (0, 0);
            for net in current.difference(&wanted).copied().collect::<Vec<_>>() {
                if map.remove(&key_of(net)).is_ok() {
                    current.remove(&net);
                    removed += 1;
                }
            }
            for net in wanted.difference(&current).copied().collect::<Vec<_>>() {
                match map.insert(&key_of(net), 1, 0) {
                    Ok(()) => {
                        current.insert(net);
                        added += 1;
                    }
                    Err(e) => warn!("Can't block {}/{}: {e}", net.0, net.1),
                }
            }
            if added + removed > 0 {
                info!("Blocklist: {added} added, {removed} removed, {} active", current.len());
            }
            entries.store(current.len(), std::sync::atomic::Ordering::Relaxed);
            // lets the kernel skip the trie entirely while the list is empty
            if let Err(e) = size.set(0, current.len() as u64, 0) {
                warn!("Can't update blocklist size: {e}");
            }
        }
        if !shutdown.sleep(interval) {
            return;
        }
    }
}

/// Active bans (src, ban), already expired ones left out.
pub fn active_bans(bans: &BanMap, now_ns: u64) -> Vec<(Ipv4Addr, Ban)> {
    bans.iter()
        .filter_map(|e| e.ok())
        .filter(|(_, b)| b.until_ns > now_ns)
        .map(|(ip, b)| (Ipv4Addr::from(ip.to_ne_bytes()), b))
        .collect()
}

/// Logs bans that were not seen before; returns the current set.
pub fn log_new_bans(active: &[(Ipv4Addr, Ban)], seen: &mut HashMap<Ipv4Addr, u64>, ban_secs: u64) {
    for (ip, ban) in active {
        if seen.get(ip) != Some(&ban.since_ns) {
            warn!("Rate limit: banned {ip} for {ban_secs} s ({} packets in one second)", ban.rate);
            seen.insert(*ip, ban.since_ns);
        }
    }
    seen.retain(|ip, _| active.iter().any(|(a, _)| a == ip));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_blocklist_lines() {
        let set = parse_list("# comment\n89.244.93.224\n\n5.6.7.8/16 # a range\nnot-an-ip\n", "test");
        assert!(set.contains(&(Ipv4Addr::new(89, 244, 93, 224), 32)));
        assert!(set.contains(&(Ipv4Addr::new(5, 6, 0, 0), 16))); // masked
        assert_eq!(set.len(), 2);
    }
}
