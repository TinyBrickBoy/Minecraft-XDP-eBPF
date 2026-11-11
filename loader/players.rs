//! Players per server: counts the verified connections in
//! `player_connection_map` that were active recently, per destination.
//!
//! A verified connection is a completed login (java) or RakNet session
//! (bedrock); status pings never get there. The eBPF program removes an entry
//! only after the idle timeout, so a disconnected player would stay counted
//! for minutes. Instead a connection counts as long as its packet counter
//! moved within `ACTIVE_WINDOW`: clients send at least a keep alive answer
//! every 15 s, bedrock clients far more often.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use aya::Pod;
use aya::maps::{HashMap as BpfHashMap, MapData};
use log::debug;
use prometheus::{IntGauge, IntGaugeVec, register_int_gauge, register_int_gauge_vec};

use crate::addr::Addr6;
use crate::targets::Targets;

/// A connection without new packets for this long is no longer counted.
const ACTIVE_WINDOW: Duration = Duration::from_secs(30);

/// Userspace mirror of `struct flow_key` (xdp/common.h), network byte order.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    src: Addr6,
    dst: Addr6,
    src_port: u16,
    dst_port: u16,
}
// SAFETY: repr(C) struct of plain integers without padding (16 + 16 + 2 + 2).
unsafe impl Pod for FlowKey {}
const _: () = assert!(std::mem::size_of::<FlowKey>() == 36);

/// Userspace mirror of `struct player_entry` (xdp/minecraft_filter.c). The
/// bpf_timer is opaque (the kernel zeroes it when copying to userspace).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PlayerEntry {
    timer: [u64; 2],
    packets: u64,
    last_packets: u64,
    idle_ns: u64,
}
// SAFETY: repr(C) struct of plain u64 fields without padding.
unsafe impl Pod for PlayerEntry {}
const _: () = assert!(std::mem::size_of::<PlayerEntry>() == 40);

pub type PlayerMap = BpfHashMap<MapData, FlowKey, PlayerEntry>;

static PLAYERS: LazyLock<(IntGaugeVec, IntGauge, IntGauge)> = LazyLock::new(|| {
    (
        register_int_gauge_vec!(
            "minecraft_target_players",
            "Active player connections per server (verified, packets within the last 30 s)",
            &["dst_ip", "dst_port", "proto", "kind"]
        )
        .unwrap(),
        register_int_gauge!("minecraft_players", "Active player connections on all protected servers").unwrap(),
        register_int_gauge!(
            "minecraft_player_connections_tracked",
            "Entries in the verified connection table (including idle ones until their timeout)"
        )
        .unwrap(),
    )
});

/// Remembers the last packet counter of every connection between polls.
#[derive(Default)]
pub struct Tracker {
    seen: HashMap<FlowKey, (u64, Instant)>,
}

impl Tracker {
    /// Reads the connection table once and republishes the gauges.
    pub fn publish(&mut self, map: &PlayerMap, targets: &Targets) {
        let now = Instant::now();
        let mut current: HashMap<FlowKey, (u64, Instant)> = HashMap::with_capacity(self.seen.len());
        let mut per_dst: HashMap<(Addr6, u16), i64> = HashMap::new();
        for entry in map.iter() {
            let Ok((key, value)) = entry else {
                continue; // removed by the idle timer mid-iteration
            };
            let changed = match self.seen.get(&key) {
                Some(&(packets, at)) if packets == value.packets => at,
                _ => now, // new connection or new packets
            };
            current.insert(key, (value.packets, changed));
            if now.duration_since(changed) <= ACTIVE_WINDOW {
                *per_dst.entry((key.dst, key.dst_port)).or_default() += 1;
            }
        }
        self.seen = current;

        // proto and kind of every destination from the protected targets
        let mut kinds: HashMap<(Addr6, u16), (&'static str, &'static str)> = HashMap::new();
        for (key, kind, _source) in targets.snapshot() {
            let k = (key.ip(), key.port().to_be());
            kinds.entry(k).or_insert((key.proto_name(), kind.name()));
        }

        let (gauge, total, tracked) = &*PLAYERS;
        gauge.reset();
        // every protected server gets a value, also with 0 players
        for (&(ip, port), &(proto, kind)) in &kinds {
            let n = per_dst.get(&(ip, port)).copied().unwrap_or(0);
            set(gauge, ip, port, proto, kind, n);
        }
        // adopted connections of servers that are no longer protected
        for (&(ip, port), &n) in &per_dst {
            if !kinds.contains_key(&(ip, port)) {
                set(gauge, ip, port, "", "", n);
            }
        }
        total.set(per_dst.values().sum());
        tracked.set(self.seen.len() as i64);
        debug!("Players: {} active, {} tracked", total.get(), self.seen.len());
    }
}

fn set(gauge: &IntGaugeVec, ip: Addr6, port: u16, proto: &str, kind: &str, n: i64) {
    let ip = ip.to_string();
    let port = u16::from_be(port).to_string();
    gauge.with_label_values(&[&ip, &port, proto, kind]).set(n);
}

#[cfg(test)]
mod tests {
    #[test]
    fn flow_key_layout() {
        assert_eq!(std::mem::size_of::<super::FlowKey>(), 36);
    }
}
