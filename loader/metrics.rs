use std::sync::{Arc, LazyLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray, PerCpuHashMap};
use aya::{Ebpf, Pod};
use log::{debug, error, info};
use prometheus::{
    Encoder, IntCounter, IntCounterVec, IntGaugeVec, TextEncoder, register_int_counter,
    register_int_counter_vec, register_int_gauge_vec,
};

use crate::config::Config;
use crate::shutdown::Shutdown;
use crate::reflection::{self, StatsMap as ReflectionStatsMap};
use crate::targets::{DstKey, Targets};
use crate::blocklist;
use crate::unused::{self, StatsMap as UnusedStatsMap};

/// Optional statistics maps of the network wide protections.
pub struct Extra {
    pub reflection: Option<ReflectionStatsMap>,
    pub unused: Option<UnusedStatsMap>,
    pub blocklist: Option<blocklist::Handles>,
}

/// Defines the userspace mirror of `struct statistics` (see xdp/stats.h)
/// together with one Prometheus counter per field, so the struct layout, the
/// per-cpu summing and the published metrics all stay in sync from a single
/// field list. Field order and types must match the C struct exactly.
macro_rules! statistics {
    ($($field:ident => $metric:literal, $dst_metric:literal, $help:literal;)+) => {
        #[repr(C)]
        #[derive(Copy, Clone, Debug, Default)]
        pub struct Statistics {
            $(pub $field: u64,)+
        }

        // SAFETY: repr(C) struct of plain u64 fields without padding, valid
        // for any bit pattern read from the map.
        unsafe impl Pod for Statistics {}

        impl Statistics {
            fn add(&mut self, other: &Statistics) {
                $(self.$field += other.$field;)+
            }
        }

        struct Counters {
            $($field: IntCounter,)+
        }

        impl Counters {
            fn new() -> Self {
                Self {
                    $($field: register_int_counter!($metric, $help).unwrap(),)+
                }
            }

            /// Publishes cumulative map totals as counter increments. The
            /// unpinned stats map and this process always die together, so
            /// publishing the delta since the last poll keeps proper counter
            /// semantics; on restart both reset together, which Prometheus
            /// handles as a regular counter reset.
            fn publish(&self, total: &Statistics) {
                $(self.$field.inc_by(total.$field.saturating_sub(self.$field.get()));)+
            }
        }

        /// Same counters as `Counters`, labelled per destination ip:port.
        struct DstCounters {
            $($field: IntCounterVec,)+
        }

        impl DstCounters {
            fn new() -> Self {
                Self {
                    $($field: register_int_counter_vec!(
                        $dst_metric,
                        concat!($help, " per destination ip:port"),
                        &["dst_ip", "dst_port", "proto"]
                    ).unwrap(),)+
                }
            }

            /// Like `Counters::publish`. An entry evicted from the LRU map
            /// restarts at 0; saturating_sub keeps the counter monotonic.
            fn publish(&self, labels: &[&str], total: &Statistics) {
                $(
                    let counter = self.$field.with_label_values(labels);
                    counter.inc_by(total.$field.saturating_sub(counter.get()));
                )+
            }
        }
    };
}

statistics! {
    verified        => "minecraft_verified_connections", "minecraft_target_verified_connections", "Total verified connections";
    dropped_packets => "minecraft_dropped_packets", "minecraft_target_dropped_packets", "Total dropped packets";
    state_switches  => "minecraft_state_switches", "minecraft_target_state_switches", "Total state switches";
    drop_connection => "minecraft_dropped_connections", "minecraft_target_dropped_connections", "Total dropped connections";
    syn             => "minecraft_syn_packets", "minecraft_target_syn_packets", "Total SYN packets";
    tcp_bypass      => "minecraft_tcp_bypass", "minecraft_target_tcp_bypass", "Total TCP bypass attempts";
    incoming_bytes  => "minecraft_incoming_bytes", "minecraft_target_incoming_bytes", "Total incoming bytes";
    dropped_bytes   => "minecraft_dropped_bytes", "minecraft_target_dropped_bytes", "Total dropped bytes";
    adopted         => "minecraft_adopted_connections", "minecraft_target_adopted_connections", "Total connections adopted during a grace window";
}

// compile-time layout check, mirrors the _Static_assert in xdp/stats.h
const _: () = assert!(std::mem::size_of::<Statistics>() == 72);

static COUNTERS: LazyLock<Counters> = LazyLock::new(Counters::new);
static DST_COUNTERS: LazyLock<DstCounters> = LazyLock::new(DstCounters::new);
static REFLECTION: LazyLock<(IntCounterVec, IntCounterVec)> = LazyLock::new(|| {
    let labels = &["dst_ip", "src_port", "service"];
    (
        register_int_counter_vec!(
            "xdp_reflection_packets",
            "UDP reflection packets (dropped when enforcing, only counted when monitoring)",
            labels
        )
        .unwrap(),
        register_int_counter_vec!("xdp_reflection_bytes", "UDP reflection bytes", labels).unwrap(),
    )
});
static UNUSED: LazyLock<(IntCounterVec, IntCounterVec)> = LazyLock::new(|| {
    (
        register_int_counter_vec!(
            "xdp_unused_packets",
            "Packets dropped because their destination has no route",
            &["dst_ip"]
        )
        .unwrap(),
        register_int_counter_vec!(
            "xdp_unused_bytes",
            "Bytes dropped because their destination has no route",
            &["dst_ip"]
        )
        .unwrap(),
    )
});
static BLOCK: LazyLock<[IntCounter; 6]> = LazyLock::new(|| {
    [
        register_int_counter!("xdp_blocklist_dropped_packets", "Packets dropped by the manual blocklist").unwrap(),
        register_int_counter!("xdp_blocklist_dropped_bytes", "Bytes dropped by the manual blocklist").unwrap(),
        register_int_counter!("xdp_ratelimit_banned_packets", "Packets of banned sources (dropped when enforcing)").unwrap(),
        register_int_counter!("xdp_ratelimit_banned_bytes", "Bytes of banned sources").unwrap(),
        register_int_counter!("xdp_ratelimit_bans", "Automatic bans issued for the packet rate").unwrap(),
        register_int_counter!("xdp_ratelimit_strike_bans", "Automatic bans issued for repeated violations").unwrap(),
    ]
});
static BLOCK_GAUGES: LazyLock<(prometheus::IntGauge, prometheus::IntGauge, IntGaugeVec)> = LazyLock::new(|| {
    (
        prometheus::register_int_gauge!("xdp_blocklist_entries", "Active blocklist entries (manual and automatic)").unwrap(),
        prometheus::register_int_gauge!("xdp_ratelimit_active_bans", "Currently banned sources").unwrap(),
        register_int_gauge_vec!("xdp_ratelimit_ban", "Packets dropped per currently banned source (top 200)", &["src_ip"]).unwrap(),
    )
});
static AUTO_ENTRIES: LazyLock<prometheus::IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!("xdp_blocklist_auto_entries", "Blocklist entries written automatically after repeated bans").unwrap()
});
static BLOCKED_SOURCES: LazyLock<(IntCounterVec, IntCounterVec)> = LazyLock::new(|| {
    (
        register_int_counter_vec!("xdp_blocklist_source_packets", "Packets per blocklisted source address", &["src_ip"]).unwrap(),
        register_int_counter_vec!("xdp_blocklist_source_bytes", "Bytes per blocklisted source address", &["src_ip"]).unwrap(),
    )
});
static TARGET_INFO: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "minecraft_target_protected",
        "1 for every protected (or explicitly excluded, kind=none) destination",
        &["dst_ip", "dst_port", "proto", "kind", "source"]
    )
    .unwrap()
});

/// Starts the metrics machinery if enabled in the config: takes ownership of
/// the stats map, spawns the polling thread and (when an address is
/// configured) the HTTP endpoint. Returns the polling thread's handle.
pub fn start(
    ebpf: &mut Ebpf,
    config: &Config,
    targets: Arc<Targets>,
    extra: Extra,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<JoinHandle<()>>> {
    if !config.metrics.enabled {
        return Ok(None);
    }

    let map = ebpf
        .take_map("stats_map")
        .context("can't take map 'stats_map'")?;
    let stats = PerCpuArray::try_from(map)?;
    let dst_map = ebpf
        .take_map("dst_stats_map")
        .context("can't take map 'dst_stats_map'")?;
    let dst_stats = PerCpuHashMap::try_from(dst_map)?;

    match &config.metrics.addr {
        Some(addr) => serve_http(addr.clone()),
        None => info!("Metrics collection enabled but no addr set; HTTP endpoint disabled"),
    }

    let poll_interval = Duration::from_secs(config.metrics.poll_secs);
    let shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("track-stats".into())
        .spawn(move || {
            poll_loop(stats, dst_stats, targets, extra, shutdown, poll_interval)
        })?;
    Ok(Some(handle))
}

/// Sums the per-cpu slices of the stats map and publishes the totals every
/// `poll_interval` until shutdown ends the loop. Read errors are logged and
/// retried next interval: metrics are auxiliary and must never take down the
/// filter itself.
fn poll_loop(
    stats: PerCpuArray<MapData, Statistics>,
    dst_stats: PerCpuHashMap<MapData, DstKey, Statistics>,
    targets: Arc<Targets>,
    extra: Extra,
    shutdown: Arc<Shutdown>,
    poll_interval: Duration,
) {
    loop {
        match stats.get(&0, 0) {
            Ok(per_cpu) => {
                let mut total = Statistics::default();
                for cpu_stats in per_cpu.iter() {
                    total.add(cpu_stats);
                }
                debug!("Stats: {total:?}");
                COUNTERS.publish(&total);
            }
            Err(e) => {
                error!("Failed to read stats map (retrying next interval): {e}");
            }
        }
        publish_dst_stats(&dst_stats);
        publish_targets(&targets);
        if let Some(map) = &extra.reflection {
            publish_reflection(map);
        }
        if let Some(map) = &extra.unused {
            publish_unused(map);
        }
        if let Some(handles) = &extra.blocklist {
            publish_block(handles);
        }
        if !shutdown.sleep(poll_interval) {
            return;
        }
    }
}

/// Sums and publishes every entry of the per destination ip:port map.
fn publish_dst_stats(dst_stats: &PerCpuHashMap<MapData, DstKey, Statistics>) {
    for entry in dst_stats.iter() {
        match entry {
            Ok((key, per_cpu)) => {
                let mut total = Statistics::default();
                for cpu_stats in per_cpu.iter() {
                    total.add(cpu_stats);
                }
                let addr = key.addr();
                let (ip, port) = (addr.ip().to_string(), addr.port().to_string());
                DST_COUNTERS.publish(&[&ip, &port, key.proto_name()], &total);
            }
            Err(e) => {
                // keys can vanish mid-iteration through LRU eviction
                debug!("Failed to read dst stats entry: {e}");
            }
        }
    }
}

/// Sums and publishes the reflection statistics per victim and source port.
fn publish_reflection(map: &ReflectionStatsMap) {
    let (packets, bytes) = &*REFLECTION;
    for entry in map.iter() {
        let Ok((key, per_cpu)) = entry else {
            continue; // evicted mid-iteration
        };
        let (mut total_packets, mut total_bytes) = (0u64, 0u64);
        for stats in per_cpu.iter() {
            total_packets += stats.packets;
            total_bytes += stats.bytes;
        }
        let (ip, port) = (key.daddr().to_string(), key.sport().to_string());
        let labels = [ip.as_str(), port.as_str(), reflection::service_name(key.sport())];
        let counter = packets.with_label_values(&labels);
        counter.inc_by(total_packets.saturating_sub(counter.get()));
        let counter = bytes.with_label_values(&labels);
        counter.inc_by(total_bytes.saturating_sub(counter.get()));
    }
}

/// Publishes the blocklist and rate limit counters, current bans, and logs
/// newly banned sources.
fn publish_block(h: &blocklist::Handles) {
    if let Ok(per_cpu) = h.stats.get(&0, 0) {
        let mut t = blocklist::BlockStats::default();
        for s in per_cpu.iter() {
            t.blocklist_packets += s.blocklist_packets;
            t.blocklist_bytes += s.blocklist_bytes;
            t.banned_packets += s.banned_packets;
            t.banned_bytes += s.banned_bytes;
            t.bans += s.bans;
            t.strike_bans += s.strike_bans;
        }
        for (counter, total) in BLOCK.iter().zip([t.blocklist_packets, t.blocklist_bytes, t.banned_packets, t.banned_bytes, t.bans, t.strike_bans]) {
            counter.inc_by(total.saturating_sub(counter.get()));
        }
    }
    let (src_packets, src_bytes) = &*BLOCKED_SOURCES;
    let sources = h.sources.lock().unwrap_or_else(|e| e.into_inner()).clone();
    for (ip, s) in sources {
        let (p, b) = (s.packets, s.bytes);
        let ip = ip.to_string();
        let c = src_packets.with_label_values(&[&ip]);
        c.inc_by(p.saturating_sub(c.get()));
        let c = src_bytes.with_label_values(&[&ip]);
        c.inc_by(b.saturating_sub(c.get()));
    }
    let (entries, active, per_ip) = &*BLOCK_GAUGES;
    entries.set(h.entries.load(std::sync::atomic::Ordering::Relaxed) as i64);
    AUTO_ENTRIES.set(h.auto_entries.load(std::sync::atomic::Ordering::Relaxed) as i64);
    let mut bans = h.bans.lock().unwrap_or_else(|e| e.into_inner()).clone();
    active.set(bans.len() as i64);
    bans.sort_by(|a, b| b.1.dropped.cmp(&a.1.dropped));
    per_ip.reset();
    for (ip, ban) in bans.iter().take(200) {
        per_ip.with_label_values(&[&ip.to_string()]).set(ban.dropped as i64);
    }
}

/// Sums and publishes the unused address drops per destination.
fn publish_unused(map: &UnusedStatsMap) {
    let (packets, bytes) = &*UNUSED;
    for entry in map.iter() {
        let Ok((key, per_cpu)) = entry else {
            continue; // evicted mid-iteration
        };
        let (mut total_packets, mut total_bytes) = (0u64, 0u64);
        for stats in per_cpu.iter() {
            total_packets += stats.packets;
            total_bytes += stats.bytes;
        }
        let ip = unused::addr(key).to_string();
        let counter = packets.with_label_values(&[&ip]);
        counter.inc_by(total_packets.saturating_sub(counter.get()));
        let counter = bytes.with_label_values(&[&ip]);
        counter.inc_by(total_bytes.saturating_sub(counter.get()));
    }
}

/// Republishes the current target list (removed targets disappear).
fn publish_targets(targets: &Targets) {
    TARGET_INFO.reset();
    for (key, kind, source) in targets.snapshot() {
        let addr = key.addr();
        let (ip, port) = (addr.ip().to_string(), addr.port().to_string());
        TARGET_INFO
            .with_label_values(&[&ip, &port, key.proto_name(), kind.name(), source.name()])
            .set(1);
    }
}

/// Serves the Prometheus text endpoint on `addr` from its own thread.
fn serve_http(addr: String) {
    thread::spawn(move || {
        let server = match tiny_http::Server::http(&addr) {
            Ok(server) => server,
            Err(e) => {
                error!("Failed to start metrics server: {e}");
                return;
            }
        };
        info!("Prometheus metrics server running on {addr}/metrics");
        for request in server.incoming_requests() {
            if request.url() != "/metrics" {
                let _ = request.respond(tiny_http::Response::empty(404));
                continue;
            }
            debug!("Received metrics request from {:?}", request.remote_addr());
            let mut buffer = vec![];
            if let Err(e) = TextEncoder::new().encode(&prometheus::gather(), &mut buffer) {
                error!("Failed to encode metrics: {e}");
                continue;
            }
            let response = tiny_http::Response::from_data(buffer).with_header(
                tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"text/plain; version=0.0.4; charset=utf-8"[..],
                )
                .unwrap(),
            );
            let _ = request.respond(response);
        }
    });
}
