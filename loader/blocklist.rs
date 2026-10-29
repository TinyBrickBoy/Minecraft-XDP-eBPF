//! Userspace side of the source blocklist and the per source rate limit
//! (see xdp/blocklist.h).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::Pod;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray};
use log::{info, warn};
use serde::{Deserialize, Serialize};

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
    /// 1 = packet rate, 2 = repeated violations (`enum ban_reason`)
    pub reason: u64,
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
    pub strike_bans: u64,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for BlockStats {}

/// Userspace mirror of `struct dns_verdict`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DnsVerdict {
    pub checked_ns: u64,
    pub has_server: u64,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for DnsVerdict {}

/// Userspace mirror of `struct dns_query`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DnsQuery {
    pub dst: u32,
    pub pad: u32,
    pub last_ns: u64,
    pub count: u64,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for DnsQuery {}

/// Blocklist map values (`enum block_scope`).
const BLOCK_ALL: u8 = 1;
const BLOCK_PROTECTED: u8 = 2;

/// Userspace mirror of `struct source_stats`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct SourceStats {
    pub packets: u64,
    pub bytes: u64,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for SourceStats {}

type BanMap = BpfHashMap<MapData, u32, Ban>;
pub type SourceMap = aya::maps::PerCpuHashMap<MapData, u32, SourceStats>;
pub type StatsMap = PerCpuArray<MapData, BlockStats>;

/// What the metrics need from this module.
pub struct Handles {
    /// Packets/bytes per blocklisted source, refreshed by the blocklist thread.
    pub sources: Arc<Mutex<HashMap<Ipv4Addr, SourceStats>>>,
    pub stats: StatsMap,
    pub entries: Arc<AtomicUsize>,
    pub auto_entries: Arc<AtomicUsize>,
    /// Active automatic bans, refreshed by the blocklist thread.
    pub bans: Arc<Mutex<Vec<(Ipv4Addr, Ban)>>>,
}

fn key_of(net: (Ipv4Addr, u8)) -> Key<u32> {
    let (addr, len) = net;
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Key::new(len as u32, (u32::from(addr) & mask).to_be())
}

fn contains(net: (Ipv4Addr, u8), ip: Ipv4Addr) -> bool {
    let mask = if net.1 == 0 { 0 } else { u32::MAX << (32 - net.1) };
    u32::from(ip) & mask == u32::from(net.0) & mask
}

/// Parses blocklist lines: one address or prefix per line, `#` comments.
/// Invalid lines are reported and skipped, they never block everything.
#[cfg(test)]
pub fn parse_list(text: &str, origin: &str) -> HashSet<(Ipv4Addr, u8)> {
    parse_scoped(text, origin).into_keys().collect()
}

/// Like parse_list, with the scope of every entry: automatic lines only
/// block traffic to the protected networks, manual lines everything (a
/// manual line wins over an automatic one for the same entry).
fn parse_scoped(text: &str, origin: &str) -> HashMap<(Ipv4Addr, u8), u8> {
    let mut out: HashMap<(Ipv4Addr, u8), u8> = HashMap::new();
    for (no, raw) in text.lines().enumerate() {
        // anything this program wrote only concerns the protected networks
        let scope = if raw.contains(AUTO_TAG) { BLOCK_PROTECTED } else { BLOCK_ALL };
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match parse_cidr(line) {
            Ok((addr, len)) => {
                let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
                let entry = out.entry((Ipv4Addr::from(u32::from(addr) & mask), len)).or_insert(scope);
                *entry = (*entry).min(scope);
            }
            Err(e) => warn!("{origin}:{}: ignoring invalid entry '{line}': {e:#}", no + 1),
        }
    }
    out
}

/// Marker of lines this program writes; only those are ever removed by it.
const AUTO_MARK: &str = "# auto until=";
/// Every automatically written line contains this.
const AUTO_TAG: &str = "# auto";

/// An entry for a DNS scanner, expiring like the other automatic entries.
fn dns_line(ip: Ipv4Addr, dst: Ipv4Addr, until: u64) -> String {
    format!("{ip}   {AUTO_MARK}{until} ({}) dns-scan: queried {dst}:53 without a DNS server", local_time(until))
}

/// True if `dst` answers a DNS query on udp/53 (any answer, also REFUSED).
fn probe_dns(dst: Ipv4Addr, timeout: Duration) -> bool {
    let result = (|| -> std::io::Result<bool> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(timeout))?;
        socket.connect((dst, 53))?;
        // id 0x5a5a, recursion desired, one question: ". IN NS"
        let query = [0x5a, 0x5a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x02, 0x00, 0x01];
        socket.send(&query)?;
        let mut buf = [0u8; 512];
        let len = socket.recv(&mut buf)?;
        Ok(len >= 12 && buf[0] == 0x5a && buf[1] == 0x5a)
    })();
    result.unwrap_or(false)
}

/// The expiry (unix seconds) of an automatically written line.
fn auto_until(line: &str) -> Option<u64> {
    let rest = &line[line.find(AUTO_MARK)? + AUTO_MARK.len()..];
    rest.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

fn local_time(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

fn auto_line(ip: Ipv4Addr, until: u64, bans: usize) -> String {
    format!("{ip}   {AUTO_MARK}{until} ({}) after {bans} rate limit bans", local_time(until))
}

/// The address of a line, if it is a single address.
fn line_ip(line: &str) -> Option<Ipv4Addr> {
    line.split('#').next()?.trim().split('/').next()?.parse().ok()
}

/// Removes expired automatic lines and automatic lines of `idle` sources
/// from `text`, appends `add`; manual lines are kept byte for byte. Returns
/// None when nothing changes.
fn rewrite(text: &str, now: u64, add: &[String], idle: &HashSet<Ipv4Addr>) -> Option<String> {
    let mut changed = !add.is_empty();
    let mut out: Vec<&str> = Vec::new();
    for line in text.lines() {
        if let Some(until) = auto_until(line) {
            if until <= now || line_ip(line).is_some_and(|ip| idle.contains(&ip)) {
                changed = true;
                continue;
            }
        }
        out.push(line);
    }
    if !changed {
        return None;
    }
    let mut text: String = out.join("\n");
    for line in add {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(line);
    }
    text.push('\n');
    Some(text)
}

/// Escalation of repeated rate limit bans to blocklist entries.
#[derive(Default, Serialize, Deserialize)]
struct History {
    /// unix seconds of the bans per source within the window
    bans: HashMap<Ipv4Addr, Vec<u64>>,
}

struct Auto {
    after_bans: usize,
    window: u64,
    duration: u64,
    allow: Vec<(Ipv4Addr, u8)>,
    state: PathBuf,
    history: History,
    /// ban start (ktime) already counted per source
    counted: HashMap<Ipv4Addr, u64>,
}

impl Auto {
    /// Counts new bans; returns the sources that reached `after_bans`.
    fn record(&mut self, active: &[(Ipv4Addr, Ban)], now: u64) -> Vec<(Ipv4Addr, usize)> {
        let mut escalate = Vec::new();
        let mut changed = false;
        for (ip, ban) in active {
            if self.counted.get(ip) == Some(&ban.since_ns) {
                continue;
            }
            self.counted.insert(*ip, ban.since_ns);
            if self.allow.iter().any(|net| contains(*net, *ip)) {
                continue;
            }
            let times = self.history.bans.entry(*ip).or_default();
            times.push(now);
            times.retain(|t| now - *t < self.window);
            changed = true;
            if times.len() >= self.after_bans {
                escalate.push((*ip, times.len()));
                self.history.bans.remove(ip);
            }
        }
        self.counted.retain(|ip, _| active.iter().any(|(a, _)| a == ip));
        let before = self.history.bans.len();
        self.history.bans.retain(|_, times| {
            times.retain(|t| now - *t < self.window);
            !times.is_empty()
        });
        if changed || before != self.history.bans.len() {
            self.save();
        }
        escalate
    }

    fn load(&mut self) {
        if let Ok(text) = std::fs::read_to_string(&self.state) {
            match serde_json::from_str(&text) {
                Ok(history) => self.history = history,
                Err(e) => warn!("Ignoring unreadable {}: {e}", self.state.display()),
            }
        }
    }

    fn save(&self) {
        let tmp = self.state.with_extension("tmp");
        let result = serde_json::to_string(&self.history)
            .map_err(anyhow::Error::from)
            .and_then(|json| Ok(std::fs::write(&tmp, json)?))
            .and_then(|()| Ok(std::fs::rename(&tmp, &self.state)?));
        if let Err(e) = result {
            warn!("Can't save {}: {e:#}", self.state.display());
        }
    }
}

/// Fills the rate limit networks and allowlist, starts the thread that keeps
/// the blocklist map in sync with the config and the blocklist file, follows
/// the automatic bans and escalates repeated ones onto the blocklist.
pub fn setup(ebpf: &mut Ebpf, config: &Config, shutdown: &Arc<Shutdown>) -> Result<(Option<Handles>, Option<JoinHandle<()>>)> {
    let rl = &config.ratelimit;
    let mut allow_nets = Vec::new();
    for entry in &rl.allow {
        allow_nets.push(parse_cidr(entry)?);
    }
    // the protected networks: used by the rate limit, the scope of automatic
    // entries and the DNS scan detection
    if rl.mode != ProtectionMode::Off || (config.blocklist.enabled && !rl.networks.is_empty()) {
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
    }
    if rl.mode != ProtectionMode::Off {
        let mut allow: LpmTrie<MapData, u32, u8> = LpmTrie::try_from(
            ebpf.take_map("ratelimit_allow").context("can't take map 'ratelimit_allow'")?,
        )?;
        for net in &allow_nets {
            allow.insert(&key_of(*net), 1, 0)?;
        }
        info!(
            "Rate limit ({:?}): > {} packets/s per source to {:?} -> ban for {} s, {} allowlisted",
            rl.mode, rl.pps, rl.networks, rl.ban_secs, rl.allow.len()
        );
    }

    let bl = &config.blocklist;
    let list = if bl.enabled {
        let map: LpmTrie<MapData, u32, u8> =
            LpmTrie::try_from(ebpf.take_map("blocklist").context("can't take map 'blocklist'")?)?;
        let size: Array<MapData, u64> =
            Array::try_from(ebpf.take_map("blocklist_size").context("can't take map 'blocklist_size'")?)?;
        Some((map, size))
    } else {
        None
    };
    let dns = if bl.enabled && bl.dns_scan && !rl.networks.is_empty() {
        let verdicts: BpfHashMap<MapData, u32, DnsVerdict> =
            BpfHashMap::try_from(ebpf.take_map("dns_verdicts").context("can't take map 'dns_verdicts'")?)?;
        let queries: BpfHashMap<MapData, u32, DnsQuery> =
            BpfHashMap::try_from(ebpf.take_map("dns_queries").context("can't take map 'dns_queries'")?)?;
        info!(
            "DNS scan detection: sources querying protected addresses without a DNS server are blocklisted for {} s (verdict cached {} s)",
            bl.auto_duration_secs, bl.dns_recheck_secs
        );
        Some(Dns {
            verdicts,
            queries,
            cache: HashMap::new(),
            recheck: bl.dns_recheck_secs,
            duration: bl.auto_duration_secs,
        })
    } else {
        None
    };
    let auto = (bl.enabled && bl.auto && rl.mode == ProtectionMode::Enforce).then(|| {
        let mut auto = Auto {
            after_bans: bl.auto_after_bans as usize,
            window: bl.auto_window_secs,
            duration: bl.auto_duration_secs,
            allow: allow_nets.clone(),
            state: PathBuf::from(&bl.auto_state_file),
            history: History::default(),
            counted: HashMap::new(),
        };
        auto.load();
        info!(
            "Auto blocklist: {} bans within {} s -> blocklisted for {} s",
            bl.auto_after_bans, bl.auto_window_secs, bl.auto_duration_secs
        );
        auto
    });

    let source_map: SourceMap = aya::maps::PerCpuHashMap::try_from(
        ebpf.take_map("blocked_sources").context("can't take map 'blocked_sources'")?,
    )?;
    let handles = Handles {
        sources: Arc::new(Mutex::new(HashMap::new())),
        stats: PerCpuArray::try_from(ebpf.take_map("block_stats").context("can't take map 'block_stats'")?)?,
        entries: Arc::new(AtomicUsize::new(0)),
        auto_entries: Arc::new(AtomicUsize::new(0)),
        bans: Arc::new(Mutex::new(Vec::new())),
    };
    let bans: BanMap =
        BpfHashMap::try_from(ebpf.take_map("ratelimit_bans").context("can't take map 'ratelimit_bans'")?)?;

    let mut worker = Worker {
        list,
        bans,
        source_map,
        sources: handles.sources.clone(),
        idle_secs: bl.auto_idle_secs,
        activity: HashMap::new(),
        static_entries: parse_scoped(&bl.entries.join("\n"), "[blocklist] entries"),
        file: PathBuf::from(&bl.file),
        auto,
        dns,
        allow: allow_nets.clone(),
        ban_secs: rl.ban_secs,
        entries: handles.entries.clone(),
        auto_entries: handles.auto_entries.clone(),
        snapshot: handles.bans.clone(),
        current: HashMap::new(),
        last_mtime: None,
        logged: HashMap::new(),
    };
    let interval = Duration::from_secs(bl.reload_secs);
    let shutdown = shutdown.clone();
    let thread = thread::Builder::new().name("blocklist".into()).spawn(move || {
        let mut first = true;
        loop {
            worker.tick(first);
            first = false;
            if !shutdown.sleep(interval) {
                return;
            }
        }
    })?;
    Ok((Some(handles), Some(thread)))
}

struct Worker {
    list: Option<(LpmTrie<MapData, u32, u8>, Array<MapData, u64>)>,
    bans: BanMap,
    source_map: SourceMap,
    sources: Arc<Mutex<HashMap<Ipv4Addr, SourceStats>>>,
    /// automatic entries are removed after this long without a packet (0 = never)
    idle_secs: u64,
    /// per automatic entry: packet count when it last changed, and when
    activity: HashMap<Ipv4Addr, (u64, u64)>,
    static_entries: HashMap<(Ipv4Addr, u8), u8>,
    file: PathBuf,
    auto: Option<Auto>,
    dns: Option<Dns>,
    allow: Vec<(Ipv4Addr, u8)>,
    ban_secs: u64,
    entries: Arc<AtomicUsize>,
    auto_entries: Arc<AtomicUsize>,
    snapshot: Arc<Mutex<Vec<(Ipv4Addr, Ban)>>>,
    current: HashMap<(Ipv4Addr, u8), u8>,
    last_mtime: Option<SystemTime>,
    logged: HashMap<Ipv4Addr, u64>,
}

impl Worker {
    fn tick(&mut self, first: bool) {
        // automatic bans: log new ones, publish them, escalate repeated ones
        let active = active_bans(&self.bans, crate::targets::monotonic_ns());
        log_new_bans(&active, &mut self.logged, self.ban_secs);
        let now = unix_now();
        let mut add = Vec::new();
        if let Some(auto) = &mut self.auto {
            for (ip, bans) in auto.record(&active, now) {
                if self.current.keys().any(|net| contains(*net, ip)) {
                    continue; // already blocked, manually or automatically
                }
                warn!("Auto blocklist: {ip} banned {bans} times, blocklisted for {} s", auto.duration);
                add.push(auto_line(ip, now + auto.duration, bans));
            }
        }
        *self.snapshot.lock().unwrap_or_else(|e| e.into_inner()) = active;

        // DNS scanners: probe unknown destinations, blocklist their sources
        if let Some(dns) = &mut self.dns {
            for (src, dst) in dns.process(now) {
                if self.allow.iter().any(|net| contains(*net, src))
                    || self.current.keys().any(|net| contains(*net, src))
                    || add.iter().any(|l| line_ip(l) == Some(src))
                {
                    continue;
                }
                warn!("DNS scan: {src} queried {dst}:53 where no DNS server runs, blocklisted for {} s", dns.duration);
                add.push(dns_line(src, dst, now + dns.duration));
            }
        }

        // per source counters of blocklisted addresses
        let mut sources = HashMap::new();
        for entry in self.source_map.iter() {
            let Ok((ip, per_cpu)) = entry else { continue };
            let mut total = SourceStats::default();
            for s in per_cpu.iter() {
                total.packets += s.packets;
                total.bytes += s.bytes;
            }
            sources.insert(Ipv4Addr::from(ip.to_ne_bytes()), total);
        }

        if self.list.is_none() {
            *self.sources.lock().unwrap_or_else(|e| e.into_inner()) = sources;
            return;
        }
        // expire automatic lines (time limit, or no packet for idle_secs),
        // append new ones; manual lines are never touched
        let text = std::fs::read_to_string(&self.file).unwrap_or_default();
        let mut idle = HashSet::new();
        let mut listed = HashSet::new();
        for line in text.lines().filter(|l| auto_until(l).is_some()) {
            let Some(ip) = line_ip(line) else { continue };
            listed.insert(ip);
            let packets = sources.get(&ip).map(|s| s.packets).unwrap_or(0);
            let seen = self.activity.entry(ip).or_insert((packets, now));
            if seen.0 != packets {
                *seen = (packets, now);
            } else if self.idle_secs > 0 && now - seen.1 >= self.idle_secs {
                info!("Auto blocklist: {ip} sent nothing for {} s, unblocked", self.idle_secs);
                idle.insert(ip);
            }
        }
        self.activity.retain(|ip, _| listed.contains(ip) && !idle.contains(ip));
        *self.sources.lock().unwrap_or_else(|e| e.into_inner()) = sources;
        if let Some(new_text) = rewrite(&text, now, &add, &idle) {
            let tmp = self.file.with_extension("tmp");
            let written = std::fs::write(&tmp, &new_text).and_then(|()| std::fs::rename(&tmp, &self.file));
            if let Err(e) = written {
                warn!("Can't update blocklist {}: {e}", self.file.display());
            }
        }
        self.sync(first);
    }

    /// Re-reads the blocklist file when it changed and applies the difference.
    fn sync(&mut self, force: bool) {
        let mtime = std::fs::metadata(&self.file).and_then(|m| m.modified()).ok();
        if !force && mtime == self.last_mtime {
            return;
        }
        self.last_mtime = mtime;
        let Some((map, size)) = &mut self.list else { return };
        let mut wanted = self.static_entries.clone();
        let mut auto = 0;
        match std::fs::read_to_string(&self.file) {
            Ok(text) => {
                for (net, scope) in parse_scoped(&text, &self.file.display().to_string()) {
                    let entry = wanted.entry(net).or_insert(scope);
                    *entry = (*entry).min(scope);
                }
                auto = text.lines().filter(|l| l.contains(AUTO_TAG)).count();
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("Can't read blocklist {}: {e}", self.file.display()),
        }
        let (mut added, mut removed) = (0, 0);
        let gone: Vec<_> = self.current.keys().filter(|n| !wanted.contains_key(n)).copied().collect();
        for net in gone {
            if map.remove(&key_of(net)).is_ok() {
                self.current.remove(&net);
                removed += 1;
            }
        }
        for (net, scope) in wanted {
            if self.current.get(&net) == Some(&scope) {
                continue;
            }
            match map.insert(&key_of(net), scope, 0) {
                Ok(()) => {
                    if self.current.insert(net, scope).is_none() {
                        added += 1;
                    }
                }
                Err(e) => warn!("Can't block {}/{}: {e}", net.0, net.1),
            }
        }
        if added + removed > 0 {
            info!("Blocklist: {added} added, {removed} removed, {} active", self.current.len());
        }
        self.entries.store(self.current.len(), Ordering::Relaxed);
        self.auto_entries.store(auto, Ordering::Relaxed);
        // lets the kernel skip the trie entirely while the list is empty
        if let Err(e) = size.set(0, self.current.len() as u64, 0) {
            warn!("Can't update blocklist size: {e}");
        }
    }
}

/// Probing state of the DNS scan detection.
struct Dns {
    verdicts: BpfHashMap<MapData, u32, DnsVerdict>,
    queries: BpfHashMap<MapData, u32, DnsQuery>,
    /// destination -> (has a DNS server, unix time of the probe)
    cache: HashMap<Ipv4Addr, (bool, u64)>,
    recheck: u64,
    /// how long a scanner stays blocklisted
    duration: u64,
}

impl Dns {
    /// Consumes the noted queries; returns (source, destination) for every
    /// query to a destination without a DNS server. A destination is probed
    /// at most once per `recheck` seconds, and only while queries come in.
    fn process(&mut self, now: u64) -> Vec<(Ipv4Addr, Ipv4Addr)> {
        let noted: Vec<(u32, DnsQuery)> = self.queries.iter().filter_map(|e| e.ok()).collect();
        let mut found = Vec::new();
        let mut probes = 0;
        for (src_raw, q) in noted {
            let _ = self.queries.remove(&src_raw);
            let (src, dst) = (Ipv4Addr::from(src_raw.to_ne_bytes()), Ipv4Addr::from(q.dst.to_ne_bytes()));
            let has_server = match self.cache.get(&dst) {
                Some(&(has, at)) if now < at + self.recheck => has,
                _ => {
                    if probes >= 32 {
                        continue; // the rest waits for the next round
                    }
                    probes += 1;
                    let has = probe_dns(dst, Duration::from_millis(1500));
                    self.cache.insert(dst, (has, now));
                    let verdict = DnsVerdict { checked_ns: crate::targets::monotonic_ns(), has_server: has as u64 };
                    if let Err(e) = self.verdicts.insert(q.dst, verdict, 0) {
                        warn!("Can't store DNS verdict for {dst}: {e}");
                    }
                    if has {
                        info!("DNS scan: {dst} runs a DNS server, queries to it are fine");
                    }
                    has
                }
            };
            if !has_server {
                found.push((src, dst));
            }
        }
        let recheck = self.recheck;
        self.cache.retain(|_, (_, at)| now < *at + recheck);
        found
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Active bans (src, ban), already expired ones left out.
pub fn active_bans(bans: &BanMap, now_ns: u64) -> Vec<(Ipv4Addr, Ban)> {
    bans.iter()
        .filter_map(|e| e.ok())
        .filter(|(_, b)| b.until_ns > now_ns)
        .map(|(ip, b)| (Ipv4Addr::from(ip.to_ne_bytes()), b))
        .collect()
}

/// Logs bans that were not seen before.
pub fn log_new_bans(active: &[(Ipv4Addr, Ban)], seen: &mut HashMap<Ipv4Addr, u64>, ban_secs: u64) {
    for (ip, ban) in active {
        if seen.get(ip) != Some(&ban.since_ns) {
            if ban.reason == 2 {
                warn!("Rate limit: banned {ip} for {ban_secs} s ({} violations: unused addresses, invalid handshakes)", ban.rate);
            } else {
                warn!("Rate limit: banned {ip} for {ban_secs} s ({} packets in one second)", ban.rate);
            }
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
        let scoped = parse_scoped(&format!("9.9.9.9\n{}\n", auto_line(Ipv4Addr::new(8, 8, 8, 8), 1, 2)), "test");
        assert_eq!(scoped[&(Ipv4Addr::new(9, 9, 9, 9), 32)], BLOCK_ALL);
        assert_eq!(scoped[&(Ipv4Addr::new(8, 8, 8, 8), 32)], BLOCK_PROTECTED);
        let set = parse_list("# comment\n89.244.93.224\n\n5.6.7.8/16 # a range\nnot-an-ip\n", "test");
        assert!(set.contains(&(Ipv4Addr::new(89, 244, 93, 224), 32)));
        assert!(set.contains(&(Ipv4Addr::new(5, 6, 0, 0), 16))); // masked
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn auto_lines_expire_and_manual_lines_stay() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let line = auto_line(ip, 1000, 3);
        assert_eq!(auto_until(&line), Some(1000));
        assert!(parse_list(&line, "t").contains(&(ip, 32)));
        let text = format!("# header\n9.9.9.9 # manual, until=5\n{line}\n");
        // not expired yet: unchanged
        assert!(rewrite(&text, 999, &[], &HashSet::new()).is_none());
        // expired: only the auto line goes
        let out = rewrite(&text, 1000, &[], &HashSet::new()).unwrap();
        assert!(out.contains("9.9.9.9 # manual, until=5") && out.contains("# header") && !out.contains("1.2.3.4"));
        // appending keeps everything
        let out = rewrite("9.9.9.9\n", 0, &[auto_line(ip, 50, 3)], &HashSet::new()).unwrap();
        assert!(out.starts_with("9.9.9.9\n1.2.3.4"));
        // idle sources lose their automatic line, never a manual one
        let idle: HashSet<Ipv4Addr> = [ip, Ipv4Addr::new(9, 9, 9, 9)].into();
        let out = rewrite(&text, 999, &[], &idle).unwrap();
        assert!(out.contains("9.9.9.9") && !out.contains("1.2.3.4"));
    }

    #[test]
    fn escalates_after_repeated_bans_only() {
        let dir = std::env::temp_dir().join(format!("xdp-auto-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut auto = Auto {
            after_bans: 3,
            window: 100,
            duration: 50,
            allow: vec![(Ipv4Addr::new(10, 0, 0, 0), 8)],
            state: dir.join("state.json"),
            history: History::default(),
            counted: HashMap::new(),
        };
        let bad = Ipv4Addr::new(1, 2, 3, 4);
        let allowed = Ipv4Addr::new(10, 1, 1, 1);
        let ban = |since| Ban { until_ns: u64::MAX, since_ns: since, rate: 9999, dropped: 1, reason: 1 };
        for (i, now) in [(1u64, 10u64), (2, 20)] {
            assert!(auto.record(&[(bad, ban(i)), (allowed, ban(i))], now).is_empty());
        }
        // the same ban seen again does not count twice
        assert!(auto.record(&[(bad, ban(2))], 25).is_empty());
        assert_eq!(auto.record(&[(bad, ban(3)), (allowed, ban(3))], 30), vec![(bad, 3)]);
        // bans spread wider than the window never escalate
        for (i, now) in [(10u64, 1000u64), (11, 1200), (12, 1400)] {
            assert!(auto.record(&[(bad, ban(i))], now).is_empty());
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
