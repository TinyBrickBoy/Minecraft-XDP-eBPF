use std::collections::HashMap as StdHashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Mutex;

use anyhow::{Context, Result};
use aya::Pod;
use aya::maps::{HashMap, MapData, MapError};
use log::{info, warn};

use crate::addr::Addr6;

pub const PROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
pub const PROTO_UDP: u8 = libc::IPPROTO_UDP as u8;

/// Userspace mirror of `struct dst_key` (see xdp/stats.h), address in the
/// 128-bit form, port in network byte order.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct DstKey {
    daddr: Addr6,
    dport: u16,
    proto: u8,
    pad: u8,
}

// SAFETY: repr(C) struct of plain integers without padding (16 + 2 + 1 + 1),
// valid for any bit pattern read from the map.
unsafe impl Pod for DstKey {}

const _: () = assert!(std::mem::size_of::<DstKey>() == 20);

impl DstKey {
    pub fn new(addr: SocketAddr, proto: u8) -> Self {
        Self { daddr: Addr6::from_ip(addr.ip()), dport: addr.port().to_be(), proto, pad: 0 }
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.daddr.to_ip(), u16::from_be(self.dport))
    }

    pub fn ip(&self) -> Addr6 {
        self.daddr
    }

    pub fn port(&self) -> u16 {
        u16::from_be(self.dport)
    }

    pub fn proto(&self) -> u8 {
        self.proto
    }

    pub fn proto_name(&self) -> &'static str {
        match self.proto {
            PROTO_TCP => "tcp",
            PROTO_UDP => "udp",
            _ => "other",
        }
    }
}

impl fmt::Display for DstKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr(), self.proto_name())
    }
}

/// Userspace mirror of `struct target_entry` (see xdp/minecraft_filter.c).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TargetEntry {
    grace_until_ns: u64,
    online_until_ns: u64,
    kind: u8,
    pad: [u8; 7],
}

// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for TargetEntry {}

const _: () = assert!(std::mem::size_of::<TargetEntry>() == 24);

/// How a destination is protected, `enum target_kind` on the C side.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Explicitly unprotected, overrides the static java range.
    None = 0,
    Java = 1,
    Bedrock = 2,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::None => "none",
            Kind::Java => "java",
            Kind::Bedrock => "bedrock",
        }
    }

    /// The protocol a server of this kind listens on.
    pub fn proto(self) -> u8 {
        match self {
            Kind::Bedrock => PROTO_UDP,
            _ => PROTO_TCP,
        }
    }
}

/// Where a target entry comes from. Static entries and excludes from the
/// config always win over auto detection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Static,
    Exclude,
    Auto,
}

impl Source {
    pub fn name(self) -> &'static str {
        match self {
            Source::Static => "static",
            Source::Exclude => "exclude",
            Source::Auto => "auto",
        }
    }
}

/// The protected_targets map plus a userspace index of its entries. Every
/// change is written to the kernel immediately, so protection starts or ends
/// without reloading the program.
pub struct Targets {
    map: Mutex<HashMap<MapData, DstKey, TargetEntry>>,
    /// protected_addrs: addresses with at least one protecting entry
    addrs: Mutex<HashMap<MapData, Addr6, u8>>,
    entries: Mutex<StdHashMap<DstKey, (Kind, Source)>>,
    /// java targets seen in online mode, until when (ktime)
    online: Mutex<StdHashMap<DstKey, u64>>,
    grace_ns: u64,
}

impl Targets {
    pub fn new(map: HashMap<MapData, DstKey, TargetEntry>, addrs: HashMap<MapData, Addr6, u8>, grace_secs: u64) -> Self {
        Self {
            map: Mutex::new(map),
            addrs: Mutex::new(addrs),
            entries: Mutex::new(StdHashMap::new()),
            online: Mutex::new(StdHashMap::new()),
            grace_ns: grace_secs * 1_000_000_000,
        }
    }

    /// Protects `key` as `kind` (or excludes it with `Kind::None`). A newly
    /// protected target starts with a grace window in which established flows
    /// are adopted. Auto detection never overrides config entries.
    pub fn set(&self, key: DstKey, kind: Kind, source: Source) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(&(old_kind, old_source)) = entries.get(&key) {
            if source == Source::Auto && old_source != Source::Auto {
                return Ok(());
            }
            if old_kind == kind && old_source == source {
                // retries a protected_addrs update that failed earlier
                self.sync_addr(&entries, key.ip());
                return Ok(());
            }
        }
        let entry = TargetEntry {
            grace_until_ns: monotonic_ns() + self.grace_ns,
            online_until_ns: self.online.lock().unwrap().get(&key).copied().unwrap_or(0),
            kind: kind as u8,
            pad: [0; 7],
        };
        self.map
            .lock()
            .unwrap()
            .insert(key, entry, 0)
            .with_context(|| format!("failed to write target {key}"))?;
        info!("Target {key}: {} ({})", kind.name(), source.name());
        entries.insert(key, (kind, source));
        self.sync_addr(&entries, key.ip());
        Ok(())
    }

    /// Keeps `protected_addrs` equal to the set of addresses with at least
    /// one protecting entry (Kind::None does not protect).
    fn sync_addr(&self, entries: &StdHashMap<DstKey, (Kind, Source)>, ip: Addr6) {
        let mut addrs = self.addrs.lock().unwrap();
        let result = if protects(entries, ip) {
            addrs.insert(ip, 1, 0)
        } else {
            match addrs.remove(&ip) {
                Err(MapError::KeyNotFound) => Ok(()),
                other => other,
            }
        };
        if let Err(e) = result {
            warn!("Failed to update protected address {ip}: {e}");
        }
    }

    /// Removes an auto detected target; config entries are kept.
    pub fn remove_auto(&self, key: &DstKey) {
        let mut entries = self.entries.lock().unwrap();
        if entries.get(key).map(|&(_, source)| source) != Some(Source::Auto) {
            return;
        }
        if let Err(e) = self.map.lock().unwrap().remove(key) {
            warn!("Failed to remove target {key}: {e}");
            return;
        }
        info!("Target {key}: removed");
        entries.remove(key);
        self.sync_addr(&entries, key.ip());
    }

    /// Records that the java target `key` asked a client for encryption,
    /// i.e. runs in online mode; valid for `ttl_ns` after the last sighting.
    pub fn mark_online(&self, key: DstKey, ttl_ns: u64) {
        if self.entries.lock().unwrap().get(&key).map(|e| e.0) != Some(Kind::Java) {
            return;
        }
        let now = monotonic_ns();
        let until = now + ttl_ns;
        let was_online = self.online.lock().unwrap().insert(key, until).is_some_and(|u| u > now);
        let mut map = self.map.lock().unwrap();
        match map.get(&key, 0) {
            Ok(mut entry) => {
                entry.online_until_ns = until;
                if let Err(e) = map.insert(key, entry, 0) {
                    warn!("Failed to mark {key} online: {e}");
                    return;
                }
                if !was_online {
                    info!("Target {key}: online mode (offline-uuid logins are rejected)");
                }
            }
            Err(e) => warn!("Failed to read target {key}: {e}"),
        }
    }

    /// Whether the target currently counts as online mode.
    pub fn is_online(&self, key: &DstKey) -> bool {
        self.online.lock().unwrap().get(key).is_some_and(|u| *u > monotonic_ns())
    }

    pub fn snapshot(&self) -> Vec<(DstKey, Kind, Source)> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|(key, &(kind, source))| (*key, kind, source))
            .collect()
    }
}

/// Whether some entry protects `ip` (Kind::None does not).
fn protects(entries: &StdHashMap<DstKey, (Kind, Source)>, ip: Addr6) -> bool {
    entries.iter().any(|(k, &(kind, _))| k.ip() == ip && kind != Kind::None)
}

/// CLOCK_MONOTONIC in nanoseconds, the clock behind bpf_ktime_get_ns().
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer to a timespec, CLOCK_MONOTONIC always exists.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dst_key_round_trips() {
        let v4: SocketAddr = "85.93.5.1:25569".parse().unwrap();
        let key = DstKey::new(v4, PROTO_TCP);
        assert_eq!(key.addr(), v4);
        assert_eq!(key.to_string(), "85.93.5.1:25569/tcp");
        assert_eq!(key.daddr.0[10..], [0xff, 0xff, 85, 93, 5, 1]);
        assert_eq!(key.dport.to_ne_bytes(), 25569u16.to_be_bytes());

        let v6: SocketAddr = "[2001:db8::10]:19132".parse().unwrap();
        let key = DstKey::new(v6, PROTO_UDP);
        assert_eq!(key.addr(), v6);
        assert_eq!(key.to_string(), "[2001:db8::10]:19132/udp");
        assert_eq!(std::mem::size_of::<DstKey>(), 20);
    }

    #[test]
    fn protects_follows_entries() {
        let a = DstKey::new("10.0.0.1:25565".parse().unwrap(), PROTO_TCP);
        let a2 = DstKey::new("10.0.0.1:25566".parse().unwrap(), PROTO_TCP);
        let b = DstKey::new("10.0.0.2:25565".parse().unwrap(), PROTO_TCP);
        let mut entries = StdHashMap::new();
        assert!(!protects(&entries, a.ip()));
        entries.insert(a, (Kind::Java, Source::Static));
        assert!(protects(&entries, a.ip()));
        assert!(!protects(&entries, b.ip()));
        entries.insert(a2, (Kind::Bedrock, Source::Auto));
        entries.remove(&a);
        assert!(protects(&entries, a.ip()));
        entries.insert(a2, (Kind::None, Source::Exclude));
        assert!(!protects(&entries, a.ip()));
    }

    #[test]
    fn display_v6_target() {
        let key = DstKey::new("[2001:db8::1]:25565".parse().unwrap(), PROTO_TCP);
        assert_eq!(key.ip().to_string(), "2001:db8::1");
        assert_eq!(key.port(), 25565);
    }
}
