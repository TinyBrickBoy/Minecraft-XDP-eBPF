use std::collections::HashMap as StdHashMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;

use anyhow::{Context, Result};
use aya::Pod;
use aya::maps::{HashMap, MapData};
use log::{info, warn};

pub const PROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
pub const PROTO_UDP: u8 = libc::IPPROTO_UDP as u8;

/// Userspace mirror of `struct dst_key` (see xdp/stats.h), address and port
/// in network byte order.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct DstKey {
    daddr: u32,
    dport: u16,
    proto: u8,
    pad: u8,
}

// SAFETY: repr(C) struct of plain integers without padding, valid for any bit
// pattern read from the map.
unsafe impl Pod for DstKey {}

const _: () = assert!(std::mem::size_of::<DstKey>() == 8);

impl DstKey {
    pub fn new(addr: SocketAddrV4, proto: u8) -> Self {
        Self {
            daddr: u32::from_ne_bytes(addr.ip().octets()),
            dport: addr.port().to_be(),
            proto,
            pad: 0,
        }
    }

    pub fn addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(
            Ipv4Addr::from(self.daddr.to_ne_bytes()),
            u16::from_be(self.dport),
        )
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
    kind: u8,
    pad: [u8; 7],
}

// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for TargetEntry {}

const _: () = assert!(std::mem::size_of::<TargetEntry>() == 16);

/// How a destination is protected, `enum target_kind` on the C side.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Explicitly unprotected, overrides the static java range.
    None = 0,
    Java = 1,
    Bedrock = 2,
    Http = 3,
    Https = 4,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::None => "none",
            Kind::Java => "java",
            Kind::Bedrock => "bedrock",
            Kind::Http => "http",
            Kind::Https => "https",
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
    entries: Mutex<StdHashMap<DstKey, (Kind, Source)>>,
    grace_ns: u64,
}

impl Targets {
    pub fn new(map: HashMap<MapData, DstKey, TargetEntry>, grace_secs: u64) -> Self {
        Self {
            map: Mutex::new(map),
            entries: Mutex::new(StdHashMap::new()),
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
                return Ok(());
            }
        }
        let entry = TargetEntry {
            grace_until_ns: monotonic_ns() + self.grace_ns,
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
        Ok(())
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
        let addr: SocketAddrV4 = "85.93.5.1:25569".parse().unwrap();
        let key = DstKey::new(addr, PROTO_TCP);
        assert_eq!(key.addr(), addr);
        assert_eq!(key.to_string(), "85.93.5.1:25569/tcp");
        // network byte order, as the kernel compares it with the headers
        assert_eq!(key.daddr.to_ne_bytes(), [85, 93, 5, 1]);
        assert_eq!(key.dport.to_ne_bytes(), 25569u16.to_be_bytes());
    }
}
