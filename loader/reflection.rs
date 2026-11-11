//! Userspace side of the UDP reflection protection (see xdp/reflection.h).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::Pod;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, MapData, PerCpuHashMap};
use aya::programs::{SchedClassifier, TcAttachType};
use log::{error, info};

use crate::config::{Config, ProtectionMode, parse_cidr};
use crate::shutdown::Shutdown;

/// Userspace mirror of `struct reflection_config`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ReflectionConfig {
    window_ns: u64,
    mode: u8,
    drop_fragments: u8,
    pad: [u8; 6],
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for ReflectionConfig {}
const _: () = assert!(std::mem::size_of::<ReflectionConfig>() == 16);

/// Userspace mirror of `struct port_bitmap`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PortBitmap {
    bits: [u64; 1024],
}
// SAFETY: plain array of integers.
unsafe impl Pod for PortBitmap {}

/// Userspace mirror of `struct reflection_key`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ReflectionKey {
    daddr: u32,
    sport: u16,
    pad: u16,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for ReflectionKey {}

impl ReflectionKey {
    pub fn daddr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.daddr.to_ne_bytes())
    }

    pub fn sport(&self) -> u16 {
        self.sport
    }
}

/// Userspace mirror of `struct reflection_stats`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ReflectionStats {
    pub packets: u64,
    pub bytes: u64,
}
// SAFETY: repr(C) struct of plain integers without padding.
unsafe impl Pod for ReflectionStats {}

pub type StatsMap = PerCpuHashMap<MapData, ReflectionKey, ReflectionStats>;

/// Service behind a reflection source port, for the metric labels.
pub fn service_name(port: u16) -> &'static str {
    match port {
        0 => "fragment",
        19 => "chargen",
        53 => "dns",
        69 => "tftp",
        111 => "portmap",
        123 => "ntp",
        137 => "netbios",
        161 => "snmp",
        389 => "cldap",
        427 => "slp",
        520 => "rip",
        1900 => "ssdp",
        3283 => "ard",
        3702 => "ws-discovery",
        5353 => "mdns",
        5683 => "coap",
        10001 => "ubiquiti",
        11211 => "memcached",
        37810 => "dvr",
        _ => "other",
    }
}

/// Sets up the protection when enabled: fills networks and ports, attaches
/// the egress request recorder and only then switches the mode on. Returns
/// the statistics map, or None when the protection is off or could not be
/// set up (then it stays off: enforcing without the recorder would drop every
/// legitimate answer).
pub fn setup(
    ebpf: &mut Ebpf,
    interface: &str,
    config: &Config,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<StatsMap>> {
    let refl = &config.reflection;
    if refl.mode == ProtectionMode::Off {
        return Ok(None);
    }

    let mut networks: LpmTrie<MapData, u32, u8> = LpmTrie::try_from(
        ebpf.take_map("reflection_networks")
            .context("can't take map 'reflection_networks'")?,
    )?;
    for network in &refl.networks {
        let (addr, len) = parse_cidr(network)?;
        let key = Key::new(len as u32, u32::from_ne_bytes(addr.octets()));
        networks.insert(&key, 1, 0)?;
    }

    let mut bitmap = PortBitmap { bits: [0; 1024] };
    for &port in &refl.ports {
        bitmap.bits[(port >> 6) as usize] |= 1 << (port & 63);
    }
    let mut ports: Array<MapData, PortBitmap> = Array::try_from(
        ebpf.take_map("reflection_ports")
            .context("can't take map 'reflection_ports'")?,
    )?;
    ports.set(0, bitmap, 0)?;

    let recorder: Result<()> = (|| {
        let program: &mut SchedClassifier = ebpf
            .program_mut("reflection_egress")
            .context("program 'reflection_egress' not found")?
            .try_into()?;
        program.load()?;
        program.attach(interface, TcAttachType::Egress)?;
        Ok(())
    })();
    if let Err(e) = recorder {
        error!("UDP reflection protection disabled, egress recorder failed: {e:#}");
        return Ok(None);
    }

    let mut config_map: Array<MapData, ReflectionConfig> = Array::try_from(
        ebpf.take_map("reflection_config")
            .context("can't take map 'reflection_config'")?,
    )?;
    let window_ns = refl.reply_window_secs * 1_000_000_000;
    let monitor = ReflectionConfig {
        window_ns,
        mode: 1,
        drop_fragments: refl.drop_fragments as u8,
        pad: [0; 6],
    };
    config_map.set(0, monitor, 0)?;
    info!(
        "UDP reflection protection on {interface} for {:?}: monitoring",
        refl.networks
    );

    if refl.mode == ProtectionMode::Enforce {
        // requests sent right before this start were not recorded: only count
        // during one reply window, then drop
        let window = Duration::from_secs(refl.reply_window_secs);
        let shutdown = shutdown.clone();
        thread::Builder::new()
            .name("reflection-arm".into())
            .spawn(move || {
                if !shutdown.sleep(window) {
                    return;
                }
                let enforce = ReflectionConfig { mode: 2, ..monitor };
                match config_map.set(0, enforce, 0) {
                    Ok(()) => info!("UDP reflection protection: enforcing"),
                    Err(e) => error!("Failed to enable reflection enforcing: {e}"),
                }
            })?;
    }

    let stats = PerCpuHashMap::try_from(
        ebpf.take_map("reflection_stats")
            .context("can't take map 'reflection_stats'")?,
    )?;
    Ok(Some(stats))
}
