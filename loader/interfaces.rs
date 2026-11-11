//! Further interfaces (`[xdp] extra_interfaces`), e.g. the GRE tunnel of an
//! upstream DDoS protection: the same XDP and tc programs, attached in skb
//! mode. Interfaces without a link layer header are listed in the
//! `l3_interfaces` map, see xdp/l3.h.

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::HashMap as BpfHashMap;
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpMode};
use log::{info, warn};

/// The kernel index of `name`, 0 when it does not exist.
pub fn index(name: &str) -> u32 {
    let Ok(name) = std::ffi::CString::new(name) else { return 0 };
    // SAFETY: name is a valid C string.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

/// True for interfaces whose packets start at the IP header (no Ethernet).
pub fn is_l3(name: &str) -> bool {
    // ARPHRD_ETHER = 1
    std::fs::read_to_string(format!("/sys/class/net/{name}/type")).is_ok_and(|t| t.trim() != "1")
}

/// Registers `name` in `l3_interfaces` when it has no link layer header.
pub fn register(ebpf: &mut Ebpf, name: &str) -> Result<()> {
    let index = index(name);
    if index == 0 || !is_l3(name) {
        return Ok(());
    }
    let mut map: BpfHashMap<_, u32, u8> =
        BpfHashMap::try_from(ebpf.map_mut("l3_interfaces").context("map 'l3_interfaces' not found")?)?;
    map.insert(index, 1, 0)?;
    Ok(())
}

/// Attaches the filter to the extra interfaces, after all programs of the
/// main interface are loaded. Returns every extra interface with its index
/// at that time (0 = missing), for the interface watchdog.
pub fn attach_extra(ebpf: &mut Ebpf, names: &[String]) -> Vec<(String, u32)> {
    let mut watched = Vec::new();
    for name in names {
        let index = index(name);
        watched.push((name.clone(), index));
        if index == 0 {
            warn!("Interface {name} does not exist yet, the filter restarts once it appears");
            continue;
        }
        if let Err(e) = attach_one(ebpf, name) {
            warn!("Interface {name}: {e:#}");
        }
    }
    watched
}

fn attach_one(ebpf: &mut Ebpf, name: &str) -> Result<()> {
    register(ebpf, name)?;
    let xdp: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .context("program 'minecraft_filter' not found")?
        .try_into()?;
    xdp.attach(name, XdpMode::Skb).with_context(|| format!("failed to attach the filter to {name}"))?;

    // the tc programs that are in use on the main interface
    let mut attached = vec!["xdp"];
    for (program, direction) in [
        ("penalty_mark", TcAttachType::Ingress),
        ("reflection_egress", TcAttachType::Egress),
        ("outbound_record", TcAttachType::Egress),
    ] {
        let Some(p) = ebpf.program_mut(program) else { continue };
        let Ok(classifier) = <&mut SchedClassifier>::try_from(p) else { continue };
        if classifier.fd().is_err() {
            continue; // feature off: never loaded
        }
        match classifier.attach(name, direction) {
            Ok(_) => attached.push(program),
            Err(e) => warn!("Interface {name}: can't attach {program}: {e}"),
        }
    }
    info!(
        "Filter attached to {name} in skb mode ({}{})",
        attached.join(", "),
        if is_l3(name) { ", no link layer header" } else { "" }
    );
    Ok(())
}
