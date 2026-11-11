//! Penalty box (see xdp/penalty.h): a tiny minecraft service that answers
//! the server list with a notice and a login with a disconnect message, the
//! netfilter redirect of penalized clients to it, and the tc program that
//! marks their packets.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use aya::Ebpf;
use aya::maps::{Array, MapData};
use aya::programs::{SchedClassifier, TcAttachType};
use log::{debug, info, warn};

use crate::config::Config;
use crate::shutdown::Shutdown;

const NFT_TABLE: &str = "xdp_penalty";
const NFT_FAMILY: &str = "inet";
/// Table family used by older loader versions, removed on upgrade.
const NFT_LEGACY_FAMILY: &str = "ip";
const PENALTY_MARK: u32 = 0x400_0000;
const MAX_CONNECTIONS: usize = 64;

/// Removes the redirect again when dropped.
pub struct Redirect;

impl Drop for Redirect {
    fn drop(&mut self) {
        delete_tables();
    }
}

/// Deletes the current and the legacy (IPv4-only) table, errors ignored.
fn delete_tables() {
    for family in [NFT_FAMILY, NFT_LEGACY_FAMILY] {
        let _ = Command::new("nft").args(["delete", "table", family, NFT_TABLE]).stderr(Stdio::null()).status();
    }
}

fn redirect_rules(v4: Option<SocketAddrV4>, v6: Option<SocketAddrV6>) -> String {
    let mut rules = format!(
        "table {NFT_FAMILY} {NFT_TABLE} {{\n\tchain prerouting {{\n\t\ttype nat hook prerouting priority -110; policy accept;\n"
    );
    if let Some(listen) = v4 {
        rules += &format!(
            "\t\tmeta nfproto ipv4 meta mark & {PENALTY_MARK:#x} == {PENALTY_MARK:#x} meta l4proto tcp dnat ip to {listen}\n"
        );
    }
    if let Some(listen) = v6 {
        rules += &format!(
            "\t\tmeta nfproto ipv6 meta mark & {PENALTY_MARK:#x} == {PENALTY_MARK:#x} meta l4proto tcp dnat ip6 to {listen}\n"
        );
    }
    rules += "\t}\n}\n";
    rules
}

fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// First IPv4 and first non-link-local IPv6 address of a list.
fn select_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let (mut v4, mut v6) = (None, None);
    for addr in addrs {
        match addr {
            IpAddr::V4(a) => v4 = v4.or(Some(a)),
            IpAddr::V6(a) if !is_link_local_v6(&a) => v6 = v6.or(Some(a)),
            IpAddr::V6(_) => {}
        }
    }
    (v4, v6)
}

/// Sets everything up when enabled. Any failure leaves the penalty box off
/// (throttled clients are then dropped as before), it never stops the filter.
pub fn setup(
    ebpf: &mut Ebpf,
    interface: &str,
    config: &Config,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<(Redirect, JoinHandle<()>)>> {
    let p = &config.penalty;
    if !p.enabled {
        return Ok(None);
    }
    let (v4, v6) = interface_addrs(interface);
    if v4.is_none() && v6.is_none() {
        bail!("no IPv4 or IPv6 address on {interface}");
    }
    let listen4 = v4.map(|ip| SocketAddrV4::new(ip, p.port));
    let listen6 = v6.map(|ip| SocketAddrV6::new(ip, p.port, 0, 0));
    let listeners: Vec<TcpListener> = listen4
        .map(SocketAddr::V4)
        .into_iter()
        .chain(listen6.map(SocketAddr::V6))
        .map(|a| TcpListener::bind(a).with_context(|| format!("can't listen on {a}")))
        .collect::<Result<_>>()?;
    for l in &listeners {
        l.set_nonblocking(true)?;
    }
    let service = [listen4.map(|a| a.to_string()), listen6.map(|a| a.to_string())]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");

    let program: &mut SchedClassifier = ebpf
        .program_mut("penalty_mark")
        .context("program 'penalty_mark' not found")?
        .try_into()?;
    program.load()?;
    program.attach(interface, TcAttachType::Ingress)?;

    let rules = redirect_rules(listen4, listen6);
    delete_tables();
    let mut child = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).spawn().context("nft not found")?;
    child.stdin.take().context("nft stdin")?.write_all(rules.as_bytes())?;
    if !child.wait()?.success() {
        bail!("nft rejected the redirect rules");
    }
    let redirect = Redirect;

    let mut ready: Array<MapData, u64> =
        Array::try_from(ebpf.take_map("penalty_ready").context("can't take map 'penalty_ready'")?)?;
    ready.set(0, 1, 0)?;
    info!(
        "Penalty box: throttled real clients see \"{}\" for {} s (service on {service})",
        p.message, p.seconds
    );

    let message = p.message.clone();
    let shutdown = shutdown.clone();
    let handle = thread::Builder::new().name("penalty".into()).spawn(move || {
        let active = Arc::new(AtomicUsize::new(0));
        while shutdown.is_running() {
            let mut idle = true;
            for listener in &listeners {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        idle = false;
                        if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                            continue; // dropped: closes the connection
                        }
                        active.fetch_add(1, Ordering::Relaxed);
                        let (active, message) = (active.clone(), message.clone());
                        let _ = thread::Builder::new().name("penalty-conn".into()).spawn(move || {
                            if let Err(e) = serve(stream, &message) {
                                debug!("penalty connection from {peer}: {e}");
                            }
                            active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        idle = false;
                        warn!("penalty service accept: {e}");
                        shutdown.sleep(Duration::from_secs(1));
                    }
                }
            }
            if idle {
                shutdown.sleep(Duration::from_millis(100));
            }
        }
    })?;
    Ok(Some((redirect, handle)))
}

fn interface_addrs(interface: &str) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates the list, freed below.
    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return (None, None);
    }
    let mut addrs = Vec::new();
    let mut current = ifaddrs;
    while !current.is_null() {
        // SAFETY: current is a valid node of the list.
        let entry = unsafe { &*current };
        // SAFETY: ifa_name is a valid C string.
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_string_lossy();
        if name == interface && !entry.ifa_addr.is_null() {
            // SAFETY: non-null, family checked before each cast.
            match unsafe { (*entry.ifa_addr).sa_family } as i32 {
                libc::AF_INET => {
                    let sin = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                    addrs.push(IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())));
                }
                libc::AF_INET6 => {
                    let sin6 = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                    addrs.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                }
                _ => {}
            }
        }
        current = entry.ifa_next;
    }
    // SAFETY: freed exactly once.
    unsafe { libc::freeifaddrs(ifaddrs) };
    select_addrs(addrs)
}

fn write_varint(buf: &mut Vec<u8>, value: i32) {
    let mut value = value as u32;
    loop {
        if value & !0x7f == 0 {
            buf.push(value as u8);
            return;
        }
        buf.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
}

fn read_varint(stream: &mut impl Read) -> std::io::Result<i32> {
    let mut value = 0u32;
    for i in 0..5 {
        let mut byte = [0u8];
        stream.read_exact(&mut byte)?;
        value |= ((byte[0] & 0x7f) as u32) << (7 * i);
        if byte[0] & 0x80 == 0 {
            return Ok(value as i32);
        }
    }
    Err(std::io::Error::other("varint too long"))
}

fn packet(id: u8, body: &[u8]) -> Vec<u8> {
    let mut inner = vec![id];
    inner.extend_from_slice(body);
    let mut out = Vec::new();
    write_varint(&mut out, inner.len() as i32);
    out.extend_from_slice(&inner);
    out
}

fn string(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, text.len() as i32);
    out.extend_from_slice(text.as_bytes());
    out
}

fn json_text(message: &str) -> String {
    serde_json::json!({"text": message, "color": "red"}).to_string()
}

/// Reads one length-prefixed packet (bounded), returns its body.
fn read_packet(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let len = read_varint(stream)?;
    if !(1..=1024).contains(&len) {
        return Err(std::io::Error::other("bad packet length"));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body)?;
    Ok(body)
}

/// Answers one connection: server list -> notice, login -> disconnect.
fn serve(mut stream: TcpStream, message: &str) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let handshake = read_packet(&mut stream)?;
    // id 0, protocol varint, host, port (2), next state varint (last byte)
    if handshake.first() != Some(&0) {
        return Ok(());
    }
    match handshake.last() {
        Some(1) => {
            read_packet(&mut stream)?; // status request
            let status = serde_json::json!({
                "version": {"name": "Bitte warten", "protocol": -1},
                "players": {"max": 0, "online": 0},
                "description": {"text": message, "color": "red"},
            });
            stream.write_all(&packet(0x00, &string(&status.to_string())))?;
            if let Ok(ping) = read_packet(&mut stream) {
                stream.write_all(&packet(0x01, ping.get(1..).unwrap_or(&[])))?;
            }
        }
        Some(2) | Some(3) => {
            let _ = read_packet(&mut stream); // login start
            // login disconnect: a JSON text component in the login state
            stream.write_all(&packet(0x00, &string(&json_text(message))))?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnect_packet_layout() {
        let pkt = packet(0x00, &string(&json_text("wait")));
        // length, id 0, string length, then the JSON
        assert_eq!(pkt[1], 0x00);
        let json = String::from_utf8_lossy(&pkt[3..]);
        assert!(json.contains("\"text\":\"wait\""));
        assert_eq!(pkt[0] as usize, pkt.len() - 1);
    }

    #[test]
    fn redirect_rules_cover_both_families() {
        let rules = redirect_rules(
            Some("10.0.0.1:25599".parse().unwrap()),
            Some("[2001:db8::1]:25599".parse().unwrap()),
        );
        assert!(rules.starts_with("table inet xdp_penalty {"));
        assert!(rules.contains("meta nfproto ipv4 meta mark & 0x4000000 == 0x4000000 meta l4proto tcp dnat ip to 10.0.0.1:25599"));
        assert!(rules.contains("meta nfproto ipv6 meta mark & 0x4000000 == 0x4000000 meta l4proto tcp dnat ip6 to [2001:db8::1]:25599"));
        let v4_only = redirect_rules(Some("10.0.0.1:25599".parse().unwrap()), None);
        assert!(!v4_only.contains("ipv6"));
    }

    #[test]
    fn address_selection_skips_link_local_and_takes_first() {
        let addrs: Vec<IpAddr> = ["fe80::1", "10.0.0.1", "2001:db8::1", "10.0.0.2", "2001:db8::2"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let (v4, v6) = select_addrs(addrs);
        assert_eq!(v4, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(v6, Some("2001:db8::1".parse().unwrap()));
        let only_ll: Vec<IpAddr> = vec!["fe80::1".parse().unwrap()];
        assert_eq!(select_addrs(only_ll), (None, None));
    }

    #[test]
    fn link_local_detection() {
        assert!(is_link_local_v6(&"fe80::1".parse().unwrap()));
        assert!(is_link_local_v6(&"febf::1".parse().unwrap()));
        assert!(!is_link_local_v6(&"fec0::1".parse().unwrap()));
        assert!(!is_link_local_v6(&"2001:db8::1".parse().unwrap()));
    }
}
