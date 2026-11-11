//! Penalty box (see xdp/penalty.h): a tiny minecraft service that answers
//! the server list with a notice and a login with a disconnect message, the
//! netfilter redirect of penalized clients to it, and the tc program that
//! marks their packets.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
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
const PENALTY_MARK: u32 = 0x400_0000;
const MAX_CONNECTIONS: usize = 64;

/// Removes the redirect again when dropped.
pub struct Redirect;

impl Drop for Redirect {
    fn drop(&mut self) {
        let _ = Command::new("nft").args(["delete", "table", "ip", NFT_TABLE]).stderr(Stdio::null()).status();
    }
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
    let ip = interface_ipv4(interface).with_context(|| format!("no IPv4 address on {interface}"))?;
    let listen = SocketAddrV4::new(ip, p.port);
    let listener = TcpListener::bind(listen).with_context(|| format!("can't listen on {listen}"))?;
    listener.set_nonblocking(true)?;

    let program: &mut SchedClassifier = ebpf
        .program_mut("penalty_mark")
        .context("program 'penalty_mark' not found")?
        .try_into()?;
    program.load()?;
    program.attach(interface, TcAttachType::Ingress)?;

    let rules = format!(
        "table ip {NFT_TABLE} {{\n\
         \tchain prerouting {{\n\
         \t\ttype nat hook prerouting priority -110; policy accept;\n\
         \t\tmeta mark & {PENALTY_MARK:#x} == {PENALTY_MARK:#x} meta l4proto tcp dnat to {listen}\n\
         \t}}\n\
         }}\n"
    );
    let _ = Command::new("nft").args(["delete", "table", "ip", NFT_TABLE]).stderr(Stdio::null()).status();
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
        "Penalty box: throttled real clients see \"{}\" for {} s (service on {listen})",
        p.message, p.seconds
    );

    let message = p.message.clone();
    let shutdown = shutdown.clone();
    let handle = thread::Builder::new().name("penalty".into()).spawn(move || {
        let active = Arc::new(AtomicUsize::new(0));
        while shutdown.is_running() {
            match listener.accept() {
                Ok((stream, peer)) => {
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
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    shutdown.sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    warn!("penalty service accept: {e}");
                    shutdown.sleep(Duration::from_secs(1));
                }
            }
        }
    })?;
    Ok(Some((redirect, handle)))
}

fn interface_ipv4(interface: &str) -> Option<Ipv4Addr> {
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates the list, freed below.
    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return None;
    }
    let mut found = None;
    let mut current = ifaddrs;
    while !current.is_null() {
        // SAFETY: current is a valid node of the list.
        let entry = unsafe { &*current };
        // SAFETY: ifa_name is a valid C string.
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_string_lossy();
        if name == interface && !entry.ifa_addr.is_null() {
            // SAFETY: non-null, family checked before the cast.
            if unsafe { (*entry.ifa_addr).sa_family } as i32 == libc::AF_INET {
                let sin = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                found = Some(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()));
                break;
            }
        }
        current = entry.ifa_next;
    }
    // SAFETY: freed exactly once.
    unsafe { libc::freeifaddrs(ifaddrs) };
    found
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
}
