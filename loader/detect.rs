//! Live detection of minecraft servers.
//!
//! Candidates come from the listening sockets of this host and from server
//! replies observed on the sniff interfaces (TCP SYN-ACKs and RakNet pongs of
//! remote servers, e.g. behind a tunnel). Every candidate is confirmed with a
//! real protocol probe (java status ping over TCP, RakNet unconnected ping
//! over UDP) before it is protected, so forged traffic can not make the filter
//! protect, or stop protecting, anything. Confirmed servers are re-probed
//! periodically and removed once they stayed unreachable for
//! `remove_after_secs`.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::config::{AutodetectConfig, Config, parse_cidr, parse_exclude};
use crate::shutdown::Shutdown;
use crate::targets::{DstKey, Kind, PROTO_TCP, PROTO_UDP, Source, Targets};

const RAKNET_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];
const RAKNET_UNCONNECTED_PING: u8 = 0x01;
const RAKNET_UNCONNECTED_PONG: u8 = 0x1c;

/// How often the listening sockets of this host are scanned.
const SOCKET_SCAN_INTERVAL: Duration = Duration::from_secs(30);
/// A sniffer reports the same server at most this often.
const SNIFF_REPORT_INTERVAL: Duration = Duration::from_secs(60);
/// Receive buffer of a sniffer: a SYN-ACK flood of a busy server overflows it
/// and the excess is dropped in the kernel instead of costing CPU here.
const SNIFF_RCVBUF: i32 = 64 * 1024;
/// Upper bound of remembered probe results, bounds the memory use.
const MAX_RECORDS: usize = 65536;

/// A possible server, `hint` is set when the observation already identifies
/// the protocol (a RakNet pong).
struct Candidate {
    key: DstKey,
    hint: Option<Kind>,
}

/// Probe history of one destination.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Record {
    addr: SocketAddrV4,
    proto: u8,
    /// Detected kind, None while it never answered a probe.
    kind: Option<Kind2>,
    /// Unix seconds of the last successful probe.
    last_ok: u64,
    /// Unix seconds of the last probe, successful or not (not persisted).
    #[serde(skip)]
    last_probe: u64,
}

/// Serializable twin of `Kind` (only the kinds a probe can detect).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Kind2 {
    Java,
    Bedrock,
}

impl From<Kind2> for Kind {
    fn from(kind: Kind2) -> Self {
        match kind {
            Kind2::Java => Kind::Java,
            Kind2::Bedrock => Kind::Bedrock,
        }
    }
}

/// Which destinations may be probed at all.
#[derive(Clone)]
struct Scope {
    networks: Vec<(u32, u32)>,
    min_port: u16,
    exclude_ports: HashSet<u16>,
    exclude: HashSet<DstKey>,
}

impl Scope {
    fn new(config: &Config) -> Result<Self> {
        let auto = &config.autodetect;
        let mut networks = Vec::new();
        for network in &auto.networks {
            let (addr, len) = parse_cidr(network)?;
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            networks.push((u32::from(addr) & mask, mask));
        }
        let mut exclude = HashSet::new();
        for entry in &config.targets.exclude {
            let (addr, proto) = parse_exclude(entry)?;
            exclude.insert(DstKey::new(addr, proto));
        }
        Ok(Self {
            networks,
            min_port: auto.min_port,
            exclude_ports: auto.exclude_ports.iter().copied().collect(),
            exclude,
        })
    }

    fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        let ip = u32::from(ip);
        self.networks.iter().any(|&(net, mask)| ip & mask == net)
    }

    fn allows(&self, key: &DstKey) -> bool {
        let addr = key.addr();
        self.contains_ip(*addr.ip())
            && addr.port() >= self.min_port
            && !self.exclude_ports.contains(&addr.port())
            && !self.exclude.contains(key)
    }
}

/// Starts the detection threads. Returns their handles; they all end once
/// `shutdown` is triggered.
pub fn start(
    config: &Config,
    targets: Arc<Targets>,
    shutdown: &Arc<Shutdown>,
) -> Result<Vec<JoinHandle<()>>> {
    let auto = config.autodetect.clone();
    let scope = Scope::new(config)?;
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();

    {
        let (scope, tx, shutdown) = (scope.clone(), tx.clone(), shutdown.clone());
        handles.push(
            thread::Builder::new()
                .name("detect-sockets".into())
                .spawn(move || socket_scan_loop(scope, tx, shutdown))?,
        );
    }

    for interface in &auto.sniff_interfaces {
        // detection is an add-on: a missing interface must never keep the
        // filter itself from running
        let socket = match Sniffer::open(interface) {
            Ok(socket) => socket,
            Err(e) => {
                warn!("Not sniffing on '{interface}': {e:#}");
                continue;
            }
        };
        info!("Auto detection sniffing server replies on {interface}");
        let (scope, tx, shutdown) = (scope.clone(), tx.clone(), shutdown.clone());
        handles.push(
            thread::Builder::new()
                .name(format!("detect-{interface}"))
                .spawn(move || sniff_loop(socket, scope, tx, shutdown))?,
        );
    }
    drop(tx);

    let shutdown = shutdown.clone();
    let mut prober = Prober::new(auto, scope, targets);
    prober.restore();
    handles.push(
        thread::Builder::new()
            .name("detect-probe".into())
            .spawn(move || prober.run(rx, shutdown))?,
    );
    Ok(handles)
}

/* ------------------------------------------------------------------------
 * Probing
 * --------------------------------------------------------------------- */

struct Prober {
    config: AutodetectConfig,
    scope: Scope,
    targets: Arc<Targets>,
    records: HashMap<DstKey, Record>,
    state_file: PathBuf,
}

impl Prober {
    fn new(config: AutodetectConfig, scope: Scope, targets: Arc<Targets>) -> Self {
        let state_file = PathBuf::from(&config.state_file);
        Self {
            config,
            scope,
            targets,
            records: HashMap::new(),
            state_file,
        }
    }

    /// Re-protects the servers detected before the last restart, so they are
    /// covered (and their players adopted) right away instead of after the
    /// first probe round.
    fn restore(&mut self) {
        let records: Vec<Record> = match std::fs::read_to_string(&self.state_file) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(records) => records,
                Err(e) => {
                    warn!("Ignoring unreadable state file {:?}: {e}", self.state_file);
                    return;
                }
            },
            Err(_) => return,
        };
        for record in records {
            let key = DstKey::new(record.addr, record.proto);
            if !self.scope.allows(&key) {
                continue;
            }
            if let Some(kind) = record.kind {
                if let Err(e) = self.targets.set(key, kind.into(), Source::Auto) {
                    warn!("{e:#}");
                }
            }
            self.records.insert(key, record);
        }
        info!("Restored {} detected server(s) from {:?}", self.records.len(), self.state_file);
    }

    fn run(mut self, rx: Receiver<Candidate>, shutdown: Arc<Shutdown>) {
        let mut last_sweep = Instant::now();
        loop {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(candidate) => self.consider(candidate),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if !shutdown.is_running() {
                return;
            }
            if last_sweep.elapsed() >= Duration::from_secs(10) {
                last_sweep = Instant::now();
                self.sweep();
            }
        }
    }

    /// Probes a new candidate, unless it was probed recently.
    fn consider(&mut self, candidate: Candidate) {
        if !self.scope.allows(&candidate.key) {
            return;
        }
        let now = unix_now();
        if let Some(record) = self.records.get(&candidate.key) {
            let retry = if record.kind.is_some() {
                self.config.probe_interval_secs
            } else {
                self.config.retry_negative_secs
            };
            if now < record.last_probe + retry {
                return;
            }
        }
        debug!("Probing candidate {} (hint {:?})", candidate.key, candidate.hint.map(Kind::name));
        self.probe(candidate.key);
    }

    /// Re-probes known servers that are due and removes the dead ones.
    fn sweep(&mut self) {
        let now = unix_now();
        let due: Vec<DstKey> = self
            .records
            .iter()
            .filter(|(_, r)| r.kind.is_some() && now >= r.last_probe + self.config.probe_interval_secs)
            .map(|(key, _)| *key)
            .collect();
        for key in due {
            self.probe(key);
        }
    }

    fn probe(&mut self, key: DstKey) {
        let now = unix_now();
        let timeout = Duration::from_millis(self.config.probe_timeout_ms);
        let detected = match key.proto() {
            PROTO_TCP => probe_java(key.addr(), timeout).then_some(Kind2::Java),
            PROTO_UDP => probe_bedrock(key.addr(), timeout).then_some(Kind2::Bedrock),
            _ => None,
        };

        if self.records.len() >= MAX_RECORDS && !self.records.contains_key(&key) {
            // forget negative results first, they are only a probe cache
            let retry = self.config.retry_negative_secs;
            self.records.retain(|_, r| r.kind.is_some() || now < r.last_probe + retry);
            if self.records.len() >= MAX_RECORDS {
                return;
            }
        }
        let record = self.records.entry(key).or_insert(Record {
            addr: key.addr(),
            proto: key.proto(),
            kind: None,
            last_ok: 0,
            last_probe: 0,
        });
        record.last_probe = now;
        let mut changed = false;
        match detected {
            Some(kind) => {
                changed = record.kind != Some(kind) || now >= record.last_ok + 3600;
                record.kind = Some(kind);
                record.last_ok = now;
                if let Err(e) = self.targets.set(key, kind.into(), Source::Auto) {
                    warn!("{e:#}");
                }
            }
            None if record.kind.is_some() => {
                // keep protecting while it is down: an attack that makes the
                // server unreachable must not switch its protection off
                if now >= record.last_ok + self.config.remove_after_secs {
                    info!("{key} did not answer for {}s, no longer protected", now - record.last_ok);
                    record.kind = None;
                    self.targets.remove_auto(&key);
                    changed = true;
                } else {
                    debug!("{key} did not answer the probe, keeping it protected");
                }
            }
            None => {}
        }
        if changed {
            self.save();
        }
    }

    fn save(&self) {
        let detected: Vec<&Record> = self.records.values().filter(|r| r.kind.is_some()).collect();
        let result = serde_json::to_string_pretty(&detected)
            .map_err(anyhow::Error::from)
            .and_then(|json| {
                let tmp = self.state_file.with_extension("tmp");
                std::fs::write(&tmp, json)?;
                std::fs::rename(&tmp, &self.state_file)?;
                Ok(())
            });
        if let Err(e) = result {
            warn!("Failed to save {:?}: {e:#}", self.state_file);
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

fn read_varint(stream: &mut impl Read) -> Option<i32> {
    let mut value = 0u32;
    for i in 0..5 {
        let mut byte = [0u8];
        stream.read_exact(&mut byte).ok()?;
        value |= ((byte[0] & 0x7f) as u32) << (7 * i);
        if byte[0] & 0x80 == 0 {
            return Some(value as i32);
        }
    }
    None
}

/// Builds handshake (next state status) + status request.
fn java_status_request(addr: SocketAddrV4) -> Vec<u8> {
    let host = addr.ip().to_string();
    let mut handshake = vec![0x00];
    write_varint(&mut handshake, -1); // protocol version: "just asking"
    write_varint(&mut handshake, host.len() as i32);
    handshake.extend_from_slice(host.as_bytes());
    handshake.extend_from_slice(&addr.port().to_be_bytes());
    write_varint(&mut handshake, 1);

    let mut request = Vec::new();
    write_varint(&mut request, handshake.len() as i32);
    request.extend_from_slice(&handshake);
    request.extend_from_slice(&[0x01, 0x00]);
    request
}

/// True if `addr` answers a java status ping with a status JSON.
fn probe_java(addr: SocketAddrV4, timeout: Duration) -> bool {
    let result = (|| -> Option<bool> {
        let mut stream = TcpStream::connect_timeout(&SocketAddr::V4(addr), timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;
        stream.write_all(&java_status_request(addr)).ok()?;

        let length = read_varint(&mut stream)?;
        if !(3..=(1 << 21)).contains(&length) || read_varint(&mut stream)? != 0x00 {
            return Some(false);
        }
        let json_len = read_varint(&mut stream)?;
        if json_len <= 0 {
            return Some(false);
        }
        // the beginning is enough, the favicon can make the JSON huge
        let mut json = vec![0u8; (json_len as usize).min(16 * 1024)];
        stream.read_exact(&mut json).ok()?;
        let json = String::from_utf8_lossy(&json);
        Some(
            json.trim_start().starts_with('{')
                && (json.contains("\"version\"") || json.contains("\"description\"")),
        )
    })();
    result.unwrap_or(false)
}

/// True if `addr` answers a RakNet unconnected ping with a pong.
fn probe_bedrock(addr: SocketAddrV4, timeout: Duration) -> bool {
    let result = (|| -> Option<bool> {
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.set_read_timeout(Some(timeout)).ok()?;
        socket.connect(addr).ok()?;
        let mut ping = vec![RAKNET_UNCONNECTED_PING];
        ping.extend_from_slice(&(unix_now() * 1000).to_be_bytes());
        ping.extend_from_slice(&RAKNET_MAGIC);
        ping.extend_from_slice(&0x2a2a_2a2a_2a2a_2a2au64.to_be_bytes()); // client guid
        socket.send(&ping).ok()?;

        let mut buf = [0u8; 2048];
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let len = socket.recv(&mut buf).ok()?;
            if is_raknet_pong(&buf[..len]) {
                return Some(true);
            }
        }
        Some(false)
    })();
    result.unwrap_or(false)
}

/// id, time (8), server guid (8), magic (16), then the server info string.
fn is_raknet_pong(payload: &[u8]) -> bool {
    payload.len() >= 33 && payload[0] == RAKNET_UNCONNECTED_PONG && payload[17..33] == RAKNET_MAGIC
}

/* ------------------------------------------------------------------------
 * Candidate sources: listening sockets of this host
 * --------------------------------------------------------------------- */

fn socket_scan_loop(scope: Scope, tx: Sender<Candidate>, shutdown: Arc<Shutdown>) {
    loop {
        let local_ips: Vec<Ipv4Addr> = local_ipv4s()
            .into_iter()
            .filter(|ip| scope.contains_ip(*ip))
            .collect();
        for (proto, files) in [
            (PROTO_TCP, ["/proc/net/tcp", "/proc/net/tcp6"]),
            (PROTO_UDP, ["/proc/net/udp", "/proc/net/udp6"]),
        ] {
            for file in files {
                let Ok(contents) = std::fs::read_to_string(file) else {
                    continue;
                };
                for (ip, port) in parse_listeners(&contents, proto) {
                    let ips = if ip.is_unspecified() { local_ips.clone() } else { vec![ip] };
                    for ip in ips {
                        let key = DstKey::new(SocketAddrV4::new(ip, port), proto);
                        if scope.allows(&key) && tx.send(Candidate { key, hint: None }).is_err() {
                            return;
                        }
                    }
                }
            }
        }
        if !shutdown.sleep(SOCKET_SCAN_INTERVAL) {
            return;
        }
    }
}

/// Listening (TCP state 0A) / unconnected bound (UDP state 07) IPv4 sockets
/// of a /proc/net/{tcp,udp}[6] table. IPv6 sockets count when they are bound
/// to :: (dual stack) or to a v4-mapped address.
fn parse_listeners(contents: &str, proto: u8) -> Vec<(Ipv4Addr, u16)> {
    let wanted_state = if proto == PROTO_TCP { "0A" } else { "07" };
    let mut listeners = Vec::new();
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[3] != wanted_state {
            continue;
        }
        let Some((addr, port)) = fields[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port, 16) else {
            continue;
        };
        let ip = match addr.len() {
            8 => u32::from_str_radix(addr, 16).ok().map(|v| Ipv4Addr::from(v.to_le_bytes())),
            32 => {
                // four native endian u32 words
                let words: Vec<u32> = (0..4)
                    .filter_map(|i| u32::from_str_radix(&addr[i * 8..i * 8 + 8], 16).ok())
                    .collect();
                match words.as_slice() {
                    [0, 0, 0, 0] => Some(Ipv4Addr::UNSPECIFIED),
                    [0, 0, mapped, v4] if mapped.to_le_bytes() == [0, 0, 0xff, 0xff] => {
                        Some(Ipv4Addr::from(v4.to_le_bytes()))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(ip) = ip {
            listeners.push((ip, port));
        }
    }
    listeners
}

fn local_ipv4s() -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates the list, freed below with freeifaddrs.
    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return ips;
    }
    let mut current = ifaddrs;
    while !current.is_null() {
        // SAFETY: current is a valid node of the list returned by getifaddrs.
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() {
            // SAFETY: ifa_addr is non-null and its family says sockaddr_in.
            let family = unsafe { (*entry.ifa_addr).sa_family } as i32;
            if family == libc::AF_INET {
                let sin = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                ips.push(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()));
            }
        }
        current = entry.ifa_next;
    }
    // SAFETY: ifaddrs came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(ifaddrs) };
    ips
}

/* ------------------------------------------------------------------------
 * Candidate sources: replies of remote servers on the sniff interfaces
 * --------------------------------------------------------------------- */

/// AF_PACKET socket that only receives TCP SYN-ACKs and RakNet pongs.
struct Sniffer {
    fd: i32,
}

impl Drop for Sniffer {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this struct.
        unsafe { libc::close(self.fd) };
    }
}

impl Sniffer {
    fn open(interface: &str) -> Result<Self> {
        let name = std::ffi::CString::new(interface)?;
        // SAFETY: plain libc calls with checked results.
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            bail!("interface not found");
        }
        let protocol = (libc::ETH_P_IP as u16).to_be() as i32;
        // SOCK_DGRAM: packets start at the IP header on every link type
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, protocol) };
        if fd < 0 {
            bail!("socket(AF_PACKET): {}", std::io::Error::last_os_error());
        }
        let sniffer = Sniffer { fd };

        // classic BPF, operating on the IP header: accept non-fragmented TCP
        // segments with SYN+ACK set (sampled 1 in 4: a busy server is still
        // seen at once, a flood costs a quarter) and UDP datagrams whose
        // payload starts with the RakNet pong id. 256 bytes are enough for the
        // headers and the pong magic
        let filter: [libc::sock_filter; 19] = [
            bpf(0x30, 0, 0, 9),              // 0: ldb [9]            ip protocol
            bpf(0x15, 0, 9, 6),              // 1: jeq #6 ? 2 : 11
            bpf(0x28, 0, 0, 6),              // 2: ldh [6]            frag_off
            bpf(0x45, 14, 0, 0x1fff),        // 3: fragment -> reject
            bpf(0xb1, 0, 0, 0),              // 4: ldxb 4*([0]&0xf)   ip header length
            bpf(0x50, 0, 0, 13),             // 5: ldb [x+13]         tcp flags
            bpf(0x54, 0, 0, 0x12),           // 6: and #SYN|ACK
            bpf(0x15, 0, 10, 0x12),          // 7: SYN-ACK ? 8 : reject
            bpf(0x20, 0, 0, 0xffff_f038),    // 8: ld rand            (SKF_AD_RANDOM)
            bpf(0x54, 0, 0, 3),              // 9: and #3
            bpf(0x15, 6, 7, 0),              // 10: 1 in 4 -> accept : reject
            bpf(0x15, 0, 6, 17),             // 11: udp ? 12 : reject
            bpf(0x28, 0, 0, 6),              // 12: ldh [6]
            bpf(0x45, 4, 0, 0x1fff),         // 13: fragment -> reject
            bpf(0xb1, 0, 0, 0),              // 14: ldxb 4*([0]&0xf)
            bpf(0x50, 0, 0, 8),              // 15: ldb [x+8]         first payload byte
            bpf(0x15, 0, 1, RAKNET_UNCONNECTED_PONG as u32), // 16: pong ? accept : reject
            bpf(0x06, 0, 0, 256),            // 17: accept
            bpf(0x06, 0, 0, 0),              // 18: reject
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: program points to a valid filter for the duration of the call.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &program as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as u32,
            )
        };
        if ret < 0 {
            bail!("SO_ATTACH_FILTER: {}", std::io::Error::last_os_error());
        }

        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = protocol as u16;
        addr.sll_ifindex = ifindex as i32;
        // SAFETY: addr is a valid sockaddr_ll.
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            bail!("bind: {}", std::io::Error::last_os_error());
        }

        // SAFETY: SNIFF_RCVBUF is a valid int option value.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &SNIFF_RCVBUF as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            )
        };

        // a receive timeout lets the loop notice shutdown
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        // SAFETY: timeout is a valid timeval.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        Ok(sniffer)
    }

    fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        // SAFETY: buf is valid for buf.len() bytes.
        let len = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        (len > 0).then_some(len as usize)
    }
}

const fn bpf(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn sniff_loop(sniffer: Sniffer, scope: Scope, tx: Sender<Candidate>, shutdown: Arc<Shutdown>) {
    let mut reported: HashMap<DstKey, Instant> = HashMap::new();
    let mut buf = [0u8; 256];
    while shutdown.is_running() {
        let Some(len) = sniffer.recv(&mut buf) else {
            continue;
        };
        let Some(candidate) = parse_server_reply(&buf[..len]) else {
            continue;
        };
        if !scope.allows(&candidate.key) {
            continue;
        }
        // a flood of SYN-ACKs from one busy server must not flood the prober
        let now = Instant::now();
        if reported
            .get(&candidate.key)
            .is_some_and(|last| now.duration_since(*last) < SNIFF_REPORT_INTERVAL)
        {
            continue;
        }
        reported.insert(candidate.key, now);
        if reported.len() > 65536 {
            reported.retain(|_, last| now.duration_since(*last) < SNIFF_REPORT_INTERVAL);
        }
        if tx.send(candidate).is_err() {
            return;
        }
    }
}

/// Extracts the server side (source) of a SYN-ACK or RakNet pong.
fn parse_server_reply(packet: &[u8]) -> Option<Candidate> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let l4 = packet.get(ihl..)?;
    let port = u16::from_be_bytes([*l4.first()?, *l4.get(1)?]);
    let addr = SocketAddrV4::new(src, port);
    match packet[9] {
        6 => {
            let flags = *l4.get(13)?;
            (flags & 0x12 == 0x12).then(|| Candidate {
                key: DstKey::new(addr, PROTO_TCP),
                hint: Some(Kind::Java),
            })
        }
        17 => is_raknet_pong(l4.get(8..)?).then(|| Candidate {
            key: DstKey::new(addr, PROTO_UDP),
            hint: Some(Kind::Bedrock),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_encoding() {
        let mut buf = Vec::new();
        write_varint(&mut buf, -1);
        assert_eq!(buf, [0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert_eq!(read_varint(&mut buf.as_slice()), Some(-1));
        let mut buf = Vec::new();
        write_varint(&mut buf, 300);
        assert_eq!(buf, [0xac, 0x02]);
    }

    #[test]
    fn parses_proc_listeners() {
        let tcp = "  sl  local_address rem_address   st\n\
                   0: 0205505D:63DD 00000000:0000 0A 0\n\
                   1: 00000000:1F90 00000000:0000 0A 0\n\
                   2: 0205505D:C350 0A0A0A0A:01BB 01 0\n";
        assert_eq!(
            parse_listeners(tcp, PROTO_TCP),
            vec![
                (Ipv4Addr::new(93, 80, 5, 2), 0x63dd),
                (Ipv4Addr::UNSPECIFIED, 8080)
            ]
        );
        let tcp6 = "  sl  local_address rem_address st\n\
                    0: 00000000000000000000000000000000:63DD 00000000000000000000000000000000:0000 0A 0\n\
                    1: 0000000000000000FFFF00000205505D:63DE 00000000000000000000000000000000:0000 0A 0\n";
        assert_eq!(
            parse_listeners(tcp6, PROTO_TCP),
            vec![
                (Ipv4Addr::UNSPECIFIED, 0x63dd),
                (Ipv4Addr::new(93, 80, 5, 2), 0x63de)
            ]
        );
    }

    #[test]
    fn parses_server_replies() {
        // ip header (20) + tcp header with SYN+ACK from 85.93.5.80:25565
        let mut syn_ack = vec![0u8; 40];
        syn_ack[0] = 0x45;
        syn_ack[9] = 6;
        syn_ack[12..16].copy_from_slice(&[85, 93, 5, 80]);
        syn_ack[20..22].copy_from_slice(&25565u16.to_be_bytes());
        syn_ack[33] = 0x12;
        let candidate = parse_server_reply(&syn_ack).unwrap();
        assert_eq!(candidate.key.to_string(), "85.93.5.80:25565/tcp");

        syn_ack[33] = 0x02; // plain SYN is not a server reply
        assert!(parse_server_reply(&syn_ack).is_none());

        let mut pong = vec![0u8; 28 + 40];
        pong[0] = 0x45;
        pong[9] = 17;
        pong[12..16].copy_from_slice(&[85, 93, 5, 2]);
        pong[20..22].copy_from_slice(&19132u16.to_be_bytes());
        pong[28] = RAKNET_UNCONNECTED_PONG;
        pong[45..61].copy_from_slice(&RAKNET_MAGIC);
        let candidate = parse_server_reply(&pong).unwrap();
        assert_eq!(candidate.key.to_string(), "85.93.5.2:19132/udp");
    }

    #[test]
    fn scope_filters_candidates() {
        let config: Config = toml::from_str(
            "[autodetect]\nnetworks = [\"85.93.5.0/24\"]\n\n[targets]\nexclude = [\"85.93.5.55:25565/tcp\"]",
        )
        .unwrap();
        let scope = Scope::new(&config).unwrap();
        let key = |s: &str, proto| DstKey::new(s.parse().unwrap(), proto);
        assert!(scope.allows(&key("85.93.5.80:25565", PROTO_TCP)));
        assert!(!scope.allows(&key("85.93.6.80:25565", PROTO_TCP))); // other network
        assert!(!scope.allows(&key("85.93.5.80:443", PROTO_TCP))); // below min_port
        assert!(!scope.allows(&key("85.93.5.80:3306", PROTO_TCP))); // excluded port
        assert!(!scope.allows(&key("85.93.5.55:25565", PROTO_TCP))); // excluded target
        assert!(scope.allows(&key("85.93.5.55:25565", PROTO_UDP)));
    }
}
