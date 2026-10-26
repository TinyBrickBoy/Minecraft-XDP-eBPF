use anyhow::{Context, Result, bail};
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// Default configuration file written on first run, with documentation for
/// every option. Mirrors [`Config::default`].
pub const DEFAULT_CONFIG_TOML: &str = r#"# Minecraft XDP filter configuration.
# This file is applied at load time; restart the loader after editing.
# Every option is listed with its default value.

[filter]
# Static inclusive TCP destination port range protected as minecraft java on
# every destination address. Use the same value for both to protect a single
# port, or 0 for both to only protect the targets from [targets] and
# [autodetect].
start_port = 25565
end_port = 25565

# SYN connection throttle: max new connections (SYNs) per source IP within
# each throttle window (see hit_count_reset_secs). Set to 0 to disable
# throttling.
hit_count = 10

# Length of the throttle window in seconds, enforced inside the eBPF program:
# each source IP gets its own window starting at its first SYN, and the counter
# resets in-kernel once the window expires. e.g. hit_count = 10 with
# hit_count_reset_secs = 3 allows 10 new connections per source IP every
# 3 seconds. Must be between 1 and 86400 (one day).
hit_count_reset_secs = 3

# Idle timeout for verified player connections in seconds, enforced inside the
# eBPF program: a connection's entry is removed after one to two timeout
# intervals without packets, so a returning client has to redo the handshake.
# Must be between 1 and 86400 (one day).
player_idle_timeout_secs = 60

# Enforce online-mode username rules during login inspection.
# true  -> usernames are limited to 16 characters (Mojang online mode).
# false -> allow the protocol maximum (offline / cracked servers).
online_names = true

# Online mode check: when a java server is seen asking clients for
# encryption (it runs in online mode), logins with an offline-mode uuid
# (cracked launchers, most bots) are rejected before they reach it. The
# server counts as online mode for online_mode_cache_secs after the last
# time it was seen; needs [autodetect] sniff_interfaces.
online_mode_check = true
online_mode_cache_secs = 300

# Grace window in seconds after the loader starts and after a target becomes
# protected: connections established before are adopted instead of dropped,
# so restarts and newly protected servers do not kick players. 0 disables
# adoption. Must be between 0 and 3600.
adopt_grace_secs = 120

[targets]
# Destinations protected regardless of auto detection, as "ip:port".
java = []
bedrock = []
http = []
https = []

# Destinations that are never protected, as "ip:port/tcp" or "ip:port/udp".
# Overrides the static range and auto detection.
exclude = []

[autodetect]
# Find minecraft servers automatically and protect them live: listening
# sockets of this host and servers that answer through sniff_interfaces are
# probed with a real java status ping / RakNet ping, and only servers that
# answer correctly are protected.
enabled = false

# Only servers inside these networks are considered, e.g. ["85.93.5.0/24"].
networks = []

# Interfaces on which server replies (TCP SYN-ACKs, RakNet pongs) of remote
# servers are observed, e.g. a tunnel interface like "wg-bgp".
sniff_interfaces = []

# Ports below min_port and the ports in exclude_ports are never probed.
min_port = 1024
exclude_ports = [1433, 1521, 2049, 3306, 3389, 5432, 5672, 6379, 9000, 9090, 9200, 11211, 15672, 27017]

# Seconds between re-probes of known servers.
probe_interval_secs = 300

# Timeout of a single probe in milliseconds.
probe_timeout_ms = 2000

# A protected server that did not answer for this many seconds is removed.
remove_after_secs = 21600

# A port that is no minecraft server is probed again after this many seconds.
retry_negative_secs = 21600

# File that keeps the detected servers across restarts.
state_file = "targets.json"

[web]
# HTTP/HTTPS protection: a clean TCP handshake, then the first segment of a
# connection has to be an http request line (HTTP) or a TLS ClientHello
# (HTTPS); everything else is dropped. Encrypted request floods can not be
# told apart from visitors at this layer, that needs a reverse proxy.
# "off", "monitor" (only count what would be dropped) or "enforce".
mode = "off"

# Let auto detection probe for web servers (http request, TLS handshake) on
# every candidate port, plus these ports below min_port.
detect = true
ports = [80, 443]

# Verified web connections are forgotten after this many idle seconds
# (keep-alive, HTTP/2 and websockets idle much longer than game clients).
# Must be between 60 and 86400.
idle_timeout_secs = 900

# Max new connections per source ip per throttle window on web targets, 0
# disables it. Browsers, NATs and CDNs open many connections from one ip.
hit_count = 0

[reflection]
# UDP reflection/amplification protection for whole networks: answers from
# the service ports below (DNS, NTP, memcached, SSDP, ...) only pass when
# they answer a request a protected address sent out through this interface.
# "off", "monitor" (only count what would be dropped) or "enforce". Start
# with "monitor" and check the xdp_reflection_* metrics before enforcing.
mode = "off"

# Protected networks, e.g. ["85.93.5.0/24"].
networks = []

# UDP source ports whose answers are checked.
ports = [19, 53, 69, 111, 123, 137, 161, 389, 427, 520, 1900, 3283, 3702, 5353, 5683, 10001, 11211, 37810]

# Also drop non-first UDP fragments to protected addresses: large amplified
# answers arrive fragmented, legitimate UDP traffic practically never does.
drop_fragments = true

# Seconds a recorded request accepts answers. Must be between 1 and 300.
reply_window_secs = 30

[blocklist]
# Sources that are always dropped, checked before everything else: one
# address or prefix per line in `file` (re-read live when it changes, `#`
# starts a comment) plus `entries`.
enabled = true
file = "blocklist.txt"
entries = []
reload_secs = 5

# Sources banned by the rate limit `auto_after_bans` times within
# `auto_window_secs` are appended to `file` for `auto_duration_secs`, with an
# "auto until=<unix time>" comment; expired automatic lines are removed again,
# manual lines are never touched. Needs [ratelimit] mode = enforce.
auto = true
auto_after_bans = 3
auto_window_secs = 86400
auto_duration_secs = 604800
auto_state_file = "auto-blocklist.json"

# An automatic entry is also removed once its source sent nothing for this
# many seconds (0 keeps it until auto_duration_secs).
auto_idle_secs = 300

[ratelimit]
# Automatic bans: a source sending more than `pps` packets per second to
# `networks` is banned (all its traffic dropped) for `ban_secs`. Sources in
# `allow` (own proxies, CDNs) are never banned. Players send 20-200 packets/s.
# "off", "monitor" (only count and log would-be bans) or "enforce".
mode = "off"
networks = []
pps = 3000
ban_secs = 300
allow = []

# Violations (packets to unused addresses, invalid handshakes, forged TCP
# flags, invalid RakNet messages) per source: more than `strikes` within
# `strike_window_secs` ban the source like the packet rate. 0 disables.
strikes = 30
strike_window_secs = 60

[unused]
# Drop traffic to addresses of these networks that the kernel has no route
# for (e.g. not yet assigned customer addresses behind an unreachable
# route) at the driver, instead of letting the stack drop them and answer
# with ICMP errors. Decided per packet by the kernel routing table, so a
# newly routed address is reachable at once. At most 8 networks.
enabled = false
networks = []

[xdp]
# How the filter attaches to the network interface.
# "auto"   -> native driver mode if the NIC supports XDP, with automatic
#             fallback to generic mode otherwise. Recommended.
# "driver" -> force native driver mode: fastest, but fails on NICs without
#             XDP support (including most virtual machines).
# "skb"    -> force generic (skb) mode: works on any interface but is
#             slower; use it when the driver misbehaves in native mode.
mode = "auto"

# Sizes of the in-kernel connection tables below. The maps are preallocated,
# so higher limits cost kernel memory up front, not per connection.

# Connections that have not finished the Minecraft handshake yet. The
# least-recently-used entry is evicted when the table is full, bounding how
# many half-open connections an attacker can keep alive at once.
max_pending_connections = 16384

# Verified player connections. New connections cannot be verified while this
# table is full, so keep it well above the expected player count.
max_player_connections = 65535

# Source IPs tracked by the SYN throttle. When the table is full, new SYNs
# are dropped (fail closed) until expired windows are reclaimed in-kernel.
max_throttled_ips = 65535

[metrics]
# Collect packet statistics inside the eBPF program. Required for any metrics
# output. Adds a small per-packet cost, so it is disabled by default.
enabled = false

# Address to expose Prometheus metrics on (only used when enabled = true).
# Leave commented out to collect stats without starting the HTTP server.
# The endpoint has no authentication, so only bind to a public address
# (e.g. "0.0.0.0:1999") if you really want it reachable from outside.
# addr = "127.0.0.1:1999"

# How often the in-kernel statistics are read and published, in seconds.
poll_secs = 10

[logging]
# Verbosity of console and file logging:
# "off", "error", "warn", "info", "debug" or "trace".
# The RUST_LOG environment variable overrides this setting at runtime.
level = "info"

# The log file (xdp-loader.log) is rotated once it grows past this many
# megabytes; the 5 most recent rotated files are kept.
file_max_mb = 100
"#;

/// Runtime configuration for the XDP filter, grouped like the TOML file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub filter: FilterConfig,
    pub targets: TargetsConfig,
    pub autodetect: AutodetectConfig,
    pub web: WebConfig,
    pub reflection: ReflectionConfig,
    pub blocklist: BlocklistConfig,
    pub ratelimit: RatelimitConfig,
    pub unused: UnusedConfig,
    pub xdp: XdpConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
}

/// `[filter]` — which traffic is filtered and how strictly.
///
/// These fields are pushed into the eBPF program's `volatile const` globals at
/// load time; see `load_and_attach` in `loader/ebpf.rs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterConfig {
    /// First port of the inclusive filtered range. Maps to `START_PORT`.
    pub start_port: u16,
    /// Last port of the inclusive filtered range. Maps to `END_PORT`.
    pub end_port: u16,
    /// Max SYNs per source IP per throttle window (0 = disabled). Maps to `HIT_COUNT`.
    pub hit_count: u32,
    /// Throttle window length in seconds; each IP's SYN counter resets in-kernel
    /// once its window expires. Maps to `HIT_COUNT_RESET_NS` (converted to ns).
    pub hit_count_reset_secs: u64,
    /// Idle timeout for verified connections in seconds; an entry is removed
    /// in-kernel after one to two intervals without packets. Maps to
    /// `PLAYER_IDLE_NS` (converted to ns).
    pub player_idle_timeout_secs: u64,
    /// Enforce online-mode (<= 16 char) usernames. Maps to `ONLINE_NAMES`.
    pub online_names: bool,
    /// Seconds during which established flows of newly protected targets
    /// (and of every target right after start) are adopted.
    pub adopt_grace_secs: u64,
    pub online_mode_check: bool,
    pub online_mode_cache_secs: u64,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            start_port: 25565,
            end_port: 25565,
            hit_count: 10,
            hit_count_reset_secs: 3,
            player_idle_timeout_secs: 60,
            online_names: true,
            adopt_grace_secs: 120,
            online_mode_check: true,
            online_mode_cache_secs: 300,
        }
    }
}

/// `[targets]` — manually protected and excluded destinations.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TargetsConfig {
    /// "ip:port" destinations always protected as java.
    pub java: Vec<String>,
    /// "ip:port" destinations always protected as bedrock.
    pub bedrock: Vec<String>,
    /// "ip:port" destinations always protected as http.
    pub http: Vec<String>,
    /// "ip:port" destinations always protected as https.
    pub https: Vec<String>,
    /// "ip:port/tcp|udp" destinations that are never protected.
    pub exclude: Vec<String>,
}

/// `[autodetect]` — live detection of minecraft servers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutodetectConfig {
    pub enabled: bool,
    /// CIDRs whose servers are considered.
    pub networks: Vec<String>,
    /// Interfaces on which replies of remote servers are observed.
    pub sniff_interfaces: Vec<String>,
    pub min_port: u16,
    pub exclude_ports: Vec<u16>,
    pub probe_interval_secs: u64,
    pub probe_timeout_ms: u64,
    pub remove_after_secs: u64,
    pub retry_negative_secs: u64,
    pub state_file: String,
}

impl Default for AutodetectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            networks: Vec::new(),
            sniff_interfaces: Vec::new(),
            min_port: 1024,
            exclude_ports: vec![
                1433, 1521, 2049, 3306, 3389, 5432, 5672, 6379, 9000, 9090, 9200, 11211, 15672,
                27017,
            ],
            probe_interval_secs: 300,
            probe_timeout_ms: 2000,
            remove_after_secs: 21600,
            retry_negative_secs: 21600,
            state_file: "targets.json".into(),
        }
    }
}

/// `[web]` — HTTP/HTTPS targets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    pub mode: ProtectionMode,
    pub detect: bool,
    pub ports: Vec<u16>,
    pub idle_timeout_secs: u64,
    pub hit_count: u32,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            mode: ProtectionMode::Off,
            detect: true,
            ports: vec![80, 443],
            idle_timeout_secs: 900,
            hit_count: 0,
        }
    }
}

impl WebConfig {
    /// Whether auto detection probes for web servers.
    pub fn detects(&self) -> bool {
        self.mode != ProtectionMode::Off && self.detect
    }

    fn validate(&self) -> Result<()> {
        check_range("[web] idle_timeout_secs", self.idle_timeout_secs, 60, 86_400)
    }
}

/// `[reflection]` — UDP reflection protection for whole networks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReflectionConfig {
    pub mode: ProtectionMode,
    pub networks: Vec<String>,
    pub ports: Vec<u16>,
    pub drop_fragments: bool,
    pub reply_window_secs: u64,
}

impl Default for ReflectionConfig {
    fn default() -> Self {
        Self {
            mode: ProtectionMode::Off,
            networks: Vec::new(),
            ports: vec![19, 53, 69, 111, 123, 137, 161, 389, 427, 520, 1900, 3283, 3702, 5353, 5683, 10001, 11211, 37810],
            drop_fragments: true,
            reply_window_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtectionMode {
    Off,
    Monitor,
    Enforce,
}

impl ReflectionConfig {
    fn validate(&self) -> Result<()> {
        for network in &self.networks {
            parse_cidr(network).context("[reflection] networks")?;
        }
        if self.mode != ProtectionMode::Off && self.networks.is_empty() {
            bail!("[reflection] networks must not be empty when the protection is on");
        }
        check_range("[reflection] reply_window_secs", self.reply_window_secs, 1, 300)
    }
}

/// `[blocklist]` — always dropped sources.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlocklistConfig {
    pub enabled: bool,
    pub file: String,
    pub entries: Vec<String>,
    pub reload_secs: u64,
    pub auto: bool,
    pub auto_after_bans: u64,
    pub auto_window_secs: u64,
    pub auto_duration_secs: u64,
    pub auto_state_file: String,
    pub auto_idle_secs: u64,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file: "blocklist.txt".into(),
            entries: Vec::new(),
            reload_secs: 5,
            auto: true,
            auto_after_bans: 3,
            auto_window_secs: 86_400,
            auto_duration_secs: 604_800,
            auto_state_file: "auto-blocklist.json".into(),
            auto_idle_secs: 300,
        }
    }
}

impl BlocklistConfig {
    fn validate(&self) -> Result<()> {
        for entry in &self.entries {
            parse_cidr(entry).context("[blocklist] entries")?;
        }
        check_range("[blocklist] reload_secs", self.reload_secs, 1, 3_600)?;
        check_range("[blocklist] auto_after_bans", self.auto_after_bans, 1, 100)?;
        check_range("[blocklist] auto_window_secs", self.auto_window_secs, 10, 30 * 86_400)?;
        check_range("[blocklist] auto_duration_secs", self.auto_duration_secs, 10, 365 * 86_400)?;
        if self.auto_idle_secs != 0 {
            check_range("[blocklist] auto_idle_secs", self.auto_idle_secs, 10, 30 * 86_400)?;
        }
        Ok(())
    }
}

/// `[ratelimit]` — automatic bans of sources sending too many packets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RatelimitConfig {
    pub mode: ProtectionMode,
    pub networks: Vec<String>,
    pub pps: u64,
    pub ban_secs: u64,
    pub allow: Vec<String>,
    pub strikes: u64,
    pub strike_window_secs: u64,
}

impl Default for RatelimitConfig {
    fn default() -> Self {
        Self {
            mode: ProtectionMode::Off,
            networks: Vec::new(),
            pps: 3000,
            ban_secs: 300,
            allow: Vec::new(),
            strikes: 30,
            strike_window_secs: 60,
        }
    }
}

impl RatelimitConfig {
    fn validate(&self) -> Result<()> {
        for network in self.networks.iter().chain(&self.allow) {
            parse_cidr(network).context("[ratelimit] networks/allow")?;
        }
        if self.mode != ProtectionMode::Off && self.networks.is_empty() {
            bail!("[ratelimit] networks must not be empty when the rate limit is on");
        }
        check_range("[ratelimit] pps", self.pps, 50, 10_000_000)?;
        check_range("[ratelimit] ban_secs", self.ban_secs, 5, 86_400)?;
        check_range("[ratelimit] strike_window_secs", self.strike_window_secs, 1, 3_600)
    }
}

/// `[unused]` — drop traffic to unrouted addresses of whole networks.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UnusedConfig {
    pub enabled: bool,
    pub networks: Vec<String>,
}

impl UnusedConfig {
    fn validate(&self) -> Result<()> {
        for network in &self.networks {
            parse_cidr(network).context("[unused] networks")?;
        }
        if self.networks.len() > 8 {
            bail!("[unused] supports at most 8 networks");
        }
        if self.enabled && self.networks.is_empty() {
            bail!("[unused] networks must not be empty when enabled");
        }
        Ok(())
    }
}

/// `[xdp]` — how the program attaches and the capacity of its maps.
///
/// The capacities override the placeholder `max_entries` of the corresponding
/// map in `xdp/minecraft_filter.c` at load time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XdpConfig {
    /// XDP attach mode.
    pub mode: ConfigXdpMode,
    /// Capacity of `conntrack_map`: concurrent unverified (mid-handshake)
    /// connections, oldest evicted when full.
    pub max_pending_connections: u32,
    /// Capacity of `player_connection_map`: concurrent verified connections.
    pub max_player_connections: u32,
    /// Capacity of `connection_throttle`: source IPs with an active throttle
    /// window.
    pub max_throttled_ips: u32,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            mode: ConfigXdpMode::Auto,
            max_pending_connections: 16384,
            max_player_connections: 65535,
            max_throttled_ips: 65535,
        }
    }
}

/// XDP attach mode, the `mode` option in `[xdp]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigXdpMode {
    /// Native driver mode when the NIC supports it, automatic fallback to
    /// generic mode otherwise.
    Auto,
    /// Force native driver mode, fail when unsupported.
    Driver,
    /// Force generic (skb) mode.
    Skb,
}

impl fmt::Display for ConfigXdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConfigXdpMode::Auto => "auto",
            ConfigXdpMode::Driver => "driver",
            ConfigXdpMode::Skb => "skb",
        })
    }
}

/// `[metrics]` — statistics collection and the Prometheus endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Collect statistics inside the eBPF program. Maps to `PROMETHEUS`.
    pub enabled: bool,
    /// Optional address for the Prometheus HTTP endpoint (e.g. `127.0.0.1:1999`).
    pub addr: Option<String>,
    /// Seconds between reads of the in-kernel statistics map.
    pub poll_secs: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: None,
            poll_secs: 10,
        }
    }
}

/// `[logging]` — console/file log verbosity and rotation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log verbosity, overridable at runtime via the `RUST_LOG` env variable.
    pub level: LogLevel,
    /// Rotate the log file once it grows past this size in megabytes.
    pub file_max_mb: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            file_max_mb: 100,
        }
    }
}

/// Log verbosity, the `level` option in `[logging]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

impl Config {
    /// Load the configuration from `path`, creating a documented default file if
    /// it does not exist yet.
    ///
    /// Runs before logging is initialized (the log level lives in here), so the
    /// "wrote defaults" notice goes to stderr directly.
    pub fn load(path: &Path) -> Result<Config> {
        if !path.exists() {
            eprintln!(
                "Config file '{}' not found, writing documented defaults",
                path.display()
            );
            std::fs::write(path, DEFAULT_CONFIG_TOML).with_context(|| {
                format!("failed to write default config to '{}'", path.display())
            })?;
        }

        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file '{}'", path.display()))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file '{}'", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Reject values the eBPF program or loader cannot represent sensibly.
    fn validate(&self) -> Result<()> {
        self.filter.validate()?;
        self.targets.validate()?;
        self.autodetect.validate()?;
        self.web.validate()?;
        self.reflection.validate()?;
        self.blocklist.validate()?;
        self.ratelimit.validate()?;
        self.unused.validate()?;
        self.xdp.validate()?;
        self.metrics.validate()?;
        self.logging.validate()
    }
}

/// Bail with a uniform message unless `min <= value <= max`.
fn check_range(option: &str, value: u64, min: u64, max: u64) -> Result<()> {
    if value < min || value > max {
        bail!("{option} must be between {min} and {max} (got {value})");
    }
    Ok(())
}

impl FilterConfig {
    fn validate(&self) -> Result<()> {
        if self.start_port == 0 && self.end_port != 0 {
            bail!("[filter] start_port must be >= 1 (or 0 for both to disable the static range)");
        }
        if self.start_port > self.end_port {
            bail!(
                "[filter] start_port ({}) must be <= end_port ({})",
                self.start_port,
                self.end_port
            );
        }
        check_range(
            "[filter] hit_count_reset_secs",
            self.hit_count_reset_secs,
            1,
            86_400,
        )?;
        check_range(
            "[filter] player_idle_timeout_secs",
            self.player_idle_timeout_secs,
            1,
            86_400,
        )?;
        check_range("[filter] online_mode_cache_secs", self.online_mode_cache_secs, 10, 86_400)?;
        check_range("[filter] adopt_grace_secs", self.adopt_grace_secs, 0, 3_600)
    }
}

impl TargetsConfig {
    fn validate(&self) -> Result<()> {
        for entry in self.java.iter().chain(&self.bedrock).chain(&self.http).chain(&self.https) {
            parse_socket_addr(entry).with_context(|| format!("[targets] invalid entry '{entry}'"))?;
        }
        for entry in &self.exclude {
            parse_exclude(entry).with_context(|| format!("[targets] invalid exclude '{entry}'"))?;
        }
        Ok(())
    }
}

/// Parses "ip:port" (IPv4 only, the filter does not inspect IPv6).
pub fn parse_socket_addr(entry: &str) -> Result<std::net::SocketAddrV4> {
    entry
        .parse()
        .with_context(|| format!("expected \"ipv4:port\", got '{entry}'"))
}

/// Parses "ip:port/tcp" or "ip:port/udp" into the address and its IP protocol.
pub fn parse_exclude(entry: &str) -> Result<(std::net::SocketAddrV4, u8)> {
    let (addr, proto) = entry
        .rsplit_once('/')
        .with_context(|| format!("expected \"ipv4:port/tcp\" or \"ipv4:port/udp\", got '{entry}'"))?;
    let proto = match proto {
        "tcp" => libc::IPPROTO_TCP as u8,
        "udp" => libc::IPPROTO_UDP as u8,
        other => bail!("unknown protocol '{other}', expected tcp or udp"),
    };
    Ok((parse_socket_addr(addr)?, proto))
}

/// Parses "a.b.c.d/len" into (network address, prefix length).
pub fn parse_cidr(entry: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (addr, len) = entry.split_once('/').unwrap_or((entry, "32"));
    let addr: std::net::Ipv4Addr = addr
        .parse()
        .with_context(|| format!("invalid network address in '{entry}'"))?;
    let len: u8 = len
        .parse()
        .with_context(|| format!("invalid prefix length in '{entry}'"))?;
    if len > 32 {
        bail!("prefix length of '{entry}' must be <= 32");
    }
    Ok((addr, len))
}

impl AutodetectConfig {
    fn validate(&self) -> Result<()> {
        for network in &self.networks {
            parse_cidr(network).context("[autodetect] networks")?;
        }
        if self.enabled && self.networks.is_empty() {
            bail!("[autodetect] networks must not be empty when auto detection is enabled");
        }
        check_range("[autodetect] probe_interval_secs", self.probe_interval_secs, 10, 86_400)?;
        check_range("[autodetect] probe_timeout_ms", self.probe_timeout_ms, 100, 30_000)?;
        check_range("[autodetect] remove_after_secs", self.remove_after_secs, 60, 30 * 86_400)?;
        check_range("[autodetect] retry_negative_secs", self.retry_negative_secs, 10, 30 * 86_400)
    }
}

impl XdpConfig {
    fn validate(&self) -> Result<()> {
        const MAX_ENTRIES: u64 = 1 << 20;
        check_range(
            "[xdp] max_pending_connections",
            self.max_pending_connections as u64,
            1,
            MAX_ENTRIES,
        )?;
        check_range(
            "[xdp] max_player_connections",
            self.max_player_connections as u64,
            1,
            MAX_ENTRIES,
        )?;
        check_range(
            "[xdp] max_throttled_ips",
            self.max_throttled_ips as u64,
            1,
            MAX_ENTRIES,
        )
    }
}

impl MetricsConfig {
    fn validate(&self) -> Result<()> {
        check_range("[metrics] poll_secs", self.poll_secs, 1, 3_600)
    }
}

impl LoggingConfig {
    fn validate(&self) -> Result<()> {
        check_range("[logging] file_max_mb", self.file_max_mb, 1, 10_240)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_default_matches_struct_default() {
        // The documented template shipped to users must parse and agree with
        // Config::default (metrics addr is commented out -> None).
        let parsed: Config = toml::from_str(DEFAULT_CONFIG_TOML).expect("default toml parses");
        assert_eq!(parsed, Config::default());
        parsed.validate().expect("default config is valid");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>("nonsense_key = 1").unwrap_err();
        assert!(err.to_string().contains("nonsense_key"));
        // also inside a section
        assert!(toml::from_str::<Config>("[filter]\nnonsense_key = 1").is_err());
    }

    #[test]
    fn partial_config_falls_back_to_defaults() {
        let cfg: Config =
            toml::from_str("[filter]\nhit_count = 0\n\n[metrics]\nenabled = true").unwrap();
        assert_eq!(cfg.filter.hit_count, 0); // throttle disabled
        assert!(cfg.metrics.enabled);
        assert_eq!(cfg.filter.start_port, 25565); // default preserved
        assert_eq!(cfg.xdp.mode, ConfigXdpMode::Auto); // untouched section defaulted
    }

    #[test]
    fn rejects_inverted_port_range() {
        let cfg: Config = toml::from_str("[filter]\nstart_port = 30000\nend_port = 25565").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_start_port() {
        let cfg: Config = toml::from_str("[filter]\nstart_port = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_disabled_static_range() {
        let cfg: Config = toml::from_str("[filter]\nstart_port = 0\nend_port = 0").unwrap();
        cfg.validate().expect("0/0 disables the static range");
    }

    #[test]
    fn parses_targets_and_excludes() {
        let cfg: Config = toml::from_str(
            "[targets]\njava = [\"85.93.5.1:25569\"]\nexclude = [\"85.93.5.55:443/tcp\"]",
        )
        .unwrap();
        cfg.validate().expect("valid targets");
        assert!(parse_exclude("1.2.3.4:5/icmp").is_err());
        assert!(parse_socket_addr("1.2.3.4").is_err());
        assert_eq!(parse_cidr("85.93.5.0/24").unwrap().1, 24);
    }

    #[test]
    fn reflection_requires_networks() {
        let cfg: Config = toml::from_str("[reflection]\nmode = \"monitor\"").unwrap();
        assert!(cfg.validate().is_err());
        let cfg: Config =
            toml::from_str("[reflection]\nmode = \"enforce\"\nnetworks = [\"85.93.5.0/24\"]").unwrap();
        cfg.validate().expect("valid reflection config");
    }

    #[test]
    fn ratelimit_validation() {
        let cfg: Config = toml::from_str("[ratelimit]\nmode = \"enforce\"").unwrap();
        assert!(cfg.validate().is_err()); // no networks
        let cfg: Config = toml::from_str(
            "[ratelimit]\nmode = \"enforce\"\nnetworks = [\"85.93.5.0/24\"]\nallow = [\"1.2.3.4\"]",
        )
        .unwrap();
        cfg.validate().expect("valid rate limit");
        let cfg: Config = toml::from_str("[blocklist]\nentries = [\"nope\"]").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn unused_requires_networks() {
        let cfg: Config = toml::from_str("[unused]\nenabled = true").unwrap();
        assert!(cfg.validate().is_err());
        let cfg: Config =
            toml::from_str("[unused]\nenabled = true\nnetworks = [\"85.93.5.0/24\"]").unwrap();
        cfg.validate().expect("valid unused config");
    }

    #[test]
    fn autodetect_requires_networks() {
        let cfg: Config = toml::from_str("[autodetect]\nenabled = true").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_reset_window() {
        let cfg: Config = toml::from_str("[filter]\nhit_count_reset_secs = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_oversized_reset_window() {
        let cfg: Config = toml::from_str("[filter]\nhit_count_reset_secs = 86401").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_idle_timeout() {
        let cfg: Config = toml::from_str("[filter]\nplayer_idle_timeout_secs = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_oversized_idle_timeout() {
        let cfg: Config = toml::from_str("[filter]\nplayer_idle_timeout_secs = 86401").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_xdp_mode() {
        let err = toml::from_str::<Config>("[xdp]\nmode = \"hardware\"").unwrap_err();
        assert!(err.to_string().contains("hardware"));
    }

    #[test]
    fn rejects_zero_map_capacity() {
        for option in [
            "max_pending_connections",
            "max_player_connections",
            "max_throttled_ips",
        ] {
            let cfg: Config = toml::from_str(&format!("[xdp]\n{option} = 0")).unwrap();
            assert!(cfg.validate().is_err(), "{option} = 0 must be rejected");
        }
    }

    #[test]
    fn rejects_zero_poll_interval() {
        let cfg: Config = toml::from_str("[metrics]\npoll_secs = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_log_level() {
        let err = toml::from_str::<Config>("[logging]\nlevel = \"verbose\"").unwrap_err();
        assert!(err.to_string().contains("verbose"));
    }
}
