use anyhow::{Context, Result};
use aya::programs::{Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader, include_bytes_aligned};
use log::info;

use crate::config::{Config, ConfigXdpMode};

/// Loads the embedded eBPF object, applies the runtime configuration and
/// attaches the XDP program to `interface`.
///
/// The returned handle owns the attachment: dropping it detaches the filter.
/// No userspace involvement is needed while it runs, all map cleanup
/// (throttle windows, idle player connections) happens in-kernel via
/// `bpf_timer`.
pub fn load_and_attach(interface: &str, config: &Config) -> Result<Ebpf> {
    let object = include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/xdp/minecraft_filter.o"
    ));
    info!("Loaded BPF object ({} bytes)", object.len());

    // Push the runtime configuration into the program's `volatile const`
    // globals (BPF .rodata). Each Rust type MUST match its C declaration in
    // xdp/config.h exactly, since set_global() patches size_of::<T>() bytes at
    // the symbol's offset. `must_exist = true` fails loudly if a symbol is
    // missing (e.g. renamed on the C side) instead of silently ignoring the
    // configured value.
    let filter = &config.filter;
    let prometheus: u8 = config.metrics.enabled as u8;
    let online_names: u8 = filter.online_names as u8;
    let start_port: u32 = filter.start_port as u32;
    let end_port: u32 = filter.end_port as u32;
    let hit_count: u32 = filter.hit_count;
    let hit_count_reset_ns: u64 = filter.hit_count_reset_secs * 1_000_000_000;
    let player_idle_ns: u64 = filter.player_idle_timeout_secs * 1_000_000_000;
    // established flows to the static range are adopted for a while after
    // start, so a restart does not kick the connected players
    let unused_drop: u8 = config.unused.enabled as u8;
    let blocklist_active: u8 = config.blocklist.enabled as u8;
    let ratelimit_mode: u8 = match config.ratelimit.mode {
        crate::config::ProtectionMode::Off => 0,
        crate::config::ProtectionMode::Monitor => 1,
        crate::config::ProtectionMode::Enforce => 2,
    };
    let ratelimit_pps: u64 = config.ratelimit.pps;
    let ratelimit_ban_ns: u64 = config.ratelimit.ban_secs * 1_000_000_000;
    let strike_limit: u64 = config.ratelimit.strikes;
    let strike_window_ns: u64 = config.ratelimit.strike_window_secs * 1_000_000_000;
    let web_enforce: u8 = (config.web.mode == crate::config::ProtectionMode::Enforce) as u8;
    let web_hit_count: u32 = config.web.hit_count;
    let web_idle_ns: u64 = config.web.idle_timeout_secs * 1_000_000_000;
    let static_grace_until_ns: u64 =
        crate::targets::monotonic_ns() + filter.adopt_grace_secs * 1_000_000_000;

    let mut ebpf = EbpfLoader::new()
        .override_global("PROMETHEUS", &prometheus, true)
        .override_global("ONLINE_NAMES", &online_names, true)
        .override_global("START_PORT", &start_port, true)
        .override_global("END_PORT", &end_port, true)
        .override_global("STATIC_GRACE_UNTIL_NS", &static_grace_until_ns, true)
        .override_global("UNUSED_DROP", &unused_drop, true)
        .override_global("BLOCKLIST_ACTIVE", &blocklist_active, true)
        .override_global("RATELIMIT_MODE", &ratelimit_mode, true)
        .override_global("RATELIMIT_PPS", &ratelimit_pps, true)
        .override_global("RATELIMIT_BAN_NS", &ratelimit_ban_ns, true)
        .override_global("STRIKE_LIMIT", &strike_limit, true)
        .override_global("STRIKE_WINDOW_NS", &strike_window_ns, true)
        .override_global("WEB_ENFORCE", &web_enforce, true)
        .override_global("WEB_HIT_COUNT", &web_hit_count, true)
        .override_global("WEB_IDLE_NS", &web_idle_ns, true)
        .override_global("HIT_COUNT", &hit_count, true)
        .override_global("HIT_COUNT_RESET_NS", &hit_count_reset_ns, true)
        .override_global("PLAYER_IDLE_NS", &player_idle_ns, true)
        // Replace the placeholder map capacities baked into the object with
        // the configured ones. The names must match the map definitions in
        // xdp/minecraft_filter.c; unlike set_global() there is no must_exist
        // flag, a mismatched name would be silently ignored.
        .map_max_entries("conntrack_map", config.xdp.max_pending_connections)
        .map_max_entries("player_connection_map", config.xdp.max_player_connections)
        .map_max_entries("connection_throttle", config.xdp.max_throttled_ips)
        .map_max_entries("web_throttle", config.xdp.max_throttled_ips)
        .load(object)
        .context("failed to load BPF program")?;

    let program: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .context("program 'minecraft_filter' not found")?
        .try_into()?;
    program.load()?;

    // Auto does its own driver -> skb fallback instead of leaving the choice
    // to the kernel, so the mode that is actually active can be logged.
    let (link, mode) = match config.xdp.mode {
        ConfigXdpMode::Auto => match program.attach(interface, XdpMode::Driver) {
            Ok(link) => (link, ConfigXdpMode::Driver),
            Err(err) => {
                info!("'{interface}' does not support native XDP ({err}), using generic skb mode");
                let link = program
                    .attach(interface, aya::programs::XdpMode::Skb)
                    .with_context(|| format!("failed to attach to interface '{interface}'"))?;
                (link, ConfigXdpMode::Skb)
            }
        },
        ConfigXdpMode::Driver => {
            let link = program
                .attach(interface, XdpMode::Driver)
                .with_context(|| {
                    format!(
                        "failed to attach to interface '{interface}' in native driver mode \
                     (the NIC driver may not support XDP; try mode = \"skb\")"
                    )
                })?;
            (link, ConfigXdpMode::Driver)
        }
        ConfigXdpMode::Skb => {
            let link = program.attach(interface, XdpMode::Skb).with_context(|| {
                format!("failed to attach to interface '{interface}' in skb mode")
            })?;
            (link, ConfigXdpMode::Skb)
        }
    };
    info!("BPF program attached to interface {interface} in {mode} mode ({link:?})");

    for (name, _) in ebpf.maps() {
        info!("Found map: {name}");
    }

    Ok(ebpf)
}
