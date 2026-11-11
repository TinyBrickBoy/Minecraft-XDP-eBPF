# Minecraft XDP Filter using eBPF – L7 DDoS Protection

This project offers a high-performance XDP-based firewall utilizing eBPF, specifically designed for Minecraft Java Edition servers.  
It effectively mitigates L7 DDoS attacks by filtering malicious packets at the kernel level (before they reach the network stack).  
The filter protects IPv4 and IPv6 and supports Minecraft versions 1.8 - 26.3    
The default filtered port is 25565.

💬 Questions, feedback or help needed? Join the Discord: https://discord.gg/JnBJPgV4GW

## Fork additions

This fork of [Outfluencer/Minecraft-XDP-eBPF](https://github.com/Outfluencer/Minecraft-XDP-eBPF) adds:

- **Live target list**: protected destinations are kept per `ip:port/proto` in
  a kernel map that is changed at runtime, no reload needed. The `[filter]`
  port range still works as a static java range (`0`/`0` disables it).
- **Auto detection** (`[autodetect]`): listening sockets of the host and
  servers answering through `sniff_interfaces` (TCP SYN-ACKs, RakNet pongs,
  sampled and filtered in the kernel) become candidates; only candidates that
  answer a real java status ping or RakNet ping get protected. A protected
  server that stops answering stays protected for `remove_after_secs`, so an
  attack can not switch its own protection off. Detected servers survive
  restarts via `state_file`.
- **Bedrock (RakNet)**: unverified flows may only send valid offline
  handshake messages (magic checked, throttled per source ip); a valid open
  connection request 2 verifies the flow. Amplification source ports and
  fragments are dropped.
- **No kicks on restart/update**: established connections are adopted during
  `adopt_grace_secs` after the loader starts and after a target is added.
  `contrib/update.sh` builds and tests in docker, checks the config with the
  new binary, installs atomically, restarts and rolls back on a failed
  health check.
- **Per target metrics**: `minecraft_target_*{dst_ip,dst_port,proto}` and
  `minecraft_target_protected{...,kind,source}`.
- **UDP reflection protection** (`[reflection]`) for whole networks: a tc
  egress program records requests of protected addresses to abused service
  ports (DNS, NTP, memcached, SSDP, ...); answers from those ports pass only
  when they match a recorded request, non-first UDP fragments are dropped.
  `mode = "monitor"` only counts (`xdp_reflection_*` metrics), `"enforce"`
  drops; enforcing is only switched on once the recorder is attached.
- **Unused address drop** (`[unused]`): traffic to addresses of the
  configured networks that the kernel has no route for (unreachable,
  blackhole, prohibit; decided per packet with `bpf_fib_lookup`) is dropped
  at the driver instead of walking the stack and triggering ICMP errors.
  Routing an address makes it reachable at once (`xdp_unused_*` metrics).
- **Blocklist and rate limit** (`[blocklist]`, `[ratelimit]`): sources in a
  live reloaded file (addresses and prefixes) are dropped before anything
  else; a source sending more than `pps` packets per second to the protected
  networks is banned for `ban_secs` (allowlist for own proxies/CDNs). Bans
  are logged, per source counters are exported (`xdp_blocklist_*`,
  `xdp_ratelimit_*`).
- **Manual overrides** (`[targets]`): always protected `java`/`bedrock`
  entries and `exclude` entries that are never filtered.
- **IPv6**: every feature works for IPv6 destinations and sources. Targets
  are written as `"[2001:db8::10]:25565"`, networks as `"2001:db8::/48"`;
  v4-mapped input (`::ffff:a.b.c.d`) and IPv6 networks overlapping
  `::ffff:0:0/96` (`::/0`, `::/64`, ...) are rejected, write IPv4 as
  `a.b.c.d`; the kernel stores IPv4 v4-mapped, so such a network would also
  match every IPv4 address (automatic bans are never escalated to one).
  IPv6 packets from `::/80` (`::1`, v4-mapped, ...) or multicast sources and
  to `::/80` destinations never appear on the wire and are dropped for every
  destination; only neighbour solicitations from `::` (duplicate address
  detection) pass.
  Throttle, rate limit, strikes, bans and the penalty box count IPv6
  sources per `[filter] ipv6_source_prefix` (default /64). IPv6 fragments
  to protected targets are dropped. Packets with more than four extension
  headers or a truncated header chain cannot be matched to a port: they are
  dropped when the destination address has any protected target (any port)
  or a static java port range is configured, and pass to other
  destinations. Neighbour discovery (ICMPv6 133-137) is never dropped. DNS
  scan detection blocklists IPv6 scanners per exact address. IPv4 `/32`
  and IPv6 `/128` entries are shown as plain addresses everywhere (logs,
  auto-blocklist file, state file, `source` label of `xdp_ratelimit_ban`);
  real prefixes keep their length. The `source` label of a ban is the
  banned /64 prefix for IPv6 (`2001:db8::/64`) and the plain address for
  IPv4. The penalty box uses an nftables `inet` table (`xdp_penalty`) with
  ip and ip6 dnat; a legacy `ip xdp_penalty` table of older versions is
  removed automatically. Each family is set up on its own: the service
  listens on the interface's first IPv4 and first global IPv6 address (any
  global IPv6 address of the host when the interface has none); a family
  without an address or whose listener can not be bound stays without the
  penalty box (its throttled clients are dropped as with `enabled = false`)
  and gets no redirect rule, the other family keeps it.

Tests: `cargo test` and `tests/e2e_docker.sh` (real traffic through the
filter inside an isolated privileged container, see the script header).

## Features
- **Protocol Analysis**: Analyzes Minecraft handshakes, status, ping, and login requests.
- **Deep Packet Inspection**: Drops invalid packets, bad VarInts, and protocol violations.
- **Connection Throttle**: Integrated SYN rate limiting (default: 10 SYNs per 3 seconds per IP).
- **Zero-Copy Dropping**: Malicious traffic is dropped at the driver level (XDP_DROP) for maximum performance.

## Installation (Linux)

### Download from releases

https://github.com/Outfluencer/Minecraft-XDP-eBPF/releases

You can download the latest build from the Releases Tab  
Then just run the executable in sudo mode or via root

### Prerequisites
- Rust toolchain (stable)
- **System Dependencies**:
  ```bash
  sudo apt update
  sudo apt install -y gcc-multilib wget gnupg software-properties-common git libbpf-dev
  ```
  If software-properties-common was not found remove it from the command.
- **LLVM/Clang Toolchain**:
  The build requires a recent LLVM version (CI uses LLVM 21).
  ```bash
  wget https://apt.llvm.org/llvm.sh
  chmod +x llvm.sh
  sudo ./llvm.sh 21 all
  ```

### Build & Run
1.  **Build the project**:
    ```bash
    ./build.sh
    ```
    The compiled binary will be at `target/release/xdp-loader`.

2.  **Run the tests** (optional):
    ```bash
    cargo test
    ```
    Besides the Rust unit tests this compiles the eBPF parsing code (VarInt
    reader, packet inspectors) natively with ASan/UBSan and runs its C unit
    tests (see `xdp/tests/protocol_test.c`).

3.  **Run the firewall**:
    ```bash
    sudo ./target/release/xdp-loader <network_interface>
    # Example:
    sudo ./target/release/xdp-loader eth0
    ```

    To enable Prometheus metrics export, set `enabled = true` and an `addr`
    in the `[metrics]` section of `config.toml` (see
    [Configuration](#configuration)), then run the loader normally. With
    `addr = "127.0.0.1:1999"` the metrics are available at:
    `http://127.0.0.1:1999/metrics`

**Note:** This project uses a persistent XDP loader. The userspace program must stay running to keep the filter attached; all map state (throttle windows, verified connections) is managed in-kernel via `bpf_timer`. Stopping the loader will unload the firewall. Requires Linux kernel 5.15 or newer.

## Configuration

Runtime behavior is controlled by a `config.toml` file next to the binary.
On first run it is created automatically with documented defaults; edit it and
restart the loader. Use `--config <path>` to point at a different file.

**`[filter]`** — what traffic is filtered and how strictly:

| Option         | Type   | Default | Description |
|----------------|--------|---------|-------------|
| `start_port`   | int    | 25565   | First port of the inclusive filtered range. |
| `end_port`     | int    | 25565   | Last port of the inclusive filtered range. |
| `hit_count`    | int    | 10      | Max SYNs per source IP per throttle window (`0` disables throttling). |
| `hit_count_reset_secs` | int | 3   | Throttle window length in seconds; each IP's SYN counter resets in-kernel once its window expires. |
| `player_idle_timeout_secs` | int | 60 | Idle timeout for verified connections; an idle entry is removed in-kernel after one to two intervals, requiring a new handshake. |
| `online_names` | bool   | true    | Enforce online-mode usernames (≤16 chars). |
| `ipv6_source_prefix` | int | 64 | Prefix length per IPv6 source for throttling, rate limits and bans (32–128). IPv4 is always per address. |

**`[xdp]`** — how the program attaches and the capacity of its in-kernel tables
(the maps are preallocated, so higher limits cost kernel memory up front):

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `mode` | string | `"auto"` | XDP attach mode: `"auto"` (native if the NIC supports it, automatic fallback to generic), `"driver"` (force native, fails when unsupported) or `"skb"` (force generic; works everywhere, slower). |
| `max_pending_connections` | int | 16384 | Concurrent connections mid-handshake; the least-recently-used entry is evicted when full. |
| `max_player_connections` | int | 65535 | Concurrent verified player connections; size well above the expected player count. |
| `max_throttled_ips` | int | 65535 | Source IPs tracked by the SYN throttle; new SYNs are dropped while full (fail closed). |

**`[metrics]`** — statistics collection and the Prometheus endpoint:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | false | Collect packet statistics inside the eBPF program. |
| `addr` | string | (unset) | Address for the Prometheus HTTP endpoint (requires `enabled = true`). |
| `poll_secs` | int | 10 | How often the in-kernel statistics are read and published. |

**`[logging]`** — console and file logging:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `level` | string | `"info"` | Verbosity: `"off"`, `"error"`, `"warn"`, `"info"`, `"debug"` or `"trace"`. Overridden by the `RUST_LOG` env variable. |
| `file_max_mb` | int | 100 | Rotate `xdp-loader.log` once it grows past this size; the 5 newest rotated files are kept. |

The `[filter]` values and map capacities are pushed into the eBPF program at
load time (via `.rodata` globals and map definitions), so changing them only
requires a restart — **not a rebuild**.  

## Troubleshooting

### Non-root / Permission Errors
Please always check if you are running as root if any error occurred. If you are not, try again with `sudo`.  

⭐ **Don't forget to star the project on GitHub!**  
