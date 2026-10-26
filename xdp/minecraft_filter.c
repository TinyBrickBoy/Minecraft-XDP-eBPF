/*
 * minecraft_filter - XDP program protecting Minecraft Java Edition servers
 * against L7 (D)DoS attacks.
 *
 * Which destinations are protected, and as what, is decided per ip:port in
 * the protected_targets map (filled live by the loader's auto detection) plus
 * the optional static java port range from the config. Java targets get the
 * TCP state machine below, bedrock targets the RakNet checks in handle_udp().
 *
 * Every TCP packet for a protected java target runs through a small state
 * machine that validates the TCP handshake and the first Minecraft packets
 * of the connection (handshake, then status+ping or login). Connections that
 * complete the sequence are promoted to a verified fast path and are no
 * longer inspected; everything else is dropped at the driver level. New
 * connections are additionally rate limited per source ip. All map cleanup
 * happens in-kernel via bpf_timer, userspace never has to touch the maps.
 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/time.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "config.h"
#include "protocol.h"
#include "stats.h"

// fragment bits of iphdr->frag_off (kernel-internal net/ip.h, not uapi)
#ifndef IP_MF
#define IP_MF 0x2000 // flag: "more fragments"
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF // "fragment offset" part
#endif

#include "reflection.h"
#include "unused.h"

/* ------------------------------------------------------------------------
 * Connection tracking of unverified connections
 * --------------------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);          // placeholder, set by the loader ([xdp] max_pending_connections)
    __type(key, struct ipv4_flow_key);   // flow key
    __type(value, struct initial_state); // inspection state machine data
} conntrack_map SEC(".maps");

/* ------------------------------------------------------------------------
 * Verified connections (players)
 * --------------------------------------------------------------------- */

struct player_entry
{
    struct bpf_timer timer; // deletes the entry when the connection goes idle
    __u64 packets;          // incremented for every packet of this flow
    __u64 last_packets;     // snapshot taken by the idle check timer
    __u64 idle_ns;          // idle check interval of this connection
};
_Static_assert(sizeof(struct player_entry) == 40, "player_entry size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);         // placeholder, set by the loader ([xdp] max_player_connections)
    __type(key, struct ipv4_flow_key);  // flow key
    __type(value, struct player_entry); // idle timer + packet counter
} player_connection_map SEC(".maps");

/*
 * bpf_timer callback: delete the verified connection if it was idle for a
 * full interval, otherwise snapshot the counter and check again next interval
 */
static __s32 player_connection_idle_check(void *map, struct ipv4_flow_key *key, struct player_entry *entry)
{
    const __u64 packets = entry->packets;
    if (packets == entry->last_packets)
    {
        bpf_map_delete_elem(map, key);
        return 0;
    }
    entry->last_packets = packets;
    // re-arming can only fail if this entry is concurrently being freed (map
    // delete/teardown NULLs the timer under its lock); then there is nothing
    // left to re-arm, so the result is deliberately ignored
    bpf_timer_start(&entry->timer, entry->idle_ns, 0);
    return 0;
}

/* ------------------------------------------------------------------------
 * Per-ip connection throttle
 * --------------------------------------------------------------------- */

struct throttle_entry
{
    struct bpf_timer timer; // deletes the entry when the window expires
    __u32 hits;             // SYNs counted within the current window
    __u32 pad;
};
_Static_assert(sizeof(struct throttle_entry) == 24, "throttle_entry size mismatch!");

struct
{
    // plain HASH on purpose (no LRU): during a big attack the map fills up,
    // inserts fail and ALL unverified traffic is dropped; only verified
    // connections keep passing. Capacity recovers in-kernel as the per-entry
    // timers fire and delete the expired windows.
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);           // placeholder, set by the loader ([xdp] max_throttled_ips)
    __type(key, __u32);                   // ipv4 source address
    __type(value, struct throttle_entry); // window timer + hit counter
} connection_throttle SEC(".maps");

// same, for web targets (own limit: browsers open many connections at once)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);           // placeholder, set by the loader ([xdp] max_throttled_ips)
    __type(key, __u32);                   // ipv4 source address
    __type(value, struct throttle_entry); // window timer + hit counter
} web_throttle SEC(".maps");

// while connection_throttle is full, only retry inserting after this long
// (per core): a failed insert on a full preallocated map scans every cpu's
// freelist under spinlocks, so during that time we drop without even trying
#define THROTTLE_BACKOFF_NS (100ULL * 1000000ULL) // 100ms

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); // per-cpu: no insert retry before this ktime
} throttle_insert_backoff SEC(".maps");

/*
 * bpf_timer callback: the throttle window of this ip is over. Entries that
 * saw SYNs during the window are recycled (counter reset, timer re-armed) so
 * repeat senders cause no map/timer churn; entries that were idle for the
 * whole window are deleted.
 */
static __s32 throttle_window_expired(void *map, __u32 *key, struct throttle_entry *entry)
{
    if (__sync_lock_test_and_set(&entry->hits, 0) == 0)
    {
        bpf_map_delete_elem(map, key);
        return 0;
    }
    // re-arming can only fail if this entry is concurrently being freed (map
    // delete/teardown NULLs the timer under its lock); then there is nothing
    // left to re-arm, so the result is deliberately ignored
    bpf_timer_start(&entry->timer, HIT_COUNT_RESET_NS, 0);
    return 0;
}

/* ------------------------------------------------------------------------
 * Statistics (only used when PROMETHEUS is enabled, see stats.h)
 * --------------------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct statistics);
} stats_map SEC(".maps");

// per destination ip:port statistics, so the metrics show which address is
// being attacked. LRU so a flood across many addresses can never fail an
// insert, at worst the least active destinations lose their counters
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dst_key);
    __type(value, struct statistics);
} dst_stats_map SEC(".maps");

/* ------------------------------------------------------------------------
 * Protected targets
 * --------------------------------------------------------------------- */

enum target_kind
{
    KIND_NONE = 0,    // explicitly unprotected (overrides the static range)
    KIND_JAVA = 1,    // TCP, minecraft java state machine
    KIND_BEDROCK = 2, // UDP, RakNet offline handshake checks
    KIND_HTTP = 3,    // TCP, first segment must be an http request line
    KIND_HTTPS = 4,   // TCP, first segment must be a TLS ClientHello
};

// must match `TargetEntry` in loader/targets.rs
struct target_entry
{
    __u64 grace_until_ns; // ktime until which established flows are adopted
    __u8 kind;            // enum target_kind
    __u8 pad[7];
};
_Static_assert(sizeof(struct target_entry) == 16, "target_entry size mismatch!");

// written by the loader at runtime, so targets can be added and removed
// without reloading the program (which would drop all verified connections)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dst_key);
    __type(value, struct target_entry);
} protected_targets SEC(".maps");

/*
 * Returns how daddr:dport/proto is protected. *grace is set when the target
 * is within its adoption window: flows that were established before the
 * target became protected (or before the loader started) are unknown to our
 * maps, and without adoption they would all be cut off.
 */
static __always_inline __u8 lookup_target(const __u32 daddr, const __u16 dport, const __u8 proto, __u8 *grace)
{
    const struct dst_key key = {.daddr = daddr, .dport = dport, .proto = proto, .pad = 0};
    const struct target_entry *target = bpf_map_lookup_elem(&protected_targets, &key);
    if (target)
    {
        *grace = bpf_ktime_get_ns() < target->grace_until_ns;
        return target->kind;
    }

    const __u16 port = bpf_ntohs(dport);
    if (proto == IPPROTO_TCP && START_PORT && port >= START_PORT && port <= END_PORT)
    {
        *grace = bpf_ktime_get_ns() < STATIC_GRACE_UNTIL_NS;
        return KIND_JAVA;
    }
    return KIND_NONE;
}

/*
 * Looks up the global and the per destination statistics slots. Returns 0
 * only if the global slot is missing, which can not happen (per-cpu array
 * index 0 always exists).
 */
static __always_inline __u8 lookup_stats(const __u32 daddr, const __u16 dport, const __u8 proto,
                                         struct statistics **stats_ptr, struct statistics **dst_stats_ptr)
{
    if (!PROMETHEUS)
    {
        return 1;
    }

    __u32 key = 0;
    *stats_ptr = bpf_map_lookup_elem(&stats_map, &key);
    if (!*stats_ptr)
    {
        return 0;
    }

    const struct dst_key dst = {.daddr = daddr, .dport = dport, .proto = proto, .pad = 0};
    *dst_stats_ptr = bpf_map_lookup_elem(&dst_stats_map, &dst);
    if (!*dst_stats_ptr)
    {
        const struct statistics zero = {0};
        bpf_map_update_elem(&dst_stats_map, &dst, &zero, BPF_NOEXIST);
        *dst_stats_ptr = bpf_map_lookup_elem(&dst_stats_map, &dst);
    }
    return 1;
}

/* ------------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

// flag combinations that never occur on legitimate client traffic
static __always_inline __u8 detect_tcp_bypass(const struct tcphdr *tcp)
{
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) || // none of SYN/ACK/FIN/RST set
        (tcp->syn && tcp->ack) ||                             // SYN+ACK from outside is never a client
        (tcp->syn && (tcp->fin || tcp->rst)) ||               // SYN+FIN / SYN+RST are always forged
        tcp->urg)                                             // URG is unused by the protocol
    {
        return 1;
    }
    return 0;
}

/*
 * Connection throttle, fully in kernel: every source ip gets its own window
 * of HIT_COUNT_RESET_NS, opened by its first new connection and closed by the
 * bpf_timer that deletes the entry again. Returns 0 when the source has used
 * up its window or the throttle map is full (fail closed).
 */
static __always_inline __u8 throttle_allows_in(void *throttle_map, const __u32 src_ip, const __u32 limit)
{
    if (!limit)
    {
        return 1;
    }

    struct throttle_entry *entry = bpf_map_lookup_elem(throttle_map, &src_ip);
    if (entry)
    {
        if (entry->hits >= limit)
        {
            return 0;
        }
        __sync_fetch_and_add(&entry->hits, 1);
        return 1;
    }

    __u32 zero = 0;
    __u64 *backoff = bpf_map_lookup_elem(&throttle_insert_backoff, &zero);
    if (!backoff)
    {
        // per-cpu array index 0 always exists, this is unreachable
        return 0;
    }
    const __u64 now = bpf_ktime_get_ns();
    if (now < *backoff)
    {
        // the map was full just before: fail closed without
        // paying for another doomed insert attempt
        return 0;
    }
    const struct throttle_entry fresh = {.hits = 1, .pad = 0};
    const long err = bpf_map_update_elem(throttle_map, &src_ip, &fresh, BPF_NOEXIST);
    if (err < 0)
    {
        if (err != -EEXIST)
        {
            // map full (attack): fail closed and back off
            *backoff = now + THROTTLE_BACKOFF_NS;
        }
        return 0;
    }
    entry = bpf_map_lookup_elem(throttle_map, &src_ip);
    if (!entry)
    {
        return 0;
    }
    if (bpf_timer_init(&entry->timer, throttle_map, CLOCK_MONOTONIC) < 0 ||
        bpf_timer_set_callback(&entry->timer, throttle_window_expired) < 0 ||
        bpf_timer_start(&entry->timer, HIT_COUNT_RESET_NS, 0) < 0)
    {
        // never leak an entry that has no expiry timer armed
        bpf_map_delete_elem(throttle_map, &src_ip);
        return 0;
    }
    return 1;
}

static __always_inline __u8 throttle_allows(const __u32 src_ip)
{
    return throttle_allows_in(&connection_throttle, src_ip, HIT_COUNT);
}

/*
 * The connection passed the full inspection sequence (or is adopted during a
 * grace window, see lookup_target): move it from the conntrack map into the
 * player map so its packets skip inspection from now on, and arm the idle
 * timer that will eventually clean the entry up. `stat` is the counter that
 * records the promotion (VERIFIED or ADOPTED).
 */
static __always_inline __u32 switch_to_verified_idle(const __u64 raw_packet_len, struct statistics *stats_ptr, struct statistics *dst_stats_ptr, const struct ipv4_flow_key *flow_key, const __u32 stat, const __u64 idle_ns)
{
    bpf_map_delete_elem(&conntrack_map, flow_key);
    const struct player_entry fresh = {.packets = 1, .last_packets = 0, .idle_ns = idle_ns};
    if (bpf_map_update_elem(&player_connection_map, flow_key, &fresh, BPF_NOEXIST) < 0)
    {
        goto drop;
    }
    struct player_entry *entry = bpf_map_lookup_elem(&player_connection_map, flow_key);
    if (!entry)
    {
        goto drop;
    }
    if (bpf_timer_init(&entry->timer, &player_connection_map, CLOCK_MONOTONIC) < 0 ||
        bpf_timer_set_callback(&entry->timer, player_connection_idle_check) < 0 ||
        bpf_timer_start(&entry->timer, idle_ns, 0) < 0)
    {
        // never leak an entry that has no idle timer armed
        bpf_map_delete_elem(&player_connection_map, flow_key);
        goto drop;
    }
    count_stats(stats_ptr, dst_stats_ptr, stat, 1);
    return XDP_PASS;
drop:
    count_stats(stats_ptr, dst_stats_ptr, DROPPED_BYTES, raw_packet_len);
    count_stats(stats_ptr, dst_stats_ptr, DROP_CONNECTION | DROPPED_PACKET, 1);
    return XDP_DROP;
}

static __always_inline __u32 switch_to_verified(const __u64 raw_packet_len, struct statistics *stats_ptr, struct statistics *dst_stats_ptr, const struct ipv4_flow_key *flow_key, const __u32 stat)
{
    return switch_to_verified_idle(raw_packet_len, stats_ptr, dst_stats_ptr, flow_key, stat, PLAYER_IDLE_NS);
}

/* ------------------------------------------------------------------------
 * Bedrock (RakNet over UDP)
 * --------------------------------------------------------------------- */

// RakNet offline message ids sent by clients
#define RAKNET_UNCONNECTED_PING 0x01
#define RAKNET_UNCONNECTED_PING_OPEN 0x02
#define RAKNET_OPEN_CONNECTION_REQUEST_1 0x05
#define RAKNET_OPEN_CONNECTION_REQUEST_2 0x07

// minimum payload sizes: id + time + magic + guid for pings, id + magic +
// protocol (+ mtu padding) for request 1, id + magic + ipv4 address + mtu +
// guid for request 2
#define RAKNET_PING_LEN 33
#define RAKNET_REQUEST_1_MIN_LEN 18
#define RAKNET_REQUEST_2_MIN_LEN 34

/*
 * Checks the 16 byte RakNet offline message magic
 * 00 ff ff 00 fe fe fe fe fd fd fd fd 12 34 56 78 at p, compared as two
 * little endian u64 words.
 */
static __always_inline __u8 raknet_magic_at(const __u8 *p, const void *data_end)
{
    if ((const void *)(p + 16) > data_end)
    {
        return 0;
    }
    __u64 first, second;
    __builtin_memcpy(&first, p, 8);
    __builtin_memcpy(&second, p + 8, 8);
    return first == 0xfefefefe00ffff00ULL && second == 0x78563412fdfdfdfdULL;
}

// source ports of common UDP reflection/amplification services; a RakNet
// client always sends from an ephemeral port
static __always_inline __u8 is_amplification_port(const __u16 port)
{
    switch (port)
    {
    case 0: case 7: case 17: case 19: case 53: case 69: case 111: case 123:
    case 137: case 138: case 161: case 162: case 389: case 427: case 520:
    case 1900: case 3283: case 3702: case 5353: case 5683: case 10001:
    case 11211:
        return 1;
    }
    return 0;
}

/*
 * UDP packets for protected bedrock targets. Unverified flows may only send
 * the RakNet offline handshake (pings and the two open connection requests,
 * each with a valid magic); pings and request 1 are throttled per source ip
 * like java SYNs, and a valid request 2 promotes the flow to the player map,
 * after which its game traffic passes uninspected. Everything else from an
 * unverified flow is dropped. Stateless parts of the RakNet stream are
 * deliberately not inspected: they differ between RakNet implementations.
 */
static __always_inline __s32 handle_udp(const void *data, const void *data_end, const struct iphdr *ip)
{
    const __u64 raw_packet_len = (__u64)(data_end - data);

    // non-first fragments carry no udp header: only the reflection check
    // (fragmented amplified answers) applies, see also the tcp path
    if (ip->frag_off & bpf_htons(IP_OFFSET))
    {
        const __s32 verdict = reflection_check(ip, NULL, raw_packet_len);
        return verdict < 0 ? XDP_PASS : verdict;
    }

    const struct udphdr *udp = (const void *)ip + (ip->ihl * 4);
    if ((const void *)(udp + 1) > data_end)
    {
        return XDP_DROP;
    }

    // unsolicited answers of abused udp services, for whole networks
    const __s32 verdict = reflection_check(ip, udp, raw_packet_len);
    if (verdict >= 0)
    {
        return verdict;
    }

    __u8 grace = 0;
    if (lookup_target(ip->daddr, udp->dest, IPPROTO_UDP, &grace) != KIND_BEDROCK)
    {
        return XDP_PASS;
    }

    struct statistics *stats_ptr = NULL;
    struct statistics *dst_stats_ptr = NULL;
    if (!lookup_stats(ip->daddr, udp->dest, IPPROTO_UDP, &stats_ptr, &dst_stats_ptr))
    {
        return XDP_DROP;
    }

    count_stats(stats_ptr, dst_stats_ptr, INCOMING_BYTES, raw_packet_len);

    // RakNet datagrams always fit the MTU, a fragmented one is forged
    if (ip->frag_off & bpf_htons(IP_MF))
    {
        goto drop;
    }

    const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(ip->saddr, ip->daddr, udp->source, udp->dest);

    // verified connections skip all further inspection
    struct player_entry *player = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (player)
    {
        player->packets++;
        return XDP_PASS;
    }

    const __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len <= sizeof(struct udphdr))
    {
        goto drop;
    }
    const __u16 payload_len = udp_len - sizeof(struct udphdr);
    const __u8 *payload = (const __u8 *)(udp + 1);
    if ((const void *)(payload + 1) > data_end || (const void *)payload + payload_len > data_end)
    {
        goto drop;
    }

    if (is_amplification_port(bpf_ntohs(udp->source)))
    {
        goto drop;
    }

    const __u8 id = payload[0];
    switch (id)
    {
    case RAKNET_UNCONNECTED_PING:
    case RAKNET_UNCONNECTED_PING_OPEN:
        if (payload_len < RAKNET_PING_LEN || !raknet_magic_at(payload + 9, data_end))
        {
            goto drop;
        }
        break;
    case RAKNET_OPEN_CONNECTION_REQUEST_1:
        if (payload_len < RAKNET_REQUEST_1_MIN_LEN || !raknet_magic_at(payload + 1, data_end))
        {
            goto drop;
        }
        break;
    case RAKNET_OPEN_CONNECTION_REQUEST_2:
        if (payload_len < RAKNET_REQUEST_2_MIN_LEN || !raknet_magic_at(payload + 1, data_end))
        {
            goto drop;
        }
        return switch_to_verified(raw_packet_len, stats_ptr, dst_stats_ptr, &flow_key, VERIFIED);
    default:
        // connected RakNet traffic (frame sets 0x80-0x8f, ACK 0xc0, NACK
        // 0xa0) of a session that existed before the target was protected
        if (grace && ((id & 0xf0) == 0x80 || id == 0xa0 || id == 0xc0))
        {
            return switch_to_verified(raw_packet_len, stats_ptr, dst_stats_ptr, &flow_key, ADOPTED);
        }
        goto drop;
    }

    // pings and request 1: new handshakes, throttled like java SYNs
    count_stats(stats_ptr, dst_stats_ptr, SYN_RECEIVE, 1);
    if (!throttle_allows(ip->saddr))
    {
        goto drop;
    }
    count_stats(stats_ptr, dst_stats_ptr, STATE_SWITCH, 1);
    return XDP_PASS;

drop:
    count_stats(stats_ptr, dst_stats_ptr, DROPPED_PACKET, 1);
    count_stats(stats_ptr, dst_stats_ptr, DROPPED_BYTES, raw_packet_len);
    return XDP_DROP;
}

/* ------------------------------------------------------------------------
 * Web (HTTP and HTTPS over TCP)
 * --------------------------------------------------------------------- */

// longest request method token checked (WebDAV's PROPPATCH has 9 letters)
#define HTTP_METHOD_MAX 10

/*
 * The first segment of a plain http connection starts with a request line:
 * a method of 3 to HTTP_METHOD_MAX uppercase letters followed by a space.
 * This covers every method including WebDAV, HTTP/2 prior knowledge ("PRI *")
 * and the PROXY protocol v1 header ("PROXY TCP4 ...").
 */
static __always_inline __u8 http_request_start(const __u8 *p, const __u8 *end, const void *data_end)
{
    const __u8 *cursor = p;
#pragma unroll
    for (__u32 i = 0; i <= HTTP_METHOD_MAX; i++)
    {
        CHECK_BOUNDS_OR_RETURN(cursor, 1, end, data_end);
        const __u8 c = *cursor;
        if (c == ' ')
        {
            return i >= 3;
        }
        if (c < 'A' || c > 'Z')
        {
            return 0;
        }
        cursor++;
    }
    return 0;
}

/*
 * The first segment of a TLS connection starts with a handshake record
 * (0x16), version 3.x, carrying a ClientHello (handshake type 1 at byte 5).
 * Only the header is checked: modern ClientHellos (post-quantum key shares)
 * are larger than one segment.
 */
static __always_inline __u8 tls_client_hello_start(const __u8 *p, const __u8 *end, const void *data_end)
{
    CHECK_BOUNDS_OR_RETURN(p, 6, end, data_end);
    return p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x04 && p[5] == 0x01;
}

/*
 * TCP packets for protected web targets: a clean handshake, then the first
 * data segment has to be an http request or a TLS ClientHello. Both are
 * accepted on http and https targets alike: proxies like traefik serve both
 * on one port, and a wrong http/https classification must never break a
 * site. Afterwards the flow is verified and passes uninspected until
 * it is idle for WEB_IDLE_NS. Unlike the java path the empty ACK finishing
 * the handshake passes, so preconnected browser sockets that send their
 * request later keep working. Without WEB_ENFORCE everything is only counted.
 */
static __always_inline __s32 handle_web(const void *data, const void *data_end, const struct iphdr *ip,
                                        const struct tcphdr *tcp, const __u8 kind, const __u8 grace)
{
    if (tcp->doff < 5)
    {
        return XDP_DROP;
    }
    const __u32 tcp_hdr_len = tcp->doff * 4;
    if ((const void *)tcp + tcp_hdr_len > data_end)
    {
        return XDP_DROP;
    }

    struct statistics *stats_ptr = NULL;
    struct statistics *dst_stats_ptr = NULL;
    if (!lookup_stats(ip->daddr, tcp->dest, IPPROTO_TCP, &stats_ptr, &dst_stats_ptr))
    {
        return XDP_DROP;
    }

    const __u64 raw_packet_len = (__u64)(data_end - data);
    count_stats(stats_ptr, dst_stats_ptr, INCOMING_BYTES, raw_packet_len);

    const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(ip->saddr, ip->daddr, tcp->source, tcp->dest);

    // see the java path: legitimate tcp never fragments
    if (ip->frag_off & bpf_htons(IP_MF))
    {
        goto drop;
    }

    if (detect_tcp_bypass(tcp))
    {
        count_stats(stats_ptr, dst_stats_ptr, TCP_BYPASS, 1);
        goto drop;
    }

    if (tcp->syn)
    {
        count_stats(stats_ptr, dst_stats_ptr, SYN_RECEIVE, 1);
        if (bpf_ntohs(ip->tot_len) > (ip->ihl * 4) + tcp_hdr_len)
        {
            count_stats(stats_ptr, dst_stats_ptr, TCP_BYPASS, 1);
            goto drop;
        }
        if (!throttle_allows_in(&web_throttle, ip->saddr, WEB_HIT_COUNT))
        {
            goto drop;
        }
        const struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, bpf_ntohl(tcp->seq) + 1);
        if (bpf_map_update_elem(&conntrack_map, &flow_key, &new_state, BPF_ANY) < 0)
        {
            goto drop;
        }
        return XDP_PASS;
    }

    struct player_entry *verified = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (verified)
    {
        verified->packets++;
        return XDP_PASS;
    }

    struct initial_state *initial_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    if (!initial_state)
    {
        if (grace)
        {
            if (tcp->ack)
            {
                const __s32 v = switch_to_verified_idle(raw_packet_len, stats_ptr, dst_stats_ptr, &flow_key, ADOPTED, WEB_IDLE_NS);
                return WEB_ENFORCE ? v : XDP_PASS;
            }
            return XDP_PASS;
        }
        goto drop;
    }

    const __u8 *payload = (const __u8 *)tcp + tcp_hdr_len;
    const __u16 payload_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4) - tcp_hdr_len;
    const __u8 *payload_end = payload + payload_len;
    if (payload_end > (const __u8 *)data_end)
    {
        goto drop;
    }

    if (initial_state->state == AWAIT_ACK)
    {
        if (!tcp->ack || initial_state->expected_sequence != bpf_ntohl(tcp->seq))
        {
            goto drop;
        }
        initial_state->state = AWAIT_WEB_DATA;
    }

    // pure ACKs, FIN and RST while the first request is pending
    if (payload >= payload_end)
    {
        return XDP_PASS;
    }

    if (!tcp->ack)
    {
        goto drop_connection;
    }
    if (initial_state->expected_sequence != bpf_ntohl(tcp->seq))
    {
        // retransmission or reordering before the first request
        if (++initial_state->fails > MAX_OUT_OF_ORDER)
        {
            goto drop_connection;
        }
        goto drop;
    }

    // the expected protocol of the target first, the other one as fallback
    const __u8 valid = kind == KIND_HTTP
                           ? (http_request_start(payload, payload_end, data_end) || tls_client_hello_start(payload, payload_end, data_end))
                           : (tls_client_hello_start(payload, payload_end, data_end) || http_request_start(payload, payload_end, data_end));
    if (!valid)
    {
        goto drop_connection;
    }
    count_stats(stats_ptr, dst_stats_ptr, STATE_SWITCH, 1);
    const __s32 v = switch_to_verified_idle(raw_packet_len, stats_ptr, dst_stats_ptr, &flow_key, VERIFIED, WEB_IDLE_NS);
    return WEB_ENFORCE ? v : XDP_PASS;

drop_connection:
    count_stats(stats_ptr, dst_stats_ptr, DROP_CONNECTION, 1);
    bpf_map_delete_elem(&conntrack_map, &flow_key);
drop:
    count_stats(stats_ptr, dst_stats_ptr, DROPPED_PACKET, 1);
    count_stats(stats_ptr, dst_stats_ptr, DROPPED_BYTES, raw_packet_len);
    return WEB_ENFORCE ? XDP_DROP : XDP_PASS;
}

/* ------------------------------------------------------------------------
 * XDP entry point
 * --------------------------------------------------------------------- */

SEC("xdp")
__s32 minecraft_filter(struct xdp_md *ctx)
{
    const void *data = (const void *)(long)ctx->data;
    const void *data_end = (const void *)(long)ctx->data_end;

    const struct ethhdr *eth = data;
    if ((const void *)(eth + 1) > data_end)
    {
        return XDP_DROP;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    const struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((const void *)(ip + 1) > data_end || ip->ihl < 5)
    {
        return XDP_DROP;
    }

    // addresses without a route would be dropped by the stack anyway
    if (unused_destination(ctx, ip))
    {
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_UDP)
    {
        return handle_udp(data, data_end, ip);
    }

    if (ip->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    // non-first fragments (fragment offset != 0) carry no tcp header, so the
    // port check below cannot run on them: pass them up the stack so other
    // services keep receiving their fragmented traffic. Safe for the filtered
    // range because the matching first fragment is dropped after the port
    // check, so reassembly never completes and the kernel discards the rest
    // after the frag timeout. The ports can not be forged via fragment
    // overlap either: they live in bytes 0-3 of the tcp header while the
    // smallest non-first offset is 8 bytes, and linux >= 4.19 drops
    // overlapping fragments outright
    if (ip->frag_off & bpf_htons(IP_OFFSET))
    {
        return XDP_PASS;
    }

    const struct tcphdr *tcp = (const void *)ip + (ip->ihl * 4);
    if ((const void *)(tcp + 1) > data_end)
    {
        return XDP_DROP;
    }

    // everything that is not a protected java or web target is not our business
    __u8 grace = 0;
    const __u8 kind = lookup_target(ip->daddr, tcp->dest, IPPROTO_TCP, &grace);
    if (kind == KIND_HTTP || kind == KIND_HTTPS)
    {
        return handle_web(data, data_end, ip, tcp, kind, grace);
    }
    if (kind != KIND_JAVA)
    {
        return XDP_PASS;
    }

    // first fragment of a fragmented packet (MF set, offset 0) aimed at our
    // range: the remaining payload is in fragments the state machine never
    // sees, so after kernel reassembly the backend would receive uninspected
    // data. Legitimate tcp does not fragment, the MSS keeps segments below
    // the MTU. Dropping the first fragment makes reassembly impossible, the
    // kernel discards the passed non-first fragments after the frag timeout
    if (ip->frag_off & bpf_htons(IP_MF))
    {
        return XDP_DROP;
    }

    if (tcp->doff < 5)
    {
        return XDP_DROP;
    }

    const __u32 tcp_hdr_len = tcp->doff * 4;
    if ((const void *)tcp + tcp_hdr_len > data_end)
    {
        return XDP_DROP;
    }

    struct statistics *stats_ptr = NULL;
    struct statistics *dst_stats_ptr = NULL;
    if (!lookup_stats(ip->daddr, tcp->dest, IPPROTO_TCP, &stats_ptr, &dst_stats_ptr))
    {
        return XDP_DROP;
    }

    const __u64 raw_packet_len = (__u64)(data_end - data);
    count_stats(stats_ptr, dst_stats_ptr, INCOMING_BYTES, raw_packet_len);

    if (detect_tcp_bypass(tcp))
    {
        count_stats(stats_ptr, dst_stats_ptr, TCP_BYPASS, 1);
        goto drop;
    }

    const __u32 src_ip = ip->saddr;
    const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);

    // new connection: throttle it, then start tracking it
    if (tcp->syn)
    {
        count_stats(stats_ptr, dst_stats_ptr, SYN_RECEIVE, 1);

        // drop SYNs carrying payload (e.g. TCP fast open): the data would
        // reach the backend without ever passing the inspection state machine
        if (bpf_ntohs(ip->tot_len) > (ip->ihl * 4) + tcp_hdr_len)
        {
            count_stats(stats_ptr, dst_stats_ptr, TCP_BYPASS, 1);
            goto drop;
        }

        if (!throttle_allows(src_ip))
        {
            goto drop;
        }

        // track the connection: the next packet has to be the ACK finishing
        // the TCP handshake, with the sequence number following this SYN
        const struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, bpf_ntohl(tcp->seq) + 1);
        if (bpf_map_update_elem(&conntrack_map, &flow_key, &new_state, BPF_ANY) < 0)
        {
            goto drop;
        }

        return XDP_PASS;
    }

    // verified connections skip all further inspection
    struct player_entry *player = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (player)
    {
        // non-atomic on purpose: racing increments (flow migrating cpus) can
        // only lose single steps, never regress the counter across a window.
        // The idle check thus only false-matches if the connection sent
        // nothing for ~a full window, and minecraft clients keepalive every
        // few seconds, so such a connection is dead anyway
        player->packets++;
        return XDP_PASS;
    }

    struct initial_state *initial_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    if (!initial_state)
    {
        // neither tracked nor verified: during the grace window this is a
        // connection that was established before the target was protected,
        // adopt it instead of cutting the player off. Teardown segments of
        // such flows (FIN/RST without ACK) just pass
        if (grace)
        {
            if (tcp->ack)
            {
                return switch_to_verified(raw_packet_len, stats_ptr, dst_stats_ptr, &flow_key, ADOPTED);
            }
            return XDP_PASS;
        }
        goto drop;
    }

    const __u8 *tcp_payload = (const __u8 *)tcp + tcp_hdr_len;

    // ip total length - ip header - tcp header = length of the tcp payload
    const __u16 ip_tot_len = bpf_ntohs(ip->tot_len);
    const __u16 tcp_payload_len = ip_tot_len - (ip->ihl * 4) - tcp_hdr_len;
    const __u8 *tcp_payload_end = tcp_payload + tcp_payload_len;

    // tcp packet split over multiple ethernet frames, we don't support that
    if (tcp_payload_end > (const __u8 *)data_end)
    {
        goto drop;
    }

    __u32 state = initial_state->state;
    if (state == AWAIT_ACK)
    {
        // not an ack, or not the ack matching our SYN
        if (!tcp->ack || initial_state->expected_sequence != bpf_ntohl(tcp->seq))
        {
            goto drop;
        }

        // advance the state machine before the early drop below, the next
        // packet has to be matched against AWAIT_MC_HANDSHAKE
        initial_state->state = state = AWAIT_MC_HANDSHAKE;

        // the empty ack finishing the TCP handshake is dropped on purpose:
        // the backend will accept the first minecraft data packet as that
        // ack, which elegantly limits backend connections to clients whose
        // handshake passed inspection. If the ack already carries payload,
        // fall through into payload inspection instead
        if (tcp_payload >= tcp_payload_end)
        {
            goto drop;
        }
    }

    if (tcp_payload < tcp_payload_end)
    {
        // payload without an ack flag is never legitimate mid-handshake
        if (!tcp->ack)
        {
            goto drop_connection;
        }

        // we fully track the tcp sequence, so a mismatch here is either a
        // retransmission or an out-of-order packet: drop the packet, and
        // drop the whole connection once that happens too often. Everything
        // that survives this check is exactly the in-order byte stream the
        // backend would see, which is what allows the hard punishments below
        if (initial_state->expected_sequence != bpf_ntohl(tcp->seq))
        {
            if (++initial_state->fails > MAX_OUT_OF_ORDER)
            {
                goto drop_connection;
            }
            goto drop;
        }

        if (state == AWAIT_MC_HANDSHAKE)
        {
            // if the status request or login packet is in the same tcp
            // segment as the handshake, inspect_handshake returns a
            // DIRECT_READ_* state and advances tcp_payload to the rest
            const __s32 next_state = inspect_handshake(tcp_payload, tcp_payload_end, data_end, &initial_state->protocol, &tcp_payload);
            if (!next_state)
            {
                // even with retransmissions the handshake of a legitimate
                // client is always parseable, this connection is bogus
                goto drop;
            }
            if (next_state == RECEIVED_LEGACY_PING)
            {
                goto drop_connection;
            }
            if (next_state == DIRECT_READ_STATUS_REQUEST)
            {
                goto read_status;
            }
            if (next_state == DIRECT_READ_LOGIN)
            {
                goto read_login;
            }
            initial_state->state = next_state;
            goto update_state;
        }
        if (state == AWAIT_STATUS_REQUEST)
        read_status:
        {
            if (!inspect_status_request(tcp_payload, tcp_payload_end, data_end))
            {
                goto drop;
            }
            initial_state->state = AWAIT_PING;
            goto update_state;
        }
        if (state == AWAIT_PING)
        {
            if (!inspect_ping_request(tcp_payload, tcp_payload_end, data_end))
            {
                goto drop;
            }
            initial_state->state = PING_COMPLETE;
            goto update_state;
        }
        if (state == AWAIT_LOGIN)
        read_login:
        {
            if (!inspect_login_packet(tcp_payload, tcp_payload_end, data_end, initial_state->protocol))
            {
                goto drop;
            }
            // tracking ends here, no need to update the expected sequence
            return switch_to_verified(raw_packet_len, stats_ptr, dst_stats_ptr, &flow_key, VERIFIED);
        }
        if (state == PING_COMPLETE)
        {
            // a finished ping flow has nothing more to say
            goto drop_connection;
        }
    }
    else if (state == AWAIT_MC_HANDSHAKE)
    {
        // empty acks are not allowed while the handshake is pending,
        // otherwise an attacker could sit on a half-inspected connection
        goto drop;
    }

    // empty segments in the remaining states (pure acks, FIN/RST teardown)
    return XDP_PASS;

// shared exit paths: jumping here instead of duplicating these blocks keeps
// the generated program drastically smaller
drop_connection:
    count_stats(stats_ptr, dst_stats_ptr, DROP_CONNECTION, 1);
    bpf_map_delete_elem(&conntrack_map, &flow_key);
    // fall through
drop:
    count_stats(stats_ptr, dst_stats_ptr, DROPPED_PACKET, 1);
    count_stats(stats_ptr, dst_stats_ptr, DROPPED_BYTES, raw_packet_len);
    return XDP_DROP;
update_state:
    initial_state->expected_sequence += tcp_payload_len;
    count_stats(stats_ptr, dst_stats_ptr, STATE_SWITCH, 1);
    return XDP_PASS;
}

// must be GPL-compatible: the bpf_timer_* helpers used by the connection
// throttle are gpl_only, the kernel refuses to load them otherwise
char _license[] SEC("license") = "Dual BSD/GPL";
