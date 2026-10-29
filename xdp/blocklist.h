#ifndef BLOCKLIST_H
#define BLOCKLIST_H

/*
 * Source address blocking, checked before everything else:
 *
 * - a manual blocklist of addresses and prefixes (longest prefix match),
 *   filled live by the loader from a file
 * - automatic bans: a source sending more than RATELIMIT_PPS packets per
 *   second to the rate limited networks is banned for RATELIMIT_BAN_NS
 * - an allowlist of prefixes that are never rate limited (own proxies, CDNs)
 *
 * Bans live in an LRU map, so a botnet larger than the map evicts its oldest
 * bans instead of failing; legitimate high rate sources belong on the
 * allowlist. Spoofed floods send little per address and are not affected,
 * those are handled by the protocol checks behind this.
 */

#include <linux/types.h>

enum ratelimit_mode
{
    RATELIMIT_OFF = 0,
    RATELIMIT_MONITOR = 1, // count who would be banned, drop nothing
    RATELIMIT_ENFORCE = 2,
};

// blocklist entry scope (map value): manual entries drop everything from
// the source, automatic ones only traffic to the protected networks, so a
// spoofed source (e.g. a BGP neighbour) can never be cut off from the router
enum block_scope
{
    BLOCK_ALL = 1,
    BLOCK_PROTECTED = 2,
};

// why a source was banned
enum ban_reason
{
    BAN_RATE = 1,    // packets per second above RATELIMIT_PPS
    BAN_STRIKES = 2, // repeated violations (unused addresses, invalid handshakes)
};

// manual blocklist and allowlist, keyed like reflection_networks (net_key)
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct net_key);
    __type(value, __u8);
} blocklist SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct net_key);
    __type(value, __u8);
} ratelimit_allow SEC(".maps");

// networks whose inbound traffic is rate limited per source (customer
// prefix), as masks like unused_networks: cheaper than a trie per packet
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, UNUSED_MAX_NETWORKS);
    __type(key, __u32);
    __type(value, struct unused_network);
} ratelimit_networks SEC(".maps");

// [0] = number of blocklist entries, written by the loader: an empty list
// costs no trie lookup at all
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} blocklist_size SEC(".maps");

static __always_inline __u8 in_ratelimit_networks(const __u32 daddr)
{
#pragma unroll
    for (__u32 i = 0; i < UNUSED_MAX_NETWORKS; i++)
    {
        __u32 key = i;
        const struct unused_network *net = bpf_map_lookup_elem(&ratelimit_networks, &key);
        if (!net || !net->valid)
        {
            return 0;
        }
        if ((daddr & net->mask) == net->addr)
        {
            return 1;
        }
    }
    return 0;
}

/*
 * Remote hosts our protected addresses recently connected to (recorded on egress
 * by outbound_record below). Their answers, e.g. a fast download a server
 * started itself, are no flood and never trip the rate limit. A spoofer
 * would have to know both the remote host and which of our addresses is
 * talking to it right now.
 */
struct outbound_key
{
    __u32 remote;
    __u32 local;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct outbound_key);
    __type(value, __u64); // ktime of the last packet sent
} outbound_peers SEC(".maps");

#define OUTBOUND_WINDOW_NS (30ULL * 1000000000ULL)

static __always_inline __u8 outbound_peer(const __u32 remote, const __u32 local)
{
    const struct outbound_key key = {.remote = remote, .local = local};
    const __u64 *last = bpf_map_lookup_elem(&outbound_peers, &key);
    return last && bpf_ktime_get_ns() - *last < OUTBOUND_WINDOW_NS;
}

static __always_inline __u8 blocklist_nonempty(void)
{
    __u32 zero = 0;
    const __u64 *size = bpf_map_lookup_elem(&blocklist_size, &zero);
    return size && *size;
}

// packets of one source within the current one second window
struct rate_window
{
    __u64 start_ns;
    __u64 packets;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); // source address
    __type(value, struct rate_window);
} ratelimit_windows SEC(".maps");

// an automatic ban; must match `Ban` in loader/blocklist.rs
struct ban
{
    __u64 until_ns;  // ktime when the ban ends
    __u64 since_ns;  // ktime when it started
    __u64 rate;      // packets (or violations) in the window that triggered it
    __u64 dropped;   // packets dropped since
    __u64 reason;    // enum ban_reason
};

// violations per source within the current strike window
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_window);
} strike_windows SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct ban);
} ratelimit_bans SEC(".maps");

// global counters; must match `BlockStats` in loader/blocklist.rs
struct block_stats
{
    __u64 blocklist_packets; // dropped by the manual blocklist
    __u64 blocklist_bytes;
    __u64 banned_packets;    // dropped by automatic bans (or would be, when monitoring)
    __u64 banned_bytes;
    __u64 bans;              // automatic bans issued (rate)
    __u64 strike_bans;       // automatic bans issued (violations)
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct block_stats);
} block_stats SEC(".maps");

// packets/bytes per blocklisted source address (not per list entry, so a
// blocked /16 still shows which addresses knock); must match `SourceStats`
struct source_stats
{
    __u64 packets;
    __u64 bytes;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct source_stats);
} blocked_sources SEC(".maps");

static __always_inline struct block_stats *block_stats_slot(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&block_stats, &zero);
}

static __always_inline __u8 lpm_contains(void *trie, const __u32 addr)
{
    const struct net_key key = {.prefixlen = 32, .addr = addr};
    return bpf_map_lookup_elem(trie, &key) != NULL;
}

static __always_inline __u8 lpm_value(void *trie, const __u32 addr)
{
    const struct net_key key = {.prefixlen = 32, .addr = addr};
    const __u8 *value = bpf_map_lookup_elem(trie, &key);
    return value ? *value : 0;
}

static __always_inline void issue_ban(const __u32 src, const __u64 now, const __u64 count, const __u64 reason)
{
    const struct ban fresh = {.until_ns = now + RATELIMIT_BAN_NS, .since_ns = now, .rate = count, .dropped = 0, .reason = reason};
    if (bpf_map_update_elem(&ratelimit_bans, &src, &fresh, BPF_NOEXIST) == 0)
    {
        struct block_stats *st = block_stats_slot();
        if (st)
        {
            if (reason == BAN_STRIKES)
            {
                st->strike_bans++;
            }
            else
            {
                st->bans++;
            }
        }
    }
}

/*
 * Returns 1 when the packet has to be dropped because of its source.
 * bytes is the frame length, for the statistics.
 */
static __always_inline __u8 blocked_source(const struct iphdr *ip, const __u64 bytes)
{
    const __u32 src = ip->saddr;

    const __u8 scope = BLOCKLIST_ACTIVE && blocklist_nonempty() ? lpm_value(&blocklist, src) : 0;
    if (scope == BLOCK_ALL || (scope == BLOCK_PROTECTED && in_ratelimit_networks(ip->daddr)))
    {
        struct block_stats *st = block_stats_slot();
        if (st)
        {
            st->blocklist_packets++;
            st->blocklist_bytes += bytes;
        }
        struct source_stats *per = bpf_map_lookup_elem(&blocked_sources, &src);
        if (!per)
        {
            const struct source_stats zero = {0};
            bpf_map_update_elem(&blocked_sources, &src, &zero, BPF_NOEXIST);
            per = bpf_map_lookup_elem(&blocked_sources, &src);
        }
        if (per)
        {
            per->packets++;
            per->bytes += bytes;
        }
        return 1;
    }

    if (RATELIMIT_MODE == RATELIMIT_OFF)
    {
        return 0;
    }

    // automatic bans and the rate limit only concern the protected networks:
    // traffic to the router itself (BGP, tunnels) is never cut off
    if (!in_ratelimit_networks(ip->daddr))
    {
        return 0;
    }

    const __u64 now = bpf_ktime_get_ns();
    struct ban *ban = bpf_map_lookup_elem(&ratelimit_bans, &src);
    if (ban)
    {
        if (now < ban->until_ns)
        {
            __sync_fetch_and_add(&ban->dropped, 1);
            struct block_stats *st = block_stats_slot();
            if (st)
            {
                st->banned_packets++;
                st->banned_bytes += bytes;
            }
            return RATELIMIT_MODE == RATELIMIT_ENFORCE;
        }
        bpf_map_delete_elem(&ratelimit_bans, &src);
    }

    struct rate_window *window = bpf_map_lookup_elem(&ratelimit_windows, &src);
    if (!window)
    {
        const struct rate_window fresh = {.start_ns = now, .packets = 1};
        bpf_map_update_elem(&ratelimit_windows, &src, &fresh, BPF_ANY);
        return 0;
    }
    if (now - window->start_ns >= 1000000000ULL)
    {
        // new window; racing CPUs can only lose a few counts, never ban early
        window->start_ns = now;
        window->packets = 1;
        return 0;
    }
    const __u64 packets = __sync_fetch_and_add(&window->packets, 1) + 1;
    if (packets <= RATELIMIT_PPS)
    {
        return 0;
    }
    // the allowlist and the outbound peers are only consulted for sources
    // above the limit
    if (lpm_contains(&ratelimit_allow, src) || outbound_peer(src, ip->daddr))
    {
        window->start_ns = now;
        window->packets = 1;
        return 0;
    }

    issue_ban(src, now, packets, BAN_RATE);
    bpf_map_delete_elem(&ratelimit_windows, &src);
    return RATELIMIT_MODE == RATELIMIT_ENFORCE;
}

/*
 * Counts a violation of src: a packet to an unused address, an invalid
 * handshake, forged TCP flags, an invalid RakNet message. More than
 * STRIKE_LIMIT within STRIKE_WINDOW_NS ban the source like the rate limit.
 * Never call it for traffic whose source is typically spoofed on behalf of
 * a victim (reflection answers).
 */
static __always_inline void add_strike(const __u32 src)
{
    if (RATELIMIT_MODE == RATELIMIT_OFF || !STRIKE_LIMIT)
    {
        return;
    }
    const __u64 now = bpf_ktime_get_ns();
    struct rate_window *window = bpf_map_lookup_elem(&strike_windows, &src);
    if (!window)
    {
        const struct rate_window fresh = {.start_ns = now, .packets = 1};
        bpf_map_update_elem(&strike_windows, &src, &fresh, BPF_ANY);
        return;
    }
    if (now - window->start_ns >= STRIKE_WINDOW_NS)
    {
        window->start_ns = now;
        window->packets = 1;
        return;
    }
    const __u64 strikes = __sync_fetch_and_add(&window->packets, 1) + 1;
    if (strikes <= STRIKE_LIMIT)
    {
        return;
    }
    bpf_map_delete_elem(&strike_windows, &src);
    if (lpm_contains(&ratelimit_allow, src))
    {
        return;
    }
    issue_ban(src, now, strikes, BAN_STRIKES);
}

/*
 * DNS scanners: a query to a protected address that runs no DNS server is a
 * scan for open resolvers. Queries to destinations without a fresh verdict
 * are noted for the loader, which probes the destination once (the verdict
 * is trusted for DNS_RECHECK_NS, so it is re-probed only when queries keep
 * coming) and blocklists the sources if nothing answers. Queries to
 * destinations known to have no DNS server are dropped right away.
 */
struct dns_verdict
{
    __u64 checked_ns;
    __u64 has_server;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // destination address
    __type(value, struct dns_verdict);
} dns_verdicts SEC(".maps");

// must match `DnsQuery` in loader/blocklist.rs
struct dns_query
{
    __u32 dst;
    __u32 pad;
    __u64 last_ns;
    __u64 count;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32); // source address
    __type(value, struct dns_query);
} dns_queries SEC(".maps");

// returns 1 when the packet is a DNS query to a protected address that is
// known to run no DNS server (drop it)
static __always_inline __u8 dns_scan_check(const struct iphdr *ip, const void *data_end)
{
    if (!DNS_SCAN || ip->protocol != IPPROTO_UDP || (ip->frag_off & bpf_htons(IP_OFFSET)))
    {
        return 0;
    }
    const struct udphdr *udp = (const void *)ip + (ip->ihl * 4);
    if ((const void *)(udp + 1) > data_end || udp->dest != bpf_htons(53) || !in_ratelimit_networks(ip->daddr))
    {
        return 0;
    }
    // only queries count: answers arriving at port 53 come from resolvers
    // abused in a reflection attack with our address as spoofed source
    // (source port 53); those are the reflection check's job, the
    // resolvers themselves did nothing wrong
    const __u8 *dns = (const void *)(udp + 1);
    if ((const void *)(dns + 12) > data_end || udp->source == bpf_htons(53) || (dns[2] & 0x80))
    {
        return 0;
    }
    const __u32 dst = ip->daddr;
    const __u64 now = bpf_ktime_get_ns();
    const struct dns_verdict *verdict = bpf_map_lookup_elem(&dns_verdicts, &dst);
    const __u8 fresh = verdict && now - verdict->checked_ns < DNS_RECHECK_NS;
    if (fresh && verdict->has_server)
    {
        return 0;
    }
    // unknown or no server: note the source for the loader
    const __u32 src = ip->saddr;
    struct dns_query *q = bpf_map_lookup_elem(&dns_queries, &src);
    if (q)
    {
        q->dst = dst;
        q->last_ns = now;
        __sync_fetch_and_add(&q->count, 1);
    }
    else
    {
        const struct dns_query fresh_q = {.dst = dst, .pad = 0, .last_ns = now, .count = 1};
        bpf_map_update_elem(&dns_queries, &src, &fresh_q, BPF_ANY);
    }
    return fresh; // known to have no server: drop
}

/*
 * tc egress: notes which remote hosts the protected addresses open
 * connections to (see outbound_peers). Refreshes an entry at most once a
 * second.
 */
SEC("classifier")
__s32 outbound_record(struct __sk_buff *skb)
{
    const void *data = (const void *)(long)skb->data;
    const void *data_end = (const void *)(long)skb->data_end;
    const struct ethhdr *eth = data;
    if ((const void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_UNSPEC;
    }
    const struct iphdr *ip = (const void *)(eth + 1);
    if ((const void *)(ip + 1) > data_end || ip->ihl < 5 || !in_ratelimit_networks(ip->saddr))
    {
        return TC_ACT_UNSPEC;
    }
    const struct outbound_key key = {.remote = ip->daddr, .local = ip->saddr};
    const __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&outbound_peers, &key);
    if (last)
    {
        // any packet keeps a known peer alive
        if (now - *last >= 1000000000ULL)
        {
            *last = now;
        }
        return TC_ACT_UNSPEC;
    }
    // a new peer only when the server opens the connection itself: a TCP
    // SYN, or UDP from an ephemeral client port to a well-known service port
    // (QUIC 443, DNS 53, ...). Answers to clients (that could be an
    // attacker) never exempt them.
    __u8 opens = 0;
    if (!(ip->frag_off & bpf_htons(IP_OFFSET)))
    {
        if (ip->protocol == IPPROTO_TCP)
        {
            const struct tcphdr *tcp = (const void *)ip + (ip->ihl * 4);
            opens = (const void *)(tcp + 1) <= data_end && tcp->syn && !tcp->ack;
        }
        else if (ip->protocol == IPPROTO_UDP)
        {
            const struct udphdr *udp = (const void *)ip + (ip->ihl * 4);
            opens = (const void *)(udp + 1) <= data_end && bpf_ntohs(udp->source) >= 32768 &&
                    bpf_ntohs(udp->dest) < 1024;
        }
    }
    if (opens)
    {
        bpf_map_update_elem(&outbound_peers, &key, &now, BPF_ANY);
    }
    return TC_ACT_UNSPEC;
}

#endif
