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
    __u64 rate;      // packets in the window that triggered it
    __u64 dropped;   // packets dropped since
};

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
    __u64 bans;              // automatic bans issued
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

/*
 * Returns 1 when the packet has to be dropped because of its source.
 * bytes is the frame length, for the statistics.
 */
static __always_inline __u8 blocked_source(const struct iphdr *ip, const __u64 bytes)
{
    const __u32 src = ip->saddr;

    if (BLOCKLIST_ACTIVE && blocklist_nonempty() && lpm_contains(&blocklist, src))
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

    // only traffic to the protected networks counts
    if (!in_ratelimit_networks(ip->daddr))
    {
        return 0;
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
    // the allowlist is only consulted for sources above the limit
    if (lpm_contains(&ratelimit_allow, src))
    {
        window->start_ns = now;
        window->packets = 1;
        return 0;
    }

    const struct ban fresh_ban = {.until_ns = now + RATELIMIT_BAN_NS, .since_ns = now, .rate = packets, .dropped = 1};
    if (bpf_map_update_elem(&ratelimit_bans, &src, &fresh_ban, BPF_NOEXIST) == 0)
    {
        struct block_stats *st = block_stats_slot();
        if (st)
        {
            st->bans++;
        }
    }
    bpf_map_delete_elem(&ratelimit_windows, &src);
    return RATELIMIT_MODE == RATELIMIT_ENFORCE;
}

#endif
