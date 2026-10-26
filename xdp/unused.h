#ifndef UNUSED_H
#define UNUSED_H

/*
 * Drops traffic to unused addresses of the configured networks right at the
 * driver. "Unused" is decided by the kernel's own routing table via
 * bpf_fib_lookup(): an address whose best route is unreachable, blackhole or
 * prohibit would be dropped by the kernel anyway (after walking the stack and
 * answering with ICMP errors), so dropping it here can never hit traffic that
 * would otherwise have been delivered, and assigning an address (adding its
 * route) takes effect immediately without any list to maintain.
 */

#include <linux/types.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#define UNUSED_MAX_NETWORKS 8

// must match `UnusedNetwork` in loader/unused.rs
struct unused_network
{
    __u32 addr; // network byte order, already masked
    __u32 mask; // network byte order
    __u32 valid;
    __u32 pad;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, UNUSED_MAX_NETWORKS);
    __type(key, __u32);
    __type(value, struct unused_network);
} unused_networks SEC(".maps");

// packets/bytes per unused destination; must match `UnusedStats`
struct unused_stats
{
    __u64 packets;
    __u64 bytes;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // destination address, network byte order
    __type(value, struct unused_stats);
} unused_stats SEC(".maps");

// fib verdict per destination, re-checked at most once per UNUSED_CACHE_NS:
// a fib lookup costs several hundred ns, and every packet to the customer
// prefix would pay it; a newly routed address works within that time
#define UNUSED_CACHE_NS 1000000000ULL

struct unused_verdict
{
    __u64 checked_ns;
    __u64 unrouted; // 1 = unreachable/blackhole/prohibit
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // destination address
    __type(value, struct unused_verdict);
} unused_cache SEC(".maps");

static __always_inline __u8 unused_in_networks(const __u32 daddr)
{
#pragma unroll
    for (__u32 i = 0; i < UNUSED_MAX_NETWORKS; i++)
    {
        __u32 key = i;
        const struct unused_network *net = bpf_map_lookup_elem(&unused_networks, &key);
        if (!net || !net->valid)
        {
            return 0; // entries are filled from index 0 without gaps
        }
        if ((daddr & net->mask) == net->addr)
        {
            return 1;
        }
    }
    return 0;
}

static __always_inline __u8 unused_fib_unrouted(struct xdp_md *ctx, const struct iphdr *ip)
{
    struct bpf_fib_lookup fib = {0};
    fib.family = AF_INET;
    fib.tos = ip->tos;
    fib.l4_protocol = ip->protocol;
    fib.tot_len = bpf_ntohs(ip->tot_len);
    fib.ipv4_src = ip->saddr;
    fib.ipv4_dst = ip->daddr;
    fib.ifindex = ctx->ingress_ifindex;

    const long ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    // routed, local, or anything we do not understand: deliver
    return ret == BPF_FIB_LKUP_RET_UNREACHABLE || ret == BPF_FIB_LKUP_RET_BLACKHOLE ||
           ret == BPF_FIB_LKUP_RET_PROHIBIT;
}

static __always_inline void unused_count(struct xdp_md *ctx, const struct iphdr *ip)
{
    const __u32 daddr = ip->daddr;
    const __u64 bytes = (__u64)((long)ctx->data_end - (long)ctx->data);
    struct unused_stats *stats = bpf_map_lookup_elem(&unused_stats, &daddr);
    if (!stats)
    {
        const struct unused_stats zero = {0};
        bpf_map_update_elem(&unused_stats, &daddr, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&unused_stats, &daddr);
    }
    if (stats)
    {
        stats->packets++;
        stats->bytes += bytes;
    }
    }


/*
 * Returns 1 when the packet goes to an address of the configured networks
 * that the kernel has no usable route for.
 */
static __always_inline __u8 unused_destination(struct xdp_md *ctx, const struct iphdr *ip)
{
    if (!UNUSED_DROP || !unused_in_networks(ip->daddr))
    {
        return 0;
    }

    const __u32 cache_key = ip->daddr;
    const __u64 now = bpf_ktime_get_ns();
    __u8 unrouted;
    struct unused_verdict *cached = bpf_map_lookup_elem(&unused_cache, &cache_key);
    if (cached && now - cached->checked_ns < UNUSED_CACHE_NS)
    {
        unrouted = cached->unrouted;
    }
    else
    {
        unrouted = unused_fib_unrouted(ctx, ip);
        const struct unused_verdict fresh = {.checked_ns = now, .unrouted = unrouted};
        bpf_map_update_elem(&unused_cache, &cache_key, &fresh, BPF_ANY);
    }
    if (!unrouted)
    {
        return 0;
    }
    unused_count(ctx, ip);
    return 1;
}

#endif
