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
#ifndef AF_INET6
#define AF_INET6 10
#endif

#define UNUSED_MAX_NETWORKS 8

// must match `UnusedNetwork` in loader/unused.rs
struct unused_network
{
    struct addr6 addr; // already masked
    struct addr6 mask;
    __u32 valid;
    __u32 pad;
};
_Static_assert(sizeof(struct unused_network) == 40, "unused_network size mismatch!");

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
    __type(key, struct addr6); // destination address
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
    __type(key, struct addr6); // destination address
    __type(value, struct unused_verdict);
} unused_cache SEC(".maps");

static __always_inline __u8 net_match(const struct addr6 *a, const struct unused_network *net)
{
    return (a->w[0] & net->mask.w[0]) == net->addr.w[0] && (a->w[1] & net->mask.w[1]) == net->addr.w[1] &&
           (a->w[2] & net->mask.w[2]) == net->addr.w[2] && (a->w[3] & net->mask.w[3]) == net->addr.w[3];
}

static __always_inline __u8 unused_in_networks(const struct addr6 *daddr)
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
        if (net_match(daddr, net))
        {
            return 1;
        }
    }
    return 0;
}

static __always_inline __u8 unused_fib_unrouted(struct xdp_md *ctx, const struct l3 *l)
{
    struct bpf_fib_lookup fib = {0};
    fib.l4_protocol = l->proto;
    fib.tot_len = l->l3len;
    fib.ifindex = ctx->ingress_ifindex;
    if (l->family == FAMILY_V4)
    {
        fib.family = AF_INET;
        fib.tos = l->tos;
        fib.ipv4_src = addr_v4(&l->src);
        fib.ipv4_dst = addr_v4(&l->dst);
    }
    else
    {
        fib.family = AF_INET6;
        __builtin_memcpy(fib.ipv6_src, &l->src, 16);
        __builtin_memcpy(fib.ipv6_dst, &l->dst, 16);
    }

    const long ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    // routed, local, or anything we do not understand: deliver
    return ret == BPF_FIB_LKUP_RET_UNREACHABLE || ret == BPF_FIB_LKUP_RET_BLACKHOLE ||
           ret == BPF_FIB_LKUP_RET_PROHIBIT;
}

static __always_inline void unused_count(struct xdp_md *ctx, const struct addr6 *daddr)
{
    const __u64 bytes = (__u64)((long)ctx->data_end - (long)ctx->data);
    struct unused_stats *stats = bpf_map_lookup_elem(&unused_stats, daddr);
    if (!stats)
    {
        const struct unused_stats zero = {0};
        bpf_map_update_elem(&unused_stats, daddr, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&unused_stats, daddr);
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
static __always_inline __u8 unused_destination(struct xdp_md *ctx, const struct l3 *l)
{
    if (!UNUSED_DROP || !unused_in_networks(&l->dst))
    {
        return 0;
    }

    const __u64 now = bpf_ktime_get_ns();
    __u8 unrouted;
    struct unused_verdict *cached = bpf_map_lookup_elem(&unused_cache, &l->dst);
    if (cached && now - cached->checked_ns < UNUSED_CACHE_NS)
    {
        unrouted = cached->unrouted;
    }
    else
    {
        unrouted = unused_fib_unrouted(ctx, l);
        const struct unused_verdict fresh = {.checked_ns = now, .unrouted = unrouted};
        bpf_map_update_elem(&unused_cache, &l->dst, &fresh, BPF_ANY);
    }
    if (!unrouted)
    {
        return 0;
    }
    unused_count(ctx, &l->dst);
    return 1;
}

#endif
