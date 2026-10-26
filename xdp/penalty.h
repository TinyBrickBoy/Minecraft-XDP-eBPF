#ifndef PENALTY_H
#define PENALTY_H

/*
 * Penalty box for rejected java clients: instead of silently dropping the
 * connection attempts of a client that ran into the connection throttle,
 * its new connections to java targets are redirected for PENALTY_NS to a
 * small service of the loader that answers the server list with a notice
 * and a login with a disconnect message ("please wait ...").
 *
 * The redirect itself is done by netfilter (DNAT on a packet mark): the XDP
 * program passes the packets of penalized sources, and the tc ingress
 * program below marks them. Only sources that recently completed a real
 * status ping or login are ever penalized: spoofed SYN floods have no such
 * history and keep being dropped, so the router never answers them.
 */

#include <linux/types.h>
#include <linux/pkt_cls.h>

#define PENALTY_MARK 0x4000000

// sources that recently completed a status ping or login (ktime)
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} verified_sources SEC(".maps");

// penalized sources, until when (ktime)
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} penalty SEC(".maps");

// [0] = 1 once the loader has the redirect and the service in place;
// without them penalized sources would reach the backend unfiltered
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} penalty_ready SEC(".maps");

static __always_inline __u8 penalty_enabled(void)
{
    if (!PENALTY_NS)
    {
        return 0;
    }
    __u32 zero = 0;
    const __u64 *ready = bpf_map_lookup_elem(&penalty_ready, &zero);
    return ready && *ready;
}

static __always_inline void note_verified_source(const __u32 src)
{
    if (!PENALTY_NS)
    {
        return;
    }
    const __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&verified_sources, &src, &now, BPF_ANY);
}

static __always_inline __u8 penalized(const __u32 src)
{
    if (!penalty_enabled())
    {
        return 0;
    }
    const __u64 *until = bpf_map_lookup_elem(&penalty, &src);
    return until && bpf_ktime_get_ns() < *until;
}

// puts src in the penalty box if it is a known real client; returns 1 then
static __always_inline __u8 try_penalize(const __u32 src)
{
    if (!penalty_enabled())
    {
        return 0;
    }
    const __u64 now = bpf_ktime_get_ns();
    const __u64 *verified = bpf_map_lookup_elem(&verified_sources, &src);
    if (!verified || now - *verified > PENALTY_VERIFIED_NS)
    {
        return 0;
    }
    const __u64 until = now + PENALTY_NS;
    bpf_map_update_elem(&penalty, &src, &until, BPF_ANY);
    return 1;
}

/*
 * tc ingress: marks packets of penalized sources to java targets, so the
 * netfilter rule of the loader redirects their new connections to the
 * penalty service. Never drops or changes anything else.
 */
SEC("classifier")
__s32 penalty_mark(struct __sk_buff *skb)
{
    const void *data = (const void *)(long)skb->data;
    const void *data_end = (const void *)(long)skb->data_end;
    const struct ethhdr *eth = data;
    if ((const void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_UNSPEC;
    }
    const struct iphdr *ip = (const void *)(eth + 1);
    if ((const void *)(ip + 1) > data_end || ip->ihl < 5 || ip->protocol != IPPROTO_TCP)
    {
        return TC_ACT_UNSPEC;
    }
    const struct tcphdr *tcp = (const void *)ip + (ip->ihl * 4);
    if ((const void *)(tcp + 1) > data_end)
    {
        return TC_ACT_UNSPEC;
    }
    if (!penalized(ip->saddr))
    {
        return TC_ACT_UNSPEC;
    }
    __u8 grace = 0;
    if (lookup_target(ip->daddr, tcp->dest, IPPROTO_TCP, &grace) == KIND_JAVA)
    {
        skb->mark |= PENALTY_MARK;
    }
    return TC_ACT_UNSPEC;
}

#endif
