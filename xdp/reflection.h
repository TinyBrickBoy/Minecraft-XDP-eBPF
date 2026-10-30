#ifndef REFLECTION_H
#define REFLECTION_H

/*
 * UDP reflection/amplification protection for whole networks (e.g. the
 * customer prefixes routed through this host).
 *
 * Reflection floods are answers from abused UDP services (DNS, NTP,
 * memcached, SSDP, ...) to requests the victim never sent. A tc egress
 * program records every request a protected address sends to such a service
 * port; the XDP program lets a packet from one of those source ports pass only
 * when it answers a recorded request within the reply window. Everything else
 * from those ports, and (optionally) non-first UDP fragments, which large
 * amplified answers produce, is dropped before it costs any forwarding or
 * tunnel encryption work.
 *
 * The mode lives in a map instead of .rodata, so the loader can switch between
 * off, monitor (count only) and enforce at runtime, and only turns enforcing
 * on once the egress recorder is attached: without it every legitimate answer
 * would be dropped.
 */

#include <linux/types.h>
#include <linux/pkt_cls.h>

enum reflection_mode
{
    REFLECTION_OFF = 0,
    REFLECTION_MONITOR = 1, // count what would be dropped, drop nothing
    REFLECTION_ENFORCE = 2,
};

// must match `ReflectionConfig` in loader/reflection.rs
struct reflection_config
{
    __u64 window_ns; // how long a recorded request accepts answers
    __u8 mode;       // enum reflection_mode
    __u8 drop_fragments;
    __u8 pad[6];
};
_Static_assert(sizeof(struct reflection_config) == 16, "reflection_config size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct reflection_config);
} reflection_config SEC(".maps");

// protected networks, longest prefix match on the ipv4 address
struct net_key
{
    __u32 prefixlen;
    __u32 addr; // network byte order
};

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC); // required for LPM tries
    __type(key, struct net_key);
    __type(value, __u8);
} reflection_networks SEC(".maps");

// one bit per UDP port: service ports whose answers are checked
struct port_bitmap
{
    __u64 bits[1024];
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct port_bitmap);
} reflection_ports SEC(".maps");

// a request a protected address sent to a service port; must match
// `ExpectKey` in loader/reflection.rs
struct expect_key
{
    __u32 local_ip;  // protected address, network byte order
    __u32 remote_ip; // service address
    __u16 local_port;
    __u16 remote_port; // the service port
};
_Static_assert(sizeof(struct expect_key) == 12, "expect_key size mismatch!");

struct
{
    // LRU: a busy resolver evicts its oldest requests instead of failing
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct expect_key);
    __type(value, __u64); // ktime until which answers are accepted
} reflection_expect SEC(".maps");

// statistics per victim address and source port (0 = fragments); must match
// `ReflectionKey` / `ReflectionStats` in loader/reflection.rs
struct reflection_key
{
    __u32 daddr;
    __u16 sport; // host byte order
    __u16 pad;
};

struct reflection_stats
{
    __u64 packets;
    __u64 bytes;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct reflection_key);
    __type(value, struct reflection_stats);
} reflection_stats SEC(".maps");

static __always_inline const struct reflection_config *reflection_active(void)
{
    __u32 zero = 0;
    const struct reflection_config *config = bpf_map_lookup_elem(&reflection_config, &zero);
    if (!config || config->mode == REFLECTION_OFF)
    {
        return NULL;
    }
    return config;
}

static __always_inline __u8 reflection_protects(const __u32 addr)
{
    const struct net_key key = {.prefixlen = 32, .addr = addr};
    return bpf_map_lookup_elem(&reflection_networks, &key) != NULL;
}

static __always_inline __u8 reflection_port(const __u16 port)
{
    __u32 zero = 0;
    const struct port_bitmap *ports = bpf_map_lookup_elem(&reflection_ports, &zero);
    if (!ports)
    {
        return 0;
    }
    // the barrier hides the u16 range from the compiler, so it keeps the
    // mask the verifier needs to bound the index (bswap loses the range)
    __u32 bit = port;
    barrier_var(bit);
    return (ports->bits[(bit >> 6) & 1023] >> (bit & 63)) & 1;
}

/*
 * Counts a reflection packet and returns the verdict for it: XDP_DROP when
 * enforcing, XDP_PASS in monitor mode.
 */
static __always_inline __s32 reflection_verdict(const struct reflection_config *config, const __u32 daddr,
                                                const __u16 sport, const __u64 bytes)
{
    const struct reflection_key key = {.daddr = daddr, .sport = sport, .pad = 0};
    struct reflection_stats *stats = bpf_map_lookup_elem(&reflection_stats, &key);
    if (!stats)
    {
        const struct reflection_stats zero = {0};
        bpf_map_update_elem(&reflection_stats, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&reflection_stats, &key);
    }
    if (stats)
    {
        stats->packets++;
        stats->bytes += bytes;
    }
    return config->mode == REFLECTION_ENFORCE ? XDP_DROP : XDP_PASS;
}

/*
 * XDP side, for every inbound UDP packet. Returns -1 when the packet is not
 * a reflection packet (the caller continues with its own checks), otherwise
 * the verdict. udp may be NULL for non-first fragments.
 */
static __always_inline __s32 reflection_check(const struct iphdr *ip, const struct udphdr *udp, const __u64 bytes)
{
    const struct reflection_config *config = reflection_active();
    if (!config)
    {
        return -1;
    }

    if (!udp)
    {
        if (config->drop_fragments && reflection_protects(ip->daddr))
        {
            return reflection_verdict(config, ip->daddr, 0, bytes);
        }
        return -1;
    }

    const __u16 sport = bpf_ntohs(udp->source);
    if (!reflection_port(sport) || !reflection_protects(ip->daddr))
    {
        return -1;
    }

    const struct expect_key key = {
        .local_ip = ip->daddr,
        .remote_ip = ip->saddr,
        .local_port = udp->dest,
        .remote_port = udp->source,
    };
    const __u64 *expires = bpf_map_lookup_elem(&reflection_expect, &key);
    if (expires && bpf_ktime_get_ns() < *expires)
    {
        return -1; // an answer to a request we saw leaving
    }
    return reflection_verdict(config, ip->daddr, sport, bytes);
}

/*
 * tc egress side: records requests of protected addresses to service ports.
 * Never drops or modifies anything.
 */
SEC("classifier")
__s32 reflection_egress(struct __sk_buff *skb)
{
    const struct reflection_config *config = reflection_active();
    if (!config)
    {
        return TC_ACT_UNSPEC;
    }

    const void *data = (const void *)(long)skb->data;
    const void *data_end = (const void *)(long)skb->data_end;
    const struct iphdr *ip = ipv4_header(data, data_end, skb->ifindex);
    if (!ip || ip->ihl < 5 || ip->protocol != IPPROTO_UDP ||
        (ip->frag_off & bpf_htons(IP_OFFSET)))
    {
        return TC_ACT_UNSPEC;
    }
    const struct udphdr *udp = (const void *)ip + (ip->ihl * 4);
    if ((const void *)(udp + 1) > data_end)
    {
        return TC_ACT_UNSPEC;
    }
    if (!reflection_port(bpf_ntohs(udp->dest)) || !reflection_protects(ip->saddr))
    {
        return TC_ACT_UNSPEC;
    }

    const struct expect_key key = {
        .local_ip = ip->saddr,
        .remote_ip = ip->daddr,
        .local_port = udp->source,
        .remote_port = udp->dest,
    };
    const __u64 expires = bpf_ktime_get_ns() + config->window_ns;
    bpf_map_update_elem(&reflection_expect, &key, &expires, BPF_ANY);
    return TC_ACT_UNSPEC;
}

#endif
