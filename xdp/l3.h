#ifndef L3_H
#define L3_H

/*
 * Interfaces without a link layer header (GRE, IPIP, WireGuard): their
 * packets start right at the IP header, in XDP and in tc. The loader lists
 * them here by index; L3_INTERFACES skips the lookup on routers that have
 * none.
 */

#include <linux/types.h>
#include <linux/if_ether.h>
#include "l3parse.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);  // ifindex
    __type(value, __u8); // 1
} l3_interfaces SEC(".maps");

/*
 * Parses the IP header of a packet on `ifindex` into *out. Returns the
 * L3_* result; *ip_out points at the IP header on L3_OK and L3_BAD.
 */
static __always_inline int packet_l3(const void *data, const void *data_end, __u32 ifindex,
                                     struct l3 *out, const void **ip_out)
{
    const void *ip = data;
    if (!(L3_INTERFACES && bpf_map_lookup_elem(&l3_interfaces, &ifindex)))
    {
        const struct ethhdr *eth = data;
        if ((const void *)(eth + 1) > data_end)
        {
            return L3_NOT_IP;
        }
        if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6))
        {
            return L3_NOT_IP;
        }
        ip = eth + 1;
    }
    *ip_out = ip;
    return parse_l3(ip, data_end, out);
}

// the source as counted by throttle, rate limit, strikes, bans and penalty:
// IPv4 per address, IPv6 per IPV6_SOURCE_PREFIX
static __always_inline struct addr6 src_prefix(const struct addr6 *src)
{
    if (addr_is_v4(src))
    {
        return *src;
    }
    return addr_mask(*src, IPV6_SOURCE_PREFIX);
}

// the coarser IPv6 tier of the handshake throttle (IPV6_AGGREGATE_PREFIX,
// default /48): one site owns a whole /48, so rotating through its /64s
// must not multiply its SYN budget. Returns 0 (no
// tier) for IPv4 and while the tier is off
static __always_inline __u8 src_aggregate(const struct addr6 *src, struct addr6 *out)
{
    if (!IPV6_AGGREGATE_PREFIX || addr_is_v4(src))
    {
        return 0;
    }
    *out = addr_mask(*src, IPV6_AGGREGATE_PREFIX);
    return 1;
}

#endif
