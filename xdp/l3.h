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
#include <linux/ip.h>

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);  // ifindex
    __type(value, __u8); // 1
} l3_interfaces SEC(".maps");

// the IPv4 header of a packet on `ifindex`, or NULL for anything else
static __always_inline const struct iphdr *ipv4_header(const void *data, const void *data_end, __u32 ifindex)
{
    if (L3_INTERFACES && bpf_map_lookup_elem(&l3_interfaces, &ifindex))
    {
        const struct iphdr *ip = data;
        if ((const void *)(ip + 1) > data_end || ip->version != 4)
        {
            return NULL;
        }
        return ip;
    }
    const struct ethhdr *eth = data;
    if ((const void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return NULL;
    }
    const struct iphdr *ip = (const void *)(eth + 1);
    if ((const void *)(ip + 1) > data_end)
    {
        return NULL;
    }
    return ip;
}

#endif
