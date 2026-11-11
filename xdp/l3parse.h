#ifndef L3PARSE_H
#define L3PARSE_H

/*
 * Pure L3 parser shared by the XDP and tc programs (and the native unit
 * tests): no maps, no helpers besides byte order macros. `ip` points at the
 * first byte of the IPv4 or IPv6 header.
 */

#include <linux/types.h>
#include "common.h"

#define FAMILY_V4 4
#define FAMILY_V6 6

#define FRAG_NONE 0
#define FRAG_FIRST 1 // offset 0 (more fragments follow, or atomic fragment)
#define FRAG_LATER 2 // offset != 0, no l4 header

#define L3_OK 0
#define L3_NOT_IP 1 // not IPv4/IPv6: not our business
#define L3_BAD 2    // IP, but malformed or too many extension headers

#define MAX_EXT_HDRS 4
// extension headers end before this offset or the packet is L3_BAD; keeps
// every offset bounded for the verifier
#define MAX_L3_HDRLEN 512

#define NEXTHDR_HOP 0
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_DEST 60

struct l3
{
    struct addr6 src;
    struct addr6 dst;
    __u32 l4off;  // offset of the l4 header from `ip`
    __u32 l3len;  // IPv4 tot_len, IPv6 40 + payload length
    __u32 hdrlen; // all IP headers incl. extension headers (== l4off)
    __u8 family;  // FAMILY_V4 / FAMILY_V6
    __u8 proto;   // l4 protocol after all extension headers
    __u8 frag;    // FRAG_*
    __u8 tos;     // IPv4 tos / IPv6 traffic class
};

static __always_inline int parse_l3_v4(const __u8 *ip, const void *data_end, struct l3 *out)
{
    out->family = FAMILY_V4; // set first: callers read it on L3_BAD too
    if ((const void *)(ip + 20) > data_end)
    {
        return L3_BAD;
    }
    const __u32 ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || (const void *)(ip + ihl) > data_end)
    {
        return L3_BAD;
    }
    __u16 tot, frag_off;
    __builtin_memcpy(&tot, ip + 2, 2);
    __builtin_memcpy(&frag_off, ip + 6, 2);
    __u32 s, d;
    __builtin_memcpy(&s, ip + 12, 4);
    __builtin_memcpy(&d, ip + 16, 4);
    out->src = addr_from_v4(s);
    out->dst = addr_from_v4(d);
    out->family = FAMILY_V4;
    out->proto = ip[9];
    out->tos = ip[1];
    out->l4off = ihl;
    out->hdrlen = ihl;
    out->l3len = bpf_ntohs(tot);
    frag_off = bpf_ntohs(frag_off);
    out->frag = (frag_off & 0x1fff) ? FRAG_LATER : (frag_off & 0x2000) ? FRAG_FIRST : FRAG_NONE;
    return L3_OK;
}

static __always_inline int parse_l3_v6(const __u8 *ip, const void *data_end, struct l3 *out)
{
    out->family = FAMILY_V6; // set first: callers read it on L3_BAD too
    if ((const void *)(ip + 40) > data_end)
    {
        return L3_BAD;
    }
    __u16 plen;
    __builtin_memcpy(&plen, ip + 4, 2);
    __builtin_memcpy(&out->src, ip + 8, 16);
    __builtin_memcpy(&out->dst, ip + 24, 16);
    out->family = FAMILY_V6;
    out->tos = ((ip[0] & 0x0f) << 4) | (ip[1] >> 4);
    out->l3len = 40 + bpf_ntohs(plen);
    out->frag = FRAG_NONE;

    __u8 next = ip[6];
    __u32 off = 40;
#pragma unroll
    for (__u32 i = 0; i < MAX_EXT_HDRS; i++)
    {
        if (next != NEXTHDR_HOP && next != NEXTHDR_ROUTING && next != NEXTHDR_FRAGMENT && next != NEXTHDR_DEST)
        {
            break;
        }
        const __u8 *h = ip + off;
        if ((const void *)(h + 8) > data_end)
        {
            return L3_BAD;
        }
        if (next == NEXTHDR_FRAGMENT)
        {
            __u16 fo;
            __builtin_memcpy(&fo, h + 2, 2);
            out->frag = (bpf_ntohs(fo) & 0xfff8) ? FRAG_LATER : FRAG_FIRST;
            off += 8;
        }
        else
        {
            off += ((__u32)h[1] + 1) * 8;
        }
        next = h[0];
        if (off > MAX_L3_HDRLEN)
        {
            return L3_BAD;
        }
    }
    if (next == NEXTHDR_HOP || next == NEXTHDR_ROUTING || next == NEXTHDR_FRAGMENT || next == NEXTHDR_DEST)
    {
        return L3_BAD; // more than MAX_EXT_HDRS extension headers
    }
    out->proto = next;
    out->l4off = off;
    out->hdrlen = off;
    return L3_OK;
}

// *out is always fully initialised (zeroed first), also on L3_BAD/L3_NOT_IP;
// a truncated IPv6 header leaves dst = ::
static __always_inline int parse_l3(const void *ip, const void *data_end, struct l3 *out)
{
    __builtin_memset(out, 0, sizeof(*out));
    const __u8 *p = ip;
    if ((const void *)(p + 1) > data_end)
    {
        return L3_NOT_IP;
    }
    switch (p[0] >> 4)
    {
    case 4:
        return parse_l3_v4(p, data_end, out);
    case 6:
        return parse_l3_v6(p, data_end, out);
    }
    return L3_NOT_IP;
}

#endif
