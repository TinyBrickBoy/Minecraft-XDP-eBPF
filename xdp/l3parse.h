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
#define L3_BAD 2    // IP, but malformed or too many extension headers, or
                    // IPv6 with addresses that never appear on the wire (bogus)

// struct l3.bogus: IPv6 addresses that are never legitimate on the wire
#define BOGUS_NONE 0
#define BOGUS_UNSPEC 1 // source :: (only neighbour solicitations of duplicate address detection)
#define BOGUS_ADDR 2   // any other source in ::/80 (::1, v4-mapped, ...) or ff00::/8,
                       // or a destination in ::/80 (v4-mapped, ::1, ::)

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
    __u8 hoplimit; // IPv4 ttl / IPv6 hop limit
    __u8 bogus;   // BOGUS_* (IPv6 only, parse result L3_BAD when set)
};

static __always_inline int is_ext_hdr(const __u8 next)
{
    return next == NEXTHDR_HOP || next == NEXTHDR_ROUTING || next == NEXTHDR_FRAGMENT || next == NEXTHDR_DEST;
}

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
    out->hoplimit = ip[8];
    frag_off = bpf_ntohs(frag_off);
    out->frag = (frag_off & 0x1fff) ? FRAG_LATER : (frag_off & 0x2000) ? FRAG_FIRST : FRAG_NONE;
    return L3_OK;
}

// first 80 bits zero: ::, ::1, the v4-mapped ::ffff:0:0/96 and the
// deprecated IPv4-compatible ::/96. IPv4 is stored v4-mapped, so such an IPv6
// address would alias IPv4 state (bans, throttle, targets)
static __always_inline __u8 addr_in_zero80(const struct addr6 *a)
{
    return a->w[0] == 0 && a->w[1] == 0 && (a->w[2] & bpf_htonl(0xffff0000)) == 0;
}

static __always_inline __u8 v6_bogus(const struct addr6 *src, const struct addr6 *dst)
{
    if (addr_in_zero80(dst) || (src->w[0] & bpf_htonl(0xff000000)) == bpf_htonl(0xff000000))
    {
        return BOGUS_ADDR;
    }
    if (addr_in_zero80(src))
    {
        return src->w[2] == 0 && src->w[3] == 0 ? BOGUS_UNSPEC : BOGUS_ADDR;
    }
    return BOGUS_NONE;
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
    out->hoplimit = ip[7];
    out->frag = FRAG_NONE;
    // decided on the fixed header, before the chain walk: a bogus packet is
    // dropped also when its chain is unparseable (L3_BAD from below keeps
    // the mark)
    out->bogus = v6_bogus(&out->src, &out->dst);

    __u8 next = ip[6];
    __u32 off = 40;
#pragma unroll
    for (__u32 i = 0; i < MAX_EXT_HDRS; i++)
    {
        if (!is_ext_hdr(next))
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
            // sticky: a later fragment header never downgrades FRAG_LATER
            const __u8 frag = (bpf_ntohs(fo) & 0xfff8) ? FRAG_LATER : FRAG_FIRST;
            if (frag > out->frag)
            {
                out->frag = frag;
            }
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
    if (is_ext_hdr(next))
    {
        return L3_BAD; // more than MAX_EXT_HDRS extension headers
    }
    if ((const void *)(ip + off) > data_end)
    {
        return L3_BAD; // extension header body truncated
    }
    out->proto = next;
    out->l4off = off;
    out->hdrlen = off;
    // fully parsed (the caller may still look at the l4 header), but a
    // bogus one is never legitimate: dropped whatever the destination
    return out->bogus ? L3_BAD : L3_OK;
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

// l4 header pointer, bounded for the verifier (l4off <= MAX_L3_HDRLEN)
static __always_inline const void *l4_ptr(const void *ip, const struct l3 *l)
{
    return (const __u8 *)ip + (l->l4off & 1023);
}

/*
 * ICMPv6 router solicitation/advertisement, neighbour solicitation/
 * advertisement and redirect: never dropped, or the host loses its
 * neighbours. Only what RFC 4861 allows on the wire is exempt: hop limit
 * 255 (proves the sender is on the link), no extension headers (NDP is
 * never fragmented, RFC 6980, and needs no other header) and at most
 * NDP_MAX_LEN bytes; anything else is filtered like other traffic.
 */
#define NDP_MAX_LEN 1280

static __always_inline __u8 is_ndp(const void *ip, const void *data_end, const struct l3 *l)
{
    if (l->family != FAMILY_V6 || l->proto != 58 || l->frag != FRAG_NONE || l->hoplimit != 255 || l->l4off != 40 ||
        l->l3len > NDP_MAX_LEN)
    {
        return 0;
    }
    const __u8 *icmp = l4_ptr(ip, l);
    if ((const void *)(icmp + 1) > data_end)
    {
        return 0;
    }
    return icmp[0] >= 133 && icmp[0] <= 137;
}

#endif
