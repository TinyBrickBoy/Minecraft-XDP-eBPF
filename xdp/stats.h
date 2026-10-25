#ifndef STATS_H
#define STATS_H

#include <linux/types.h>

#include "config.h"

// selects which statistics count_stats() increments; a bitmask so related
// counters can be bumped in one call (e.g. DROP_CONNECTION | DROPPED_PACKET)
enum stats_mask {
    VERIFIED        = 1u << 0,
    DROPPED_PACKET  = 1u << 1,
    STATE_SWITCH    = 1u << 2,
    DROP_CONNECTION = 1u << 3,
    SYN_RECEIVE     = 1u << 4,
    TCP_BYPASS      = 1u << 5,
    INCOMING_BYTES  = 1u << 6,
    DROPPED_BYTES   = 1u << 7,
};

// one per-cpu slot of stats_map; must match `Statistics` in loader/metrics.rs
struct statistics
{
    __u64 verified;
    __u64 dropped_packets;
    __u64 state_switches;
    __u64 drop_connection;
    __u64 syn;
    __u64 tcp_bypass;
    __u64 incoming_bytes;
    __u64 dropped_bytes;
};
_Static_assert(sizeof(struct statistics) == 64, "statistics size mismatch!");

// key of dst_stats_map: one entry per protected destination ip:port, both in
// network byte order; must match `DstKey` in loader/metrics.rs
struct dst_key
{
    __u32 daddr;
    __u16 dport;
    __u16 pad;
};
_Static_assert(sizeof(struct dst_key) == 8, "dst_key size mismatch!");

static __always_inline void add_stats(struct statistics *stats_ptr, const __u32 bitmask, const __u64 amount)
{
    if (bitmask & INCOMING_BYTES)
    {
        stats_ptr->incoming_bytes += amount;
    }

    if (bitmask & DROPPED_BYTES)
    {
        stats_ptr->dropped_bytes += amount;
    }

    if (bitmask & VERIFIED)
    {
        stats_ptr->verified += amount;
    }

    if (bitmask & DROPPED_PACKET)
    {
        stats_ptr->dropped_packets += amount;
    }

    if (bitmask & STATE_SWITCH)
    {
        stats_ptr->state_switches += amount;
    }

    if (bitmask & DROP_CONNECTION)
    {
        stats_ptr->drop_connection += amount;
    }

    if (bitmask & SYN_RECEIVE)
    {
        stats_ptr->syn += amount;
    }

    if (bitmask & TCP_BYPASS)
    {
        stats_ptr->tcp_bypass += amount;
    }
}

/*
 * Adds `amount` to every counter selected by `bitmask`, both in the global
 * totals and in the per destination ip:port entry.
 *
 * stats_ptr is NULL whenever PROMETHEUS is 0 (the filter only looks it up
 * when enabled), so the PROMETHEUS check below also guards the dereference.
 * Since PROMETHEUS lives in .rodata, the verifier knows its value at load
 * time and removes either the early return or the entire body as dead code;
 * with constant bitmasks the compiler reduces each call to the few
 * increments that are actually selected. dst_stats_ptr can be NULL even with
 * PROMETHEUS enabled (dst_stats_map full and insert raced), so it is checked.
 */
static __always_inline void count_stats(struct statistics *stats_ptr, struct statistics *dst_stats_ptr, const __u32 bitmask, const __u64 amount)
{
    if (!PROMETHEUS)
    {
        return;
    }

    add_stats(stats_ptr, bitmask, amount);
    if (dst_stats_ptr)
    {
        add_stats(dst_stats_ptr, bitmask, amount);
    }
}

#endif
