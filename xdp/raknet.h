#ifndef RAKNET_H
#define RAKNET_H

/*
 * Pure RakNet offline message checks shared by the XDP program and the
 * native unit tests: no maps, no helpers besides byte order macros.
 */

#include <linux/types.h>

// RakNet offline message ids sent by clients
#define RAKNET_UNCONNECTED_PING 0x01
#define RAKNET_UNCONNECTED_PING_OPEN 0x02
#define RAKNET_OPEN_CONNECTION_REQUEST_1 0x05
#define RAKNET_OPEN_CONNECTION_REQUEST_2 0x07

// minimum payload sizes: id + time + magic + guid for pings, id + magic +
// protocol (+ mtu padding) for request 1, id + magic + address (ipv4 7 bytes,
// ipv6 29 bytes) + mtu + guid for request 2 (the ipv4 form is the shorter one)
#define RAKNET_PING_LEN 33
#define RAKNET_REQUEST_1_MIN_LEN 18
#define RAKNET_REQUEST_2_MIN_LEN 34

// offset of the server address in request 2 (after id and magic), and the
// address sizes after its family byte: ipv4 address + port, or (sockaddr_in6
// as RakNet writes it) family + port + flow info + address + scope id
#define RAKNET_REQUEST_2_ADDR_OFF 17
#define RAKNET_ADDR4_LEN 6
#define RAKNET_ADDR6_LEN 28

/*
 * MTU sizes a client may ask for in request 2: RakNet's own bounds
 * (MINIMUM_MTU_SIZE 400, MAXIMUM_MTU_SIZE 1492; bedrock clients try 1492,
 * 1200 and 576), rounded up to the ethernet MTU of 1500 for implementations
 * that probe the full frame. Anything else is forged.
 */
#define RAKNET_MTU_MIN 400
#define RAKNET_MTU_MAX 1500

/*
 * Checks the 16 byte RakNet offline message magic
 * 00 ff ff 00 fe fe fe fe fd fd fd fd 12 34 56 78 at p, compared as two
 * little endian u64 words.
 */
static __always_inline __u8 raknet_magic_at(const __u8 *p, const void *data_end)
{
    if ((const void *)(p + 16) > data_end)
    {
        return 0;
    }
    __u64 first, second;
    __builtin_memcpy(&first, p, 8);
    __builtin_memcpy(&second, p + 8, 8);
    return first == 0xfefefefe00ffff00ULL && second == 0x78563412fdfdfdfdULL;
}

/*
 * Open connection request 2 after its magic: a server address of family 4
 * or 6, then an MTU within RAKNET_MTU_MIN..RAKNET_MTU_MAX and the client
 * guid. payload_len is the udp payload length, payload + payload_len must
 * not be past data_end.
 */
static __always_inline __u8 raknet_request_2_fields_valid(const __u8 *payload, const __u32 payload_len,
                                                          const void *data_end)
{
    const __u8 *family = payload + RAKNET_REQUEST_2_ADDR_OFF;
    if ((const void *)(family + 1) > data_end)
    {
        return 0;
    }
    __u32 mtu_off;
    if (*family == 4)
    {
        mtu_off = RAKNET_REQUEST_2_ADDR_OFF + 1 + RAKNET_ADDR4_LEN;
    }
    else if (*family == 6)
    {
        mtu_off = RAKNET_REQUEST_2_ADDR_OFF + 1 + RAKNET_ADDR6_LEN;
    }
    else
    {
        return 0;
    }
    // mtu (2) and guid (8) must follow
    if (payload_len < mtu_off + 2 + 8)
    {
        return 0;
    }
    const __u8 *mtu_p = payload + mtu_off;
    if ((const void *)(mtu_p + 2) > data_end)
    {
        return 0;
    }
    const __u32 mtu = ((__u32)mtu_p[0] << 8) | mtu_p[1];
    return mtu >= RAKNET_MTU_MIN && mtu <= RAKNET_MTU_MAX;
}

#endif
