//! One address type for both families, mirroring `struct addr6`
//! (xdp/common.h): IPv6 as is, IPv4 v4-mapped (::ffff:a.b.c.d), bytes in
//! network order.

// Parts are consumed by the modules migrated in the following tasks.
#![allow(dead_code)]

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use aya::Pod;
use aya::maps::lpm_trie::Key;

#[repr(C, align(4))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Addr6(pub [u8; 16]);

// SAFETY: repr(C) wrapper of a byte array, valid for any bit pattern.
unsafe impl Pod for Addr6 {}

impl Addr6 {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self(v4.to_ipv6_mapped().octets()),
            IpAddr::V6(v6) => Self(v6.octets()),
        }
    }

    pub fn to_ip(self) -> IpAddr {
        let v6 = Ipv6Addr::from(self.0);
        match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        }
    }

    /// Keeps the first `len` bits (0..=128) of the 128-bit form.
    pub fn mask(self, len: u8) -> Self {
        let bits = u128::from_be_bytes(self.0);
        let mask = if len == 0 {
            0
        } else {
            u128::MAX << (128 - u32::from(len.min(128)))
        };
        Self((bits & mask).to_be_bytes())
    }
}

impl fmt::Display for Addr6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_ip().fmt(f)
    }
}

/// A network of either family; `len` is in the family's own bits.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Net {
    pub addr: IpAddr,
    pub len: u8,
}

impl Net {
    /// Prefix length in the 128-bit (v4-mapped) form.
    pub fn lpm_len(&self) -> u32 {
        match self.addr {
            IpAddr::V4(_) => u32::from(self.len) + 96,
            IpAddr::V6(_) => u32::from(self.len),
        }
    }

    /// The network address, masked, in the 128-bit form.
    pub fn addr6(&self) -> Addr6 {
        Addr6::from_ip(self.addr).mask(self.lpm_len() as u8)
    }

    /// The netmask in the 128-bit form.
    pub fn mask6(&self) -> Addr6 {
        Addr6([0xff; 16]).mask(self.lpm_len() as u8)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        if ip.is_ipv4() != self.addr.is_ipv4() {
            return false;
        }
        Addr6::from_ip(ip).mask(self.lpm_len() as u8) == self.addr6()
    }

    /// True when every address of `other` is inside `self` (same family).
    pub fn covers(&self, other: &Net) -> bool {
        self.lpm_len() <= other.lpm_len() && self.contains(other.addr)
    }

    /// True when the two networks share addresses (one covers the other).
    pub fn overlaps(&self, other: &Net) -> bool {
        self.covers(other) || other.covers(self)
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr6(), self.len)
    }
}

/// LPM trie key of `struct net_key` (xdp/reflection.h).
pub fn lpm_key(net: &Net) -> Key<Addr6> {
    Key::new(net.lpm_len(), net.addr6())
}

/// The source as counted by throttle, rate limit and bans (see src_prefix()
/// in xdp/l3.h): IPv4 per address, IPv6 per `v6_len`.
pub fn source_prefix(ip: IpAddr, v6_len: u8) -> Net {
    let len = if ip.is_ipv4() { 32 } else { v6_len };
    let net = Net { addr: ip, len };
    Net {
        addr: net.addr6().to_ip(),
        len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn v4_is_mapped() {
        let a = Addr6::from_ip("1.2.3.4".parse().unwrap());
        assert_eq!(a.0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]);
        assert_eq!(a.to_ip(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(a.to_string(), "1.2.3.4");
    }

    #[test]
    fn v6_round_trips_canonical() {
        let ip: IpAddr = "2001:0db8:0000:0000:0000:0000:0000:0010".parse().unwrap();
        let a = Addr6::from_ip(ip);
        assert_eq!(a.to_ip(), ip);
        assert_eq!(a.to_string(), "2001:db8::10");
    }

    #[test]
    fn masks() {
        let a = Addr6::from_ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap());
        assert_eq!(a.mask(64).to_string(), "2001:db8:1:2::");
        assert_eq!(a.mask(56).to_string(), "2001:db8:1::");
        assert_eq!(a.mask(128), a);
        assert_eq!(a.mask(0), Addr6::default());
    }

    #[test]
    fn nets() {
        let v4 = Net {
            addr: "10.1.2.3".parse().unwrap(),
            len: 24,
        };
        assert_eq!(v4.lpm_len(), 120);
        assert_eq!(v4.addr6().to_string(), "10.1.2.0");
        assert!(v4.contains("10.1.2.200".parse().unwrap()));
        assert!(!v4.contains("10.1.3.1".parse().unwrap()));
        assert!(!v4.contains("::ffff:10.1.3.1".parse::<Ipv6Addr>().unwrap().into()));
        let v6 = Net {
            addr: "2001:db8::".parse().unwrap(),
            len: 32,
        };
        assert_eq!(v6.lpm_len(), 32);
        assert!(v6.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!v6.contains("1.2.3.4".parse().unwrap()));
        assert_eq!(v6.to_string(), "2001:db8::/32");
    }

    #[test]
    fn masks_keys_and_empty_nets() {
        let v4 = Net {
            addr: "10.1.2.3".parse().unwrap(),
            len: 24,
        };
        assert_eq!(v4.mask6().0[..12], [0xff; 12]);
        assert_eq!(v4.mask6().0[12..], [0xff, 0xff, 0xff, 0]);
        let v6 = Net {
            addr: "2001:db8::".parse().unwrap(),
            len: 32,
        };
        assert_eq!(v6.mask6().0[..4], [0xff; 4]);
        assert_eq!(v6.mask6().0[4..], [0; 12]);

        let k4 = lpm_key(&Net {
            addr: "10.9.9.9".parse().unwrap(),
            len: 8,
        });
        assert_eq!(k4.prefix_len(), 104);
        assert_eq!(k4.data().to_string(), "10.0.0.0");
        let k6 = lpm_key(&v6);
        assert_eq!(k6.prefix_len(), 32);
        assert_eq!(k6.data().to_string(), "2001:db8::");

        let any4 = Net {
            addr: "0.0.0.0".parse().unwrap(),
            len: 0,
        };
        assert!(any4.contains("203.0.113.9".parse().unwrap()));
        assert!(!any4.contains("2001:db8::1".parse().unwrap()));
        let any6 = Net {
            addr: "::".parse().unwrap(),
            len: 0,
        };
        assert!(any6.contains("2001:db8::1".parse().unwrap()));
        assert!(!any6.contains("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn covers_and_overlaps() {
        let n = |t: &str| {
            let (a, l) = t.split_once('/').unwrap();
            Net {
                addr: a.parse().unwrap(),
                len: l.parse().unwrap(),
            }
        };
        assert!(n("1.2.3.0/24").covers(&n("1.2.3.4/32")));
        assert!(!n("1.2.3.4/32").covers(&n("1.2.3.0/24")));
        assert!(n("1.2.3.4/32").overlaps(&n("1.2.3.0/24")));
        assert!(n("1.2.3.0/24").overlaps(&n("1.2.3.4/32")));
        assert!(!n("1.2.3.4/32").overlaps(&n("1.2.4.0/24")));
        assert!(n("2001:db8:1:2::/64").covers(&n("2001:db8:1:2::9/128")));
        assert!(!n("2001:db8:1:2::9/128").covers(&n("2001:db8:1:2::/64")));
        assert!(n("2001:db8:1:2::9/128").overlaps(&n("2001:db8:1:2::/64")));
        assert!(!n("2001:db8:1:2::/64").overlaps(&n("2001:db8:1:3::/64")));
        assert!(!n("0.0.0.0/0").covers(&n("::/0")));
        assert!(!n("::/0").overlaps(&n("1.2.3.4/32")));
    }

    #[test]
    fn source_prefixes() {
        assert_eq!(
            source_prefix("1.2.3.4".parse().unwrap(), 64).to_string(),
            "1.2.3.4/32"
        );
        assert_eq!(
            source_prefix("2001:db8::1:2:3:4".parse().unwrap(), 64).to_string(),
            "2001:db8::/64"
        );
    }

    #[test]
    fn layout() {
        assert_eq!(std::mem::size_of::<Addr6>(), 16);
        assert_eq!(std::mem::align_of::<Addr6>(), 4);
    }
}
