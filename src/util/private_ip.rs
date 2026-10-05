use ipnet::IpNet;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// All RFC-reserved ranges — mirrors src/lib/private-ip.ts in the Node.js probe.
// `new_assert` is const, so an invalid prefix is a compile-time error rather than
// a runtime parse failure in probe startup.
const PRIVATE_RANGES: &[IpNet] = &[
    // IPv4
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)), 24),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(192, 88, 99, 0)), 24),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), 4),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 0)), 4),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::BROADCAST), 32),
    // IPv6
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128),
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
    IpNet::new_assert(
        IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0)),
        48,
    ),
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0)), 64),
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0)), 32),
    IpNet::new_assert(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 0)),
        28,
    ),
    IpNet::new_assert(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0)),
        28,
    ),
    IpNet::new_assert(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
        32,
    ),
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0)), 16),
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)), 8),
];

#[must_use]
pub fn is_ip_private(ip: IpAddr) -> bool {
    // Normalise IPv6 forms that embed an IPv4 address so that e.g.
    // `::ffff:127.0.0.1` (IPv4-mapped) or `64:ff9b::a.b.c.d` (NAT64) cannot be
    // used to smuggle a private IPv4 target past the range filter. Without this,
    // `::ffff:169.254.169.254` would reach cloud metadata endpoints (SSRF).
    let ip = canonicalize(ip);

    if get_local_ips().contains(&ip) {
        return true;
    }
    PRIVATE_RANGES.iter().any(|net| net.contains(&ip))
}

/// Collapse IPv6 addresses that embed an IPv4 address down to that IPv4 address
/// so range checks apply to the address actually routed to.
///
/// Handles:
/// - IPv4-mapped IPv6 (`::ffff:a.b.c.d`)
/// - NAT64 well-known prefix (`64:ff9b::/96`)
///
/// All other addresses are returned unchanged.
fn canonicalize(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else { return ip };

    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }

    let seg = v6.segments();
    // 64:ff9b::/96 — NAT64 well-known prefix; embedded IPv4 is the low 32 bits.
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        let o = v6.octets();
        return IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }

    ip
}

fn get_local_ips() -> HashSet<IpAddr> {
    use std::net::UdpSocket;
    let mut ips = HashSet::new();
    // Probe the OS for the outbound IP — lightweight, no external crate needed yet
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.connect("8.8.8.8:80");
        if let Ok(addr) = sock.local_addr() {
            ips.insert(addr.ip());
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ipv4_ranges_are_blocked() {
        assert!(is_ip_private("10.0.0.1".parse().unwrap()));
        assert!(is_ip_private("192.168.1.1".parse().unwrap()));
        assert!(is_ip_private("172.16.0.1".parse().unwrap()));
        assert!(is_ip_private("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn public_ipv4_is_allowed() {
        assert!(!is_ip_private("1.1.1.1".parse().unwrap()));
        assert!(!is_ip_private("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn private_ipv6_ranges_are_blocked() {
        assert!(is_ip_private("::1".parse().unwrap()));
        assert!(is_ip_private("fc00::1".parse().unwrap()));
        assert!(is_ip_private("fe80::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6_private_is_blocked() {
        // Regression: these must not bypass the filter via the IPv6 encoding.
        assert!(is_ip_private("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_ip_private("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_ip_private("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_ip_private("::ffff:169.254.169.254".parse().unwrap())); // cloud metadata
    }

    #[test]
    fn ipv4_mapped_ipv6_public_is_allowed() {
        // Mapped *public* addresses must still be permitted (normalise, don't blanket-block).
        assert!(!is_ip_private("::ffff:1.1.1.1".parse().unwrap()));
        assert!(!is_ip_private("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn nat64_embedded_private_is_blocked() {
        // 64:ff9b::169.254.169.254 → 169.254.169.254
        assert!(is_ip_private("64:ff9b::a9fe:a9fe".parse().unwrap()));
        // 64:ff9b::10.0.0.1
        assert!(is_ip_private("64:ff9b::a00:1".parse().unwrap()));
    }
}
