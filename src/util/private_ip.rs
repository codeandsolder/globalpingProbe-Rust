use std::net::IpAddr;

#[must_use]
pub fn is_ip_private(ip: IpAddr) -> bool {
    globalping_behavior_core::ip::is_private_or_reserved(ip, local_addresses())
}

pub(crate) fn local_address_strings() -> Vec<String> {
    local_addresses()
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}

#[cfg(feature = "native")]
fn local_addresses() -> Vec<IpAddr> {
    if_addrs::get_if_addrs().map_or_else(
        |_| Vec::new(),
        |interfaces| {
            let mut addresses = interfaces
                .into_iter()
                .map(|interface| interface.ip())
                .collect::<Vec<_>>();
            addresses.sort_unstable();
            addresses.dedup();
            addresses
        },
    )
}

#[cfg(not(feature = "native"))]
fn local_addresses() -> Vec<IpAddr> {
    Vec::new()
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
        assert!(is_ip_private("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_ip_private("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_ip_private("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_ip_private("::ffff:169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6_public_is_allowed() {
        assert!(!is_ip_private("::ffff:1.1.1.1".parse().unwrap()));
        assert!(!is_ip_private("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn nat64_embedded_private_is_blocked() {
        assert!(is_ip_private("64:ff9b::a9fe:a9fe".parse().unwrap()));
        assert!(is_ip_private("64:ff9b::a00:1".parse().unwrap()));
    }
}
