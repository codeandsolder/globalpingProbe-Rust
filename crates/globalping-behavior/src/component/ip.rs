use alloc::string::String;
use core::net::IpAddr;

fn prefix_matches(bytes: &[u8], network: &[u8], prefix_bits: u8) -> bool {
    let full_bytes = usize::from(prefix_bits / 8);
    let remaining_bits = prefix_bits % 8;
    if bytes[..full_bytes] != network[..full_bytes] {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - remaining_bits);
    bytes[full_bytes] & mask == network[full_bytes] & mask
}

fn canonical_address(address: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = address else {
        return address;
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }
    let octets = v6.octets();
    if octets[..12] == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
        return IpAddr::V4(core::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    address
}

pub(super) fn is_private_or_reserved(address: IpAddr, local_addresses: &[String]) -> bool {
    let address = canonical_address(address);
    if local_addresses.iter().any(|local| {
        local
            .parse::<IpAddr>()
            .is_ok_and(|local| canonical_address(local) == address)
    }) {
        return true;
    }
    match address {
        IpAddr::V4(v4) => {
            let bytes = v4.octets();
            [
                ([0, 0, 0, 0], 8),
                ([10, 0, 0, 0], 8),
                ([100, 64, 0, 0], 10),
                ([127, 0, 0, 0], 8),
                ([169, 254, 0, 0], 16),
                ([172, 16, 0, 0], 12),
                ([192, 0, 0, 0], 24),
                ([192, 0, 2, 0], 24),
                ([192, 88, 99, 0], 24),
                ([192, 168, 0, 0], 16),
                ([198, 18, 0, 0], 15),
                ([198, 51, 100, 0], 24),
                ([203, 0, 113, 0], 24),
                ([224, 0, 0, 0], 4),
                ([240, 0, 0, 0], 4),
            ]
            .iter()
            .any(|(network, prefix)| prefix_matches(&bytes, network, *prefix))
        }
        IpAddr::V6(v6) => {
            let bytes = v6.octets();
            [
                ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 128),
                ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128),
                (
                    [
                        0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                    48,
                ),
                ([0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 64),
                ([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32),
                (
                    [0x20, 0x01, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    28,
                ),
                (
                    [0x20, 0x01, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    28,
                ),
                (
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    32,
                ),
                ([0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 16),
                ([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
                ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
                ([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8),
            ]
            .iter()
            .any(|(network, prefix)| prefix_matches(&bytes, network, *prefix))
        }
    }
}
