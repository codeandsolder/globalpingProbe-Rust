use alloc::string::String;
use core::net::IpAddr;

pub(super) fn is_private_or_reserved(address: IpAddr, local_addresses: &[String]) -> bool {
    globalping_behavior_core::ip::is_private_or_reserved(
        address,
        local_addresses
            .iter()
            .filter_map(|local| local.parse::<IpAddr>().ok()),
    )
}
