pub use globalping_behavior_core::dns::{
    ClassicResult, DnsAnswer, DnsStatus, DnsTimings, TraceHop, TraceResult, parse_trace,
};

/// Parse classic `dig` output using the native private/local-address policy.
#[must_use]
pub fn parse_classic(raw: &str) -> ClassicResult {
    let local_addresses = crate::util::private_ip::local_address_strings();
    globalping_behavior_core::dns::parse_classic(raw, &local_addresses)
}
