use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TracerouteStatus {
    Finished,
    Failed,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HopTiming {
    pub rtt: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TracerouteHop {
    pub resolved_address: Option<String>,
    pub resolved_hostname: Option<String>,
    pub timings: Vec<HopTiming>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ParsedTraceroute {
    pub status: TracerouteStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_source: Option<String>,
    pub raw_output: String,
    pub resolved_address: Option<String>,
    pub resolved_hostname: Option<String>,
    pub hops: Vec<TracerouteHop>,
}

#[derive(Debug, Clone, Copy)]
pub struct TracerouteIdentity<'a> {
    pub address: IpAddr,
    pub hostname: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TracerouteExecutionStatus {
    pub timed_out: bool,
    pub succeeded: Option<bool>,
}

pub type TracerouteHostnames = BTreeMap<IpAddr, String>;

fn failed(raw_output: &str) -> ParsedTraceroute {
    ParsedTraceroute {
        status: TracerouteStatus::Failed,
        failure_source: None,
        raw_output: raw_output.to_string(),
        resolved_address: None,
        resolved_hostname: None,
        hops: Vec::new(),
    }
}

#[must_use]
pub fn failed_traceroute(
    failure_source: impl Into<String>,
    raw_output: impl Into<String>,
) -> ParsedTraceroute {
    ParsedTraceroute {
        status: TracerouteStatus::Failed,
        failure_source: Some(failure_source.into()),
        raw_output: raw_output.into(),
        resolved_address: None,
        resolved_hostname: None,
        hops: Vec::new(),
    }
}

fn parenthesized_address(line: &str) -> Option<IpAddr> {
    for (open, _) in line.match_indices('(') {
        let tail = &line[open + 1..];
        let Some(close) = tail.find(')') else {
            continue;
        };
        if let Ok(address) = tail[..close].parse::<IpAddr>() {
            return Some(address);
        }
    }
    None
}

fn line_address_tokens(line: &str) -> Vec<(&str, IpAddr)> {
    line.split_whitespace()
        .filter_map(|token| {
            let text = token.trim_matches(|ch| matches!(ch, '(' | ')' | ',' | '[' | ']'));
            text.parse::<IpAddr>().ok().map(|address| (text, address))
        })
        .collect()
}

#[must_use]
pub fn line_addresses(line: &str) -> Vec<IpAddr> {
    line_address_tokens(line)
        .into_iter()
        .map(|(_, address)| address)
        .collect()
}

fn host_pair(line: &str) -> (Option<String>, Option<String>) {
    for (open, _) in line.match_indices('(') {
        let tail = &line[open + 1..];
        let Some(close) = tail.find(')') else {
            continue;
        };
        let address = &tail[..close];
        if address.parse::<IpAddr>().is_err() {
            continue;
        }
        let before = line[..open].trim_end();
        let hostname = before.split_whitespace().last().map(str::to_string);
        return (Some(address.to_string()), hostname);
    }
    (None, None)
}

fn timings(line: &str) -> Vec<HopTiming> {
    let words = line.split_whitespace().collect::<Vec<_>>();
    words
        .windows(2)
        .filter_map(|pair| {
            if pair[1] != "ms" {
                return None;
            }
            pair[0].parse().ok().map(|rtt| HopTiming { rtt })
        })
        .collect()
}

fn sanitize_gateway(line: &str) -> String {
    let (_, hostname) = host_pair(line);
    let Some(hostname) = hostname else {
        return line.to_string();
    };
    if hostname == "_gateway" {
        return line.to_string();
    }
    line.replacen(&hostname, "_gateway", 1)
}

fn parse_hop(line: &str) -> TracerouteHop {
    let (resolved_address, resolved_hostname) = host_pair(line);
    TracerouteHop {
        resolved_address,
        resolved_hostname,
        timings: timings(line),
    }
}

#[must_use]
pub fn parse(raw_output: &str) -> ParsedTraceroute {
    let mut lines = raw_output.lines();
    let Some(header) = lines.next() else {
        return failed(raw_output);
    };
    let Some(resolved_address) = parenthesized_address(header) else {
        return failed(raw_output);
    };

    let mut output_lines = Vec::new();
    output_lines.push(header.to_string());
    for (index, line) in lines.enumerate() {
        if index == 0 {
            output_lines.push(sanitize_gateway(line));
        } else {
            output_lines.push(line.to_string());
        }
    }

    let hops = output_lines
        .iter()
        .skip(1)
        .map(|line| parse_hop(line))
        .collect::<Vec<_>>();
    let resolved_hostname = hops
        .iter()
        .rev()
        .find_map(|hop| hop.resolved_hostname.as_deref())
        .map(str::to_string);

    ParsedTraceroute {
        status: TracerouteStatus::Finished,
        failure_source: None,
        raw_output: output_lines.join("\n"),
        resolved_address: Some(resolved_address.to_string()),
        resolved_hostname,
        hops,
    }
}

fn normalize_header(first: &str, identity: TracerouteIdentity<'_>) -> String {
    let Some(rest) = first.strip_prefix("traceroute to ") else {
        return first.to_string();
    };
    let Some(open) = rest.find('(') else {
        return first.to_string();
    };
    let tail = &rest[open + 1..];
    let Some(close) = tail.find(')') else {
        return first.to_string();
    };
    let Ok(address) = tail[..close].parse::<IpAddr>() else {
        return first.to_string();
    };
    if address != identity.address {
        return first.to_string();
    }
    let suffix = &tail[close + 1..];
    format!(
        "traceroute to {} ({}){suffix}",
        identity.hostname, identity.address
    )
}

#[must_use]
pub fn normalize_numeric_output(
    raw: &str,
    identity: TracerouteIdentity<'_>,
    hostnames: &TracerouteHostnames,
) -> String {
    let mut lines = raw.lines();
    let Some(first) = lines.next() else {
        return String::new();
    };
    let header = normalize_header(first, identity);
    let mut output = Vec::new();
    output.push(header);

    for (index, line) in lines.enumerate() {
        let mut normalized = line.to_string();
        let mut search_from = 0;
        for (source_text, ip) in line_address_tokens(line) {
            let ip_text = ip.to_string();
            let hostname = if index == 0 {
                "_gateway".to_string()
            } else if ip == identity.address {
                identity.hostname.to_string()
            } else {
                hostnames
                    .get(&ip)
                    .cloned()
                    .unwrap_or_else(|| ip_text.clone())
            };
            let Some(relative) = normalized[search_from..].find(source_text) else {
                continue;
            };
            let start = search_from + relative;
            let end = start + source_text.len();
            let replacement = format!("{hostname} ({ip_text})");
            normalized.replace_range(start..end, &replacement);
            search_from = start + replacement.len();
        }
        output.push(normalized);
    }
    output.join("\n")
}

#[must_use]
pub fn progress_output(raw: &str, identity: TracerouteIdentity<'_>) -> String {
    normalize_numeric_output(raw, identity, &TracerouteHostnames::new())
}

fn has_upstream_unreachable(output: &str) -> bool {
    output.split_whitespace().any(|token| {
        matches!(token, "!N" | "!H" | "!P" | "!X" | "!S" | "!F" | "!V" | "!C")
            || token.strip_prefix('!').is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
    })
}

fn timeout_failure_source(
    raw: &str,
    parsed: &ParsedTraceroute,
    identity: TracerouteIdentity<'_>,
) -> &'static str {
    let address = identity.address.to_string();
    let target_responded = parsed.hops.last().is_some_and(|hop| {
        hop.resolved_address.as_deref() == Some(address.as_str()) && !hop.timings.is_empty()
    });
    if target_responded {
        return "internal";
    }
    if raw.lines().skip(1).any(|line| line.contains('*')) {
        "target"
    } else {
        "internal"
    }
}

#[must_use]
pub fn shape_traceroute_output(
    raw: &str,
    stderr: &str,
    execution: TracerouteExecutionStatus,
    identity: TracerouteIdentity<'_>,
    hostnames: &TracerouteHostnames,
) -> ParsedTraceroute {
    let normalized = normalize_numeric_output(raw, identity, hostnames);
    let mut parsed = parse(&normalized);
    parsed.resolved_address = Some(identity.address.to_string());
    parsed.resolved_hostname = Some(identity.hostname.to_string());

    if execution.timed_out {
        parsed.status = TracerouteStatus::Failed;
        parsed.failure_source = Some(timeout_failure_source(raw, &parsed, identity).to_string());
        let mut timeout_raw = raw.to_string();
        if !timeout_raw.is_empty() {
            timeout_raw.push_str("\n\n");
        }
        timeout_raw.push_str("The measurement command timed out.");
        parsed.raw_output = normalize_numeric_output(&timeout_raw, identity, hostnames);
    } else if execution.succeeded == Some(false) {
        parsed.status = TracerouteStatus::Failed;
        parsed.failure_source = Some(
            if has_upstream_unreachable(&normalized) {
                "target"
            } else {
                "internal"
            }
            .to_string(),
        );
        if parsed.raw_output.trim().is_empty() {
            parsed.raw_output = if stderr.trim().is_empty() {
                "Test failed. Please try again.".to_string()
            } else {
                stderr.to_string()
            };
        }
    } else if parsed.status == TracerouteStatus::Failed {
        parsed.failure_source = Some("internal".to_string());
        if parsed.raw_output.trim().is_empty() {
            parsed.raw_output = "Test failed. Please try again.".to_string();
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUCCESS_OUTPUT: &str = "\
traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets
 1  _gateway (192.168.1.1)  1.234 ms  1.156 ms
 2  10.0.0.1 (10.0.0.1)  5.678 ms  5.432 ms
 3  * * *
 4  1.1.1.1 (1.1.1.1)  8.123 ms  7.956 ms";

    const GATEWAY_HOSTNAME_OUTPUT: &str = "\
traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets
 1  router.home (192.168.1.1)  1.0 ms  1.1 ms
 2  1.1.1.1 (1.1.1.1)  8.0 ms  8.1 ms";

    fn identity() -> TracerouteIdentity<'static> {
        TracerouteIdentity {
            address: IpAddr::V4(core::net::Ipv4Addr::new(1, 1, 1, 1)),
            hostname: "one.one.one.one",
        }
    }

    #[test]
    fn parses_header_and_hops() {
        let result = parse(SUCCESS_OUTPUT);
        assert_eq!(result.status, TracerouteStatus::Finished);
        assert_eq!(result.resolved_address.as_deref(), Some("1.1.1.1"));
        assert_eq!(result.hops.len(), 4);
    }

    #[test]
    fn gateway_first_hop_is_redacted() {
        let result = parse(GATEWAY_HOSTNAME_OUTPUT);
        assert!(result.raw_output.contains("_gateway"));
        assert!(!result.raw_output.contains("router.home"));
        assert_eq!(
            result.hops[0].resolved_hostname.as_deref(),
            Some("_gateway")
        );
        assert_eq!(
            result.hops[0].resolved_address.as_deref(),
            Some("192.168.1.1")
        );
    }

    #[test]
    fn star_hop_has_no_address_and_no_timings() {
        let result = parse(SUCCESS_OUTPUT);
        let star = &result.hops[2];
        assert_eq!(star.resolved_address, None);
        assert_eq!(star.resolved_hostname, None);
        assert!(star.timings.is_empty());
    }

    #[test]
    fn rtt_values_are_parsed() {
        let result = parse(SUCCESS_OUTPUT);
        assert_eq!(result.hops[0].timings.len(), 2);
        assert!((result.hops[0].timings[0].rtt - 1.234).abs() < 0.001);
        assert!((result.hops[0].timings[1].rtt - 1.156).abs() < 0.001);
    }

    #[test]
    fn resolved_hostname_is_last_hop_hostname() {
        let result = parse(SUCCESS_OUTPUT);
        assert_eq!(result.resolved_hostname.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn empty_or_headerless_input_fails() {
        assert_eq!(parse("").status, TracerouteStatus::Failed);
        assert_eq!(
            parse("some garbage\n 1  * * *\n").status,
            TracerouteStatus::Failed
        );
    }

    #[test]
    fn ipv6_target_is_parsed() {
        let raw = "\
traceroute to 2606:4700:4700::1111 (2606:4700:4700::1111), 20 hops max, 80 byte packets
 1  _gateway (fe80::1)  1.0 ms  1.1 ms
 2  2606:4700:4700::1111 (2606:4700:4700::1111)  9.5 ms  9.3 ms";
        let result = parse(raw);
        assert_eq!(result.status, TracerouteStatus::Finished);
        assert_eq!(
            result.resolved_address.as_deref(),
            Some("2606:4700:4700::1111")
        );
        assert_eq!(result.hops.len(), 2);
        assert_eq!(
            result.hops[1].resolved_address.as_deref(),
            Some("2606:4700:4700::1111")
        );
    }

    #[test]
    fn mixed_star_and_rtt_hop_keeps_timing() {
        let raw = "\
traceroute to 8.8.8.8 (8.8.8.8), 20 hops max, 60 byte packets
 1  * 1.234 ms *
 2  8.8.8.8 (8.8.8.8)  5.0 ms  5.1 ms";
        let result = parse(raw);
        assert_eq!(result.hops[0].resolved_address, None);
        assert_eq!(result.hops[0].timings.len(), 1);
        assert!((result.hops[0].timings[0].rtt - 1.234).abs() < 0.001);
    }

    #[test]
    fn numeric_output_normalizes_gateway_target_and_ptr() {
        let raw = "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets\n 1  192.168.1.1  1.0 ms\n 2  8.8.8.8  5.0 ms\n 3  1.1.1.1  8.0 ms";
        let mut hostnames = TracerouteHostnames::new();
        hostnames.insert(
            IpAddr::V4(core::net::Ipv4Addr::new(8, 8, 8, 8)),
            "dns.google".to_string(),
        );
        let normalized = normalize_numeric_output(raw, identity(), &hostnames);
        assert!(normalized.contains("traceroute to one.one.one.one (1.1.1.1)"));
        assert!(normalized.contains("_gateway (192.168.1.1)"));
        assert!(normalized.contains("dns.google (8.8.8.8)"));
        assert!(normalized.contains("one.one.one.one (1.1.1.1)"));
    }

    #[test]
    fn repeated_address_probes_do_not_rewrite_inserted_text() {
        let raw = "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets\n 1  192.168.1.1  1.0 ms  192.168.1.1  1.1 ms\n 2  8.8.8.8  5.0 ms  8.8.8.8  5.1 ms";
        let mut hostnames = TracerouteHostnames::new();
        hostnames.insert(
            IpAddr::V4(core::net::Ipv4Addr::new(8, 8, 8, 8)),
            "dns.google".to_string(),
        );
        let normalized = normalize_numeric_output(raw, identity(), &hostnames);
        assert_eq!(normalized.matches("_gateway (192.168.1.1)").count(), 2);
        assert_eq!(normalized.matches("dns.google (8.8.8.8)").count(), 2);
        assert!(!normalized.contains("_gateway (_gateway"));
        assert!(!normalized.contains("dns.google (dns.google"));
    }

    #[test]
    fn noncanonical_ipv6_source_text_is_replaced_by_parsed_address() {
        let identity = TracerouteIdentity {
            address: "2001:db8::1"
                .parse()
                .unwrap_or_else(|error| panic!("fixture address: {error}")),
            hostname: "target.example",
        };
        let raw = "traceroute to 2001:DB8:0:0:0:0:0:1 (2001:DB8:0:0:0:0:0:1), 20 hops max, 80 byte packets\n 1  FE80:0:0:0:0:0:0:1  1.0 ms\n 2  2001:DB8:0:0:0:0:0:1  5.0 ms";
        let normalized = normalize_numeric_output(raw, identity, &TracerouteHostnames::new());
        assert!(normalized.starts_with("traceroute to target.example (2001:db8::1)"));
        assert!(normalized.contains("_gateway (fe80::1)"));
        assert!(normalized.contains("target.example (2001:db8::1)"));
    }

    #[test]
    fn timeout_with_missing_hop_is_target_failure() {
        let raw = "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets\n 1  192.168.1.1  1.0 ms\n 2  * * *";
        let result = shape_traceroute_output(
            raw,
            "",
            TracerouteExecutionStatus {
                timed_out: true,
                succeeded: None,
            },
            identity(),
            &TracerouteHostnames::new(),
        );
        assert_eq!(result.status, TracerouteStatus::Failed);
        assert_eq!(result.failure_source.as_deref(), Some("target"));
        assert!(
            result
                .raw_output
                .ends_with("The measurement command timed out.")
        );
    }

    #[test]
    fn upstream_unreachable_is_target_failure() {
        let raw = "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets\n 1  192.168.1.1  1.0 ms !H";
        let result = shape_traceroute_output(
            raw,
            "",
            TracerouteExecutionStatus {
                timed_out: false,
                succeeded: Some(false),
            },
            identity(),
            &TracerouteHostnames::new(),
        );
        assert_eq!(result.status, TracerouteStatus::Failed);
        assert_eq!(result.failure_source.as_deref(), Some("target"));
    }

    #[test]
    fn failed_empty_process_uses_stderr_or_public_fallback() {
        let status = TracerouteExecutionStatus {
            timed_out: false,
            succeeded: Some(false),
        };
        let with_stderr = shape_traceroute_output(
            "",
            "traceroute: permission denied",
            status,
            identity(),
            &TracerouteHostnames::new(),
        );
        assert_eq!(with_stderr.raw_output, "traceroute: permission denied");
        let fallback =
            shape_traceroute_output("", "", status, identity(), &TracerouteHostnames::new());
        assert_eq!(fallback.raw_output, "Test failed. Please try again.");
    }
}
