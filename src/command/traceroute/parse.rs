use regex::Regex;
use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────────────

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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TracerouteHop {
    pub resolved_address: Option<String>,
    pub resolved_hostname: Option<String>,
    pub timings: Vec<HopTiming>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ParsedTraceroute {
    pub status: TracerouteStatus,
    pub raw_output: String,
    pub resolved_address: Option<String>,
    pub resolved_hostname: Option<String>,
    pub hops: Vec<TracerouteHop>,
}

// ── Regexes ───────────────────────────────────────────────────────────────────

// Matches: hostname (IP)  — IPv4 or IPv6, with optional scope IDs
static HOST_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(\S+?)(?:%\w+)?(\s+)\(((?:\d+\.){3}\d+|[\da-fA-F:]+)(?:%\w+)?\)").unwrap()
});

// Matches: "8.123 ms" or "1 ms" (probe RTT)
static RTT_RE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"(\d+(?:\.\d+)?)\s+ms").unwrap());

// ── Public API ────────────────────────────────────────────────────────────────

pub fn parse(raw_output: &str) -> ParsedTraceroute {
    let lines: Vec<&str> = raw_output.lines().collect();

    let failed = |raw: &str| ParsedTraceroute {
        status: TracerouteStatus::Failed,
        raw_output: raw.to_string(),
        resolved_address: None,
        resolved_hostname: None,
        hops: vec![],
    };

    if lines.is_empty() {
        return failed(raw_output);
    }

    // Header: "traceroute to google.com (172.217.20.206), 30 hops max, 60 byte packets"
    let header_caps = match HOST_RE.captures(lines[0]) {
        Some(c) => c,
        None => return failed(raw_output),
    };
    let resolved_address = header_caps.get(3).map(|m| m.as_str().to_string());

    // Rewrite first hop: hide real gateway hostname for privacy.
    let mut output_lines: Vec<String> =
        lines.iter().map(std::string::ToString::to_string).collect();
    if output_lines.len() > 1 {
        output_lines[1] = HOST_RE
            .replace(&output_lines[1], |caps: &regex::Captures| {
                format!("_gateway{0}({1})", &caps[2], &caps[3])
            })
            .to_string();
    }

    // Parse each hop line (skip the header).
    let hops: Vec<TracerouteHop> = output_lines[1..]
        .iter()
        .map(|line| parse_hop_line(line))
        .collect();

    // Top-level resolvedHostname = last hop that has a real hostname.
    let resolved_hostname = hops
        .iter()
        .rev()
        .find_map(|h| h.resolved_hostname.as_deref())
        .map(str::to_string);

    ParsedTraceroute {
        status: TracerouteStatus::Finished,
        raw_output: output_lines.join("\n"),
        resolved_address,
        resolved_hostname,
        hops,
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn parse_hop_line(line: &str) -> TracerouteHop {
    let host_caps = HOST_RE.captures(line);

    let timings: Vec<HopTiming> = RTT_RE
        .captures_iter(line)
        .map(|c| HopTiming {
            rtt: c[1].parse().unwrap_or(0.0),
        })
        .collect();

    TracerouteHop {
        resolved_hostname: host_caps.as_ref().map(|c| c[1].to_string()),
        resolved_address: host_caps.map(|c| c[3].to_string()),
        timings,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SUCCESS_OUTPUT: &str = "\
traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets
 1  _gateway (192.168.1.1)  1.234 ms  1.156 ms
 2  10.0.0.1 (10.0.0.1)  5.678 ms  5.432 ms
 3  * * *
 4  1.1.1.1 (1.1.1.1)  8.123 ms  7.956 ms";

    // Fixture where first hop has a real hostname (gets rewritten to _gateway).
    const GATEWAY_HOSTNAME_OUTPUT: &str = "\
traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets
 1  router.home (192.168.1.1)  1.0 ms  1.1 ms
 2  1.1.1.1 (1.1.1.1)  8.0 ms  8.1 ms";

    #[test]
    fn parses_header_and_hops() {
        let r = parse(SUCCESS_OUTPUT);
        assert_eq!(r.status, TracerouteStatus::Finished);
        assert_eq!(r.resolved_address.as_deref(), Some("1.1.1.1"));
        assert_eq!(r.hops.len(), 4);
    }

    #[test]
    fn gateway_first_hop_preserved_as_gateway() {
        let r = parse(GATEWAY_HOSTNAME_OUTPUT);
        // The real hostname is replaced with _gateway in rawOutput.
        assert!(
            r.raw_output.contains("_gateway"),
            "expected _gateway in rawOutput"
        );
        assert!(
            !r.raw_output.contains("router.home"),
            "real hostname should be hidden"
        );
        // The hop itself also has _gateway as hostname.
        assert_eq!(r.hops[0].resolved_hostname.as_deref(), Some("_gateway"));
        assert_eq!(r.hops[0].resolved_address.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn star_hop_has_no_address_and_no_timings() {
        let r = parse(SUCCESS_OUTPUT);
        let star_hop = &r.hops[2]; // " 3  * * *"
        assert_eq!(star_hop.resolved_address, None);
        assert_eq!(star_hop.resolved_hostname, None);
        assert!(star_hop.timings.is_empty());
    }

    #[test]
    fn rtt_values_parsed_correctly() {
        let r = parse(SUCCESS_OUTPUT);
        // hop 1 (index 0): 1.234 ms and 1.156 ms
        assert_eq!(r.hops[0].timings.len(), 2);
        assert!((r.hops[0].timings[0].rtt - 1.234).abs() < 0.001);
        assert!((r.hops[0].timings[1].rtt - 1.156).abs() < 0.001);
    }

    #[test]
    fn resolved_hostname_is_last_hop_hostname() {
        let r = parse(SUCCESS_OUTPUT);
        // Last hop is 1.1.1.1 (1.1.1.1) — hostname is the target itself
        assert_eq!(r.resolved_hostname.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn empty_input_returns_failed() {
        assert_eq!(parse("").status, TracerouteStatus::Failed);
    }

    #[test]
    fn no_header_returns_failed() {
        assert_eq!(
            parse("some garbage\n 1  * * *\n").status,
            TracerouteStatus::Failed
        );
    }

    #[test]
    fn ipv6_target_parsed() {
        let raw = "\
traceroute to 2606:4700:4700::1111 (2606:4700:4700::1111), 20 hops max, 80 byte packets
 1  _gateway (fe80::1)  1.0 ms  1.1 ms
 2  2606:4700:4700::1111 (2606:4700:4700::1111)  9.5 ms  9.3 ms";

        let r = parse(raw);
        assert_eq!(r.status, TracerouteStatus::Finished);
        assert_eq!(r.resolved_address.as_deref(), Some("2606:4700:4700::1111"));
        assert_eq!(r.hops.len(), 2);
        assert_eq!(
            r.hops[1].resolved_address.as_deref(),
            Some("2606:4700:4700::1111")
        );
    }

    #[test]
    fn mixed_star_and_rtt_hops() {
        let raw = "\
traceroute to 8.8.8.8 (8.8.8.8), 20 hops max, 60 byte packets
 1  * 1.234 ms *
 2  8.8.8.8 (8.8.8.8)  5.0 ms  5.1 ms";

        let r = parse(raw);
        // hop 0: mixed — no host match, one RTT
        assert_eq!(r.hops[0].resolved_address, None);
        assert_eq!(r.hops[0].timings.len(), 1);
        assert!((r.hops[0].timings[0].rtt - 1.234).abs() < 0.001);
    }
}
