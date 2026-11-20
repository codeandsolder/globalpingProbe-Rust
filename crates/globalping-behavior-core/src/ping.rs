use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::net::IpAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PingStatus {
    Finished,
    Failed,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PingTiming {
    pub rtt: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct PingStats {
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub avg: Option<f64>,
    pub total: Option<u32>,
    pub loss: Option<f64>,
    pub rcv: Option<u32>,
    pub drop: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ParsedPing {
    pub status: PingStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_source: Option<String>,
    pub raw_output: String,
    pub resolved_address: Option<String>,
    pub resolved_hostname: Option<String>,
    pub timings: Vec<PingTiming>,
    pub stats: PingStats,
}

fn parse_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.split_once(marker).map(|(_, tail)| tail)
}

fn parse_number_prefix<T: core::str::FromStr>(text: &str) -> Option<T> {
    let token = text
        .trim_start()
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .next()?;
    if token.is_empty() {
        return None;
    }
    token.parse().ok()
}

fn header_address(raw: &str) -> Option<String> {
    let header = raw.lines().next()?;
    for (open, _) in header.match_indices('(').rev() {
        let tail = &header[open + 1..];
        let Some(close) = tail.find(')') else {
            continue;
        };
        let value = &tail[..close];
        if let Ok(address) = value.parse::<IpAddr>() {
            return Some(address.to_string());
        }
    }
    None
}

#[cfg(feature = "ping-standalone")]
fn reply_hostname(lines: &[&str]) -> String {
    lines
        .get(1)
        .and_then(|line| line.split_once("from ").map(|(_, tail)| tail))
        .and_then(|tail| {
            tail.split_once(" (")
                .map(|(hostname, _)| hostname)
                .or_else(|| tail.split_once(": ").map(|(hostname, _)| hostname))
        })
        .unwrap_or_default()
        .to_string()
}

#[must_use]
pub fn normalize_ping_output(raw: &str, address: &str, hostname: &str) -> String {
    if address == hostname {
        return raw.to_string();
    }

    raw.lines()
        .map(|line| {
            let numeric_header = format!("PING {address} ({address})");
            if line.starts_with(&numeric_header) {
                line.replacen(&numeric_header, &format!("PING {hostname} ({address})"), 1)
            } else {
                let bytes_from = format!(" bytes from {address}:");
                let from_prefix = format!("From {address} ");
                if line.contains(&bytes_from) {
                    line.replacen(
                        &bytes_from,
                        &format!(" bytes from {hostname} ({address}):"),
                        1,
                    )
                } else if line.starts_with(&from_prefix) {
                    line.replacen(&from_prefix, &format!("From {hostname} ({address}) "), 1)
                } else if line == format!("--- {address} ping statistics ---") {
                    format!("--- {hostname} ping statistics ---")
                } else {
                    line.to_string()
                }
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_timing(line: &str) -> Option<PingTiming> {
    let rtt = parse_after(line, "time=").and_then(parse_number_prefix::<f64>)?;
    let ttl = parse_after(line, "ttl=").and_then(parse_number_prefix::<u32>);
    Some(PingTiming { rtt, ttl })
}

fn parse_stats(raw: &str) -> PingStats {
    let mut stats = PingStats::default();
    for line in raw.lines() {
        if line.contains("packets transmitted") {
            stats.total = parse_number_prefix(line);
            if let Some((_, tail)) = line.split_once(',') {
                stats.rcv = parse_number_prefix(tail);
            }
            stats.loss = line
                .split(',')
                .find(|part| part.contains("packet loss"))
                .and_then(|part| part.split('%').next())
                .and_then(|part| part.split_whitespace().last())
                .and_then(|value| value.parse().ok());
            stats.drop = match (stats.total, stats.rcv) {
                (Some(total), Some(received)) => Some(total.saturating_sub(received)),
                _ => None,
            };
        } else if line.contains("min/avg/max")
            && let Some((_, values)) = line.split_once('=')
        {
            let mut numbers = values.trim().split('/').filter_map(|value| {
                value
                    .split_whitespace()
                    .next()
                    .and_then(|number| number.parse::<f64>().ok())
            });
            stats.min = numbers.next();
            stats.avg = numbers.next();
            stats.max = numbers.next();
        }
    }
    stats
}

#[must_use]
pub fn failed_ping(failure_source: impl Into<String>, raw_output: impl Into<String>) -> ParsedPing {
    ParsedPing {
        status: PingStatus::Failed,
        failure_source: Some(failure_source.into()),
        raw_output: raw_output.into(),
        resolved_address: None,
        resolved_hostname: None,
        timings: Vec::new(),
        stats: PingStats::default(),
    }
}

#[cfg(feature = "ping-standalone")]
#[must_use]
pub fn parse(raw_output: &str) -> ParsedPing {
    let lines = raw_output.lines().collect::<Vec<_>>();
    let Some(resolved_address) = header_address(raw_output) else {
        return ParsedPing {
            status: PingStatus::Failed,
            failure_source: None,
            raw_output: raw_output.to_string(),
            resolved_address: None,
            resolved_hostname: None,
            timings: Vec::new(),
            stats: PingStats::default(),
        };
    };

    let timings = lines
        .iter()
        .skip(1)
        .filter_map(|line| parse_timing(line))
        .collect::<Vec<_>>();
    let stats = parse_stats(raw_output);

    ParsedPing {
        status: PingStatus::Finished,
        failure_source: None,
        raw_output: raw_output.trim_end_matches('\n').to_string(),
        resolved_address: Some(resolved_address),
        resolved_hostname: Some(reply_hostname(&lines)),
        timings,
        stats,
    }
}

#[must_use]
pub fn shape_ping_output(
    raw_output: &str,
    address: &str,
    hostname: &str,
    timed_out: bool,
) -> ParsedPing {
    let normalized = normalize_ping_output(raw_output, address, hostname);
    let timings = normalized
        .lines()
        .filter_map(parse_timing)
        .collect::<Vec<_>>();
    let stats = parse_stats(&normalized);
    let parsed = !normalized.is_empty() && header_address(&normalized).is_some();
    let failure_source = if timed_out {
        Some(
            if timings.is_empty()
                && (normalized.contains("no answer yet for ")
                    || normalized.contains("100% packet loss"))
            {
                "target"
            } else {
                "internal"
            }
            .to_string(),
        )
    } else if !parsed {
        Some("internal".to_string())
    } else {
        None
    };

    ParsedPing {
        status: if failure_source.is_some() {
            PingStatus::Failed
        } else {
            PingStatus::Finished
        },
        failure_source,
        raw_output: normalized.trim_end_matches('\n').to_string(),
        resolved_address: Some(address.to_string()),
        resolved_hostname: Some(hostname.to_string()),
        timings,
        stats,
    }
}
#[cfg(all(test, feature = "ping-standalone"))]
mod tests {
    use super::*;

    const SUCCESS: &str = "PING google.com (172.217.20.206) 56(84) bytes of data.\n\
64 bytes from lhr25s33-in-f14.1e100.net (172.217.20.206): icmp_seq=1 ttl=37 time=7.99 ms\n\
64 bytes from lhr25s33-in-f14.1e100.net (172.217.20.206): icmp_seq=2 ttl=37 time=8.12 ms\n\
64 bytes from lhr25s33-in-f14.1e100.net (172.217.20.206): icmp_seq=3 ttl=37 time=7.95 ms\n\
\n\
--- google.com ping statistics ---\n\
3 packets transmitted, 3 received, 0% packet loss, time 404ms\n\
rtt min/avg/max/mdev = 7.948/8.018/8.120/0.073 ms\n";

    const NO_DOMAIN: &str = "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n\
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=41.7 ms\n\
64 bytes from 1.1.1.1: icmp_seq=2 ttl=58 time=41.7 ms\n\
64 bytes from 1.1.1.1: icmp_seq=3 ttl=58 time=41.7 ms\n\
\n\
--- 1.1.1.1 ping statistics ---\n\
3 packets transmitted, 3 received, 0% packet loss, time 1003ms\n\
rtt min/avg/max/mdev = 41.666/41.689/41.706/0.017 ms\n";

    const IPV6: &str = "PING google.com(hem08s10-in-x0e.1e100.net (2a00:1450:4026:808::200e)) 56 data bytes\n\
64 bytes from hem08s10-in-x0e.1e100.net (2a00:1450:4026:808::200e): icmp_seq=1 ttl=57 time=1.47 ms\n\
64 bytes from hem08s10-in-x0e.1e100.net (2a00:1450:4026:808::200e): icmp_seq=2 ttl=57 time=1.14 ms\n\
64 bytes from hem08s10-in-x0e.1e100.net (2a00:1450:4026:808::200e): icmp_seq=3 ttl=57 time=1.07 ms\n\
\n\
--- google.com ping statistics ---\n\
3 packets transmitted, 3 received, 0% packet loss, time 1003ms\n\
rtt min/avg/max/mdev = 1.072/1.224/1.466/0.172 ms\n";

    const PACKET_LOSS: &str = "PING google.com (172.217.20.206) 56(84) bytes of data.\n\
64 bytes from lhr25s33-in-f14.1e100.net (172.217.20.206): icmp_seq=1 ttl=37 time=8.05 ms\n\
no answer yet for icmp_seq=2\n\
64 bytes from lhr25s33-in-f14.1e100.net (172.217.20.206): icmp_seq=3 ttl=37 time=8.05 ms\n\
\n\
--- google.com ping statistics ---\n\
3 packets transmitted, 2 received, 33.3% packet loss, time 404ms\n\
rtt min/avg/max/mdev = 8.053/8.053/8.053/0.000 ms\n";

    const TIMEOUT: &str = "PING 123.21.43.124 (123.21.43.124) 56(84) bytes of data.\n\
no answer yet for icmp_seq=1\n\
\n\
--- 123.21.43.124 ping statistics ---\n\
1 packets transmitted, 0 received, 100% packet loss, time 2909ms\n";

    const UNREACHABLE: &str = "PING  (104.18.186.31) 56(84) bytes of data.\n\
From eth2-1109-fsn-lf-e03.productsup.int (10.254.254.17) icmp_seq=1 Destination Port Unreachable\n\
\n\
---  ping statistics ---\n\
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms\n";

    #[test]
    fn parses_standard_success() {
        let r = parse(SUCCESS);
        assert_eq!(r.status, PingStatus::Finished);
        assert_eq!(r.resolved_address.as_deref(), Some("172.217.20.206"));
        assert_eq!(
            r.resolved_hostname.as_deref(),
            Some("lhr25s33-in-f14.1e100.net")
        );
        assert_eq!(r.timings.len(), 3);
        assert_eq!(
            r.timings[0],
            PingTiming {
                rtt: 7.99,
                ttl: Some(37)
            }
        );
        assert_eq!(
            r.timings[1],
            PingTiming {
                rtt: 8.12,
                ttl: Some(37)
            }
        );
        assert_eq!(
            r.timings[2],
            PingTiming {
                rtt: 7.95,
                ttl: Some(37)
            }
        );
        assert_eq!(r.stats.min, Some(7.948));
        assert_eq!(r.stats.avg, Some(8.018));
        assert_eq!(r.stats.max, Some(8.120));
        assert_eq!(r.stats.total, Some(3));
        assert_eq!(r.stats.rcv, Some(3));
        assert_eq!(r.stats.drop, Some(0));
        assert_eq!(r.stats.loss, Some(0.0));
    }

    #[test]
    fn parses_tcp_synthetic_output() {
        let raw = "PING one.one.one.one (1.1.1.1) on port 443.\n\
Reply from one.one.one.one (1.1.1.1) on port 443: tcp_conn=1 time=12.34 ms\n\
No reply from one.one.one.one (1.1.1.1) on port 443: tcp_conn=2\n\
Reply from one.one.one.one (1.1.1.1) on port 443: tcp_conn=3 time=13 ms\n\
\n\
--- one.one.one.one (1.1.1.1) ping statistics ---\n\
3 packets transmitted, 2 received, 33.33% packet loss, time 1000 ms\n\
rtt min/avg/max/mdev = 12.340/12.670/13.000/0.330 ms";
        let parsed = parse(raw);
        assert_eq!(parsed.status, PingStatus::Finished);
        assert_eq!(parsed.resolved_address.as_deref(), Some("1.1.1.1"));
        assert_eq!(parsed.resolved_hostname.as_deref(), Some("one.one.one.one"));
        assert_eq!(parsed.timings.len(), 2);
        assert_eq!(
            parsed.timings[0],
            PingTiming {
                rtt: 12.34,
                ttl: None
            }
        );
        assert_eq!(
            parsed.timings[1],
            PingTiming {
                rtt: 13.0,
                ttl: None
            }
        );
        assert_eq!(parsed.stats.total, Some(3));
        assert_eq!(parsed.stats.rcv, Some(2));
        assert_eq!(parsed.stats.drop, Some(1));
        assert_eq!(parsed.stats.loss, Some(33.33));
        assert_eq!(parsed.stats.min, Some(12.34));
        assert_eq!(parsed.stats.avg, Some(12.67));
        assert_eq!(parsed.stats.max, Some(13.0));
    }

    #[test]
    fn parses_no_domain_target() {
        let r = parse(NO_DOMAIN);
        assert_eq!(r.status, PingStatus::Finished);
        assert_eq!(r.resolved_address.as_deref(), Some("1.1.1.1"));
        // When target is IP, hostname is the IP itself
        assert_eq!(r.resolved_hostname.as_deref(), Some("1.1.1.1"));
        assert_eq!(r.timings.len(), 3);
        assert_eq!(r.stats.total, Some(3));
    }

    #[test]
    fn parses_ipv6_header() {
        let r = parse(IPV6);
        assert_eq!(r.status, PingStatus::Finished);
        assert_eq!(
            r.resolved_address.as_deref(),
            Some("2a00:1450:4026:808::200e")
        );
        assert_eq!(
            r.resolved_hostname.as_deref(),
            Some("hem08s10-in-x0e.1e100.net")
        );
        assert_eq!(r.timings.len(), 3);
        assert_eq!(r.timings[0].rtt, 1.47);
        assert_eq!(r.stats.min, Some(1.072));
    }

    #[test]
    fn parses_packet_loss() {
        let r = parse(PACKET_LOSS);
        assert_eq!(r.status, PingStatus::Finished);
        assert_eq!(r.timings.len(), 2); // only successful packets produce timings
        assert_eq!(r.stats.total, Some(3));
        assert_eq!(r.stats.rcv, Some(2));
        assert_eq!(r.stats.drop, Some(1));
        assert_eq!(r.stats.loss, Some(33.3));
    }

    #[test]
    fn parses_full_timeout_no_rtt() {
        let r = parse(TIMEOUT);
        assert_eq!(r.status, PingStatus::Finished);
        assert_eq!(r.timings.len(), 0);
        assert_eq!(r.stats.total, Some(1));
        assert_eq!(r.stats.rcv, Some(0));
        assert_eq!(r.stats.loss, Some(100.0));
        assert_eq!(r.stats.min, None); // no RTT line when 0 received
        assert_eq!(r.stats.avg, None);
    }

    #[test]
    fn parses_unreachable_no_hostname() {
        let r = parse(UNREACHABLE);
        assert_eq!(r.status, PingStatus::Finished);
        assert_eq!(r.resolved_address.as_deref(), Some("104.18.186.31"));
        assert_eq!(r.timings.len(), 0);
        assert_eq!(r.stats.total, Some(1));
        assert_eq!(r.stats.rcv, Some(0));
        assert_eq!(r.stats.loss, Some(100.0));
    }

    #[test]
    fn returns_failed_on_empty_input() {
        let r = parse("");
        assert_eq!(r.status, PingStatus::Failed);
        assert!(r.timings.is_empty());
    }

    #[test]
    fn returns_failed_on_no_header() {
        let r = parse("some random output\nwithout a ping header\n");
        assert_eq!(r.status, PingStatus::Failed);
    }

    #[test]
    fn raw_output_strips_trailing_newline() {
        let r = parse(SUCCESS);
        assert!(!r.raw_output.ends_with('\n'));
    }
}
