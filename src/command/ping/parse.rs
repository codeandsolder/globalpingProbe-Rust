use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

// ── Output types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PingStatus {
    Finished,
    Failed,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PingTiming {
    pub rtt: f64,
    pub ttl: u32,
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
    pub raw_output: String,
    pub resolved_address: Option<String>,
    pub resolved_hostname: Option<String>,
    pub timings: Vec<PingTiming>,
    pub stats: PingStats,
}

// ── Regex patterns (compiled once) ──────────────────────────────────────────

fn compile_regex(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

// Matches: PING <host> (<addr>)   or   PING <host>(<ipv6-host> (<addr>))
static HEADER_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"^PING\s([^()\s]*?)\s?\((?:[^()\s]+\s?\()?([^()\s]+?)\)"));

// Matches:  64 bytes from <host> [(<ip>)]: [icmp_]seq=N ttl=T time=X ms
static PACKET_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile_regex(
        r"^\d+ bytes from (.*?)(?:\s\([^)]*\))?: (?:icmp_)?seq=\d+ ttl=(\d+) time=(\d*(?:\.\d+)?) ms",
    )
});

// Captures the hostname from the first reply line: "from <host> (" or "from <host>: "
static HOSTNAME_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"from\s(.*?)(?:\s\(|:\s)"));

static STATS_HEADER_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"^---\s.*\sstatistics ---"));

// rtt min/avg/max/mdev = X/Y/Z/W ms   or   round-trip min/avg/max = X/Y/Z ms
static RTT_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile_regex(r"^(?:round-trip|rtt)\s.*\s=\s(\d*(?:\.\d+)?)\/(\d*(?:\.\d+)?)\/(\d*(?:\.\d+)?)")
});

static TRANSMITTED_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"\b(\d+)\spackets\stransmitted"));

static RCV_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"\b(\d+)\s(?:received|packets received)"));

static LOSS_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"\b(\d*(?:\.\d+)?)%\spacket\sloss"));

// ── Public API ───────────────────────────────────────────────────────────────

pub fn parse(raw_output: &str) -> ParsedPing {
    let lines: Vec<&str> = raw_output.lines().collect();

    let failed = |raw: &str| ParsedPing {
        status: PingStatus::Failed,
        raw_output: raw.to_string(),
        resolved_address: None,
        resolved_hostname: None,
        timings: vec![],
        stats: PingStats::default(),
    };

    if raw_output.is_empty() || lines.is_empty() {
        return failed(raw_output);
    }

    let Some(header_caps) = HEADER_RE.as_ref().and_then(|re| re.captures(lines[0])) else {
        return failed(raw_output);
    };

    let resolved_address = header_caps.get(2).map(|m| m.as_str().to_string());

    // Hostname comes from the first reply line, not the header
    let resolved_hostname = lines
        .get(1)
        .and_then(|line| HOSTNAME_RE.as_ref().and_then(|re| re.captures(line)))
        .and_then(|captures| captures.get(1))
        .map_or_else(String::new, |matched| matched.as_str().to_string());

    let timings: Vec<PingTiming> = lines
        .iter()
        .skip(1)
        .filter_map(|l| parse_packet_line(l))
        .collect();

    let stats_idx = lines
        .iter()
        .position(|l| STATS_HEADER_RE.as_ref().is_some_and(|re| re.is_match(l)));
    let stats = stats_idx.map_or_else(PingStats::default, |i| parse_summary(&lines[i + 1..]));

    ParsedPing {
        status: PingStatus::Finished,
        raw_output: raw_output.trim_end_matches('\n').to_string(),
        resolved_address,
        resolved_hostname: Some(resolved_hostname),
        timings,
        stats,
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn parse_packet_line(line: &str) -> Option<PingTiming> {
    let caps = PACKET_RE.as_ref()?.captures(line)?;
    let ttl = caps.get(2)?.as_str().parse::<u32>().ok()?;
    let rtt = caps.get(3)?.as_str().parse::<f64>().ok()?;
    Some(PingTiming { rtt, ttl })
}

fn parse_summary(lines: &[&str]) -> PingStats {
    let mut stats = PingStats::default();

    if let Some(&packets_line) = lines.first() {
        stats.total = TRANSMITTED_RE
            .as_ref()
            .and_then(|re| re.captures(packets_line))
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok());

        stats.rcv = RCV_RE
            .as_ref()
            .and_then(|re| re.captures(packets_line))
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok());

        stats.loss = LOSS_RE
            .as_ref()
            .and_then(|re| re.captures(packets_line))
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok());

        stats.drop = match (stats.total, stats.rcv) {
            (Some(t), Some(r)) => Some(t.saturating_sub(r)),
            _ => None,
        };
    }

    if let Some(&rtt_line) = lines.get(1)
        && let Some(caps) = RTT_RE.as_ref().and_then(|re| re.captures(rtt_line))
    {
        stats.min = caps.get(1).and_then(|m| m.as_str().parse().ok());
        // Order in the string: min/avg/max/mdev — we capture min(1), avg(2), max(3)
        stats.avg = caps.get(2).and_then(|m| m.as_str().parse().ok());
        stats.max = caps.get(3).and_then(|m| m.as_str().parse().ok());
    }

    stats
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
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
        assert_eq!(r.timings[0], PingTiming { rtt: 7.99, ttl: 37 });
        assert_eq!(r.timings[1], PingTiming { rtt: 8.12, ttl: 37 });
        assert_eq!(r.timings[2], PingTiming { rtt: 7.95, ttl: 37 });
        assert_eq!(r.stats.min, Some(7.948));
        assert_eq!(r.stats.avg, Some(8.018));
        assert_eq!(r.stats.max, Some(8.120));
        assert_eq!(r.stats.total, Some(3));
        assert_eq!(r.stats.rcv, Some(3));
        assert_eq!(r.stats.drop, Some(0));
        assert_eq!(r.stats.loss, Some(0.0));
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
