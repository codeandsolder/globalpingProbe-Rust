// Integration tests for PingCommand and ping parser

use globalping_probe::command::ping::parse::{PingStatus, parse};

// ── Parser integration tests (fixture strings, no real process) ──────────────

#[test]
fn full_success_round_trip() {
    let raw = "PING google.com (172.217.20.206) 56(84) bytes of data.\n\
64 bytes from lhr25s33-in-f14.1e100.net (172.217.20.206): icmp_seq=1 ttl=37 time=7.99 ms\n\
64 bytes from lhr25s33-in-f14.1e100.net (172.217.20.206): icmp_seq=2 ttl=37 time=8.12 ms\n\
64 bytes from lhr25s33-in-f14.1e100.net (172.217.20.206): icmp_seq=3 ttl=37 time=7.95 ms\n\
\n\
--- google.com ping statistics ---\n\
3 packets transmitted, 3 received, 0% packet loss, time 404ms\n\
rtt min/avg/max/mdev = 7.948/8.018/8.120/0.073 ms\n";

    let r = parse(raw);
    assert_eq!(r.status, PingStatus::Finished);
    assert_eq!(r.resolved_address.as_deref(), Some("172.217.20.206"));
    assert_eq!(
        r.resolved_hostname.as_deref(),
        Some("lhr25s33-in-f14.1e100.net")
    );
    assert_eq!(r.timings.len(), 3);
    assert_eq!(r.stats.min, Some(7.948));
    assert_eq!(r.stats.avg, Some(8.018));
    assert_eq!(r.stats.max, Some(8.120));
    assert_eq!(r.stats.total, Some(3));
    assert_eq!(r.stats.rcv, Some(3));
    assert_eq!(r.stats.drop, Some(0));
    assert_eq!(r.stats.loss, Some(0.0));
}

#[test]
fn ipv6_success_round_trip() {
    let raw = "PING google.com(hem08s10-in-x0e.1e100.net (2a00:1450:4026:808::200e)) 56 data bytes\n\
64 bytes from hem08s10-in-x0e.1e100.net (2a00:1450:4026:808::200e): icmp_seq=1 ttl=57 time=1.47 ms\n\
64 bytes from hem08s10-in-x0e.1e100.net (2a00:1450:4026:808::200e): icmp_seq=2 ttl=57 time=1.14 ms\n\
64 bytes from hem08s10-in-x0e.1e100.net (2a00:1450:4026:808::200e): icmp_seq=3 ttl=57 time=1.07 ms\n\
\n\
--- google.com ping statistics ---\n\
3 packets transmitted, 3 received, 0% packet loss, time 1003ms\n\
rtt min/avg/max/mdev = 1.072/1.224/1.466/0.172 ms\n";

    let r = parse(raw);
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
    assert_eq!(r.stats.min, Some(1.072));
}

#[test]
fn packet_loss_partial() {
    let raw = "PING google.com (172.217.20.206) 56(84) bytes of data.\n\
64 bytes from lhr25s33-in-f14.1e100.net (172.217.20.206): icmp_seq=1 ttl=37 time=8.05 ms\n\
no answer yet for icmp_seq=2\n\
64 bytes from lhr25s33-in-f14.1e100.net (172.217.20.206): icmp_seq=3 ttl=37 time=8.05 ms\n\
\n\
--- google.com ping statistics ---\n\
3 packets transmitted, 2 received, 33.3% packet loss, time 404ms\n\
rtt min/avg/max/mdev = 8.053/8.053/8.053/0.000 ms\n";

    let r = parse(raw);
    assert_eq!(r.timings.len(), 2);
    assert_eq!(r.stats.total, Some(3));
    assert_eq!(r.stats.rcv, Some(2));
    assert_eq!(r.stats.drop, Some(1));
    assert_eq!(r.stats.loss, Some(33.3));
}

#[test]
fn full_timeout_zero_rtt() {
    let raw = "PING 123.21.43.124 (123.21.43.124) 56(84) bytes of data.\n\
no answer yet for icmp_seq=1\n\
\n\
--- 123.21.43.124 ping statistics ---\n\
1 packets transmitted, 0 received, 100% packet loss, time 2909ms\n";

    let r = parse(raw);
    assert_eq!(r.status, PingStatus::Finished);
    assert_eq!(r.timings.len(), 0);
    assert_eq!(r.stats.total, Some(1));
    assert_eq!(r.stats.rcv, Some(0));
    assert_eq!(r.stats.loss, Some(100.0));
    assert_eq!(r.stats.min, None);
}

#[test]
fn empty_and_no_header_return_failed() {
    assert_eq!(parse("").status, PingStatus::Failed);
    assert_eq!(parse("not a ping header\n").status, PingStatus::Failed);
}

// ── Live process tests (Linux only — requires NET_RAW capability) ─────────────

#[cfg(target_os = "linux")]
mod live {
    use globalping_probe::command::ping::PingCommand;
    use globalping_probe::command::ping::parse::PingStatus;

    async fn run_ping(target: &str, ip_version: u8) -> serde_json::Value {
        let opts = serde_json::json!({
            "target": target,
            "packets": 3,
            "ipVersion": ip_version,
            "protocol": "ICMP",
            "inProgressUpdates": false,
        });
        PingCommand.run(opts).await.expect("ping command failed")
    }

    #[tokio::test]
    async fn live_ipv4_cloudflare_dns() {
        let result = run_ping("1.1.1.1", 4).await;
        let parsed: globalping_probe::command::ping::parse::ParsedPing =
            serde_json::from_value(result).unwrap();

        assert_eq!(
            parsed.status,
            PingStatus::Finished,
            "status should be finished"
        );
        assert_eq!(parsed.resolved_address.as_deref(), Some("1.1.1.1"));
        assert!(
            !parsed.timings.is_empty(),
            "should have at least one timing"
        );
        assert!(parsed.timings[0].rtt > 0.0, "RTT should be positive");
        assert!(parsed.timings[0].ttl > 0, "TTL should be positive");
        assert_eq!(parsed.stats.total, Some(3));
        assert!(parsed.stats.min.is_some(), "min RTT should be present");
        assert!(parsed.stats.avg.is_some(), "avg RTT should be present");
        assert!(parsed.stats.max.is_some(), "max RTT should be present");

        println!(
            "IPv4 1.1.1.1 — RTT min/avg/max = {:.3}/{:.3}/{:.3} ms, loss = {}%",
            parsed.stats.min.unwrap(),
            parsed.stats.avg.unwrap(),
            parsed.stats.max.unwrap(),
            parsed.stats.loss.unwrap_or(0.0),
        );
    }

    #[tokio::test]
    async fn live_ipv6_cloudflare_dns() {
        let result = run_ping("2606:4700:4700::1111", 6).await;
        let parsed: globalping_probe::command::ping::parse::ParsedPing =
            serde_json::from_value(result).unwrap();

        // Some environments block ICMPv6, or parallel test load causes packet loss.
        // Skip assertions rather than hard-fail when IPv6 is not reachable.
        let has_successful_rtt = parsed.timings.iter().any(|t| t.rtt > 0.0);
        if parsed.status == PingStatus::Failed || !has_successful_rtt {
            println!("IPv6 ICMP not reachable (blocked or all packets lost) — skipping assertions");
            return;
        }

        assert_eq!(
            parsed.resolved_address.as_deref(),
            Some("2606:4700:4700::1111")
        );
        assert!(
            !parsed.timings.is_empty(),
            "should have at least one timing"
        );
        assert!(parsed.timings[0].rtt > 0.0, "RTT should be positive");
        assert_eq!(parsed.stats.total, Some(3));
        assert!(parsed.stats.min.is_some());

        println!(
            "IPv6 2606:4700:4700::1111 — RTT min/avg/max = {:.3}/{:.3}/{:.3} ms",
            parsed.stats.min.unwrap(),
            parsed.stats.avg.unwrap(),
            parsed.stats.max.unwrap(),
        );
    }

    #[tokio::test]
    async fn live_private_ip_rejected_at_validation() {
        let opts = serde_json::json!({
            "target": "10.0.0.1",
            "packets": 1,
            "ipVersion": 4,
            "protocol": "ICMP",
            "inProgressUpdates": false,
        });
        let err = PingCommand.run(opts).await.unwrap_err();
        assert!(err.to_string().contains("Private IP"), "got: {err}");
    }
}
