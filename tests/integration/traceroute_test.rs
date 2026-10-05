use globalping_probe::command::traceroute::parse::{TracerouteStatus, parse};

// ── Fixture-based parser tests ────────────────────────────────────────────────

const SUCCESS_ICMP: &str = "\
traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets
 1  router.home (192.168.1.1)  1.234 ms  0.987 ms
 2  10.20.0.1 (10.20.0.1)  5.678 ms  5.432 ms
 3  * * *
 4  1.1.1.1 (1.1.1.1)  8.123 ms  7.956 ms";

#[test]
fn full_success_parses_address_and_hops() {
    let r = parse(SUCCESS_ICMP);
    assert_eq!(r.status, TracerouteStatus::Finished);
    assert_eq!(r.resolved_address.as_deref(), Some("1.1.1.1"));
    assert_eq!(r.hops.len(), 4);
}

#[test]
fn gateway_hostname_rewritten_in_raw_output() {
    let r = parse(SUCCESS_ICMP);
    assert!(
        r.raw_output.contains("_gateway"),
        "expected _gateway in rawOutput"
    );
    assert!(
        !r.raw_output.contains("router.home"),
        "real gateway hostname must be hidden"
    );
    assert_eq!(r.hops[0].resolved_hostname.as_deref(), Some("_gateway"));
    assert_eq!(r.hops[0].resolved_address.as_deref(), Some("192.168.1.1"));
}

#[test]
fn star_hop_produces_null_address_and_empty_timings() {
    let r = parse(SUCCESS_ICMP);
    let star = &r.hops[2];
    assert_eq!(star.resolved_address, None);
    assert_eq!(star.resolved_hostname, None);
    assert!(star.timings.is_empty());
}

#[test]
fn rtt_values_correct() {
    let r = parse(SUCCESS_ICMP);
    assert_eq!(r.hops[0].timings.len(), 2);
    assert!((r.hops[0].timings[0].rtt - 1.234).abs() < 0.001);
    assert!((r.hops[0].timings[1].rtt - 0.987).abs() < 0.001);
    assert_eq!(r.hops[1].timings.len(), 2);
    assert_eq!(r.hops[3].timings.len(), 2);
}

#[test]
fn resolved_hostname_is_last_real_hop() {
    let r = parse(SUCCESS_ICMP);
    // last hop hostname = "1.1.1.1" (traceroute shows IP when no rDNS)
    assert_eq!(r.resolved_hostname.as_deref(), Some("1.1.1.1"));
}

#[test]
fn empty_input_fails() {
    assert_eq!(parse("").status, TracerouteStatus::Failed);
}

#[test]
fn no_header_fails() {
    assert_eq!(
        parse("garbage\n 1  * * *\n").status,
        TracerouteStatus::Failed
    );
}

#[test]
fn all_star_hops_resolved_hostname_is_none() {
    let raw = "\
traceroute to 8.8.8.8 (8.8.8.8), 20 hops max, 60 byte packets
 1  * * *
 2  * * *";
    let r = parse(raw);
    assert_eq!(r.status, TracerouteStatus::Finished);
    assert_eq!(r.resolved_address.as_deref(), Some("8.8.8.8"));
    assert_eq!(r.resolved_hostname, None);
}

#[test]
fn ipv6_header_parsed() {
    let raw = "\
traceroute to 2606:4700:4700::1111 (2606:4700:4700::1111), 20 hops max, 80 byte packets
 1  _gateway (fe80::1)  1.0 ms  1.1 ms
 2  2606:4700:4700::1111 (2606:4700:4700::1111)  9.5 ms  9.3 ms";
    let r = parse(raw);
    assert_eq!(r.resolved_address.as_deref(), Some("2606:4700:4700::1111"));
    assert_eq!(r.hops.len(), 2);
    assert_eq!(
        r.hops[1].resolved_address.as_deref(),
        Some("2606:4700:4700::1111")
    );
}

#[test]
fn mixed_star_and_rtt_in_same_hop() {
    let raw = "\
traceroute to 8.8.8.8 (8.8.8.8), 20 hops max, 60 byte packets
 1  * 1.234 ms *
 2  8.8.8.8 (8.8.8.8)  5.0 ms  5.1 ms";
    let r = parse(raw);
    assert_eq!(r.hops[0].timings.len(), 1);
    assert!((r.hops[0].timings[0].rtt - 1.234).abs() < 0.001);
    assert_eq!(r.hops[0].resolved_address, None);
}

// ── Live process tests (Linux only) ──────────────────────────────────────────

#[cfg(target_os = "linux")]
mod live {
    use globalping_probe::command::traceroute::{parse::TracerouteStatus, run_trace};

    #[tokio::test]
    async fn live_icmp_ipv4_cloudflare() {
        let r = run_trace("1.1.1.1", "ICMP", 4)
            .await
            .expect("traceroute command failed to spawn");

        // ICMP traceroute requires NET_RAW (root or cap). Skip gracefully when not privileged.
        if r.status == TracerouteStatus::Failed && r.raw_output.to_lowercase().contains("privilege")
        {
            println!("ICMP traceroute requires elevated privileges — skipping assertions");
            return;
        }

        assert_eq!(
            r.status,
            TracerouteStatus::Finished,
            "raw:\n{}",
            r.raw_output
        );
        assert_eq!(r.resolved_address.as_deref(), Some("1.1.1.1"));
        assert!(!r.hops.is_empty(), "should have at least one hop");

        let total_timings: usize = r.hops.iter().map(|h| h.timings.len()).sum();
        assert!(
            total_timings > 0,
            "should have at least one RTT measurement"
        );

        println!(
            "ICMP trace 1.1.1.1: {} hops, {} RTT measurements",
            r.hops.len(),
            total_timings
        );
        for (i, hop) in r.hops.iter().enumerate() {
            let rtts: Vec<String> = hop
                .timings
                .iter()
                .map(|t| format!("{:.1}ms", t.rtt))
                .collect();
            println!(
                "  hop {:2}: addr={:?} host={:?} rtts=[{}]",
                i + 1,
                hop.resolved_address,
                hop.resolved_hostname,
                rtts.join(", ")
            );
        }
    }

    #[tokio::test]
    async fn live_udp_ipv4_google_dns() {
        let r = run_trace("8.8.8.8", "UDP", 4)
            .await
            .expect("traceroute failed");

        assert_eq!(
            r.status,
            TracerouteStatus::Finished,
            "raw:\n{}",
            r.raw_output
        );
        assert!(!r.hops.is_empty());
        println!("UDP trace 8.8.8.8: {} hops", r.hops.len());
    }

    #[tokio::test]
    async fn live_private_ip_rejected() {
        let result = run_trace("10.0.0.1", "ICMP", 4)
            .await
            .expect("private IP should produce a structured failure");
        assert_eq!(result.status, TracerouteStatus::Failed);
        assert_eq!(result.failure_source.as_deref(), Some("target"));
        assert_eq!(result.raw_output, "Private IP ranges are not allowed.");
    }

    #[tokio::test]
    async fn live_gateway_hostname_hidden_in_raw() {
        let r = run_trace("1.1.1.1", "ICMP", 4)
            .await
            .expect("traceroute failed");

        // rawOutput must have _gateway for the first hop, not the real hostname.
        if r.hops.len() > 0 && r.hops[0].resolved_address.is_some() {
            assert!(
                r.raw_output
                    .lines()
                    .nth(1)
                    .unwrap_or("")
                    .contains("_gateway"),
                "first hop line should contain _gateway, got: {}",
                r.raw_output.lines().nth(1).unwrap_or("")
            );
        }
    }
}
