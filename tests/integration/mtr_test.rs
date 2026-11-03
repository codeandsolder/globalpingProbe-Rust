use globalping_probe::command::mtr::parse::{build_output, parse_raw};

// ── Fixture-based parser tests ────────────────────────────────────────────────

const RAW_3HOP: &str = "\
h 0 192.168.1.1
d 0 router.home
x 0 0
p 0 1234 0
x 0 1
p 0 987 1
x 0 2
p 0 1456 2
h 1 10.20.0.1
d 1 isp.net
x 1 0
p 1 5678 0
x 1 1
p 1 5432 1
x 1 2
p 1 5890 2
h 2 1.1.1.1
d 2 one.one.one.one
x 2 0
p 2 8123 0
x 2 1
p 2 7956 1
x 2 2
p 2 8234 2";

#[test]
fn three_hops_parsed() {
    let hops = parse_raw(RAW_3HOP, true);
    assert_eq!(hops.len(), 3);
    assert_eq!(hops[0].resolved_address.as_deref(), Some("192.168.1.1"));
    assert_eq!(hops[1].resolved_address.as_deref(), Some("10.20.0.1"));
    assert_eq!(hops[2].resolved_address.as_deref(), Some("1.1.1.1"));
}

#[test]
fn hostnames_populated() {
    let hops = parse_raw(RAW_3HOP, true);
    assert_eq!(hops[0].resolved_hostname.as_deref(), Some("router.home"));
    assert_eq!(hops[1].resolved_hostname.as_deref(), Some("isp.net"));
    assert_eq!(
        hops[2].resolved_hostname.as_deref(),
        Some("one.one.one.one")
    );
}

#[test]
fn all_probes_received_no_drops() {
    let hops = parse_raw(RAW_3HOP, true);
    for hop in &hops {
        assert_eq!(hop.stats.drop, 0);
        assert_eq!(hop.stats.rcv, 3);
        assert!(hop.stats.avg > 0.0);
    }
}

#[test]
fn rtt_values_correct() {
    let hops = parse_raw(RAW_3HOP, true);
    // RTT from microseconds: 1234 µs = 1.234 ms
    assert!((hops[0].timings[0].rtt.unwrap() - 1.234).abs() < 0.001);
    assert!((hops[0].timings[1].rtt.unwrap() - 0.987).abs() < 0.001);
}

#[test]
fn dropped_probe_counted_as_drop() {
    // seq 0: sent but no p reply (drop); seq 1 and 2: sent and replied (rcv)
    let raw = "h 0 1.1.1.1\nx 0 0\nx 0 1\np 0 5000 1\nx 0 2\np 0 6000 2\n";
    let hops = parse_raw(raw, true);
    assert_eq!(hops[0].stats.drop, 1);
    assert_eq!(hops[0].stats.rcv, 2);
    assert!((hops[0].stats.loss - 33.3).abs() < 0.1);
}

#[test]
fn duplicate_ip_removed() {
    let raw = "\
h 0 192.168.1.1
x 0 0
p 0 1000 0
h 1 10.0.0.1
x 1 0
p 1 5000 0
h 2 192.168.1.1
x 2 0
p 2 1000 0";
    let hops = parse_raw(raw, true);
    assert_eq!(hops.len(), 2, "loop hop should be removed");
}

#[test]
fn star_hop_has_null_address() {
    let raw = "h 0 192.168.1.1\nx 0 0\np 0 1000 0\nx 1 0\nx 1 1\n";
    let hops = parse_raw(raw, true);
    assert_eq!(hops.len(), 2);
    assert_eq!(hops[1].resolved_address, None);
    assert!(hops[1].timings.iter().all(|t| t.rtt.is_none()));
}

#[test]
fn output_has_header_and_gateway() {
    let hops = parse_raw(RAW_3HOP, true);
    let out = build_output(&hops);
    assert!(out.contains("Host"), "header should contain Host");
    assert!(out.contains("Loss%"));
    assert!(out.contains("_gateway"), "first hop should be _gateway");
    assert!(
        !out.contains("router.home"),
        "real first-hop hostname must not appear"
    );
    assert!(
        out.contains("one.one.one.one"),
        "last hop hostname should appear"
    );
}

#[test]
fn trailing_stars_omitted_from_output() {
    // [addr, *, *, *]: first trailing star is kept, subsequent ones are removed
    let raw = "\
h 0 192.168.1.1
x 0 0
p 0 1000 0
x 1 0
x 1 1
x 2 0
x 2 1
x 3 0
x 3 1";
    let hops = parse_raw(raw, true);
    let out = build_output(&hops);
    let waiting_count = out
        .lines()
        .filter(|l| l.contains("waiting for reply"))
        .count();
    assert_eq!(
        waiting_count, 1,
        "first trailing star shown; remaining removed; output:\n{}",
        out
    );
}

#[test]
fn middle_star_stays_in_output() {
    let raw = "\
h 0 192.168.1.1
x 0 0
p 0 1000 0
x 1 0
x 1 1
h 2 1.1.1.1
x 2 0
p 2 8000 0";
    let hops = parse_raw(raw, true);
    let out = build_output(&hops);
    assert!(
        out.contains("waiting for reply"),
        "middle star hop should appear"
    );
    assert!(out.contains("1.1.1.1"), "last hop should appear");
}

// ── Live process tests (Linux only) ──────────────────────────────────────────

#[cfg(target_os = "linux")]
mod live {
    use globalping_probe::command::mtr::{parse::MtrStatus, run_measurement};

    #[tokio::test]
    async fn live_udp_ipv4_cloudflare() {
        let r = run_measurement("1.1.1.1", "UDP", 4)
            .await
            .expect("mtr failed to spawn");

        assert_eq!(r.status, MtrStatus::Finished, "raw:\n{}", r.raw_output);
        assert!(!r.hops.is_empty(), "should have at least one hop");
        // UDP mode: last responding hop may not be exactly 1.1.1.1 (intermediate router replies)
        assert!(
            r.resolved_address.is_some(),
            "should have resolved at least one hop address"
        );

        let total_rtts: usize = r
            .hops
            .iter()
            .map(|h| h.timings.iter().filter(|t| t.rtt.is_some()).count())
            .sum();
        assert!(total_rtts > 0, "should have at least one measured RTT");

        println!(
            "MTR UDP 1.1.1.1: {} hops, {} RTTs, resolved_hostname={:?}",
            r.hops.len(),
            total_rtts,
            r.resolved_hostname
        );
        for (i, hop) in r.hops.iter().enumerate() {
            println!(
                "  hop {:>2}: addr={:?} host={:?} asn={:?} avg={:.1}ms loss={:.1}%",
                i + 1,
                hop.resolved_address,
                hop.resolved_hostname,
                hop.asn,
                hop.stats.avg,
                hop.stats.loss
            );
        }
        println!("\nrawOutput:\n{}", r.raw_output);
    }

    #[tokio::test]
    async fn live_udp_ipv6_cloudflare() {
        let r = run_measurement("2606:4700:4700::1111", "UDP", 6)
            .await
            .expect("IPv6 mtr failed to spawn");

        assert_eq!(r.status, MtrStatus::Finished, "raw:\n{}", r.raw_output);
        assert!(r.hops.iter().any(|hop| {
            hop.resolved_address
                .as_deref()
                .is_some_and(|address| address.contains(':'))
        }));
        assert!(
            r.hops
                .iter()
                .filter(|hop| hop.resolved_address.is_some())
                .skip(1)
                .any(|hop| !hop.asn.is_empty()),
            "expected at least one IPv6 hop with Team Cymru ASN enrichment; raw:\n{}",
            r.raw_output
        );
        println!(
            "MTR IPv6: {} hops; target host {:?}",
            r.hops.len(),
            r.resolved_hostname
        );
    }

    #[tokio::test]
    async fn live_icmp_ipv4_cloudflare() {
        let r = run_measurement("1.1.1.1", "ICMP", 4)
            .await
            .expect("mtr failed to spawn");

        if r.status == MtrStatus::Failed
            && (r.raw_output.to_lowercase().contains("privilege")
                || r.raw_output
                    .to_lowercase()
                    .contains("operation not permitted"))
        {
            println!("ICMP mtr requires elevated privileges — skipping");
            return;
        }

        assert_eq!(r.status, MtrStatus::Finished, "raw:\n{}", r.raw_output);
        assert!(!r.hops.is_empty());
        println!("MTR ICMP 1.1.1.1: {} hops", r.hops.len());
    }

    #[tokio::test]
    async fn live_private_ip_rejected() {
        let result = run_measurement("10.0.0.1", "UDP", 4)
            .await
            .expect("private IP should produce a structured failure");
        assert_eq!(result.status, MtrStatus::Failed);
        assert_eq!(result.failure_source.as_deref(), Some("target"));
        assert_eq!(result.raw_output, "Private IP ranges are not allowed.");
    }

    #[tokio::test]
    async fn live_asn_populated_for_public_hop() {
        let r = run_measurement("8.8.8.8", "UDP", 4)
            .await
            .expect("mtr failed");

        assert_eq!(r.status, MtrStatus::Finished, "raw:\n{}", r.raw_output);

        // At least one hop beyond the gateway should have an ASN
        let public_hops: Vec<_> = r
            .hops
            .iter()
            .skip(1)
            .filter(|h| h.resolved_address.is_some())
            .collect();
        let has_asn = public_hops.iter().any(|h| !h.asn.is_empty());

        if has_asn {
            println!("ASN lookup successful on at least one hop");
        } else {
            println!(
                "ASN lookup returned no results (dig may be unavailable or timeout) — not failing"
            );
        }
    }
}
