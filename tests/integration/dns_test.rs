use globalping_probe::command::dns::parse::{DnsStatus, parse_classic, parse_trace};

// ── Fixture-based parser tests ────────────────────────────────────────────────

#[test]
fn classic_full_success_with_private_resolver() {
    // Fixture mirrors test/mocks/dns-success-linux.txt
    let raw = ";; Truncated, retrying in TCP mode.\n\
; <<>> DiG 9.16.1-Ubuntu <<>> google.com -t TXT -p 53 -4 +timeout=3 +tries=2 +nocookie\n\
;; global options: +cmd\n\
;; Got answer:\n\
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29356\n\
;; flags: qr rd ra; QUERY: 1, ANSWER: 9, AUTHORITY: 0, ADDITIONAL: 0\n\
\n\
;; QUESTION SECTION:\n\
;google.com.\t\t\tIN\tTXT\n\
\n\
;; ANSWER SECTION:\n\
google.com.\t\t3600\tIN\tTXT\t\"v=spf1 include:_spf.google.com ~all\"\n\
google.com.\t\t3600\tIN\tTXT\t\"facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95\"\n\
\n\
;; Query time: 0 msec\n\
;; SERVER: 192.168.0.49#53(192.168.0.49)\n\
;; WHEN: Mon Apr 04 12:25:44 UTC 2022\n\
;; MSG SIZE  rcvd: 614\n";

    let r = parse_classic(raw);
    assert_eq!(r.status, DnsStatus::Finished);
    assert_eq!(r.status_code_name.as_deref(), Some("NOERROR"));
    assert_eq!(r.status_code, Some(0));
    assert_eq!(r.resolver.as_deref(), Some("private"));
    assert_eq!(r.timings.total, 0);
    assert_eq!(r.answers.len(), 2);
    assert_eq!(r.answers[0].name, "google.com.");
    assert_eq!(r.answers[0].record_type, "TXT");
    assert_eq!(r.answers[0].ttl, 3600);
    // rawOutput has private IP redacted
    assert!(r.raw_output.contains("x.x.x.x"));
    assert!(!r.raw_output.contains("192.168.0.49"));
}

#[test]
fn classic_connection_refused_fails_gracefully() {
    let raw = ";; Connection to 8.8.8.8#212(8.8.8.8) for abc.com failed: connection refused.";
    let r = parse_classic(raw);
    assert_eq!(r.status, DnsStatus::Failed);
    assert!(r.answers.is_empty());
    assert_eq!(r.resolver, None);
    assert_eq!(r.status_code_name, None);
    assert!(r.raw_output.contains("connection refused"));
}

#[test]
fn classic_bad_packet_fails() {
    let raw = ";; Got bad packet: FORMERR\n205 bytes\nsome hex\n";
    let r = parse_classic(raw);
    assert_eq!(r.status, DnsStatus::Failed);
}

#[test]
fn classic_public_resolver_not_redacted() {
    let raw = "; <<>> DiG 9.16 <<>> example.com\n\
;; global options: +cmd\n\
;; Got answer:\n\
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n\
;; flags: qr rd ra;\n\
\n\
;; QUESTION SECTION:\n\
;example.com.\tIN\tA\n\
\n\
;; ANSWER SECTION:\n\
example.com.\t3600\tIN\tA\t93.184.216.34\n\
\n\
;; Query time: 12 msec\n\
;; SERVER: 8.8.8.8#53(8.8.8.8)\n\
;; MSG SIZE  rcvd: 56\n";

    let r = parse_classic(raw);
    assert_eq!(r.status, DnsStatus::Finished);
    assert_eq!(r.resolver.as_deref(), Some("8.8.8.8"));
    assert!(!r.raw_output.contains("x.x.x.x"));
    assert_eq!(r.timings.total, 12);
    assert_eq!(r.answers.len(), 1);
    assert_eq!(r.answers[0].value, "93.184.216.34");
}

#[test]
fn classic_nxdomain_returns_code_3() {
    let raw = "; <<>> DiG 9.16 <<>> nonexistent.invalid\n\
;; global options: +cmd\n\
;; Got answer:\n\
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 42\n\
;; flags: qr rd ra;\n\
\n\
;; QUESTION SECTION:\n\
;nonexistent.invalid.\tIN\tA\n\
\n\
;; Query time: 5 msec\n\
;; SERVER: 8.8.8.8#53(8.8.8.8)\n\
;; MSG SIZE  rcvd: 44\n";

    let r = parse_classic(raw);
    assert_eq!(r.status_code_name.as_deref(), Some("NXDOMAIN"));
    assert_eq!(r.status_code, Some(3));
    assert!(r.answers.is_empty());
}

#[test]
fn trace_full_fixture() {
    // Fixture mirrors test/mocks/dns-trace-success.txt (abbreviated)
    let raw = "; <<>> DiG 9.18.1 <<>> +trace cdn.jsdelivr.net\n\
;; global options: +cmd\n\
.\t\t\t6593\tIN\tNS\tj.root-servers.net.\n\
.\t\t\t6593\tIN\tNS\ta.root-servers.net.\n\
;; Received 811 bytes from 127.0.0.53#53(127.0.0.53) in 4 ms\n\
\n\
net.\t\t\t172800\tIN\tNS\ta.gtld-servers.net.\n\
;; Received 1173 bytes from 199.7.91.13#53(d.root-servers.net) in 24 ms\n\
\n\
cdn.jsdelivr.net.\t900\tIN\tCNAME\tjsdelivr.map.fastly.net.\n\
;; Received 79 bytes from 185.136.98.122#53(gns3.cloudns.net) in 28 ms\n";

    let r = parse_trace(raw);
    assert_eq!(r.status, DnsStatus::Finished);
    assert_eq!(r.hops.len(), 3);

    assert_eq!(r.hops[0].resolver.as_deref(), Some("127.0.0.53"));
    assert_eq!(r.hops[0].timings.total, 4);
    assert_eq!(r.hops[0].answers.len(), 2);

    assert_eq!(r.hops[1].resolver.as_deref(), Some("d.root-servers.net"));
    assert_eq!(r.hops[1].timings.total, 24);

    assert_eq!(r.hops[2].resolver.as_deref(), Some("gns3.cloudns.net"));
    assert_eq!(r.hops[2].timings.total, 28);
    assert_eq!(r.hops[2].answers[0].record_type, "CNAME");
    assert_eq!(r.hops[2].answers[0].value, "jsdelivr.map.fastly.net.");
}

// ── Live process tests (Linux only) ──────────────────────────────────────────

#[cfg(target_os = "linux")]
mod live {
    use globalping_probe::command::dns::parse::DnsStatus;
    use globalping_probe::command::dns::{query_classic, query_trace};

    #[tokio::test]
    async fn live_a_record_cloudflare() {
        let r = query_classic("one.one.one.one", "A", Some("8.8.8.8"))
            .await
            .expect("dig failed");

        assert_eq!(r.status, DnsStatus::Finished, "rawOutput: {}", r.raw_output);
        assert_eq!(r.status_code_name.as_deref(), Some("NOERROR"));
        assert!(!r.answers.is_empty(), "should have A answers");
        assert!(
            r.answers.iter().all(|a| a.record_type == "A"),
            "all answers should be A"
        );
        // one.one.one.one always resolves to 1.1.1.1 or 1.0.0.1
        let addrs: Vec<_> = r.answers.iter().map(|a| a.value.as_str()).collect();
        assert!(
            addrs.contains(&"1.1.1.1") || addrs.contains(&"1.0.0.1"),
            "expected Cloudflare IP, got: {:?}",
            addrs
        );
        assert_eq!(r.resolver.as_deref(), Some("8.8.8.8"));
        assert!(r.timings.total < 5000);

        println!(
            "A one.one.one.one via 8.8.8.8 → {:?} in {} ms",
            addrs, r.timings.total
        );
    }

    #[tokio::test]
    async fn live_aaaa_record_cloudflare() {
        let r = query_classic("one.one.one.one", "AAAA", Some("8.8.8.8"))
            .await
            .expect("dig failed");

        assert_eq!(r.status, DnsStatus::Finished, "rawOutput: {}", r.raw_output);
        let addrs: Vec<_> = r.answers.iter().map(|a| a.value.as_str()).collect();
        println!("AAAA one.one.one.one → {:?}", addrs);
        // Must have AAAA records (may be empty on IPv6-disabled network, so we accept either)
        for a in &r.answers {
            assert_eq!(a.record_type, "AAAA");
        }
    }

    #[tokio::test]
    async fn live_txt_record_google() {
        let r = query_classic("google.com", "TXT", Some("8.8.8.8"))
            .await
            .expect("dig failed");

        assert_eq!(r.status, DnsStatus::Finished);
        assert!(!r.answers.is_empty());
        let has_spf = r.answers.iter().any(|a| a.value.contains("v=spf1"));
        assert!(has_spf, "expected SPF TXT record for google.com");
        println!("TXT google.com: {} records", r.answers.len());
    }

    #[tokio::test]
    async fn live_nxdomain() {
        let r = query_classic(
            "this-domain-definitely-does-not-exist-xyzabc123.com",
            "A",
            Some("8.8.8.8"),
        )
        .await
        .expect("dig failed");

        // dig returns exit 0 for NXDOMAIN, just with status NXDOMAIN in the header
        assert_eq!(r.status_code_name.as_deref(), Some("NXDOMAIN"));
        assert_eq!(r.status_code, Some(3));
        assert!(r.answers.is_empty());
        println!("NXDOMAIN test passed, status={:?}", r.status_code_name);
    }

    #[tokio::test]
    async fn live_trace_resolves_hops() {
        let r = query_trace("one.one.one.one", Some("8.8.8.8"))
            .await
            .expect("dig +trace failed");

        assert_eq!(
            r.status,
            DnsStatus::Finished,
            "status failed. raw:\n{}",
            r.raw_output
        );
        assert!(
            !r.hops.is_empty(),
            "trace should produce at least one hop. raw:\n{}",
            r.raw_output
        );
        // First hop must have root NS records
        let first = &r.hops[0];
        assert!(
            !first.answers.is_empty(),
            "first hop has no answers ({} hops total). raw:\n{}",
            r.hops.len(),
            r.raw_output
        );
        assert!(
            first.answers.iter().any(|a| a.record_type == "NS"),
            "first hop should have NS records, got: {:?}",
            first.answers
        );
        println!("Trace one.one.one.one: {} hops", r.hops.len());
        for (i, hop) in r.hops.iter().enumerate() {
            println!(
                "  hop {}: resolver={:?} timing={}ms answers={}",
                i,
                hop.resolver,
                hop.timings.total,
                hop.answers.len()
            );
        }
    }
}
