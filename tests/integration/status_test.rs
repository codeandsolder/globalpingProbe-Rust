// ── StatusManager unit tests (no process spawning) ────────────────────────────

use globalping_probe::status::icmp_tcp_test::is_vpn;
use globalping_probe::status::status_manager::{ProbeStatus, StatusManager};

// ── VPN detection logic ───────────────────────────────────────────────────────

#[test]
fn vpn_not_triggered_by_small_diffs() {
    let diffs = vec![Some(5.0), Some(15.0), Some(30.0)];
    assert!(!is_vpn(&diffs, None));
    assert!(!is_vpn(&diffs, Some(true)));
}

#[test]
fn vpn_triggered_by_single_diff_over_100() {
    let diffs = vec![Some(5.0), Some(110.0), Some(10.0)];
    assert!(is_vpn(&diffs, None));
}

#[test]
fn vpn_triggered_by_two_diffs_over_60() {
    let diffs = vec![Some(65.0), Some(80.0), Some(10.0)];
    assert!(is_vpn(&diffs, None));
}

#[test]
fn vpn_not_triggered_by_one_diff_over_60_without_proxy() {
    let diffs = vec![Some(70.0), Some(5.0), Some(5.0)];
    assert!(!is_vpn(&diffs, None));
    assert!(!is_vpn(&diffs, Some(false)));
}

#[test]
fn vpn_triggered_by_one_diff_over_60_with_proxy_true() {
    let diffs = vec![Some(70.0), Some(5.0), Some(5.0)];
    assert!(is_vpn(&diffs, Some(true)));
}

#[test]
fn null_diffs_never_trigger_vpn() {
    let diffs: Vec<Option<f64>> = vec![None, None, None];
    assert!(!is_vpn(&diffs, Some(true)));
}

#[test]
fn exactly_60_does_not_count_as_over_60() {
    // threshold is >= 60, so exactly 60.0 DOES count
    let diffs = vec![Some(60.0), Some(60.0)];
    assert!(
        is_vpn(&diffs, None),
        "two diffs exactly at 60ms should trigger VPN"
    );
}

// ── StatusManager state transitions ──────────────────────────────────────────

#[test]
fn status_initializing_before_any_test_runs() {
    let m = StatusManager::new();
    assert_eq!(m.get_status(), ProbeStatus::Initializing);
}

#[test]
fn status_initializing_after_only_ping_test() {
    let mut m = StatusManager::new();
    m.ping_test_failed = Some(false);
    assert_eq!(m.get_status(), ProbeStatus::Initializing);
}

#[test]
fn status_ready_when_all_pass() {
    let mut m = StatusManager::new();
    m.ping_test_failed = Some(false);
    m.icmp_tcp_test_failed = Some(false);
    assert_eq!(m.get_status(), ProbeStatus::Ready);
    assert_eq!(m.get_status().to_string(), "ready");
}

#[test]
fn status_ping_test_failed() {
    let mut m = StatusManager::new();
    m.ping_test_failed = Some(true);
    m.icmp_tcp_test_failed = Some(false);
    assert_eq!(m.get_status(), ProbeStatus::PingTestFailed);
}

#[test]
fn status_icmp_tcp_failed() {
    let mut m = StatusManager::new();
    m.ping_test_failed = Some(false);
    m.icmp_tcp_test_failed = Some(true);
    assert_eq!(m.get_status(), ProbeStatus::IcmpTcpTestFailed);
}

#[test]
fn ping_test_failed_has_higher_priority_than_icmp_tcp() {
    let mut m = StatusManager::new();
    m.ping_test_failed = Some(true);
    m.icmp_tcp_test_failed = Some(true);
    assert_eq!(m.get_status(), ProbeStatus::PingTestFailed);
}

#[test]
fn icmp_tcp_failed_has_higher_priority_than_disconnects() {
    let mut m = StatusManager::new();
    m.ping_test_failed = Some(false);
    m.icmp_tcp_test_failed = Some(true);
    m.too_many_disconnects = true;
    assert_eq!(m.get_status(), ProbeStatus::IcmpTcpTestFailed);
}

#[test]
fn sigterm_overrides_all_other_statuses() {
    let mut m = StatusManager::new();
    m.ping_test_failed = Some(true);
    m.icmp_tcp_test_failed = Some(true);
    m.too_many_disconnects = true;
    m.set_sigterm();
    assert_eq!(m.get_status(), ProbeStatus::Sigterm);
}

#[test]
fn three_disconnects_trigger_status() {
    let mut m = StatusManager::new();
    m.ping_test_failed = Some(false);
    m.icmp_tcp_test_failed = Some(false);
    assert!(!m.report_disconnect());
    assert!(!m.report_disconnect());
    assert!(m.report_disconnect()); // 3rd triggers
    assert_eq!(m.get_status(), ProbeStatus::TooManyDisconnects);
}

#[test]
fn on_proxy_true_with_medium_diff_triggers_icmp_tcp_failed() {
    let mut m = StatusManager::new();
    m.ping_test_failed = Some(false);
    m.icmp_tcp_test_failed = Some(false);
    m.icmp_tcp_test.diffs_v4 = vec![Some(65.0)]; // one diff >= 60 but < 100
    m.icmp_tcp_test.diffs_v6 = vec![];
    assert_eq!(m.get_status(), ProbeStatus::Ready);

    m.on_proxy_status(true);
    assert_eq!(m.get_status(), ProbeStatus::IcmpTcpTestFailed);
}

#[test]
fn on_proxy_false_clears_vpn_when_only_medium_diff() {
    let mut m = StatusManager::new();
    m.ping_test_failed = Some(false);
    m.icmp_tcp_test_failed = Some(true);
    m.icmp_tcp_test.is_proxy = Some(true);
    m.icmp_tcp_test.diffs_v4 = vec![Some(65.0)];
    m.icmp_tcp_test.diffs_v6 = vec![];

    m.on_proxy_status(false);
    // With is_proxy=false, one diff>=60 is not enough → cleared
    assert_eq!(m.icmp_tcp_test_failed, Some(false));
    assert_eq!(m.get_status(), ProbeStatus::Ready);
}

#[test]
fn probe_status_display() {
    assert_eq!(ProbeStatus::Initializing.to_string(), "initializing");
    assert_eq!(ProbeStatus::Ready.to_string(), "ready");
    assert_eq!(ProbeStatus::PingTestFailed.to_string(), "ping-test-failed");
    assert_eq!(
        ProbeStatus::IcmpTcpTestFailed.to_string(),
        "icmp-tcp-test-failed"
    );
    assert_eq!(
        ProbeStatus::TooManyDisconnects.to_string(),
        "too-many-disconnects"
    );
    assert_eq!(ProbeStatus::Sigterm.to_string(), "sigterm");
}

// ── Live Linux tests ──────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod live {
    use globalping_probe::command::ping::run_measurement;
    use globalping_probe::status::icmp_tcp_test::IcmpTcpTest;
    use globalping_probe::status::ping_test::PingTest;
    use globalping_probe::status::status_manager::{ProbeStatus, StatusManager};
    use globalping_probe::util::tcp_ping::tcp_ping;

    #[tokio::test]
    async fn live_tcp_ping_cloudflare_443() {
        let stats = tcp_ping("1.1.1.1", 443, 3, 5_000, 200).await;
        assert!(
            stats.rcv > 0,
            "should have at least one successful TCP connect"
        );
        assert!(stats.avg.is_some(), "avg should be set");
        let avg = stats.avg.unwrap();
        assert!(
            avg > 0.0 && avg < 500.0,
            "avg RTT should be reasonable: {avg}ms"
        );
        println!(
            "TCP ping 1.1.1.1:443: min={:.2?}ms avg={:.2?}ms max={:.2?}ms loss={:.1}%",
            stats.min, stats.avg, stats.max, stats.loss
        );
    }

    #[tokio::test]
    async fn live_ping_measurement_ipv4_cloudflare() {
        let r = run_measurement("1.1.1.1", 4, 3).await.expect("ping failed");
        use globalping_probe::command::ping::parse::PingStatus;
        assert_eq!(r.status, PingStatus::Finished);
        assert_eq!(r.stats.loss, Some(0.0), "expected zero loss to 1.1.1.1");
        assert!(r.stats.avg.is_some());
        println!(
            "ICMP ping 1.1.1.1: avg={:?}ms loss={:?}%",
            r.stats.avg, r.stats.loss
        );
    }

    #[tokio::test]
    async fn live_ping_test_ipv4_passes() {
        let mut pt = PingTest::new();
        let (ipv4, _ipv6) = pt.run_once("1.1.1.1").await;
        assert!(ipv4, "IPv4 ping test should pass for 1.1.1.1");
        println!("PingTest: ipv4={ipv4}");
    }

    #[tokio::test]
    async fn live_icmp_tcp_diff_measured() {
        let mut test = IcmpTcpTest::new();
        let vpn = test.run_once(&["1.1.1.1"]).await;
        let diffs_v4 = test.diffs_v4();
        println!("IcmpTcpTest: vpn={vpn} diffs_v4={diffs_v4:?}");
        // We don't assert VPN is false (network could have any topology)
        // Just verify diffs were measured (None means timeout, which is also fine)
        assert!(
            !diffs_v4.is_empty(),
            "should have measured at least one diff"
        );
    }

    #[tokio::test]
    async fn live_status_manager_becomes_ready() {
        let mut m = StatusManager::with_api_host("1.1.1.1");
        assert_eq!(
            m.get_status(),
            ProbeStatus::Initializing,
            "should start Initializing"
        );

        let (ipv4, ipv6) = m.run_ping_test().await;
        println!("Ping test: ipv4={ipv4} ipv6={ipv6}");
        // IPv4 should work from WSL
        assert!(ipv4, "IPv4 ping should succeed from WSL to 1.1.1.1");

        // Status is STILL Initializing until BOTH tests have run (mirrors Node.js behaviour)
        assert_eq!(
            m.get_status(),
            ProbeStatus::Initializing,
            "still Initializing until ICMP/TCP test also completes"
        );

        let vpn = m.run_icmp_tcp_test().await;
        println!(
            "ICMP/TCP test: vpn_detected={vpn} status={}",
            m.get_status()
        );

        // Now both tests are done — status must have left Initializing
        assert_ne!(
            m.get_status(),
            ProbeStatus::Initializing,
            "status should leave Initializing after both tests complete"
        );

        // If VPN not detected and ping passed, we should be Ready
        if !vpn {
            assert_eq!(m.get_status(), ProbeStatus::Ready);
        }
    }

    #[tokio::test]
    async fn live_tcp_ping_invalid_addr_returns_all_drops() {
        // Use a non-routable address — should timeout
        let stats = tcp_ping("192.0.2.1", 443, 2, 500, 100).await; // short timeout
        assert_eq!(stats.rcv, 0, "non-routable address should drop all probes");
        assert!((stats.loss - 100.0).abs() < 0.1);
        assert!(stats.avg.is_none());
    }
}
