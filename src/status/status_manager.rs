use super::disconnect::DisconnectTracker;
use super::icmp_tcp_test::IcmpTcpTest;
use super::ping_test::PingTest;

const DEFAULT_ICMP_TCP_TARGETS: &[&str] = &["1.1.1.1", "8.8.8.8", "9.9.9.9"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeStatus {
    Initializing,
    Ready,
    PingTestFailed,
    IcmpTcpTestFailed,
    TooManyDisconnects,
    Sigterm,
}

impl std::fmt::Display for ProbeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initializing => write!(f, "initializing"),
            Self::Ready => write!(f, "ready"),
            Self::PingTestFailed => write!(f, "ping-test-failed"),
            Self::IcmpTcpTestFailed => write!(f, "icmp-tcp-test-failed"),
            Self::TooManyDisconnects => write!(f, "too-many-disconnects"),
            Self::Sigterm => write!(f, "sigterm"),
        }
    }
}

pub struct StatusManager {
    pub ping_test_failed: Option<bool>,     // None = not yet run
    pub icmp_tcp_test_failed: Option<bool>, // None = not yet run
    pub too_many_disconnects: bool,
    sigterm: bool,
    ping_test: PingTest,
    pub icmp_tcp_test: IcmpTcpTest,
    disconnect_tracker: DisconnectTracker,
    api_host: String,
}

impl StatusManager {
    #[must_use]
    pub fn new() -> Self {
        Self::with_api_host("api.globalping.io")
    }

    #[must_use]
    pub fn with_api_host(host: &str) -> Self {
        Self {
            ping_test_failed: None,
            icmp_tcp_test_failed: None,
            too_many_disconnects: false,
            sigterm: false,
            ping_test: PingTest::new(),
            icmp_tcp_test: IcmpTcpTest::new(),
            disconnect_tracker: DisconnectTracker::new(),
            api_host: host.to_string(),
        }
    }

    /// Derive the current probe status. Mirrors `StatusManager.getStatus()` in TypeScript.
    /// Priority (highest → lowest): sigterm → initializing → ping-test-failed →
    /// icmp-tcp-test-failed → too-many-disconnects → ready.
    #[must_use]
    pub fn get_status(&self) -> ProbeStatus {
        if self.sigterm {
            return ProbeStatus::Sigterm;
        }
        if self.ping_test_failed.is_none() || self.icmp_tcp_test_failed.is_none() {
            return ProbeStatus::Initializing;
        }
        if self.ping_test_failed == Some(true) {
            return ProbeStatus::PingTestFailed;
        }
        if self.icmp_tcp_test_failed == Some(true) {
            return ProbeStatus::IcmpTcpTestFailed;
        }
        if self.too_many_disconnects {
            return ProbeStatus::TooManyDisconnects;
        }
        ProbeStatus::Ready
    }

    /// Run the ping health check and record results.
    /// Returns (`ipv4_supported`, `ipv6_supported`).
    pub async fn run_ping_test(&mut self) -> (bool, bool) {
        let host = self.api_host.clone();
        let (ipv4, ipv6) = self.ping_test.run_once(&host).await;
        self.ping_test_failed = Some(!ipv4 && !ipv6);
        (ipv4, ipv6)
    }

    /// Run the ICMP/TCP VPN-detection test and record result.
    /// Returns true if VPN detected (test failed).
    pub async fn run_icmp_tcp_test(&mut self) -> bool {
        let detected = self.icmp_tcp_test.run_once(DEFAULT_ICMP_TCP_TARGETS).await;
        self.icmp_tcp_test_failed = Some(detected);
        detected
    }

    /// Notify that `is_proxy` info arrived from the API (via socket event).
    /// Re-evaluates VPN detection with existing diffs.
    pub fn on_proxy_status(&mut self, is_proxy: bool) {
        let vpn = self.icmp_tcp_test.set_proxy_and_evaluate(is_proxy);
        if self.icmp_tcp_test_failed.is_some() {
            self.icmp_tcp_test_failed = Some(vpn);
        }
    }

    /// Record a disconnect; returns true if the "too-many-disconnects" threshold is hit.
    pub fn report_disconnect(&mut self) -> bool {
        let too_many = self.disconnect_tracker.record();
        self.too_many_disconnects = too_many;
        too_many
    }

    /// Re-evaluate disconnect status after TTL may have expired entries.
    /// Mirrors Node.js `TTLCache` dispose callback resetting the flag to false.
    pub fn recheck_disconnect_status(&mut self) {
        let too_many = self.disconnect_tracker.count() >= 3;
        self.too_many_disconnects = too_many;
    }

    pub const fn set_sigterm(&mut self) {
        self.sigterm = true;
    }

    #[must_use]
    pub fn ipv4_supported(&self) -> Option<bool> {
        // If ping test hasn't run, unknown
        self.ping_test_failed
            .map(|f| !f || self.ping_test.failed)
            .or(None)
    }
}

impl Default for StatusManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> StatusManager {
        StatusManager::new()
    }

    #[test]
    fn initial_status_is_initializing() {
        let m = mgr();
        assert_eq!(m.get_status(), ProbeStatus::Initializing);
    }

    #[test]
    fn sigterm_overrides_everything() {
        let mut m = mgr();
        m.sigterm = true;
        // Even with everything else ok, sigterm wins
        m.ping_test_failed = Some(false);
        m.icmp_tcp_test_failed = Some(false);
        assert_eq!(m.get_status(), ProbeStatus::Sigterm);
    }

    #[test]
    fn status_ready_when_all_tests_pass() {
        let mut m = mgr();
        m.ping_test_failed = Some(false);
        m.icmp_tcp_test_failed = Some(false);
        assert_eq!(m.get_status(), ProbeStatus::Ready);
    }

    #[test]
    fn ping_test_failed_status() {
        let mut m = mgr();
        m.ping_test_failed = Some(true);
        m.icmp_tcp_test_failed = Some(false);
        assert_eq!(m.get_status(), ProbeStatus::PingTestFailed);
    }

    #[test]
    fn icmp_tcp_test_failed_status() {
        let mut m = mgr();
        m.ping_test_failed = Some(false);
        m.icmp_tcp_test_failed = Some(true);
        assert_eq!(m.get_status(), ProbeStatus::IcmpTcpTestFailed);
    }

    #[test]
    fn too_many_disconnects_status() {
        let mut m = mgr();
        m.ping_test_failed = Some(false);
        m.icmp_tcp_test_failed = Some(false);
        m.too_many_disconnects = true;
        assert_eq!(m.get_status(), ProbeStatus::TooManyDisconnects);
    }

    #[test]
    fn ping_test_failed_takes_priority_over_icmp_tcp() {
        let mut m = mgr();
        m.ping_test_failed = Some(true);
        m.icmp_tcp_test_failed = Some(true);
        assert_eq!(m.get_status(), ProbeStatus::PingTestFailed);
    }

    #[test]
    fn icmp_tcp_takes_priority_over_disconnects() {
        let mut m = mgr();
        m.ping_test_failed = Some(false);
        m.icmp_tcp_test_failed = Some(true);
        m.too_many_disconnects = true;
        assert_eq!(m.get_status(), ProbeStatus::IcmpTcpTestFailed);
    }

    #[test]
    fn initializing_when_only_ping_test_done() {
        let mut m = mgr();
        m.ping_test_failed = Some(false);
        // icmp_tcp_test_failed is still None
        assert_eq!(m.get_status(), ProbeStatus::Initializing);
    }

    #[test]
    fn report_disconnect_triggers_status_after_three() {
        let mut m = mgr();
        m.ping_test_failed = Some(false);
        m.icmp_tcp_test_failed = Some(false);
        assert!(!m.report_disconnect());
        assert!(!m.report_disconnect());
        let too_many = m.report_disconnect();
        assert!(too_many);
        assert_eq!(m.get_status(), ProbeStatus::TooManyDisconnects);
    }

    #[test]
    fn on_proxy_status_updates_icmp_tcp_failed() {
        let mut m = mgr();
        m.ping_test_failed = Some(false);
        m.icmp_tcp_test_failed = Some(false);
        // inject a border-line diff (>= 60ms but < 100ms) — needs is_proxy to trigger
        m.icmp_tcp_test.diffs_v4 = vec![Some(65.0)];
        m.icmp_tcp_test.diffs_v6 = vec![];
        assert_eq!(m.get_status(), ProbeStatus::Ready);

        m.on_proxy_status(true);
        assert_eq!(m.icmp_tcp_test_failed, Some(true));
        assert_eq!(m.get_status(), ProbeStatus::IcmpTcpTestFailed);
    }

    #[test]
    fn status_display_strings() {
        assert_eq!(ProbeStatus::Ready.to_string(), "ready");
        assert_eq!(ProbeStatus::Initializing.to_string(), "initializing");
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
}
