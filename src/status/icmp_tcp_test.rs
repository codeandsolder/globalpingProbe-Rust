// ICMP vs TCP RTT comparison for VPN/proxy detection — mirrors src/status-manager/icmp-tcp-test.ts
use tokio::process::Command;
use tokio::time::{Duration, timeout};
use tracing::warn;

use crate::command::ping::parse::parse as parse_ping;
use crate::util::tcp_ping::tcp_ping;

const VPN_DIFF_HIGH: f64 = 100.0; // ms — one hit is enough
const VPN_DIFF_MED: f64 = 60.0; // ms — needs 2 hits, or 1 + is_proxy

const TCP_PORT: u16 = 443;
const ICMP_PACKETS: u8 = 3;
const TCP_PACKETS: u8 = 3;
const TCP_TIMEOUT_MS: u64 = 10_000;
const TCP_INTERVAL_MS: u64 = 500;
const ICMP_TIMEOUT_SECS: u64 = 20;

pub struct IcmpTcpTest {
    pub failed: bool,
    pub is_proxy: Option<bool>,
    pub diffs_v4: Vec<Option<f64>>,
    pub diffs_v6: Vec<Option<f64>>,
}

impl IcmpTcpTest {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            failed: false,
            is_proxy: None,
            diffs_v4: Vec::new(),
            diffs_v6: Vec::new(),
        }
    }

    /// Called when the API sends the `isProxy` flag via socket.
    /// Re-evaluates VPN detection against already-measured diffs.
    pub fn set_proxy_and_evaluate(&mut self, is_proxy: bool) -> bool {
        self.is_proxy = Some(is_proxy);
        self.failed = self.is_vpn_detected();
        self.failed
    }

    pub const fn set_is_proxy(&mut self, is_proxy: bool) {
        self.is_proxy = Some(is_proxy);
    }

    /// Measure ICMP vs TCP diffs for all `targets` and return true if VPN detected.
    pub async fn run_once(&mut self, targets: &[&str]) -> bool {
        let (diffs_v4, diffs_v6) = tokio::join!(measure_all(targets, 4), measure_all(targets, 6),);
        self.diffs_v4 = diffs_v4;
        self.diffs_v6 = diffs_v6;
        self.failed = self.is_vpn_detected();
        if self.failed {
            warn!(target: "status-manager", "ICMP/TCP ping RTT diff exceeds the threshold. Retrying in 1 hour. Probe temporarily disconnected.");
        }
        self.failed
    }

    #[must_use]
    pub fn is_vpn_detected(&self) -> bool {
        is_vpn(&self.diffs_v4, self.is_proxy) || is_vpn(&self.diffs_v6, self.is_proxy)
    }

    #[must_use]
    pub fn diffs_v4(&self) -> &[Option<f64>] {
        &self.diffs_v4
    }
    #[must_use]
    pub fn diffs_v6(&self) -> &[Option<f64>] {
        &self.diffs_v6
    }
}

impl Default for IcmpTcpTest {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if the diffs indicate a VPN/proxy setup.
/// null diffs (error cases) are treated as pass (conservative).
#[must_use]
pub fn is_vpn(diffs: &[Option<f64>], is_proxy: Option<bool>) -> bool {
    let numeric: Vec<f64> = diffs.iter().filter_map(|d| *d).collect();
    let over_high = numeric.iter().filter(|&&d| d >= VPN_DIFF_HIGH).count();
    let over_med = numeric.iter().filter(|&&d| d >= VPN_DIFF_MED).count();

    if over_high >= 1 {
        return true;
    }
    if over_med >= 2 {
        return true;
    }
    if over_med >= 1 && is_proxy == Some(true) {
        return true;
    }
    false
}

async fn measure_all(targets: &[&str], ip_version: u8) -> Vec<Option<f64>> {
    let futs: Vec<_> = targets
        .iter()
        .map(|t| measure_diff(t, ip_version))
        .collect();
    futures::future::join_all(futs).await
}

/// Measure (ICMP avg) – (TCP avg) for one target. Returns None on any error.
async fn measure_diff(target: &str, ip_version: u8) -> Option<f64> {
    let flag = format!("-{ip_version}");

    let icmp_fut = timeout(
        Duration::from_secs(ICMP_TIMEOUT_SECS),
        Command::new("ping")
            .args([
                flag.as_str(),
                "-c",
                &ICMP_PACKETS.to_string(),
                "-i",
                "0.5",
                "-w",
                "10",
                target,
            ])
            .output(),
    );

    let tcp_fut = tcp_ping(
        target,
        TCP_PORT,
        TCP_PACKETS,
        TCP_TIMEOUT_MS,
        TCP_INTERVAL_MS,
    );

    let (icmp_result, tcp_stats) = tokio::join!(icmp_fut, tcp_fut);

    let icmp_avg = match icmp_result {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            parse_ping(&stdout).stats.avg?
        }
        _ => return None,
    };

    let tcp_avg = tcp_stats.avg?;
    Some(icmp_avg - tcp_avg)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_not_detected_when_diffs_all_small() {
        let diffs = vec![Some(5.0), Some(10.0), Some(20.0)];
        assert!(!is_vpn(&diffs, None));
        assert!(!is_vpn(&diffs, Some(false)));
        assert!(!is_vpn(&diffs, Some(true)));
    }

    #[test]
    fn vpn_detected_when_one_diff_over_100() {
        let diffs = vec![Some(5.0), Some(120.0), Some(10.0)];
        assert!(is_vpn(&diffs, None));
    }

    #[test]
    fn vpn_detected_when_two_diffs_over_60() {
        let diffs = vec![Some(65.0), Some(70.0), Some(5.0)];
        assert!(is_vpn(&diffs, None));
    }

    #[test]
    fn vpn_not_detected_when_only_one_diff_over_60_without_proxy() {
        let diffs = vec![Some(65.0), Some(5.0), Some(5.0)];
        assert!(!is_vpn(&diffs, None));
        assert!(!is_vpn(&diffs, Some(false)));
    }

    #[test]
    fn vpn_detected_when_one_diff_over_60_with_proxy() {
        let diffs = vec![Some(65.0), Some(5.0), Some(5.0)];
        assert!(is_vpn(&diffs, Some(true)));
    }

    #[test]
    fn null_diffs_do_not_trigger_vpn() {
        let diffs = vec![None, None, None];
        assert!(!is_vpn(&diffs, Some(true)));
    }

    #[test]
    fn empty_diffs_do_not_trigger_vpn() {
        assert!(!is_vpn(&[], Some(true)));
    }

    #[test]
    fn set_proxy_and_evaluate_re_triggers_on_existing_diffs() {
        let mut test = IcmpTcpTest::new();
        // inject diffs directly (bypassing async run_once)
        test.diffs_v4 = vec![Some(65.0), Some(5.0)];
        test.diffs_v6 = vec![Some(5.0), Some(5.0)];

        // Without proxy: one v4 diff >= 60 but only one → not VPN
        assert!(!test.is_vpn_detected());

        // Set is_proxy = true → one diff >= 60 + proxy = VPN
        let vpn = test.set_proxy_and_evaluate(true);
        assert!(vpn);
        assert!(test.failed);
    }

    #[test]
    fn set_proxy_and_evaluate_clears_vpn_when_proxy_false() {
        let mut test = IcmpTcpTest::new();
        test.diffs_v4 = vec![Some(65.0)];
        test.diffs_v6 = vec![];
        test.is_proxy = Some(true);
        test.failed = true;

        // Re-evaluate with is_proxy = false
        let vpn = test.set_proxy_and_evaluate(false);
        assert!(!vpn, "single diff >= 60 without proxy should not flag VPN");
        assert!(!test.failed);
    }
}
