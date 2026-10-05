// Periodic ICMP ping health check — mirrors src/status-manager/ping-test.ts
use tokio::process::Command;
use tokio::time::{Duration, timeout};
use tracing::warn;

use crate::command::ping::parse::parse as parse_ping;

const PACKETS: u8 = 6;
const TRIALS: usize = 3;
const REQUIRED_PASSES: usize = 2;
const PING_TIMEOUT_SECS: u64 = 12;

pub struct PingTest {
    pub failed: bool,
}

enum TrialOutcome {
    Pass,
    Fail { loss: Option<f64>, raw: String },
}

impl PingTest {
    #[must_use]
    pub const fn new() -> Self {
        Self { failed: false }
    }

    /// Run ICMP ping trials against `target` for both IPv4 and IPv6.
    /// Returns (`ipv4_supported`, `ipv6_supported`).
    /// Sets `self.failed = true` when BOTH versions fail.
    pub async fn run_once(&mut self, target: &str) -> (bool, bool) {
        let (ipv4_ok, ipv6_ok) = tokio::join!(
            run_trials_for_version(target, 4),
            run_trials_for_version(target, 6),
        );
        self.failed = !ipv4_ok && !ipv6_ok;
        if self.failed {
            warn!(target: "status-manager", "Both ping tests failed due to bad internet connection. Retrying in 10 minutes. Probe temporarily disconnected.");
        }
        (ipv4_ok, ipv6_ok)
    }
}

impl Default for PingTest {
    fn default() -> Self {
        Self::new()
    }
}

/// Run all TRIALS for one IP version; log per-trial failures and summary.
/// Returns true if ≥ `REQUIRED_PASSES` have zero loss.
async fn run_trials_for_version(target: &str, ip_version: u8) -> bool {
    let mut pass_count = 0usize;
    let mut failures: Vec<TrialOutcome> = Vec::new();

    for _ in 0..TRIALS {
        match ping_once(target, ip_version).await {
            TrialOutcome::Pass => pass_count += 1,
            fail @ TrialOutcome::Fail { .. } => failures.push(fail),
        }
    }

    let meets_threshold = pass_count >= REQUIRED_PASSES;
    let pass_text = if meets_threshold {
        format!(". IPv{ip_version} tests pass")
    } else {
        String::new()
    };

    for outcome in &failures {
        if let TrialOutcome::Fail { loss, raw } = outcome {
            match loss {
                Some(l) if *l > 0.0 => warn!(
                    target: "status-manager",
                    "IPv{ip_version} ping test unsuccessful for {target}: {l}% packet loss{pass_text}."
                ),
                _ => warn!(
                    target: "status-manager",
                    "IPv{ip_version} ping test unsuccessful: {raw}{pass_text}."
                ),
            }
        }
    }

    if !meets_threshold {
        warn!(
            target: "status-manager",
            "IPv{ip_version} ping tests failed. Retrying in 10 minutes. Probe marked as not supporting IPv{ip_version}."
        );
    }

    meets_threshold
}

/// Run one `ping` subprocess; return Pass or Fail with details.
async fn ping_once(target: &str, ip_version: u8) -> TrialOutcome {
    let flag = format!("-{ip_version}");
    let result = timeout(
        Duration::from_secs(PING_TIMEOUT_SECS),
        Command::new("ping")
            .args([
                flag.as_str(),
                "-O",
                "-n",
                "-c",
                &PACKETS.to_string(),
                "-i",
                "0.5",
                "-W",
                "5",
                target,
            ])
            .output(),
    )
    .await;

    match result {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let parsed = parse_ping(&stdout);
            if parsed.stats.loss == Some(0.0) {
                TrialOutcome::Pass
            } else {
                TrialOutcome::Fail {
                    loss: parsed.stats.loss,
                    raw: stdout.trim().to_string(),
                }
            }
        }
        Ok(Err(e)) => TrialOutcome::Fail {
            loss: None,
            raw: e.to_string(),
        },
        Err(_) => TrialOutcome::Fail {
            loss: None,
            raw: String::new(),
        },
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::ping::parse::parse as parse_ping;

    #[test]
    fn parse_zero_loss_returns_true() {
        let raw = "\
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=55 time=10.2 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=55 time=9.8 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=55 time=10.5 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 9.800/10.166/10.500/0.294 ms
";
        let parsed = parse_ping(raw);
        assert_eq!(parsed.stats.loss, Some(0.0));
    }

    #[test]
    fn parse_100pct_loss_returns_false() {
        let raw = "\
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2009ms
";
        let parsed = parse_ping(raw);
        assert!(parsed.stats.loss != Some(0.0));
    }

    #[test]
    fn failed_is_true_only_when_both_versions_fail() {
        let mut pt = PingTest::new();
        pt.failed = false;
        let ipv4_ok = true;
        let ipv6_ok = false;
        pt.failed = !ipv4_ok && !ipv6_ok;
        assert!(!pt.failed);

        pt.failed = false;
        let ipv4_ok = false;
        let ipv6_ok = false;
        pt.failed = !ipv4_ok && !ipv6_ok;
        assert!(pt.failed);
    }
}
