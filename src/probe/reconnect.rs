use std::time::Duration;

/// What the client should do after a disconnect or connect error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// SIGTERM / CTRL-C — stop the loop entirely.
    CleanShutdown,
    /// Server rejected us because of IP rate-limit or VPN/GeoIP policy — wait 1 hour.
    IpLimitOrVpn,
    /// Server rejected us due to invalid metadata — wait 1 minute.
    MetadataError,
    /// Server says our version is unsupported — exit the process.
    InvalidVersion,
    /// Server is restarting — reconnect immediately.
    ServerTerminating,
    /// Network hiccup / clean disconnect — use exponential back-off.
    Transient,
}

/// Parse the socket.io connect-error message and return the reconnect policy.
#[must_use]
pub fn classify_error(msg: &str) -> ConnectOutcome {
    let lower = msg.to_lowercase();
    if lower.contains("invalid probe version") || lower.contains("invalid version") {
        return ConnectOutcome::InvalidVersion;
    }
    if lower.contains("ip limit") || lower.contains("vpn") || lower.contains("geoip") {
        return ConnectOutcome::IpLimitOrVpn;
    }
    if lower.contains("metadata") {
        return ConnectOutcome::MetadataError;
    }
    if lower.contains("server-terminating") || lower.contains("server terminating") {
        return ConnectOutcome::ServerTerminating;
    }
    ConnectOutcome::Transient
}

/// How long to wait before the next connection attempt.
pub fn reconnect_delay(
    outcome: &ConnectOutcome,
    backoff: &mut ExponentialBackoff,
) -> Option<Duration> {
    match outcome {
        ConnectOutcome::CleanShutdown => None,
        ConnectOutcome::InvalidVersion => None,
        ConnectOutcome::IpLimitOrVpn => Some(Duration::from_hours(1)),
        ConnectOutcome::MetadataError => Some(Duration::from_secs(60)),
        ConnectOutcome::ServerTerminating => Some(Duration::ZERO),
        ConnectOutcome::Transient => Some(backoff.next()),
    }
}

// ── Exponential back-off ──────────────────────────────────────────────────────

/// Doubles the delay each call, clamped between `min` and `max`.
pub struct ExponentialBackoff {
    current: Duration,
    min: Duration,
    max: Duration,
}

impl ExponentialBackoff {
    #[must_use]
    pub const fn new(min: Duration, max: Duration) -> Self {
        Self {
            current: min,
            min,
            max,
        }
    }

    /// Return the current delay and double it for next time.
    pub fn next(&mut self) -> Duration {
        let d = self.current;
        self.current = (self.current * 2).min(self.max);
        d
    }

    pub const fn reset(&mut self) {
        self.current = self.min;
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_error ────────────────────────────────────────────────────────

    #[test]
    fn classifies_ip_limit() {
        assert_eq!(classify_error("ip limit"), ConnectOutcome::IpLimitOrVpn);
        assert_eq!(classify_error("IP LIMIT"), ConnectOutcome::IpLimitOrVpn);
    }

    #[test]
    fn classifies_vpn() {
        assert_eq!(classify_error("vpn detected"), ConnectOutcome::IpLimitOrVpn);
        assert_eq!(classify_error("VPN"), ConnectOutcome::IpLimitOrVpn);
    }

    #[test]
    fn classifies_geoip() {
        assert_eq!(
            classify_error("geoip lookup failed"),
            ConnectOutcome::IpLimitOrVpn
        );
    }

    #[test]
    fn classifies_metadata() {
        assert_eq!(
            classify_error("invalid metadata"),
            ConnectOutcome::MetadataError
        );
        assert_eq!(
            classify_error("metadata error"),
            ConnectOutcome::MetadataError
        );
    }

    #[test]
    fn classifies_invalid_version() {
        assert_eq!(
            classify_error("invalid probe version (0.1.0)"),
            ConnectOutcome::InvalidVersion
        );
        assert_eq!(
            classify_error("invalid version"),
            ConnectOutcome::InvalidVersion
        );
    }

    #[test]
    fn classifies_server_terminating() {
        assert_eq!(
            classify_error("server-terminating"),
            ConnectOutcome::ServerTerminating
        );
        assert_eq!(
            classify_error("server terminating"),
            ConnectOutcome::ServerTerminating
        );
    }

    #[test]
    fn classifies_unknown_as_transient() {
        assert_eq!(classify_error(""), ConnectOutcome::Transient);
        assert_eq!(
            classify_error("connection reset by peer"),
            ConnectOutcome::Transient
        );
        assert_eq!(classify_error("timeout"), ConnectOutcome::Transient);
    }

    // ── reconnect_delay ───────────────────────────────────────────────────────

    #[test]
    fn clean_shutdown_returns_none() {
        let mut bo = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(300));
        assert_eq!(
            reconnect_delay(&ConnectOutcome::CleanShutdown, &mut bo),
            None
        );
    }

    #[test]
    fn invalid_version_returns_none() {
        let mut bo = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(300));
        assert_eq!(
            reconnect_delay(&ConnectOutcome::InvalidVersion, &mut bo),
            None
        );
    }

    #[test]
    fn ip_limit_returns_one_hour() {
        let mut bo = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(300));
        assert_eq!(
            reconnect_delay(&ConnectOutcome::IpLimitOrVpn, &mut bo),
            Some(Duration::from_secs(3600))
        );
    }

    #[test]
    fn metadata_error_returns_one_minute() {
        let mut bo = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(300));
        assert_eq!(
            reconnect_delay(&ConnectOutcome::MetadataError, &mut bo),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn server_terminating_returns_zero() {
        let mut bo = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(300));
        assert_eq!(
            reconnect_delay(&ConnectOutcome::ServerTerminating, &mut bo),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn transient_uses_backoff() {
        let mut bo = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(300));
        assert_eq!(
            reconnect_delay(&ConnectOutcome::Transient, &mut bo),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            reconnect_delay(&ConnectOutcome::Transient, &mut bo),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            reconnect_delay(&ConnectOutcome::Transient, &mut bo),
            Some(Duration::from_secs(4))
        );
    }

    // ── ExponentialBackoff ────────────────────────────────────────────────────

    #[test]
    fn backoff_doubles_each_call() {
        let mut bo = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(300));
        assert_eq!(bo.next(), Duration::from_secs(1));
        assert_eq!(bo.next(), Duration::from_secs(2));
        assert_eq!(bo.next(), Duration::from_secs(4));
        assert_eq!(bo.next(), Duration::from_secs(8));
    }

    #[test]
    fn backoff_clamps_at_max() {
        let mut bo = ExponentialBackoff::new(Duration::from_secs(128), Duration::from_secs(300));
        bo.next(); // 128
        bo.next(); // 256
        bo.next(); // would be 512, clamped to 300
        assert_eq!(bo.next(), Duration::from_secs(300));
    }

    #[test]
    fn backoff_resets_to_min() {
        let mut bo = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(300));
        bo.next();
        bo.next();
        bo.next(); // advance a few times
        bo.reset();
        assert_eq!(bo.next(), Duration::from_secs(1));
    }
}
