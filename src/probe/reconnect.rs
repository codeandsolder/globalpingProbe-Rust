use std::time::Duration;

/// What the client should do after a disconnect or connect error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// SIGTERM / CTRL-C — stop the loop entirely.
    CleanShutdown,
    /// API-requested restart — drain active jobs, then exit cleanly.
    RestartRequested,
    /// Server rejected us because of IP/ASN/VPN/GeoIP policy — wait 1 hour.
    ProbePolicyError,
    /// Server rejected us because probe metadata could not be collected — wait 1 minute.
    MetadataError,
    /// Server says our version is unsupported — exit the process.
    InvalidVersion,
    /// Server is terminating — reconnect using the ordinary 2-second delay.
    ServerTerminating,
    /// Ordinary connection error/disconnect — reconnect after 2 seconds.
    Transient,
}

/// Parse the socket.io connect-error message and return the upstream reconnect policy.
#[must_use]
pub fn classify_error(msg: &str) -> ConnectOutcome {
    let lower = msg.to_lowercase();
    if lower.starts_with("invalid probe version") || lower.contains("invalid version") {
        return ConnectOutcome::InvalidVersion;
    }
    if [
        "ip limit",
        "user asn limit",
        "vpn detected",
        "unresolvable geoip",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
    {
        return ConnectOutcome::ProbePolicyError;
    }
    if lower.starts_with("failed to collect probe metadata") || lower.contains("metadata error") {
        return ConnectOutcome::MetadataError;
    }
    if lower.contains("server is terminating")
        || lower.contains("server-terminating")
        || lower.contains("server terminating")
    {
        return ConnectOutcome::ServerTerminating;
    }
    ConnectOutcome::Transient
}

/// How long to wait before the next connection attempt.
#[must_use]
pub const fn reconnect_delay(outcome: &ConnectOutcome) -> Option<Duration> {
    match outcome {
        ConnectOutcome::CleanShutdown
        | ConnectOutcome::RestartRequested
        | ConnectOutcome::InvalidVersion => None,
        ConnectOutcome::ProbePolicyError => Some(Duration::from_hours(1)),
        ConnectOutcome::MetadataError => Some(Duration::from_secs(60)),
        ConnectOutcome::ServerTerminating | ConnectOutcome::Transient => {
            Some(Duration::from_secs(2))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_current_probe_policy_errors() {
        for message in [
            "ip limit",
            "user asn limit exceeded",
            "vpn detected",
            "unresolvable geoip",
        ] {
            assert_eq!(classify_error(message), ConnectOutcome::ProbePolicyError);
        }
    }

    #[test]
    fn metadata_error_waits_one_minute() {
        assert_eq!(
            reconnect_delay(&ConnectOutcome::MetadataError),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn ordinary_errors_wait_two_seconds() {
        assert_eq!(
            reconnect_delay(&ConnectOutcome::Transient),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            reconnect_delay(&ConnectOutcome::ServerTerminating),
            Some(Duration::from_secs(2))
        );
    }

    #[test]
    fn exit_outcomes_do_not_reconnect() {
        for outcome in [
            ConnectOutcome::CleanShutdown,
            ConnectOutcome::RestartRequested,
            ConnectOutcome::InvalidVersion,
        ] {
            assert_eq!(reconnect_delay(&outcome), None);
        }
    }
}
