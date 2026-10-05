use std::net::IpAddr;
use std::time::Duration;

use tokio::net::lookup_host;
use tokio::process::Command;
use tokio::time::timeout;

use crate::util::private_ip::is_ip_private;

pub const DNS_TIMEOUT_MESSAGE: &str = "The measurement timed out during DNS resolution.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub address: IpAddr,
    pub hostname: String,
}

#[derive(Debug)]
pub enum ResolveTargetError {
    PrivateIp,
    TimedOut,
    NotFound,
    Lookup(String),
}

impl std::fmt::Display for ResolveTargetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivateIp => formatter.write_str("Private IP ranges are not allowed."),
            Self::TimedOut => formatter.write_str(DNS_TIMEOUT_MESSAGE),
            Self::NotFound => {
                formatter.write_str("target did not resolve for the requested IP family")
            }
            Self::Lookup(error) => write!(formatter, "target lookup failed: {error}"),
        }
    }
}

impl std::error::Error for ResolveTargetError {}

impl ResolveTargetError {
    #[must_use]
    pub const fn failure_source(&self) -> &'static str {
        "target"
    }

    #[must_use]
    pub const fn is_exposed(&self) -> bool {
        matches!(self, Self::PrivateIp | Self::TimedOut)
    }

    #[must_use]
    pub fn public_message(&self) -> String {
        if self.is_exposed() {
            self.to_string()
        } else {
            "Test failed. Please try again.".to_string()
        }
    }
}

async fn reverse_lookup(address: IpAddr, budget: Duration) -> Option<String> {
    if budget.is_zero() {
        return None;
    }
    let args = ["-x", &address.to_string(), "+short", "+tries=1"];
    let output = timeout(budget, Command::new("dig").args(args).output())
        .await
        .ok()?
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.trim_end_matches('.').to_string())
}

/// Resolve a measurement target to one public address of the requested family.
///
/// Literal IP targets are preserved and get a best-effort PTR hostname. Hostnames
/// are resolved through the system resolver before any measurement subprocess is
/// spawned, so a DNS answer cannot silently redirect the command into a private
/// range.
///
/// # Errors
/// Returns a target-scoped error for DNS timeout/failure, family mismatch, or a
/// private resolved address.
pub async fn resolve_command_target(
    target: &str,
    ip_version: u8,
    budget: Duration,
) -> Result<ResolvedTarget, ResolveTargetError> {
    if let Ok(address) = target.parse::<IpAddr>() {
        if is_ip_private(address) {
            return Err(ResolveTargetError::PrivateIp);
        }
        let hostname = reverse_lookup(address, budget.min(Duration::from_secs(2)))
            .await
            .unwrap_or_else(|| target.to_string());
        return Ok(ResolvedTarget { address, hostname });
    }

    let lookup = timeout(budget, lookup_host((target, 0)))
        .await
        .map_err(|_| ResolveTargetError::TimedOut)?
        .map_err(|error| ResolveTargetError::Lookup(error.to_string()))?;
    let address = lookup
        .map(|socket| socket.ip())
        .find(|address| {
            matches!(
                (ip_version, address),
                (4, IpAddr::V4(_)) | (6, IpAddr::V6(_))
            )
        })
        .ok_or(ResolveTargetError::NotFound)?;
    if is_ip_private(address) {
        return Err(ResolveTargetError::PrivateIp);
    }
    Ok(ResolvedTarget {
        address,
        hostname: target.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn private_literal_is_rejected_before_lookup() {
        let error = resolve_command_target("127.0.0.1", 4, Duration::from_secs(1))
            .await
            .expect_err("loopback must be rejected");
        assert!(matches!(error, ResolveTargetError::PrivateIp));
        assert_eq!(error.failure_source(), "target");
    }

    #[tokio::test]
    async fn public_literal_is_preserved() {
        let resolved = resolve_command_target("1.1.1.1", 4, Duration::from_millis(1))
            .await
            .expect("public literal should resolve without DNS");
        assert_eq!(resolved.address, "1.1.1.1".parse::<IpAddr>().unwrap());
    }
}
