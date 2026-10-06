use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::util::private_ip::is_ip_private;

pub const MAX_RAW_EXECUTION_BYTES: usize = 64 * 1024;
pub const MAX_PROGRESS_JSON_BYTES: usize = 10_240;
pub const MAX_FINAL_JSON_BYTES: usize = 10_240;
pub const MAX_POLL_CALLS: u32 = 4_096;
pub const MAX_ENRICHMENT_LOOKUPS: u32 = 128;
pub const MAX_PROGRESS_EVENTS: u32 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapabilityToken {
    pub hi: u64,
    pub lo: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasurementKind {
    Ping,
    Dns,
    Traceroute,
    Mtr,
    Http,
}

impl MeasurementKind {
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "ping" => Some(Self::Ping),
            "dns" => Some(Self::Dns),
            "traceroute" => Some(Self::Traceroute),
            "mtr" => Some(Self::Mtr),
            "http" => Some(Self::Http),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    UnknownMeasurement,
    MissingTarget,
    InvalidTimeout,
    Expired,
    AlreadyStarted,
    NotStarted,
    UnknownAddress,
    PrivateAddress,
    RawOutputQuota,
    PollQuota,
    EnrichmentQuota,
    ProgressEventQuota,
    ProgressQuota,
    FinalResultQuota,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownMeasurement => "unknown measurement type",
            Self::MissingTarget => "measurement target is missing",
            Self::InvalidTimeout => "measurement timeout must be between 5 and 30 seconds",
            Self::Expired => "capability expired",
            Self::AlreadyStarted => "native execution already started",
            Self::NotStarted => "native execution has not started",
            Self::UnknownAddress => "address was not observed by this measurement",
            Self::PrivateAddress => "operation is not allowed for a private address",
            Self::RawOutputQuota => "raw execution output quota exceeded",
            Self::PollQuota => "native execution poll quota exceeded",
            Self::EnrichmentQuota => "measurement enrichment lookup quota exceeded",
            Self::ProgressEventQuota => "progress event quota exceeded",
            Self::ProgressQuota => "progress payload quota exceeded",
            Self::FinalResultQuota => "final result payload quota exceeded",
        })
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone)]
pub struct MeasurementScope {
    pub kind: MeasurementKind,
    pub target: String,
    pub timeout: Duration,
    /// Exact immutable server request. Native execution is derived from this
    /// value, never from guest-supplied argv/URL/socket parameters.
    pub measurement: Value,
}

impl MeasurementScope {
    /// Freeze a server-issued measurement into the capability scope.
    ///
    /// # Errors
    /// Returns a policy error when the measurement type or target is missing,
    /// or when its requested timeout is outside the supervisor's hard bounds.
    pub fn from_server_measurement(measurement: Value) -> Result<Self, PolicyError> {
        let kind = measurement
            .get("type")
            .and_then(Value::as_str)
            .and_then(MeasurementKind::from_str)
            .ok_or(PolicyError::UnknownMeasurement)?;
        let target = measurement
            .get("target")
            .and_then(Value::as_str)
            .filter(|target| !target.is_empty())
            .ok_or(PolicyError::MissingTarget)?
            .to_owned();
        let timeout = measurement
            .get("timeout")
            .and_then(Value::as_u64)
            .unwrap_or(30);
        if !(5..=30).contains(&timeout) {
            return Err(PolicyError::InvalidTimeout);
        }
        Ok(Self {
            kind,
            target,
            timeout: Duration::from_secs(timeout),
            measurement,
        })
    }
}

#[derive(Debug)]
pub struct CapabilityLease {
    pub token: CapabilityToken,
    pub scope: MeasurementScope,
    expires_at: Instant,
    started: bool,
    raw_bytes: usize,
    poll_calls: u32,
    enrichment_lookups: u32,
    progress_events: u32,
    observed_addresses: HashSet<IpAddr>,
}

impl CapabilityLease {
    #[must_use]
    pub fn new(token: CapabilityToken, scope: MeasurementScope, now: Instant) -> Self {
        let expires_at = now + scope.timeout + Duration::from_secs(2);
        Self {
            token,
            scope,
            expires_at,
            started: false,
            raw_bytes: 0,
            poll_calls: 0,
            enrichment_lookups: 0,
            progress_events: 0,
            observed_addresses: HashSet::new(),
        }
    }

    /// Authorize the single native execution owned by this capability.
    ///
    /// # Errors
    /// Returns an error when the lease expired or execution already started.
    pub fn authorize_start(&mut self, now: Instant) -> Result<(), PolicyError> {
        self.ensure_live(now)?;
        if self.started {
            return Err(PolicyError::AlreadyStarted);
        }
        self.started = true;
        Ok(())
    }

    /// Account and authorize one poll of the native execution.
    ///
    /// # Errors
    /// Returns an error when the lease is unusable or the poll quota is exhausted.
    pub fn authorize_poll(&mut self, now: Instant) -> Result<(), PolicyError> {
        self.ensure_live(now)?;
        if !self.started {
            return Err(PolicyError::NotStarted);
        }
        self.poll_calls = self
            .poll_calls
            .checked_add(1)
            .ok_or(PolicyError::PollQuota)?;
        if self.poll_calls > MAX_POLL_CALLS {
            return Err(PolicyError::PollQuota);
        }
        Ok(())
    }

    /// Account raw native output before exposing it to the behavior component.
    ///
    /// # Errors
    /// Returns an error when the lease is unusable or the cumulative byte quota
    /// would be exceeded.
    pub fn account_raw_bytes(&mut self, bytes: usize, now: Instant) -> Result<(), PolicyError> {
        self.ensure_live(now)?;
        if !self.started {
            return Err(PolicyError::NotStarted);
        }
        self.raw_bytes = self
            .raw_bytes
            .checked_add(bytes)
            .ok_or(PolicyError::RawOutputQuota)?;
        if self.raw_bytes > MAX_RAW_EXECUTION_BYTES {
            return Err(PolicyError::RawOutputQuota);
        }
        Ok(())
    }

    /// Record an address actually observed by the authorized native execution.
    ///
    /// # Errors
    /// Returns an error when the lease is expired or execution has not started.
    pub fn observe_address(&mut self, address: IpAddr, now: Instant) -> Result<(), PolicyError> {
        self.ensure_live(now)?;
        if !self.started {
            return Err(PolicyError::NotStarted);
        }
        self.observed_addresses.insert(address);
        Ok(())
    }

    /// Authorize PTR enrichment for an address observed by this measurement.
    ///
    /// # Errors
    /// Returns an error when the lease is unusable, the address was not observed,
    /// or the enrichment quota is exhausted.
    pub fn authorize_reverse_lookup(
        &mut self,
        address: IpAddr,
        now: Instant,
    ) -> Result<(), PolicyError> {
        self.ensure_observed(address, now)?;
        self.account_enrichment_lookup()
    }

    /// Authorize ASN enrichment for an observed public address.
    ///
    /// # Errors
    /// Returns an error when the lease is unusable, the address was not observed,
    /// the address is private, or the enrichment quota is exhausted.
    pub fn authorize_asn_lookup(
        &mut self,
        address: IpAddr,
        now: Instant,
    ) -> Result<(), PolicyError> {
        self.ensure_observed(address, now)?;
        if is_ip_private(address) {
            return Err(PolicyError::PrivateAddress);
        }
        self.account_enrichment_lookup()
    }

    /// Authorize one bounded progress payload emitted by the behavior component.
    ///
    /// # Errors
    /// Returns an error when the lease expired, the payload is too large, or the
    /// progress-event quota is exhausted. Rejected oversized payloads do not
    /// consume an event slot.
    pub fn authorize_progress(&mut self, json: &str, now: Instant) -> Result<(), PolicyError> {
        self.ensure_live(now)?;
        if json.len() > MAX_PROGRESS_JSON_BYTES {
            return Err(PolicyError::ProgressQuota);
        }
        self.progress_events = self
            .progress_events
            .checked_add(1)
            .ok_or(PolicyError::ProgressEventQuota)?;
        if self.progress_events > MAX_PROGRESS_EVENTS {
            return Err(PolicyError::ProgressEventQuota);
        }
        Ok(())
    }

    /// Authorize the final serialized result returned by the behavior component.
    ///
    /// # Errors
    /// Returns an error when the lease expired or the result exceeds the hard
    /// final-payload limit.
    pub fn authorize_final_result(&self, json: &str, now: Instant) -> Result<(), PolicyError> {
        self.ensure_live(now)?;
        if json.len() > MAX_FINAL_JSON_BYTES {
            return Err(PolicyError::FinalResultQuota);
        }
        Ok(())
    }

    fn ensure_observed(&self, address: IpAddr, now: Instant) -> Result<(), PolicyError> {
        self.ensure_live(now)?;
        if !self.started {
            return Err(PolicyError::NotStarted);
        }
        if !self.observed_addresses.contains(&address) {
            return Err(PolicyError::UnknownAddress);
        }
        Ok(())
    }

    fn account_enrichment_lookup(&mut self) -> Result<(), PolicyError> {
        self.enrichment_lookups = self
            .enrichment_lookups
            .checked_add(1)
            .ok_or(PolicyError::EnrichmentQuota)?;
        if self.enrichment_lookups > MAX_ENRICHMENT_LOOKUPS {
            return Err(PolicyError::EnrichmentQuota);
        }
        Ok(())
    }

    fn ensure_live(&self, now: Instant) -> Result<(), PolicyError> {
        if now > self.expires_at {
            Err(PolicyError::Expired)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ping_scope(timeout: u64) -> MeasurementScope {
        MeasurementScope::from_server_measurement(json!({
            "type": "ping",
            "target": "1.1.1.1",
            "protocol": "ICMP",
            "packets": 3,
            "ipVersion": 4,
            "timeout": timeout
        }))
        .unwrap_or_else(|error| panic!("fixture must be valid: {error}"))
    }

    #[test]
    fn server_request_becomes_immutable_scope() {
        let scope = ping_scope(10);
        assert_eq!(scope.kind, MeasurementKind::Ping);
        assert_eq!(scope.target, "1.1.1.1");
        assert_eq!(scope.timeout, Duration::from_secs(10));
        assert_eq!(scope.measurement["packets"], 3);
    }

    #[test]
    fn rejects_out_of_policy_timeout_before_wasm_sees_token() {
        let result = MeasurementScope::from_server_measurement(json!({
            "type": "ping",
            "target": "1.1.1.1",
            "timeout": 31
        }));
        assert_eq!(result.unwrap_err(), PolicyError::InvalidTimeout);
    }

    #[test]
    fn execution_can_start_only_once() {
        let now = Instant::now();
        let mut lease = CapabilityLease::new(CapabilityToken { hi: 1, lo: 2 }, ping_scope(10), now);
        assert_eq!(lease.authorize_start(now), Ok(()));
        assert_eq!(lease.authorize_start(now), Err(PolicyError::AlreadyStarted));
    }

    #[test]
    fn enrichment_is_limited_to_observed_addresses() {
        let now = Instant::now();
        let mut lease = CapabilityLease::new(CapabilityToken { hi: 1, lo: 2 }, ping_scope(10), now);
        lease
            .authorize_start(now)
            .unwrap_or_else(|error| panic!("{error}"));
        let observed: IpAddr = "1.1.1.1"
            .parse()
            .unwrap_or_else(|error| panic!("valid IP: {error}"));
        let invented: IpAddr = "8.8.8.8"
            .parse()
            .unwrap_or_else(|error| panic!("valid IP: {error}"));
        lease
            .observe_address(observed, now)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(lease.authorize_reverse_lookup(observed, now), Ok(()));
        assert_eq!(
            lease.authorize_reverse_lookup(invented, now),
            Err(PolicyError::UnknownAddress)
        );
    }

    #[test]
    fn private_observed_address_may_get_ptr_but_not_cymru_asn() {
        let now = Instant::now();
        let mut lease = CapabilityLease::new(CapabilityToken { hi: 1, lo: 2 }, ping_scope(10), now);
        lease
            .authorize_start(now)
            .unwrap_or_else(|error| panic!("{error}"));
        let gateway: IpAddr = "192.168.1.1"
            .parse()
            .unwrap_or_else(|error| panic!("valid IP: {error}"));
        lease
            .observe_address(gateway, now)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(lease.authorize_reverse_lookup(gateway, now), Ok(()));
        assert_eq!(
            lease.authorize_asn_lookup(gateway, now),
            Err(PolicyError::PrivateAddress)
        );
    }

    #[test]
    fn output_quotas_are_supervisor_enforced() {
        let now = Instant::now();
        let mut lease = CapabilityLease::new(CapabilityToken { hi: 1, lo: 2 }, ping_scope(10), now);
        lease
            .authorize_start(now)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            lease.account_raw_bytes(MAX_RAW_EXECUTION_BYTES, now),
            Ok(())
        );
        assert_eq!(
            lease.account_raw_bytes(1, now),
            Err(PolicyError::RawOutputQuota)
        );
        assert_eq!(
            lease.authorize_progress(&"x".repeat(MAX_PROGRESS_JSON_BYTES + 1), now),
            Err(PolicyError::ProgressQuota)
        );
        assert_eq!(
            lease.authorize_final_result(&"x".repeat(MAX_FINAL_JSON_BYTES + 1), now),
            Err(PolicyError::FinalResultQuota)
        );
    }

    #[test]
    fn rejected_progress_payload_does_not_consume_event_quota() {
        let now = Instant::now();
        let mut lease = CapabilityLease::new(CapabilityToken { hi: 1, lo: 2 }, ping_scope(10), now);
        assert_eq!(lease.authorize_start(now), Ok(()));

        assert_eq!(
            lease.authorize_progress(&"x".repeat(MAX_PROGRESS_JSON_BYTES + 1), now),
            Err(PolicyError::ProgressQuota)
        );
        assert_eq!(lease.progress_events, 0);
        for _ in 0..MAX_PROGRESS_EVENTS {
            assert_eq!(lease.authorize_progress("{}", now), Ok(()));
        }
        assert_eq!(
            lease.authorize_progress("{}", now),
            Err(PolicyError::ProgressEventQuota)
        );
    }

    #[test]
    fn host_call_counts_are_bounded_independently_of_payload_size() {
        let now = Instant::now();
        let mut lease = CapabilityLease::new(CapabilityToken { hi: 1, lo: 2 }, ping_scope(10), now);
        lease
            .authorize_start(now)
            .unwrap_or_else(|error| panic!("{error}"));

        for _ in 0..MAX_POLL_CALLS {
            assert_eq!(lease.authorize_poll(now), Ok(()));
        }
        assert_eq!(lease.authorize_poll(now), Err(PolicyError::PollQuota));

        let observed: IpAddr = "1.1.1.1"
            .parse()
            .unwrap_or_else(|error| panic!("valid IP: {error}"));
        lease
            .observe_address(observed, now)
            .unwrap_or_else(|error| panic!("{error}"));
        for _ in 0..MAX_ENRICHMENT_LOOKUPS {
            assert_eq!(lease.authorize_reverse_lookup(observed, now), Ok(()));
        }
        assert_eq!(
            lease.authorize_reverse_lookup(observed, now),
            Err(PolicyError::EnrichmentQuota)
        );

        for _ in 0..MAX_PROGRESS_EVENTS {
            assert_eq!(lease.authorize_progress("{}", now), Ok(()));
        }
        assert_eq!(
            lease.authorize_progress("{}", now),
            Err(PolicyError::ProgressEventQuota)
        );
    }

    #[test]
    fn expired_capability_cannot_be_reused() {
        let now = Instant::now();
        let mut lease = CapabilityLease::new(CapabilityToken { hi: 1, lo: 2 }, ping_scope(5), now);
        let late = now + Duration::from_secs(8);
        assert_eq!(lease.authorize_start(late), Err(PolicyError::Expired));
    }
}
