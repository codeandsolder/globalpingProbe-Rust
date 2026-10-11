//! Health accounting for behavior execution health.
//!
//! Only failures that are attributable to the behavior component advance the
//! rollback streak. A structurally valid component success resets that streak
//! immediately, before any native-oracle comparison finishes. Match/divergence
//! diagnostics are tracked separately and never mutate rollback state; this makes
//! late oracle results harmless. Host/native failures remain inconclusive so
//! unrelated machine/network problems cannot roll back a healthy component.

use std::num::NonZeroU32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BehaviorHealthPolicy {
    consecutive_faults_before_rollback: NonZeroU32,
}

impl Default for BehaviorHealthPolicy {
    fn default() -> Self {
        Self {
            consecutive_faults_before_rollback: NonZeroU32::MIN.saturating_add(2),
        }
    }
}

impl BehaviorHealthPolicy {
    #[must_use]
    pub const fn new(consecutive_faults_before_rollback: NonZeroU32) -> Self {
        Self {
            consecutive_faults_before_rollback,
        }
    }

    #[must_use]
    pub const fn consecutive_faults_before_rollback(self) -> NonZeroU32 {
        self.consecutive_faults_before_rollback
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorHealthEvent {
    Success,
    RuntimeFault,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthDecision {
    None,
    RollbackRecommended,
    IgnoredStaleSequence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorDiagnosticEvent {
    Match,
    Divergence,
    OracleFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticDecision {
    None,
    FirstDivergence,
    IgnoredStaleSequence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BehaviorHealthSnapshot {
    pub active_sequence: Option<u64>,
    pub consecutive_faults: u32,
    pub matches: u64,
    pub divergences: u64,
    pub runtime_faults: u64,
    pub inconclusive: u64,
}

#[derive(Debug)]
pub struct BehaviorHealthState {
    policy: BehaviorHealthPolicy,
    snapshot: BehaviorHealthSnapshot,
    rollback_recommended: bool,
}

impl BehaviorHealthState {
    #[must_use]
    pub const fn new(policy: BehaviorHealthPolicy, active_sequence: Option<u64>) -> Self {
        Self {
            policy,
            snapshot: BehaviorHealthSnapshot {
                active_sequence,
                consecutive_faults: 0,
                matches: 0,
                divergences: 0,
                runtime_faults: 0,
                inconclusive: 0,
            },
            rollback_recommended: false,
        }
    }

    #[must_use]
    pub const fn snapshot(&self) -> BehaviorHealthSnapshot {
        self.snapshot
    }

    pub const fn reset(&mut self, active_sequence: Option<u64>) {
        self.snapshot = BehaviorHealthSnapshot {
            active_sequence,
            consecutive_faults: 0,
            matches: 0,
            divergences: 0,
            runtime_faults: 0,
            inconclusive: 0,
        };
        self.rollback_recommended = false;
    }

    pub const fn clear_rollback_recommendation(&mut self) {
        self.rollback_recommended = false;
    }

    pub fn observe(&mut self, sequence: u64, event: BehaviorHealthEvent) -> HealthDecision {
        if self.snapshot.active_sequence != Some(sequence) {
            return HealthDecision::IgnoredStaleSequence;
        }

        match event {
            BehaviorHealthEvent::Success => {
                self.snapshot.consecutive_faults = 0;
                self.rollback_recommended = false;
            }
            BehaviorHealthEvent::RuntimeFault => {
                self.snapshot.runtime_faults = self.snapshot.runtime_faults.saturating_add(1);
                self.snapshot.consecutive_faults =
                    self.snapshot.consecutive_faults.saturating_add(1);
            }
            BehaviorHealthEvent::Inconclusive => {
                self.snapshot.inconclusive = self.snapshot.inconclusive.saturating_add(1);
            }
        }

        if !self.rollback_recommended
            && self.snapshot.consecutive_faults
                >= self.policy.consecutive_faults_before_rollback.get()
        {
            self.rollback_recommended = true;
            HealthDecision::RollbackRecommended
        } else {
            HealthDecision::None
        }
    }

    pub fn observe_diagnostic(
        &mut self,
        sequence: u64,
        event: BehaviorDiagnosticEvent,
    ) -> DiagnosticDecision {
        if self.snapshot.active_sequence != Some(sequence) {
            return DiagnosticDecision::IgnoredStaleSequence;
        }

        match event {
            BehaviorDiagnosticEvent::Match => {
                self.snapshot.matches = self.snapshot.matches.saturating_add(1);
                DiagnosticDecision::None
            }
            BehaviorDiagnosticEvent::Divergence => {
                self.snapshot.divergences = self.snapshot.divergences.saturating_add(1);
                if self.snapshot.divergences == 1 {
                    DiagnosticDecision::FirstDivergence
                } else {
                    DiagnosticDecision::None
                }
            }
            BehaviorDiagnosticEvent::OracleFailure => {
                self.snapshot.inconclusive = self.snapshot.inconclusive.saturating_add(1);
                DiagnosticDecision::None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(threshold: u32) -> BehaviorHealthPolicy {
        BehaviorHealthPolicy::new(
            NonZeroU32::new(threshold).unwrap_or_else(|| panic!("threshold must be non-zero")),
        )
    }

    #[test]
    fn valid_component_success_resets_the_fault_streak() {
        let mut health = BehaviorHealthState::new(policy(2), Some(7));
        assert_eq!(
            health.observe(7, BehaviorHealthEvent::RuntimeFault),
            HealthDecision::None
        );
        assert_eq!(health.snapshot().consecutive_faults, 1);
        assert_eq!(
            health.observe(7, BehaviorHealthEvent::Success),
            HealthDecision::None
        );
        assert_eq!(health.snapshot().consecutive_faults, 0);
        assert_eq!(
            health.observe(7, BehaviorHealthEvent::RuntimeFault),
            HealthDecision::None
        );
        assert_eq!(health.snapshot().consecutive_faults, 1);
    }

    #[test]
    fn late_oracle_diagnostics_never_mutate_the_fault_streak() {
        let mut health = BehaviorHealthState::new(policy(2), Some(8));
        assert_eq!(
            health.observe(8, BehaviorHealthEvent::RuntimeFault),
            HealthDecision::None
        );
        assert_eq!(health.snapshot().consecutive_faults, 1);
        assert_eq!(
            health.observe_diagnostic(8, BehaviorDiagnosticEvent::Divergence),
            DiagnosticDecision::FirstDivergence
        );
        assert_eq!(health.snapshot().consecutive_faults, 1);
        assert_eq!(
            health.observe_diagnostic(8, BehaviorDiagnosticEvent::Match),
            DiagnosticDecision::None
        );
        let snapshot = health.snapshot();
        assert_eq!(snapshot.consecutive_faults, 1);
        assert_eq!(snapshot.matches, 1);
        assert_eq!(snapshot.divergences, 1);
        assert_eq!(snapshot.runtime_faults, 1);
    }

    #[test]
    fn inconclusive_errors_never_advance_or_reset_the_fault_streak() {
        let mut health = BehaviorHealthState::new(policy(2), Some(9));
        assert_eq!(
            health.observe(9, BehaviorHealthEvent::RuntimeFault),
            HealthDecision::None
        );
        assert_eq!(
            health.observe(9, BehaviorHealthEvent::Inconclusive),
            HealthDecision::None
        );
        assert_eq!(health.snapshot().consecutive_faults, 1);
        assert_eq!(health.snapshot().inconclusive, 1);
    }

    #[test]
    fn oracle_failure_is_diagnostic_only() {
        let mut health = BehaviorHealthState::new(policy(2), Some(9));
        assert_eq!(
            health.observe(9, BehaviorHealthEvent::RuntimeFault),
            HealthDecision::None
        );
        assert_eq!(
            health.observe_diagnostic(9, BehaviorDiagnosticEvent::OracleFailure),
            DiagnosticDecision::None
        );
        let snapshot = health.snapshot();
        assert_eq!(snapshot.consecutive_faults, 1);
        assert_eq!(snapshot.inconclusive, 1);
    }

    #[test]
    fn runtime_fault_threshold_recommends_rollback_only_once_until_reset() {
        let mut health = BehaviorHealthState::new(policy(2), Some(10));
        assert_eq!(
            health.observe(10, BehaviorHealthEvent::RuntimeFault),
            HealthDecision::None
        );
        assert_eq!(
            health.observe(10, BehaviorHealthEvent::RuntimeFault),
            HealthDecision::RollbackRecommended
        );
        assert_eq!(
            health.observe(10, BehaviorHealthEvent::RuntimeFault),
            HealthDecision::None
        );
        health.clear_rollback_recommendation();
        assert_eq!(
            health.observe(10, BehaviorHealthEvent::RuntimeFault),
            HealthDecision::RollbackRecommended
        );
    }

    #[test]
    fn stale_sequence_health_and_diagnostics_are_ignored() {
        let mut health = BehaviorHealthState::new(policy(1), Some(11));
        assert_eq!(
            health.observe(10, BehaviorHealthEvent::Success),
            HealthDecision::IgnoredStaleSequence
        );
        assert_eq!(
            health.observe_diagnostic(10, BehaviorDiagnosticEvent::Divergence),
            DiagnosticDecision::IgnoredStaleSequence
        );
        assert_eq!(health.snapshot().consecutive_faults, 0);
        assert_eq!(health.snapshot().divergences, 0);
    }
}
