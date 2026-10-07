//! Health accounting for diagnostic behavior shadows.
//!
//! Only failures that are attributable to the behavior component advance the
//! rollback streak. Host/native failures are recorded as inconclusive so an
//! unrelated machine/network problem cannot roll back a healthy component.

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
pub enum ShadowHealthEvent {
    Match,
    Divergence,
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

    pub fn observe(&mut self, sequence: u64, event: ShadowHealthEvent) -> HealthDecision {
        if self.snapshot.active_sequence != Some(sequence) {
            return HealthDecision::IgnoredStaleSequence;
        }

        match event {
            ShadowHealthEvent::Match => {
                self.snapshot.matches = self.snapshot.matches.saturating_add(1);
                self.snapshot.consecutive_faults = 0;
                self.rollback_recommended = false;
            }
            ShadowHealthEvent::Divergence => {
                self.snapshot.divergences = self.snapshot.divergences.saturating_add(1);
                self.snapshot.consecutive_faults =
                    self.snapshot.consecutive_faults.saturating_add(1);
            }
            ShadowHealthEvent::RuntimeFault => {
                self.snapshot.runtime_faults = self.snapshot.runtime_faults.saturating_add(1);
                self.snapshot.consecutive_faults =
                    self.snapshot.consecutive_faults.saturating_add(1);
            }
            ShadowHealthEvent::Inconclusive => {
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
    fn exact_matches_reset_the_fault_streak() {
        let mut health = BehaviorHealthState::new(policy(2), Some(7));
        assert_eq!(
            health.observe(7, ShadowHealthEvent::Divergence),
            HealthDecision::None
        );
        assert_eq!(health.snapshot().consecutive_faults, 1);
        assert_eq!(
            health.observe(7, ShadowHealthEvent::Match),
            HealthDecision::None
        );
        assert_eq!(health.snapshot().consecutive_faults, 0);
        assert_eq!(
            health.observe(7, ShadowHealthEvent::RuntimeFault),
            HealthDecision::None
        );
        assert_eq!(health.snapshot().consecutive_faults, 1);
    }

    #[test]
    fn inconclusive_errors_never_advance_the_fault_streak() {
        let mut health = BehaviorHealthState::new(policy(2), Some(8));
        assert_eq!(
            health.observe(8, ShadowHealthEvent::Divergence),
            HealthDecision::None
        );
        assert_eq!(
            health.observe(8, ShadowHealthEvent::Inconclusive),
            HealthDecision::None
        );
        assert_eq!(health.snapshot().consecutive_faults, 1);
        assert_eq!(health.snapshot().inconclusive, 1);
    }

    #[test]
    fn threshold_recommends_rollback_only_once_until_reset() {
        let mut health = BehaviorHealthState::new(policy(2), Some(9));
        assert_eq!(
            health.observe(9, ShadowHealthEvent::Divergence),
            HealthDecision::None
        );
        assert_eq!(
            health.observe(9, ShadowHealthEvent::RuntimeFault),
            HealthDecision::RollbackRecommended
        );
        assert_eq!(
            health.observe(9, ShadowHealthEvent::Divergence),
            HealthDecision::None
        );
        health.clear_rollback_recommendation();
        assert_eq!(
            health.observe(9, ShadowHealthEvent::Divergence),
            HealthDecision::RollbackRecommended
        );
    }

    #[test]
    fn stale_sequence_results_are_ignored() {
        let mut health = BehaviorHealthState::new(policy(1), Some(10));
        assert_eq!(
            health.observe(9, ShadowHealthEvent::Divergence),
            HealthDecision::IgnoredStaleSequence
        );
        assert_eq!(health.snapshot().consecutive_faults, 0);
        assert_eq!(health.snapshot().divergences, 0);
    }
}
