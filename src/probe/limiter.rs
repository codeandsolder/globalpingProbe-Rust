use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Maximum concurrent measurements the probe will run simultaneously.
/// Matches the Node.js probe's hard-coded limit.
pub const MAX_CONCURRENT: usize = 3;

/// A slot in the concurrent-measurement budget.  Dropping it releases the slot.
pub type MeasurementSlot = OwnedSemaphorePermit;

/// Token-bucket limiter: at most `capacity` measurements run at the same time.
/// Clone-able and cheap to share across tasks.
#[derive(Clone)]
pub struct MeasurementLimiter {
    semaphore: Arc<Semaphore>,
    capacity: usize,
}

impl MeasurementLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(MAX_CONCURRENT)
    }

    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(n)),
            capacity: n,
        }
    }

    /// Attempt to acquire a slot without blocking.
    /// Returns `Some(slot)` if capacity is available, `None` if full.
    #[must_use]
    pub fn try_acquire(&self) -> Option<MeasurementSlot> {
        Arc::clone(&self.semaphore).try_acquire_owned().ok()
    }

    /// Number of measurements currently running.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.capacity
            .saturating_sub(self.semaphore.available_permits())
    }

    /// Maximum simultaneous measurements.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Block until all in-flight measurements have released their slots.
    ///
    /// Implemented by acquiring *all* permits at once — this can only succeed
    /// when every slot has been returned, i.e. `in_flight() == 0`.  The permits
    /// are released immediately on return, so callers that start measurements
    /// afterwards will still be able to acquire slots normally.
    pub async fn wait_idle(&self) {
        let Ok(_guard) = self.semaphore.acquire_many(self.capacity as u32).await else {
            return;
        };
        // _guard dropped here, all permits returned
    }
}

impl Default for MeasurementLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_limiter_has_correct_capacity() {
        let lim = MeasurementLimiter::with_capacity(3);
        assert_eq!(lim.capacity(), 3);
        assert_eq!(lim.in_flight(), 0);
    }

    #[test]
    fn acquiring_slots_reduces_available() {
        let lim = MeasurementLimiter::with_capacity(3);
        let _s1 = lim.try_acquire().unwrap();
        assert_eq!(lim.in_flight(), 1);
        let _s2 = lim.try_acquire().unwrap();
        assert_eq!(lim.in_flight(), 2);
        let _s3 = lim.try_acquire().unwrap();
        assert_eq!(lim.in_flight(), 3);
    }

    #[test]
    fn try_acquire_returns_none_when_full() {
        let lim = MeasurementLimiter::with_capacity(2);
        let _s1 = lim.try_acquire().unwrap();
        let _s2 = lim.try_acquire().unwrap();
        assert!(lim.try_acquire().is_none(), "should be at capacity");
    }

    #[test]
    fn dropping_slot_restores_capacity() {
        let lim = MeasurementLimiter::with_capacity(1);
        {
            let _s = lim.try_acquire().unwrap();
            assert_eq!(lim.in_flight(), 1);
            assert!(lim.try_acquire().is_none());
        } // _s dropped here
        assert_eq!(lim.in_flight(), 0);
        assert!(lim.try_acquire().is_some(), "slot should be free again");
    }

    #[test]
    fn clone_shares_the_same_pool() {
        let lim1 = MeasurementLimiter::with_capacity(2);
        let lim2 = lim1.clone();
        let _s = lim1.try_acquire().unwrap();
        // Both views see the same in-flight count
        assert_eq!(lim2.in_flight(), 1);
        assert_eq!(lim2.capacity(), 2);
    }

    #[test]
    fn default_capacity_is_max_concurrent() {
        let lim = MeasurementLimiter::new();
        assert_eq!(lim.capacity(), MAX_CONCURRENT);
    }

    #[test]
    fn in_flight_saturates_at_zero() {
        // Artificially verify saturating_sub doesn't underflow
        let lim = MeasurementLimiter::with_capacity(2);
        assert_eq!(lim.in_flight(), 0);
    }

    #[tokio::test]
    async fn released_slot_is_immediately_reacquirable() {
        let lim = MeasurementLimiter::with_capacity(1);
        for _ in 0..10 {
            let s = lim
                .try_acquire()
                .expect("slot should be free at start of each iter");
            drop(s);
        }
    }
}
