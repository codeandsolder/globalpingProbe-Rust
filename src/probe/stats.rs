use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Tracks how many measurements were started and finished in the current
/// reporting window.  All methods are lock-free (atomic operations).
pub struct MeasurementStats {
    started: AtomicU64,
    finished: AtomicU64,
}

impl MeasurementStats {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: AtomicU64::new(0),
            finished: AtomicU64::new(0),
        })
    }

    pub fn record_start(&self) {
        self.started.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_finish(&self) {
        self.finished.fetch_add(1, Ordering::Relaxed);
    }

    pub fn started(&self) -> u64 {
        self.started.load(Ordering::Relaxed)
    }
    pub fn finished(&self) -> u64 {
        self.finished.load(Ordering::Relaxed)
    }

    /// Take a snapshot and reset both counters to zero atomically.
    pub fn take(&self) -> (u64, u64) {
        let s = self.started.swap(0, Ordering::Relaxed);
        let f = self.finished.swap(0, Ordering::Relaxed);
        (s, f)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_counts_are_zero() {
        let s = MeasurementStats::new();
        assert_eq!(s.started(), 0);
        assert_eq!(s.finished(), 0);
    }

    #[test]
    fn record_start_increments() {
        let s = MeasurementStats::new();
        s.record_start();
        s.record_start();
        assert_eq!(s.started(), 2);
        assert_eq!(s.finished(), 0);
    }

    #[test]
    fn record_finish_increments() {
        let s = MeasurementStats::new();
        s.record_start();
        s.record_finish();
        assert_eq!(s.started(), 1);
        assert_eq!(s.finished(), 1);
    }

    #[test]
    fn take_returns_snapshot_and_resets() {
        let s = MeasurementStats::new();
        s.record_start();
        s.record_start();
        s.record_finish();
        let (started, finished) = s.take();
        assert_eq!(started, 2);
        assert_eq!(finished, 1);
        // counters reset after take
        assert_eq!(s.started(), 0);
        assert_eq!(s.finished(), 0);
    }

    #[test]
    fn take_on_zero_returns_zeros() {
        let s = MeasurementStats::new();
        let (a, b) = s.take();
        assert_eq!(a, 0);
        assert_eq!(b, 0);
    }

    #[tokio::test]
    async fn shared_arc_accumulates_from_multiple_tasks() {
        let s = MeasurementStats::new();
        let mut handles = vec![];
        for _ in 0..10 {
            let s2 = Arc::clone(&s);
            handles.push(tokio::spawn(async move {
                s2.record_start();
                s2.record_finish();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(s.started(), 10);
        assert_eq!(s.finished(), 10);
    }

    #[test]
    fn second_take_after_new_activity() {
        let s = MeasurementStats::new();
        s.record_start();
        s.take(); // clears to 0
        s.record_start();
        s.record_start();
        let (started, _) = s.take();
        assert_eq!(started, 2);
    }
}
