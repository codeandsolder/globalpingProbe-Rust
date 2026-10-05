use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;

#[derive(Default)]
struct Inner {
    count: AtomicUsize,
    idle: Notify,
}

/// Tracks currently active measurements without imposing a local concurrency cap.
///
/// Current upstream accepts every measurement while the probe is `ready` and uses
/// its active-job map only for stats reporting and graceful shutdown. This mirrors
/// that behavior while keeping lifetime tracking RAII-safe.
#[derive(Clone, Default)]
pub struct ActiveJobs {
    inner: Arc<Inner>,
}

impl ActiveJobs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one active measurement. Dropping the returned guard completes it.
    #[must_use]
    pub fn start(&self) -> ActiveJob {
        self.inner.count.fetch_add(1, Ordering::AcqRel);
        ActiveJob {
            inner: Arc::clone(&self.inner),
        }
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.inner.count.load(Ordering::Acquire)
    }

    /// Wait until all active measurement guards have been dropped.
    pub async fn wait_idle(&self) {
        loop {
            let notified = self.inner.idle.notified();
            if self.count() == 0 {
                return;
            }
            notified.await;
        }
    }
}

pub struct ActiveJob {
    inner: Arc<Inner>,
}

impl Drop for ActiveJob {
    fn drop(&mut self) {
        let previous = self.inner.count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "active-job counter underflow");
        if previous == 1 {
            self.inner.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_zero() {
        assert_eq!(ActiveJobs::new().count(), 0);
    }

    #[test]
    fn guards_track_active_jobs() {
        let jobs = ActiveJobs::new();
        let first = jobs.start();
        let second = jobs.start();
        assert_eq!(jobs.count(), 2);
        drop(first);
        assert_eq!(jobs.count(), 1);
        drop(second);
        assert_eq!(jobs.count(), 0);
    }

    #[tokio::test]
    async fn wait_idle_waits_for_last_guard() {
        let jobs = ActiveJobs::new();
        let job = jobs.start();
        let waiter = {
            let jobs = jobs.clone();
            tokio::spawn(async move { jobs.wait_idle().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(job);
        waiter.await.unwrap();
    }
}
