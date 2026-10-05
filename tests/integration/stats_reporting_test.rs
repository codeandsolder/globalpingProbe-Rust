/// Integration tests for measurement stats reporting and the timeout constant.
use globalping_probe::probe::{
    client::{MEASUREMENT_TIMEOUT, STATS_INTERVAL},
    stats::MeasurementStats,
};
use std::sync::Arc;
use tokio::time::Duration;

// ── MeasurementStats unit-level tests ─────────────────────────────────────────

#[test]
fn stats_initial_counts_are_zero() {
    let s = MeasurementStats::new();
    assert_eq!(s.started(), 0);
    assert_eq!(s.finished(), 0);
}

#[test]
fn stats_record_start_increments_started_only() {
    let s = MeasurementStats::new();
    s.record_start();
    assert_eq!(s.started(), 1);
    assert_eq!(s.finished(), 0);
}

#[test]
fn stats_record_finish_increments_finished_only() {
    let s = MeasurementStats::new();
    s.record_finish();
    assert_eq!(s.started(), 0);
    assert_eq!(s.finished(), 1);
}

#[test]
fn stats_take_returns_current_and_resets() {
    let s = MeasurementStats::new();
    s.record_start();
    s.record_start();
    s.record_finish();
    let (started, finished) = s.take();
    assert_eq!(started, 2);
    assert_eq!(finished, 1);
    assert_eq!(s.started(), 0);
    assert_eq!(s.finished(), 0);
}

#[test]
fn stats_take_on_zero_returns_zeros() {
    let s = MeasurementStats::new();
    assert_eq!(s.take(), (0, 0));
}

#[test]
fn stats_multiple_takes_are_independent() {
    let s = MeasurementStats::new();
    s.record_start();
    let first = s.take();
    assert_eq!(first, (1, 0));

    s.record_start();
    s.record_finish();
    let second = s.take();
    assert_eq!(second, (1, 1));

    assert_eq!(s.take(), (0, 0)); // third take is empty
}

#[test]
fn stats_start_and_finish_independence() {
    let s = MeasurementStats::new();
    for _ in 0..5 {
        s.record_start();
    }
    for _ in 0..3 {
        s.record_finish();
    }
    assert_eq!(s.started(), 5);
    assert_eq!(s.finished(), 3);
}

// ── Concurrent access ─────────────────────────────────────────────────────────

#[tokio::test]
async fn stats_shared_arc_accumulates_from_concurrent_tasks() {
    let s = MeasurementStats::new();
    let mut handles = vec![];
    for _ in 0..20 {
        let s2 = Arc::clone(&s);
        handles.push(tokio::spawn(async move {
            s2.record_start();
            s2.record_finish();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(s.started(), 20);
    assert_eq!(s.finished(), 20);
}

#[tokio::test]
async fn stats_take_while_writers_finish() {
    let s = MeasurementStats::new();
    for _ in 0..5 {
        s.record_start();
    }

    // Take a snapshot mid-way
    let (snapshot_started, _) = s.take();
    assert!(snapshot_started <= 5);

    // Add more after the take
    s.record_start();
    assert_eq!(s.started(), 1, "only post-take increment should be visible");
}

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn measurement_timeout_is_thirty_seconds() {
    assert_eq!(
        MEASUREMENT_TIMEOUT,
        Duration::from_secs(30),
        "hard measurement timeout must be 30 s"
    );
}

#[test]
fn stats_interval_is_sixty_seconds() {
    assert_eq!(
        STATS_INTERVAL,
        Duration::from_secs(60),
        "stats flush interval must be 60 s"
    );
}

// ── Timeout mechanics ─────────────────────────────────────────────────────────

#[tokio::test]
async fn timeout_fires_for_hanging_future() {
    let result = tokio::time::timeout(
        Duration::from_millis(10),
        tokio::time::sleep(Duration::from_secs(60)),
    )
    .await;
    assert!(result.is_err(), "should have timed out");
}

#[tokio::test]
async fn timeout_passes_for_fast_future() {
    let result = tokio::time::timeout(Duration::from_secs(5), async { 42u32 }).await;
    assert_eq!(result.unwrap(), 42);
}

#[tokio::test]
async fn timeout_wraps_result_value() {
    let r: Result<u32, _> = tokio::time::timeout(Duration::from_millis(50), async { 7u32 }).await;
    assert_eq!(r.unwrap(), 7);
}

/// Simulate what dispatch does: record_start, run with timeout,
/// record_finish regardless of outcome.
#[tokio::test]
async fn stats_recorded_on_timeout_path() {
    let s = MeasurementStats::new();

    s.record_start();
    let r = tokio::time::timeout(
        Duration::from_millis(5),
        tokio::time::sleep(Duration::from_secs(60)),
    )
    .await;
    let timed_out = r.is_err();
    s.record_finish(); // always called even on timeout

    assert!(timed_out);
    let (started, finished) = s.take();
    assert_eq!(started, 1);
    assert_eq!(finished, 1);
}

/// Simulate a measurement that completes before the timeout.
#[tokio::test]
async fn stats_recorded_on_success_path() {
    let s = MeasurementStats::new();

    s.record_start();
    let r = tokio::time::timeout(Duration::from_secs(5), async { "done" }).await;
    s.record_finish();

    assert_eq!(r.unwrap(), "done");
    let (started, finished) = s.take();
    assert_eq!(started, 1);
    assert_eq!(finished, 1);
}

// ── Stats + in-progress flag interaction ─────────────────────────────────────

#[test]
fn in_progress_flag_does_not_affect_stats_shape() {
    // stats counters are independent of whether in-progress streaming is used
    let s = MeasurementStats::new();
    s.record_start(); // in-progress path
    s.record_finish();
    s.record_start(); // non-progress path
    s.record_finish();
    let (started, finished) = s.take();
    assert_eq!(started, 2);
    assert_eq!(finished, 2);
}
