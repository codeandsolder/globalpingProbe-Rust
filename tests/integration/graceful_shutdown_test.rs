/// Integration tests for graceful-shutdown drain behaviour.
/// Verifies that `MeasurementLimiter::wait_idle` correctly blocks until all
/// in-flight slots are released and that the drain-timeout constant is sane.
use globalping_probe::probe::{client::DRAIN_TIMEOUT, limiter::MeasurementLimiter};
use tokio::time::Duration;

// ── wait_idle — no slots held ─────────────────────────────────────────────────

#[tokio::test]
async fn wait_idle_returns_immediately_when_no_slots_taken() {
    let lim = MeasurementLimiter::with_capacity(3);
    // Should complete well within 100 ms when idle.
    tokio::time::timeout(Duration::from_millis(100), lim.wait_idle())
        .await
        .expect("wait_idle should return immediately when no slots are held");
}

#[tokio::test]
async fn wait_idle_returns_immediately_after_slot_released() {
    let lim = MeasurementLimiter::with_capacity(2);
    let slot = lim.try_acquire().unwrap();
    drop(slot); // release before waiting
    tokio::time::timeout(Duration::from_millis(100), lim.wait_idle())
        .await
        .expect("wait_idle should return immediately once slot is released");
}

// ── wait_idle — slots still held ─────────────────────────────────────────────

#[tokio::test]
async fn wait_idle_blocks_while_slot_is_held() {
    let lim = MeasurementLimiter::with_capacity(1);
    let slot = lim.try_acquire().unwrap();

    // wait_idle should NOT complete while slot is held.
    let result = tokio::time::timeout(Duration::from_millis(50), lim.wait_idle()).await;
    assert!(
        result.is_err(),
        "wait_idle should block while a slot is held"
    );

    drop(slot);
    // Now it should complete.
    tokio::time::timeout(Duration::from_millis(100), lim.wait_idle())
        .await
        .expect("wait_idle should complete after slot is released");
}

#[tokio::test]
async fn wait_idle_blocks_until_all_slots_released() {
    let lim = MeasurementLimiter::with_capacity(3);
    let s1 = lim.try_acquire().unwrap();
    let s2 = lim.try_acquire().unwrap();
    let s3 = lim.try_acquire().unwrap();

    let result = tokio::time::timeout(Duration::from_millis(30), lim.wait_idle()).await;
    assert!(result.is_err(), "should block while all 3 slots held");

    drop(s1);
    drop(s2);
    // Still one slot held
    let result = tokio::time::timeout(Duration::from_millis(30), lim.wait_idle()).await;
    assert!(result.is_err(), "should still block with 1 slot remaining");

    drop(s3);
    // All released now
    tokio::time::timeout(Duration::from_millis(100), lim.wait_idle())
        .await
        .expect("should complete once all slots released");
}

// ── wait_idle across clones ───────────────────────────────────────────────────

#[tokio::test]
async fn wait_idle_on_clone_sees_shared_slots() {
    let lim1 = MeasurementLimiter::with_capacity(2);
    let lim2 = lim1.clone();

    let slot = lim1.try_acquire().unwrap(); // acquired via lim1

    // lim2.wait_idle() should block because lim1's slot is still held
    let result = tokio::time::timeout(Duration::from_millis(30), lim2.wait_idle()).await;
    assert!(result.is_err(), "clone should see the same semaphore state");

    drop(slot);
    tokio::time::timeout(Duration::from_millis(100), lim2.wait_idle())
        .await
        .expect("should complete after slot released on sibling clone");
}

// ── Async drain simulation ────────────────────────────────────────────────────

/// Simulate the real shutdown pattern: a "measurement" task holds a slot while
/// running, the drain waits for it to finish, and completes successfully.
#[tokio::test]
async fn drain_completes_after_background_measurement_finishes() {
    let lim = MeasurementLimiter::with_capacity(3);
    let lim_worker = lim.clone();

    // Spawn a fake measurement that holds a slot for 50 ms then releases it.
    tokio::spawn(async move {
        let _slot = lim_worker.try_acquire().expect("slot should be free");
        tokio::time::sleep(Duration::from_millis(50)).await;
        // _slot dropped here
    });

    // Give the spawn a moment to actually acquire the slot.
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(lim.in_flight(), 1);

    // Drain with a generous timeout — should succeed once the 50ms sleep ends.
    tokio::time::timeout(Duration::from_millis(500), lim.wait_idle())
        .await
        .expect("drain should complete after measurement finishes");

    assert_eq!(lim.in_flight(), 0);
}

/// Drain timeout fires when a measurement takes longer than the budget.
#[tokio::test]
async fn drain_timeout_fires_when_measurement_too_slow() {
    let lim = MeasurementLimiter::with_capacity(1);
    let lim_worker = lim.clone();

    // Hold the slot for 500 ms — longer than our 30 ms drain budget.
    tokio::spawn(async move {
        let _slot = lim_worker.try_acquire().expect("slot should be free");
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    tokio::time::sleep(Duration::from_millis(5)).await;

    let drained = tokio::time::timeout(Duration::from_millis(30), lim.wait_idle()).await;
    assert!(
        drained.is_err(),
        "drain timeout should fire before slow measurement finishes"
    );
    assert_eq!(lim.in_flight(), 1, "slot still held after timeout");
}

/// Multiple concurrent measurements all drain within the budget.
#[tokio::test]
async fn drain_waits_for_all_concurrent_measurements() {
    let lim = MeasurementLimiter::with_capacity(3);

    for i in 0..3u64 {
        let lw = lim.clone();
        tokio::spawn(async move {
            let _slot = lw.try_acquire().expect("slot free");
            tokio::time::sleep(Duration::from_millis(20 + i * 10)).await;
        });
    }

    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(lim.in_flight(), 3);

    // All 3 should finish within 200 ms (longest is 40 ms).
    tokio::time::timeout(Duration::from_millis(200), lim.wait_idle())
        .await
        .expect("all measurements should drain within budget");

    assert_eq!(lim.in_flight(), 0);
}

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn drain_timeout_constant_is_reasonable() {
    assert!(
        DRAIN_TIMEOUT >= Duration::from_secs(1),
        "drain timeout must be at least 1 s to allow measurements to finish"
    );
    assert!(
        DRAIN_TIMEOUT <= Duration::from_secs(30),
        "drain timeout must not exceed 30 s to avoid slow shutdowns"
    );
}

#[test]
fn drain_timeout_is_five_seconds() {
    assert_eq!(DRAIN_TIMEOUT, Duration::from_secs(5));
}
