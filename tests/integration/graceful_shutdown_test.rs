use globalping_probe::probe::{
    client::{RESTART_DRAIN_TIMEOUT, SIGTERM_DRAIN_TIMEOUT},
    jobs::ActiveJobs,
};
use tokio::time::Duration;

#[tokio::test]
async fn wait_idle_returns_immediately_when_no_jobs_are_active() {
    let jobs = ActiveJobs::new();
    tokio::time::timeout(Duration::from_millis(100), jobs.wait_idle())
        .await
        .expect("idle tracker should return immediately");
}

#[tokio::test]
async fn wait_idle_blocks_until_all_jobs_finish() {
    let jobs = ActiveJobs::new();
    let first = jobs.start();
    let second = jobs.start();

    let waiter = {
        let jobs = jobs.clone();
        tokio::spawn(async move { jobs.wait_idle().await })
    };
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    drop(first);
    assert!(!waiter.is_finished());
    drop(second);
    waiter.await.unwrap();
}

#[tokio::test]
async fn drain_timeout_can_bound_a_stuck_job() {
    let jobs = ActiveJobs::new();
    let _stuck = jobs.start();
    let result = tokio::time::timeout(Duration::from_millis(20), jobs.wait_idle()).await;
    assert!(result.is_err());
    assert_eq!(jobs.count(), 1);
}

#[test]
fn shutdown_budgets_match_current_upstream() {
    assert_eq!(SIGTERM_DRAIN_TIMEOUT, Duration::from_secs(60));
    assert_eq!(RESTART_DRAIN_TIMEOUT, Duration::from_secs(40));
}
