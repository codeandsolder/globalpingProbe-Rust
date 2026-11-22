use globalping_probe::probe::{client::STATS_INTERVAL, jobs::ActiveJobs, stats::parse_proc_stat};
use tokio::time::Duration;

#[test]
fn stats_interval_matches_current_upstream() {
    assert_eq!(STATS_INTERVAL, Duration::from_secs(10));
}

#[test]
fn proc_stat_parser_reports_one_entry_per_logical_cpu() {
    let sample =
        "cpu  100 0 50 850 0 0 0 0\ncpu0 50 0 25 425 0 0 0 0\ncpu1 50 0 25 425 0 0 0 0\nintr 123\n";
    assert_eq!(parse_proc_stat(sample).len(), 2);
}

#[test]
fn stats_job_count_comes_from_active_jobs() {
    let jobs = ActiveJobs::new();
    let first = jobs.start();
    let second = jobs.start();
    assert_eq!(jobs.count(), 2);
    drop(first);
    assert_eq!(jobs.count(), 1);
    drop(second);
    assert_eq!(jobs.count(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn live_cpu_sample_has_entries_and_sane_percentages() {
    let load = globalping_probe::probe::stats::get_cpu_usage()
        .await
        .expect("/proc/stat should be readable on Linux");
    assert!(!load.is_empty());
    assert!(load.iter().all(|cpu| (0.0..=100.0).contains(&cpu.usage)));
}
