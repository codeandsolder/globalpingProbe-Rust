use std::time::{Duration, Instant};

use rand::random_range;
use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use tokio::{sync::watch, task::JoinHandle};
use tracing::{info, warn};

use super::client::VERSION;

const RELEASE_URL: &str =
    "https://data.jsdelivr.com/v1/packages/gh/jsdelivr/globalping-probe/resolved";
const UPDATE_INTERVAL: Duration = Duration::from_secs(300);
const UPDATE_MAX_DEVIATION: Duration = Duration::from_secs(300);
const UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_FAILED_UPDATE_WINDOW: Duration = Duration::from_hours(1);

const UPTIME_INTERVAL: Duration = Duration::from_secs(300);
const UPTIME_MAX_DEVIATION: Duration = Duration::from_hours(24);
const MAX_UPTIME: Duration = Duration::from_hours(168);

#[derive(Debug, Deserialize)]
struct ReleaseInfo {
    version: String,
}

pub struct LifecycleTasks {
    update: Option<JoinHandle<()>>,
    uptime: JoinHandle<()>,
}

impl LifecycleTasks {
    #[must_use]
    pub fn spawn(shutdown_tx: watch::Sender<bool>) -> Self {
        let update = (std::env::var("NODE_ENV").as_deref() != Ok("development")).then(|| {
            let shutdown_tx = shutdown_tx.clone();
            tokio::spawn(run_update_loop(shutdown_tx))
        });
        let uptime = tokio::spawn(run_uptime_loop(shutdown_tx));
        Self { update, uptime }
    }

    pub fn abort(self) {
        if let Some(update) = self.update {
            update.abort();
        }
        self.uptime.abort();
    }
}

fn randomized_interval(base: Duration, max_deviation: Duration) -> Duration {
    base + Duration::from_secs(random_range(0..=max_deviation.as_secs()))
}

fn newer_release(current: &str, candidate: &str) -> Result<Option<Version>, semver::Error> {
    let current = Version::parse(current.trim_start_matches('v'))?;
    let candidate = Version::parse(candidate.trim_start_matches('v'))?;
    Ok((candidate > current).then_some(candidate))
}

async fn fetch_release(client: &Client) -> Result<ReleaseInfo, reqwest::Error> {
    client
        .get(RELEASE_URL)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

async fn run_update_loop(shutdown_tx: watch::Sender<bool>) {
    let interval = randomized_interval(UPDATE_INTERVAL, UPDATE_MAX_DEVIATION);
    let client = match Client::builder().timeout(UPDATE_REQUEST_TIMEOUT).build() {
        Ok(client) => client,
        Err(error) => {
            warn!(target: "probe-self-update", %error, "Failed to create the probe update client.");
            return;
        }
    };
    let mut last_successful_check = Instant::now();

    loop {
        tokio::time::sleep(interval).await;
        match fetch_release(&client).await {
            Ok(release) => {
                last_successful_check = Instant::now();
                match newer_release(VERSION, &release.version) {
                    Ok(Some(latest)) => {
                        info!(
                            target: "probe-self-update",
                            latest_version = %latest,
                            current_version = VERSION,
                            "New probe version found. Starting self-update."
                        );
                        let _ = shutdown_tx.send(true);
                        return;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(
                            target: "probe-self-update",
                            release_version = release.version,
                            %error,
                            "The probe release endpoint returned an invalid version."
                        );
                    }
                }
            }
            Err(error) => {
                if last_successful_check.elapsed() >= MAX_FAILED_UPDATE_WINDOW {
                    warn!(
                        target: "probe-self-update",
                        "No successful update check in the last hour. Restarting the process."
                    );
                    let _ = shutdown_tx.send(true);
                    return;
                }
                if error.is_timeout() {
                    warn!(target: "probe-self-update", %error, "The request timed out while checking for a new probe version.");
                } else if let Some(status) = error.status() {
                    warn!(target: "probe-self-update", %error, %status, "The request failed with an HTTP error while checking for a new probe version.");
                } else {
                    warn!(target: "probe-self-update", %error, "The request failed while checking for a new probe version.");
                }
            }
        }
    }
}

async fn run_uptime_loop(shutdown_tx: watch::Sender<bool>) {
    let started = Instant::now();
    let interval = randomized_interval(UPTIME_INTERVAL, UPTIME_MAX_DEVIATION);
    loop {
        tokio::time::sleep(interval).await;
        if started.elapsed() >= MAX_UPTIME {
            info!(
                target: "general",
                max_uptime = MAX_UPTIME.as_secs(),
                "Scheduled Probe restart."
            );
            let _ = shutdown_tx.send(true);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_version_comparison_matches_expected_ordering() {
        assert_eq!(
            newer_release("0.53.0", "v0.54.0").expect("valid versions"),
            Some(Version::new(0, 54, 0))
        );
        assert_eq!(
            newer_release("0.53.0", "0.53.0").expect("valid versions"),
            None
        );
        assert_eq!(
            newer_release("0.53.0", "0.52.9").expect("valid versions"),
            None
        );
    }

    #[test]
    fn rejects_invalid_release_versions() {
        assert!(newer_release("0.53.0", "banana").is_err());
    }

    #[test]
    fn randomized_update_interval_stays_inside_upstream_window() {
        for _ in 0..64 {
            let interval = randomized_interval(UPDATE_INTERVAL, UPDATE_MAX_DEVIATION);
            assert!(interval >= Duration::from_secs(300));
            assert!(interval <= Duration::from_secs(600));
        }
    }

    #[test]
    fn randomized_uptime_interval_stays_inside_upstream_window() {
        for _ in 0..64 {
            let interval = randomized_interval(UPTIME_INTERVAL, UPTIME_MAX_DEVIATION);
            assert!(interval >= Duration::from_secs(300));
            assert!(interval <= Duration::from_secs(86_700));
        }
    }
}
