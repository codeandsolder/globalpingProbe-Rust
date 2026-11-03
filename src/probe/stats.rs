use anyhow::{Context, Result};
use serde::Serialize;
use tokio::time::{Duration, sleep};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTimes {
    total: u64,
    idle: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CpuLoad {
    pub usage: f64,
}

/// Parse per-logical-CPU counters from Linux `/proc/stat`.
#[must_use]
pub fn parse_proc_stat(input: &str) -> Vec<CpuTimes> {
    input
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            if !name.starts_with("cpu")
                || name == "cpu"
                || !name[3..].bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            let values: Vec<u64> = fields.filter_map(|field| field.parse().ok()).collect();
            if values.len() < 4 {
                return None;
            }
            let total = values.iter().take(8).copied().sum();
            let idle = values[3].saturating_add(values.get(4).copied().unwrap_or(0));
            Some(CpuTimes { total, idle })
        })
        .collect()
}

fn usage_percent(start: CpuTimes, end: CpuTimes) -> f64 {
    let total = end.total.saturating_sub(start.total);
    if total == 0 {
        return 0.0;
    }
    let idle = end.idle.saturating_sub(start.idle).min(total);
    let idle_basis_points =
        ((u128::from(idle) * 10_000 + u128::from(total / 2)) / u128::from(total)).min(10_000);
    let busy_basis_points = 10_000_u128.saturating_sub(idle_basis_points);
    let bounded = u32::try_from(busy_basis_points).unwrap_or(10_000);
    f64::from(bounded) / 100.0
}

async fn read_cpu_times() -> Result<Vec<CpuTimes>> {
    let stat = tokio::fs::read_to_string("/proc/stat")
        .await
        .context("failed to read /proc/stat")?;
    Ok(parse_proc_stat(&stat))
}

/// Sample per-CPU utilization over one second, matching the official probe's cadence.
///
/// # Errors
/// Returns an error when Linux CPU counters cannot be read.
pub async fn get_cpu_usage() -> Result<Vec<CpuLoad>> {
    let start = read_cpu_times().await?;
    sleep(Duration::from_secs(1)).await;
    let end = read_cpu_times().await?;
    Ok(start
        .into_iter()
        .zip(end)
        .map(|(before, after)| CpuLoad {
            usage: usage_percent(before, after),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_per_cpu_lines() {
        let input =
            "cpu  30 0 20 50 0 0 0 0\ncpu0 10 0 5 25 0 0 0 0\ncpu1 20 0 15 25 0 0 0 0\nintr 7\n";
        let parsed = parse_proc_stat(input);
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0],
            CpuTimes {
                total: 40,
                idle: 25
            }
        );
        assert_eq!(
            parsed[1],
            CpuTimes {
                total: 60,
                idle: 25
            }
        );
    }

    #[test]
    fn computes_usage_to_two_decimal_places() {
        let start = CpuTimes {
            total: 100,
            idle: 40,
        };
        let end = CpuTimes {
            total: 300,
            idle: 90,
        };
        assert_eq!(usage_percent(start, end), 75.0);
    }

    #[test]
    fn zero_delta_is_zero_usage() {
        let times = CpuTimes {
            total: 100,
            idle: 40,
        };
        assert_eq!(usage_percent(times, times), 0.0);
    }
}
