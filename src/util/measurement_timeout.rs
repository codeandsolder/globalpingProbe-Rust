use std::time::{Duration, Instant};

pub const PROCESS_GRACE: Duration = Duration::from_secs(2);
const PING_INTERVAL: f64 = 0.5;
const PING_MIN_INTERVAL: f64 = 0.2;
const MTR_INTERVAL: f64 = 0.5;
const MTR_MIN_INTERVAL: f64 = 0.2;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PingBudget {
    pub interval: f64,
    pub response_timeout: f64,
    pub dns_headroom: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TracerouteBudget {
    pub wait: f64,
    pub dns_headroom: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MtrBudget {
    pub interval: f64,
    pub grace: f64,
    pub native_timeout: u64,
    pub dns_headroom: f64,
}

fn round_down(value: f64) -> f64 {
    ((value + 1e-9) * 100.0).floor() / 100.0
}

fn take_budget(remaining: &mut f64, requested: f64) -> f64 {
    let allocated = requested.clamp(0.0, remaining.max(0.0));
    *remaining -= allocated;
    allocated
}

fn ceil_native_timeout(value: f64) -> u64 {
    for candidate in 1_u32..=5 {
        if value <= f64::from(candidate) {
            return u64::from(candidate);
        }
    }
    5
}

#[must_use]
pub fn http_dns_timeout(timeout_seconds: u32) -> f64 {
    round_down((f64::from(timeout_seconds) * 0.4).max(2.0))
}

#[must_use]
pub fn ping_budget(
    packets: u8,
    timeout_seconds: u32,
    interval_override: Option<f64>,
) -> PingBudget {
    let minimum_dns_headroom = 1.0;
    let minimum_response_timeout = 1.0;
    let dns_headroom_share = 0.2;
    let preferred_dns_headroom_floor: f64 = 2.0;
    let preferred_response_timeout = 3.0;
    let maximum_response_timeout = 5.0;
    let target_interval = interval_override.unwrap_or(PING_INTERVAL);
    let packet_gaps = f64::from(packets.saturating_sub(1));
    let mut interval = interval_override.unwrap_or(if packet_gaps == 0.0 {
        target_interval
    } else {
        PING_MIN_INTERVAL
    });
    let mut remaining = packet_gaps.mul_add(-interval, f64::from(timeout_seconds));

    let mut dns_headroom = take_budget(&mut remaining, minimum_dns_headroom);
    let mut response_timeout = take_budget(&mut remaining, minimum_response_timeout);
    let preferred_dns_headroom =
        preferred_dns_headroom_floor.max(f64::from(timeout_seconds) * dns_headroom_share);
    dns_headroom += take_budget(&mut remaining, preferred_dns_headroom - dns_headroom);
    response_timeout += take_budget(
        &mut remaining,
        preferred_response_timeout - response_timeout,
    );

    let interval_upgrade = if interval_override.is_none() {
        target_interval - interval
    } else {
        0.0
    };
    let interval_upgrade_cost = packet_gaps * interval_upgrade;
    let response_upgrade = maximum_response_timeout - response_timeout;
    let combined_upgrade_cost = interval_upgrade_cost + response_upgrade;
    let progress = if combined_upgrade_cost == 0.0 {
        0.0
    } else {
        (remaining / combined_upgrade_cost).clamp(0.0, 1.0)
    };

    interval = interval_upgrade.mul_add(progress, interval);
    response_timeout = response_upgrade.mul_add(progress, response_timeout);
    remaining = combined_upgrade_cost.mul_add(-progress, remaining);
    dns_headroom += remaining.max(0.0);

    PingBudget {
        interval: round_down(interval),
        response_timeout: round_down(response_timeout),
        dns_headroom: round_down(dns_headroom),
    }
}

#[must_use]
pub fn traceroute_budget(timeout_seconds: u32, probe_waves: u8) -> TracerouteBudget {
    let maximum_wait: f64 = 5.0;
    let timeout = f64::from(timeout_seconds);
    let waves = f64::from(probe_waves.max(1));
    let wait = maximum_wait.min(round_down(timeout * 0.6 / waves));
    TracerouteBudget {
        wait,
        dns_headroom: round_down(waves.mul_add(-wait, timeout)),
    }
}

#[must_use]
pub fn mtr_budget(packets: u8, timeout_seconds: u32) -> MtrBudget {
    let minimum_response_timeout = 1.0;
    let preferred_response_timeout = 3.0;
    let maximum_response_timeout = 5.0;
    let preferred_dns_headroom_floor: f64 = 2.0;
    let dns_headroom_share = 0.2;
    let packet_gaps = f64::from(packets.saturating_sub(1));
    let mut interval = if packet_gaps == 0.0 {
        MTR_INTERVAL
    } else {
        MTR_MIN_INTERVAL
    };
    let mut response_timeout = minimum_response_timeout;
    let timeout = f64::from(timeout_seconds);
    let mut remaining = packet_gaps.mul_add(-interval, timeout - response_timeout);

    let preferred_dns = preferred_dns_headroom_floor.max(timeout * dns_headroom_share);
    let _reserved_dns = take_budget(&mut remaining, preferred_dns);
    response_timeout += take_budget(
        &mut remaining,
        preferred_response_timeout - response_timeout,
    );

    let interval_upgrade = MTR_INTERVAL - interval;
    interval += take_budget(&mut remaining, packet_gaps * interval_upgrade) / packet_gaps.max(1.0);
    response_timeout += take_budget(&mut remaining, maximum_response_timeout - response_timeout);

    interval = round_down(interval);
    response_timeout = round_down(response_timeout);
    let grace = round_down(response_timeout - interval);
    let native_timeout = ceil_native_timeout(response_timeout);
    let dns_headroom = round_down(f64::from(packets).mul_add(-interval, timeout - grace));

    MtrBudget {
        interval,
        grace,
        native_timeout,
        dns_headroom,
    }
}

#[must_use]
pub fn process_timeout(timeout_seconds: f64) -> Duration {
    Duration::from_secs_f64(timeout_seconds.max(0.0)).saturating_add(PROCESS_GRACE)
}

#[derive(Debug, Clone, Copy)]
pub struct MeasurementDeadline {
    deadline: Instant,
}

impl MeasurementDeadline {
    #[must_use]
    pub fn new(timeout_seconds: u32) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(u64::from(timeout_seconds)),
        }
    }

    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    #[must_use]
    pub fn process_timeout(&self) -> Duration {
        self.remaining().saturating_add(PROCESS_GRACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dns_budget_matches_upstream() {
        for (timeout, expected) in [(5, 2.0), (10, 4.0), (15, 6.0), (30, 12.0)] {
            assert_eq!(http_dns_timeout(timeout), expected);
        }
    }

    #[test]
    fn ping_examples_match_upstream() {
        for (packets, timeout, expected) in [
            (
                3,
                5,
                PingBudget {
                    interval: 0.2,
                    response_timeout: 2.6,
                    dns_headroom: 2.0,
                },
            ),
            (
                3,
                6,
                PingBudget {
                    interval: 0.26,
                    response_timeout: 3.46,
                    dns_headroom: 2.0,
                },
            ),
            (
                3,
                8,
                PingBudget {
                    interval: 0.5,
                    response_timeout: 5.0,
                    dns_headroom: 2.0,
                },
            ),
            (
                3,
                10,
                PingBudget {
                    interval: 0.5,
                    response_timeout: 5.0,
                    dns_headroom: 4.0,
                },
            ),
            (
                16,
                5,
                PingBudget {
                    interval: 0.2,
                    response_timeout: 1.0,
                    dns_headroom: 1.0,
                },
            ),
            (
                16,
                10,
                PingBudget {
                    interval: 0.29,
                    response_timeout: 3.61,
                    dns_headroom: 2.0,
                },
            ),
            (
                16,
                16,
                PingBudget {
                    interval: 0.5,
                    response_timeout: 5.0,
                    dns_headroom: 3.5,
                },
            ),
        ] {
            assert_eq!(ping_budget(packets, timeout, None), expected);
        }
        assert_eq!(
            ping_budget(6, 10, Some(1.0)),
            PingBudget {
                interval: 1.0,
                response_timeout: 3.0,
                dns_headroom: 2.0
            }
        );
    }

    #[test]
    fn every_ping_budget_fits_supported_range() {
        for timeout in 5..=30 {
            for packets in 1..=16 {
                let budget = ping_budget(packets, timeout, None);
                assert!((0.2..=0.5).contains(&budget.interval));
                assert!((1.0..=5.0).contains(&budget.response_timeout));
                assert!(budget.dns_headroom >= 1.0);
                let total = f64::from(packets - 1) * budget.interval
                    + budget.response_timeout
                    + budget.dns_headroom;
                assert!(
                    total <= timeout as f64 + 1e-9,
                    "packets={packets} timeout={timeout} {budget:?}"
                );
            }
        }
    }

    #[test]
    fn traceroute_examples_match_upstream() {
        for (timeout, waves, expected) in [
            (
                5,
                2,
                TracerouteBudget {
                    wait: 1.5,
                    dns_headroom: 2.0,
                },
            ),
            (
                5,
                4,
                TracerouteBudget {
                    wait: 0.75,
                    dns_headroom: 2.0,
                },
            ),
            (
                10,
                2,
                TracerouteBudget {
                    wait: 3.0,
                    dns_headroom: 4.0,
                },
            ),
            (
                10,
                3,
                TracerouteBudget {
                    wait: 2.0,
                    dns_headroom: 4.0,
                },
            ),
            (
                16,
                2,
                TracerouteBudget {
                    wait: 4.8,
                    dns_headroom: 6.4,
                },
            ),
            (
                17,
                2,
                TracerouteBudget {
                    wait: 5.0,
                    dns_headroom: 7.0,
                },
            ),
            (
                30,
                2,
                TracerouteBudget {
                    wait: 5.0,
                    dns_headroom: 20.0,
                },
            ),
        ] {
            assert_eq!(traceroute_budget(timeout, waves), expected);
        }
    }

    #[test]
    fn production_mtr_examples_fit_budget() {
        for (packets, timeout, expected) in [
            (
                3,
                5,
                MtrBudget {
                    interval: 0.2,
                    grace: 2.4,
                    native_timeout: 3,
                    dns_headroom: 2.0,
                },
            ),
            (
                3,
                10,
                MtrBudget {
                    interval: 0.5,
                    grace: 4.5,
                    native_timeout: 5,
                    dns_headroom: 4.0,
                },
            ),
            (
                16,
                5,
                MtrBudget {
                    interval: 0.2,
                    grace: 0.8,
                    native_timeout: 1,
                    dns_headroom: 1.0,
                },
            ),
            (
                16,
                10,
                MtrBudget {
                    interval: 0.33,
                    grace: 2.67,
                    native_timeout: 3,
                    dns_headroom: 2.05,
                },
            ),
            (
                16,
                16,
                MtrBudget {
                    interval: 0.5,
                    grace: 4.5,
                    native_timeout: 5,
                    dns_headroom: 3.5,
                },
            ),
        ] {
            assert_eq!(mtr_budget(packets, timeout), expected);
        }
    }

    #[test]
    fn every_production_mtr_budget_fits_supported_range() {
        for timeout in 5..=30 {
            for packets in 1..=16 {
                let budget = mtr_budget(packets, timeout);
                assert!((0.2..=0.5).contains(&budget.interval));
                assert!((0.5..=5.0).contains(&budget.grace));
                assert!(budget.native_timeout >= 1);
                assert!(budget.dns_headroom >= 1.0);
                let total =
                    f64::from(packets) * budget.interval + budget.grace + budget.dns_headroom;
                assert!(
                    total <= timeout as f64 + 1e-9,
                    "packets={packets} timeout={timeout} {budget:?}"
                );
            }
        }
    }

    #[test]
    fn process_timeout_adds_two_second_grace() {
        assert_eq!(process_timeout(5.0), Duration::from_secs(7));
        assert_eq!(process_timeout(14.999), Duration::from_millis(16_999));
    }
}
