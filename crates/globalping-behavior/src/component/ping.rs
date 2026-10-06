use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use serde::Serialize;

use super::codeandsolder::globalping_behavior::host::{CapabilityToken, MeasurementKind};
use super::execution::{self, NativeExecution};
use super::exports::codeandsolder::globalping_behavior::guest::BehaviorError;

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Finished,
    Failed,
}

#[derive(Debug, Serialize)]
struct Timing {
    rtt: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

#[derive(Debug, Default, Serialize)]
struct Stats {
    min: Option<f64>,
    max: Option<f64>,
    avg: Option<f64>,
    total: Option<u32>,
    loss: Option<f64>,
    rcv: Option<u32>,
    drop: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultPayload {
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_source: Option<String>,
    raw_output: String,
    resolved_address: Option<String>,
    resolved_hostname: Option<String>,
    timings: Vec<Timing>,
    stats: Stats,
}

fn parse_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.split_once(marker).map(|(_, tail)| tail)
}

fn parse_number_prefix<T: core::str::FromStr>(text: &str) -> Option<T> {
    let token = text
        .trim_start()
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .next()?;
    if token.is_empty() {
        return None;
    }
    token.parse().ok()
}

fn header_address(raw: &str) -> Option<String> {
    let header = raw.lines().next()?;
    let mut rest = header;
    let mut candidate = None;
    while let Some(open) = rest.find('(') {
        rest = &rest[open + 1..];
        let Some(close) = rest.find(')') else { break };
        let value = &rest[..close];
        if value.contains('.') || value.contains(':') {
            candidate = Some(value.to_string());
        }
        rest = &rest[close + 1..];
    }
    candidate
}

fn normalize(raw: &str, target: &str, address: Option<&str>) -> String {
    let Some(address) = address else {
        return raw.to_string();
    };
    if address == target {
        return raw.to_string();
    }

    raw.lines()
        .map(|line| {
            let numeric_header = format!("PING {address} ({address})");
            if line.starts_with(&numeric_header) {
                line.replacen(&numeric_header, &format!("PING {target} ({address})"), 1)
            } else {
                let bytes_from = format!(" bytes from {address}:");
                let from_prefix = format!("From {address} ");
                if line.contains(&bytes_from) {
                    line.replacen(
                        &bytes_from,
                        &format!(" bytes from {target} ({address}):"),
                        1,
                    )
                } else if line.starts_with(&from_prefix) {
                    line.replacen(&from_prefix, &format!("From {target} ({address}) "), 1)
                } else if line == format!("--- {address} ping statistics ---") {
                    format!("--- {target} ping statistics ---")
                } else {
                    line.to_string()
                }
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_timing(line: &str) -> Option<Timing> {
    let rtt = parse_after(line, "time=").and_then(parse_number_prefix::<f64>)?;
    let ttl = parse_after(line, "ttl=").and_then(parse_number_prefix::<u32>);
    Some(Timing { rtt, ttl })
}

fn parse_stats(raw: &str) -> Stats {
    let mut stats = Stats::default();
    for line in raw.lines() {
        if line.contains("packets transmitted") {
            stats.total = parse_number_prefix(line);
            if let Some((_, tail)) = line.split_once(',') {
                stats.rcv = parse_number_prefix(tail);
            }
            stats.loss = line
                .split(',')
                .find(|part| part.contains("packet loss"))
                .and_then(|part| part.split('%').next())
                .and_then(|part| part.split_whitespace().last())
                .and_then(|value| value.parse().ok());
            stats.drop = match (stats.total, stats.rcv) {
                (Some(total), Some(received)) => Some(total.saturating_sub(received)),
                _ => None,
            };
        } else if line.contains("min/avg/max")
            && let Some((_, values)) = line.split_once('=')
        {
            let mut numbers = values.trim().split('/').filter_map(|value| {
                value
                    .split_whitespace()
                    .next()
                    .and_then(|number| number.parse::<f64>().ok())
            });
            stats.min = numbers.next();
            stats.avg = numbers.next();
            stats.max = numbers.next();
        }
    }
    stats
}

fn shape(native: &NativeExecution) -> ResultPayload {
    let header_address = header_address(&native.stdout);
    let normalized = normalize(
        &native.stdout,
        &native.resolved_hostname,
        Some(&native.resolved_address),
    );
    let timings = normalized
        .lines()
        .filter_map(parse_timing)
        .collect::<Vec<_>>();
    let stats = parse_stats(&normalized);
    let parsed = !normalized.is_empty() && header_address.is_some();
    let failure_source = if native.timed_out {
        Some(
            if timings.is_empty()
                && (normalized.contains("no answer yet for ")
                    || normalized.contains("100% packet loss"))
            {
                "target"
            } else {
                "internal"
            }
            .to_string(),
        )
    } else if !parsed {
        Some("internal".to_string())
    } else {
        None
    };

    ResultPayload {
        status: if failure_source.is_some() {
            Status::Failed
        } else {
            Status::Finished
        },
        failure_source,
        raw_output: normalized.trim_end_matches('\n').to_string(),
        resolved_address: Some(native.resolved_address.clone()),
        resolved_hostname: Some(native.resolved_hostname.clone()),
        timings,
        stats,
    }
}

pub fn run(
    token: &CapabilityToken,
    in_progress_updates: bool,
    tcp_progress: bool,
) -> Result<String, BehaviorError> {
    let native = execution::collect(token, MeasurementKind::Ping, |line, all, start| {
        if !in_progress_updates {
            return Ok(());
        }
        let progress = if tcp_progress {
            if !line.contains("tcp_conn=") {
                return Ok(());
            }
            normalize(all, &start.resolved_hostname, Some(&start.resolved_address))
        } else {
            let mut line = normalize(
                line,
                &start.resolved_hostname,
                Some(&start.resolved_address),
            );
            line.push('\n');
            line
        };
        let payload = serde_json::to_string(&serde_json::json!({ "rawOutput": progress }))
            .map_err(|error| BehaviorError::Internal(error.to_string()))?;
        execution::emit_progress(token, &payload, false)
    })?;
    let payload = shape(&native);
    serde_json::to_string(&payload).map_err(|error| BehaviorError::Internal(error.to_string()))
}

pub fn self_test() -> Result<(), String> {
    let native = NativeExecution {
        resolved_address: "1.1.1.1".to_string(),
        resolved_hostname: "one.one.one.one".to_string(),
        target_is_icann: true,
        local_addresses: Vec::new(),
        stdout: "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=41.7 ms\n\n--- 1.1.1.1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 1003ms\nrtt min/avg/max/mdev = 41.700/41.700/41.700/0.000 ms\n".to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        timed_out: false,
    };
    let parsed = shape(&native);
    if !matches!(parsed.status, Status::Finished)
        || parsed.resolved_address.as_deref() != Some("1.1.1.1")
        || parsed.resolved_hostname.as_deref() != Some("one.one.one.one")
        || parsed.timings.len() != 1
        || parsed.timings[0].ttl != Some(58)
        || (parsed.timings[0].rtt - 41.7).abs() > f64::EPSILON
        || parsed.stats.total != Some(1)
        || parsed.stats.rcv != Some(1)
        || parsed.stats.loss != Some(0.0)
    {
        return Err("ping behavior parser self-test failed".to_string());
    }
    Ok(())
}
