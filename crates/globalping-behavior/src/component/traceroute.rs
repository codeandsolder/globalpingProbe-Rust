use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;

use serde::Serialize;

use super::codeandsolder::globalping_behavior::host::{CapabilityToken, MeasurementKind};
use super::execution::{self, NativeExecution};
use super::exports::codeandsolder::globalping_behavior::guest::BehaviorError;
use super::ip::is_private_or_reserved;

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Finished,
    Failed,
}

#[derive(Debug, Serialize)]
struct HopTiming {
    rtt: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Hop {
    resolved_address: Option<String>,
    resolved_hostname: Option<String>,
    timings: Vec<HopTiming>,
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
    hops: Vec<Hop>,
}

fn header_address(raw: &str) -> Option<String> {
    let header = raw.lines().next()?;
    let open = header.find('(')?;
    let tail = &header[open + 1..];
    let close = tail.find(')')?;
    let value = &tail[..close];
    value
        .parse::<IpAddr>()
        .ok()
        .map(|address| address.to_string())
}

fn ip_tokens(line: &str) -> Vec<String> {
    line.split_whitespace()
        .filter_map(|token| {
            let clean = token.trim_matches(|ch| matches!(ch, '(' | ')' | ',' | '[' | ']'));
            clean
                .parse::<IpAddr>()
                .ok()
                .map(|address| address.to_string())
        })
        .collect()
}

fn normalize_with<F>(raw: &str, target: &str, mut lookup: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    let address = header_address(raw);
    let mut lines = raw.lines();
    let Some(first) = lines.next() else {
        return String::new();
    };
    let header = address.as_deref().map_or_else(
        || first.to_string(),
        |address| {
            let numeric = format!("traceroute to {address} ({address})");
            first.replacen(&numeric, &format!("traceroute to {target} ({address})"), 1)
        },
    );
    let mut output = Vec::new();
    output.push(header);

    for (index, line) in lines.enumerate() {
        let mut normalized = line.to_string();
        for ip in ip_tokens(line) {
            let hostname = if index == 0 {
                "_gateway".to_string()
            } else if address.as_deref() == Some(ip.as_str()) {
                target.to_string()
            } else {
                lookup(&ip).unwrap_or_else(|| ip.clone())
            };
            normalized = normalized.replacen(&ip, &format!("{hostname} ({ip})"), 1);
        }
        output.push(normalized);
    }
    output.join("\n")
}

fn host_pair(line: &str) -> (Option<String>, Option<String>) {
    let Some(open) = line.find('(') else {
        return (None, None);
    };
    let tail = &line[open + 1..];
    let Some(close) = tail.find(')') else {
        return (None, None);
    };
    let address = &tail[..close];
    if address.parse::<IpAddr>().is_err() {
        return (None, None);
    }
    let before = line[..open].trim_end();
    let hostname = before.split_whitespace().last().map(ToString::to_string);
    (Some(address.to_string()), hostname)
}

fn timings(line: &str) -> Vec<HopTiming> {
    let words = line.split_whitespace().collect::<Vec<_>>();
    words
        .windows(2)
        .filter_map(|pair| {
            if pair[1] != "ms" {
                return None;
            }
            pair[0].parse().ok().map(|rtt| HopTiming { rtt })
        })
        .collect()
}

fn parse_hops(normalized: &str) -> Vec<Hop> {
    normalized
        .lines()
        .skip(1)
        .map(|line| {
            let (resolved_address, resolved_hostname) = host_pair(line);
            Hop {
                resolved_address,
                resolved_hostname,
                timings: timings(line),
            }
        })
        .collect()
}

fn has_upstream_unreachable(output: &str) -> bool {
    output.split_whitespace().any(|token| {
        matches!(token, "!N" | "!H" | "!P" | "!X" | "!S" | "!F" | "!V" | "!C")
            || token.strip_prefix('!').is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
    })
}

fn shape<F>(native: NativeExecution, lookup: F) -> ResultPayload
where
    F: FnMut(&str) -> Option<String>,
{
    let parsed_header_address = header_address(&native.stdout);
    let normalized = normalize_with(&native.stdout, &native.resolved_hostname, lookup);
    let mut hops = parse_hops(&normalized);
    let parsed = !normalized.is_empty() && parsed_header_address.is_some();
    let target_responded = hops.last().is_some_and(|hop| {
        hop.resolved_address.as_deref() == Some(native.resolved_address.as_str())
            && !hop.timings.is_empty()
    });

    let mut raw_output = normalized;
    let failure_source = if native.timed_out {
        if !raw_output.is_empty() {
            raw_output.push_str("\n\n");
        }
        raw_output.push_str("The measurement command timed out.");
        Some(
            if target_responded {
                "internal"
            } else if native.stdout.lines().skip(1).any(|line| line.contains('*')) {
                "target"
            } else {
                "internal"
            }
            .to_string(),
        )
    } else if native.exit_code.is_some_and(|code| code != 0) {
        if raw_output.trim().is_empty() {
            raw_output = if native.stderr.trim().is_empty() {
                "Test failed. Please try again.".to_string()
            } else {
                native.stderr
            };
            hops.clear();
        }
        Some(
            if has_upstream_unreachable(&raw_output) {
                "target"
            } else {
                "internal"
            }
            .to_string(),
        )
    } else if !parsed {
        if raw_output.trim().is_empty() {
            raw_output = "Test failed. Please try again.".to_string();
        }
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
        raw_output,
        resolved_address: Some(native.resolved_address),
        resolved_hostname: Some(native.resolved_hostname),
        hops,
    }
}

pub fn run(token: &CapabilityToken, in_progress_updates: bool) -> Result<String, BehaviorError> {
    let native = execution::collect(token, MeasurementKind::Traceroute, |_chunk, all, start| {
        if !in_progress_updates {
            return Ok(());
        }
        let progress = normalize_with(all, &start.resolved_hostname, |_| None);
        if progress.is_empty() {
            return Ok(());
        }
        let payload = serde_json::to_string(&serde_json::json!({ "rawOutput": progress }))
            .map_err(|error| BehaviorError::Internal(error.to_string()))?;
        execution::emit_progress(token, &payload, false)
    })?;

    let local_addresses = native.local_addresses.clone();
    let mut seen = BTreeSet::new();
    let mut hostnames = BTreeMap::new();
    for address in native.stdout.lines().skip(1).flat_map(ip_tokens) {
        if address == native.resolved_address || !seen.insert(address.clone()) {
            continue;
        }
        let Ok(parsed) = address.parse::<IpAddr>() else {
            continue;
        };
        if is_private_or_reserved(parsed, &local_addresses) {
            continue;
        }
        if let Some(hostname) = execution::reverse_lookup(token, &address)? {
            hostnames.insert(address, hostname);
        }
    }
    let payload = shape(native, |address| hostnames.get(address).cloned());
    serde_json::to_string(&payload).map_err(|error| BehaviorError::Internal(error.to_string()))
}

pub fn self_test() -> Result<(), String> {
    let native = NativeExecution {
        resolved_address: "1.1.1.1".to_string(),
        resolved_hostname: "one.one.one.one".to_string(),
        target_is_icann: true,
        local_addresses: Vec::new(),
        stdout: "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets\n 1  192.168.1.1  1.234 ms  1.156 ms\n 2  10.0.0.1  5.678 ms  5.432 ms\n 3  * * *\n 4  1.1.1.1  8.123 ms  7.956 ms".to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        timed_out: false,
    };
    let parsed = shape(native, |_| None);
    if !matches!(parsed.status, Status::Finished)
        || parsed.resolved_address.as_deref() != Some("1.1.1.1")
        || parsed.resolved_hostname.as_deref() != Some("one.one.one.one")
        || parsed.hops.len() != 4
        || parsed.hops[0].resolved_hostname.as_deref() != Some("_gateway")
        || parsed.hops[0].resolved_address.as_deref() != Some("192.168.1.1")
        || parsed.hops[2].resolved_address.is_some()
        || parsed.hops[3].timings.len() != 2
    {
        return Err("traceroute behavior parser self-test failed".to_string());
    }
    Ok(())
}
