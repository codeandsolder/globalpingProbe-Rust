use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use globalping_behavior_core::ping::{
    ParsedPing, PingStatus, failed_ping, normalize_ping_output, shape_ping_output,
};

use super::codeandsolder::globalping_behavior::host::{CapabilityToken, MeasurementKind};
use super::execution::{self, ExecutionOutcome, NativeExecution};
use super::exports::codeandsolder::globalping_behavior::guest::BehaviorError;

fn resolution_failure(
    reason: &super::codeandsolder::globalping_behavior::host::ResolutionFailure,
) -> ParsedPing {
    failed_ping(
        execution::resolution_failure_source(reason, "internal"),
        execution::resolution_failure_message(reason),
    )
}

pub fn run(
    token: &CapabilityToken,
    in_progress_updates: bool,
    tcp_progress: bool,
) -> Result<String, BehaviorError> {
    let outcome = execution::collect(token, MeasurementKind::Ping, |line, all, start| {
        if !in_progress_updates {
            return Ok(());
        }
        let progress = if tcp_progress {
            if !line.contains("tcp_conn=") {
                return Ok(());
            }
            normalize_ping_output(all, &start.resolved_address, &start.resolved_hostname)
        } else {
            let mut line =
                normalize_ping_output(line, &start.resolved_address, &start.resolved_hostname);
            line.push('\n');
            line
        };
        let payload = serde_json::to_string(&serde_json::json!({ "rawOutput": progress }))
            .map_err(|error| BehaviorError::Internal(error.to_string()))?;
        let mode = if tcp_progress {
            execution::ProgressMode::Diff
        } else {
            execution::ProgressMode::Append
        };
        execution::emit_progress(token, &payload, mode)
    })?;
    let payload = match outcome {
        ExecutionOutcome::Executed(native) => shape_ping_output(
            &native.stdout,
            &native.resolved_address,
            &native.resolved_hostname,
            native.timed_out,
        ),
        ExecutionOutcome::ResolutionFailed(reason) => resolution_failure(&reason),
    };
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
    let parsed = shape_ping_output(
        &native.stdout,
        &native.resolved_address,
        &native.resolved_hostname,
        native.timed_out,
    );
    if !matches!(parsed.status, PingStatus::Finished)
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
