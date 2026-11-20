use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::net::IpAddr;

use globalping_behavior_core::traceroute::{
    TracerouteExecutionStatus, TracerouteHostnames, TracerouteIdentity, TracerouteStatus,
    failed_traceroute, line_addresses, progress_output, shape_traceroute_output,
};

use super::codeandsolder::globalping_behavior::host::{CapabilityToken, MeasurementKind};
use super::execution::{self, ExecutionOutcome, NativeExecution};
use super::exports::codeandsolder::globalping_behavior::guest::BehaviorError;
use super::ip::is_private_or_reserved;

fn resolution_failure(
    reason: &super::codeandsolder::globalping_behavior::host::ResolutionFailure,
) -> globalping_behavior_core::traceroute::ParsedTraceroute {
    failed_traceroute(
        execution::resolution_failure_source(reason, "resolver"),
        execution::resolution_failure_message(reason),
    )
}

fn identity(native: &NativeExecution) -> Result<TracerouteIdentity<'_>, BehaviorError> {
    let address = native
        .resolved_address
        .parse::<IpAddr>()
        .map_err(|error| BehaviorError::Internal(error.to_string()))?;
    Ok(TracerouteIdentity {
        address,
        hostname: &native.resolved_hostname,
    })
}

pub fn run(token: &CapabilityToken, in_progress_updates: bool) -> Result<String, BehaviorError> {
    let outcome = execution::collect(token, MeasurementKind::Traceroute, |_chunk, all, start| {
        if !in_progress_updates {
            return Ok(());
        }
        let address = start
            .resolved_address
            .parse::<IpAddr>()
            .map_err(|error| BehaviorError::Internal(error.to_string()))?;
        let progress = progress_output(
            all,
            TracerouteIdentity {
                address,
                hostname: &start.resolved_hostname,
            },
        );
        if progress.is_empty() {
            return Ok(());
        }
        let payload = serde_json::to_string(&serde_json::json!({ "rawOutput": progress }))
            .map_err(|error| BehaviorError::Internal(error.to_string()))?;
        execution::emit_progress(token, &payload, execution::ProgressMode::Diff)
    })?;
    let native = match outcome {
        ExecutionOutcome::Executed(native) => native,
        ExecutionOutcome::ResolutionFailed(reason) => {
            return serde_json::to_string(&resolution_failure(&reason))
                .map_err(|error| BehaviorError::Internal(error.to_string()));
        }
    };

    let local_addresses = native.local_addresses.clone();
    let resolved_address = native
        .resolved_address
        .parse::<IpAddr>()
        .map_err(|error| BehaviorError::Internal(error.to_string()))?;
    let mut seen = BTreeSet::new();
    let mut hostnames = TracerouteHostnames::new();
    for address in native.stdout.lines().skip(1).flat_map(line_addresses) {
        if address == resolved_address || !seen.insert(address) {
            continue;
        }
        if is_private_or_reserved(address, &local_addresses) {
            continue;
        }
        if let Some(hostname) = execution::reverse_lookup(token, &address.to_string())? {
            hostnames.insert(address, hostname);
        }
    }
    let payload = shape_traceroute_output(
        &native.stdout,
        &native.stderr,
        TracerouteExecutionStatus {
            timed_out: native.timed_out,
            succeeded: native.exit_code.map(|code| code == 0),
        },
        identity(&native)?,
        &hostnames,
    );
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
    let parsed = shape_traceroute_output(
        &native.stdout,
        &native.stderr,
        TracerouteExecutionStatus {
            timed_out: native.timed_out,
            succeeded: native.exit_code.map(|code| code == 0),
        },
        TracerouteIdentity {
            address: "1.1.1.1"
                .parse()
                .map_err(|error: core::net::AddrParseError| error.to_string())?,
            hostname: &native.resolved_hostname,
        },
        &BTreeMap::new(),
    );
    if !matches!(parsed.status, TracerouteStatus::Finished)
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
