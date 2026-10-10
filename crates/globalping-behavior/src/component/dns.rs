use alloc::string::{String, ToString as _};

use globalping_behavior_core::dns::{
    DnsExecutionStatus, DnsPolicy, DnsProgress, DnsStatus, parse_classic, progress_output,
    shape_classic_output, shape_trace_output,
};

use super::codeandsolder::globalping_behavior::host::{CapabilityToken, MeasurementKind};
use super::execution::{self, ExecutionOutcome};
use super::exports::codeandsolder::globalping_behavior::guest::BehaviorError;

pub fn run(
    token: &CapabilityToken,
    trace: bool,
    in_progress_updates: bool,
) -> Result<String, BehaviorError> {
    let mut private_seen = false;
    let outcome = execution::collect(token, MeasurementKind::Dns, |_line, cumulative, start| {
        if !in_progress_updates {
            return Ok(());
        }
        let mut raw = cumulative.to_string();
        raw.push('\n');
        match progress_output(
            &raw,
            trace,
            DnsPolicy {
                target_is_icann: start.target_is_icann,
                local_addresses: &start.local_addresses,
            },
        ) {
            DnsProgress::Ignore => Ok(()),
            DnsProgress::Private => {
                private_seen = true;
                Ok(())
            }
            DnsProgress::Emit(output) => {
                let payload = serde_json::to_string(&serde_json::json!({ "rawOutput": output }))
                    .map_err(|error| BehaviorError::Internal(error.to_string()))?;
                execution::emit_progress(token, &payload, execution::ProgressMode::Diff)
            }
        }
    })?;
    let native = match outcome {
        ExecutionOutcome::Executed(native) => native,
        ExecutionOutcome::ResolutionFailed(_) => {
            return Err(BehaviorError::Internal(
                "DNS host unexpectedly reported pre-resolution failure".to_string(),
            ));
        }
    };
    let process_failed = native.exit_code.is_some_and(|code| code != 0);
    let payload = if trace {
        serde_json::to_string(&shape_trace_output(
            &native.stdout,
            &native.stderr,
            DnsExecutionStatus {
                timed_out: native.timed_out,
                process_failed,
            },
            private_seen,
            DnsPolicy {
                target_is_icann: native.target_is_icann,
                local_addresses: &native.local_addresses,
            },
        ))
    } else {
        serde_json::to_string(&shape_classic_output(
            &native.stdout,
            &native.stderr,
            DnsExecutionStatus {
                timed_out: native.timed_out,
                process_failed,
            },
            private_seen,
            DnsPolicy {
                target_is_icann: native.target_is_icann,
                local_addresses: &native.local_addresses,
            },
        ))
    };
    payload.map_err(|error| BehaviorError::Internal(error.to_string()))
}

pub fn self_test() -> Result<(), String> {
    const RAW: &str = "; <<>> DiG 9.20 <<>> example.com -t A\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1\n;; ANSWER SECTION:\nexample.com. 60 IN A 93.184.216.34\n\n;; Query time: 12 msec\n;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)\n";
    let result = parse_classic(RAW, &[]);
    if result.status != DnsStatus::Finished
        || result.answers.len() != 1
        || result.answers[0].value != "93.184.216.34"
        || result.timings.total != 12
        || result.resolver.as_deref() != Some("1.1.1.1")
        || result.status_code != Some(0)
    {
        return Err("dns behavior parser self-test failed".to_string());
    }
    Ok(())
}
