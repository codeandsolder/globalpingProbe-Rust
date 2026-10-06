use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use super::codeandsolder::globalping_behavior::host::{
    self, CapabilityToken, ExecutionEvent, HostError, HostErrorCode, MeasurementKind,
};
use super::exports::codeandsolder::globalping_behavior::guest::BehaviorError;

pub struct NativeExecution {
    pub resolved_address: String,
    pub resolved_hostname: String,
    pub target_is_icann: bool,
    pub local_addresses: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

const fn copy_token(token: &CapabilityToken) -> CapabilityToken {
    CapabilityToken {
        hi: token.hi,
        lo: token.lo,
    }
}

const fn same_kind(left: MeasurementKind, right: MeasurementKind) -> bool {
    matches!(
        (left, right),
        (MeasurementKind::Ping, MeasurementKind::Ping)
            | (MeasurementKind::Dns, MeasurementKind::Dns)
            | (MeasurementKind::Traceroute, MeasurementKind::Traceroute)
            | (MeasurementKind::Mtr, MeasurementKind::Mtr)
            | (MeasurementKind::Http, MeasurementKind::Http)
    )
}

fn map_host_error(error: HostError) -> BehaviorError {
    match error.code {
        HostErrorCode::InvalidToken
        | HostErrorCode::WrongMeasurementKind
        | HostErrorCode::InvalidRequest => BehaviorError::InvalidJob(error.message),
        _ => BehaviorError::Internal(error.message),
    }
}

fn decode_utf8(bytes: &[u8]) -> Result<&str, BehaviorError> {
    core::str::from_utf8(bytes).map_err(|_| {
        BehaviorError::Internal("native execution emitted non-UTF-8 output".to_string())
    })
}

pub fn collect<F>(
    token: &CapabilityToken,
    expected_kind: MeasurementKind,
    on_stdout: F,
) -> Result<NativeExecution, BehaviorError>
where
    F: FnMut(&str, &str, &host::ExecutionStart) -> Result<(), BehaviorError>,
{
    collect_with_observed(token, expected_kind, on_stdout, |_address, _raw, _start| {
        Ok(())
    })
}

pub fn collect_with_observed<F, G>(
    token: &CapabilityToken,
    expected_kind: MeasurementKind,
    mut on_stdout: F,
    mut on_observed: G,
) -> Result<NativeExecution, BehaviorError>
where
    F: FnMut(&str, &str, &host::ExecutionStart) -> Result<(), BehaviorError>,
    G: FnMut(&str, &str, &host::ExecutionStart) -> Result<(), BehaviorError>,
{
    let start = host::start(copy_token(token)).map_err(map_host_error)?;
    if !same_kind(start.kind, expected_kind) {
        return Err(BehaviorError::Internal(
            "host started the wrong measurement kind".to_string(),
        ));
    }

    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_line_start = 0;
    let mut exit_code = None;
    let mut timed_out = false;

    loop {
        let Some(event) = host::poll(copy_token(token)).map_err(map_host_error)? else {
            continue;
        };
        match event {
            ExecutionEvent::Stdout(bytes) => {
                stdout_bytes.extend_from_slice(&bytes);
                while let Some(relative_end) = stdout_bytes[stdout_line_start..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                {
                    let line_end = stdout_line_start + relative_end;
                    let line = decode_utf8(&stdout_bytes[stdout_line_start..line_end])?;
                    let cumulative = decode_utf8(&stdout_bytes[..line_end])?;
                    on_stdout(line, cumulative, &start)?;
                    stdout_line_start = line_end + 1;
                }
            }
            ExecutionEvent::Stderr(bytes) => {
                stderr_bytes.extend_from_slice(&bytes);
            }
            ExecutionEvent::ObservedAddress(address) => {
                let cumulative = decode_utf8(&stdout_bytes)?;
                on_observed(&address, cumulative, &start)?;
            }
            ExecutionEvent::Exited(code) => {
                exit_code = Some(code);
                break;
            }
            ExecutionEvent::TimedOut => {
                timed_out = true;
                break;
            }
        }
    }

    if stdout_line_start < stdout_bytes.len() {
        let line = decode_utf8(&stdout_bytes[stdout_line_start..])?;
        let cumulative = decode_utf8(&stdout_bytes)?;
        on_stdout(line, cumulative, &start)?;
    }

    let stdout = decode_utf8(&stdout_bytes)?.to_string();
    let stderr = decode_utf8(&stderr_bytes)?.to_string();
    Ok(NativeExecution {
        resolved_address: start.resolved_address,
        resolved_hostname: start.resolved_hostname,
        target_is_icann: start.target_is_icann,
        local_addresses: start.local_addresses,
        stdout,
        stderr,
        exit_code,
        timed_out,
    })
}

pub fn emit_progress(
    token: &CapabilityToken,
    result_json: &str,
    overwrite: bool,
) -> Result<(), BehaviorError> {
    host::emit_progress(copy_token(token), result_json, overwrite).map_err(map_host_error)
}

pub fn reverse_lookup(
    token: &CapabilityToken,
    address: &str,
) -> Result<Option<String>, BehaviorError> {
    host::reverse_lookup(copy_token(token), address).map_err(map_host_error)
}

pub fn lookup_asn(token: &CapabilityToken, address: &str) -> Result<Vec<u32>, BehaviorError> {
    host::lookup_asn(copy_token(token), address).map_err(map_host_error)
}
