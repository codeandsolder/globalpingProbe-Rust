use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use super::codeandsolder::globalping_behavior::host::{
    self, CapabilityToken, ExecutionEvent, HostError, HostErrorCode, MeasurementKind,
};
use super::exports::codeandsolder::globalping_behavior::guest::BehaviorError;

pub struct NativeExecution {
    pub resolved_address: String,
    pub resolved_hostname: String,
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
    mut on_stdout: F,
) -> Result<NativeExecution, BehaviorError>
where
    F: FnMut(&str, &str, &host::ExecutionStart) -> Result<(), BehaviorError>,
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
            ExecutionEvent::ObservedAddress(_) => {}
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

pub fn reverse_lookup(token: &CapabilityToken, address: &str) -> Option<String> {
    host::reverse_lookup(copy_token(token), address)
        .ok()
        .flatten()
}
