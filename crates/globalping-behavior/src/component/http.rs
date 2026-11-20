use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::net::IpAddr;

use globalping_behavior_core::http::{
    BODY_SIZE_LIMIT, HttpSuccessInput, TlsEnrichment, apply_tls_enrichment, curl_timeout_message,
    failed_result, parse_header_file, parse_metrics, parse_tls_verbose, shape_success_http_result,
};

use super::codeandsolder::globalping_behavior::host::{
    self, CapabilityToken, ExecutionEvent, ExecutionStart, HostError, HostErrorCode,
    HttpNativeFailure, HttpTlsEnrichment, MeasurementKind, ResolutionFailure,
};
use super::execution;
use super::exports::codeandsolder::globalping_behavior::guest::BehaviorError;
use super::ip::is_private_or_reserved;

struct HttpExecution {
    start: ExecutionStart,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    headers: Vec<u8>,
    body: Vec<u8>,
    tls_enrichment: Option<HttpTlsEnrichment>,
    native_failure: Option<HttpNativeFailure>,
    timed_out: bool,
}

enum HttpOutcome {
    Executed(HttpExecution),
    ResolutionFailed(ResolutionFailure),
}

const fn copy_token(token: &CapabilityToken) -> CapabilityToken {
    CapabilityToken {
        hi: token.hi,
        lo: token.lo,
    }
}

fn map_host_error(error: HostError) -> BehaviorError {
    match error.code {
        HostErrorCode::InvalidToken
        | HostErrorCode::WrongMeasurementKind
        | HostErrorCode::InvalidRequest => BehaviorError::InvalidJob(error.message),
        _ => BehaviorError::Internal(error.message),
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn progress_headers(raw: &[u8]) -> (String, String) {
    let text = lossy(raw);
    let status_line = text
        .lines()
        .next()
        .unwrap_or_default()
        .trim_end_matches('\r')
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let headers = parse_header_file(&text)
        .into_iter()
        .map(|(key, value)| format!("{key}: {value}"))
        .collect::<Vec<_>>()
        .join("\n");
    (status_line, headers)
}

fn emit_body_progress(
    token: &CapabilityToken,
    headers: &[u8],
    chunk: &[u8],
    already_emitted: &mut usize,
) -> Result<(), BehaviorError> {
    if *already_emitted >= BODY_SIZE_LIMIT || chunk.is_empty() {
        return Ok(());
    }
    let remaining = BODY_SIZE_LIMIT - *already_emitted;
    let visible = &chunk[..chunk.len().min(remaining)];
    if visible.is_empty() {
        return Ok(());
    }
    let raw_body = lossy(visible);
    let first = *already_emitted == 0;
    *already_emitted += visible.len();
    let payload = if first {
        let (status_line, raw_headers) = progress_headers(headers);
        let prefix = if status_line.is_empty() {
            String::new()
        } else {
            format!("{status_line}\n{raw_headers}\n\n")
        };
        serde_json::json!({
            "rawHeaders": raw_headers,
            "rawBody": raw_body,
            "rawOutput": format!("{prefix}{raw_body}"),
        })
    } else {
        serde_json::json!({
            "rawBody": raw_body,
            "rawOutput": raw_body,
        })
    };
    let payload = serde_json::to_string(&payload)
        .map_err(|error| BehaviorError::Internal(error.to_string()))?;
    execution::emit_progress(token, &payload, execution::ProgressMode::Append)
}

fn collect_http(
    token: &CapabilityToken,
    in_progress_updates: bool,
) -> Result<HttpOutcome, BehaviorError> {
    let start = match host::start(copy_token(token)).map_err(map_host_error)? {
        host::ExecutionStartResult::Started(start) => start,
        host::ExecutionStartResult::ResolutionFailed(reason) => {
            return Ok(HttpOutcome::ResolutionFailed(reason));
        }
    };
    if !matches!(start.kind, MeasurementKind::Http) {
        return Err(BehaviorError::Internal(
            "host started the wrong measurement kind".to_string(),
        ));
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut headers = Vec::new();
    let mut body = Vec::new();
    let mut tls_enrichment = None;
    let mut native_failure = None;
    let mut timed_out = false;
    let mut progress_bytes = 0_usize;

    loop {
        let Some(event) = host::poll(copy_token(token)).map_err(map_host_error)? else {
            continue;
        };
        match event {
            ExecutionEvent::Stdout(bytes) => stdout.extend_from_slice(&bytes),
            ExecutionEvent::Stderr(bytes) => stderr.extend_from_slice(&bytes),
            ExecutionEvent::HttpResponseHeaders(bytes) => headers = bytes,
            ExecutionEvent::HttpResponseBody(bytes) => {
                if in_progress_updates {
                    emit_body_progress(token, &headers, &bytes, &mut progress_bytes)?;
                }
                body.extend_from_slice(&bytes);
            }
            ExecutionEvent::HttpTlsEnrichment(enrichment) => {
                tls_enrichment = Some(enrichment);
            }
            ExecutionEvent::HttpNativeFailure(failure) => native_failure = Some(failure),
            ExecutionEvent::ObservedAddress(_) => {}
            ExecutionEvent::Exited(_) => break,
            ExecutionEvent::TimedOut => {
                timed_out = true;
                break;
            }
        }
    }

    Ok(HttpOutcome::Executed(HttpExecution {
        start,
        stdout,
        stderr,
        headers,
        body,
        tls_enrichment,
        native_failure,
        timed_out,
    }))
}

fn convert_enrichment(enrichment: HttpTlsEnrichment) -> TlsEnrichment {
    TlsEnrichment {
        authorized: enrichment.authorized,
        subject_alt: enrichment.subject_alt,
        key_type: enrichment.key_type,
        key_bits: enrichment.key_bits,
        serial_number: enrichment.serial_number,
        fingerprint256: enrichment.fingerprint256,
    }
}

pub fn run(
    token: &CapabilityToken,
    protocol: &str,
    method: &str,
    in_progress_updates: bool,
) -> Result<String, BehaviorError> {
    let outcome = collect_http(token, in_progress_updates)?;
    let result = match outcome {
        HttpOutcome::ResolutionFailed(failure) => {
            let source = execution::resolution_failure_source(&failure, "target");
            let message = failure.public_message.as_ref().map_or_else(
                || execution::resolution_failure_message(&failure),
                Clone::clone,
            );
            failed_result(source, message)
        }
        HttpOutcome::Executed(native) => {
            if let Some(failure) = native.native_failure {
                failed_result(&failure.failure_source, failure.message)
            } else {
                let is_https = !protocol.eq_ignore_ascii_case("HTTP");
                let stderr = lossy(&native.stderr);
                if native.timed_out {
                    failed_result("target", curl_timeout_message(&stderr, is_https))
                } else {
                    let stdout = lossy(&native.stdout);
                    match parse_metrics(stdout.trim(), &stderr) {
                        Err(message) => failed_result("target", message),
                        Ok(metrics) => {
                            let final_resolved_ip = if metrics.remote_ip.is_empty() {
                                native.start.resolved_address.clone()
                            } else {
                                metrics.remote_ip.clone()
                            };
                            if final_resolved_ip.parse::<IpAddr>().is_ok_and(|address| {
                                is_private_or_reserved(address, &native.start.local_addresses)
                            }) {
                                failed_result(
                                    "target",
                                    "Private IP ranges are not allowed.".to_string(),
                                )
                            } else {
                                let mut tls = if is_https {
                                    parse_tls_verbose(&stderr, metrics.ssl_verify_result)
                                } else {
                                    None
                                };
                                if let (Some(tls), Some(enrichment)) =
                                    (&mut tls, native.tls_enrichment)
                                {
                                    apply_tls_enrichment(tls, convert_enrichment(enrichment));
                                }
                                shape_success_http_result(HttpSuccessInput {
                                    method,
                                    protocol,
                                    raw_header_file: &lossy(&native.headers),
                                    raw_body_bytes: &native.body,
                                    metrics: &metrics,
                                    final_resolved_ip,
                                    dns_ms: native.start.dns_duration_ms,
                                    tls,
                                })
                            }
                        }
                    }
                }
            }
        }
    };
    serde_json::to_string(&result).map_err(|error| BehaviorError::Internal(error.to_string()))
}

pub fn self_test() -> Result<(), String> {
    let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    let metrics = parse_metrics(
        r#"{"remote_ip":"93.184.216.34","time_namelookup":0.0,"time_connect":0.010,"time_appconnect":0.020,"time_starttransfer":0.030,"time_total":0.040,"http_version":"1.1","response_code":200,"ssl_verify_result":0}"#,
        "",
    )?;
    let result = shape_success_http_result(HttpSuccessInput {
        method: "GET",
        protocol: "HTTPS",
        raw_header_file: headers,
        raw_body_bytes: b"ok",
        metrics: &metrics,
        final_resolved_ip: "93.184.216.34".to_string(),
        dns_ms: Some(5),
        tls: None,
    });
    if result.status_code != Some(200)
        || result.raw_body.as_deref() != Some("ok")
        || result.timings.total != Some(45)
    {
        return Err("http behavior shaper self-test failed".to_string());
    }
    Ok(())
}
