use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::net::IpAddr;

use serde::Serialize;

use super::codeandsolder::globalping_behavior::host::{CapabilityToken, MeasurementKind};
use super::execution::{self, ExecutionOutcome, NativeExecution};
use super::exports::codeandsolder::globalping_behavior::guest::BehaviorError;
use super::ip::is_private_or_reserved;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Finished,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Answer {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    ttl: u32,
    class: String,
    value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
struct Timings {
    total: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClassicResult {
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_source: Option<String>,
    status_code_name: Option<String>,
    status_code: Option<u16>,
    answers: Vec<Answer>,
    timings: Timings,
    resolver: Option<String>,
    raw_output: String,
}

#[derive(Debug, Clone, Serialize)]
struct TraceHop {
    answers: Vec<Answer>,
    timings: Timings,
    resolver: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TraceResult {
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_source: Option<String>,
    hops: Vec<TraceHop>,
    raw_output: String,
}

enum Progress {
    Ignore,
    Emit(String),
    Private,
}

fn answer_is_private(value: &str, local_addresses: &[String]) -> bool {
    value
        .parse::<IpAddr>()
        .is_ok_and(|address| is_private_or_reserved(address, local_addresses))
}

fn parse_answer_line(line: &str) -> Option<Answer> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 5 {
        return None;
    }
    let ttl = parts[1].parse::<u32>().ok()?;
    Some(Answer {
        name: parts[0].to_string(),
        ttl,
        class: parts[2].to_string(),
        record_type: parts[3].to_string(),
        value: parts[4..].join(" "),
    })
}

fn parse_u32_after(line: &str, marker: &str) -> Option<u32> {
    let tail = line.split_once(marker)?.1.trim_start();
    let digits = tail
        .bytes()
        .take_while(u8::is_ascii_digit)
        .map(char::from)
        .collect::<String>();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn status_name(line: &str) -> Option<String> {
    let tail = line.split_once("status:")?.1.trim_start();
    let value = tail
        .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .next()?;
    (!value.is_empty()).then(|| value.to_string())
}

fn status_number(name: &str) -> Option<u16> {
    match name.to_ascii_lowercase().as_str() {
        "noerror" => Some(0),
        "formerr" => Some(1),
        "servfail" => Some(2),
        "nxdomain" => Some(3),
        "notimp" => Some(4),
        "refused" => Some(5),
        "yxdomain" => Some(6),
        "yxrrset" => Some(7),
        "nxrrset" => Some(8),
        "notauth" => Some(9),
        "notzone" => Some(10),
        "dsotypeni" => Some(11),
        "badvers" | "badsig" => Some(16),
        "badkey" => Some(17),
        "badtime" => Some(18),
        "badmode" => Some(19),
        "badname" => Some(20),
        "badalg" => Some(21),
        "badtrunc" => Some(22),
        "badcookie" => Some(23),
        _ => None,
    }
}

fn server_ip(line: &str) -> Option<&str> {
    let tail = line.split_once("SERVER:")?.1.trim_start();
    let end = tail
        .find(|ch: char| ch == '#' || ch.is_ascii_whitespace())
        .unwrap_or(tail.len());
    let value = &tail[..end];
    (!value.is_empty()).then_some(value)
}

fn rewrite_classic(raw: &str, local_addresses: &[String]) -> String {
    raw.split('\n')
        .map(|line| {
            let Some(ip_text) = server_ip(line) else {
                return line.to_string();
            };
            if ip_text
                .parse::<IpAddr>()
                .is_ok_and(|address| is_private_or_reserved(address, local_addresses))
            {
                line.replace(ip_text, "x.x.x.x")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn resolver_from_server(line: &str) -> Option<String> {
    let tail = line.split_once("SERVER:")?.1;
    let open = tail.find('(')?;
    let after_open = &tail[open + 1..];
    let close = after_open.find(')')?;
    let value = &after_open[..close];
    Some(if value == "x.x.x.x" {
        "private".to_string()
    } else {
        value.to_string()
    })
}

fn section_name(line: &str) -> Option<&str> {
    let value = line.strip_prefix(";; ")?.strip_suffix(" SECTION:")?;
    Some(value)
}

fn parse_classic(raw: &str, local_addresses: &[String]) -> ClassicResult {
    let rewritten = rewrite_classic(raw, local_addresses);
    let lines = rewritten.split('\n').collect::<Vec<_>>();
    let failed = |output: String| ClassicResult {
        status: Status::Failed,
        failure_source: None,
        status_code_name: None,
        status_code: None,
        answers: Vec::new(),
        timings: Timings::default(),
        resolver: None,
        raw_output: output,
    };
    if lines.len() < 6
        || lines
            .first()
            .is_some_and(|line| line.starts_with(";; Got bad packet:"))
    {
        return failed(rewritten);
    }

    let mut answers = Vec::new();
    let mut timings = Timings::default();
    let mut resolver = None;
    let mut code_name = None;
    let mut code = None;
    let mut section = "header";
    for line in lines {
        if let Some(total) = parse_u32_after(line, "Query time:") {
            timings.total = total;
        }
        if let Some(name) = status_name(line) {
            code = status_number(&name);
            code_name = Some(name);
        }
        if let Some(value) = resolver_from_server(line) {
            resolver = Some(value);
        }

        let mut changed = false;
        if line.is_empty() {
            section = "";
        } else if let Some(name) = section_name(line) {
            section = if name.eq_ignore_ascii_case("ANSWER") {
                "answer"
            } else {
                "other"
            };
            changed = true;
        }
        if section == "answer"
            && !changed
            && !line.starts_with(';')
            && let Some(answer) = parse_answer_line(line)
        {
            answers.push(answer);
        }
    }

    ClassicResult {
        status: Status::Finished,
        failure_source: None,
        status_code_name: code_name,
        status_code: code,
        answers,
        timings,
        resolver,
        raw_output: rewritten,
    }
}

fn trace_received(line: &str) -> Option<(String, u32)> {
    let tail = line.split_once(" from ")?.1;
    let open = tail.find('(')?;
    let after_open = &tail[open + 1..];
    let close = after_open.find(')')?;
    let resolver = after_open[..close].to_string();
    let after_close = &after_open[close + 1..];
    let total = parse_u32_after(after_close, "in ")?;
    Some((resolver, total))
}

fn push_trace_hop(
    hops: &mut Vec<TraceHop>,
    answers: &mut Vec<Answer>,
    timings: &mut Timings,
    resolver: &mut Option<String>,
) {
    if !answers.is_empty() || resolver.is_some() {
        hops.push(TraceHop {
            answers: core::mem::take(answers),
            timings: core::mem::take(timings),
            resolver: resolver.take(),
        });
    }
}

fn parse_trace(raw: &str) -> TraceResult {
    let lines = raw.split('\n').collect::<Vec<_>>();
    if lines.len() < 3
        || lines
            .first()
            .is_some_and(|line| line.starts_with(";; Got bad packet:"))
    {
        return TraceResult {
            status: Status::Failed,
            failure_source: None,
            hops: Vec::new(),
            raw_output: raw.to_string(),
        };
    }

    let mut hops = Vec::new();
    let mut answers = Vec::new();
    let mut timings = Timings::default();
    let mut resolver = None;
    for line in lines {
        if line.is_empty() {
            push_trace_hop(&mut hops, &mut answers, &mut timings, &mut resolver);
            continue;
        }
        if line.starts_with(";;") {
            if let Some((name, total)) = trace_received(line) {
                resolver = Some(name);
                timings.total = total;
            }
            continue;
        }
        if let Some(answer) = parse_answer_line(line) {
            answers.push(answer);
        }
    }
    push_trace_hop(&mut hops, &mut answers, &mut timings, &mut resolver);
    TraceResult {
        status: Status::Finished,
        failure_source: None,
        hops,
        raw_output: raw.to_string(),
    }
}

fn classic_has_private_answer(
    result: &ClassicResult,
    target_is_icann: bool,
    local_addresses: &[String],
) -> bool {
    !target_is_icann
        && result
            .answers
            .iter()
            .any(|answer| answer_is_private(&answer.value, local_addresses))
}

fn trace_has_private_answer(
    result: &TraceResult,
    target_is_icann: bool,
    local_addresses: &[String],
) -> bool {
    !target_is_icann
        && result
            .hops
            .iter()
            .flat_map(|hop| &hop.answers)
            .any(|answer| answer_is_private(&answer.value, local_addresses))
}

fn progress_output(
    raw: &str,
    target_is_icann: bool,
    trace: bool,
    local_addresses: &[String],
) -> Progress {
    if trace {
        let result = parse_trace(raw);
        if result.status == Status::Finished
            && trace_has_private_answer(&result, target_is_icann, local_addresses)
        {
            return Progress::Private;
        }
        if result.status == Status::Finished
            || raw.to_ascii_lowercase().contains("connection refused")
        {
            return Progress::Emit(result.raw_output);
        }
        return Progress::Ignore;
    }
    let result = parse_classic(raw, local_addresses);
    if result.status == Status::Finished
        && classic_has_private_answer(&result, target_is_icann, local_addresses)
    {
        return Progress::Private;
    }
    if result.status == Status::Finished || raw.to_ascii_lowercase().contains("connection refused")
    {
        Progress::Emit(result.raw_output)
    } else {
        Progress::Ignore
    }
}

fn resolver_failure(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    [
        "couldn't get address for",
        "got bad packet:",
        "connection refused",
        "connection timed out",
        "communications error",
        "no servers could be reached",
    ]
    .iter()
    .any(|pattern| lower.contains(pattern))
}

fn failure_source(native: &NativeExecution, raw_output: &str) -> &'static str {
    if native.timed_out || resolver_failure(raw_output) {
        "resolver"
    } else {
        "internal"
    }
}

fn append_timeout(raw_output: &mut String) {
    if !raw_output.is_empty() {
        raw_output.push_str("\n\n");
    }
    raw_output.push_str("The measurement command timed out.");
}

fn shape_classic(native: NativeExecution, private_seen: bool) -> ClassicResult {
    let mut result = parse_classic(&native.stdout, &native.local_addresses);
    if private_seen
        || classic_has_private_answer(&result, native.target_is_icann, &native.local_addresses)
    {
        let resolver = result.resolver.clone();
        result.status = Status::Failed;
        result.failure_source = Some("target".to_string());
        result.status_code_name = None;
        result.status_code = None;
        result.answers.clear();
        result.timings = Timings::default();
        result.resolver = resolver;
        result.raw_output = "Private IP ranges are not allowed.".to_string();
        return result;
    }
    let process_failed = native.exit_code.is_some_and(|code| code != 0);
    if native.timed_out {
        result.status = Status::Failed;
        append_timeout(&mut result.raw_output);
    }
    if native.timed_out || process_failed || result.status == Status::Failed {
        result.failure_source = Some(failure_source(&native, &result.raw_output).to_string());
        if result.raw_output.trim().is_empty() && !native.stderr.trim().is_empty() {
            result.raw_output = native.stderr;
        }
    }
    result
}

fn shape_trace(native: NativeExecution, private_seen: bool) -> TraceResult {
    let mut result = parse_trace(&native.stdout);
    if private_seen
        || trace_has_private_answer(&result, native.target_is_icann, &native.local_addresses)
    {
        result.status = Status::Failed;
        result.failure_source = Some("target".to_string());
        result.hops.clear();
        result.raw_output = "Private IP ranges are not allowed.".to_string();
        return result;
    }
    let process_failed = native.exit_code.is_some_and(|code| code != 0);
    if native.timed_out {
        result.status = Status::Failed;
        append_timeout(&mut result.raw_output);
    }
    if native.timed_out || process_failed || result.status == Status::Failed {
        result.failure_source = Some(failure_source(&native, &result.raw_output).to_string());
        if result.raw_output.trim().is_empty() && !native.stderr.trim().is_empty() {
            result.raw_output = native.stderr;
        }
    }
    result
}

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
        match progress_output(&raw, start.target_is_icann, trace, &start.local_addresses) {
            Progress::Ignore => Ok(()),
            Progress::Private => {
                private_seen = true;
                Ok(())
            }
            Progress::Emit(output) => {
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
    let payload = if trace {
        serde_json::to_string(&shape_trace(native, private_seen))
    } else {
        serde_json::to_string(&shape_classic(native, private_seen))
    };
    payload.map_err(|error| BehaviorError::Internal(error.to_string()))
}

pub fn self_test() -> Result<(), String> {
    const RAW: &str = "; <<>> DiG 9.20 <<>> example.com -t A\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1\n;; ANSWER SECTION:\nexample.com. 60 IN A 93.184.216.34\n\n;; Query time: 12 msec\n;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)\n";
    let result = parse_classic(RAW, &[]);
    if result.status != Status::Finished
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
