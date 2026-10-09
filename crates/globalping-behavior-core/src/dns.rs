use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::net::IpAddr;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsStatus {
    Finished,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsAnswer {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub ttl: u32,
    pub class: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DnsTimings {
    pub total: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassicResult {
    pub status: DnsStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_source: Option<String>,
    pub status_code_name: Option<String>,
    pub status_code: Option<u16>,
    pub answers: Vec<DnsAnswer>,
    pub timings: DnsTimings,
    pub resolver: Option<String>,
    pub raw_output: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceHop {
    pub answers: Vec<DnsAnswer>,
    pub timings: DnsTimings,
    pub resolver: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceResult {
    pub status: DnsStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_source: Option<String>,
    pub hops: Vec<TraceHop>,
    pub raw_output: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsProgress {
    Ignore,
    Emit(String),
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsExecutionStatus {
    pub timed_out: bool,
    pub process_failed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsPolicy<'a> {
    pub target_is_icann: bool,
    pub local_addresses: &'a [String],
}

fn parse_answer_line(line: &str) -> Option<DnsAnswer> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 5 {
        return None;
    }
    let ttl = parts[1].parse::<u32>().ok()?;
    Some(DnsAnswer {
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
    line.strip_prefix(";; ")?.strip_suffix(" SECTION:")
}

fn address_is_private(address: IpAddr, local_addresses: &[String]) -> bool {
    crate::ip::is_private_or_reserved(
        address,
        local_addresses
            .iter()
            .filter_map(|local| local.parse::<IpAddr>().ok()),
    )
}

fn rewrite_classic(raw: &str, local_addresses: &[String]) -> String {
    raw.split('\n')
        .map(|line| {
            let Some(ip_text) = server_ip(line) else {
                return line.to_string();
            };
            if ip_text
                .parse::<IpAddr>()
                .is_ok_and(|address| address_is_private(address, local_addresses))
            {
                line.replace(ip_text, "x.x.x.x")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_classic_inner(raw: &str, local_addresses: &[String]) -> ClassicResult {
    let rewritten = rewrite_classic(raw, local_addresses);
    let lines = rewritten.split('\n').collect::<Vec<_>>();
    if lines.len() < 6
        || lines
            .first()
            .is_some_and(|line| line.starts_with(";; Got bad packet:"))
    {
        return ClassicResult {
            status: DnsStatus::Failed,
            failure_source: None,
            status_code_name: None,
            status_code: None,
            answers: Vec::new(),
            timings: DnsTimings::default(),
            resolver: None,
            raw_output: rewritten,
        };
    }

    let mut answers = Vec::new();
    let mut timings = DnsTimings::default();
    let mut resolver = None;
    let mut status_code_name = None;
    let mut status_code = None;
    let mut section = "header";
    for line in lines {
        if let Some(total) = parse_u32_after(line, "Query time:") {
            timings.total = total;
        }
        if let Some(name) = status_name(line) {
            status_code = status_number(&name);
            status_code_name = Some(name);
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
        status: DnsStatus::Finished,
        failure_source: None,
        status_code_name,
        status_code,
        answers,
        timings,
        resolver,
        raw_output: rewritten,
    }
}

/// Parse classic `dig` output and redact resolver addresses rejected by the shared policy.
#[must_use]
pub fn parse_classic(raw: &str, local_addresses: &[String]) -> ClassicResult {
    parse_classic_inner(raw, local_addresses)
}

fn trace_received(line: &str) -> Option<(String, u32)> {
    let tail = line.split_once(" from ")?.1;
    let open = tail.find('(')?;
    let after_open = &tail[open + 1..];
    let close = after_open.find(')')?;
    let resolver = after_open[..close].to_string();
    let total = parse_u32_after(&after_open[close + 1..], "in ")?;
    Some((resolver, total))
}

fn push_trace_hop(
    hops: &mut Vec<TraceHop>,
    answers: &mut Vec<DnsAnswer>,
    timings: &mut DnsTimings,
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

/// Parse `dig +trace` output.
#[must_use]
pub fn parse_trace(raw: &str) -> TraceResult {
    let lines = raw.split('\n').collect::<Vec<_>>();
    if lines.len() < 3
        || lines
            .first()
            .is_some_and(|line| line.starts_with(";; Got bad packet:"))
    {
        return TraceResult {
            status: DnsStatus::Failed,
            failure_source: None,
            hops: Vec::new(),
            raw_output: raw.to_string(),
        };
    }

    let mut hops = Vec::new();
    let mut answers = Vec::new();
    let mut timings = DnsTimings::default();
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
        status: DnsStatus::Finished,
        failure_source: None,
        hops,
        raw_output: raw.to_string(),
    }
}

fn answer_is_private(value: &str, local_addresses: &[String]) -> bool {
    value
        .parse::<IpAddr>()
        .is_ok_and(|address| address_is_private(address, local_addresses))
}

fn classic_has_private_answer_inner(result: &ClassicResult, policy: DnsPolicy<'_>) -> bool {
    !policy.target_is_icann
        && result
            .answers
            .iter()
            .any(|answer| answer_is_private(&answer.value, policy.local_addresses))
}

#[must_use]
pub fn classic_has_private_answer(result: &ClassicResult, policy: DnsPolicy<'_>) -> bool {
    classic_has_private_answer_inner(result, policy)
}

fn trace_has_private_answer_inner(result: &TraceResult, policy: DnsPolicy<'_>) -> bool {
    !policy.target_is_icann
        && result
            .hops
            .iter()
            .flat_map(|hop| &hop.answers)
            .any(|answer| answer_is_private(&answer.value, policy.local_addresses))
}

#[must_use]
pub fn trace_has_private_answer(result: &TraceResult, policy: DnsPolicy<'_>) -> bool {
    trace_has_private_answer_inner(result, policy)
}

/// Classify an incremental DNS stdout prefix for API progress.
#[must_use]
pub fn progress_output(raw: &str, trace: bool, policy: DnsPolicy<'_>) -> DnsProgress {
    if trace {
        let result = parse_trace(raw);
        if result.status == DnsStatus::Finished && trace_has_private_answer_inner(&result, policy) {
            return DnsProgress::Private;
        }
        return if result.status == DnsStatus::Finished
            || raw.to_ascii_lowercase().contains("connection refused")
        {
            DnsProgress::Emit(result.raw_output)
        } else {
            DnsProgress::Ignore
        };
    }

    let result = parse_classic_inner(raw, policy.local_addresses);
    if result.status == DnsStatus::Finished && classic_has_private_answer_inner(&result, policy) {
        return DnsProgress::Private;
    }
    if result.status == DnsStatus::Finished
        || raw.to_ascii_lowercase().contains("connection refused")
    {
        DnsProgress::Emit(result.raw_output)
    } else {
        DnsProgress::Ignore
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

fn failure_source(timed_out: bool, raw_output: &str) -> &'static str {
    if timed_out || resolver_failure(raw_output) {
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

fn apply_private_classic_failure(result: &mut ClassicResult) {
    let resolver = result.resolver.clone();
    result.status = DnsStatus::Failed;
    result.failure_source = Some("target".to_string());
    result.status_code_name = None;
    result.status_code = None;
    result.answers.clear();
    result.timings = DnsTimings::default();
    result.resolver = resolver;
    result.raw_output = "Private IP ranges are not allowed.".to_string();
}

fn apply_private_trace_failure(result: &mut TraceResult) {
    result.status = DnsStatus::Failed;
    result.failure_source = Some("target".to_string());
    result.hops.clear();
    result.raw_output = "Private IP ranges are not allowed.".to_string();
}

fn apply_failure(
    status: &mut DnsStatus,
    failure_source_out: &mut Option<String>,
    raw: &mut String,
    stderr: &str,
    timed_out: bool,
    process_failed: bool,
) {
    if timed_out {
        *status = DnsStatus::Failed;
        append_timeout(raw);
    }
    if timed_out || process_failed || *status == DnsStatus::Failed {
        *failure_source_out = Some(failure_source(timed_out, raw).to_string());
        if raw.trim().is_empty() && !stderr.trim().is_empty() {
            *raw = stderr.to_string();
        }
    }
}

#[must_use]
pub fn shape_classic_output(
    raw: &str,
    stderr: &str,
    execution: DnsExecutionStatus,
    private_result: bool,
    policy: DnsPolicy<'_>,
) -> ClassicResult {
    let mut result = parse_classic_inner(raw, policy.local_addresses);
    if private_result || classic_has_private_answer_inner(&result, policy) {
        apply_private_classic_failure(&mut result);
    } else {
        apply_failure(
            &mut result.status,
            &mut result.failure_source,
            &mut result.raw_output,
            stderr,
            execution.timed_out,
            execution.process_failed,
        );
    }
    result
}

#[must_use]
pub fn shape_trace_output(
    raw: &str,
    stderr: &str,
    execution: DnsExecutionStatus,
    private_result: bool,
    policy: DnsPolicy<'_>,
) -> TraceResult {
    let mut result = parse_trace(raw);
    if private_result || trace_has_private_answer_inner(&result, policy) {
        apply_private_trace_failure(&mut result);
    } else {
        apply_failure(
            &mut result.status,
            &mut result.failure_source,
            &mut result.raw_output,
            stderr,
            execution.timed_out,
            execution.process_failed,
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(target_is_icann: bool) -> DnsPolicy<'static> {
        DnsPolicy {
            target_is_icann,
            local_addresses: &[],
        }
    }

    fn classic(raw: &str) -> ClassicResult {
        parse_classic(raw, &[])
    }

    const SUCCESS_CLASSIC: &str = ";; Truncated, retrying in TCP mode.\n; <<>> DiG 9.16.1-Ubuntu <<>> google.com -t TXT -p 53 -4 +timeout=3 +tries=2 +nocookie\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29356\n;; flags: qr rd ra; QUERY: 1, ANSWER: 9, AUTHORITY: 0, ADDITIONAL: 0\n\n;; QUESTION SECTION:\n;google.com.\t\t\tIN\tTXT\n\n;; ANSWER SECTION:\ngoogle.com.\t\t3600\tIN\tTXT\t\"v=spf1 include:_spf.google.com ~all\"\n\n;; Query time: 0 msec\n;; SERVER: 192.168.0.49#53(192.168.0.49)\n;; WHEN: Mon Apr 04 12:25:44 UTC 2022\n;; MSG SIZE  rcvd: 614\n";
    const SUCCESS_TRACE: &str = "; <<>> DiG 9.18.1-1ubuntu1-Ubuntu <<>> +trace +nocookie cdn.jsdelivr.net\n;; global options: +cmd\n.\t\t\t6593\tIN\tNS\tj.root-servers.net.\n.\t\t\t6593\tIN\tNS\ta.root-servers.net.\n;; Received 811 bytes from 127.0.0.53#53(127.0.0.53) in 4 ms\n\ncdn.jsdelivr.net.\t900\tIN\tCNAME\tjsdelivr.map.fastly.net.\n;; Received 79 bytes from 185.136.98.122#53(gns3.cloudns.net) in 28 ms\n";

    #[test]
    fn classic_parser_preserves_native_fixture_behavior() {
        let result = classic(SUCCESS_CLASSIC);
        assert_eq!(result.status, DnsStatus::Finished);
        assert_eq!(result.status_code_name.as_deref(), Some("NOERROR"));
        assert_eq!(result.status_code, Some(0));
        assert_eq!(result.resolver.as_deref(), Some("private"));
        assert_eq!(result.answers.len(), 1);
        assert_eq!(result.answers[0].record_type, "TXT");
        assert!(result.answers[0].value.contains("v=spf1"));
        assert!(result.raw_output.contains("x.x.x.x"));
        assert!(!result.raw_output.contains("192.168.0.49"));
    }

    #[test]
    fn classic_connection_refused_and_bad_packet_fail() {
        let refused = classic(
            ";; Connection to 8.8.8.8#212(8.8.8.8) for abc.com failed: connection refused.",
        );
        assert_eq!(refused.status, DnsStatus::Failed);
        let bad = classic(";; Got bad packet: FORMERR\n205 bytes\nsome hex dump");
        assert_eq!(bad.status, DnsStatus::Failed);
    }

    #[test]
    fn classic_public_resolver_and_nxdomain_metadata_are_kept() {
        let raw = "; <<>> DiG 9.16 <<>> nxdomain-test.example\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 42\n;; flags: qr rd ra;\n\n;; QUESTION SECTION:\n;nxdomain-test.example.\tIN\tA\n\n;; ANSWER SECTION:\n\n;; Query time: 10 msec\n;; SERVER: 8.8.8.8#53(8.8.8.8)\n;; MSG SIZE  rcvd: 100\n";
        let result = classic(raw);
        assert_eq!(result.status_code_name.as_deref(), Some("NXDOMAIN"));
        assert_eq!(result.status_code, Some(3));
        assert_eq!(result.resolver.as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn trace_parser_preserves_hops_resolvers_and_timings() {
        let result = parse_trace(SUCCESS_TRACE);
        assert_eq!(result.status, DnsStatus::Finished);
        assert_eq!(result.hops.len(), 2);
        assert_eq!(result.hops[0].resolver.as_deref(), Some("127.0.0.53"));
        assert_eq!(result.hops[0].timings.total, 4);
        assert_eq!(result.hops[0].answers.len(), 2);
        assert_eq!(result.hops[1].resolver.as_deref(), Some("gns3.cloudns.net"));
        assert_eq!(result.hops[1].timings.total, 28);
    }

    #[test]
    fn answer_parser_preserves_txt_spaces() {
        let answer =
            parse_answer_line("google.com. 3600 IN TXT \"v=spf1 include:_spf.google.com ~all\"")
                .unwrap_or_else(|| panic!("TXT fixture did not parse"));
        assert_eq!(answer.record_type, "TXT");
        assert_eq!(answer.value, "\"v=spf1 include:_spf.google.com ~all\"");
    }

    #[test]
    fn answer_parser_preserves_ns_record() {
        let answer = parse_answer_line("example.com. 3600 IN NS ns1.example.net.")
            .unwrap_or_else(|| panic!("NS fixture did not parse"));
        assert_eq!(answer.name, "example.com.");
        assert_eq!(answer.ttl, 3600);
        assert_eq!(answer.class, "IN");
        assert_eq!(answer.record_type, "NS");
        assert_eq!(answer.value, "ns1.example.net.");
    }

    #[test]
    fn trace_bad_packet_returns_failed() {
        let result = parse_trace(";; Got bad packet: FORMERR\n205 bytes\nsome hex dump\n");
        assert_eq!(result.status, DnsStatus::Failed);
        assert_eq!(result.hops.len(), 0);
    }

    #[test]
    fn non_icann_private_answer_is_suppressed_in_progress_and_final() {
        let raw = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;printer.lan. IN A\n\n;; ANSWER SECTION:\nprinter.lan. 60 IN A 192.168.1.5\n\n;; Query time: 1 msec\n;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)\n";
        assert_eq!(
            progress_output(raw, false, policy(false)),
            DnsProgress::Private
        );
        let result = shape_classic_output(
            raw,
            "",
            DnsExecutionStatus {
                timed_out: false,
                process_failed: false,
            },
            false,
            policy(false),
        );
        assert_eq!(result.status, DnsStatus::Failed);
        assert_eq!(result.failure_source.as_deref(), Some("target"));
        assert_eq!(result.raw_output, "Private IP ranges are not allowed.");
        assert!(result.answers.is_empty());
        assert_eq!(result.resolver.as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn icann_private_answer_is_allowed() {
        let raw = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;example.com. IN A\n\n;; ANSWER SECTION:\nexample.com. 60 IN A 192.168.1.5\n\n;; Query time: 1 msec\n;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)\n";
        let result = shape_classic_output(
            raw,
            "",
            DnsExecutionStatus {
                timed_out: false,
                process_failed: false,
            },
            false,
            policy(true),
        );
        assert_eq!(result.status, DnsStatus::Finished);
        assert_eq!(result.answers.len(), 1);
    }

    #[test]
    fn timeout_appends_public_message_and_uses_resolver_failure_source() {
        let result = shape_classic_output(
            SUCCESS_CLASSIC,
            "",
            DnsExecutionStatus {
                timed_out: true,
                process_failed: true,
            },
            false,
            policy(true),
        );
        assert_eq!(result.status, DnsStatus::Failed);
        assert_eq!(result.failure_source.as_deref(), Some("resolver"));
        assert!(
            result
                .raw_output
                .ends_with("The measurement command timed out.")
        );
    }
}
