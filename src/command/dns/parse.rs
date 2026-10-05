use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::util::private_ip::is_ip_private;

// ── Shared types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsStatus {
    Finished,
    Failed,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub ttl: u32,
    pub class: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct DnsTimings {
    pub total: u32,
}

// ── Classic output types ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClassicResult {
    pub status: DnsStatus,
    pub status_code_name: Option<String>,
    pub status_code: Option<u16>,
    pub answers: Vec<DnsAnswer>,
    pub timings: DnsTimings,
    pub resolver: Option<String>,
    pub raw_output: String,
}

// ── Trace output types ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TraceHop {
    pub answers: Vec<DnsAnswer>,
    pub timings: DnsTimings,
    pub resolver: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TraceResult {
    pub status: DnsStatus,
    pub hops: Vec<TraceHop>,
    pub raw_output: String,
}

// ── Regex patterns ────────────────────────────────────────────────────────────

fn compile_regex(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

static SECTION_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"(;; )(\S+)( SECTION:)"));
static QUERY_TIME_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"Query\s+time:\s+(\d+)"));
static RESOLVER_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"SERVER:.*?\((.*?)\)"));
static STATUS_CODE_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"status:\s*([A-Z]+)"));
// Trace: ";; Received N bytes from IP#53(name) in N ms"
static TRACE_RECEIVED_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"from\s+\S+\(([^)]+)\)\s+in\s+(\d+)\s+ms"));
// Match an IPv4 or IPv6 address in a SERVER line
static IP_IN_SERVER_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile_regex(r"SERVER:\s*([^\s#]+)"));

// ── Status code map ───────────────────────────────────────────────────────────

static STATUS_MAP: LazyLock<HashMap<&'static str, u16>> = LazyLock::new(|| {
    [
        ("noerror", 0),
        ("formerr", 1),
        ("servfail", 2),
        ("nxdomain", 3),
        ("notimp", 4),
        ("refused", 5),
        ("yxdomain", 6),
        ("yxrrset", 7),
        ("nxrrset", 8),
        ("notauth", 9),
        ("notzone", 10),
        ("dsotypeni", 11),
        ("badvers", 16),
        ("badsig", 16),
        ("badkey", 17),
        ("badtime", 18),
        ("badmode", 19),
        ("badname", 20),
        ("badalg", 21),
        ("badtrunc", 22),
        ("badcookie", 23),
    ]
    .into_iter()
    .collect()
});

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse classic `dig` output (no +trace).
pub fn parse_classic(raw: &str) -> ClassicResult {
    let rewritten = rewrite_classic(raw);
    let lines: Vec<&str> = rewritten.split('\n').collect();

    let failed = |output: &str| ClassicResult {
        status: DnsStatus::Failed,
        status_code_name: None,
        status_code: None,
        answers: vec![],
        timings: DnsTimings::default(),
        resolver: None,
        raw_output: output.to_string(),
    };

    if lines.len() < 6
        || lines
            .first()
            .is_some_and(|l| l.starts_with(";; Got bad packet:"))
    {
        return failed(&rewritten);
    }

    let mut answers: Vec<DnsAnswer> = vec![];
    let mut timings = DnsTimings::default();
    let mut resolver: Option<String> = None;
    let mut status_code_name: Option<String> = None;
    let mut status_code: Option<u16> = None;
    let mut section = "header";
    let mut section_changed;

    for line in &lines {
        if let Some(caps) = QUERY_TIME_RE.as_ref().and_then(|re| re.captures(line)) {
            timings.total = caps[1].parse().unwrap_or(0);
        }
        if let Some(caps) = STATUS_CODE_RE.as_ref().and_then(|re| re.captures(line)) {
            let name = caps[1].to_string();
            status_code = STATUS_MAP.get(name.to_lowercase().as_str()).copied();
            status_code_name = Some(name);
        }
        if let Some(caps) = RESOLVER_RE.as_ref().and_then(|re| re.captures(line)) {
            let ip = &caps[1];
            resolver = Some(if ip == "x.x.x.x" {
                "private".into()
            } else {
                ip.to_string()
            });
        }

        section_changed = false;
        if line.is_empty() {
            section = "";
        } else if let Some(caps) = SECTION_RE.as_ref().and_then(|re| re.captures(line)) {
            section = match &caps[2] {
                s if s.eq_ignore_ascii_case("ANSWER") => "answer",
                s if s.eq_ignore_ascii_case("QUESTION") => "question",
                s if s.eq_ignore_ascii_case("AUTHORITY") => "authority",
                s if s.eq_ignore_ascii_case("ADDITIONAL") => "additional",
                _ => "other",
            };
            section_changed = true;
        }

        if section.is_empty() || section_changed {
            continue;
        }
        if section == "answer"
            && !line.starts_with(';')
            && let Some(answer) = parse_answer_line(line)
        {
            answers.push(answer);
        }
    }

    ClassicResult {
        status: DnsStatus::Finished,
        status_code_name,
        status_code,
        answers,
        timings,
        resolver,
        raw_output: rewritten,
    }
}

/// Parse `dig +trace` output.
#[must_use]
pub fn parse_trace(raw: &str) -> TraceResult {
    let lines: Vec<&str> = raw.split('\n').collect();

    let failed = || TraceResult {
        status: DnsStatus::Failed,
        hops: vec![],
        raw_output: raw.to_string(),
    };

    if lines.len() < 3
        || lines
            .first()
            .is_some_and(|l| l.starts_with(";; Got bad packet:"))
    {
        return failed();
    }

    // Pass all lines; parse_trace_hops ignores ;;-comments and non-answer lines naturally.
    let hops = parse_trace_hops(&lines);

    TraceResult {
        status: DnsStatus::Finished,
        hops,
        raw_output: raw.to_string(),
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Replace private IPs in the SERVER line with "x.x.x.x" so the output is
/// safe to transmit and the parser maps them to resolver = "private".
fn rewrite_classic(raw: &str) -> String {
    raw.split('\n')
        .map(|line| {
            if !line.contains("SERVER:") {
                return line.to_string();
            }
            // Extract the IP before '#'
            if let Some(caps) = IP_IN_SERVER_RE.as_ref().and_then(|re| re.captures(line)) {
                let ip_str = &caps[1];
                if let Ok(ip) = ip_str.parse()
                    && is_ip_private(ip)
                {
                    return line.replace(ip_str, "x.x.x.x");
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse one answer line: `name  TTL  class  type  value...`
fn parse_answer_line(line: &str) -> Option<DnsAnswer> {
    let parts: Vec<&str> = line.split_whitespace().collect();
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

fn parse_trace_hops(lines: &[&str]) -> Vec<TraceHop> {
    let mut hops: Vec<TraceHop> = vec![];
    let mut current_answers: Vec<DnsAnswer> = vec![];
    let mut current_timings = DnsTimings::default();
    let mut current_resolver: Option<String> = None;

    let push_hop = |hops: &mut Vec<TraceHop>,
                    answers: &mut Vec<DnsAnswer>,
                    timings: &mut DnsTimings,
                    resolver: &mut Option<String>| {
        if !answers.is_empty() || resolver.is_some() {
            hops.push(TraceHop {
                answers: std::mem::take(answers),
                timings: std::mem::take(timings),
                resolver: resolver.take(),
            });
        }
    };

    for line in lines {
        if line.is_empty() {
            push_hop(
                &mut hops,
                &mut current_answers,
                &mut current_timings,
                &mut current_resolver,
            );
            continue;
        }
        if line.starts_with(";;") {
            if let Some(caps) = TRACE_RECEIVED_RE.as_ref().and_then(|re| re.captures(line)) {
                current_resolver = Some(caps[1].to_string());
                current_timings.total = caps[2].parse().unwrap_or(0);
            }
            continue;
        }
        if let Some(answer) = parse_answer_line(line) {
            current_answers.push(answer);
        }
    }

    // Flush any final hop not followed by a blank line
    push_hop(
        &mut hops,
        &mut current_answers,
        &mut current_timings,
        &mut current_resolver,
    );

    hops
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SUCCESS_CLASSIC: &str = ";; Truncated, retrying in TCP mode.\n\
; <<>> DiG 9.16.1-Ubuntu <<>> google.com -t TXT -p 53 -4 +timeout=3 +tries=2 +nocookie\n\
;; global options: +cmd\n\
;; Got answer:\n\
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29356\n\
;; flags: qr rd ra; QUERY: 1, ANSWER: 9, AUTHORITY: 0, ADDITIONAL: 0\n\
\n\
;; QUESTION SECTION:\n\
;google.com.\t\t\tIN\tTXT\n\
\n\
;; ANSWER SECTION:\n\
google.com.\t\t3600\tIN\tTXT\t\"v=spf1 include:_spf.google.com ~all\"\n\
\n\
;; Query time: 0 msec\n\
;; SERVER: 192.168.0.49#53(192.168.0.49)\n\
;; WHEN: Mon Apr 04 12:25:44 UTC 2022\n\
;; MSG SIZE  rcvd: 614\n";

    const CONNECTION_REFUSED: &str =
        ";; Connection to 8.8.8.8#212(8.8.8.8) for abc.com failed: connection refused.";

    const FORMERR: &str = ";; Got bad packet: FORMERR\n205 bytes\nsome hex dump";

    const SUCCESS_TRACE: &str = "; <<>> DiG 9.18.1-1ubuntu1-Ubuntu <<>> +trace +nocookie cdn.jsdelivr.net\n\
;; global options: +cmd\n\
.\t\t\t6593\tIN\tNS\tj.root-servers.net.\n\
.\t\t\t6593\tIN\tNS\ta.root-servers.net.\n\
;; Received 811 bytes from 127.0.0.53#53(127.0.0.53) in 4 ms\n\
\n\
cdn.jsdelivr.net.\t900\tIN\tCNAME\tjsdelivr.map.fastly.net.\n\
;; Received 79 bytes from 185.136.98.122#53(gns3.cloudns.net) in 28 ms\n";

    // ── Classic ──────────────────────────────────────────────────────────────

    #[test]
    fn classic_parses_answers_and_metadata() {
        let r = parse_classic(SUCCESS_CLASSIC);
        assert_eq!(r.status, DnsStatus::Finished);
        assert_eq!(r.status_code_name.as_deref(), Some("NOERROR"));
        assert_eq!(r.status_code, Some(0));
        assert_eq!(r.timings.total, 0);
        // Private SERVER IP → rewritten to "private"
        assert_eq!(r.resolver.as_deref(), Some("private"));
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].name, "google.com.");
        assert_eq!(r.answers[0].record_type, "TXT");
        assert_eq!(r.answers[0].ttl, 3600);
        assert_eq!(r.answers[0].class, "IN");
        assert!(r.answers[0].value.contains("v=spf1"));
        // rawOutput must contain the rewritten IP
        assert!(r.raw_output.contains("x.x.x.x"));
        assert!(!r.raw_output.contains("192.168.0.49"));
    }

    #[test]
    fn classic_connection_refused_returns_failed() {
        let r = parse_classic(CONNECTION_REFUSED);
        assert_eq!(r.status, DnsStatus::Failed);
        assert!(r.answers.is_empty());
        assert_eq!(r.resolver, None);
        assert!(r.raw_output.contains("connection refused"));
    }

    #[test]
    fn classic_bad_packet_returns_failed() {
        let r = parse_classic(FORMERR);
        assert_eq!(r.status, DnsStatus::Failed);
    }

    #[test]
    fn classic_public_resolver_is_kept_as_is() {
        let output = "; <<>> DiG 9.16 <<>> google.com\n\
;; global options: +cmd\n\
;; Got answer:\n\
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n\
;; flags: qr rd ra;\n\
\n\
;; QUESTION SECTION:\n\
;google.com.\tIN\tA\n\
\n\
;; ANSWER SECTION:\n\
google.com.\t300\tIN\tA\t142.250.200.46\n\
\n\
;; Query time: 5 msec\n\
;; SERVER: 8.8.8.8#53(8.8.8.8)\n\
;; MSG SIZE  rcvd: 55\n";
        let r = parse_classic(output);
        assert_eq!(r.resolver.as_deref(), Some("8.8.8.8"));
        assert!(!r.raw_output.contains("x.x.x.x"));
    }

    #[test]
    fn classic_nxdomain_status_code() {
        let output = "; <<>> DiG 9.16 <<>> nxdomain-test.example\n\
;; global options: +cmd\n\
;; Got answer:\n\
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 42\n\
;; flags: qr rd ra;\n\
\n\
;; QUESTION SECTION:\n\
;nxdomain-test.example.\tIN\tA\n\
\n\
;; ANSWER SECTION:\n\
\n\
;; Query time: 10 msec\n\
;; SERVER: 8.8.8.8#53(8.8.8.8)\n\
;; MSG SIZE  rcvd: 100\n";
        let r = parse_classic(output);
        assert_eq!(r.status_code_name.as_deref(), Some("NXDOMAIN"));
        assert_eq!(r.status_code, Some(3));
    }

    // ── Trace ─────────────────────────────────────────────────────────────────

    #[test]
    fn trace_parses_hops_resolvers_timings() {
        let r = parse_trace(SUCCESS_TRACE);
        assert_eq!(r.status, DnsStatus::Finished);
        assert_eq!(r.hops.len(), 2);

        let hop0 = &r.hops[0];
        assert_eq!(hop0.resolver.as_deref(), Some("127.0.0.53"));
        assert_eq!(hop0.timings.total, 4);
        assert_eq!(hop0.answers.len(), 2);
        assert_eq!(hop0.answers[0].name, ".");
        assert_eq!(hop0.answers[0].record_type, "NS");

        let hop1 = &r.hops[1];
        assert_eq!(hop1.resolver.as_deref(), Some("gns3.cloudns.net"));
        assert_eq!(hop1.timings.total, 28);
        assert_eq!(hop1.answers[0].record_type, "CNAME");
    }

    #[test]
    fn trace_bad_packet_returns_failed() {
        let r = parse_trace(";; Got bad packet: FORMERR\n1 line\n");
        assert_eq!(r.status, DnsStatus::Failed);
    }

    // ── Answer line parsing ───────────────────────────────────────────────────

    #[test]
    fn answer_line_parses_txt_with_spaces() {
        let line = "google.com.\t3600\tIN\tTXT\t\"v=spf1 include:_spf.google.com ~all\"";
        let a = parse_answer_line(line).unwrap();
        assert_eq!(a.name, "google.com.");
        assert_eq!(a.record_type, "TXT");
        assert_eq!(a.ttl, 3600);
        assert_eq!(a.class, "IN");
        assert_eq!(a.value, "\"v=spf1 include:_spf.google.com ~all\"");
    }

    #[test]
    fn answer_line_parses_ns_record() {
        let line = ".\t6593\tIN\tNS\tj.root-servers.net.";
        let a = parse_answer_line(line).unwrap();
        assert_eq!(a.name, ".");
        assert_eq!(a.record_type, "NS");
        assert_eq!(a.ttl, 6593);
        assert_eq!(a.value, "j.root-servers.net.");
    }
}
