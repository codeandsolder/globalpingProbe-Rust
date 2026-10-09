pub mod parse;

use super::{ProgressTx, RawExecutionTx};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio::process::Command;
use tokio::time::timeout;

use crate::util::measurement_timeout::process_timeout;
use crate::util::private_ip::is_ip_private;
use crate::util::validate::is_safe_host;
#[cfg(test)]
use parse::DnsStatus;
use parse::{ClassicResult, TraceResult};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsOptions {
    pub target: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub resolver: Option<String>,
    #[serde(default)]
    pub trace: bool,
    #[serde(default)]
    pub query: QueryOptions,
    #[serde(default = "default_ip_version")]
    pub ip_version: u8,
    #[serde(default)]
    pub in_progress_updates: bool,
    pub timeout: u32,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct QueryOptions {
    #[serde(rename = "type", default = "default_query_type")]
    pub record_type: String,
}

fn default_protocol() -> String {
    "UDP".into()
}
const fn default_port() -> u16 {
    53
}
const fn default_ip_version() -> u8 {
    4
}
fn default_query_type() -> String {
    "A".into()
}

const ALLOWED_TYPES: &[&str] = &[
    "A", "AAAA", "ANY", "CNAME", "DNSKEY", "DS", "HTTPS", "MX", "NS", "NSEC", "PTR", "RRSIG",
    "SOA", "TXT", "SRV", "SVCB",
];
const ALLOWED_PROTOCOLS: &[&str] = &["UDP", "TCP"];

pub(crate) fn validate(opts: &DnsOptions) -> Result<()> {
    if !ALLOWED_TYPES.contains(&opts.query.record_type.as_str()) {
        bail!("unsupported query type: {}", opts.query.record_type);
    }
    if !ALLOWED_PROTOCOLS
        .iter()
        .any(|protocol| protocol.eq_ignore_ascii_case(&opts.protocol))
    {
        bail!("protocol must be UDP or TCP");
    }
    if opts.ip_version != 4 && opts.ip_version != 6 {
        bail!("ipVersion must be 4 or 6");
    }
    if !is_safe_host(&opts.target) {
        bail!("Invalid target.");
    }
    if let Some(resolver) = &opts.resolver {
        if !is_safe_host(resolver) {
            bail!("Invalid resolver.");
        }
        if let Ok(ip) = resolver.parse()
            && is_ip_private(ip)
        {
            bail!("Private IP ranges are not allowed.");
        }
    }
    Ok(())
}

#[must_use]
pub fn build_args(opts: &DnsOptions) -> Vec<String> {
    let mut args = Vec::new();
    if opts.query.record_type == "PTR" {
        args.push("-x".into());
    } else {
        args.push("-t".into());
        args.push(opts.query.record_type.clone());
    }
    args.push(opts.target.clone());
    if let Some(resolver) = &opts.resolver {
        args.push(format!("@{resolver}"));
    }
    args.push("-p".into());
    args.push(opts.port.to_string());
    args.push(format!("-{}", opts.ip_version));
    let native_timeout = if opts.trace { 3 } else { opts.timeout / 2 };
    args.push(format!("+timeout={native_timeout}"));
    args.push("+tries=2".into());
    args.push("+nofail".into());
    args.push("+nocookie".into());
    args.push("+nosplit".into());
    args.push("+nsid".into());
    if opts.trace {
        args.push("+trace".into());
    }
    if opts.protocol.eq_ignore_ascii_case("tcp") {
        args.push("+tcp".into());
    }
    args
}

pub struct DnsCommand;

impl DnsCommand {
    /// # Errors
    /// Returns an error for invalid options, rejected targets, process failures, or serialization failures.
    pub async fn run(&self, options: Value) -> Result<Value> {
        self.run_inner(options, None).await
    }

    /// # Errors
    /// Returns an error for invalid options, rejected targets, process failures, or serialization failures.
    pub async fn run_with_progress(&self, options: Value, tx: ProgressTx) -> Result<Value> {
        self.run_inner(options, Some(tx)).await
    }

    async fn run_inner(&self, options: Value, progress: Option<ProgressTx>) -> Result<Value> {
        let opts: DnsOptions = serde_json::from_value(options)?;
        validate(&opts)?;
        let native = run_dig(&opts, progress.as_ref()).await?;
        let process_failed = native.status.is_some_and(|status| !status.success());
        let result = if opts.trace {
            serde_json::to_value(shape_trace_output(
                &native.raw,
                &native.stderr,
                native.timed_out,
                process_failed,
                native.private_result,
                &opts.target,
            ))?
        } else {
            serde_json::to_value(shape_classic_output(
                &native.raw,
                &native.stderr,
                native.timed_out,
                process_failed,
                native.private_result,
                &opts.target,
            ))?
        };
        Ok(result)
    }
}

pub(crate) struct NativeDnsOutput {
    pub(crate) raw: String,
    pub(crate) stderr: String,
    pub(crate) timed_out: bool,
    pub(crate) status: Option<std::process::ExitStatus>,
    pub(crate) private_result: bool,
}

pub(crate) use globalping_behavior_core::dns::DnsProgress;

fn target_is_icann(target: &str) -> bool {
    psl::suffix(target.trim_end_matches('.').as_bytes())
        .is_some_and(|suffix| suffix.typ() == Some(psl::Type::Icann))
}

pub(crate) fn dns_progress_output(raw: &str, opts: &DnsOptions) -> DnsProgress {
    let local_addresses = crate::util::private_ip::local_address_strings();
    globalping_behavior_core::dns::progress_output(
        raw,
        opts.trace,
        globalping_behavior_core::dns::DnsPolicy {
            target_is_icann: target_is_icann(&opts.target),
            local_addresses: &local_addresses,
        },
    )
}

pub(crate) async fn run_dig(
    opts: &DnsOptions,
    progress: Option<&ProgressTx>,
) -> Result<NativeDnsOutput> {
    run_dig_inner(opts, progress, None).await
}

pub(crate) async fn run_dig_stream(
    opts: &DnsOptions,
    progress: Option<&ProgressTx>,
    raw_events: &RawExecutionTx,
) -> Result<NativeDnsOutput> {
    run_dig_inner(opts, progress, Some(raw_events)).await
}

async fn run_dig_inner(
    opts: &DnsOptions,
    progress: Option<&ProgressTx>,
    raw_events: Option<&RawExecutionTx>,
) -> Result<NativeDnsOutput> {
    let mut child = Command::new("dig")
        .args(build_args(opts))
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .context("child stdout pipe was unavailable")?;
    let mut stderr = child
        .stderr
        .take()
        .context("child stderr pipe was unavailable")?;
    let raw_stderr = raw_events.cloned();
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            match stderr.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    bytes.extend_from_slice(&chunk[..read]);
                    if let Some(tx) = &raw_stderr {
                        tx.stderr_chunk(&chunk[..read]).await;
                    }
                }
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    });
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let mut raw = String::new();
    let mut private_result = false;
    let completed = timeout(process_timeout(f64::from(opts.timeout)), async {
        while let Some(line) = lines.next_line().await? {
            raw.push_str(&line);
            raw.push('\n');
            if let Some(tx) = raw_events {
                tx.stdout_line(&line).await;
            }
            match dns_progress_output(&raw, opts) {
                DnsProgress::Private => {
                    private_result = true;
                    child.kill().await.ok();
                    break;
                }
                DnsProgress::Emit(output) => {
                    if let Some(tx) = progress {
                        tx.send(json!({ "rawOutput": output })).ok();
                    }
                }
                DnsProgress::Ignore => {}
            }
        }
        child.wait().await
    })
    .await;
    let (timed_out, status) = if let Ok(result) = completed {
        (false, Some(result?))
    } else {
        child.kill().await.ok();
        (true, child.wait().await.ok())
    };
    Ok(NativeDnsOutput {
        raw,
        stderr: stderr_task.await.unwrap_or_default(),
        timed_out,
        status,
        private_result,
    })
}

pub(crate) fn shape_classic_output(
    raw: &str,
    stderr: &str,
    timed_out: bool,
    process_failed: bool,
    private_result: bool,
    target: &str,
) -> ClassicResult {
    let local_addresses = crate::util::private_ip::local_address_strings();
    globalping_behavior_core::dns::shape_classic_output(
        raw,
        stderr,
        globalping_behavior_core::dns::DnsExecutionStatus {
            timed_out,
            process_failed,
        },
        private_result,
        globalping_behavior_core::dns::DnsPolicy {
            target_is_icann: target_is_icann(target),
            local_addresses: &local_addresses,
        },
    )
}

pub(crate) fn shape_trace_output(
    raw: &str,
    stderr: &str,
    timed_out: bool,
    process_failed: bool,
    private_result: bool,
    target: &str,
) -> TraceResult {
    let local_addresses = crate::util::private_ip::local_address_strings();
    globalping_behavior_core::dns::shape_trace_output(
        raw,
        stderr,
        globalping_behavior_core::dns::DnsExecutionStatus {
            timed_out,
            process_failed,
        },
        private_result,
        globalping_behavior_core::dns::DnsPolicy {
            target_is_icann: target_is_icann(target),
            local_addresses: &local_addresses,
        },
    )
}

/// # Errors
/// Returns an error if the `dig` process cannot be executed or its output cannot be read.
pub async fn query_classic(
    target: &str,
    record_type: &str,
    resolver: Option<&str>,
) -> Result<ClassicResult> {
    let opts = DnsOptions {
        target: target.to_string(),
        protocol: "UDP".into(),
        port: 53,
        resolver: resolver.map(str::to_string),
        trace: false,
        query: QueryOptions {
            record_type: record_type.to_string(),
        },
        ip_version: 4,
        in_progress_updates: false,
        timeout: 10,
    };
    let native = run_dig(&opts, None).await?;
    let process_failed = native.status.is_some_and(|status| !status.success());
    Ok(shape_classic_output(
        &native.raw,
        &native.stderr,
        native.timed_out,
        process_failed,
        native.private_result,
        target,
    ))
}

/// # Errors
/// Returns an error if the `dig` process cannot be executed or its output cannot be read.
pub async fn query_trace(target: &str, resolver: Option<&str>) -> Result<TraceResult> {
    let opts = DnsOptions {
        target: target.to_string(),
        protocol: "UDP".into(),
        port: 53,
        resolver: resolver.map(str::to_string),
        trace: true,
        query: QueryOptions {
            record_type: "A".to_string(),
        },
        ip_version: 4,
        in_progress_updates: false,
        timeout: 10,
    };
    let native = run_dig(&opts, None).await?;
    let process_failed = native.status.is_some_and(|status| !status.success());
    Ok(shape_trace_output(
        &native.raw,
        &native.stderr,
        native.timed_out,
        process_failed,
        native.private_result,
        target,
    ))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_opts(record_type: &str, trace: bool, protocol: &str) -> DnsOptions {
        DnsOptions {
            target: "example.com".into(),
            protocol: protocol.into(),
            port: 53,
            resolver: None,
            trace,
            query: QueryOptions {
                record_type: record_type.into(),
            },
            ip_version: 4,
            in_progress_updates: false,
            timeout: 10,
        }
    }

    #[test]
    fn build_args_basic_a_query() {
        let opts = make_opts("A", false, "UDP");
        let args = build_args(&opts);
        assert_eq!(args[0], "-t");
        assert_eq!(args[1], "A");
        assert_eq!(args[2], "example.com");
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"53".to_string()));
        assert!(args.contains(&"-4".to_string()));
        assert!(args.contains(&"+timeout=5".to_string()));
        assert!(args.contains(&"+nofail".to_string()));
        assert!(!args.contains(&"+trace".to_string()));
        assert!(!args.contains(&"+tcp".to_string()));
    }

    #[test]
    fn build_args_ptr_uses_dash_x() {
        let opts = make_opts("PTR", false, "UDP");
        let args = build_args(&opts);
        assert_eq!(args[0], "-x");
        assert_eq!(args[1], "example.com");
    }

    #[test]
    fn build_args_trace_adds_plus_trace() {
        let opts = make_opts("A", true, "UDP");
        let args = build_args(&opts);
        assert!(args.contains(&"+trace".to_string()));
    }

    #[test]
    fn build_args_tcp_protocol_adds_plus_tcp() {
        let opts = make_opts("A", false, "TCP");
        let args = build_args(&opts);
        assert!(args.contains(&"+tcp".to_string()));
    }

    #[test]
    fn build_args_resolver_prefixed_with_at() {
        let mut opts = make_opts("A", false, "UDP");
        opts.resolver = Some("8.8.8.8".into());
        let args = build_args(&opts);
        assert!(args.contains(&"@8.8.8.8".to_string()));
    }

    #[test]
    fn build_args_ipv6_flag() {
        let mut opts = make_opts("AAAA", false, "UDP");
        opts.ip_version = 6;
        let args = build_args(&opts);
        assert!(args.contains(&"-6".to_string()));
    }

    #[test]
    fn validate_rejects_unknown_type() {
        let opts = make_opts("INVALID", false, "UDP");
        assert!(validate(&opts).is_err());
    }

    #[test]
    fn validate_accepts_all_allowed_types() {
        for &t in ALLOWED_TYPES {
            let opts = make_opts(t, false, "UDP");
            assert!(validate(&opts).is_ok(), "type {t} should be allowed");
        }
    }

    #[test]
    fn validate_rejects_argument_injection_target() {
        // Target is passed to `dig` as a bare arg; a leading `-`/`+` would be an option.
        for bad in ["-f/etc/passwd", "+norecurse", "evil.com; id", "a b"] {
            let mut opts = make_opts("A", false, "UDP");
            opts.target = bad.into();
            assert!(validate(&opts).is_err(), "should reject target {bad:?}");
        }
    }

    #[test]
    fn validate_rejects_private_resolver() {
        // Prevents using the probe as an internal port scanner over DNS (SSRF).
        for bad in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "::1",
            "::ffff:127.0.0.1",
        ] {
            let mut opts = make_opts("A", false, "UDP");
            opts.resolver = Some(bad.into());
            assert!(validate(&opts).is_err(), "should reject resolver {bad:?}");
        }
    }

    #[test]
    fn validate_accepts_public_resolver() {
        let mut opts = make_opts("A", false, "UDP");
        opts.resolver = Some("8.8.8.8".into());
        assert!(validate(&opts).is_ok());
    }

    #[test]
    fn validate_rejects_injection_resolver() {
        let mut opts = make_opts("A", false, "UDP");
        opts.resolver = Some("-x".into());
        assert!(validate(&opts).is_err());
    }
    fn private_answer_fixture(name: &str, ip: &str) -> String {
        format!(
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; QUESTION SECTION:\n;{name}. IN A\n\n;; ANSWER SECTION:\n{name}. 60 IN A {ip}\n\n;; Query time: 1 msec\n;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)\n"
        )
    }

    #[test]
    fn private_answer_rejected_for_non_icann_target() {
        let raw = private_answer_fixture("printer.lan", "192.168.1.5");
        let failed = shape_classic_output(&raw, "", false, false, false, "printer.lan");
        assert_eq!(failed.status, DnsStatus::Failed);
        assert_eq!(failed.failure_source.as_deref(), Some("target"));
        assert_eq!(failed.raw_output, "Private IP ranges are not allowed.");
        assert_eq!(failed.answers.len(), 0);
        assert_eq!(failed.resolver.as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn private_answer_allowed_for_icann_target() {
        let raw = private_answer_fixture("example.com", "192.168.1.5");
        let result = shape_classic_output(&raw, "", false, false, false, "example.com");
        assert_eq!(result.status, DnsStatus::Finished);
        assert_eq!(result.answers.len(), 1);
    }

    #[test]
    fn psl_private_section_is_not_icann() {
        assert!(target_is_icann("example.com"));
        assert!(!target_is_icann("foo.blogspot.com"));
        assert!(!target_is_icann("printer.lan"));
    }
    #[test]
    fn progress_suppresses_private_answer_for_non_icann_target() {
        let mut opts = make_opts("A", false, "UDP");
        opts.target = "printer.lan".into();
        let raw = private_answer_fixture("printer.lan", "192.168.1.5");
        assert!(matches!(
            dns_progress_output(&raw, &opts),
            DnsProgress::Private
        ));
    }

    #[test]
    fn progress_keeps_private_answer_for_icann_target() {
        let opts = make_opts("A", false, "UDP");
        let raw = private_answer_fixture("example.com", "192.168.1.5");
        assert!(matches!(
            dns_progress_output(&raw, &opts),
            DnsProgress::Emit(_)
        ));
    }
}
