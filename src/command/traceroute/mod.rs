pub mod parse;

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio::process::Command;
use tokio::time::timeout;

use super::ProgressTx;
use crate::util::measurement_timeout::{MeasurementDeadline, traceroute_budget};
use crate::util::private_ip::is_ip_private;
use crate::util::resolve_target::{
    ResolveTargetError, ResolvedTarget, resolve_command_target, reverse_lookup,
};
use crate::util::validate::is_safe_host;
use parse::{ParsedTraceroute, TracerouteStatus, parse};

const TRACEROUTE_PACKETS: u8 = 2;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TracerouteOptions {
    pub target: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_ip_version")]
    pub ip_version: u8,
    #[serde(default)]
    pub in_progress_updates: bool,
    pub timeout: u32,
}

fn default_protocol() -> String {
    "ICMP".into()
}
const fn default_port() -> u16 {
    80
}
const fn default_ip_version() -> u8 {
    4
}

fn validate(opts: &TracerouteOptions) -> Result<()> {
    if !is_safe_host(&opts.target) {
        bail!("Invalid target.");
    }
    if opts.ip_version != 4 && opts.ip_version != 6 {
        bail!("ipVersion must be 4 or 6");
    }
    let proto = opts.protocol.to_uppercase();
    if proto != "ICMP" && proto != "TCP" && proto != "UDP" {
        bail!("protocol must be ICMP, TCP, or UDP");
    }
    Ok(())
}

#[must_use]
pub fn build_args(opts: &TracerouteOptions) -> Vec<String> {
    let budget = traceroute_budget(opts.timeout, TRACEROUTE_PACKETS);
    let mut args = vec![
        "-n".into(),
        format!("-{}", opts.ip_version),
        "-m".into(),
        "20".into(),
        "-w".into(),
        budget.wait.to_string(),
        "-q".into(),
        TRACEROUTE_PACKETS.to_string(),
        "-N".into(),
        "20".into(),
        format!("--{}", opts.protocol.to_lowercase()),
    ];
    if opts.protocol.eq_ignore_ascii_case("TCP") {
        args.push("-p".into());
        args.push(opts.port.to_string());
    }
    args.push(opts.target.clone());
    args
}

pub struct TracerouteCommand;

impl TracerouteCommand {
    /// # Errors
    /// Returns an error for invalid options, process/IO failures, or serialization failures.
    pub async fn run(&self, options: Value) -> Result<Value> {
        let opts: TracerouteOptions = serde_json::from_value(options)?;
        let result = run_traceroute(&opts, None).await?;
        Ok(serde_json::to_value(result)?)
    }

    /// # Errors
    /// Returns an error for invalid options, process/IO failures, or serialization failures.
    pub async fn run_with_progress(&self, options: Value, tx: ProgressTx) -> Result<Value> {
        let opts: TracerouteOptions = serde_json::from_value(options)?;
        let result = run_traceroute(&opts, Some(tx)).await?;
        Ok(serde_json::to_value(result)?)
    }
}

fn resolution_failure(error: &ResolveTargetError) -> ParsedTraceroute {
    ParsedTraceroute {
        status: TracerouteStatus::Failed,
        failure_source: Some(error.failure_source_or("resolver").to_string()),
        raw_output: error.public_message(),
        resolved_address: None,
        resolved_hostname: None,
        hops: vec![],
    }
}

fn line_ip_tokens(line: &str) -> Vec<IpAddr> {
    line.split_whitespace()
        .filter_map(|token| {
            token
                .trim_matches(|ch| matches!(ch, '(' | ')' | ',' | '[' | ']'))
                .parse()
                .ok()
        })
        .collect()
}

fn normalize_numeric_output(
    raw: &str,
    target: &ResolvedTarget,
    hostnames: &HashMap<IpAddr, String>,
) -> String {
    let address = target.address.to_string();
    let mut lines = raw.lines();
    let Some(first) = lines.next() else {
        return String::new();
    };
    let header = first.replacen(
        &format!("traceroute to {address} ({address})"),
        &format!("traceroute to {} ({address})", target.hostname),
        1,
    );
    let mut output = vec![header];

    for (index, line) in lines.enumerate() {
        let mut normalized = line.to_string();
        for ip in line_ip_tokens(line) {
            let ip_text = ip.to_string();
            let hostname = if index == 0 {
                "_gateway".to_string()
            } else if ip == target.address {
                target.hostname.clone()
            } else {
                hostnames
                    .get(&ip)
                    .cloned()
                    .unwrap_or_else(|| ip_text.clone())
            };
            normalized = normalized.replacen(&ip_text, &format!("{hostname} ({ip_text})"), 1);
        }
        output.push(normalized);
    }
    output.join("\n")
}

async fn enrich_hostnames(
    raw: &str,
    target: &ResolvedTarget,
    budget: Duration,
) -> HashMap<IpAddr, String> {
    let mut addresses = Vec::new();
    for (index, line) in raw.lines().skip(1).enumerate() {
        if index == 0 {
            continue;
        }
        for address in line_ip_tokens(line) {
            if address != target.address && !is_ip_private(address) && !addresses.contains(&address)
            {
                addresses.push(address);
            }
        }
    }
    let per_lookup = budget.min(Duration::from_secs(2));
    futures::future::join_all(addresses.into_iter().map(|address| async move {
        reverse_lookup(address, per_lookup)
            .await
            .map(|hostname| (address, hostname))
    }))
    .await
    .into_iter()
    .flatten()
    .collect()
}

fn timeout_failure_source(
    raw: &str,
    parsed: &ParsedTraceroute,
    target: &ResolvedTarget,
) -> &'static str {
    let target_address = target.address.to_string();
    let target_responded = parsed.hops.last().is_some_and(|hop| {
        hop.resolved_address.as_deref() == Some(target_address.as_str()) && !hop.timings.is_empty()
    });
    if target_responded {
        return "internal";
    }
    if raw.lines().skip(1).any(|line| line.contains('*')) {
        "target"
    } else {
        "internal"
    }
}

fn has_upstream_unreachable(output: &str) -> bool {
    output.split_whitespace().any(|token| {
        matches!(token, "!N" | "!H" | "!P" | "!X" | "!S" | "!F" | "!V" | "!C")
            || token.strip_prefix('!').is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
    })
}

struct NativeTraceOutput {
    raw: String,
    stderr: String,
    timed_out: bool,
    status: Option<std::process::ExitStatus>,
}

async fn run_native_traceroute(
    args: &[String],
    process_timeout: Duration,
    target: &ResolvedTarget,
    progress: Option<&ProgressTx>,
) -> Result<NativeTraceOutput> {
    let mut child = Command::new("traceroute")
        .args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .context("child stdout pipe was unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("child stderr pipe was unavailable")?;
    let stderr_task = tokio::spawn(async move {
        let mut stderr = stderr;
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text).await;
        text
    });
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let mut raw_lines = Vec::new();
    let completed = timeout(process_timeout, async {
        while let Some(line) = lines.next_line().await? {
            raw_lines.push(line);
            if let Some(tx) = progress {
                let raw = raw_lines.join(
                    "
",
                );
                let normalized = normalize_numeric_output(&raw, target, &HashMap::new());
                let partial = parse(&normalized);
                if !partial.hops.is_empty() {
                    tx.send(json!({
                        "status": "in-progress",
                        "rawOutput": normalized,
                        "resolvedAddress": target.address.to_string(),
                        "resolvedHostname": target.hostname,
                        "hops": partial.hops,
                    }))
                    .ok();
                }
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
    Ok(NativeTraceOutput {
        raw: raw_lines.join(
            "
",
        ),
        stderr: stderr_task.await.unwrap_or_default(),
        timed_out,
        status,
    })
}

async fn run_traceroute(
    opts: &TracerouteOptions,
    progress: Option<ProgressTx>,
) -> Result<ParsedTraceroute> {
    validate(opts)?;
    let deadline = MeasurementDeadline::new(opts.timeout);
    let budget = traceroute_budget(opts.timeout, TRACEROUTE_PACKETS);
    let dns_budget = Duration::from_secs_f64(budget.dns_headroom.max(0.0));
    let target = match resolve_command_target(&opts.target, opts.ip_version, dns_budget).await {
        Ok(target) => target,
        Err(error) => return Ok(resolution_failure(&error)),
    };
    let mut resolved_options = opts.clone();
    resolved_options.target = target.address.to_string();
    let native = run_native_traceroute(
        &build_args(&resolved_options),
        deadline.process_timeout(),
        &target,
        progress.as_ref(),
    )
    .await?;
    let hostnames = enrich_hostnames(&native.raw, &target, deadline.remaining()).await;
    let normalized = normalize_numeric_output(&native.raw, &target, &hostnames);
    let mut parsed = parse(&normalized);
    parsed.resolved_address = Some(target.address.to_string());
    parsed.resolved_hostname = Some(target.hostname.clone());

    if native.timed_out {
        parsed.status = TracerouteStatus::Failed;
        parsed.failure_source =
            Some(timeout_failure_source(&native.raw, &parsed, &target).to_string());
        let mut raw = native.raw;
        if !raw.is_empty() {
            raw.push_str(
                "

",
            );
        }
        raw.push_str("The measurement command timed out.");
        parsed.raw_output = normalize_numeric_output(&raw, &target, &hostnames);
    } else if native.status.is_some_and(|status| !status.success()) {
        parsed.status = TracerouteStatus::Failed;
        parsed.failure_source = Some(
            if has_upstream_unreachable(&normalized) {
                "target"
            } else {
                "internal"
            }
            .to_string(),
        );
        if parsed.raw_output.trim().is_empty() {
            parsed.raw_output = if native.stderr.trim().is_empty() {
                "Test failed. Please try again.".to_string()
            } else {
                native.stderr
            };
        }
    } else if parsed.status == TracerouteStatus::Failed {
        parsed.failure_source = Some("internal".to_string());
        if parsed.raw_output.trim().is_empty() {
            parsed.raw_output = "Test failed. Please try again.".to_string();
        }
    }
    Ok(parsed)
}

/// Run one traceroute measurement without the socket layer.
///
/// # Errors
/// Returns an error for invalid options or process/IO failures.
pub async fn run_trace(target: &str, protocol: &str, ip_version: u8) -> Result<ParsedTraceroute> {
    let opts = TracerouteOptions {
        target: target.to_string(),
        protocol: protocol.to_string(),
        port: 80,
        ip_version,
        in_progress_updates: false,
        timeout: 10,
    };
    run_traceroute(&opts, None).await
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_opts(protocol: &str, ip_version: u8) -> TracerouteOptions {
        TracerouteOptions {
            target: "1.1.1.1".into(),
            protocol: protocol.into(),
            port: 80,
            ip_version,
            in_progress_updates: false,
            timeout: 10,
        }
    }

    #[test]
    fn build_args_icmp_ipv4() {
        let args = build_args(&make_opts("ICMP", 4));
        assert!(args.contains(&"-4".to_string()));
        assert!(args.contains(&"--icmp".to_string()));
        assert!(args.contains(&"-m".to_string()));
        assert!(args.contains(&"20".to_string()));
        assert!(args.contains(&"-w".to_string()));
        assert!(args.contains(&"2".to_string()));
        assert!(args.contains(&"-q".to_string()));
        assert!(args.contains(&"-N".to_string()));
        assert!(!args.contains(&"-p".to_string()));
        assert_eq!(args.last().unwrap(), "1.1.1.1");
    }

    #[test]
    fn build_args_tcp_adds_port() {
        let args = build_args(&make_opts("TCP", 4));
        assert!(args.contains(&"--tcp".to_string()));
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"80".to_string()));
    }

    #[test]
    fn build_args_udp_ipv6() {
        let args = build_args(&make_opts("UDP", 6));
        assert!(args.contains(&"-6".to_string()));
        assert!(args.contains(&"--udp".to_string()));
    }

    #[test]
    fn validate_accepts_private_literal_for_structured_runtime_rejection() {
        let mut opts = make_opts("ICMP", 4);
        opts.target = "192.168.1.1".into();
        assert!(validate(&opts).is_ok());
    }

    #[test]
    fn validate_rejects_bad_ip_version() {
        let mut opts = make_opts("ICMP", 4);
        opts.ip_version = 5;
        assert!(validate(&opts).is_err());
    }

    #[test]
    fn validate_rejects_unknown_protocol() {
        let mut opts = make_opts("SCTP", 4);
        opts.protocol = "SCTP".into();
        assert!(validate(&opts).is_err());
    }

    #[test]
    fn validate_accepts_valid_opts() {
        for proto in &["ICMP", "TCP", "UDP"] {
            for ver in &[4u8, 6u8] {
                let opts = make_opts(proto, *ver);
                assert!(
                    validate(&opts).is_ok(),
                    "expected ok for {} v{}",
                    proto,
                    ver
                );
            }
        }
    }
}
