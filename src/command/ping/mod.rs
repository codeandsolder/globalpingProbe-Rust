pub mod parse;

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::time::timeout;

use super::ProgressTx;
use crate::util::measurement_timeout::{MeasurementDeadline, ping_budget};
use crate::util::private_ip::is_ip_private;
use crate::util::resolve_target::{ResolveTargetError, ResolvedTarget, resolve_command_target};
use crate::util::tcp_ping::{TcpPingProbe, compute_tcp_stats, tcp_ping_single};
use crate::util::validate::is_safe_host;
use parse::{ParsedPing, PingStats, PingStatus, PingTiming, parse};

// ── Options (deserialised from the socket.io job payload) ───────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PingOptions {
    pub target: String,
    #[serde(default = "default_packets")]
    pub packets: u8,
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

const fn default_packets() -> u8 {
    3
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

// ── Validation ───────────────────────────────────────────────────────────────

fn validate(opts: &PingOptions) -> Result<()> {
    if !is_safe_host(&opts.target) {
        bail!("Invalid target.");
    }
    if !(1..=16).contains(&opts.packets) {
        bail!("packets must be 1–16");
    }
    if opts.ip_version != 4 && opts.ip_version != 6 {
        bail!("ipVersion must be 4 or 6");
    }
    if let Ok(ip) = opts.target.parse()
        && is_ip_private(ip)
    {
        bail!("Private IP ranges are not allowed.");
    }
    Ok(())
}

// ── Arg builder ──────────────────────────────────────────────────────────────

/// Builds the argument list for the system `ping` binary (Linux format).
#[must_use]
pub fn build_args(opts: &PingOptions) -> Vec<String> {
    let budget = ping_budget(opts.packets, opts.timeout, None);
    vec![
        format!("-{}", opts.ip_version),
        "-O".into(),
        "-n".into(),
        "-c".into(),
        opts.packets.to_string(),
        "-i".into(),
        budget.interval.to_string(),
        "-W".into(),
        budget.response_timeout.to_string(),
        opts.target.clone(),
    ]
}

// ── Command ──────────────────────────────────────────────────────────────────

pub struct PingCommand;

impl PingCommand {
    /// Execute a ping command from a socket payload.
    ///
    /// # Errors
    /// Returns an error for invalid options, process/IO failures, or serialization failures.
    pub async fn run(&self, options: Value) -> Result<Value> {
        let opts: PingOptions = serde_json::from_value(options)?;
        let result = run_ping(&opts, None).await?;
        Ok(serde_json::to_value(result)?)
    }

    /// Execute a ping command while streaming partial packet results.
    ///
    /// # Errors
    /// Returns an error for invalid options, process/IO failures, or serialization failures.
    pub async fn run_with_progress(&self, options: Value, tx: ProgressTx) -> Result<Value> {
        let opts: PingOptions = serde_json::from_value(options)?;
        let result = run_ping(&opts, Some(tx)).await?;
        Ok(serde_json::to_value(result)?)
    }
}

fn resolution_failure(error: &ResolveTargetError) -> ParsedPing {
    ParsedPing {
        status: PingStatus::Failed,
        failure_source: Some(error.failure_source().to_string()),
        raw_output: error.public_message(),
        resolved_address: None,
        resolved_hostname: None,
        timings: vec![],
        stats: PingStats::default(),
    }
}

async fn run_ping(opts: &PingOptions, progress: Option<ProgressTx>) -> Result<ParsedPing> {
    validate(opts)?;
    let deadline = MeasurementDeadline::new(opts.timeout);
    let budget = ping_budget(opts.packets, opts.timeout, None);
    let dns_budget = Duration::from_secs_f64(budget.dns_headroom.max(0.0));
    let target = match resolve_command_target(&opts.target, opts.ip_version, dns_budget).await {
        Ok(target) => target,
        Err(error) => return Ok(resolution_failure(&error)),
    };

    let mut resolved_options = opts.clone();
    resolved_options.target = target.address.to_string();
    if opts.protocol.eq_ignore_ascii_case("TCP") {
        run_tcp(&resolved_options, &target, progress, deadline.remaining()).await
    } else {
        run_icmp(
            &resolved_options,
            &target,
            progress,
            deadline.process_timeout(),
        )
        .await
    }
}

fn normalize_ping_output(output: &str, address: &str, hostname: &str) -> String {
    if address == hostname {
        return output.to_string();
    }
    output
        .lines()
        .map(|line| {
            if line.starts_with(&format!("PING {address} ({address})")) {
                line.replacen(
                    &format!("PING {address} ({address})"),
                    &format!("PING {hostname} ({address})"),
                    1,
                )
            } else if line.contains(&format!(" bytes from {address}:")) {
                line.replacen(
                    &format!(" bytes from {address}:"),
                    &format!(" bytes from {hostname} ({address}):"),
                    1,
                )
            } else if line.starts_with(&format!("From {address} ")) {
                line.replacen(
                    &format!("From {address} "),
                    &format!("From {hostname} ({address}) "),
                    1,
                )
            } else if line == format!("--- {address} ping statistics ---") {
                format!("--- {hostname} ping statistics ---")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn run_icmp(
    opts: &PingOptions,
    target: &ResolvedTarget,
    progress: Option<ProgressTx>,
    process_timeout: Duration,
) -> Result<ParsedPing> {
    let args = build_args(opts);
    let mut child = Command::new("ping")
        .args(&args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .context("child stdout pipe was unavailable")?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let mut raw_output = String::new();
    let address = target.address.to_string();

    let completed = timeout(process_timeout, async {
        while let Some(line) = lines.next_line().await? {
            raw_output.push_str(&line);
            raw_output.push('\n');
            if let Some(tx) = &progress
                && line.contains("bytes from ")
                && line.contains(" time=")
            {
                let normalized = normalize_ping_output(&raw_output, &address, &target.hostname);
                let partial = parse(&normalized);
                if !partial.timings.is_empty() {
                    tx.send(json!({
                        "status": "in-progress",
                        "rawOutput": normalized,
                        "resolvedAddress": address,
                        "resolvedHostname": target.hostname,
                        "timings": partial.timings,
                        "stats": partial.stats,
                    }))
                    .ok();
                }
            }
        }
        child.wait().await.map(|_| ())
    })
    .await;

    let timed_out = completed.is_err();
    if timed_out {
        child.kill().await.ok();
        child.wait().await.ok();
    } else {
        completed??;
    }

    let normalized = normalize_ping_output(&raw_output, &address, &target.hostname);
    let mut parsed = parse(&normalized);
    parsed.resolved_address = Some(address);
    parsed.resolved_hostname = Some(target.hostname.clone());
    if timed_out {
        parsed.status = PingStatus::Failed;
        parsed.failure_source = Some(
            if parsed.timings.is_empty()
                && (normalized.contains("no answer yet for ")
                    || normalized.contains("100% packet loss"))
            {
                "target"
            } else {
                "internal"
            }
            .to_string(),
        );
    } else if parsed.status == PingStatus::Failed {
        parsed.failure_source = Some("internal".to_string());
    }
    Ok(parsed)
}

fn format_compact(value: f64, decimals: usize) -> String {
    let mut value = format!("{value:.decimals$}");
    while value.contains('.') && value.ends_with('0') {
        value.pop();
    }
    if value.ends_with('.') {
        value.pop();
    }
    value
}

fn spawn_tcp_probes(
    opts: &PingOptions,
    address: &str,
    remaining: Duration,
) -> Vec<tokio::task::JoinHandle<TcpPingProbe>> {
    let budget = ping_budget(opts.packets, opts.timeout, None);
    let deadline = tokio::time::Instant::now() + remaining;
    let mut tasks = Vec::with_capacity(usize::from(opts.packets));
    for index in 0..opts.packets {
        let address = address.to_string();
        let port = opts.port;
        let delay = Duration::from_secs_f64(budget.interval * f64::from(index));
        tasks.push(tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let timeout_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
            tcp_ping_single(&address, port, timeout_ms).await
        }));
    }
    tasks
}

async fn run_tcp(
    opts: &PingOptions,
    target: &ResolvedTarget,
    progress: Option<ProgressTx>,
    remaining: Duration,
) -> Result<ParsedPing> {
    let start = Instant::now();
    let address = target.address.to_string();
    let tasks = spawn_tcp_probes(opts, &address, remaining);

    let mut probes: Vec<TcpPingProbe> = Vec::with_capacity(usize::from(opts.packets));
    let mut raw_lines = vec![format!(
        "PING {} ({}) on port {}.",
        target.hostname, address, opts.port
    )];
    let mut timings = Vec::new();

    for (index, task) in tasks.into_iter().enumerate() {
        let probe = task.await.unwrap_or(TcpPingProbe { rtt_ms: None });
        let number = index + 1;
        match probe.rtt_ms {
            Some(rtt) => {
                timings.push(PingTiming { rtt, ttl: None });
                raw_lines.push(format!(
                    "Reply from {} ({}) on port {}: tcp_conn={} time={} ms",
                    target.hostname,
                    address,
                    opts.port,
                    number,
                    format_compact(rtt, 2),
                ));
            }
            None => raw_lines.push(format!(
                "No reply from {} ({}) on port {}: tcp_conn={number}",
                target.hostname, address, opts.port,
            )),
        }
        probes.push(probe);

        if let Some(tx) = &progress {
            let stats = compute_tcp_stats(&probes, u8::try_from(probes.len()).unwrap_or(u8::MAX));
            tx.send(json!({
                "status": "in-progress",
                "rawOutput": raw_lines.join("\n"),
                "resolvedAddress": address,
                "resolvedHostname": target.hostname,
                "timings": timings,
                "stats": {
                    "min": stats.min,
                    "max": stats.max,
                    "avg": stats.avg,
                    "total": stats.total,
                    "loss": stats.loss,
                    "rcv": stats.rcv,
                    "drop": stats.drop,
                },
            }))
            .ok();
        }
    }

    let stats = compute_tcp_stats(&probes, opts.packets);
    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    raw_lines.push(String::new());
    raw_lines.push(format!(
        "--- {} ({}) ping statistics ---",
        target.hostname, address
    ));
    raw_lines.push(format!(
        "{} packets transmitted, {} received, {}% packet loss, time {} ms",
        stats.total,
        stats.rcv,
        format_compact(stats.loss, 2),
        elapsed_ms,
    ));
    if let (Some(min), Some(avg), Some(max), Some(mdev)) =
        (stats.min, stats.avg, stats.max, stats.mdev)
    {
        raw_lines.push(format!(
            "rtt min/avg/max/mdev = {min:.3}/{avg:.3}/{max:.3}/{mdev:.3} ms"
        ));
    }

    Ok(ParsedPing {
        status: PingStatus::Finished,
        failure_source: None,
        raw_output: raw_lines.join("\n"),
        resolved_address: Some(address),
        resolved_hostname: Some(target.hostname.clone()),
        timings,
        stats: PingStats {
            min: stats.min,
            max: stats.max,
            avg: stats.avg,
            total: Some(stats.total),
            loss: Some(stats.loss),
            rcv: Some(stats.rcv),
            drop: Some(stats.drop),
        },
    })
}

// ── Public helper for integration tests / status manager ─────────────────────

/// Run one ping measurement without the socket layer.
///
/// # Errors
/// Returns an error for invalid options or process/IO failures.
pub async fn run_measurement(
    target: &str,
    ip_version: u8,
    packets: u8,
) -> Result<parse::ParsedPing> {
    let opts = PingOptions {
        target: target.to_string(),
        packets,
        protocol: "ICMP".into(),
        port: 80,
        ip_version,
        in_progress_updates: false,
        timeout: 10,
    };
    run_ping(&opts, None).await
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_ipv4() {
        let opts = PingOptions {
            target: "1.1.1.1".into(),
            packets: 3,
            protocol: "ICMP".into(),
            port: 80,
            ip_version: 4,
            in_progress_updates: false,
            timeout: 10,
        };
        let args = build_args(&opts);
        assert_eq!(args[0], "-4");
        assert!(args.contains(&"-O".to_string()));
        assert!(args.contains(&"-c".to_string()));
        assert!(args.contains(&"3".to_string()));
        assert_eq!(args.last().unwrap(), "1.1.1.1");
    }

    #[test]
    fn build_args_ipv6() {
        let opts = PingOptions {
            target: "2606:4700:4700::1111".into(),
            packets: 5,
            protocol: "ICMP".into(),
            port: 80,
            ip_version: 6,
            in_progress_updates: false,
            timeout: 10,
        };
        let args = build_args(&opts);
        assert_eq!(args[0], "-6");
        assert!(args.contains(&"-c".to_string()));
        assert!(args.contains(&"5".to_string()));
        assert_eq!(args.last().unwrap(), "2606:4700:4700::1111");
    }

    #[test]
    fn validate_rejects_invalid_packet_count() {
        let mut opts = PingOptions {
            target: "1.1.1.1".into(),
            packets: 0,
            protocol: "ICMP".into(),
            port: 80,
            ip_version: 4,
            in_progress_updates: false,
            timeout: 10,
        };
        assert!(validate(&opts).is_err());
        opts.packets = 17;
        assert!(validate(&opts).is_err());
        opts.packets = 3;
        assert!(validate(&opts).is_ok());
    }

    #[test]
    fn validate_rejects_private_ip_target() {
        let opts = PingOptions {
            target: "10.0.0.1".into(),
            packets: 3,
            protocol: "ICMP".into(),
            port: 80,
            ip_version: 4,
            in_progress_updates: false,
            timeout: 10,
        };
        let err = validate(&opts).unwrap_err();
        assert!(err.to_string().contains("Private IP"));
    }

    #[test]
    fn validate_accepts_public_ip() {
        let opts = PingOptions {
            target: "1.1.1.1".into(),
            packets: 3,
            protocol: "ICMP".into(),
            port: 80,
            ip_version: 4,
            in_progress_updates: false,
            timeout: 10,
        };
        assert!(validate(&opts).is_ok());
    }

    #[test]
    fn validate_rejects_argument_injection_target() {
        // A target that begins with `-` would be parsed by `ping` as a flag
        // (e.g. `-f` flood). It must be rejected before spawning anything.
        for bad in ["-f", "--help", "-O", "evil.com; id", "a b"] {
            let opts = PingOptions {
                target: bad.into(),
                packets: 3,
                protocol: "ICMP".into(),
                port: 80,
                ip_version: 4,
                in_progress_updates: false,
                timeout: 10,
            };
            assert!(validate(&opts).is_err(), "should reject target {bad:?}");
        }
    }
}
