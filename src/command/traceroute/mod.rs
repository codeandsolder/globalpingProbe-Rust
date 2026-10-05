pub mod parse;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;

use super::{MeasurementCommand, ProgressTx};
use crate::util::private_ip::is_ip_private;
use crate::util::validate::is_safe_host;
use parse::{ParsedTraceroute, TracerouteStatus, parse};

// ── Options ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
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

// ── Validation ────────────────────────────────────────────────────────────────

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
    if let Ok(ip) = opts.target.parse()
        && is_ip_private(ip)
    {
        bail!("Private IP ranges are not allowed");
    }
    Ok(())
}

// ── Arg builder ───────────────────────────────────────────────────────────────

#[must_use]
pub fn build_args(opts: &TracerouteOptions) -> Vec<String> {
    let mut args: Vec<String> = vec![
        format!("-{}", opts.ip_version),
        "-m".into(),
        "20".into(),
        "-w".into(),
        "2".into(),
        "-q".into(),
        "2".into(),
        "-N".into(),
        "20".into(),
        format!("--{}", opts.protocol.to_lowercase()),
    ];

    if opts.protocol.to_uppercase() == "TCP" {
        args.push("-p".into());
        args.push(opts.port.to_string());
    }

    args.push(opts.target.clone());
    args
}

// ── Command ───────────────────────────────────────────────────────────────────

pub struct TracerouteCommand;

#[async_trait::async_trait]
impl MeasurementCommand for TracerouteCommand {
    async fn run(&self, options: Value) -> Result<Value> {
        let opts: TracerouteOptions = serde_json::from_value(options)?;
        validate(&opts)?;
        let result = run_traceroute(&opts, None).await?;
        Ok(serde_json::to_value(result)?)
    }

    async fn run_with_progress(&self, options: Value, tx: ProgressTx) -> Result<Value> {
        let opts: TracerouteOptions = serde_json::from_value(options)?;
        validate(&opts)?;
        let result = run_traceroute(&opts, Some(tx)).await?;
        Ok(serde_json::to_value(result)?)
    }
}

// Matches any traceroute hop line: starts with whitespace + hop number
static HOP_LINE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^\s*\d+\s").unwrap());

async fn run_traceroute(
    opts: &TracerouteOptions,
    progress: Option<ProgressTx>,
) -> Result<ParsedTraceroute> {
    validate(opts)?;
    let args = build_args(opts);

    let mut child = Command::new("traceroute")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .context("child stdout pipe was unavailable")?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();

    let mut raw_lines: Vec<String> = vec![];

    while let Some(line) = lines.next_line().await? {
        raw_lines.push(line.clone());

        // Emit a partial result after every hop line
        if let Some(tx) = &progress
            && HOP_LINE.is_match(&line)
        {
            let accumulated = raw_lines.join("\n");
            let partial = parse(&accumulated);
            if !partial.hops.is_empty() {
                tx.send(json!({
                    "status":            "in-progress",
                    "rawOutput":         accumulated,
                    "resolvedAddress":   partial.resolved_address,
                    "resolvedHostname":  partial.resolved_hostname,
                    "hops":              partial.hops,
                }))
                .ok();
            }
        }
    }

    let _ = child.wait().await;

    let raw = raw_lines.join("\n");

    if raw.trim().is_empty() {
        return Ok(ParsedTraceroute {
            status: TracerouteStatus::Failed,
            raw_output: String::new(),
            resolved_address: None,
            resolved_hostname: None,
            hops: vec![],
        });
    }

    let mut parsed = parse(&raw);

    if let Some(addr) = &parsed.resolved_address
        && let Ok(ip) = addr.parse()
        && is_ip_private(ip)
    {
        parsed.status = TracerouteStatus::Failed;
        parsed.raw_output = "Private IP ranges are not allowed.".into();
        parsed.hops.clear();
    }

    Ok(parsed)
}

// ── Helper for integration tests ──────────────────────────────────────────────

pub async fn run_trace(target: &str, protocol: &str, ip_version: u8) -> Result<ParsedTraceroute> {
    let opts = TracerouteOptions {
        target: target.to_string(),
        protocol: protocol.to_string(),
        port: 80,
        ip_version,
        in_progress_updates: false,
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
    fn validate_rejects_private_ip() {
        let mut opts = make_opts("ICMP", 4);
        opts.target = "192.168.1.1".into();
        assert!(validate(&opts).is_err());
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
