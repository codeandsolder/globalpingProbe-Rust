pub mod parse;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;

use super::ProgressTx;
use crate::util::private_ip::is_ip_private;
use crate::util::validate::is_safe_host;
use parse::{ParsedPing, PingStats, PingStatus, parse};

// ── Options (deserialised from the socket.io job payload) ───────────────────

#[derive(Debug, Deserialize)]
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
    // Reject targets that aren't a clean hostname/IP — in particular anything
    // starting with `-` (would be parsed as a `ping` flag) or containing shell
    // metacharacters. See util::validate.
    if !is_safe_host(&opts.target) {
        bail!("Invalid target.");
    }
    if opts.packets < 1 || opts.packets > 16 {
        bail!("packets must be 1–16");
    }
    if opts.ip_version != 4 && opts.ip_version != 6 {
        bail!("ipVersion must be 4 or 6");
    }
    // Reject private IP targets before spawning anything
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
    vec![
        format!("-{}", opts.ip_version), // -4 or -6
        "-O".into(),                     // report unanswered packets
        "-c".into(),
        opts.packets.to_string(), // packet count
        "-i".into(),
        "0.5".into(), // 0.5s interval
        "-w".into(),
        "10".into(), // 10s overall deadline
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
        validate(&opts)?;
        let result = run_icmp(&opts, None).await?;
        Ok(serde_json::to_value(result)?)
    }

    /// Execute a ping command while streaming partial packet results.
    ///
    /// # Errors
    /// Returns an error for invalid options, process/IO failures, or serialization failures.
    pub async fn run_with_progress(&self, options: Value, tx: ProgressTx) -> Result<Value> {
        let opts: PingOptions = serde_json::from_value(options)?;
        validate(&opts)?;
        let result = run_icmp(&opts, Some(tx)).await?;
        Ok(serde_json::to_value(result)?)
    }
}

async fn run_icmp(opts: &PingOptions, progress: Option<ProgressTx>) -> Result<ParsedPing> {
    let args = build_args(opts);

    let mut child = Command::new("ping")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .context("child stdout pipe was unavailable")?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();

    let mut raw_output = String::new();
    let mut resolved_address: Option<String> = None;
    let mut is_private = false;

    while let Some(line) = lines.next_line().await? {
        raw_output.push_str(&line);
        raw_output.push('\n');

        // After the first packet reply we know the resolved IP — check it
        if resolved_address.is_none() {
            let partial = parse(&raw_output);
            if let Some(addr) = &partial.resolved_address {
                if let Ok(ip) = addr.parse()
                    && is_ip_private(ip)
                {
                    is_private = true;
                    child.kill().await.ok();
                    break;
                }
                resolved_address = Some(addr.clone());
            }
        }

        // Emit in-progress partial after each packet reply line
        if let Some(tx) = &progress
            && line.contains("bytes from ")
            && line.contains(" time=")
        {
            let partial = parse(&raw_output);
            if !partial.timings.is_empty() {
                tx.send(json!({
                    "status":            "in-progress",
                    "rawOutput":         raw_output,
                    "resolvedAddress":   partial.resolved_address,
                    "resolvedHostname":  partial.resolved_hostname,
                    "timings":           partial.timings,
                    "stats":             partial.stats,
                }))
                .ok();
            }
        }
    }

    // Wait for the process (it may already be dead)
    let _ = child.wait().await;

    if is_private {
        return Ok(ParsedPing {
            status: PingStatus::Failed,
            raw_output: "Private IP ranges are not allowed.".into(),
            resolved_address: None,
            resolved_hostname: None,
            timings: vec![],
            stats: PingStats::default(),
        });
    }

    Ok(parse(&raw_output))
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
    };
    validate(&opts)?;
    run_icmp(&opts, None).await
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
            };
            assert!(validate(&opts).is_err(), "should reject target {bad:?}");
        }
    }
}
