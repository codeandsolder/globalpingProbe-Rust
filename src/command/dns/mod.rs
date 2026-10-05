pub mod parse;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;

use super::MeasurementCommand;
use crate::util::private_ip::is_ip_private;
use crate::util::validate::is_safe_host;
use parse::{ClassicResult, TraceResult, parse_classic, parse_trace};

// ── Options ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
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
}

#[derive(Debug, Deserialize, Default)]
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

// ── Validation ────────────────────────────────────────────────────────────────

const ALLOWED_TYPES: &[&str] = &[
    "A", "AAAA", "ANY", "CNAME", "DNSKEY", "DS", "HTTPS", "MX", "NS", "NSEC", "PTR", "RRSIG",
    "SOA", "TXT", "SRV", "SVCB",
];
const ALLOWED_PROTOCOLS: &[&str] = &["UDP", "TCP"];

fn validate(opts: &DnsOptions) -> Result<()> {
    if !ALLOWED_TYPES.contains(&opts.query.record_type.as_str()) {
        bail!("unsupported query type: {}", opts.query.record_type);
    }
    if !ALLOWED_PROTOCOLS
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&opts.protocol))
    {
        bail!("protocol must be UDP or TCP");
    }
    if opts.ip_version != 4 && opts.ip_version != 6 {
        bail!("ipVersion must be 4 or 6");
    }
    // Target is passed to `dig` as a bare argument; reject anything that could be
    // read as a flag (leading `-`/`+`) or shell syntax. For PTR queries the target
    // is an IP literal, which is_safe_host accepts.
    if !is_safe_host(&opts.target) {
        bail!("Invalid target.");
    }
    // A custom resolver must be a clean host and must not be a private/internal
    // address — otherwise the probe could be turned into an internal port scanner
    // by pointing DNS queries at arbitrary internal IPs/ports (SSRF).
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

// ── Arg builder ───────────────────────────────────────────────────────────────

#[must_use]
pub fn build_args(opts: &DnsOptions) -> Vec<String> {
    let mut args: Vec<String> = vec![];

    // Query type: PTR uses -x, everything else uses -t <type>
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
    args.push("+timeout=3".into());
    args.push("+tries=2".into());
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

// ── Command ───────────────────────────────────────────────────────────────────

pub struct DnsCommand;

#[async_trait::async_trait]
impl MeasurementCommand for DnsCommand {
    async fn run(&self, options: Value) -> Result<Value> {
        let opts: DnsOptions = serde_json::from_value(options)?;
        validate(&opts)?;

        let raw = run_dig(&opts).await?;

        let result = if opts.trace {
            let r = parse_trace(&raw);
            serde_json::to_value(r)?
        } else {
            let r = parse_classic(&raw);
            // Propagate failures (connection refused, bad packet) as the result,
            // not as a Rust error — the probe reports them to the API as failed jobs.
            serde_json::to_value(r)?
        };

        Ok(result)
    }
}

async fn run_dig(opts: &DnsOptions) -> Result<String> {
    let args = build_args(opts);

    let mut child = Command::new("dig")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .context("child stdout pipe was unavailable")?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let mut raw = String::new();

    while let Some(line) = lines.next_line().await? {
        raw.push_str(&line);
        raw.push('\n');
    }

    let _ = child.wait().await;
    Ok(raw)
}

// ── Helpers for integration tests ─────────────────────────────────────────────

/// Run a classic query and return the parsed result directly (no socket layer).
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
    };
    let raw = run_dig(&opts).await?;
    Ok(parse_classic(&raw))
}

/// Run a trace query and return the parsed result directly.
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
    };
    let raw = run_dig(&opts).await?;
    Ok(parse_trace(&raw))
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
        assert!(args.contains(&"+timeout=3".to_string()));
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
}
