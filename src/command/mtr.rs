pub mod parse;

// ── Imports ───────────────────────────────────────────────────────────────────

use super::ProgressTx;
use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use tokio::process::Command;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};

use crate::util::measurement_timeout::{MeasurementDeadline, mtr_budget};
use crate::util::private_ip::is_ip_private;
use crate::util::resolve_target::{
    ResolveTargetError, ResolvedTarget, resolve_command_target, reverse_lookup,
};
use crate::util::validate::is_safe_host;
use parse::{
    MtrEnrichmentEntry, MtrEnrichmentMap, MtrStatus, ParsedMtr, normalize_ip_text, render_progress,
    shape_result,
};

// ── Options ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MtrOptions {
    pub target: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_packets")]
    pub packets: u8,
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
const fn default_packets() -> u8 {
    3
}
const fn default_ip_version() -> u8 {
    4
}

// ── Validation ────────────────────────────────────────────────────────────────

pub(crate) fn validate(opts: &MtrOptions) -> Result<()> {
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
    if opts.packets == 0 || opts.packets > 16 {
        bail!("packets must be between 1 and 16");
    }
    Ok(())
}

// ── Arg builder ───────────────────────────────────────────────────────────────

#[must_use]
pub fn build_args(opts: &MtrOptions) -> Vec<String> {
    let budget = mtr_budget(opts.packets, opts.timeout);
    let mut args: Vec<String> = vec![
        format!("-{}", opts.ip_version),
        "--interval".into(),
        budget.interval.to_string(),
        "--gracetime".into(),
        budget.grace.to_string(),
        "--max-ttl".into(),
        "30".into(),
        "--timeout".into(),
        budget.native_timeout.to_string(),
        "-n".into(),
    ];

    let proto = opts.protocol.to_uppercase();
    if proto == "TCP" {
        args.push("--tcp".into());
    } else if proto == "UDP" {
        args.push("--udp".into());
    }
    // ICMP is mtr's default — no flag needed

    args.push("-c".into());
    args.push(opts.packets.to_string());
    args.push("--raw".into());
    args.push("-P".into());
    args.push(opts.port.to_string());
    args.push(opts.target.clone());
    args
}

// ── Command ───────────────────────────────────────────────────────────────────

pub struct MtrCommand;

impl MtrCommand {
    /// Execute an MTR command from a socket payload.
    ///
    /// # Errors
    /// Returns an error for invalid options, process failures, ASN lookup failures, or serialization failures.
    pub async fn run(&self, options: Value) -> Result<Value> {
        let opts: MtrOptions = serde_json::from_value(options)?;
        let result = run_mtr(&opts, None).await?;
        Ok(serde_json::to_value(result)?)
    }

    /// Execute MTR while streaming overwrite snapshots.
    ///
    /// # Errors
    /// Returns an error for invalid options, process failures, ASN lookup failures, or serialization failures.
    pub async fn run_with_progress(&self, options: Value, tx: ProgressTx) -> Result<Value> {
        let opts: MtrOptions = serde_json::from_value(options)?;
        let result = run_mtr(&opts, Some(tx)).await?;
        Ok(serde_json::to_value(result)?)
    }
}

// ── Internal runner ───────────────────────────────────────────────────────────

fn resolution_failure(error: &ResolveTargetError) -> ParsedMtr {
    ParsedMtr {
        status: MtrStatus::Failed,
        failure_source: Some(error.failure_source_or("internal").to_string()),
        raw_output: error.public_message(),
        resolved_address: None,
        resolved_hostname: None,
        hops: vec![],
    }
}

pub(crate) struct NativeMtrOutput {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) timed_out: bool,
}

#[derive(Clone, Default)]
struct EnrichmentCache {
    entries: Arc<RwLock<HashMap<IpAddr, MtrEnrichmentEntry>>>,
}

impl EnrichmentCache {
    fn seed_hostname(&self, address: IpAddr, hostname: String) {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.entry(address).or_default().hostname = Some(hostname);
    }

    fn has_hostname(&self, address: IpAddr) -> bool {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&address)
            .and_then(|entry| entry.hostname.as_ref())
            .is_some()
    }

    fn update(&self, address: IpAddr, hostname: Option<String>, asn: Vec<u32>) {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = entries.entry(address).or_default();
        if hostname.is_some() {
            entry.hostname = hostname;
        }
        if !asn.is_empty() {
            entry.asn = asn;
        }
        drop(entries);
    }

    fn snapshot(&self) -> MtrEnrichmentMap {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(address, entry)| (address.to_string(), entry.clone()))
            .collect()
    }
}

struct MtrEnrichment {
    cache: EnrichmentCache,
    seen: HashSet<IpAddr>,
    tasks: JoinSet<()>,
}

impl MtrEnrichment {
    fn new(target: &ResolvedTarget) -> Self {
        let cache = EnrichmentCache::default();
        if target.hostname != target.address.to_string() {
            cache.seed_hostname(target.address, target.hostname.clone());
        }
        Self {
            cache,
            seen: HashSet::new(),
            tasks: JoinSet::new(),
        }
    }

    fn add(
        &mut self,
        address: IpAddr,
        budget: Duration,
        progress: Option<ProgressTx>,
        raw: Arc<RwLock<String>>,
    ) {
        if is_ip_private(address) || !self.seen.insert(address) {
            return;
        }

        let cache = self.cache.clone();
        let ptr_seeded = cache.has_hostname(address);
        self.tasks.spawn(async move {
            let ptr = async {
                if ptr_seeded {
                    None
                } else {
                    reverse_lookup(address, budget.min(Duration::from_secs(3))).await
                }
            };
            let (hostname, asn) = tokio::join!(ptr, lookup_asn(address, budget));
            cache.update(address, hostname, asn);
            if let Some(tx) = progress {
                queue_mtr_progress(&tx, raw, cache);
            }
        });
    }

    async fn wait(&mut self) {
        while self.tasks.join_next().await.is_some() {}
    }
}

fn render_mtr_progress(raw: &str, cache: &EnrichmentCache) -> Value {
    json!({ "rawOutput": render_progress(raw, &cache.snapshot()) })
}

pub(crate) fn shape_mtr_output(
    stdout: &str,
    stderr: &str,
    timed_out: bool,
    target: &ResolvedTarget,
    enrichment: &MtrEnrichmentMap,
) -> ParsedMtr {
    shape_result(
        stdout,
        stderr,
        timed_out,
        &target.address.to_string(),
        &target.hostname,
        enrichment,
    )
}

fn queue_mtr_progress(tx: &ProgressTx, raw: Arc<RwLock<String>>, cache: EnrichmentCache) {
    tx.send_lazy(move || {
        let raw = raw
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        render_mtr_progress(&raw, &cache)
    })
    .ok();
}

fn hop_address_from_raw_line(line: &str) -> Option<IpAddr> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "h" {
        return None;
    }
    let _index = parts.next()?;
    normalize_ip_text(parts.next()?).parse().ok()
}

pub(crate) async fn run_native_mtr_raw(
    args: &[String],
    process_timeout: Duration,
) -> Result<NativeMtrOutput> {
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};

    let mut child = Command::new("mtr")
        .args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("mtr stdout pipe unavailable"))?;
    let mut stdout_lines = tokio::io::BufReader::new(stdout).lines();
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("mtr stderr pipe unavailable"))?;
    let stderr_task = tokio::spawn(async move {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text).await;
        text
    });
    let mut raw = String::new();
    let completed = timeout(process_timeout, async {
        while let Some(line) = stdout_lines.next_line().await? {
            raw.push_str(&line);
            raw.push('\n');
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
    Ok(NativeMtrOutput {
        stdout: raw,
        stderr: stderr_task.await.unwrap_or_default(),
        timed_out,
    })
}

async fn run_native_mtr(
    args: &[String],
    process_timeout: Duration,
    progress: Option<&ProgressTx>,
    enrichment: &mut MtrEnrichment,
    deadline: &MeasurementDeadline,
) -> Result<NativeMtrOutput> {
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};

    let mut child = Command::new("mtr")
        .args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("mtr stdout pipe unavailable"))?;
    let mut stdout_lines = tokio::io::BufReader::new(stdout).lines();
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("mtr stderr pipe unavailable"))?;
    let stderr_task = tokio::spawn(async move {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text).await;
        text
    });
    let raw_stdout = Arc::new(RwLock::new(String::new()));
    let completed = timeout(process_timeout, async {
        while let Some(line) = stdout_lines.next_line().await? {
            {
                let mut raw = raw_stdout
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                raw.push_str(&line);
                raw.push('\n');
            }
            if let Some(address) = hop_address_from_raw_line(&line) {
                enrichment.add(
                    address,
                    deadline.remaining(),
                    progress.cloned(),
                    Arc::clone(&raw_stdout),
                );
            }
            if let Some(tx) = progress {
                queue_mtr_progress(tx, Arc::clone(&raw_stdout), enrichment.cache.clone());
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
    let stdout = raw_stdout
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Ok(NativeMtrOutput {
        stdout,
        stderr: stderr_task.await.unwrap_or_default(),
        timed_out,
    })
}

async fn run_mtr(opts: &MtrOptions, progress: Option<ProgressTx>) -> Result<ParsedMtr> {
    validate(opts)?;
    let deadline = MeasurementDeadline::new(opts.timeout);
    let budget = mtr_budget(opts.packets, opts.timeout);
    let dns_budget = Duration::from_secs_f64(budget.dns_headroom.max(0.0));
    let target = match resolve_command_target(&opts.target, opts.ip_version, dns_budget).await {
        Ok(target) => target,
        Err(error) => return Ok(resolution_failure(&error)),
    };
    let mut resolved_options = opts.clone();
    resolved_options.target = target.address.to_string();
    let mut enrichment = MtrEnrichment::new(&target);
    let native = run_native_mtr(
        &build_args(&resolved_options),
        deadline.process_timeout(),
        progress.as_ref(),
        &mut enrichment,
        &deadline,
    )
    .await?;
    enrichment.wait().await;

    Ok(shape_mtr_output(
        &native.stdout,
        &native.stderr,
        native.timed_out,
        &target,
        &enrichment.cache.snapshot(),
    ))
}

fn cymru_query_name(address: IpAddr) -> String {
    let address = match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address @ IpAddr::V4(_) => address,
    };
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            format!(
                "{}.{}.{}.{}.origin.asn.cymru.com",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(address) => {
            let mut labels = Vec::with_capacity(32);
            for byte in address.octets().iter().rev() {
                labels.push(format!("{:x}", byte & 0x0f));
                labels.push(format!("{:x}", byte >> 4));
            }
            format!("{}.origin6.asn.cymru.com", labels.join("."))
        }
    }
}

fn parse_cymru_asns(stdout: &str) -> Vec<u32> {
    for line in stdout.lines() {
        let line = line.trim().trim_matches('"');
        let Some(asn_part) = line.split('|').next() else {
            continue;
        };
        let asns = asn_part
            .split_whitespace()
            .filter_map(|value| value.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .collect::<Vec<_>>();
        if !asns.is_empty() {
            return asns;
        }
    }
    Vec::new()
}

pub(crate) async fn lookup_asn(address: IpAddr, budget: Duration) -> Vec<u32> {
    if budget.is_zero() || is_ip_private(address) {
        return Vec::new();
    }
    let query = cymru_query_name(address);
    let Ok(output) = timeout(
        budget.min(Duration::from_secs(3)),
        Command::new("dig")
            .args(["+short", &query, "TXT", "+tries=1"])
            .output(),
    )
    .await
    else {
        return Vec::new();
    };
    let Ok(output) = output else {
        return Vec::new();
    };
    parse_cymru_asns(&String::from_utf8_lossy(&output.stdout))
}

// ── Public helper for integration tests ───────────────────────────────────────

/// Run one MTR measurement without the socket layer.
///
/// # Errors
/// Returns an error when validation or the underlying MTR/ASN lookup process fails.
pub async fn run_measurement(target: &str, protocol: &str, ip_version: u8) -> Result<ParsedMtr> {
    let opts = MtrOptions {
        target: target.to_string(),
        protocol: protocol.to_string(),
        port: 80,
        packets: 3,
        ip_version,
        in_progress_updates: false,
        timeout: 10,
    };
    run_mtr(&opts, None).await
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use parse::{HopTiming, compute_stats};
    use parse::{build_output, parse_raw};

    const RAW_3HOP: &str = "\
h 0 192.168.1.1
d 0 router.home
x 0 0
p 0 1234 0
x 0 1
p 0 987 1
x 0 2
p 0 1456 2
h 1 10.20.0.1
d 1 isp.net
x 1 0
p 1 5678 0
x 1 1
p 1 5432 1
x 1 2
p 1 5890 2
h 2 1.1.1.1
d 2 one.one.one.one
x 2 0
p 2 8123 0
x 2 1
p 2 7956 1
x 2 2
p 2 8234 2";

    #[test]
    fn parse_three_hops() {
        let hops = parse_raw(RAW_3HOP, true);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].resolved_address.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[1].resolved_address.as_deref(), Some("10.20.0.1"));
        assert_eq!(hops[2].resolved_address.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn parse_hostnames() {
        let hops = parse_raw(RAW_3HOP, true);
        assert_eq!(hops[0].resolved_hostname.as_deref(), Some("router.home"));
        assert_eq!(
            hops[2].resolved_hostname.as_deref(),
            Some("one.one.one.one")
        );
    }

    #[test]
    fn parse_timings_all_received() {
        let hops = parse_raw(RAW_3HOP, true);
        assert_eq!(hops[0].timings.len(), 3);
        assert!(hops[0].timings.iter().all(|t| t.rtt.is_some()));
        assert!((hops[0].timings[0].rtt.unwrap() - 1.234).abs() < 0.001);
    }

    #[test]
    fn parse_drop_when_x_without_p() {
        // seq 0: sent but no reply (drop), seq 1 and 2: sent and replied (rcv)
        let raw = "h 0 1.1.1.1\nx 0 0\nx 0 1\np 0 5000 1\nx 0 2\np 0 6000 2\n";
        let hops = parse_raw(raw, true);
        // Drop entries (no rtt) are stripped from the output `timings` to match the
        // Node.js probe, but are still counted in `stats`.
        assert_eq!(hops[0].timings.len(), 2);
        assert!(hops[0].timings.iter().all(|t| t.rtt.is_some()));
        assert_eq!(hops[0].stats.total, 3);
        assert_eq!(hops[0].stats.drop, 1);
        assert_eq!(hops[0].stats.rcv, 2);
    }

    #[test]
    fn parse_star_hop_has_no_address() {
        let raw = "h 0 192.168.1.1\nx 0 0\np 0 1000 0\nx 1 0\nx 1 1\n"; // hop 1: x but no h
        let hops = parse_raw(raw, true);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[1].resolved_address, None);
    }

    #[test]
    fn parse_duplicate_removal() {
        // Same IP at index 0 and index 2 → index 2 should be removed
        let raw = "\
h 0 192.168.1.1
x 0 0
p 0 1000 0
h 1 10.0.0.1
x 1 0
p 1 5000 0
h 2 192.168.1.1
x 2 0
p 2 1000 0";
        let hops = parse_raw(raw, true);
        assert_eq!(hops.len(), 2, "duplicate hop should be removed");
        assert_eq!(hops[0].resolved_address.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[1].resolved_address.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn parse_hostname_fulfillment() {
        // Hop 0 gets hostname via 'd' at hop 2 (same address)
        let raw = "\
h 0 1.1.1.1
x 0 0
p 0 1000 0
h 1 10.0.0.1
d 1 isp.net
x 1 0
p 1 5000 0
h 2 1.1.1.1
d 2 one.one.one.one
x 2 0
p 2 1000 0";
        // hop 2 is a duplicate of hop 0, so only 2 hops remain
        let hops = parse_raw(raw, true);
        assert_eq!(hops.len(), 2);
        // hop 0 should have the hostname from addr_to_hostname propagation
        assert_eq!(
            hops[0].resolved_hostname.as_deref(),
            Some("one.one.one.one")
        );
    }

    #[test]
    fn stats_avg_correct() {
        let timings = vec![
            HopTiming { rtt: Some(1.0) },
            HopTiming { rtt: Some(2.0) },
            HopTiming { rtt: Some(3.0) },
        ];
        let stats = compute_stats(&timings, true);
        assert!((stats.avg - 2.0).abs() < 0.01);
        assert!((stats.min - 1.0).abs() < 0.01);
        assert!((stats.max - 3.0).abs() < 0.01);
        assert_eq!(stats.total, 3);
        assert_eq!(stats.rcv, 3);
        assert_eq!(stats.drop, 0);
        assert!((stats.loss - 0.0).abs() < 0.01);
    }

    #[test]
    fn stats_drop_counted_final() {
        let timings = vec![
            HopTiming { rtt: Some(5.0) },
            HopTiming { rtt: None },
            HopTiming { rtt: Some(5.0) },
        ];
        let stats = compute_stats(&timings, true);
        assert_eq!(stats.drop, 1);
        assert_eq!(stats.rcv, 2);
        assert!((stats.loss - 33.3).abs() < 0.1);
    }

    #[test]
    fn stats_last_probe_excluded_when_not_final() {
        // With is_final=false, the last timing entry is skipped from rcv/drop count
        let timings = vec![
            HopTiming { rtt: Some(5.0) },
            HopTiming { rtt: Some(6.0) },
            HopTiming { rtt: None }, // last — in-flight, not counted
        ];
        let stats = compute_stats(&timings, false);
        assert_eq!(stats.rcv, 2);
        assert_eq!(stats.drop, 0);
        assert_eq!(stats.total, 3);
    }

    #[test]
    fn stats_jitter_computed() {
        // pairs: |1.0-3.0|=2.0, single pair so j_min=j_max=j_avg=2.0
        let timings = vec![HopTiming { rtt: Some(1.0) }, HopTiming { rtt: Some(3.0) }];
        let stats = compute_stats(&timings, true);
        assert!((stats.j_avg - 2.0).abs() < 0.01);
        assert!((stats.j_min - 2.0).abs() < 0.01);
        assert!((stats.j_max - 2.0).abs() < 0.01);
    }

    #[test]
    fn build_output_has_header_and_gateway() {
        let hops = parse_raw(RAW_3HOP, true);
        let out = build_output(&hops);
        assert!(out.contains("Host"), "output should have Host header");
        assert!(out.contains("Loss%"), "output should have Loss% column");
        assert!(out.contains("_gateway"), "first hop should be _gateway");
        assert!(
            !out.contains("router.home"),
            "real hostname of first hop must not appear"
        );
    }

    #[test]
    fn build_output_trailing_stars_omitted() {
        // With [addr, *, *, *]: the first trailing star is kept (hops[i-1..] includes the addressed hop).
        // Stars after the first trailing star are removed.
        let raw = "\
h 0 192.168.1.1
x 0 0
p 0 1000 0
x 1 0
x 1 1
x 2 0
x 2 1
x 3 0
x 3 1";
        let hops = parse_raw(raw, true);
        let out = build_output(&hops);
        let waiting_count = out
            .lines()
            .filter(|l| l.contains("waiting for reply"))
            .count();
        assert_eq!(
            waiting_count, 1,
            "first trailing star shown; subsequent ones removed; output:\n{}",
            out
        );
    }

    #[test]
    fn normalize_ip_text_strips_scope_and_canonicalizes() {
        assert_eq!(normalize_ip_text("2001:0db8::1%eth0"), "2001:db8::1");
        assert_eq!(normalize_ip_text("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn cymru_query_names_cover_ipv4_and_ipv6() {
        let v4 = "1.2.3.4".parse().expect("valid IPv4");
        assert_eq!(cymru_query_name(v4), "4.3.2.1.origin.asn.cymru.com");

        let v6 = "2001:4860:4860::8888".parse().expect("valid IPv6");
        let query = cymru_query_name(v6);
        assert!(query.ends_with(".origin6.asn.cymru.com"));
        assert!(query.starts_with("8.8.8.8."));
    }

    #[test]
    fn parses_multiple_cymru_asns() {
        assert_eq!(
            parse_cymru_asns("\"13335 209242 | 1.1.1.0/24 | AU | apnic | 2011-08-11\"\n"),
            vec![13335, 209242]
        );
    }

    #[test]
    fn progress_render_applies_completed_enrichment() {
        let cache = EnrichmentCache::default();
        let address = "1.1.1.1".parse().expect("valid address");
        cache.update(address, Some("one.one.one.one".into()), vec![13335]);
        let raw = "h 0 192.168.1.1\nx 0 0\np 0 1000 0\nh 1 1.1.1.1\nx 1 0\np 1 2000 0\n";
        let rendered = render_mtr_progress(raw, &cache);
        let output = rendered["rawOutput"].as_str().expect("raw output");
        assert!(output.contains("AS13335"));
        assert!(output.contains("one.one.one.one (1.1.1.1)"));
    }

    #[test]
    fn build_args_icmp_no_protocol_flag() {
        let args = build_args(&MtrOptions {
            target: "1.1.1.1".into(),
            protocol: "ICMP".into(),
            port: 80,
            packets: 3,
            ip_version: 4,
            in_progress_updates: false,
            timeout: 10,
        });
        assert!(args.contains(&"-4".to_string()));
        assert!(!args.contains(&"--icmp".to_string()));
        assert!(args.contains(&"--raw".to_string()));
        assert!(args.contains(&"-c".to_string()));
        assert!(args.contains(&"3".to_string()));
    }

    #[test]
    fn build_args_tcp_adds_flag_and_port() {
        let args = build_args(&MtrOptions {
            target: "1.1.1.1".into(),
            protocol: "TCP".into(),
            port: 443,
            packets: 3,
            ip_version: 4,
            in_progress_updates: false,
            timeout: 10,
        });
        assert!(args.contains(&"--tcp".to_string()));
        assert!(args.contains(&"-P".to_string()));
        assert!(args.contains(&"443".to_string()));
    }

    #[test]
    fn build_args_udp_flag() {
        let args = build_args(&MtrOptions {
            target: "1.1.1.1".into(),
            protocol: "UDP".into(),
            port: 80,
            packets: 3,
            ip_version: 6,
            in_progress_updates: false,
            timeout: 10,
        });
        assert!(args.contains(&"-6".to_string()));
        assert!(args.contains(&"--udp".to_string()));
    }

    #[test]
    fn validate_accepts_private_literal_for_structured_runtime_rejection() {
        let opts = MtrOptions {
            target: "10.0.0.1".into(),
            protocol: "ICMP".into(),
            port: 80,
            packets: 3,
            ip_version: 4,
            in_progress_updates: false,
            timeout: 10,
        };
        assert!(validate(&opts).is_ok());
    }

    #[test]
    fn validate_rejects_bad_packets() {
        let opts = MtrOptions {
            target: "1.1.1.1".into(),
            protocol: "ICMP".into(),
            port: 80,
            packets: 0,
            ip_version: 4,
            in_progress_updates: false,
            timeout: 10,
        };
        assert!(validate(&opts).is_err());
    }

    #[test]
    fn validate_accepts_valid() {
        for proto in &["ICMP", "TCP", "UDP"] {
            for ver in &[4u8, 6u8] {
                let opts = MtrOptions {
                    target: "1.1.1.1".into(),
                    protocol: proto.to_string(),
                    port: 80,
                    packets: 3,
                    ip_version: *ver,
                    in_progress_updates: false,
                    timeout: 10,
                };
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
