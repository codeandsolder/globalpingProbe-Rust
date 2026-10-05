pub mod parse {
    use serde::Serialize;
    use std::collections::HashMap;
    use std::fmt::Write as _;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum MtrStatus {
        Finished,
        Failed,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct HopTiming {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub rtt: Option<f64>, // ms; None = timeout/drop
    }

    #[derive(Debug, Clone, Default, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct HopStats {
        pub min: f64,
        pub max: f64,
        pub avg: f64,
        pub total: usize,
        pub loss: f64,
        pub rcv: usize,
        pub drop: usize,
        pub st_dev: f64,
        pub j_min: f64,
        pub j_max: f64,
        pub j_avg: f64,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MtrHop {
        pub resolved_address: Option<String>,
        pub resolved_hostname: Option<String>,
        pub asn: Vec<u32>,
        pub stats: HopStats,
        pub timings: Vec<HopTiming>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ParsedMtr {
        pub status: MtrStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub failure_source: Option<String>,
        pub raw_output: String,
        pub resolved_address: Option<String>,
        pub resolved_hostname: Option<String>,
        pub hops: Vec<MtrHop>,
    }

    struct HopBuilder {
        resolved_address: Option<String>,
        resolved_hostname: Option<String>,
        timings: Vec<(String, Option<f64>)>, // (seq, rtt_ms)
        duplicate: bool,
    }

    const fn fresh() -> HopBuilder {
        HopBuilder {
            resolved_address: None,
            resolved_hostname: None,
            timings: Vec::new(),
            duplicate: false,
        }
    }

    /// Parse mtr `--raw` output into hops.
    /// `is_final` controls whether the last probe-in-flight is counted as a drop.
    pub fn parse_raw(data: &str, is_final: bool) -> Vec<MtrHop> {
        let mut builders: Vec<Option<HopBuilder>> = Vec::new();
        let mut addr_to_hostname: HashMap<String, String> = HashMap::new();

        for line in data.lines() {
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 3 {
                continue;
            }
            let action = parts[0];
            let Ok(idx): Result<usize, _> = parts[1].parse() else {
                continue;
            };
            while builders.len() <= idx {
                builders.push(None);
            }

            match action {
                "h" => {
                    let addr = parts[2].to_string();
                    // Mark duplicate if the same IP appeared at a lower hop index
                    let is_dup = builders[..idx].iter().any(|b| {
                        b.as_ref()
                            .is_some_and(|b| b.resolved_address.as_deref() == Some(&addr))
                    });
                    let entry = builders[idx].get_or_insert_with(fresh);
                    entry.resolved_address = Some(addr);
                    entry.duplicate = is_dup;
                }
                "d" => {
                    let hn = parts[2].to_string();
                    let entry = builders[idx].get_or_insert_with(fresh);
                    entry.resolved_hostname = Some(hn.clone());
                    if let Some(addr) = entry.resolved_address.clone() {
                        addr_to_hostname.insert(addr, hn);
                    }
                }
                "x" => {
                    let seq = parts[2].to_string();
                    let entry = builders[idx].get_or_insert_with(fresh);
                    if !entry.timings.iter().any(|(s, _)| s == &seq) {
                        entry.timings.push((seq, None));
                    }
                }
                "p" => {
                    if parts.len() < 4 {
                        continue;
                    }
                    let Ok(rtt_us): Result<f64, _> = parts[2].parse() else {
                        continue;
                    };
                    let seq = parts[3].trim().to_string();
                    if let Some(entry) = builders[idx].as_mut() {
                        for (s, rtt) in &mut entry.timings {
                            if *s == seq {
                                *rtt = Some(rtt_us / 1000.0);
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Propagate hostnames from address→hostname map to hops that share an address
        for b in builders.iter_mut().flatten() {
            if (b.resolved_hostname.is_none() || b.resolved_hostname == b.resolved_address)
                && let Some(addr) = &b.resolved_address
                && let Some(hn) = addr_to_hostname.get(addr)
            {
                b.resolved_hostname = Some(hn.clone());
            }
        }

        builders
            .into_iter()
            .flatten()
            .filter(|b| !b.duplicate)
            .map(|b| {
                let timings: Vec<HopTiming> = b
                    .timings
                    .iter()
                    .map(|(_, rtt)| HopTiming { rtt: *rtt })
                    .collect();
                let stats = compute_stats(&timings, is_final);
                // Node.js filters out drop-timings (no rtt) from the final output.
                // Stats are computed first (accounting for drops), then we strip None entries.
                let timings_out: Vec<HopTiming> =
                    timings.into_iter().filter(|t| t.rtt.is_some()).collect();
                MtrHop {
                    resolved_address: b.resolved_address,
                    resolved_hostname: b.resolved_hostname,
                    asn: Vec::new(),
                    stats,
                    timings: timings_out,
                }
            })
            .collect()
    }

    fn count_as_f64(count: usize) -> f64 {
        f64::from(u32::try_from(count).unwrap_or(u32::MAX))
    }

    pub fn compute_stats(timings: &[HopTiming], is_final: bool) -> HopStats {
        if timings.is_empty() {
            return HopStats::default();
        }
        let total = timings.len();
        let rtts: Vec<f64> = timings.iter().filter_map(|t| t.rtt).collect();

        let (min, max, avg, st_dev) = if rtts.is_empty() {
            (0.0, 0.0, 0.0, 0.0)
        } else {
            let min = rtts.iter().copied().fold(f64::INFINITY, f64::min);
            let max = rtts.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let avg = r1(rtts.iter().sum::<f64>() / count_as_f64(rtts.len()));
            // Node.js uses the rounded avg when computing stDev
            let var =
                rtts.iter().map(|&x| (x - avg).powi(2)).sum::<f64>() / count_as_f64(rtts.len());
            (min, max, avg, r1(var.sqrt()))
        };

        let mut rcv = 0usize;
        let mut drop = 0usize;
        for (i, t) in timings.iter().enumerate() {
            if i == total - 1 && !is_final {
                continue; // last probe may still be in-flight
            }
            if t.rtt.is_some() {
                rcv += 1;
            } else {
                drop += 1;
            }
        }
        let loss = r1((count_as_f64(drop) / count_as_f64(total)) * 100.0);

        // Jitter: absolute diff between consecutive pairs of received RTTs
        let mut jv: Vec<f64> = Vec::new();
        let mut i = 0;
        while i + 1 < rtts.len() {
            jv.push((rtts[i] - rtts[i + 1]).abs());
            i += 2;
        }
        let (j_min, j_max, j_avg) = if jv.is_empty() {
            (0.0, 0.0, 0.0)
        } else {
            (
                r1(jv.iter().copied().fold(f64::INFINITY, f64::min)),
                r1(jv.iter().copied().fold(f64::NEG_INFINITY, f64::max)),
                r1(jv.iter().sum::<f64>() / count_as_f64(jv.len())),
            )
        };

        HopStats {
            min,
            max,
            avg,
            total,
            loss,
            rcv,
            drop,
            st_dev,
            j_min,
            j_max,
            j_avg,
        }
    }

    fn r1(v: f64) -> f64 {
        (v * 10.0).round() / 10.0
    }

    fn filter_output_hops(hops: &[MtrHop]) -> Vec<&MtrHop> {
        let mut filtered = Vec::new();
        for (index, hop) in hops.iter().enumerate() {
            if hop.resolved_address.is_none() {
                let from = index.saturating_sub(1);
                if hops[from..]
                    .iter()
                    .all(|candidate| candidate.resolved_address.is_none())
                {
                    continue;
                }
            }
            filtered.push(hop);
        }
        filtered
    }

    fn asn_string(hop: &MtrHop) -> String {
        if hop.asn.is_empty() {
            "AS???".to_string()
        } else {
            format!(
                "AS{}",
                hop.asn
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    }

    fn display_host(display_index: usize, hop: &MtrHop) -> String {
        if display_index == 0 {
            "_gateway".to_string()
        } else {
            hop.resolved_hostname
                .as_deref()
                .or(hop.resolved_address.as_deref())
                .unwrap_or("")
                .to_string()
        }
    }

    struct OutputWidths {
        index: usize,
        asn: usize,
        hostname: usize,
        loss: usize,
        drop: usize,
        received: usize,
        average: usize,
        stdev: usize,
        jitter: usize,
        host: usize,
    }

    fn output_widths(hops: &[&MtrHop]) -> OutputWidths {
        let index = hops.len().to_string().len();
        let asn = 2 + hops
            .iter()
            .map(|hop| asn_string(hop).len())
            .max()
            .unwrap_or(5);
        let address = hops
            .iter()
            .map(|hop| hop.resolved_address.as_deref().unwrap_or("").len())
            .max()
            .unwrap_or(0);
        let hostname_name = hops
            .iter()
            .enumerate()
            .map(|(display_index, hop)| display_host(display_index, hop).len())
            .max()
            .unwrap_or(0);
        let hostname = 3 + address + hostname_name;
        let drop_max = hops
            .iter()
            .map(|hop| hop.stats.drop.to_string().len())
            .max()
            .unwrap_or(1);
        let drop = drop_max.max(4);
        let received = 2 + drop_max;
        let average = hops
            .iter()
            .map(|hop| format!("{:.1}", hop.stats.avg).len())
            .max()
            .unwrap_or(3)
            .max(3);
        let asn_width = asn;
        OutputWidths {
            index,
            asn,
            hostname,
            loss: 6,
            drop,
            received,
            average,
            stdev: 6,
            jitter: 5,
            host: index + asn_width + hostname + 4,
        }
    }

    fn render_header(widths: &OutputWidths) -> String {
        format!(
            "{:<hc$} {:>lw$} {:>dw$} {:>rw$} {:>aw$} {:>sw$} {:>jw$}\n",
            "Host",
            "Loss%",
            "Drop",
            "Rcv",
            "Avg",
            "StDev",
            "Javg",
            hc = widths.host,
            lw = widths.loss + 1,
            dw = widths.drop,
            rw = widths.received,
            aw = widths.average,
            sw = widths.stdev,
            jw = widths.jitter,
        )
    }

    fn render_row(display_index: usize, hop: &MtrHop, widths: &OutputWidths) -> String {
        let index = format!("{:>width$}.", display_index + 1, width = widths.index);
        let asn = format!("{:<width$}", asn_string(hop), width = widths.asn);
        let hostname = display_host(display_index, hop);
        let host_label = hop.resolved_address.as_ref().map_or_else(
            || "(waiting for reply)".to_string(),
            |address| format!("{hostname} ({address})"),
        );
        let host = format!("{host_label:<width$}", width = widths.hostname);
        let mut line = format!("{index} {asn} {host}");
        if hop.resolved_address.is_some() {
            let _ = write!(
                line,
                " {:>lw$}% {:>dw$} {:>rw$} {:>aw$.1} {:>sw$.1} {:>jw$.1}",
                format!("{:.1}", hop.stats.loss),
                hop.stats.drop,
                hop.stats.rcv,
                hop.stats.avg,
                hop.stats.st_dev,
                hop.stats.j_avg,
                lw = widths.loss - 1,
                dw = widths.drop,
                rw = widths.received,
                aw = widths.average,
                sw = widths.stdev,
                jw = widths.jitter,
            );
        }
        line.push('\n');
        line
    }

    /// Build a human-readable table from parsed hops.
    /// First hop hostname is replaced with `_gateway` (mirrors Node.js behavior).
    #[must_use]
    pub fn build_output(hops: &[MtrHop]) -> String {
        if hops.is_empty() {
            return String::new();
        }
        let filtered = filter_output_hops(hops);
        if filtered.is_empty() {
            return String::new();
        }
        let widths = output_widths(&filtered);
        let mut output = render_header(&widths);
        for (display_index, hop) in filtered.into_iter().enumerate() {
            output.push_str(&render_row(display_index, hop, &widths));
        }
        output
    }
}

// ── Imports ───────────────────────────────────────────────────────────────────

use super::ProgressTx;
use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::util::measurement_timeout::{MeasurementDeadline, mtr_budget};
use crate::util::private_ip::is_ip_private;
use crate::util::resolve_target::{ResolveTargetError, resolve_command_target};
use crate::util::validate::is_safe_host;
use parse::{MtrStatus, ParsedMtr, build_output, parse_raw};

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

fn validate(opts: &MtrOptions) -> Result<()> {
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

struct NativeMtrOutput {
    stdout: String,
    stderr: String,
    timed_out: bool,
}

async fn run_native_mtr(
    args: &[String],
    process_timeout: Duration,
    progress: Option<&ProgressTx>,
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
    let mut raw_stdout = String::new();
    let completed = timeout(process_timeout, async {
        while let Some(line) = stdout_lines.next_line().await? {
            raw_stdout.push_str(&line);
            raw_stdout.push('\n');
            if let Some(tx) = progress {
                let hops = parse_raw(&raw_stdout, false);
                tx.send(json!({ "rawOutput": build_output(&hops) })).ok();
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
    Ok(NativeMtrOutput {
        stdout: raw_stdout,
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
    let native = run_native_mtr(
        &build_args(&resolved_options),
        deadline.process_timeout(),
        progress.as_ref(),
    )
    .await?;

    if native.stdout.trim().is_empty() {
        return Ok(ParsedMtr {
            status: MtrStatus::Failed,
            failure_source: Some("internal".to_string()),
            raw_output: if native.stderr.trim().is_empty() {
                "Test failed. Please try again.".into()
            } else {
                native.stderr
            },
            resolved_address: None,
            resolved_hostname: None,
            hops: vec![],
        });
    }

    let mut hops = parse_raw(&native.stdout, true);
    let addresses: Vec<Option<String>> = hops
        .iter()
        .map(|hop| hop.resolved_address.clone())
        .collect();
    let asns = lookup_asns(&addresses).await;
    for (hop, asn_nums) in hops.iter_mut().zip(asns) {
        hop.asn = asn_nums;
    }
    let target_address = target.address.to_string();
    let target_responded = hops.last().is_some_and(|hop| {
        hop.resolved_address.as_deref() == Some(target_address.as_str())
            && hop.timings.iter().any(|timing| timing.rtt.is_some())
    });
    let has_drop = hops.iter().any(|hop| hop.stats.drop > 0);
    let mut raw_output = build_output(&hops);
    let mut status = MtrStatus::Finished;
    let mut failure_source = None;
    if native.timed_out {
        status = MtrStatus::Failed;
        failure_source = Some(
            if !target_responded && has_drop {
                "target"
            } else {
                "internal"
            }
            .to_string(),
        );
        if !raw_output.is_empty() {
            raw_output.push('\n');
        }
        raw_output.push_str("The measurement command timed out.");
    }
    Ok(ParsedMtr {
        status,
        failure_source,
        raw_output,
        resolved_address: Some(target_address),
        resolved_hostname: Some(target.hostname),
        hops,
    })
}

// ── ASN lookup ────────────────────────────────────────────────────────────────

/// Query ASN for every hop address in parallel. Returns empty vec on failure.
async fn lookup_asns(addresses: &[Option<String>]) -> Vec<Vec<u32>> {
    let futs: Vec<_> = addresses
        .iter()
        .map(|addr| {
            let addr = addr.clone();
            async move {
                match addr {
                    None => vec![],
                    Some(a) => lookup_asn(&a).await,
                }
            }
        })
        .collect();

    futures::future::join_all(futs).await
}

async fn lookup_asn(addr: &str) -> Vec<u32> {
    // Only look up public IPv4 for now (cymru.com only supports IPv4 reversals cleanly)
    let ip: std::net::IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => return vec![],
    };
    if is_ip_private(ip) {
        return vec![];
    }
    let std::net::IpAddr::V4(v4) = ip else {
        return vec![];
    };

    let octets = v4.octets();
    let reversed = format!(
        "{}.{}.{}.{}.origin.asn.cymru.com",
        octets[3], octets[2], octets[1], octets[0]
    );

    // Spawn `dig +short <reversed> TXT` with a short timeout
    let Ok(output) = timeout(
        Duration::from_secs(3),
        Command::new("dig")
            .args(["+short", &reversed, "TXT"])
            .output(),
    )
    .await
    else {
        return vec![];
    };

    let Ok(output) = output else { return vec![] };
    let stdout = String::from_utf8_lossy(&output.stdout);

    // TXT record: "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"
    // May be quoted: "\"15169 | ...\""
    for line in stdout.lines() {
        let line = line.trim().trim_matches('"');
        if let Some(asn_part) = line.split('|').next() {
            let nums: Vec<u32> = asn_part
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !nums.is_empty() {
                return nums;
            }
        }
    }
    vec![]
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
