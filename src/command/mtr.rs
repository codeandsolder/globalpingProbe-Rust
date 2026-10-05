pub mod parse {
    use serde::Serialize;
    use std::collections::HashMap;

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
            let avg = r1(rtts.iter().sum::<f64>() / rtts.len() as f64);
            // Node.js uses the rounded avg when computing stDev
            let var = rtts.iter().map(|&x| (x - avg).powi(2)).sum::<f64>() / rtts.len() as f64;
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
        let loss = r1((drop as f64 / total as f64) * 100.0);

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
                r1(jv.iter().sum::<f64>() / jv.len() as f64),
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

    /// Build a human-readable table from parsed hops.
    /// First hop hostname is replaced with `_gateway` (mirrors Node.js behavior).
    #[must_use]
    pub fn build_output(hops: &[MtrHop]) -> String {
        if hops.is_empty() {
            return String::new();
        }

        // Skip trailing all-star hops (no resolved address from that point on)
        let mut filtered: Vec<(usize, &MtrHop)> = Vec::new();
        for (i, hop) in hops.iter().enumerate() {
            if hop.resolved_address.is_none() {
                let from = i.saturating_sub(1);
                if hops[from..].iter().all(|h| h.resolved_address.is_none()) {
                    continue;
                }
            }
            filtered.push((i, hop));
        }
        if filtered.is_empty() {
            return String::new();
        }

        // Dynamic column widths
        let idx_w = filtered.len().to_string().len();

        let asn_str = |h: &MtrHop| -> String {
            if h.asn.is_empty() {
                "AS???".to_string()
            } else {
                format!(
                    "AS{}",
                    h.asn
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
        };
        let asn_w = 2 + filtered
            .iter()
            .map(|(_, h)| asn_str(h).len())
            .max()
            .unwrap_or(5);

        let addr_w = filtered
            .iter()
            .map(|(_, h)| h.resolved_address.as_deref().unwrap_or("").len())
            .max()
            .unwrap_or(0);
        let display_host = |display_i: usize, h: &MtrHop| -> String {
            if display_i == 0 {
                "_gateway".to_string()
            } else {
                h.resolved_hostname
                    .as_deref()
                    .or(h.resolved_address.as_deref())
                    .unwrap_or("")
                    .to_string()
            }
        };
        let hn_w = filtered
            .iter()
            .enumerate()
            .map(|(di, (_, h))| display_host(di, h).len())
            .max()
            .unwrap_or(0);
        let hostname_col = 3 + addr_w + hn_w; // space + hostname + space + (address)

        let loss_w = 6usize; // "100.0%" = 6
        let drop_max = filtered
            .iter()
            .map(|(_, h)| h.stats.drop.to_string().len())
            .max()
            .unwrap_or(1);
        let drop_w = drop_max.max(4);
        let rcv_w = 2 + drop_max;
        let avg_w = filtered
            .iter()
            .map(|(_, h)| format!("{:.1}", h.stats.avg).len())
            .max()
            .unwrap_or(3)
            .max(3);
        let stdev_w = 6usize;
        let javg_w = 5usize;
        let host_col = idx_w + asn_w + hostname_col + 4;

        let mut out = format!(
            "{:<hc$} {:>lw$} {:>dw$} {:>rw$} {:>aw$} {:>sw$} {:>jw$}\n",
            "Host",
            "Loss%",
            "Drop",
            "Rcv",
            "Avg",
            "StDev",
            "Javg",
            hc = host_col,
            lw = loss_w + 1,
            dw = drop_w,
            rw = rcv_w,
            aw = avg_w,
            sw = stdev_w,
            jw = javg_w,
        );

        for (di, (_, hop)) in filtered.iter().enumerate() {
            let sindex = format!("{:>iw$}.", di + 1, iw = idx_w);
            let sasn = format!("{:<aw$}", asn_str(hop), aw = asn_w);
            let hn = display_host(di, hop);
            let shost = if let Some(addr) = &hop.resolved_address {
                format!("{:<hw$}", format!("{} ({})", hn, addr), hw = hostname_col)
            } else {
                format!("{:<hw$}", "(waiting for reply)", hw = hostname_col)
            };
            let mut line = format!("{sindex} {sasn} {shost}");
            if hop.resolved_address.is_some() {
                line.push_str(&format!(
                    " {:>lw$}% {:>dw$} {:>rw$} {:>aw$.1} {:>sw$.1} {:>jw$.1}",
                    format!("{:.1}", hop.stats.loss),
                    hop.stats.drop,
                    hop.stats.rcv,
                    hop.stats.avg,
                    hop.stats.st_dev,
                    hop.stats.j_avg,
                    lw = loss_w - 1,
                    dw = drop_w,
                    rw = rcv_w,
                    aw = avg_w,
                    sw = stdev_w,
                    jw = javg_w,
                ));
            }
            line.push('\n');
            out.push_str(&line);
        }

        out
    }
}

// ── Imports ───────────────────────────────────────────────────────────────────

use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::Value;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use super::MeasurementCommand;
use crate::util::private_ip::is_ip_private;
use crate::util::validate::is_safe_host;
use parse::{MtrStatus, ParsedMtr, build_output, parse_raw};

// ── Options ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
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
    if let Ok(ip) = opts.target.parse()
        && is_ip_private(ip)
    {
        bail!("Private IP ranges are not allowed");
    }
    Ok(())
}

// ── Arg builder ───────────────────────────────────────────────────────────────

#[must_use]
pub fn build_args(opts: &MtrOptions) -> Vec<String> {
    let mut args: Vec<String> = vec![
        format!("-{}", opts.ip_version),
        "--interval".into(),
        "1.0".into(),
        "--gracetime".into(),
        "3".into(),
        "--max-ttl".into(),
        "30".into(),
        "--timeout".into(),
        "15".into(),
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

#[async_trait::async_trait]
impl MeasurementCommand for MtrCommand {
    async fn run(&self, options: Value) -> Result<Value> {
        let opts: MtrOptions = serde_json::from_value(options)?;
        validate(&opts)?;
        let result = run_mtr(&opts).await?;
        Ok(serde_json::to_value(result)?)
    }
}

// ── Internal runner ───────────────────────────────────────────────────────────

async fn run_mtr(opts: &MtrOptions) -> Result<ParsedMtr> {
    validate(opts)?;
    let args = build_args(opts);

    // mtr runs for (packets × interval) + gracetime seconds; cap with a hard timeout
    let output = timeout(
        Duration::from_secs(60),
        Command::new("mtr").args(&args).output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("mtr command timed out"))?
    .map_err(|e| anyhow::anyhow!("failed to spawn mtr: {e}"))?;

    let raw_stdout = String::from_utf8_lossy(&output.stdout).to_string();

    if raw_stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Ok(ParsedMtr {
            status: MtrStatus::Failed,
            raw_output: if stderr.trim().is_empty() {
                "Test failed. Please try again.".into()
            } else {
                stderr
            },
            resolved_address: None,
            resolved_hostname: None,
            hops: vec![],
        });
    }

    let mut hops = parse_raw(&raw_stdout, true);

    // Kill-switch: target IP resolved to a private range
    let last_real = hops.iter().rev().find(|h| h.resolved_address.is_some());
    if let Some(hop) = last_real
        && let Some(addr) = &hop.resolved_address
        && let Ok(ip) = addr.parse()
        && is_ip_private(ip)
    {
        return Ok(ParsedMtr {
            status: MtrStatus::Failed,
            raw_output: "Private IP ranges are not allowed.".into(),
            resolved_address: None,
            resolved_hostname: None,
            hops: vec![],
        });
    }

    // ASN lookup (best-effort, non-blocking)
    let addresses: Vec<Option<String>> = hops.iter().map(|h| h.resolved_address.clone()).collect();
    let asns = lookup_asns(&addresses).await;
    for (hop, asn_nums) in hops.iter_mut().zip(asns) {
        hop.asn = asn_nums;
    }

    let last_hop = hops.iter().rev().find(|h| h.resolved_address.is_some());
    let resolved_address = last_hop.and_then(|h| h.resolved_address.clone());
    let resolved_hostname = last_hop.and_then(|h| h.resolved_hostname.clone());
    let raw_output = build_output(&hops);

    Ok(ParsedMtr {
        status: MtrStatus::Finished,
        raw_output,
        resolved_address,
        resolved_hostname,
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

pub async fn run_measurement(target: &str, protocol: &str, ip_version: u8) -> Result<ParsedMtr> {
    let opts = MtrOptions {
        target: target.to_string(),
        protocol: protocol.to_string(),
        port: 80,
        packets: 3,
        ip_version,
        in_progress_updates: false,
    };
    run_mtr(&opts).await
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
        });
        assert!(args.contains(&"-6".to_string()));
        assert!(args.contains(&"--udp".to_string()));
    }

    #[test]
    fn validate_rejects_private_ip() {
        let opts = MtrOptions {
            target: "10.0.0.1".into(),
            protocol: "ICMP".into(),
            port: 80,
            packets: 3,
            ip_version: 4,
            in_progress_updates: false,
        };
        assert!(validate(&opts).is_err());
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
