use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::net::IpAddr;
use serde::Serialize;

#[must_use]
pub fn normalize_ip_text(raw: &str) -> String {
    let address = raw.split_once('%').map_or(raw, |(address, _)| address);
    address
        .parse::<IpAddr>()
        .map_or_else(|_| address.to_string(), |address| address.to_string())
}

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
#[must_use]
pub fn parse_raw(data: &str, is_final: bool) -> Vec<MtrHop> {
    let mut builders: Vec<Option<HopBuilder>> = Vec::new();
    let mut addr_to_hostname: BTreeMap<String, String> = BTreeMap::new();

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
                let addr = normalize_ip_text(parts[2]);
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

#[must_use]
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
            rtts.iter().map(|&x| (x - avg) * (x - avg)).sum::<f64>() / count_as_f64(rtts.len());
        (min, max, avg, r1(libm::sqrt(var)))
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
    libm::round(v * 10.0) / 10.0
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
                .map(ToString::to_string)
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

#[derive(Debug, Clone, Default)]
pub struct MtrEnrichmentEntry {
    pub hostname: Option<String>,
    pub asn: Vec<u32>,
}

pub type MtrEnrichmentMap = BTreeMap<String, MtrEnrichmentEntry>;

pub fn apply_enrichment(hops: &mut [MtrHop], entries: &MtrEnrichmentMap) {
    for hop in hops {
        let Some(address) = hop.resolved_address.as_deref() else {
            continue;
        };
        let Some(entry) = entries.get(address) else {
            continue;
        };
        if let Some(hostname) = &entry.hostname {
            hop.resolved_hostname = Some(hostname.clone());
        }
        if !entry.asn.is_empty() {
            hop.asn.clone_from(&entry.asn);
        }
    }
}

#[must_use]
pub fn render_progress(raw: &str, entries: &MtrEnrichmentMap) -> String {
    let mut hops = parse_raw(raw, false);
    apply_enrichment(&mut hops, entries);
    build_output(&hops)
}

#[must_use]
pub fn shape_result(
    stdout: &str,
    stderr: &str,
    timed_out: bool,
    resolved_address: &str,
    resolved_hostname: &str,
    entries: &MtrEnrichmentMap,
) -> ParsedMtr {
    if stdout.trim().is_empty() {
        return ParsedMtr {
            status: MtrStatus::Failed,
            failure_source: Some("internal".to_string()),
            raw_output: if stderr.trim().is_empty() {
                "Test failed. Please try again.".to_string()
            } else {
                stderr.to_string()
            },
            resolved_address: None,
            resolved_hostname: None,
            hops: Vec::new(),
        };
    }

    let mut hops = parse_raw(stdout, true);
    apply_enrichment(&mut hops, entries);
    let target_responded = hops.last().is_some_and(|hop| {
        hop.resolved_address.as_deref() == Some(resolved_address)
            && hop.timings.iter().any(|timing| timing.rtt.is_some())
    });
    let has_drop = hops.iter().any(|hop| hop.stats.drop > 0);
    let mut raw_output = build_output(&hops);
    if let Some(first_hop) = hops.first_mut()
        && first_hop.resolved_address.is_some()
    {
        first_hop.resolved_hostname = Some("_gateway".to_string());
    }

    let (status, failure_source) = if timed_out {
        if !raw_output.is_empty() {
            raw_output.push('\n');
        }
        raw_output.push_str("The measurement command timed out.");
        (
            MtrStatus::Failed,
            Some(
                if !target_responded && has_drop {
                    "target"
                } else {
                    "internal"
                }
                .to_string(),
            ),
        )
    } else {
        (MtrStatus::Finished, None)
    };

    ParsedMtr {
        status,
        failure_source,
        raw_output,
        resolved_address: Some(resolved_address.to_string()),
        resolved_hostname: Some(resolved_hostname.to_string()),
        hops,
    }
}
