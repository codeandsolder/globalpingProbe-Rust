use regex::Regex;
use std::path::Path;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Total physical system RAM in bytes, read from `/proc/meminfo` on Linux.
#[must_use]
pub fn host_total_memory_bytes() -> u64 {
    parse_meminfo_total(&std::fs::read_to_string("/proc/meminfo").unwrap_or_default())
}

/// Memory effectively available to this process. Upstream v0.53.0 runs on
/// Node 22.22.3 / libuv 1.51.0, where `process.constrainedMemory()` is derived
/// from cgroup v1/v2 memory limits only.
#[must_use]
pub fn effective_total_memory_bytes() -> u64 {
    let host_total = host_total_memory_bytes();
    constrained_memory_bytes().map_or(host_total, |limit| host_total.min(limit))
}

fn constrained_memory_bytes() -> Option<u64> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    cgroup_constrained_memory(&cgroup, read_memory_limit)
}

fn cgroup_constrained_memory<F>(cgroup: &str, mut read_limit: F) -> Option<u64>
where
    F: FnMut(&Path) -> u64,
{
    let (high, max) = if let Some(path) = cgroup.strip_prefix("0::/") {
        let path = path.lines().next().unwrap_or_default();
        let base = Path::new(CGROUP_ROOT).join(path);
        (
            read_limit(&base.join("memory.high")),
            read_limit(&base.join("memory.max")),
        )
    } else {
        cgroup1_memory_limits(cgroup, &mut read_limit)
    };

    (high != 0 && max != 0).then_some(high.min(max))
}

fn cgroup1_memory_limits<F>(cgroup: &str, read_limit: &mut F) -> (u64, u64)
where
    F: FnMut(&Path) -> u64,
{
    let scoped = cgroup.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        (controllers == "memory").then_some(path.trim_start_matches('/'))
    });

    if let Some(path) = scoped {
        let base = Path::new(CGROUP_ROOT).join("memory").join(path);
        let high = read_limit(&base.join("memory.soft_limit_in_bytes"));
        let max = read_limit(&base.join("memory.limit_in_bytes"));
        if high != 0 && max != 0 {
            return (high, max);
        }
    }

    let base = Path::new(CGROUP_ROOT).join("memory");
    (
        read_limit(&base.join("memory.soft_limit_in_bytes")),
        read_limit(&base.join("memory.limit_in_bytes")),
    )
}

fn read_memory_limit(path: &Path) -> u64 {
    let Ok(value) = std::fs::read_to_string(path) else {
        return 0;
    };
    parse_memory_limit(&value)
}

fn parse_memory_limit(value: &str) -> u64 {
    let value = value.trim();
    if value == "max" {
        u64::MAX
    } else {
        value.parse::<u64>().unwrap_or(0)
    }
}

#[must_use]
pub fn parse_meminfo_total(content: &str) -> u64 {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

/// Disk usage of "/" in (`total_mb`, `available_mb`).
/// Returns (0, 0) if unavailable.
#[must_use]
pub fn disk_info_mb() -> (u64, u64) {
    parse_df_output(&run_df())
}

fn run_df() -> String {
    std::process::Command::new("df")
        .args(["-BM", "--output=size,avail", "/"])
        .output()
        .map_or_else(
            |_| String::new(),
            |output| String::from_utf8_lossy(&output.stdout).into_owned(),
        )
}

/// Parse `df -BM --output=size,avail /` output.
#[must_use]
pub fn parse_df_output(output: &str) -> (u64, u64) {
    let mut lines = output.lines().skip(1); // skip header
    if let Some(line) = lines.next() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let total = parts[0].trim_end_matches('M').parse::<u64>().unwrap_or(0);
            let avail = parts[1].trim_end_matches('M').parse::<u64>().unwrap_or(0);
            return (total, avail);
        }
    }
    (0, 0)
}

#[must_use]
pub fn looks_like_v1_hardware_device() -> bool {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let logical_cpus = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
    looks_like_v1_hardware_values(
        logical_cpus,
        &cpuinfo,
        hostname.trim(),
        host_total_memory_bytes(),
    )
}

#[must_use]
pub fn looks_like_v1_hardware_values(
    logical_cpus: usize,
    cpuinfo: &str,
    hostname: &str,
    total_memory: u64,
) -> bool {
    let hostname_matches =
        Regex::new(r"^globalping-probe-\w{4}$").is_ok_and(|pattern| pattern.is_match(hostname));
    logical_cpus == 4
        && cpuinfo.contains("ARMv7 Processor rev 5 (v7l)")
        && hostname_matches
        && total_memory < 550_000_000
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MEMINFO: &str = "MemTotal:       16282616 kB\n\
MemFree:         8192000 kB\n\
MemAvailable:   12000000 kB\n";

    #[test]
    fn parses_mem_total_from_meminfo() {
        let bytes = parse_meminfo_total(MEMINFO);
        assert_eq!(bytes, 16_282_616 * 1024);
    }

    #[test]
    fn returns_zero_when_meminfo_missing_key() {
        let bytes = parse_meminfo_total("SomethingElse: 1234 kB\n");
        assert_eq!(bytes, 0);
    }

    #[test]
    fn returns_zero_on_empty_meminfo() {
        assert_eq!(parse_meminfo_total(""), 0);
    }

    const DF_OUTPUT: &str = "1M-blocks Avail\n    50000 30000\n";

    #[test]
    fn parses_df_output_total_and_avail() {
        let (total, avail) = parse_df_output(DF_OUTPUT);
        assert_eq!(total, 50_000);
        assert_eq!(avail, 30_000);
    }

    #[test]
    fn parses_df_output_with_m_suffix() {
        let (total, avail) = parse_df_output("Size Avail\n 50000M 30000M\n");
        assert_eq!(total, 50_000);
        assert_eq!(avail, 30_000);
    }

    #[test]
    fn returns_zeros_on_empty_df_output() {
        let (total, avail) = parse_df_output("");
        assert_eq!(total, 0);
        assert_eq!(avail, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_host_total_memory_is_nonzero() {
        let bytes = host_total_memory_bytes();
        assert!(bytes > 0, "expected non-zero total memory on Linux");
        println!("Total memory: {} MB", bytes / (1024 * 1024));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_effective_total_memory_is_nonzero_and_not_above_host() {
        let host = host_total_memory_bytes();
        let effective = effective_total_memory_bytes();
        assert!(effective > 0, "expected non-zero effective memory on Linux");
        assert!(
            effective <= host,
            "effective memory must not exceed host RAM"
        );
    }

    #[test]
    fn cgroup_v2_uses_minimum_of_high_and_max() {
        let cgroup = "0::/user.slice/example.scope\n";
        let result =
            cgroup_constrained_memory(cgroup, |path| match path.to_string_lossy().as_ref() {
                "/sys/fs/cgroup/user.slice/example.scope/memory.high" => 536_870_912,
                "/sys/fs/cgroup/user.slice/example.scope/memory.max" => 1_073_741_824,
                _ => 0,
            });
        assert_eq!(result, Some(536_870_912));
    }

    #[test]
    fn cgroup_v2_treats_max_as_unbounded() {
        assert_eq!(parse_memory_limit("max\n"), u64::MAX);
        let result = cgroup_constrained_memory("0::/demo\n", |path| {
            match path.file_name().and_then(|name| name.to_str()) {
                Some("memory.high") => u64::MAX,
                Some("memory.max") => 536_870_912,
                _ => 0,
            }
        });
        assert_eq!(result, Some(536_870_912));
    }

    #[test]
    fn cgroup_v2_requires_both_limit_files() {
        let result = cgroup_constrained_memory("0::/demo\n", |path| {
            if path.file_name().and_then(|name| name.to_str()) == Some("memory.max") {
                536_870_912
            } else {
                0
            }
        });
        assert_eq!(result, None);
    }

    #[test]
    fn cgroup_v1_uses_memory_controller_soft_and_hard_limits() {
        let cgroup = "5:memory:/docker/abc\n4:cpu:/docker/abc\n";
        let result =
            cgroup_constrained_memory(cgroup, |path| match path.to_string_lossy().as_ref() {
                "/sys/fs/cgroup/memory/docker/abc/memory.soft_limit_in_bytes" => 805_306_368,
                "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes" => 1_073_741_824,
                _ => 0,
            });
        assert_eq!(result, Some(805_306_368));
    }

    #[test]
    fn cgroup_v1_falls_back_to_global_controller_limits() {
        let cgroup = "5:memory:/docker/abc\n";
        let result =
            cgroup_constrained_memory(cgroup, |path| match path.to_string_lossy().as_ref() {
                "/sys/fs/cgroup/memory/docker/abc/memory.soft_limit_in_bytes" => 0,
                "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes" => 1_073_741_824,
                "/sys/fs/cgroup/memory/memory.soft_limit_in_bytes" => 402_653_184,
                "/sys/fs/cgroup/memory/memory.limit_in_bytes" => 536_870_912,
                _ => 0,
            });
        assert_eq!(result, Some(402_653_184));
    }

    #[test]
    fn cgroup_v1_does_not_treat_combined_controller_name_as_memory() {
        let cgroup = "5:memory,cpu:/docker/abc\n";
        let result =
            cgroup_constrained_memory(cgroup, |path| match path.to_string_lossy().as_ref() {
                "/sys/fs/cgroup/memory/memory.soft_limit_in_bytes" => 402_653_184,
                "/sys/fs/cgroup/memory/memory.limit_in_bytes" => 536_870_912,
                _ => 0,
            });
        assert_eq!(result, Some(402_653_184));
    }

    #[test]
    fn invalid_memory_limit_reads_as_zero() {
        assert_eq!(parse_memory_limit("banana\n"), 0);
        assert_eq!(parse_memory_limit("0\n"), 0);
        assert_eq!(parse_memory_limit("536870912\n"), 536_870_912);
    }

    #[test]
    fn detects_v1_hardware_signature() {
        assert!(looks_like_v1_hardware_values(
            4,
            "model name : ARMv7 Processor rev 5 (v7l)\n",
            "globalping-probe-708e",
            520_839_168,
        ));
    }

    #[test]
    fn rejects_partial_v1_signature() {
        assert!(!looks_like_v1_hardware_values(
            4,
            "model name : Some Intel CPU\n",
            "globalping-probe-708e",
            520_839_168,
        ));
        assert!(!looks_like_v1_hardware_values(
            4,
            "model name : ARMv7 Processor rev 5 (v7l)\n",
            "gp-probe",
            520_839_168,
        ));
    }
}
