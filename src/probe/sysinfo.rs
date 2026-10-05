use regex::Regex;

/// Total system RAM in bytes, read from /proc/meminfo on Linux.
#[must_use]
pub fn total_memory_bytes() -> u64 {
    parse_meminfo_total(&std::fs::read_to_string("/proc/meminfo").unwrap_or_default())
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
        total_memory_bytes(),
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
    fn live_total_memory_is_nonzero() {
        let bytes = total_memory_bytes();
        assert!(bytes > 0, "expected non-zero total memory on Linux");
        println!("Total memory: {} MB", bytes / (1024 * 1024));
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
