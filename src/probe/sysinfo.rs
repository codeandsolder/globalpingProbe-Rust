use regex::Regex;
use std::path::{Path, PathBuf};

/// Total physical system RAM in bytes, read from `/proc/meminfo` on Linux.
#[must_use]
pub fn host_total_memory_bytes() -> u64 {
    parse_meminfo_total(&std::fs::read_to_string("/proc/meminfo").unwrap_or_default())
}

/// Memory effectively available to this process. This matches upstream's
/// `Math.min(process.constrainedMemory() || Infinity, os.totalmem())` semantics.
#[must_use]
pub fn effective_total_memory_bytes() -> u64 {
    let host_total = host_total_memory_bytes();
    constrained_memory_bytes().map_or(host_total, |limit| host_total.min(limit))
}

fn constrained_memory_bytes() -> Option<u64> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap_or_default();

    [
        cgroup_memory_limit_bytes(&cgroup, &mountinfo),
        parse_rlimit_memory_bytes(&limits),
    ]
    .into_iter()
    .flatten()
    .filter(|limit| *limit > 0)
    .min()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CgroupMemoryLocation {
    mount_point: PathBuf,
    current: PathBuf,
    limit_file: &'static str,
}

fn parse_cgroup_memory_location(cgroup: &str, mountinfo: &str) -> Option<CgroupMemoryLocation> {
    let unified_path = cgroup.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        (hierarchy == "0" && controllers.is_empty()).then_some(path)
    });

    if let Some(path) = unified_path {
        let (mount_root, mount_point) = find_cgroup_mount(mountinfo, "cgroup2", None)?;
        return map_cgroup_path(&mount_root, &mount_point, path).map(|current| {
            CgroupMemoryLocation {
                mount_point,
                current,
                limit_file: "memory.max",
            }
        });
    }

    let legacy_path = cgroup.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        controllers
            .split(',')
            .any(|controller| controller == "memory")
            .then_some(path)
    })?;
    let (mount_root, mount_point) = find_cgroup_mount(mountinfo, "cgroup", Some("memory"))?;
    map_cgroup_path(&mount_root, &mount_point, legacy_path).map(|current| CgroupMemoryLocation {
        mount_point,
        current,
        limit_file: "memory.limit_in_bytes",
    })
}

fn find_cgroup_mount(
    mountinfo: &str,
    fs_type: &str,
    required_option: Option<&str>,
) -> Option<(PathBuf, PathBuf)> {
    mountinfo.lines().find_map(|line| {
        let (left, right) = line.split_once(" - ")?;
        let left_fields = left.split_whitespace().collect::<Vec<_>>();
        if left_fields.len() < 5 {
            return None;
        }
        let mut right_fields = right.split_whitespace();
        let found_fs_type = right_fields.next()?;
        let _source = right_fields.next()?;
        let super_options = right_fields.next().unwrap_or_default();
        if found_fs_type != fs_type
            || required_option
                .is_some_and(|required| !super_options.split(',').any(|option| option == required))
        {
            return None;
        }
        Some((PathBuf::from(left_fields[3]), PathBuf::from(left_fields[4])))
    })
}

fn map_cgroup_path(mount_root: &Path, mount_point: &Path, cgroup_path: &str) -> Option<PathBuf> {
    let cgroup_path = Path::new(cgroup_path);
    let relative = cgroup_path
        .strip_prefix(mount_root)
        .or_else(|_| cgroup_path.strip_prefix("/"))
        .ok()?;
    Some(mount_point.join(relative))
}

fn cgroup_memory_limit_bytes(cgroup: &str, mountinfo: &str) -> Option<u64> {
    let location = parse_cgroup_memory_location(cgroup, mountinfo)?;
    hierarchical_memory_limit(
        &location.current,
        &location.mount_point,
        location.limit_file,
    )
}

fn hierarchical_memory_limit(current: &Path, mount_point: &Path, limit_file: &str) -> Option<u64> {
    let mut path = current.to_path_buf();
    let mut minimum = None;
    loop {
        if let Ok(value) = std::fs::read_to_string(path.join(limit_file))
            && let Some(limit) = parse_memory_limit(&value)
        {
            minimum = Some(minimum.map_or(limit, |existing: u64| existing.min(limit)));
        }
        if path == mount_point || !path.pop() {
            break;
        }
        if !path.starts_with(mount_point) {
            break;
        }
    }
    minimum
}

fn parse_memory_limit(value: &str) -> Option<u64> {
    let value = value.trim();
    if value == "max" || value == "-1" {
        None
    } else {
        value.parse::<u64>().ok().filter(|value| *value > 0)
    }
}

fn parse_rlimit_memory_bytes(content: &str) -> Option<u64> {
    ["Max data size", "Max address space"]
        .into_iter()
        .filter_map(|label| {
            let line = content.lines().find(|line| line.starts_with(label))?;
            let value = line[label.len()..].split_whitespace().next()?;
            if value == "unlimited" {
                None
            } else {
                value.parse::<u64>().ok().filter(|value| *value > 0)
            }
        })
        .min()
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
    fn parses_v2_cgroup_location() {
        let location = parse_cgroup_memory_location(
            "0::/user.slice/example.scope\n",
            "35 27 0:31 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
        )
        .expect("v2 cgroup location");
        assert_eq!(location.mount_point, Path::new("/sys/fs/cgroup"));
        assert_eq!(
            location.current,
            Path::new("/sys/fs/cgroup/user.slice/example.scope")
        );
        assert_eq!(location.limit_file, "memory.max");
    }

    #[test]
    fn parses_namespaced_v2_cgroup_location() {
        let location = parse_cgroup_memory_location(
            "0::/\n",
            "35 27 0:31 /docker/abc /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
        )
        .expect("namespaced v2 cgroup location");
        assert_eq!(location.current, Path::new("/sys/fs/cgroup"));
    }

    #[test]
    fn parses_v1_memory_cgroup_location() {
        let location = parse_cgroup_memory_location(
            "5:memory,cpu:/docker/abc\n",
            "29 23 0:26 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
        )
        .expect("v1 memory cgroup location");
        assert_eq!(
            location.current,
            Path::new("/sys/fs/cgroup/memory/docker/abc")
        );
        assert_eq!(location.limit_file, "memory.limit_in_bytes");
    }

    #[test]
    fn parses_memory_limit_values() {
        assert_eq!(parse_memory_limit("536870912\n"), Some(536_870_912));
        assert_eq!(parse_memory_limit("max\n"), None);
        assert_eq!(parse_memory_limit("-1\n"), None);
        assert_eq!(parse_memory_limit("0\n"), None);
    }

    #[test]
    fn parses_rlimit_memory_minimum() {
        let limits = "\
Limit                     Soft Limit           Hard Limit           Units\n\
Max data size             1073741824           unlimited            bytes\n\
Max address space         2147483648           unlimited            bytes\n";
        assert_eq!(parse_rlimit_memory_bytes(limits), Some(1_073_741_824));
    }

    #[test]
    fn ignores_unlimited_rlimits() {
        let limits = "\
Limit                     Soft Limit           Hard Limit           Units\n\
Max data size             unlimited            unlimited            bytes\n\
Max address space         unlimited            unlimited            bytes\n";
        assert_eq!(parse_rlimit_memory_bytes(limits), None);
    }

    #[test]
    fn hierarchy_uses_tightest_memory_limit() {
        let root = tempfile::tempdir().expect("temp cgroup root");
        let group = root.path().join("a/b");
        std::fs::create_dir_all(&group).expect("create cgroup hierarchy");
        std::fs::write(root.path().join("memory.max"), "max\n").expect("root limit");
        std::fs::write(root.path().join("a/memory.max"), "1073741824\n").expect("parent limit");
        std::fs::write(group.join("memory.max"), "2147483648\n").expect("child limit");
        assert_eq!(
            hierarchical_memory_limit(&group, root.path(), "memory.max"),
            Some(1_073_741_824)
        );
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
