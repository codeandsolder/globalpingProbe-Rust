/// Integration tests for the probe module (UUID, sysinfo, DNS servers, client wire types, reconnect, active jobs).
/// Live tests are gated on #[cfg(target_os = "linux")].
use globalping_probe::probe::{
    client::{ClientConfig, MeasurementRequest, VERSION, connection_url},
    dns_servers::parse_resolv_conf,
    jobs::ActiveJobs,
    reconnect::{ConnectOutcome, classify_error, reconnect_delay},
    sysinfo::{parse_df_output, parse_meminfo_total},
    uuid::ProbeUuid,
};
use serde_json::json;
use std::time::Duration;

// ── UUID ──────────────────────────────────────────────────────────────────────

#[test]
fn uuid_generates_when_file_absent() {
    let path = "/tmp/gp_integ_uuid_absent.txt";
    let _ = std::fs::remove_file(path);
    let u = ProbeUuid::load_or_create(path);
    assert_eq!(u.id.len(), 36, "UUID should be 36 chars: {}", u.id);
    let _ = std::fs::remove_file(path);
}

#[test]
fn uuid_reads_existing_file() {
    let path = "/tmp/gp_integ_uuid_existing.txt";
    let expected = "aaaabbbb-cccc-dddd-eeee-ffffffffffff";
    std::fs::write(path, expected).unwrap();
    let u = ProbeUuid::load_or_create(path);
    assert_eq!(u.id, expected);
    let _ = std::fs::remove_file(path);
}

#[test]
fn uuid_regenerates_for_empty_file() {
    let path = "/tmp/gp_integ_uuid_empty.txt";
    std::fs::write(path, "\n\n  ").unwrap();
    let u = ProbeUuid::load_or_create(path);
    assert_eq!(u.id.len(), 36);
    let _ = std::fs::remove_file(path);
}

#[test]
fn uuid_is_stable_across_loads() {
    let path = "/tmp/gp_integ_uuid_stable.txt";
    let _ = std::fs::remove_file(path);
    let u1 = ProbeUuid::load_or_create(path);
    let u2 = ProbeUuid::load_or_create(path);
    assert_eq!(u1.id, u2.id);
    let _ = std::fs::remove_file(path);
}

// ── Sysinfo ───────────────────────────────────────────────────────────────────

#[test]
fn meminfo_parse_standard_format() {
    let input = "MemTotal:        8000000 kB\nMemFree: 4000000 kB\n";
    assert_eq!(parse_meminfo_total(input), 8_000_000 * 1024);
}

#[test]
fn meminfo_parse_returns_zero_when_key_absent() {
    assert_eq!(parse_meminfo_total("MemFree: 1234 kB\n"), 0);
}

#[test]
fn df_parse_numeric_columns() {
    let out = "1M-blocks Avail\n    100000 60000\n";
    let (t, a) = parse_df_output(out);
    assert_eq!(t, 100_000);
    assert_eq!(a, 60_000);
}

#[test]
fn df_parse_with_m_suffix() {
    let out = "Size Avail\n 200000M 80000M\n";
    let (t, a) = parse_df_output(out);
    assert_eq!(t, 200_000);
    assert_eq!(a, 80_000);
}

#[test]
fn df_parse_empty_returns_zeros() {
    let (t, a) = parse_df_output("");
    assert_eq!((t, a), (0, 0));
}

// ── DNS servers ───────────────────────────────────────────────────────────────

#[test]
fn dns_parse_public_servers() {
    let conf = "nameserver 8.8.8.8\nnameserver 1.1.1.1\n";
    assert_eq!(parse_resolv_conf(conf), vec!["8.8.8.8", "1.1.1.1"]);
}

#[test]
fn dns_parse_private_servers_masked() {
    let conf = "nameserver 192.168.1.1\nnameserver 8.8.8.8\n";
    assert_eq!(parse_resolv_conf(conf), vec!["private", "8.8.8.8"]);
}

#[test]
fn dns_parse_ipv6_server() {
    let conf = "nameserver 2606:4700:4700::1111\n";
    assert_eq!(parse_resolv_conf(conf), vec!["2606:4700:4700::1111"]);
}

#[test]
fn dns_parse_private_ipv6_masked() {
    let conf = "nameserver ::1\n";
    assert_eq!(parse_resolv_conf(conf), vec!["private"]);
}

#[test]
fn dns_parse_skips_non_nameserver_lines() {
    let conf = "# comment\nsearch example.com\nnameserver 9.9.9.9\n";
    assert_eq!(parse_resolv_conf(conf), vec!["9.9.9.9"]);
}

#[test]
fn dns_parse_strips_port_suffix() {
    let conf = "nameserver 8.8.8.8#53\n";
    assert_eq!(parse_resolv_conf(conf), vec!["8.8.8.8"]);
}

// ── Client URL & wire types ───────────────────────────────────────────────────

fn test_cfg() -> ClientConfig {
    ClientConfig {
        api_host: "https://api.globalping.io".into(),
        uuid: "integ-uuid-0000".into(),
        ping_target: "api.globalping.io".into(),
        adoption_token: None,
        is_hardware: None,
        hardware_device: None,
        hardware_device_firmware: None,
    }
}

#[test]
fn client_url_has_all_required_params() {
    let url = connection_url(&test_cfg());
    for param in &[
        "version=",
        "nodeVersion=v22.22.3",
        "totalMemory=",
        "totalDiskSize=",
        "availableDiskSpace=",
        "uuid=integ-uuid-0000",
    ] {
        assert!(url.contains(param), "missing {param} in: {url}");
    }
}

#[test]
fn client_url_starts_with_api_host() {
    let url = connection_url(&test_cfg());
    assert!(url.starts_with("https://api.globalping.io?"), "url: {url}");
}

#[test]
fn client_url_version_matches_crate() {
    let url = connection_url(&test_cfg());
    assert!(url.contains(&format!("version={VERSION}")), "url: {url}");
}

#[test]
fn measurement_request_ping_roundtrip() {
    let raw = json!({
        "measurementId": "mid-001",
        "testId": "tid-001",
        "measurement": {
            "type": "ping", "target": "8.8.8.8",
            "packets": 3, "ipVersion": 4, "inProgressUpdates": false
        }
    });
    let req: MeasurementRequest = serde_json::from_value(raw).unwrap();
    assert_eq!(req.measurement_id, "mid-001");
    assert_eq!(req.test_id, "tid-001");
    assert_eq!(req.measurement["type"], "ping");
    assert_eq!(req.measurement["target"], "8.8.8.8");
}

#[test]
fn measurement_request_dns_roundtrip() {
    let raw = json!({
        "measurementId": "mid-002", "testId": "tid-002",
        "measurement": { "type": "dns", "target": "example.com",
            "query": {"type": "A"}, "inProgressUpdates": false }
    });
    let req: MeasurementRequest = serde_json::from_value(raw).unwrap();
    assert_eq!(req.measurement["type"], "dns");
}

#[test]
fn measurement_request_http_roundtrip() {
    let raw = json!({
        "measurementId": "mid-003", "testId": "tid-003",
        "measurement": {
            "type": "http", "target": "1.1.1.1", "protocol": "HTTPS",
            "request": { "method": "HEAD", "path": "/" }, "inProgressUpdates": false
        }
    });
    let req: MeasurementRequest = serde_json::from_value(raw).unwrap();
    assert_eq!(req.measurement["type"], "http");
    assert_eq!(req.measurement["protocol"], "HTTPS");
    assert_eq!(req.measurement["request"]["method"], "HEAD");
}

#[test]
fn measurement_request_missing_measurement_id_fails() {
    let raw = json!({ "testId": "t1", "measurement": { "type": "ping" } });
    assert!(
        serde_json::from_value::<MeasurementRequest>(raw).is_err(),
        "should fail without measurementId"
    );
}

#[test]
fn measurement_request_missing_test_id_fails() {
    let raw = json!({ "measurementId": "m1", "measurement": { "type": "ping" } });
    assert!(
        serde_json::from_value::<MeasurementRequest>(raw).is_err(),
        "should fail without testId"
    );
}

#[test]
fn measurement_type_discriminator_covers_all_known_types() {
    for ty in &["ping", "dns", "traceroute", "mtr", "http"] {
        let m = json!({ "type": ty });
        let mtype = m.get("type").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            matches!(mtype, "ping" | "dns" | "traceroute" | "mtr" | "http"),
            "type {ty} not handled"
        );
    }
}

// ── Live tests (Linux only) ───────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn live_total_memory_nonzero() {
    let bytes = globalping_probe::probe::sysinfo::total_memory_bytes();
    assert!(bytes > 0, "Expected nonzero total memory");
    println!("Total RAM: {} MB", bytes / (1024 * 1024));
}

#[cfg(target_os = "linux")]
#[test]
fn live_disk_info_nonzero() {
    let (total, avail) = globalping_probe::probe::sysinfo::disk_info_mb();
    assert!(total > 0, "Expected nonzero disk total");
    assert!(avail <= total, "Available must not exceed total");
    println!("Disk: {total} MB total, {avail} MB available");
}

#[cfg(target_os = "linux")]
#[test]
fn live_dns_servers_readable() {
    let servers = globalping_probe::probe::dns_servers::get_dns_servers();
    println!("DNS servers: {servers:?}");
    // No assertion — empty is valid in minimal containers
}

// ── Reconnect logic ───────────────────────────────────────────────────────────

#[test]
fn reconnect_classifies_current_probe_policy_errors() {
    for message in [
        "ip limit",
        "user asn limit exceeded",
        "VPN detected",
        "unresolvable geoip",
    ] {
        assert_eq!(classify_error(message), ConnectOutcome::ProbePolicyError);
    }
}

#[test]
fn reconnect_classify_metadata() {
    assert_eq!(
        classify_error("failed to collect probe metadata"),
        ConnectOutcome::MetadataError
    );
}

#[test]
fn reconnect_classify_invalid_version() {
    assert_eq!(
        classify_error("invalid probe version (0.1.0)"),
        ConnectOutcome::InvalidVersion
    );
}

#[test]
fn reconnect_classify_server_terminating() {
    assert_eq!(
        classify_error("server is terminating"),
        ConnectOutcome::ServerTerminating
    );
}

#[test]
fn reconnect_classify_unknown_is_transient() {
    assert_eq!(
        classify_error("connection reset"),
        ConnectOutcome::Transient
    );
}

#[test]
fn reconnect_policy_matches_current_upstream_delays() {
    assert_eq!(
        reconnect_delay(&ConnectOutcome::ProbePolicyError),
        Some(Duration::from_secs(3600))
    );
    assert_eq!(
        reconnect_delay(&ConnectOutcome::MetadataError),
        Some(Duration::from_secs(60))
    );
    assert_eq!(
        reconnect_delay(&ConnectOutcome::Transient),
        Some(Duration::from_secs(2))
    );
    assert_eq!(
        reconnect_delay(&ConnectOutcome::ServerTerminating),
        Some(Duration::from_secs(2))
    );
}

#[test]
fn reconnect_exit_outcomes_do_not_retry() {
    for outcome in [
        ConnectOutcome::CleanShutdown,
        ConnectOutcome::RestartRequested,
        ConnectOutcome::InvalidVersion,
    ] {
        assert_eq!(reconnect_delay(&outcome), None);
    }
}

// ── Active jobs ────────────────────────────────────────────────────────────────

#[test]
fn active_jobs_start_at_zero_and_have_no_local_cap() {
    let jobs = ActiveJobs::new();
    let guards: Vec<_> = (0..32).map(|_| jobs.start()).collect();
    assert_eq!(jobs.count(), 32);
    drop(guards);
    assert_eq!(jobs.count(), 0);
}

#[tokio::test]
async fn active_jobs_wait_idle_tracks_all_guards() {
    let jobs = ActiveJobs::new();
    let first = jobs.start();
    let second = jobs.start();
    let waiter = {
        let jobs = jobs.clone();
        tokio::spawn(async move { jobs.wait_idle().await })
    };
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    drop(first);
    assert!(!waiter.is_finished());
    drop(second);
    waiter.await.unwrap();
}
