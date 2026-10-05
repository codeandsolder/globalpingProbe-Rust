/// Integration tests for rawOutput size limiting.
use globalping_probe::util::output_limit::{
    MAX_RAW_OUTPUT_BYTES, limit_raw_output, truncate_output,
};
use serde_json::json;

// ── Constant ──────────────────────────────────────────────────────────────────

#[test]
fn max_raw_output_bytes_is_ten_kib() {
    assert_eq!(MAX_RAW_OUTPUT_BYTES, 10_240);
}

// ── truncate_output ───────────────────────────────────────────────────────────

#[test]
fn short_output_unchanged() {
    let s = "PING 1.1.1.1: 56 data bytes\n64 bytes from 1.1.1.1: seq=0 ttl=58 time=10 ms";
    assert_eq!(truncate_output(s, MAX_RAW_OUTPUT_BYTES), s);
}

#[test]
fn output_exactly_at_limit_unchanged() {
    let s = "a".repeat(MAX_RAW_OUTPUT_BYTES);
    let out = truncate_output(&s, MAX_RAW_OUTPUT_BYTES);
    assert_eq!(out.len(), MAX_RAW_OUTPUT_BYTES);
    assert!(!out.contains("[...truncated]"));
}

#[test]
fn output_one_byte_over_limit_gets_truncated() {
    let s = "b".repeat(MAX_RAW_OUTPUT_BYTES + 1);
    let out = truncate_output(&s, MAX_RAW_OUTPUT_BYTES);
    assert!(out.contains("[...truncated]"), "marker must appear");
    assert!(out.len() <= MAX_RAW_OUTPUT_BYTES + "[...truncated]".len() + 1);
}

#[test]
fn truncated_output_is_valid_utf8() {
    // Build a string where a 4-byte emoji straddles the cut point.
    // Pad to MAX_RAW_OUTPUT_BYTES - 2 with ASCII, then append the emoji.
    let pad = "a".repeat(MAX_RAW_OUTPUT_BYTES - 2);
    let emoji = "\u{1F4E1}"; // 4 bytes — antenna emoji
    let s = format!("{pad}{emoji}");
    // The cut at MAX_RAW_OUTPUT_BYTES falls inside the emoji; truncate_output
    // must walk back to a valid boundary and not produce invalid UTF-8.
    let out = truncate_output(&s, MAX_RAW_OUTPUT_BYTES);
    assert!(
        std::str::from_utf8(out.as_bytes()).is_ok(),
        "output must be valid UTF-8"
    );
    assert!(out.contains("[...truncated]"));
}

#[test]
fn large_output_prefix_preserved() {
    let s = format!("HEADER\n{}\nFOOTER", "x".repeat(50_000));
    let out = truncate_output(&s, MAX_RAW_OUTPUT_BYTES);
    assert!(out.starts_with("HEADER"), "prefix must be preserved");
    assert!(out.contains("[...truncated]"));
}

#[test]
fn empty_input_returned_unchanged() {
    assert_eq!(truncate_output("", MAX_RAW_OUTPUT_BYTES), "");
}

// ── limit_raw_output — ping-shaped result ────────────────────────────────────

#[test]
fn ping_result_within_limit_unchanged() {
    let raw = "PING 1.1.1.1\n64 bytes from 1.1.1.1: time=5ms".to_string();
    let mut v = json!({
        "status": "finished",
        "rawOutput": raw,
        "timings": [{"rtt": 5.0}],
    });
    limit_raw_output(&mut v);
    assert_eq!(v["status"], "finished");
    assert!(!v["rawOutput"].as_str().unwrap().contains("[...truncated]"));
}

#[test]
fn oversized_ping_result_is_capped() {
    let big_raw = format!(
        "PING 1.1.1.1\n{}",
        "64 bytes from 1.1.1.1: seq=0 ttl=58 time=5ms\n".repeat(500)
    );
    let mut v = json!({ "status": "finished", "rawOutput": big_raw });
    limit_raw_output(&mut v);
    let raw = v["rawOutput"].as_str().unwrap();
    assert!(
        raw.contains("[...truncated]"),
        "large ping rawOutput should be capped"
    );
    assert!(raw.len() <= MAX_RAW_OUTPUT_BYTES + "[...truncated]\n".len());
}

// ── limit_raw_output — traceroute-shaped result ───────────────────────────────

#[test]
fn oversized_traceroute_result_is_capped() {
    let big_raw = format!(
        "traceroute to 1.1.1.1\n{}",
        " 1  192.168.1.1  1.23 ms  1.45 ms  1.67 ms\n".repeat(500)
    );
    let mut v = json!({
        "status": "finished",
        "rawOutput": big_raw,
        "hops": [],
    });
    limit_raw_output(&mut v);
    let raw = v["rawOutput"].as_str().unwrap();
    assert!(raw.contains("[...truncated]"));
    assert_eq!(
        v["hops"].as_array().unwrap().len(),
        0,
        "other fields unchanged"
    );
}

// ── limit_raw_output — progress event ────────────────────────────────────────

#[test]
fn in_progress_event_rawoutput_capped() {
    let big_raw = "x".repeat(MAX_RAW_OUTPUT_BYTES * 2);
    let mut partial = json!({
        "status": "in-progress",
        "rawOutput": big_raw,
        "timings": [{"rtt": 10.0}],
    });
    limit_raw_output(&mut partial);
    assert!(
        partial["rawOutput"]
            .as_str()
            .unwrap()
            .contains("[...truncated]")
    );
    assert_eq!(
        partial["status"], "in-progress",
        "status field must survive"
    );
    assert_eq!(partial["timings"][0]["rtt"], 10.0, "timings must survive");
}

// ── limit_raw_output — edge cases ────────────────────────────────────────────

#[test]
fn missing_rawoutput_field_is_noop() {
    let mut v = json!({ "status": "finished", "timings": [] });
    limit_raw_output(&mut v);
    assert!(v.get("rawOutput").is_none());
    assert_eq!(v["status"], "finished");
}

#[test]
fn null_rawoutput_field_is_noop() {
    let mut v = json!({ "rawOutput": null, "status": "finished" });
    limit_raw_output(&mut v);
    assert!(v["rawOutput"].is_null());
}

#[test]
fn failed_result_error_message_capped_if_huge() {
    let giant_error = "e".repeat(MAX_RAW_OUTPUT_BYTES + 5000);
    let mut v = json!({ "status": "failed", "rawOutput": giant_error });
    limit_raw_output(&mut v);
    let raw = v["rawOutput"].as_str().unwrap();
    assert!(raw.contains("[...truncated]"));
    assert_eq!(v["status"], "failed");
}

// ── end-to-end: simulated dispatch pipeline ───────────────────────────────────

#[test]
fn dispatch_pipeline_caps_result_before_emit() {
    // Simulate what dispatch does: get result, limit it, then "emit".
    let big = "output line\n".repeat(2000); // ~24 KiB
    let mut result = json!({ "status": "finished", "rawOutput": big });

    // This is the line added to dispatch:
    limit_raw_output(&mut result);

    let final_raw = result["rawOutput"].as_str().unwrap();
    assert!(final_raw.len() < big.len(), "should have been truncated");
    assert!(final_raw.contains("[...truncated]"));
    assert_eq!(result["status"], "finished", "status preserved");
}

#[test]
fn dispatch_pipeline_passes_small_result_through() {
    let small = "PING ok\n64 bytes: time=5ms";
    let mut result = json!({ "status": "finished", "rawOutput": small });
    limit_raw_output(&mut result);
    assert_eq!(result["rawOutput"].as_str().unwrap(), small);
}
