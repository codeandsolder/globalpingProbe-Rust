use serde_json::{Value, json};

/// Maximum size of the `rawOutput` field in any measurement result or
/// in-progress event sent to the API.  Matches the Node.js probe's
/// `MEASUREMENT_RESPONSE_SIZE_LIMIT`.
pub const MAX_RAW_OUTPUT_BYTES: usize = 10_240;

const TRUNCATION_MARKER: &str = "\n[...truncated]";

/// Truncate `s` to at most `max_bytes` bytes, preserving valid UTF-8.
/// Appends `[...truncated]` on a new line if any bytes were removed.
/// Returns the original string unchanged if it fits within the limit.
#[must_use]
pub fn truncate_output(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    // Walk back to the nearest valid UTF-8 char boundary.
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{}", &s[..cut], TRUNCATION_MARKER)
}

/// Apply `truncate_output(MAX_RAW_OUTPUT_BYTES)` to the `rawOutput` field of
/// a JSON measurement result or progress event in-place.
/// No-ops if the field is absent, null, or within the limit.
pub fn limit_raw_output(result: &mut Value) {
    if let Some(raw) = result.get("rawOutput").and_then(|v| v.as_str())
        && raw.len() > MAX_RAW_OUTPUT_BYTES
    {
        let truncated = truncate_output(raw, MAX_RAW_OUTPUT_BYTES);
        result["rawOutput"] = json!(truncated);
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── truncate_output ───────────────────────────────────────────────────────

    #[test]
    fn short_string_returned_unchanged() {
        let s = "hello";
        assert_eq!(truncate_output(s, 100), "hello");
    }

    #[test]
    fn string_exactly_at_limit_returned_unchanged() {
        let s = "a".repeat(64);
        let out = truncate_output(&s, 64);
        assert_eq!(out, s);
        assert!(!out.contains("[...truncated]"));
    }

    #[test]
    fn string_over_limit_is_truncated_and_marked() {
        let s = "x".repeat(200);
        let out = truncate_output(&s, 100);
        assert!(out.len() < 200, "truncated output should be shorter");
        assert!(out.ends_with("[...truncated]"), "should end with marker");
        assert!(out.starts_with("xxx"), "should keep prefix");
    }

    #[test]
    fn truncated_output_obeys_byte_limit_on_prefix() {
        let s = "a".repeat(1000);
        let out = truncate_output(&s, 50);
        // Prefix (before marker) must be ≤ 50 bytes
        let prefix = out
            .trim_end_matches("[...truncated]")
            .trim_end_matches('\n');
        assert!(prefix.len() <= 50);
    }

    #[test]
    fn truncation_marker_always_present_when_over_limit() {
        for limit in [1, 10, 100, 1024] {
            let s = "z".repeat(limit + 1);
            let out = truncate_output(&s, limit);
            assert!(out.contains("[...truncated]"), "limit={limit}");
        }
    }

    #[test]
    fn no_marker_when_within_limit() {
        for limit in [5, 50, 500] {
            let s = "a".repeat(limit);
            assert!(
                !truncate_output(&s, limit).contains("[...truncated]"),
                "limit={limit}"
            );
        }
    }

    #[test]
    fn empty_string_returned_unchanged() {
        assert_eq!(truncate_output("", 10), "");
    }

    #[test]
    fn zero_limit_gives_only_marker() {
        let out = truncate_output("hello", 0);
        assert_eq!(out, TRUNCATION_MARKER);
    }

    #[test]
    fn valid_utf8_boundary_respected() {
        // "é" is 2 bytes (0xC3 0xA9). Cutting at byte 1 would split it.
        let s = "aé"; // bytes: [0x61, 0xC3, 0xA9]
        // limit=2 would catch the 'a' and first byte of 'é', but
        // truncate_output must not produce invalid UTF-8.
        let out = truncate_output(s, 2);
        assert!(
            std::str::from_utf8(out.as_bytes()).is_ok(),
            "must be valid UTF-8"
        );
    }

    #[test]
    fn multibyte_char_at_boundary_is_not_split() {
        let s = "hello\u{1F600}world"; // emoji = 4 bytes
        // limit places a cut right in the middle of the emoji
        let emoji_start = "hello".len(); // byte 5
        let out = truncate_output(s, emoji_start + 2); // cuts into emoji
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        assert!(!out.contains('\u{1F600}'), "partial emoji must not appear");
    }

    // ── limit_raw_output ──────────────────────────────────────────────────────

    #[test]
    fn limit_raw_output_noop_when_within_limit() {
        let mut v = json!({ "rawOutput": "short", "status": "finished" });
        limit_raw_output(&mut v);
        assert_eq!(v["rawOutput"].as_str().unwrap(), "short");
    }

    #[test]
    fn limit_raw_output_truncates_oversized_field() {
        let big = "x".repeat(MAX_RAW_OUTPUT_BYTES * 2);
        let mut v = json!({ "rawOutput": big.clone(), "status": "finished" });
        limit_raw_output(&mut v);
        let raw = v["rawOutput"].as_str().unwrap();
        assert!(raw.contains("[...truncated]"), "marker must be present");
        // The retained prefix must fit within the limit.
        let prefix_len = raw.find("\n[...truncated]").unwrap_or(raw.len());
        assert!(
            prefix_len <= MAX_RAW_OUTPUT_BYTES,
            "prefix must be within limit"
        );
        assert!(
            raw.len() < big.len(),
            "overall output must be shorter than the 2× input"
        );
    }

    #[test]
    fn limit_raw_output_leaves_other_fields_intact() {
        let big = "y".repeat(MAX_RAW_OUTPUT_BYTES + 100);
        let mut v = json!({ "rawOutput": big, "status": "finished", "hops": [1, 2] });
        limit_raw_output(&mut v);
        assert_eq!(v["status"].as_str().unwrap(), "finished");
        assert_eq!(v["hops"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn limit_raw_output_noop_when_field_absent() {
        let mut v = json!({ "status": "finished" });
        limit_raw_output(&mut v);
        assert!(v.get("rawOutput").is_none());
    }

    #[test]
    fn limit_raw_output_noop_when_null() {
        let mut v = json!({ "rawOutput": null });
        limit_raw_output(&mut v);
        assert!(v["rawOutput"].is_null());
    }

    #[test]
    fn max_raw_output_bytes_constant_is_correct() {
        assert_eq!(MAX_RAW_OUTPUT_BYTES, 10_240);
    }
}
