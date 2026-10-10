use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub const HEADERS_SIZE_LIMIT: usize = 10_000;
pub const BODY_SIZE_LIMIT: usize = 10_000;
const TRUNCATION_MARK: &str = "...[truncated]";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpStatus {
    Finished,
    Failed,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpTimings {
    pub total: Option<u64>,
    pub dns: Option<u64>,
    pub tcp: Option<u64>,
    pub tls: Option<u64>,
    pub first_byte: Option<u64>,
    pub download: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsSubject {
    #[serde(rename = "CN", skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(rename = "alt", skip_serializing_if = "Option::is_none")]
    pub alt: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsIssuer {
    #[serde(rename = "CN", skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(rename = "O", skip_serializing_if = "Option::is_none")]
    pub o: Option<String>,
    #[serde(rename = "C", skip_serializing_if = "Option::is_none")]
    pub c: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInfo {
    pub authorized: bool,
    pub protocol: Option<String>,
    pub cipher_name: Option<String>,
    pub created_at: Option<String>,
    pub expires_at: Option<String>,
    pub subject: TlsSubject,
    pub issuer: TlsIssuer,
    pub key_type: Option<String>,
    pub key_bits: Option<u32>,
    pub serial_number: Option<String>,
    pub fingerprint256: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedHttp {
    pub status: HttpStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_source: Option<String>,
    pub status_code: Option<u16>,
    pub status_code_name: Option<String>,
    pub resolved_address: Option<String>,
    #[serde(skip)]
    pub http_version: Option<String>,
    /// Lowercased header name → string or `Vec<String>` if duplicate
    pub headers: BTreeMap<String, serde_json::Value>,
    pub raw_headers: Option<String>,
    pub raw_body: Option<String>,
    pub truncated: bool,
    pub tls: Option<TlsInfo>,
    pub timings: HttpTimings,
    pub raw_output: Option<String>,
}

// ── Header parsing ────────────────────────────────────────────────────────

/// Parse the `-D` dump-header file content into (name, value) pairs.
/// Skips the first line (HTTP status line) and empty lines.
#[must_use]
pub fn parse_header_file(raw: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim_end_matches('\r').trim();
        if i == 0 || line.is_empty() {
            continue; // skip status line and blank lines
        }
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_string();
            let value = line[colon + 1..].trim().to_string();
            pairs.push((name, value));
        }
    }
    pairs
}

/// Extract HTTP status text from the dump-header first line.
/// e.g. "HTTP/1.1 200 OK" → Some("OK")
#[must_use]
pub fn parse_status_text(raw: &str) -> Option<String> {
    let first = raw.lines().next()?.trim_end_matches('\r');
    let parts: Vec<&str> = first.splitn(3, ' ').collect();
    if parts.len() >= 3 {
        Some(parts[2].trim().to_string())
    } else {
        None
    }
}

// ── Header truncation (port of handlers/http/truncate-headers.ts) ─────────

pub struct TruncateResult {
    pub truncated: bool,
    pub headers: Vec<(String, String)>,
}

const fn pair_size(k: &str, v: &str) -> usize {
    k.len() + v.len() + 3 // ": " + "\n"
}
fn pair_min_size(k: &str, v: &str) -> usize {
    k.len() + v.len().min(TRUNCATION_MARK.len()) + 3
}

#[must_use]
pub fn truncate_headers(pairs: Vec<(String, String)>) -> TruncateResult {
    if pairs.is_empty() {
        return TruncateResult {
            truncated: false,
            headers: pairs,
        };
    }
    let size: usize = pairs
        .iter()
        .map(|(k, v)| pair_size(k, v))
        .sum::<usize>()
        .saturating_sub(1);
    let min_size: usize = pairs
        .iter()
        .map(|(k, v)| pair_min_size(k, v))
        .sum::<usize>()
        .saturating_sub(1);

    if size <= HEADERS_SIZE_LIMIT {
        return TruncateResult {
            truncated: false,
            headers: pairs,
        };
    }

    let mut kept = pairs;
    let mut current_size = size;
    let mut current_min = min_size;

    // Drop headers phase: remove largest (by min size) until we can fit with truncation
    if current_min > HEADERS_SIZE_LIMIT {
        let mut indexed: Vec<(usize, usize)> = kept
            .iter()
            .enumerate()
            .map(|(i, (k, v))| (i, pair_min_size(k, v)))
            .collect();
        indexed.sort_unstable_by_key(|entry| core::cmp::Reverse(entry.1));

        let mut dropped = BTreeSet::new();
        for (i, min) in &indexed {
            if current_min <= HEADERS_SIZE_LIMIT {
                break;
            }
            let (k, v) = &kept[*i];
            current_size -= pair_size(k, v);
            current_min -= min;
            dropped.insert(*i);
        }
        kept = kept
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !dropped.contains(i))
            .map(|(_, p)| p)
            .collect();
    }

    if current_size <= HEADERS_SIZE_LIMIT {
        return TruncateResult {
            truncated: true,
            headers: kept,
        };
    }

    // Shrink values phase: find uniform cap L
    let mut sorted_lengths: Vec<usize> = kept.iter().map(|(_, v)| v.len()).collect();
    sorted_lengths.sort_unstable_by(|a, b| b.cmp(a));
    let values_size: usize = sorted_lengths.iter().sum();
    let value_budget = HEADERS_SIZE_LIMIT + values_size - current_size;
    let mut total = values_size;
    let mut cap = 0usize;

    for n in 1..=sorted_lengths.len() {
        let len = sorted_lengths[n - 1];
        let next_len = if n < sorted_lengths.len() {
            sorted_lengths[n]
        } else {
            0
        };
        let reduction = n * (len - next_len);
        if total.saturating_sub(reduction) <= value_budget {
            let diff = total.saturating_sub(value_budget);
            cap = len.saturating_sub(diff.div_ceil(n)); // ceiling division keeps total ≤ budget
            break;
        }
        total = total.saturating_sub(reduction);
    }

    cap = cap.max(TRUNCATION_MARK.len());

    let headers = kept
        .into_iter()
        .map(|(k, v)| {
            if v.len() > cap {
                let truncated_v = format!("{}{TRUNCATION_MARK}", &v[..cap - TRUNCATION_MARK.len()]);
                (k, truncated_v)
            } else {
                (k, v)
            }
        })
        .collect();

    TruncateResult {
        truncated: true,
        headers,
    }
}

/// Collapse header pairs into the deduplicated map (lowercased keys, single or Vec values)
#[must_use]
pub fn dedup_headers(pairs: &[(String, String)]) -> BTreeMap<String, serde_json::Value> {
    let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (k, v) in pairs {
        let lk = k.to_lowercase();
        match map.get_mut(&lk) {
            Some(serde_json::Value::Array(arr)) => {
                arr.push(serde_json::Value::String(v.clone()));
            }
            Some(existing @ serde_json::Value::String(_)) => {
                let prev = existing.clone();
                *existing =
                    serde_json::Value::Array(vec![prev, serde_json::Value::String(v.clone())]);
            }
            _ => {
                map.insert(lk, serde_json::Value::String(v.clone()));
            }
        }
    }
    map
}

// ── TLS verbose parsing ───────────────────────────────────────────────────

/// Parse curl -v stderr output for TLS connection details.
/// Returns None if no TLS info found (plain HTTP).
#[must_use]
pub fn parse_tls_verbose(verbose: &str, ssl_verify_result: u32) -> Option<TlsInfo> {
    let mut protocol: Option<String> = None;
    let mut cipher_name: Option<String> = None;
    let mut created_at: Option<String> = None;
    let mut expires_at: Option<String> = None;
    let mut subject = TlsSubject::default();
    let mut issuer = TlsIssuer::default();
    let mut found_tls = false;

    for line in verbose.lines() {
        let line = line.trim();
        if !line.starts_with("* ") && !line.starts_with("*  ") {
            continue;
        }
        let content = line.trim_start_matches('*').trim();

        // SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
        if let Some(rest) = content.strip_prefix("SSL connection using ") {
            found_tls = true;
            let parts: Vec<&str> = rest.splitn(3, " / ").collect();
            protocol = Some(parts[0].trim().to_string());
            if parts.len() >= 2 {
                cipher_name = Some(parts[1].trim().to_string());
            }
        }
        // start date: Nov  5 00:00:00 2024 GMT
        else if let Some(rest) = content.strip_prefix("start date: ") {
            created_at = parse_curl_date(rest.trim());
        }
        // expire date: Nov  4 23:59:59 2025 GMT
        else if let Some(rest) = content.strip_prefix("expire date: ") {
            expires_at = parse_curl_date(rest.trim());
        }
        // subject: CN=cloudflare.com
        else if let Some(rest) = content.strip_prefix("subject: ") {
            for part in rest.split(';') {
                let part = part.trim();
                if let Some(cn) = part.strip_prefix("CN=") {
                    subject.cn = Some(cn.trim().to_string());
                }
            }
        }
        // issuer: C=US; O=DigiCert Inc; CN=DigiCert TLS RSA SHA256 2020 CA1
        else if let Some(rest) = content.strip_prefix("issuer: ") {
            for part in rest.split(';') {
                let part = part.trim();
                if let Some(cn) = part.strip_prefix("CN=") {
                    issuer.cn = Some(cn.trim().to_string());
                } else if let Some(o) = part.strip_prefix("O=") {
                    issuer.o = Some(o.trim().to_string());
                } else if let Some(c) = part.strip_prefix("C=") {
                    issuer.c = Some(c.trim().to_string());
                }
            }
        }
        // subjectAltName: host "example.com" matched cert's "example.com"
        // subjectAltName: IP address "1.1.1.1"
        else if let Some(rest) = content.strip_prefix("subjectAltName: ") {
            subject.alt = Some(rest.trim().to_string());
        }
    }

    if !found_tls {
        return None;
    }

    Some(TlsInfo {
        authorized: ssl_verify_result == 0,
        protocol,
        cipher_name,
        created_at,
        expires_at,
        subject,
        issuer,
        key_type: None,
        key_bits: None,
        serial_number: None,
        fingerprint256: None,
        public_key: None,
    })
}

/// Parse curl's date format: "Nov  5 00:00:00 2024 GMT" → ISO 8601.
fn parse_curl_date(s: &str) -> Option<String> {
    let parts = s.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 4 {
        return None;
    }
    let month = match parts[0] {
        "Jan" => 1_u8,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day = parts[1].parse::<u8>().ok()?;
    let year = parts[3].parse::<u16>().ok()?;
    let mut time = parts[2].split(':');
    let hour = time.next()?.parse::<u8>().ok()?;
    let minute = time.next()?.parse::<u8>().ok()?;
    let second = time.next()?.parse::<u8>().ok()?;
    if time.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > max_day {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000Z"
    ))
}

// ── rawOutput builder ─────────────────────────────────────────────────────

#[must_use]
pub fn build_raw_output(
    http_version: Option<&str>,
    status_code: Option<u16>,
    raw_headers: Option<&str>,
    raw_body: Option<&str>,
    method: &str,
) -> Option<String> {
    let version = http_version?;
    let code = status_code?;
    let headers = raw_headers.unwrap_or("");

    let base = format!("HTTP/{version} {code}\n{headers}");

    if method == "HEAD" || raw_body.is_none_or(str::is_empty) {
        Some(base)
    } else {
        Some(format!("{base}\n\n{}", raw_body.unwrap_or("")))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpMetrics {
    pub remote_ip: String,
    pub time_namelookup: f64,
    pub time_connect: f64,
    pub time_appconnect: f64,
    pub time_starttransfer: f64,
    pub time_total: f64,
    pub http_version: String,
    pub response_code: u16,
    pub ssl_verify_result: u32,
}

#[derive(Debug, Clone, Default)]
pub struct TlsEnrichment {
    pub authorized: Option<bool>,
    pub subject_alt: Option<String>,
    pub key_type: Option<String>,
    pub key_bits: Option<u32>,
    pub serial_number: Option<String>,
    pub fingerprint256: Option<String>,
}

pub fn apply_tls_enrichment(tls: &mut TlsInfo, enrichment: TlsEnrichment) {
    if let Some(authorized) = enrichment.authorized {
        tls.authorized = authorized;
    }
    if enrichment.subject_alt.is_some() {
        tls.subject.alt = enrichment.subject_alt;
    }
    if enrichment.key_type.is_some() {
        tls.key_type = enrichment.key_type;
    }
    if enrichment.key_bits.is_some() {
        tls.key_bits = enrichment.key_bits;
    }
    if enrichment.serial_number.is_some() {
        tls.serial_number = enrichment.serial_number;
    }
    if enrichment.fingerprint256.is_some() {
        tls.fingerprint256 = enrichment.fingerprint256;
    }
}

/// Parse curl write-out metrics, using curl verbose output for the public error text.
///
/// # Errors
/// Returns the same public HTTP failure text used by native behavior when curl's
/// write-out JSON is malformed.
pub fn parse_metrics(raw: &str, verbose: &str) -> Result<HttpMetrics, String> {
    let metrics: HttpMetrics =
        serde_json::from_str(raw).map_err(|_| curl_failure_message(verbose, false))?;
    if metrics.response_code == 0 {
        Err(curl_failure_message(verbose, true))
    } else {
        Ok(metrics)
    }
}

#[must_use]
pub fn curl_failure_message(verbose: &str, prefer_last: bool) -> String {
    let candidate =
        |line: &&str| line.contains("curl:") || line.contains("error") || line.starts_with("* ");
    let mut lines = verbose.lines();
    let line = if prefer_last {
        lines.rfind(candidate)
    } else {
        lines.find(candidate)
    };
    line.map_or_else(
        || "HTTP request failed".to_string(),
        |value| value.trim_start_matches("* ").trim().to_string(),
    )
}

#[must_use]
pub fn curl_timeout_message(verbose: &str, is_https: bool) -> String {
    if verbose.contains("< HTTP/") || verbose.contains("< HTTP/2") {
        return "Request timed out while downloading the response.".to_string();
    }
    let tls_established = verbose.contains("SSL connection using")
        || verbose.contains("ALPN: server accepted")
        || verbose.contains("SSL certificate verify result");
    if tls_established || (!is_https && verbose.contains("Connected to")) {
        return "Request timed out while waiting for the first response byte.".to_string();
    }
    if is_https && verbose.contains("Connected to") {
        return "Request timed out during the TLS handshake.".to_string();
    }
    "Request timed out while establishing the TCP connection.".to_string()
}

fn rounded_millis(seconds: f64) -> u64 {
    if !seconds.is_finite() || seconds <= 0.0 {
        return 0;
    }
    let Ok(duration) = core::time::Duration::try_from_secs_f64(seconds) else {
        return u64::MAX;
    };
    let millis = duration.as_nanos().saturating_add(500_000) / 1_000_000;
    u64::try_from(millis).unwrap_or(u64::MAX)
}

#[must_use]
pub fn build_http_timings(
    metrics: &HttpMetrics,
    dns_ms: Option<u64>,
    is_https: bool,
) -> HttpTimings {
    let lookup = rounded_millis(metrics.time_namelookup);
    let tcp = rounded_millis(metrics.time_connect - metrics.time_namelookup);
    let tls = is_https.then(|| rounded_millis(metrics.time_appconnect - metrics.time_connect));
    let app_connect = if is_https {
        metrics.time_appconnect
    } else {
        metrics.time_connect
    };
    let first_byte = rounded_millis(metrics.time_starttransfer - app_connect);
    let download = rounded_millis(metrics.time_total - metrics.time_starttransfer);
    let total = dns_ms
        .unwrap_or(0)
        .saturating_add(rounded_millis(metrics.time_total));
    HttpTimings {
        total: Some(total),
        dns: dns_ms,
        tcp: Some(tcp + lookup),
        tls,
        first_byte: Some(first_byte),
        download: Some(download),
    }
}

#[must_use]
pub fn normalize_http_version(version: &str) -> Option<String> {
    match version {
        "2" | "2.0" => Some("2".to_string()),
        "1.0" => Some("1.0".to_string()),
        "1.1" => Some("1.1".to_string()),
        value if !value.is_empty() => Some(value.to_string()),
        _ => None,
    }
}

#[must_use]
pub fn truncate_body(raw_body: &[u8]) -> (String, bool) {
    if raw_body.len() > BODY_SIZE_LIMIT {
        (
            String::from_utf8_lossy(&raw_body[..BODY_SIZE_LIMIT]).to_string(),
            true,
        )
    } else {
        (String::from_utf8_lossy(raw_body).to_string(), false)
    }
}

#[must_use]
pub fn failed_result(failure_source: &str, message: String) -> ParsedHttp {
    ParsedHttp {
        status: HttpStatus::Failed,
        failure_source: Some(failure_source.to_string()),
        status_code: None,
        status_code_name: None,
        resolved_address: None,
        http_version: None,
        headers: BTreeMap::new(),
        raw_headers: None,
        raw_body: None,
        truncated: false,
        tls: None,
        timings: HttpTimings::default(),
        raw_output: Some(message),
    }
}

pub struct HttpSuccessInput<'a> {
    pub method: &'a str,
    pub protocol: &'a str,
    pub raw_header_file: &'a str,
    pub raw_body_bytes: &'a [u8],
    pub metrics: &'a HttpMetrics,
    pub final_resolved_ip: String,
    pub dns_ms: Option<u64>,
    pub tls: Option<TlsInfo>,
}

#[must_use]
pub fn shape_success_http_result(input: HttpSuccessInput<'_>) -> ParsedHttp {
    let is_https = !input.protocol.eq_ignore_ascii_case("HTTP");
    let status_text = parse_status_text(input.raw_header_file);
    let truncate_result = truncate_headers(parse_header_file(input.raw_header_file));
    let headers = dedup_headers(&truncate_result.headers);
    let raw_headers = truncate_result
        .headers
        .iter()
        .map(|(key, value)| format!("{key}: {value}"))
        .collect::<Vec<_>>()
        .join("\n");
    let (raw_body, body_truncated) = truncate_body(input.raw_body_bytes);
    let truncated = truncate_result.truncated || body_truncated;
    let http_version = normalize_http_version(&input.metrics.http_version);
    let timings = build_http_timings(input.metrics, input.dns_ms, is_https);
    let raw_body = (!raw_body.is_empty()).then_some(raw_body);
    let raw_output = build_raw_output(
        http_version.as_deref(),
        Some(input.metrics.response_code),
        Some(&raw_headers),
        raw_body.as_deref(),
        input.method,
    );
    ParsedHttp {
        status: HttpStatus::Finished,
        failure_source: None,
        status_code: Some(input.metrics.response_code),
        status_code_name: status_text,
        resolved_address: Some(input.final_resolved_ip),
        http_version,
        headers,
        raw_headers: (!raw_headers.is_empty()).then_some(raw_headers),
        raw_body,
        truncated,
        tls: input.tls,
        timings,
        raw_output,
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_file_basic() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Foo: bar\r\n\r\n";
        let pairs = parse_header_file(raw);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "Content-Type");
        assert_eq!(pairs[0].1, "text/html");
        assert_eq!(pairs[1].0, "X-Foo");
        assert_eq!(pairs[1].1, "bar");
    }

    #[test]
    fn parse_header_file_http2_lowercase() {
        let raw = "HTTP/2 200 \r\ncontent-type: application/json\r\n";
        let pairs = parse_header_file(raw);
        assert_eq!(pairs[0].0, "content-type");
    }

    #[test]
    fn parse_status_text_ok() {
        assert_eq!(parse_status_text("HTTP/1.1 200 OK\r\n"), Some("OK".into()));
        assert_eq!(parse_status_text("HTTP/2 200 \r\n"), Some("".into()));
        assert_eq!(
            parse_status_text("HTTP/1.1 404 Not Found"),
            Some("Not Found".into())
        );
    }

    #[test]
    fn dedup_headers_singles() {
        let pairs = vec![
            ("Content-Type".into(), "text/html".into()),
            ("X-Foo".into(), "bar".into()),
        ];
        let map = dedup_headers(&pairs);
        assert_eq!(
            map["content-type"],
            serde_json::Value::String("text/html".into())
        );
    }

    #[test]
    fn dedup_headers_duplicates_become_array() {
        let pairs = vec![
            ("Set-Cookie".into(), "a=1".into()),
            ("Set-Cookie".into(), "b=2".into()),
        ];
        let map = dedup_headers(&pairs);
        assert!(map["set-cookie"].is_array());
        let arr = map["set-cookie"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn truncate_headers_no_truncation_needed() {
        let pairs = vec![("X-Foo".into(), "bar".into())];
        let res = truncate_headers(pairs);
        assert!(!res.truncated);
        assert_eq!(res.headers.len(), 1);
    }

    #[test]
    fn truncate_headers_shrinks_large_value() {
        // One header with a very large value
        let big_value = "x".repeat(11_000);
        let pairs = vec![("X-Big".into(), big_value)];
        let res = truncate_headers(pairs);
        assert!(res.truncated);
        let val = &res.headers[0].1;
        assert!(
            val.ends_with(TRUNCATION_MARK),
            "value should end with truncation mark: {}",
            &val[val.len().saturating_sub(20)..]
        );
        let raw_size = res
            .headers
            .iter()
            .map(|(k, v)| k.len() + v.len() + 2)
            .sum::<usize>();
        assert!(
            raw_size <= HEADERS_SIZE_LIMIT + 10,
            "output size should be within limit"
        );
    }

    #[test]
    fn truncate_headers_drops_headers_when_too_many() {
        // Many headers each with a large min-size
        let pairs: Vec<(String, String)> = (0..200)
            .map(|i| (format!("X-Header-{i:03}"), "x".repeat(100)))
            .collect();
        let res = truncate_headers(pairs);
        assert!(res.truncated);
        let total: usize = res
            .headers
            .iter()
            .map(|(k, v)| k.len() + v.len() + 3)
            .sum::<usize>()
            .saturating_sub(1);
        assert!(
            total <= HEADERS_SIZE_LIMIT,
            "total after truncation: {total}"
        );
    }

    #[test]
    fn parse_tls_verbose_extracts_fields() {
        let verbose = "\
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* Server certificate:
*  subject: CN=cloudflare.com
*  start date: Oct  1 00:00:00 2024 GMT
*  expire date: Oct  1 23:59:59 2025 GMT
*  subjectAltName: host \"cloudflare.com\" matched cert's \"cloudflare.com\"
*  issuer: C=US; O=DigiCert Inc; CN=DigiCert TLS RSA SHA256 2020 CA1
";
        let tls = parse_tls_verbose(verbose, 0).expect("should parse TLS");
        assert!(tls.authorized);
        assert_eq!(tls.protocol.as_deref(), Some("TLSv1.3"));
        assert_eq!(tls.cipher_name.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(tls.subject.cn.as_deref(), Some("cloudflare.com"));
        assert_eq!(
            tls.issuer.cn.as_deref(),
            Some("DigiCert TLS RSA SHA256 2020 CA1")
        );
        assert_eq!(tls.issuer.o.as_deref(), Some("DigiCert Inc"));
        assert_eq!(tls.issuer.c.as_deref(), Some("US"));
        assert_eq!(tls.created_at.as_deref(), Some("2024-10-01T00:00:00.000Z"));
        assert_eq!(tls.expires_at.as_deref(), Some("2025-10-01T23:59:59.000Z"));
    }

    #[test]
    fn curl_date_validates_leap_days_and_time_fields() {
        assert_eq!(
            parse_curl_date("Feb 29 12:34:56 2024 GMT").as_deref(),
            Some("2024-02-29T12:34:56.000Z")
        );
        assert!(parse_curl_date("Feb 29 12:34:56 2025 GMT").is_none());
        assert!(parse_curl_date("Apr 31 12:34:56 2025 GMT").is_none());
        assert!(parse_curl_date("Jan 1 24:00:00 2025 GMT").is_none());
    }

    #[test]
    fn parse_tls_verbose_returns_none_for_http() {
        let verbose = "* Connected to example.com (1.2.3.4) port 80";
        assert!(parse_tls_verbose(verbose, 0).is_none());
    }

    #[test]
    fn build_raw_output_head_no_body() {
        let out = build_raw_output(
            Some("1.1"),
            Some(200),
            Some("Content-Type: text/html"),
            None,
            "HEAD",
        );
        assert!(out.is_some());
        let s = out.unwrap();
        assert!(s.starts_with("HTTP/1.1 200"));
        assert!(!s.contains("\n\n"));
    }

    #[test]
    fn build_raw_output_get_with_body() {
        let out = build_raw_output(
            Some("1.1"),
            Some(200),
            Some("Content-Type: text/html"),
            Some("<html>"),
            "GET",
        );
        let s = out.unwrap();
        assert!(s.contains("\n\n<html>"));
    }
}
