use serde::Serialize;
use std::collections::HashMap;

const HEADERS_SIZE_LIMIT: usize = 10_000;
const TRUNCATION_MARK: &str = "...[truncated]";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpStatus {
    Finished,
    Failed,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpTimings {
    pub total: Option<u64>,
    pub dns: Option<u64>,
    pub tcp: Option<u64>,
    pub tls: Option<u64>,
    pub first_byte: Option<u64>,
    pub download: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TlsSubject {
    #[serde(rename = "CN", skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(rename = "alt", skip_serializing_if = "Option::is_none")]
    pub alt: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TlsIssuer {
    #[serde(rename = "CN", skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(rename = "O", skip_serializing_if = "Option::is_none")]
    pub o: Option<String>,
    #[serde(rename = "C", skip_serializing_if = "Option::is_none")]
    pub c: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Serialize)]
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
    pub headers: HashMap<String, serde_json::Value>,
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
        indexed.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.1));

        let mut dropped = std::collections::HashSet::new();
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
pub fn dedup_headers(pairs: &[(String, String)]) -> HashMap<String, serde_json::Value> {
    let mut map: HashMap<String, serde_json::Value> = HashMap::new();
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

/// Parse curl's date format: "Nov  5 00:00:00 2024 GMT" → ISO 8601
fn parse_curl_date(s: &str) -> Option<String> {
    // Format: "Mon DD HH:MM:SS YYYY GMT"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    // Use chrono to parse
    let date_str = format!("{} {} {} {}", parts[0], parts[1], parts[2], parts[3]);
    let formats = ["%b %e %H:%M:%S %Y", "%b %d %H:%M:%S %Y"];
    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&date_str, fmt) {
            return Some(
                dt.and_utc()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            );
        }
    }
    None
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

// ── Unit tests ────────────────────────────────────────────────────────────

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
        assert!(tls.created_at.is_some());
        assert!(tls.expires_at.is_some());
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
