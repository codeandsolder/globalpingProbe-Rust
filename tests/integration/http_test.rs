use globalping_probe::command::http::parse::{
    build_raw_output, dedup_headers, parse_header_file, parse_status_text, parse_tls_verbose,
    truncate_headers,
};

// ── Fixture-based parser tests ────────────────────────────────────────────────

const HEADER_FILE_HTTP11: &str = "HTTP/1.1 200 OK\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: 1234\r\n\
Set-Cookie: a=1; Path=/\r\n\
Set-Cookie: b=2; Path=/\r\n\
\r\n";

const HEADER_FILE_HTTP2: &str = "HTTP/2 301 \r\n\
content-type: text/html\r\n\
location: https://www.example.com/\r\n\
\r\n";

#[test]
fn parse_headers_http11() {
    let pairs = parse_header_file(HEADER_FILE_HTTP11);
    assert_eq!(pairs.len(), 4);
    assert_eq!(pairs[0].0, "Content-Type");
    assert_eq!(pairs[0].1, "text/html; charset=utf-8");
    assert_eq!(pairs[2].0, "Set-Cookie");
    assert_eq!(pairs[3].0, "Set-Cookie");
}

#[test]
fn parse_status_text_http11() {
    assert_eq!(parse_status_text(HEADER_FILE_HTTP11), Some("OK".into()));
}

#[test]
fn parse_status_text_http2_empty() {
    // HTTP/2 often has no status text after code
    assert_eq!(parse_status_text(HEADER_FILE_HTTP2), Some("".into()));
}

#[test]
fn parse_headers_http2_lowercase() {
    let pairs = parse_header_file(HEADER_FILE_HTTP2);
    assert_eq!(pairs[0].0, "content-type");
    assert_eq!(pairs[1].0, "location");
}

#[test]
fn dedup_sets_cookies_as_array() {
    let pairs = parse_header_file(HEADER_FILE_HTTP11);
    let map = dedup_headers(&pairs);
    // set-cookie (lowercase) should be an array
    assert!(map.get("set-cookie").map(|v| v.is_array()).unwrap_or(false));
    let arr = map["set-cookie"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
}

#[test]
fn dedup_single_header_is_string() {
    let pairs = parse_header_file(HEADER_FILE_HTTP11);
    let map = dedup_headers(&pairs);
    assert_eq!(
        map["content-type"],
        serde_json::Value::String("text/html; charset=utf-8".into())
    );
}

#[test]
fn truncate_no_op_for_small_headers() {
    let pairs = vec![("Content-Type".into(), "text/html".into())];
    let res = truncate_headers(pairs);
    assert!(!res.truncated);
    assert_eq!(res.headers.len(), 1);
}

#[test]
fn truncate_shrinks_large_value() {
    let pairs = vec![("X-Big".into(), "y".repeat(12_000))];
    let res = truncate_headers(pairs);
    assert!(res.truncated);
    assert!(res.headers[0].1.ends_with("...[truncated]"));
    let total: usize = res
        .headers
        .iter()
        .map(|(k, v)| k.len() + v.len() + 3)
        .sum::<usize>()
        - 1;
    assert!(total <= 10_000, "size after truncation: {total}");
}

#[test]
fn truncate_drops_excess_headers() {
    let pairs: Vec<(String, String)> = (0..300)
        .map(|i| (format!("X-H-{i:03}"), "val".repeat(10)))
        .collect();
    let res = truncate_headers(pairs);
    assert!(res.truncated);
    let total: usize = res
        .headers
        .iter()
        .map(|(k, v)| k.len() + v.len() + 3)
        .sum::<usize>()
        .saturating_sub(1);
    assert!(total <= 10_000, "total {total} exceeds limit");
}

const TLS_VERBOSE: &str = "\
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN: server accepted h2
* Server certificate:
*  subject: CN=cloudflare-dns.com
*  start date: Nov  5 00:00:00 2024 GMT
*  expire date: Nov  4 23:59:59 2025 GMT
*  subjectAltName: host \"cloudflare-dns.com\" matched cert's \"cloudflare-dns.com\"
*  issuer: C=US; O=Google Trust Services; CN=WR2
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
";

#[test]
fn parse_tls_verbose_ok() {
    let tls = parse_tls_verbose(TLS_VERBOSE, 18).expect("should parse TLS");
    assert!(!tls.authorized); // ssl_verify_result != 0
    assert_eq!(tls.protocol.as_deref(), Some("TLSv1.3"));
    assert_eq!(tls.cipher_name.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
    assert_eq!(tls.subject.cn.as_deref(), Some("cloudflare-dns.com"));
    assert_eq!(tls.issuer.cn.as_deref(), Some("WR2"));
    assert_eq!(tls.issuer.o.as_deref(), Some("Google Trust Services"));
    assert_eq!(tls.issuer.c.as_deref(), Some("US"));
    assert!(tls.created_at.is_some(), "created_at should be parsed");
    assert!(tls.expires_at.is_some(), "expires_at should be parsed");
    // ISO 8601 format
    assert!(tls.created_at.as_deref().unwrap().contains('T'));
}

#[test]
fn parse_tls_verbose_authorized_true() {
    let tls = parse_tls_verbose(TLS_VERBOSE, 0).expect("TLS present");
    assert!(tls.authorized);
}

#[test]
fn parse_tls_verbose_no_tls_returns_none() {
    assert!(parse_tls_verbose("* Connected to example.com (1.2.3.4) port 80", 0).is_none());
}

#[test]
fn build_raw_output_head() {
    let out = build_raw_output(
        Some("1.1"),
        Some(200),
        Some("Content-Type: text/html"),
        None,
        "HEAD",
    );
    let s = out.unwrap();
    assert!(s.starts_with("HTTP/1.1 200"));
    assert!(s.contains("Content-Type: text/html"));
    assert!(!s.contains("\n\n"));
}

#[test]
fn build_raw_output_get_with_body() {
    let out = build_raw_output(
        Some("2"),
        Some(200),
        Some("Content-Type: text/html"),
        Some("<html>hello</html>"),
        "GET",
    );
    let s = out.unwrap();
    assert!(s.starts_with("HTTP/2 200"));
    assert!(s.contains("\n\n<html>hello</html>"));
}

// ── Live process tests (Linux only) ──────────────────────────────────────────

#[cfg(target_os = "linux")]
mod live {
    use globalping_probe::command::http::{parse::HttpStatus, run_measurement};

    #[tokio::test]
    async fn live_https_head_cloudflare() {
        let r = run_measurement("1.1.1.1", "HTTPS", "HEAD", "/", None, 4)
            .await
            .expect("run_measurement failed");

        assert_eq!(
            r.status,
            HttpStatus::Finished,
            "raw_output: {:?}",
            r.raw_output
        );
        assert!(r.status_code.is_some(), "should have status code");
        assert!(r.resolved_address.is_some(), "should have resolved address");
        assert!(r.timings.total.is_some());
        assert!(r.timings.tcp.is_some());
        assert!(r.raw_output.is_some());

        println!(
            "HTTPS HEAD 1.1.1.1: status={} version={:?} resolved={:?}",
            r.status_code.unwrap(),
            r.http_version,
            r.resolved_address
        );
        println!(
            "  timings: total={:?}ms dns={:?}ms tcp={:?}ms tls={:?}ms first_byte={:?}ms",
            r.timings.total, r.timings.dns, r.timings.tcp, r.timings.tls, r.timings.first_byte
        );
        if let Some(tls) = &r.tls {
            println!(
                "  TLS: authorized={} protocol={:?} cipher={:?}",
                tls.authorized, tls.protocol, tls.cipher_name
            );
            println!(
                "       subject.CN={:?} issuer.CN={:?}",
                tls.subject.cn, tls.issuer.cn
            );
            println!(
                "       created={:?} expires={:?}",
                tls.created_at, tls.expires_at
            );
        }
    }

    #[tokio::test]
    async fn live_https_get_cloudflare_body_present() {
        let r = run_measurement("1.1.1.1", "HTTPS", "GET", "/", None, 4)
            .await
            .expect("run_measurement failed");

        assert_eq!(
            r.status,
            HttpStatus::Finished,
            "raw_output: {:?}",
            r.raw_output
        );
        // GET should return a body (redirect or content)
        println!(
            "HTTPS GET 1.1.1.1: status={:?} body_len={:?}",
            r.status_code,
            r.raw_body.as_ref().map(|b| b.len())
        );
        println!(
            "rawOutput:\n{}",
            r.raw_output.as_deref().unwrap_or("(none)")
        );
    }

    #[tokio::test]
    async fn live_http2_head_cloudflare() {
        let r = run_measurement("1.1.1.1", "HTTP2", "HEAD", "/", None, 4)
            .await
            .expect("run_measurement failed");

        assert_eq!(
            r.status,
            HttpStatus::Finished,
            "raw_output: {:?}",
            r.raw_output
        );
        // HTTP2 should negotiate h2 protocol
        if let Some(ver) = &r.http_version {
            println!("HTTP2 HEAD 1.1.1.1: negotiated version={ver}");
        }
    }

    #[tokio::test]
    async fn live_http_head_example() {
        let r = run_measurement("93.184.216.34", "HTTP", "HEAD", "/", None, 4)
            .await
            .expect("run_measurement returned Err (not Failed)");

        // Port 80 on example.com may be blocked in some CI/WSL environments — just print
        println!(
            "HTTP HEAD 93.184.216.34: status={:?} code={:?}",
            r.status, r.status_code
        );
        println!("  raw_output: {:?}", r.raw_output);
    }

    #[tokio::test]
    async fn live_private_ip_rejected() {
        let result = run_measurement("192.168.1.1", "HTTPS", "HEAD", "/", None, 4)
            .await
            .expect("private IP should produce a structured failure");
        assert_eq!(result.status, HttpStatus::Failed);
        assert_eq!(result.failure_source.as_deref(), Some("target"));
        assert_eq!(
            result.raw_output.as_deref(),
            Some("Private IP ranges are not allowed.")
        );
    }

    #[tokio::test]
    async fn live_https_with_headers_map() {
        let r = run_measurement("1.1.1.1", "HTTPS", "HEAD", "/", None, 4)
            .await
            .expect("run_measurement failed");

        assert_eq!(r.status, HttpStatus::Finished);
        // Should have at least a content-type or some headers
        println!("Headers: {:?}", r.headers.keys().collect::<Vec<_>>());
        assert!(!r.headers.is_empty(), "headers map should not be empty");
    }

    #[tokio::test]
    async fn live_tls_details_populated() {
        let r = run_measurement("1.1.1.1", "HTTPS", "HEAD", "/", None, 4)
            .await
            .expect("run_measurement failed");

        assert_eq!(r.status, HttpStatus::Finished);
        let tls = r.tls.expect("TLS info should be present for HTTPS");
        assert!(tls.protocol.is_some(), "TLS protocol should be set");
        assert!(tls.cipher_name.is_some(), "cipher should be set");
    }
}
