pub mod parse;

// ── Imports ───────────────────────────────────────────────────────────────────

use super::ProgressTx;
use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use tokio::fs;
use tokio::process::Command;
use tokio::time::{Duration, Instant, timeout};

use crate::util::measurement_timeout::{MeasurementDeadline, http_dns_timeout};
use crate::util::private_ip::is_ip_private;
use crate::util::validate::{is_safe_host, is_safe_url_component};
use parse::{
    HttpStatus, HttpTimings, ParsedHttp, TlsInfo, build_raw_output, dedup_headers,
    parse_header_file, parse_status_text, parse_tls_verbose, truncate_headers,
};

// ── Options ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpRequestOptions {
    #[serde(default = "default_method")]
    pub method: String,
    pub host: Option<String>,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpOptions {
    pub target: String,
    pub resolver: Option<String>,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub port: Option<u16>,
    #[serde(default = "default_ip_version")]
    pub ip_version: u8,
    #[serde(default)]
    pub in_progress_updates: bool,
    pub timeout: u32,
    pub request: HttpRequestOptions,
}

fn default_method() -> String {
    "HEAD".into()
}
fn default_path() -> String {
    "/".into()
}
fn default_protocol() -> String {
    "HTTPS".into()
}
const fn default_ip_version() -> u8 {
    4
}

// ── Validation ────────────────────────────────────────────────────────────────

fn validate(opts: &HttpOptions) -> Result<()> {
    // Target is embedded in the curl URL and in `--resolve`; reject metacharacters
    // and anything that isn't a clean hostname/IP.
    if !is_safe_host(&opts.target) {
        bail!("Invalid target.");
    }
    if opts.ip_version != 4 && opts.ip_version != 6 {
        bail!("ipVersion must be 4 or 6");
    }
    let proto = opts.protocol.to_uppercase();
    if proto != "HTTP" && proto != "HTTPS" && proto != "HTTP2" {
        bail!("protocol must be HTTP, HTTPS, or HTTP2");
    }
    let method = opts.request.method.to_uppercase();
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        bail!("method must be GET, HEAD, or OPTIONS");
    }
    // A custom resolver must be a clean host and must not be private (SSRF /
    // internal port-scan via dig — see resolve_target).
    if let Some(resolver) = &opts.resolver {
        let ip: std::net::IpAddr = resolver
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid resolver."))?;
        if is_ip_private(ip) {
            bail!("Private IP ranges are not allowed.");
        }
    }
    // The Host-header / SNI override is NOT used for DNS resolution but IS used as
    // the TLS servername during cert enrichment. It must be a clean hostname so it
    // can never carry shell syntax or break the request.
    if let Some(host) = &opts.request.host
        && !is_safe_host(host)
    {
        bail!("Invalid host header.");
    }
    // Path and query are concatenated into the curl URL — forbid control chars and
    // whitespace (request-smuggling / CRLF injection).
    if !is_safe_url_component(&opts.request.path) {
        bail!("Invalid request path.");
    }
    if !is_safe_url_component(&opts.request.query) {
        bail!("Invalid request query.");
    }
    // Custom request headers must not contain control characters (header injection).
    for (k, v) in &opts.request.headers {
        if k.bytes().chain(v.bytes()).any(|b| b.is_ascii_control()) {
            bail!("Invalid request header.");
        }
    }
    // Private IP check if target is already an IP
    Ok(())
}

// ── DNS pre-resolution ────────────────────────────────────────────────────────

#[derive(Debug)]
enum HttpResolveError {
    TimedOut,
    PrivateIp,
    Failed(String),
}

impl HttpResolveError {
    const fn failure_source(&self) -> &'static str {
        match self {
            Self::TimedOut => "resolver",
            Self::PrivateIp | Self::Failed(_) => "target",
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::TimedOut => "The measurement timed out during DNS resolution.".to_string(),
            Self::PrivateIp => "Private IP ranges are not allowed.".to_string(),
            Self::Failed(message) => message.clone(),
        }
    }
}

async fn resolve_target(
    target: &str,
    resolver: Option<&str>,
    ip_version: u8,
    timeout_seconds: u32,
) -> std::result::Result<(String, Option<u64>), HttpResolveError> {
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        if is_ip_private(ip) {
            return Err(HttpResolveError::PrivateIp);
        }
        return Ok((target.to_string(), None));
    }

    let query_type = if ip_version == 6 { "AAAA" } else { "A" };
    let mut args = Vec::new();
    if let Some(resolver) = resolver {
        args.push(format!("@{resolver}"));
    }
    args.push(target.to_string());
    args.push(query_type.to_string());
    args.push("+short".into());
    args.push("+tries=1".into());

    let dns_budget = Duration::from_secs_f64(http_dns_timeout(timeout_seconds));
    let start = Instant::now();
    let output = timeout(dns_budget, Command::new("dig").args(&args).output())
        .await
        .map_err(|_| HttpResolveError::TimedOut)?
        .map_err(|error| HttpResolveError::Failed(format!("DNS resolution failed: {error}")))?;
    let dns_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let address = stdout
        .lines()
        .map(str::trim)
        .filter_map(|line| line.parse::<std::net::IpAddr>().ok())
        .find(|address| {
            matches!(
                (ip_version, address),
                (4, std::net::IpAddr::V4(_)) | (6, std::net::IpAddr::V6(_))
            )
        })
        .ok_or_else(|| {
            HttpResolveError::Failed(format!("DNS resolution returned no results for {target}"))
        })?;
    if is_ip_private(address) {
        return Err(HttpResolveError::PrivateIp);
    }
    Ok((address.to_string(), Some(dns_ms)))
}

// ── URL builder ───────────────────────────────────────────────────────────────

fn build_url(opts: &HttpOptions, port: u16) -> String {
    let proto = opts.protocol.to_uppercase();
    let scheme = if proto == "HTTP" { "http" } else { "https" };
    let host = if opts.target.contains(':') {
        // IPv6 address needs brackets
        format!("[{}]", opts.target)
    } else {
        opts.target.clone()
    };
    let path = format!("/{}", opts.request.path.trim_start_matches('/'));
    let query = if opts.request.query.is_empty() {
        String::new()
    } else {
        format!("?{}", opts.request.query.trim_start_matches('?'))
    };
    format!("{scheme}://{host}:{port}{path}{query}")
}

// ── curl arg builder ──────────────────────────────────────────────────────────

const CURL_WRITE_FMT: &str = concat!(
    r#"{"remote_ip":"%{remote_ip}","time_namelookup":%{time_namelookup},"#,
    r#""time_connect":%{time_connect},"time_appconnect":%{time_appconnect},"#,
    r#""time_starttransfer":%{time_starttransfer},"time_total":%{time_total},"#,
    r#""http_version":"%{http_version}","response_code":%{response_code},"#,
    r#""ssl_verify_result":%{ssl_verify_result}}"#,
);

#[derive(Debug, serde::Deserialize)]
struct CurlStats {
    remote_ip: String,
    time_namelookup: f64,
    time_connect: f64,
    time_appconnect: f64,
    time_starttransfer: f64,
    time_total: f64,
    http_version: String,
    response_code: u16,
    ssl_verify_result: u32,
}

fn build_curl_args(
    opts: &HttpOptions,
    url: &str,
    port: u16,
    resolved_ip: &str,
    headers_path: &str,
    body_path: &str,
    max_time: Duration,
) -> Vec<String> {
    let proto = opts.protocol.to_uppercase();
    let method = opts.request.method.to_uppercase();
    let host_header = opts
        .request
        .host
        .as_deref()
        .unwrap_or(&opts.target)
        .to_string();

    let mut args: Vec<String> = vec![
        "-sS".into(),          // silent, show errors
        "-k".into(),           // don't abort on TLS errors (but still report ssl_verify_result)
        "-v".into(),           // verbose → TLS info on stderr
        "--compressed".into(), // accept gzip/brotli
        "--max-time".into(),
        max_time.as_secs_f64().max(0.001).to_string(),
        "-X".into(),
        method,
        format!("-{}", opts.ip_version),
        "-D".into(),
        headers_path.into(), // dump response headers to file
        "-o".into(),
        body_path.into(), // write body to file
        "--write-out".into(),
        CURL_WRITE_FMT.into(),
        "-H".into(),
        format!("Host: {host_header}"),
        "-H".into(),
        "User-Agent: globalping probe (https://github.com/jsdelivr/globalping)".into(),
        "-H".into(),
        "Connection: close".into(),
        "-H".into(),
        "Accept-Encoding: gzip, deflate, br".into(),
    ];

    // Extra request headers
    for (k, v) in &opts.request.headers {
        args.push("-H".into());
        args.push(format!("{k}: {v}"));
    }

    // Protocol flag
    match proto.as_str() {
        "HTTP2" => {
            args.push("--http2".into());
        }
        "HTTP" => {
            args.push("--http1.1".into());
        }
        _ => {} // HTTPS uses curl default (HTTP/1.1 or HTTP/2 via ALPN)
    }

    // Force connection to pre-resolved IP (bypasses curl's DNS)
    if opts.target.parse::<std::net::IpAddr>().is_err() {
        args.push("--resolve".into());
        let connection_ip = if resolved_ip.contains(':') {
            // IPv6: curl needs brackets in --resolve
            format!("[{resolved_ip}]")
        } else {
            resolved_ip.to_string()
        };
        args.push(format!("{}:{port}:{connection_ip}", opts.target));
    }

    args.push(url.to_string());
    args
}

// ── TLS cert enrichment via openssl ──────────────────────────────────────────

/// Spawn `cmd` with an explicit argv (NO shell), feed `stdin_data` to its stdin,
/// and capture stdout with a timeout. stderr is discarded. Returns `None` on
/// spawn/timeout/IO failure.
///
/// Using an explicit argv is what makes the TLS enrichment injection-proof:
/// there is no shell to interpret metacharacters in the servername/host.
async fn run_capturing(
    cmd: &str,
    args: &[String],
    stdin_data: &[u8],
    dur: Duration,
) -> Option<Vec<u8>> {
    use tokio::io::AsyncWriteExt;
    let mut child = Command::new(cmd)
        .args(args)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_data).await;
        let _ = stdin.shutdown().await; // EOF, like `echo |`
    }
    let out = timeout(dur, child.wait_with_output()).await.ok()?.ok()?;
    Some(out.stdout)
}

/// Extract the first PEM certificate block (inclusive of BEGIN/END markers).
fn extract_pem(s: &str) -> Option<String> {
    const END: &str = "-----END CERTIFICATE-----";
    let begin = s.find("-----BEGIN CERTIFICATE-----")?;
    let end = s[begin..].find(END)? + begin + END.len();
    Some(s[begin..end].to_string())
}

/// Read at most `cap + 1` bytes from `path` (the extra byte lets callers detect
/// overflow) without loading an arbitrarily large file into memory. Curl already
/// bounds transfers with `--max-time`, but a fast server could still deliver a
/// large body within the window; this caps the memory we commit to it.
async fn read_capped(path: &str, cap: usize) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let Ok(file) = fs::File::open(path).await else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    let _ = file.take(cap as u64 + 1).read_to_end(&mut buf).await;
    buf
}

/// After a successful HTTPS request, run `openssl s_client` then `openssl x509`
/// to extract the fields curl -v doesn't expose: fingerprint256, serialNumber,
/// keyType, keyBits, subject.alt, and the real authorized status.
///
/// Security: both openssl invocations use an explicit argv via [`run_capturing`]
/// — there is NO shell and NO temp file. Earlier this used `sh -c` with the
/// servername interpolated into the command string, which was a command-injection
/// (RCE) vector because the Host-header override flows in here unvalidated-for-DNS.
async fn enrich_tls(
    tls: &mut TlsInfo,
    ip: &str,
    port: u16,
    servername: &str,
    deadline: MeasurementDeadline,
) {
    let connect_addr = if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    };

    // Build s_client args as discrete argv entries (no shell, no interpolation).
    let mut sc_args: Vec<String> = vec!["s_client".into(), "-connect".into(), connect_addr];
    // No SNI when the target is already an IP address.
    if servername.parse::<std::net::IpAddr>().is_ok() {
        sc_args.push("-noservername".into());
    } else {
        sc_args.push("-servername".into());
        sc_args.push(servername.to_string());
    }

    // s_client prints connection info + the PEM cert + "Verify return code" to
    // stdout. Feed it a single newline (like `echo |`) so it finishes the
    // handshake and exits instead of waiting for application data.
    let s_client_budget = deadline.remaining().min(Duration::from_secs(10));
    if s_client_budget.is_zero() {
        return;
    }
    let Some(sc_stdout) = run_capturing("openssl", &sc_args, b"\n", s_client_budget).await else {
        return;
    };
    let full_text = String::from_utf8_lossy(&sc_stdout);

    // Verify result, printed by s_client itself.
    for line in full_text.lines() {
        if line.contains("Verify return code:") {
            tls.authorized = line.contains("Verify return code: 0 (ok)");
            break;
        }
    }

    // Extract the PEM block in-process (no `sed`, no temp file) and pipe it to
    // `openssl x509` over stdin (no `-in <path>`).
    let Some(pem) = extract_pem(&full_text) else {
        return;
    };
    let x509_args: Vec<String> = vec![
        "x509".into(),
        "-noout".into(),
        "-fingerprint".into(),
        "-sha256".into(),
        "-serial".into(),
        "-text".into(),
    ];
    let x509_budget = deadline.remaining().min(Duration::from_secs(4));
    if x509_budget.is_zero() {
        return;
    }
    let Some(x509_stdout) = run_capturing("openssl", &x509_args, pem.as_bytes(), x509_budget).await
    else {
        return;
    };
    let text = String::from_utf8_lossy(&x509_stdout);

    let mut next_is_san = false;
    for line in text.lines() {
        let t = line.trim();

        // OpenSSL 3.x outputs "sha256 Fingerprint=", 1.x outputs "SHA256 Fingerprint="
        if let Some(fp) = t
            .strip_prefix("sha256 Fingerprint=")
            .or_else(|| t.strip_prefix("SHA256 Fingerprint="))
        {
            tls.fingerprint256 = Some(fp.trim().to_string());
        }
        // "serial=AABB..." → "AA:BB:..."
        else if let Some(hex) = t.strip_prefix("serial=") {
            let hex = hex.trim().to_uppercase();
            let fmt: Vec<String> = hex
                .chars()
                .collect::<Vec<_>>()
                .chunks(2)
                .map(|c| c.iter().collect())
                .collect();
            if !fmt.is_empty() {
                tls.serial_number = Some(fmt.join(":"));
            }
        }
        // "Public Key Algorithm: id-ecPublicKey" / "rsaEncryption"
        else if t.starts_with("Public Key Algorithm:") {
            if t.contains("ecPublicKey") || t.contains("id-ec") {
                tls.key_type = Some("EC".to_string());
            } else if t.contains("rsaEncryption") {
                tls.key_type = Some("RSA".to_string());
            }
        }
        // "Public-Key: (256 bit)"
        else if let Some(rest) = t.strip_prefix("Public-Key: (") {
            if let Some(bits_str) = rest.strip_suffix(" bit)")
                && let Ok(bits) = bits_str.parse::<u32>()
            {
                tls.key_bits = Some(bits);
            }
        }
        // "X509v3 Subject Alternative Name:" → next non-empty line has the SANs
        else if t.starts_with("X509v3 Subject Alternative Name") {
            next_is_san = true;
        } else if next_is_san && !t.is_empty() {
            tls.subject.alt = Some(t.to_string());
            next_is_san = false;
        }
    }
}

// ── Runner ────────────────────────────────────────────────────────────────────

const BODY_LIMIT: usize = 10_000;

fn rounded_millis(seconds: f64) -> u64 {
    if !seconds.is_finite() || seconds <= 0.0 {
        return 0;
    }
    let Ok(duration) = Duration::try_from_secs_f64(seconds) else {
        return u64::MAX;
    };
    let millis = duration.as_nanos().saturating_add(500_000) / 1_000_000;
    u64::try_from(millis).unwrap_or(u64::MAX)
}

struct CurlCapture {
    stats: String,
    verbose: String,
    raw_headers: String,
    raw_body: Vec<u8>,
}

async fn remove_curl_files(headers_path: &str, body_path: &str) {
    let _ = fs::remove_file(headers_path).await;
    let _ = fs::remove_file(body_path).await;
}

#[derive(Debug)]
enum CurlRunError {
    TimedOut(String),
    Spawn(String),
}

fn curl_timeout_message(verbose: &str, is_https: bool) -> String {
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

async fn emit_http_progress(
    headers_path: &str,
    body_path: &str,
    sent_body: &mut usize,
    tx: &ProgressTx,
) {
    let body = read_capped(body_path, BODY_LIMIT).await;
    let capped_len = body.len().min(BODY_LIMIT);
    if capped_len <= *sent_body {
        return;
    }
    let chunk = String::from_utf8_lossy(&body[*sent_body..capped_len]).to_string();
    *sent_body = capped_len;
    if chunk.is_empty() {
        return;
    }

    if *sent_body == chunk.len() {
        let header_file = fs::read_to_string(headers_path).await.unwrap_or_default();
        let status_line = header_file
            .lines()
            .next()
            .unwrap_or_default()
            .trim_end_matches('\r');
        let status_line = status_line
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let raw_headers = parse_header_file(&header_file)
            .into_iter()
            .map(|(key, value)| format!("{key}: {value}"))
            .collect::<Vec<_>>()
            .join("\n");
        let prefix = if status_line.is_empty() {
            String::new()
        } else {
            format!("{status_line}\n{raw_headers}\n\n")
        };
        tx.send(json!({
            "rawHeaders": raw_headers,
            "rawBody": chunk,
            "rawOutput": format!("{prefix}{chunk}"),
        }))
        .ok();
    } else {
        tx.send(json!({
            "rawBody": chunk,
            "rawOutput": chunk,
        }))
        .ok();
    }
}

async fn execute_curl(
    opts: &HttpOptions,
    url: &str,
    port: u16,
    resolved_ip: &str,
    remaining: Duration,
    is_https: bool,
    progress: Option<&ProgressTx>,
) -> std::result::Result<CurlCapture, CurlRunError> {
    use tokio::io::AsyncReadExt as _;

    let id = uuid::Uuid::new_v4().to_string().replace('-', "");
    let headers_path = format!("/tmp/gp_hdr_{id}.txt");
    let body_path = format!("/tmp/gp_body_{id}.txt");
    let args = build_curl_args(
        opts,
        url,
        port,
        resolved_ip,
        &headers_path,
        &body_path,
        remaining,
    );
    let mut child = Command::new("curl")
        .args(&args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| CurlRunError::Spawn(format!("curl failed to spawn: {error}")))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| CurlRunError::Spawn("curl stdout pipe unavailable".to_string()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| CurlRunError::Spawn("curl stderr pipe unavailable".to_string()))?;
    let stdout_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes).await;
        bytes
    });
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes).await;
        bytes
    });

    let mut sent_body = 0_usize;
    let mut poll = tokio::time::interval(Duration::from_millis(25));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    poll.tick().await;
    let completed = timeout(remaining, async {
        loop {
            tokio::select! {
                status = child.wait() => break status,
                _ = poll.tick(), if progress.is_some() => {
                    if let Some(tx) = progress {
                        emit_http_progress(&headers_path, &body_path, &mut sent_body, tx).await;
                    }
                }
            }
        }
    })
    .await;
    let (status, timed_out) = match completed {
        Ok(Ok(status)) => (Some(status), false),
        Ok(Err(error)) => {
            remove_curl_files(&headers_path, &body_path).await;
            return Err(CurlRunError::Spawn(format!("curl wait failed: {error}")));
        }
        Err(_) => {
            child.kill().await.ok();
            let status = child.wait().await.ok();
            (status, true)
        }
    };
    if let Some(tx) = progress {
        emit_http_progress(&headers_path, &body_path, &mut sent_body, tx).await;
    }

    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();
    let verbose = String::from_utf8_lossy(&stderr).to_string();
    if timed_out || status.is_some_and(|status| !status.success() && status.code() == Some(28)) {
        let message = curl_timeout_message(&verbose, is_https);
        remove_curl_files(&headers_path, &body_path).await;
        return Err(CurlRunError::TimedOut(message));
    }
    let capture = CurlCapture {
        stats: String::from_utf8_lossy(&stdout).trim().to_string(),
        verbose,
        raw_headers: fs::read_to_string(&headers_path).await.unwrap_or_default(),
        raw_body: read_capped(&body_path, BODY_LIMIT).await,
    };
    remove_curl_files(&headers_path, &body_path).await;
    Ok(capture)
}

fn curl_failure_message(verbose: &str, prefer_last: bool) -> String {
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

fn parse_curl_stats(capture: &CurlCapture) -> std::result::Result<CurlStats, String> {
    let stats: CurlStats = serde_json::from_str(&capture.stats)
        .map_err(|_| curl_failure_message(&capture.verbose, false))?;
    if stats.response_code == 0 {
        return Err(curl_failure_message(&capture.verbose, true));
    }
    Ok(stats)
}

fn truncate_body(raw_body: &[u8]) -> (String, bool) {
    if raw_body.len() > BODY_LIMIT {
        (
            String::from_utf8_lossy(&raw_body[..BODY_LIMIT]).to_string(),
            true,
        )
    } else {
        (String::from_utf8_lossy(raw_body).to_string(), false)
    }
}

fn normalize_http_version(version: &str) -> Option<String> {
    match version {
        "2" | "2.0" => Some("2".to_string()),
        "1.0" => Some("1.0".to_string()),
        "1.1" => Some("1.1".to_string()),
        value if !value.is_empty() => Some(value.to_string()),
        _ => None,
    }
}

fn build_http_timings(stats: &CurlStats, dns_ms: Option<u64>, is_https: bool) -> HttpTimings {
    let lookup = rounded_millis(stats.time_namelookup);
    let tcp = rounded_millis(stats.time_connect - stats.time_namelookup);
    let tls = is_https.then(|| rounded_millis(stats.time_appconnect - stats.time_connect));
    let app_connect = if is_https {
        stats.time_appconnect
    } else {
        stats.time_connect
    };
    let first_byte = rounded_millis(stats.time_starttransfer - app_connect);
    let download = rounded_millis(stats.time_total - stats.time_starttransfer);
    let total = dns_ms
        .unwrap_or(0)
        .saturating_add(rounded_millis(stats.time_total));
    HttpTimings {
        total: Some(total),
        dns: dns_ms,
        tcp: Some(tcp + lookup),
        tls,
        first_byte: Some(first_byte),
        download: Some(download),
    }
}

async fn build_tls_info(
    opts: &HttpOptions,
    stats: &CurlStats,
    final_resolved_ip: &str,
    port: u16,
    is_https: bool,
    verbose: &str,
    deadline: MeasurementDeadline,
) -> Option<TlsInfo> {
    if !is_https {
        return None;
    }
    let mut tls = parse_tls_verbose(verbose, stats.ssl_verify_result)?;
    let server_name = opts.request.host.as_deref().unwrap_or(&opts.target);
    enrich_tls(&mut tls, final_resolved_ip, port, server_name, deadline).await;
    Some(tls)
}

async fn build_success_http_result(
    opts: &HttpOptions,
    capture: &CurlCapture,
    stats: &CurlStats,
    final_resolved_ip: String,
    dns_ms: Option<u64>,
    port: u16,
    deadline: MeasurementDeadline,
) -> ParsedHttp {
    let is_https = !opts.protocol.eq_ignore_ascii_case("HTTP");
    let status_text = parse_status_text(&capture.raw_headers);
    let truncate_result = truncate_headers(parse_header_file(&capture.raw_headers));
    let headers = dedup_headers(&truncate_result.headers);
    let raw_headers = truncate_result
        .headers
        .iter()
        .map(|(key, value)| format!("{key}: {value}"))
        .collect::<Vec<_>>()
        .join("\n");
    let (raw_body, body_truncated) = truncate_body(&capture.raw_body);
    let truncated = truncate_result.truncated || body_truncated;
    let http_version = normalize_http_version(&stats.http_version);
    let tls = build_tls_info(
        opts,
        stats,
        &final_resolved_ip,
        port,
        is_https,
        &capture.verbose,
        deadline,
    )
    .await;
    let timings = build_http_timings(stats, dns_ms, is_https);
    let raw_body = (!raw_body.is_empty()).then_some(raw_body);
    let raw_output = build_raw_output(
        http_version.as_deref(),
        Some(stats.response_code),
        Some(&raw_headers),
        raw_body.as_deref(),
        &opts.request.method,
    );
    ParsedHttp {
        status: HttpStatus::Finished,
        failure_source: None,
        status_code: Some(stats.response_code),
        status_code_name: status_text,
        resolved_address: Some(final_resolved_ip),
        http_version,
        headers,
        raw_headers: (!raw_headers.is_empty()).then_some(raw_headers),
        raw_body,
        truncated,
        tls,
        timings,
        raw_output,
    }
}

async fn run_http(opts: &HttpOptions, progress: Option<ProgressTx>) -> Result<ParsedHttp> {
    validate(opts)?;
    let deadline = MeasurementDeadline::new(opts.timeout);
    let protocol = opts.protocol.to_uppercase();
    let is_https = protocol != "HTTP";
    let port = opts
        .port
        .unwrap_or(if protocol == "HTTP" { 80 } else { 443 });
    let (resolved_ip, dns_ms) = match resolve_target(
        &opts.target,
        opts.resolver.as_deref(),
        opts.ip_version,
        opts.timeout,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            return Ok(failed_result(
                error.failure_source(),
                error.public_message(),
            ));
        }
    };
    let remaining = deadline.remaining();
    if remaining.is_zero() {
        return Ok(failed_result(
            "target",
            "Request timed out while establishing the TCP connection.".to_string(),
        ));
    }
    let url = build_url(opts, port);
    let capture = match execute_curl(
        opts,
        &url,
        port,
        &resolved_ip,
        remaining,
        is_https,
        progress.as_ref(),
    )
    .await
    {
        Ok(capture) => capture,
        Err(CurlRunError::TimedOut(message)) => return Ok(failed_result("target", message)),
        Err(CurlRunError::Spawn(message)) => return Ok(failed_result("internal", message)),
    };
    let stats = match parse_curl_stats(&capture) {
        Ok(stats) => stats,
        Err(message) => return Ok(failed_result("target", message)),
    };
    let final_resolved_ip = if stats.remote_ip.is_empty() {
        resolved_ip
    } else {
        stats.remote_ip.clone()
    };
    if final_resolved_ip.parse().is_ok_and(is_ip_private) {
        return Ok(failed_result(
            "target",
            "Private IP ranges are not allowed.".to_string(),
        ));
    }

    Ok(build_success_http_result(
        opts,
        &capture,
        &stats,
        final_resolved_ip,
        dns_ms,
        port,
        deadline,
    )
    .await)
}

fn failed_result(failure_source: &str, message: String) -> ParsedHttp {
    ParsedHttp {
        status: HttpStatus::Failed,
        failure_source: Some(failure_source.to_string()),
        status_code: None,
        status_code_name: None,
        resolved_address: None,
        http_version: None,
        headers: HashMap::new(),
        raw_headers: None,
        raw_body: None,
        truncated: false,
        tls: None,
        timings: HttpTimings::default(),
        raw_output: Some(message),
    }
}

// ── Command ───────────────────────────────────────────────────────────────────

pub struct HttpCommand;

impl HttpCommand {
    /// Execute an HTTP command from a socket payload.
    ///
    /// # Errors
    /// Returns an error for invalid options, DNS/process failures, or serialization failures.
    pub async fn run(&self, options: Value) -> Result<Value> {
        let opts: HttpOptions = serde_json::from_value(options)?;
        let result = run_http(&opts, None).await?;
        Ok(serde_json::to_value(result)?)
    }

    /// Execute an HTTP command while streaming response-body progress.
    ///
    /// # Errors
    /// Returns an error for invalid options, DNS/process failures, or serialization failures.
    pub async fn run_with_progress(&self, options: Value, tx: ProgressTx) -> Result<Value> {
        let opts: HttpOptions = serde_json::from_value(options)?;
        let result = run_http(&opts, Some(tx)).await?;
        Ok(serde_json::to_value(result)?)
    }
}

// ── Public helper for integration tests ───────────────────────────────────────

/// Run one HTTP measurement without the socket layer.
///
/// # Errors
/// Returns an error when validation, DNS resolution, process execution, or result serialization fails.
pub async fn run_measurement(
    target: &str,
    protocol: &str,
    method: &str,
    path: &str,
    resolver: Option<&str>,
    ip_version: u8,
) -> Result<ParsedHttp> {
    let opts = HttpOptions {
        target: target.to_string(),
        resolver: resolver.map(String::from),
        protocol: protocol.to_string(),
        port: None,
        ip_version,
        in_progress_updates: false,
        timeout: 10,
        request: HttpRequestOptions {
            method: method.to_string(),
            host: None,
            path: path.to_string(),
            query: String::new(),
            headers: HashMap::new(),
        },
    };
    run_http(&opts, None).await
}

// ── Security / validation tests ───────────────────────────────────────────────

#[cfg(test)]
mod validate_tests {
    use super::*;

    fn opts() -> HttpOptions {
        HttpOptions {
            target: "example.com".into(),
            resolver: None,
            protocol: "HTTPS".into(),
            port: None,
            ip_version: 4,
            in_progress_updates: false,
            timeout: 10,
            request: HttpRequestOptions {
                method: "HEAD".into(),
                host: None,
                path: "/".into(),
                query: String::new(),
                headers: HashMap::new(),
            },
        }
    }

    #[test]
    fn curl_timeout_phase_messages_match_upstream() {
        assert_eq!(
            curl_timeout_message("", true),
            "Request timed out while establishing the TCP connection."
        );
        assert_eq!(
            curl_timeout_message("* Connected to example.com", true),
            "Request timed out during the TLS handshake."
        );
        assert_eq!(
            curl_timeout_message(
                "* Connected to example.com\n* SSL connection using TLSv1.3",
                true
            ),
            "Request timed out while waiting for the first response byte."
        );
        assert_eq!(
            curl_timeout_message("* Connected to example.com\n< HTTP/1.1 200 OK", true),
            "Request timed out while downloading the response."
        );
        assert_eq!(
            curl_timeout_message("* Connected to example.com", false),
            "Request timed out while waiting for the first response byte."
        );
    }

    #[test]
    fn accepts_clean_request() {
        assert!(validate(&opts()).is_ok());
    }

    #[test]
    fn rejects_host_header_command_injection() {
        // Regression for the enrich_tls RCE: the Host override is used as the TLS
        // servername. Shell syntax here must never be accepted.
        for bad in [
            "evil.com; touch /tmp/pwned",
            "$(id)",
            "`id`",
            "a.com\nb",
            "evil.com -x",
        ] {
            let mut o = opts();
            o.request.host = Some(bad.into());
            assert!(validate(&o).is_err(), "should reject host {bad:?}");
        }
    }

    #[test]
    fn rejects_argument_injection_target() {
        let mut o = opts();
        o.target = "-o/tmp/x".into();
        assert!(validate(&o).is_err());
    }

    #[test]
    fn rejects_private_resolver() {
        let mut o = opts();
        o.resolver = Some("169.254.169.254".into());
        assert!(validate(&o).is_err());
    }

    #[test]
    fn rejects_crlf_in_path_and_query() {
        let mut o = opts();
        o.request.path = "/x\r\nInjected: 1".into();
        assert!(validate(&o).is_err());
        let mut o = opts();
        o.request.query = "a=1 b".into();
        assert!(validate(&o).is_err());
    }

    #[test]
    fn rejects_control_chars_in_headers() {
        let mut o = opts();
        o.request
            .headers
            .insert("X-Foo".into(), "bar\r\nEvil: 1".into());
        assert!(validate(&o).is_err());
    }

    #[test]
    fn extract_pem_pulls_only_cert_block() {
        let s = "noise\n-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\ntrailer";
        let pem = extract_pem(s).expect("should find PEM");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----"));
        assert!(!pem.contains("noise"));
        assert!(!pem.contains("trailer"));
    }

    #[test]
    fn extract_pem_none_when_absent() {
        assert!(extract_pem("no cert here").is_none());
    }
}
