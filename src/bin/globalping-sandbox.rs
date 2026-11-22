use std::io::{self, BufRead as _, Write as _};

use globalping_probe::parsers::{dns, http, mtr, ping, traceroute};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
#[serde(tag = "parser", rename_all = "kebab-case")]
enum ParseRequest {
    Ping {
        raw: String,
    },
    Traceroute {
        raw: String,
    },
    DnsClassic {
        raw: String,
    },
    DnsTrace {
        raw: String,
    },
    Mtr {
        raw: String,
        #[serde(default = "default_true")]
        is_final: bool,
    },
    HttpHeaders {
        raw: String,
    },
    HttpTls {
        verbose: String,
        #[serde(default)]
        ssl_verify_result: u32,
    },
}

const fn default_true() -> bool {
    true
}

fn parse_request(request: ParseRequest) -> Value {
    match request {
        ParseRequest::Ping { raw } => json!(ping::parse(&raw)),
        ParseRequest::Traceroute { raw } => json!(traceroute::parse(&raw)),
        ParseRequest::DnsClassic { raw } => json!(dns::parse_classic(&raw)),
        ParseRequest::DnsTrace { raw } => json!(dns::parse_trace(&raw)),
        ParseRequest::Mtr { raw, is_final } => {
            let hops = mtr::parse_raw(&raw, is_final);
            let raw_output = mtr::build_output(&hops);
            json!({ "hops": hops, "rawOutput": raw_output })
        }
        ParseRequest::HttpHeaders { raw } => {
            let pairs = http::parse_header_file(&raw);
            json!({
                "statusText": http::parse_status_text(&raw),
                "headers": http::dedup_headers(&pairs),
            })
        }
        ParseRequest::HttpTls {
            verbose,
            ssl_verify_result,
        } => json!(http::parse_tls_verbose(&verbose, ssl_verify_result)),
    }
}

fn handle_line(line: &str) -> Value {
    match serde_json::from_str::<ParseRequest>(line) {
        Ok(request) => json!({ "ok": true, "result": parse_request(request) }),
        Err(error) => json!({ "ok": false, "error": error.to_string() }),
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        serde_json::to_writer(&mut stdout, &handle_line(&line))?;
        stdout.write_all(b"\n")?;
    }
    stdout.flush()
}
