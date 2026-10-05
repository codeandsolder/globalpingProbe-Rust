use rust_socketio::asynchronous::Client;
use serde::Deserialize;
use std::net::IpAddr;
use tokio::time::Duration;
use tracing::{info, warn};

enum AltIpError {
    Rejected(String), // HTTP 400 — API explicitly rejected this IP
    Failed(String),   // Any other error
}

/// Enumerate all public IP addresses from local network interfaces.
/// Uses `ip -o addr show scope global` to filter out loopback and link-local.
#[must_use]
pub fn get_local_public_ips() -> Vec<IpAddr> {
    let Ok(out) = std::process::Command::new("ip")
        .args(["-o", "addr", "show", "scope", "global"])
        .output()
    else {
        return vec![];
    };

    let text = String::from_utf8_lossy(&out.stdout);
    let mut ips = Vec::new();

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, &part) in parts.iter().enumerate() {
            if (part == "inet" || part == "inet6") && i + 1 < parts.len() {
                let ip_str = parts[i + 1].split('/').next().unwrap_or("");
                // Exclude link-local IPv6 and IPv4 addresses
                if ip_str.to_lowercase().starts_with("fe80:") || ip_str.starts_with("169.254.") {
                    continue;
                }
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    ips.push(ip);
                }
            }
        }
    }

    ips
}

#[derive(Deserialize)]
struct AltIpResponse {
    ip: String,
    token: String,
}

/// POST to `/alternative-ip` with the request bound to `local_ip` so the API
/// can verify the probe actually owns that address. Returns (ip, token) on success.
async fn fetch_alt_ip_token(
    local_ip: IpAddr,
    http_host: &str,
) -> Result<(String, String), AltIpError> {
    let client = reqwest::Client::builder()
        .local_address(local_ip)
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| AltIpError::Failed(e.to_string()))?;

    let response = client
        .post(format!("{http_host}/alternative-ip"))
        .json(&serde_json::json!({ "localAddress": local_ip.to_string() }))
        .send()
        .await
        .map_err(|e| AltIpError::Failed(e.to_string()))?;

    if response.status() == reqwest::StatusCode::BAD_REQUEST {
        let msg = response.text().await.unwrap_or_default();
        return Err(AltIpError::Rejected(msg));
    }

    let resp: AltIpResponse = response
        .error_for_status()
        .map_err(|e| AltIpError::Failed(e.to_string()))?
        .json()
        .await
        .map_err(|e| AltIpError::Failed(e.to_string()))?;

    Ok((resp.ip, resp.token))
}

/// Discover all local public IPs, fetch ownership tokens for each (excluding the
/// main IP the API already knows), and emit `probe:alt-ips` so the API registers
/// them all for this probe session.
pub async fn refresh_alt_ips(socket: &Client, http_host: &str, main_ip: &str) {
    let local_ips = get_local_public_ips();

    let alt_ips: Vec<IpAddr> = local_ips
        .into_iter()
        .filter(|ip| ip.to_string() != main_ip)
        .collect();

    if alt_ips.is_empty() {
        info!("IP address of the probe: {main_ip}.");
        return;
    }

    let results =
        futures::future::join_all(alt_ips.iter().map(|&ip| fetch_alt_ip_token(ip, http_host)))
            .await;

    let mut tokens: Vec<serde_json::Value> = Vec::new();
    let mut confirmed_ips: Vec<String> = vec![main_ip.to_string()];
    for (ip, result) in alt_ips.iter().zip(results) {
        match result {
            Ok((confirmed_ip, token)) => {
                if !confirmed_ips.contains(&confirmed_ip) {
                    confirmed_ips.push(confirmed_ip.clone());
                }
                tokens.push(serde_json::json!([confirmed_ip, token]));
            }
            Err(AltIpError::Rejected(reason)) => {
                warn!(target: "api:connect:alt-ips-handler", "IP {ip} rejected: {reason}");
            }
            Err(AltIpError::Failed(error)) => {
                warn!(target: "api:connect:alt-ips-handler", "{error} (via {ip}).");
            }
        }
    }

    // Sort so IPv4 addresses appear before IPv6
    confirmed_ips.sort_by_key(|ip| {
        let parsed: std::net::IpAddr = ip
            .parse()
            .ok()
            .unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
        u8::from(matches!(parsed, std::net::IpAddr::V6(_)))
    });
    let noun = if confirmed_ips.len() == 1 {
        "IP address"
    } else {
        "IP addresses"
    };
    info!("{noun} of the probe: {}.", confirmed_ips.join(", "));

    if let Err(e) = socket
        .emit("probe:alt-ips", serde_json::Value::Array(tokens))
        .await
    {
        warn!("Failed to emit probe:alt-ips: {e}");
    }
}
