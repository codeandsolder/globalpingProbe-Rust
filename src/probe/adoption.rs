use anyhow::{Context as _, Result};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, Request, Response, StatusCode, header},
    response::IntoResponse,
};
use chrono::{DateTime, SecondsFormat, Utc};
use if_addrs::get_if_addrs;
use rand::random;
use std::{collections::HashSet, fmt::Write as _, net::SocketAddr, sync::Arc, time::SystemTime};
use tokio::{
    sync::{Mutex, oneshot},
    task::JoinHandle,
    time::Duration,
};
use tracing::{error, warn};

pub const DEFAULT_ADOPTION_PORT: u16 = 7201;
pub const DEFAULT_ADOPTION_LIFETIME: Duration = Duration::from_hours(1);
pub const DEFAULT_DASHBOARD_URL: &str = "https://dash.globalping.io";

#[derive(Debug, Clone)]
pub struct AdoptionSession {
    pub token: String,
    pub expires_at: String,
    pub address: SocketAddr,
}

struct RunningServer {
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

#[derive(Clone)]
struct HttpState {
    token: Arc<str>,
    dashboard_url: Arc<str>,
}

pub struct AdoptionServer {
    port: u16,
    lifetime: Duration,
    dashboard_url: String,
    running: Mutex<Option<RunningServer>>,
}

impl AdoptionServer {
    #[must_use]
    pub fn new(port: u16, lifetime: Duration, dashboard_url: impl Into<String>) -> Self {
        Self {
            port,
            lifetime,
            dashboard_url: dashboard_url.into(),
            running: Mutex::new(None),
        }
    }

    #[must_use]
    pub fn production() -> Self {
        Self::new(
            DEFAULT_ADOPTION_PORT,
            DEFAULT_ADOPTION_LIFETIME,
            DEFAULT_DASHBOARD_URL,
        )
    }

    /// Start a fresh adoption server session, replacing any previous session.
    ///
    /// # Errors
    /// Returns an error when the listening socket cannot be bound or inspected.
    pub async fn start(&self) -> Result<AdoptionSession> {
        self.stop().await;

        let token = random_token();
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", self.port))
            .await
            .with_context(|| format!("failed to bind adoption server on port {}", self.port))?;
        let address = listener.local_addr()?;
        let state = HttpState {
            token: Arc::from(token.as_str()),
            dashboard_url: Arc::from(self.dashboard_url.as_str()),
        };
        let app = Router::new().fallback(adoption_request).with_state(state);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let lifetime = self.lifetime;
        let task = tokio::spawn(async move {
            let shutdown = async move {
                tokio::select! {
                    _ = shutdown_rx => {}
                    () = tokio::time::sleep(lifetime) => {}
                }
            };
            if let Err(error) = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await
            {
                error!(target: "adoption-server", %error, "Adoption server error.");
            }
        });
        *self.running.lock().await = Some(RunningServer {
            shutdown: shutdown_tx,
            task,
        });

        let expires: DateTime<Utc> = (SystemTime::now() + self.lifetime).into();
        Ok(AdoptionSession {
            token,
            expires_at: expires.to_rfc3339_opts(SecondsFormat::Millis, true),
            address,
        })
    }

    pub async fn stop(&self) {
        let running = self.running.lock().await.take();
        if let Some(running) = running {
            let _ = running.shutdown.send(());
            let _ = running.task.await;
        }
    }
}

fn random_token() -> String {
    let bytes: [u8; 32] = random();
    let mut token = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

async fn adoption_request(
    State(state): State<HttpState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let method = request.method();
    let path = request.uri().path();
    let (status, body, content_type, location) = if *method == Method::OPTIONS {
        (StatusCode::NO_CONTENT, String::new(), None, None)
    } else if *method != Method::GET {
        (StatusCode::METHOD_NOT_ALLOWED, String::new(), None, None)
    } else if path == "/" {
        (
            StatusCode::OK,
            serde_json::json!({ "token": state.token.as_ref() }).to_string(),
            Some("application/json; charset=utf-8"),
            None,
        )
    } else if path == "/adopt" {
        (
            StatusCode::TEMPORARY_REDIRECT,
            String::new(),
            None,
            Some(format!("{}?adopt={}", state.dashboard_url, state.token)),
        )
    } else {
        (StatusCode::NOT_FOUND, String::new(), None, None)
    };

    let mut builder = Response::builder()
        .status(status)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS")
        .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type")
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate");
    if let Some(value) = content_type {
        builder = builder.header(header::CONTENT_TYPE, value);
    }
    if let Some(value) = location {
        builder = builder.header(header::LOCATION, value);
    }
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[must_use]
pub fn local_ips(limit: usize) -> Vec<String> {
    let interfaces = match get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(error) => {
            warn!(target: "adoption-server", %error, "Failed to enumerate local IP addresses.");
            return Vec::new();
        }
    };
    let mut seen = HashSet::new();
    let mut ips = Vec::new();
    for interface in interfaces {
        let ip = interface.ip();
        let link_local = match ip {
            std::net::IpAddr::V4(ip) => ip.is_link_local(),
            std::net::IpAddr::V6(ip) => ip.is_unicast_link_local(),
        };
        if ip.is_loopback() || link_local || !seen.insert(ip) {
            continue;
        }
        ips.push(ip.to_string());
        if ips.len() >= limit {
            break;
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn token_is_32_random_bytes_as_hex() {
        let token = random_token();
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn serves_token_redirect_and_cors() -> anyhow::Result<()> {
        let server = AdoptionServer::new(0, Duration::from_secs(10), "https://dash.example");
        let session = server.start().await?;
        let base = format!("http://127.0.0.1:{}", session.address.port());
        let client = reqwest::Client::new();
        let no_redirect = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let root = client.get(&base).send().await?;
        assert_eq!(root.status(), StatusCode::OK);
        assert_eq!(root.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(root.json::<Value>().await?["token"], session.token);

        let adopt = no_redirect.get(format!("{base}/adopt")).send().await?;
        assert_eq!(adopt.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            adopt.headers()[header::LOCATION],
            format!("https://dash.example?adopt={}", session.token)
        );

        let options = client
            .request(Method::OPTIONS, format!("{base}/anything"))
            .send()
            .await?;
        assert_eq!(options.status(), StatusCode::NO_CONTENT);
        server.stop().await;
        server.stop().await;
        Ok(())
    }
}
