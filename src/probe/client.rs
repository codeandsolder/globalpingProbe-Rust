use anyhow::Result;
use futures_util::FutureExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Mutex, Notify, watch};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use rust_socketio::{
    Payload, TransportType,
    asynchronous::{Client, ClientBuilder},
};

use crate::command::{
    ProgressTx, dns::DnsCommand, http::HttpCommand, mtr::MtrCommand, ping::PingCommand,
    traceroute::TracerouteCommand,
};
use crate::probe::progress::ProgressEmitter;
use crate::probe::{
    dns_servers::get_dns_servers,
    limiter::MeasurementLimiter,
    reconnect::{ConnectOutcome, ExponentialBackoff, classify_error, reconnect_delay},
    stats::MeasurementStats,
    sysinfo::{disk_info_mb, total_memory_bytes},
};
use crate::status::{
    icmp_tcp_test::IcmpTcpTest, ping_test::PingTest, status_manager::StatusManager,
};
use crate::util::logs_transport::{API_LOG_BUFFER, run_logs_loop};
use crate::util::output_limit::limit_raw_output;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const NODE_VERSION: &str = "v22.22.3";

/// Hard time limit for any single measurement. Prevents a hung process from
/// holding a limiter slot indefinitely.
pub const MEASUREMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often stats are flushed to the API.
pub const STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum time to wait for in-flight measurements to finish on graceful shutdown.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub api_host: String,
    pub uuid: String,
    pub ping_target: String,
    pub adoption_token: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            api_host: "https://api.globalping.io".into(),
            uuid: String::new(),
            ping_target: "api.globalping.io".into(),
            adoption_token: None,
        }
    }
}

// ── URL ───────────────────────────────────────────────────────────────────────

/// Build the WebSocket handshake URL with probe metadata as query params.
#[must_use]
pub fn connection_url(cfg: &ClientConfig) -> String {
    let mem = total_memory_bytes();
    let (total_disk, avail_disk) = disk_info_mb();
    let mut url = format!(
        "{}?version={VERSION}&nodeVersion={NODE_VERSION}&totalMemory={mem}&totalDiskSize={total_disk}&availableDiskSpace={avail_disk}&uuid={}",
        cfg.api_host, cfg.uuid,
    );
    if let Some(token) = &cfg.adoption_token {
        url.push_str("&adoptionToken=");
        url.push_str(token);
    }
    url
}

// ── Wire types ────────────────────────────────────────────────────────────────

/// Measurement job sent by the API over socket.io.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasurementRequest {
    pub measurement_id: String,
    pub test_id: String,
    pub measurement: Value,
}

// ── Outcome signalling ────────────────────────────────────────────────────────

/// Shared state for communicating disconnect/error outcomes from event handlers
/// back to the outer reconnect loop.  First write wins (subsequent events ignored).
#[derive(Clone)]
struct OutcomeSignal {
    value: Arc<Mutex<Option<ConnectOutcome>>>,
    notify: Arc<Notify>,
}

impl OutcomeSignal {
    fn new() -> Self {
        Self {
            value: Arc::new(Mutex::new(None)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Record the outcome and wake the waiter (only the first call has effect).
    async fn signal(&self, outcome: ConnectOutcome) {
        let should_notify = {
            let mut guard = self.value.lock().await;
            if guard.is_some() {
                false
            } else {
                *guard = Some(outcome);
                true
            }
        };
        if should_notify {
            self.notify.notify_one();
        }
    }

    /// Block until an outcome has been signalled, then return it.
    async fn wait(&self) -> ConnectOutcome {
        loop {
            self.notify.notified().await;
            let outcome = self.value.lock().await.clone();
            if let Some(outcome) = outcome {
                return outcome;
            }
        }
    }
}

// ── Measurement dispatch ──────────────────────────────────────────────────────

enum CommandKind {
    Ping,
    Dns,
    Traceroute,
    Mtr,
    Http,
}

impl CommandKind {
    async fn run(&self, options: Value) -> Result<Value> {
        match self {
            Self::Ping => PingCommand.run(options).await,
            Self::Dns => DnsCommand.run(options).await,
            Self::Traceroute => TracerouteCommand.run(options).await,
            Self::Mtr => MtrCommand.run(options).await,
            Self::Http => HttpCommand.run(options).await,
        }
    }

    async fn run_with_progress(&self, options: Value, tx: ProgressTx) -> Result<Value> {
        match self {
            Self::Ping => PingCommand.run_with_progress(options, tx).await,
            Self::Traceroute => TracerouteCommand.run_with_progress(options, tx).await,
            _ => self.run(options).await,
        }
    }
}

/// Map a measurement type string to its command implementation.
fn make_command(mtype: &str) -> Option<CommandKind> {
    match mtype {
        "ping" => Some(CommandKind::Ping),
        "dns" => Some(CommandKind::Dns),
        "traceroute" => Some(CommandKind::Traceroute),
        "mtr" => Some(CommandKind::Mtr),
        "http" => Some(CommandKind::Http),
        _ => None,
    }
}

/// Run one measurement job and emit the result back to the API.
///
/// `limiter` guards the concurrency cap; the acquired slot is held for the
/// entire duration of the measurement and released automatically when this
/// function returns.
pub async fn dispatch(
    req: MeasurementRequest,
    client: Client,
    status_manager: Arc<Mutex<StatusManager>>,
    limiter: MeasurementLimiter,
    measurement_stats: Arc<MeasurementStats>,
) {
    let mid = req.measurement_id.clone();
    let tid = req.test_id.clone();

    // Concurrency guard — reject if already at capacity.
    let Some(_slot) = limiter.try_acquire() else {
        warn!(
            "Measurement {mid} rejected — already running {} of {} max.",
            limiter.in_flight(),
            limiter.capacity()
        );
        return;
    };

    let current_status = status_manager.lock().await.get_status().to_string();
    if current_status != "ready" {
        warn!("Measurement was sent to probe with {current_status} status.");
        return;
    }

    if let Err(e) = client.emit("probe:measurement:ack", json!(null)).await {
        warn!("Failed to ack measurement {mid}: {e}");
        return;
    }

    let mtype = req
        .measurement
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let Some(cmd) = make_command(mtype) else {
        let result_json = json!({ "status": "failed", "rawOutput": format!("Unknown measurement type: {mtype}") });
        client
            .emit(
                "probe:measurement:result",
                json!({
                    "testId": tid, "measurementId": mid, "result": result_json,
                }),
            )
            .await
            .ok();
        return;
    };

    let in_progress = req
        .measurement
        .get("inProgressUpdates")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    debug!("{mtype} request {mid} received.");
    measurement_stats.record_start();

    let measurement_fut = async {
        if in_progress {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let emitter = ProgressEmitter::new(client.clone(), tid.clone(), mid.clone());
            tokio::spawn(emitter.forward(rx));
            cmd.run_with_progress(req.measurement.clone(), tx).await
        } else {
            cmd.run(req.measurement.clone()).await
        }
    };

    let run_result: Result<Value> = tokio::time::timeout(MEASUREMENT_TIMEOUT, measurement_fut)
        .await
        .unwrap_or_else(|_| {
            warn!(
                "Measurement {mid} timed out after {}s.",
                MEASUREMENT_TIMEOUT.as_secs()
            );
            Ok(json!({ "status": "failed", "rawOutput": "Measurement timed out." }))
        });

    measurement_stats.record_finish();

    let mut result_json = match run_result {
        Ok(v) => v,
        Err(e) => {
            error!(target: "test-error-handler", "Failed to run the measurement: {e}");
            json!({ "status": "failed", "rawOutput": e.to_string() })
        }
    };

    limit_raw_output(&mut result_json);

    if let Err(e) = client
        .emit(
            "probe:measurement:result",
            json!({
                "testId": tid,
                "measurementId": mid,
                "result": result_json,
            }),
        )
        .await
    {
        warn!("Failed to send result for {mid}: {e}");
    }
}

// ── Payload helpers ───────────────────────────────────────────────────────────

pub fn extract_first_value(payload: &Payload) -> Option<Value> {
    match payload {
        Payload::Text(values) => values.first().cloned(),
        _ => None,
    }
}

pub fn extract_first_string(payload: &Payload) -> Option<String> {
    extract_first_value(payload).and_then(|v| v.as_str().map(str::to_string))
}

// ── Stats loop ────────────────────────────────────────────────────────────────

/// Background task: flush measurement counters to the API every minute.
pub async fn run_stats_loop(stats: Arc<MeasurementStats>, client: Client) {
    loop {
        tokio::time::sleep(STATS_INTERVAL).await;
        let (started, finished) = stats.take();
        client
            .emit(
                "probe:stats:report",
                json!({
                    "measurementsStarted":  started,
                    "measurementsFinished": finished,
                }),
            )
            .await
            .ok();
    }
}

// ── Status loop ───────────────────────────────────────────────────────────────

/// Background task: periodic ping + ICMP/TCP health checks every 10 minutes.
/// Also refreshes the DNS server list each cycle.
pub async fn run_status_loop(
    status: Arc<Mutex<StatusManager>>,
    client: Client,
    ping_target: String,
) {
    const INTERVAL: Duration = Duration::from_mins(10);
    const ICMP_TARGETS: &[&str] = &["1.1.1.1", "8.8.8.8", "9.9.9.9"];

    loop {
        let (ipv4, ipv6) = PingTest::new().run_once(&ping_target).await;
        {
            let mut mgr = status.lock().await;
            mgr.ping_test_failed = Some(!ipv4 && !ipv6);
        }
        client
            .emit("probe:isIPv4Supported:update", json!(ipv4))
            .await
            .ok();
        client
            .emit("probe:isIPv6Supported:update", json!(ipv6))
            .await
            .ok();

        let vpn = IcmpTcpTest::new().run_once(ICMP_TARGETS).await;
        {
            let mut mgr = status.lock().await;
            mgr.icmp_tcp_test_failed = Some(vpn);
            // Re-evaluate disconnect status: TTL-expired entries may have cleared.
            mgr.recheck_disconnect_status();
            let st = mgr.get_status().to_string();
            drop(mgr);
            client.emit("probe:status:update", json!(st)).await.ok();
        }

        // Refresh DNS servers in case resolvers changed since last connect.
        client
            .emit("probe:dns:update", json!(get_dns_servers()))
            .await
            .ok();

        tokio::time::sleep(INTERVAL).await;
    }
}

// ── Single connection attempt ─────────────────────────────────────────────────

#[derive(Clone)]
struct ConnectionHandlers {
    status_manager: Arc<Mutex<StatusManager>>,
    limiter: MeasurementLimiter,
    measurement_stats: Arc<MeasurementStats>,
    signal: OutcomeSignal,
    already_connected: Arc<AtomicBool>,
}

impl ConnectionHandlers {
    fn new(status_manager: Arc<Mutex<StatusManager>>) -> Self {
        Self {
            status_manager,
            limiter: MeasurementLimiter::new(),
            measurement_stats: MeasurementStats::new(),
            signal: OutcomeSignal::new(),
            already_connected: Arc::new(AtomicBool::new(false)),
        }
    }
}

async fn handle_open(state: ConnectionHandlers, client: Client) {
    if state.already_connected.swap(true, Ordering::SeqCst) {
        state.signal.signal(ConnectOutcome::Transient).await;
        return;
    }
    let status = state.status_manager.lock().await.get_status().to_string();
    client.emit("probe:status:update", json!(status)).await.ok();
    client
        .emit("probe:dns:update", json!(get_dns_servers()))
        .await
        .ok();
    debug!("Connection to API established.");
}

async fn handle_close(state: ConnectionHandlers, payload: Payload, client: Client) {
    let reason = extract_first_string(&payload).unwrap_or_default();
    debug!(target: "api:error", "Disconnected from API: ({reason}).");
    if reason == "ping timeout" || reason == "transport error" {
        let status = {
            let mut manager = state.status_manager.lock().await;
            manager.report_disconnect();
            manager.get_status().to_string()
        };
        client.emit("probe:status:update", json!(status)).await.ok();
    }
    state.signal.signal(ConnectOutcome::Transient).await;
}

async fn handle_error(state: ConnectionHandlers, payload: Payload) {
    let (message, ip_address) = parse_connect_error(&payload);
    let outcome = classify_error(&message);
    if !matches!(outcome, ConnectOutcome::ServerTerminating) {
        error!(target: "api:error", "Connection to API failed: {message}");
    }
    if matches!(outcome, ConnectOutcome::IpLimitOrVpn) && message.contains("ip limit") {
        let ip = ip_address.as_deref().unwrap_or("");
        error!(target: "api:error",
            "Only 1 connection per IP address is allowed. Please make sure you don't have another probe running on IP {ip}.");
    }
    state.signal.signal(outcome).await;
}

async fn handle_location(payload: Payload, client: Client) {
    if let Some(location) = extract_first_value(&payload) {
        let text = |key: &str| {
            location
                .get(key)
                .and_then(|value| value.as_str())
                .unwrap_or("?")
                .to_string()
        };
        let number = |key: &str| {
            location
                .get(key)
                .and_then(|value| {
                    value
                        .as_f64()
                        .map(|number| number.to_string())
                        .or_else(|| value.as_str().map(str::to_string))
                })
                .unwrap_or_else(|| "?".to_string())
        };
        let asn = location
            .get("asn")
            .and_then(|value| {
                value
                    .as_u64()
                    .map(|number| number.to_string())
                    .or_else(|| value.as_str().map(str::to_string))
            })
            .unwrap_or_else(|| "?".to_string());
        info!(
            target: "api:connect:location",
            "Connected from {}, {}, {} ({}, ASN: {}, lat: {} long: {}).",
            text("city"), text("country"), text("continent"), text("network"), asn,
            number("latitude"), number("longitude"),
        );
    }
    client
        .emit("probe:dns:update", json!(get_dns_servers()))
        .await
        .ok();
}

fn handle_adoption(payload: &Payload) {
    let Some(value) = extract_first_value(payload) else {
        return;
    };
    let message = value
        .get("message")
        .and_then(|field| field.as_str())
        .unwrap_or("");
    match value
        .get("level")
        .and_then(|field| field.as_str())
        .unwrap_or("info")
    {
        "warn" => warn!(target: "api:connect:adoption", "{message}"),
        "error" => error!(target: "api:connect:adoption", "{message}"),
        _ => info!(target: "api:connect:adoption", "{message}"),
    }
}

fn handle_ip(payload: &Payload, client: Client) {
    let Some(value) = extract_first_value(payload) else {
        return;
    };
    let main_ip = value
        .get("ip")
        .and_then(|field| field.as_str())
        .unwrap_or("?")
        .to_string();
    tokio::spawn(async move {
        crate::probe::alt_ips::refresh_alt_ips(&client, "https://api.globalping.io/v1", &main_ip)
            .await;
    });
}

async fn handle_proxy(state: ConnectionHandlers, payload: Payload, client: Client) {
    let Some(value) = extract_first_value(&payload) else {
        return;
    };
    let is_proxy = value
        .get("isProxy")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let status = {
        let mut manager = state.status_manager.lock().await;
        manager.on_proxy_status(is_proxy);
        manager.get_status().to_string()
    };
    client.emit("probe:status:update", json!(status)).await.ok();
}

fn handle_logs_transport(payload: &Payload) {
    let Some(value) = extract_first_value(payload) else {
        return;
    };
    let is_active = value.get("isActive").and_then(serde_json::Value::as_bool);
    let send_interval = value
        .get("sendInterval")
        .and_then(serde_json::Value::as_u64);
    let max_buffer = value
        .get("maxBufferSize")
        .and_then(serde_json::Value::as_u64)
        .and_then(|number| usize::try_from(number).ok());
    API_LOG_BUFFER.update(is_active, send_interval, max_buffer);
}

fn handle_measurement(state: ConnectionHandlers, payload: &Payload, client: Client) {
    let Some(data) = extract_first_value(payload) else {
        warn!("Empty measurement payload");
        return;
    };
    match serde_json::from_value::<MeasurementRequest>(data) {
        Ok(request) => {
            tokio::spawn(dispatch(
                request,
                client,
                state.status_manager,
                state.limiter,
                state.measurement_stats,
            ));
        }
        Err(error) => warn!("Bad measurement request: {error}"),
    }
}

fn register_socket_handlers(builder: ClientBuilder, state: &ConnectionHandlers) -> ClientBuilder {
    let open = state.clone();
    let close = state.clone();
    let error = state.clone();
    let proxy = state.clone();
    let measurement = state.clone();
    builder
        .on("open", move |_, client| {
            let state = open.clone();
            async move { handle_open(state, client).await }.boxed()
        })
        .on("close", move |payload, client| {
            let state = close.clone();
            async move { handle_close(state, payload, client).await }.boxed()
        })
        .on("error", move |payload, _| {
            let state = error.clone();
            async move { handle_error(state, payload).await }.boxed()
        })
        .on("probe:sigkill", |_, _| {
            async move {
                info!("Probe restart requested by the API. Exiting...");
                std::process::exit(0);
            }
            .boxed()
        })
        .on("api:connect:location", |payload, client| {
            async move { handle_location(payload, client).await }.boxed()
        })
        .on("api:connect:adoption", |payload, _| {
            async move { handle_adoption(&payload) }.boxed()
        })
        .on("api:connect:ip", |payload, client| {
            async move { handle_ip(&payload, client) }.boxed()
        })
        .on("api:connect:isProxy", move |payload, client| {
            let state = proxy.clone();
            async move { handle_proxy(state, payload, client).await }.boxed()
        })
        .on("api:logs-transport:set", |payload, _| {
            async move { handle_logs_transport(&payload) }.boxed()
        })
        .on("probe:measurement:request", move |payload, client| {
            let state = measurement.clone();
            async move { handle_measurement(state, &payload, client) }.boxed()
        })
}

struct ConnectionTasks {
    health: tokio::task::JoinHandle<()>,
    metrics: tokio::task::JoinHandle<()>,
    logs: tokio::task::JoinHandle<()>,
}

impl ConnectionTasks {
    fn spawn(state: &ConnectionHandlers, socket: &Client, ping_target: &str) -> Self {
        Self {
            health: tokio::spawn(run_status_loop(
                Arc::clone(&state.status_manager),
                socket.clone(),
                ping_target.to_string(),
            )),
            metrics: tokio::spawn(run_stats_loop(
                Arc::clone(&state.measurement_stats),
                socket.clone(),
            )),
            logs: tokio::spawn(run_logs_loop(socket.clone())),
        }
    }

    fn abort(self) {
        self.health.abort();
        self.metrics.abort();
        self.logs.abort();
    }
}

async fn graceful_shutdown(state: &ConnectionHandlers, socket: &Client) {
    state.status_manager.lock().await.set_sigterm();
    socket
        .emit("probe:status:update", json!("sigterm"))
        .await
        .ok();
    if state.limiter.in_flight() > 0
        && tokio::time::timeout(DRAIN_TIMEOUT, state.limiter.wait_idle())
            .await
            .is_err()
    {
        warn!("SIGTERM timeout. Force closing.");
    }
}

/// Connect once, run until shutdown or disconnect.
/// Returns `(outcome, was_connected)` — `was_connected` is true if the socket.io
/// `connect` event fired at least once, meaning the session was real (not just a
/// handshake failure). The caller uses this to decide whether to reset backoff.
async fn connect_once(
    cfg: &ClientConfig,
    status_manager: Arc<Mutex<StatusManager>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> (ConnectOutcome, bool) {
    let state = ConnectionHandlers::new(status_manager);
    let connected_reader = Arc::clone(&state.already_connected);
    let builder = ClientBuilder::new(connection_url(cfg))
        .transport_type(TransportType::Websocket)
        .namespace("/probes");
    let socket = match register_socket_handlers(builder, &state).connect().await {
        Ok(socket) => socket,
        Err(error) => {
            error!(target: "api:error", "Connection to API failed: {error}");
            return (ConnectOutcome::Transient, false);
        }
    };

    let tasks = ConnectionTasks::spawn(&state, &socket, &cfg.ping_target);
    let outcome = tokio::select! {
        _ = shutdown_rx.changed() => ConnectOutcome::CleanShutdown,
        outcome = state.signal.wait() => outcome,
    };
    tasks.abort();

    if matches!(outcome, ConnectOutcome::CleanShutdown) {
        graceful_shutdown(&state, &socket).await;
    }
    socket.disconnect().await.ok();
    let was_connected = connected_reader.load(Ordering::SeqCst);
    (outcome, was_connected)
}

// ── Main entry point ──────────────────────────────────────────────────────────

/// Connect to the Globalping API and run with automatic reconnection until shutdown.
///
/// # Errors
/// Returns an error if process-signal setup or a fatal client operation fails.
pub async fn run(cfg: ClientConfig) -> Result<()> {
    let status = Arc::new(Mutex::new(StatusManager::with_api_host(&cfg.ping_target)));

    info!(
        "Starting probe version {VERSION} in a production mode with UUID {}.",
        &cfg.uuid[..cfg.uuid.len().min(8)]
    );

    // One signal handler for the entire lifetime of the process.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if let Err(error) = wait_for_signal().await {
            error!(%error, "Failed to install process signal handler.");
            return;
        }
        let _ = shutdown_tx.send(true);
    });

    let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(300));

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        let (outcome, was_connected) =
            connect_once(&cfg, Arc::clone(&status), shutdown_rx.clone()).await;

        match reconnect_delay(&outcome, &mut backoff) {
            None => {
                if matches!(outcome, ConnectOutcome::InvalidVersion) {
                    info!(target: "api:error", "Detected an outdated probe. Restarting.");
                    std::process::exit(1);
                }
                break;
            }
            Some(delay) => {
                // Reset backoff when: outcome is non-transient (explicit server policy),
                // OR the session was real (connect event fired).  Without this, EngineIO
                // errors during a long healthy session would accumulate backoff toward 5 min.
                if !matches!(outcome, ConnectOutcome::Transient) || was_connected {
                    backoff.reset();
                }
                match &outcome {
                    ConnectOutcome::IpLimitOrVpn => {
                        error!(target: "api:error", "Retrying in 1 hour. Probe temporarily disconnected.");
                    }
                    ConnectOutcome::MetadataError => {
                        error!(target: "api:error", "Retrying in 1 minute. Probe temporarily disconnected.");
                    }
                    ConnectOutcome::ServerTerminating => {
                        debug!(target: "api:error", "The server is terminating. Connecting to another one.");
                    }
                    _ => {}
                }
                if !delay.is_zero() {
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        () = async {
                            let mut rx = shutdown_rx.clone();
                            let _ = rx.changed().await;
                        } => break,
                    }
                }
            }
        }
    }

    debug!("Closing process.");
    Ok(())
}

async fn wait_for_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = sigterm.recv()          => { info!("SIGTERM received."); }
            result = tokio::signal::ctrl_c() => {
                result?;
                info!("CTRL-C received.");
            }
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;

    Ok(())
}

// ── Error parsing ─────────────────────────────────────────────────────────────

/// Extract (`inner_message`, `ip_address`) from a socket.io connect-error payload.
///
/// rust-socketio wraps connect errors as:
///   `{ "message": "Received an ConnectError frame: {\"message\":\"ip limit\",\"data\":{...}}" }`
///
/// Node.js receives the inner message directly.  We parse the nested JSON so our
/// logs match the Node.js format exactly.
fn parse_connect_error(payload: &Payload) -> (String, Option<String>) {
    let outer_msg = extract_first_value(payload)
        .and_then(|v| {
            v.get("message")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .or_else(|| extract_first_string(payload))
        .unwrap_or_default();

    // Try to find an embedded JSON object inside the outer message.
    if let Some(json_start) = outer_msg.find('{')
        && let Ok(inner) = serde_json::from_str::<Value>(&outer_msg[json_start..])
    {
        let inner_msg = inner
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or(&outer_msg)
            .to_string();
        let ip = inner
            .get("data")
            .and_then(|d| d.get("ipAddress"))
            .and_then(|ip| ip.as_str())
            .map(str::to_string);
        return (inner_msg, ip);
    }

    (outer_msg, None)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(uuid: &str) -> ClientConfig {
        ClientConfig {
            api_host: "https://api.globalping.io".into(),
            uuid: uuid.into(),
            ping_target: "api.globalping.io".into(),
            adoption_token: None,
        }
    }

    // ── URL building ──────────────────────────────────────────────────────────

    #[test]
    fn url_contains_required_fields() {
        let url = connection_url(&cfg("my-uuid-123"));
        assert!(url.contains("uuid=my-uuid-123"), "url: {url}");
        assert!(url.contains(&format!("version={VERSION}")), "url: {url}");
        assert!(url.contains("totalMemory="), "url: {url}");
        assert!(url.contains("totalDiskSize="), "url: {url}");
        assert!(url.contains("availableDiskSpace="), "url: {url}");
        assert!(url.contains("nodeVersion=v22.22.3"), "url: {url}");
    }

    #[test]
    fn url_base_is_api_host() {
        let url = connection_url(&cfg("x"));
        assert!(url.starts_with("https://api.globalping.io?"), "url: {url}");
    }

    #[test]
    fn url_includes_adoption_token_when_set() {
        let mut c = cfg("u");
        c.adoption_token = Some("mytoken123".into());
        let url = connection_url(&c);
        assert!(url.contains("adoptionToken=mytoken123"), "url: {url}");
    }

    #[test]
    fn url_omits_adoption_token_when_none() {
        let url = connection_url(&cfg("u"));
        assert!(!url.contains("adoptionToken"), "url: {url}");
    }

    // ── OutcomeSignal ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn outcome_signal_delivers_first_value() {
        let sig = OutcomeSignal::new();
        let sig2 = sig.clone();
        tokio::spawn(async move {
            sig2.signal(ConnectOutcome::IpLimitOrVpn).await;
        });
        let outcome = sig.wait().await;
        assert_eq!(outcome, ConnectOutcome::IpLimitOrVpn);
    }

    #[tokio::test]
    async fn outcome_signal_only_first_write_wins() {
        let sig = OutcomeSignal::new();
        sig.signal(ConnectOutcome::MetadataError).await;
        sig.signal(ConnectOutcome::Transient).await; // should be ignored
        let outcome = sig.wait().await;
        assert_eq!(outcome, ConnectOutcome::MetadataError);
    }

    // ── MeasurementRequest deserialisation ────────────────────────────────────

    #[test]
    fn deserialise_ping_request() {
        let raw = json!({
            "measurementId": "abc", "testId": "t1",
            "measurement": { "type": "ping", "target": "1.1.1.1", "packets": 3, "ipVersion": 4, "inProgressUpdates": false }
        });
        let req: MeasurementRequest = serde_json::from_value(raw).unwrap();
        assert_eq!(req.measurement_id, "abc");
        assert_eq!(req.measurement["type"], "ping");
    }

    #[test]
    fn deserialise_dns_request() {
        let raw = json!({ "measurementId": "m1", "testId": "t1",
            "measurement": { "type": "dns", "target": "example.com", "query": {"type":"A"}, "inProgressUpdates": false } });
        let req: MeasurementRequest = serde_json::from_value(raw).unwrap();
        assert_eq!(req.measurement["type"], "dns");
    }

    #[test]
    fn deserialise_http_request() {
        let raw = json!({ "measurementId": "m4", "testId": "t4",
            "measurement": { "type": "http", "target": "1.1.1.1", "protocol": "HTTPS",
                "request": { "method": "HEAD", "path": "/" }, "inProgressUpdates": false } });
        let req: MeasurementRequest = serde_json::from_value(raw).unwrap();
        assert_eq!(req.measurement["type"], "http");
        assert_eq!(req.measurement["protocol"], "HTTPS");
    }

    #[test]
    fn deserialise_missing_field_fails() {
        let raw = json!({ "testId": "t1", "measurement": {} });
        assert!(serde_json::from_value::<MeasurementRequest>(raw).is_err());
    }

    // ── Payload helpers ───────────────────────────────────────────────────────

    #[test]
    fn extract_value_from_text_payload() {
        let p = Payload::Text(vec![json!({"key": "val"})]);
        assert_eq!(extract_first_value(&p).unwrap()["key"], "val");
    }

    #[test]
    fn extract_string_from_text_payload() {
        let p = Payload::Text(vec![json!("hello")]);
        assert_eq!(extract_first_string(&p), Some("hello".into()));
    }

    #[test]
    fn extract_returns_none_for_empty_text() {
        assert!(extract_first_value(&Payload::Text(vec![])).is_none());
    }

    #[test]
    fn extract_returns_none_for_binary() {
        assert!(extract_first_value(&Payload::Binary(bytes::Bytes::new())).is_none());
    }

    // ── Type discriminator ────────────────────────────────────────────────────

    #[test]
    fn dispatch_selects_correct_command_by_type() {
        for ty in &["ping", "dns", "traceroute", "mtr", "http"] {
            let v = json!({ "type": ty });
            let mtype = v["type"].as_str().unwrap_or("");
            assert!(
                matches!(mtype, "ping" | "dns" | "traceroute" | "mtr" | "http"),
                "{ty}"
            );
        }
        let v = json!({ "type": "unknown" });
        let mtype = v["type"].as_str().unwrap_or("");
        assert!(!matches!(
            mtype,
            "ping" | "dns" | "traceroute" | "mtr" | "http"
        ));
    }

    // ── Error message parsing via reconnect ───────────────────────────────────

    #[test]
    fn error_message_json_envelope_is_parsed() {
        // The API sends: {"message":"ip limit","data":{"ipAddress":"..."}}
        let envelope = json!({"message": "ip limit", "data": {"ipAddress": "1.2.3.4"}});
        let raw = envelope
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        assert_eq!(classify_error(raw), ConnectOutcome::IpLimitOrVpn);
    }
}
