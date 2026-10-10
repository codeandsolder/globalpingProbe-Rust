use anyhow::Result;
use futures_util::FutureExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Mutex, Notify, watch};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use rust_socketio::{
    Payload, TransportType,
    asynchronous::{Client, ClientBuilder},
};

use crate::command::{
    ProgressSink, ProgressTx, dns::DnsCommand, http::HttpCommand, mtr::MtrCommand,
    ping::PingCommand, traceroute::TracerouteCommand,
};
use crate::probe::progress::ProgressEmitter;
use crate::probe::{
    adoption::{AdoptionServer, local_ips},
    dns_servers::get_dns_servers,
    jobs::ActiveJobs,
    reconnect::{ConnectOutcome, classify_error, reconnect_delay},
    settings::ProbeSettingsStore,
    stats::get_cpu_usage,
    sysinfo::{disk_info_mb, total_memory_bytes},
};
use crate::status::{
    icmp_tcp_test::{DEFAULT_TARGETS as ICMP_TCP_TARGETS, IcmpTcpTest},
    ping_test::PingTest,
    status_manager::StatusManager,
};
use crate::supervisor::bootstrap::{
    BehaviorController, BehaviorDiagnosticAction, BehaviorHealthAction,
};
use crate::supervisor::health::{BehaviorDiagnosticEvent, BehaviorHealthEvent};
use crate::supervisor::runtime::{BehaviorOracle, ResolvedBehaviorOracle, RuntimeError};
use crate::util::logger::{REGISTERED_SCOPES, log_scope_report_delay};
use crate::util::logs_transport::{API_LOG_BUFFER, flush_logs, run_logs_loop};
use crate::util::output_limit::limit_raw_output;
use crate::util::progress_buffer::BufferMode;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const NODE_VERSION: &str = "v22.22.3";

/// Hard time limit for any single measurement. Prevents a hung process from
/// holding a limiter slot indefinitely.
pub const MIN_MEASUREMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often stats are flushed to the API.
pub const STATS_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum time to wait for measurements on ordinary process shutdown.
pub const SIGTERM_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum time to wait when the API explicitly requests a probe restart.
pub const RESTART_DRAIN_TIMEOUT: Duration = Duration::from_secs(40);

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub api_host: String,
    pub uuid: String,
    pub ping_target: String,
    pub adoption_token: Option<String>,
    pub is_hardware: Option<String>,
    pub hardware_device: Option<String>,
    pub hardware_device_firmware: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            api_host: "https://api.globalping.io".into(),
            uuid: String::new(),
            ping_target: "api.globalping.io".into(),
            adoption_token: None,
            is_hardware: None,
            hardware_device: None,
            hardware_device_firmware: None,
        }
    }
}

// ── URL ───────────────────────────────────────────────────────────────────────

/// Build the WebSocket handshake URL with probe metadata as query params.
#[must_use]
pub fn connection_url(cfg: &ClientConfig) -> String {
    let mem = total_memory_bytes();
    let (total_disk, avail_disk) = disk_info_mb();
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("version", VERSION)
        .append_pair("nodeVersion", NODE_VERSION)
        .append_pair("totalMemory", &mem.to_string())
        .append_pair("totalDiskSize", &total_disk.to_string())
        .append_pair("availableDiskSpace", &avail_disk.to_string())
        .append_pair("uuid", &cfg.uuid);
    if let Some(value) = &cfg.is_hardware {
        query.append_pair("isHardware", value);
    }
    if let Some(value) = &cfg.hardware_device {
        query.append_pair("hardwareDevice", value);
    }
    if let Some(value) = &cfg.hardware_device_firmware {
        query.append_pair("hardwareDeviceFirmware", value);
    }
    if let Some(token) = &cfg.adoption_token {
        query.append_pair("adoptionToken", token);
    }
    format!("{}?{}", cfg.api_host, query.finish())
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
    fn progress_mode(&self, options: &Value) -> BufferMode {
        match self {
            Self::Ping
                if options
                    .get("protocol")
                    .and_then(Value::as_str)
                    .is_some_and(|protocol| protocol.eq_ignore_ascii_case("TCP")) =>
            {
                BufferMode::Diff
            }
            Self::Ping | Self::Http => BufferMode::Append,
            Self::Dns | Self::Traceroute => BufferMode::Diff,
            Self::Mtr => BufferMode::Overwrite,
        }
    }

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
            Self::Dns => DnsCommand.run_with_progress(options, tx).await,
            Self::Traceroute => TracerouteCommand.run_with_progress(options, tx).await,
            Self::Mtr => MtrCommand.run_with_progress(options, tx).await,
            Self::Http => HttpCommand.run_with_progress(options, tx).await,
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

async fn apply_behavior_health(
    controller: &BehaviorController,
    sequence: u64,
    event: BehaviorHealthEvent,
) {
    match controller.observe_health(sequence, event).await {
        Ok(BehaviorHealthAction::None) => {}
        Ok(BehaviorHealthAction::IgnoredStaleSequence) => {
            debug!(
                target: "behavior-runtime",
                behavior_sequence = sequence,
                "Ignored health result from a behavior slot that is no longer active."
            );
        }
        Ok(BehaviorHealthAction::ThresholdReachedNoPrevious) => {
            warn!(
                target: "behavior-runtime",
                behavior_sequence = sequence,
                "Behavior health threshold reached, but no previous verified slot exists for rollback."
            );
        }
        Ok(BehaviorHealthAction::RolledBack {
            from_sequence,
            to_sequence,
        }) => {
            warn!(
                target: "behavior-runtime",
                from_sequence,
                to_sequence,
                "Behavior health threshold triggered automatic local rollback."
            );
        }
        Err(error) => {
            warn!(
                target: "behavior-runtime",
                behavior_sequence = sequence,
                %error,
                "Behavior health accounting could not complete rollback."
            );
        }
    }
}

async fn apply_behavior_diagnostic(
    controller: &BehaviorController,
    sequence: u64,
    event: BehaviorDiagnosticEvent,
    measurement_id: &str,
    measurement_type: &str,
    build_id: &str,
) {
    match controller.observe_diagnostic(sequence, event).await {
        BehaviorDiagnosticAction::None => {}
        BehaviorDiagnosticAction::FirstDivergence => {
            warn!(
                target: "behavior-runtime",
                measurement_id,
                measurement_type,
                behavior_sequence = sequence,
                behavior_build_id = build_id,
                "Verified behavior produced its first structurally valid divergence from the native diagnostic oracle; divergence is diagnostic-only and does not advance rollback."
            );
        }
        BehaviorDiagnosticAction::IgnoredStaleSequence => {
            debug!(
                target: "behavior-runtime",
                behavior_sequence = sequence,
                "Ignored oracle diagnostic from a behavior slot that is no longer active."
            );
        }
    }
}

#[cfg(test)]
static FORCE_BEHAVIOR_DIVERGENCE: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static FORCED_BEHAVIOR_MATCHES: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static BEHAVIOR_PRESTART_FALLBACKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static BEHAVIOR_COMPONENT_AUTHORITIES: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static BEHAVIOR_DIAGNOSTIC_COMPLETIONS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
async fn wait_for_behavior_diagnostics(expected: usize) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while BEHAVIOR_DIAGNOSTIC_COMPLETIONS.load(Ordering::SeqCst) < expected {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {expected} behavior diagnostics"));
}

const fn behavior_error_health_event(error: &RuntimeError) -> BehaviorHealthEvent {
    if error.is_component_health_fault() {
        BehaviorHealthEvent::RuntimeFault
    } else {
        BehaviorHealthEvent::Inconclusive
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BehaviorResultAuthority {
    Component,
    OracleFallback,
}

fn log_behavior_error(
    error: &RuntimeError,
    after_native_start: bool,
    measurement_id: &str,
    measurement_type: &str,
    sequence: u64,
    build_id: &str,
) -> BehaviorHealthEvent {
    let event = behavior_error_health_event(error);
    warn!(
        target: "behavior-runtime",
        measurement_id,
        measurement_type,
        behavior_sequence = sequence,
        behavior_build_id = build_id,
        component_health_fault = error.is_component_health_fault(),
        %error,
        phase = if after_native_start { "post-start" } else { "pre-start" },
        "Behavior execution failed."
    );
    event
}

#[allow(
    clippy::too_many_arguments,
    reason = "diagnostic task needs immutable measurement identity plus execution metadata"
)]
async fn record_behavior_diagnostic(
    controller: &BehaviorController,
    resolved: &ResolvedBehaviorOracle,
    component: &Value,
    measurement_id: &str,
    measurement_type: &str,
    sequence: u64,
    build_id: &str,
    progress_events: usize,
    streamed_progress: bool,
    #[cfg(test)] original_component: Option<&Value>,
) {
    #[cfg(test)]
    if original_component
        .is_some_and(|original| resolved.error.is_none() && original == &resolved.value)
    {
        FORCED_BEHAVIOR_MATCHES.fetch_add(1, Ordering::SeqCst);
    }

    let event = resolved.error.as_deref().map_or_else(
        || {
            if component == &resolved.value {
                debug!(
                    target: "behavior-runtime",
                    measurement_id,
                    measurement_type,
                    behavior_sequence = sequence,
                    behavior_build_id = build_id,
                    progress_events,
                    streamed_progress,
                    "Behavior result matched its native diagnostic oracle."
                );
                BehaviorDiagnosticEvent::Match
            } else {
                debug!(
                    target: "behavior-runtime",
                    measurement_id,
                    measurement_type,
                    behavior_sequence = sequence,
                    behavior_build_id = build_id,
                    progress_events,
                    streamed_progress,
                    "Behavior result diverged from its native diagnostic oracle; the result remains authoritative and divergence is diagnostic-only."
                );
                BehaviorDiagnosticEvent::Divergence
            }
        },
        |error| {
            warn!(
                target: "behavior-runtime",
                measurement_id,
                measurement_type,
                behavior_sequence = sequence,
                behavior_build_id = build_id,
                oracle_error = error,
                "Native execution failed after an authoritative behavior result was already available."
            );
            BehaviorDiagnosticEvent::OracleFailure
        },
    );

    apply_behavior_diagnostic(
        controller,
        sequence,
        event,
        measurement_id,
        measurement_type,
        build_id,
    )
    .await;

    #[cfg(test)]
    BEHAVIOR_DIAGNOSTIC_COMPLETIONS.fetch_add(1, Ordering::SeqCst);
}

#[allow(
    clippy::too_many_arguments,
    reason = "diagnostic task owns immutable measurement identity plus execution metadata"
)]
async fn finish_behavior_diagnostic(
    controller: Arc<BehaviorController>,
    oracle: BehaviorOracle,
    component: Value,
    measurement_id: String,
    measurement_type: String,
    sequence: u64,
    build_id: String,
    progress_events: usize,
    streamed_progress: bool,
    #[cfg(test)] original_component: Option<Value>,
) {
    let resolved = oracle.resolve().await;
    record_behavior_diagnostic(
        &controller,
        &resolved,
        &component,
        &measurement_id,
        &measurement_type,
        sequence,
        &build_id,
        progress_events,
        streamed_progress,
        #[cfg(test)]
        original_component.as_ref(),
    )
    .await;
}

async fn finish_behavior_fault(
    controller: &BehaviorController,
    oracle: BehaviorOracle,
    error: &RuntimeError,
    measurement_id: &str,
    measurement_type: &str,
    sequence: u64,
    build_id: &str,
) -> Value {
    let resolved = oracle.resolve().await;
    let health_event = resolved.error.as_deref().map_or_else(
        || {
            log_behavior_error(
                error,
                true,
                measurement_id,
                measurement_type,
                sequence,
                build_id,
            )
        },
        |oracle_error| {
            warn!(
                target: "behavior-runtime",
                measurement_id,
                measurement_type,
                behavior_sequence = sequence,
                behavior_build_id = build_id,
                oracle_error,
                "Native execution failed while behavior fault fallback was required."
            );
            BehaviorHealthEvent::Inconclusive
        },
    );
    apply_behavior_health(controller, sequence, health_event).await;
    let authority = BehaviorResultAuthority::OracleFallback;
    debug!(
        target: "behavior-runtime",
        measurement_id,
        measurement_type,
        behavior_sequence = sequence,
        behavior_build_id = build_id,
        ?authority,
        "Selected final measurement result after behavior fault."
    );
    resolved.value
}

#[allow(
    clippy::too_many_arguments,
    reason = "success handling needs immutable measurement identity plus execution metadata"
)]
async fn finish_behavior_success(
    controller: &Arc<BehaviorController>,
    oracle: BehaviorOracle,
    component: Value,
    measurement_id: &str,
    measurement_type: &str,
    sequence: u64,
    build_id: &str,
    progress_events: usize,
    streamed_progress: bool,
) -> Value {
    #[cfg(test)]
    let (component, original_component) = if FORCE_BEHAVIOR_DIVERGENCE.load(Ordering::SeqCst) {
        let original = component.clone();
        let mut divergent = component;
        divergent["__forcedHealthTestDivergence"] = Value::Bool(true);
        (divergent, Some(original))
    } else {
        (component, None)
    };

    if let Some(resolved) = oracle.try_resolve() {
        if resolved.error.is_some() {
            record_behavior_diagnostic(
                controller,
                &resolved,
                &component,
                measurement_id,
                measurement_type,
                sequence,
                build_id,
                progress_events,
                streamed_progress,
                #[cfg(test)]
                original_component.as_ref(),
            )
            .await;
            let authority = BehaviorResultAuthority::OracleFallback;
            debug!(
                target: "behavior-runtime",
                measurement_id,
                measurement_type,
                behavior_sequence = sequence,
                behavior_build_id = build_id,
                ?authority,
                "Selected native failure result because the oracle had already failed."
            );
            return resolved.value;
        }

        apply_behavior_health(controller, sequence, BehaviorHealthEvent::Success).await;
        record_behavior_diagnostic(
            controller,
            &resolved,
            &component,
            measurement_id,
            measurement_type,
            sequence,
            build_id,
            progress_events,
            streamed_progress,
            #[cfg(test)]
            original_component.as_ref(),
        )
        .await;
    } else {
        apply_behavior_health(controller, sequence, BehaviorHealthEvent::Success).await;
        let diagnostic_component = component.clone();
        tokio::spawn(finish_behavior_diagnostic(
            Arc::clone(controller),
            oracle,
            diagnostic_component,
            measurement_id.to_string(),
            measurement_type.to_string(),
            sequence,
            build_id.to_string(),
            progress_events,
            streamed_progress,
            #[cfg(test)]
            original_component,
        ));
    }

    #[cfg(test)]
    BEHAVIOR_COMPONENT_AUTHORITIES.fetch_add(1, Ordering::SeqCst);
    let authority = BehaviorResultAuthority::Component;
    debug!(
        target: "behavior-runtime",
        measurement_id,
        measurement_type,
        behavior_sequence = sequence,
        behavior_build_id = build_id,
        ?authority,
        "Selected final measurement result without waiting for a pending diagnostic oracle."
    );
    component
}

async fn run_behavior_measurement(
    behavior_controller: Option<&Arc<BehaviorController>>,
    measurement: &Value,
    measurement_id: &str,
    measurement_type: &str,
    behavior_progress_sink: Option<ProgressSink>,
) -> Option<Result<Value, RuntimeError>> {
    let controller = behavior_controller?;
    let executor = controller.executor().await?;
    let sequence = executor.sequence();
    let build_id = executor.build_id().to_string();
    let execution_result = executor
        .run_with_behavior_progress(measurement.clone(), behavior_progress_sink)
        .await;

    let result = match execution_result {
        Ok(result) => result,
        Err(error) => {
            let health_event = log_behavior_error(
                &error,
                false,
                measurement_id,
                measurement_type,
                sequence,
                &build_id,
            );
            apply_behavior_health(controller, sequence, health_event).await;
            return Some(Err(error));
        }
    };

    let oracle = result.oracle_handle();
    let progress_events = result.progress.len();
    let streamed_progress = result.progress_during_native_execution;

    match result.component {
        Ok(component) => Some(Ok(finish_behavior_success(
            controller,
            oracle,
            component,
            measurement_id,
            measurement_type,
            sequence,
            &build_id,
            progress_events,
            streamed_progress,
        )
        .await)),
        Err(error) => Some(Ok(finish_behavior_fault(
            controller,
            oracle,
            &error,
            measurement_id,
            measurement_type,
            sequence,
            &build_id,
        )
        .await)),
    }
}

async fn run_measurement(
    cmd: &CommandKind,
    measurement: Value,
    behavior_controller: Option<&Arc<BehaviorController>>,
    measurement_id: &str,
    measurement_type: &str,
    progress_sink: Option<ProgressSink>,
) -> Result<Value> {
    if let Some(shared) = run_behavior_measurement(
        behavior_controller,
        &measurement,
        measurement_id,
        measurement_type,
        progress_sink.clone(),
    )
    .await
    {
        match shared {
            Ok(native) => return Ok(native),
            Err(error) => {
                #[cfg(test)]
                BEHAVIOR_PRESTART_FALLBACKS.fetch_add(1, Ordering::SeqCst);
                warn!(
                    target: "behavior-runtime",
                    measurement_id,
                    measurement_type,
                    %error,
                    "Behavior failed before native execution started; falling back to the ordinary native path."
                );
            }
        }
    }

    match progress_sink {
        Some(sink) => {
            let mode = cmd.progress_mode(&measurement);
            cmd.run_with_progress(measurement, sink.fixed(mode)).await
        }
        None => cmd.run(measurement).await,
    }
}

/// Run one measurement job and emit the result back to the API.
///
/// The `ActiveJob` guard tracks stats and graceful shutdown for the API-visible
/// measurement lifetime; upstream-compatible dispatch imposes no local cap.
pub async fn dispatch(
    req: MeasurementRequest,
    client: Client,
    status_manager: Arc<Mutex<StatusManager>>,
    jobs: ActiveJobs,
    behavior_controller: Option<Arc<BehaviorController>>,
) {
    let mid = req.measurement_id.clone();
    let tid = req.test_id.clone();

    let current_status = status_manager.lock().await.get_status().to_string();
    if current_status != "ready" {
        warn!("Measurement was sent to probe with {current_status} status.");
        return;
    }

    let mtype = req
        .measurement
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let Some(cmd) = make_command(mtype) else {
        warn!("Unknown measurement type: {mtype}");
        return;
    };
    let _job = jobs.start();

    let in_progress = req
        .measurement
        .get("inProgressUpdates")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    debug!("{mtype} request {mid} received.");

    let measurement_fut = async {
        if in_progress {
            let (progress_sink, rx) = ProgressSink::channel();
            let emitter = ProgressEmitter::new(client.clone(), tid.clone(), mid.clone());
            let emitter_task = tokio::spawn(emitter.forward(rx));
            let result = run_measurement(
                &cmd,
                req.measurement.clone(),
                behavior_controller.as_ref(),
                &mid,
                mtype,
                Some(progress_sink),
            )
            .await;
            let _ = emitter_task.await;
            result
        } else {
            run_measurement(
                &cmd,
                req.measurement.clone(),
                behavior_controller.as_ref(),
                &mid,
                mtype,
                None,
            )
            .await
        }
    };

    let requested_timeout = req
        .measurement
        .get("timeout")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(MIN_MEASUREMENT_TIMEOUT.as_secs());
    let measurement_timeout = Duration::from_secs(
        requested_timeout
            .saturating_add(2)
            .max(MIN_MEASUREMENT_TIMEOUT.as_secs()),
    );
    let run_result: Result<Value> = tokio::time::timeout(measurement_timeout, measurement_fut)
        .await
        .unwrap_or_else(|_| {
            warn!(
                "Measurement {mid} timed out after {}s.",
                measurement_timeout.as_secs()
            );
            Ok(json!({
                "status": "failed",
                "failureSource": "internal",
                "rawOutput": "Measurement timed out."
            }))
        });

    let mut result_json = match run_result {
        Ok(v) => v,
        Err(e) => {
            error!(target: "general", "Failed to run the measurement: {e}");
            json!({ "status": "failed", "failureSource": "internal", "rawOutput": e.to_string() })
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

/// Background task: report per-CPU utilization and active jobs every 10 seconds.
pub async fn run_stats_loop(jobs: ActiveJobs, client: Client) {
    loop {
        tokio::time::sleep(STATS_INTERVAL).await;
        match get_cpu_usage().await {
            Ok(load) => {
                client
                    .emit(
                        "probe:stats:report",
                        json!({
                            "cpu": { "load": load },
                            "jobs": { "count": jobs.count() },
                        }),
                    )
                    .await
                    .ok();
            }
            Err(error) => {
                warn!(target: "probe-stats-reporter", %error, "Failed to collect CPU usage");
            }
        }
    }
}

// ── Status loop ───────────────────────────────────────────────────────────────

// Status checks run independently below: connectivity ping every 10 minutes,
// ICMP/TCP VPN detection every hour, matching the official probe.
async fn run_ping_status_cycle(
    status: &Arc<Mutex<StatusManager>>,
    client: &Client,
    ping_target: &str,
) {
    let (ipv4, ipv6) = PingTest::new().run_once(ping_target).await;
    let current_status = {
        let mut mgr = status.lock().await;
        mgr.ping_test_failed = Some(!ipv4 && !ipv6);
        mgr.get_status().to_string()
    };
    client
        .emit("probe:isIPv4Supported:update", json!(ipv4))
        .await
        .ok();
    client
        .emit("probe:isIPv6Supported:update", json!(ipv6))
        .await
        .ok();
    client
        .emit("probe:status:update", json!(current_status))
        .await
        .ok();
    client
        .emit("probe:dns:update", json!(get_dns_servers()))
        .await
        .ok();
}

async fn run_icmp_tcp_status_cycle(status: &Arc<Mutex<StatusManager>>, client: &Client) {
    let initial_proxy = status.lock().await.icmp_tcp_test.is_proxy();
    let mut test = IcmpTcpTest::new();
    if let Some(is_proxy) = initial_proxy {
        test.set_is_proxy(is_proxy);
    }

    let mut failed = if initial_proxy.is_some() {
        Some(test.run_once(ICMP_TCP_TARGETS).await)
    } else {
        test.measure_once(ICMP_TCP_TARGETS).await;
        None
    };

    let latest_proxy = status.lock().await.icmp_tcp_test.is_proxy();
    if latest_proxy != initial_proxy
        && let Some(is_proxy) = latest_proxy
    {
        test.set_is_proxy(is_proxy);
        if test.is_vpn_detected() {
            test.measure_once(ICMP_TCP_TARGETS).await;
        }
        failed = Some(test.is_vpn_detected());
    }

    let current_status = {
        let mut mgr = status.lock().await;
        mgr.icmp_tcp_test = test;
        mgr.icmp_tcp_test_failed = failed;
        mgr.recheck_disconnect_status();
        mgr.get_status().to_string()
    };
    client
        .emit("probe:status:update", json!(current_status))
        .await
        .ok();
}

/// Run the upstream status checks on their independent schedules: connectivity
/// ping every 10 minutes and ICMP/TCP VPN detection every hour.
pub async fn run_status_loop(
    status: Arc<Mutex<StatusManager>>,
    client: Client,
    ping_target: String,
) {
    let ping_loop = async {
        loop {
            run_ping_status_cycle(&status, &client, &ping_target).await;
            tokio::time::sleep(Duration::from_mins(10)).await;
        }
    };
    let icmp_tcp_loop = async {
        loop {
            run_icmp_tcp_status_cycle(&status, &client).await;
            tokio::time::sleep(Duration::from_hours(1)).await;
        }
    };
    tokio::join!(ping_loop, icmp_tcp_loop);
}

// ── Single connection attempt ─────────────────────────────────────────────────

#[derive(Clone)]
struct ConnectionHandlers {
    status_manager: Arc<Mutex<StatusManager>>,
    settings: Arc<ProbeSettingsStore>,
    adoption: Arc<AdoptionServer>,
    is_hardware: bool,
    jobs: ActiveJobs,
    behavior_controller: Option<Arc<BehaviorController>>,
    signal: OutcomeSignal,
    already_connected: Arc<AtomicBool>,
}

impl ConnectionHandlers {
    fn new(
        status_manager: Arc<Mutex<StatusManager>>,
        settings: Arc<ProbeSettingsStore>,
        adoption: Arc<AdoptionServer>,
        is_hardware: bool,
        behavior_controller: Option<Arc<BehaviorController>>,
    ) -> Self {
        Self {
            status_manager,
            settings,
            adoption,
            is_hardware,
            jobs: ActiveJobs::new(),
            behavior_controller,
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
    debug!(target: "api-connection", "Connection to API established.");
}

async fn handle_close(state: ConnectionHandlers, payload: Payload, client: Client) {
    let reason = extract_first_string(&payload).unwrap_or_default();
    debug!(target: "api-connection", "Disconnected from API: ({reason}).");
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
        error!(target: "api-connection", "Connection to API failed: {message}");
    }
    if matches!(outcome, ConnectOutcome::ProbePolicyError) && message.contains("ip limit") {
        let ip = ip_address.as_deref().unwrap_or("");
        error!(target: "api-connection",
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
            target: "probe-location",
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

async fn handle_adoption(state: ConnectionHandlers, payload: Payload, client: Client) {
    let Some(value) = extract_first_value(&payload) else {
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
        "warn" => warn!(target: "adoption-status", "{message}"),
        "error" => error!(target: "adoption-status", "{message}"),
        _ => info!(target: "adoption-status", "{message}"),
    }

    let adopted = value
        .get("adopted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !adopted && state.is_hardware {
        match state.adoption.start().await {
            Ok(session) => {
                client
                    .emit(
                        "probe:adoption:ready",
                        json!({
                            "token": session.token,
                            "expiresAt": session.expires_at,
                            "ips": local_ips(32),
                        }),
                    )
                    .await
                    .ok();
            }
            Err(error) => {
                error!(target: "adoption-server", %error, "Failed to start local adoption server.");
            }
        }
    } else {
        state.adoption.stop().await;
    }
}

fn handle_adoption_code(payload: &Payload) {
    let Some(value) = extract_first_value(payload) else {
        return;
    };
    let Some(code) = value.get("code").and_then(Value::as_str) else {
        return;
    };
    warn!(
        target: "adoption-code",
        "Your adoption code is: {code}"
    );
}

async fn handle_settings(state: ConnectionHandlers, payload: Payload, client: Client) {
    let Some(settings) = extract_first_value(&payload) else {
        return;
    };
    if state.settings.update(&settings).await {
        client.emit("probe:settings:update", settings).await.ok();
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

    let needs_confirmation = {
        let mut manager = state.status_manager.lock().await;
        manager.on_proxy_status(is_proxy)
    };

    if needs_confirmation {
        let mut confirmation = IcmpTcpTest::new();
        confirmation.set_is_proxy(is_proxy);
        confirmation.measure_once(ICMP_TCP_TARGETS).await;

        let mut manager = state.status_manager.lock().await;
        let latest_proxy = manager.icmp_tcp_test.is_proxy().unwrap_or(is_proxy);
        confirmation.set_is_proxy(latest_proxy);
        manager.icmp_tcp_test_failed = Some(confirmation.is_vpn_detected());
        manager.icmp_tcp_test = confirmation;
    }

    let status = state.status_manager.lock().await.get_status().to_string();
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
                state.jobs,
                state.behavior_controller,
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
    let restart = state.clone();
    let adoption = state.clone();
    let settings = state.clone();
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
        .on("probe:sigkill", move |_, _| {
            let state = restart.clone();
            async move {
                info!(
                    "Probe restart requested by the API; draining {} active jobs.",
                    state.jobs.count()
                );
                state.signal.signal(ConnectOutcome::RestartRequested).await;
            }
            .boxed()
        })
        .on("api:connect:location", |payload, client| {
            async move { handle_location(payload, client).await }.boxed()
        })
        .on("api:connect:adoption", move |payload, client| {
            let state = adoption.clone();
            async move { handle_adoption(state, payload, client).await }.boxed()
        })
        .on("api:connect:ip", |payload, client| {
            async move { handle_ip(&payload, client) }.boxed()
        })
        .on("api:settings:update", move |payload, client| {
            let state = settings.clone();
            async move { handle_settings(state, payload, client).await }.boxed()
        })
        .on("api:connect:isProxy", move |payload, client| {
            let state = proxy.clone();
            async move { handle_proxy(state, payload, client).await }.boxed()
        })
        .on("api:logs-transport:set", |payload, _| {
            async move { handle_logs_transport(&payload) }.boxed()
        })
        .on("probe:adoption:code", |payload, _| {
            async move { handle_adoption_code(&payload) }.boxed()
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
    log_scopes: tokio::task::JoinHandle<()>,
}

impl ConnectionTasks {
    fn spawn(state: &ConnectionHandlers, socket: &Client, ping_target: &str) -> Self {
        Self {
            health: tokio::spawn(run_status_loop(
                Arc::clone(&state.status_manager),
                socket.clone(),
                ping_target.to_string(),
            )),
            metrics: tokio::spawn(run_stats_loop(state.jobs.clone(), socket.clone())),
            logs: tokio::spawn(run_logs_loop(socket.clone())),
            log_scopes: tokio::spawn(report_log_scopes(socket.clone())),
        }
    }

    fn abort(self) {
        self.health.abort();
        self.metrics.abort();
        self.logs.abort();
        self.log_scopes.abort();
    }
}

async fn report_log_scopes(client: Client) {
    tokio::time::sleep(log_scope_report_delay()).await;
    client
        .emit("probe:log-scopes", json!(REGISTERED_SCOPES))
        .await
        .ok();
}

async fn graceful_shutdown(state: &ConnectionHandlers, socket: &Client, drain_timeout: Duration) {
    state.status_manager.lock().await.set_sigterm();
    socket
        .emit("probe:status:update", json!("sigterm"))
        .await
        .ok();
    let active_jobs = state.jobs.count();
    if active_jobs > 0
        && tokio::time::timeout(drain_timeout, state.jobs.wait_idle())
            .await
            .is_err()
    {
        warn!(
            "Shutdown timeout after {}s with {} active jobs. Force closing.",
            drain_timeout.as_secs(),
            state.jobs.count()
        );
    }
    flush_logs(socket).await;
}

/// Connect once and run until shutdown, an API-requested restart, or disconnect.
async fn connect_once(
    cfg: &ClientConfig,
    status_manager: Arc<Mutex<StatusManager>>,
    settings: Arc<ProbeSettingsStore>,
    adoption: Arc<AdoptionServer>,
    behavior_controller: Option<Arc<BehaviorController>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> ConnectOutcome {
    let state = ConnectionHandlers::new(
        status_manager,
        settings,
        adoption,
        cfg.is_hardware.is_some(),
        behavior_controller,
    );
    let builder = ClientBuilder::new(connection_url(cfg))
        .transport_type(TransportType::Websocket)
        .namespace("/probes");
    let socket = match register_socket_handlers(builder, &state).connect().await {
        Ok(socket) => socket,
        Err(error) => {
            error!(target: "api-connection", "Connection to API failed: {error}");
            return ConnectOutcome::Transient;
        }
    };

    let tasks = ConnectionTasks::spawn(&state, &socket, &cfg.ping_target);
    let outcome = tokio::select! {
        _ = shutdown_rx.changed() => ConnectOutcome::CleanShutdown,
        outcome = state.signal.wait() => outcome,
    };
    tasks.abort();

    match outcome {
        ConnectOutcome::CleanShutdown => {
            graceful_shutdown(&state, &socket, SIGTERM_DRAIN_TIMEOUT).await;
        }
        ConnectOutcome::RestartRequested => {
            graceful_shutdown(&state, &socket, RESTART_DRAIN_TIMEOUT).await;
        }
        _ => {}
    }
    socket.disconnect().await.ok();
    outcome
}

// ── Main entry point ──────────────────────────────────────────────────────────

/// Connect to the Globalping API and run with automatic reconnection until shutdown.
///
/// # Errors
/// Returns an error if process-signal setup or a fatal client operation fails.
pub async fn run(cfg: ClientConfig) -> Result<()> {
    run_with_behavior_controller(cfg, None).await
}

/// Connect to the Globalping API with an optional trusted behavior controller.
///
/// The controller supplies only verified/self-tested behavior executors. When
/// enabled, WASM and the native diagnostic oracle share one supervisor-owned
/// execution. A successful structurally valid component result is authoritative
/// and does not wait for pending native shaping/enrichment; the sequence-gated
/// oracle comparison completes independently and cannot mutate rollback streak
/// state. Post-start component faults wait for the same-run native result and
/// fall back without rerunning the measurement. Verified WASM progress is
/// API-facing when behavior is active; native progress is suppressed on that
/// shared execution and is used only for native-only or pre-start fallback paths.
///
/// # Errors
/// Returns an error if process-signal setup or a fatal client operation fails.
pub async fn run_with_behavior_controller(
    cfg: ClientConfig,
    behavior_controller: Option<Arc<BehaviorController>>,
) -> Result<()> {
    let status = Arc::new(Mutex::new(StatusManager::with_api_host(&cfg.ping_target)));
    let settings = Arc::new(ProbeSettingsStore::production());
    let adoption = Arc::new(AdoptionServer::production());

    info!(
        "Starting probe version {VERSION} in a production mode with UUID {}.",
        &cfg.uuid[..cfg.uuid.len().min(8)]
    );
    if cfg.is_hardware.is_some() {
        let device = cfg
            .hardware_device
            .as_deref()
            .and_then(|value| value.strip_prefix('v'))
            .unwrap_or("unknown");
        let firmware = cfg
            .hardware_device_firmware
            .as_deref()
            .and_then(|value| value.strip_prefix('v'))
            .unwrap_or("unknown");
        info!(target: "general", "Hardware probe version {device} running firmware version {firmware}.");
    }

    // One signal handler for the entire lifetime of the process.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if let Err(error) = wait_for_signal().await {
            error!(%error, "Failed to install process signal handler.");
            return;
        }
        let _ = shutdown_tx.send(true);
    });

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        let outcome = connect_once(
            &cfg,
            Arc::clone(&status),
            Arc::clone(&settings),
            Arc::clone(&adoption),
            behavior_controller.clone(),
            shutdown_rx.clone(),
        )
        .await;

        match reconnect_delay(&outcome) {
            None => {
                if matches!(outcome, ConnectOutcome::InvalidVersion) {
                    info!(target: "api-connection", "Detected an outdated probe. Restarting.");
                    std::process::exit(0);
                }
                break;
            }
            Some(delay) => {
                match &outcome {
                    ConnectOutcome::ProbePolicyError => {
                        error!(target: "api-connection", "Retrying in 1 hour. Probe temporarily disconnected.");
                    }
                    ConnectOutcome::MetadataError => {
                        error!(target: "api-connection", "Retrying in 1 minute. Probe temporarily disconnected.");
                    }
                    ConnectOutcome::ServerTerminating => {
                        debug!(target: "api-connection", "The server is terminating. Connecting to another one.");
                    }
                    _ => {}
                }
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

    adoption.stop().await;
    debug!(target: "general", "Closing process.");
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

    #[cfg(target_os = "linux")]
    use std::num::NonZeroU32;
    #[cfg(target_os = "linux")]
    use std::path::Path;

    #[cfg(target_os = "linux")]
    use ed25519_dalek::{Signer as _, SigningKey};
    #[cfg(target_os = "linux")]
    use semver::Version;
    #[cfg(target_os = "linux")]
    use sha2::{Digest as _, Sha256};

    #[cfg(target_os = "linux")]
    use crate::supervisor::bootstrap::BehaviorBootstrapConfig;
    #[cfg(target_os = "linux")]
    use crate::supervisor::health::BehaviorHealthPolicy;
    #[cfg(target_os = "linux")]
    use crate::supervisor::storage::PersistentBehaviorSlots;
    #[cfg(target_os = "linux")]
    use crate::supervisor::update::{BehaviorManifest, SUPPORTED_ABI_MAJOR, SUPPORTED_ABI_MINOR};

    fn cfg(uuid: &str) -> ClientConfig {
        ClientConfig {
            api_host: "https://api.globalping.io".into(),
            uuid: uuid.into(),
            ping_target: "api.globalping.io".into(),
            adoption_token: None,
            is_hardware: None,
            hardware_device: None,
            hardware_device_firmware: None,
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

    #[test]
    fn url_includes_hardware_metadata() {
        let mut c = cfg("u");
        c.is_hardware = Some("true".into());
        c.hardware_device = Some("v1".into());
        c.hardware_device_firmware = Some("v2.3".into());
        let url = connection_url(&c);
        assert!(url.contains("isHardware=true"), "url: {url}");
        assert!(url.contains("hardwareDevice=v1"), "url: {url}");
        assert!(url.contains("hardwareDeviceFirmware=v2.3"), "url: {url}");
    }

    // ── OutcomeSignal ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn outcome_signal_delivers_first_value() {
        let sig = OutcomeSignal::new();
        let sig2 = sig.clone();
        tokio::spawn(async move {
            sig2.signal(ConnectOutcome::ProbePolicyError).await;
        });
        let outcome = sig.wait().await;
        assert_eq!(outcome, ConnectOutcome::ProbePolicyError);
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

    #[test]
    fn tcp_ping_uses_diff_progress_buffering() {
        let options = json!({ "type": "ping", "protocol": "TCP" });
        assert!(matches!(
            CommandKind::Ping.progress_mode(&options),
            BufferMode::Diff
        ));
        let icmp = json!({ "type": "ping", "protocol": "ICMP" });
        assert!(matches!(
            CommandKind::Ping.progress_mode(&icmp),
            BufferMode::Append
        ));
    }

    #[test]
    fn attributable_behavior_error_advances_fault_health() {
        assert_eq!(
            behavior_error_health_event(&RuntimeError::GuestInvalidOutput("bad shape".to_string())),
            BehaviorHealthEvent::RuntimeFault
        );
    }

    #[test]
    fn ambiguous_guest_internal_error_is_inconclusive() {
        assert_eq!(
            behavior_error_health_event(&RuntimeError::GuestInternal("fixture".to_string())),
            BehaviorHealthEvent::Inconclusive
        );
    }

    #[cfg(target_os = "linux")]
    fn live_behavior_cases() -> [Value; 6] {
        [
            json!({
                "type": "ping", "target": "1.1.1.1", "protocol": "ICMP",
                "packets": 2, "ipVersion": 4, "timeout": 10, "inProgressUpdates": true
            }),
            json!({
                "type": "ping", "target": "1.1.1.1", "protocol": "TCP", "port": 443,
                "packets": 2, "ipVersion": 4, "timeout": 10, "inProgressUpdates": true
            }),
            json!({
                "type": "dns", "target": "example.com", "protocol": "UDP", "port": 53,
                "resolver": null, "trace": false, "query": {"type": "A"},
                "ipVersion": 4, "timeout": 10, "inProgressUpdates": true
            }),
            json!({
                "type": "traceroute", "target": "1.1.1.1", "protocol": "ICMP", "port": 80,
                "ipVersion": 4, "timeout": 10, "inProgressUpdates": true
            }),
            json!({
                "type": "mtr", "target": "1.1.1.1", "protocol": "ICMP", "port": 80,
                "packets": 2, "ipVersion": 4, "timeout": 10, "inProgressUpdates": true
            }),
            json!({
                "type": "http", "target": "example.com", "protocol": "HTTPS",
                "ipVersion": 4, "timeout": 10, "inProgressUpdates": true,
                "request": {"method": "GET", "path": "/", "query": "", "headers": {}}
            }),
        ]
    }

    #[cfg(target_os = "linux")]
    fn health_test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x47; 32])
    }

    #[cfg(target_os = "linux")]
    fn signed_health_test_component(
        path: &Path,
        sequence: u64,
        build_id: &str,
    ) -> (BehaviorManifest, Vec<u8>) {
        let component = std::fs::read(path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let signing_key = health_test_signing_key();
        let digest = Sha256::digest(&component);
        let mut manifest = BehaviorManifest {
            sequence,
            abi_major: SUPPORTED_ABI_MAJOR,
            abi_minor: SUPPORTED_ABI_MINOR,
            min_supervisor_version: env!("CARGO_PKG_VERSION").to_string(),
            size: u64::try_from(component.len())
                .unwrap_or_else(|error| panic!("component size does not fit in u64: {error}")),
            sha256: hex::encode(digest),
            build_id: build_id.to_string(),
            signature: String::new(),
        };
        manifest.signature = hex::encode(signing_key.sign(&manifest.signing_payload()).to_bytes());
        (manifest, component)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network tools/access plus a prebuilt WASIp2 behavior component"]
    async fn live_exact_behavior_results_are_selected_for_all_six_measurements() {
        let component_path = std::env::var_os("GLOBALPING_BEHAVIOR_HEALTH_COMPONENT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                panic!("GLOBALPING_BEHAVIOR_HEALTH_COMPONENT must point to the release component")
            });
        let root = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let config =
            BehaviorBootstrapConfig::new(root.path(), health_test_signing_key().verifying_key());
        let controller = BehaviorController::load(config)
            .await
            .unwrap_or_else(|error| panic!("behavior controller bootstrap failed: {error}"));
        let (manifest, component) =
            signed_health_test_component(&component_path, 1, "authority-healthy");
        controller
            .activate_candidate(manifest, component)
            .await
            .unwrap_or_else(|error| panic!("behavior activation failed: {error}"));

        BEHAVIOR_COMPONENT_AUTHORITIES.store(0, Ordering::SeqCst);
        BEHAVIOR_PRESTART_FALLBACKS.store(0, Ordering::SeqCst);
        BEHAVIOR_DIAGNOSTIC_COMPLETIONS.store(0, Ordering::SeqCst);
        for (index, measurement) in live_behavior_cases().into_iter().enumerate() {
            let measurement_type = measurement["type"]
                .as_str()
                .unwrap_or_else(|| panic!("test measurement is missing type"));
            let selected = run_behavior_measurement(
                Some(&controller),
                &measurement,
                &format!("authority-{index}-{measurement_type}"),
                measurement_type,
                None,
            )
            .await
            .unwrap_or_else(|| panic!("active behavior executor must exist"))
            .unwrap_or_else(|error| panic!("shared behavior execution failed: {error}"));
            assert!(selected.get("status").is_some());
        }

        assert_eq!(BEHAVIOR_COMPONENT_AUTHORITIES.load(Ordering::SeqCst), 6);
        assert_eq!(BEHAVIOR_PRESTART_FALLBACKS.load(Ordering::SeqCst), 0);
        wait_for_behavior_diagnostics(6).await;
        let health = controller.health_snapshot().await;
        assert_eq!(health.active_sequence, Some(1));
        assert_eq!(health.matches, 6);
        assert_eq!(health.consecutive_faults, 0);
        assert_eq!(health.divergences, 0);
        assert_eq!(health.runtime_faults, 0);
        assert_eq!(health.inconclusive, 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network tools/access plus a prebuilt WASIp2 behavior component"]
    async fn live_behavior_health_records_all_six_divergences_without_rollback() {
        let component_path = std::env::var_os("GLOBALPING_BEHAVIOR_HEALTH_COMPONENT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                panic!("GLOBALPING_BEHAVIOR_HEALTH_COMPONENT must point to the release component")
            });
        let root = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let threshold =
            NonZeroU32::new(1).unwrap_or_else(|| panic!("health threshold must be non-zero"));
        let config =
            BehaviorBootstrapConfig::new(root.path(), health_test_signing_key().verifying_key())
                .with_health_policy(BehaviorHealthPolicy::new(threshold));
        let controller = BehaviorController::load(config)
            .await
            .unwrap_or_else(|error| panic!("behavior controller bootstrap failed: {error}"));

        let (normal_manifest, normal_component) =
            signed_health_test_component(&component_path, 1, "health-normal");
        controller
            .activate_candidate(normal_manifest, normal_component)
            .await
            .unwrap_or_else(|error| panic!("normal behavior activation failed: {error}"));
        let (active_manifest, active_component) =
            signed_health_test_component(&component_path, 2, "health-test-active");
        controller
            .activate_candidate(active_manifest, active_component)
            .await
            .unwrap_or_else(|error| panic!("test behavior activation failed: {error}"));

        struct ForcedDivergenceGuard;
        impl Drop for ForcedDivergenceGuard {
            fn drop(&mut self) {
                FORCE_BEHAVIOR_DIVERGENCE.store(false, Ordering::SeqCst);
            }
        }
        FORCED_BEHAVIOR_MATCHES.store(0, Ordering::SeqCst);
        BEHAVIOR_DIAGNOSTIC_COMPLETIONS.store(0, Ordering::SeqCst);
        FORCE_BEHAVIOR_DIVERGENCE.store(true, Ordering::SeqCst);
        let _forced_divergence = ForcedDivergenceGuard;

        let cases = live_behavior_cases();
        for (index, measurement) in cases.into_iter().enumerate() {
            let measurement_type = measurement["type"]
                .as_str()
                .unwrap_or_else(|| panic!("test measurement is missing type"));
            let shared = run_behavior_measurement(
                Some(&controller),
                &measurement,
                &format!("health-{index}-{measurement_type}"),
                measurement_type,
                None,
            )
            .await
            .unwrap_or_else(|| panic!("active behavior executor must exist"));
            shared.unwrap_or_else(|error| panic!("shared behavior execution failed: {error}"));
            wait_for_behavior_diagnostics(index + 1).await;

            assert_eq!(controller.active_sequence().unwrap_or(None), Some(2));
            let health = controller.health_snapshot().await;
            assert_eq!(health.active_sequence, Some(2));
            assert_eq!(health.consecutive_faults, 0);
            assert_eq!(
                health.divergences,
                u64::try_from(index + 1).unwrap_or(u64::MAX)
            );
            assert_eq!(health.runtime_faults, 0);
            assert_eq!(health.inconclusive, 0);
        }

        assert_eq!(FORCED_BEHAVIOR_MATCHES.load(Ordering::SeqCst), 6);
        assert_eq!(controller.active_sequence().unwrap_or(None), Some(2));
        assert_eq!(controller.accepted_sequence().unwrap_or_default(), 2);
        assert!(controller.has_previous().unwrap_or(false));
        let executor = controller
            .executor()
            .await
            .unwrap_or_else(|| panic!("active executor must exist"));
        assert_eq!(executor.sequence(), 2);
        assert_eq!(executor.build_id(), "health-test-active");
        let health = controller.health_snapshot().await;
        assert_eq!(health.active_sequence, Some(2));
        assert_eq!(health.consecutive_faults, 0);
        assert_eq!(health.divergences, 6);
        assert_eq!(health.runtime_faults, 0);
        assert_eq!(health.inconclusive, 0);

        let persisted = PersistentBehaviorSlots::load(
            root.path(),
            &health_test_signing_key().verifying_key(),
            &Version::parse(env!("CARGO_PKG_VERSION"))
                .unwrap_or_else(|error| panic!("package version is invalid semver: {error}")),
        )
        .unwrap_or_else(|error| panic!("persisted behavior reload failed: {error}"));
        assert_eq!(persisted.active().manifest.sequence, 2);
        assert_eq!(persisted.active().manifest.build_id, "health-test-active");
        assert_eq!(persisted.accepted_sequence(), 2);
        let previous = persisted
            .previous()
            .unwrap_or_else(|| panic!("previous verified slot must remain available"));
        assert_eq!(previous.manifest.sequence, 1);
        assert_eq!(previous.manifest.build_id, "health-normal");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network access plus a post-start-fault WASIp2 behavior fixture"]
    async fn live_post_start_behavior_fault_preserves_native_without_fallback() {
        let component_path = std::env::var_os("GLOBALPING_BEHAVIOR_FAULT_COMPONENT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                panic!("GLOBALPING_BEHAVIOR_FAULT_COMPONENT must point to the fault fixture")
            });
        let root = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let config =
            BehaviorBootstrapConfig::new(root.path(), health_test_signing_key().verifying_key());
        let controller = BehaviorController::load(config)
            .await
            .unwrap_or_else(|error| panic!("behavior controller bootstrap failed: {error}"));
        let (manifest, component) =
            signed_health_test_component(&component_path, 1, "post-start-fault");
        controller
            .activate_candidate(manifest, component)
            .await
            .unwrap_or_else(|error| panic!("fault fixture activation failed: {error}"));

        BEHAVIOR_PRESTART_FALLBACKS.store(0, Ordering::SeqCst);
        let measurement = json!({
            "type": "ping",
            "target": "1.1.1.1",
            "protocol": "TCP",
            "port": 443,
            "packets": 1,
            "ipVersion": 4,
            "timeout": 10,
            "inProgressUpdates": true
        });
        let (progress_sink, mut progress_rx) = ProgressSink::channel();
        let result = run_measurement(
            &CommandKind::Ping,
            measurement,
            Some(&controller),
            "post-start-fault",
            "ping",
            Some(progress_sink),
        )
        .await
        .unwrap_or_else(|error| panic!("shared native execution failed: {error}"));

        let mut progress = Vec::new();
        while let Ok(update) = progress_rx.try_recv() {
            progress.push(update.resolve());
        }
        assert_eq!(
            progress.len(),
            2,
            "native progress must not be mixed into the WASM stream"
        );
        assert!(
            progress[0]["rawOutput"]
                .as_str()
                .is_some_and(|raw| raw.contains("tcp_conn=1"))
        );
        assert_eq!(
            progress[1]["rawOutput"],
            "__post_start_fault_fixture_progress__"
        );
        assert_eq!(BEHAVIOR_PRESTART_FALLBACKS.load(Ordering::SeqCst), 0);
        assert!(result.get("status").is_some());
        assert!(result.get("rawOutput").is_some());
        let health = controller.health_snapshot().await;
        assert_eq!(health.active_sequence, Some(1));
        assert_eq!(health.consecutive_faults, 1);
        assert_eq!(health.runtime_faults, 1);
        assert_eq!(health.divergences, 0);
        assert_eq!(health.inconclusive, 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network access plus normal and divergent WASIp2 behavior fixtures"]
    async fn live_signed_valid_divergence_is_authoritative_and_remains_active() {
        let normal_path = std::env::var_os("GLOBALPING_BEHAVIOR_HEALTH_COMPONENT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                panic!("GLOBALPING_BEHAVIOR_HEALTH_COMPONENT must point to the release component")
            });
        let divergent_path = std::env::var_os("GLOBALPING_BEHAVIOR_DIVERGENCE_COMPONENT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                panic!(
                    "GLOBALPING_BEHAVIOR_DIVERGENCE_COMPONENT must point to the divergence fixture"
                )
            });
        let root = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let threshold =
            NonZeroU32::new(1).unwrap_or_else(|| panic!("health threshold must be non-zero"));
        let config =
            BehaviorBootstrapConfig::new(root.path(), health_test_signing_key().verifying_key())
                .with_health_policy(BehaviorHealthPolicy::new(threshold));
        let controller = BehaviorController::load(config)
            .await
            .unwrap_or_else(|error| panic!("behavior controller bootstrap failed: {error}"));

        let (normal_manifest, normal_component) =
            signed_health_test_component(&normal_path, 1, "divergence-normal");
        controller
            .activate_candidate(normal_manifest, normal_component)
            .await
            .unwrap_or_else(|error| panic!("normal behavior activation failed: {error}"));
        let (divergent_manifest, divergent_component) =
            signed_health_test_component(&divergent_path, 2, "divergence-authoritative");
        controller
            .activate_candidate(divergent_manifest, divergent_component)
            .await
            .unwrap_or_else(|error| panic!("divergent behavior activation failed: {error}"));

        BEHAVIOR_PRESTART_FALLBACKS.store(0, Ordering::SeqCst);
        BEHAVIOR_DIAGNOSTIC_COMPLETIONS.store(0, Ordering::SeqCst);
        let result = run_measurement(
            &CommandKind::Ping,
            json!({
                "type": "ping", "target": "1.1.1.1", "protocol": "TCP", "port": 443,
                "packets": 1, "ipVersion": 4, "timeout": 10, "inProgressUpdates": false
            }),
            Some(&controller),
            "signed-divergence",
            "ping",
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("shared behavior execution failed: {error}"));
        wait_for_behavior_diagnostics(1).await;

        assert!(result.get("status").and_then(Value::as_str).is_some());
        assert!(
            result["rawOutput"]
                .as_str()
                .is_some_and(|raw| raw.contains("__intentional_divergence__"))
        );
        assert_eq!(BEHAVIOR_PRESTART_FALLBACKS.load(Ordering::SeqCst), 0);
        assert_eq!(controller.active_sequence().unwrap_or(None), Some(2));
        assert_eq!(controller.accepted_sequence().unwrap_or_default(), 2);
        let executor = controller
            .executor()
            .await
            .unwrap_or_else(|| panic!("divergent executor must remain active"));
        assert_eq!(executor.build_id(), "divergence-authoritative");
        let health = controller.health_snapshot().await;
        assert_eq!(health.active_sequence, Some(2));
        assert_eq!(health.consecutive_faults, 0);
        assert_eq!(health.divergences, 1);
        assert_eq!(health.runtime_faults, 0);
        assert_eq!(health.inconclusive, 0);

        let persisted = PersistentBehaviorSlots::load(
            root.path(),
            &health_test_signing_key().verifying_key(),
            &Version::parse(env!("CARGO_PKG_VERSION"))
                .unwrap_or_else(|error| panic!("package version is invalid semver: {error}")),
        )
        .unwrap_or_else(|error| panic!("persisted behavior reload failed: {error}"));
        assert_eq!(persisted.active().manifest.sequence, 2);
        assert_eq!(
            persisted.active().manifest.build_id,
            "divergence-authoritative"
        );
        assert_eq!(persisted.accepted_sequence(), 2);
        assert_eq!(
            persisted
                .previous()
                .unwrap_or_else(|| panic!("previous verified slot must remain"))
                .manifest
                .sequence,
            1
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network access plus normal and invalid-output WASIp2 behavior fixtures"]
    async fn live_signed_invalid_output_falls_back_and_rolls_back() {
        let normal_path = std::env::var_os("GLOBALPING_BEHAVIOR_HEALTH_COMPONENT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                panic!("GLOBALPING_BEHAVIOR_HEALTH_COMPONENT must point to the release component")
            });
        let invalid_path = std::env::var_os("GLOBALPING_BEHAVIOR_INVALID_OUTPUT_COMPONENT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                panic!(
                    "GLOBALPING_BEHAVIOR_INVALID_OUTPUT_COMPONENT must point to the invalid-output fixture"
                )
            });
        let root = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let threshold =
            NonZeroU32::new(1).unwrap_or_else(|| panic!("health threshold must be non-zero"));
        let config =
            BehaviorBootstrapConfig::new(root.path(), health_test_signing_key().verifying_key())
                .with_health_policy(BehaviorHealthPolicy::new(threshold));
        let controller = BehaviorController::load(config)
            .await
            .unwrap_or_else(|error| panic!("behavior controller bootstrap failed: {error}"));

        let (normal_manifest, normal_component) =
            signed_health_test_component(&normal_path, 1, "invalid-output-normal");
        controller
            .activate_candidate(normal_manifest, normal_component)
            .await
            .unwrap_or_else(|error| panic!("normal behavior activation failed: {error}"));
        let (invalid_manifest, invalid_component) =
            signed_health_test_component(&invalid_path, 2, "invalid-output-active");
        controller
            .activate_candidate(invalid_manifest, invalid_component)
            .await
            .unwrap_or_else(|error| panic!("invalid-output behavior activation failed: {error}"));

        BEHAVIOR_PRESTART_FALLBACKS.store(0, Ordering::SeqCst);
        let result = run_measurement(
            &CommandKind::Ping,
            json!({
                "type": "ping", "target": "1.1.1.1", "protocol": "TCP", "port": 443,
                "packets": 1, "ipVersion": 4, "timeout": 10, "inProgressUpdates": false
            }),
            Some(&controller),
            "signed-invalid-output",
            "ping",
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("shared behavior execution failed: {error}"));

        assert!(result.get("status").is_some());
        assert!(result.get("rawOutput").is_some());
        assert!(result.get("__intentionalInvalidOutput").is_none());
        assert_eq!(BEHAVIOR_PRESTART_FALLBACKS.load(Ordering::SeqCst), 0);
        assert_eq!(controller.active_sequence().unwrap_or(None), Some(1));
        assert_eq!(controller.accepted_sequence().unwrap_or_default(), 2);
        let executor = controller
            .executor()
            .await
            .unwrap_or_else(|| panic!("rolled-back executor must exist"));
        assert_eq!(executor.build_id(), "invalid-output-normal");

        let persisted = PersistentBehaviorSlots::load(
            root.path(),
            &health_test_signing_key().verifying_key(),
            &Version::parse(env!("CARGO_PKG_VERSION"))
                .unwrap_or_else(|error| panic!("package version is invalid semver: {error}")),
        )
        .unwrap_or_else(|error| panic!("persisted behavior reload failed: {error}"));
        assert_eq!(persisted.active().manifest.sequence, 1);
        assert_eq!(
            persisted.active().manifest.build_id,
            "invalid-output-normal"
        );
        assert_eq!(persisted.accepted_sequence(), 2);
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
        assert_eq!(classify_error(raw), ConnectOutcome::ProbePolicyError);
    }
}
