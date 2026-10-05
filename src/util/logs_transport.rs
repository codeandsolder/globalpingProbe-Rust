use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use tracing::{Event, Subscriber};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

pub static API_LOG_BUFFER: std::sync::LazyLock<ApiLogsBuffer> =
    std::sync::LazyLock::new(ApiLogsBuffer::new);

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub message: String,
    pub level: String,
    pub timestamp: String,
    pub scope: String,
}

struct Settings {
    is_active: bool,
    send_interval_ms: u64,
    max_buffer_size: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            is_active: false,
            send_interval_ms: 10_000,
            max_buffer_size: 100,
        }
    }
}

struct Inner {
    entries: VecDeque<LogEntry>,
    dropped: u64,
    settings: Settings,
}

// ── Buffer ────────────────────────────────────────────────────────────────────

pub struct ApiLogsBuffer {
    inner: Mutex<Inner>,
}

impl ApiLogsBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: VecDeque::new(),
                dropped: 0,
                settings: Settings::default(),
            }),
        }
    }

    pub fn push(&self, entry: LogEntry) {
        let Ok(mut g) = self.inner.lock() else { return };
        g.entries.push_back(entry);
        let max = g.settings.max_buffer_size;
        let overflow = g.entries.len().saturating_sub(max);
        if overflow > 0 {
            g.entries.drain(..overflow);
            g.dropped += overflow as u64;
        }
    }

    pub fn update(
        &self,
        is_active: Option<bool>,
        send_interval_ms: Option<u64>,
        max_buffer_size: Option<usize>,
    ) {
        let Ok(mut g) = self.inner.lock() else { return };
        if let Some(v) = is_active {
            g.settings.is_active = v;
        }
        if let Some(v) = send_interval_ms {
            g.settings.send_interval_ms = v;
        }
        if let Some(v) = max_buffer_size {
            g.settings.max_buffer_size = v;
        }
    }

    pub fn is_active(&self) -> bool {
        self.inner.lock().is_ok_and(|g| g.settings.is_active)
    }

    pub fn send_interval_ms(&self) -> u64 {
        self.inner
            .lock()
            .map_or(10_000, |g| g.settings.send_interval_ms)
    }

    /// Take buffered entries for sending. Returns None if inactive or empty.
    pub fn take(&self) -> Option<serde_json::Value> {
        let Ok(mut g) = self.inner.lock() else {
            return None;
        };
        if !g.settings.is_active || g.entries.is_empty() {
            return None;
        }
        let logs: Vec<LogEntry> = g.entries.drain(..).collect();
        let skipped = g.dropped;
        g.dropped = 0;
        Some(json!({ "logs": logs, "skipped": skipped }))
    }
}

impl Default for ApiLogsBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tracing layer ─────────────────────────────────────────────────────────────

pub struct ApiLogsLayer;

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for ApiLogsLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = meta.level().as_str().to_lowercase();
        let target = meta.target();
        // "log" is the target used by the tracing-log bridge for the `log` crate.
        // These are internal library messages (rust-socketio internals) that should
        // not appear in API logs, so we skip them here.
        let scope = if target == "log" {
            return;
        } else if target.contains("::") {
            "general"
        } else {
            target
        };

        let mut v = MessageVisitor(String::new());
        event.record(&mut v);

        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        API_LOG_BUFFER.push(LogEntry {
            message: v.0,
            level,
            timestamp,
            scope: scope.to_string(),
        });
    }
}

// ── Background flush loop ─────────────────────────────────────────────────────

use rust_socketio::asynchronous::Client;
use tokio::time::{Duration, sleep};

pub async fn flush_logs(client: &Client) {
    if let Some(payload) = API_LOG_BUFFER.take() {
        client.emit("probe:logs", payload).await.ok();
    }
}

pub async fn run_logs_loop(client: Client) {
    loop {
        let interval = API_LOG_BUFFER.send_interval_ms();
        sleep(Duration::from_millis(interval)).await;
        flush_logs(&client).await;
    }
}
