use jiff::Timestamp;
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
    dropped: usize,
    has_logged_discard: bool,
    settings: Settings,
}

// ── Buffer ────────────────────────────────────────────────────────────────────

pub struct ApiLogsBuffer {
    inner: Mutex<Inner>,
    send_lock: tokio::sync::Mutex<()>,
}

impl ApiLogsBuffer {
    #[must_use = "retain the transport to collect and forward logs"]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: VecDeque::new(),
                dropped: 0,
                has_logged_discard: false,
                settings: Settings::default(),
            }),
            send_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn push(&self, entry: LogEntry) {
        let Ok(mut g) = self.inner.lock() else { return };
        g.entries.push_back(entry);
        let max = g.settings.max_buffer_size;
        let overflow = g.entries.len().saturating_sub(max);
        if overflow > 0 {
            g.entries.drain(..overflow);
            g.dropped = g.dropped.saturating_add(overflow);
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

    fn snapshot(&self) -> Option<LogBatch> {
        let g = self.inner.lock().ok()?;
        if !g.settings.is_active || g.entries.is_empty() {
            return None;
        }
        Some(LogBatch {
            payload: json!({ "logs": g.entries, "skipped": g.dropped }),
            present: g.entries.len(),
            skipped: g.dropped,
        })
    }

    fn commit(&self, batch: &LogBatch, discarded: bool) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let lost = g.dropped.saturating_sub(batch.skipped);
        let remaining = batch.present.saturating_sub(lost).min(g.entries.len());
        g.entries.drain(..remaining);
        g.dropped = lost.saturating_sub(batch.present);
        let warn = discarded && !g.has_logged_discard;
        g.has_logged_discard = discarded;
        warn
    }
}

struct LogBatch {
    payload: serde_json::Value,
    present: usize,
    skipped: usize,
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
        // These are internal library messages (transport library internals) that should
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

        let timestamp = crate::util::timestamp::wire_timestamp(Timestamp::now());

        API_LOG_BUFFER.push(LogEntry {
            message: v.0,
            level,
            timestamp,
            scope: scope.to_string(),
        });
    }
}

// ── Background flush loop ─────────────────────────────────────────────────────

use crate::probe::socket::EventSender;
use tokio::time::{Duration, sleep};

pub(crate) async fn flush_logs(client: &EventSender) {
    let _guard = API_LOG_BUFFER.send_lock.lock().await;
    let Some(batch) = API_LOG_BUFFER.snapshot() else {
        return;
    };
    match client
        .emit_with_ack("probe:logs", batch.payload.clone())
        .await
    {
        Ok(response) => match response.first().and_then(serde_json::Value::as_str) {
            Some("success") => {
                API_LOG_BUFFER.commit(&batch, false);
            }
            Some("discard") => {
                if API_LOG_BUFFER.commit(&batch, true) {
                    tracing::warn!(target: "api-connection", "API discarded probe log batch");
                }
            }
            _ => {
                tracing::warn!(target: "api-connection", "Unexpected probe log acknowledgement: {response:?}")
            }
        },
        Err(error) => {
            tracing::warn!(target: "api-connection", "Probe logs retained after delivery failure: {error:#}")
        }
    }
}

pub(crate) async fn run_logs_loop(client: EventSender) {
    loop {
        let interval = API_LOG_BUFFER.send_interval_ms();
        sleep(Duration::from_millis(interval)).await;
        flush_logs(&client).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(message: &str) -> LogEntry {
        LogEntry {
            message: message.to_owned(),
            level: "info".to_owned(),
            timestamp: "2026-01-01T00:00:00.000Z".to_owned(),
            scope: "test".to_owned(),
        }
    }

    #[test]
    fn acknowledgement_removes_only_the_sent_batch_after_overflow() {
        let buffer = ApiLogsBuffer::new();
        buffer.update(Some(true), None, Some(2));
        for message in ["a", "b", "c"] {
            buffer.push(log(message));
        }
        let Some(batch) = buffer.snapshot() else {
            panic!("missing batch")
        };
        assert_eq!(batch.payload["skipped"], 1);
        buffer.push(log("d"));
        assert!(!buffer.commit(&batch, false));
        let Some(next) = buffer.snapshot() else {
            panic!("missing next batch")
        };
        assert_eq!(next.payload["skipped"], 0);
        assert_eq!(next.payload["logs"][0]["message"], "d");
        assert_eq!(next.present, 1);
    }
}
