use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, sleep_until};
use tracing::warn;

use crate::command::{LazyProgress, ProgressUpdate};
use crate::util::output_limit::limit_raw_output;
use crate::util::progress_buffer::{BufferMode, ProgressBuffer};
use rust_socketio::asynchronous::Client;

pub const PROGRESS_INTERVAL: Duration = Duration::from_millis(500);

/// Receives partial string fields from a command and forwards coalesced
/// `probe:measurement:progress` events using the same modes as upstream.
pub struct ProgressEmitter {
    client: Client,
    test_id: String,
    measurement_id: String,
    buffer: Option<ProgressBuffer>,
    pending_lazy: Option<(LazyProgress, BufferMode)>,
}

impl ProgressEmitter {
    pub fn new(
        client: Client,
        test_id: impl Into<String>,
        measurement_id: impl Into<String>,
    ) -> Self {
        Self {
            client,
            test_id: test_id.into(),
            measurement_id: measurement_id.into(),
            buffer: None,
            pending_lazy: None,
        }
    }

    fn ensure_mode(&mut self, mode: BufferMode) -> bool {
        match self.buffer.as_ref() {
            Some(buffer) if buffer.mode() != mode => {
                warn!(
                    "Ignoring progress mode change for {}: {:?} -> {:?}",
                    self.measurement_id,
                    buffer.mode(),
                    mode
                );
                false
            }
            Some(_) => true,
            None => {
                self.buffer = Some(ProgressBuffer::new(mode));
                true
            }
        }
    }

    fn merge(&mut self, partial: Value, mode: BufferMode) {
        if !self.ensure_mode(mode) {
            return;
        }
        let Value::Object(fields) = partial else {
            return;
        };
        let Some(buffer) = self.buffer.as_mut() else {
            return;
        };
        for (field, value) in fields {
            if let Some(value) = value.as_str() {
                buffer.push(&field, value);
            }
        }
    }

    fn merge_update(&mut self, update: ProgressUpdate) {
        match update {
            ProgressUpdate::Value { value, mode } => self.merge(value, mode),
            ProgressUpdate::Lazy { render, mode } => {
                if self.ensure_mode(mode) {
                    self.pending_lazy = Some((render, mode));
                }
            }
        }
    }

    async fn emit_buffer(&mut self) {
        if let Some((render, mode)) = self.pending_lazy.take() {
            self.merge(render(), mode);
        }
        let Some(buffer) = self.buffer.as_mut() else {
            return;
        };
        if buffer.is_empty() {
            return;
        }
        let fields = buffer.take_progress();
        if fields.values().all(String::is_empty) {
            return;
        }
        let overwrite = buffer.overwrite();
        let mut partial = Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, Value::String(value)))
                .collect::<Map<_, _>>(),
        );
        limit_raw_output(&mut partial);
        if let Err(error) = self
            .client
            .emit(
                "probe:measurement:progress",
                json!({
                    "testId": self.test_id,
                    "measurementId": self.measurement_id,
                    "overwrite": overwrite,
                    "result": partial,
                }),
            )
            .await
        {
            warn!(
                "Failed to emit progress for {}: {error}",
                self.measurement_id
            );
        }
    }

    /// Drain partial progress until the producer closes. The first update is sent
    /// immediately; later updates are coalesced for 500 ms. Pending progress is
    /// discarded when the producer closes because the final result supersedes it.
    pub async fn forward(mut self, mut rx: mpsc::UnboundedReceiver<ProgressUpdate>) {
        let mut first = true;
        let mut deadline: Option<Instant> = None;
        loop {
            if let Some(at) = deadline {
                tokio::select! {
                    message = rx.recv() => {
                        let Some(message) = message else { return; };
                        self.merge_update(message);
                    }
                    () = sleep_until(at) => {
                        self.emit_buffer().await;
                        deadline = None;
                    }
                }
            } else {
                let Some(message) = rx.recv().await else {
                    return;
                };
                self.merge_update(message);
                if first {
                    first = false;
                    self.emit_buffer().await;
                } else {
                    deadline = Some(Instant::now() + PROGRESS_INTERVAL);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_matches_upstream() {
        assert_eq!(PROGRESS_INTERVAL, Duration::from_millis(500));
    }

    #[test]
    fn buffer_modes_have_expected_overwrite_flag() {
        assert!(!ProgressBuffer::new(BufferMode::Append).overwrite());
        assert!(!ProgressBuffer::new(BufferMode::Diff).overwrite());
        assert!(ProgressBuffer::new(BufferMode::Overwrite).overwrite());
    }
}
