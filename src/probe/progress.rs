use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, sleep_until};
use tracing::warn;

use crate::util::output_limit::limit_raw_output;
use crate::util::progress_buffer::{BufferMode, ProgressBuffer};
use rust_socketio::asynchronous::Client;

pub const PROGRESS_INTERVAL: Duration = Duration::from_millis(500);

pub type ProgressTransform = fn(Value) -> Value;

/// Receives partial string fields from a command and forwards coalesced
/// `probe:measurement:progress` events using the same modes as upstream.
pub struct ProgressEmitter {
    client: Client,
    test_id: String,
    measurement_id: String,
    buffer: ProgressBuffer,
    transform: Option<ProgressTransform>,
}

impl ProgressEmitter {
    pub fn new(
        client: Client,
        test_id: impl Into<String>,
        measurement_id: impl Into<String>,
        mode: BufferMode,
        transform: Option<ProgressTransform>,
    ) -> Self {
        Self {
            client,
            test_id: test_id.into(),
            measurement_id: measurement_id.into(),
            buffer: ProgressBuffer::new(mode),
            transform,
        }
    }

    fn merge(&mut self, partial: Value) {
        let Value::Object(fields) = partial else {
            return;
        };
        for (field, value) in fields {
            if let Some(value) = value.as_str() {
                self.buffer.push(&field, value);
            }
        }
    }

    async fn emit_buffer(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let fields = self.buffer.take_progress();
        if fields.values().all(String::is_empty) {
            return;
        }
        let mut partial = Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, Value::String(value)))
                .collect::<Map<_, _>>(),
        );
        if let Some(transform) = self.transform {
            partial = transform(partial);
        }
        limit_raw_output(&mut partial);
        if let Err(error) = self
            .client
            .emit(
                "probe:measurement:progress",
                json!({
                    "testId": self.test_id,
                    "measurementId": self.measurement_id,
                    "overwrite": self.buffer.overwrite(),
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
    pub async fn forward(mut self, mut rx: mpsc::UnboundedReceiver<Value>) {
        let mut first = true;
        let mut deadline: Option<Instant> = None;
        loop {
            if let Some(at) = deadline {
                tokio::select! {
                    message = rx.recv() => {
                        let Some(message) = message else { return; };
                        self.merge(message);
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
                self.merge(message);
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
