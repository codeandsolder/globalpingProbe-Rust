use serde_json::{Value, json};
use tokio::sync::mpsc;
use tracing::warn;

use crate::util::output_limit::limit_raw_output;
use rust_socketio::asynchronous::Client;

/// Receives partial measurement results from a command and forwards them to
/// the API as `probe:measurement:progress` socket.io events.
pub struct ProgressEmitter {
    client: Client,
    test_id: String,
    measurement_id: String,
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
        }
    }

    /// Consume the emitter and drain `rx` until the sender is dropped,
    /// forwarding each partial result to the API.  Designed to be spawned
    /// as a background task alongside the measurement.
    pub async fn forward(self, mut rx: mpsc::UnboundedReceiver<Value>) {
        while let Some(mut partial) = rx.recv().await {
            limit_raw_output(&mut partial);
            if let Err(e) = self
                .client
                .emit(
                    "probe:measurement:progress",
                    json!({
                        "testId":        self.test_id,
                        "measurementId": self.measurement_id,
                        "result":        partial,
                    }),
                )
                .await
            {
                warn!("Failed to emit progress for {}: {e}", self.measurement_id);
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: exercise the channel mechanics without a real socket.
    #[tokio::test]
    async fn channel_forwards_all_values_in_order() {
        let (tx, rx) = mpsc::unbounded_channel::<Value>();

        // Send three partial results
        tx.send(json!({"status": "in-progress", "hop": 1})).unwrap();
        tx.send(json!({"status": "in-progress", "hop": 2})).unwrap();
        tx.send(json!({"status": "in-progress", "hop": 3})).unwrap();
        drop(tx); // close sender so recv loop terminates

        let mut received = vec![];
        let mut rx = rx;
        while let Some(v) = rx.recv().await {
            received.push(v["hop"].as_u64().unwrap());
        }
        assert_eq!(received, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn channel_terminates_when_sender_dropped() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
        tx.send(json!({"x": 1})).unwrap();
        drop(tx);
        assert!(rx.recv().await.is_some());
        assert!(
            rx.recv().await.is_none(),
            "channel should close after sender drop"
        );
    }

    #[test]
    fn sender_clone_shares_channel() {
        let (tx, _rx) = mpsc::unbounded_channel::<Value>();
        let tx2 = tx.clone();
        tx.send(json!(1)).unwrap();
        tx2.send(json!(2)).unwrap();
        // Both senders go to the same receiver — no assertion needed on rx here,
        // just confirming neither send panics
    }
}
