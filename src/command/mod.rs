pub mod dns;
pub mod http;
pub mod mtr;
pub mod ping;
pub mod traceroute;

use anyhow::Result;
use serde_json::Value;
use tokio::sync::mpsc::UnboundedSender;

/// Partial-result channel used for in-progress streaming.
/// Commands send `Value`s on this while running; the probe client forwards
/// each value to the API as a `probe:measurement:progress` event.
pub type ProgressTx = UnboundedSender<Value>;

/// Every measurement command implements this trait.
/// Mirrors `CommandInterface`<T> in the Node.js probe.
#[async_trait::async_trait]
pub trait MeasurementCommand: Send + Sync {
    /// Run to completion and return the final result.
    async fn run(&self, options: Value) -> Result<Value>;

    /// Run with optional streaming progress.  Sends partial `Value`s on `tx`
    /// as they become available (e.g. per-hop for traceroute, per-packet for
    /// ping).  The default implementation ignores `tx` and delegates to `run`.
    async fn run_with_progress(&self, options: Value, _tx: ProgressTx) -> Result<Value> {
        self.run(options).await
    }
}
