pub mod dns;
pub mod http;
pub mod mtr;
pub mod ping;
pub mod traceroute;

use serde_json::Value;
use tokio::sync::mpsc::UnboundedSender;

/// Partial-result channel used for in-progress streaming.
/// Commands send `Value`s on this while running; the probe client forwards
/// each value to the API as a `probe:measurement:progress` event.
pub type ProgressTx = UnboundedSender<Value>;
