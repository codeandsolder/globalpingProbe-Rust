pub mod dns;
pub mod http;
pub mod mtr;
pub mod ping;
pub mod traceroute;

use serde_json::Value;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, error::SendError};

pub type LazyProgress = Box<dyn FnOnce() -> Value + Send + 'static>;

/// One pending progress update.
///
/// Lazy updates mirror upstream's `pushLazyProgress`: expensive parsing and
/// rendering is deferred until the coalescing window actually emits.
pub enum ProgressUpdate {
    Value(Value),
    Lazy(LazyProgress),
}

impl ProgressUpdate {
    #[must_use]
    pub fn resolve(self) -> Value {
        match self {
            Self::Value(value) => value,
            Self::Lazy(render) => render(),
        }
    }
}

/// Partial-result channel used for in-progress streaming.
#[derive(Clone)]
pub struct ProgressTx(UnboundedSender<ProgressUpdate>);

impl ProgressTx {
    #[must_use]
    pub fn channel() -> (Self, UnboundedReceiver<ProgressUpdate>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Self(tx), rx)
    }

    /// Queue an already-materialized progress update.
    ///
    /// # Errors
    /// Returns an error if the progress receiver has already been dropped.
    pub fn send(&self, value: Value) -> Result<(), SendError<ProgressUpdate>> {
        self.0.send(ProgressUpdate::Value(value))
    }

    /// Queue a progress update that is rendered only when the coalescer emits.
    ///
    /// # Errors
    /// Returns an error if the progress receiver has already been dropped.
    pub fn send_lazy<F>(&self, render: F) -> Result<(), SendError<ProgressUpdate>>
    where
        F: FnOnce() -> Value + Send + 'static,
    {
        self.0.send(ProgressUpdate::Lazy(Box::new(render)))
    }
}
