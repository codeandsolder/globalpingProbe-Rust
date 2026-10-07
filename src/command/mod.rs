pub mod dns;
pub mod http;
pub mod mtr;
pub mod ping;
pub mod traceroute;

use std::net::IpAddr;

use serde_json::Value;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender, error::SendError};

pub(crate) const RAW_EXECUTION_EVENT_CAPACITY: usize = 32;

#[derive(Debug)]
pub(crate) enum RawExecutionEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    ObservedAddress(IpAddr),
    HttpResponseHeaders(Vec<u8>),
    HttpResponseBody(Vec<u8>),
    HttpTlsEnrichment(globalping_behavior_core::http::TlsEnrichment),
    HttpNativeFailure {
        failure_source: String,
        message: String,
    },
    Exited(i32),
    TimedOut,
}

#[derive(Clone)]
pub(crate) struct RawExecutionTx(Sender<RawExecutionEvent>);

impl RawExecutionTx {
    #[must_use]
    pub(crate) fn channel() -> (Self, Receiver<RawExecutionEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(RAW_EXECUTION_EVENT_CAPACITY);
        (Self(tx), rx)
    }

    pub(crate) async fn send(
        &self,
        event: RawExecutionEvent,
    ) -> Result<(), SendError<RawExecutionEvent>> {
        self.0.send(event).await
    }

    pub(crate) async fn stdout_line(&self, line: &str) -> Result<(), SendError<RawExecutionEvent>> {
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        self.send(RawExecutionEvent::Stdout(bytes)).await
    }

    pub(crate) async fn stderr_chunk(
        &self,
        bytes: &[u8],
    ) -> Result<(), SendError<RawExecutionEvent>> {
        self.send(RawExecutionEvent::Stderr(bytes.to_vec())).await
    }

    pub(crate) async fn observe(
        &self,
        address: IpAddr,
    ) -> Result<(), SendError<RawExecutionEvent>> {
        self.send(RawExecutionEvent::ObservedAddress(address)).await
    }
}

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
