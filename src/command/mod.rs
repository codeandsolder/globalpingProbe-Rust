pub mod dns;
pub mod http;
pub mod mtr;
pub mod ping;
pub mod traceroute;

use std::net::IpAddr;

use serde_json::Value;

use crate::util::progress_buffer::BufferMode;
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

    /// Best-effort raw-event delivery. Dropping the WASM consumer must never
    /// abort the authoritative native measurement.
    pub(crate) async fn send(&self, event: RawExecutionEvent) {
        let _ = self.0.send(event).await;
    }

    pub(crate) async fn stdout_line(&self, line: &str) {
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(10);
        self.send(RawExecutionEvent::Stdout(bytes)).await;
    }

    pub(crate) async fn stderr_chunk(&self, bytes: &[u8]) {
        self.send(RawExecutionEvent::Stderr(bytes.to_vec())).await;
    }

    pub(crate) async fn observe(&self, address: IpAddr) {
        self.send(RawExecutionEvent::ObservedAddress(address)).await;
    }
}

pub type LazyProgress = Box<dyn FnOnce() -> Value + Send + 'static>;

/// One pending progress update plus the coalescing policy chosen by its producer.
pub enum ProgressUpdate {
    Value {
        value: Value,
        mode: BufferMode,
    },
    Lazy {
        render: LazyProgress,
        mode: BufferMode,
    },
}

impl ProgressUpdate {
    #[must_use]
    pub const fn mode(&self) -> BufferMode {
        match self {
            Self::Value { mode, .. } | Self::Lazy { mode, .. } => *mode,
        }
    }

    #[must_use]
    pub fn resolve(self) -> Value {
        match self {
            Self::Value { value, .. } => value,
            Self::Lazy { render, .. } => render(),
        }
    }
}

/// Neutral progress sink. The behavior host supplies a mode per event; native
/// commands are given a fixed-mode `ProgressTx` only when the native path runs.
#[derive(Clone)]
pub(crate) struct ProgressSink(UnboundedSender<ProgressUpdate>);

impl ProgressSink {
    #[must_use]
    pub(crate) fn channel() -> (Self, UnboundedReceiver<ProgressUpdate>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Self(tx), rx)
    }

    #[must_use]
    pub(crate) fn fixed(&self, mode: BufferMode) -> ProgressTx {
        ProgressTx {
            tx: self.0.clone(),
            mode,
        }
    }

    /// Queue an explicitly-mode-tagged behavior progress update.
    ///
    /// # Errors
    /// Returns an error if the progress receiver has already been dropped.
    pub(crate) fn send(
        &self,
        value: Value,
        mode: BufferMode,
    ) -> Result<(), SendError<ProgressUpdate>> {
        self.0.send(ProgressUpdate::Value { value, mode })
    }
}

/// Fixed-mode progress sender used by native command implementations.
#[derive(Clone)]
pub struct ProgressTx {
    tx: UnboundedSender<ProgressUpdate>,
    mode: BufferMode,
}

impl ProgressTx {
    #[must_use]
    pub fn channel(mode: BufferMode) -> (Self, UnboundedReceiver<ProgressUpdate>) {
        let (sink, rx) = ProgressSink::channel();
        (sink.fixed(mode), rx)
    }

    /// Queue an already-materialized progress update.
    ///
    /// # Errors
    /// Returns an error if the progress receiver has already been dropped.
    pub fn send(&self, value: Value) -> Result<(), SendError<ProgressUpdate>> {
        self.tx.send(ProgressUpdate::Value {
            value,
            mode: self.mode,
        })
    }

    /// Queue a progress update that is rendered only when the coalescer emits.
    ///
    /// # Errors
    /// Returns an error if the progress receiver has already been dropped.
    pub fn send_lazy<F>(&self, render: F) -> Result<(), SendError<ProgressUpdate>>
    where
        F: FnOnce() -> Value + Send + 'static,
    {
        self.tx.send(ProgressUpdate::Lazy {
            render: Box::new(render),
            mode: self.mode,
        })
    }
}
