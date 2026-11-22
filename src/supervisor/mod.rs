//! Supervisor trust-boundary policy and artifact verification.
//!
//! The supervisor is the trust boundary around updateable WASM behavior. It owns
//! API connectivity, native network/process access, deadlines, output limits,
//! update verification, and rollback. The behavior component receives only a
//! short-lived capability token for a single server-issued measurement.

#[cfg(feature = "native")]
pub mod bootstrap;
#[cfg(feature = "native")]
pub mod capability;
#[cfg(feature = "native")]
pub mod health;
#[cfg(feature = "native")]
pub mod runtime;
#[cfg(feature = "native")]
pub mod storage;
#[cfg(feature = "native")]
pub mod transport;
pub mod update;
