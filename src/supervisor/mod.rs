//! Stable native supervisor policy.
//!
//! The supervisor is the trust boundary around updateable WASM behavior. It owns
//! API connectivity, native network/process access, deadlines, output limits,
//! update verification, and rollback. The behavior component receives only a
//! short-lived capability token for a single server-issued measurement.

pub mod capability;
pub mod runtime;
pub mod storage;
pub mod update;
