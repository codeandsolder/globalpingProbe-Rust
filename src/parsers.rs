//! Host-neutral measurement parsers.
//!
//! These modules are available in the `wasm-core` build without process,
//! socket.io, filesystem, or ambient-network capabilities. Native builds
//! re-export the exact parser modules used by the measurement executors.

#[cfg(feature = "native")]
pub use crate::command::{
    dns::parse as dns, http::parse as http, mtr::parse as mtr, ping::parse as ping,
    traceroute::parse as traceroute,
};

#[cfg(not(feature = "native"))]
#[path = "command/dns/parse.rs"]
pub mod dns;
#[cfg(not(feature = "native"))]
#[path = "command/http/parse.rs"]
pub mod http;
#[cfg(not(feature = "native"))]
#[path = "command/mtr/parse.rs"]
pub mod mtr;
#[cfg(not(feature = "native"))]
#[path = "command/ping/parse.rs"]
pub mod ping;
#[cfg(not(feature = "native"))]
#[path = "command/traceroute/parse.rs"]
pub mod traceroute;
