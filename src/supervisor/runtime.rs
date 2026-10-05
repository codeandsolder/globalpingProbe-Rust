//! WebAssembly Component Model runtime for the updateable behavior layer.
//!
//! The stable native supervisor only compiles artifacts that already passed
//! signature, digest, ABI, and anti-rollback verification. Per-job stores are
//! separately bounded by memory, fuel, and epoch deadlines.

use std::sync::Arc;

use wasmtime::component::Component;
use wasmtime::{Config, Engine, StoreLimits, StoreLimitsBuilder};

use super::update::VerifiedBehavior;

pub const MAX_GUEST_MEMORY_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_GUEST_TABLE_ELEMENTS: usize = 10_000;
pub const MAX_GUEST_INSTANCES: usize = 16;
pub const MAX_GUEST_TABLES: usize = 16;
pub const JOB_FUEL: u64 = 50_000_000;

#[derive(Debug)]
pub enum RuntimeError {
    Engine(wasmtime::Error),
    Component(wasmtime::Error),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Engine(error) => write!(f, "failed to configure Wasmtime: {error}"),
            Self::Component(error) => write!(f, "invalid WebAssembly component: {error}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Clone)]
pub struct BehaviorRuntime {
    engine: Engine,
}

impl BehaviorRuntime {
    /// Create the stable runtime.
    ///
    /// # Errors
    /// Returns an error if Wasmtime rejects a security-relevant engine setting.
    pub fn new() -> Result<Self, RuntimeError> {
        let mut config = Config::new();
        config
            .wasm_component_model(true)
            .consume_fuel(true)
            .epoch_interruption(true);
        let engine = Engine::new(&config).map_err(RuntimeError::Engine)?;
        Ok(Self { engine })
    }

    #[must_use]
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Compile a cryptographically verified behavior component.
    ///
    /// # Errors
    /// Returns an error if the verified bytes are not a valid Component Model artifact.
    pub fn compile(&self, verified: VerifiedBehavior) -> Result<CompiledBehavior, RuntimeError> {
        let component = Component::from_binary(&self.engine, &verified.component)
            .map_err(RuntimeError::Component)?;
        Ok(CompiledBehavior {
            sequence: verified.manifest.sequence,
            build_id: verified.manifest.build_id,
            component: Arc::new(component),
        })
    }

    #[must_use]
    pub fn store_limits() -> StoreLimits {
        StoreLimitsBuilder::new()
            .memory_size(MAX_GUEST_MEMORY_BYTES)
            .table_elements(MAX_GUEST_TABLE_ELEMENTS)
            .instances(MAX_GUEST_INSTANCES)
            .tables(MAX_GUEST_TABLES)
            .build()
    }

    pub fn increment_epoch(&self) {
        self.engine.increment_epoch();
    }
}

#[derive(Clone)]
pub struct CompiledBehavior {
    pub sequence: u64,
    pub build_id: String,
    pub component: Arc<Component>,
}

wasmtime::component::bindgen!({
    path: "wit",
    world: "probe-behavior",
    imports: { default: async },
    exports: { default: async },
});
