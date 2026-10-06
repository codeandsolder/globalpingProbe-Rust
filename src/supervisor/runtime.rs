//! WebAssembly Component Model runtime for the updateable behavior layer.
//!
//! The stable native supervisor only compiles artifacts that already passed
//! signature, digest, ABI, and anti-rollback verification. Per-job stores are
//! separately bounded by memory, fuel, and epoch deadlines. The linker exposes
//! only the versioned Globalping host interface; ambient WASI is never linked.

use std::future::{Future, ready};
use std::sync::Arc;

use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

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
    Linker(wasmtime::Error),
    Store(wasmtime::Error),
    Instantiate(wasmtime::Error),
    Call(wasmtime::Error),
    GuestSelfTest(String),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Engine(error) => write!(f, "failed to configure Wasmtime: {error}"),
            Self::Component(error) => write!(f, "invalid WebAssembly component: {error}"),
            Self::Linker(error) => write!(f, "failed to configure behavior linker: {error}"),
            Self::Store(error) => write!(f, "failed to configure behavior store: {error}"),
            Self::Instantiate(error) => {
                write!(f, "failed to instantiate behavior component: {error}")
            }
            Self::Call(error) => write!(f, "behavior component call failed: {error}"),
            Self::GuestSelfTest(error) => write!(f, "behavior component self-test failed: {error}"),
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

    /// Instantiate the component with no ambient WASI and execute its built-in
    /// self-test under the same resource ceilings used for measurement jobs.
    ///
    /// # Errors
    /// Returns an error when linking, instantiation, resource configuration,
    /// the component call, or the guest-level self-test fails.
    pub async fn self_test(&self, compiled: &CompiledBehavior) -> Result<(), RuntimeError> {
        let mut linker = Linker::<SelfTestState>::new(&self.engine);
        ProbeBehavior::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(RuntimeError::Linker)?;

        let mut store = Store::new(&self.engine, SelfTestState::new());
        store.limiter(|state| &mut state.limits);
        store.set_fuel(JOB_FUEL).map_err(RuntimeError::Store)?;
        store.set_epoch_deadline(1);

        let bindings = ProbeBehavior::instantiate_async(&mut store, &compiled.component, &linker)
            .await
            .map_err(RuntimeError::Instantiate)?;
        let result = bindings
            .codeandsolder_globalping_behavior_guest()
            .call_self_test(&mut store)
            .await
            .map_err(RuntimeError::Call)?;
        result.map_err(RuntimeError::GuestSelfTest)
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

struct SelfTestState {
    limits: StoreLimits,
}

impl SelfTestState {
    fn new() -> Self {
        Self {
            limits: BehaviorRuntime::store_limits(),
        }
    }

    fn denied<T>() -> Result<T, codeandsolder::globalping_behavior::host::HostError> {
        use codeandsolder::globalping_behavior::host::{HostError, HostErrorCode};

        Err(HostError {
            code: HostErrorCode::PolicyDenied,
            message: "host capabilities are unavailable during component self-test".to_string(),
        })
    }
}

use codeandsolder::globalping_behavior::host as wit_host;

impl wit_host::Host for SelfTestState {
    fn start(
        &mut self,
        _token: wit_host::CapabilityToken,
    ) -> impl Future<Output = Result<wit_host::ExecutionStart, wit_host::HostError>> + Send {
        ready(Self::denied())
    }

    fn poll(
        &mut self,
        _token: wit_host::CapabilityToken,
    ) -> impl Future<Output = Result<Option<wit_host::ExecutionEvent>, wit_host::HostError>> + Send
    {
        ready(Self::denied())
    }

    fn reverse_lookup(
        &mut self,
        _token: wit_host::CapabilityToken,
        _address: String,
    ) -> impl Future<Output = Result<Option<String>, wit_host::HostError>> + Send {
        ready(Self::denied())
    }

    fn lookup_asn(
        &mut self,
        _token: wit_host::CapabilityToken,
        _address: String,
    ) -> impl Future<Output = Result<Vec<u32>, wit_host::HostError>> + Send {
        ready(Self::denied())
    }

    fn emit_progress(
        &mut self,
        _token: wit_host::CapabilityToken,
        _result_json: String,
        _overwrite: bool,
    ) -> impl Future<Output = Result<(), wit_host::HostError>> + Send {
        ready(Self::denied())
    }
}

wasmtime::component::bindgen!({
    path: "wit",
    world: "probe-behavior",
    imports: { default: async },
    exports: { default: async },
});
