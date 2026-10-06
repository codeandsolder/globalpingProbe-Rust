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

#[cfg(test)]
mod differential_tests {
    use std::collections::{HashMap, VecDeque};
    use std::future::{Future, ready};
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};

    use serde_json::{Value, json};
    use wasmtime::Store;
    use wasmtime::component::{Component, HasSelf, Linker};

    use super::*;
    use crate::command::ping::{normalize_ping_output, shape_icmp_output};
    use crate::command::traceroute::{normalize_numeric_output, shape_traceroute_output};
    use crate::util::resolve_target::ResolvedTarget;

    const COMPONENT_ENV: &str = "GLOBALPING_BEHAVIOR_COMPONENT";

    #[derive(Clone, Copy)]
    enum FixtureKind {
        Ping,
        Traceroute,
    }

    impl FixtureKind {
        const fn wit(self) -> wit_host::MeasurementKind {
            match self {
                Self::Ping => wit_host::MeasurementKind::Ping,
                Self::Traceroute => wit_host::MeasurementKind::Traceroute,
            }
        }
    }

    struct FixtureState {
        limits: StoreLimits,
        token_hi: u64,
        token_lo: u64,
        kind: FixtureKind,
        events: VecDeque<wit_host::ExecutionEvent>,
        reverse: HashMap<String, String>,
        resolved_address: String,
        resolved_hostname: String,
        progress: Vec<(String, bool)>,
        reverse_requests: Vec<String>,
        started: bool,
    }

    impl FixtureState {
        fn new(
            token: &wit_host::CapabilityToken,
            kind: FixtureKind,
            events: Vec<wit_host::ExecutionEvent>,
            reverse: HashMap<String, String>,
        ) -> Self {
            Self {
                limits: BehaviorRuntime::store_limits(),
                token_hi: token.hi,
                token_lo: token.lo,
                kind,
                events: events.into(),
                reverse,
                resolved_address: "1.1.1.1".to_string(),
                resolved_hostname: "one.one.one.one".to_string(),
                progress: Vec::new(),
                reverse_requests: Vec::new(),
                started: false,
            }
        }

        fn valid_token(&self, token: &wit_host::CapabilityToken) -> bool {
            token.hi == self.token_hi && token.lo == self.token_lo
        }

        fn error(code: wit_host::HostErrorCode, message: &str) -> wit_host::HostError {
            wit_host::HostError {
                code,
                message: message.to_string(),
            }
        }
    }

    impl wit_host::Host for FixtureState {
        fn start(
            &mut self,
            token: wit_host::CapabilityToken,
        ) -> impl Future<Output = Result<wit_host::ExecutionStart, wit_host::HostError>> + Send
        {
            let result = if !self.valid_token(&token) {
                Err(Self::error(
                    wit_host::HostErrorCode::InvalidToken,
                    "fixture token mismatch",
                ))
            } else if self.started {
                Err(Self::error(
                    wit_host::HostErrorCode::PolicyDenied,
                    "fixture execution already started",
                ))
            } else {
                self.started = true;
                Ok(wit_host::ExecutionStart {
                    kind: self.kind.wit(),
                    raw_byte_limit: 64 * 1024,
                    deadline_ms: 30_000,
                    resolved_address: self.resolved_address.clone(),
                    resolved_hostname: self.resolved_hostname.clone(),
                })
            };
            ready(result)
        }

        fn poll(
            &mut self,
            token: wit_host::CapabilityToken,
        ) -> impl Future<Output = Result<Option<wit_host::ExecutionEvent>, wit_host::HostError>> + Send
        {
            ready(if self.valid_token(&token) {
                Ok(self.events.pop_front())
            } else {
                Err(Self::error(
                    wit_host::HostErrorCode::InvalidToken,
                    "fixture token mismatch",
                ))
            })
        }

        fn reverse_lookup(
            &mut self,
            token: wit_host::CapabilityToken,
            address: String,
        ) -> impl Future<Output = Result<Option<String>, wit_host::HostError>> + Send {
            let result = if self.valid_token(&token) {
                self.reverse_requests.push(address.clone());
                Ok(self.reverse.get(&address).cloned())
            } else {
                Err(Self::error(
                    wit_host::HostErrorCode::InvalidToken,
                    "fixture token mismatch",
                ))
            };
            ready(result)
        }

        fn lookup_asn(
            &mut self,
            token: wit_host::CapabilityToken,
            _address: String,
        ) -> impl Future<Output = Result<Vec<u32>, wit_host::HostError>> + Send {
            ready(if self.valid_token(&token) {
                Ok(Vec::new())
            } else {
                Err(Self::error(
                    wit_host::HostErrorCode::InvalidToken,
                    "fixture token mismatch",
                ))
            })
        }

        fn emit_progress(
            &mut self,
            token: wit_host::CapabilityToken,
            result_json: String,
            overwrite: bool,
        ) -> impl Future<Output = Result<(), wit_host::HostError>> + Send {
            let result = if self.valid_token(&token) {
                self.progress.push((result_json, overwrite));
                Ok(())
            } else {
                Err(Self::error(
                    wit_host::HostErrorCode::InvalidToken,
                    "fixture token mismatch",
                ))
            };
            ready(result)
        }
    }

    struct FixtureResult {
        final_json: Value,
        progress: Vec<(Value, bool)>,
        reverse_requests: Vec<String>,
    }

    fn component_path() -> PathBuf {
        std::env::var_os(COMPONENT_ENV).map_or_else(
            || {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("target/wasm32-wasip2/release/globalping_behavior.wasm")
            },
            PathBuf::from,
        )
    }

    fn stdout(text: &str) -> wit_host::ExecutionEvent {
        wit_host::ExecutionEvent::Stdout(text.as_bytes().to_vec())
    }

    fn chunked_stdout(raw: &str, cuts: &[usize]) -> Vec<wit_host::ExecutionEvent> {
        let mut events = Vec::new();
        let mut start = 0;
        for &end in cuts {
            if end > start && end < raw.len() {
                events.push(stdout(&raw[start..end]));
                start = end;
            }
        }
        if start < raw.len() {
            events.push(stdout(&raw[start..]));
        }
        events
    }

    async fn run_fixture(
        kind: FixtureKind,
        measurement: Value,
        events: Vec<wit_host::ExecutionEvent>,
        reverse: HashMap<String, String>,
    ) -> FixtureResult {
        let runtime = BehaviorRuntime::new()
            .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
        let path = component_path();
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let component = Component::from_binary(runtime.engine(), &bytes)
            .unwrap_or_else(|error| panic!("component compilation failed: {error}"));
        let mut linker = Linker::<FixtureState>::new(runtime.engine());
        ProbeBehavior::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .unwrap_or_else(|error| panic!("fixture linker failed: {error}"));

        let token = wit_host::CapabilityToken {
            hi: 0x0123_4567_89ab_cdef,
            lo: 0xfedc_ba98_7654_3210,
        };
        let state = FixtureState::new(&token, kind, events, reverse);
        let mut store = Store::new(runtime.engine(), state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(JOB_FUEL)
            .unwrap_or_else(|error| panic!("failed to set fixture fuel: {error}"));
        store.set_epoch_deadline(1);

        let bindings = ProbeBehavior::instantiate_async(&mut store, &component, &linker)
            .await
            .unwrap_or_else(|error| panic!("fixture instantiation failed: {error}"));
        let job = exports::codeandsolder::globalping_behavior::guest::Job {
            token,
            kind: kind.wit(),
            measurement_json: serde_json::to_string(&measurement)
                .unwrap_or_else(|error| panic!("measurement serialization failed: {error}")),
        };
        let result = bindings
            .codeandsolder_globalping_behavior_guest()
            .call_handle(&mut store, &job)
            .await
            .unwrap_or_else(|error| panic!("fixture guest call trapped: {error}"))
            .unwrap_or_else(|error| panic!("fixture guest rejected job: {error:?}"));
        let final_json = serde_json::from_str(&result)
            .unwrap_or_else(|error| panic!("guest returned invalid JSON: {error}: {result}"));
        let progress = store
            .data()
            .progress
            .iter()
            .map(|(payload, overwrite)| {
                (
                    serde_json::from_str(payload).unwrap_or_else(|error| {
                        panic!("guest emitted invalid progress JSON: {error}: {payload}")
                    }),
                    *overwrite,
                )
            })
            .collect();
        FixtureResult {
            final_json,
            progress,
            reverse_requests: store.data().reverse_requests.clone(),
        }
    }

    fn ping_progress(raw: &str, address: &str, hostname: &str) -> Vec<(Value, bool)> {
        raw.lines().map(|line| (
            json!({"rawOutput": format!("{}\n", normalize_ping_output(line, address, hostname))}),
            false,
        )).collect()
    }

    fn traceroute_progress(raw: &str, target: &ResolvedTarget) -> Vec<(Value, bool)> {
        let lines = raw.lines().collect::<Vec<_>>();
        (1..=lines.len()).map(|count| {
            let current = lines[..count].join("\n");
            (json!({"rawOutput": normalize_numeric_output(&current, target, &HashMap::new())}), false)
        }).collect()
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_ping_success_matches_native_with_arbitrary_chunks() {
        const RAW: &str = "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n\
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=41.7 ms\n\
64 bytes from 1.1.1.1: icmp_seq=2 ttl=58 time=42.1 ms\n\
\n\
--- 1.1.1.1 ping statistics ---\n\
2 packets transmitted, 2 received, 0% packet loss, time 1003ms\n\
rtt min/avg/max/mdev = 41.700/41.900/42.100/0.200 ms\n";
        let mut events = chunked_stdout(RAW, &[7, 31, 78, 119, 173, 221]);
        events.push(wit_host::ExecutionEvent::Exited(0));
        let actual = run_fixture(
            FixtureKind::Ping,
            json!({"type":"ping","target":"one.one.one.one","timeout":10,"inProgressUpdates":true}),
            events,
            HashMap::new(),
        )
        .await;
        let expected =
            serde_json::to_value(shape_icmp_output(RAW, "1.1.1.1", "one.one.one.one", false))
                .unwrap_or_else(|error| panic!("native ping serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert_eq!(
            actual.progress,
            ping_progress(RAW, "1.1.1.1", "one.one.one.one")
        );
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_ping_uses_host_resolved_identity_not_request_text() {
        const RAW: &str = "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=41.7 ms\n";
        let events = vec![stdout(RAW), wit_host::ExecutionEvent::Exited(0)];
        let actual = run_fixture(
            FixtureKind::Ping,
            json!({"type":"ping","target":"request-name.invalid","timeout":10,"inProgressUpdates":false}),
            events,
            HashMap::new(),
        )
        .await;
        assert_eq!(actual.final_json["resolvedAddress"], "1.1.1.1");
        assert_eq!(actual.final_json["resolvedHostname"], "one.one.one.one");
        assert!(
            actual.final_json["rawOutput"]
                .as_str()
                .is_some_and(|raw| raw.contains("one.one.one.one (1.1.1.1)"))
        );
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_ping_timeout_matches_native() {
        const RAW: &str = "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n\
no answer yet for icmp_seq=1\n\
\n\
--- 1.1.1.1 ping statistics ---\n\
1 packets transmitted, 0 received, 100% packet loss, time 2909ms\n";
        let mut events = chunked_stdout(RAW, &[11, 52, 87]);
        events.push(wit_host::ExecutionEvent::TimedOut);
        let actual = run_fixture(
            FixtureKind::Ping,
            json!({"type":"ping","target":"one.one.one.one","timeout":10,"inProgressUpdates":false}),
            events, HashMap::new(),
        ).await;
        let expected =
            serde_json::to_value(shape_icmp_output(RAW, "1.1.1.1", "one.one.one.one", true))
                .unwrap_or_else(|error| panic!("native ping serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert!(actual.progress.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_traceroute_success_matches_native_and_skips_private_ptr() {
        const RAW: &str = "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets\n\
 1  192.168.1.1  1.234 ms  1.156 ms\n\
 2  10.0.0.1  5.678 ms  5.432 ms\n\
 3  8.8.8.8  7.100 ms  7.200 ms\n\
 4  1.1.1.1  8.123 ms  7.956 ms";
        let target = ResolvedTarget {
            address: "1.1.1.1"
                .parse::<IpAddr>()
                .unwrap_or_else(|error| panic!("fixture address failed: {error}")),
            hostname: "one.one.one.one".to_string(),
        };
        let native_hostnames = HashMap::from([(
            "8.8.8.8"
                .parse::<IpAddr>()
                .unwrap_or_else(|error| panic!("fixture address failed: {error}")),
            "dns.google".to_string(),
        )]);
        let reverse = HashMap::from([
            ("10.0.0.1".to_string(), "private.invalid".to_string()),
            ("8.8.8.8".to_string(), "dns.google".to_string()),
        ]);
        let mut events = chunked_stdout(RAW, &[4, 49, 81, 117, 151]);
        events.push(wit_host::ExecutionEvent::Exited(0));
        let actual = run_fixture(
            FixtureKind::Traceroute,
            json!({"type":"traceroute","target":"one.one.one.one","timeout":10,"inProgressUpdates":true}),
            events, reverse,
        ).await;
        let expected = serde_json::to_value(shape_traceroute_output(
            RAW,
            "",
            false,
            Some(true),
            &target,
            &native_hostnames,
        ))
        .unwrap_or_else(|error| panic!("native traceroute serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert_eq!(actual.progress, traceroute_progress(RAW, &target));
        assert_eq!(actual.reverse_requests, vec!["8.8.8.8".to_string()]);
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_traceroute_timeout_matches_native() {
        const RAW: &str = "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets\n\
 1  192.168.1.1  1.234 ms  1.156 ms\n\
 2  * * *\n\
 3  * * *";
        let target = ResolvedTarget {
            address: "1.1.1.1"
                .parse::<IpAddr>()
                .unwrap_or_else(|error| panic!("fixture address failed: {error}")),
            hostname: "one.one.one.one".to_string(),
        };
        let mut events = chunked_stdout(RAW, &[19, 64, 95]);
        events.push(wit_host::ExecutionEvent::TimedOut);
        let actual = run_fixture(
            FixtureKind::Traceroute,
            json!({"type":"traceroute","target":"one.one.one.one","timeout":10,"inProgressUpdates":false}),
            events,
            HashMap::new(),
        )
        .await;
        let expected = serde_json::to_value(shape_traceroute_output(
            RAW,
            "",
            true,
            None,
            &target,
            &HashMap::new(),
        ))
        .unwrap_or_else(|error| panic!("native traceroute serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert!(actual.progress.is_empty());
        assert!(actual.reverse_requests.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_traceroute_upstream_unreachable_matches_native() {
        const RAW: &str = "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets\n\
 1  192.168.1.1  1.234 ms  1.156 ms\n\
 2  1.1.1.1  5.000 ms !H";
        let target = ResolvedTarget {
            address: "1.1.1.1"
                .parse::<IpAddr>()
                .unwrap_or_else(|error| panic!("fixture address failed: {error}")),
            hostname: "one.one.one.one".to_string(),
        };
        let mut events = chunked_stdout(RAW, &[17, 74, 101]);
        events.push(wit_host::ExecutionEvent::Exited(1));
        let actual = run_fixture(
            FixtureKind::Traceroute,
            json!({"type":"traceroute","target":"one.one.one.one","timeout":10,"inProgressUpdates":false}),
            events,
            HashMap::new(),
        )
        .await;
        let expected = serde_json::to_value(shape_traceroute_output(
            RAW,
            "",
            false,
            Some(false),
            &target,
            &HashMap::new(),
        ))
        .unwrap_or_else(|error| panic!("native traceroute serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_traceroute_empty_failure_matches_native() {
        const STDERR: &str = "traceroute: fixture failure";
        let target = ResolvedTarget {
            address: "1.1.1.1"
                .parse::<IpAddr>()
                .unwrap_or_else(|error| panic!("fixture address failed: {error}")),
            hostname: "one.one.one.one".to_string(),
        };
        let events = vec![
            wit_host::ExecutionEvent::Stderr(STDERR.as_bytes().to_vec()),
            wit_host::ExecutionEvent::Exited(2),
        ];
        let actual = run_fixture(
            FixtureKind::Traceroute,
            json!({"type":"traceroute","target":"one.one.one.one","timeout":10,"inProgressUpdates":false}),
            events,
            HashMap::new(),
        )
        .await;
        let expected = serde_json::to_value(shape_traceroute_output(
            "",
            STDERR,
            false,
            Some(false),
            &target,
            &HashMap::new(),
        ))
        .unwrap_or_else(|error| panic!("native traceroute serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
    }
}
