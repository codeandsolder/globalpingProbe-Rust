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
    Job(String),
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
            Self::Job(error) => write!(f, "behavior component job failed: {error}"),
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

mod production;
pub use production::BehaviorShadowResult;

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
    use crate::command::dns::{
        DnsOptions, DnsProgress, dns_progress_output, shape_classic_output, shape_trace_output,
    };
    use crate::command::mtr::shape_mtr_output;
    use crate::command::ping::{PingCommand, normalize_ping_output, shape_ping_output};
    use crate::command::traceroute::{
        TracerouteOptions, build_args as build_traceroute_args, enrich_hostnames,
        normalize_numeric_output, run_native_traceroute, shape_traceroute_output,
    };
    use crate::util::measurement_timeout::MeasurementDeadline;
    use crate::util::resolve_target::{ResolvedTarget, resolve_command_target};
    use globalping_behavior_core::mtr::{MtrEnrichmentEntry, MtrEnrichmentMap, render_progress};

    const COMPONENT_ENV: &str = "GLOBALPING_BEHAVIOR_COMPONENT";

    #[derive(Clone, Copy)]
    enum FixtureKind {
        Ping,
        Dns,
        Traceroute,
        Mtr,
    }

    impl FixtureKind {
        const fn wit(self) -> wit_host::MeasurementKind {
            match self {
                Self::Ping => wit_host::MeasurementKind::Ping,
                Self::Dns => wit_host::MeasurementKind::Dns,
                Self::Traceroute => wit_host::MeasurementKind::Traceroute,
                Self::Mtr => wit_host::MeasurementKind::Mtr,
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
        asn: HashMap<String, Vec<u32>>,
        resolved_address: String,
        resolved_hostname: String,
        target_is_icann: bool,
        progress: Vec<(String, bool)>,
        reverse_requests: Vec<String>,
        asn_requests: Vec<String>,
        started: bool,
    }

    impl FixtureState {
        fn new(
            token: &wit_host::CapabilityToken,
            kind: FixtureKind,
            events: Vec<wit_host::ExecutionEvent>,
            reverse: HashMap<String, String>,
            asn: HashMap<String, Vec<u32>>,
            resolved_address: impl Into<String>,
            resolved_hostname: impl Into<String>,
            target_is_icann: bool,
        ) -> Self {
            Self {
                limits: BehaviorRuntime::store_limits(),
                token_hi: token.hi,
                token_lo: token.lo,
                kind,
                events: events.into(),
                reverse,
                asn,
                resolved_address: resolved_address.into(),
                resolved_hostname: resolved_hostname.into(),
                target_is_icann,
                progress: Vec::new(),
                reverse_requests: Vec::new(),
                asn_requests: Vec::new(),
                started: false,
            }
        }

        const fn valid_token(&self, token: &wit_host::CapabilityToken) -> bool {
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
                    target_is_icann: self.target_is_icann,
                    local_addresses: Vec::new(),
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
            address: String,
        ) -> impl Future<Output = Result<Vec<u32>, wit_host::HostError>> + Send {
            let result = if self.valid_token(&token) {
                self.asn_requests.push(address.clone());
                Ok(self.asn.get(&address).cloned().unwrap_or_default())
            } else {
                Err(Self::error(
                    wit_host::HostErrorCode::InvalidToken,
                    "fixture token mismatch",
                ))
            };
            ready(result)
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
        asn_requests: Vec<String>,
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
        run_fixture_with_identity(
            kind,
            measurement,
            events,
            reverse,
            "1.1.1.1",
            "one.one.one.one",
        )
        .await
    }

    async fn run_fixture_with_identity(
        kind: FixtureKind,
        measurement: Value,
        events: Vec<wit_host::ExecutionEvent>,
        reverse: HashMap<String, String>,
        resolved_address: &str,
        resolved_hostname: &str,
    ) -> FixtureResult {
        run_fixture_with_enrichment(
            kind,
            measurement,
            events,
            reverse,
            HashMap::new(),
            resolved_address,
            resolved_hostname,
        )
        .await
    }

    async fn run_fixture_with_enrichment(
        kind: FixtureKind,
        measurement: Value,
        events: Vec<wit_host::ExecutionEvent>,
        reverse: HashMap<String, String>,
        asn: HashMap<String, Vec<u32>>,
        resolved_address: &str,
        resolved_hostname: &str,
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
        let target_is_icann = measurement
            .get("target")
            .and_then(Value::as_str)
            .is_some_and(|target| {
                psl::suffix(target.trim_end_matches('.').as_bytes())
                    .is_some_and(|suffix| suffix.typ() == Some(psl::Type::Icann))
            });
        let state = FixtureState::new(
            &token,
            kind,
            events,
            reverse,
            asn,
            resolved_address,
            resolved_hostname,
            target_is_icann,
        );
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
            asn_requests: store.data().asn_requests.clone(),
        }
    }

    fn dns_progress(raw: &str, opts: &DnsOptions) -> Vec<(Value, bool)> {
        let mut cumulative = String::new();
        let mut progress = Vec::new();
        for line in raw.lines() {
            cumulative.push_str(line);
            cumulative.push('\n');
            match dns_progress_output(&cumulative, opts) {
                DnsProgress::Ignore => {}
                DnsProgress::Private => break,
                DnsProgress::Emit(output) => {
                    progress.push((json!({ "rawOutput": output }), false));
                }
            }
        }
        progress
    }

    fn ping_progress(raw: &str, address: &str, hostname: &str) -> Vec<(Value, bool)> {
        raw.lines().map(|line| (
            json!({"rawOutput": format!("{}\n", normalize_ping_output(line, address, hostname))}),
            false,
        )).collect()
    }

    fn tcp_ping_progress(raw: &str, address: &str, hostname: &str) -> Vec<(Value, bool)> {
        let mut lines = Vec::new();
        let mut progress = Vec::new();
        for line in raw.lines() {
            lines.push(line);
            if line.contains("tcp_conn=") {
                progress.push((
                    json!({
                        "rawOutput": normalize_ping_output(&lines.join("\n"), address, hostname)
                    }),
                    false,
                ));
            }
        }
        progress
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
    async fn differential_mtr_enrichment_and_overwrite_progress_match_native() {
        const RAW: &str = "h 0 192.168.1.1\nx 0 0\np 0 1200 0\nh 1 8.8.8.8\nx 1 0\np 1 5000 0\nh 2 1.1.1.1\nx 2 0\np 2 8000 0\n";
        let measurement = json!({
            "type":"mtr",
            "target":"one.one.one.one",
            "protocol":"ICMP",
            "packets":1,
            "ipVersion":4,
            "timeout":10,
            "inProgressUpdates":true
        });
        let lines = [
            "h 0 192.168.1.1\n",
            "x 0 0\n",
            "p 0 1200 0\n",
            "h 1 8.8.8.8\n",
            "x 1 0\n",
            "p 1 5000 0\n",
            "h 2 1.1.1.1\n",
            "x 2 0\n",
            "p 2 8000 0\n",
        ];
        let mut events = Vec::new();
        for line in lines {
            events.push(stdout(line));
            if let Some(address) = line
                .strip_prefix("h ")
                .and_then(|tail| tail.split_whitespace().nth(1))
            {
                events.push(wit_host::ExecutionEvent::ObservedAddress(
                    address.to_string(),
                ));
            }
        }
        events.push(wit_host::ExecutionEvent::Exited(0));
        let reverse = HashMap::from([("8.8.8.8".to_string(), "dns.google".to_string())]);
        let asn = HashMap::from([
            ("8.8.8.8".to_string(), vec![15169]),
            ("1.1.1.1".to_string(), vec![13335]),
        ]);
        let actual = run_fixture_with_enrichment(
            FixtureKind::Mtr,
            measurement,
            events,
            reverse,
            asn,
            "1.1.1.1",
            "one.one.one.one",
        )
        .await;
        let target = ResolvedTarget {
            address: "1.1.1.1"
                .parse()
                .unwrap_or_else(|error| panic!("fixture IP failed: {error}")),
            hostname: "one.one.one.one".to_string(),
        };
        let enrichment = MtrEnrichmentMap::from([
            (
                "8.8.8.8".to_string(),
                MtrEnrichmentEntry {
                    hostname: Some("dns.google".to_string()),
                    asn: vec![15169],
                },
            ),
            (
                "1.1.1.1".to_string(),
                MtrEnrichmentEntry {
                    hostname: Some("one.one.one.one".to_string()),
                    asn: vec![13335],
                },
            ),
        ]);
        let expected = serde_json::to_value(shape_mtr_output(RAW, "", false, &target, &enrichment))
            .unwrap_or_else(|error| panic!("native MTR serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert!(actual.progress.iter().all(|(_, overwrite)| *overwrite));
        assert_eq!(
            actual.progress.last().map(|(value, _)| value),
            Some(&json!({ "rawOutput": render_progress(RAW, &enrichment) }))
        );
        assert_eq!(actual.reverse_requests, vec!["8.8.8.8".to_string()]);
        assert_eq!(
            actual.asn_requests,
            vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
        );
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_mtr_timeout_target_failure_matches_native() {
        const RAW: &str = "h 0 192.168.1.1\nx 0 0\np 0 1200 0\nh 1 8.8.8.8\nx 1 0\n";
        let events = vec![stdout(RAW), wit_host::ExecutionEvent::TimedOut];
        let actual = run_fixture_with_enrichment(
            FixtureKind::Mtr,
            json!({"type":"mtr","target":"1.1.1.1","timeout":2,"inProgressUpdates":false}),
            events,
            HashMap::new(),
            HashMap::new(),
            "1.1.1.1",
            "1.1.1.1",
        )
        .await;
        let target = ResolvedTarget {
            address: "1.1.1.1"
                .parse()
                .unwrap_or_else(|error| panic!("fixture IP failed: {error}")),
            hostname: "1.1.1.1".to_string(),
        };
        let expected = serde_json::to_value(shape_mtr_output(
            RAW,
            "",
            true,
            &target,
            &MtrEnrichmentMap::new(),
        ))
        .unwrap_or_else(|error| panic!("native timeout MTR serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert_eq!(actual.final_json["failureSource"], "target");
        assert!(actual.progress.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_dns_classic_matches_native_with_progress() {
        const RAW: &str = "; <<>> DiG 9.20 <<>> example.com A\n\
;; global options: +cmd\n\
;; Got answer:\n\
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 123\n\
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\
\n\
;; QUESTION SECTION:\n\
;example.com. IN A\n\
\n\
;; ANSWER SECTION:\n\
example.com. 300 IN A 93.184.216.34\n\
\n\
;; Query time: 12 msec\n\
;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)\n\
;; WHEN: Tue Oct 06 19:00:00 CEST 2026\n\
;; MSG SIZE  rcvd: 56\n";
        let measurement = json!({
            "type":"dns",
            "target":"example.com",
            "protocol":"UDP",
            "port":53,
            "trace":false,
            "query":{"type":"A"},
            "ipVersion":4,
            "timeout":10,
            "inProgressUpdates":true
        });
        let opts: DnsOptions = serde_json::from_value(measurement.clone())
            .unwrap_or_else(|error| panic!("DNS options fixture failed: {error}"));
        let mut events = chunked_stdout(RAW, &[3, 29, 61, 117, 193, 251]);
        events.push(wit_host::ExecutionEvent::Exited(0));
        let actual = run_fixture(FixtureKind::Dns, measurement, events, HashMap::new()).await;
        let expected = serde_json::to_value(shape_classic_output(
            RAW,
            "",
            false,
            false,
            false,
            "example.com",
        ))
        .unwrap_or_else(|error| panic!("native DNS serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert_eq!(actual.progress, dns_progress(RAW, &opts));
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_dns_private_non_icann_answer_matches_native() {
        const RAW: &str = "; <<>> DiG 9.20 <<>> router.home A\n\
;; global options: +cmd\n\
;; Got answer:\n\
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44\n\
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n\
;; ANSWER SECTION:\n\
router.home. 60 IN A 192.168.1.1\n\
\n\
;; Query time: 1 msec\n\
;; SERVER: 192.168.1.1#53(192.168.1.1) (UDP)\n";
        let events = vec![stdout(RAW), wit_host::ExecutionEvent::Exited(0)];
        let actual = run_fixture(
            FixtureKind::Dns,
            json!({
                "type":"dns",
                "target":"router.home",
                "trace":false,
                "timeout":10,
                "inProgressUpdates":false
            }),
            events,
            HashMap::new(),
        )
        .await;
        let expected = serde_json::to_value(shape_classic_output(
            RAW,
            "",
            false,
            false,
            false,
            "router.home",
        ))
        .unwrap_or_else(|error| panic!("native private DNS serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert!(actual.progress.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_dns_trace_matches_native() {
        const RAW: &str = ". 518400 IN NS a.root-servers.net.\n\
. 518400 IN NS b.root-servers.net.\n\
;; Received 239 bytes from 8.8.8.8#53(8.8.8.8) in 12 ms\n\
\n\
com. 172800 IN NS a.gtld-servers.net.\n\
;; Received 1170 bytes from 198.41.0.4#53(a.root-servers.net) in 24 ms\n";
        let measurement = json!({
            "type":"dns",
            "target":"example.com",
            "trace":true,
            "timeout":10,
            "inProgressUpdates":true
        });
        let opts: DnsOptions = serde_json::from_value(measurement.clone())
            .unwrap_or_else(|error| panic!("DNS trace options fixture failed: {error}"));
        let mut events = chunked_stdout(RAW, &[7, 48, 93, 137]);
        events.push(wit_host::ExecutionEvent::Exited(0));
        let actual = run_fixture(FixtureKind::Dns, measurement, events, HashMap::new()).await;
        let expected = serde_json::to_value(shape_trace_output(
            RAW,
            "",
            false,
            false,
            false,
            "example.com",
        ))
        .unwrap_or_else(|error| panic!("native trace DNS serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert_eq!(actual.progress, dns_progress(RAW, &opts));
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_dns_timeout_matches_native() {
        const RAW: &str = "; <<>> DiG 9.20 <<>> example.com A\n;; global options: +cmd\n";
        let events = vec![stdout(RAW), wit_host::ExecutionEvent::TimedOut];
        let actual = run_fixture(
            FixtureKind::Dns,
            json!({
                "type":"dns",
                "target":"example.com",
                "trace":false,
                "timeout":10,
                "inProgressUpdates":false
            }),
            events,
            HashMap::new(),
        )
        .await;
        let expected = serde_json::to_value(shape_classic_output(
            RAW,
            "",
            true,
            false,
            false,
            "example.com",
        ))
        .unwrap_or_else(|error| panic!("native timeout DNS serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
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
            serde_json::to_value(shape_ping_output(RAW, "1.1.1.1", "one.one.one.one", false))
                .unwrap_or_else(|error| panic!("native ping serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert_eq!(
            actual.progress,
            ping_progress(RAW, "1.1.1.1", "one.one.one.one")
        );
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_tcp_ping_matches_native_final_and_cumulative_progress() {
        const RAW: &str = "PING one.one.one.one (1.1.1.1) on port 443.\n\
Reply from one.one.one.one (1.1.1.1) on port 443: tcp_conn=1 time=12.34 ms\n\
No reply from one.one.one.one (1.1.1.1) on port 443: tcp_conn=2\n\
Reply from one.one.one.one (1.1.1.1) on port 443: tcp_conn=3 time=13 ms\n\
\n\
--- one.one.one.one (1.1.1.1) ping statistics ---\n\
3 packets transmitted, 2 received, 33.33% packet loss, time 1000 ms\n\
rtt min/avg/max/mdev = 12.340/12.670/13.000/0.330 ms";
        let mut events = chunked_stdout(RAW, &[9, 37, 76, 113, 158, 202, 249]);
        events.push(wit_host::ExecutionEvent::Exited(0));
        let actual = run_fixture(
            FixtureKind::Ping,
            json!({
                "type":"ping",
                "target":"one.one.one.one",
                "protocol":"TCP",
                "port":443,
                "timeout":10,
                "inProgressUpdates":true
            }),
            events,
            HashMap::new(),
        )
        .await;
        let expected =
            serde_json::to_value(shape_ping_output(RAW, "1.1.1.1", "one.one.one.one", false))
                .unwrap_or_else(|error| panic!("native TCP ping serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert_eq!(
            actual.progress,
            tcp_ping_progress(RAW, "1.1.1.1", "one.one.one.one")
        );
    }

    #[tokio::test]
    #[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
    async fn differential_tcp_ping_all_drop_matches_native() {
        const RAW: &str = "PING one.one.one.one (1.1.1.1) on port 443.\n\
No reply from one.one.one.one (1.1.1.1) on port 443: tcp_conn=1\n\
No reply from one.one.one.one (1.1.1.1) on port 443: tcp_conn=2\n\
\n\
--- one.one.one.one (1.1.1.1) ping statistics ---\n\
2 packets transmitted, 0 received, 100% packet loss, time 1000 ms";
        let mut events = chunked_stdout(RAW, &[5, 41, 83, 127]);
        events.push(wit_host::ExecutionEvent::Exited(0));
        let actual = run_fixture(
            FixtureKind::Ping,
            json!({
                "type":"ping",
                "target":"one.one.one.one",
                "protocol":"TCP",
                "port":443,
                "timeout":10,
                "inProgressUpdates":true
            }),
            events,
            HashMap::new(),
        )
        .await;
        let expected =
            serde_json::to_value(shape_ping_output(RAW, "1.1.1.1", "one.one.one.one", false))
                .unwrap_or_else(|error| panic!("native TCP ping serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert_eq!(
            actual.progress,
            tcp_ping_progress(RAW, "1.1.1.1", "one.one.one.one")
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
            serde_json::to_value(shape_ping_output(RAW, "1.1.1.1", "one.one.one.one", true))
                .unwrap_or_else(|error| panic!("native ping serialization failed: {error}"));
        assert_eq!(actual.final_json, expected);
        assert!(actual.progress.is_empty());
    }

    async fn run_real_host_shadow(measurement: Value) -> BehaviorShadowResult {
        let runtime = BehaviorRuntime::new()
            .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
        let path = component_path();
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let component = Component::from_binary(runtime.engine(), &bytes)
            .unwrap_or_else(|error| panic!("component compilation failed: {error}"));
        runtime
            .shadow_component(&component, measurement, None)
            .await
            .unwrap_or_else(|error| panic!("real host shadow failed: {error}"))
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network tools/access and a prebuilt wasm32-wasip2 behavior component"]
    async fn live_shadow_real_host_adapter_matches_native_oracles() {
        let cases = [
            (
                json!({
                    "type": "ping",
                    "target": "1.1.1.1",
                    "protocol": "ICMP",
                    "packets": 2,
                    "ipVersion": 4,
                    "timeout": 10,
                    "inProgressUpdates": true
                }),
                false,
            ),
            (
                json!({
                    "type": "ping",
                    "target": "1.1.1.1",
                    "protocol": "TCP",
                    "port": 443,
                    "packets": 2,
                    "ipVersion": 4,
                    "timeout": 10,
                    "inProgressUpdates": true
                }),
                false,
            ),
            (
                json!({
                    "type": "dns",
                    "target": "example.com",
                    "protocol": "UDP",
                    "port": 53,
                    "resolver": null,
                    "trace": false,
                    "query": {"type": "A"},
                    "ipVersion": 4,
                    "timeout": 10,
                    "inProgressUpdates": true
                }),
                false,
            ),
            (
                json!({
                    "type": "traceroute",
                    "target": "1.1.1.1",
                    "protocol": "ICMP",
                    "port": 80,
                    "ipVersion": 4,
                    "timeout": 10,
                    "inProgressUpdates": true
                }),
                false,
            ),
            (
                json!({
                    "type": "mtr",
                    "target": "1.1.1.1",
                    "protocol": "ICMP",
                    "port": 80,
                    "packets": 2,
                    "ipVersion": 4,
                    "timeout": 10,
                    "inProgressUpdates": true
                }),
                true,
            ),
        ];

        for (measurement, overwrite) in cases {
            let kind = measurement["type"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let shadow = run_real_host_shadow(measurement).await;
            assert_eq!(shadow.component, shadow.native, "{kind} shadow mismatch");
            assert!(
                !shadow.progress.is_empty(),
                "{kind} should emit progress through the real host adapter"
            );
            assert!(
                shadow
                    .progress
                    .iter()
                    .all(|(_, actual)| *actual == overwrite),
                "{kind} emitted the wrong overwrite mode"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network tools/access and a prebuilt wasm32-wasip2 behavior component"]
    async fn live_shadow_progress_is_emitted_before_native_execution_finishes() {
        let shadow = run_real_host_shadow(json!({
            "type": "ping",
            "target": "one.one.one.one",
            "protocol": "TCP",
            "port": 443,
            "packets": 8,
            "ipVersion": 4,
            "timeout": 10,
            "inProgressUpdates": true
        }))
        .await;
        assert_eq!(shadow.component, shadow.native);
        assert!(!shadow.progress.is_empty());
        assert!(
            shadow.progress_during_native_execution,
            "progress was emitted only after the native execution had already completed"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network access and a prebuilt wasm32-wasip2 behavior component"]
    async fn live_shadow_icmp_ping_matches_native_result() {
        let measurement = json!({
            "type": "ping",
            "target": "1.1.1.1",
            "protocol": "ICMP",
            "packets": 2,
            "ipVersion": 4,
            "timeout": 10,
            "inProgressUpdates": false
        });
        let native = PingCommand
            .run(measurement.clone())
            .await
            .unwrap_or_else(|error| panic!("native live ping failed: {error}"));
        let raw = native["rawOutput"]
            .as_str()
            .unwrap_or_else(|| panic!("native live ping omitted rawOutput"));
        let address = native["resolvedAddress"]
            .as_str()
            .unwrap_or_else(|| panic!("native live ping omitted resolvedAddress"));
        let hostname = native["resolvedHostname"]
            .as_str()
            .unwrap_or_else(|| panic!("native live ping omitted resolvedHostname"));
        let actual = run_fixture_with_identity(
            FixtureKind::Ping,
            measurement,
            vec![stdout(raw), wit_host::ExecutionEvent::Exited(0)],
            HashMap::new(),
            address,
            hostname,
        )
        .await;
        assert_eq!(actual.final_json, native);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network access and a prebuilt wasm32-wasip2 behavior component"]
    async fn live_shadow_tcp_ping_matches_native_result() {
        let measurement = json!({
            "type": "ping",
            "target": "1.1.1.1",
            "protocol": "TCP",
            "port": 443,
            "packets": 2,
            "ipVersion": 4,
            "timeout": 10,
            "inProgressUpdates": false
        });
        let native = PingCommand
            .run(measurement.clone())
            .await
            .unwrap_or_else(|error| panic!("native live TCP ping failed: {error}"));
        let raw = native["rawOutput"]
            .as_str()
            .unwrap_or_else(|| panic!("native live TCP ping omitted rawOutput"));
        let address = native["resolvedAddress"]
            .as_str()
            .unwrap_or_else(|| panic!("native live TCP ping omitted resolvedAddress"));
        let hostname = native["resolvedHostname"]
            .as_str()
            .unwrap_or_else(|| panic!("native live TCP ping omitted resolvedHostname"));
        let actual = run_fixture_with_identity(
            FixtureKind::Ping,
            measurement,
            vec![stdout(raw), wit_host::ExecutionEvent::Exited(0)],
            HashMap::new(),
            address,
            hostname,
        )
        .await;
        assert_eq!(actual.final_json, native);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network access and a prebuilt wasm32-wasip2 behavior component"]
    async fn live_shadow_traceroute_matches_native_raw_pipeline() {
        let measurement = json!({
            "type": "traceroute",
            "target": "1.1.1.1",
            "protocol": "ICMP",
            "port": 80,
            "ipVersion": 4,
            "timeout": 10,
            "inProgressUpdates": false
        });
        let opts: TracerouteOptions = serde_json::from_value(measurement.clone())
            .unwrap_or_else(|error| panic!("live traceroute options failed: {error}"));
        let deadline = MeasurementDeadline::new(opts.timeout);
        let target = resolve_command_target(
            &opts.target,
            opts.ip_version,
            std::time::Duration::from_secs(4),
        )
        .await
        .unwrap_or_else(|error| panic!("live traceroute target resolution failed: {error}"));
        let mut resolved_options = opts.clone();
        resolved_options.target = target.address.to_string();
        let native = run_native_traceroute(
            &build_traceroute_args(&resolved_options),
            deadline.process_timeout(),
            &target,
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("native raw traceroute failed: {error}"));
        let hostnames = enrich_hostnames(&native.raw, &target, deadline.remaining()).await;
        let expected = serde_json::to_value(shape_traceroute_output(
            &native.raw,
            &native.stderr,
            native.timed_out,
            native.status.map(|status| status.success()),
            &target,
            &hostnames,
        ))
        .unwrap_or_else(|error| panic!("native traceroute serialization failed: {error}"));

        let reverse = hostnames
            .into_iter()
            .map(|(address, hostname)| (address.to_string(), hostname))
            .collect();
        let mut events = chunked_stdout(&native.raw, &[13, 47, 101, 173]);
        if !native.stderr.is_empty() {
            events.push(wit_host::ExecutionEvent::Stderr(
                native.stderr.as_bytes().to_vec(),
            ));
        }
        if native.timed_out {
            events.push(wit_host::ExecutionEvent::TimedOut);
        } else {
            events.push(wit_host::ExecutionEvent::Exited(
                native.status.and_then(|status| status.code()).unwrap_or(1),
            ));
        }
        let actual = run_fixture_with_identity(
            FixtureKind::Traceroute,
            measurement,
            events,
            reverse,
            &target.address.to_string(),
            &target.hostname,
        )
        .await;
        assert_eq!(actual.final_json, expected);
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
