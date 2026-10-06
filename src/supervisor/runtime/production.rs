use super::{
    BehaviorRuntime, CompiledBehavior, Component, Future, HasSelf, JOB_FUEL, Linker, ProbeBehavior,
    RuntimeError, Store, StoreLimits, exports, ready, wit_host,
};

#[derive(Debug)]
pub struct BehaviorShadowResult {
    pub native: serde_json::Value,
    pub component: serde_json::Value,
    pub progress: Vec<(serde_json::Value, bool)>,
}

#[derive(Debug)]
enum ShadowOracle {
    Ready(serde_json::Value),
    Traceroute {
        raw: String,
        stderr: String,
        timed_out: bool,
        succeeded: Option<bool>,
        target: crate::util::resolve_target::ResolvedTarget,
    },
    Mtr {
        raw: String,
        stderr: String,
        timed_out: bool,
        target: crate::util::resolve_target::ResolvedTarget,
    },
}

struct PreparedExecution {
    start: wit_host::ExecutionStart,
    events: std::collections::VecDeque<wit_host::ExecutionEvent>,
    oracle: ShadowOracle,
}

struct ProductionHost {
    limits: StoreLimits,
    lease: crate::supervisor::capability::CapabilityLease,
    events: std::collections::VecDeque<wit_host::ExecutionEvent>,
    progress_tx: Option<crate::command::ProgressTx>,
    progress: Vec<(serde_json::Value, bool)>,
    reverse_results: std::collections::HashMap<std::net::IpAddr, String>,
    asn_results: std::collections::HashMap<std::net::IpAddr, Vec<u32>>,
    oracle: Option<ShadowOracle>,
}

impl ProductionHost {
    fn new(
        lease: crate::supervisor::capability::CapabilityLease,
        progress_tx: Option<crate::command::ProgressTx>,
    ) -> Self {
        Self {
            limits: BehaviorRuntime::store_limits(),
            lease,
            events: std::collections::VecDeque::new(),
            progress_tx,
            progress: Vec::new(),
            reverse_results: std::collections::HashMap::new(),
            asn_results: std::collections::HashMap::new(),
            oracle: None,
        }
    }

    const fn valid_token(&self, token: &wit_host::CapabilityToken) -> bool {
        token.hi == self.lease.token.hi && token.lo == self.lease.token.lo
    }

    fn check_token(&self, token: &wit_host::CapabilityToken) -> Result<(), wit_host::HostError> {
        if self.valid_token(token) {
            Ok(())
        } else {
            Err(host_error(
                wit_host::HostErrorCode::InvalidToken,
                "capability token mismatch",
            ))
        }
    }

    fn oracle_result(&self) -> Result<serde_json::Value, String> {
        let oracle = self
            .oracle
            .as_ref()
            .ok_or_else(|| "native shadow oracle was not initialized".to_string())?;
        match oracle {
            ShadowOracle::Ready(value) => Ok(value.clone()),
            ShadowOracle::Traceroute {
                raw,
                stderr,
                timed_out,
                succeeded,
                target,
            } => serde_json::to_value(crate::command::traceroute::shape_traceroute_output(
                raw,
                stderr,
                *timed_out,
                *succeeded,
                target,
                &self.reverse_results,
            ))
            .map_err(|error| error.to_string()),
            ShadowOracle::Mtr {
                raw,
                stderr,
                timed_out,
                target,
            } => {
                use crate::command::mtr::parse::{MtrEnrichmentEntry, MtrEnrichmentMap};
                let mut enrichment = MtrEnrichmentMap::new();
                if target.hostname != target.address.to_string() {
                    enrichment.insert(
                        target.address.to_string(),
                        MtrEnrichmentEntry {
                            hostname: Some(target.hostname.clone()),
                            asn: Vec::new(),
                        },
                    );
                }
                for (address, hostname) in &self.reverse_results {
                    enrichment.entry(address.to_string()).or_default().hostname =
                        Some(hostname.clone());
                }
                for (address, asn) in &self.asn_results {
                    enrichment
                        .entry(address.to_string())
                        .or_default()
                        .asn
                        .clone_from(asn);
                }
                serde_json::to_value(crate::command::mtr::shape_mtr_output(
                    raw,
                    stderr,
                    *timed_out,
                    target,
                    &enrichment,
                ))
                .map_err(|error| error.to_string())
            }
        }
    }
}

fn host_error(code: wit_host::HostErrorCode, message: impl Into<String>) -> wit_host::HostError {
    wit_host::HostError {
        code,
        message: message.into(),
    }
}

fn native_error(error: impl std::fmt::Display) -> wit_host::HostError {
    host_error(wit_host::HostErrorCode::NativeFailure, error.to_string())
}

fn policy_error(error: crate::supervisor::capability::PolicyError) -> wit_host::HostError {
    use crate::supervisor::capability::PolicyError;
    let code = match error {
        PolicyError::Expired => wit_host::HostErrorCode::ExpiredToken,
        PolicyError::RawOutputQuota
        | PolicyError::PollQuota
        | PolicyError::EnrichmentQuota
        | PolicyError::ProgressEventQuota
        | PolicyError::ProgressQuota
        | PolicyError::FinalResultQuota => wit_host::HostErrorCode::QuotaExceeded,
        PolicyError::UnknownMeasurement
        | PolicyError::MissingTarget
        | PolicyError::InvalidTimeout => wit_host::HostErrorCode::InvalidRequest,
        PolicyError::AlreadyStarted
        | PolicyError::NotStarted
        | PolicyError::UnknownAddress
        | PolicyError::PrivateAddress => wit_host::HostErrorCode::PolicyDenied,
    };
    host_error(code, error.to_string())
}

fn target_is_icann(target: &str) -> bool {
    psl::suffix(target.trim_end_matches('.').as_bytes())
        .is_some_and(|suffix| suffix.typ() == Some(psl::Type::Icann))
}

fn local_addresses() -> Vec<String> {
    if_addrs::get_if_addrs().map_or_else(
        |_| Vec::new(),
        |interfaces| {
            let mut addresses = interfaces
                .into_iter()
                .map(|interface| interface.ip().to_string())
                .collect::<Vec<_>>();
            addresses.sort();
            addresses.dedup();
            addresses
        },
    )
}

fn terminal_event(
    timed_out: bool,
    status: Option<std::process::ExitStatus>,
) -> wit_host::ExecutionEvent {
    if timed_out {
        wit_host::ExecutionEvent::TimedOut
    } else {
        wit_host::ExecutionEvent::Exited(status.map_or(1, |status| {
            status
                .code()
                .unwrap_or_else(|| i32::from(!status.success()))
        }))
    }
}

fn collect_ip_tokens(raw: &str) -> Vec<std::net::IpAddr> {
    let mut addresses = Vec::new();
    for token in raw.split_whitespace() {
        let token = token.trim_matches(|ch| matches!(ch, '(' | ')' | ',' | '[' | ']'));
        let token = token.split_once('%').map_or(token, |(address, _)| address);
        if let Ok(address) = token.parse::<std::net::IpAddr>()
            && !addresses.contains(&address)
        {
            addresses.push(address);
        }
    }
    addresses
}

fn push_common_events(
    events: &mut std::collections::VecDeque<wit_host::ExecutionEvent>,
    stdout: &str,
    stderr: &str,
    observed: impl IntoIterator<Item = std::net::IpAddr>,
    terminal: wit_host::ExecutionEvent,
) {
    if !stdout.is_empty() {
        events.push_back(wit_host::ExecutionEvent::Stdout(stdout.as_bytes().to_vec()));
    }
    for address in observed {
        events.push_back(wit_host::ExecutionEvent::ObservedAddress(
            address.to_string(),
        ));
    }
    if !stderr.is_empty() {
        events.push_back(wit_host::ExecutionEvent::Stderr(stderr.as_bytes().to_vec()));
    }
    events.push_back(terminal);
}

fn execution_start(
    kind: wit_host::MeasurementKind,
    scope: &crate::supervisor::capability::MeasurementScope,
    resolved_address: String,
    resolved_hostname: String,
) -> wit_host::ExecutionStart {
    wit_host::ExecutionStart {
        kind,
        raw_byte_limit: u32::try_from(crate::supervisor::capability::MAX_RAW_EXECUTION_BYTES)
            .unwrap_or(u32::MAX),
        deadline_ms: u32::try_from(scope.timeout.as_millis()).unwrap_or(u32::MAX),
        resolved_address,
        resolved_hostname,
        target_is_icann: target_is_icann(&scope.target),
        local_addresses: local_addresses(),
    }
}

async fn prepare_ping(
    scope: &crate::supervisor::capability::MeasurementScope,
) -> Result<PreparedExecution, wit_host::HostError> {
    let native = crate::command::ping::PingCommand
        .run(scope.measurement.clone())
        .await
        .map_err(native_error)?;
    let address = native
        .get("resolvedAddress")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| native_error("native ping did not resolve a target"))?
        .to_string();
    let hostname = native
        .get("resolvedHostname")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&address)
        .to_string();
    let raw = native
        .get("rawOutput")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let mut events = std::collections::VecDeque::new();
    if !raw.is_empty() {
        events.push_back(wit_host::ExecutionEvent::Stdout(raw.as_bytes().to_vec()));
    }
    let failed = native.get("status").and_then(serde_json::Value::as_str) == Some("failed");
    events.push_back(if failed {
        wit_host::ExecutionEvent::TimedOut
    } else {
        wit_host::ExecutionEvent::Exited(0)
    });
    Ok(PreparedExecution {
        start: execution_start(wit_host::MeasurementKind::Ping, scope, address, hostname),
        events,
        oracle: ShadowOracle::Ready(native),
    })
}

async fn prepare_dns(
    scope: &crate::supervisor::capability::MeasurementScope,
) -> Result<PreparedExecution, wit_host::HostError> {
    use crate::command::dns;
    let opts: dns::DnsOptions =
        serde_json::from_value(scope.measurement.clone()).map_err(native_error)?;
    dns::validate(&opts).map_err(native_error)?;
    let native = dns::run_dig(&opts, None).await.map_err(native_error)?;
    let process_failed = native.status.is_some_and(|status| !status.success());
    let oracle = if opts.trace {
        serde_json::to_value(dns::shape_trace_output(
            &native.raw,
            &native.stderr,
            native.timed_out,
            process_failed,
            native.private_result,
            &opts.target,
        ))
    } else {
        serde_json::to_value(dns::shape_classic_output(
            &native.raw,
            &native.stderr,
            native.timed_out,
            process_failed,
            native.private_result,
            &opts.target,
        ))
    }
    .map_err(native_error)?;
    let mut events = std::collections::VecDeque::new();
    push_common_events(
        &mut events,
        &native.raw,
        &native.stderr,
        [],
        terminal_event(native.timed_out, native.status),
    );
    Ok(PreparedExecution {
        start: execution_start(
            wit_host::MeasurementKind::Dns,
            scope,
            opts.target.clone(),
            opts.target,
        ),
        events,
        oracle: ShadowOracle::Ready(oracle),
    })
}

async fn prepare_traceroute(
    scope: &crate::supervisor::capability::MeasurementScope,
) -> Result<PreparedExecution, wit_host::HostError> {
    use crate::command::traceroute;
    use crate::util::measurement_timeout::{MeasurementDeadline, traceroute_budget};
    use crate::util::resolve_target::resolve_command_target;
    use std::time::Duration;

    let opts: traceroute::TracerouteOptions =
        serde_json::from_value(scope.measurement.clone()).map_err(native_error)?;
    traceroute::validate(&opts).map_err(native_error)?;
    let budget = traceroute_budget(opts.timeout, 2);
    let dns_budget = Duration::from_secs_f64(budget.dns_headroom.max(0.0));
    let target = resolve_command_target(&opts.target, opts.ip_version, dns_budget)
        .await
        .map_err(native_error)?;
    let deadline = MeasurementDeadline::new(opts.timeout);
    let mut resolved_options = opts.clone();
    resolved_options.target = target.address.to_string();
    let native = traceroute::run_native_traceroute(
        &traceroute::build_args(&resolved_options),
        deadline.process_timeout(),
        &target,
        None,
    )
    .await
    .map_err(native_error)?;
    let mut events = std::collections::VecDeque::new();
    push_common_events(
        &mut events,
        &native.raw,
        &native.stderr,
        collect_ip_tokens(&native.raw),
        terminal_event(native.timed_out, native.status),
    );
    Ok(PreparedExecution {
        start: execution_start(
            wit_host::MeasurementKind::Traceroute,
            scope,
            target.address.to_string(),
            target.hostname.clone(),
        ),
        events,
        oracle: ShadowOracle::Traceroute {
            raw: native.raw,
            stderr: native.stderr,
            timed_out: native.timed_out,
            succeeded: native.status.map(|status| status.success()),
            target,
        },
    })
}

async fn prepare_mtr(
    scope: &crate::supervisor::capability::MeasurementScope,
) -> Result<PreparedExecution, wit_host::HostError> {
    use crate::command::mtr;
    use crate::util::measurement_timeout::{MeasurementDeadline, mtr_budget};
    use crate::util::resolve_target::resolve_command_target;
    use std::time::Duration;

    let opts: mtr::MtrOptions =
        serde_json::from_value(scope.measurement.clone()).map_err(native_error)?;
    mtr::validate(&opts).map_err(native_error)?;
    let budget = mtr_budget(opts.packets, opts.timeout);
    let dns_budget = Duration::from_secs_f64(budget.dns_headroom.max(0.0));
    let target = resolve_command_target(&opts.target, opts.ip_version, dns_budget)
        .await
        .map_err(native_error)?;
    let deadline = MeasurementDeadline::new(opts.timeout);
    let mut resolved_options = opts.clone();
    resolved_options.target = target.address.to_string();
    let native = mtr::run_native_mtr_raw(
        &mtr::build_args(&resolved_options),
        deadline.process_timeout(),
    )
    .await
    .map_err(native_error)?;
    let observed = native
        .stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next()? == "h")
                .then(|| parts.nth(1))
                .flatten()
                .and_then(|address| {
                    let address = address.split_once('%').map_or(address, |(ip, _)| ip);
                    address.parse::<std::net::IpAddr>().ok()
                })
        })
        .collect::<Vec<_>>();
    let terminal = if native.timed_out {
        wit_host::ExecutionEvent::TimedOut
    } else {
        wit_host::ExecutionEvent::Exited(0)
    };
    let mut events = std::collections::VecDeque::new();
    push_common_events(
        &mut events,
        &native.stdout,
        &native.stderr,
        observed,
        terminal,
    );
    Ok(PreparedExecution {
        start: execution_start(
            wit_host::MeasurementKind::Mtr,
            scope,
            target.address.to_string(),
            target.hostname.clone(),
        ),
        events,
        oracle: ShadowOracle::Mtr {
            raw: native.stdout,
            stderr: native.stderr,
            timed_out: native.timed_out,
            target,
        },
    })
}

async fn prepare_native_execution(
    scope: &crate::supervisor::capability::MeasurementScope,
) -> Result<PreparedExecution, wit_host::HostError> {
    match scope.kind {
        crate::supervisor::capability::MeasurementKind::Ping => prepare_ping(scope).await,
        crate::supervisor::capability::MeasurementKind::Dns => prepare_dns(scope).await,
        crate::supervisor::capability::MeasurementKind::Traceroute => {
            prepare_traceroute(scope).await
        }
        crate::supervisor::capability::MeasurementKind::Mtr => prepare_mtr(scope).await,
        crate::supervisor::capability::MeasurementKind::Http => Err(host_error(
            wit_host::HostErrorCode::WrongMeasurementKind,
            "HTTP behavior has not migrated to the component yet",
        )),
    }
}

impl wit_host::Host for ProductionHost {
    async fn start(
        &mut self,
        token: wit_host::CapabilityToken,
    ) -> Result<wit_host::ExecutionStart, wit_host::HostError> {
        self.check_token(&token)?;
        self.lease
            .authorize_start(std::time::Instant::now())
            .map_err(policy_error)?;
        let scope = self.lease.scope.clone();
        let prepared = prepare_native_execution(&scope).await?;
        self.events = prepared.events;
        self.oracle = Some(prepared.oracle);
        Ok(prepared.start)
    }

    fn poll(
        &mut self,
        token: wit_host::CapabilityToken,
    ) -> impl Future<Output = Result<Option<wit_host::ExecutionEvent>, wit_host::HostError>> + Send
    {
        let result = (|| {
            self.check_token(&token)?;
            let now = std::time::Instant::now();
            self.lease.authorize_poll(now).map_err(policy_error)?;
            let Some(event) = self.events.pop_front() else {
                return Ok(None);
            };
            match &event {
                wit_host::ExecutionEvent::Stdout(bytes)
                | wit_host::ExecutionEvent::Stderr(bytes) => self
                    .lease
                    .account_raw_bytes(bytes.len(), now)
                    .map_err(policy_error)?,
                wit_host::ExecutionEvent::ObservedAddress(address) => {
                    let address = address.parse().map_err(|_| {
                        host_error(
                            wit_host::HostErrorCode::NativeFailure,
                            "native execution reported an invalid observed address",
                        )
                    })?;
                    self.lease
                        .observe_address(address, now)
                        .map_err(policy_error)?;
                }
                wit_host::ExecutionEvent::Exited(_) | wit_host::ExecutionEvent::TimedOut => {}
            }
            Ok(Some(event))
        })();
        ready(result)
    }

    async fn reverse_lookup(
        &mut self,
        token: wit_host::CapabilityToken,
        address: String,
    ) -> Result<Option<String>, wit_host::HostError> {
        self.check_token(&token)?;
        let address: std::net::IpAddr = address
            .parse()
            .map_err(|_| host_error(wit_host::HostErrorCode::InvalidRequest, "invalid address"))?;
        let now = std::time::Instant::now();
        self.lease
            .authorize_reverse_lookup(address, now)
            .map_err(policy_error)?;
        let hostname = crate::util::resolve_target::reverse_lookup(
            address,
            self.lease
                .remaining(now)
                .min(std::time::Duration::from_secs(3)),
        )
        .await;
        if let Some(hostname) = &hostname {
            self.reverse_results.insert(address, hostname.clone());
        }
        Ok(hostname)
    }

    async fn lookup_asn(
        &mut self,
        token: wit_host::CapabilityToken,
        address: String,
    ) -> Result<Vec<u32>, wit_host::HostError> {
        self.check_token(&token)?;
        let address: std::net::IpAddr = address
            .parse()
            .map_err(|_| host_error(wit_host::HostErrorCode::InvalidRequest, "invalid address"))?;
        let now = std::time::Instant::now();
        self.lease
            .authorize_asn_lookup(address, now)
            .map_err(policy_error)?;
        let asn = crate::command::mtr::lookup_asn(address, self.lease.remaining(now)).await;
        if !asn.is_empty() {
            self.asn_results.insert(address, asn.clone());
        }
        Ok(asn)
    }

    fn emit_progress(
        &mut self,
        token: wit_host::CapabilityToken,
        result_json: String,
        overwrite: bool,
    ) -> impl Future<Output = Result<(), wit_host::HostError>> + Send {
        let result = (|| {
            self.check_token(&token)?;
            self.lease
                .authorize_progress(&result_json, std::time::Instant::now())
                .map_err(policy_error)?;
            let value: serde_json::Value = serde_json::from_str(&result_json).map_err(|error| {
                host_error(wit_host::HostErrorCode::InvalidRequest, error.to_string())
            })?;
            if let Some(tx) = &self.progress_tx {
                tx.send(value.clone()).map_err(|error| {
                    host_error(wit_host::HostErrorCode::NativeFailure, error.to_string())
                })?;
            }
            self.progress.push((value, overwrite));
            Ok(())
        })();
        ready(result)
    }
}

impl BehaviorRuntime {
    pub(crate) async fn shadow_component(
        &self,
        component: &Component,
        measurement: serde_json::Value,
        progress_tx: Option<crate::command::ProgressTx>,
    ) -> Result<BehaviorShadowResult, RuntimeError> {
        let scope = crate::supervisor::capability::MeasurementScope::from_server_measurement(
            measurement.clone(),
        )
        .map_err(|error| RuntimeError::Job(error.to_string()))?;
        let token = crate::supervisor::capability::CapabilityToken {
            hi: rand::random(),
            lo: rand::random(),
        };
        let wit_token = wit_host::CapabilityToken {
            hi: token.hi,
            lo: token.lo,
        };
        let kind = match scope.kind {
            crate::supervisor::capability::MeasurementKind::Ping => wit_host::MeasurementKind::Ping,
            crate::supervisor::capability::MeasurementKind::Dns => wit_host::MeasurementKind::Dns,
            crate::supervisor::capability::MeasurementKind::Traceroute => {
                wit_host::MeasurementKind::Traceroute
            }
            crate::supervisor::capability::MeasurementKind::Mtr => wit_host::MeasurementKind::Mtr,
            crate::supervisor::capability::MeasurementKind::Http => wit_host::MeasurementKind::Http,
        };
        let lease = crate::supervisor::capability::CapabilityLease::new(
            token,
            scope,
            std::time::Instant::now(),
        );
        let mut linker = Linker::<ProductionHost>::new(&self.engine);
        ProbeBehavior::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(RuntimeError::Linker)?;
        let mut store = Store::new(&self.engine, ProductionHost::new(lease, progress_tx));
        store.limiter(|state| &mut state.limits);
        store.set_fuel(JOB_FUEL).map_err(RuntimeError::Store)?;
        store.set_epoch_deadline(1);
        let bindings = ProbeBehavior::instantiate_async(&mut store, component, &linker)
            .await
            .map_err(RuntimeError::Instantiate)?;
        let job = exports::codeandsolder::globalping_behavior::guest::Job {
            token: wit_token,
            kind,
            measurement_json: serde_json::to_string(&measurement)
                .map_err(|error| RuntimeError::Job(error.to_string()))?,
        };
        let result = bindings
            .codeandsolder_globalping_behavior_guest()
            .call_handle(&mut store, &job)
            .await
            .map_err(RuntimeError::Call)?
            .map_err(|error| RuntimeError::Job(format!("{error:?}")))?;
        store
            .data()
            .lease
            .authorize_final_result(&result, std::time::Instant::now())
            .map_err(|error| RuntimeError::Job(error.to_string()))?;
        let component_result =
            serde_json::from_str(&result).map_err(|error| RuntimeError::Job(error.to_string()))?;
        let native = store.data().oracle_result().map_err(RuntimeError::Job)?;
        Ok(BehaviorShadowResult {
            native,
            component: component_result,
            progress: store.data().progress.clone(),
        })
    }

    /// Execute one immutable measurement through the real bounded host adapter
    /// while retaining the native result from the exact same raw execution as
    /// an oracle. The component does not become authoritative here.
    ///
    /// # Errors
    /// Returns an error for capability-policy, native-execution, Wasmtime,
    /// guest, or result-serialization failures.
    pub async fn shadow_measurement(
        &self,
        compiled: &CompiledBehavior,
        measurement: serde_json::Value,
        progress_tx: Option<crate::command::ProgressTx>,
    ) -> Result<BehaviorShadowResult, RuntimeError> {
        self.shadow_component(&compiled.component, measurement, progress_tx)
            .await
    }
}
