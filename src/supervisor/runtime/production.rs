use super::{
    BehaviorRuntime, CompiledBehavior, Component, Future, HasSelf, JOB_FUEL, Linker, ProbeBehavior,
    RuntimeError, Store, StoreLimits, exports, ready, wit_host,
};

#[derive(Debug)]
pub struct BehaviorShadowResult {
    pub native: serde_json::Value,
    pub component: serde_json::Value,
    pub progress: Vec<(serde_json::Value, bool)>,
    pub progress_during_native_execution: bool,
}

#[derive(Clone, Debug)]
enum ShadowOracle {
    Ready(serde_json::Value),
    Ping {
        raw: String,
        timed_out: bool,
        target: crate::util::resolve_target::ResolvedTarget,
    },
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

type OracleSlot = std::sync::Arc<std::sync::Mutex<Option<Result<ShadowOracle, String>>>>;

struct StartedExecution {
    start: wit_host::ExecutionStartResult,
    events: tokio::sync::mpsc::Receiver<crate::command::RawExecutionEvent>,
    oracle: OracleSlot,
    mtr_enrichment: Option<crate::command::mtr::MtrEnrichmentBroker>,
}

struct ProductionHost {
    limits: StoreLimits,
    lease: crate::supervisor::capability::CapabilityLease,
    events: Option<tokio::sync::mpsc::Receiver<crate::command::RawExecutionEvent>>,
    native_progress_tx: Option<crate::command::ProgressTx>,
    progress: Vec<(serde_json::Value, bool)>,
    progress_during_native_execution: bool,
    reverse_results: std::collections::HashMap<std::net::IpAddr, String>,
    asn_results: std::collections::HashMap<std::net::IpAddr, Vec<u32>>,
    mtr_enrichment: Option<crate::command::mtr::MtrEnrichmentBroker>,
    oracle: Option<OracleSlot>,
}

impl ProductionHost {
    fn new(
        lease: crate::supervisor::capability::CapabilityLease,
        native_progress_tx: Option<crate::command::ProgressTx>,
    ) -> Self {
        Self {
            limits: BehaviorRuntime::store_limits(),
            lease,
            events: None,
            native_progress_tx,
            progress: Vec::new(),
            progress_during_native_execution: false,
            reverse_results: std::collections::HashMap::new(),
            asn_results: std::collections::HashMap::new(),
            mtr_enrichment: None,
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
        let slot = self
            .oracle
            .as_ref()
            .ok_or_else(|| "native shadow oracle was not initialized".to_string())?;
        let oracle = {
            let guard = slot
                .lock()
                .map_err(|_| "native shadow oracle lock was poisoned".to_string())?;
            guard
                .as_ref()
                .ok_or_else(|| "native shadow oracle was not ready at terminal event".to_string())?
                .clone()?
        };
        match &oracle {
            ShadowOracle::Ready(value) => Ok(value.clone()),
            ShadowOracle::Ping {
                raw,
                timed_out,
                target,
            } => serde_json::to_value(crate::command::ping::shape_ping_output(
                raw,
                &target.address.to_string(),
                &target.hostname,
                *timed_out,
            ))
            .map_err(|error| error.to_string()),
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
                let enrichment = self.mtr_enrichment.as_ref().map_or_else(
                    Default::default,
                    crate::command::mtr::MtrEnrichmentBroker::snapshot,
                );
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
        dns_duration_ms: None,
        target_is_icann: target_is_icann(&scope.target),
        local_addresses: local_addresses(),
    }
}

fn new_oracle_slot() -> OracleSlot {
    std::sync::Arc::new(std::sync::Mutex::new(None))
}

const fn resolution_failure_kind(
    error: &crate::util::resolve_target::ResolveTargetError,
) -> wit_host::ResolutionFailureKind {
    use crate::util::resolve_target::ResolveTargetError;
    match error {
        ResolveTargetError::PrivateIp => wit_host::ResolutionFailureKind::PrivateAddress,
        ResolveTargetError::TimedOut => wit_host::ResolutionFailureKind::TimedOut,
        ResolveTargetError::NotFound => wit_host::ResolutionFailureKind::NotFound,
        ResolveTargetError::Lookup(_) => wit_host::ResolutionFailureKind::LookupFailed,
    }
}

fn resolution_failed_execution_with_message(
    reason: wit_host::ResolutionFailureKind,
    public_message: Option<String>,
    native: serde_json::Value,
) -> StartedExecution {
    let (_tx, events) = crate::command::RawExecutionTx::channel();
    let oracle = new_oracle_slot();
    store_oracle(&oracle, Ok(ShadowOracle::Ready(native)));
    StartedExecution {
        start: wit_host::ExecutionStartResult::ResolutionFailed(wit_host::ResolutionFailure {
            kind: reason,
            public_message,
        }),
        events,
        oracle,
        mtr_enrichment: None,
    }
}

fn resolution_failed_execution(
    reason: wit_host::ResolutionFailureKind,
    native: serde_json::Value,
) -> StartedExecution {
    resolution_failed_execution_with_message(reason, None, native)
}

fn store_oracle(slot: &OracleSlot, oracle: Result<ShadowOracle, String>) {
    if let Ok(mut guard) = slot.lock() {
        *guard = Some(oracle);
    }
}

async fn send_terminal(
    tx: &crate::command::RawExecutionTx,
    timed_out: bool,
    exit_code: Option<i32>,
) {
    let event = if timed_out {
        crate::command::RawExecutionEvent::TimedOut
    } else {
        crate::command::RawExecutionEvent::Exited(exit_code.unwrap_or(1))
    };
    tx.send(event).await;
}

async fn prepare_ping(
    scope: &crate::supervisor::capability::MeasurementScope,
    native_progress: Option<crate::command::ProgressTx>,
) -> Result<StartedExecution, wit_host::HostError> {
    use crate::command::ping;
    use crate::util::measurement_timeout::{MeasurementDeadline, ping_budget};
    use crate::util::resolve_target::resolve_command_target;
    use std::time::Duration;

    let opts: ping::PingOptions =
        serde_json::from_value(scope.measurement.clone()).map_err(native_error)?;
    ping::validate(&opts).map_err(native_error)?;
    let deadline = MeasurementDeadline::new(opts.timeout);
    let budget = ping_budget(opts.packets, opts.timeout, None);
    let dns_budget = Duration::from_secs_f64(budget.dns_headroom.max(0.0));
    let target = match resolve_command_target(&opts.target, opts.ip_version, dns_budget).await {
        Ok(target) => target,
        Err(error) => {
            let reason = resolution_failure_kind(&error);
            let native =
                serde_json::to_value(ping::resolution_failure(&error)).map_err(native_error)?;
            return Ok(resolution_failed_execution(reason, native));
        }
    };
    let mut resolved_options = opts.clone();
    resolved_options.target = target.address.to_string();
    let (tx, events) = crate::command::RawExecutionTx::channel();
    let oracle = new_oracle_slot();
    let task_oracle = std::sync::Arc::clone(&oracle);
    let task_target = target.clone();
    tokio::spawn(async move {
        let native = if resolved_options.protocol.eq_ignore_ascii_case("TCP") {
            ping::run_tcp_raw_stream(
                &resolved_options,
                &task_target,
                native_progress,
                deadline.remaining(),
                &tx,
            )
            .await
        } else {
            ping::run_icmp_raw_stream(
                &resolved_options,
                &task_target,
                native_progress,
                deadline.process_timeout(),
                &tx,
            )
            .await
        };
        match native {
            Ok(native) => {
                let timed_out = native.timed_out;
                store_oracle(
                    &task_oracle,
                    Ok(ShadowOracle::Ping {
                        raw: native.raw,
                        timed_out,
                        target: task_target,
                    }),
                );
                send_terminal(&tx, timed_out, native.exit_code).await;
            }
            Err(error) => store_oracle(&task_oracle, Err(error.to_string())),
        }
    });
    Ok(StartedExecution {
        start: wit_host::ExecutionStartResult::Started(execution_start(
            wit_host::MeasurementKind::Ping,
            scope,
            target.address.to_string(),
            target.hostname,
        )),
        events,
        oracle,
        mtr_enrichment: None,
    })
}

fn prepare_dns(
    scope: &crate::supervisor::capability::MeasurementScope,
    native_progress: Option<crate::command::ProgressTx>,
) -> Result<StartedExecution, wit_host::HostError> {
    use crate::command::dns;

    let opts: dns::DnsOptions =
        serde_json::from_value(scope.measurement.clone()).map_err(native_error)?;
    dns::validate(&opts).map_err(native_error)?;
    let start_target = opts.target.clone();
    let (tx, events) = crate::command::RawExecutionTx::channel();
    let oracle = new_oracle_slot();
    let task_oracle = std::sync::Arc::clone(&oracle);
    tokio::spawn(async move {
        match dns::run_dig_stream(&opts, native_progress.as_ref(), &tx).await {
            Ok(native) => {
                let process_failed = native.status.is_some_and(|status| !status.success());
                let shaped = if opts.trace {
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
                };
                match shaped {
                    Ok(value) => {
                        store_oracle(&task_oracle, Ok(ShadowOracle::Ready(value)));
                        send_terminal(
                            &tx,
                            native.timed_out,
                            native.status.map(|status| {
                                status
                                    .code()
                                    .unwrap_or_else(|| i32::from(!status.success()))
                            }),
                        )
                        .await;
                    }
                    Err(error) => store_oracle(&task_oracle, Err(error.to_string())),
                }
            }
            Err(error) => store_oracle(&task_oracle, Err(error.to_string())),
        }
    });
    Ok(StartedExecution {
        start: wit_host::ExecutionStartResult::Started(execution_start(
            wit_host::MeasurementKind::Dns,
            scope,
            start_target.clone(),
            start_target,
        )),
        events,
        oracle,
        mtr_enrichment: None,
    })
}

async fn prepare_traceroute(
    scope: &crate::supervisor::capability::MeasurementScope,
    native_progress: Option<crate::command::ProgressTx>,
) -> Result<StartedExecution, wit_host::HostError> {
    use crate::command::traceroute;
    use crate::util::measurement_timeout::{MeasurementDeadline, traceroute_budget};
    use crate::util::resolve_target::resolve_command_target;
    use std::time::Duration;

    let opts: traceroute::TracerouteOptions =
        serde_json::from_value(scope.measurement.clone()).map_err(native_error)?;
    traceroute::validate(&opts).map_err(native_error)?;
    let deadline = MeasurementDeadline::new(opts.timeout);
    let budget = traceroute_budget(opts.timeout, 2);
    let dns_budget = Duration::from_secs_f64(budget.dns_headroom.max(0.0));
    let target = match resolve_command_target(&opts.target, opts.ip_version, dns_budget).await {
        Ok(target) => target,
        Err(error) => {
            let reason = resolution_failure_kind(&error);
            let native = serde_json::to_value(traceroute::resolution_failure(&error))
                .map_err(native_error)?;
            return Ok(resolution_failed_execution(reason, native));
        }
    };
    let mut resolved_options = opts.clone();
    resolved_options.target = target.address.to_string();
    let args = traceroute::build_args(&resolved_options);
    let (tx, events) = crate::command::RawExecutionTx::channel();
    let oracle = new_oracle_slot();
    let task_oracle = std::sync::Arc::clone(&oracle);
    let task_target = target.clone();
    tokio::spawn(async move {
        match traceroute::run_native_traceroute_stream(
            &args,
            deadline.process_timeout(),
            &task_target,
            native_progress.as_ref(),
            &tx,
        )
        .await
        {
            Ok(native) => {
                let timed_out = native.timed_out;
                let status = native.status;
                store_oracle(
                    &task_oracle,
                    Ok(ShadowOracle::Traceroute {
                        raw: native.raw,
                        stderr: native.stderr,
                        timed_out,
                        succeeded: status.map(|status| status.success()),
                        target: task_target,
                    }),
                );
                send_terminal(
                    &tx,
                    timed_out,
                    status.map(|status| {
                        status
                            .code()
                            .unwrap_or_else(|| i32::from(!status.success()))
                    }),
                )
                .await;
            }
            Err(error) => store_oracle(&task_oracle, Err(error.to_string())),
        }
    });
    Ok(StartedExecution {
        start: wit_host::ExecutionStartResult::Started(execution_start(
            wit_host::MeasurementKind::Traceroute,
            scope,
            target.address.to_string(),
            target.hostname,
        )),
        events,
        oracle,
        mtr_enrichment: None,
    })
}

async fn prepare_mtr(
    scope: &crate::supervisor::capability::MeasurementScope,
    native_progress: Option<crate::command::ProgressTx>,
) -> Result<StartedExecution, wit_host::HostError> {
    use crate::command::mtr;
    use crate::util::measurement_timeout::{MeasurementDeadline, mtr_budget};
    use crate::util::resolve_target::resolve_command_target;
    use std::time::Duration;

    let opts: mtr::MtrOptions =
        serde_json::from_value(scope.measurement.clone()).map_err(native_error)?;
    mtr::validate(&opts).map_err(native_error)?;
    let deadline = MeasurementDeadline::new(opts.timeout);
    let budget = mtr_budget(opts.packets, opts.timeout);
    let dns_budget = Duration::from_secs_f64(budget.dns_headroom.max(0.0));
    let target = match resolve_command_target(&opts.target, opts.ip_version, dns_budget).await {
        Ok(target) => target,
        Err(error) => {
            let reason = resolution_failure_kind(&error);
            let native =
                serde_json::to_value(mtr::resolution_failure(&error)).map_err(native_error)?;
            return Ok(resolution_failed_execution(reason, native));
        }
    };
    let mut resolved_options = opts.clone();
    resolved_options.target = target.address.to_string();
    let args = mtr::build_args(&resolved_options);
    let (tx, events) = crate::command::RawExecutionTx::channel();
    let oracle = new_oracle_slot();
    let task_oracle = std::sync::Arc::clone(&oracle);
    let task_target = target.clone();
    let mut enrichment = mtr::MtrEnrichment::new(&target);
    let shared_enrichment = enrichment.broker();
    let task_progress = native_progress.clone();
    tokio::spawn(async move {
        match mtr::run_native_mtr_stream(
            &args,
            deadline.process_timeout(),
            task_progress.as_ref(),
            &mut enrichment,
            &deadline,
            &tx,
        )
        .await
        {
            Ok(native) => {
                enrichment.wait().await;
                let timed_out = native.timed_out;
                store_oracle(
                    &task_oracle,
                    Ok(ShadowOracle::Mtr {
                        raw: native.stdout,
                        stderr: native.stderr,
                        timed_out,
                        target: task_target,
                    }),
                );
                send_terminal(&tx, timed_out, native.exit_code).await;
            }
            Err(error) => store_oracle(&task_oracle, Err(error.to_string())),
        }
    });
    Ok(StartedExecution {
        start: wit_host::ExecutionStartResult::Started(execution_start(
            wit_host::MeasurementKind::Mtr,
            scope,
            target.address.to_string(),
            target.hostname,
        )),
        events,
        oracle,
        mtr_enrichment: Some(shared_enrichment),
    })
}

async fn prepare_http(
    scope: &crate::supervisor::capability::MeasurementScope,
    native_progress: Option<crate::command::ProgressTx>,
) -> Result<StartedExecution, wit_host::HostError> {
    use crate::command::http;
    use crate::util::measurement_timeout::MeasurementDeadline;

    let opts: http::HttpOptions =
        serde_json::from_value(scope.measurement.clone()).map_err(native_error)?;
    http::validate(&opts).map_err(native_error)?;
    let deadline = MeasurementDeadline::new(opts.timeout);
    let (resolved_ip, dns_ms) = match http::resolve_target(
        &opts.target,
        opts.resolver.as_deref(),
        opts.ip_version,
        opts.timeout,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            let reason = match error {
                http::HttpResolveError::PrivateIp => {
                    wit_host::ResolutionFailureKind::PrivateAddress
                }
                http::HttpResolveError::TimedOut => wit_host::ResolutionFailureKind::TimedOut,
                http::HttpResolveError::Failed(_) => wit_host::ResolutionFailureKind::LookupFailed,
            };
            let message = error.public_message();
            let native = serde_json::to_value(globalping_behavior_core::http::failed_result(
                error.failure_source(),
                message.clone(),
            ))
            .map_err(native_error)?;
            return Ok(resolution_failed_execution_with_message(
                reason,
                Some(message),
                native,
            ));
        }
    };

    let (tx, events) = crate::command::RawExecutionTx::channel();
    let oracle = new_oracle_slot();
    let task_oracle = std::sync::Arc::clone(&oracle);
    let task_opts = opts.clone();
    let task_ip = resolved_ip.clone();
    tokio::spawn(async move {
        let raw = http::run_raw_stream(
            &task_opts,
            task_ip,
            dns_ms,
            deadline,
            native_progress.as_ref(),
            &tx,
        )
        .await;
        match serde_json::to_value(raw.native) {
            Ok(native) => {
                store_oracle(&task_oracle, Ok(ShadowOracle::Ready(native)));
                send_terminal(&tx, raw.timed_out, raw.exit_code).await;
            }
            Err(error) => store_oracle(&task_oracle, Err(error.to_string())),
        }
    });
    let mut start = execution_start(
        wit_host::MeasurementKind::Http,
        scope,
        resolved_ip,
        opts.target.clone(),
    );
    start.dns_duration_ms = dns_ms;
    Ok(StartedExecution {
        start: wit_host::ExecutionStartResult::Started(start),
        events,
        oracle,
        mtr_enrichment: None,
    })
}

async fn prepare_native_execution(
    scope: &crate::supervisor::capability::MeasurementScope,
    native_progress: Option<crate::command::ProgressTx>,
) -> Result<StartedExecution, wit_host::HostError> {
    match scope.kind {
        crate::supervisor::capability::MeasurementKind::Ping => {
            prepare_ping(scope, native_progress).await
        }
        crate::supervisor::capability::MeasurementKind::Dns => prepare_dns(scope, native_progress),
        crate::supervisor::capability::MeasurementKind::Traceroute => {
            prepare_traceroute(scope, native_progress).await
        }
        crate::supervisor::capability::MeasurementKind::Mtr => {
            prepare_mtr(scope, native_progress).await
        }
        crate::supervisor::capability::MeasurementKind::Http => {
            prepare_http(scope, native_progress).await
        }
    }
}

impl wit_host::Host for ProductionHost {
    async fn start(
        &mut self,
        token: wit_host::CapabilityToken,
    ) -> Result<wit_host::ExecutionStartResult, wit_host::HostError> {
        self.check_token(&token)?;
        self.lease
            .authorize_start(std::time::Instant::now())
            .map_err(policy_error)?;
        let scope = self.lease.scope.clone();
        let started = prepare_native_execution(&scope, self.native_progress_tx.clone()).await?;
        self.mtr_enrichment.clone_from(&started.mtr_enrichment);
        self.events = Some(started.events);
        self.oracle = Some(started.oracle);
        Ok(started.start)
    }

    async fn poll(
        &mut self,
        token: wit_host::CapabilityToken,
    ) -> Result<Option<wit_host::ExecutionEvent>, wit_host::HostError> {
        self.check_token(&token)?;
        let remaining = self.lease.remaining(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(policy_error(
                crate::supervisor::capability::PolicyError::Expired,
            ));
        }
        let event = {
            let receiver = self.events.as_mut().ok_or_else(|| {
                host_error(
                    wit_host::HostErrorCode::PolicyDenied,
                    "native execution has not been started",
                )
            })?;
            match tokio::time::timeout(remaining, receiver.recv()).await {
                Ok(Some(event)) => event,
                Ok(None) => {
                    let message = self
                        .oracle
                        .as_ref()
                        .and_then(|slot| slot.lock().ok())
                        .and_then(|guard| match guard.as_ref() {
                            Some(Err(error)) => Some(error.clone()),
                            _ => None,
                        })
                        .unwrap_or_else(|| {
                            "native execution event stream closed before a terminal event"
                                .to_string()
                        });
                    return Err(host_error(wit_host::HostErrorCode::NativeFailure, message));
                }
                Err(_) => {
                    return Err(policy_error(
                        crate::supervisor::capability::PolicyError::Expired,
                    ));
                }
            }
        };
        let now = std::time::Instant::now();
        self.lease.authorize_poll(now).map_err(policy_error)?;
        let event = match event {
            crate::command::RawExecutionEvent::Stdout(bytes) => {
                self.lease
                    .account_raw_bytes(bytes.len(), now)
                    .map_err(policy_error)?;
                wit_host::ExecutionEvent::Stdout(bytes)
            }
            crate::command::RawExecutionEvent::Stderr(bytes) => {
                self.lease
                    .account_raw_bytes(bytes.len(), now)
                    .map_err(policy_error)?;
                wit_host::ExecutionEvent::Stderr(bytes)
            }
            crate::command::RawExecutionEvent::ObservedAddress(address) => {
                self.lease
                    .observe_address(address, now)
                    .map_err(policy_error)?;
                wit_host::ExecutionEvent::ObservedAddress(address.to_string())
            }
            crate::command::RawExecutionEvent::HttpResponseHeaders(bytes) => {
                self.lease
                    .account_raw_bytes(bytes.len(), now)
                    .map_err(policy_error)?;
                wit_host::ExecutionEvent::HttpResponseHeaders(bytes)
            }
            crate::command::RawExecutionEvent::HttpResponseBody(bytes) => {
                self.lease
                    .account_raw_bytes(bytes.len(), now)
                    .map_err(policy_error)?;
                wit_host::ExecutionEvent::HttpResponseBody(bytes)
            }
            crate::command::RawExecutionEvent::HttpTlsEnrichment(enrichment) => {
                wit_host::ExecutionEvent::HttpTlsEnrichment(wit_host::HttpTlsEnrichment {
                    authorized: enrichment.authorized,
                    subject_alt: enrichment.subject_alt,
                    key_type: enrichment.key_type,
                    key_bits: enrichment.key_bits,
                    serial_number: enrichment.serial_number,
                    fingerprint256: enrichment.fingerprint256,
                })
            }
            crate::command::RawExecutionEvent::HttpNativeFailure {
                failure_source,
                message,
            } => wit_host::ExecutionEvent::HttpNativeFailure(wit_host::HttpNativeFailure {
                failure_source,
                message,
            }),
            crate::command::RawExecutionEvent::Exited(code) => {
                wit_host::ExecutionEvent::Exited(code)
            }
            crate::command::RawExecutionEvent::TimedOut => wit_host::ExecutionEvent::TimedOut,
        };
        Ok(Some(event))
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
        let hostname = if let Some(broker) = &self.mtr_enrichment {
            broker
                .lookup(address, self.lease.remaining(now))
                .await
                .hostname
        } else {
            crate::util::resolve_target::reverse_lookup(
                address,
                self.lease
                    .remaining(now)
                    .min(std::time::Duration::from_secs(3)),
            )
            .await
        };
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
        let asn = if let Some(broker) = &self.mtr_enrichment {
            broker.lookup(address, self.lease.remaining(now)).await.asn
        } else {
            crate::command::mtr::lookup_asn(address, self.lease.remaining(now)).await
        };
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
            if self
                .oracle
                .as_ref()
                .is_some_and(|slot| slot.lock().is_ok_and(|guard| guard.is_none()))
            {
                self.progress_during_native_execution = true;
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
        native_progress_tx: Option<crate::command::ProgressTx>,
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
        let mut store = Store::new(&self.engine, ProductionHost::new(lease, native_progress_tx));
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
            .map_err(RuntimeError::Call)?;
        let result = match result {
            Ok(result) => result,
            Err(exports::codeandsolder::globalping_behavior::guest::BehaviorError::InvalidJob(
                message,
            )) => return Err(RuntimeError::GuestInvalidJob(message)),
            Err(exports::codeandsolder::globalping_behavior::guest::BehaviorError::Internal(
                message,
            )) => return Err(RuntimeError::GuestInternal(message)),
        };
        store
            .data()
            .lease
            .authorize_final_result(&result, std::time::Instant::now())
            .map_err(|error| RuntimeError::Policy(error.to_string()))?;
        let component_result = serde_json::from_str(&result)
            .map_err(|error| RuntimeError::GuestInvalidOutput(error.to_string()))?;
        let native = store.data().oracle_result().map_err(RuntimeError::Job)?;
        Ok(BehaviorShadowResult {
            native,
            component: component_result,
            progress: store.data().progress.clone(),
            progress_during_native_execution: store.data().progress_during_native_execution,
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
        native_progress_tx: Option<crate::command::ProgressTx>,
    ) -> Result<BehaviorShadowResult, RuntimeError> {
        self.shadow_component(&compiled.component, measurement, native_progress_tx)
            .await
    }
}

#[derive(Clone)]
pub struct BehaviorShadowExecutor {
    runtime: BehaviorRuntime,
    compiled: CompiledBehavior,
}

impl BehaviorShadowExecutor {
    /// Build a diagnostic shadow executor from an artifact that has already
    /// passed signature, digest, ABI, supervisor-version, and rollback checks.
    ///
    /// # Errors
    /// Returns an error if the runtime cannot be configured, the verified
    /// component cannot be compiled, or its built-in self-test fails.
    pub async fn from_verified(
        verified: crate::supervisor::update::VerifiedBehavior,
    ) -> Result<Self, RuntimeError> {
        let runtime = BehaviorRuntime::new()?;
        let compiled = runtime.compile(verified)?;
        runtime.self_test(&compiled).await?;
        Ok(Self { runtime, compiled })
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.compiled.sequence
    }

    #[must_use]
    pub fn build_id(&self) -> &str {
        &self.compiled.build_id
    }

    /// Run one diagnostic-only behavior shadow. No guest progress is forwarded
    /// outside the executor; callers decide what to do with the parity result.
    ///
    /// # Errors
    /// Returns any bounded host, Wasmtime, guest, or serialization failure.
    pub async fn run(
        &self,
        measurement: serde_json::Value,
    ) -> Result<BehaviorShadowResult, RuntimeError> {
        self.runtime
            .shadow_measurement(&self.compiled, measurement, None)
            .await
    }
}
