use alloc::collections::BTreeSet;
use alloc::string::{String, ToString as _};
use core::cell::RefCell;
use core::net::IpAddr;

use globalping_behavior_core::mtr::{
    MtrEnrichmentEntry, MtrEnrichmentMap, MtrStatus, ParsedMtr, normalize_ip_text, render_progress,
    shape_result,
};

use super::codeandsolder::globalping_behavior::host::{
    CapabilityToken, ExecutionStart, MeasurementKind,
};
use super::execution::{self, ExecutionOutcome};
use super::exports::codeandsolder::globalping_behavior::guest::BehaviorError;
use super::ip::is_private_or_reserved;

fn resolution_failure(
    reason: &super::codeandsolder::globalping_behavior::host::ResolutionFailure,
) -> ParsedMtr {
    ParsedMtr {
        status: MtrStatus::Failed,
        failure_source: Some(execution::resolution_failure_source(reason, "internal").to_string()),
        raw_output: execution::resolution_failure_message(reason),
        resolved_address: None,
        resolved_hostname: None,
        hops: alloc::vec::Vec::new(),
    }
}

#[derive(Default)]
struct State {
    enrichment: MtrEnrichmentMap,
    seen: BTreeSet<String>,
    seeded: bool,
}

impl State {
    fn ensure_seeded(&mut self, start: &ExecutionStart) {
        if self.seeded {
            return;
        }
        self.seeded = true;
        if start.resolved_hostname != start.resolved_address {
            self.enrichment
                .entry(start.resolved_address.clone())
                .or_default()
                .hostname = Some(start.resolved_hostname.clone());
        }
    }

    fn enrich(
        &mut self,
        token: &CapabilityToken,
        address: &str,
        start: &ExecutionStart,
    ) -> Result<(), BehaviorError> {
        self.ensure_seeded(start);
        let address = normalize_ip_text(address);
        let Ok(parsed) = address.parse::<IpAddr>() else {
            return Ok(());
        };
        if is_private_or_reserved(parsed, &start.local_addresses)
            || !self.seen.insert(address.clone())
        {
            return Ok(());
        }

        let entry = self.enrichment.entry(address.clone()).or_default();
        if entry.hostname.is_none() {
            entry.hostname = execution::reverse_lookup(token, &address)?;
        }
        let asn = execution::lookup_asn(token, &address)?;
        if !asn.is_empty() {
            entry.asn = asn;
        }
        Ok(())
    }
}

fn emit_snapshot(token: &CapabilityToken, raw: &str, state: &State) -> Result<(), BehaviorError> {
    let payload = serde_json::to_string(&serde_json::json!({
        "rawOutput": render_progress(raw, &state.enrichment),
    }))
    .map_err(|error| BehaviorError::Internal(error.to_string()))?;
    execution::emit_progress(token, &payload, true)
}

pub fn run(token: &CapabilityToken, in_progress_updates: bool) -> Result<String, BehaviorError> {
    let state = RefCell::new(State::default());
    let outcome = execution::collect_with_observed(
        token,
        MeasurementKind::Mtr,
        |_line, cumulative, start| {
            let mut state = state.borrow_mut();
            state.ensure_seeded(start);
            if in_progress_updates {
                emit_snapshot(token, cumulative, &state)?;
            }
            Ok(())
        },
        |address, cumulative, start| {
            let mut state = state.borrow_mut();
            state.enrich(token, address, start)?;
            if in_progress_updates {
                emit_snapshot(token, cumulative, &state)?;
            }
            Ok(())
        },
    )?;
    let native = match outcome {
        ExecutionOutcome::Executed(native) => native,
        ExecutionOutcome::ResolutionFailed(reason) => {
            return serde_json::to_string(&resolution_failure(&reason))
                .map_err(|error| BehaviorError::Internal(error.to_string()));
        }
    };

    let mut state = state.into_inner();
    if !state.seeded && native.resolved_hostname != native.resolved_address {
        state.enrichment.insert(
            native.resolved_address.clone(),
            MtrEnrichmentEntry {
                hostname: Some(native.resolved_hostname.clone()),
                asn: alloc::vec::Vec::new(),
            },
        );
    }
    let result = shape_result(
        &native.stdout,
        &native.stderr,
        native.timed_out,
        &native.resolved_address,
        &native.resolved_hostname,
        &state.enrichment,
    );
    serde_json::to_string(&result).map_err(|error| BehaviorError::Internal(error.to_string()))
}

pub fn self_test() -> Result<(), String> {
    let raw = "h 0 192.168.1.1\nx 0 0\np 0 1200 0\nh 1 1.1.1.1\nx 1 0\np 1 8000 0\n";
    let mut enrichment = MtrEnrichmentMap::new();
    enrichment.insert(
        "1.1.1.1".to_string(),
        MtrEnrichmentEntry {
            hostname: Some("one.one.one.one".to_string()),
            asn: alloc::vec![13335],
        },
    );
    let result = shape_result(raw, "", false, "1.1.1.1", "one.one.one.one", &enrichment);
    if result.hops.len() != 2
        || result.hops[0].resolved_hostname.as_deref() != Some("_gateway")
        || result.hops[1].asn != [13335]
        || result.hops[1].resolved_hostname.as_deref() != Some("one.one.one.one")
    {
        return Err("mtr behavior self-test failed".to_string());
    }
    Ok(())
}
