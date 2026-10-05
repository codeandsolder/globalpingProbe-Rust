//! Updateable Globalping measurement behavior component.
//!
//! This crate intentionally has no native feature and no ambient host API. All
//! privileged operations are available only through the `probe-behavior` WIT
//! capability interface implemented by the stable native supervisor.

// `wit-bindgen` generates the canonical ABI shims, which necessarily contain
// unsafe exports/blocks. Keep that exemption confined to generated glue; the
// rest of this crate remains under the workspace `unsafe_code = "deny"` lint.
#[allow(unsafe_code)]
mod component {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "probe-behavior",
    });

    use exports::codeandsolder::globalping_behavior::guest::{BehaviorError, Guest, Job};

    struct Behavior;

    impl Guest for Behavior {
        fn handle(job: Job) -> Result<String, BehaviorError> {
            // The first migration checkpoint only proves the custom component ABI.
            // Measurement execution moves here one command at a time; until then,
            // the native implementation remains authoritative.
            serde_json::from_str::<serde_json::Value>(&job.measurement_json)
                .map_err(|error| BehaviorError::InvalidJob(error.to_string()))?;
            Err(BehaviorError::Internal(
                "measurement behavior has not migrated to the component yet".to_string(),
            ))
        }

        fn self_test() -> Result<(), String> {
            Ok(())
        }
    }

    export!(Behavior);
}
