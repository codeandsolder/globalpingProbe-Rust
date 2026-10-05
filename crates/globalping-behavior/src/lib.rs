#![no_std]

//! Updateable Globalping measurement behavior component.
//!
//! This crate intentionally has no native feature and no ambient host API. All
//! privileged operations are available only through the `probe-behavior` WIT
//! capability interface implemented by the stable native supervisor.

extern crate alloc;

use core::panic::PanicInfo;

#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

// `wit-bindgen` generates the canonical ABI shims, which necessarily contain
// unsafe exports/blocks. Keep that exemption confined to generated glue; the
// rest of this crate remains under the workspace `unsafe_code = "deny"` lint.
#[allow(unsafe_code)]
mod component {
    use alloc::string::{String, ToString as _};

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
            if job.measurement_json.is_empty() {
                return Err(BehaviorError::InvalidJob(
                    "measurement request is empty".to_string(),
                ));
            }
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
