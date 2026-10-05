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
    use alloc::alloc::{Layout, alloc, dealloc, realloc};
    use alloc::string::{String, ToString as _};

    // `wasm-component-ld` requires this canonical ABI allocator export. The
    // implementation deliberately lives beside wit-bindgen's generated unsafe
    // glue, and all size/alignment arithmetic is validated before touching the
    // global allocator.
    #[unsafe(export_name = "cabi_realloc")]
    unsafe extern "C" fn canonical_abi_realloc(
        old_ptr: *mut u8,
        old_len: usize,
        align: usize,
        new_len: usize,
    ) -> *mut u8 {
        if old_len == 0 {
            if new_len == 0 {
                return align as *mut u8;
            }
            let Ok(layout) = Layout::from_size_align(new_len, align) else {
                core::arch::wasm32::unreachable();
            };
            // SAFETY: `layout` was validated immediately above.
            let pointer = unsafe { alloc(layout) };
            if pointer.is_null() {
                core::arch::wasm32::unreachable();
            }
            return pointer;
        }

        let Ok(old_layout) = Layout::from_size_align(old_len, align) else {
            core::arch::wasm32::unreachable();
        };
        if new_len == 0 {
            // SAFETY: canonical ABI callers only return pointers previously
            // allocated by this function with this exact layout.
            unsafe { dealloc(old_ptr, old_layout) };
            return align as *mut u8;
        }

        // SAFETY: same allocation provenance/layout invariant as above; the new
        // size is non-zero on this branch.
        let pointer = unsafe { realloc(old_ptr, old_layout, new_len) };
        if pointer.is_null() {
            core::arch::wasm32::unreachable();
        }
        pointer
    }

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
