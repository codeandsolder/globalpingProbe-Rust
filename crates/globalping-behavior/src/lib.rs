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
#[allow(
    unsafe_code,
    reason = "wit-bindgen generates canonical ABI glue that requires unsafe exports and blocks"
)]
#[allow(
    clippy::same_length_and_capacity,
    reason = "wit-bindgen reconstructs exact-length canonical ABI buffers"
)]
mod component {
    use alloc::alloc::{Layout, alloc, dealloc, realloc};
    use alloc::string::{String, ToString as _};

    use core::ffi::c_void;

    use serde::Deserialize;

    // The freestanding custom-world component deliberately links no WASI libc.
    // LLVM/core may still lower byte-slice equality to the conventional C ABI
    // `memcmp` symbol, so provide that one runtime primitive locally.
    //
    // SAFETY: callers must provide readable `len`-byte regions when `len > 0`;
    // the zero-length case performs no pointer access and therefore also accepts
    // null pointers, matching the C `memcmp` contract.
    #[unsafe(export_name = "memcmp")]
    unsafe extern "C" fn runtime_memcmp(
        left: *const c_void,
        right: *const c_void,
        len: usize,
    ) -> i32 {
        let left = left.cast::<u8>();
        let right = right.cast::<u8>();
        for index in 0..len {
            // SAFETY: guaranteed by the function's C ABI caller contract above.
            let left_byte = unsafe { *left.add(index) };
            // SAFETY: guaranteed by the function's C ABI caller contract above.
            let right_byte = unsafe { *right.add(index) };
            if left_byte != right_byte {
                return i32::from(left_byte) - i32::from(right_byte);
            }
        }
        0
    }

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

    use codeandsolder::globalping_behavior::host::MeasurementKind;
    use exports::codeandsolder::globalping_behavior::guest::{BehaviorError, Guest, Job};

    mod dns;
    mod execution;
    mod ip;
    mod mtr;
    mod ping;
    mod traceroute;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MeasurementRequest {
        target: String,
        #[serde(default)]
        protocol: Option<String>,
        #[serde(default)]
        in_progress_updates: bool,
        #[serde(default)]
        trace: bool,
    }

    struct Behavior;

    impl Guest for Behavior {
        fn handle(job: Job) -> Result<String, BehaviorError> {
            if job.measurement_json.is_empty() {
                return Err(BehaviorError::InvalidJob(
                    "measurement request is empty".to_string(),
                ));
            }
            let measurement: MeasurementRequest = serde_json::from_str(&job.measurement_json)
                .map_err(|error| BehaviorError::InvalidJob(error.to_string()))?;
            if measurement.target.is_empty() {
                return Err(BehaviorError::InvalidJob(
                    "measurement target is empty".to_string(),
                ));
            }

            match job.kind {
                MeasurementKind::Dns => dns::run(
                    &job.token,
                    measurement.trace,
                    measurement.in_progress_updates,
                ),
                MeasurementKind::Ping => ping::run(
                    &job.token,
                    measurement.in_progress_updates,
                    measurement
                        .protocol
                        .as_deref()
                        .is_some_and(|protocol| protocol.eq_ignore_ascii_case("TCP")),
                ),
                MeasurementKind::Traceroute => {
                    traceroute::run(&job.token, measurement.in_progress_updates)
                }
                MeasurementKind::Mtr => mtr::run(&job.token, measurement.in_progress_updates),
                MeasurementKind::Http => Err(BehaviorError::Internal(
                    "measurement behavior has not migrated to the component yet".to_string(),
                )),
            }
        }

        fn self_test() -> Result<(), String> {
            dns::self_test()?;
            ping::self_test()?;
            mtr::self_test()?;
            traceroute::self_test()?;
            Ok(())
        }
    }

    export!(Behavior);
}
