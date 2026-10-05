use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use globalping_probe::supervisor::runtime::BehaviorRuntime;
use globalping_probe::supervisor::update::{
    BehaviorManifest, SUPPORTED_ABI_MAJOR, SUPPORTED_ABI_MINOR, verify_candidate,
};
use semver::Version;
use sha2::{Digest as _, Sha256};

const COMPONENT_ENV: &str = "GLOBALPING_BEHAVIOR_COMPONENT";

fn component_path() -> PathBuf {
    std::env::var_os(COMPONENT_ENV).map_or_else(
        || {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/wasm32-wasip2/release/globalping_behavior.wasm")
        },
        PathBuf::from,
    )
}

#[tokio::test]
#[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
async fn signed_component_instantiates_without_ambient_wasi() {
    let path = component_path();
    let component = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

    let signing_key = SigningKey::from_bytes(&[0x47; 32]);
    let digest = Sha256::digest(&component);
    let mut manifest = BehaviorManifest {
        sequence: 1,
        abi_major: SUPPORTED_ABI_MAJOR,
        abi_minor: SUPPORTED_ABI_MINOR,
        min_supervisor_version: "0.48.0".to_string(),
        size: component.len() as u64,
        sha256: hex::encode(digest),
        build_id: "integration-self-test".to_string(),
        signature: String::new(),
    };
    manifest.signature = hex::encode(signing_key.sign(&manifest.signing_payload()).to_bytes());

    let verified = verify_candidate(
        manifest,
        component,
        &signing_key.verifying_key(),
        0,
        &Version::new(0, 48, 0),
    )
    .unwrap_or_else(|error| panic!("component verification failed: {error}"));

    let runtime = BehaviorRuntime::new()
        .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
    let compiled = runtime
        .compile(verified)
        .unwrap_or_else(|error| panic!("component compilation failed: {error}"));
    runtime
        .self_test(&compiled)
        .await
        .unwrap_or_else(|error| panic!("component self-test failed: {error}"));
}
