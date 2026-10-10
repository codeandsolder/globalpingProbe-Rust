use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use globalping_probe::supervisor::bootstrap::{
    BehaviorBootstrapConfig, BehaviorController, BehaviorDiagnosticAction, BehaviorHealthAction,
    BootstrapError,
};
use globalping_probe::supervisor::health::{
    BehaviorDiagnosticEvent, BehaviorHealthEvent, BehaviorHealthPolicy,
};
use globalping_probe::supervisor::runtime::{BehaviorExecutor, BehaviorRuntime};
use globalping_probe::supervisor::storage::{PersistentBehaviorSlots, StorageError};
use globalping_probe::supervisor::update::{
    BehaviorManifest, SUPPORTED_ABI_MAJOR, SUPPORTED_ABI_MINOR, UpdateError, verify_candidate,
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

fn component_bytes() -> Vec<u8> {
    let path = component_path();
    std::fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn behavior_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x47; 32])
}

fn signed_component(sequence: u64, build_id: &str) -> (BehaviorManifest, Vec<u8>) {
    let component = component_bytes();
    let signing_key = behavior_signing_key();
    let digest = Sha256::digest(&component);
    let mut manifest = BehaviorManifest {
        sequence,
        abi_major: SUPPORTED_ABI_MAJOR,
        abi_minor: SUPPORTED_ABI_MINOR,
        min_supervisor_version: "0.48.0".to_string(),
        size: component.len() as u64,
        sha256: hex::encode(digest),
        build_id: build_id.to_string(),
        signature: String::new(),
    };
    manifest.signature = hex::encode(signing_key.sign(&manifest.signing_payload()).to_bytes());
    (manifest, component)
}

fn verified_component(
    sequence: u64,
    build_id: &str,
) -> globalping_probe::supervisor::update::VerifiedBehavior {
    let (manifest, component) = signed_component(sequence, build_id);
    verify_candidate(
        manifest,
        component,
        &behavior_signing_key().verifying_key(),
        sequence.saturating_sub(1),
        &Version::new(0, 48, 0),
    )
    .unwrap_or_else(|error| panic!("component verification failed: {error}"))
}

#[tokio::test]
#[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
async fn signed_component_instantiates_without_ambient_wasi() {
    let verified = verified_component(1, "integration-self-test");

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

#[tokio::test]
#[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
async fn verified_component_builds_behavior_executor() {
    let executor = BehaviorExecutor::from_verified(verified_component(7, "dispatch-behavior"))
        .await
        .unwrap_or_else(|error| panic!("behavior executor construction failed: {error}"));
    assert_eq!(executor.sequence(), 7);
    assert_eq!(executor.build_id(), "dispatch-behavior");
}

#[tokio::test]
#[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
async fn behavior_controller_loads_persisted_active_and_previous() {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let mut slots =
        PersistentBehaviorSlots::initialize(dir.path(), verified_component(10, "previous"))
            .unwrap_or_else(|error| panic!("persistent behavior initialization failed: {error}"));
    slots
        .activate(verified_component(11, "persistent-active"))
        .unwrap_or_else(|error| panic!("persistent behavior activation failed: {error}"));
    drop(slots);

    let config = BehaviorBootstrapConfig::new(dir.path(), behavior_signing_key().verifying_key());
    let controller = BehaviorController::load(config)
        .await
        .unwrap_or_else(|error| panic!("persistent behavior bootstrap failed: {error}"));

    assert_eq!(controller.active_sequence().unwrap_or(None), Some(11));
    assert_eq!(controller.accepted_sequence().unwrap_or_default(), 11);
    assert!(controller.has_previous().unwrap_or(false));
    let executor = controller
        .executor()
        .await
        .unwrap_or_else(|| panic!("active executor must be available"));
    assert_eq!(executor.sequence(), 11);
    assert_eq!(executor.build_id(), "persistent-active");

    let rolled_back = controller
        .rollback()
        .await
        .unwrap_or_else(|error| panic!("rollback failed: {error}"));
    assert_eq!(rolled_back.sequence(), 10);
    assert_eq!(rolled_back.build_id(), "previous");
    assert_eq!(controller.active_sequence().unwrap_or(None), Some(10));
    assert_eq!(controller.accepted_sequence().unwrap_or_default(), 11);
    assert!(!controller.has_previous().unwrap_or(true));
}

#[tokio::test]
#[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
async fn behavior_controller_activates_signed_updates_and_preserves_high_water() {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let config = BehaviorBootstrapConfig::new(dir.path(), behavior_signing_key().verifying_key());
    let controller = BehaviorController::load(config)
        .await
        .unwrap_or_else(|error| panic!("empty behavior controller failed: {error}"));
    assert!(controller.executor().await.is_none());
    assert_eq!(controller.accepted_sequence().unwrap_or_default(), 0);

    let (first_manifest, first_component) = signed_component(1, "first");
    let first = controller
        .activate_candidate(first_manifest, first_component)
        .await
        .unwrap_or_else(|error| panic!("first activation failed: {error}"));
    assert_eq!(first.sequence(), 1);
    assert_eq!(controller.active_sequence().unwrap_or(None), Some(1));
    assert!(!controller.has_previous().unwrap_or(true));

    let (second_manifest, second_component) = signed_component(2, "second");
    let second = controller
        .activate_candidate(second_manifest, second_component)
        .await
        .unwrap_or_else(|error| panic!("second activation failed: {error}"));
    assert_eq!(second.sequence(), 2);
    assert_eq!(controller.accepted_sequence().unwrap_or_default(), 2);
    assert!(controller.has_previous().unwrap_or(false));

    let rolled_back = controller
        .rollback()
        .await
        .unwrap_or_else(|error| panic!("rollback failed: {error}"));
    assert_eq!(rolled_back.sequence(), 1);
    assert_eq!(controller.active_sequence().unwrap_or(None), Some(1));
    assert_eq!(controller.accepted_sequence().unwrap_or_default(), 2);

    let (replay_manifest, replay_component) = signed_component(2, "replay");
    assert!(matches!(
        controller
            .activate_candidate(replay_manifest, replay_component)
            .await,
        Err(BootstrapError::Update(UpdateError::RollbackSequence))
    ));

    let reloaded = PersistentBehaviorSlots::load(
        dir.path(),
        &behavior_signing_key().verifying_key(),
        &Version::new(0, 48, 0),
    )
    .unwrap_or_else(|error| panic!("persistent behavior reload failed: {error}"));
    assert_eq!(reloaded.active().manifest.sequence, 1);
    assert_eq!(reloaded.accepted_sequence(), 2);
    assert!(reloaded.previous().is_none());
}

#[tokio::test]
#[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
async fn behavior_controller_auto_rolls_back_after_hard_fault_threshold() {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let policy = BehaviorHealthPolicy::new(
        NonZeroU32::new(2).unwrap_or_else(|| panic!("threshold must be non-zero")),
    );
    let config = BehaviorBootstrapConfig::new(dir.path(), behavior_signing_key().verifying_key())
        .with_health_policy(policy);
    let controller = BehaviorController::load(config)
        .await
        .unwrap_or_else(|error| panic!("empty behavior controller failed: {error}"));

    let (first_manifest, first_component) = signed_component(1, "healthy-previous");
    controller
        .activate_candidate(first_manifest, first_component)
        .await
        .unwrap_or_else(|error| panic!("first activation failed: {error}"));
    let (second_manifest, second_component) = signed_component(2, "unhealthy-active");
    controller
        .activate_candidate(second_manifest, second_component)
        .await
        .unwrap_or_else(|error| panic!("second activation failed: {error}"));

    assert_eq!(
        controller
            .observe_health(2, BehaviorHealthEvent::Success)
            .await
            .unwrap_or_else(|error| panic!("success health accounting failed: {error}")),
        BehaviorHealthAction::None
    );
    assert_eq!(
        controller
            .observe_diagnostic(2, BehaviorDiagnosticEvent::Divergence)
            .await,
        BehaviorDiagnosticAction::FirstDivergence
    );
    let divergent_health = controller.health_snapshot().await;
    assert_eq!(divergent_health.consecutive_faults, 0);
    assert_eq!(divergent_health.divergences, 1);

    assert_eq!(
        controller
            .observe_health(2, BehaviorHealthEvent::RuntimeFault)
            .await
            .unwrap_or_else(|error| panic!("first hard fault accounting failed: {error}")),
        BehaviorHealthAction::None
    );
    assert_eq!(controller.health_snapshot().await.consecutive_faults, 1);
    assert_eq!(
        controller
            .observe_diagnostic(2, BehaviorDiagnosticEvent::Match)
            .await,
        BehaviorDiagnosticAction::None
    );
    assert_eq!(
        controller.health_snapshot().await.consecutive_faults,
        1,
        "a late oracle diagnostic must not erase a newer component fault"
    );

    assert_eq!(
        controller
            .observe_health(2, BehaviorHealthEvent::RuntimeFault)
            .await
            .unwrap_or_else(|error| panic!("health rollback failed: {error}")),
        BehaviorHealthAction::RolledBack {
            from_sequence: 2,
            to_sequence: 1,
        }
    );
    assert_eq!(controller.active_sequence().unwrap_or(None), Some(1));
    assert_eq!(controller.accepted_sequence().unwrap_or_default(), 2);
    assert!(!controller.has_previous().unwrap_or(true));
    let executor = controller
        .executor()
        .await
        .unwrap_or_else(|| panic!("rollback executor must be available"));
    assert_eq!(executor.sequence(), 1);
    let health = controller.health_snapshot().await;
    assert_eq!(health.active_sequence, Some(1));
    assert_eq!(health.consecutive_faults, 0);
    assert_eq!(health.matches, 0);
}

#[tokio::test]
#[ignore = "requires a prebuilt wasm32-wasip2 globalping-behavior component"]
async fn behavior_controller_rejects_wrong_trust_root() {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    PersistentBehaviorSlots::initialize(dir.path(), verified_component(12, "wrong-key"))
        .unwrap_or_else(|error| panic!("persistent behavior initialization failed: {error}"));

    let wrong_key = SigningKey::from_bytes(&[0x99; 32]).verifying_key();
    let config = BehaviorBootstrapConfig::new(dir.path(), wrong_key);
    let result = BehaviorController::load(config).await;
    assert!(matches!(
        result,
        Err(BootstrapError::Storage(StorageError::Update(
            UpdateError::SignatureMismatch
        )))
    ));
}

#[tokio::test]
async fn behavior_controller_distinguishes_empty_store_and_invalid_root() {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let key = behavior_signing_key().verifying_key();
    let config = BehaviorBootstrapConfig::new(dir.path(), key);
    let controller = BehaviorController::load(config)
        .await
        .unwrap_or_else(|error| panic!("empty controller failed: {error}"));
    assert!(controller.executor().await.is_none());
    assert_eq!(controller.active_sequence().unwrap_or(None), None);
    assert_eq!(controller.accepted_sequence().unwrap_or_default(), 0);

    let relative = BehaviorBootstrapConfig::new("relative-behavior-store", key);
    assert!(matches!(
        BehaviorController::load(relative).await,
        Err(BootstrapError::RelativeRoot)
    ));
}
