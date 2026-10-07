use std::fmt;
use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const SUPPORTED_ABI_MAJOR: u16 = 5;
pub const SUPPORTED_ABI_MINOR: u16 = 0;
pub const MAX_COMPONENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehaviorManifest {
    pub sequence: u64,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub min_supervisor_version: String,
    pub size: u64,
    pub sha256: String,
    pub build_id: String,
    pub signature: String,
}

impl BehaviorManifest {
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        format!(
            concat!(
                "globalping-behavior-v1\n",
                "sequence={}\n",
                "abi={}.{}\n",
                "min-supervisor={}\n",
                "size={}\n",
                "sha256={}\n",
                "build-id={}\n"
            ),
            self.sequence,
            self.abi_major,
            self.abi_minor,
            self.min_supervisor_version,
            self.size,
            self.sha256,
            self.build_id,
        )
        .into_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    ComponentTooLarge,
    SizeMismatch,
    InvalidDigest,
    DigestMismatch,
    InvalidSignature,
    SignatureMismatch,
    RollbackSequence,
    UnsupportedAbi,
    InvalidSupervisorVersion,
    SupervisorTooOld,
    NoPreviousVersion,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ComponentTooLarge => "behavior component exceeds the supervisor size limit",
            Self::SizeMismatch => "behavior component size does not match its manifest",
            Self::InvalidDigest => "manifest SHA-256 is malformed",
            Self::DigestMismatch => "behavior component SHA-256 does not match its manifest",
            Self::InvalidSignature => "manifest Ed25519 signature is malformed",
            Self::SignatureMismatch => "manifest Ed25519 signature verification failed",
            Self::RollbackSequence => "update sequence is not newer than the accepted sequence",
            Self::UnsupportedAbi => "behavior ABI is not supported by this supervisor",
            Self::InvalidSupervisorVersion => "manifest supervisor version is malformed",
            Self::SupervisorTooOld => "behavior requires a newer native supervisor",
            Self::NoPreviousVersion => "no previous behavior component is available for rollback",
        })
    }
}

impl std::error::Error for UpdateError {}

#[derive(Debug, Clone)]
pub struct VerifiedBehavior {
    pub manifest: BehaviorManifest,
    pub component: Arc<[u8]>,
}

fn validate_manifest_metadata(
    manifest: &BehaviorManifest,
    supervisor_version: &Version,
) -> Result<[u8; 32], UpdateError> {
    if manifest.size > MAX_COMPONENT_BYTES as u64 {
        return Err(UpdateError::ComponentTooLarge);
    }
    if manifest.abi_major != SUPPORTED_ABI_MAJOR || manifest.abi_minor > SUPPORTED_ABI_MINOR {
        return Err(UpdateError::UnsupportedAbi);
    }
    let min_supervisor = Version::parse(&manifest.min_supervisor_version)
        .map_err(|_| UpdateError::InvalidSupervisorVersion)?;
    if &min_supervisor > supervisor_version {
        return Err(UpdateError::SupervisorTooOld);
    }
    let expected_digest = hex::decode(&manifest.sha256).map_err(|_| UpdateError::InvalidDigest)?;
    expected_digest
        .try_into()
        .map_err(|_| UpdateError::InvalidDigest)
}

fn verify_manifest_signature(
    manifest: &BehaviorManifest,
    verifying_key: &VerifyingKey,
) -> Result<(), UpdateError> {
    let signature_bytes =
        hex::decode(&manifest.signature).map_err(|_| UpdateError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| UpdateError::InvalidSignature)?;
    verifying_key
        .verify_strict(&manifest.signing_payload(), &signature)
        .map_err(|_| UpdateError::SignatureMismatch)
}

/// Verify signed manifest metadata before downloading its component payload.
///
/// This authenticates the sequence/ABI/minimum-supervisor/size/digest metadata,
/// but deliberately cannot prove that remote component bytes match the digest.
/// [`verify_artifact`] repeats these checks and verifies the bytes before use.
///
/// # Errors
/// Returns an error for oversized or malformed metadata, unsupported ABI or
/// supervisor requirements, or an invalid Ed25519 signature.
pub fn verify_manifest(
    manifest: &BehaviorManifest,
    verifying_key: &VerifyingKey,
    supervisor_version: &Version,
) -> Result<(), UpdateError> {
    let _ = validate_manifest_metadata(manifest, supervisor_version)?;
    verify_manifest_signature(manifest, verifying_key)
}

/// Verify a signed behavior artifact without applying network anti-rollback policy.
///
/// This is used when reloading an already accepted on-disk slot after restart.
/// The caller must separately restore the persisted highest accepted sequence.
///
/// # Errors
/// Returns an error for oversized or mismatched bytes, malformed or invalid
/// cryptographic metadata, unsupported ABI versions, or a component requiring
/// a newer supervisor.
pub fn verify_artifact(
    manifest: BehaviorManifest,
    component: Vec<u8>,
    verifying_key: &VerifyingKey,
    supervisor_version: &Version,
) -> Result<VerifiedBehavior, UpdateError> {
    if component.len() > MAX_COMPONENT_BYTES {
        return Err(UpdateError::ComponentTooLarge);
    }
    if manifest.size != component.len() as u64 {
        return Err(UpdateError::SizeMismatch);
    }
    let expected_digest = validate_manifest_metadata(&manifest, supervisor_version)?;
    let actual_digest = Sha256::digest(&component);
    if actual_digest.as_slice() != expected_digest {
        return Err(UpdateError::DigestMismatch);
    }
    verify_manifest_signature(&manifest, verifying_key)?;

    Ok(VerifiedBehavior {
        manifest,
        component: component.into(),
    })
}

/// Verify a network update artifact before it can enter an activation slot.
///
/// # Errors
/// Returns an error for rollback attempts or any artifact-integrity,
/// compatibility, or signature failure reported by [`verify_artifact`].
pub fn verify_candidate(
    manifest: BehaviorManifest,
    component: Vec<u8>,
    verifying_key: &VerifyingKey,
    accepted_sequence: u64,
    supervisor_version: &Version,
) -> Result<VerifiedBehavior, UpdateError> {
    if manifest.sequence <= accepted_sequence {
        return Err(UpdateError::RollbackSequence);
    }
    verify_artifact(manifest, component, verifying_key, supervisor_version)
}

#[derive(Debug)]
pub struct BehaviorSlots {
    active: VerifiedBehavior,
    previous: Option<VerifiedBehavior>,
    accepted_sequence: u64,
}

impl BehaviorSlots {
    #[must_use]
    pub const fn new(active: VerifiedBehavior) -> Self {
        let accepted_sequence = active.manifest.sequence;
        Self {
            active,
            previous: None,
            accepted_sequence,
        }
    }

    #[must_use]
    pub const fn active(&self) -> &VerifiedBehavior {
        &self.active
    }

    #[must_use]
    pub const fn accepted_sequence(&self) -> u64 {
        self.accepted_sequence
    }

    pub fn activate(&mut self, candidate: VerifiedBehavior) {
        self.accepted_sequence = self.accepted_sequence.max(candidate.manifest.sequence);
        self.previous = Some(std::mem::replace(&mut self.active, candidate));
    }

    /// Restore the immediately previous verified slot without lowering the
    /// highest network update sequence ever accepted.
    ///
    /// # Errors
    /// Returns [`UpdateError::NoPreviousVersion`] when there is no rollback slot.
    pub fn rollback(&mut self) -> Result<(), UpdateError> {
        let previous = self.previous.take().ok_or(UpdateError::NoPreviousVersion)?;
        self.active = previous;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn signed_candidate(sequence: u64, bytes: &[u8], signing_key: &SigningKey) -> BehaviorManifest {
        let digest = Sha256::digest(bytes);
        let mut manifest = BehaviorManifest {
            sequence,
            abi_major: SUPPORTED_ABI_MAJOR,
            abi_minor: SUPPORTED_ABI_MINOR,
            min_supervisor_version: "0.48.0".to_string(),
            size: bytes.len() as u64,
            sha256: hex::encode(digest),
            build_id: format!("test-{sequence}"),
            signature: String::new(),
        };
        manifest.signature = hex::encode(signing_key.sign(&manifest.signing_payload()).to_bytes());
        manifest
    }

    fn verified(sequence: u64, bytes: &[u8], signing_key: &SigningKey) -> VerifiedBehavior {
        verify_candidate(
            signed_candidate(sequence, bytes, signing_key),
            bytes.to_vec(),
            &signing_key.verifying_key(),
            sequence.saturating_sub(1),
            &Version::new(0, 48, 0),
        )
        .unwrap_or_else(|error| panic!("candidate should verify: {error}"))
    }

    #[test]
    fn signed_manifest_preflight_does_not_require_component_bytes() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let manifest = signed_candidate(2, b"component-v2", &key);
        assert_eq!(
            verify_manifest(&manifest, &key.verifying_key(), &Version::new(0, 48, 0)),
            Ok(())
        );
    }

    #[test]
    fn manifest_preflight_rejects_wrong_signer_before_component_download() {
        let trusted = SigningKey::from_bytes(&[7; 32]);
        let attacker = SigningKey::from_bytes(&[9; 32]);
        let manifest = signed_candidate(2, b"component-v2", &attacker);
        assert_eq!(
            verify_manifest(&manifest, &trusted.verifying_key(), &Version::new(0, 48, 0),),
            Err(UpdateError::SignatureMismatch)
        );
    }

    #[test]
    fn verifies_hash_signature_abi_sequence_and_supervisor_version() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let bytes = b"component-v2";
        let candidate = verify_candidate(
            signed_candidate(2, bytes, &key),
            bytes.to_vec(),
            &key.verifying_key(),
            1,
            &Version::new(0, 48, 0),
        );
        assert!(candidate.is_ok());
    }

    #[test]
    fn rejects_tampered_component() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let manifest = signed_candidate(2, b"component-v2", &key);
        let result = verify_candidate(
            manifest,
            b"component-XX".to_vec(),
            &key.verifying_key(),
            1,
            &Version::new(0, 48, 0),
        );
        assert!(matches!(
            result,
            Err(UpdateError::SizeMismatch | UpdateError::DigestMismatch)
        ));
    }

    #[test]
    fn rejects_manifest_signed_by_another_key() {
        let trusted = SigningKey::from_bytes(&[7; 32]);
        let attacker = SigningKey::from_bytes(&[9; 32]);
        let bytes = b"component-v2";
        let result = verify_candidate(
            signed_candidate(2, bytes, &attacker),
            bytes.to_vec(),
            &trusted.verifying_key(),
            1,
            &Version::new(0, 48, 0),
        );
        assert!(matches!(result, Err(UpdateError::SignatureMismatch)));
    }

    #[test]
    fn rejects_network_rollback_even_when_old_artifact_is_validly_signed() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let bytes = b"component-v1";
        let result = verify_candidate(
            signed_candidate(4, bytes, &key),
            bytes.to_vec(),
            &key.verifying_key(),
            4,
            &Version::new(0, 48, 0),
        );
        assert!(matches!(result, Err(UpdateError::RollbackSequence)));
    }

    #[test]
    fn activation_replaces_rollback_slot_with_immediate_previous_version() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let first = verified(1, b"component-v1", &key);
        let second = verified(2, b"component-v2", &key);
        let third = verified(3, b"component-v3", &key);
        let mut slots = BehaviorSlots::new(first);
        slots.activate(second);
        slots.activate(third);

        assert_eq!(slots.active().manifest.sequence, 3);
        assert_eq!(slots.accepted_sequence(), 3);
        assert_eq!(slots.rollback(), Ok(()));
        assert_eq!(slots.active().manifest.sequence, 2);
        assert_eq!(slots.accepted_sequence(), 3);
        assert_eq!(slots.rollback(), Err(UpdateError::NoPreviousVersion));
    }

    #[test]
    fn local_health_rollback_uses_previous_verified_slot() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let first = verified(1, b"component-v1", &key);
        let second = verified(2, b"component-v2", &key);
        let mut slots = BehaviorSlots::new(first);
        slots.activate(second);
        assert_eq!(slots.active().manifest.sequence, 2);
        slots
            .rollback()
            .unwrap_or_else(|error| panic!("rollback should be available: {error}"));
        assert_eq!(slots.active().manifest.sequence, 1);
        assert_eq!(
            slots.accepted_sequence(),
            2,
            "local rollback must never reopen network rollback"
        );
    }
}
