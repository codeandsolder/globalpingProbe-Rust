//! Crash-safe persistence for signed behavior components.
//!
//! Artifacts are stored as immutable, sequence-named bundles. The small state
//! file is the only activation pointer and is replaced atomically after a new
//! bundle is fully written and synced. This avoids overwriting the rollback
//! target while staging the next update.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::VerifyingKey;
use semver::Version;
use serde::{Deserialize, Serialize};

use super::update::{BehaviorManifest, UpdateError, VerifiedBehavior, verify_artifact};

const STATE_FILE: &str = "state.json";
const BUNDLE_MAGIC: &[u8; 4] = b"GPB1";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Json(serde_json::Error),
    Update(UpdateError),
    AlreadyInitialized,
    MissingState,
    InvalidState,
    InvalidBundle,
    ManifestTooLarge,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "behavior storage I/O failed: {error}"),
            Self::Json(error) => write!(f, "behavior storage JSON failed: {error}"),
            Self::Update(error) => write!(f, "stored behavior verification failed: {error}"),
            Self::AlreadyInitialized => f.write_str("behavior storage is already initialized"),
            Self::MissingState => f.write_str("behavior storage state is missing"),
            Self::InvalidState => f.write_str("behavior storage state is inconsistent"),
            Self::InvalidBundle => f.write_str("behavior artifact bundle is malformed"),
            Self::ManifestTooLarge => f.write_str("behavior manifest exceeds storage limit"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<UpdateError> for StorageError {
    fn from(error: UpdateError) -> Self {
        Self::Update(error)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PersistedState {
    accepted_sequence: u64,
    active_sequence: u64,
    previous_sequence: Option<u64>,
}

#[derive(Debug)]
pub struct PersistentBehaviorSlots {
    root: PathBuf,
    active: VerifiedBehavior,
    previous: Option<VerifiedBehavior>,
    accepted_sequence: u64,
}

impl PersistentBehaviorSlots {
    /// Create a new behavior store around an already verified initial artifact.
    ///
    /// # Errors
    /// Returns an error if the store already has state or durable writes fail.
    pub fn initialize(
        root: impl Into<PathBuf>,
        active: VerifiedBehavior,
    ) -> Result<Self, StorageError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        if root.join(STATE_FILE).exists() {
            return Err(StorageError::AlreadyInitialized);
        }

        write_bundle(&root, &active)?;
        let state = PersistedState {
            accepted_sequence: active.manifest.sequence,
            active_sequence: active.manifest.sequence,
            previous_sequence: None,
        };
        write_state(&root, state)?;

        Ok(Self {
            root,
            accepted_sequence: active.manifest.sequence,
            active,
            previous: None,
        })
    }

    /// Reload active/rollback artifacts and re-verify their signatures and
    /// content before they can execute.
    ///
    /// # Errors
    /// Returns an error for missing/inconsistent state, corrupt artifacts,
    /// signature or compatibility failures, or storage I/O failures.
    pub fn load(
        root: impl Into<PathBuf>,
        verifying_key: &VerifyingKey,
        supervisor_version: &Version,
    ) -> Result<Self, StorageError> {
        let root = root.into();
        let state_path = root.join(STATE_FILE);
        let state_bytes = match fs::read(&state_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::MissingState);
            }
            Err(error) => return Err(error.into()),
        };
        let state: PersistedState = serde_json::from_slice(&state_bytes)?;

        let active = load_bundle(
            &root,
            state.active_sequence,
            verifying_key,
            supervisor_version,
        )?;
        let previous = state
            .previous_sequence
            .map(|sequence| load_bundle(&root, sequence, verifying_key, supervisor_version))
            .transpose()?;

        if state.accepted_sequence < state.active_sequence
            || state
                .previous_sequence
                .is_some_and(|sequence| sequence > state.accepted_sequence)
            || state.previous_sequence == Some(state.active_sequence)
        {
            return Err(StorageError::InvalidState);
        }

        Ok(Self {
            root,
            active,
            previous,
            accepted_sequence: state.accepted_sequence,
        })
    }

    #[must_use]
    pub const fn active(&self) -> &VerifiedBehavior {
        &self.active
    }

    #[must_use]
    pub const fn previous(&self) -> Option<&VerifiedBehavior> {
        self.previous.as_ref()
    }

    #[must_use]
    pub const fn accepted_sequence(&self) -> u64 {
        self.accepted_sequence
    }

    /// Persist and atomically activate a newer verified behavior artifact.
    ///
    /// The existing active artifact becomes the rollback target only after the
    /// new immutable bundle has reached disk. Any older rollback bundle is then
    /// best-effort pruned after the new activation state is durable.
    ///
    /// # Errors
    /// Returns an error for a non-monotonic candidate or failed durable write.
    pub fn activate(&mut self, candidate: VerifiedBehavior) -> Result<(), StorageError> {
        if candidate.manifest.sequence <= self.accepted_sequence {
            return Err(StorageError::Update(UpdateError::RollbackSequence));
        }

        write_bundle(&self.root, &candidate)?;
        let old_active_sequence = self.active.manifest.sequence;
        let old_previous_sequence = self.previous.as_ref().map(|item| item.manifest.sequence);
        let accepted_sequence = candidate.manifest.sequence;
        let state = PersistedState {
            accepted_sequence,
            active_sequence: candidate.manifest.sequence,
            previous_sequence: Some(old_active_sequence),
        };
        write_state(&self.root, state)?;

        self.accepted_sequence = accepted_sequence;
        self.previous = Some(std::mem::replace(&mut self.active, candidate));
        if let Some(sequence) = old_previous_sequence {
            best_effort_remove_bundle(&self.root, sequence);
        }
        Ok(())
    }

    /// Switch execution back to the immediately previous verified artifact
    /// while preserving the highest accepted network sequence.
    ///
    /// # Errors
    /// Returns an error when no rollback artifact exists or state persistence
    /// fails. The active in-memory artifact is not changed unless persistence
    /// succeeds first.
    pub fn rollback(&mut self) -> Result<(), StorageError> {
        let previous = self
            .previous
            .as_ref()
            .ok_or(StorageError::Update(UpdateError::NoPreviousVersion))?;
        let previous_sequence = previous.manifest.sequence;
        let old_active_sequence = self.active.manifest.sequence;
        let state = PersistedState {
            accepted_sequence: self.accepted_sequence,
            active_sequence: previous_sequence,
            previous_sequence: None,
        };
        write_state(&self.root, state)?;

        let previous = self.previous.take().ok_or(StorageError::InvalidState)?;
        self.active = previous;
        best_effort_remove_bundle(&self.root, old_active_sequence);
        Ok(())
    }
}

fn bundle_path(root: &Path, sequence: u64) -> PathBuf {
    root.join(format!("behavior-{sequence}.bundle"))
}

fn write_bundle(root: &Path, behavior: &VerifiedBehavior) -> Result<(), StorageError> {
    let manifest = serde_json::to_vec(&behavior.manifest)?;
    let manifest_len = u32::try_from(manifest.len()).map_err(|_| StorageError::ManifestTooLarge)?;
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(StorageError::ManifestTooLarge);
    }

    let mut bundle = Vec::with_capacity(
        BUNDLE_MAGIC.len() + size_of::<u32>() + manifest.len() + behavior.component.len(),
    );
    bundle.extend_from_slice(BUNDLE_MAGIC);
    bundle.extend_from_slice(&manifest_len.to_le_bytes());
    bundle.extend_from_slice(&manifest);
    bundle.extend_from_slice(&behavior.component);
    atomic_write(&bundle_path(root, behavior.manifest.sequence), &bundle)
}

fn load_bundle(
    root: &Path,
    sequence: u64,
    verifying_key: &VerifyingKey,
    supervisor_version: &Version,
) -> Result<VerifiedBehavior, StorageError> {
    let bundle = fs::read(bundle_path(root, sequence))?;
    if bundle.len() < BUNDLE_MAGIC.len() + size_of::<u32>()
        || &bundle[..BUNDLE_MAGIC.len()] != BUNDLE_MAGIC
    {
        return Err(StorageError::InvalidBundle);
    }

    let length_start = BUNDLE_MAGIC.len();
    let length_end = length_start + size_of::<u32>();
    let manifest_len_bytes: [u8; 4] = bundle[length_start..length_end]
        .try_into()
        .map_err(|_| StorageError::InvalidBundle)?;
    let manifest_len = usize::try_from(u32::from_le_bytes(manifest_len_bytes))
        .map_err(|_| StorageError::InvalidBundle)?;
    if manifest_len > MAX_MANIFEST_BYTES {
        return Err(StorageError::ManifestTooLarge);
    }
    let manifest_end = length_end
        .checked_add(manifest_len)
        .filter(|end| *end <= bundle.len())
        .ok_or(StorageError::InvalidBundle)?;
    let manifest: BehaviorManifest = serde_json::from_slice(&bundle[length_end..manifest_end])?;
    if manifest.sequence != sequence {
        return Err(StorageError::InvalidBundle);
    }
    let component = bundle[manifest_end..].to_vec();
    verify_artifact(manifest, component, verifying_key, supervisor_version).map_err(Into::into)
}

fn write_state(root: &Path, state: PersistedState) -> Result<(), StorageError> {
    let bytes = serde_json::to_vec_pretty(&state)?;
    atomic_write(&root.join(STATE_FILE), &bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let parent = path.parent().ok_or(StorageError::InvalidState)?;
    fs::create_dir_all(parent)?;
    let file_name = path.file_name().ok_or(StorageError::InvalidState)?;

    let (temp_path, mut file) = loop {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(
            ".{}.tmp-{}-{nonce}",
            file_name.to_string_lossy(),
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => break (temp_path, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    };

    let result = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result.map_err(Into::into)
}

fn best_effort_remove_bundle(root: &Path, sequence: u64) {
    let _ = fs::remove_file(bundle_path(root, sequence));
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};
    use tempfile::tempdir;

    use super::*;
    use crate::supervisor::update::{SUPPORTED_ABI_MAJOR, SUPPORTED_ABI_MINOR, verify_candidate};

    fn verified(sequence: u64, bytes: &[u8], key: &SigningKey) -> VerifiedBehavior {
        let mut manifest = BehaviorManifest {
            sequence,
            abi_major: SUPPORTED_ABI_MAJOR,
            abi_minor: SUPPORTED_ABI_MINOR,
            min_supervisor_version: "0.48.0".to_string(),
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
            build_id: format!("test-{sequence}"),
            signature: String::new(),
        };
        manifest.signature = hex::encode(key.sign(&manifest.signing_payload()).to_bytes());
        verify_candidate(
            manifest,
            bytes.to_vec(),
            &key.verifying_key(),
            sequence.saturating_sub(1),
            &Version::new(0, 48, 0),
        )
        .unwrap_or_else(|error| panic!("test artifact should verify: {error}"))
    }

    #[test]
    fn activation_and_restart_preserve_rollback_and_anti_rollback() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let key = SigningKey::from_bytes(&[7; 32]);
        let first = verified(1, b"first", &key);
        let second = verified(2, b"second", &key);
        let mut store = PersistentBehaviorSlots::initialize(dir.path(), first)?;
        store.activate(second)?;

        let mut reloaded = PersistentBehaviorSlots::load(
            dir.path(),
            &key.verifying_key(),
            &Version::new(0, 48, 0),
        )?;
        assert_eq!(reloaded.active().manifest.sequence, 2);
        assert_eq!(
            reloaded.previous().map(|item| item.manifest.sequence),
            Some(1)
        );
        assert_eq!(reloaded.accepted_sequence(), 2);

        reloaded.rollback()?;
        let rolled_back = PersistentBehaviorSlots::load(
            dir.path(),
            &key.verifying_key(),
            &Version::new(0, 48, 0),
        )?;
        assert_eq!(rolled_back.active().manifest.sequence, 1);
        assert!(rolled_back.previous().is_none());
        assert_eq!(rolled_back.accepted_sequence(), 2);
        Ok(())
    }

    #[test]
    fn subsequent_activation_keeps_current_active_as_rollback_target() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut store = PersistentBehaviorSlots::initialize(dir.path(), verified(1, b"one", &key))?;
        store.activate(verified(2, b"two", &key))?;
        store.activate(verified(3, b"three", &key))?;

        let reloaded = PersistentBehaviorSlots::load(
            dir.path(),
            &key.verifying_key(),
            &Version::new(0, 48, 0),
        )?;
        assert_eq!(reloaded.active().manifest.sequence, 3);
        assert_eq!(
            reloaded.previous().map(|item| item.manifest.sequence),
            Some(2)
        );
        assert_eq!(reloaded.accepted_sequence(), 3);
        assert!(!bundle_path(dir.path(), 1).exists());
        Ok(())
    }

    #[test]
    fn tampered_bundle_is_rejected_on_restart() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let key = SigningKey::from_bytes(&[7; 32]);
        let store = PersistentBehaviorSlots::initialize(dir.path(), verified(1, b"first", &key))?;
        fs::write(bundle_path(dir.path(), 1), b"not-a-valid-bundle")?;

        let result = PersistentBehaviorSlots::load(
            dir.path(),
            &key.verifying_key(),
            &Version::new(0, 48, 0),
        );
        assert!(matches!(result, Err(StorageError::InvalidBundle)));
        assert_eq!(store.accepted_sequence(), 1);
        Ok(())
    }

    #[test]
    fn candidate_at_or_below_persisted_high_water_mark_is_rejected() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut store = PersistentBehaviorSlots::initialize(dir.path(), verified(2, b"two", &key))?;
        let result = store.activate(verified(2, b"same-sequence", &key));
        assert!(matches!(
            result,
            Err(StorageError::Update(UpdateError::RollbackSequence))
        ));
        Ok(())
    }
}
