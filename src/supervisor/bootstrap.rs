//! Trusted startup and activation controller for signed behavior components.
//!
//! This module deliberately does not choose a production key, storage path, or
//! network update transport. A caller supplies the trusted Ed25519 key and an
//! absolute persistent-slot root. The controller re-verifies durable state,
//! compiles/self-tests behavior before exposing it, and serializes signed
//! activation and local rollback without interrupting current measurements.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use ed25519_dalek::VerifyingKey;
use semver::Version;
use tokio::sync::{Mutex, RwLock};

use super::runtime::{BehaviorShadowExecutor, RuntimeError};
use super::storage::{PersistentBehaviorSlots, StorageError};
use super::update::{BehaviorManifest, UpdateError, verify_candidate};

type SharedSlots = Arc<StdMutex<Option<PersistentBehaviorSlots>>>;

#[derive(Debug, Clone)]
pub struct BehaviorBootstrapConfig {
    root: PathBuf,
    verifying_key: VerifyingKey,
}

impl BehaviorBootstrapConfig {
    /// Configure behavior storage and its trust root.
    ///
    /// The root is intentionally explicit: the supervisor does not guess a
    /// production filesystem location. Relative paths are rejected by
    /// [`BehaviorController::load`].
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, verifying_key: VerifyingKey) -> Self {
        Self {
            root: root.into(),
            verifying_key,
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

#[derive(Debug)]
pub enum BootstrapError {
    RelativeRoot,
    InvalidSupervisorVersion(semver::Error),
    Storage(StorageError),
    Update(UpdateError),
    Runtime(RuntimeError),
    StorageLockPoisoned,
    BlockingTask(tokio::task::JoinError),
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativeRoot => f.write_str("behavior storage root must be an absolute path"),
            Self::InvalidSupervisorVersion(error) => {
                write!(f, "native supervisor version is invalid: {error}")
            }
            Self::Storage(error) => write!(f, "behavior storage failed: {error}"),
            Self::Update(error) => write!(f, "behavior update was rejected: {error}"),
            Self::Runtime(error) => write!(f, "behavior runtime failed: {error}"),
            Self::StorageLockPoisoned => f.write_str("behavior storage lock was poisoned"),
            Self::BlockingTask(error) => write!(f, "behavior storage task failed: {error}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

impl From<StorageError> for BootstrapError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<UpdateError> for BootstrapError {
    fn from(error: UpdateError) -> Self {
        Self::Update(error)
    }
}

impl From<RuntimeError> for BootstrapError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

struct ExecutorSlots {
    active: Option<Arc<BehaviorShadowExecutor>>,
    previous: Option<Arc<BehaviorShadowExecutor>>,
}

pub struct BehaviorController {
    root: PathBuf,
    verifying_key: VerifyingKey,
    supervisor_version: Version,
    update_lock: Mutex<()>,
    slots: SharedSlots,
    executors: RwLock<ExecutorSlots>,
}

impl BehaviorController {
    /// Load persistent behavior state using an explicitly supplied trust root.
    ///
    /// Missing `state.json` creates an empty controller ready to accept its
    /// first signed candidate. Any other storage/signature/ABI/state error is
    /// returned. A loaded active component is compiled and self-tested before
    /// this function returns.
    ///
    /// # Errors
    /// Returns an error for a relative root, malformed native version,
    /// invalid/corrupt persisted state, a failed blocking storage task, or an
    /// active component that cannot compile/self-test.
    pub async fn load(config: BehaviorBootstrapConfig) -> Result<Arc<Self>, BootstrapError> {
        if !config.root.is_absolute() {
            return Err(BootstrapError::RelativeRoot);
        }
        let supervisor_version = Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(BootstrapError::InvalidSupervisorVersion)?;
        let load_root = config.root.clone();
        let load_key = config.verifying_key;
        let load_version = supervisor_version.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            PersistentBehaviorSlots::load(load_root, &load_key, &load_version)
        })
        .await
        .map_err(BootstrapError::BlockingTask)?;
        let slots = match loaded {
            Ok(slots) => Some(slots),
            Err(StorageError::MissingState) => None,
            Err(error) => return Err(error.into()),
        };
        let active = slots.as_ref().map(|slots| slots.active().clone());
        let previous = slots
            .as_ref()
            .and_then(PersistentBehaviorSlots::previous)
            .cloned();
        let active_executor = if let Some(active) = active {
            Some(Arc::new(
                BehaviorShadowExecutor::from_verified(active).await?,
            ))
        } else {
            None
        };
        let previous_executor = if let Some(previous) = previous {
            Some(Arc::new(
                BehaviorShadowExecutor::from_verified(previous).await?,
            ))
        } else {
            None
        };
        Ok(Arc::new(Self {
            root: config.root,
            verifying_key: config.verifying_key,
            supervisor_version,
            update_lock: Mutex::new(()),
            slots: Arc::new(StdMutex::new(slots)),
            executors: RwLock::new(ExecutorSlots {
                active: active_executor,
                previous: previous_executor,
            }),
        }))
    }

    /// Return the behavior executor currently admitted for new measurements.
    #[must_use]
    pub async fn executor(&self) -> Option<Arc<BehaviorShadowExecutor>> {
        self.executors.read().await.active.clone()
    }

    /// Highest network sequence ever accepted, including after local rollback.
    ///
    /// # Errors
    /// Returns an error only if the internal persistent-slot lock was poisoned.
    pub fn accepted_sequence(&self) -> Result<u64, BootstrapError> {
        self.with_slots(|slots| slots.map_or(0, PersistentBehaviorSlots::accepted_sequence))
    }

    /// Sequence currently active for new measurements.
    ///
    /// # Errors
    /// Returns an error only if the internal persistent-slot lock was poisoned.
    pub fn active_sequence(&self) -> Result<Option<u64>, BootstrapError> {
        self.with_slots(|slots| slots.map(|slots| slots.active().manifest.sequence))
    }

    /// Whether an immediately previous verified behavior is available locally.
    ///
    /// # Errors
    /// Returns an error only if the internal persistent-slot lock was poisoned.
    pub fn has_previous(&self) -> Result<bool, BootstrapError> {
        self.with_slots(|slots| slots.is_some_and(|slots| slots.previous().is_some()))
    }

    /// Verify, compile/self-test, durably persist, and atomically admit a newer
    /// signed behavior artifact for subsequent measurements.
    ///
    /// The current executor remains available while verification/self-test and
    /// durable writes are in progress. The executor pointer is changed only
    /// after storage activation succeeds.
    ///
    /// # Errors
    /// Returns an error for non-monotonic or invalid signatures/manifests,
    /// component runtime/self-test failure, persistence failure, or a poisoned
    /// storage lock.
    pub async fn activate_candidate(
        &self,
        manifest: BehaviorManifest,
        component: Vec<u8>,
    ) -> Result<Arc<BehaviorShadowExecutor>, BootstrapError> {
        let _update = self.update_lock.lock().await;
        let accepted_sequence = self.accepted_sequence()?;
        let verified = verify_candidate(
            manifest,
            component,
            &self.verifying_key,
            accepted_sequence,
            &self.supervisor_version,
        )?;
        let next_executor =
            Arc::new(BehaviorShadowExecutor::from_verified(verified.clone()).await?);
        let root = self.root.clone();
        let slots = Arc::clone(&self.slots);
        tokio::task::spawn_blocking(move || -> Result<(), BootstrapError> {
            let mut guard = slots
                .lock()
                .map_err(|_| BootstrapError::StorageLockPoisoned)?;
            if let Some(existing) = guard.as_mut() {
                existing.activate(verified)?;
            } else {
                *guard = Some(PersistentBehaviorSlots::initialize(root, verified)?);
            }
            drop(guard);
            Ok(())
        })
        .await
        .map_err(BootstrapError::BlockingTask)??;
        let mut executors = self.executors.write().await;
        let old_active = executors.active.replace(Arc::clone(&next_executor));
        executors.previous = old_active;
        drop(executors);
        Ok(next_executor)
    }

    /// Roll back to the immediately previous verified local slot while keeping
    /// the highest accepted network sequence unchanged.
    ///
    /// The rollback target is precompiled/self-tested when it enters the
    /// previous slot. New measurements keep using the current executor until
    /// the durable state change succeeds.
    ///
    /// # Errors
    /// Returns an error when no previous slot exists, persistence fails, or the
    /// storage lock is poisoned.
    pub async fn rollback(&self) -> Result<Arc<BehaviorShadowExecutor>, BootstrapError> {
        let _update = self.update_lock.lock().await;
        if !self.has_previous()? {
            return Err(UpdateError::NoPreviousVersion.into());
        }
        let next_executor = self
            .executors
            .read()
            .await
            .previous
            .clone()
            .ok_or(UpdateError::NoPreviousVersion)?;
        let slots = Arc::clone(&self.slots);
        tokio::task::spawn_blocking(move || -> Result<(), BootstrapError> {
            let mut guard = slots
                .lock()
                .map_err(|_| BootstrapError::StorageLockPoisoned)?;
            let existing = guard.as_mut().ok_or(UpdateError::NoPreviousVersion)?;
            existing.rollback()?;
            drop(guard);
            Ok(())
        })
        .await
        .map_err(BootstrapError::BlockingTask)??;
        let mut executors = self.executors.write().await;
        executors.active = Some(Arc::clone(&next_executor));
        executors.previous = None;
        drop(executors);
        Ok(next_executor)
    }

    fn with_slots<T>(
        &self,
        inspect: impl FnOnce(Option<&PersistentBehaviorSlots>) -> T,
    ) -> Result<T, BootstrapError> {
        let guard = self
            .slots
            .lock()
            .map_err(|_| BootstrapError::StorageLockPoisoned)?;
        Ok(inspect(guard.as_ref()))
    }
}
