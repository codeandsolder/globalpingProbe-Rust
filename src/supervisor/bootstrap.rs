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
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

use super::health::{
    BehaviorDiagnosticEvent, BehaviorHealthEvent, BehaviorHealthPolicy, BehaviorHealthSnapshot,
    BehaviorHealthState, DiagnosticDecision, HealthDecision,
};
use super::runtime::{BehaviorExecutor, RuntimeError};
use super::storage::{PersistentBehaviorSlots, StorageError};
use super::update::{BehaviorManifest, UpdateError, verify_candidate, verify_manifest};

#[derive(Debug, Clone)]
pub struct BehaviorBootstrapConfig {
    root: PathBuf,
    verifying_key: VerifyingKey,
    health_policy: BehaviorHealthPolicy,
}

impl BehaviorBootstrapConfig {
    /// Configure behavior storage and its trust root.
    ///
    /// The root is intentionally explicit: the supervisor does not guess a
    /// production filesystem location. Relative paths are rejected by
    /// [`BehaviorController::load`].
    #[must_use = "retain the configuration to initialize the trusted behavior controller"]
    pub fn new(root: impl Into<PathBuf>, verifying_key: VerifyingKey) -> Self {
        Self {
            root: root.into(),
            verifying_key,
            health_policy: BehaviorHealthPolicy::default(),
        }
    }

    #[must_use = "the returned path identifies the behavior storage root"]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use = "the returned key identifies the configured trust root"]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    #[must_use = "the returned configuration replaces the consumed configuration"]
    pub const fn with_health_policy(mut self, health_policy: BehaviorHealthPolicy) -> Self {
        self.health_policy = health_policy;
        self
    }

    #[must_use = "the returned policy determines when a behavior fault triggers rollback"]
    pub const fn health_policy(&self) -> BehaviorHealthPolicy {
        self.health_policy
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorHealthAction {
    None,
    IgnoredStaleSequence,
    ThresholdReachedNoPrevious,
    RolledBack {
        from_sequence: u64,
        to_sequence: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorDiagnosticAction {
    None,
    FirstDivergence,
    IgnoredStaleSequence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorSlotSnapshot {
    pub sequence: u64,
    pub build_id: String,
}

impl BehaviorSlotSnapshot {
    fn from_executor(executor: &BehaviorExecutor) -> Self {
        Self {
            sequence: executor.sequence(),
            build_id: executor.build_id().to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorOperatorSnapshot {
    pub active: Option<BehaviorSlotSnapshot>,
    pub previous: Option<BehaviorSlotSnapshot>,
    pub accepted_sequence: u64,
    pub health: BehaviorHealthSnapshot,
}

struct ExecutorSlots {
    active: Option<Arc<BehaviorExecutor>>,
    previous: Option<Arc<BehaviorExecutor>>,
}

pub struct BehaviorController {
    root: PathBuf,
    verifying_key: VerifyingKey,
    supervisor_version: Version,
    update_lock: Arc<Mutex<()>>,
    slots: StdMutex<Option<PersistentBehaviorSlots>>,
    executors: RwLock<ExecutorSlots>,
    health: Mutex<BehaviorHealthState>,
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
        let health_policy = config.health_policy;
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
            Some(Arc::new(BehaviorExecutor::from_verified(active).await?))
        } else {
            None
        };
        let previous_executor = if let Some(previous) = previous {
            Some(Arc::new(BehaviorExecutor::from_verified(previous).await?))
        } else {
            None
        };
        Ok(Arc::new(Self {
            root: config.root,
            verifying_key: config.verifying_key,
            supervisor_version,
            update_lock: Arc::new(Mutex::new(())),
            slots: StdMutex::new(slots),
            health: Mutex::new(BehaviorHealthState::new(
                health_policy,
                active_executor.as_ref().map(|executor| executor.sequence()),
            )),
            executors: RwLock::new(ExecutorSlots {
                active: active_executor,
                previous: previous_executor,
            }),
        }))
    }

    /// Return the behavior executor currently admitted for new measurements.
    #[must_use = "the returned executor is the admitted behavior for new measurements"]
    pub async fn executor(&self) -> Option<Arc<BehaviorExecutor>> {
        self.executors.read().await.active.clone()
    }

    #[must_use = "the returned snapshot contains the current behavior health counters"]
    pub async fn health_snapshot(&self) -> BehaviorHealthSnapshot {
        self.health.lock().await.snapshot()
    }

    /// Return a coherent operator-facing view of the currently admitted behavior,
    /// rollback slot, accepted network high-water mark, and health counters.
    ///
    /// # Errors
    /// Returns an error only if the persistent-slot lock was poisoned.
    pub async fn operator_snapshot(&self) -> Result<BehaviorOperatorSnapshot, BootstrapError> {
        let _update = self.update_lock.lock().await;
        let (active, previous) = {
            let executors = self.executors.read().await;
            (
                executors
                    .active
                    .as_deref()
                    .map(BehaviorSlotSnapshot::from_executor),
                executors
                    .previous
                    .as_deref()
                    .map(BehaviorSlotSnapshot::from_executor),
            )
        };
        let accepted_sequence = self.accepted_sequence()?;
        let health = self.health.lock().await.snapshot();
        Ok(BehaviorOperatorSnapshot {
            active,
            previous,
            accepted_sequence,
            health,
        })
    }

    /// Record one behavior execution health outcome and roll back when the configured
    /// consecutive hard-fault threshold is reached for the still-active slot.
    ///
    /// # Errors
    /// Returns an error only when a recommended rollback cannot be persisted.
    pub async fn observe_health(
        self: &Arc<Self>,
        sequence: u64,
        event: BehaviorHealthEvent,
    ) -> Result<BehaviorHealthAction, BootstrapError> {
        let update = Arc::clone(&self.update_lock).lock_owned().await;
        let decision = {
            let mut health = self.health.lock().await;
            health.observe(sequence, event)
        };
        match decision {
            HealthDecision::None => {
                drop(update);
                return Ok(BehaviorHealthAction::None);
            }
            HealthDecision::IgnoredStaleSequence => {
                drop(update);
                return Ok(BehaviorHealthAction::IgnoredStaleSequence);
            }
            HealthDecision::RollbackRecommended => {}
        }

        if !self.has_previous()? {
            drop(update);
            return Ok(BehaviorHealthAction::ThresholdReachedNoPrevious);
        }

        // Transfer ownership of the guard to the cancellation-safe transition;
        // it is released by the commit, not by this waiting future.
        self.rollback_with_guard(update).await.map(|next_executor| {
            BehaviorHealthAction::RolledBack {
                from_sequence: sequence,
                to_sequence: next_executor.sequence(),
            }
        })
    }

    /// Record one native-oracle diagnostic without mutating rollback streak state.
    pub async fn observe_diagnostic(
        &self,
        sequence: u64,
        event: BehaviorDiagnosticEvent,
    ) -> BehaviorDiagnosticAction {
        let decision = self.health.lock().await.observe_diagnostic(sequence, event);
        match decision {
            DiagnosticDecision::None => BehaviorDiagnosticAction::None,
            DiagnosticDecision::FirstDivergence => BehaviorDiagnosticAction::FirstDivergence,
            DiagnosticDecision::IgnoredStaleSequence => {
                BehaviorDiagnosticAction::IgnoredStaleSequence
            }
        }
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

    /// Authenticate a newer candidate manifest before its component is downloaded.
    ///
    /// Full component size/digest/signature verification is repeated by
    /// [`Self::activate_candidate`] after download, so this method only avoids
    /// fetching payloads whose signed metadata is already unacceptable.
    ///
    /// # Errors
    /// Returns an error for stale sequence, invalid signature/metadata, unsupported
    /// ABI, or a manifest requiring a newer native supervisor.
    pub fn preflight_candidate_manifest(
        &self,
        manifest: &BehaviorManifest,
    ) -> Result<(), BootstrapError> {
        if manifest.sequence <= self.accepted_sequence()? {
            return Err(UpdateError::RollbackSequence.into());
        }
        verify_manifest(manifest, &self.verifying_key, &self.supervisor_version)?;
        Ok(())
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
        self: &Arc<Self>,
        manifest: BehaviorManifest,
        component: Vec<u8>,
    ) -> Result<Arc<BehaviorExecutor>, BootstrapError> {
        let update = Arc::clone(&self.update_lock).lock_owned().await;
        let accepted_sequence = self.accepted_sequence()?;
        let verified = verify_candidate(
            manifest,
            component,
            &self.verifying_key,
            accepted_sequence,
            &self.supervisor_version,
        )?;
        let next_executor = Arc::new(BehaviorExecutor::from_verified(verified.clone()).await?);
        let controller = Arc::clone(self);
        complete_transition(update, move || {
            let mut slots = controller
                .slots
                .lock()
                .map_err(|_| BootstrapError::StorageLockPoisoned)?;
            if let Some(existing) = slots.as_mut() {
                existing.activate(verified)?;
            } else {
                *slots = Some(PersistentBehaviorSlots::initialize(
                    controller.root.clone(),
                    verified,
                )?);
            }
            let mut executors = controller.executors.blocking_write();
            let mut health = controller.health.blocking_lock();
            executors.previous = executors.active.replace(Arc::clone(&next_executor));
            health.reset(Some(next_executor.sequence()));
            // Keep the durable slots locked until both live views are updated.
            drop(health);
            drop(executors);
            drop(slots);
            Ok(next_executor)
        })
        .await
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
    pub async fn rollback(self: &Arc<Self>) -> Result<Arc<BehaviorExecutor>, BootstrapError> {
        let update = Arc::clone(&self.update_lock).lock_owned().await;
        self.rollback_with_guard(update).await
    }

    async fn rollback_with_guard(
        self: &Arc<Self>,
        update: OwnedMutexGuard<()>,
    ) -> Result<Arc<BehaviorExecutor>, BootstrapError> {
        let controller = Arc::clone(self);
        complete_transition(update, move || {
            let result = controller.rollback_locked();
            if result.is_err() {
                controller
                    .health
                    .blocking_lock()
                    .clear_rollback_recommendation();
            }
            result
        })
        .await
    }

    fn rollback_locked(&self) -> Result<Arc<BehaviorExecutor>, BootstrapError> {
        let next_executor = self
            .executors
            .blocking_read()
            .previous
            .clone()
            .ok_or(UpdateError::NoPreviousVersion)?;
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| BootstrapError::StorageLockPoisoned)?;
        let existing = slots.as_mut().ok_or(UpdateError::NoPreviousVersion)?;
        existing.rollback()?;
        let mut executors = self.executors.blocking_write();
        let mut health = self.health.blocking_lock();
        executors.active = Some(Arc::clone(&next_executor));
        executors.previous = None;
        health.reset(Some(next_executor.sequence()));
        drop(health);
        drop(executors);
        drop(slots);
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

/// Transfer the serialization guard into the blocking commit itself. Dropping
/// the caller's future cannot interrupt a started commit or admit another
/// transition before durable state and live executor/health state agree.
async fn complete_transition<T: Send + 'static>(
    update: OwnedMutexGuard<()>,
    commit: impl FnOnce() -> Result<T, BootstrapError> + Send + 'static,
) -> Result<T, BootstrapError> {
    tokio::task::spawn_blocking(move || {
        let _update = update;
        commit()
    })
    .await
    .map_err(BootstrapError::BlockingTask)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn cancelling_transition_waiter_does_not_release_serialization_guard()
    -> anyhow::Result<()> {
        let lock = Arc::new(Mutex::new(()));
        let update = Arc::clone(&lock).lock_owned().await;
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (committed_tx, committed_rx) = oneshot::channel();
        let waiter = tokio::spawn(complete_transition(update, move || {
            let _ = started_tx.send(());
            let _ = release_rx.blocking_recv();
            let _ = committed_tx.send(());
            Ok(())
        }));
        started_rx.await?;
        waiter.abort();
        assert!(waiter.await.is_err_and(|error| error.is_cancelled()));
        let locked = lock.try_lock().is_err();
        let _ = release_tx.send(());
        committed_rx.await?;
        let _next_update = lock.lock().await;
        assert!(
            locked,
            "cancellation released the transition lock before commit"
        );
        Ok(())
    }
}
