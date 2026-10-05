use serde::Serialize;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;
use tracing::{error, info};

pub const DEFAULT_SETTINGS_PATH: &str = "/.globalping-probe.json";

fn default_settings() -> Map<String, Value> {
    let mut settings = Map::new();
    settings.insert("meteredConnection".to_string(), Value::Bool(false));
    settings
}

fn validate(settings: &Map<String, Value>) -> bool {
    settings
        .get("meteredConnection")
        .is_none_or(Value::is_boolean)
}

fn load_settings(path: &Path) -> Map<String, Value> {
    let defaults = default_settings();
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return defaults,
        Err(_) => return defaults,
    };

    let parsed = serde_json::from_str::<Value>(&raw).ok();
    let Some(Value::Object(object)) = parsed else {
        let _ = std::fs::remove_file(path);
        return defaults;
    };
    if !validate(&object) {
        let _ = std::fs::remove_file(path);
        return defaults;
    }

    let mut merged = defaults;
    merged.extend(object);
    merged
}

fn serialize_pretty_tabs(settings: &Map<String, Value>) -> serde_json::Result<Vec<u8>> {
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"\t");
    let mut serializer = serde_json::Serializer::with_formatter(Vec::new(), formatter);
    settings.serialize(&mut serializer)?;
    Ok(serializer.into_inner())
}

pub struct ProbeSettingsStore {
    path: PathBuf,
    settings: Mutex<Map<String, Value>>,
    write_serial: Mutex<()>,
}

impl ProbeSettingsStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            settings: Mutex::new(load_settings(&path)),
            write_serial: Mutex::new(()),
            path,
        }
    }

    #[must_use]
    pub fn production() -> Self {
        Self::new(DEFAULT_SETTINGS_PATH)
    }

    pub async fn get(&self) -> Value {
        Value::Object(self.settings.lock().await.clone())
    }

    /// Merge and persist a partial settings object.
    ///
    /// Unknown keys are intentionally preserved for forward compatibility.
    /// Persistence failures do not roll back the in-memory update, matching upstream.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the write mutex intentionally serializes persistence and acknowledgements"
    )]
    pub async fn update(&self, update: &Value) -> bool {
        let Value::Object(update) = update else {
            error!(target: "probe-settings", "Invalid probe settings received: expected an object.");
            return false;
        };
        if !validate(update) {
            error!(target: "probe-settings", "Invalid probe settings received.");
            return false;
        }

        let _write_serial = self.write_serial.lock().await;
        let mut guard = self.settings.lock().await;
        let mut next = guard.clone();
        next.extend(update.clone());
        if !validate(&next) {
            return false;
        }
        if *guard == next {
            return true;
        }

        guard.clone_from(&next);
        drop(guard);
        match serialize_pretty_tabs(&next) {
            Ok(bytes) => {
                if let Err(error) = tokio::fs::write(&self.path, bytes).await {
                    error!(target: "probe-settings", %error, "Probe settings updated in memory, but failed to save.");
                } else {
                    info!(target: "probe-settings", settings = ?next, "Probe settings updated.");
                }
            }
            Err(error) => {
                error!(target: "probe-settings", %error, "Probe settings updated in memory, but could not be serialized.");
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn defaults_when_missing() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let store = ProbeSettingsStore::new(dir.path().join("settings"));
        assert_eq!(store.get().await["meteredConnection"], false);
        Ok(())
    }

    #[tokio::test]
    async fn preserves_unknown_and_persists_updates() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("settings");
        std::fs::write(&path, r#"{"meteredConnection":true,"unknown":true}"#)?;
        let store = ProbeSettingsStore::new(&path);
        assert_eq!(store.get().await["unknown"], true);
        assert!(
            store
                .update(&serde_json::json!({ "meteredConnection": false }))
                .await
        );
        let reloaded = ProbeSettingsStore::new(&path);
        assert_eq!(reloaded.get().await["meteredConnection"], false);
        assert_eq!(reloaded.get().await["unknown"], true);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_invalid_known_value() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let store = ProbeSettingsStore::new(dir.path().join("settings"));
        assert!(
            !store
                .update(&serde_json::json!({ "meteredConnection": "true" }))
                .await
        );
        assert_eq!(store.get().await["meteredConnection"], false);
        Ok(())
    }

    #[tokio::test]
    async fn removes_invalid_existing_file() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("settings");
        std::fs::write(&path, "{")?;
        let store = ProbeSettingsStore::new(&path);
        assert_eq!(store.get().await["meteredConnection"], false);
        assert!(!path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn persistence_failure_keeps_memory_update() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("settings-dir");
        std::fs::create_dir(&path)?;
        let store = ProbeSettingsStore::new(&path);
        assert!(
            store
                .update(&serde_json::json!({ "meteredConnection": true }))
                .await
        );
        assert_eq!(store.get().await["meteredConnection"], true);
        Ok(())
    }
}
