use std::fs;
use uuid::Uuid;

/// Default UUID path — `/.globalping-probe-uuid` when running as root (production),
/// or `$HOME/.globalping-probe-uuid` as a writable fallback.
pub const UUID_PATH: &str = "/.globalping-probe-uuid";

/// Resolve the actual UUID file path: use `/.globalping-probe-uuid` if writable (root),
/// otherwise fall back to `$HOME/.globalping-probe-uuid`.
#[must_use]
pub fn resolve_uuid_path() -> String {
    // Try the canonical path first (works when running as root)
    if std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(UUID_PATH)
        .is_ok()
    {
        return UUID_PATH.to_string();
    }
    // Fallback to home directory
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    format!("{home}/.globalping-probe-uuid")
}

#[derive(Debug, Clone)]
pub struct ProbeUuid {
    pub id: String,
}

impl ProbeUuid {
    /// Load UUID from `path`, or generate and persist a new one.
    pub fn load_or_create(path: &str) -> Self {
        match fs::read_to_string(path) {
            Ok(content) => {
                let id = content.trim().to_string();
                if !id.is_empty() {
                    return Self { id };
                }
                Self::generate(path)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("No UUID file at {path}. Generating new UUID.");
                Self::generate(path)
            }
            Err(e) => {
                tracing::warn!("Failed to read UUID file ({e}). Generating new UUID.");
                Self::generate(path)
            }
        }
    }

    fn generate(path: &str) -> Self {
        let id = Uuid::new_v4().to_string();
        if let Err(e) = fs::write(path, &id) {
            tracing::warn!("Failed to write UUID file to {path}: {e}");
        }
        tracing::info!("Generated new probe UUID: {}…", &id[..8]);
        Self { id }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn generates_uuid_when_file_missing() {
        let p = "/tmp/gp_uuid_nonexistent_test_file_xyz.txt";
        let _ = fs::remove_file(p); // ensure it doesn't exist
        let u = ProbeUuid::load_or_create(p);
        assert!(!u.id.is_empty());
        assert_eq!(u.id.len(), 36); // UUID v4 canonical form
        let _ = fs::remove_file(p);
    }

    #[test]
    fn reads_existing_uuid_from_file() {
        let f = NamedTempFile::new().unwrap();
        let expected = "550e8400-e29b-41d4-a716-446655440000";
        fs::write(f.path(), expected).unwrap();
        let u = ProbeUuid::load_or_create(f.path().to_str().unwrap());
        assert_eq!(u.id, expected);
    }

    #[test]
    fn generates_new_uuid_when_file_is_empty() {
        let f = NamedTempFile::new().unwrap();
        fs::write(f.path(), "   \n").unwrap();
        let u = ProbeUuid::load_or_create(f.path().to_str().unwrap());
        assert_eq!(u.id.len(), 36);
    }

    #[test]
    fn persists_generated_uuid_to_file() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_string();
        drop(f); // delete file so it doesn't exist
        let u = ProbeUuid::load_or_create(&path);
        let stored = fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(stored.trim(), u.id.as_str());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn consecutive_loads_return_same_uuid() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_string();
        drop(f);
        let u1 = ProbeUuid::load_or_create(&path);
        let u2 = ProbeUuid::load_or_create(&path);
        assert_eq!(u1.id, u2.id);
        let _ = fs::remove_file(&path);
    }
}
