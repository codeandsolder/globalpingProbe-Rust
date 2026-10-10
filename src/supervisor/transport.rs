//! Production bootstrap and HTTPS transport for signed behavior updates.
//!
//! The update endpoint is only a discovery/transport channel. The Ed25519 key
//! configured locally remains the trust root, and every downloaded artifact is
//! still subject to signature, digest, ABI, supervisor-version and monotonic
//! sequence checks before activation.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use reqwest::redirect::Policy;
use tracing::{debug, info, warn};
use url::Url;

use super::bootstrap::{BehaviorBootstrapConfig, BehaviorController, BootstrapError};
use super::update::{BehaviorManifest, MAX_COMPONENT_BYTES, MAX_MANIFEST_BYTES};

pub const DEFAULT_BEHAVIOR_ROOT: &str = "/.globalping-behavior";
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(300);
const UPDATE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum BehaviorTransportError {
    MissingVerifyingKey,
    Environment {
        name: &'static str,
        error: std::env::VarError,
    },
    InvalidVerifyingKeyHex(hex::FromHexError),
    InvalidVerifyingKeyLength(usize),
    InvalidVerifyingKey(ed25519_dalek::SignatureError),
    RelativeRoot,
    UpdateIntervalWithoutSource,
    InvalidUpdateInterval(String),
    InvalidUpdateUrl(url::ParseError),
    InsecureUpdateUrl,
    UpdateUrlMissingHost,
    UpdateUrlCredentials,
    UpdateUrlQueryOrFragment,
    HttpClient(reqwest::Error),
    Http(reqwest::Error),
    PayloadTooLarge {
        kind: &'static str,
        limit: usize,
    },
    Manifest(serde_json::Error),
    Bootstrap(BootstrapError),
}

impl fmt::Display for BehaviorTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVerifyingKey => f.write_str(
                "behavior configuration requires GP_BEHAVIOR_VERIFYING_KEY when any behavior option is set",
            ),
            Self::Environment { name, error } => {
                write!(f, "behavior environment variable {name} is invalid: {error}")
            }
            Self::InvalidVerifyingKeyHex(error) => {
                write!(f, "behavior verifying key is not valid hex: {error}")
            }
            Self::InvalidVerifyingKeyLength(length) => write!(
                f,
                "behavior verifying key must decode to 32 bytes, got {length}"
            ),
            Self::InvalidVerifyingKey(error) => {
                write!(f, "behavior verifying key is invalid: {error}")
            }
            Self::RelativeRoot => f.write_str("behavior storage root must be an absolute path"),
            Self::UpdateIntervalWithoutSource => f.write_str(
                "GP_BEHAVIOR_UPDATE_INTERVAL_SECS requires GP_BEHAVIOR_UPDATE_URL",
            ),
            Self::InvalidUpdateInterval(value) => write!(
                f,
                "behavior update interval must be a non-zero integer number of seconds, got {value:?}"
            ),
            Self::InvalidUpdateUrl(error) => write!(f, "behavior update URL is invalid: {error}"),
            Self::InsecureUpdateUrl => f.write_str("behavior update URL must use HTTPS"),
            Self::UpdateUrlMissingHost => {
                f.write_str("behavior update URL must contain a host")
            }
            Self::UpdateUrlCredentials => {
                f.write_str("behavior update URL must not contain embedded credentials")
            }
            Self::UpdateUrlQueryOrFragment => {
                f.write_str("behavior update base URL must not contain a query or fragment")
            }
            Self::HttpClient(error) => write!(f, "behavior update HTTP client failed: {error}"),
            Self::Http(error) => write!(f, "behavior update request failed: {error}"),
            Self::PayloadTooLarge { kind, limit } => {
                write!(f, "behavior {kind} exceeds the {limit}-byte transport limit")
            }
            Self::Manifest(error) => write!(f, "behavior update manifest is invalid: {error}"),
            Self::Bootstrap(error) => write!(f, "behavior update activation failed: {error}"),
        }
    }
}

impl std::error::Error for BehaviorTransportError {}

impl From<BootstrapError> for BehaviorTransportError {
    fn from(error: BootstrapError) -> Self {
        Self::Bootstrap(error)
    }
}

#[derive(Debug, Clone)]
pub struct ProductionBehaviorConfig {
    bootstrap: BehaviorBootstrapConfig,
    update_base: Option<Url>,
    update_interval: Duration,
}

impl ProductionBehaviorConfig {
    /// Read the optional production behavior configuration from `GP_BEHAVIOR_*`.
    ///
    /// With no behavior variables set this returns `None`, preserving native-only
    /// startup. If any behavior variable is present, a locally provisioned
    /// Ed25519 verifying key is mandatory.
    ///
    /// # Errors
    /// Returns an error for non-Unicode environment values, partial/invalid
    /// configuration, a malformed key, relative storage path, or unsafe update
    /// URL.
    pub fn from_env() -> Result<Option<Self>, BehaviorTransportError> {
        Self::from_values(
            env_optional("GP_BEHAVIOR_VERIFYING_KEY")?,
            env_optional("GP_BEHAVIOR_ROOT")?,
            env_optional("GP_BEHAVIOR_UPDATE_URL")?,
            env_optional("GP_BEHAVIOR_UPDATE_INTERVAL_SECS")?,
        )
    }

    fn from_values(
        verifying_key: Option<String>,
        root: Option<String>,
        update_url: Option<String>,
        update_interval: Option<String>,
    ) -> Result<Option<Self>, BehaviorTransportError> {
        let configured = verifying_key.is_some()
            || root.is_some()
            || update_url.is_some()
            || update_interval.is_some();
        if !configured {
            return Ok(None);
        }
        let key = verifying_key.ok_or(BehaviorTransportError::MissingVerifyingKey)?;
        let verifying_key = parse_verifying_key(&key)?;
        let root = PathBuf::from(root.unwrap_or_else(|| DEFAULT_BEHAVIOR_ROOT.to_string()));
        if !root.is_absolute() {
            return Err(BehaviorTransportError::RelativeRoot);
        }
        if update_interval.is_some() && update_url.is_none() {
            return Err(BehaviorTransportError::UpdateIntervalWithoutSource);
        }
        let update_base = update_url
            .map(|value| normalize_update_base(&value))
            .transpose()?;
        let update_interval = if let Some(value) = update_interval {
            let seconds = value
                .parse::<u64>()
                .ok()
                .filter(|seconds| *seconds != 0)
                .ok_or_else(|| BehaviorTransportError::InvalidUpdateInterval(value.clone()))?;
            Duration::from_secs(seconds)
        } else {
            DEFAULT_UPDATE_INTERVAL
        };
        Ok(Some(Self {
            bootstrap: BehaviorBootstrapConfig::new(root, verifying_key),
            update_base,
            update_interval,
        }))
    }

    #[must_use]
    pub fn bootstrap_config(&self) -> BehaviorBootstrapConfig {
        self.bootstrap.clone()
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        self.bootstrap.root()
    }

    #[must_use]
    pub const fn update_base(&self) -> Option<&Url> {
        self.update_base.as_ref()
    }

    /// Build an updater if a network source was configured.
    ///
    /// # Errors
    /// Returns an error if the bounded HTTPS client cannot be constructed.
    pub fn updater(&self) -> Result<Option<BehaviorUpdater>, BehaviorTransportError> {
        self.update_base
            .as_ref()
            .map(|base| BehaviorUpdater::new(base, self.update_interval))
            .transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorUpdateOutcome {
    Current { sequence: u64 },
    Activated { sequence: u64, build_id: String },
}

#[derive(Clone)]
pub struct BehaviorUpdater {
    client: reqwest::Client,
    manifest_url: Url,
    component_url: Url,
    interval: Duration,
}

fn update_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .https_only(true)
        .connect_timeout(UPDATE_CONNECT_TIMEOUT)
        .timeout(UPDATE_REQUEST_TIMEOUT)
        .user_agent(concat!(
            "globalping-probe/",
            env!("CARGO_PKG_VERSION"),
            " behavior-updater"
        ))
}

impl BehaviorUpdater {
    fn new(base: &Url, interval: Duration) -> Result<Self, BehaviorTransportError> {
        let client = update_http_client_builder()
            .build()
            .map_err(BehaviorTransportError::HttpClient)?;
        Self::with_client(base, interval, client)
    }

    fn with_client(
        base: &Url,
        interval: Duration,
        client: reqwest::Client,
    ) -> Result<Self, BehaviorTransportError> {
        let manifest_url = base
            .join("manifest.json")
            .map_err(BehaviorTransportError::InvalidUpdateUrl)?;
        let component_url = base
            .join("component.wasm")
            .map_err(BehaviorTransportError::InvalidUpdateUrl)?;
        Ok(Self {
            client,
            manifest_url,
            component_url,
            interval,
        })
    }

    /// Fetch and, if newer, activate one signed behavior update.
    ///
    /// The manifest is bounded and parsed before the component is fetched. A
    /// sequence that is not newer than the durable accepted high-water mark
    /// causes no component download.
    ///
    /// # Errors
    /// Returns transport/format errors or any verification/runtime/storage error
    /// reported by the controller during activation.
    pub async fn check_once(
        &self,
        controller: &BehaviorController,
    ) -> Result<BehaviorUpdateOutcome, BehaviorTransportError> {
        let manifest_bytes = self
            .fetch_limited(&self.manifest_url, MAX_MANIFEST_BYTES, "manifest")
            .await?;
        let manifest: BehaviorManifest =
            serde_json::from_slice(&manifest_bytes).map_err(BehaviorTransportError::Manifest)?;
        let accepted = controller.accepted_sequence()?;
        if manifest.sequence <= accepted {
            return Ok(BehaviorUpdateOutcome::Current { sequence: accepted });
        }
        controller.preflight_candidate_manifest(&manifest)?;
        let expected_size = usize::try_from(manifest.size).map_err(|_| {
            BehaviorTransportError::PayloadTooLarge {
                kind: "component",
                limit: MAX_COMPONENT_BYTES,
            }
        })?;
        let component = self
            .fetch_limited(&self.component_url, expected_size, "component")
            .await?;
        let sequence = manifest.sequence;
        let build_id = manifest.build_id.clone();
        controller.activate_candidate(manifest, component).await?;
        Ok(BehaviorUpdateOutcome::Activated { sequence, build_id })
    }

    /// Poll the configured signed update source until this task is aborted.
    pub async fn run(self, controller: Arc<BehaviorController>) {
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match self.check_once(&controller).await {
                Ok(BehaviorUpdateOutcome::Current { sequence }) => {
                    debug!(target: "behavior-update", accepted_sequence = sequence, "Behavior component is current.");
                }
                Ok(BehaviorUpdateOutcome::Activated { sequence, build_id }) => {
                    info!(target: "behavior-update", behavior_sequence = sequence, behavior_build_id = %build_id, "Activated signed behavior component update.");
                }
                Err(error) => {
                    warn!(target: "behavior-update", %error, "Signed behavior update check failed; keeping the current behavior slot.");
                }
            }
        }
    }

    async fn fetch_limited(
        &self,
        url: &Url,
        limit: usize,
        kind: &'static str,
    ) -> Result<Vec<u8>, BehaviorTransportError> {
        let mut response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(BehaviorTransportError::Http)?
            .error_for_status()
            .map_err(BehaviorTransportError::Http)?;
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(BehaviorTransportError::PayloadTooLarge { kind, limit });
        }
        let capacity = response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(limit);
        let mut body = Vec::with_capacity(capacity);
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(BehaviorTransportError::Http)?
        {
            if body
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > limit)
            {
                return Err(BehaviorTransportError::PayloadTooLarge { kind, limit });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn env_optional(name: &'static str) -> Result<Option<String>, BehaviorTransportError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(BehaviorTransportError::Environment { name, error }),
    }
}

fn parse_verifying_key(value: &str) -> Result<VerifyingKey, BehaviorTransportError> {
    let bytes =
        hex::decode(value.trim()).map_err(BehaviorTransportError::InvalidVerifyingKeyHex)?;
    let length = bytes.len();
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| BehaviorTransportError::InvalidVerifyingKeyLength(length))?;
    VerifyingKey::from_bytes(&bytes).map_err(BehaviorTransportError::InvalidVerifyingKey)
}

fn normalize_update_base(value: &str) -> Result<Url, BehaviorTransportError> {
    let mut url = Url::parse(value).map_err(BehaviorTransportError::InvalidUpdateUrl)?;
    if url.scheme() != "https" {
        return Err(BehaviorTransportError::InsecureUpdateUrl);
    }
    if !url.has_host() {
        return Err(BehaviorTransportError::UpdateUrlMissingHost);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(BehaviorTransportError::UpdateUrlCredentials);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(BehaviorTransportError::UpdateUrlQueryOrFragment);
    }
    if !url.path().ends_with('/') {
        let mut path = url.path().to_string();
        path.push('/');
        url.set_path(&path);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::SocketAddr;
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Router, routing::get};
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;
    use crate::supervisor::health::{BehaviorHealthEvent, BehaviorHealthPolicy};
    use crate::supervisor::runtime::RuntimeError;
    use crate::supervisor::update::{SUPPORTED_ABI_MAJOR, SUPPORTED_ABI_MINOR, UpdateError};

    fn key_hex() -> String {
        hex::encode(SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes())
    }

    fn signed_manifest(sequence: u64, component: &[u8], key: &SigningKey) -> BehaviorManifest {
        let mut manifest = BehaviorManifest {
            sequence,
            abi_major: SUPPORTED_ABI_MAJOR,
            abi_minor: SUPPORTED_ABI_MINOR,
            min_supervisor_version: env!("CARGO_PKG_VERSION").to_string(),
            size: component.len() as u64,
            sha256: hex::encode(Sha256::digest(component)),
            build_id: format!("transport-test-{sequence}"),
            signature: String::new(),
        };
        manifest.signature = hex::encode(key.sign(&manifest.signing_payload()).to_bytes());
        manifest
    }

    #[derive(Clone)]
    struct ServedBehavior {
        manifest: Vec<u8>,
        component: Vec<u8>,
    }

    impl ServedBehavior {
        fn signed(sequence: u64, component: Vec<u8>, key: &SigningKey) -> Self {
            let manifest = signed_manifest(sequence, &component, key);
            let manifest = serde_json::to_vec(&manifest)
                .unwrap_or_else(|error| panic!("manifest serialization failed: {error}"));
            Self {
                manifest,
                component,
            }
        }
    }

    struct TestTlsListener {
        tcp: tokio::net::TcpListener,
        acceptor: TlsAcceptor,
    }

    impl axum::serve::Listener for TestTlsListener {
        type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
        type Addr = SocketAddr;

        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            loop {
                match self.tcp.accept().await {
                    Ok((stream, address)) => {
                        if let Ok(stream) = self.acceptor.accept(stream).await {
                            return (stream, address);
                        }
                    }
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        }

        fn local_addr(&self) -> io::Result<Self::Addr> {
            self.tcp.local_addr()
        }
    }

    struct TestHttpsServer {
        base: Url,
        root_certificate: reqwest::Certificate,
        artifact_state: Arc<RwLock<ServedBehavior>>,
        component_hits: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl TestHttpsServer {
        fn serve(&self, artifact: ServedBehavior) {
            *self
                .artifact_state
                .write()
                .unwrap_or_else(|_| panic!("served behavior lock poisoned")) = artifact;
        }

        fn component_hits(&self) -> usize {
            self.component_hits.load(Ordering::Relaxed)
        }

        async fn shutdown(self) {
            self.task.abort();
            let _ = self.task.await;
        }
    }

    async fn spawn_test_https_server(initial: ServedBehavior) -> TestHttpsServer {
        let artifact_state = Arc::new(RwLock::new(initial));
        let component_hits = Arc::new(AtomicUsize::new(0));
        let manifest_route = {
            let artifact_state = Arc::clone(&artifact_state);
            move || {
                let artifact_state = Arc::clone(&artifact_state);
                async move {
                    artifact_state
                        .read()
                        .unwrap_or_else(|_| panic!("served behavior lock poisoned"))
                        .manifest
                        .clone()
                }
            }
        };
        let component_route = {
            let artifact_state = Arc::clone(&artifact_state);
            let component_hits = Arc::clone(&component_hits);
            move || {
                let artifact_state = Arc::clone(&artifact_state);
                let component_hits = Arc::clone(&component_hits);
                async move {
                    component_hits.fetch_add(1, Ordering::Relaxed);
                    artifact_state
                        .read()
                        .unwrap_or_else(|_| panic!("served behavior lock poisoned"))
                        .component
                        .clone()
                }
            }
        };
        let app = Router::new()
            .route("/manifest.json", get(manifest_route))
            .route("/component.wasm", get(component_route));

        // Fixed test-only localhost certificate and private key. These bytes are
        // intentionally public fixtures, not production signing or TLS material.
        let cert_der = tokio_rustls::rustls::pki_types::CertificateDer::from(
            include_bytes!("../../tests/fixtures/behavior-update-localhost-cert.der").to_vec(),
        );
        let key_der = PrivatePkcs8KeyDer::from(
            include_bytes!("../../tests/fixtures/behavior-update-localhost-key.der").to_vec(),
        );
        let tls = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
            .unwrap_or_else(|error| panic!("test TLS configuration failed: {error}"));
        let tcp = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|error| panic!("test HTTPS listener bind failed: {error}"));
        let address = tcp
            .local_addr()
            .unwrap_or_else(|error| panic!("test HTTPS listener address failed: {error}"));
        let listener = TestTlsListener {
            tcp,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
        };
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let base = Url::parse(&format!("https://{address}/"))
            .unwrap_or_else(|error| panic!("test HTTPS URL failed: {error}"));
        let root_certificate = reqwest::Certificate::from_der(include_bytes!(
            "../../tests/fixtures/behavior-update-localhost-ca.der"
        ))
        .unwrap_or_else(|error| panic!("test root certificate failed: {error}"));
        TestHttpsServer {
            base,
            root_certificate,
            artifact_state,
            component_hits,
            task,
        }
    }

    fn tcp_ping_measurement() -> serde_json::Value {
        serde_json::json!({
            "type": "ping",
            "target": "1.1.1.1",
            "protocol": "TCP",
            "port": 443,
            "packets": 1,
            "ipVersion": 4,
            "timeout": 10,
            "inProgressUpdates": false
        })
    }

    #[test]
    fn no_behavior_values_leave_native_only_startup() {
        assert!(
            ProductionBehaviorConfig::from_values(None, None, None, None)
                .unwrap_or_else(|error| panic!("empty config failed: {error}"))
                .is_none()
        );
    }

    #[test]
    fn key_only_uses_production_slot_root_without_network_updates() {
        let config = ProductionBehaviorConfig::from_values(Some(key_hex()), None, None, None)
            .unwrap_or_else(|error| panic!("key-only config failed: {error}"))
            .unwrap_or_else(|| panic!("key must enable behavior bootstrap"));
        assert_eq!(config.root(), Path::new(DEFAULT_BEHAVIOR_ROOT));
        assert!(config.update_base().is_none());
    }

    #[test]
    fn partial_configuration_without_key_is_rejected() {
        assert!(matches!(
            ProductionBehaviorConfig::from_values(
                None,
                Some("/tmp/behavior".to_string()),
                None,
                None,
            ),
            Err(BehaviorTransportError::MissingVerifyingKey)
        ));
        assert!(matches!(
            ProductionBehaviorConfig::from_values(
                None,
                None,
                Some("https://updates.example/behavior/".to_string()),
                None,
            ),
            Err(BehaviorTransportError::MissingVerifyingKey)
        ));
    }

    #[tokio::test]
    async fn key_only_empty_root_loads_inert_controller() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let config = ProductionBehaviorConfig::from_values(
            Some(key_hex()),
            Some(dir.path().to_string_lossy().into_owned()),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("key-only config failed: {error}"))
        .unwrap_or_else(|| panic!("key must enable behavior bootstrap"));
        let controller = BehaviorController::load(config.bootstrap_config())
            .await
            .unwrap_or_else(|error| panic!("empty controller load failed: {error}"));
        assert_eq!(
            controller
                .accepted_sequence()
                .unwrap_or_else(|error| panic!("accepted sequence failed: {error}")),
            0
        );
        assert_eq!(
            controller
                .active_sequence()
                .unwrap_or_else(|error| panic!("active sequence failed: {error}")),
            None
        );
        assert!(controller.executor().await.is_none());
    }

    #[test]
    fn update_base_is_https_credentialless_and_directory_scoped() {
        let config = ProductionBehaviorConfig::from_values(
            Some(key_hex()),
            Some("/var/lib/globalping/behavior".to_string()),
            Some("https://updates.example/releases/current".to_string()),
            Some("60".to_string()),
        )
        .unwrap_or_else(|error| panic!("valid behavior config failed: {error}"))
        .unwrap_or_else(|| panic!("behavior config unexpectedly disabled"));
        assert_eq!(
            config.update_base().map(Url::as_str),
            Some("https://updates.example/releases/current/")
        );
        let updater = config
            .updater()
            .unwrap_or_else(|error| panic!("updater construction failed: {error}"))
            .unwrap_or_else(|| panic!("configured source must produce updater"));
        assert_eq!(
            updater.manifest_url.as_str(),
            "https://updates.example/releases/current/manifest.json"
        );
        assert_eq!(
            updater.component_url.as_str(),
            "https://updates.example/releases/current/component.wasm"
        );
    }

    #[test]
    fn unsafe_or_ambiguous_update_urls_are_rejected() {
        for value in [
            "http://updates.example/behavior/",
            "https:///",
            "https://user:pass@updates.example/behavior/",
            "https://updates.example/behavior/?channel=stable",
            "https://updates.example/behavior/#stable",
        ] {
            assert!(
                ProductionBehaviorConfig::from_values(
                    Some(key_hex()),
                    None,
                    Some(value.to_string()),
                    None,
                )
                .is_err(),
                "accepted unsafe URL: {value}"
            );
        }
    }

    #[test]
    fn update_interval_requires_source_and_nonzero_seconds() {
        assert!(matches!(
            ProductionBehaviorConfig::from_values(
                Some(key_hex()),
                None,
                None,
                Some("60".to_string()),
            ),
            Err(BehaviorTransportError::UpdateIntervalWithoutSource)
        ));
        assert!(matches!(
            ProductionBehaviorConfig::from_values(
                Some(key_hex()),
                None,
                Some("https://updates.example/behavior/".to_string()),
                Some("0".to_string()),
            ),
            Err(BehaviorTransportError::InvalidUpdateInterval(_))
        ));
    }

    #[tokio::test]
    async fn bad_manifest_signature_is_rejected_before_component_download() {
        let trusted = SigningKey::from_bytes(&[11; 32]);
        let attacker = SigningKey::from_bytes(&[12; 32]);
        let component = b"not-even-downloaded".to_vec();
        let manifest = signed_manifest(1, &component, &attacker);
        let manifest_body = serde_json::to_vec(&manifest)
            .unwrap_or_else(|error| panic!("manifest serialization failed: {error}"));
        let component_hits = Arc::new(AtomicUsize::new(0));
        let manifest_route = {
            let manifest_body = manifest_body.clone();
            move || {
                let body = manifest_body.clone();
                async move { body }
            }
        };
        let component_route = {
            let component = component.clone();
            let component_hits = Arc::clone(&component_hits);
            move || {
                let body = component.clone();
                let component_hits = Arc::clone(&component_hits);
                async move {
                    component_hits.fetch_add(1, Ordering::Relaxed);
                    body
                }
            }
        };
        let app = Router::new()
            .route("/manifest.json", get(manifest_route))
            .route("/component.wasm", get(component_route));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|error| panic!("test listener bind failed: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("test listener address failed: {error}"));
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = Url::parse(&format!("http://{address}/"))
            .unwrap_or_else(|error| panic!("test URL failed: {error}"));
        let updater = BehaviorUpdater {
            client: reqwest::Client::builder()
                .redirect(Policy::none())
                .build()
                .unwrap_or_else(|error| panic!("test HTTP client failed: {error}")),
            manifest_url: base
                .join("manifest.json")
                .unwrap_or_else(|error| panic!("manifest URL failed: {error}")),
            component_url: base
                .join("component.wasm")
                .unwrap_or_else(|error| panic!("component URL failed: {error}")),
            interval: DEFAULT_UPDATE_INTERVAL,
        };
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let controller = BehaviorController::load(BehaviorBootstrapConfig::new(
            dir.path(),
            trusted.verifying_key(),
        ))
        .await
        .unwrap_or_else(|error| panic!("controller load failed: {error}"));

        let result = updater.check_once(&controller).await;
        assert!(matches!(
            result,
            Err(BehaviorTransportError::Bootstrap(BootstrapError::Update(
                UpdateError::SignatureMismatch
            )))
        ));
        assert_eq!(component_hits.load(Ordering::Relaxed), 0);
        server.abort();
        let _ = server.await;
    }

    fn behavior_fixture(name: &'static str) -> Vec<u8> {
        let path =
            std::env::var_os(name).map_or_else(|| panic!("{name} is required"), PathBuf::from);
        std::fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
    }

    struct ProductionRolloutHarness {
        signing_key: SigningKey,
        normal: Vec<u8>,
        invalid: Vec<u8>,
        https: TestHttpsServer,
        _storage: tempfile::TempDir,
        config: ProductionBehaviorConfig,
        updater: BehaviorUpdater,
        policy: BehaviorHealthPolicy,
    }

    impl ProductionRolloutHarness {
        async fn start() -> Self {
            let normal = behavior_fixture("GLOBALPING_BEHAVIOR_HEALTH_COMPONENT");
            let invalid = behavior_fixture("GLOBALPING_BEHAVIOR_INVALID_OUTPUT_COMPONENT");
            let signing_key = SigningKey::from_bytes(&[11; 32]);
            let https =
                spawn_test_https_server(ServedBehavior::signed(1, normal.clone(), &signing_key))
                    .await;
            let storage =
                tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
            let config = ProductionBehaviorConfig::from_values(
                Some(hex::encode(signing_key.verifying_key().to_bytes())),
                Some(storage.path().to_string_lossy().into_owned()),
                Some(https.base.to_string()),
                Some("1".to_string()),
            )
            .unwrap_or_else(|error| panic!("production behavior config failed: {error}"))
            .unwrap_or_else(|| panic!("production behavior config unexpectedly disabled"));
            assert_eq!(config.update_base(), Some(&https.base));
            assert!(config.updater().is_ok());
            let client = update_http_client_builder()
                .add_root_certificate(https.root_certificate.clone())
                .build()
                .unwrap_or_else(|error| panic!("test production HTTPS client failed: {error}"));
            let updater = BehaviorUpdater::with_client(&https.base, Duration::from_secs(1), client)
                .unwrap_or_else(|error| panic!("test updater failed: {error}"));
            let policy = BehaviorHealthPolicy::new(
                std::num::NonZeroU32::new(1)
                    .unwrap_or_else(|| panic!("health threshold must be non-zero")),
            );
            Self {
                signing_key,
                normal,
                invalid,
                https,
                _storage: storage,
                config,
                updater,
                policy,
            }
        }

        async fn load_controller(&self) -> Arc<BehaviorController> {
            BehaviorController::load(
                self.config
                    .bootstrap_config()
                    .with_health_policy(self.policy),
            )
            .await
            .unwrap_or_else(|error| panic!("controller load failed: {error}"))
        }

        fn serve(&self, sequence: u64, component: Vec<u8>) {
            self.https.serve(ServedBehavior::signed(
                sequence,
                component,
                &self.signing_key,
            ));
        }

        async fn activate(&self, controller: &BehaviorController, sequence: u64) {
            assert_eq!(
                self.updater
                    .check_once(controller)
                    .await
                    .unwrap_or_else(|error| panic!("update {sequence} failed: {error:?}")),
                BehaviorUpdateOutcome::Activated {
                    sequence,
                    build_id: format!("transport-test-{sequence}"),
                }
            );
        }

        async fn assert_initial_activation(&self) -> Arc<BehaviorController> {
            let controller = self.load_controller().await;
            assert_eq!(controller.active_sequence().unwrap_or(None), None);
            assert_eq!(controller.accepted_sequence().unwrap_or_default(), 0);
            self.activate(&controller, 1).await;
            assert_eq!(controller.active_sequence().unwrap_or(None), Some(1));
            assert_eq!(controller.accepted_sequence().unwrap_or_default(), 1);
            assert_eq!(self.https.component_hits(), 1);
            let result = controller
                .executor()
                .await
                .unwrap_or_else(|| panic!("healthy executor missing"))
                .run(tcp_ping_measurement())
                .await
                .unwrap_or_else(|error| panic!("healthy behavior execution failed: {error}"));
            let oracle = result.resolve_oracle().await;
            assert!(
                oracle.error.is_none(),
                "healthy oracle failed: {:?}",
                oracle.error
            );
            assert!(result.component.is_ok());
            controller
        }

        async fn assert_bad_update_rolls_back(&self, controller: &BehaviorController) {
            self.serve(2, self.invalid.clone());
            self.activate(controller, 2).await;
            assert_eq!(controller.active_sequence().unwrap_or(None), Some(2));
            assert_eq!(controller.accepted_sequence().unwrap_or_default(), 2);
            assert!(controller.has_previous().unwrap_or(false));
            assert_eq!(self.https.component_hits(), 2);

            let result = controller
                .executor()
                .await
                .unwrap_or_else(|| panic!("bad executor missing"))
                .run(tcp_ping_measurement())
                .await
                .unwrap_or_else(|error| {
                    panic!("bad behavior execution failed before native start: {error}")
                });
            let oracle = result.resolve_oracle().await;
            assert!(
                oracle.error.is_none(),
                "fault fallback oracle failed: {:?}",
                oracle.error
            );
            let component_error = result
                .component
                .err()
                .unwrap_or_else(|| panic!("invalid-output fixture unexpectedly succeeded"));
            assert!(matches!(
                component_error,
                RuntimeError::GuestInvalidOutput(_)
            ));
            assert!(component_error.is_component_health_fault());
            assert_eq!(
                controller
                    .observe_health(2, BehaviorHealthEvent::RuntimeFault)
                    .await
                    .unwrap_or_else(|error| panic!("health rollback failed: {error}")),
                crate::supervisor::bootstrap::BehaviorHealthAction::RolledBack {
                    from_sequence: 2,
                    to_sequence: 1,
                }
            );
            assert_eq!(controller.active_sequence().unwrap_or(None), Some(1));
            assert_eq!(controller.accepted_sequence().unwrap_or_default(), 2);
            assert!(!controller.has_previous().unwrap_or(true));
        }

        async fn assert_stale_is_not_redownloaded_and_recover(
            &self,
            controller: &BehaviorController,
        ) {
            let hits_before = self.https.component_hits();
            assert_eq!(
                self.updater
                    .check_once(controller)
                    .await
                    .unwrap_or_else(|error| panic!("stale update check failed: {error}")),
                BehaviorUpdateOutcome::Current { sequence: 2 }
            );
            assert_eq!(self.https.component_hits(), hits_before);

            self.serve(3, self.normal.clone());
            self.activate(controller, 3).await;
            assert_eq!(controller.active_sequence().unwrap_or(None), Some(3));
            assert_eq!(controller.accepted_sequence().unwrap_or_default(), 3);
            assert!(controller.has_previous().unwrap_or(false));
        }

        async fn shutdown(self) {
            self.https.shutdown().await;
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires live network access plus normal and invalid-output WASIp2 behavior fixtures"]
    async fn production_rollout_survives_activation_restart_fault_rollback_and_restart() {
        let harness = ProductionRolloutHarness::start().await;
        let controller = harness.assert_initial_activation().await;
        drop(controller);

        let controller = harness.load_controller().await;
        assert_eq!(controller.active_sequence().unwrap_or(None), Some(1));
        assert_eq!(controller.accepted_sequence().unwrap_or_default(), 1);
        harness.assert_bad_update_rolls_back(&controller).await;
        drop(controller);

        let controller = harness.load_controller().await;
        assert_eq!(controller.active_sequence().unwrap_or(None), Some(1));
        assert_eq!(controller.accepted_sequence().unwrap_or_default(), 2);
        assert!(!controller.has_previous().unwrap_or(true));
        harness
            .assert_stale_is_not_redownloaded_and_recover(&controller)
            .await;
        drop(controller);
        harness.shutdown().await;
    }

    #[test]
    fn malformed_verifying_keys_are_rejected() {
        assert!(matches!(
            ProductionBehaviorConfig::from_values(Some("zz".to_string()), None, None, None,),
            Err(BehaviorTransportError::InvalidVerifyingKeyHex(_))
        ));
        assert!(matches!(
            ProductionBehaviorConfig::from_values(Some("00".repeat(31)), None, None, None,),
            Err(BehaviorTransportError::InvalidVerifyingKeyLength(31))
        ));
    }
}
