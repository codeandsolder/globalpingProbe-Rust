use globalping_probe::probe::{
    client::{self, ClientConfig},
    sysinfo::looks_like_v1_hardware_device,
    uuid::{self, ProbeUuid},
};
use globalping_probe::supervisor::{
    bootstrap::BehaviorController, transport::ProductionBehaviorConfig,
};
use globalping_probe::util;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    util::logger::init();

    let uuid_path = std::env::var("GP_UUID_PATH").unwrap_or_else(|_| uuid::resolve_uuid_path());
    let uuid = ProbeUuid::load_or_create(&uuid_path);
    let looks_like_v1 = looks_like_v1_hardware_device();
    let cfg = ClientConfig {
        api_host: std::env::var("GP_API_HOST")
            .unwrap_or_else(|_| "https://api.globalping.io".into()),
        uuid: uuid.id,
        ping_target: std::env::var("GP_PING_TARGET").unwrap_or_else(|_| "api.globalping.io".into()),
        adoption_token: std::env::var("GP_ADOPTION_TOKEN").ok(),
        is_hardware: std::env::var("GP_HOST_HW")
            .ok()
            .or_else(|| looks_like_v1.then(|| "true".to_string())),
        hardware_device: std::env::var("GP_HOST_DEVICE")
            .ok()
            .or_else(|| looks_like_v1.then(|| "v1".to_string())),
        hardware_device_firmware: std::env::var("GP_HOST_FIRMWARE").ok(),
    };

    let behavior_config = ProductionBehaviorConfig::from_env()?;
    let (behavior_controller, updater_task) = if let Some(behavior_config) = behavior_config {
        let controller = BehaviorController::load(behavior_config.bootstrap_config()).await?;
        info!(
            target: "behavior-update",
            root = %behavior_config.root().display(),
            active_sequence = ?controller.active_sequence()?,
            update_source = ?behavior_config.update_base().map(url::Url::as_str),
            "Trusted behavior controller enabled."
        );
        let updater_task = behavior_config
            .updater()?
            .map(|updater| tokio::spawn(updater.run(Arc::clone(&controller))));
        (Some(controller), updater_task)
    } else {
        (None, None)
    };

    let result = client::run_with_behavior_controller(cfg, behavior_controller).await;
    if let Some(task) = updater_task {
        task.abort();
        let _ = task.await;
    }
    result
}
