use globalping_probe::probe::{
    client::{self, ClientConfig},
    sysinfo::looks_like_v1_hardware_device,
    uuid::{self, ProbeUuid},
};
use globalping_probe::supervisor::{
    bootstrap::BehaviorController, transport::ProductionBehaviorConfig,
};
use globalping_probe::util;
use std::{future::Future, sync::Arc};
use tracing::info;

async fn run_probe_with_updater<F>(
    client_future: F,
    updater_task: Option<tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
{
    let Some(mut updater_task) = updater_task else {
        return client_future.await;
    };
    tokio::pin!(client_future);

    tokio::select! {
        biased;

        updater_result = &mut updater_task => match updater_result {
            Ok(()) => Err(anyhow::anyhow!("behavior updater task exited unexpectedly")),
            Err(error) => Err(anyhow::anyhow!("behavior updater task terminated unexpectedly: {error}")),
        },
        client_result = &mut client_future => {
            updater_task.abort();
            match updater_task.await {
                Err(error) if error.is_cancelled() => client_result,
                Ok(()) => Err(anyhow::anyhow!("behavior updater task exited unexpectedly during probe shutdown")),
                Err(error) => Err(anyhow::anyhow!("behavior updater task terminated unexpectedly during probe shutdown: {error}")),
            }
        }
    }
}

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
        let behavior_state = controller.operator_snapshot().await?;
        info!(
            target: "behavior-update",
            root = %behavior_config.root().display(),
            active = ?behavior_state.active,
            previous = ?behavior_state.previous,
            accepted_sequence = behavior_state.accepted_sequence,
            health = ?behavior_state.health,
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

    run_probe_with_updater(
        Box::pin(client::run_with_behavior_controller(
            cfg,
            behavior_controller,
        )),
        updater_task,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::run_probe_with_updater;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn client_completion_cancels_updater() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let updater = tokio::spawn(async move {
            let _drop_flag = DropFlag(task_dropped);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        assert!(started_rx.await.is_ok());

        let result = run_probe_with_updater(async { Ok(()) }, Some(updater)).await;
        assert!(result.is_ok());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn updater_exit_is_fatal() {
        let updater = tokio::spawn(async {});
        let result = run_probe_with_updater(std::future::pending(), Some(updater)).await;
        let error = result
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(error.contains("behavior updater task exited unexpectedly"));
    }

    #[tokio::test]
    async fn updater_panic_is_fatal() {
        let updater = tokio::spawn(async { panic!("intentional updater panic") });
        let result = run_probe_with_updater(std::future::pending(), Some(updater)).await;
        let error = result
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(error.contains("behavior updater task terminated unexpectedly"));
    }

    #[tokio::test]
    async fn no_updater_preserves_client_result() {
        let result = run_probe_with_updater(async { Ok(()) }, None).await;
        assert!(result.is_ok());
    }
}
