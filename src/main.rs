use globalping_probe::probe::{
    client::{self, ClientConfig},
    sysinfo::looks_like_v1_hardware_device,
    uuid::{self, ProbeUuid},
};
use globalping_probe::util;

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

    client::run(cfg).await
}
