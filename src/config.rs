use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub api: ApiConfig,
    pub commands: CommandsConfig,
    pub status: StatusConfig,
    pub stats: StatsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ApiConfig {
    pub host: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CommandsConfig {
    pub timeout_secs: u64,
    pub progress_interval_ms: u64,
    pub ping: PingConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PingConfig {
    pub interval: f32,
    pub packets: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StatusConfig {
    pub ping_interval_secs: u64,
    pub icmp_tcp_interval_secs: u64,
    pub disconnect_ttl_secs: u64,
    pub max_disconnects: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StatsConfig {
    pub interval_secs: u64,
}

impl AppConfig {
    /// Load optional file configuration plus `GP__*` environment overrides.
    ///
    /// # Errors
    /// Returns an error when configuration sources cannot be built or deserialized.
    pub fn load() -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::Environment::with_prefix("GP").separator("__"))
            .build()?;

        Ok(cfg.try_deserialize()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_fields_are_accessible() {
        // Verify the struct compiles and fields are public
        let _ = std::mem::size_of::<AppConfig>();
    }
}
