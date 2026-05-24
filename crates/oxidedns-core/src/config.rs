use std::{fs, net::SocketAddr, path::Path};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration from {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },

    #[error("failed to parse TOML configuration: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    pub server: ServerSettings,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub zones: Vec<ZoneConfig>,
    #[serde(default)]
    pub tsig_keys: Vec<TsigKeyConfig>,
}

impl ServerConfig {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&text)
    }

    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let config = toml::from_str::<Self>(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.listen_udp.is_empty() && self.server.listen_tcp.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one UDP or TCP listener is required".to_owned(),
            ));
        }

        if self.zones.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one served zone is required".to_owned(),
            ));
        }

        for zone in &self.zones {
            zone.validate()?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ServerSettings {
    #[serde(default)]
    pub listen_udp: Vec<SocketAddr>,
    #[serde(default)]
    pub listen_tcp: Vec<SocketAddr>,
    pub health: Option<SocketAddr>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Limits {
    #[serde(default = "default_axfr_timeout_secs")]
    pub axfr_timeout_secs: u64,
    #[serde(default = "default_ixfr_timeout_secs")]
    pub ixfr_timeout_secs: u64,
    #[serde(default = "default_notify_dedup_secs")]
    pub notify_dedup_secs: u64,
    #[serde(default = "default_max_concurrent_transfers")]
    pub max_concurrent_transfers: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            axfr_timeout_secs: default_axfr_timeout_secs(),
            ixfr_timeout_secs: default_ixfr_timeout_secs(),
            notify_dedup_secs: default_notify_dedup_secs(),
            max_concurrent_transfers: default_max_concurrent_transfers(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ZoneConfig {
    pub name: String,
    #[serde(default = "default_dns_class")]
    pub class: String,
    pub primaries: Vec<SocketAddr>,
    #[serde(default)]
    pub notify_sources: Vec<std::net::IpAddr>,
    pub tsig_key: Option<String>,
}

impl ZoneConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "zone name must not be empty".to_owned(),
            ));
        }

        if !self.name.ends_with('.') {
            return Err(ConfigError::Invalid(format!(
                "zone {} must be an absolute DNS name ending with '.'",
                self.name
            )));
        }

        if !self.class.eq_ignore_ascii_case("IN") {
            return Err(ConfigError::Invalid(format!(
                "zone {} uses unsupported class {}; only IN is currently allowed",
                self.name, self.class
            )));
        }

        if self.primaries.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "zone {} requires at least one primary",
                self.name
            )));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TsigKeyConfig {
    pub name: String,
    pub algorithm: String,
    pub secret: String,
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn default_dns_class() -> String {
    "IN".to_owned()
}

fn default_axfr_timeout_secs() -> u64 {
    300
}

fn default_ixfr_timeout_secs() -> u64 {
    60
}

fn default_notify_dedup_secs() -> u64 {
    1
}

fn default_max_concurrent_transfers() -> usize {
    4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_valid_config() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.server.listen_udp.len(), 1);
        assert_eq!(config.zones[0].class, "IN");
        assert_eq!(config.limits.ixfr_timeout_secs, 60);
    }

    #[test]
    fn rejects_relative_zone_name() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test"
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("relative zone must fail");

        assert!(error.to_string().contains("absolute DNS name"));
    }
}
