use std::{collections::HashSet, fmt, fs, net::SocketAddr, path::Path};

use serde::Deserialize;
use thiserror::Error;

use crate::{
    dns::{AnyResponseMode, DomainName},
    tsig::TsigKey,
};

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
    pub query: QuerySettings,
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

        if self.limits.max_udp_payload < 512 {
            return Err(ConfigError::Invalid(
                "limits.max_udp_payload must be at least 512".to_owned(),
            ));
        }
        if self.limits.max_cname_chain == 0 {
            return Err(ConfigError::Invalid(
                "limits.max_cname_chain must be at least 1".to_owned(),
            ));
        }
        if self.limits.tcp_idle_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.tcp_idle_timeout_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.tcp_read_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.tcp_read_timeout_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.tcp_write_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.tcp_write_timeout_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.max_tcp_connections == 0 {
            return Err(ConfigError::Invalid(
                "limits.max_tcp_connections must be at least 1".to_owned(),
            ));
        }
        if self.limits.graceful_shutdown_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.graceful_shutdown_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.max_concurrent_transfers == 0 {
            return Err(ConfigError::Invalid(
                "limits.max_concurrent_transfers must be at least 1".to_owned(),
            ));
        }
        if self.limits.edns_padding_block_size == 1 {
            return Err(ConfigError::Invalid(
                "limits.edns_padding_block_size must be 0 to disable padding or at least 2"
                    .to_owned(),
            ));
        }
        if self.limits.zsm_min_interval_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.zsm_min_interval_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.zsm_initial_retry_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.zsm_initial_retry_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.zsm_initial_retry_max_secs < self.limits.zsm_initial_retry_secs {
            return Err(ConfigError::Invalid(
                "limits.zsm_initial_retry_max_secs must be at least limits.zsm_initial_retry_secs"
                    .to_owned(),
            ));
        }
        if self.limits.ixfr_disabled_cooldown_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.ixfr_disabled_cooldown_secs must be at least 1".to_owned(),
            ));
        }

        let tsig_key_names = self.validate_tsig_keys()?;

        for zone in &self.zones {
            zone.validate()?;
            if let Some(tsig_key) = &zone.tsig_key {
                let key_name = DomainName::from_absolute_str(tsig_key).map_err(|_| {
                    ConfigError::Invalid(format!(
                        "zone {} references TSIG key {tsig_key}; TSIG key names must be absolute DNS names",
                        zone.name
                    ))
                })?;
                if !tsig_key_names.contains(&key_name.canonical_key()) {
                    return Err(ConfigError::Invalid(format!(
                        "zone {} references unknown TSIG key {tsig_key}",
                        zone.name
                    )));
                }
            }
        }

        Ok(())
    }

    fn validate_tsig_keys(&self) -> Result<HashSet<String>, ConfigError> {
        let mut names = HashSet::new();
        for key in &self.tsig_keys {
            let parsed_key =
                TsigKey::from_base64(&key.name, &key.algorithm, &key.secret).map_err(|error| {
                    ConfigError::Invalid(format!("invalid TSIG key {}: {error}", key.name))
                })?;
            if !names.insert(parsed_key.name.canonical_key()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate TSIG key {}",
                    key.name
                )));
            }
        }
        Ok(names)
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
pub struct QuerySettings {
    #[serde(default)]
    pub any_response: AnyResponseConfig,
}

impl QuerySettings {
    pub fn any_response_mode(&self) -> AnyResponseMode {
        match self.any_response {
            AnyResponseConfig::Minimal => AnyResponseMode::Minimal,
            AnyResponseConfig::Full => AnyResponseMode::Full,
        }
    }
}

impl Default for QuerySettings {
    fn default() -> Self {
        Self {
            any_response: AnyResponseConfig::Minimal,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AnyResponseConfig {
    #[default]
    Minimal,
    Full,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Limits {
    #[serde(default = "default_max_udp_payload")]
    pub max_udp_payload: u16,
    #[serde(default = "default_max_cname_chain")]
    pub max_cname_chain: usize,
    #[serde(default = "default_tcp_idle_timeout_secs")]
    pub tcp_idle_timeout_secs: u64,
    #[serde(default = "default_tcp_read_timeout_secs")]
    pub tcp_read_timeout_secs: u64,
    #[serde(default = "default_tcp_write_timeout_secs")]
    pub tcp_write_timeout_secs: u64,
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,
    #[serde(default = "default_graceful_shutdown_secs")]
    pub graceful_shutdown_secs: u64,
    #[serde(default = "default_edns_padding_block_size")]
    pub edns_padding_block_size: u16,
    #[serde(default = "default_axfr_timeout_secs")]
    pub axfr_timeout_secs: u64,
    #[serde(default = "default_ixfr_timeout_secs")]
    pub ixfr_timeout_secs: u64,
    #[serde(default = "default_ixfr_disabled_cooldown_secs")]
    pub ixfr_disabled_cooldown_secs: u64,
    #[serde(default = "default_notify_dedup_secs")]
    pub notify_dedup_secs: u64,
    #[serde(default = "default_max_concurrent_transfers")]
    pub max_concurrent_transfers: usize,
    #[serde(default = "default_zsm_min_interval_secs")]
    pub zsm_min_interval_secs: u64,
    #[serde(default = "default_zsm_initial_retry_secs")]
    pub zsm_initial_retry_secs: u64,
    #[serde(default = "default_zsm_initial_retry_max_secs")]
    pub zsm_initial_retry_max_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_udp_payload: default_max_udp_payload(),
            max_cname_chain: default_max_cname_chain(),
            tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
            tcp_read_timeout_secs: default_tcp_read_timeout_secs(),
            tcp_write_timeout_secs: default_tcp_write_timeout_secs(),
            max_tcp_connections: default_max_tcp_connections(),
            graceful_shutdown_secs: default_graceful_shutdown_secs(),
            edns_padding_block_size: default_edns_padding_block_size(),
            axfr_timeout_secs: default_axfr_timeout_secs(),
            ixfr_timeout_secs: default_ixfr_timeout_secs(),
            ixfr_disabled_cooldown_secs: default_ixfr_disabled_cooldown_secs(),
            notify_dedup_secs: default_notify_dedup_secs(),
            max_concurrent_transfers: default_max_concurrent_transfers(),
            zsm_min_interval_secs: default_zsm_min_interval_secs(),
            zsm_initial_retry_secs: default_zsm_initial_retry_secs(),
            zsm_initial_retry_max_secs: default_zsm_initial_retry_max_secs(),
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

        DomainName::from_absolute_str(&self.name).map_err(|_| {
            ConfigError::Invalid(format!("zone {} is not a valid DNS name", self.name))
        })?;

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

#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct TsigKeyConfig {
    pub name: String,
    pub algorithm: String,
    pub secret: String,
}

impl fmt::Debug for TsigKeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TsigKeyConfig")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"<redacted>")
            .finish()
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn default_dns_class() -> String {
    "IN".to_owned()
}

fn default_max_udp_payload() -> u16 {
    1232
}

fn default_max_cname_chain() -> usize {
    8
}

fn default_tcp_idle_timeout_secs() -> u64 {
    30
}

fn default_tcp_read_timeout_secs() -> u64 {
    30
}

fn default_tcp_write_timeout_secs() -> u64 {
    30
}

fn default_max_tcp_connections() -> usize {
    1024
}

fn default_graceful_shutdown_secs() -> u64 {
    30
}

fn default_edns_padding_block_size() -> u16 {
    0
}

fn default_axfr_timeout_secs() -> u64 {
    300
}

fn default_ixfr_timeout_secs() -> u64 {
    60
}

fn default_ixfr_disabled_cooldown_secs() -> u64 {
    3600
}

fn default_notify_dedup_secs() -> u64 {
    1
}

fn default_max_concurrent_transfers() -> usize {
    4
}

fn default_zsm_min_interval_secs() -> u64 {
    60
}

fn default_zsm_initial_retry_secs() -> u64 {
    60
}

fn default_zsm_initial_retry_max_secs() -> u64 {
    3600
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
        assert_eq!(config.query.any_response, AnyResponseConfig::Minimal);
        assert_eq!(config.query.any_response_mode(), AnyResponseMode::Minimal);
        assert_eq!(config.zones[0].class, "IN");
        assert_eq!(config.limits.max_udp_payload, 1232);
        assert_eq!(config.limits.max_cname_chain, 8);
        assert_eq!(config.limits.tcp_idle_timeout_secs, 30);
        assert_eq!(config.limits.tcp_read_timeout_secs, 30);
        assert_eq!(config.limits.tcp_write_timeout_secs, 30);
        assert_eq!(config.limits.max_tcp_connections, 1024);
        assert_eq!(config.limits.graceful_shutdown_secs, 30);
        assert_eq!(config.limits.edns_padding_block_size, 0);
        assert_eq!(config.limits.ixfr_timeout_secs, 60);
        assert_eq!(config.limits.ixfr_disabled_cooldown_secs, 3600);
        assert_eq!(config.limits.max_concurrent_transfers, 4);
        assert_eq!(config.limits.zsm_min_interval_secs, 60);
        assert_eq!(config.limits.zsm_initial_retry_secs, 60);
        assert_eq!(config.limits.zsm_initial_retry_max_secs, 3600);
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

    #[test]
    fn rejects_too_small_udp_payload_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_udp_payload = 511

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("small UDP limit must fail");

        assert!(error.to_string().contains("max_udp_payload"));
    }

    #[test]
    fn parses_full_any_response_policy() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [query]
                any_response = "full"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.query.any_response, AnyResponseConfig::Full);
        assert_eq!(config.query.any_response_mode(), AnyResponseMode::Full);
    }

    #[test]
    fn rejects_invalid_any_response_policy() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [query]
                any_response = "hinfo"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("invalid any-response policy must fail");

        assert!(error.to_string().contains("any_response"));
    }

    #[test]
    fn parses_custom_cname_chain_limit() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_cname_chain = 4

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.max_cname_chain, 4);
    }

    #[test]
    fn rejects_zero_cname_chain_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_cname_chain = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero CNAME chain limit must fail");

        assert!(error.to_string().contains("max_cname_chain"));
    }

    #[test]
    fn parses_custom_tcp_idle_timeout() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                tcp_idle_timeout_secs = 5
                tcp_read_timeout_secs = 6
                tcp_write_timeout_secs = 7

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.tcp_idle_timeout_secs, 5);
        assert_eq!(config.limits.tcp_read_timeout_secs, 6);
        assert_eq!(config.limits.tcp_write_timeout_secs, 7);
    }

    #[test]
    fn rejects_zero_tcp_idle_timeout() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                tcp_idle_timeout_secs = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero TCP idle timeout must fail");

        assert!(error.to_string().contains("tcp_idle_timeout_secs"));
    }

    #[test]
    fn rejects_zero_tcp_read_or_write_timeout() {
        for (key, expected) in [
            ("tcp_read_timeout_secs", "tcp_read_timeout_secs"),
            ("tcp_write_timeout_secs", "tcp_write_timeout_secs"),
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_tcp = ["127.0.0.1:5300"]

                    [limits]
                    {key} = 0

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("zero TCP read/write timeout must fail");

            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn parses_custom_tcp_connection_limit() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                max_tcp_connections = 16

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.max_tcp_connections, 16);
    }

    #[test]
    fn rejects_zero_tcp_connection_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                max_tcp_connections = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero TCP connection limit must fail");

        assert!(error.to_string().contains("max_tcp_connections"));
    }

    #[test]
    fn parses_custom_graceful_shutdown_limit() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                graceful_shutdown_secs = 10

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.graceful_shutdown_secs, 10);
    }

    #[test]
    fn rejects_zero_graceful_shutdown_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                graceful_shutdown_secs = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero graceful shutdown limit must fail");

        assert!(error.to_string().contains("graceful_shutdown_secs"));
    }

    #[test]
    fn parses_custom_edns_padding_block_size() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                edns_padding_block_size = 128

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.edns_padding_block_size, 128);
    }

    #[test]
    fn rejects_one_octet_edns_padding_block_size() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                edns_padding_block_size = 1

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("one-octet padding block is not useful");

        assert!(error.to_string().contains("edns_padding_block_size"));
    }

    #[test]
    fn parses_custom_zsm_intervals() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                zsm_min_interval_secs = 120
                zsm_initial_retry_secs = 30
                zsm_initial_retry_max_secs = 900

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.zsm_min_interval_secs, 120);
        assert_eq!(config.limits.zsm_initial_retry_secs, 30);
        assert_eq!(config.limits.zsm_initial_retry_max_secs, 900);
    }

    #[test]
    fn parses_custom_ixfr_disabled_cooldown() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                ixfr_disabled_cooldown_secs = 300

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.ixfr_disabled_cooldown_secs, 300);
    }

    #[test]
    fn rejects_zero_ixfr_disabled_cooldown() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                ixfr_disabled_cooldown_secs = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero IXFR disabled cooldown must fail");

        assert!(error.to_string().contains("ixfr_disabled_cooldown_secs"));
    }

    #[test]
    fn parses_custom_transfer_concurrency_limit() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_concurrent_transfers = 2

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.max_concurrent_transfers, 2);
    }

    #[test]
    fn rejects_zero_transfer_concurrency_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_concurrent_transfers = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero transfer concurrency limit must fail");

        assert!(error.to_string().contains("max_concurrent_transfers"));
    }

    #[test]
    fn parses_hmac_sha256_tsig_key_and_zone_reference() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret = "c2VjcmV0LWtleQ=="

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        )
        .expect("valid TSIG config");

        assert_eq!(config.tsig_keys.len(), 1);
        assert_eq!(config.zones[0].tsig_key.as_deref(), Some("transfer-key."));
        assert!(!format!("{config:?}").contains("c2VjcmV0LWtleQ=="));
    }

    #[test]
    fn parses_hmac_sha1_tsig_key_and_zone_reference() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha1"
                secret = "c2VjcmV0LWtleQ=="

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        )
        .expect("valid HMAC-SHA1 TSIG config");

        assert_eq!(config.tsig_keys[0].algorithm, "hmac-sha1");
        assert_eq!(config.zones[0].tsig_key.as_deref(), Some("transfer-key."));
    }

    #[test]
    fn parses_hmac_sha384_and_sha512_tsig_keys() {
        for algorithm in ["hmac-sha384", "hmac-sha512"] {
            let config = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [[tsig_keys]]
                    name = "transfer-key."
                    algorithm = "{algorithm}"
                    secret = "c2VjcmV0LWtleQ=="

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                    tsig_key = "transfer-key."
                "#
            ))
            .expect("valid HMAC-SHA TSIG config");

            assert_eq!(config.tsig_keys[0].algorithm, algorithm);
            assert_eq!(config.zones[0].tsig_key.as_deref(), Some("transfer-key."));
        }
    }

    #[test]
    fn rejects_invalid_tsig_secret_without_leaking_it() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret = "not base64"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        )
        .expect_err("invalid TSIG secret must fail");
        let message = error.to_string();

        assert!(message.contains("invalid TSIG key transfer-key."));
        assert!(!message.contains("not base64"));
    }

    #[test]
    fn rejects_unknown_zone_tsig_key_reference() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "missing-key."
            "#,
        )
        .expect_err("unknown TSIG key reference must fail");

        assert!(error.to_string().contains("unknown TSIG key"));
    }

    #[test]
    fn rejects_hmac_md5_tsig_key_algorithm() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-md5.sig-alg.reg.int."
                secret = "c2VjcmV0LWtleQ=="

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        )
        .expect_err("HMAC-MD5 must be rejected");

        assert!(error.to_string().contains("hmac-md5.sig-alg.reg.int"));
    }

    #[test]
    fn rejects_zero_zsm_intervals() {
        for (key, expected) in [
            ("zsm_min_interval_secs", "zsm_min_interval_secs"),
            ("zsm_initial_retry_secs", "zsm_initial_retry_secs"),
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [limits]
                    {key} = 0

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("zero ZSM interval must fail");

            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn rejects_initial_retry_max_below_initial_retry() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                zsm_initial_retry_secs = 60
                zsm_initial_retry_max_secs = 59

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("retry max below initial retry must fail");

        assert!(error.to_string().contains("zsm_initial_retry_max_secs"));
    }
}
