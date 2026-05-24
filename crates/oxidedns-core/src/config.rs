use std::{
    collections::HashSet,
    fmt, fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};

use serde::{Deserialize, Serialize};
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

    #[error("failed to serialize TOML configuration: {0}")]
    Serialize(#[from] toml::ser::Error),

    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServerConfig {
    pub server: ServerSettings,
    #[serde(default)]
    pub query: QuerySettings,
    #[serde(default)]
    pub rrl: RrlConfig,
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

    pub fn to_redacted_toml(&self) -> Result<String, ConfigError> {
        let mut redacted = self.clone();
        for key in &mut redacted.tsig_keys {
            key.secret = "<redacted>".to_owned();
        }
        Ok(toml::to_string_pretty(&redacted)?)
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
        self.rrl.validate()?;

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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServerSettings {
    #[serde(default = "default_dns_listeners")]
    pub listen_udp: Vec<SocketAddr>,
    #[serde(default = "default_dns_listeners")]
    pub listen_tcp: Vec<SocketAddr>,
    pub health: Option<SocketAddr>,
    #[serde(default)]
    pub nsid: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub log_format: LogFormatConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AnyResponseConfig {
    #[default]
    Minimal,
    Full,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormatConfig {
    #[default]
    Json,
    Plain,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RrlConfig {
    #[serde(default = "default_rrl_enabled")]
    pub enabled: bool,
    #[serde(default = "default_rrl_ipv4_prefix_len")]
    pub ipv4_prefix_len: u8,
    #[serde(default = "default_rrl_ipv6_prefix_len")]
    pub ipv6_prefix_len: u8,
    #[serde(default = "default_rrl_positive_per_second")]
    pub positive_per_second: u32,
    #[serde(default = "default_rrl_nxdomain_per_second")]
    pub nxdomain_per_second: u32,
    #[serde(default = "default_rrl_nodata_per_second")]
    pub nodata_per_second: u32,
    #[serde(default = "default_rrl_referral_per_second")]
    pub referral_per_second: u32,
    #[serde(default = "default_rrl_error_per_second")]
    pub error_per_second: u32,
    #[serde(default = "default_rrl_slip")]
    pub slip: u32,
    #[serde(default = "default_rrl_max_keys")]
    pub max_keys: usize,
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for RrlConfig {
    fn default() -> Self {
        Self {
            enabled: default_rrl_enabled(),
            ipv4_prefix_len: default_rrl_ipv4_prefix_len(),
            ipv6_prefix_len: default_rrl_ipv6_prefix_len(),
            positive_per_second: default_rrl_positive_per_second(),
            nxdomain_per_second: default_rrl_nxdomain_per_second(),
            nodata_per_second: default_rrl_nodata_per_second(),
            referral_per_second: default_rrl_referral_per_second(),
            error_per_second: default_rrl_error_per_second(),
            slip: default_rrl_slip(),
            max_keys: default_rrl_max_keys(),
            allowlist: Vec::new(),
        }
    }
}

impl RrlConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.ipv4_prefix_len > 32 {
            return Err(ConfigError::Invalid(
                "rrl.ipv4_prefix_len must be at most 32".to_owned(),
            ));
        }
        if self.ipv6_prefix_len > 128 {
            return Err(ConfigError::Invalid(
                "rrl.ipv6_prefix_len must be at most 128".to_owned(),
            ));
        }
        if self.max_keys == 0 {
            return Err(ConfigError::Invalid(
                "rrl.max_keys must be at least 1".to_owned(),
            ));
        }
        for prefix in &self.allowlist {
            validate_ip_prefix(prefix).map_err(|error| {
                ConfigError::Invalid(format!("invalid rrl.allowlist entry {prefix:?}: {error}"))
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZoneConfig {
    pub name: String,
    #[serde(default = "default_dns_class")]
    pub class: String,
    #[serde(default)]
    pub primaries: Vec<SocketAddr>,
    #[serde(default)]
    pub transfer_primaries: Vec<TransferPrimaryConfig>,
    #[serde(default)]
    pub notify_sources: Vec<std::net::IpAddr>,
    pub tsig_key: Option<String>,
}

impl ZoneConfig {
    pub fn transfer_targets(&self) -> Vec<TransferPrimaryConfig> {
        if self.transfer_primaries.is_empty() {
            self.primaries
                .iter()
                .copied()
                .map(TransferPrimaryConfig::tcp)
                .collect()
        } else {
            self.transfer_primaries.clone()
        }
    }

    pub fn transfer_target_addrs(&self) -> Vec<SocketAddr> {
        self.transfer_targets()
            .into_iter()
            .map(|target| target.addr)
            .collect()
    }

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

        if self.primaries.is_empty() && self.transfer_primaries.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "zone {} requires at least one primary or transfer primary",
                self.name
            )));
        }

        if !self.primaries.is_empty() && !self.transfer_primaries.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "zone {} must not mix legacy primaries and transfer_primaries",
                self.name
            )));
        }

        for primary in &self.transfer_primaries {
            primary.validate(&self.name)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TransferPrimaryConfig {
    pub addr: SocketAddr,
    #[serde(default)]
    pub transport: TransferTransportConfig,
    pub server_name: Option<String>,
    #[serde(default)]
    pub trust_anchors: Vec<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

impl TransferPrimaryConfig {
    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            addr,
            transport: TransferTransportConfig::Tcp,
            server_name: None,
            trust_anchors: Vec::new(),
            client_cert: None,
            client_key: None,
        }
    }

    fn validate(&self, zone_name: &str) -> Result<(), ConfigError> {
        if self.addr.port() == 0 {
            return Err(ConfigError::Invalid(format!(
                "zone {zone_name} transfer primary {} must use a non-zero port",
                self.addr
            )));
        }

        match self.transport {
            TransferTransportConfig::Tcp => self.validate_tcp(zone_name),
            TransferTransportConfig::Xot => self.validate_xot(zone_name),
        }
    }

    fn validate_tcp(&self, zone_name: &str) -> Result<(), ConfigError> {
        if self.server_name.is_some()
            || !self.trust_anchors.is_empty()
            || self.client_cert.is_some()
            || self.client_key.is_some()
        {
            return Err(ConfigError::Invalid(format!(
                "zone {zone_name} TCP transfer primary {} must not set XoT TLS fields",
                self.addr
            )));
        }
        Ok(())
    }

    fn validate_xot(&self, zone_name: &str) -> Result<(), ConfigError> {
        let Some(server_name) = self.server_name.as_deref() else {
            return Err(ConfigError::Invalid(format!(
                "zone {zone_name} XoT transfer primary {} requires server_name",
                self.addr
            )));
        };
        validate_xot_server_name(server_name).map_err(|error| {
            ConfigError::Invalid(format!(
                "zone {zone_name} XoT transfer primary {} has invalid server_name {server_name:?}: {error}",
                self.addr
            ))
        })?;
        if self.trust_anchors.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "zone {zone_name} XoT transfer primary {} requires at least one trust_anchors entry",
                self.addr
            )));
        }
        for trust_anchor in &self.trust_anchors {
            if trust_anchor.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "zone {zone_name} XoT transfer primary {} has an empty trust_anchors entry",
                    self.addr
                )));
            }
        }
        match (&self.client_cert, &self.client_key) {
            (Some(cert), Some(key)) if cert.trim().is_empty() || key.trim().is_empty() => {
                Err(ConfigError::Invalid(format!(
                    "zone {zone_name} XoT transfer primary {} has an empty client certificate or key path",
                    self.addr
                )))
            }
            (Some(_), Some(_)) | (None, None) => Ok(()),
            _ => Err(ConfigError::Invalid(format!(
                "zone {zone_name} XoT transfer primary {} requires client_cert and client_key to be configured together",
                self.addr
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TransferTransportConfig {
    #[default]
    Tcp,
    Xot,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
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

fn default_dns_listeners() -> Vec<SocketAddr> {
    vec![
        SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)),
        SocketAddr::from((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53)),
    ]
}

fn default_rrl_enabled() -> bool {
    true
}

fn default_rrl_ipv4_prefix_len() -> u8 {
    24
}

fn default_rrl_ipv6_prefix_len() -> u8 {
    56
}

fn default_rrl_positive_per_second() -> u32 {
    20
}

fn default_rrl_nxdomain_per_second() -> u32 {
    5
}

fn default_rrl_nodata_per_second() -> u32 {
    10
}

fn default_rrl_referral_per_second() -> u32 {
    10
}

fn default_rrl_error_per_second() -> u32 {
    5
}

fn default_rrl_slip() -> u32 {
    2
}

fn default_rrl_max_keys() -> usize {
    100_000
}

fn validate_ip_prefix(prefix: &str) -> Result<(), &'static str> {
    let Some((addr, len)) = prefix.split_once('/') else {
        prefix
            .parse::<IpAddr>()
            .map(|_| ())
            .map_err(|_| "expected IP address or CIDR prefix")?;
        return Ok(());
    };
    let addr = addr
        .parse::<IpAddr>()
        .map_err(|_| "expected IP address before '/'")?;
    let len = len
        .parse::<u8>()
        .map_err(|_| "expected numeric prefix length after '/'")?;
    match addr {
        IpAddr::V4(_) if len <= 32 => Ok(()),
        IpAddr::V6(_) if len <= 128 => Ok(()),
        IpAddr::V4(_) => Err("IPv4 prefix length must be at most 32"),
        IpAddr::V6(_) => Err("IPv6 prefix length must be at most 128"),
    }
}

fn validate_xot_server_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 253 {
        return Err("expected non-empty DNS name of at most 253 octets");
    }
    if name.ends_with('.') {
        return Err("expected DNS name without a trailing root label for TLS SNI");
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("expected DNS labels between 1 and 63 octets");
        }
        let bytes = label.as_bytes();
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return Err("expected DNS labels not to start or end with '-'");
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err("expected only ASCII letters, digits, '-' and '.'");
        }
    }
    Ok(())
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
        assert_eq!(
            config.server.listen_tcp,
            vec![
                SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)),
                SocketAddr::from((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53)),
            ]
        );
        assert_eq!(config.server.log_level, "info");
        assert_eq!(config.server.log_format, LogFormatConfig::Json);
        assert_eq!(config.server.nsid, "");
        assert!(config.rrl.enabled);
        assert_eq!(config.rrl.ipv4_prefix_len, 24);
        assert_eq!(config.rrl.ipv6_prefix_len, 56);
        assert_eq!(config.rrl.positive_per_second, 20);
        assert_eq!(config.rrl.nxdomain_per_second, 5);
        assert_eq!(config.rrl.nodata_per_second, 10);
        assert_eq!(config.rrl.referral_per_second, 10);
        assert_eq!(config.rrl.error_per_second, 5);
        assert_eq!(config.rrl.slip, 2);
        assert_eq!(config.rrl.max_keys, 100_000);
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
        assert_eq!(
            config.zones[0].transfer_targets(),
            vec![TransferPrimaryConfig::tcp(SocketAddr::from((
                Ipv4Addr::new(192, 0, 2, 53),
                53
            )))]
        );
    }

    #[test]
    fn parses_explicit_tcp_transfer_primary_config() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:53"
                transport = "tcp"
            "#,
        )
        .expect("valid config");

        assert!(config.zones[0].primaries.is_empty());
        assert_eq!(config.zones[0].transfer_primaries.len(), 1);
        assert_eq!(
            config.zones[0].transfer_primaries[0].transport,
            TransferTransportConfig::Tcp
        );
        assert_eq!(
            config.zones[0].transfer_targets(),
            config.zones[0].transfer_primaries
        );
    }

    #[test]
    fn parses_xot_transfer_primary_config() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
                client_cert = "/etc/oxidedns/client.pem"
                client_key = "/etc/oxidedns/client.key"
            "#,
        )
        .expect("valid config");

        let target = &config.zones[0].transfer_primaries[0];
        assert_eq!(
            target.addr,
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 853))
        );
        assert_eq!(target.transport, TransferTransportConfig::Xot);
        assert_eq!(target.server_name.as_deref(), Some("primary.example.test"));
        assert_eq!(target.trust_anchors, vec!["/etc/oxidedns/ca.pem"]);
        assert_eq!(target.client_cert.as_deref(), Some("/etc/oxidedns/client.pem"));
        assert_eq!(target.client_key.as_deref(), Some("/etc/oxidedns/client.key"));
    }

    #[test]
    fn rejects_zone_without_transfer_primary() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
            "#,
        )
        .expect_err("missing transfer primary must fail");

        assert!(error.to_string().contains("requires at least one primary"));
    }

    #[test]
    fn rejects_mixed_legacy_and_explicit_transfer_primaries() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]

                [[zones.transfer_primaries]]
                addr = "192.0.2.54:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
            "#,
        )
        .expect_err("mixed primary forms must fail");

        assert!(error.to_string().contains("must not mix legacy primaries"));
    }

    #[test]
    fn rejects_xot_transfer_primary_without_server_name() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
            "#,
        )
        .expect_err("xot server name is required");

        assert!(error.to_string().contains("requires server_name"));
    }

    #[test]
    fn rejects_xot_transfer_primary_without_trust_anchor() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
            "#,
        )
        .expect_err("xot trust anchor is required");

        assert!(
            error
                .to_string()
                .contains("requires at least one trust_anchors")
        );
    }

    #[test]
    fn rejects_xot_transfer_primary_with_unpaired_client_key_material() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
                client_cert = "/etc/oxidedns/client.pem"
            "#,
        )
        .expect_err("xot client certificate and key must be paired");

        assert!(error.to_string().contains("configured together"));
    }

    #[test]
    fn rejects_tcp_transfer_primary_with_xot_fields() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:53"
                transport = "tcp"
                server_name = "primary.example.test"
            "#,
        )
        .expect_err("tcp target must not accept tls fields");

        assert!(error.to_string().contains("must not set XoT TLS fields"));
    }

    #[test]
    fn rejects_xot_server_name_with_trailing_root_label() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test."
                trust_anchors = ["/etc/oxidedns/ca.pem"]
            "#,
        )
        .expect_err("xot server name should use SNI form");

        assert!(error.to_string().contains("without a trailing root label"));
    }

    #[test]
    fn defaults_dns_listeners_when_omitted() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        let expected = vec![
            SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)),
            SocketAddr::from((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53)),
        ];
        assert_eq!(config.server.listen_udp, expected);
        assert_eq!(config.server.listen_tcp, expected);
    }

    #[test]
    fn preserves_explicit_high_port_listeners() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = ["127.0.0.1:5301", "[::1]:5301"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(
            config.server.listen_udp,
            vec![SocketAddr::from(([127, 0, 0, 1], 5300))]
        );
        assert_eq!(
            config.server.listen_tcp,
            vec![
                SocketAddr::from(([127, 0, 0, 1], 5301)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 5301)),
            ]
        );
    }

    #[test]
    fn rejects_explicitly_empty_dns_listeners() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = []
                listen_tcp = []

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("explicitly empty listeners must fail");

        assert!(
            error
                .to_string()
                .contains("at least one UDP or TCP listener")
        );
    }

    #[test]
    fn parses_rrl_configuration() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [rrl]
                enabled = false
                ipv4_prefix_len = 28
                ipv6_prefix_len = 64
                positive_per_second = 3
                nxdomain_per_second = 4
                nodata_per_second = 5
                referral_per_second = 6
                error_per_second = 7
                slip = 1
                max_keys = 9
                allowlist = ["127.0.0.1", "192.0.2.0/24", "2001:db8::/48"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert!(!config.rrl.enabled);
        assert_eq!(config.rrl.ipv4_prefix_len, 28);
        assert_eq!(config.rrl.ipv6_prefix_len, 64);
        assert_eq!(config.rrl.positive_per_second, 3);
        assert_eq!(config.rrl.nxdomain_per_second, 4);
        assert_eq!(config.rrl.nodata_per_second, 5);
        assert_eq!(config.rrl.referral_per_second, 6);
        assert_eq!(config.rrl.error_per_second, 7);
        assert_eq!(config.rrl.slip, 1);
        assert_eq!(config.rrl.max_keys, 9);
        assert_eq!(config.rrl.allowlist.len(), 3);
    }

    #[test]
    fn rejects_invalid_rrl_configuration() {
        for (key, value, expected) in [
            ("ipv4_prefix_len", "33", "ipv4_prefix_len"),
            ("ipv6_prefix_len", "129", "ipv6_prefix_len"),
            ("max_keys", "0", "max_keys"),
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [rrl]
                    {key} = {value}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("invalid RRL setting must fail");

            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn rejects_invalid_rrl_allowlist_prefix() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [rrl]
                allowlist = ["192.0.2.0/33"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("invalid allowlist prefix must fail");

        assert!(error.to_string().contains("rrl.allowlist"));
    }

    #[test]
    fn parses_plain_log_format() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                log_level = "debug"
                log_format = "plain"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.server.log_level, "debug");
        assert_eq!(config.server.log_format, LogFormatConfig::Plain);
    }

    #[test]
    fn parses_configured_nsid() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                nsid = "dns-bud-1"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.server.nsid, "dns-bud-1");
    }

    #[test]
    fn rejects_invalid_log_format() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                log_format = "syslog"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("invalid log format must fail");

        assert!(error.to_string().contains("log_format"));
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
    fn redacted_toml_dump_preserves_shape_without_secret_material() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                nsid = "dns-bud-1"

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

        let dumped = config.to_redacted_toml().expect("redacted TOML dump");

        assert!(dumped.contains("[[tsig_keys]]"));
        assert!(dumped.contains("name = \"transfer-key.\""));
        assert!(dumped.contains("secret = \"<redacted>\""));
        assert!(dumped.contains("nsid = \"dns-bud-1\""));
        assert!(!dumped.contains("c2VjcmV0LWtleQ=="));
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
