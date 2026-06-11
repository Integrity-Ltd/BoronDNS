use std::{
    collections::HashSet,
    fmt, fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    dns::{AnyResponseMode, DomainName, ExtendedDnsErrorsMode},
    tsig::{DEFAULT_TSIG_FUDGE_SECS, TsigKey},
};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration from {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },

    #[error("failed to read secret file {path}: {source}")]
    ReadSecretFile {
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
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub server: ServerSettings,
    #[serde(default)]
    pub interfaces: InterfacesConfig,
    #[serde(default)]
    pub process: ProcessConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub control_plane: ControlPlaneConfig,
    #[serde(default)]
    pub query: QuerySettings,
    #[serde(default)]
    pub edns: EdnsConfig,
    #[serde(default)]
    pub chaos: ChaosConfig,
    #[serde(default)]
    pub dnssec: DnssecConfig,
    #[serde(default)]
    pub cookie: CookieConfig,
    #[serde(default)]
    pub rrl: RrlConfig,
    #[serde(default)]
    pub tsig: TsigConfig,
    #[serde(default)]
    pub transfer: TransferConfig,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub xdp: XdpConfig,
    #[serde(default)]
    pub zones: Vec<ZoneConfig>,
    #[serde(default)]
    pub catalog_zones: Vec<CatalogZoneConfig>,
    #[serde(default)]
    pub tsig_keys: Vec<TsigKeyConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    pub code: &'static str,
    pub parameter: String,
    pub message: String,
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
        for zone in &mut redacted.zones {
            for primary in &mut zone.transfer_primaries {
                if primary.client_key_pem.is_some() {
                    primary.client_key_pem = Some("<redacted>".to_owned());
                }
            }
        }
        for catalog_zone in &mut redacted.catalog_zones {
            for primary in catalog_zone
                .transfer_primaries
                .iter_mut()
                .chain(catalog_zone.catalog_transfer_primaries.iter_mut())
                .chain(catalog_zone.member_transfer_primaries.iter_mut())
            {
                if primary.client_key_pem.is_some() {
                    primary.client_key_pem = Some("<redacted>".to_owned());
                }
            }
        }
        for key in &mut redacted.tsig_keys {
            if key.secret.is_some() {
                key.secret = Some("<redacted>".to_owned());
            }
        }
        if redacted.control_plane.telemetry.bearer_token.is_some() {
            redacted.control_plane.telemetry.bearer_token = Some("<redacted>".to_owned());
        }
        if redacted.control_plane.operations.bearer_token.is_some() {
            redacted.control_plane.operations.bearer_token = Some("<redacted>".to_owned());
        }
        if redacted.cookie.server_secret.is_some() {
            redacted.cookie.server_secret = Some("<redacted>".to_owned());
        }
        if redacted.cookie.previous_server_secret.is_some() {
            redacted.cookie.previous_server_secret = Some("<redacted>".to_owned());
        }
        Ok(toml::to_string_pretty(&redacted)?)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.interfaces.validate(&self.server)?;
        self.process.validate()?;
        if self.dns_udp_listeners().is_empty() && self.dns_tcp_listeners().is_empty() {
            return Err(ConfigError::Invalid(
                "at least one UDP or TCP listener is required".to_owned(),
            ));
        }
        self.logging.validate()?;
        self.metrics.validate()?;
        self.observability.validate()?;
        self.control_plane.validate()?;
        self.chaos.validate()?;
        self.dnssec.validate()?;

        if self.zones.is_empty() && self.catalog_zones.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one [[zones]] or [[catalog_zones]] entry is required; OxideDNS is a secondary-only authoritative server, so configure a primary DNS server to transfer from before starting service".to_owned(),
            ));
        }

        if self.limits.max_udp_payload < 512 {
            return Err(ConfigError::Invalid(
                "limits.max_udp_payload must be at least 512".to_owned(),
            ));
        }
        if self.limits.udp_batch_size == 0 {
            return Err(ConfigError::Invalid(
                "limits.udp_batch_size must be at least 1".to_owned(),
            ));
        }
        self.xdp.validate(self.limits.udp_backend)?;
        self.limits.validate_udp_worker_settings()?;
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
        if self.limits.tcp_connect_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.tcp_connect_timeout_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.max_tcp_connections == 0 {
            return Err(ConfigError::Invalid(
                "limits.max_tcp_connections must be at least 1".to_owned(),
            ));
        }
        if self.limits.max_tcp_connections_per_source == Some(0) {
            return Err(ConfigError::Invalid(
                "limits.max_tcp_connections_per_source must be at least 1 when configured"
                    .to_owned(),
            ));
        }
        if self.limits.max_tcp_inflight_queries_per_connection == 0 {
            return Err(ConfigError::Invalid(
                "limits.max_tcp_inflight_queries_per_connection must be at least 1".to_owned(),
            ));
        }
        if self.limits.tcp_inflight_limit_timeout_secs == Some(0) {
            return Err(ConfigError::Invalid(
                "limits.tcp_inflight_limit_timeout_secs must be at least 1 when configured"
                    .to_owned(),
            ));
        }
        if self.limits.graceful_shutdown_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.graceful_shutdown_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.notify_dedup_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.notify_dedup_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.notify_log_rate_window_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.notify_log_rate_window_secs must be at least 1".to_owned(),
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
        if self.limits.zsm_max_interval_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.zsm_max_interval_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.zsm_max_interval_secs < self.limits.zsm_min_interval_secs {
            return Err(ConfigError::Invalid(
                "limits.zsm_max_interval_secs must be at least limits.zsm_min_interval_secs"
                    .to_owned(),
            ));
        }
        if self.limits.zsm_initial_retry_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.zsm_initial_retry_secs must be at least 1".to_owned(),
            ));
        }
        if self.limits.zsm_loading_warning_threshold_secs == 0 {
            return Err(ConfigError::Invalid(
                "limits.zsm_loading_warning_threshold_secs must be at least 1".to_owned(),
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
        if self.limits.max_transfer_ingest_bytes == 0 {
            return Err(ConfigError::Invalid(
                "limits.max_transfer_ingest_bytes must be at least 1".to_owned(),
            ));
        }
        self.cookie.validate()?;
        self.health.validate()?;
        self.rrl.validate()?;
        self.tsig.validate()?;
        self.transfer.validate()?;

        let tsig_key_names = self.validate_tsig_keys()?;

        for zone in &self.zones {
            zone.validate()?;
            if self.transfer.require_tsig && zone.tsig_key.is_none() {
                return Err(ConfigError::Invalid(format!(
                    "zone {} requires tsig_key because transfer.require_tsig is true",
                    zone.name
                )));
            }
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
        for catalog_zone in &self.catalog_zones {
            catalog_zone.validate()?;
            if catalog_zone.catalog_tsig_key_name().is_none() {
                return Err(ConfigError::Invalid(format!(
                    "catalog zone {} requires tsig_key because catalog-zone transfers must be TSIG-authenticated",
                    catalog_zone.name
                )));
            }
            for (field, tsig_key) in catalog_zone.tsig_key_references() {
                let key_name = DomainName::from_absolute_str(tsig_key).map_err(|_| {
                    ConfigError::Invalid(format!(
                        "catalog zone {} references {field} {tsig_key}; TSIG key names must be absolute DNS names",
                        catalog_zone.name
                    ))
                })?;
                if !tsig_key_names.contains(&key_name.canonical_key()) {
                    return Err(ConfigError::Invalid(format!(
                        "catalog zone {} references unknown {field} {tsig_key}",
                        catalog_zone.name
                    )));
                }
            }
        }
        self.validate_transfer_sources_cover_targets()?;

        Ok(())
    }

    pub fn udp_listeners(&self) -> Vec<SocketAddr> {
        self.dns_udp_listeners()
    }

    pub fn tcp_listeners(&self) -> Vec<SocketAddr> {
        self.dns_tcp_listeners()
    }

    pub fn dns_udp_listeners(&self) -> Vec<SocketAddr> {
        self.interfaces
            .dns
            .as_ref()
            .map(|dns| dns.iter().map(InterfaceEndpoint::addr).collect())
            .unwrap_or_else(|| self.server.listen_udp.clone())
    }

    pub fn dns_tcp_listeners(&self) -> Vec<SocketAddr> {
        self.interfaces
            .dns
            .as_ref()
            .map(|dns| dns.iter().map(InterfaceEndpoint::addr).collect())
            .unwrap_or_else(|| self.server.listen_tcp.clone())
    }

    pub fn health_listeners(&self) -> Vec<SocketAddr> {
        if let (Some(bind_address), Some(bind_port)) =
            (self.health.bind_address, self.health.bind_port)
        {
            vec![SocketAddr::from((bind_address, bind_port))]
        } else if let Some(addr) = self.server.health {
            vec![addr]
        } else {
            self.interfaces
                .mgmt
                .iter()
                .map(|addr| SocketAddr::from((addr.ip(), self.health.default_port)))
                .collect()
        }
    }

    pub fn transfer_source(&self) -> Option<SocketAddr> {
        self.interfaces.transfer.first().copied()
    }

    pub fn configuration_warnings(&self) -> Vec<ConfigWarning> {
        let mut warnings = Vec::new();

        if self.cookie.policy == CookiePolicyConfig::Disabled {
            warnings.push(ConfigWarning {
                code: "dns_cookies_disabled",
                parameter: "cookie.policy".to_owned(),
                message: "DNS Cookies are disabled; this is an operationally significant security regression".to_owned(),
            });
        }

        for allowlist in &self.rrl.allowlist {
            if allowlist == "0.0.0.0/0" || allowlist == "::/0" {
                warnings.push(ConfigWarning {
                    code: "rrl_global_allowlist",
                    parameter: "rrl.allowlist".to_owned(),
                    message: format!(
                        "RRL allowlist entry {allowlist} effectively disables response-rate limiting"
                    ),
                });
            }
        }

        let dns = self.interfaces.dns_addrs();
        if self.interfaces.dns.is_some()
            && !dns.is_empty()
            && !self.interfaces.mgmt.is_empty()
            && !socket_addr_sets_equal(&dns, &self.interfaces.mgmt)
            && dns.iter().any(|dns| {
                self.interfaces
                    .mgmt
                    .iter()
                    .any(|mgmt| socket_addrs_overlap(*dns, *mgmt))
            })
        {
            warnings.push(ConfigWarning {
                code: "interfaces_dns_mgmt_overlap",
                parameter: "interfaces.mgmt".to_owned(),
                message: "interfaces.dns and interfaces.mgmt overlap; set them equal only when intentional co-location is desired".to_owned(),
            });
        }

        if self.limits.tcp_idle_timeout_secs > 120 {
            warnings.push(ConfigWarning {
                code: "tcp_idle_timeout_large",
                parameter: "limits.tcp_idle_timeout_secs".to_owned(),
                message: format!(
                    "TCP idle timeout {} seconds is larger than the SRS suspicious-configuration threshold of 120 seconds",
                    self.limits.tcp_idle_timeout_secs
                ),
            });
        }

        if self.tsig.fudge_seconds > 60 {
            warnings.push(ConfigWarning {
                code: "tsig_fudge_large",
                parameter: "tsig.fudge_seconds".to_owned(),
                message: format!(
                    "TSIG fudge value {} seconds is larger than the SRS suspicious-configuration threshold of 60 seconds",
                    self.tsig.fudge_seconds
                ),
            });
        }

        if self.limits.max_transfer_ingest_bytes < 100 * 1024 * 1024 {
            warnings.push(ConfigWarning {
                code: "transfer_ingest_cap_low",
                parameter: "limits.max_transfer_ingest_bytes".to_owned(),
                message: format!(
                    "AXFR/IXFR ingestion size cap {} bytes is below the SRS suspicious-configuration threshold of 100 MiB",
                    self.limits.max_transfer_ingest_bytes
                ),
            });
        }

        if self.dnssec.nsec3_max_iterations > default_nsec3_max_iterations() {
            warnings.push(ConfigWarning {
                code: "nsec3_iterations_large",
                parameter: "dnssec.nsec3_max_iterations".to_owned(),
                message: format!(
                    "NSEC3 iteration cap {} exceeds the OxideDNS compatibility default of {}; RFC 9276 / BCP 236 recommends zero iterations for NSEC3 publishers",
                    self.dnssec.nsec3_max_iterations,
                    default_nsec3_max_iterations()
                ),
            });
        }

        if looks_like_precise_build_version(&self.chaos.version) {
            warnings.push(ConfigWarning {
                code: "chaos_version_discloses_build",
                parameter: "chaos.version".to_owned(),
                message: "chaos.version looks like a precise build version; public-facing deployments should prefer a soft-identifying value or the default REFUSED behavior".to_owned(),
            });
        }

        if !self.transfer.require_tsig {
            for zone in &self.zones {
                if zone.tsig_key.is_none() {
                    for primary in zone.transfer_target_addrs() {
                        warnings.push(ConfigWarning {
                            code: "zone_transfer_unauthenticated",
                            parameter: format!("zones.{}.primary.{}", zone.name, primary),
                            message: format!(
                                "zone {} transfer from primary {} is not TSIG-authenticated; set transfer.require_tsig = true for production fail-closed validation",
                                zone.name, primary
                            ),
                        });
                    }
                }
            }
        }

        for catalog_zone in &self.catalog_zones {
            if catalog_zone
                .transfer_targets()
                .iter()
                .any(|primary| primary.transport != TransferTransportConfig::Xot)
            {
                warnings.push(ConfigWarning {
                    code: "catalog_transfer_cleartext",
                    parameter: format!("catalog_zones.{}", catalog_zone.name),
                    message: format!(
                        "catalog zone {} has at least one non-XoT primary; TSIG authenticates catalog contents but does not encrypt them",
                        catalog_zone.name
                    ),
                });
            }
        }

        for key in &self.tsig_keys {
            if key.algorithm.eq_ignore_ascii_case("hmac-sha1") {
                warnings.push(ConfigWarning {
                    code: "tsig_hmac_sha1",
                    parameter: format!("tsig_keys.{}", key.name),
                    message: format!(
                        "TSIG key {} uses HMAC-SHA1; HMAC-SHA256 is preferred",
                        key.name
                    ),
                });
            }
        }

        warnings
    }

    fn validate_tsig_keys(&self) -> Result<HashSet<String>, ConfigError> {
        let mut names = HashSet::new();
        for key in &self.tsig_keys {
            let secret = key.secret_base64()?;
            let parsed_key =
                TsigKey::from_base64(&key.name, &key.algorithm, &secret).map_err(|error| {
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

    fn validate_transfer_sources_cover_targets(&self) -> Result<(), ConfigError> {
        if self.interfaces.transfer.is_empty() {
            return Ok(());
        }

        let has_ipv4 = self
            .interfaces
            .transfer
            .iter()
            .any(|source| source.is_ipv4());
        let has_ipv6 = self
            .interfaces
            .transfer
            .iter()
            .any(|source| source.is_ipv6());

        for (zone_name, primary) in self
            .zones
            .iter()
            .flat_map(|zone| {
                zone.transfer_targets()
                    .into_iter()
                    .map(|primary| (&zone.name, primary))
            })
            .chain(self.catalog_zones.iter().flat_map(|zone| {
                zone.all_transfer_targets()
                    .into_iter()
                    .map(|primary| (&zone.name, primary))
            }))
        {
            match primary.addr {
                SocketAddr::V4(_) if !has_ipv4 => {
                    return Err(ConfigError::Invalid(format!(
                        "interfaces.transfer is configured but zone {} primary {} has no IPv4 transfer source",
                        zone_name, primary.addr
                    )));
                }
                SocketAddr::V6(_) if !has_ipv6 => {
                    return Err(ConfigError::Invalid(format!(
                        "interfaces.transfer is configured but zone {} primary {} has no IPv6 transfer source",
                        zone_name, primary.addr
                    )));
                }
                _ => {}
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TsigConfig {
    #[serde(default = "default_tsig_fudge_seconds")]
    pub fudge_seconds: u16,
}

impl Default for TsigConfig {
    fn default() -> Self {
        Self {
            fudge_seconds: default_tsig_fudge_seconds(),
        }
    }
}

impl TsigConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.fudge_seconds == 0 {
            return Err(ConfigError::Invalid(
                "tsig.fudge_seconds must be at least 1".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct TransferConfig {
    #[serde(default)]
    pub require_tsig: bool,
}

impl TransferConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<String>,
    #[serde(default = "default_true")]
    pub disable_core_dumps: bool,
    #[serde(default = "default_true")]
    pub no_new_privileges: bool,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            run_as_user: None,
            disable_core_dumps: true,
            no_new_privileges: true,
        }
    }
}

impl ProcessConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self
            .run_as_user
            .as_deref()
            .is_some_and(|user| user.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "process.run_as_user must not be empty when configured".to_owned(),
            ));
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_logging_max_entry_length_bytes")]
    pub max_entry_length_bytes: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            max_entry_length_bytes: default_logging_max_entry_length_bytes(),
        }
    }
}

impl LoggingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_entry_length_bytes < minimum_log_entry_length_bytes() {
            return Err(ConfigError::Invalid(format!(
                "logging.max_entry_length_bytes must be at least {}",
                minimum_log_entry_length_bytes()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct InterfacesConfig {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<InterfaceEndpoint>>,
    #[serde(default)]
    pub mgmt: Vec<SocketAddr>,
    #[serde(default)]
    pub transfer: Vec<SocketAddr>,
    #[serde(default)]
    pub notify: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xot: Option<Vec<SocketAddr>>,
}

impl InterfacesConfig {
    fn dns_addrs(&self) -> Vec<SocketAddr> {
        self.dns
            .as_ref()
            .map(|dns| dns.iter().map(InterfaceEndpoint::addr).collect())
            .unwrap_or_default()
    }

    fn validate(&self, _server: &ServerSettings) -> Result<(), ConfigError> {
        if self.xot.is_some() {
            return Err(ConfigError::Invalid(
                "interfaces.xot is obsolete; use per-primary transfer_primaries transport = \"xot\" and future interfaces.transfer settings instead"
                    .to_owned(),
            ));
        }

        if self.dns.as_ref().is_some_and(Vec::is_empty) {
            return Err(ConfigError::Invalid(
                "interfaces.dns must contain at least one listener when configured".to_owned(),
            ));
        }

        if !self.notify.is_empty() {
            return Err(ConfigError::Invalid(
                "interfaces.notify is not part of the three-role interface model; receive NOTIFY on interfaces.dns and restrict accepted senders with zone notify_sources"
                    .to_owned(),
            ));
        }

        if let Some(dns) = &self.dns {
            for endpoint in dns {
                if endpoint
                    .name
                    .as_deref()
                    .is_some_and(|name| name.trim().is_empty())
                {
                    return Err(ConfigError::Invalid(
                        "interfaces.dns interface name must not be empty when configured"
                            .to_owned(),
                    ));
                }
            }
        }

        let mut transfer_ipv4 = false;
        let mut transfer_ipv6 = false;
        for transfer in &self.transfer {
            if transfer.port() != 0 {
                return Err(ConfigError::Invalid(format!(
                    "interfaces.transfer source {transfer} must use port 0 so the operating system can select an ephemeral source port"
                )));
            }
            match transfer.ip() {
                IpAddr::V4(_) if transfer_ipv4 => {
                    return Err(ConfigError::Invalid(
                        "interfaces.transfer must contain at most one IPv4 source".to_owned(),
                    ));
                }
                IpAddr::V4(_) => transfer_ipv4 = true,
                IpAddr::V6(_) if transfer_ipv6 => {
                    return Err(ConfigError::Invalid(
                        "interfaces.transfer must contain at most one IPv6 source".to_owned(),
                    ));
                }
                IpAddr::V6(_) => transfer_ipv6 = true,
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InterfaceEndpoint {
    pub address: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl InterfaceEndpoint {
    pub fn new(address: SocketAddr, name: Option<String>) -> Self {
        Self { address, name }
    }

    pub fn addr(&self) -> SocketAddr {
        self.address
    }
}

impl<'de> Deserialize<'de> for InterfaceEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DetailedInterfaceEndpoint {
            address: SocketAddr,
            #[serde(default)]
            name: Option<String>,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum InterfaceEndpointRepr {
            Address(SocketAddr),
            Detailed(DetailedInterfaceEndpoint),
        }

        match InterfaceEndpointRepr::deserialize(deserializer)? {
            InterfaceEndpointRepr::Address(address) => Ok(Self {
                address,
                name: None,
            }),
            InterfaceEndpointRepr::Detailed(detailed) => Ok(Self {
                address: detailed.address,
                name: detailed.name,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_port: Option<u16>,
    #[serde(default = "default_health_port")]
    pub default_port: u16,
    #[serde(default = "default_metrics_rate_limit_per_minute")]
    pub metrics_rate_limit_per_minute: u32,
    #[serde(default = "default_metrics_rate_limit_idle_seconds")]
    pub metrics_rate_limit_idle_seconds: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            bind_address: None,
            bind_port: None,
            default_port: default_health_port(),
            metrics_rate_limit_per_minute: default_metrics_rate_limit_per_minute(),
            metrics_rate_limit_idle_seconds: default_metrics_rate_limit_idle_seconds(),
        }
    }
}

impl HealthConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.bind_address.is_some() != self.bind_port.is_some() {
            return Err(ConfigError::Invalid(
                "health.bind_address and health.bind_port must be configured together".to_owned(),
            ));
        }
        if self.default_port == 0 {
            return Err(ConfigError::Invalid(
                "health.default_port must be at least 1".to_owned(),
            ));
        }
        if self.metrics_rate_limit_per_minute == 0 {
            return Err(ConfigError::Invalid(
                "health.metrics_rate_limit_per_minute must be at least 1".to_owned(),
            ));
        }
        if self.metrics_rate_limit_idle_seconds == 0 {
            return Err(ConfigError::Invalid(
                "health.metrics_rate_limit_idle_seconds must be at least 1".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default = "default_latency_histogram_buckets")]
    pub latency_histogram_buckets: Vec<LatencyHistogramBucketSeconds>,
    #[serde(default)]
    pub hot_path_detail: MetricsHotPathDetail,
    #[serde(default)]
    pub pipeline_timing_enabled: bool,
    #[serde(default)]
    pub zone_shape_enabled: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            latency_histogram_buckets: default_latency_histogram_buckets(),
            hot_path_detail: MetricsHotPathDetail::default(),
            pipeline_timing_enabled: false,
            zone_shape_enabled: false,
        }
    }
}

impl MetricsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.latency_histogram_buckets.is_empty() {
            return Err(ConfigError::Invalid(
                "metrics.latency_histogram_buckets must contain at least one bucket".to_owned(),
            ));
        }

        let mut previous = None;
        for bucket in &self.latency_histogram_buckets {
            let seconds = bucket.seconds();
            if !seconds.is_finite() || seconds <= 0.0 {
                return Err(ConfigError::Invalid(
                    "metrics.latency_histogram_buckets values must be positive finite seconds"
                        .to_owned(),
                ));
            }
            if previous.is_some_and(|previous| seconds <= previous) {
                return Err(ConfigError::Invalid(
                    "metrics.latency_histogram_buckets values must be strictly increasing"
                        .to_owned(),
                ));
            }
            previous = Some(seconds);
        }

        Ok(())
    }

    pub fn latency_histogram_buckets_seconds(&self) -> Vec<f64> {
        self.latency_histogram_buckets
            .iter()
            .map(|bucket| bucket.seconds())
            .collect()
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum MetricsHotPathDetail {
    #[serde(rename = "full")]
    #[default]
    Full,
    #[serde(rename = "reduced")]
    Reduced,
    #[serde(rename = "off")]
    Off,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_observability_path_prefix")]
    pub path_prefix: String,
    #[serde(default = "default_observability_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_observability_rate_limit_idle_seconds")]
    pub rate_limit_idle_seconds: u64,
    #[serde(default = "default_true")]
    pub include_filesystems: bool,
    #[serde(default = "default_true")]
    pub include_process_resources: bool,
    #[serde(default = "default_true")]
    pub include_time_sync_status: bool,
    #[serde(default = "default_true")]
    pub include_certificate_status: bool,
    #[serde(default = "default_true")]
    pub include_zone_detail: bool,
    #[serde(default = "default_true")]
    pub include_config_summary: bool,
    #[serde(default)]
    pub bearer_token_file: Option<PathBuf>,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path_prefix: default_observability_path_prefix(),
            rate_limit_per_minute: default_observability_rate_limit_per_minute(),
            rate_limit_idle_seconds: default_observability_rate_limit_idle_seconds(),
            include_filesystems: true,
            include_process_resources: true,
            include_time_sync_status: true,
            include_certificate_status: true,
            include_zone_detail: true,
            include_config_summary: true,
            bearer_token_file: None,
        }
    }
}

impl ObservabilityConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.path_prefix.is_empty() || !self.path_prefix.starts_with('/') {
            return Err(ConfigError::Invalid(
                "observability.path_prefix must be an absolute HTTP path".to_owned(),
            ));
        }
        if self.path_prefix.len() > 1 && self.path_prefix.ends_with('/') {
            return Err(ConfigError::Invalid(
                "observability.path_prefix must not end with '/'".to_owned(),
            ));
        }
        if self
            .path_prefix
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        {
            return Err(ConfigError::Invalid(
                "observability.path_prefix must not contain '.' or '..' path segments".to_owned(),
            ));
        }
        if self.rate_limit_per_minute == 0 {
            return Err(ConfigError::Invalid(
                "observability.rate_limit_per_minute must be at least 1".to_owned(),
            ));
        }
        if self.rate_limit_idle_seconds == 0 {
            return Err(ConfigError::Invalid(
                "observability.rate_limit_idle_seconds must be at least 1".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneConfig {
    #[serde(default)]
    pub telemetry: ControlPlaneTelemetryConfig,
    #[serde(default)]
    pub operations: ControlPlaneOperationsConfig,
}

impl ControlPlaneConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        self.telemetry.validate()?;
        self.operations.validate()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneTelemetryConfig {
    #[serde(default)]
    pub endpoint_url: Option<String>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default = "default_control_plane_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for ControlPlaneTelemetryConfig {
    fn default() -> Self {
        Self {
            endpoint_url: None,
            node_id: None,
            bearer_token: None,
            timeout_secs: default_control_plane_timeout_secs(),
        }
    }
}

impl ControlPlaneTelemetryConfig {
    pub fn enabled(&self) -> bool {
        self.endpoint_url.is_some() && self.node_id.is_some() && self.bearer_token.is_some()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let configured = [
            self.endpoint_url.is_some(),
            self.node_id.is_some(),
            self.bearer_token.is_some(),
        ];
        if configured.iter().any(|configured| *configured)
            && configured.iter().any(|configured| !*configured)
        {
            return Err(ConfigError::Invalid(
                "control_plane.telemetry endpoint_url, node_id, and bearer_token must be set together".to_owned(),
            ));
        }
        if let Some(endpoint_url) = self.endpoint_url.as_deref() {
            let endpoint_url = endpoint_url.trim();
            if !(endpoint_url.starts_with("http://") || endpoint_url.starts_with("https://")) {
                return Err(ConfigError::Invalid(
                    "control_plane.telemetry.endpoint_url must start with http:// or https://"
                        .to_owned(),
                ));
            }
            if endpoint_url.ends_with('/') {
                return Err(ConfigError::Invalid(
                    "control_plane.telemetry.endpoint_url must not end with '/'".to_owned(),
                ));
            }
        }
        if self
            .node_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "control_plane.telemetry.node_id must not be empty".to_owned(),
            ));
        }
        if self
            .bearer_token
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "control_plane.telemetry.bearer_token must not be empty".to_owned(),
            ));
        }
        if self.timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "control_plane.telemetry.timeout_secs must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

fn default_control_plane_timeout_secs() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneOperationsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint_url: Option<String>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default = "default_control_plane_poll_interval_secs")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_control_plane_operation_lease_secs")]
    pub lease_seconds: u64,
    #[serde(default = "default_control_plane_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for ControlPlaneOperationsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint_url: None,
            node_id: None,
            bearer_token: None,
            poll_interval_secs: default_control_plane_poll_interval_secs(),
            lease_seconds: default_control_plane_operation_lease_secs(),
            timeout_secs: default_control_plane_timeout_secs(),
        }
    }
}

impl ControlPlaneOperationsConfig {
    pub fn enabled(&self) -> bool {
        self.enabled
            && self.endpoint_url.is_some()
            && self.node_id.is_some()
            && self.bearer_token.is_some()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let configured = [
            self.endpoint_url.is_some(),
            self.node_id.is_some(),
            self.bearer_token.is_some(),
        ];
        if self.enabled && configured.iter().any(|configured| !*configured) {
            return Err(ConfigError::Invalid(
                "control_plane.operations endpoint_url, node_id, and bearer_token must be set when operations polling is enabled".to_owned(),
            ));
        }
        if configured.iter().any(|configured| *configured)
            && configured.iter().any(|configured| !*configured)
        {
            return Err(ConfigError::Invalid(
                "control_plane.operations endpoint_url, node_id, and bearer_token must be set together".to_owned(),
            ));
        }
        if let Some(endpoint_url) = self.endpoint_url.as_deref() {
            let endpoint_url = endpoint_url.trim();
            if !(endpoint_url.starts_with("http://") || endpoint_url.starts_with("https://")) {
                return Err(ConfigError::Invalid(
                    "control_plane.operations.endpoint_url must start with http:// or https://"
                        .to_owned(),
                ));
            }
            if endpoint_url.ends_with('/') {
                return Err(ConfigError::Invalid(
                    "control_plane.operations.endpoint_url must not end with '/'".to_owned(),
                ));
            }
        }
        if self
            .node_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "control_plane.operations.node_id must not be empty".to_owned(),
            ));
        }
        if self
            .bearer_token
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "control_plane.operations.bearer_token must not be empty".to_owned(),
            ));
        }
        if self.poll_interval_secs == 0 {
            return Err(ConfigError::Invalid(
                "control_plane.operations.poll_interval_secs must be greater than zero".to_owned(),
            ));
        }
        if self.lease_seconds == 0 {
            return Err(ConfigError::Invalid(
                "control_plane.operations.lease_seconds must be greater than zero".to_owned(),
            ));
        }
        if self.timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "control_plane.operations.timeout_secs must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

fn default_control_plane_poll_interval_secs() -> u64 {
    5
}

fn default_control_plane_operation_lease_secs() -> u64 {
    300
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(transparent)]
pub struct LatencyHistogramBucketSeconds(pub f64);

impl LatencyHistogramBucketSeconds {
    pub fn seconds(self) -> f64 {
        self.0
    }
}

impl PartialEq for LatencyHistogramBucketSeconds {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for LatencyHistogramBucketSeconds {}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdnsConfig {
    #[serde(default)]
    pub extended_dns_errors: ExtendedDnsErrorsConfig,
}

impl EdnsConfig {
    pub fn extended_dns_errors_mode(&self) -> ExtendedDnsErrorsMode {
        match self.extended_dns_errors {
            ExtendedDnsErrorsConfig::Off => ExtendedDnsErrorsMode::Off,
            ExtendedDnsErrorsConfig::Minimal => ExtendedDnsErrorsMode::Minimal,
        }
    }
}

impl Default for EdnsConfig {
    fn default() -> Self {
        Self {
            extended_dns_errors: ExtendedDnsErrorsConfig::Off,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ChaosConfig {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub hostname: String,
}

impl ChaosConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_txt_character_string("chaos.version", &self.version)?;
        validate_txt_character_string("chaos.hostname", &self.hostname)?;
        Ok(())
    }
}

fn validate_txt_character_string(parameter: &str, value: &str) -> Result<(), ConfigError> {
    if value.len() > 255 {
        return Err(ConfigError::Invalid(format!(
            "{parameter} must fit in one DNS TXT character-string of at most 255 octets"
        )));
    }
    Ok(())
}

fn looks_like_precise_build_version(value: &str) -> bool {
    let mut parts = value.splitn(4, '.');
    let (Some(major), Some(minor), Some(patch)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && !patch.is_empty()
        && major.chars().all(|ch| ch.is_ascii_digit())
        && minor.chars().all(|ch| ch.is_ascii_digit())
        && patch.chars().next().is_some_and(|ch| ch.is_ascii_digit())
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ExtendedDnsErrorsConfig {
    #[default]
    Off,
    Minimal,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnssecConfig {
    #[serde(default = "default_nsec3_max_iterations")]
    pub nsec3_max_iterations: u16,
}

impl DnssecConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            nsec3_max_iterations: default_nsec3_max_iterations(),
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
    Logfmt,
    Plain,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CookieConfig {
    #[serde(default)]
    pub policy: CookiePolicyConfig,
    #[serde(default)]
    pub server_secret: Option<String>,
    #[serde(default)]
    pub previous_server_secret: Option<String>,
    #[serde(default = "default_cookie_timestamp_past_tolerance_seconds")]
    pub timestamp_past_tolerance_seconds: u32,
    #[serde(default = "default_cookie_timestamp_future_tolerance_seconds")]
    pub timestamp_future_tolerance_seconds: u32,
    #[serde(default)]
    pub secret_rotation_interval_secs: u64,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            policy: CookiePolicyConfig::Lenient,
            server_secret: None,
            previous_server_secret: None,
            timestamp_past_tolerance_seconds: default_cookie_timestamp_past_tolerance_seconds(),
            timestamp_future_tolerance_seconds: default_cookie_timestamp_future_tolerance_seconds(),
            secret_rotation_interval_secs: 0,
        }
    }
}

impl CookieConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.server_secret.is_some() && self.secret_rotation_interval_secs > 0 {
            return Err(ConfigError::Invalid(
                "cookie.secret_rotation_interval_secs cannot be used with cookie.server_secret; rotate shared Server Secrets by setting server_secret and previous_server_secret".to_owned(),
            ));
        }
        if self.previous_server_secret.is_some() && self.server_secret.is_none() {
            return Err(ConfigError::Invalid(
                "cookie.previous_server_secret requires cookie.server_secret".to_owned(),
            ));
        }
        if let Some(secret) = self.server_secret.as_deref() {
            decode_cookie_server_secret("cookie.server_secret", secret)?;
        }
        if let Some(secret) = self.previous_server_secret.as_deref() {
            decode_cookie_server_secret("cookie.previous_server_secret", secret)?;
        }
        if self.timestamp_past_tolerance_seconds >= 2_147_483_648 {
            return Err(ConfigError::Invalid(
                "cookie.timestamp_past_tolerance_seconds must be less than 2147483648".to_owned(),
            ));
        }
        if self.timestamp_future_tolerance_seconds >= 2_147_483_648 {
            return Err(ConfigError::Invalid(
                "cookie.timestamp_future_tolerance_seconds must be less than 2147483648".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn server_secret_bytes(&self) -> Result<Option<[u8; 16]>, ConfigError> {
        self.server_secret
            .as_deref()
            .map(|secret| decode_cookie_server_secret("cookie.server_secret", secret))
            .transpose()
    }

    pub fn previous_server_secret_bytes(&self) -> Result<Option<[u8; 16]>, ConfigError> {
        self.previous_server_secret
            .as_deref()
            .map(|secret| decode_cookie_server_secret("cookie.previous_server_secret", secret))
            .transpose()
    }
}

fn decode_cookie_server_secret(parameter: &str, value: &str) -> Result<[u8; 16], ConfigError> {
    let value = value.trim();
    if value.len() != 32 {
        return Err(ConfigError::Invalid(format!(
            "{parameter} must be exactly 32 hexadecimal characters"
        )));
    }
    let mut secret = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(chunk[0]).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "{parameter} must contain only hexadecimal characters"
            ))
        })?;
        let low = decode_hex_nibble(chunk[1]).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "{parameter} must contain only hexadecimal characters"
            ))
        })?;
        secret[index] = (high << 4) | low;
    }
    Ok(secret)
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CookiePolicyConfig {
    Disabled,
    #[default]
    Lenient,
    Strict,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    #[serde(default = "default_rrl_summary_log_interval_secs")]
    pub summary_log_interval_secs: u64,
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
            summary_log_interval_secs: default_rrl_summary_log_interval_secs(),
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
        if self.summary_log_interval_secs == 0 {
            return Err(ConfigError::Invalid(
                "rrl.summary_log_interval_secs must be at least 1".to_owned(),
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
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_max_udp_payload")]
    pub max_udp_payload: u16,
    #[serde(default = "default_udp_batch_size")]
    pub udp_batch_size: usize,
    #[serde(default = "default_udp_reuseport_workers")]
    pub udp_reuseport_workers: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_worker_cpu_affinity: Option<Vec<usize>>,
    #[serde(default)]
    pub udp_runtime: UdpRuntime,
    #[serde(default)]
    pub udp_idle_strategy: UdpIdleStrategy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_socket_receive_buffer_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_socket_send_buffer_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_socket_max_pacing_rate_bytes_per_second: Option<usize>,
    #[serde(default)]
    pub udp_backend: UdpBackend,
    #[serde(default = "default_max_cname_chain")]
    pub max_cname_chain: usize,
    #[serde(default = "default_tcp_idle_timeout_secs")]
    pub tcp_idle_timeout_secs: u64,
    #[serde(default = "default_tcp_read_timeout_secs")]
    pub tcp_read_timeout_secs: u64,
    #[serde(default = "default_tcp_write_timeout_secs")]
    pub tcp_write_timeout_secs: u64,
    #[serde(default = "default_tcp_connect_timeout_secs")]
    pub tcp_connect_timeout_secs: u64,
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tcp_connections_per_source: Option<usize>,
    #[serde(default = "default_max_tcp_inflight_queries_per_connection")]
    pub max_tcp_inflight_queries_per_connection: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_inflight_limit_timeout_secs: Option<u64>,
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
    #[serde(default = "default_max_transfer_ingest_bytes")]
    pub max_transfer_ingest_bytes: u64,
    #[serde(default = "default_notify_dedup_secs")]
    pub notify_dedup_secs: u64,
    #[serde(default = "default_notify_log_rate_window_secs")]
    pub notify_log_rate_window_secs: u64,
    #[serde(default = "default_max_concurrent_transfers")]
    pub max_concurrent_transfers: usize,
    #[serde(default = "default_zsm_min_interval_secs")]
    pub zsm_min_interval_secs: u64,
    #[serde(default = "default_zsm_max_interval_secs")]
    pub zsm_max_interval_secs: u64,
    #[serde(default = "default_zsm_initial_retry_secs")]
    pub zsm_initial_retry_secs: u64,
    #[serde(default = "default_zsm_initial_retry_max_secs")]
    pub zsm_initial_retry_max_secs: u64,
    #[serde(default = "default_zsm_loading_warning_threshold_secs")]
    pub zsm_loading_warning_threshold_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_udp_payload: default_max_udp_payload(),
            udp_batch_size: default_udp_batch_size(),
            udp_reuseport_workers: default_udp_reuseport_workers(),
            udp_worker_cpu_affinity: None,
            udp_runtime: UdpRuntime::default(),
            udp_idle_strategy: UdpIdleStrategy::default(),
            udp_socket_receive_buffer_bytes: None,
            udp_socket_send_buffer_bytes: None,
            udp_socket_max_pacing_rate_bytes_per_second: None,
            udp_backend: UdpBackend::default(),
            max_cname_chain: default_max_cname_chain(),
            tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
            tcp_read_timeout_secs: default_tcp_read_timeout_secs(),
            tcp_write_timeout_secs: default_tcp_write_timeout_secs(),
            tcp_connect_timeout_secs: default_tcp_connect_timeout_secs(),
            max_tcp_connections: default_max_tcp_connections(),
            max_tcp_connections_per_source: None,
            max_tcp_inflight_queries_per_connection:
                default_max_tcp_inflight_queries_per_connection(),
            tcp_inflight_limit_timeout_secs: None,
            graceful_shutdown_secs: default_graceful_shutdown_secs(),
            edns_padding_block_size: default_edns_padding_block_size(),
            axfr_timeout_secs: default_axfr_timeout_secs(),
            ixfr_timeout_secs: default_ixfr_timeout_secs(),
            ixfr_disabled_cooldown_secs: default_ixfr_disabled_cooldown_secs(),
            max_transfer_ingest_bytes: default_max_transfer_ingest_bytes(),
            notify_dedup_secs: default_notify_dedup_secs(),
            notify_log_rate_window_secs: default_notify_log_rate_window_secs(),
            max_concurrent_transfers: default_max_concurrent_transfers(),
            zsm_min_interval_secs: default_zsm_min_interval_secs(),
            zsm_max_interval_secs: default_zsm_max_interval_secs(),
            zsm_initial_retry_secs: default_zsm_initial_retry_secs(),
            zsm_initial_retry_max_secs: default_zsm_initial_retry_max_secs(),
            zsm_loading_warning_threshold_secs: default_zsm_loading_warning_threshold_secs(),
        }
    }
}

impl Limits {
    fn validate_udp_worker_settings(&self) -> Result<(), ConfigError> {
        if self.udp_reuseport_workers == 0 {
            return Err(ConfigError::Invalid(
                "limits.udp_reuseport_workers must be at least 1".to_owned(),
            ));
        }
        if self.udp_backend == UdpBackend::AfXdp && self.udp_runtime != UdpRuntime::Tokio {
            return Err(ConfigError::Invalid(
                "limits.udp_runtime must be \"tokio\" when limits.udp_backend = \"af_xdp\""
                    .to_owned(),
            ));
        }
        if self.udp_idle_strategy != UdpIdleStrategy::Park
            && self.udp_runtime != UdpRuntime::Dedicated
        {
            return Err(ConfigError::Invalid(
                "limits.udp_idle_strategy other than \"park\" requires limits.udp_runtime = \"dedicated\""
                    .to_owned(),
            ));
        }
        if matches!(self.udp_socket_receive_buffer_bytes, Some(0)) {
            return Err(ConfigError::Invalid(
                "limits.udp_socket_receive_buffer_bytes must be greater than zero".to_owned(),
            ));
        }
        if matches!(self.udp_socket_send_buffer_bytes, Some(0)) {
            return Err(ConfigError::Invalid(
                "limits.udp_socket_send_buffer_bytes must be greater than zero".to_owned(),
            ));
        }
        if matches!(self.udp_socket_max_pacing_rate_bytes_per_second, Some(0)) {
            return Err(ConfigError::Invalid(
                "limits.udp_socket_max_pacing_rate_bytes_per_second must be greater than zero"
                    .to_owned(),
            ));
        }
        if let Some(cpus) = &self.udp_worker_cpu_affinity {
            if cpus.is_empty() {
                return Err(ConfigError::Invalid(
                    "limits.udp_worker_cpu_affinity must not be empty when configured".to_owned(),
                ));
            }
            if self.udp_backend == UdpBackend::AfXdp {
                return Err(ConfigError::Invalid(
                    "limits.udp_worker_cpu_affinity is only supported by the standard UDP backend"
                        .to_owned(),
                ));
            }
            if self.udp_runtime != UdpRuntime::Dedicated {
                return Err(ConfigError::Invalid(
                    "limits.udp_worker_cpu_affinity requires limits.udp_runtime = \"dedicated\""
                        .to_owned(),
                ));
            }
            if cpus.len() != self.udp_reuseport_workers {
                return Err(ConfigError::Invalid(
                    "limits.udp_worker_cpu_affinity length must match limits.udp_reuseport_workers"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum UdpRuntime {
    #[serde(rename = "tokio")]
    #[default]
    Tokio,
    #[serde(rename = "dedicated")]
    Dedicated,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum UdpIdleStrategy {
    #[serde(rename = "park")]
    #[default]
    Park,
    #[serde(rename = "spin")]
    Spin,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum UdpBackend {
    #[serde(rename = "std")]
    #[default]
    Std,
    #[serde(rename = "af_xdp")]
    AfXdp,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XdpConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_object: Option<PathBuf>,
    #[serde(default)]
    pub mode: XdpMode,
    #[serde(default)]
    pub queue_id: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queue_ids: Vec<u32>,
    #[serde(default = "default_xdp_umem_frame_count")]
    pub umem_frame_count: u32,
    #[serde(default = "default_xdp_rx_ring_size")]
    pub rx_ring_size: u32,
    #[serde(default = "default_xdp_tx_ring_size")]
    pub tx_ring_size: u32,
    #[serde(default = "default_xdp_fill_ring_size")]
    pub fill_ring_size: u32,
    #[serde(default = "default_xdp_completion_ring_size")]
    pub completion_ring_size: u32,
    #[serde(default = "default_xdp_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_xdp_rx_drain_passes")]
    pub rx_drain_passes: usize,
    #[serde(default = "default_xdp_tx_wakeup_interval")]
    pub tx_wakeup_interval: usize,
    #[serde(default)]
    pub zero_copy: XdpZeroCopyMode,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            interface: None,
            redirect_object: None,
            mode: XdpMode::default(),
            queue_id: 0,
            queue_ids: Vec::new(),
            umem_frame_count: default_xdp_umem_frame_count(),
            rx_ring_size: default_xdp_rx_ring_size(),
            tx_ring_size: default_xdp_tx_ring_size(),
            fill_ring_size: default_xdp_fill_ring_size(),
            completion_ring_size: default_xdp_completion_ring_size(),
            batch_size: default_xdp_batch_size(),
            rx_drain_passes: default_xdp_rx_drain_passes(),
            tx_wakeup_interval: default_xdp_tx_wakeup_interval(),
            zero_copy: XdpZeroCopyMode::default(),
        }
    }
}

impl XdpConfig {
    fn validate(&self, udp_backend: UdpBackend) -> Result<(), ConfigError> {
        if self.interface.as_deref().is_some_and(str::is_empty) {
            return Err(ConfigError::Invalid(
                "xdp.interface must not be empty when configured".to_owned(),
            ));
        }
        if udp_backend == UdpBackend::AfXdp && self.interface.is_none() {
            return Err(ConfigError::Invalid(
                "xdp.interface must be set when limits.udp_backend = \"af_xdp\"".to_owned(),
            ));
        }
        if udp_backend == UdpBackend::AfXdp && self.redirect_object.is_none() {
            return Err(ConfigError::Invalid(
                "xdp.redirect_object must be set when limits.udp_backend = \"af_xdp\"".to_owned(),
            ));
        }
        if self.umem_frame_count == 0 {
            return Err(ConfigError::Invalid(
                "xdp.umem_frame_count must be at least 1".to_owned(),
            ));
        }
        if self.rx_ring_size == 0 {
            return Err(ConfigError::Invalid(
                "xdp.rx_ring_size must be at least 1".to_owned(),
            ));
        }
        if self.tx_ring_size == 0 {
            return Err(ConfigError::Invalid(
                "xdp.tx_ring_size must be at least 1".to_owned(),
            ));
        }
        if self.fill_ring_size == 0 {
            return Err(ConfigError::Invalid(
                "xdp.fill_ring_size must be at least 1".to_owned(),
            ));
        }
        if self.completion_ring_size == 0 {
            return Err(ConfigError::Invalid(
                "xdp.completion_ring_size must be at least 1".to_owned(),
            ));
        }
        for (parameter, value) in [
            ("xdp.rx_ring_size", self.rx_ring_size),
            ("xdp.tx_ring_size", self.tx_ring_size),
            ("xdp.fill_ring_size", self.fill_ring_size),
            ("xdp.completion_ring_size", self.completion_ring_size),
        ] {
            if !value.is_power_of_two() {
                return Err(ConfigError::Invalid(format!(
                    "{parameter} must be a power of two"
                )));
            }
        }
        if self.batch_size == 0 {
            return Err(ConfigError::Invalid(
                "xdp.batch_size must be at least 1".to_owned(),
            ));
        }
        if self.rx_drain_passes == 0 {
            return Err(ConfigError::Invalid(
                "xdp.rx_drain_passes must be at least 1".to_owned(),
            ));
        }
        if self.tx_wakeup_interval == 0 {
            return Err(ConfigError::Invalid(
                "xdp.tx_wakeup_interval must be at least 1".to_owned(),
            ));
        }
        if !self.queue_ids.is_empty() {
            if self.queue_id != 0 {
                return Err(ConfigError::Invalid(
                    "xdp.queue_id must not be set when xdp.queue_ids is configured".to_owned(),
                ));
            }
            let mut queue_ids = self.queue_ids.clone();
            queue_ids.sort_unstable();
            if queue_ids.windows(2).any(|window| window[0] == window[1]) {
                return Err(ConfigError::Invalid(
                    "xdp.queue_ids must not contain duplicate queue ids".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum XdpMode {
    #[serde(rename = "skb")]
    #[default]
    Skb,
    #[serde(rename = "drv")]
    Drv,
    #[serde(rename = "hw")]
    Hw,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum XdpZeroCopyMode {
    #[serde(rename = "auto")]
    #[default]
    Auto,
    #[serde(rename = "require")]
    Require,
    #[serde(rename = "disable")]
    Disable,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct CatalogZoneConfig {
    pub name: String,
    #[serde(default = "default_dns_class")]
    pub class: String,
    #[serde(default)]
    pub primaries: Vec<SocketAddr>,
    #[serde(default)]
    pub transfer_primaries: Vec<TransferPrimaryConfig>,
    #[serde(default)]
    pub catalog_primaries: Vec<SocketAddr>,
    #[serde(default)]
    pub catalog_transfer_primaries: Vec<TransferPrimaryConfig>,
    #[serde(default)]
    pub member_primaries: Vec<SocketAddr>,
    #[serde(default)]
    pub member_transfer_primaries: Vec<TransferPrimaryConfig>,
    #[serde(default)]
    pub notify_sources: Vec<std::net::IpAddr>,
    pub tsig_key: Option<String>,
    pub catalog_tsig_key: Option<String>,
    pub member_tsig_key: Option<String>,
    #[serde(default)]
    pub serve_catalog_zone: bool,
    #[serde(default)]
    pub member_transfer_extensions: bool,
    #[serde(default = "default_catalog_max_member_zones")]
    pub max_member_zones: usize,
}

impl CatalogZoneConfig {
    pub fn transfer_targets(&self) -> Vec<TransferPrimaryConfig> {
        self.catalog_transfer_targets()
    }

    pub fn catalog_transfer_targets(&self) -> Vec<TransferPrimaryConfig> {
        if !self.catalog_transfer_primaries.is_empty() {
            self.catalog_transfer_primaries.clone()
        } else if !self.catalog_primaries.is_empty() {
            self.catalog_primaries
                .iter()
                .copied()
                .map(TransferPrimaryConfig::tcp)
                .collect()
        } else {
            self.shared_transfer_targets()
        }
    }

    pub fn member_transfer_targets(&self) -> Vec<TransferPrimaryConfig> {
        if !self.member_transfer_primaries.is_empty() {
            self.member_transfer_primaries.clone()
        } else if !self.member_primaries.is_empty() {
            self.member_primaries
                .iter()
                .copied()
                .map(TransferPrimaryConfig::tcp)
                .collect()
        } else {
            self.shared_transfer_targets()
        }
    }

    pub fn all_transfer_targets(&self) -> Vec<TransferPrimaryConfig> {
        let mut targets = self.catalog_transfer_targets();
        targets.extend(self.member_transfer_targets());
        targets
    }

    fn shared_transfer_targets(&self) -> Vec<TransferPrimaryConfig> {
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
        self.catalog_transfer_target_addrs()
    }

    pub fn catalog_transfer_target_addrs(&self) -> Vec<SocketAddr> {
        self.catalog_transfer_targets()
            .into_iter()
            .map(|target| target.addr)
            .collect()
    }

    pub fn member_transfer_target_addrs(&self) -> Vec<SocketAddr> {
        self.member_transfer_targets()
            .into_iter()
            .map(|target| target.addr)
            .collect()
    }

    pub fn catalog_tsig_key_name(&self) -> Option<&str> {
        self.catalog_tsig_key
            .as_deref()
            .or(self.tsig_key.as_deref())
    }

    pub fn member_tsig_key_name(&self) -> Option<&str> {
        self.member_tsig_key.as_deref().or(self.tsig_key.as_deref())
    }

    fn tsig_key_references(&self) -> Vec<(&'static str, &str)> {
        let mut references = Vec::new();
        if let Some(tsig_key) = self.tsig_key.as_deref() {
            references.push(("tsig_key", tsig_key));
        }
        if let Some(tsig_key) = self.catalog_tsig_key.as_deref() {
            references.push(("catalog_tsig_key", tsig_key));
        }
        if let Some(tsig_key) = self.member_tsig_key.as_deref() {
            references.push(("member_tsig_key", tsig_key));
        }
        references
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_member_zones == 0 {
            return Err(ConfigError::Invalid(format!(
                "catalog zone {} max_member_zones must be at least 1",
                self.name
            )));
        }
        validate_catalog_transfer_group(
            &self.name,
            "catalog zone",
            &self.primaries,
            &self.transfer_primaries,
        )?;
        validate_catalog_transfer_group(
            &self.name,
            "catalog zone catalog",
            &self.catalog_primaries,
            &self.catalog_transfer_primaries,
        )?;
        validate_catalog_transfer_group(
            &self.name,
            "catalog zone member",
            &self.member_primaries,
            &self.member_transfer_primaries,
        )?;
        if !self.primaries.is_empty() || !self.transfer_primaries.is_empty() {
            if !self.catalog_primaries.is_empty() || !self.catalog_transfer_primaries.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "catalog zone {} must not mix shared primaries/transfer_primaries with catalog_primaries/catalog_transfer_primaries",
                    self.name
                )));
            }
            if !self.member_primaries.is_empty() || !self.member_transfer_primaries.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "catalog zone {} must not mix shared primaries/transfer_primaries with member_primaries/member_transfer_primaries",
                    self.name
                )));
            }
        }
        if self.catalog_transfer_targets().is_empty() {
            return Err(ConfigError::Invalid(format!(
                "catalog zone {} requires at least one catalog primary or shared primary",
                self.name
            )));
        }
        if self.member_transfer_targets().is_empty() {
            return Err(ConfigError::Invalid(format!(
                "catalog zone {} requires at least one member primary or shared primary",
                self.name
            )));
        }
        Ok(())
    }
}

fn validate_catalog_transfer_group(
    zone_name: &str,
    label: &str,
    primaries: &[SocketAddr],
    transfer_primaries: &[TransferPrimaryConfig],
) -> Result<(), ConfigError> {
    if !primaries.is_empty() && !transfer_primaries.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{label} {zone_name} must not mix legacy primaries and transfer_primaries"
        )));
    }
    for primary in transfer_primaries {
        primary.validate(zone_name)?;
    }
    Ok(())
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferPrimaryConfig {
    pub addr: SocketAddr,
    #[serde(default)]
    pub transport: TransferTransportConfig,
    pub server_name: Option<String>,
    #[serde(default)]
    pub trust_anchors: Vec<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_pem: Option<String>,
}

impl fmt::Debug for TransferPrimaryConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferPrimaryConfig")
            .field("addr", &self.addr)
            .field("transport", &self.transport)
            .field("server_name", &self.server_name)
            .field("trust_anchors", &self.trust_anchors)
            .field("client_cert", &self.client_cert)
            .field("client_key", &self.client_key)
            .field(
                "client_key_pem",
                &self.client_key_pem.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
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
            client_key_pem: None,
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
            || self.client_key_pem.is_some()
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
        match (&self.client_cert, &self.client_key, &self.client_key_pem) {
            (Some(cert), Some(key), None) if cert.trim().is_empty() || key.trim().is_empty() => {
                Err(ConfigError::Invalid(format!(
                    "zone {zone_name} XoT transfer primary {} has an empty client certificate or key path",
                    self.addr
                )))
            }
            (Some(cert), None, Some(key_pem))
                if cert.trim().is_empty() || key_pem.trim().is_empty() =>
            {
                Err(ConfigError::Invalid(format!(
                    "zone {zone_name} XoT transfer primary {} has an empty client certificate path or inline client key",
                    self.addr
                )))
            }
            (Some(_), Some(_), None) | (Some(_), None, Some(_)) | (None, None, None) => Ok(()),
            (Some(_), Some(_), Some(_)) => Err(ConfigError::Invalid(format!(
                "zone {zone_name} XoT transfer primary {} must set exactly one of client_key or client_key_pem",
                self.addr
            ))),
            _ => Err(ConfigError::Invalid(format!(
                "zone {zone_name} XoT transfer primary {} requires client_cert and exactly one of client_key or client_key_pem to be configured together",
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
#[serde(deny_unknown_fields)]
pub struct TsigKeyConfig {
    pub name: String,
    pub algorithm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_file: Option<String>,
}

impl fmt::Debug for TsigKeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TsigKeyConfig")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"<redacted>")
            .field("secret_file", &self.secret_file)
            .finish()
    }
}

impl TsigKeyConfig {
    pub fn secret_base64(&self) -> Result<Zeroizing<String>, ConfigError> {
        match (&self.secret, &self.secret_file) {
            (Some(secret), None) => Ok(Zeroizing::new(secret.clone())),
            (None, Some(path)) => read_secret_file(path),
            (Some(_), Some(_)) | (None, None) => Err(ConfigError::Invalid(format!(
                "TSIG key {} must set exactly one of secret or secret_file",
                self.name
            ))),
        }
    }
}

fn read_secret_file(path: &str) -> Result<Zeroizing<String>, ConfigError> {
    if path.trim().is_empty() {
        return Err(ConfigError::Invalid(
            "TSIG secret_file path must not be empty".to_owned(),
        ));
    }
    validate_secret_file_mode(path)?;
    let secret = fs::read_to_string(path).map_err(|source| ConfigError::ReadSecretFile {
        path: path.to_owned(),
        source,
    })?;
    Ok(Zeroizing::new(secret.trim().to_owned()))
}

#[cfg(unix)]
fn validate_secret_file_mode(path: &str) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|source| ConfigError::ReadSecretFile {
        path: path.to_owned(),
        source,
    })?;
    if metadata.permissions().mode() & 0o004 != 0 {
        return Err(ConfigError::Invalid(format!(
            "TSIG secret_file {path:?} must not be world-readable"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_file_mode(_path: &str) -> Result<(), ConfigError> {
    Ok(())
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn default_logging_max_entry_length_bytes() -> usize {
    16_384
}

fn minimum_log_entry_length_bytes() -> usize {
    128
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

fn default_cookie_timestamp_past_tolerance_seconds() -> u32 {
    3600
}

fn default_cookie_timestamp_future_tolerance_seconds() -> u32 {
    300
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

fn default_rrl_summary_log_interval_secs() -> u64 {
    60
}

fn default_tsig_fudge_seconds() -> u16 {
    DEFAULT_TSIG_FUDGE_SECS
}

fn default_nsec3_max_iterations() -> u16 {
    100
}

fn default_catalog_max_member_zones() -> usize {
    10_000
}

fn default_health_port() -> u16 {
    8080
}

fn socket_addr_sets_equal(left: &[SocketAddr], right: &[SocketAddr]) -> bool {
    left.len() == right.len() && left.iter().all(|addr| right.contains(addr))
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

fn socket_addrs_overlap(left: SocketAddr, right: SocketAddr) -> bool {
    if left.port() != right.port() {
        return false;
    }

    match (left.ip(), right.ip()) {
        (IpAddr::V4(left), IpAddr::V4(right)) => {
            left.is_unspecified() || right.is_unspecified() || left == right
        }
        (IpAddr::V6(left), IpAddr::V6(right)) => {
            left.is_unspecified() || right.is_unspecified() || left == right
        }
        _ => false,
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

fn default_udp_batch_size() -> usize {
    1
}

fn default_udp_reuseport_workers() -> usize {
    1
}

fn default_xdp_umem_frame_count() -> u32 {
    4096
}

fn default_xdp_rx_ring_size() -> u32 {
    1024
}

fn default_xdp_tx_ring_size() -> u32 {
    1024
}

fn default_xdp_fill_ring_size() -> u32 {
    2048
}

fn default_xdp_completion_ring_size() -> u32 {
    1024
}

fn default_xdp_batch_size() -> usize {
    64
}

fn default_xdp_rx_drain_passes() -> usize {
    1
}

fn default_xdp_tx_wakeup_interval() -> usize {
    8
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

fn default_tcp_connect_timeout_secs() -> u64 {
    10
}

fn default_max_tcp_connections() -> usize {
    1024
}

fn default_max_tcp_inflight_queries_per_connection() -> usize {
    64
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

fn default_max_transfer_ingest_bytes() -> u64 {
    4 * 1024 * 1024 * 1024
}

fn default_notify_dedup_secs() -> u64 {
    1
}

fn default_notify_log_rate_window_secs() -> u64 {
    60
}

fn default_max_concurrent_transfers() -> usize {
    4
}

fn default_zsm_min_interval_secs() -> u64 {
    60
}

fn default_zsm_max_interval_secs() -> u64 {
    86_400
}

fn default_zsm_initial_retry_secs() -> u64 {
    60
}

fn default_zsm_initial_retry_max_secs() -> u64 {
    3600
}

fn default_zsm_loading_warning_threshold_secs() -> u64 {
    3600
}

fn default_metrics_rate_limit_per_minute() -> u32 {
    60
}

fn default_metrics_rate_limit_idle_seconds() -> u64 {
    300
}

fn default_observability_path_prefix() -> String {
    "/observability/v1".to_owned()
}

fn default_observability_rate_limit_per_minute() -> u32 {
    60
}

fn default_observability_rate_limit_idle_seconds() -> u64 {
    300
}

fn default_latency_histogram_buckets() -> Vec<LatencyHistogramBucketSeconds> {
    [
        0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.1,
    ]
    .into_iter()
    .map(LatencyHistogramBucketSeconds)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

    include!("config_tests/support.rs");
    include!("config_tests/general_catalog_interfaces.rs");
    include!("config_tests/transfer_xot_listeners.rs");
    include!("config_tests/policy_observability.rs");
    include!("config_tests/udp_xdp.rs");
    include!("config_tests/limits_transfer.rs");
    include!("config_tests/tsig_redaction.rs");
    include!("config_tests/zsm_retry.rs");
}
