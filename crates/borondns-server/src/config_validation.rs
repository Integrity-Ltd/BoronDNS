use std::time::{SystemTime, UNIX_EPOCH};

use borondns_core::{
    ConfigWarning, ServerConfig,
    config::{TransferPrimaryConfig, TransferTransportConfig, UdpBackend},
};
use tokio_rustls::rustls::pki_types::ServerName;
use x509_parser::parse_x509_certificate;

use crate::{
    RuntimeError, TransferError, build_xot_client_config, load_pem_certs_for_primary,
    resource_limits,
    secret_store::{SecretManager, SecretSnapshot, SnapshotCertificateFile},
};

const XOT_TRUST_ANCHOR_EXPIRY_WARNING_SECS: i64 = 30 * 24 * 60 * 60;

pub fn validate_runtime_config(config: &ServerConfig) -> Result<(), TransferError> {
    for (_zone_name, primary) in transfer_targets_with_names(config) {
        if primary.transport == TransferTransportConfig::Xot {
            validate_xot_transfer_target(&primary)?;
        }
    }
    Ok(())
}

pub(super) fn validate_file_descriptor_limit(config: &ServerConfig) -> Result<(), RuntimeError> {
    let required = required_file_descriptor_limit_inner(config);
    let current = resource_limits::current_file_descriptor_limit()
        .map_err(RuntimeError::FileDescriptorLimit)?;
    if current >= required {
        Ok(())
    } else {
        Err(RuntimeError::InsufficientFileDescriptorLimit { current, required })
    }
}

#[cfg(test)]
pub(super) fn required_file_descriptor_limit(config: &ServerConfig) -> u64 {
    required_file_descriptor_limit_inner(config)
}

#[cfg(test)]
pub(super) fn validate_file_descriptor_limit_value(
    config: &ServerConfig,
    current: u64,
) -> Result<(), RuntimeError> {
    let required = required_file_descriptor_limit_inner(config);
    if current >= required {
        Ok(())
    } else {
        Err(RuntimeError::InsufficientFileDescriptorLimit { current, required })
    }
}

pub fn runtime_config_warnings(config: &ServerConfig) -> Result<Vec<ConfigWarning>, TransferError> {
    if !config.secret_store.enabled() {
        return runtime_config_warnings_from_snapshot_at(
            config,
            &SecretSnapshot::default(),
            current_unix_time_secs_i64(),
        );
    }
    let secrets = SecretManager::from_config(config).map_err(|error| TransferError::XotConfig {
        addr: "0.0.0.0:0"
            .parse()
            .expect("hard-coded placeholder socket address is valid"),
        message: format!("failed to load secret snapshot for runtime warnings: {error}"),
    })?;
    runtime_config_warnings_with_secrets_at(config, &secrets, current_unix_time_secs_i64())
}

pub(super) fn runtime_config_warnings_with_secrets(
    config: &ServerConfig,
    secrets: &SecretManager,
) -> Result<Vec<ConfigWarning>, TransferError> {
    runtime_config_warnings_with_secrets_at(config, secrets, current_unix_time_secs_i64())
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn runtime_config_warnings_at(
    config: &ServerConfig,
    now_unix_secs: i64,
) -> Result<Vec<ConfigWarning>, TransferError> {
    if !config.secret_store.enabled() {
        return runtime_config_warnings_from_snapshot_at(
            config,
            &SecretSnapshot::default(),
            now_unix_secs,
        );
    }
    let secrets = SecretManager::from_config(config).map_err(|error| TransferError::XotConfig {
        addr: "0.0.0.0:0"
            .parse()
            .expect("hard-coded placeholder socket address is valid"),
        message: format!("failed to load secret snapshot for runtime warnings: {error}"),
    })?;
    runtime_config_warnings_with_secrets_at(config, &secrets, now_unix_secs)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn runtime_config_warnings_with_secrets_at(
    config: &ServerConfig,
    secrets: &SecretManager,
    now_unix_secs: i64,
) -> Result<Vec<ConfigWarning>, TransferError> {
    let snapshot = secrets
        .current_snapshot()
        .map_err(|error| TransferError::XotConfig {
            addr: "0.0.0.0:0"
                .parse()
                .expect("hard-coded placeholder socket address is valid"),
            message: format!("failed to read secret snapshot for runtime warnings: {error}"),
        })?;
    runtime_config_warnings_from_snapshot_at(config, &snapshot, now_unix_secs)
}

fn runtime_config_warnings_from_snapshot_at(
    config: &ServerConfig,
    snapshot: &SecretSnapshot,
    now_unix_secs: i64,
) -> Result<Vec<ConfigWarning>, TransferError> {
    let mut warnings = Vec::new();
    for (zone_name, primary) in transfer_targets_with_names(config) {
        if primary.transport != TransferTransportConfig::Xot {
            continue;
        }
        if let Some(profile_name) = primary.xot_profile.as_deref() {
            let Some(profile) = snapshot.xot_profile(profile_name) else {
                // Reference validation reports an unavailable profile. Warning
                // collection remains best-effort so schema-only tooling can
                // inspect configs before the external secret store is mounted.
                continue;
            };
            warnings.extend(xot_snapshot_trust_anchor_expiry_warnings(
                &zone_name,
                &primary,
                &profile.trust_anchor_certificates,
                now_unix_secs,
            )?);
            continue;
        }
        warnings.extend(xot_trust_anchor_expiry_warnings(
            &zone_name,
            &primary,
            now_unix_secs,
        )?);
    }
    Ok(warnings)
}

fn required_file_descriptor_limit_inner(config: &ServerConfig) -> u64 {
    let tcp_connections = config.limits.max_tcp_connections as u64;
    let outbound_transfers = config.limits.max_concurrent_transfers as u64;
    let udp_listener_count = config.udp_listeners().len() as u64;
    let udp_workers = config.limits.udp_reuseport_workers as u64;
    let udp_sockets_per_listener = match config.limits.udp_backend {
        UdpBackend::Std => udp_workers,
        // One XSK descriptor per queue plus the bound kernel UDP fallback
        // socket which serves XDP_PASS traffic.
        UdpBackend::AfXdp => (config
            .xdp
            .effective_queue_count(config.limits.udp_reuseport_workers)
            as u64)
            .saturating_add(1),
    };
    let udp_sockets = udp_listener_count.saturating_mul(udp_sockets_per_listener);
    let tcp_listeners = config.tcp_listeners().len() as u64;
    let health_listeners = config.health_listeners().len() as u64;
    let health_connections = if health_listeners == 0 {
        0
    } else {
        config.health.max_connections as u64
    };
    tcp_connections
        .saturating_add(outbound_transfers)
        .saturating_add(udp_sockets)
        .saturating_add(tcp_listeners)
        .saturating_add(health_listeners)
        .saturating_add(health_connections)
        // Post-accept admission may transiently hold one unadmitted descriptor
        // per health listener before closing it.
        .saturating_add(health_listeners)
        .saturating_add(100)
        .saturating_mul(2)
}

fn transfer_targets_with_names(config: &ServerConfig) -> Vec<(String, TransferPrimaryConfig)> {
    config
        .zones
        .iter()
        .flat_map(|zone| {
            zone.transfer_targets()
                .into_iter()
                .map(|primary| (zone.name.clone(), primary))
        })
        .chain(config.catalog_zones.iter().flat_map(|zone| {
            zone.all_transfer_targets()
                .into_iter()
                .map(|primary| (zone.name.clone(), primary))
        }))
        .collect()
}

fn xot_trust_anchor_expiry_warnings(
    zone_name: &str,
    primary: &TransferPrimaryConfig,
    now_unix_secs: i64,
) -> Result<Vec<ConfigWarning>, TransferError> {
    let mut warnings = Vec::new();
    let warning_deadline = now_unix_secs.saturating_add(XOT_TRUST_ANCHOR_EXPIRY_WARNING_SECS);
    for trust_anchor in &primary.trust_anchors {
        let certs = load_pem_certs_for_primary(primary.addr, trust_anchor)?;
        append_xot_trust_anchor_expiry_warnings(
            &mut warnings,
            zone_name,
            primary,
            trust_anchor,
            &certs,
            warning_deadline,
        )?;
    }
    Ok(warnings)
}

fn xot_snapshot_trust_anchor_expiry_warnings(
    zone_name: &str,
    primary: &TransferPrimaryConfig,
    trust_anchors: &[SnapshotCertificateFile],
    now_unix_secs: i64,
) -> Result<Vec<ConfigWarning>, TransferError> {
    let mut warnings = Vec::new();
    let warning_deadline = now_unix_secs.saturating_add(XOT_TRUST_ANCHOR_EXPIRY_WARNING_SECS);
    for trust_anchor in trust_anchors {
        append_xot_trust_anchor_expiry_warnings(
            &mut warnings,
            zone_name,
            primary,
            &trust_anchor.path,
            &trust_anchor.certificates,
            warning_deadline,
        )?;
    }
    Ok(warnings)
}

fn append_xot_trust_anchor_expiry_warnings(
    warnings: &mut Vec<ConfigWarning>,
    zone_name: &str,
    primary: &TransferPrimaryConfig,
    trust_anchor: &str,
    certs: &[tokio_rustls::rustls::pki_types::CertificateDer<'static>],
    warning_deadline: i64,
) -> Result<(), TransferError> {
    for (index, cert) in certs.iter().enumerate() {
        let (_, parsed) =
            parse_x509_certificate(cert.as_ref()).map_err(|error| TransferError::XotConfig {
                addr: primary.addr,
                message: format!(
                    "failed to parse trust anchor certificate {trust_anchor:?}: {error}"
                ),
            })?;
        let not_after = parsed.validity().not_after.timestamp();
        if not_after <= warning_deadline {
            warnings.push(ConfigWarning {
                code: "xot_trust_anchor_expiring_soon",
                parameter: format!(
                    "zones[{zone_name}].transfer_primaries[{}].trust_anchors[{trust_anchor}][{index}]",
                    primary.addr
                ),
                message: format!(
                    "XoT trust anchor expires at Unix timestamp {not_after}, within 30 days of process startup"
                ),
            });
        }
    }
    Ok(())
}

fn current_unix_time_secs_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or_default()
}

fn validate_xot_transfer_target(primary: &TransferPrimaryConfig) -> Result<(), TransferError> {
    if primary.xot_profile.is_some() {
        return Ok(());
    }
    let server_name = primary
        .server_name
        .as_deref()
        .ok_or_else(|| TransferError::XotConfig {
            addr: primary.addr,
            message: "server_name is required".to_owned(),
        })?;
    ServerName::try_from(server_name.to_owned()).map_err(|error| TransferError::XotConfig {
        addr: primary.addr,
        message: format!("invalid XoT server_name {server_name:?}: {error}"),
    })?;
    build_xot_client_config(primary).map(|_| ())
}
