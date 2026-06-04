use std::time::{SystemTime, UNIX_EPOCH};

use oxidedns_core::{
    ConfigWarning, ServerConfig,
    config::{TransferPrimaryConfig, TransferTransportConfig},
};
use tokio_rustls::rustls::pki_types::ServerName;
use x509_parser::parse_x509_certificate;

use crate::{
    RuntimeError, TransferError, build_xot_client_config, load_pem_certs_for_primary,
    resource_limits,
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
    runtime_config_warnings_at(config, current_unix_time_secs_i64())
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn runtime_config_warnings_at(
    config: &ServerConfig,
    now_unix_secs: i64,
) -> Result<Vec<ConfigWarning>, TransferError> {
    let mut warnings = Vec::new();
    for (zone_name, primary) in transfer_targets_with_names(config) {
        if primary.transport != TransferTransportConfig::Xot {
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
    2 * (tcp_connections + outbound_transfers + 100)
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
        for (index, cert) in certs.iter().enumerate() {
            let (_, parsed) = parse_x509_certificate(cert.as_ref()).map_err(|error| {
                TransferError::XotConfig {
                    addr: primary.addr,
                    message: format!(
                        "failed to parse trust anchor certificate {trust_anchor:?}: {error}"
                    ),
                }
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
    }
    Ok(warnings)
}

fn current_unix_time_secs_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or_default()
}

fn validate_xot_transfer_target(primary: &TransferPrimaryConfig) -> Result<(), TransferError> {
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
