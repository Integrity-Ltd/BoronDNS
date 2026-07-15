use std::{
    fmt, fs,
    fs::File,
    io::{Error, ErrorKind, Read},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use axum::http::{HeaderMap, header};
use oxidedns_core::config::{
    ObservabilityConfig, ServerConfig, TransferPrimaryConfig, TransferTransportConfig,
    open_readonly_no_follow,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

use crate::{resource_limits, secret_store::SecretSnapshot, transfer::load_pem_certs};

/// Maximum bearer token file size accepted by the management API. HTTP
/// authorization tokens are expected to be short and must fit comfortably in
/// ordinary request-header limits; 8 KiB prevents configuration-driven
/// startup allocation without constraining practical token formats.
pub(crate) const MAX_OBSERVABILITY_BEARER_TOKEN_BYTES: usize = 8 * 1024;

#[derive(Clone, Default)]
pub(crate) struct ObservabilityAuth {
    bearer_token_digest: Option<Arc<Zeroizing<[u8; 32]>>>,
}

impl fmt::Debug for ObservabilityAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservabilityAuth")
            .field(
                "bearer_token_configured",
                &self.bearer_token_digest.is_some(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservabilityAuthError {
    Missing,
    Invalid,
}

impl ObservabilityAuth {
    pub(crate) fn from_config(config: &ObservabilityConfig) -> Result<Self, std::io::Error> {
        Self::from_config_with_hook(config, || {}).map(|(auth, _)| auth)
    }

    fn from_config_with_hook(
        config: &ObservabilityConfig,
        after_open: impl FnOnce(),
    ) -> Result<(Self, usize), std::io::Error> {
        let Some(path) = config.bearer_token_file.as_deref() else {
            return Ok((Self::default(), 0));
        };
        let mut file = open_token_file(path)?;
        after_open();
        let mut token = Zeroizing::new(Vec::new());
        file.by_ref()
            .take((MAX_OBSERVABILITY_BEARER_TOKEN_BYTES + 1) as u64)
            .read_to_end(&mut token)?;
        if token.len() > MAX_OBSERVABILITY_BEARER_TOKEN_BYTES {
            return Err(token_size_error(path));
        }
        let token = trim_ascii_whitespace(&token);
        if token.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("observability bearer token file {path:?} must not be empty"),
            ));
        }
        let token_len = token.len();
        let digest = <[u8; 32]>::from(Sha256::digest(token));
        Ok((
            Self {
                bearer_token_digest: Some(Arc::new(Zeroizing::new(digest))),
            },
            token_len,
        ))
    }

    pub(crate) fn is_configured(&self) -> bool {
        self.bearer_token_digest.is_some()
    }

    pub(crate) fn authorize(&self, headers: &HeaderMap) -> Result<(), ObservabilityAuthError> {
        let Some(expected) = self.bearer_token_digest.as_deref() else {
            return Ok(());
        };
        let Some(actual) = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::as_bytes)
        else {
            return Err(ObservabilityAuthError::Missing);
        };
        let actual_digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(actual)));
        if bool::from(expected[..].ct_eq(&actual_digest[..])) {
            Ok(())
        } else {
            Err(ObservabilityAuthError::Invalid)
        }
    }
}

#[cfg(test)]
pub(crate) fn observability_token_len_after_open_for_test(
    path: &Path,
    after_open: impl FnOnce(),
) -> Result<usize, Error> {
    let config = ObservabilityConfig {
        bearer_token_file: Some(path.to_owned()),
        ..ObservabilityConfig::default()
    };
    ObservabilityAuth::from_config_with_hook(&config, after_open).map(|(_, token_len)| token_len)
}

fn token_size_error(path: &Path) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!(
            "observability bearer token file {path:?} exceeds {MAX_OBSERVABILITY_BEARER_TOKEN_BYTES} byte limit"
        ),
    )
}

fn open_token_file(path: &Path) -> Result<File, Error> {
    let file = open_readonly_no_follow(path)?;
    validate_token_file(&file, path)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_token_file(file: &File, path: &Path) -> Result<(), Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("observability bearer token file {path:?} must be a regular file"),
        ));
    }
    if metadata.len() > MAX_OBSERVABILITY_BEARER_TOKEN_BYTES as u64 {
        return Err(token_size_error(path));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "observability bearer token file {path:?} must not be accessible by group or other users"
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_token_file(file: &File, path: &Path) -> Result<(), Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("observability bearer token file {path:?} must be a regular file"),
        ));
    }
    if metadata.len() > MAX_OBSERVABILITY_BEARER_TOKEN_BYTES as u64 {
        return Err(token_size_error(path));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransferMaterial {
    pub(crate) scope: &'static str,
    pub(crate) zone: String,
    pub(crate) primary: String,
    pub(crate) transport: &'static str,
    pub(crate) server_name: Option<String>,
    pub(crate) xot_profile: Option<String>,
    pub(crate) trust_anchors: Vec<String>,
    pub(crate) client_cert: Option<String>,
    pub(crate) client_key_configured: bool,
    pub(crate) inline_client_key_configured: bool,
    pub(crate) snapshot_certificates: Option<Vec<SnapshotCertificateMaterial>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SnapshotCertificateMaterial {
    role: &'static str,
    path: String,
    certificates: Arc<[CertificateDer<'static>]>,
}

impl TransferMaterial {
    pub(crate) fn from_config(config: &ServerConfig) -> Vec<Self> {
        let mut materials = Vec::new();
        for zone in &config.zones {
            materials.extend(
                zone.transfer_primaries
                    .iter()
                    .map(|primary| Self::from_primary("zone", &zone.name, primary)),
            );
        }
        for catalog in &config.catalog_zones {
            materials.extend(
                catalog
                    .catalog_transfer_targets()
                    .iter()
                    .map(|primary| Self::from_primary("catalog_zone", &catalog.name, primary)),
            );
            materials.extend(
                catalog
                    .member_transfer_targets()
                    .iter()
                    .map(|primary| Self::from_primary("catalog_member", &catalog.name, primary)),
            );
        }
        materials
    }

    fn from_primary(scope: &'static str, zone: &str, primary: &TransferPrimaryConfig) -> Self {
        Self {
            scope,
            zone: zone.to_owned(),
            primary: primary.addr.to_string(),
            transport: match primary.transport {
                TransferTransportConfig::Tcp => "tcp",
                TransferTransportConfig::Xot => "xot",
            },
            server_name: primary.server_name.clone(),
            xot_profile: primary.xot_profile.clone(),
            trust_anchors: primary.trust_anchors.clone(),
            client_cert: primary.client_cert.clone(),
            client_key_configured: primary.client_key.is_some(),
            inline_client_key_configured: primary.client_key_pem.is_some(),
            snapshot_certificates: None,
        }
    }

    pub(crate) fn resolved_from_snapshot(&self, snapshot: &SecretSnapshot) -> Self {
        let Some(profile_name) = self.xot_profile.as_deref() else {
            return self.clone();
        };
        let Some(profile) = snapshot.xot_profile(profile_name) else {
            return self.clone();
        };
        let mut resolved = self.clone();
        resolved.trust_anchors = profile.trust_anchors;
        resolved.client_cert = profile.client_cert;
        resolved.client_key_configured = profile.client_key.is_some();
        resolved.inline_client_key_configured = profile.client_key_pem.is_some();
        let mut certificates = profile
            .trust_anchor_certificates
            .into_iter()
            .map(|file| SnapshotCertificateMaterial {
                role: "trust_anchor",
                path: file.path,
                certificates: file.certificates,
            })
            .collect::<Vec<_>>();
        if let Some(file) = profile.client_certificate {
            certificates.push(SnapshotCertificateMaterial {
                role: "client_certificate",
                path: file.path,
                certificates: file.certificates,
            });
        }
        resolved.snapshot_certificates = Some(certificates);
        resolved
    }
}

pub(crate) fn resolve_transfer_materials_from_snapshot(
    materials: &[TransferMaterial],
    snapshot: &SecretSnapshot,
) -> Vec<TransferMaterial> {
    materials
        .iter()
        .map(|material| material.resolved_from_snapshot(snapshot))
        .collect()
}

pub(crate) fn filesystem_observability_value() -> Value {
    let root = filesystem_df_value("/");
    let fd_limit = process_fd_limit();
    json!({
        "status": if root["status"] == "ok" { "ok" } else { "partial" },
        "root": root,
        "file_descriptor_limit": fd_limit,
    })
}

pub(crate) fn process_resources_observability_value() -> Value {
    let status = parse_proc_status();
    let fd_count = fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count());
    let cpu = parse_proc_stat();
    json!({
        "status": if status.is_object() || fd_count.is_some() || cpu.is_object() { "ok" } else { "unknown" },
        "pid": std::process::id(),
        "threads": status["threads"].clone(),
        "memory": status["memory"].clone(),
        "file_descriptors_open": fd_count,
        "cpu": cpu,
    })
}

fn filesystem_df_value(path: &str) -> Value {
    match resource_limits::filesystem_stats(path) {
        Ok(stats) => json!({
            "status": "ok",
            "path": path,
            "source": "statvfs",
            "total_bytes": stats.total_bytes,
            "free_bytes": stats.free_bytes,
            "available_bytes": stats.available_bytes,
            "files_total": stats.files_total,
            "files_free": stats.files_free,
        }),
        Err(error) => json!({
            "status": "unknown",
            "path": path,
            "source": "statvfs",
            "error": error.to_string(),
        }),
    }
}

fn process_fd_limit() -> Value {
    let Ok(limits) = fs::read_to_string("/proc/self/limits") else {
        return json!({"status": "unknown"});
    };
    for line in limits.lines() {
        if let Some(rest) = line.strip_prefix("Max open files") {
            let fields = rest.split_whitespace().collect::<Vec<_>>();
            return json!({
                "status": "ok",
                "soft": fields.first().copied().unwrap_or("unknown"),
                "hard": fields.get(1).copied().unwrap_or("unknown"),
            });
        }
    }
    json!({"status": "unknown"})
}

fn parse_proc_status() -> Value {
    let Ok(text) = fs::read_to_string("/proc/self/status") else {
        return json!({});
    };
    let mut threads = None;
    let mut vm_rss_kib = None;
    let mut vm_size_kib = None;
    let mut vm_data_kib = None;
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let first_number = value
            .split_whitespace()
            .next()
            .and_then(|number| number.parse::<u64>().ok());
        match name {
            "Threads" => threads = first_number,
            "VmRSS" => vm_rss_kib = first_number,
            "VmSize" => vm_size_kib = first_number,
            "VmData" => vm_data_kib = first_number,
            _ => {}
        }
    }
    json!({
        "threads": threads,
        "memory": {
            "rss_bytes": vm_rss_kib.map(kib_to_bytes),
            "virtual_bytes": vm_size_kib.map(kib_to_bytes),
            "data_bytes": vm_data_kib.map(kib_to_bytes),
        }
    })
}

fn parse_proc_stat() -> Value {
    let Ok(text) = fs::read_to_string("/proc/self/stat") else {
        return json!({});
    };
    let Some(end_comm) = text.rfind(") ") else {
        return json!({});
    };
    let fields = text[end_comm + 2..].split_whitespace().collect::<Vec<_>>();
    json!({
        "user_ticks": fields.get(11).and_then(|value| value.parse::<u64>().ok()),
        "system_ticks": fields.get(12).and_then(|value| value.parse::<u64>().ok()),
    })
}

fn kib_to_bytes(kib: u64) -> u64 {
    kib.saturating_mul(1024)
}

pub(crate) fn time_sync_observability_value() -> Value {
    json!({
        "status": "unknown",
        "source": "unavailable",
        "checked": [],
    })
}

pub(crate) fn certificate_observability_value(materials: &[TransferMaterial]) -> Value {
    let certificates = materials
        .iter()
        .flat_map(certificate_material_values)
        .collect::<Vec<_>>();
    let expiring_within_30_days = certificates
        .iter()
        .filter(|entry| entry["status"] == "expiring_soon")
        .count();
    let expired = certificates
        .iter()
        .filter(|entry| entry["status"] == "expired")
        .count();
    let errors = certificates
        .iter()
        .filter(|entry| entry["status"] == "error")
        .count();
    json!({
        "status": if errors > 0 { "partial" } else { "ok" },
        "configured_materials": materials.len(),
        "certificates": certificates,
        "summary": {
            "expired": expired,
            "expiring_within_30_days": expiring_within_30_days,
            "errors": errors,
        }
    })
}

fn certificate_material_values(material: &TransferMaterial) -> Vec<Value> {
    if let Some(certificates) = material.snapshot_certificates.as_ref() {
        return certificates
            .iter()
            .flat_map(|source| {
                certificate_values(
                    material,
                    source.role,
                    &source.path,
                    source.certificates.as_ref(),
                )
            })
            .collect();
    }
    let mut values = Vec::new();
    for trust_anchor in &material.trust_anchors {
        values.extend(certificate_file_values(
            material,
            "trust_anchor",
            Path::new(trust_anchor),
        ));
    }
    if let Some(client_cert) = material.client_cert.as_deref() {
        values.extend(certificate_file_values(
            material,
            "client_certificate",
            Path::new(client_cert),
        ));
    }
    values
}

fn certificate_file_values(
    material: &TransferMaterial,
    role: &'static str,
    path: &Path,
) -> Vec<Value> {
    let path_text = path.display().to_string();
    let certs = match load_pem_certs(&path_text) {
        Ok(certs) => certs,
        Err(error) => {
            return vec![json!({
                "status": "error",
                "role": role,
                "scope": material.scope,
                "zone": material.zone,
                "primary": material.primary,
                "path": path_text,
                "error": error.to_string(),
            })];
        }
    };
    if certs.is_empty() {
        return vec![json!({
            "status": "error",
            "role": role,
            "scope": material.scope,
            "zone": material.zone,
            "primary": material.primary,
            "path": path_text,
            "error": "certificate file did not contain certificates",
        })];
    }
    certificate_values(material, role, &path_text, &certs)
}

fn certificate_values(
    material: &TransferMaterial,
    role: &'static str,
    path: &str,
    certs: &[CertificateDer<'_>],
) -> Vec<Value> {
    if certs.is_empty() {
        return vec![json!({
            "status": "error",
            "role": role,
            "scope": material.scope,
            "zone": material.zone,
            "primary": material.primary,
            "path": path,
            "error": "certificate file did not contain certificates",
        })];
    }
    certs
        .iter()
        .enumerate()
        .map(|(index, cert)| certificate_value(material, role, path, index, cert))
        .collect()
}

fn certificate_value(
    material: &TransferMaterial,
    role: &'static str,
    path: &str,
    index: usize,
    cert: &CertificateDer<'_>,
) -> Value {
    let now = unix_timestamp_seconds_now();
    let (_, parsed) = match parse_x509_certificate(cert.as_ref()) {
        Ok(parsed) => parsed,
        Err(error) => {
            return json!({
                "status": "error",
                "role": role,
                "scope": material.scope,
                "zone": material.zone,
                "primary": material.primary,
                "path": path,
                "index": index,
                "error": error.to_string(),
            });
        }
    };
    let not_before = parsed.validity().not_before.timestamp().max(0) as u64;
    let not_after = parsed.validity().not_after.timestamp().max(0) as u64;
    let status = if not_after <= now {
        "expired"
    } else if not_after.saturating_sub(now) <= 30 * 24 * 60 * 60 {
        "expiring_soon"
    } else if not_before > now {
        "not_yet_valid"
    } else {
        "ok"
    };
    json!({
        "status": status,
        "role": role,
        "scope": material.scope,
        "zone": material.zone,
        "primary": material.primary,
        "server_name": material.server_name,
        "path": path,
        "index": index,
        "subject": parsed.subject().to_string(),
        "issuer": parsed.issuer().to_string(),
        "sha256_fingerprint": format!("{:x}", Sha256::digest(cert.as_ref())),
        "not_before_unix_seconds": not_before,
        "not_after_unix_seconds": not_after,
        "client_key_configured": material.client_key_configured,
        "inline_client_key_configured": material.inline_client_key_configured,
    })
}

pub(crate) fn transfer_material_observability_counts(materials: &[TransferMaterial]) -> Value {
    json!({
        "configured": materials.len(),
        "xot": materials.iter().filter(|material| material.transport == "xot").count(),
        "tcp": materials.iter().filter(|material| material.transport == "tcp").count(),
        "with_client_certificate": materials.iter().filter(|material| material.client_cert.is_some()).count(),
    })
}

pub(crate) fn fraction_value(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

fn unix_timestamp_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn trim_ascii_whitespace(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();
    while start < end && value[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && value[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &value[start..end]
}
