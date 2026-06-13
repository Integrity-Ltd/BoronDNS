use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::http::{HeaderMap, header};
use oxidedns_core::config::{
    ObservabilityConfig, ServerConfig, TransferPrimaryConfig, TransferTransportConfig,
};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::parse_x509_certificate;

use crate::{resource_limits, transfer::load_pem_certs};

#[derive(Clone, Debug, Default)]
pub(crate) struct ObservabilityAuth {
    bearer_token: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservabilityAuthError {
    Missing,
    Invalid,
}

impl ObservabilityAuth {
    pub(crate) fn from_config(config: &ObservabilityConfig) -> Result<Self, std::io::Error> {
        let Some(path) = config.bearer_token_file.as_deref() else {
            return Ok(Self::default());
        };
        let token = fs::read(path)?;
        let token = trim_ascii_whitespace(&token).to_vec();
        Ok(Self {
            bearer_token: Some(token),
        })
    }

    pub(crate) fn is_configured(&self) -> bool {
        self.bearer_token.is_some()
    }

    pub(crate) fn authorize(&self, headers: &HeaderMap) -> Result<(), ObservabilityAuthError> {
        let Some(expected) = self.bearer_token.as_deref() else {
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
        if expected.len() == actual.len() && expected.ct_eq(actual).into() {
            Ok(())
        } else {
            Err(ObservabilityAuthError::Invalid)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransferMaterial {
    pub(crate) scope: &'static str,
    pub(crate) zone: String,
    pub(crate) primary: String,
    pub(crate) transport: &'static str,
    pub(crate) server_name: Option<String>,
    pub(crate) trust_anchors: Vec<String>,
    pub(crate) client_cert: Option<String>,
    pub(crate) client_key_configured: bool,
    pub(crate) inline_client_key_configured: bool,
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
            trust_anchors: primary.trust_anchors.clone(),
            client_cert: primary.client_cert.clone(),
            client_key_configured: primary.client_key.is_some(),
            inline_client_key_configured: primary.client_key_pem.is_some(),
        }
    }
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
    certs
        .iter()
        .enumerate()
        .map(|(index, cert)| certificate_value(material, role, &path_text, index, cert))
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
