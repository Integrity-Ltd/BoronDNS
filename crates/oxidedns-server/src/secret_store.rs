use std::{
    collections::HashMap,
    fmt, fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use oxidedns_core::{
    ServerConfig,
    config::{ConfigSecretString, TransferPrimaryConfig, TransferTransportConfig},
    dns::DomainName,
    tsig::TsigKey,
};
use serde::{Deserialize, Deserializer};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::transfer::build_xot_client_config;

#[derive(Debug, Error)]
pub(crate) enum SecretStoreError {
    #[error("failed to read secret-store manifest {path}: {source}")]
    ReadManifest {
        path: String,
        source: std::io::Error,
    },

    #[error("failed to parse secret-store manifest {path}: {source}")]
    ParseManifest {
        path: String,
        source: toml::de::Error,
    },

    #[error("failed to read secret-store file {path}: {source}")]
    ReadSecretFile {
        path: String,
        source: std::io::Error,
    },

    #[error("invalid secret-store snapshot: {0}")]
    Invalid(String),
}

pub(crate) trait SecretStore: Send + Sync {
    fn load_snapshot(&self) -> Result<SecretSnapshot, SecretStoreError>;
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SecretSnapshot {
    tsig_keys_by_name: HashMap<String, Arc<TsigKey>>,
    xot_profiles_by_name: HashMap<String, XotSecretProfile>,
}

impl SecretSnapshot {
    fn with_static_tsig_keys(config: &ServerConfig) -> Result<Self, SecretStoreError> {
        let mut snapshot = Self::default();
        for key in &config.tsig_keys {
            let secret = key.secret_base64().map_err(|error| {
                SecretStoreError::Invalid(format!("invalid static TSIG key {}: {error}", key.name))
            })?;
            let key =
                TsigKey::from_base64(&key.name, &key.algorithm, &secret).map_err(|error| {
                    SecretStoreError::Invalid(format!(
                        "invalid static TSIG key {}: {error}",
                        key.name
                    ))
                })?;
            let key_name = key.name.clone();
            if snapshot
                .tsig_keys_by_name
                .insert(key.name.canonical_key(), Arc::new(key))
                .is_some()
            {
                return Err(SecretStoreError::Invalid(format!(
                    "duplicate static TSIG key {}",
                    key_name
                )));
            }
        }
        Ok(snapshot)
    }

    fn merge_runtime(&self, runtime: Self) -> Result<Self, SecretStoreError> {
        let mut merged = self.clone();
        for (name, key) in runtime.tsig_keys_by_name {
            merged.tsig_keys_by_name.insert(name, key);
        }
        for (name, profile) in runtime.xot_profiles_by_name {
            merged.xot_profiles_by_name.insert(name, profile);
        }
        Ok(merged)
    }

    pub(crate) fn tsig_key(&self, name: &DomainName) -> Option<Arc<TsigKey>> {
        self.tsig_keys_by_name.get(&name.canonical_key()).cloned()
    }

    pub(crate) fn xot_profile(&self, name: &str) -> Option<XotSecretProfile> {
        self.xot_profiles_by_name.get(name).cloned()
    }

    fn tsig_key_count(&self) -> usize {
        self.tsig_keys_by_name.len()
    }

    fn xot_profile_count(&self) -> usize {
        self.xot_profiles_by_name.len()
    }

    fn validate_configured_references(
        &self,
        references: &SecretReferenceSet,
    ) -> Result<(), SecretStoreError> {
        for reference in &references.tsig_keys {
            let key_name = DomainName::from_absolute_str(&reference.key_name).map_err(|_| {
                SecretStoreError::Invalid(format!(
                    "{} {} references invalid TSIG key name {}",
                    reference.field, reference.zone_name, reference.key_name
                ))
            })?;
            if self.tsig_key(&key_name).is_none() {
                return Err(SecretStoreError::Invalid(format!(
                    "{} {} references TSIG key {}, but no static or secret-store snapshot key is loaded",
                    reference.field, reference.zone_name, reference.key_name
                )));
            }
        }
        for reference in &references.xot_profiles {
            if self.xot_profile(&reference.profile_name).is_none() {
                return Err(SecretStoreError::Invalid(format!(
                    "{} {} references XoT profile {}, but no secret-store snapshot profile is loaded",
                    reference.scope, reference.zone_name, reference.profile_name
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct SecretReferenceSet {
    tsig_keys: Vec<SecretTsigReference>,
    xot_profiles: Vec<SecretXotReference>,
}

impl SecretReferenceSet {
    fn from_config(config: &ServerConfig) -> Self {
        let mut references = Self::default();
        for zone in &config.zones {
            if let Some(tsig_key) = &zone.tsig_key {
                references.tsig_keys.push(SecretTsigReference {
                    field: "zone".to_owned(),
                    zone_name: zone.name.clone(),
                    key_name: tsig_key.clone(),
                });
            }
            for primary in zone.transfer_targets() {
                references.add_xot_profile("zone", &zone.name, &primary);
            }
        }
        for catalog in &config.catalog_zones {
            for (field, tsig_key) in catalog.tsig_key_references_for_runtime() {
                references.tsig_keys.push(SecretTsigReference {
                    field: field.to_owned(),
                    zone_name: catalog.name.clone(),
                    key_name: tsig_key.to_owned(),
                });
            }
            for primary in catalog.all_transfer_targets() {
                references.add_xot_profile("catalog zone", &catalog.name, &primary);
            }
        }
        references
    }

    fn add_xot_profile(&mut self, scope: &str, zone_name: &str, primary: &TransferPrimaryConfig) {
        if let Some(profile_name) = primary.xot_profile.as_deref() {
            self.xot_profiles.push(SecretXotReference {
                scope: scope.to_owned(),
                zone_name: zone_name.to_owned(),
                profile_name: profile_name.to_owned(),
            });
        }
    }
}

#[derive(Clone, Debug)]
struct SecretTsigReference {
    field: String,
    zone_name: String,
    key_name: String,
}

#[derive(Clone, Debug)]
struct SecretXotReference {
    scope: String,
    zone_name: String,
    profile_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct XotSecretProfile {
    pub(crate) trust_anchors: Vec<String>,
    pub(crate) client_cert: Option<String>,
    pub(crate) client_key: Option<String>,
    pub(crate) client_key_pem: Option<SecretString>,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    pub(crate) fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|secret| Self(Zeroizing::new(secret)))
    }
}

#[derive(Clone)]
pub(crate) struct SecretManager {
    static_snapshot: Arc<SecretSnapshot>,
    store: Option<Arc<dyn SecretStore>>,
    snapshot: Arc<RwLock<Arc<SecretSnapshot>>>,
    configured_references: Arc<SecretReferenceSet>,
}

impl fmt::Debug for SecretManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (tsig_keys, xot_profiles) = self.snapshot_counts();
        formatter
            .debug_struct("SecretManager")
            .field("store_configured", &self.store.is_some())
            .field("tsig_keys", &tsig_keys)
            .field("xot_profiles", &xot_profiles)
            .finish()
    }
}

impl SecretManager {
    pub(crate) fn empty_for_test() -> Self {
        let snapshot = Arc::new(SecretSnapshot::default());
        Self {
            static_snapshot: snapshot.clone(),
            store: None,
            snapshot: Arc::new(RwLock::new(snapshot)),
            configured_references: Arc::new(SecretReferenceSet::default()),
        }
    }

    pub(crate) fn from_config(config: &ServerConfig) -> Result<Self, SecretStoreError> {
        let static_snapshot = Arc::new(SecretSnapshot::with_static_tsig_keys(config)?);
        let configured_references = Arc::new(SecretReferenceSet::from_config(config));
        let store = config
            .secret_store
            .path
            .as_ref()
            .map(|path| Arc::new(FileSecretStore::new(path.clone())) as Arc<dyn SecretStore>);
        let initial = if let Some(store) = &store {
            Arc::new(static_snapshot.merge_runtime(store.load_snapshot()?)?)
        } else {
            static_snapshot.clone()
        };
        let manager = Self {
            static_snapshot,
            store,
            snapshot: Arc::new(RwLock::new(initial)),
            configured_references,
        };
        {
            let snapshot = manager.snapshot.read().map_err(|_| {
                SecretStoreError::Invalid("secret snapshot lock poisoned".to_owned())
            })?;
            snapshot.validate_configured_references(&manager.configured_references)?;
        }
        Ok(manager)
    }

    pub(crate) fn reload(&self) -> Result<(), SecretStoreError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let runtime = store.load_snapshot()?;
        let merged = Arc::new(self.static_snapshot.merge_runtime(runtime)?);
        merged.validate_configured_references(&self.configured_references)?;
        let mut current = self
            .snapshot
            .write()
            .map_err(|_| SecretStoreError::Invalid("secret snapshot lock poisoned".to_owned()))?;
        *current = merged;
        Ok(())
    }

    pub(crate) fn tsig_key(&self, name: &DomainName) -> Option<Arc<TsigKey>> {
        self.snapshot
            .read()
            .ok()
            .and_then(|snapshot| snapshot.tsig_key(name))
    }

    pub(crate) fn xot_profile(&self, name: &str) -> Option<XotSecretProfile> {
        self.snapshot
            .read()
            .ok()
            .and_then(|snapshot| snapshot.xot_profile(name))
    }

    pub(crate) fn snapshot_counts(&self) -> (usize, usize) {
        self.snapshot
            .read()
            .map(|snapshot| (snapshot.tsig_key_count(), snapshot.xot_profile_count()))
            .unwrap_or((0, 0))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FileSecretStore {
    root: PathBuf,
}

impl FileSecretStore {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join("secrets.toml")
    }
}

impl SecretStore for FileSecretStore {
    fn load_snapshot(&self) -> Result<SecretSnapshot, SecretStoreError> {
        let manifest_path = self.manifest_path();
        validate_manifest_file_mode(&manifest_path)?;
        let manifest_text = fs::read_to_string(&manifest_path).map_err(|source| {
            SecretStoreError::ReadManifest {
                path: manifest_path.display().to_string(),
                source,
            }
        })?;
        let manifest_text = Zeroizing::new(manifest_text);
        let manifest =
            toml::from_str::<FileSecretManifest>(manifest_text.as_str()).map_err(|source| {
                SecretStoreError::ParseManifest {
                    path: manifest_path.display().to_string(),
                    source,
                }
            })?;
        manifest.into_snapshot(&self.root)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSecretManifest {
    #[serde(default)]
    tsig_keys: Vec<FileTsigKey>,
    #[serde(default)]
    xot_profiles: Vec<FileXotProfile>,
}

impl FileSecretManifest {
    fn into_snapshot(self, root: &Path) -> Result<SecretSnapshot, SecretStoreError> {
        let mut snapshot = SecretSnapshot::default();
        for mut key in self.tsig_keys {
            let secret = key.secret_base64(root)?;
            let parsed =
                TsigKey::from_base64(&key.name, &key.algorithm, &secret).map_err(|error| {
                    SecretStoreError::Invalid(format!(
                        "invalid secret-store TSIG key {}: {error}",
                        key.name
                    ))
                })?;
            if snapshot
                .tsig_keys_by_name
                .insert(parsed.name.canonical_key(), Arc::new(parsed))
                .is_some()
            {
                return Err(SecretStoreError::Invalid(format!(
                    "duplicate secret-store TSIG key {}",
                    key.name
                )));
            }
        }
        for profile in self.xot_profiles {
            if profile.name.trim().is_empty() {
                return Err(SecretStoreError::Invalid(
                    "secret-store XoT profile name must not be empty".to_owned(),
                ));
            }
            if profile.trust_anchors.is_empty() {
                return Err(SecretStoreError::Invalid(format!(
                    "secret-store XoT profile {} requires at least one trust anchor",
                    profile.name
                )));
            }
            let name = profile.name.clone();
            if snapshot
                .xot_profiles_by_name
                .insert(name.clone(), profile.into_secret_profile(root)?)
                .is_some()
            {
                return Err(SecretStoreError::Invalid(format!(
                    "duplicate secret-store XoT profile {name}"
                )));
            }
        }
        Ok(snapshot)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTsigKey {
    name: String,
    algorithm: String,
    #[serde(default)]
    secret: Option<SecretString>,
    #[serde(default)]
    secret_file: Option<PathBuf>,
}

impl FileTsigKey {
    fn secret_base64(&mut self, root: &Path) -> Result<Zeroizing<String>, SecretStoreError> {
        match (self.secret.take(), &self.secret_file) {
            (Some(secret), None) => Ok(Zeroizing::new(secret.expose_secret().trim().to_owned())),
            (None, Some(path)) => read_store_text_file(root, path)
                .map(|secret| Zeroizing::new(secret.trim().to_owned())),
            (Some(_secret), Some(_)) => Err(SecretStoreError::Invalid(format!(
                "secret-store TSIG key {} must set exactly one of secret or secret_file",
                self.name
            ))),
            (None, None) => Err(SecretStoreError::Invalid(format!(
                "secret-store TSIG key {} must set exactly one of secret or secret_file",
                self.name
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileXotProfile {
    name: String,
    #[serde(default)]
    trust_anchors: Vec<PathBuf>,
    #[serde(default)]
    client_cert: Option<PathBuf>,
    #[serde(default)]
    client_key: Option<PathBuf>,
    #[serde(default)]
    client_key_pem: Option<SecretString>,
}

impl FileXotProfile {
    fn into_secret_profile(self, root: &Path) -> Result<XotSecretProfile, SecretStoreError> {
        let trust_anchors = self
            .trust_anchors
            .iter()
            .map(|path| resolve_store_path(root, path))
            .collect::<Result<Vec<_>, _>>()?;
        let client_cert = self
            .client_cert
            .as_ref()
            .map(|path| resolve_store_path(root, path))
            .transpose()?;
        let client_key = self
            .client_key
            .as_ref()
            .map(|path| resolve_store_path(root, path))
            .transpose()?;
        match (&client_cert, &client_key, &self.client_key_pem) {
            (Some(_), Some(_), None) | (Some(_), None, Some(_)) | (None, None, None) => {}
            (Some(_), Some(_), Some(_)) => {
                return Err(SecretStoreError::Invalid(format!(
                    "secret-store XoT profile {} must set exactly one of client_key or client_key_pem",
                    self.name
                )));
            }
            _ => {
                return Err(SecretStoreError::Invalid(format!(
                    "secret-store XoT profile {} requires client_cert and exactly one of client_key or client_key_pem together",
                    self.name
                )));
            }
        }
        let profile = XotSecretProfile {
            trust_anchors,
            client_cert,
            client_key,
            client_key_pem: self.client_key_pem,
        };
        validate_xot_profile_material(&self.name, &profile)?;
        Ok(profile)
    }
}

fn validate_xot_profile_material(
    name: &str,
    profile: &XotSecretProfile,
) -> Result<(), SecretStoreError> {
    let primary = TransferPrimaryConfig {
        addr: std::net::SocketAddr::from(([127, 0, 0, 1], 853)),
        transport: TransferTransportConfig::Xot,
        server_name: Some("secret-store-validation.example".to_owned()),
        xot_profile: None,
        trust_anchors: profile.trust_anchors.clone(),
        client_cert: profile.client_cert.clone(),
        client_key: profile.client_key.clone(),
        client_key_pem: profile
            .client_key_pem
            .as_ref()
            .map(|secret| ConfigSecretString::from_plaintext(secret.expose_secret())),
    };
    build_xot_client_config(&primary)
        .map(|_| ())
        .map_err(|error| {
            SecretStoreError::Invalid(format!("invalid secret-store XoT profile {name}: {error}"))
        })
}

fn read_store_text_file(
    root: &Path,
    relative: &Path,
) -> Result<Zeroizing<String>, SecretStoreError> {
    let path = resolve_store_path(root, relative)?;
    validate_secret_file_mode(&path)?;
    fs::read_to_string(&path)
        .map(Zeroizing::new)
        .map_err(|source| SecretStoreError::ReadSecretFile { path, source })
}

fn resolve_store_path(root: &Path, path: &Path) -> Result<String, SecretStoreError> {
    if path.as_os_str().is_empty() {
        return Err(SecretStoreError::Invalid(
            "secret-store file path must not be empty".to_owned(),
        ));
    }
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    Ok(resolved.display().to_string())
}

#[cfg(unix)]
fn validate_manifest_file_mode(path: &Path) -> Result<(), SecretStoreError> {
    use std::os::unix::fs::PermissionsExt;

    let path_text = path.display().to_string();
    let metadata = fs::metadata(path).map_err(|source| SecretStoreError::ReadManifest {
        path: path_text.clone(),
        source,
    })?;
    if metadata.permissions().mode() & 0o004 != 0 {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store manifest {path_text:?} must not be world-readable"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_manifest_file_mode(_path: &Path) -> Result<(), SecretStoreError> {
    Ok(())
}

#[cfg(unix)]
fn validate_secret_file_mode(path: &str) -> Result<(), SecretStoreError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|source| SecretStoreError::ReadSecretFile {
        path: path.to_owned(),
        source,
    })?;
    if metadata.permissions().mode() & 0o004 != 0 {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store secret file {path:?} must not be world-readable"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_file_mode(_path: &str) -> Result<(), SecretStoreError> {
    Ok(())
}
