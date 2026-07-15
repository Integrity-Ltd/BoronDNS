use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
    sync::{Arc, RwLock},
};

use oxidedns_core::{
    ConfigParseError, ServerConfig,
    config::{
        MAX_TSIG_DECODED_BYTES_PER_SNAPSHOT, MAX_TSIG_ENCODED_BYTES_PER_SNAPSHOT,
        MAX_TSIG_KEYS_PER_SNAPSHOT, MAX_XOT_PROFILES_PER_SNAPSHOT,
        MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE, MAX_XOT_TLS_MATERIAL_BYTES_PER_SNAPSHOT,
        MAX_XOT_TRUST_ANCHORS_PER_PROFILE, TransferPrimaryConfig,
    },
    dns::DomainName,
    tsig::TsigKey,
};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::watch;
use tokio_rustls::rustls::pki_types::CertificateDer;
use zeroize::Zeroizing;

use crate::transfer::{XotClientConfig, build_xot_client_config_from_pem, parse_pem_certs};

pub(crate) const MAX_SECRET_STORE_MANIFEST_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_SECRET_STORE_MATERIAL_BYTES: usize = 4 * 1024 * 1024;

fn secret_material_fingerprint(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

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
        source: ConfigParseError,
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

#[derive(Clone, Debug)]
pub(crate) struct SecretSnapshot {
    tsig_keys_by_name: HashMap<String, Arc<TsigKey>>,
    xot_profiles_by_name: HashMap<String, XotSecretProfile>,
    material_fingerprints_by_id: HashMap<String, [u8; 32]>,
    provenance_fingerprints_by_id: HashMap<String, [u8; 32]>,
    tsig_material_sizes_by_name: HashMap<String, (usize, usize)>,
    generation: u64,
    cancellation: watch::Sender<bool>,
}

impl Default for SecretSnapshot {
    fn default() -> Self {
        Self {
            tsig_keys_by_name: HashMap::new(),
            xot_profiles_by_name: HashMap::new(),
            material_fingerprints_by_id: HashMap::new(),
            provenance_fingerprints_by_id: HashMap::new(),
            tsig_material_sizes_by_name: HashMap::new(),
            generation: 0,
            cancellation: watch::channel(false).0,
        }
    }
}

impl SecretSnapshot {
    fn with_static_tsig_keys(config: &ServerConfig) -> Result<Self, SecretStoreError> {
        if config.tsig_keys.len() > MAX_TSIG_KEYS_PER_SNAPSHOT {
            return Err(SecretStoreError::Invalid(format!(
                "static snapshot must not contain more than {MAX_TSIG_KEYS_PER_SNAPSHOT} TSIG keys"
            )));
        }
        let mut snapshot = Self::default();
        for key in &config.tsig_keys {
            let encoded_used = snapshot
                .tsig_material_sizes_by_name
                .values()
                .map(|sizes| sizes.0)
                .sum::<usize>();
            let secret = key
                .secret_base64_bounded(
                    MAX_TSIG_ENCODED_BYTES_PER_SNAPSHOT.saturating_sub(encoded_used),
                )
                .map_err(|error| {
                    SecretStoreError::Invalid(format!(
                        "invalid static TSIG key {}: {error}",
                        key.name
                    ))
                })?;
            let decoded_len = decoded_base64_len(secret.as_str());
            let decoded_used = snapshot
                .tsig_material_sizes_by_name
                .values()
                .map(|sizes| sizes.1)
                .sum::<usize>();
            if decoded_used.saturating_add(decoded_len) > MAX_TSIG_DECODED_BYTES_PER_SNAPSHOT {
                return Err(SecretStoreError::Invalid(format!(
                    "aggregate decoded TSIG material exceeds {MAX_TSIG_DECODED_BYTES_PER_SNAPSHOT} byte limit"
                )));
            }
            let key =
                TsigKey::from_base64(&key.name, &key.algorithm, &secret).map_err(|error| {
                    SecretStoreError::Invalid(format!(
                        "invalid static TSIG key {}: {error}",
                        key.name
                    ))
                })?;
            let key_name = key.name.clone();
            let canonical_name = key.name.canonical_key();
            snapshot.material_fingerprints_by_id.insert(
                format!("tsig:{canonical_name}"),
                secret_material_fingerprint(
                    "tsig",
                    &[
                        key.name.canonical_key().as_bytes(),
                        key.algorithm.name().as_bytes(),
                        secret.as_bytes(),
                    ],
                ),
            );
            if snapshot
                .tsig_keys_by_name
                .insert(canonical_name.clone(), Arc::new(key))
                .is_some()
            {
                return Err(SecretStoreError::Invalid(format!(
                    "duplicate static TSIG key {}",
                    key_name
                )));
            }
            snapshot
                .tsig_material_sizes_by_name
                .insert(canonical_name, (secret.len(), decoded_len));
        }
        Ok(snapshot)
    }

    fn merge_runtime(&self, runtime: Self) -> Result<Self, SecretStoreError> {
        let mut merged = self.clone();
        for (name, key) in runtime.tsig_keys_by_name {
            merged.tsig_keys_by_name.insert(name, key);
        }
        for (name, sizes) in runtime.tsig_material_sizes_by_name {
            merged.tsig_material_sizes_by_name.insert(name, sizes);
        }
        for (name, profile) in runtime.xot_profiles_by_name {
            merged.xot_profiles_by_name.insert(name, profile);
        }
        for (id, fingerprint) in runtime.material_fingerprints_by_id {
            merged.material_fingerprints_by_id.insert(id, fingerprint);
        }
        for (id, fingerprint) in runtime.provenance_fingerprints_by_id {
            merged.provenance_fingerprints_by_id.insert(id, fingerprint);
        }
        merged.validate_tsig_material_budget()?;
        Ok(merged)
    }

    pub(crate) fn tsig_key(&self, name: &DomainName) -> Option<Arc<TsigKey>> {
        self.tsig_keys_by_name.get(&name.canonical_key()).cloned()
    }

    fn tsig_key_with_material_identity(
        &self,
        name: &DomainName,
    ) -> Option<(Arc<TsigKey>, [u8; 32])> {
        let canonical_name = name.canonical_key();
        let key = self.tsig_keys_by_name.get(&canonical_name)?.clone();
        let identity = *self
            .material_fingerprints_by_id
            .get(&format!("tsig:{canonical_name}"))?;
        Some((key, identity))
    }

    pub(crate) fn xot_profile(&self, name: &str) -> Option<XotSecretProfile> {
        self.xot_profiles_by_name.get(name).cloned()
    }

    fn tsig_key_count(&self) -> usize {
        self.tsig_keys_by_name.len()
    }

    fn validate_tsig_material_budget(&self) -> Result<(), SecretStoreError> {
        if self.tsig_keys_by_name.len() > MAX_TSIG_KEYS_PER_SNAPSHOT {
            return Err(SecretStoreError::Invalid(format!(
                "merged snapshot must not contain more than {MAX_TSIG_KEYS_PER_SNAPSHOT} TSIG keys"
            )));
        }
        let encoded = self
            .tsig_material_sizes_by_name
            .values()
            .map(|sizes| sizes.0)
            .sum::<usize>();
        if encoded > MAX_TSIG_ENCODED_BYTES_PER_SNAPSHOT {
            return Err(SecretStoreError::Invalid(format!(
                "aggregate encoded TSIG material reaches {encoded} bytes, exceeding {MAX_TSIG_ENCODED_BYTES_PER_SNAPSHOT} byte limit"
            )));
        }
        let decoded = self
            .tsig_material_sizes_by_name
            .values()
            .map(|sizes| sizes.1)
            .sum::<usize>();
        if decoded > MAX_TSIG_DECODED_BYTES_PER_SNAPSHOT {
            return Err(SecretStoreError::Invalid(format!(
                "aggregate decoded TSIG material reaches {decoded} bytes, exceeding {MAX_TSIG_DECODED_BYTES_PER_SNAPSHOT} byte limit"
            )));
        }
        Ok(())
    }

    fn xot_profile_count(&self) -> usize {
        self.xot_profiles_by_name.len()
    }

    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) async fn cancelled(&self) {
        let mut cancellation = self.cancellation.subscribe();
        loop {
            if *cancellation.borrow_and_update() {
                return;
            }
            if cancellation.changed().await.is_err() {
                return;
            }
        }
    }

    fn cancel(&self) {
        self.cancellation.send_replace(true);
    }

    fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self.cancellation = watch::channel(false).0;
        self
    }

    fn has_same_material(&self, other: &Self) -> bool {
        self.material_fingerprints_by_id == other.material_fingerprints_by_id
    }

    fn has_same_provenance(&self, other: &Self) -> bool {
        self.provenance_fingerprints_by_id == other.provenance_fingerprints_by_id
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

#[derive(Clone)]
pub(crate) struct XotSecretProfile {
    pub(crate) trust_anchors: Vec<String>,
    pub(crate) client_cert: Option<String>,
    pub(crate) client_key: Option<String>,
    pub(crate) client_key_pem: Option<SecretString>,
    pub(crate) client_config: XotClientConfig,
    pub(crate) trust_anchor_certificates: Vec<SnapshotCertificateFile>,
    pub(crate) client_certificate: Option<SnapshotCertificateFile>,
    material_fingerprint: [u8; 32],
    provenance_fingerprint: [u8; 32],
}

#[derive(Clone)]
pub(crate) struct SnapshotCertificateFile {
    pub(crate) path: String,
    pub(crate) certificates: Arc<[CertificateDer<'static>]>,
}

impl fmt::Debug for SnapshotCertificateFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotCertificateFile")
            .field("path", &self.path)
            .field("certificate_count", &self.certificates.len())
            .finish()
    }
}

impl fmt::Debug for XotSecretProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XotSecretProfile")
            .field("trust_anchors", &self.trust_anchors)
            .field("client_cert", &self.client_cert)
            .field("client_key", &self.client_key)
            .field(
                "client_key_pem",
                &self.client_key_pem.as_ref().map(|_| "<redacted>"),
            )
            .field("client_config", &"<loaded snapshot material>")
            .field("trust_anchor_certificates", &self.trust_anchor_certificates)
            .field("client_certificate", &self.client_certificate)
            .finish()
    }
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
        let static_snapshot = Arc::new(SecretSnapshot::default());
        let snapshot = Arc::new(SecretSnapshot::default().with_generation(1));
        Self {
            static_snapshot,
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
            static_snapshot.merge_runtime(store.load_snapshot()?)?
        } else {
            static_snapshot.as_ref().clone()
        };
        let initial = Arc::new(initial.with_generation(1));
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
        let merged = self.static_snapshot.merge_runtime(runtime)?;
        merged.validate_configured_references(&self.configured_references)?;
        let mut current = self
            .snapshot
            .write()
            .map_err(|_| SecretStoreError::Invalid("secret snapshot lock poisoned".to_owned()))?;
        if current.has_same_material(&merged) {
            if current.has_same_provenance(&merged) {
                return Ok(());
            }
            // Path-only changes update the snapshot metadata used by
            // observability, but retain the cryptographic generation and its
            // cancellation channel. Transfers resolved from the prior snapshot
            // therefore remain publishable because their effective key and TLS
            // material did not change.
            let mut merged = merged;
            merged.generation = current.generation;
            merged.cancellation = current.cancellation.clone();
            *current = Arc::new(merged);
            return Ok(());
        }
        let next_generation = current.generation.wrapping_add(1).max(1);
        let merged = Arc::new(merged.with_generation(next_generation));
        current.cancel();
        *current = merged;
        Ok(())
    }

    pub(crate) fn tsig_key(&self, name: &DomainName) -> Option<Arc<TsigKey>> {
        self.current_snapshot()
            .ok()
            .and_then(|snapshot| snapshot.tsig_key(name))
    }

    pub(crate) fn tsig_key_with_material_identity(
        &self,
        name: &DomainName,
    ) -> Option<(Arc<TsigKey>, [u8; 32])> {
        self.current_snapshot()
            .ok()
            .and_then(|snapshot| snapshot.tsig_key_with_material_identity(name))
    }

    #[cfg(test)]
    pub(crate) fn xot_profile(&self, name: &str) -> Option<XotSecretProfile> {
        self.current_snapshot()
            .ok()
            .and_then(|snapshot| snapshot.xot_profile(name))
    }

    pub(crate) fn current_snapshot(&self) -> Result<Arc<SecretSnapshot>, SecretStoreError> {
        self.snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .map_err(|_| SecretStoreError::Invalid("secret snapshot lock poisoned".to_owned()))
    }

    pub(crate) fn if_current_snapshot<R>(
        &self,
        candidate: &Arc<SecretSnapshot>,
        action: impl FnOnce() -> R,
    ) -> Option<R> {
        let current = self.snapshot.read().ok()?;
        current
            .cancellation
            .same_channel(&candidate.cancellation)
            .then(action)
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

    fn load_from_opened_root(
        &self,
        root: &OpenedSecretRoot,
    ) -> Result<SecretSnapshot, SecretStoreError> {
        self.load_from_opened_root_with_manifest_hook(root, || {})
    }

    fn load_from_opened_root_with_manifest_hook(
        &self,
        root: &OpenedSecretRoot,
        after_manifest_open: impl FnOnce(),
    ) -> Result<SecretSnapshot, SecretStoreError> {
        let manifest_path = self.manifest_path();
        let mut manifest_file = root.open_manifest()?;
        after_manifest_open();
        // The manifest may contain inline TSIG secrets and XoT private keys.
        // Own the bytes under Zeroizing before the first read so I/O errors,
        // invalid UTF-8, size rejection, and TOML parse failures all scrub the
        // allocation on exit.
        let mut manifest_bytes = Zeroizing::new(Vec::new());
        manifest_file
            .by_ref()
            .take((MAX_SECRET_STORE_MANIFEST_BYTES + 1) as u64)
            .read_to_end(&mut manifest_bytes)
            .map_err(|source| SecretStoreError::ReadManifest {
                path: manifest_path.display().to_string(),
                source,
            })?;
        if manifest_bytes.len() > MAX_SECRET_STORE_MANIFEST_BYTES {
            return Err(SecretStoreError::Invalid(format!(
                "secret-store manifest {:?} exceeds {} byte limit",
                manifest_path, MAX_SECRET_STORE_MANIFEST_BYTES
            )));
        }
        let manifest_text = std::str::from_utf8(manifest_bytes.as_slice()).map_err(|source| {
            SecretStoreError::ReadManifest {
                path: manifest_path.display().to_string(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
            }
        })?;
        let manifest = toml::from_str::<FileSecretManifest>(manifest_text).map_err(|source| {
            SecretStoreError::ParseManifest {
                path: manifest_path.display().to_string(),
                source: ConfigParseError::from(source),
            }
        })?;
        manifest.into_snapshot(root)
    }

    #[cfg(test)]
    pub(crate) fn load_snapshot_after_root_capture(
        &self,
        after_capture: impl FnOnce(),
    ) -> Result<SecretSnapshot, SecretStoreError> {
        let root = OpenedSecretRoot::open(&self.root)?;
        after_capture();
        self.load_from_opened_root(&root)
    }

    #[cfg(test)]
    pub(crate) fn load_snapshot_after_manifest_open(
        &self,
        after_manifest_open: impl FnOnce(),
    ) -> Result<SecretSnapshot, SecretStoreError> {
        let root = OpenedSecretRoot::open(&self.root)?;
        self.load_from_opened_root_with_manifest_hook(&root, after_manifest_open)
    }

    #[cfg(test)]
    pub(crate) fn read_material_for_test(
        &self,
        relative: &Path,
    ) -> Result<usize, SecretStoreError> {
        let root = OpenedSecretRoot::open(&self.root)?;
        read_store_file(&root, relative, StoreFileSensitivity::Secret).map(|bytes| bytes.len())
    }

    #[cfg(test)]
    pub(crate) fn read_xot_materials_for_test(
        &self,
        relative_paths: &[&Path],
    ) -> Result<usize, SecretStoreError> {
        let root = OpenedSecretRoot::open(&self.root)?;
        let mut profile_budget =
            SecretStoreMaterialBudget::new(MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE, "XoT profile");
        let mut snapshot_budget = SecretStoreMaterialBudget::new(
            MAX_XOT_TLS_MATERIAL_BYTES_PER_SNAPSHOT,
            "secret-store snapshot",
        );
        for relative in relative_paths {
            let _material = read_store_file_with_material_budgets(
                &root,
                relative,
                StoreFileSensitivity::Public,
                &mut profile_budget,
                &mut snapshot_budget,
            )?;
        }
        Ok(profile_budget.consumed)
    }

    #[cfg(test)]
    pub(crate) fn read_xot_profiles_for_test(
        &self,
        profiles: &[Vec<&Path>],
    ) -> Result<usize, SecretStoreError> {
        let root = OpenedSecretRoot::open(&self.root)?;
        let mut snapshot_budget = SecretStoreMaterialBudget::new(
            MAX_XOT_TLS_MATERIAL_BYTES_PER_SNAPSHOT,
            "secret-store snapshot",
        );
        for relative_paths in profiles {
            let mut profile_budget = SecretStoreMaterialBudget::new(
                MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE,
                "XoT profile",
            );
            for relative in relative_paths {
                let _material = read_store_file_with_material_budgets(
                    &root,
                    relative,
                    StoreFileSensitivity::Public,
                    &mut profile_budget,
                    &mut snapshot_budget,
                )?;
            }
        }
        Ok(snapshot_budget.consumed)
    }
}

impl SecretStore for FileSecretStore {
    fn load_snapshot(&self) -> Result<SecretSnapshot, SecretStoreError> {
        let root = OpenedSecretRoot::open(&self.root)?;
        self.load_from_opened_root(&root)
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
    fn into_snapshot(self, root: &OpenedSecretRoot) -> Result<SecretSnapshot, SecretStoreError> {
        if self.tsig_keys.len() > MAX_TSIG_KEYS_PER_SNAPSHOT {
            return Err(SecretStoreError::Invalid(format!(
                "secret-store snapshot must not contain more than {MAX_TSIG_KEYS_PER_SNAPSHOT} TSIG keys"
            )));
        }
        if self.xot_profiles.len() > MAX_XOT_PROFILES_PER_SNAPSHOT {
            return Err(SecretStoreError::Invalid(format!(
                "secret-store snapshot must not contain more than {MAX_XOT_PROFILES_PER_SNAPSHOT} XoT profiles"
            )));
        }
        let mut snapshot = SecretSnapshot::default();
        for mut key in self.tsig_keys {
            let encoded_used = snapshot
                .tsig_material_sizes_by_name
                .values()
                .map(|sizes| sizes.0)
                .sum::<usize>();
            let provenance_fingerprint = key.provenance_fingerprint()?;
            let secret = key.secret_base64(
                root,
                MAX_TSIG_ENCODED_BYTES_PER_SNAPSHOT.saturating_sub(encoded_used),
            )?;
            let decoded_len = decoded_base64_len(secret.as_str());
            let decoded_used = snapshot
                .tsig_material_sizes_by_name
                .values()
                .map(|sizes| sizes.1)
                .sum::<usize>();
            if decoded_used.saturating_add(decoded_len) > MAX_TSIG_DECODED_BYTES_PER_SNAPSHOT {
                return Err(SecretStoreError::Invalid(format!(
                    "aggregate decoded TSIG material exceeds {MAX_TSIG_DECODED_BYTES_PER_SNAPSHOT} byte limit"
                )));
            }
            let parsed =
                TsigKey::from_base64(&key.name, &key.algorithm, &secret).map_err(|error| {
                    SecretStoreError::Invalid(format!(
                        "invalid secret-store TSIG key {}: {error}",
                        key.name
                    ))
                })?;
            let canonical_name = parsed.name.canonical_key();
            let material_fingerprint = secret_material_fingerprint(
                "tsig",
                &[
                    canonical_name.as_bytes(),
                    parsed.algorithm.name().as_bytes(),
                    secret.as_bytes(),
                ],
            );
            if snapshot
                .tsig_keys_by_name
                .insert(canonical_name.clone(), Arc::new(parsed))
                .is_some()
            {
                return Err(SecretStoreError::Invalid(format!(
                    "duplicate secret-store TSIG key {}",
                    key.name
                )));
            }
            snapshot
                .material_fingerprints_by_id
                .insert(format!("tsig:{canonical_name}"), material_fingerprint);
            snapshot
                .provenance_fingerprints_by_id
                .insert(format!("tsig:{canonical_name}"), provenance_fingerprint);
            snapshot
                .tsig_material_sizes_by_name
                .insert(canonical_name, (secret.len(), decoded_len));
        }
        let mut snapshot_material_budget = SecretStoreMaterialBudget::new(
            MAX_XOT_TLS_MATERIAL_BYTES_PER_SNAPSHOT,
            "secret-store snapshot",
        );
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
            if profile.trust_anchors.len() > MAX_XOT_TRUST_ANCHORS_PER_PROFILE {
                return Err(SecretStoreError::Invalid(format!(
                    "secret-store XoT profile {} must not configure more than {MAX_XOT_TRUST_ANCHORS_PER_PROFILE} trust anchors",
                    profile.name
                )));
            }
            let name = profile.name.clone();
            let profile = profile.into_secret_profile(root, &mut snapshot_material_budget)?;
            let material_fingerprint = profile.material_fingerprint;
            let provenance_fingerprint = profile.provenance_fingerprint;
            if snapshot
                .xot_profiles_by_name
                .insert(name.clone(), profile)
                .is_some()
            {
                return Err(SecretStoreError::Invalid(format!(
                    "duplicate secret-store XoT profile {name}"
                )));
            }
            snapshot
                .material_fingerprints_by_id
                .insert(format!("xot:{name}"), material_fingerprint);
            snapshot
                .provenance_fingerprints_by_id
                .insert(format!("xot:{name}"), provenance_fingerprint);
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
    fn provenance_fingerprint(&self) -> Result<[u8; 32], SecretStoreError> {
        let (kind, path) = match (&self.secret, &self.secret_file) {
            (Some(_), None) => (b"inline".as_slice(), ""),
            (None, Some(path)) => (
                b"secret_file".as_slice(),
                path.to_str().ok_or_else(|| {
                    SecretStoreError::Invalid(format!(
                        "secret-store TSIG key {} has a non-UTF-8 secret_file path",
                        self.name
                    ))
                })?,
            ),
            // Material validation emits the canonical configuration error.
            _ => (b"invalid".as_slice(), ""),
        };
        Ok(secret_material_fingerprint(
            &format!("tsig-provenance:{}", self.name),
            &[kind, path.as_bytes()],
        ))
    }

    fn secret_base64(
        &mut self,
        root: &OpenedSecretRoot,
        remaining_bytes: usize,
    ) -> Result<Zeroizing<String>, SecretStoreError> {
        match (self.secret.take(), &self.secret_file) {
            (Some(secret), None) if secret.expose_secret().trim().len() <= remaining_bytes => {
                Ok(Zeroizing::new(secret.expose_secret().trim().to_owned()))
            }
            (Some(secret), None) => Err(SecretStoreError::Invalid(format!(
                "secret-store TSIG key {} requires {} encoded bytes but only {remaining_bytes} aggregate bytes remain",
                self.name,
                secret.expose_secret().trim().len()
            ))),
            (None, Some(path)) => read_store_text_file(root, path, remaining_bytes)
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
    fn into_secret_profile(
        self,
        root: &OpenedSecretRoot,
        snapshot_material_budget: &mut SecretStoreMaterialBudget,
    ) -> Result<XotSecretProfile, SecretStoreError> {
        let mut profile_material_budget =
            SecretStoreMaterialBudget::new(MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE, "XoT profile");
        let trust_anchor_paths = self
            .trust_anchors
            .iter()
            .map(|path| resolve_store_path(root, path))
            .collect::<Result<Vec<_>, _>>()?;
        let trust_anchor_pems = self
            .trust_anchors
            .iter()
            .map(|path| {
                read_store_file_with_material_budgets(
                    root,
                    path,
                    StoreFileSensitivity::Public,
                    &mut profile_material_budget,
                    snapshot_material_budget,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let client_cert_path = self
            .client_cert
            .as_ref()
            .map(|path| resolve_store_path(root, path))
            .transpose()?;
        let client_cert_pem = self
            .client_cert
            .as_ref()
            .map(|path| {
                read_store_file_with_material_budgets(
                    root,
                    path,
                    StoreFileSensitivity::Public,
                    &mut profile_material_budget,
                    snapshot_material_budget,
                )
            })
            .transpose()?;
        let client_key_path = self
            .client_key
            .as_ref()
            .map(|path| resolve_store_path(root, path))
            .transpose()?;
        let client_key_file_pem = self
            .client_key
            .as_ref()
            .map(|path| {
                read_store_file_with_material_budgets(
                    root,
                    path,
                    StoreFileSensitivity::Secret,
                    &mut profile_material_budget,
                    snapshot_material_budget,
                )
            })
            .transpose()?;
        match (&client_cert_path, &client_key_path, &self.client_key_pem) {
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
        let trust_anchor_pems = trust_anchor_pems
            .iter()
            .map(|pem| pem.to_vec())
            .collect::<Vec<_>>();
        let inline_key_pem = self
            .client_key_pem
            .as_ref()
            .map(|secret| secret.expose_secret().as_bytes());
        if let Some(inline_key_pem) = inline_key_pem {
            profile_material_budget.charge("inline client_key_pem", inline_key_pem.len())?;
            snapshot_material_budget.charge("inline client_key_pem", inline_key_pem.len())?;
        }
        let key_pem: Option<&[u8]> = client_key_file_pem
            .as_ref()
            .map(|pem| pem.as_slice())
            .or(inline_key_pem);
        let client_config = build_xot_client_config_from_pem(
            std::net::SocketAddr::from(([127, 0, 0, 1], 853)),
            &trust_anchor_pems,
            client_cert_pem.as_ref().map(|pem| pem.as_slice()),
            key_pem,
        )
        .map(Arc::new)
        .map_err(|error| {
            SecretStoreError::Invalid(format!(
                "invalid secret-store XoT profile {}: {error}",
                self.name
            ))
        })?;
        let mut fingerprint_parts = trust_anchor_pems
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        if let Some(cert) = client_cert_pem.as_ref() {
            fingerprint_parts.push(cert.as_slice());
        }
        if let Some(key) = key_pem {
            fingerprint_parts.push(key);
        }
        let material_fingerprint =
            secret_material_fingerprint(&format!("xot:{}", self.name), &fingerprint_parts);
        let mut provenance_parts = Vec::new();
        for path in &trust_anchor_paths {
            provenance_parts.push(b"trust_anchor".as_slice());
            provenance_parts.push(path.as_bytes());
        }
        if let Some(path) = client_cert_path.as_deref() {
            provenance_parts.push(b"client_certificate".as_slice());
            provenance_parts.push(path.as_bytes());
        }
        if let Some(path) = client_key_path.as_deref() {
            provenance_parts.push(b"client_key".as_slice());
            provenance_parts.push(path.as_bytes());
        } else if self.client_key_pem.is_some() {
            provenance_parts.push(b"inline_client_key".as_slice());
        }
        let provenance_fingerprint = secret_material_fingerprint(
            &format!("xot-provenance:{}", self.name),
            &provenance_parts,
        );
        let placeholder_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 853));
        let trust_anchor_certificates = trust_anchor_paths
            .iter()
            .zip(trust_anchor_pems.iter())
            .map(|(path, pem)| {
                parse_pem_certs(placeholder_addr, pem, &format!("trust anchor {path:?}"))
                    .map(|certificates| SnapshotCertificateFile {
                        path: path.clone(),
                        certificates: certificates.into(),
                    })
                    .map_err(|error| {
                        SecretStoreError::Invalid(format!(
                            "invalid secret-store XoT profile {}: {error}",
                            self.name
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let client_certificate = client_cert_path
            .as_ref()
            .zip(client_cert_pem.as_ref())
            .map(|(path, pem)| {
                parse_pem_certs(
                    placeholder_addr,
                    pem,
                    &format!("client certificate {path:?}"),
                )
                .map(|certificates| SnapshotCertificateFile {
                    path: path.clone(),
                    certificates: certificates.into(),
                })
                .map_err(|error| {
                    SecretStoreError::Invalid(format!(
                        "invalid secret-store XoT profile {}: {error}",
                        self.name
                    ))
                })
            })
            .transpose()?;
        Ok(XotSecretProfile {
            trust_anchors: trust_anchor_paths,
            client_cert: client_cert_path,
            client_key: client_key_path,
            client_key_pem: self.client_key_pem,
            client_config,
            trust_anchor_certificates,
            client_certificate,
            material_fingerprint,
            provenance_fingerprint,
        })
    }
}

fn read_store_text_file(
    root: &OpenedSecretRoot,
    relative: &Path,
    remaining_bytes: usize,
) -> Result<Zeroizing<String>, SecretStoreError> {
    let bytes = read_store_file_bounded(
        root,
        relative,
        StoreFileSensitivity::Secret,
        remaining_bytes,
    )?;
    let path = resolve_store_path(root, relative)?;
    let text = std::str::from_utf8(bytes.as_slice()).map_err(|source| {
        SecretStoreError::Invalid(format!(
            "secret-store file {path:?} is not valid UTF-8: {source}"
        ))
    })?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn decoded_base64_len(encoded: &str) -> usize {
    let padding = encoded
        .as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'=')
        .take(2)
        .count();
    encoded.len().saturating_add(3) / 4 * 3 - padding
}

#[derive(Clone, Copy)]
enum StoreFileSensitivity {
    Public,
    Secret,
}

#[derive(Debug)]
struct SecretStoreMaterialBudget {
    limit: usize,
    consumed: usize,
    scope: &'static str,
}

impl SecretStoreMaterialBudget {
    fn new(limit: usize, scope: &'static str) -> Self {
        Self {
            limit,
            consumed: 0,
            scope,
        }
    }

    fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.consumed)
    }

    fn ensure_fits(&self, path: &str, bytes: usize) -> Result<(), SecretStoreError> {
        let total = self.consumed.saturating_add(bytes);
        if total > self.limit {
            return Err(SecretStoreError::Invalid(format!(
                "secret-store file {path:?} would raise aggregate {} XoT TLS material to {total} bytes, exceeding {} byte limit",
                self.scope, self.limit
            )));
        }
        Ok(())
    }

    fn charge(&mut self, path: &str, bytes: usize) -> Result<(), SecretStoreError> {
        self.ensure_fits(path, bytes)?;
        self.consumed = self.consumed.saturating_add(bytes);
        Ok(())
    }
}

#[cfg(test)]
fn read_store_file(
    root: &OpenedSecretRoot,
    relative: &Path,
    sensitivity: StoreFileSensitivity,
) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
    read_store_file_bounded(root, relative, sensitivity, MAX_SECRET_STORE_MATERIAL_BYTES)
}

fn read_store_file_bounded(
    root: &OpenedSecretRoot,
    relative: &Path,
    sensitivity: StoreFileSensitivity,
    remaining_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
    let path = resolve_store_path(root, relative)?;
    let mut file =
        root.open_relative_file(relative)
            .map_err(|source| SecretStoreError::ReadSecretFile {
                path: path.clone(),
                source,
            })?;
    validate_store_file(&file, &path, sensitivity)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let read_limit = MAX_SECRET_STORE_MATERIAL_BYTES.min(remaining_bytes);
    file.by_ref()
        .take(read_limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| SecretStoreError::ReadSecretFile {
            path: path.clone(),
            source,
        })?;
    if bytes.len() > read_limit {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store file {path:?} exceeds {read_limit} byte remaining aggregate limit (per-file limit {MAX_SECRET_STORE_MATERIAL_BYTES} bytes)"
        )));
    }
    Ok(bytes)
}

fn read_store_file_with_material_budgets(
    root: &OpenedSecretRoot,
    relative: &Path,
    sensitivity: StoreFileSensitivity,
    profile_budget: &mut SecretStoreMaterialBudget,
    snapshot_budget: &mut SecretStoreMaterialBudget,
) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
    let path = resolve_store_path(root, relative)?;
    let mut file =
        root.open_relative_file(relative)
            .map_err(|source| SecretStoreError::ReadSecretFile {
                path: path.clone(),
                source,
            })?;
    validate_store_file(&file, &path, sensitivity)?;
    let metadata_len = usize::try_from(
        file.metadata()
            .map_err(|source| SecretStoreError::ReadSecretFile {
                path: path.clone(),
                source,
            })?
            .len(),
    )
    .unwrap_or(usize::MAX);
    profile_budget.ensure_fits(&path, metadata_len)?;
    snapshot_budget.ensure_fits(&path, metadata_len)?;
    let remaining = profile_budget.remaining().min(snapshot_budget.remaining());
    let read_limit = MAX_SECRET_STORE_MATERIAL_BYTES.min(remaining);
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref()
        .take(read_limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| SecretStoreError::ReadSecretFile {
            path: path.clone(),
            source,
        })?;
    if bytes.len() > MAX_SECRET_STORE_MATERIAL_BYTES {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store file {path:?} exceeds {MAX_SECRET_STORE_MATERIAL_BYTES} byte limit"
        )));
    }
    profile_budget.charge(&path, bytes.len())?;
    snapshot_budget.charge(&path, bytes.len())?;
    Ok(bytes)
}

fn resolve_store_path(root: &OpenedSecretRoot, path: &Path) -> Result<String, SecretStoreError> {
    validate_relative_store_path(path)?;
    Ok(root.path.join(path).display().to_string())
}

fn validate_relative_store_path(path: &Path) -> Result<(), SecretStoreError> {
    if path.as_os_str().is_empty() {
        return Err(SecretStoreError::Invalid(
            "secret-store file path must not be empty".to_owned(),
        ));
    }
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store file path {path:?} must be a normalized relative path within the captured snapshot root"
        )));
    }
    Ok(())
}

struct OpenedSecretRoot {
    path: PathBuf,
    directory: File,
}

impl OpenedSecretRoot {
    #[cfg(unix)]
    fn open(path: &Path) -> Result<Self, SecretStoreError> {
        use rustix::fs::{Mode, OFlags, open};

        let path_text = path.display().to_string();
        // Follow the final component so the supported `current -> generation`
        // deployment layout keeps working, but require the resolved object to
        // be a directory in the open itself. In particular, a read-only open
        // of a FIFO would otherwise block before the metadata check below.
        let directory = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|source| SecretStoreError::ReadManifest {
            path: path_text.clone(),
            source: source.into(),
        })?;
        let metadata = directory
            .metadata()
            .map_err(|source| SecretStoreError::ReadManifest {
                path: path_text.clone(),
                source,
            })?;
        if !metadata.is_dir() {
            return Err(SecretStoreError::Invalid(format!(
                "secret-store root {path_text:?} must be a directory"
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(SecretStoreError::Invalid(format!(
                    "secret-store root {path_text:?} must not be group- or world-writable"
                )));
            }
        }
        #[cfg(target_os = "linux")]
        let captured_path = {
            use std::os::fd::AsRawFd;

            std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))
                .unwrap_or_else(|_| path.to_path_buf())
        };
        #[cfg(not(target_os = "linux"))]
        let captured_path = path.to_path_buf();
        Ok(Self {
            path: captured_path,
            directory,
        })
    }

    #[cfg(not(unix))]
    fn open(path: &Path) -> Result<Self, SecretStoreError> {
        Err(SecretStoreError::Invalid(format!(
            "secret-store path {:?} is unsupported on non-Unix platforms because descriptor-relative no-follow traversal is unavailable",
            path.display()
        )))
    }

    fn open_manifest(&self) -> Result<File, SecretStoreError> {
        let path_text = self.path.join("secrets.toml").display().to_string();
        let file = self
            .open_relative_file(Path::new("secrets.toml"))
            .map_err(|source| SecretStoreError::ReadManifest {
                path: path_text.clone(),
                source,
            })?;
        validate_manifest_file(&file, &path_text)?;
        Ok(file)
    }

    fn open_relative_file(&self, path: &Path) -> std::io::Result<File> {
        self.open_relative_file_with_hook(path, || {})
    }

    #[cfg(unix)]
    fn open_relative_file_with_hook(
        &self,
        path: &Path,
        mut after_intermediate_open: impl FnMut(),
    ) -> std::io::Result<File> {
        validate_relative_store_path(path).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })?;
        use rustix::fs::{Mode, OFlags, openat};

        let mut directory = self.directory.try_clone()?;
        let mut components = path.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(component) = component else {
                unreachable!("relative path was normalized")
            };
            if components.peek().is_none() {
                let file = openat(
                    &directory,
                    component,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                    Mode::empty(),
                )?;
                return Ok(File::from(file));
            }

            let child = openat(
                &directory,
                component,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK,
                Mode::empty(),
            )?;
            directory = File::from(child);
            validate_secret_store_directory(&directory)?;
            after_intermediate_open();
        }
        unreachable!("validated relative path has at least one component")
    }

    #[cfg(not(unix))]
    fn open_relative_file_with_hook(
        &self,
        _path: &Path,
        _after_intermediate_open: impl FnMut(),
    ) -> std::io::Result<File> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secret-store descriptor-relative traversal is unavailable on non-Unix platforms",
        ))
    }
}

#[cfg(unix)]
fn validate_secret_store_directory(directory: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = directory.metadata()?;
    if !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "secret-store intermediate path component must be a directory, not a symlink",
        ));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "secret-store directories must not be group- or world-writable",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
pub(crate) fn open_secret_store_relative_with_hook(
    root: &Path,
    relative: &Path,
    after_intermediate_open: impl FnMut(),
) -> Result<File, SecretStoreError> {
    OpenedSecretRoot::open(root)?
        .open_relative_file_with_hook(relative, after_intermediate_open)
        .map_err(|source| SecretStoreError::ReadSecretFile {
            path: root.join(relative).display().to_string(),
            source,
        })
}

#[cfg(unix)]
fn validate_manifest_file(file: &File, path_text: &str) -> Result<(), SecretStoreError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = file
        .metadata()
        .map_err(|source| SecretStoreError::ReadManifest {
            path: path_text.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store manifest {path_text:?} must be a regular file"
        )));
    }
    if metadata.len() > MAX_SECRET_STORE_MANIFEST_BYTES as u64 {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store manifest {path_text:?} exceeds {MAX_SECRET_STORE_MANIFEST_BYTES} byte limit"
        )));
    }
    if metadata.permissions().mode() & 0o004 != 0 {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store manifest {path_text:?} must not be world-readable"
        )));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store manifest {path_text:?} must not be group- or world-writable"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_manifest_file(file: &File, path_text: &str) -> Result<(), SecretStoreError> {
    let metadata = file
        .metadata()
        .map_err(|source| SecretStoreError::ReadManifest {
            path: path_text.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store manifest {path_text:?} must be a regular file"
        )));
    }
    if metadata.len() > MAX_SECRET_STORE_MANIFEST_BYTES as u64 {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store manifest {path_text:?} exceeds {MAX_SECRET_STORE_MANIFEST_BYTES} byte limit"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_store_file(
    file: &File,
    path: &str,
    sensitivity: StoreFileSensitivity,
) -> Result<(), SecretStoreError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = file
        .metadata()
        .map_err(|source| SecretStoreError::ReadSecretFile {
            path: path.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store secret file {path:?} must be a regular file"
        )));
    }
    if metadata.len() > MAX_SECRET_STORE_MATERIAL_BYTES as u64 {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store file {path:?} exceeds {MAX_SECRET_STORE_MATERIAL_BYTES} byte limit"
        )));
    }
    let mode = metadata.permissions().mode();
    if matches!(sensitivity, StoreFileSensitivity::Secret) && mode & 0o004 != 0 {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store secret file {path:?} must not be world-readable"
        )));
    }
    if mode & 0o022 != 0 {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store file {path:?} must not be group- or world-writable"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_store_file(
    file: &File,
    path: &str,
    _sensitivity: StoreFileSensitivity,
) -> Result<(), SecretStoreError> {
    let metadata = file
        .metadata()
        .map_err(|source| SecretStoreError::ReadSecretFile {
            path: path.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store secret file {path:?} must be a regular file"
        )));
    }
    if metadata.len() > MAX_SECRET_STORE_MATERIAL_BYTES as u64 {
        return Err(SecretStoreError::Invalid(format!(
            "secret-store file {path:?} exceeds {MAX_SECRET_STORE_MATERIAL_BYTES} byte limit"
        )));
    }
    Ok(())
}
