//! Catalog cache eligibility is a persisted lifecycle token, not a successful
//! unlink. Rotation precedes catalog publication; old in-flight transfers keep
//! an immutable namespace and cannot make revoked data eligible again.

use super::*;
use crate::transfer_plan::ZoneTransferPlan;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CatalogCacheBinding {
    identity: [u8; 32],
    pub(super) namespace: [u8; 32],
}

impl ZonePersistence {
    pub(crate) fn with_binding(&self, binding: Option<CatalogCacheBinding>) -> Self {
        Self {
            binding,
            ..self.clone()
        }
    }

    pub(crate) fn catalog_binding(
        &self,
        catalog: &DomainName,
        member_node: &DomainName,
        plan: &ZoneTransferPlan,
    ) -> Result<CatalogCacheBinding, ZonePersistenceError> {
        let identity = catalog_binding_identity(catalog, member_node, plan);
        let path = self.lifecycle_path(&identity);
        let token = match self.open_bounded_regular(&path, 32, 32) {
            Ok(mut file) => {
                let mut token = [0; 32];
                file.read_exact(&mut token)
                    .map_err(|source| self.io_error(&path, source))?;
                token
            }
            Err(ZonePersistenceError::Io { source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                self.write_lifecycle_token(&identity)?
            }
            Err(error) => return Err(error),
        };
        Ok(CatalogCacheBinding {
            identity,
            namespace: token,
        })
    }

    /// Conservatively revoke restart eligibility before committing a catalog
    /// removal/reset. A failed catalog publication may therefore cost a cold
    /// transfer, but cannot revive a removed lifecycle after a crash.
    pub(crate) fn revoke_catalog_binding(
        &self,
        binding: CatalogCacheBinding,
    ) -> Result<(), ZonePersistenceError> {
        self.write_lifecycle_token(&binding.identity).map(|_| ())
    }

    fn lifecycle_path(&self, identity: &[u8; 32]) -> PathBuf {
        let hex = identity
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        self.directory.join(format!("{hex}.lifecycle"))
    }

    fn write_lifecycle_token(&self, identity: &[u8; 32]) -> Result<[u8; 32], ZonePersistenceError> {
        fs::create_dir_all(&self.directory)
            .map_err(|source| self.io_error(&self.directory, source))?;
        let path = self.lifecycle_path(identity);
        let mut token = [0; 32];
        getrandom::fill(&mut token)
            .map_err(|error| self.io_error(&path, io::Error::other(error.to_string())))?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp =
            path.with_extension(format!("lifecycle.tmp.{}.{}", std::process::id(), sequence));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options
                .open(&temp)
                .map_err(|source| self.io_error(&temp, source))?;
            file.write_all(&token)
                .map_err(|source| self.io_error(&temp, source))?;
            file.sync_all()
                .map_err(|source| self.io_error(&temp, source))?;
            fs::rename(&temp, &path).map_err(|source| self.io_error(&path, source))?;
            File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| self.io_error(&self.directory, source))?;
            Ok(token)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

fn catalog_binding_identity(
    catalog: &DomainName,
    member_node: &DomainName,
    plan: &ZoneTransferPlan,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"borondns-catalog-lifecycle-v1\0");
    for name in [catalog, member_node, &plan.origin] {
        let key = name.canonical_key();
        digest.update((key.len() as u32).to_be_bytes());
        digest.update(key.as_bytes());
    }
    digest.update(plan.qclass.to_be_bytes());
    let key_name = plan
        .tsig_key_name
        .as_ref()
        .map(DomainName::canonical_key)
        .unwrap_or_default();
    digest.update((key_name.len() as u32).to_be_bytes());
    digest.update(key_name.as_bytes());
    // Startup rotates the preferred primary. Order is not authorization, so
    // fingerprint the sorted serialized targets rather than the chosen order.
    // Only digests are persisted; credentials never enter paths or diagnostics.
    let mut primaries = plan
        .primaries
        .iter()
        .map(|primary| {
            let encoded = serde_json::to_vec(primary).expect("transfer primary serializes");
            <[u8; 32]>::from(Sha256::digest(encoded))
        })
        .collect::<Vec<_>>();
    primaries.sort_unstable();
    digest.update((primaries.len() as u32).to_be_bytes());
    for primary in primaries {
        digest.update(primary);
    }
    let mut sources = plan.transfer_sources.clone();
    sources.sort_unstable();
    digest.update(serde_json::to_vec(&sources).expect("transfer sources serialize"));
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer_plan::TransferPlan;

    fn fixture() -> (
        PathBuf,
        ZonePersistence,
        ZoneTransferPlan,
        DomainName,
        DomainName,
    ) {
        let config = borondns_core::ServerConfig::from_toml_str(
            r#"
            [server]
            allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true
            [[zones]]
            name = "member.example."
            primaries = ["192.0.2.53:53", "192.0.2.54:53"]
        "#,
        )
        .unwrap();
        let member = DomainName::from_absolute_str("member.example.").unwrap();
        let plan = TransferPlan::from_config(&config)
            .unwrap()
            .get(&member)
            .unwrap();
        let root = std::env::temp_dir().join(format!(
            "borondns-cache-binding-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let persistence = ZonePersistence::new(root.clone(), 1024 * 1024);
        (
            root,
            persistence,
            plan,
            DomainName::from_absolute_str("catalog.example.").unwrap(),
            DomainName::from_absolute_str("node.zones.catalog.example.").unwrap(),
        )
    }

    #[test]
    fn catalog_cache_binding_is_restart_stable_and_authorization_specific() {
        let (root, persistence, mut plan, catalog, node) = fixture();
        let first = persistence.catalog_binding(&catalog, &node, &plan).unwrap();
        let restarted = ZonePersistence::new(root.clone(), 1024 * 1024);
        plan.primaries.reverse();
        let repeated = restarted.catalog_binding(&catalog, &node, &plan).unwrap();
        assert_eq!(
            first, repeated,
            "random preferred primary must not break restart restore"
        );
        let canonical = restarted
            .catalog_binding(
                &DomainName::from_absolute_str("CaTaLoG.ExAmPlE.").unwrap(),
                &DomainName::from_absolute_str("NoDe.ZoNeS.CaTaLoG.ExAmPlE.").unwrap(),
                &plan,
            )
            .unwrap();
        assert_eq!(first, canonical);
        let other_catalog = restarted
            .catalog_binding(
                &DomainName::from_absolute_str("other.example.").unwrap(),
                &node,
                &plan,
            )
            .unwrap();
        assert_ne!(first, other_catalog);
        let other_node = restarted
            .catalog_binding(
                &catalog,
                &DomainName::from_absolute_str("new.zones.catalog.example.").unwrap(),
                &plan,
            )
            .unwrap();
        assert_ne!(first, other_node);
        plan.tsig_key_name = Some(DomainName::from_absolute_str("new-key.").unwrap());
        assert_ne!(
            first,
            restarted.catalog_binding(&catalog, &node, &plan).unwrap()
        );
        plan.tsig_key_name = None;
        plan.primaries[0].server_name = Some("new-tls-identity.example".to_owned());
        assert_ne!(
            first,
            restarted.catalog_binding(&catalog, &node, &plan).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_cache_token_rotation_does_not_mutate_frozen_handles() {
        let (root, persistence, plan, catalog, node) = fixture();
        let old = persistence.catalog_binding(&catalog, &node, &plan).unwrap();
        let handle = persistence.with_binding(Some(old));
        let old_path = handle.path_for(&plan.origin);
        persistence.revoke_catalog_binding(old).unwrap();
        let new = persistence.catalog_binding(&catalog, &node, &plan).unwrap();
        assert_ne!(old, new);
        assert_eq!(old_path, handle.path_for(&plan.origin));
        assert_ne!(
            old_path,
            persistence.with_binding(Some(new)).path_for(&plan.origin)
        );
        assert_ne!(
            old_path,
            persistence.path_for(&plan.origin),
            "unbound legacy cache is ineligible"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_cache_binding_rejects_malformed_token_instead_of_reusing_cache() {
        let (root, persistence, plan, catalog, node) = fixture();
        let old = persistence.catalog_binding(&catalog, &node, &plan).unwrap();
        fs::write(persistence.lifecycle_path(&old.identity), [0; 31]).unwrap();
        assert!(persistence.catalog_binding(&catalog, &node, &plan).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn catalog_cache_binding_rejects_symlink_tokens() {
        use std::os::unix::fs::symlink;
        let (root, persistence, plan, catalog, node) = fixture();
        let old = persistence.catalog_binding(&catalog, &node, &plan).unwrap();
        let path = persistence.lifecycle_path(&old.identity);
        let moved = root.join("saved-token");
        fs::rename(&path, &moved).unwrap();
        symlink(&moved, &path).unwrap();
        assert!(persistence.catalog_binding(&catalog, &node, &plan).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
