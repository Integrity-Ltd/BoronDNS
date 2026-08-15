fn write_secret_store_manifest(root: &std::path::Path, body: &str) {
    std::fs::create_dir_all(root).expect("create secret store directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
            .expect("private secret store directory mode");
    }
    let manifest_path = root.join("secrets.toml");
    std::fs::write(&manifest_path, body).expect("write secret store manifest");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o600))
            .expect("private secret store manifest mode");
    }
}

fn copy_secret_store_file(
    root: &std::path::Path,
    source: &std::path::Path,
    name: &str,
) -> std::path::PathBuf {
    std::fs::create_dir_all(root).expect("create secret store directory");
    let destination = root.join(name);
    std::fs::copy(source, &destination).expect("copy secret-store generation material");
    destination
}

fn config_with_secret_store(root: &std::path::Path) -> ServerConfig {
    ServerConfig::from_toml_str(&format!(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [secret_store]
            path = "{}"

            [[zones]]
            name = "example.test."
            primaries = ["192.0.2.53:53"]
            tsig_key = "dynamic-key."
        "#,
        root.display()
    ))
    .expect("valid secret-store config")
}

#[test]
fn secret_store_manifest_enforces_exact_byte_limit_and_growth_fence() {
    use std::io::Write;

    let root = unique_test_path("borondns-secret-store-manifest-limit", "dir");
    let exact = "#".repeat(crate::secret_store::MAX_SECRET_STORE_MANIFEST_BYTES);
    write_secret_store_manifest(&root, &exact);
    let store = crate::secret_store::FileSecretStore::new(root.clone());
    store
        .load_snapshot_after_root_capture(|| {})
        .expect("an exact-limit manifest is accepted");

    write_secret_store_manifest(&root, &format!("{exact}#"));
    let error = store
        .load_snapshot_after_root_capture(|| {})
        .expect_err("a manifest one byte over the limit is rejected");
    assert!(error.to_string().contains("exceeds"));
    assert!(error.to_string().contains("byte limit"));

    write_secret_store_manifest(&root, &exact);
    let manifest_path = root.join("secrets.toml");
    let error = store
        .load_snapshot_after_manifest_open(|| {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&manifest_path)
                .expect("open captured manifest for hostile append")
                .write_all(b"#")
                .expect("grow captured manifest after metadata validation");
        })
        .expect_err("bounded read rejects growth after metadata validation");
    assert!(error.to_string().contains("exceeds"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn secret_store_manifest_rejects_invalid_utf8_without_rendering_inline_secret() {
    let root = unique_test_path("borondns-secret-store-manifest-invalid-utf8", "dir");
    std::fs::create_dir_all(&root).expect("create secret store directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private secret store directory mode");
    }
    let manifest_path = root.join("secrets.toml");
    let sentinel = b"MANIFEST_SECRET_SENTINEL";
    let mut manifest = br#"
        [[tsig_keys]]
        name = "dynamic-key."
        algorithm = "hmac-sha256"
        secret = "MANIFEST_SECRET_SENTINEL"
    "#
    .to_vec();
    manifest.push(0xff);
    std::fs::write(&manifest_path, manifest).expect("write invalid UTF-8 manifest");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o600))
            .expect("private secret store manifest mode");
    }

    let config = config_with_secret_store(&root);
    let error = SecretManager::from_config(&config).expect_err("invalid UTF-8 manifest rejected");
    let rendered = format!("{error}\n{error:?}");
    assert!(rendered.contains("failed to read secret-store manifest"));
    assert!(
        !rendered
            .as_bytes()
            .windows(sentinel.len())
            .any(|window| window == sentinel),
        "invalid UTF-8 error leaked inline manifest secret: {rendered}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn secret_store_material_enforces_exact_byte_limit() {
    let root = unique_test_path("borondns-secret-store-material-limit", "dir");
    write_secret_store_manifest(&root, "");
    let material_path = root.join("material.bin");
    std::fs::write(
        &material_path,
        vec![b'x'; crate::secret_store::MAX_SECRET_STORE_MATERIAL_BYTES],
    )
    .expect("write exact-limit material");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&material_path, std::fs::Permissions::from_mode(0o600))
            .expect("private material mode");
    }
    let store = crate::secret_store::FileSecretStore::new(root.clone());
    assert_eq!(
        store
            .read_material_for_test(std::path::Path::new("material.bin"))
            .expect("exact-limit material is accepted"),
        crate::secret_store::MAX_SECRET_STORE_MATERIAL_BYTES
    );

    std::fs::write(
        &material_path,
        vec![b'x'; crate::secret_store::MAX_SECRET_STORE_MATERIAL_BYTES + 1],
    )
    .expect("write over-limit material");
    let error = store
        .read_material_for_test(std::path::Path::new("material.bin"))
        .expect_err("material one byte over the limit is rejected");
    assert!(error.to_string().contains("exceeds"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn secret_store_tsig_budget_counts_repeated_files_at_exact_and_plus_one() {
    let root = unique_test_path("borondns-secret-store-tsig-aggregate", "dir");
    std::fs::create_dir_all(&root).expect("create secret store");
    let half = borondns_core::config::MAX_TSIG_ENCODED_BYTES_PER_SNAPSHOT / 2;
    std::fs::write(root.join("shared.b64"), vec![b'A'; half])
        .expect("write repeated TSIG material");
    std::fs::write(root.join("one.b64"), b"A").expect("write one extra encoded byte");
    #[cfg(unix)]
    for path in [root.join("shared.b64"), root.join("one.b64")] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private TSIG material mode");
    }
    let exact_manifest = r#"
        [[tsig_keys]]
        name = "first."
        algorithm = "hmac-sha256"
        secret_file = "shared.b64"

        [[tsig_keys]]
        name = "second."
        algorithm = "hmac-sha256"
        secret_file = "shared.b64"
    "#;
    write_secret_store_manifest(&root, exact_manifest);
    let store = crate::secret_store::FileSecretStore::new(root.clone());
    <crate::secret_store::FileSecretStore as crate::secret_store::SecretStore>::load_snapshot(
        &store,
    )
    .expect("exact aggregate repeated-file TSIG budget is accepted");

    write_secret_store_manifest(
        &root,
        &format!(
            "{exact_manifest}\n[[tsig_keys]]\nname = \"third.\"\nalgorithm = \"hmac-sha256\"\nsecret_file = \"one.b64\"\n"
        ),
    );
    let error =
        <crate::secret_store::FileSecretStore as crate::secret_store::SecretStore>::load_snapshot(
            &store,
        )
        .expect_err("one encoded byte beyond aggregate TSIG budget is rejected");
    assert!(error.to_string().contains("remaining aggregate"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn secret_store_tsig_key_count_is_bounded_before_material_loading() {
    let root = unique_test_path("borondns-secret-store-tsig-count", "dir");
    let manifest = (0..=borondns_core::config::MAX_TSIG_KEYS_PER_SNAPSHOT)
        .map(|index| {
            format!(
                "[[tsig_keys]]\nname = \"key-{index}.\"\nalgorithm = \"hmac-sha256\"\nsecret = \"YQ==\"\n"
            )
        })
        .collect::<String>();
    write_secret_store_manifest(&root, &manifest);
    let store = crate::secret_store::FileSecretStore::new(root.clone());
    let error =
        <crate::secret_store::FileSecretStore as crate::secret_store::SecretStore>::load_snapshot(
            &store,
        )
        .expect_err("TSIG key count above snapshot limit is rejected");
    assert!(
        error
            .to_string()
            .contains(&borondns_core::config::MAX_TSIG_KEYS_PER_SNAPSHOT.to_string())
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn secret_store_xot_budget_counts_repeated_material_at_exact_and_over_limit() {
    let root = unique_test_path("borondns-secret-store-xot-aggregate", "dir");
    write_secret_store_manifest(&root, "");
    let material_path = root.join("material.pem");
    let chunk_size = crate::secret_store::MAX_SECRET_STORE_MATERIAL_BYTES;
    let material = std::fs::File::create(&material_path).expect("create aggregate material");
    material
        .set_len(chunk_size as u64)
        .expect("size aggregate material");
    drop(material);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&material_path, std::fs::Permissions::from_mode(0o600))
            .expect("private aggregate material mode");
    }
    let repetitions = borondns_core::config::MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE / chunk_size;
    let repeated = vec![std::path::Path::new("material.pem"); repetitions];
    let store = crate::secret_store::FileSecretStore::new(root.clone());

    assert_eq!(
        store
            .read_xot_materials_for_test(&repeated)
            .expect("exact repeated-file profile budget is accepted"),
        borondns_core::config::MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE
    );
    let one_byte_path = root.join("one-byte.pem");
    std::fs::write(&one_byte_path, [b'x']).expect("write one-byte aggregate material");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&one_byte_path, std::fs::Permissions::from_mode(0o600))
            .expect("private one-byte aggregate material mode");
    }
    let mut over_limit = repeated;
    over_limit.push(std::path::Path::new("one-byte.pem"));
    let error = store
        .read_xot_materials_for_test(&over_limit)
        .expect_err("one byte over the repeated-file profile budget is rejected");
    assert!(error.to_string().contains("aggregate XoT profile"));
    assert!(
        error
            .to_string()
            .contains(&borondns_core::config::MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE.to_string())
    );

    let profile_count = borondns_core::config::MAX_XOT_TLS_MATERIAL_BYTES_PER_SNAPSHOT
        / borondns_core::config::MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE;
    let profiles = vec![vec![std::path::Path::new("material.pem"); repetitions]; profile_count];
    assert_eq!(
        store
            .read_xot_profiles_for_test(&profiles)
            .expect("exact repeated-file snapshot budget is accepted"),
        borondns_core::config::MAX_XOT_TLS_MATERIAL_BYTES_PER_SNAPSHOT
    );
    let mut over_snapshot_limit = profiles;
    over_snapshot_limit.push(vec![std::path::Path::new("one-byte.pem")]);
    let error = store
        .read_xot_profiles_for_test(&over_snapshot_limit)
        .expect_err("one byte over the repeated-file snapshot budget is rejected");
    assert!(
        error
            .to_string()
            .contains("aggregate secret-store snapshot")
    );
    assert!(
        error
            .to_string()
            .contains(&borondns_core::config::MAX_XOT_TLS_MATERIAL_BYTES_PER_SNAPSHOT.to_string())
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_secret_store_reloads_tsig_keys_atomically() {
    let root = unique_test_path("borondns-secret-store", "dir");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "b25lLXNlY3JldA=="
        "#,
    );
    let config = config_with_secret_store(&root);
    let secrets = SecretManager::from_config(&config).expect("initial secret snapshot");
    let zone = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = TransferPlan::from_config(&config)
        .expect("transfer plan")
        .get(&zone)
        .expect("zone transfer plan");
    assert_eq!(
        plan.tsig_key_name
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("dynamic-key.")
    );

    let before = resolve_plan_tsig_key(&plan, &secrets)
        .expect("loaded TSIG key")
        .expect("configured TSIG")
        .sign(b"probe")
        .expect("sign with initial key");

    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "dHdvLXNlY3JldA=="
        "#,
    );
    secrets.reload().expect("reload changed secret snapshot");
    let after = resolve_plan_tsig_key(&plan, &secrets)
        .expect("reloaded TSIG key")
        .expect("configured TSIG")
        .sign(b"probe")
        .expect("sign with reloaded key");

    assert_ne!(before, after);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn secret_reload_only_advances_and_cancels_for_changed_material() {
    let root = unique_test_path("borondns-secret-store-generation", "dir");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "b25lLXNlY3JldA=="
        "#,
    );
    let config = config_with_secret_store(&root);
    let secrets = SecretManager::from_config(&config).expect("initial secret snapshot");
    let initial = secrets
        .current_snapshot()
        .expect("capture initial snapshot");

    secrets.reload().expect("reload unchanged secret material");
    let unchanged = secrets
        .current_snapshot()
        .expect("capture unchanged snapshot");
    assert!(Arc::ptr_eq(&initial, &unchanged));
    assert_eq!(initial.generation(), unchanged.generation());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), initial.cancelled())
            .await
            .is_err(),
        "a no-change reload must not cancel an in-flight transfer"
    );

    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "dHdvLXNlY3JldA=="
        "#,
    );
    secrets.reload().expect("reload changed secret material");
    let changed = secrets
        .current_snapshot()
        .expect("capture changed snapshot");
    assert!(!Arc::ptr_eq(&initial, &changed));
    assert_eq!(changed.generation(), initial.generation() + 1);
    tokio::time::timeout(std::time::Duration::from_secs(1), initial.cancelled())
        .await
        .expect("changed secret material cancels the captured transfer generation");
    assert!(
        secrets.if_current_snapshot(&initial, || ()).is_none(),
        "an old-secret result must be rejected at the publication fence"
    );
    assert!(secrets.if_current_snapshot(&changed, || ()).is_some());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn failed_file_secret_store_reload_retains_previous_snapshot() {
    let root = unique_test_path("borondns-secret-store-bad-reload", "dir");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "b25lLXNlY3JldA=="
        "#,
    );
    let config = config_with_secret_store(&root);
    let secrets = SecretManager::from_config(&config).expect("initial secret snapshot");
    let key_name = DomainName::from_absolute_str("dynamic-key.").unwrap();
    let before = secrets
        .tsig_key(&key_name)
        .expect("initial key")
        .sign(b"probe")
        .expect("sign with initial key");

    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "not base64"
        "#,
    );
    secrets.reload().expect_err("invalid snapshot is rejected");
    let after = secrets
        .tsig_key(&key_name)
        .expect("previous key retained")
        .sign(b"probe")
        .expect("sign with retained key");

    assert_eq!(before, after);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_secret_store_reload_rejects_empty_tsig_candidate_and_retains_previous_snapshot() {
    let root = unique_test_path("borondns-secret-store-empty-tsig-reload", "dir");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "b25lLXNlY3JldA=="
        "#,
    );
    let config = config_with_secret_store(&root);
    let secrets = SecretManager::from_config(&config).expect("initial secret snapshot");
    let initial = secrets
        .current_snapshot()
        .expect("capture initial snapshot");
    let key_name = DomainName::from_absolute_str("dynamic-key.").unwrap();
    let before = secrets
        .tsig_key(&key_name)
        .expect("initial key")
        .sign(b"probe")
        .expect("sign with initial key");

    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = ""
        "#,
    );
    let error = secrets
        .reload()
        .expect_err("empty TSIG candidate must be rejected");
    assert!(
        error
            .to_string()
            .contains("TSIG shared secret must not be empty"),
        "{error}"
    );

    let retained = secrets
        .current_snapshot()
        .expect("capture retained snapshot");
    assert!(Arc::ptr_eq(&initial, &retained));
    assert_eq!(initial.generation(), retained.generation());
    let after = secrets
        .tsig_key(&key_name)
        .expect("previous key retained")
        .sign(b"probe")
        .expect("sign with retained key");
    assert_eq!(before, after);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn malformed_secret_store_manifest_does_not_expose_source_secret() {
    let root = unique_test_path("borondns-secret-store-malformed-secret", "dir");
    let sentinel = "SECRET_STORE_TSIG_SENTINEL";
    write_secret_store_manifest(&root, &format!("[[tsig_keys]]\nsecret = \"{sentinel}"));
    let config = config_with_secret_store(&root);
    let error = SecretManager::from_config(&config).expect_err("malformed manifest rejected");

    let mut rendered = format!("{error}\n{error:?}");
    let mut current: &dyn std::error::Error = &error;
    while let Some(source) = current.source() {
        rendered.push('\n');
        rendered.push_str(&source.to_string());
        current = source;
    }
    assert!(
        !rendered.contains(sentinel),
        "secret-store parse error leaked source: {rendered}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_secret_store_reload_rejects_missing_referenced_tsig_key() {
    let root = unique_test_path("borondns-secret-store-missing-referenced-key", "dir");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "b25lLXNlY3JldA=="
        "#,
    );
    let config = config_with_secret_store(&root);
    let secrets = SecretManager::from_config(&config).expect("initial secret snapshot");
    let key_name = DomainName::from_absolute_str("dynamic-key.").unwrap();
    let before = secrets
        .tsig_key(&key_name)
        .expect("initial key")
        .sign(b"probe")
        .expect("sign with initial key");

    write_secret_store_manifest(&root, "");
    let error = secrets
        .reload()
        .expect_err("reload without referenced TSIG key must fail");
    assert!(
        error
            .to_string()
            .contains("references TSIG key dynamic-key.")
    );
    let after = secrets
        .tsig_key(&key_name)
        .expect("previous key retained after rejected reload")
        .sign(b"probe")
        .expect("sign with retained key");

    assert_eq!(before, after);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn file_secret_store_accepts_group_readable_but_rejects_world_readable_manifest() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_test_path("borondns-secret-store-world-readable", "dir");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "b25lLXNlY3JldA=="
        "#,
    );
    std::fs::set_permissions(
        root.join("secrets.toml"),
        std::fs::Permissions::from_mode(0o640),
    )
    .expect("group-readable secret store manifest mode");

    let config = config_with_secret_store(&root);
    SecretManager::from_config(&config)
        .expect("group-readable manifest remains compatible with the documented file policy");
    std::fs::set_permissions(
        root.join("secrets.toml"),
        std::fs::Permissions::from_mode(0o604),
    )
    .expect("world-readable secret store manifest mode");
    let error = SecretManager::from_config(&config).expect_err("world-readable manifest rejected");
    assert!(error.to_string().contains("must not be world-readable"));
    for mode in [0o602, 0o620] {
        std::fs::set_permissions(
            root.join("secrets.toml"),
            std::fs::Permissions::from_mode(mode),
        )
        .expect("writable-by-others manifest mode");
        let error = SecretManager::from_config(&config)
            .expect_err("group- or world-writable manifest rejected");
        assert!(
            error
                .to_string()
                .contains("must not be group- or world-writable"),
            "mode {mode:o}: {error}"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn file_secret_store_rejects_manifest_symlink_and_non_regular_file() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = unique_test_path("borondns-secret-store-manifest-link", "dir");
    std::fs::create_dir_all(&root).expect("create secret store root");
    let target = unique_test_path("borondns-secret-store-manifest-target", "toml");
    std::fs::write(&target, "").expect("write target manifest");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
        .expect("secure target manifest");
    symlink(&target, root.join("secrets.toml")).expect("create manifest symlink");
    let config = config_with_secret_store(&root);
    SecretManager::from_config(&config).expect_err("manifest symlink rejected");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_file(&target);

    let root = unique_test_path("borondns-secret-store-manifest-directory", "dir");
    std::fs::create_dir_all(root.join("secrets.toml")).expect("create manifest directory");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("secure manifest-directory root");
    let config = config_with_secret_store(&root);
    let error = SecretManager::from_config(&config).expect_err("manifest directory rejected");
    assert!(error.to_string().contains("must be a regular file"));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
fn create_secret_store_fifo(path: &std::path::Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("invoke POSIX mkfifo utility");
    assert!(status.success(), "create secret-store FIFO");
}

#[cfg(unix)]
fn assert_secret_store_root_rejected_promptly(
    configured_root: std::path::PathBuf,
    fifo: &std::path::Path,
) {
    let config = config_with_secret_store(&configured_root);
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let result = SecretManager::from_config(&config)
            .map(|_| ())
            .map_err(|error| error.to_string());
        let _ = result_tx.send(result);
    });

    let result = match result_rx.recv_timeout(std::time::Duration::from_millis(500)) {
        Ok(result) => result,
        Err(error) => {
            // Unblock the historical read-only FIFO open before failing so a
            // regression does not leak a permanently blocked test thread.
            let _unblock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(fifo)
                .expect("open FIFO read-write to unblock regressed root open");
            let _ = result_rx.recv_timeout(std::time::Duration::from_secs(1));
            worker.join().expect("secret-store root worker");
            panic!("secret-store root validation did not return promptly: {error}");
        }
    };
    worker.join().expect("secret-store root worker");
    assert!(result.is_err(), "FIFO root must be rejected");
}

#[cfg(unix)]
#[test]
fn file_secret_store_rejects_fifo_root_without_blocking() {
    let fifo = unique_test_path("borondns-secret-store-root-fifo", "pipe");
    create_secret_store_fifo(&fifo);

    assert_secret_store_root_rejected_promptly(fifo.clone(), &fifo);

    let _ = std::fs::remove_file(fifo);
}

#[cfg(unix)]
#[test]
fn file_secret_store_rejects_generation_symlink_to_fifo_without_blocking() {
    use std::os::unix::fs::symlink;

    let base = unique_test_path("borondns-secret-store-current-fifo", "dir");
    std::fs::create_dir_all(&base).expect("create generation parent");
    let fifo = base.join("generation-fifo");
    let current = base.join("current");
    create_secret_store_fifo(&fifo);
    symlink(&fifo, &current).expect("create current generation symlink to FIFO");

    assert_secret_store_root_rejected_promptly(current, &fifo);

    let _ = std::fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn file_secret_store_checks_world_mode_and_rejects_symlinked_secret_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = unique_test_path("borondns-secret-store-secret-file", "dir");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret_file = "dynamic.key"
        "#,
    );
    let secret_path = root.join("dynamic.key");
    std::fs::write(&secret_path, "b25lLXNlY3JldA==\n").expect("write secret file");
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o640))
        .expect("group-readable secret mode");
    let config = config_with_secret_store(&root);
    SecretManager::from_config(&config)
        .expect("group-readable secret remains compatible with the documented file policy");

    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o604))
        .expect("world-readable secret mode");
    let error = SecretManager::from_config(&config).expect_err("world-readable secret rejected");
    assert!(error.to_string().contains("must not be world-readable"));

    for mode in [0o602, 0o620] {
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(mode))
            .expect("writable-by-others secret mode");
        let error = SecretManager::from_config(&config)
            .expect_err("group- or world-writable secret rejected");
        assert!(
            error
                .to_string()
                .contains("must not be group- or world-writable"),
            "mode {mode:o}: {error}"
        );
    }

    std::fs::remove_file(&secret_path).expect("remove insecure secret");
    let target = root.join("target.key");
    std::fs::write(&target, "b25lLXNlY3JldA==\n").expect("write target secret");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
        .expect("secure target secret mode");
    symlink(&target, &secret_path).expect("create secret symlink");
    SecretManager::from_config(&config).expect_err("secret symlink rejected");
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn file_secret_store_rejects_non_utf8_secret_file_without_rendering_secret_bytes() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_test_path("borondns-secret-store-non-utf8", "dir");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret_file = "dynamic.key"
        "#,
    );
    let secret_path = root.join("dynamic.key");
    let sentinel = b"SECRET_FILE_SENTINEL";
    let mut invalid_secret = sentinel.to_vec();
    invalid_secret.push(0xff);
    std::fs::write(&secret_path, invalid_secret).expect("write invalid UTF-8 secret file");
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
        .expect("secure invalid secret file mode");

    let config = config_with_secret_store(&root);
    let error = SecretManager::from_config(&config).expect_err("invalid UTF-8 secret rejected");
    let rendered = format!("{error}\n{error:?}");
    assert!(rendered.contains("not valid UTF-8"));
    assert!(
        !rendered
            .as_bytes()
            .windows(sentinel.len())
            .any(|window| window == sentinel),
        "invalid UTF-8 error leaked secret bytes: {rendered}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn file_secret_store_rejects_writable_xot_material_and_intermediate_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = unique_test_path("borondns-secret-store-xot-mode", "dir");
    let (cert, key) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    let anchor = copy_secret_store_file(&root, &cert, "anchor.pem");
    write_secret_store_manifest(
        &root,
        r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["anchor.pem"]
        "#,
    );
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [secret_store]
            path = "{}"

            [[zones]]
            name = "example.test."

            [[zones.transfer_primaries]]
            addr = "192.0.2.53:853"
            transport = "xot"
            server_name = "primary.example.test"
            xot_profile = "customer-xot"
        "#,
        root.display()
    ))
    .unwrap();
    std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o644))
        .expect("public trust anchor mode");
    SecretManager::from_config(&config).expect("world-readable public anchor is legitimate");
    for mode in [0o602, 0o620] {
        std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(mode))
            .expect("writable trust anchor mode");
        let error = SecretManager::from_config(&config)
            .expect_err("group- or world-writable trust anchor rejected");
        assert!(
            error
                .to_string()
                .contains("must not be group- or world-writable"),
            "mode {mode:o}: {error}"
        );
    }

    std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o644)).unwrap();
    let nested_target = unique_test_path("borondns-secret-store-nested-target", "dir");
    std::fs::create_dir_all(&nested_target).unwrap();
    std::fs::copy(&cert, nested_target.join("anchor.pem")).unwrap();
    symlink(&nested_target, root.join("nested")).unwrap();
    write_secret_store_manifest(
        &root,
        r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["nested/anchor.pem"]
        "#,
    );
    SecretManager::from_config(&config).expect_err("intermediate directory symlink rejected");

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(nested_target);
    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
}

#[cfg(unix)]
#[test]
fn captured_intermediate_directory_prevents_same_uid_symlink_swap() {
    use std::{
        io::Read,
        os::unix::fs::{PermissionsExt, symlink},
    };

    let root = unique_test_path("borondns-secret-store-intermediate-race", "dir");
    let outside = unique_test_path("borondns-secret-store-intermediate-outside", "dir");
    let nested = root.join("nested");
    let displaced = root.join("nested-captured");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(nested.join("secret.txt"), b"captured").unwrap();
    std::fs::write(outside.join("secret.txt"), b"outside").unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o700)).unwrap();

    let mut swapped = false;
    let mut file = crate::secret_store::open_secret_store_relative_with_hook(
        &root,
        std::path::Path::new("nested/secret.txt"),
        || {
            if swapped {
                return;
            }
            std::fs::rename(&nested, &displaced).unwrap();
            symlink(&outside, &nested).unwrap();
            swapped = true;
        },
    )
    .expect("final file remains relative to captured intermediate directory");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"captured");

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(outside);
}

#[test]
fn file_secret_store_reloads_xot_profiles() {
    let root = unique_test_path("borondns-secret-store-xot", "dir");
    let (trust_anchor_one, _key_one) = write_self_signed_xot_cert_files();
    let (trust_anchor_two, _key_two) =
        write_self_signed_xot_cert_files_for_name("primary.example.test");
    copy_secret_store_file(&root, &trust_anchor_one, "anchor-one.pem");
    copy_secret_store_file(&root, &trust_anchor_two, "anchor-two.pem");
    write_secret_store_manifest(
        &root,
        r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["anchor-one.pem"]
        "#,
    );
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [secret_store]
            path = "{}"

            [[zones]]
            name = "example.test."

            [[zones.transfer_primaries]]
            addr = "192.0.2.53:853"
            transport = "xot"
            server_name = "primary.example.test"
            xot_profile = "customer-xot"
        "#,
        root.display()
    ))
    .expect("valid XoT profile config");
    let secrets = SecretManager::from_config(&config).expect("initial secret snapshot");
    let plan = TransferPlan::from_config(&config)
        .expect("transfer plan")
        .get(&DomainName::from_absolute_str("example.test.").unwrap())
        .expect("zone transfer plan");
    let resolved = resolve_transfer_primary(&plan.primaries[0], &secrets)
        .expect("resolve initial XoT profile");
    assert_eq!(
        resolved.trust_anchors[0],
        root.join("anchor-one.pem").display().to_string()
    );

    write_secret_store_manifest(
        &root,
        r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["anchor-two.pem"]
        "#,
    );
    secrets.reload().expect("reload XoT profile");
    let resolved = resolve_transfer_primary(&plan.primaries[0], &secrets)
        .expect("resolve reloaded XoT profile");
    assert_eq!(
        resolved.trust_anchors[0],
        root.join("anchor-two.pem").display().to_string()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn xot_path_only_reload_refreshes_provenance_without_cancelling_material_generation() {
    let root = unique_test_path("borondns-secret-store-xot-provenance", "dir");
    let (trust_anchor, _key) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    copy_secret_store_file(&root, &trust_anchor, "anchor-one.pem");
    copy_secret_store_file(&root, &trust_anchor, "anchor-two.pem");
    write_secret_store_manifest(
        &root,
        r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["anchor-one.pem"]
        "#,
    );
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [secret_store]
            path = "{}"

            [[zones]]
            name = "example.test."

            [[zones.transfer_primaries]]
            addr = "192.0.2.53:853"
            transport = "xot"
            server_name = "primary.example.test"
            xot_profile = "customer-xot"
        "#,
        root.display()
    ))
    .expect("valid XoT profile config");
    let secrets = SecretManager::from_config(&config).expect("initial secret snapshot");
    let initial = secrets
        .current_snapshot()
        .expect("initial material generation");

    write_secret_store_manifest(
        &root,
        r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["anchor-two.pem"]
        "#,
    );
    secrets.reload().expect("reload path-only XoT provenance");
    let refreshed = secrets
        .current_snapshot()
        .expect("refreshed provenance snapshot");

    assert!(!Arc::ptr_eq(&initial, &refreshed));
    assert_eq!(initial.generation(), refreshed.generation());
    assert!(secrets.if_current_snapshot(&initial, || ()).is_some());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), initial.cancelled())
            .await
            .is_err(),
        "path-only provenance refresh must not cancel unchanged transfer material"
    );
    assert_eq!(
        refreshed
            .xot_profile("customer-xot")
            .expect("refreshed XoT profile")
            .trust_anchors,
        vec![root.join("anchor-two.pem").display().to_string()]
    );
    let observed = TransferMaterial::from_config(&config)
        .pop()
        .expect("configured observable transfer material")
        .resolved_from_snapshot(&refreshed);
    assert_eq!(
        observed.trust_anchors,
        vec![root.join("anchor-two.pem").display().to_string()],
        "observability must report the refreshed same-material source path"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_secret_store_enforces_xot_profile_and_trust_anchor_count_limits() {
    let root = unique_test_path("borondns-secret-store-xot-count-limits", "dir");
    let (anchor, key) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    copy_secret_store_file(&root, &anchor, "anchor.pem");
    let store = crate::secret_store::FileSecretStore::new(root.clone());

    let profiles = (0..borondns_core::config::MAX_XOT_PROFILES_PER_SNAPSHOT)
        .map(|index| {
            format!(
                r#"
                    [[xot_profiles]]
                    name = "profile-{index}"
                    trust_anchors = ["anchor.pem"]
                "#
            )
        })
        .collect::<String>();
    write_secret_store_manifest(&root, &profiles);
    store
        .load_snapshot_after_root_capture(|| {})
        .expect("exact XoT profile count limit is accepted");

    write_secret_store_manifest(
        &root,
        &format!(
            r#"
                {profiles}
                [[xot_profiles]]
                name = "one-profile-too-many"
                trust_anchors = ["anchor.pem"]
            "#
        ),
    );
    let error = store
        .load_snapshot_after_root_capture(|| {})
        .expect_err("one XoT profile over the snapshot limit is rejected");
    assert!(
        error
            .to_string()
            .contains(&borondns_core::config::MAX_XOT_PROFILES_PER_SNAPSHOT.to_string())
    );

    let anchors = std::iter::repeat_n(
        r#""anchor.pem""#,
        borondns_core::config::MAX_XOT_TRUST_ANCHORS_PER_PROFILE,
    )
    .collect::<Vec<_>>()
    .join(", ");
    write_secret_store_manifest(
        &root,
        &format!(
            r#"
                [[xot_profiles]]
                name = "anchor-count-limit"
                trust_anchors = [{anchors}]
            "#
        ),
    );
    store
        .load_snapshot_after_root_capture(|| {})
        .expect("exact XoT trust-anchor count limit is accepted");

    write_secret_store_manifest(
        &root,
        &format!(
            r#"
                [[xot_profiles]]
                name = "anchor-count-over-limit"
                trust_anchors = [{anchors}, "anchor.pem"]
            "#
        ),
    );
    let error = store
        .load_snapshot_after_root_capture(|| {})
        .expect_err("one trust anchor over the profile limit is rejected");
    assert!(
        error
            .to_string()
            .contains(&borondns_core::config::MAX_XOT_TRUST_ANCHORS_PER_PROFILE.to_string())
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_file(anchor);
    let _ = std::fs::remove_file(key);
}

#[test]
fn transfer_resolves_xot_and_tsig_from_one_snapshot_across_reload() {
    let root = unique_test_path("borondns-transfer-secret-generation", "dir");
    let (old_anchor, old_key_file) =
        write_self_signed_xot_cert_files_for_name("primary.example.test");
    let (new_anchor, new_key_file) =
        write_self_signed_xot_cert_files_for_name("primary.example.test");
    copy_secret_store_file(&root, &old_anchor, "old-anchor.pem");
    copy_secret_store_file(&root, &new_anchor, "new-anchor.pem");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "b2xkLXNlY3JldA=="

            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["old-anchor.pem"]
        "#,
    );
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [secret_store]
            path = "{}"

            [[zones]]
            name = "example.test."
            tsig_key = "dynamic-key."

            [[zones.transfer_primaries]]
            addr = "192.0.2.53:853"
            transport = "xot"
            server_name = "primary.example.test"
            xot_profile = "customer-xot"
        "#,
        root.display()
    ))
    .expect("valid transfer-secret generation configuration");
    let secrets = SecretManager::from_config(&config).expect("initial old snapshot");
    let plan = TransferPlan::from_config(&config)
        .unwrap()
        .get(&DomainName::from_absolute_str("example.test.").unwrap())
        .unwrap();
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "bmV3LXNlY3JldA=="

            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["new-anchor.pem"]
        "#,
    );

    let credentials =
        resolve_transfer_credentials_with_hook(&plan.primaries[0], &plan, &secrets, || {
            secrets
                .reload()
                .expect("commit new snapshot between resolutions")
        })
        .expect("resolve transfer credentials from captured snapshot");
    assert_eq!(
        credentials.primary.trust_anchors[0],
        root.join("old-anchor.pem").display().to_string(),
        "XoT resolution must use the captured old snapshot"
    );
    let old_signature = TsigKey::from_base64("dynamic-key.", "hmac-sha256", "b2xkLXNlY3JldA==")
        .unwrap()
        .sign(b"snapshot-probe")
        .unwrap();
    assert_eq!(
        credentials
            .tsig_key
            .unwrap()
            .sign(b"snapshot-probe")
            .unwrap(),
        old_signature,
        "TSIG resolution must remain on the same captured old snapshot"
    );
    assert_eq!(
        secrets
            .tsig_key(&DomainName::from_absolute_str("dynamic-key.").unwrap())
            .unwrap()
            .sign(b"snapshot-probe")
            .unwrap(),
        TsigKey::from_base64("dynamic-key.", "hmac-sha256", "bmV3LXNlY3JldA==",)
            .unwrap()
            .sign(b"snapshot-probe")
            .unwrap(),
        "the manager may advance independently after the transfer capture"
    );

    for path in [old_anchor, old_key_file, new_anchor, new_key_file] {
        let _ = std::fs::remove_file(path);
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_secret_store_xot_material_is_one_immutable_generation() {
    let root = unique_test_path("borondns-secret-store-xot-generation", "dir");
    let (cert_one, key_one) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    let (cert_two, key_two) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    copy_secret_store_file(&root, &cert_one, "client.pem");
    copy_secret_store_file(&root, &key_one, "client.key");
    write_secret_store_manifest(
        &root,
        r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["client.pem"]
            client_cert = "client.pem"
            client_key = "client.key"
        "#,
    );
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [secret_store]
            path = "{}"

            [[zones]]
            name = "example.test."

            [[zones.transfer_primaries]]
            addr = "192.0.2.53:853"
            transport = "xot"
            server_name = "primary.example.test"
            xot_profile = "customer-xot"
        "#,
        root.display()
    ))
    .expect("valid XoT profile config");
    let secrets = SecretManager::from_config(&config).expect("initial secret snapshot");
    let initial = secrets
        .xot_profile("customer-xot")
        .expect("initial profile");

    let staged_cert = unique_test_path("xot-atomic-cert", "pem");
    std::fs::copy(&cert_two, &staged_cert).expect("stage replacement certificate");
    std::fs::rename(&staged_cert, root.join("client.pem")).expect("atomically replace certificate");

    let unchanged = secrets
        .xot_profile("customer-xot")
        .expect("active profile after path replacement");
    assert!(Arc::ptr_eq(
        &initial.client_config,
        &unchanged.client_config
    ));
    let error = secrets
        .reload()
        .expect_err("mixed certificate/key generation must not replace active snapshot");
    assert!(error.to_string().contains("certificate/key pair"));
    let after_failed_reload = secrets
        .xot_profile("customer-xot")
        .expect("profile preserved after failed reload");
    assert!(Arc::ptr_eq(
        &initial.client_config,
        &after_failed_reload.client_config
    ));

    let staged_key = unique_test_path("xot-atomic-key", "pem");
    std::fs::copy(&key_two, &staged_key).expect("stage replacement private key");
    std::fs::rename(&staged_key, root.join("client.key")).expect("atomically replace private key");
    secrets
        .reload()
        .expect("reload complete material generation");
    let reloaded = secrets
        .xot_profile("customer-xot")
        .expect("reloaded profile");
    assert!(!Arc::ptr_eq(
        &initial.client_config,
        &reloaded.client_config
    ));

    for path in [cert_one, key_one, cert_two, key_two] {
        let _ = std::fs::remove_file(path);
    }
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn captured_secret_root_prevents_cross_generation_xot_and_tsig_mixing() {
    use std::{
        os::unix::fs::symlink,
        sync::{Arc, Barrier},
    };

    let base = unique_test_path("borondns-secret-store-generation-switch", "dir");
    let old_root = base.join("generation-old");
    let new_root = base.join("generation-new");
    let current = base.join("current");
    let (old_cert, old_key) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    let (new_cert, new_key) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    for (root, cert, key, secret) in [
        (&old_root, &old_cert, &old_key, "b2xkLXNlY3JldA=="),
        (&new_root, &new_cert, &new_key, "bmV3LXNlY3JldA=="),
    ] {
        copy_secret_store_file(root, cert, "client.pem");
        copy_secret_store_file(root, key, "client.key");
        write_secret_store_manifest(
            root,
            &format!(
                r#"
                    [[tsig_keys]]
                    name = "dynamic-key."
                    algorithm = "hmac-sha256"
                    secret = "{secret}"

                    [[xot_profiles]]
                    name = "customer-xot"
                    trust_anchors = ["client.pem"]
                    client_cert = "client.pem"
                    client_key = "client.key"
                "#
            ),
        );
    }
    symlink(&old_root, &current).expect("activate old secret generation");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [secret_store]
            path = "{}"

            [[zones]]
            name = "example.test."
            tsig_key = "dynamic-key."

            [[zones.transfer_primaries]]
            addr = "192.0.2.53:853"
            transport = "xot"
            server_name = "primary.example.test"
            xot_profile = "customer-xot"
        "#,
        current.display()
    ))
    .expect("valid generation-switch configuration");
    let secrets = SecretManager::from_config(&config).expect("load old active generation");
    let store = crate::secret_store::FileSecretStore::new(current.clone());
    let captured = Arc::new(Barrier::new(2));
    let switched = Arc::new(Barrier::new(2));
    let switcher = {
        let captured = captured.clone();
        let switched = switched.clone();
        let base = base.clone();
        let current = current.clone();
        let new_root = new_root.clone();
        std::thread::spawn(move || {
            captured.wait();
            let staged = base.join("current-next");
            symlink(new_root, &staged).expect("stage new generation link");
            std::fs::rename(staged, current).expect("atomically activate new generation");
            switched.wait();
        })
    };
    let overlapping = store
        .load_snapshot_after_root_capture(|| {
            captured.wait();
            switched.wait();
        })
        .expect("captured old root remains a complete valid snapshot");
    switcher.join().expect("generation switch thread");

    let key_name = DomainName::from_absolute_str("dynamic-key.").unwrap();
    let old_signature = TsigKey::from_base64("dynamic-key.", "hmac-sha256", "b2xkLXNlY3JldA==")
        .unwrap()
        .sign(b"generation-probe")
        .unwrap();
    let new_signature = TsigKey::from_base64("dynamic-key.", "hmac-sha256", "bmV3LXNlY3JldA==")
        .unwrap()
        .sign(b"generation-probe")
        .unwrap();
    assert_eq!(
        overlapping
            .tsig_key(&key_name)
            .unwrap()
            .sign(b"generation-probe")
            .unwrap(),
        old_signature
    );
    assert!(
        overlapping
            .xot_profile("customer-xot")
            .unwrap()
            .trust_anchors[0]
            .starts_with(&old_root.display().to_string())
    );
    assert_eq!(
        secrets
            .tsig_key(&key_name)
            .unwrap()
            .sign(b"generation-probe")
            .unwrap(),
        old_signature,
        "active snapshot remains entirely old until reload commits"
    );

    secrets
        .reload()
        .expect("load and atomically commit new generation");
    assert_eq!(
        secrets
            .tsig_key(&key_name)
            .unwrap()
            .sign(b"generation-probe")
            .unwrap(),
        new_signature
    );
    assert!(
        secrets.xot_profile("customer-xot").unwrap().trust_anchors[0]
            .starts_with(&new_root.display().to_string())
    );

    for path in [old_cert, old_key, new_cert, new_key] {
        let _ = std::fs::remove_file(path);
    }
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn file_secret_store_redacts_inline_xot_private_key_debug() {
    let root = unique_test_path("borondns-secret-store-xot-debug", "dir");
    let (cert_path, key_path) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    let key_pem = std::fs::read_to_string(&key_path).expect("read generated private key");
    copy_secret_store_file(&root, &cert_path, "client.pem");
    write_secret_store_manifest(
        &root,
        &format!(
            r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["client.pem"]
            client_cert = "client.pem"
            client_key_pem = '''
{}'''
        "#,
            key_pem
        ),
    );
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [secret_store]
            path = "{}"

            [[zones]]
            name = "example.test."

            [[zones.transfer_primaries]]
            addr = "192.0.2.53:853"
            transport = "xot"
            server_name = "primary.example.test"
            xot_profile = "customer-xot"
        "#,
        root.display()
    ))
    .expect("valid XoT profile config");
    let secrets = SecretManager::from_config(&config).expect("secret snapshot");
    let profile = secrets.xot_profile("customer-xot").expect("loaded profile");
    let debug = format!("{profile:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("PRIVATE KEY"));
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(cert_path);
}
