fn write_secret_store_manifest(root: &std::path::Path, body: &str) {
    std::fs::create_dir_all(root).expect("create secret store directory");
    let manifest_path = root.join("secrets.toml");
    std::fs::write(&manifest_path, body).expect("write secret store manifest");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o600))
            .expect("private secret store manifest mode");
    }
}

fn config_with_secret_store(root: &std::path::Path) -> ServerConfig {
    ServerConfig::from_toml_str(&format!(
        r#"
            [server]
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []

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
fn file_secret_store_reloads_tsig_keys_atomically() {
    let root = unique_test_path("oxidedns-secret-store", "dir");
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
        plan.tsig_key_name.as_ref().map(ToString::to_string).as_deref(),
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

#[test]
fn failed_file_secret_store_reload_retains_previous_snapshot() {
    let root = unique_test_path("oxidedns-secret-store-bad-reload", "dir");
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

#[cfg(unix)]
#[test]
fn file_secret_store_rejects_world_readable_manifest() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_test_path("oxidedns-secret-store-world-readable", "dir");
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
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("world-readable secret store manifest mode");

    let config = config_with_secret_store(&root);
    let error = SecretManager::from_config(&config).expect_err("world-readable manifest rejected");
    assert!(error.to_string().contains("must not be world-readable"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_secret_store_reloads_xot_profiles() {
    let root = unique_test_path("oxidedns-secret-store-xot", "dir");
    let (trust_anchor_one, _key_one) = write_self_signed_xot_cert_files();
    let (trust_anchor_two, _key_two) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    write_secret_store_manifest(
        &root,
        &format!(
            r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["{}"]
        "#,
            trust_anchor_one.display()
        ),
    );
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []

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
    assert_eq!(resolved.trust_anchors[0], trust_anchor_one.display().to_string());

    write_secret_store_manifest(
        &root,
        &format!(
            r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["{}"]
        "#,
            trust_anchor_two.display()
        ),
    );
    secrets.reload().expect("reload XoT profile");
    let resolved = resolve_transfer_primary(&plan.primaries[0], &secrets)
        .expect("resolve reloaded XoT profile");
    assert_eq!(resolved.trust_anchors[0], trust_anchor_two.display().to_string());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn file_secret_store_redacts_inline_xot_private_key_debug() {
    let root = unique_test_path("oxidedns-secret-store-xot-debug", "dir");
    let (cert_path, key_path) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    let key_pem = std::fs::read_to_string(&key_path).expect("read generated private key");
    write_secret_store_manifest(
        &root,
        &format!(
            r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["{}"]
            client_cert = "{}"
            client_key_pem = '''
{}'''
        "#,
            cert_path.display(),
            cert_path.display(),
            key_pem
        ),
    );
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []

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
