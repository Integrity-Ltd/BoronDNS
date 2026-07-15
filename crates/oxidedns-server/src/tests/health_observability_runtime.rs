#[tokio::test]
async fn health_endpoint_reports_starting_until_zone_active() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(
        listener,
        health_state(zones.clone()),
        std::future::pending(),
    ));

    let livez = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        http_request(addr, "GET", "/livez"),
    )
    .await
    .expect("/livez should answer within SRS health bound");
    assert!(livez.starts_with("HTTP/1.1 200 OK"));
    assert!(livez.contains("content-type: application/json"));
    assert!(livez.contains(r#""status":"alive""#));

    let starting = http_request(addr, "GET", "/healthz").await;
    assert!(starting.starts_with("HTTP/1.1 503 Service Unavailable"));
    assert!(starting.contains("content-type: application/json"));
    assert!(starting.ends_with(concat!(
        r#"{"status":"not-ready","reason":"no_active_zones","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","zones_active":0,"zones_loading":0,"zones_expired":0}"#
    )));

    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));

    let ready = http_request(addr, "GET", "/healthz").await;
    assert!(ready.starts_with("HTTP/1.1 200 OK"));
    assert!(ready.ends_with(concat!(
        r#"{"status":"ready","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","zones_active":1,"zones_loading":0,"zones_expired":0}"#
    )));

    server.abort();
}

#[tokio::test]
async fn hidden_active_catalog_does_not_satisfy_readiness() {
    let zones = ZoneStore::new();
    let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
    zones.insert_loading_hidden(catalog.clone());
    zones.insert_snapshot(ZoneSnapshot::active(catalog, Some(1), Vec::new()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(
        listener,
        health_state(zones),
        std::future::pending(),
    ));

    let ready = http_request(addr, "GET", "/readyz").await;
    assert!(ready.starts_with("HTTP/1.1 503 Service Unavailable"));
    assert!(ready.ends_with(concat!(
        r#"{"status":"not-ready","reason":"no_active_zones","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","zones_active":0,"zones_loading":0,"zones_expired":0}"#
    )));

    let metrics = http_request(addr, "GET", "/metrics").await;
    assert!(metrics.contains("oxidedns_zones_active 0"));

    server.abort();
}

#[tokio::test]
async fn observability_api_is_disabled_by_default() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(
        listener,
        health_state(zones),
        std::future::pending(),
    ));

    let response = http_request(addr, "GET", "/observability/v1").await;
    assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    assert!(response.ends_with(r#"{"error":"not_found","path":"/observability/v1"}"#));

    server.abort();
}

#[tokio::test]
async fn observability_api_reports_summary_and_zones() {
    let zones = ZoneStore::new();
    let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(
        active_origin.clone(),
        Some(42),
        vec![Rrset::new(
            active_origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        )],
    ));
    zones.insert_loading(DomainName::from_absolute_str("loading.test.").unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = health_state_with_observability(
        zones,
        ObservabilityConfig {
            enabled: true,
            ..ObservabilityConfig::default()
        },
    );
    state.metrics.record_query_received();
    let _ = state.metrics.record_zone_query_key("example.test.");
    let server = tokio::spawn(serve_health(listener, state, std::future::pending()));

    let summary = http_json(addr, "/observability/v1/summary").await;
    assert_eq!(summary["schema_version"], 1);
    assert_eq!(summary["data"]["zones"]["active"], 1);
    assert_eq!(summary["data"]["zones"]["loading"], 1);
    assert_eq!(summary["data"]["zone_image"]["serve_hits"], 0);

    let zones = http_json(addr, "/observability/v1/zones").await;
    assert_eq!(zones["data"]["zones"][0]["zone"], "example.test.");
    assert_eq!(zones["data"]["zones"][0]["queries"], 1);

    let zone = http_json(addr, "/observability/v1/zones/example.test.").await;
    assert_eq!(zone["data"]["serial"], 42);
    assert_eq!(zone["data"]["source"], "configured");

    server.abort();
}

#[tokio::test]
async fn observability_api_honors_custom_prefix_and_reduced_metrics() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut state = health_state_with_observability(
        zones,
        ObservabilityConfig {
            enabled: true,
            path_prefix: "/obs".to_owned(),
            ..ObservabilityConfig::default()
        },
    );
    state.metrics = RuntimeMetrics::new_reduced_for_test();
    state.metrics.record_query_received();
    let _ = state.metrics.record_zone_query_key("example.test.");
    let server = tokio::spawn(serve_health(listener, state, std::future::pending()));

    let default_path = http_request(addr, "GET", "/observability/v1").await;
    assert!(default_path.starts_with("HTTP/1.1 404 Not Found"));

    let index = http_json(addr, "/obs").await;
    assert_eq!(index["data"]["endpoints"]["summary"], "/obs/summary");
    assert_eq!(index["metrics_detail"], "reduced");

    let zones = http_json(addr, "/obs/zones").await;
    assert_eq!(zones["data"]["zones"][0]["queries"], "reduced");
    assert_eq!(zones["metrics_detail"], "reduced");

    server.abort();
}

#[tokio::test]
async fn observability_api_reports_catalog_membership() {
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(DomainName::from_absolute_str("catalog.example.").unwrap());
    zones.insert_loading(DomainName::from_absolute_str("alpha.example.").unwrap());
    let mut state = health_state_with_observability(
        zones,
        ObservabilityConfig {
            enabled: true,
            ..ObservabilityConfig::default()
        },
    );
    state.catalog_manager = CatalogManager {
        catalogs_by_key: Arc::new(HashMap::from([(
            "catalog.example.".to_owned(),
            CatalogRuntimeConfig {
                origin: DomainName::from_absolute_str("catalog.example.").unwrap(),
                config: oxidedns_core::config::CatalogZoneConfig {
                    name: "catalog.example.".to_owned(),
                    class: "IN".to_owned(),
                    primaries: vec!["192.0.2.53:53".parse().unwrap()],
                    transfer_primaries: Vec::new(),
                    catalog_primaries: Vec::new(),
                    catalog_transfer_primaries: Vec::new(),
                    member_primaries: Vec::new(),
                    member_transfer_primaries: Vec::new(),
                    notify_sources: Vec::new(),
                    tsig_key: Some("catalog-key.".to_owned()),
                    catalog_tsig_key: None,
                    member_tsig_key: None,
                    serve_catalog_zone: false,
                    member_transfer_extensions: false,
                    member_transfer_policy:
                        oxidedns_core::config::CatalogMemberTransferPolicyConfig::default(),
                    max_member_zones: 10_000,
                },
            },
        )])),
        static_zone_keys: Arc::new(HashSet::from(["static.example.".to_owned()])),
        memberships_by_catalog: Arc::new(Mutex::new(HashMap::from([(
            "catalog.example.".to_owned(),
            HashMap::from([
                (
                    "alpha.example.".to_owned(),
                    DomainName::from_absolute_str("alpha.example.").unwrap(),
                ),
                (
                    "static.example.".to_owned(),
                    DomainName::from_absolute_str("static.example.").unwrap(),
                ),
            ]),
        )]))),
        desired_memberships_by_catalog: Arc::new(Mutex::new(HashMap::new())),
        member_owners_by_key: Arc::new(Mutex::new(HashMap::new())),
        notify_refresh_registry: Arc::new(Mutex::new(None)),
        ixfr_cooldown_registry: Arc::new(Mutex::new(None)),
        reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(listener, state, std::future::pending()));

    let catalogs = http_json(addr, "/observability/v1/catalogs").await;
    assert_eq!(catalogs["data"]["configured"], 1);
    assert_eq!(
        catalogs["data"]["memberships"][0]["catalog_zone"],
        "catalog.example."
    );
    assert_eq!(catalogs["data"]["memberships"][0]["members_total"], 2);
    assert_eq!(catalogs["data"]["memberships"][0]["members_managed"], 1);
    assert_eq!(
        catalogs["data"]["memberships"][0]["members_static_overlap"],
        1
    );

    let zone = http_json(addr, "/observability/v1/zones/alpha.example.").await;
    assert_eq!(zone["data"]["source"], "catalog_derived");

    server.abort();
}

#[tokio::test]
async fn observability_api_enforces_configured_bearer_token() {
    let token_path = unique_test_path("observability-token", "txt");
    std::fs::write(&token_path, b"test-token\n").expect("write observability token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure observability token mode");
    }
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let state = health_state_with_observability(
        zones,
        ObservabilityConfig {
            enabled: true,
            bearer_token_file: Some(token_path),
            ..ObservabilityConfig::default()
        },
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(listener, state, std::future::pending()));

    let missing = http_request(addr, "GET", "/observability/v1").await;
    assert!(missing.starts_with("HTTP/1.1 401 Unauthorized"));
    assert!(missing.ends_with(r#"{"error":"missing_bearer_token"}"#));

    let wrong = String::from_utf8(
        http_request_with_headers(
            addr,
            "GET",
            "/observability/v1",
            &[("Authorization", "Bearer wrong-token")],
        )
        .await,
    )
    .expect("HTTP response should be UTF-8");
    assert!(wrong.starts_with("HTTP/1.1 401 Unauthorized"));
    assert!(wrong.ends_with(r#"{"error":"invalid_bearer_token"}"#));

    let index = http_json_with_headers(
        addr,
        "/observability/v1",
        &[("Authorization", "Bearer test-token")],
    )
    .await;
    assert_eq!(index["data"]["enabled"], true);

    server.abort();
}

#[test]
fn observability_auth_rejects_empty_and_insecure_token_files() {
    use std::os::unix::fs::PermissionsExt;

    let token_path = unique_test_path("observability-token-validation", "token");
    std::fs::write(&token_path, b"\n\t ").expect("write empty token");
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))
        .expect("secure token mode");
    let config = ObservabilityConfig {
        bearer_token_file: Some(token_path.clone()),
        ..ObservabilityConfig::default()
    };
    let error = ObservabilityAuth::from_config(&config).expect_err("empty token rejected");
    assert!(error.to_string().contains("must not be empty"));

    std::fs::write(&token_path, b"secret-token\n").expect("write token");
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o640))
        .expect("group-readable token mode");
    let error = ObservabilityAuth::from_config(&config).expect_err("insecure token mode rejected");
    assert!(error.to_string().contains("group or other users"));

    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))
        .expect("restore secure token mode");
    let auth = ObservabilityAuth::from_config(&config).expect("secure token accepted");
    assert!(auth.is_configured());
    assert!(!format!("{auth:?}").contains("secret-token"));
    let _ = std::fs::remove_file(token_path);
}

#[cfg(unix)]
#[test]
fn observability_auth_digest_comparison_handles_equal_and_unequal_lengths() {
    use std::os::unix::fs::PermissionsExt;

    let token_path = unique_test_path("observability-token-digest", "token");
    std::fs::write(&token_path, b"test-token\n").expect("write token");
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))
        .expect("secure token mode");
    let auth = ObservabilityAuth::from_config(&ObservabilityConfig {
        bearer_token_file: Some(token_path.clone()),
        ..ObservabilityConfig::default()
    })
    .expect("secure token accepted");

    let authorization_headers = |token: &str| {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}")
                .parse()
                .expect("static bearer header is valid"),
        );
        headers
    };

    assert_eq!(auth.authorize(&authorization_headers("test-token")), Ok(()));
    assert_eq!(
        auth.authorize(&authorization_headers("test-tokem")),
        Err(ObservabilityAuthError::Invalid),
        "equal-length mismatch must be rejected"
    );
    assert_eq!(
        auth.authorize(&authorization_headers("test")),
        Err(ObservabilityAuthError::Invalid),
        "short mismatch must be rejected"
    );
    assert_eq!(
        auth.authorize(&authorization_headers("test-token-extra")),
        Err(ObservabilityAuthError::Invalid),
        "long mismatch must be rejected"
    );

    let _ = std::fs::remove_file(token_path);
}

#[cfg(unix)]
#[test]
fn observability_token_loader_enforces_exact_limit_and_growth_fence() {
    use std::{io::Write, os::unix::fs::PermissionsExt};

    let limit = MAX_OBSERVABILITY_BEARER_TOKEN_BYTES;
    let token_path = unique_test_path("observability-token-limit", "token");
    std::fs::write(&token_path, vec![b'x'; limit]).expect("write exact-limit token");
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))
        .expect("secure exact-limit token mode");
    assert_eq!(
        observability_token_len_after_open_for_test(&token_path, || {})
            .expect("exact-limit observability token is accepted"),
        limit
    );

    std::fs::OpenOptions::new()
        .append(true)
        .open(&token_path)
        .expect("open token for over-limit append")
        .write_all(b"x")
        .expect("append one over-limit byte");
    let error = observability_token_len_after_open_for_test(&token_path, || {})
        .expect_err("one-byte-over observability token is rejected");
    assert!(error.to_string().contains(&limit.to_string()));

    std::fs::OpenOptions::new()
        .write(true)
        .open(&token_path)
        .expect("open token for exact-limit reset")
        .set_len(limit as u64)
        .expect("reset exact-limit token");
    let growth_path = token_path.clone();
    let error = observability_token_len_after_open_for_test(&token_path, move || {
        std::fs::OpenOptions::new()
            .append(true)
            .open(&growth_path)
            .expect("open captured observability token")
            .write_all(b"x")
            .expect("grow observability token after metadata validation");
    })
    .expect_err("bounded same-handle token read rejects post-validation growth");
    assert!(error.to_string().contains(&limit.to_string()));

    let _ = std::fs::remove_file(token_path);
}

#[cfg(unix)]
#[test]
fn observability_auth_rejects_symlinked_and_non_regular_token_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let target = unique_test_path("observability-token-target", "token");
    std::fs::write(&target, b"secret-token\n").expect("write target token");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
        .expect("secure target token");
    let link = unique_test_path("observability-token-link", "token");
    symlink(&target, &link).expect("create token symlink");
    let config = ObservabilityConfig {
        bearer_token_file: Some(link.clone()),
        ..ObservabilityConfig::default()
    };
    ObservabilityAuth::from_config(&config).expect_err("token symlink rejected");

    let directory = unique_test_path("observability-token-directory", "dir");
    std::fs::create_dir(&directory).expect("create token directory");
    let config = ObservabilityConfig {
        bearer_token_file: Some(directory.clone()),
        ..ObservabilityConfig::default()
    };
    let error = ObservabilityAuth::from_config(&config).expect_err("token directory rejected");
    assert!(error.to_string().contains("must be a regular file"));

    let _ = std::fs::remove_file(link);
    let _ = std::fs::remove_file(target);
    let _ = std::fs::remove_dir(directory);
}

#[tokio::test]
async fn observability_api_reports_resource_and_time_snapshots() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let state = health_state_with_observability(
        zones,
        ObservabilityConfig {
            enabled: true,
            ..ObservabilityConfig::default()
        },
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(listener, state, std::future::pending()));

    let resources = http_json(addr, "/observability/v1/resources").await;
    assert!(resources["data"]["filesystems"]["status"].is_string());
    assert_eq!(resources["data"]["process_resources"]["status"], "ok");
    assert!(resources["data"]["process_resources"]["pid"].is_number());
    assert!(resources["data"]["process_resources"]["file_descriptors_open"].is_number());

    let time = http_json(addr, "/observability/v1/time").await;
    assert!(time["data"]["status"].is_string());
    assert!(time["data"]["source"].is_string());

    server.abort();
}

#[tokio::test]
async fn observability_api_reports_certificate_status_for_xot_material() {
    let (cert_path, _key_path) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let mut state = health_state_with_observability(
        zones,
        ObservabilityConfig {
            enabled: true,
            ..ObservabilityConfig::default()
        },
    );
    state.transfer_materials = vec![TransferMaterial {
        scope: "zone",
        zone: "example.test.".to_owned(),
        primary: "192.0.2.53:853".to_owned(),
        transport: "xot",
        server_name: Some("primary.example.test".to_owned()),
        xot_profile: None,
        trust_anchors: vec![cert_path.display().to_string()],
        client_cert: None,
        client_key_configured: false,
        inline_client_key_configured: false,
        snapshot_certificates: None,
    }];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(listener, state, std::future::pending()));

    let certificates = http_json(addr, "/observability/v1/certificates").await;
    assert_eq!(certificates["data"]["status"], "ok");
    assert_eq!(certificates["data"]["configured_materials"], 1);
    assert_eq!(
        certificates["data"]["certificates"][0]["role"],
        "trust_anchor"
    );
    assert_eq!(certificates["data"]["certificates"][0]["scope"], "zone");
    assert_eq!(
        certificates["data"]["certificates"][0]["server_name"],
        "primary.example.test"
    );
    assert!(certificates["data"]["certificates"][0]["not_after_unix_seconds"].is_number());

    server.abort();
}

#[tokio::test]
async fn observability_api_reports_profile_backed_xot_certificates_from_current_snapshot() {
    let root = unique_test_path("oxidedns-observability-xot-profile", "dir");
    let (first_cert, first_key) =
        write_self_signed_xot_cert_files_for_name("first-observed.example.test");
    let (second_cert, second_key) =
        write_self_signed_xot_cert_files_for_name("second-observed.example.test");
    copy_secret_store_file(&root, &first_cert, "first-anchor.pem");
    write_secret_store_manifest(
        &root,
        r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["first-anchor.pem"]
        "#,
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
    .expect("valid profile-backed XoT config");
    let secrets = SecretManager::from_config(&config).expect("initial secret snapshot");
    let reload_handle = secrets.clone();

    let zones = ZoneStore::new();
    let mut state = health_state_with_observability(
        zones,
        ObservabilityConfig {
            enabled: true,
            ..ObservabilityConfig::default()
        },
    );
    state.transfer_materials = TransferMaterial::from_config(&config);
    state.secrets = secrets;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(listener, state, std::future::pending()));

    let certificates = http_json(addr, "/observability/v1/certificates").await;
    assert_eq!(certificates["data"]["status"], "ok");
    assert_eq!(certificates["data"]["configured_materials"], 1);
    assert_eq!(
        certificates["data"]["certificates"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        certificates["data"]["certificates"][0]["path"],
        root.join("first-anchor.pem").display().to_string()
    );
    assert_eq!(
        certificates["data"]["certificates"][0]["role"],
        "trust_anchor"
    );
    let first_fingerprint = certificates["data"]["certificates"][0]["sha256_fingerprint"]
        .as_str()
        .expect("certificate fingerprint")
        .to_owned();

    std::fs::write(root.join("first-anchor.pem"), b"not a certificate")
        .expect("replace certificate with invalid generation");
    reload_handle
        .reload()
        .expect_err("invalid replacement generation is rejected");
    let after_failed_reload = http_json(addr, "/observability/v1/certificates").await;
    assert_eq!(
        after_failed_reload["data"]["certificates"][0]["sha256_fingerprint"],
        first_fingerprint
    );

    std::fs::copy(&second_cert, root.join("first-anchor.pem"))
        .expect("install valid replacement certificate");
    reload_handle
        .reload()
        .expect("reload valid replacement generation");
    let after_successful_reload = http_json(addr, "/observability/v1/certificates").await;
    assert_ne!(
        after_successful_reload["data"]["certificates"][0]["sha256_fingerprint"],
        first_fingerprint
    );

    server.abort();
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_file(first_cert);
    let _ = std::fs::remove_file(first_key);
    let _ = std::fs::remove_file(second_cert);
    let _ = std::fs::remove_file(second_key);
}

#[tokio::test]
async fn observability_api_reports_transfer_security_and_reduced_detail() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let mut state = health_state_with_observability(
        zones,
        ObservabilityConfig {
            enabled: true,
            ..ObservabilityConfig::default()
        },
    );
    state.metrics = RuntimeMetrics::new_reduced_for_test();
    state.metrics.record_axfr_started();
    state.metrics.record_axfr_succeeded();
    state.metrics.record_ixfr_started();
    state.metrics.record_ixfr_failed();
    state.metrics.record_notify_received();
    state.metrics.record_notify_unauthorized();
    state
        .metrics
        .record_query_response_rcode(Rcode::Refused as u16);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(listener, state, std::future::pending()));

    let transfers = http_json(addr, "/observability/v1/transfers").await;
    assert_eq!(transfers["data"]["counters"]["total_started"], 2);
    assert_eq!(transfers["data"]["counters"]["total_succeeded"], 1);
    assert_eq!(transfers["data"]["counters"]["total_failed"], 1);
    assert_eq!(transfers["data"]["active"]["status"], "not_tracked");

    let security = http_json(addr, "/observability/v1/security").await;
    assert_eq!(security["metrics_detail"], "reduced");
    assert_eq!(security["data"]["recursion"]["refused_queries"], "reduced");
    assert_eq!(security["data"]["notify"]["received"], 1);
    assert_eq!(security["data"]["notify"]["unauthorized"], 1);

    server.abort();
}

#[tokio::test]
async fn health_endpoint_exits_on_graceful_shutdown_signal() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_health(listener, health_state(zones), async move {
        let _ = shutdown_rx.await;
    }));

    let ready = http_request(addr, "GET", "/healthz").await;
    assert!(ready.starts_with("HTTP/1.1 200 OK"));
    assert!(ready.ends_with(concat!(
        r#"{"status":"ready","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","zones_active":1,"zones_loading":0,"zones_expired":0}"#
    )));

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("health listener did not stop after graceful shutdown signal")
        .expect("health listener task panicked")
        .expect("health listener returned an error");
}

#[tokio::test]
async fn health_connection_admission_closes_excess_and_recovers_capacity() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let mut state = health_state(zones);
    state.connection_slots = Arc::new(Semaphore::new(1));
    let slots = state.connection_slots.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(listener, state, std::future::pending()));

    let first = TcpStream::connect(addr)
        .await
        .expect("first health connection");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while slots.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first health connection consumes the only admission slot");

    let mut second = TcpStream::connect(addr)
        .await
        .expect("second connection reaches listener");
    second
        .write_all(b"GET /livez HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .expect("write queued health request");
    let mut response = String::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        second.read_to_string(&mut response),
    )
    .await
    .expect("connection beyond the bound is closed promptly");
    assert!(response.is_empty());

    drop(first);
    let mut third = TcpStream::connect(addr)
        .await
        .expect("connection after capacity release");
    third
        .write_all(b"GET /livez HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .expect("write admitted health request");
    response.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        third.read_to_string(&mut response),
    )
    .await
    .expect("new health connection is admitted after a slot is released")
    .expect("read health response");
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    server.abort();
}

#[tokio::test]
async fn idle_and_partial_health_requests_time_out_and_release_saturated_capacity() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let mut state = health_state(zones);
    state.connection_slots = Arc::new(Semaphore::new(2));
    let slots = state.connection_slots.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health_with_request_read_timeout(
        listener,
        state,
        std::future::pending(),
        std::time::Duration::from_millis(50),
    ));

    let _idle = TcpStream::connect(addr)
        .await
        .expect("idle management connection");
    let mut partial = TcpStream::connect(addr)
        .await
        .expect("partial management connection");
    partial
        .write_all(b"GET /livez HTTP/1.1\r\n")
        .await
        .expect("write incomplete request header");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while slots.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("idle clients saturate management capacity");

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while slots.available_permits() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("request read deadlines release every saturated permit");

    let response = http_request(addr, "GET", "/livez").await;
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    server.abort();
}

#[tokio::test]
async fn slow_drip_health_request_hits_absolute_deadline_and_releases_capacity() {
    let mut state = health_state(ZoneStore::new());
    state.connection_slots = Arc::new(Semaphore::new(1));
    let slots = state.connection_slots.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let request_timeout = std::time::Duration::from_millis(120);
    let server = tokio::spawn(serve_health_with_request_read_timeout(
        listener,
        state,
        std::future::pending(),
        request_timeout,
    ));

    let mut trickle = TcpStream::connect(addr)
        .await
        .expect("slow-drip management connection");
    trickle
        .write_all(b"GET /livez HTTP/1.1\r\nhost: local")
        .await
        .expect("write initial incomplete request header");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while slots.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("slow-drip request consumes the only admission slot");

    let dripper = tokio::spawn(async move {
        for _ in 0..8 {
            tokio::time::sleep(std::time::Duration::from_millis(35)).await;
            if trickle.write_all(b"x").await.is_err() {
                break;
            }
        }
    });

    tokio::time::timeout(std::time::Duration::from_millis(500), async {
        while slots.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("absolute request deadline releases capacity despite sub-idle-timeout chunks");

    let response = http_request(addr, "GET", "/livez").await;
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    dripper.abort();
    server.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn stalled_management_response_write_releases_capacity_and_health_recovers() {
    let zones = ZoneStore::new();
    for index in 0..2_048 {
        let origin = DomainName::from_absolute_str(&format!(
            "zone-{index:04}.management-response-timeout.example.test."
        ))
        .unwrap();
        zones.insert_snapshot(ZoneSnapshot::active(origin, Some(index), Vec::new()));
    }
    let mut state = health_state_with_observability(
        zones,
        ObservabilityConfig {
            enabled: true,
            ..ObservabilityConfig::default()
        },
    );
    state.connection_slots = Arc::new(Semaphore::new(1));
    let slots = state.connection_slots.clone();
    let listener_socket = TcpSocket::new_v4().expect("management listener socket");
    listener_socket
        .set_send_buffer_size(4_096)
        .expect("set management listener send buffer");
    listener_socket
        .bind("127.0.0.1:0".parse().unwrap())
        .expect("bind management listener socket");
    let listener = listener_socket
        .listen(1_024)
        .expect("listen on management socket");
    let addr = listener.local_addr().unwrap();
    // Accepted TCP sockets inherit the listener's send-buffer setting. Keeping
    // it small makes a non-reading client deterministic without constructing an
    // excessively large observability snapshot.
    let server = tokio::spawn(serve_health_with_connection_timeouts(
        listener,
        state,
        std::future::pending(),
        std::time::Duration::from_secs(1),
        std::time::Duration::from_millis(50),
    ));

    let mut stalled = TcpStream::connect(addr)
        .await
        .expect("non-reading management client");
    stalled
        .write_all(
            b"GET /observability/v1/zones HTTP/1.1\r\nhost: localhost\r\nconnection: keep-alive\r\n\r\n",
        )
        .await
        .expect("request large observability response");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while slots.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stalled response consumes the only management permit");

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while slots.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("response write deadline releases the management permit");

    let recovered = http_request(addr, "GET", "/livez").await;
    assert!(recovered.starts_with("HTTP/1.1 200 OK"));
    drop(stalled);
    server.abort();
}

#[tokio::test]
async fn completed_keep_alive_response_starts_a_fresh_write_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health_with_connection_timeouts(
        listener,
        health_state(ZoneStore::new()),
        std::future::pending(),
        std::time::Duration::from_millis(500),
        std::time::Duration::from_millis(50),
    ));
    let mut connection = TcpStream::connect(addr)
        .await
        .expect("keep-alive management connection");
    connection
        .write_all(b"GET /livez HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .expect("write first request");
    let mut first_response = vec![0_u8; 1_024];
    let first_len = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        connection.read(&mut first_response),
    )
    .await
    .expect("first response arrives")
    .expect("read first response");
    assert!(first_response[..first_len].starts_with(b"HTTP/1.1 200 OK"));

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    connection
        .write_all(b"GET /livez HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .expect("write second request after first write deadline");
    let mut second_response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        connection.read_to_string(&mut second_response),
    )
    .await
    .expect("second response uses a fresh write deadline")
    .expect("read second response");
    assert!(
        second_response.contains("HTTP/1.1 200 OK"),
        "second response bytes: {second_response:?}"
    );
    server.abort();
}

#[tokio::test]
async fn completed_keep_alive_request_starts_a_fresh_absolute_deadline() {
    let mut state = health_state(ZoneStore::new());
    state.connection_slots = Arc::new(Semaphore::new(1));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let request_timeout = std::time::Duration::from_millis(160);
    let server = tokio::spawn(serve_health_with_request_read_timeout(
        listener,
        state,
        std::future::pending(),
        request_timeout,
    ));

    let mut connection = TcpStream::connect(addr)
        .await
        .expect("keep-alive management connection");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    connection
        .write_all(b"GET /livez HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await
        .expect("write first keep-alive request");

    let mut first_response = vec![0_u8; 1024];
    let first_len = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        connection.read(&mut first_response),
    )
    .await
    .expect("first keep-alive response arrives")
    .expect("read first keep-alive response");
    assert!(first_response[..first_len].starts_with(b"HTTP/1.1 200 OK"));

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    connection
        .write_all(b"GET /livez HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .expect("write second keep-alive request after original deadline");
    let mut second_response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        connection.read_to_string(&mut second_response),
    )
    .await
    .expect("second keep-alive response arrives within fresh deadline")
    .expect("read second keep-alive response");
    assert!(second_response.starts_with("HTTP/1.1 200 OK"));
    server.abort();
}

#[tokio::test]
async fn idle_health_listener_does_not_reserve_global_connection_capacity() {
    let slots = Arc::new(Semaphore::new(2));
    let mut first_state = health_state(ZoneStore::new());
    first_state.connection_slots = slots.clone();
    let mut second_state = health_state(ZoneStore::new());
    second_state.connection_slots = slots.clone();
    let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first_listener.local_addr().unwrap();
    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_server = tokio::spawn(serve_health(
        first_listener,
        first_state,
        std::future::pending(),
    ));
    let second_server = tokio::spawn(serve_health(
        second_listener,
        second_state,
        std::future::pending(),
    ));
    tokio::task::yield_now().await;
    assert_eq!(slots.available_permits(), 2);

    let _first = TcpStream::connect(first_addr)
        .await
        .expect("first busy-listener connection");
    let _second = TcpStream::connect(first_addr)
        .await
        .expect("second busy-listener connection");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while slots.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("one listener can consume all global capacity");
    first_server.abort();
    second_server.abort();
}

#[test]
fn runtime_rejects_hostile_programmatic_health_connection_limits() {
    let config = ServerConfig::from_toml_str(
        r#"
            [server]
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []

            [[zones]]
            name = "example.test."
            primaries = ["192.0.2.53:53"]
        "#,
    )
    .expect("valid base config");

    for value in [0usize, usize::MAX] {
        let mut hostile = config.clone();
        hostile.health.max_connections = value;
        let error = Runtime::new(hostile)
            .expect_err("Runtime::new must revalidate programmatically mutated health limits");
        assert!(error.to_string().contains("health.max_connections"));
    }
}

#[tokio::test]
async fn health_shutdown_completes_while_connection_capacity_is_saturated() {
    let mut state = health_state(ZoneStore::new());
    state.connection_slots = Arc::new(Semaphore::new(1));
    let slots = state.connection_slots.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_health(listener, state, async move {
        let _ = shutdown_rx.await;
    }));

    let _first = TcpStream::connect(addr)
        .await
        .expect("first health connection");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while slots.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first health connection consumes the only slot");
    let _excess = TcpStream::connect(addr)
        .await
        .expect("excess health connection reaches listener");

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("shutdown completes with saturated health admission")
        .expect("health listener task panicked")
        .expect("health listener returned an error");
}

#[tokio::test(flavor = "current_thread")]
async fn health_shutdown_completes_during_sustained_ready_accept_flood() {
    let mut state = health_state(ZoneStore::new());
    state.connection_slots = Arc::new(Semaphore::new(1));
    let held_slot = state
        .connection_slots
        .clone()
        .acquire_owned()
        .await
        .expect("hold the global management connection slot");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_health(listener, state, async move {
        let _ = shutdown_rx.await;
    }));

    let stop = Arc::new(AtomicBool::new(false));
    let successful_connections = Arc::new(AtomicUsize::new(0));
    let flood = {
        let stop = stop.clone();
        let successful_connections = successful_connections.clone();
        tokio::spawn(async move {
            while !stop.load(Ordering::Acquire) {
                if let Ok(stream) = TcpStream::connect(addr).await {
                    successful_connections.fetch_add(1, Ordering::Release);
                    drop(stream);
                }
            }
        })
    };

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while successful_connections.load(Ordering::Acquire) < 32 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sustained flood keeps the saturated accept queue active");

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("saturated ready accept flood starved graceful shutdown")
        .expect("health listener task panicked")
        .expect("health listener returned an error");

    stop.store(true, Ordering::Release);
    flood.abort();
    drop(held_slot);
}

#[test]
fn metrics_body_reports_loading_duration_seconds() {
    let zones = ZoneStore::new();
    let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(
        active_origin.clone(),
        Some(1),
        vec![Rrset::new(
            active_origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        )],
    ));
    zones.insert_loading(DomainName::from_absolute_str("loading.test.").unwrap());

    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = metrics_body(
        &zones,
        &RuntimeMetrics::new(),
        &CatalogManager::default(),
        &refresh_registry,
        3600,
        false,
    );

    assert!(metrics.contains("oxidedns_zone_loading_seconds{zone=\"example.test.\"} 0"));
    assert!(metrics.contains("oxidedns_zone_loading_seconds{zone=\"loading.test.\"} 3600"));
    assert!(metrics.contains("oxidedns_secondary_zone_loading_seconds{zone=\"example.test.\"} 0"));
    assert!(
        metrics.contains("oxidedns_secondary_zone_loading_seconds{zone=\"loading.test.\"} 3600")
    );
    assert!(!metrics.contains("oxidedns_zone_shape_rrsets"));
}

#[test]
fn metrics_body_reports_catalog_membership() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let catalog_manager = CatalogManager {
        catalogs_by_key: Arc::new(HashMap::new()),
        static_zone_keys: Arc::new(HashSet::from(["static.example.".to_owned()])),
        memberships_by_catalog: Arc::new(Mutex::new(HashMap::from([(
            "catalog.example.".to_owned(),
            HashMap::from([
                (
                    "alpha.example.".to_owned(),
                    DomainName::from_absolute_str("alpha.example.").unwrap(),
                ),
                (
                    "static.example.".to_owned(),
                    DomainName::from_absolute_str("static.example.").unwrap(),
                ),
            ]),
        )]))),
        desired_memberships_by_catalog: Arc::new(Mutex::new(HashMap::new())),
        member_owners_by_key: Arc::new(Mutex::new(HashMap::new())),
        notify_refresh_registry: Arc::new(Mutex::new(None)),
        ixfr_cooldown_registry: Arc::new(Mutex::new(None)),
        reconcile_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    let metrics = metrics_body(
        &zones,
        &RuntimeMetrics::new(),
        &catalog_manager,
        &refresh_registry,
        0,
        false,
    );

    assert!(metrics.contains(
            "oxidedns_catalog_member_info{catalog_zone=\"catalog.example.\",zone=\"alpha.example.\",managed=\"true\"} 1"
        ));
    assert!(metrics.contains(
            "oxidedns_catalog_member_info{catalog_zone=\"catalog.example.\",zone=\"static.example.\",managed=\"false\"} 1"
        ));
}

#[tokio::test]
async fn health_endpoint_handles_readyz_metrics_404_and_405() {
    let zones = ZoneStore::new();
    let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(
        active_origin.clone(),
        Some(1),
        vec![Rrset::new(
            active_origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        )],
    ));
    zones.insert_loading(DomainName::from_absolute_str("loading.test.").unwrap());
    let metrics_state = RuntimeMetrics::new();
    metrics_state.record_axfr_started();
    metrics_state.record_axfr_succeeded();
    let active_zone_key = active_origin.canonical_key();
    let active_zone_metric = metrics_state
        .record_zone_query_key(&active_zone_key)
        .expect("full metrics return a zone token");
    let _ = metrics_state.record_zone_query_key(&active_zone_key);
    metrics_state.record_query_received();
    metrics_state.record_query_received();
    metrics_state.record_query_truncated();
    metrics_state.record_query_cname_chain_limit();
    metrics_state.record_query_cname_loop();
    metrics_state.record_query_response_rcode(0);
    metrics_state.record_query_response_rcode(3);
    metrics_state.record_query_response_rcode(23);
    metrics_state.record_zone_query_response_rcode(&active_zone_metric, 0);
    metrics_state.record_zone_query_response_rcode(&active_zone_metric, 3);
    metrics_state.record_query_latency(
        QueryLatencyCategory::UdpDirect,
        std::time::Duration::from_micros(250),
    );
    metrics_state.record_query_latency(
        QueryLatencyCategory::TcpCnameChain,
        std::time::Duration::from_millis(3),
    );
    metrics_state.set_configuration_warnings(4);
    metrics_state.record_notify_received();
    metrics_state.record_notify_unauthorized();
    metrics_state.record_notify_refresh_action(NotifyRefreshAction::Signalled);
    metrics_state.record_notify_refresh_action(NotifyRefreshAction::Deduplicated);
    metrics_state.record_notify_tsig_result(NotifyTsigResult::Ok);
    metrics_state.record_notify_tsig_result(NotifyTsigResult::BadKey);
    metrics_state.record_notify_tsig_result(NotifyTsigResult::BadSig);
    metrics_state.record_notify_tsig_result(NotifyTsigResult::BadTime);
    metrics_state.record_notify_tsig_result(NotifyTsigResult::BadAlg);
    metrics_state.record_notify_tsig_result(NotifyTsigResult::BadTrunc);
    let cookie_prefix_metrics = cookie_prefix_metrics_for_test();
    metrics_state.record_dns_cookie_status(
        DnsCookieRequestStatus::NoCookie,
        "192.0.2.10".parse().unwrap(),
        cookie_prefix_metrics,
    );
    metrics_state.record_dns_cookie_status(
        DnsCookieRequestStatus::ClientCookieOnly,
        "192.0.2.10".parse().unwrap(),
        cookie_prefix_metrics,
    );
    metrics_state.record_dns_cookie_status(
        DnsCookieRequestStatus::ValidServerCookie,
        "2001:db8::10".parse().unwrap(),
        cookie_prefix_metrics,
    );
    metrics_state.record_dns_cookie_status(
        DnsCookieRequestStatus::InvalidServerCookie,
        "2001:db8::10".parse().unwrap(),
        cookie_prefix_metrics,
    );
    metrics_state.record_dns_cookie_badcookie();
    metrics_state.record_dns_cookie_badcookie_for_source(
        "192.0.2.10".parse().unwrap(),
        cookie_prefix_metrics,
    );
    metrics_state.record_nsec3_iterations_exceed_cap();
    metrics_state.record_chaos_query(ChaosQueryOutcome::Answered);
    metrics_state.record_chaos_query(ChaosQueryOutcome::MissingValue);
    metrics_state.record_chaos_query(ChaosQueryOutcome::UnrecognizedName);
    metrics_state.record_chaos_query(ChaosQueryOutcome::NonTxt);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let refresh_now = std::time::Instant::now();
    let refresh_unix = 1_700_000_000;
    refresh_registry.record_success_at_with_timestamp(
        zones
            .exact_zone_control_metadata(&active_origin)
            .as_ref()
            .expect("active metadata"),
        refresh_now,
        refresh_unix,
    );
    refresh_registry.record_failure_at_with_timestamp(
        &DomainName::from_absolute_str("loading.test.").unwrap(),
        None,
        refresh_now,
        refresh_unix,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(
        listener,
        HealthEndpointState {
            zones,
            runtime_status: RuntimeStatus::new(),
            metrics: metrics_state,
            catalog_manager: CatalogManager::default(),
            refresh_registry,
            metrics_rate_limiter: MetricsRateLimiter::default(),
            observability: ObservabilityConfig::default(),
            observability_auth: ObservabilityAuth::default(),
            observability_rate_limiter: MetricsRateLimiter::from_observability_config(
                &ObservabilityConfig::default(),
            ),
            transfer_materials: Vec::new(),
            secrets: SecretManager::empty_for_test(),
            started_at: std::time::Instant::now(),
            graceful_shutdown_secs: 30,
            zone_shape_metrics_enabled: true,
            connection_slots: Arc::new(Semaphore::new(DEFAULT_HEALTH_MAX_CONNECTIONS)),
        },
        std::future::pending(),
    ));

    let ready = http_request(addr, "GET", "/readyz").await;
    assert!(ready.starts_with("HTTP/1.1 200 OK"));
    assert!(ready.ends_with(concat!(
        r#"{"status":"ready","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","zones_active":1,"zones_loading":1,"zones_expired":0}"#
    )));

    let metrics = http_request(addr, "GET", "/metrics").await;
    assert!(metrics.starts_with("HTTP/1.1 200 OK"));
    assert!(metrics.contains("content-type: text/plain; version=0.0.4; charset=utf-8"));
    assert!(!metrics.contains("content-encoding: gzip"));
    assert!(metrics.contains("oxidedns_zones_total 2"));
    assert!(metrics.contains("oxidedns_zones_active 1"));
    assert!(metrics.contains("oxidedns_queries_received_total 2"));
    assert!(metrics.contains("oxidedns_queries_truncated_total 1"));
    assert!(metrics.contains("oxidedns_queries_cname_chain_limit_total 1"));
    assert!(metrics.contains("oxidedns_queries_cname_loop_total 1"));
    assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"NOERROR\"} 1"));
    assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"SERVFAIL\"} 0"));
    assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"NXDOMAIN\"} 1"));
    assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"BADCOOKIE\"} 1"));
    assert!(metrics.contains("oxidedns_secondary_query_responses_total{rcode=\"NOERROR\"} 1"));
    assert!(metrics.contains("oxidedns_secondary_query_responses_total{rcode=\"BADCOOKIE\"} 1"));
    assert!(metrics.contains(concat!(
        "oxidedns_secondary_build_info{version=\"",
        env!("CARGO_PKG_VERSION"),
        "\",commit=\""
    )));
    assert!(metrics.contains("rust_version=\"rustc "));
    assert!(metrics.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"udp_direct\",le=\"0.0001\"} 0"
        ));
    assert!(metrics.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"udp_direct\",le=\"0.00025\"} 1"
        ));
    assert!(metrics.contains(
        "oxidedns_secondary_query_duration_seconds_sum{query_category=\"udp_direct\"} 0.000250000"
    ));
    assert!(metrics.contains(
        "oxidedns_secondary_query_duration_seconds_count{query_category=\"udp_direct\"} 1"
    ));
    assert!(metrics.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"tcp_cname_chain\",le=\"0.0025\"} 0"
        ));
    assert!(metrics.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"tcp_cname_chain\",le=\"0.005\"} 1"
        ));
    assert!(metrics.contains("oxidedns_dns_cookie_queries_total{case=\"no_cookie\"} 1"));
    assert!(metrics.contains("oxidedns_dns_cookie_queries_total{case=\"client_only\"} 1"));
    assert!(metrics.contains("oxidedns_dns_cookie_queries_total{case=\"valid_server\"} 1"));
    assert!(metrics.contains("oxidedns_dns_cookie_queries_total{case=\"invalid_server\"} 1"));
    assert!(metrics.contains("oxidedns_dns_cookie_badcookie_responses_total 1"));
    assert!(metrics.contains(
            "oxidedns_dns_cookie_queries_by_prefix_total{source_prefix=\"192.0.2.0/24\",case=\"no_cookie\"} 1"
        ));
    assert!(metrics.contains(
            "oxidedns_dns_cookie_queries_by_prefix_total{source_prefix=\"192.0.2.0/24\",case=\"client_only\"} 1"
        ));
    assert!(metrics.contains(
            "oxidedns_dns_cookie_queries_by_prefix_total{source_prefix=\"2001:db8::/56\",case=\"valid_server\"} 1"
        ));
    assert!(metrics.contains(
        "oxidedns_dns_cookie_badcookie_responses_by_prefix_total{source_prefix=\"192.0.2.0/24\"} 1"
    ));
    assert!(metrics.contains("oxidedns_secondary_configuration_warnings_total 4"));
    assert!(metrics.contains("oxidedns_dnssec_nsec3_iterations_exceed_cap_total 1"));
    assert!(metrics.contains("oxidedns_chaos_queries_total{outcome=\"answered\"} 1"));
    assert!(metrics.contains("oxidedns_chaos_queries_total{outcome=\"missing_value\"} 1"));
    assert!(metrics.contains("oxidedns_chaos_queries_total{outcome=\"unrecognized_name\"} 1"));
    assert!(metrics.contains("oxidedns_chaos_queries_total{outcome=\"non_txt\"} 1"));
    assert!(metrics.contains("oxidedns_transfer_sessions_started_total{protocol=\"axfr\"} 1"));
    assert!(metrics.contains("oxidedns_transfer_sessions_started_total{protocol=\"ixfr\"} 0"));
    assert!(metrics.contains("oxidedns_transfer_sessions_completed_total{protocol=\"axfr\"} 1"));
    assert!(metrics.contains("oxidedns_transfer_sessions_failed_total{protocol=\"axfr\"} 0"));
    assert!(metrics.contains("oxidedns_notify_messages_received_total 1"));
    assert!(metrics.contains("oxidedns_notify_messages_unauthorized_total 1"));
    assert!(metrics.contains("oxidedns_notify_refresh_actions_total{action=\"signalled\"} 1"));
    assert!(metrics.contains("oxidedns_notify_refresh_actions_total{action=\"deduplicated\"} 1"));
    assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"ok\"} 1"));
    assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"badkey\"} 1"));
    assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"badsig\"} 1"));
    assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"badtime\"} 1"));
    assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"badalg\"} 1"));
    assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"badtrunc\"} 1"));
    assert!(metrics.contains("oxidedns_zone_state{zone=\"example.test.\",state=\"active\"} 1"));
    assert!(metrics.contains("oxidedns_zone_state{zone=\"example.test.\",state=\"loading\"} 0"));
    assert!(metrics.contains("oxidedns_zone_state{zone=\"loading.test.\",state=\"loading\"} 1"));
    assert!(metrics.contains("oxidedns_zone_loading_seconds{zone=\"example.test.\"} 0"));
    assert!(metrics.contains("oxidedns_zone_loading_seconds{zone=\"loading.test.\"} "));
    assert!(
        metrics
            .contains("oxidedns_secondary_zone_state{zone=\"example.test.\",state=\"active\"} 1")
    );
    assert!(
        metrics
            .contains("oxidedns_secondary_zone_state{zone=\"example.test.\",state=\"loading\"} 0")
    );
    assert!(
        metrics
            .contains("oxidedns_secondary_zone_state{zone=\"loading.test.\",state=\"loading\"} 1")
    );
    assert!(metrics.contains("oxidedns_secondary_zone_loading_seconds{zone=\"example.test.\"} 0"));
    assert!(metrics.contains("oxidedns_secondary_zone_loading_seconds{zone=\"loading.test.\"} "));
    assert!(!metrics.contains("oxidedns_zone_soa_serial{zone=\"loading.test.\"}"));
    assert!(metrics.contains("oxidedns_zone_soa_serial{zone=\"example.test.\"} 1"));
    assert!(!metrics.contains("oxidedns_secondary_zone_soa_serial{zone=\"loading.test.\"}"));
    assert!(metrics.contains("oxidedns_secondary_zone_soa_serial{zone=\"example.test.\"} 1"));
    assert!(metrics.contains("oxidedns_zone_shape_rrsets{zone=\"example.test.\"} 1"));
    assert!(metrics.contains("oxidedns_zone_shape_rdata_records{zone=\"example.test.\"} 1"));
    assert!(metrics.contains("oxidedns_zone_shape_single_rdata_rrsets{zone=\"example.test.\"} 1"));
    assert!(metrics.contains("oxidedns_zone_shape_multi_rdata_rrsets{zone=\"example.test.\"} 0"));
    assert!(metrics.contains("oxidedns_zone_shape_spilled_rdata_rrsets{zone=\"example.test.\"} 0"));
    assert!(metrics.contains("oxidedns_zone_shape_max_rdata_per_rrset{zone=\"example.test.\"} 1"));
    assert!(metrics.contains("oxidedns_zone_shape_owner_names{zone=\"example.test.\"} 1"));
    assert!(
        metrics.contains("oxidedns_zone_shape_empty_non_terminal_names{zone=\"example.test.\"} 0")
    );
    assert!(
        metrics
            .contains("oxidedns_zone_shape_name_key_deduplicated_bytes{zone=\"example.test.\"} 13")
    );
    assert!(metrics.contains(
        "oxidedns_zone_shape_child_name_fanout_names{zone=\"example.test.\",bucket=\"0\"} 1"
    ));
    assert!(metrics.contains(
        "oxidedns_zone_shape_rrsets_per_owner_names{zone=\"example.test.\",bucket=\"1\"} 1"
    ));
    assert!(metrics.contains(
        "oxidedns_zone_shape_rdata_records_per_rrset{zone=\"example.test.\",bucket=\"1\"} 1"
    ));
    assert!(metrics.contains(
            "oxidedns_zone_shape_rdata_payload_bytes_per_rrset{zone=\"example.test.\",bucket=\"33_64\"} 1"
        ));
    assert!(!metrics.contains("oxidedns_zone_shape_rrsets{zone=\"loading.test.\"}"));
    assert!(metrics.contains(
        "oxidedns_zone_last_success_timestamp_seconds{zone=\"example.test.\"} 1700000000"
    ));
    assert!(metrics.contains(
        "oxidedns_secondary_zone_last_refresh_seconds{zone=\"example.test.\"} 1700000000"
    ));
    assert!(metrics.contains(
        "oxidedns_zone_next_refresh_timestamp_seconds{zone=\"example.test.\"} 1700003600"
    ));
    assert!(metrics.contains(
        "oxidedns_secondary_zone_next_refresh_seconds{zone=\"example.test.\"} 1700003600"
    ));
    assert!(
        !metrics.contains("oxidedns_zone_last_success_timestamp_seconds{zone=\"loading.test.\"}")
    );
    assert!(
        !metrics.contains("oxidedns_secondary_zone_last_refresh_seconds{zone=\"loading.test.\"}")
    );
    assert!(metrics.contains(
        "oxidedns_zone_next_refresh_timestamp_seconds{zone=\"loading.test.\"} 1700000060"
    ));
    assert!(metrics.contains(
        "oxidedns_secondary_zone_next_refresh_seconds{zone=\"loading.test.\"} 1700000060"
    ));
    assert!(
        metrics.contains("oxidedns_zone_refresh_failures_since_success{zone=\"example.test.\"} 0")
    );
    assert!(
        metrics.contains("oxidedns_zone_refresh_failures_since_success{zone=\"loading.test.\"} 1")
    );
    assert!(metrics.contains("oxidedns_secondary_zone_refresh_failures{zone=\"example.test.\"} 0"));
    assert!(metrics.contains("oxidedns_secondary_zone_refresh_failures{zone=\"loading.test.\"} 1"));
    assert!(metrics.contains("oxidedns_zone_queries_total{zone=\"example.test.\"} 2"));
    assert!(metrics.contains("oxidedns_zone_queries_total{zone=\"loading.test.\"} 0"));
    assert!(metrics.contains("oxidedns_secondary_queries_total{zone=\"example.test.\"} 2"));
    assert!(metrics.contains("oxidedns_secondary_queries_total{zone=\"loading.test.\"} 0"));
    assert!(metrics.contains(
        "oxidedns_zone_query_responses_total{zone=\"example.test.\",rcode=\"NOERROR\"} 1"
    ));
    assert!(metrics.contains(
        "oxidedns_zone_query_responses_total{zone=\"example.test.\",rcode=\"NXDOMAIN\"} 1"
    ));
    assert!(metrics.contains(
        "oxidedns_secondary_query_responses_total{zone=\"example.test.\",rcode=\"NOERROR\"} 1"
    ));
    assert!(metrics.contains(
        "oxidedns_secondary_query_responses_total{zone=\"loading.test.\",rcode=\"NOERROR\"} 0"
    ));

    let compressed_metrics =
        http_request_with_headers(addr, "GET", "/metrics", &[("Accept-Encoding", "gzip")]).await;
    let (compressed_headers, compressed_body) = split_http_response(&compressed_metrics);
    assert!(compressed_headers.starts_with("HTTP/1.1 200 OK"));
    assert!(compressed_headers.contains("content-type: text/plain; version=0.0.4; charset=utf-8"));
    assert!(compressed_headers.contains("content-encoding: gzip"));
    assert!(compressed_headers.contains("vary: accept-encoding"));
    let mut decoder = flate2::read::GzDecoder::new(compressed_body);
    let mut decoded_metrics = String::new();
    std::io::Read::read_to_string(&mut decoder, &mut decoded_metrics).unwrap();
    assert!(decoded_metrics.contains("oxidedns_zones_total 2"));
    assert!(decoded_metrics.contains(concat!(
        "oxidedns_secondary_build_info{version=\"",
        env!("CARGO_PKG_VERSION"),
        "\""
    )));
    assert!(decoded_metrics.contains(
        "oxidedns_secondary_query_duration_seconds_count{query_category=\"udp_direct\"} 1"
    ));

    let gzip_disallowed =
        http_request_with_headers(addr, "GET", "/metrics", &[("Accept-Encoding", "gzip;q=0")])
            .await;
    let (gzip_disallowed_headers, gzip_disallowed_body) = split_http_response(&gzip_disallowed);
    assert!(gzip_disallowed_headers.starts_with("HTTP/1.1 200 OK"));
    assert!(!gzip_disallowed_headers.contains("content-encoding: gzip"));
    let gzip_disallowed_body = std::str::from_utf8(gzip_disallowed_body).unwrap();
    assert!(gzip_disallowed_body.contains("oxidedns_zones_total 2"));

    let missing = http_request(addr, "GET", "/missing").await;
    assert!(missing.starts_with("HTTP/1.1 404 Not Found"));
    assert!(missing.ends_with(r#"{"error":"not_found","path":"/missing"}"#));

    for method in ["HEAD", "POST"] {
        for path in ["/livez", "/healthz", "/readyz", "/metrics"] {
            let method_not_allowed = http_request(addr, method, path).await;
            assert!(method_not_allowed.starts_with("HTTP/1.1 405 Method Not Allowed"));
            assert!(method_not_allowed.contains("content-type: application/json"));
            if method == "POST" {
                assert!(method_not_allowed.ends_with(&format!(
                    r#"{{"error":"method_not_allowed","path":"{path}"}}"#
                )));
            }
        }
    }

    server.abort();
}

#[tokio::test]
async fn metrics_endpoint_rate_limits_per_source_without_limiting_health() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(
        listener,
        HealthEndpointState {
            zones,
            runtime_status: RuntimeStatus::new(),
            metrics: RuntimeMetrics::new(),
            catalog_manager: CatalogManager::default(),
            refresh_registry: ZoneRefreshRegistry::without_jitter(
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(3600),
            ),
            metrics_rate_limiter: MetricsRateLimiter::from_config(HealthConfig {
                metrics_rate_limit_per_minute: 1,
                metrics_rate_limit_idle_seconds: 300,
                ..HealthConfig::default()
            }),
            observability: ObservabilityConfig::default(),
            observability_auth: ObservabilityAuth::default(),
            observability_rate_limiter: MetricsRateLimiter::from_observability_config(
                &ObservabilityConfig::default(),
            ),
            transfer_materials: Vec::new(),
            secrets: SecretManager::empty_for_test(),
            started_at: std::time::Instant::now(),
            graceful_shutdown_secs: 30,
            zone_shape_metrics_enabled: false,
            connection_slots: Arc::new(Semaphore::new(DEFAULT_HEALTH_MAX_CONNECTIONS)),
        },
        std::future::pending(),
    ));

    let first = http_request(addr, "GET", "/metrics").await;
    assert!(first.starts_with("HTTP/1.1 200 OK"));

    let limited = http_request(addr, "GET", "/metrics").await;
    assert!(limited.starts_with("HTTP/1.1 429 Too Many Requests"));
    assert!(limited.contains("content-type: application/json"));
    assert!(limited.contains("retry-after: 60"));
    assert!(limited.ends_with(r#"{"error":"rate_limited","retry_after_seconds":60}"#));

    let livez = http_request(addr, "GET", "/livez").await;
    assert!(livez.starts_with("HTTP/1.1 200 OK"));
    let readyz = http_request(addr, "GET", "/readyz").await;
    assert!(readyz.starts_with("HTTP/1.1 200 OK"));

    server.abort();
}

#[tokio::test]
async fn management_listeners_share_metrics_and_observability_source_quotas() {
    let health_port = unused_tcp_port_on_loopback_pair().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = []

            [interfaces]
            mgmt = ["127.0.0.1:9443", "127.0.0.2:9443"]

            [health]
            default_port = {health_port}
            metrics_rate_limit_per_minute = 1

            [observability]
            enabled = true
            rate_limit_per_minute = 1

            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:9"]
        "#
    ))
    .expect("valid multi-listener management config");
    let first_addr = format!("127.0.0.1:{health_port}")
        .parse::<std::net::SocketAddr>()
        .unwrap();
    let second_addr = format!("127.0.0.2:{health_port}")
        .parse::<std::net::SocketAddr>()
        .unwrap();
    assert_eq!(config.health_listeners(), vec![first_addr, second_addr]);

    let runtime = runtime_with_portable_resource_limits(config);
    let (server, bound_addr) = spawn_runtime_with_bound_health(runtime).await;
    assert_eq!(bound_addr, first_addr);

    let first_metrics = eventually_http_request(
        first_addr,
        "GET",
        "/metrics",
        std::time::Duration::from_secs(1),
    )
    .await;
    assert!(first_metrics.starts_with("HTTP/1.1 200 OK"));
    let second_metrics = eventually_http_request(
        second_addr,
        "GET",
        "/metrics",
        std::time::Duration::from_secs(1),
    )
    .await;
    assert!(second_metrics.starts_with("HTTP/1.1 429 Too Many Requests"));

    let first_observability = http_request(first_addr, "GET", "/observability/v1").await;
    assert!(first_observability.starts_with("HTTP/1.1 200 OK"));
    let second_observability = http_request(second_addr, "GET", "/observability/v1").await;
    assert!(second_observability.starts_with("HTTP/1.1 429 Too Many Requests"));

    server.abort();
}

#[tokio::test]
async fn health_endpoint_reports_draining_and_unready_during_shutdown() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        Vec::new(),
    ));
    let runtime_status = RuntimeStatus::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_health(
        listener,
        HealthEndpointState {
            zones,
            runtime_status: runtime_status.clone(),
            metrics: RuntimeMetrics::new(),
            catalog_manager: CatalogManager::default(),
            refresh_registry: ZoneRefreshRegistry::without_jitter(
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(3600),
            ),
            metrics_rate_limiter: MetricsRateLimiter::default(),
            observability: ObservabilityConfig::default(),
            observability_auth: ObservabilityAuth::default(),
            observability_rate_limiter: MetricsRateLimiter::from_observability_config(
                &ObservabilityConfig::default(),
            ),
            transfer_materials: Vec::new(),
            secrets: SecretManager::empty_for_test(),
            started_at: std::time::Instant::now(),
            graceful_shutdown_secs: 30,
            zone_shape_metrics_enabled: false,
            connection_slots: Arc::new(Semaphore::new(DEFAULT_HEALTH_MAX_CONNECTIONS)),
        },
        std::future::pending(),
    ));

    runtime_status.mark_draining();

    let health = http_request(addr, "GET", "/healthz").await;
    assert!(health.starts_with("HTTP/1.1 503 Service Unavailable"));
    assert!(health.ends_with(concat!(
        r#"{"status":"draining","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","grace_period_remaining_seconds":30}"#
    )));

    let livez = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        http_request(addr, "GET", "/livez"),
    )
    .await
    .expect("/livez should remain responsive while draining");
    assert!(livez.starts_with("HTTP/1.1 200 OK"));

    let ready = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        http_request(addr, "GET", "/readyz"),
    )
    .await
    .expect("/readyz should answer within SRS health bound while draining");
    assert!(ready.starts_with("HTTP/1.1 503 Service Unavailable"));
    assert!(ready.ends_with(concat!(
        r#"{"status":"draining","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","grace_period_remaining_seconds":30}"#
    )));

    runtime_status.mark_unhealthy();
    let unhealthy = http_request(addr, "GET", "/healthz").await;
    assert!(unhealthy.starts_with("HTTP/1.1 503 Service Unavailable"));
    assert!(unhealthy.ends_with(concat!(
        r#"{"status":"unhealthy","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#""}"#
    )));

    server.abort();
}

#[tokio::test]
async fn runtime_binds_health_while_initial_transfer_is_in_progress() {
    let (primary, query_seen, release_primary) = spawn_blocked_axfr_primary().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []
                health = "127.0.0.1:0"

                [limits]
                axfr_timeout_secs = 5
                graceful_shutdown_secs = 1

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let runtime = runtime_with_portable_resource_limits(config);
    let (server, health_addr) = spawn_runtime_with_bound_health(runtime).await;

    tokio::time::timeout(std::time::Duration::from_secs(1), query_seen)
        .await
        .expect("initial transfer should start")
        .expect("primary should observe initial transfer query");

    let health = eventually_http_request(
        health_addr,
        "GET",
        "/healthz",
        std::time::Duration::from_secs(1),
    )
    .await;
    assert!(health.starts_with("HTTP/1.1 503 Service Unavailable"));
    assert!(health.ends_with(concat!(
        r#"{"status":"not-ready","reason":"loading","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","zones_active":0,"zones_loading":1,"zones_expired":0}"#
    )));

    let _ = release_primary.send(());
    server.abort();
}

#[tokio::test]
async fn runtime_does_not_open_health_listener_when_unconfigured() {
    let (primary, query_seen, release_primary) = spawn_blocked_axfr_primary().await;
    let tcp_guard = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = tcp_guard.local_addr().unwrap();
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["{udp_addr}"]
                listen_tcp = []

                [limits]
                axfr_timeout_secs = 5
                graceful_shutdown_secs = 1

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    assert_eq!(config.server.health, None);
    let runtime = runtime_with_portable_resource_limits(config);
    let server = tokio::spawn(runtime.run());

    tokio::time::timeout(std::time::Duration::from_secs(1), query_seen)
        .await
        .expect("initial transfer should start")
        .expect("primary should observe initial transfer query");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !server.is_finished(),
        "health endpoint must not listen when server.health is unset"
    );

    let _ = release_primary.send(());
    server.abort();
}

#[tokio::test]
async fn runtime_binds_health_on_management_interface() {
    let (primary, query_seen, release_primary) = spawn_blocked_axfr_primary().await;
    let health_port = unused_udp_tcp_addr().await.port();
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []

                [interfaces]
                mgmt = ["127.0.0.1:9443"]

                [health]
                default_port = {health_port}

                [limits]
                axfr_timeout_secs = 5
                graceful_shutdown_secs = 1

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    assert_eq!(config.server.health, None);
    assert_eq!(
        config.health_listeners(),
        vec![
            format!("127.0.0.1:{health_port}")
                .parse::<std::net::SocketAddr>()
                .unwrap()
        ]
    );
    let runtime = runtime_with_portable_resource_limits(config);
    let (server, health_addr) = spawn_runtime_with_bound_health(runtime).await;
    assert_eq!(health_addr.port(), health_port);

    tokio::time::timeout(std::time::Duration::from_secs(1), query_seen)
        .await
        .expect("initial transfer should start")
        .expect("primary should observe initial transfer query");

    let health = eventually_http_request(
        health_addr,
        "GET",
        "/healthz",
        std::time::Duration::from_secs(1),
    )
    .await;
    assert!(health.starts_with("HTTP/1.1 503 Service Unavailable"));
    assert!(health.ends_with(concat!(
        r#"{"status":"not-ready","reason":"loading","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","zones_active":0,"zones_loading":1,"zones_expired":0}"#
    )));

    let _ = release_primary.send(());
    server.abort();
}

#[tokio::test]
async fn runtime_reports_draining_until_initial_transfer_releases() {
    let (primary, query_seen, release_primary) = spawn_blocked_axfr_primary().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []
                health = "127.0.0.1:0"

                [limits]
                axfr_timeout_secs = 5
                graceful_shutdown_secs = 2

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let runtime = runtime_with_portable_resource_limits(config);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (server, health_addr) = spawn_runtime_with_bound_health_and_shutdown(runtime, async move {
        shutdown_rx.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Interrupted, "test shutdown dropped")
        })
    })
    .await;

    tokio::time::timeout(std::time::Duration::from_secs(1), query_seen)
        .await
        .expect("initial transfer should start")
        .expect("primary should observe initial transfer query");
    let starting = eventually_health_body(
        health_addr,
        concat!(
            r#"{"status":"not-ready","reason":"loading","version":""#,
            env!("CARGO_PKG_VERSION"),
            r#"","zones_active":0,"zones_loading":1,"zones_expired":0}"#
        ),
        std::time::Duration::from_secs(1),
    )
    .await;
    assert!(starting.starts_with("HTTP/1.1 503 Service Unavailable"));

    shutdown_tx
        .send("SIGTERM")
        .expect("runtime receives shutdown");
    let draining = eventually_health_body(
        health_addr,
        concat!(
            r#"{"status":"draining","version":""#,
            env!("CARGO_PKG_VERSION"),
            r#"","grace_period_remaining_seconds":2}"#
        ),
        std::time::Duration::from_secs(1),
    )
    .await;
    assert!(draining.starts_with("HTTP/1.1 503 Service Unavailable"));

    let _ = release_primary.send(());
    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("runtime should finish after transfer release")
        .expect("runtime task should join")
        .expect("runtime should shut down cleanly");
}

#[tokio::test]
async fn runtime_sigterm_stops_tcp_accept_and_drains_established_query() {
    let primary = spawn_axfr_primary().await;
    let dns_addr = unused_udp_tcp_addr().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = ["{dns_addr}"]
                health = "127.0.0.1:0"

                [limits]
                graceful_shutdown_secs = 2

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let runtime = runtime_with_portable_resource_limits(config);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (server, health_addr) = spawn_runtime_with_bound_health_and_shutdown(runtime, async move {
        shutdown_rx.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Interrupted, "test shutdown dropped")
        })
    })
    .await;

    eventually_health_body(
        health_addr,
        concat!(
            r#"{"status":"ready","version":""#,
            env!("CARGO_PKG_VERSION"),
            r#"","zones_active":1,"zones_loading":0,"zones_expired":0}"#
        ),
        std::time::Duration::from_secs(1),
    )
    .await;

    let framed = frame_tcp_message(&query(
        b"\x03www\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    ));
    let mut client = TcpStream::connect(dns_addr).await.unwrap();
    client.write_all(&framed).await.unwrap();
    let warmup_response = read_framed_tcp_response(&mut client).await;
    assert_eq!(Header::parse(&warmup_response).unwrap().id, 0x1234);
    client.write_all(&framed[..2]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    shutdown_tx
        .send("SIGTERM")
        .expect("runtime receives shutdown");
    eventually_health_body(
        health_addr,
        concat!(
            r#"{"status":"draining","version":""#,
            env!("CARGO_PKG_VERSION"),
            r#"","grace_period_remaining_seconds":2}"#
        ),
        std::time::Duration::from_secs(1),
    )
    .await;
    eventually_tcp_connect_fails(dns_addr, std::time::Duration::from_secs(1)).await;

    client.write_all(&framed[2..]).await.unwrap();
    let response = read_framed_tcp_response(&mut client).await;
    assert_eq!(Header::parse(&response).unwrap().id, 0x1234);
    drop(client);

    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("runtime should finish after established query completes")
        .expect("runtime task should join")
        .expect("runtime should shut down cleanly");
}

#[tokio::test]
async fn runtime_sigterm_rejects_wholly_post_boundary_tcp_query() {
    let primary = spawn_axfr_primary().await;
    let dns_addr = unused_udp_tcp_addr().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = ["{dns_addr}"]
                health = "127.0.0.1:0"

                [limits]
                graceful_shutdown_secs = 2

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let runtime = runtime_with_portable_resource_limits(config);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (server, health_addr) = spawn_runtime_with_bound_health_and_shutdown(runtime, async move {
        shutdown_rx.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Interrupted, "test shutdown dropped")
        })
    })
    .await;

    eventually_health_body(
        health_addr,
        concat!(
            r#"{"status":"ready","version":""#,
            env!("CARGO_PKG_VERSION"),
            r#"","zones_active":1,"zones_loading":0,"zones_expired":0}"#
        ),
        std::time::Duration::from_secs(1),
    )
    .await;

    let mut client = TcpStream::connect(dns_addr).await.unwrap();
    let admitted = frame_tcp_message(&query(
        b"\x03www\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    ));
    client.write_all(&admitted).await.unwrap();
    let response = read_framed_tcp_response(&mut client).await;
    assert_eq!(Header::parse(&response).unwrap().id, 0x1234);

    shutdown_tx
        .send("SIGTERM")
        .expect("runtime receives shutdown");
    eventually_tcp_connect_fails(dns_addr, std::time::Duration::from_secs(1)).await;

    let mut post_boundary = admitted;
    post_boundary[2..4].copy_from_slice(&0x5678u16.to_be_bytes());
    if client.write_all(&post_boundary).await.is_ok() {
        let mut byte = [0u8; 1];
        let closed =
            tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
                .await
                .expect(
                    "established connection should close without answering a post-boundary query",
                );
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "post-boundary query unexpectedly received a response byte"
        );
    }

    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("runtime should finish after stopping established TCP reads")
        .expect("runtime task should join")
        .expect("runtime should shut down cleanly");
}

#[tokio::test]
async fn runtime_sigterm_force_cancels_tcp_connection_after_grace() {
    let primary = spawn_axfr_primary().await;
    let dns_addr = unused_udp_tcp_addr().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = ["{dns_addr}"]
                health = "127.0.0.1:0"

                [limits]
                graceful_shutdown_secs = 1

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let runtime = runtime_with_portable_resource_limits(config);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (server, health_addr) = spawn_runtime_with_bound_health_and_shutdown(runtime, async move {
        shutdown_rx.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Interrupted, "test shutdown dropped")
        })
    })
    .await;

    eventually_health_body(
        health_addr,
        concat!(
            r#"{"status":"ready","version":""#,
            env!("CARGO_PKG_VERSION"),
            r#"","zones_active":1,"zones_loading":0,"zones_expired":0}"#
        ),
        std::time::Duration::from_secs(1),
    )
    .await;

    let framed = frame_tcp_message(&query(
        b"\x03www\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    ));
    let mut client = TcpStream::connect(dns_addr).await.unwrap();
    client.write_all(&framed).await.unwrap();
    let warmup_response = read_framed_tcp_response(&mut client).await;
    assert_eq!(Header::parse(&warmup_response).unwrap().id, 0x1234);
    client.write_all(&framed[..2]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    let shutdown_started = tokio::time::Instant::now();
    shutdown_tx
        .send("SIGTERM")
        .expect("runtime receives shutdown");
    eventually_tcp_connect_fails(dns_addr, std::time::Duration::from_secs(1)).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !server.is_finished(),
        "established TCP connection should remain alive during the grace period"
    );

    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .expect("runtime should force-cancel TCP connection after grace")
        .expect("runtime task should join")
        .expect("runtime should shut down cleanly");
    assert!(
        shutdown_started.elapsed() >= std::time::Duration::from_millis(800),
        "runtime force-cancelled before the configured grace period"
    );

    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("force-cancelled TCP connection should close promptly");
    assert!(matches!(closed, Ok(0) | Err(_)));
}

#[tokio::test]
async fn runtime_shutdown_uses_one_deadline_for_first_phase_and_held_health_connection() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (primary, transfer_started, _hold_transfer) = spawn_blocked_axfr_primary().await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []
                health = "127.0.0.1:0"

                [limits]
                graceful_shutdown_secs = 1
                axfr_timeout_secs = 30

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#,
        ))
        .expect("valid config");
        let runtime = runtime_with_portable_resource_limits(config);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (server, health_addr) =
            spawn_runtime_with_bound_health_and_shutdown(runtime, async move {
                shutdown_rx.await.map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::Interrupted, "test shutdown dropped")
                })
            })
            .await;
        tokio::time::timeout(std::time::Duration::from_secs(1), transfer_started)
            .await
            .expect("initial transfer did not reach the primary in time")
            .expect("blocked initial transfer reaches the first drain phase");
        eventually_health_body(
            health_addr,
            concat!(
                r#"{"status":"not-ready","reason":"loading","version":""#,
                env!("CARGO_PKG_VERSION"),
                r#"","zones_active":0,"zones_loading":1,"zones_expired":0}"#
            ),
            std::time::Duration::from_secs(1),
        )
        .await;

        // Hold one initial transfer in the first drain phase and one partial HTTP
        // request in the health server. The second phase must receive only the time
        // remaining from the single deadline, not a fresh grace period.
        let mut health_client = TcpStream::connect(health_addr).await.unwrap();
        health_client
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let shutdown_started = tokio::time::Instant::now();
        shutdown_tx.send("SIGTERM").unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(1_500), server)
            .await
            .expect("all runtime phases must fit inside one shutdown grace period")
            .expect("runtime task should join")
            .expect("runtime should shut down cleanly");
        let elapsed = shutdown_started.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_millis(800),
            "first-phase transfer should hold the runtime until near its deadline: {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(1_500),
            "health drain must not receive a second full grace period: {elapsed:?}"
        );

        drop(health_client);
    })
    .await
    .expect("absolute-deadline regression must never hang");
}

#[tokio::test]
async fn runtime_sigterm_force_cancel_does_not_detach_backpressured_tcp_writer() {
    const PIPELINED_QUERIES: usize = 512;
    const ANSWER_RECORDS: usize = 3_500;

    let (primary, _query_seen, _release_primary) = spawn_blocked_axfr_primary().await;
    let dns_addr = unused_udp_tcp_addr().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = ["{dns_addr}"]
                health = "127.0.0.1:0"

                [limits]
                graceful_shutdown_secs = 1
                tcp_write_timeout_secs = 30
                max_tcp_inflight_queries_per_connection = {PIPELINED_QUERIES}

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let runtime = runtime_with_portable_resource_limits(config);
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let owner = DomainName::from_absolute_str("www.example.test.").unwrap();
    let addresses = (0..ANSWER_RECORDS)
        .map(|index| vec![198, 51, ((index / 256) & 0xff) as u8, (index & 0xff) as u8])
        .collect();
    runtime.zones.insert_snapshot(ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![
            Rrset::new(origin, RecordType::Soa as u16, 1, 3_600, vec![soa_rdata()]),
            Rrset::new(owner, RecordType::A as u16, 1, 300, addresses),
        ],
    ));

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (server, health_addr) = spawn_runtime_with_bound_health_and_shutdown(runtime, async move {
        shutdown_rx.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Interrupted, "test shutdown dropped")
        })
    })
    .await;
    eventually_health_body(
        health_addr,
        concat!(
            r#"{"status":"ready","version":""#,
            env!("CARGO_PKG_VERSION"),
            r#"","zones_active":1,"zones_loading":0,"zones_expired":0}"#
        ),
        std::time::Duration::from_secs(1),
    )
    .await;

    let mut client = TcpStream::connect(dns_addr).await.unwrap();
    let mut pipelined = Vec::new();
    for query_id in 0..PIPELINED_QUERIES as u16 {
        let mut request = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        request[..2].copy_from_slice(&query_id.to_be_bytes());
        pipelined.extend_from_slice(&frame_tcp_message(&request));
    }
    client.write_all(&pipelined).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    shutdown_tx
        .send("SIGTERM")
        .expect("runtime receives shutdown");
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .expect("runtime should force-cancel the backpressured connection after grace")
        .expect("runtime task should join")
        .expect("runtime should shut down cleanly");

    // Drain slowly enough that a detached writer with hundreds of queued
    // responses cannot hide behind localhost throughput. A structurally owned
    // writer has already dropped its socket, leaving only the kernel-buffered
    // prefix before FIN/RST.
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut buffer = [0u8; 4096];
        loop {
            match client.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(1)).await,
            }
        }
    })
    .await
    .expect("no detached TCP writer/socket may survive beyond shutdown grace");
}

#[tokio::test]
async fn runtime_keeps_serving_after_initial_transfer_completes() {
    let primary = spawn_axfr_primary().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []
                health = "127.0.0.1:0"

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let runtime = runtime_with_portable_resource_limits(config);
    let (server, health_addr) = spawn_runtime_with_bound_health(runtime).await;

    let ready = eventually_health_body(
        health_addr,
        concat!(
            r#"{"status":"ready","version":""#,
            env!("CARGO_PKG_VERSION"),
            r#"","zones_active":1,"zones_loading":0,"zones_expired":0}"#
        ),
        std::time::Duration::from_secs(1),
    )
    .await;
    assert!(ready.starts_with("HTTP/1.1 200 OK"));

    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let still_ready = eventually_http_request(
        health_addr,
        "GET",
        "/healthz",
        std::time::Duration::from_secs(1),
    )
    .await;
    assert!(still_ready.starts_with("HTTP/1.1 200 OK"));
    assert!(still_ready.ends_with(concat!(
        r#"{"status":"ready","version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","zones_active":1,"zones_loading":0,"zones_expired":0}"#
    )));

    server.abort();
}

#[tokio::test]
async fn runtime_serves_queries_and_notify_on_configured_dns_interface() {
    let primary = spawn_axfr_primary().await;
    let dns_addr = unused_udp_tcp_addr().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = []
                listen_tcp = []
                health = "127.0.0.1:0"

                [interfaces]
                dns = ["{dns_addr}"]

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
                notify_sources = ["127.0.0.1"]
            "#
    ))
    .expect("valid config");
    let runtime = runtime_with_portable_resource_limits(config);
    let (server, health_addr) = spawn_runtime_with_bound_health(runtime).await;

    let ready = eventually_health_body(
        health_addr,
        concat!(
            r#"{"status":"ready","version":""#,
            env!("CARGO_PKG_VERSION"),
            r#"","zones_active":1,"zones_loading":0,"zones_expired":0}"#
        ),
        std::time::Duration::from_secs(1),
    )
    .await;
    assert!(ready.starts_with("HTTP/1.1 200 OK"));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    client.send_to(&request, dns_addr).await.unwrap();
    let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
        .await
        .expect("query response on DNS interface");
    let header = Header::parse(&response).unwrap();
    assert_eq!(header.id, 0x1234);
    assert_eq!(header.ancount, 1);
    assert_eq!(response_rcode(&response, &header), Rcode::NoError as u16);

    let notify = notify_packet(0x5678, "example.test.", RecordType::Soa as u16, 1);
    client.send_to(&notify, dns_addr).await.unwrap();
    let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
        .await
        .expect("NOTIFY response on DNS interface");
    let header = Header::parse(&response).unwrap();
    assert_eq!(header.id, 0x5678);
    assert_eq!(response_rcode(&response, &header), Rcode::NoError as u16);

    let mut tcp_client = TcpStream::connect(dns_addr).await.unwrap();
    let tcp_notify = notify_packet(0x6789, "example.test.", RecordType::Soa as u16, 1);
    tcp_client
        .write_all(&frame_tcp_message(&tcp_notify))
        .await
        .unwrap();
    let response = read_framed_tcp_response(&mut tcp_client).await;
    let header = Header::parse(&response).unwrap();
    assert_eq!(header.id, 0x6789);
    assert_eq!(response_rcode(&response, &header), Rcode::NoError as u16);

    server.abort();
}
