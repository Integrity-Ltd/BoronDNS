#[test]
fn runtime_initializes_loading_zones() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid config");

    let runtime = Runtime::new(config).expect("valid runtime configuration");
    assert_eq!(runtime.zone_count(), 1);
}

#[test]
fn runtime_constructor_rejects_programmatically_invalid_zone_name_without_panicking() {
    let mut config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("baseline config validates");
    config.zones[0].name = "not-an-absolute-name".to_owned();

    let error = Runtime::new(config).expect_err("invalid mutation must be rejected");
    let RuntimeError::InvalidRuntimeConfig(message) = error else {
        panic!("expected invalid runtime configuration, got {error}");
    };
    assert!(message.contains("absolute DNS name"));
}

#[test]
fn runtime_constructor_rejects_programmatic_udp_batch_overflow_before_listener_task() {
    let mut config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("baseline config validates");
    config.limits.udp_batch_size = usize::MAX;

    let error = Runtime::new(config).expect_err("invalid batch mutation must be rejected");
    let RuntimeError::InvalidRuntimeConfig(message) = error else {
        panic!("expected invalid runtime configuration, got {error}");
    };
    assert!(message.contains("udp_batch_size"));
}

#[test]
fn runtime_constructor_rejects_hostile_histogram_cardinality_before_metrics_allocation() {
    let mut config = ServerConfig::from_toml_str(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [[zones]]
            name = "example.test."
            primaries = ["192.0.2.53:53"]
        "#,
    )
    .expect("baseline config validates");
    config.metrics.latency_histogram_buckets = (1..=MAX_LATENCY_HISTOGRAM_BUCKETS + 1)
        .map(|value| LatencyHistogramBucketSeconds(value as f64))
        .collect();

    let error = Runtime::new(config)
        .expect_err("hostile programmatic histogram cardinality must be rejected");
    let RuntimeError::InvalidRuntimeConfig(message) = error else {
        panic!("expected invalid runtime configuration, got {error}");
    };
    assert!(message.contains(&MAX_LATENCY_HISTOGRAM_BUCKETS.to_string()));
}

#[tokio::test]
async fn runtime_run_revalidates_udp_batch_before_binding_or_spawning_listener() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("baseline config validates");
    let mut runtime = Runtime::new(config).expect("baseline runtime");
    runtime.config.limits.udp_batch_size = usize::MAX;

    let error = runtime
        .run_with_shutdown_signal(std::future::pending())
        .await
        .expect_err("run-time mutation must fail before listener startup");
    let RuntimeError::InvalidRuntimeConfig(message) = error else {
        panic!("expected invalid runtime configuration, got {error}");
    };
    assert!(message.contains("udp_batch_size"));
}

#[test]
fn runtime_constructor_rejects_programmatic_xdp_allocation_overflow() {
    let mut config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [limits]
                udp_backend = "af_xdp"

                [xdp]
                interface = "eth0"
                redirect_object = "target/borondns-xdp-redirect.bpf.o"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("baseline AF_XDP config validates");
    config.xdp.umem_frame_count = u32::MAX;
    config.xdp.rx_ring_size = 1 << 31;
    config.xdp.tx_ring_size = 1 << 31;
    config.xdp.batch_size = usize::MAX;

    let error = Runtime::new(config).expect_err("hostile XDP mutation must be rejected");
    let RuntimeError::InvalidRuntimeConfig(message) = error else {
        panic!("expected invalid runtime configuration, got {error}");
    };
    assert!(message.contains("xdp.umem_frame_count"));
}

#[tokio::test]
async fn runtime_run_revalidates_xdp_memory_before_socket_bind_or_umem_map() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [limits]
                udp_backend = "af_xdp"

                [xdp]
                interface = "definitely-not-a-real-interface"
                redirect_object = "definitely-not-a-real-object.bpf.o"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("baseline AF_XDP config validates without touching the interface or object");
    let mut runtime = Runtime::new(config).expect("baseline runtime");
    runtime.config.xdp.umem_frame_count =
        borondns_core::config::MAX_XDP_UMEM_FRAME_COUNT + 1;

    let error = runtime
        .run_with_shutdown_signal(std::future::pending())
        .await
        .expect_err("run-time mutation must fail before socket bind or UMEM map");
    let RuntimeError::InvalidRuntimeConfig(message) = error else {
        panic!("expected invalid runtime configuration, got {error}");
    };
    assert!(message.contains("xdp.umem_frame_count"));
    assert!(
        !message.contains("interface") && !message.contains("object"),
        "validation must fail on memory bounds before AF_XDP setup: {message}"
    );
}

#[test]
fn runtime_constructor_rejects_programmatic_af_xdp_queue_outside_redirect_map() {
    let mut config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [limits]
                udp_backend = "af_xdp"

                [xdp]
                interface = "eth0"
                redirect_object = "target/borondns-xdp-redirect.bpf.o"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("baseline AF_XDP config validates");
    config.xdp.queue_ids = vec![64];

    let error = Runtime::new(config).expect_err("invalid queue mutation must be rejected");
    let RuntimeError::InvalidRuntimeConfig(message) = error else {
        panic!("expected invalid runtime configuration, got {error}");
    };
    assert!(message.contains("queue id 64"));
}

#[tokio::test]
async fn refresh_task_panic_retires_only_its_zone_admission() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let failed = DomainName::from_absolute_str("failed-refresh.test.").unwrap();
    let unaffected = DomainName::from_absolute_str("unaffected-refresh.test.").unwrap();
    registry.record_loading_start(&failed);

    let mut transfers = JoinSet::<String>::new();
    let mut task_keys = HashMap::new();
    let mut active_keys = HashSet::from([failed.canonical_key(), unaffected.canonical_key()]);
    let failed_registry = registry.clone();
    let failed_origin = failed.clone();
    let failed_key = failed.canonical_key();
    let failed_task = transfers.spawn(async move {
        let _attempt = failed_registry.begin_attempt(&failed_origin).await;
        panic!("injected refresh panic");
    });
    task_keys.insert(failed_task.id(), failed_key.clone());

    let release_unaffected = Arc::new(Notify::new());
    let task_release = release_unaffected.clone();
    let unaffected_key = unaffected.canonical_key();
    let returned_unaffected_key = unaffected_key.clone();
    let unaffected_task = transfers.spawn(async move {
        task_release.notified().await;
        returned_unaffected_key
    });
    task_keys.insert(unaffected_task.id(), unaffected_key.clone());

    let failed_result = transfers
        .join_next_with_id()
        .await
        .expect("panicked task completes while unaffected task is blocked");
    assert!(failed_result.is_err());
    retire_refresh_transfer_task(failed_result, &mut task_keys, &mut active_keys);

    assert!(!active_keys.contains(&failed_key));
    assert!(
        active_keys.contains(&unaffected_key),
        "an unrelated active transfer must keep its admission marker"
    );
    assert_eq!(
        registry.start_due_refreshes(std::time::Instant::now()),
        vec![failed.clone()],
        "the panicked zone owner must become immediately due again"
    );

    let mut pending = VecDeque::new();
    let mut pending_keys = HashSet::new();
    assert!(
        enqueue_pending_refresh_request(
            &mut pending,
            &mut pending_keys,
            &active_keys,
            RefreshRequest::new(unaffected.clone(), None, RefreshReason::ControlPlane),
        )
        .is_none()
    );
    assert_eq!(pending.len(), 1, "the unaffected follow-up stays coalesced");

    release_unaffected.notify_one();
    let unaffected_result = transfers
        .join_next_with_id()
        .await
        .expect("unaffected task completes");
    retire_refresh_transfer_task(unaffected_result, &mut task_keys, &mut active_keys);
    assert!(active_keys.is_empty());
    assert!(task_keys.is_empty());
}

#[test]
fn runtime_initializes_catalog_zones_with_serve_policy() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "hidden.catalog.example."
                primaries = ["192.0.2.53:53"]
                tsig_key = "catalog-key."
                serve_catalog_zone = false

                [[catalog_zones]]
                name = "visible.catalog.example."
                primaries = ["192.0.2.54:53"]
                tsig_key = "catalog-key."
                serve_catalog_zone = true
            "#,
    )
    .expect("valid catalog config");
    let hidden_catalog = DomainName::from_absolute_str("hidden.catalog.example.").unwrap();
    let visible_catalog = DomainName::from_absolute_str("visible.catalog.example.").unwrap();

    let runtime = Runtime::new(config).expect("valid runtime configuration");

    assert_eq!(runtime.zone_count(), 2);
    assert!(runtime.zones.is_hidden(&hidden_catalog));
    assert!(!runtime.zones.is_hidden(&visible_catalog));
}

#[test]
fn runtime_constructor_rejects_programmatically_invalid_catalog_name_without_panicking() {
    let mut config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                primaries = ["192.0.2.53:53"]
                tsig_key = "catalog-key."
            "#,
    )
    .expect("baseline catalog config validates");
    config.catalog_zones[0].name = "not-an-absolute-catalog".to_owned();

    let error = Runtime::new(config).expect_err("invalid mutation must be rejected");
    let RuntimeError::InvalidRuntimeConfig(message) = error else {
        panic!("expected invalid runtime configuration, got {error}");
    };
    assert!(message.contains("absolute DNS name"));
}

#[test]
fn removed_transfer_plan_prevents_stale_transfer_publication() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid config");
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let stale_plan = transfer_plan.get(&origin).expect("initial transfer plan");
    transfer_plan.remove(&origin);

    let zones = ZoneStore::new();
    let snapshot = Arc::new(ZoneSnapshot::active(
        origin.clone(),
        Some(2),
        vec![
            Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                300,
                vec![soa_rdata_with_serial(2)],
            ),
            Rrset::new(
                origin.clone(),
                RecordType::Ns as u16,
                1,
                300,
                vec![ns_rdata_for_zone("example.test.")],
            ),
        ],
    ));

    let published = transfer_plan.if_current_plan(&stale_plan, || {
        zones.insert_snapshot_arc_for_transfer(snapshot)
    });

    assert!(published.is_none());
    assert!(!zones.contains_exact_zone_for_control(&origin));

    let replacement_plan = TransferPlan::from_config(&config)
        .expect("replacement transfer plan")
        .get(&origin)
        .expect("replacement plan");
    transfer_plan.insert(replacement_plan);
    let snapshot = Arc::new(ZoneSnapshot::active(
        origin.clone(),
        Some(3),
        vec![
            Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                300,
                vec![soa_rdata_with_serial(3)],
            ),
            Rrset::new(
                origin.clone(),
                RecordType::Ns as u16,
                1,
                300,
                vec![ns_rdata_for_zone("example.test.")],
            ),
        ],
    ));
    let published = transfer_plan.if_current_plan(&stale_plan, || {
        zones.insert_snapshot_arc_for_transfer(snapshot)
    });

    assert!(published.is_none());
    assert!(!zones.contains_exact_zone_for_control(&origin));
}

#[tokio::test]
async fn dequeued_refresh_cannot_rebind_across_validation_to_poll_remove_readd() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid config");
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    registry.record_loading_start(&origin);
    let request = RefreshRequest::new(origin.clone(), None, RefreshReason::ControlPlane)
        .with_plan_generation(&transfer_plan.get(&origin).expect("initial plan"));
    let validated_plan = validated_refresh_plan(&request, &registry, &transfer_plan)
        .expect("request validates at dequeue");
    let old_generation = validated_plan.generation();
    let (poll_ready_tx, poll_ready_rx) = oneshot::channel();
    let (poll_release_tx, poll_release_rx) = oneshot::channel();
    let task_registry = registry.clone();
    let task_plan = transfer_plan.clone();
    let attempt = tokio::spawn(async move {
        poll_ready_tx.send(()).expect("test observes spawn boundary");
        poll_release_rx.await.expect("test releases spawned work");
        begin_validated_refresh_attempt(
            &request,
            &task_registry,
            &task_plan,
            &validated_plan,
        )
        .await
        .is_some()
    });

    poll_ready_rx.await.expect("spawned work reaches poll barrier");
    transfer_plan.remove(&origin);
    registry.remove_zone(&origin);
    transfer_plan.insert(
        TransferPlan::from_config(&config)
            .expect("replacement plan template")
            .get(&origin)
            .expect("replacement plan"),
    );
    registry.record_loading_start(&origin);
    let replacement_generation = transfer_plan
        .get(&origin)
        .expect("replacement is installed")
        .generation();
    assert_ne!(old_generation, replacement_generation);
    poll_release_tx.send(()).expect("spawned work remains alive");

    assert!(
        !attempt.await.expect("spawned work does not panic"),
        "stale request must not begin an attempt against the replacement incarnation"
    );
    let statuses = registry.statuses.lock().unwrap();
    let replacement_status = statuses
        .get(&origin.canonical_key())
        .expect("replacement status remains present");
    assert!(
        !replacement_status.in_progress,
        "stale spawned work must not mark the replacement incarnation in progress"
    );
}

#[tokio::test]
async fn permit_waiting_refresh_is_cancelled_before_obsolete_network_io() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid config");
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let captured = transfer_plan.get(&origin).expect("captured plan");
    let transfer_limit = Arc::new(tokio::sync::Semaphore::new(0));
    let waiter = tokio::spawn({
        let transfer_plan = transfer_plan.clone();
        let captured = captured.clone();
        let transfer_limit = transfer_limit.clone();
        async move {
            acquire_transfer_permit_for_current_plan(
                &transfer_plan,
                &captured,
                transfer_limit,
            )
            .await
            .is_some()
        }
    });
    tokio::task::yield_now().await;

    transfer_plan.remove(&origin);
    transfer_plan.insert(
        TransferPlan::from_config(&config)
            .expect("replacement plan template")
            .get(&origin)
            .expect("replacement plan"),
    );

    assert!(captured.is_cancelled());
    assert!(
        !tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("cancelled permit waiter finishes promptly")
            .expect("permit waiter does not panic"),
        "obsolete work must stop without waiting for or acquiring a permit"
    );
    assert_eq!(transfer_limit.available_permits(), 0);
}

#[tokio::test]
async fn removing_plan_aborts_blocked_inflight_transfer_promptly() {
    let (primary, query_seen, hold_primary) = spawn_blocked_axfr_primary().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#,
    ))
    .expect("valid config");
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let plan = transfer_plan.get(&origin).expect("initial plan");
    let zones = ZoneStore::new();
    zones.insert_loading(origin.clone());
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    refresh_registry.record_loading_start(&origin);
    let (tx, rx) = mpsc::channel(1);
    tx.send(
        RefreshRequest::new(origin.clone(), None, RefreshReason::Catalog)
            .with_plan_generation(&plan),
    )
    .await
    .unwrap();
    drop(tx);
    let worker = tokio::spawn(serve_refresh_requests(
        rx,
        zones,
        CatalogRuntime {
            manager: CatalogManager::from_config(&config),
            transfer_plan: transfer_plan.clone(),
            refresh_registry,
            notify_authority: NotifyAuthority::from_config_for_test(&config),
            refresh_tx: mpsc::channel(1).0.downgrade(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
        },
        IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
        RuntimeMetrics::new(),
        RefreshWorkerSettings {
            axfr_timeout: std::time::Duration::from_secs(30),
            ixfr_timeout: std::time::Duration::from_secs(30),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            transfer_limit: Arc::new(tokio::sync::Semaphore::new(1)),
            max_resident_transfer_tasks: 4,
            telemetry: ControlPlaneTelemetryClient::disabled(),
            admission: RefreshAdmission::new(),
            zone_persistence: None,
        },
    ));
    tokio::time::timeout(std::time::Duration::from_secs(1), query_seen)
        .await
        .expect("blocked primary receives the transfer query")
        .expect("primary reports the query");

    transfer_plan.remove(&origin);
    tokio::time::timeout(std::time::Duration::from_secs(1), worker)
        .await
        .expect("plan removal aborts the blocked transfer without waiting for AXFR timeout")
        .expect("refresh worker does not panic")
        .expect("refresh worker exits cleanly");
    drop(hold_primary);
}

#[tokio::test]
async fn rotating_secret_aborts_blocked_inflight_transfer_promptly() {
    let (primary, query_seen, hold_primary) = spawn_blocked_axfr_primary().await;
    let secret_root = unique_test_path("borondns-blocked-transfer-secret-rotation", "dir");
    write_secret_store_manifest(
        &secret_root,
        r#"
                [[tsig_keys]]
                name = "dynamic-key."
                algorithm = "hmac-sha256"
                secret = "b2xkLXNlY3JldA=="
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
                primaries = ["{primary}"]
                tsig_key = "dynamic-key."
            "#,
        secret_root.display(),
    ))
    .expect("valid config");
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let plan = transfer_plan.get(&origin).expect("initial plan");
    let zones = ZoneStore::new();
    zones.insert_loading(origin.clone());
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    refresh_registry.record_loading_start(&origin);
    let secrets = SecretManager::from_config(&config).expect("initial secret generation");
    let (tx, rx) = mpsc::channel(1);
    tx.send(
        RefreshRequest::new(origin.clone(), None, RefreshReason::Catalog)
            .with_plan_generation(&plan),
    )
    .await
    .unwrap();
    drop(tx);
    let worker = tokio::spawn(serve_refresh_requests(
        rx,
        zones.clone(),
        CatalogRuntime {
            manager: CatalogManager::from_config(&config),
            transfer_plan: transfer_plan.clone(),
            refresh_registry,
            notify_authority: NotifyAuthority::from_config_for_test(&config),
            refresh_tx: mpsc::channel(1).0.downgrade(),
            secrets: secrets.clone(),
        },
        IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
        RuntimeMetrics::new(),
        RefreshWorkerSettings {
            axfr_timeout: std::time::Duration::from_secs(30),
            ixfr_timeout: std::time::Duration::from_secs(30),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            transfer_limit: Arc::new(tokio::sync::Semaphore::new(1)),
            max_resident_transfer_tasks: 4,
            telemetry: ControlPlaneTelemetryClient::disabled(),
            admission: RefreshAdmission::new(),
            zone_persistence: None,
        },
    ));
    tokio::time::timeout(std::time::Duration::from_secs(1), query_seen)
        .await
        .expect("blocked primary receives the transfer query")
        .expect("primary reports the query");

    write_secret_store_manifest(
        &secret_root,
        r#"
                [[tsig_keys]]
                name = "dynamic-key."
                algorithm = "hmac-sha256"
                secret = "bmV3LXNlY3JldA=="
            "#,
    );
    secrets.reload().expect("rotate active secret generation");

    tokio::time::timeout(std::time::Duration::from_secs(1), worker)
        .await
        .expect("secret rotation aborts the blocked transfer without waiting for AXFR timeout")
        .expect("refresh worker does not panic")
        .expect("refresh worker exits cleanly");
    assert_eq!(
        zones
            .exact_zone_control_metadata(&origin)
            .expect("loading zone remains known")
            .state,
        ZoneState::Loading,
        "an old-secret attempt must not publish or activate the zone"
    );

    drop(hold_primary);
    let _ = std::fs::remove_dir_all(secret_root);
}

#[test]
fn stale_transfer_plan_success_does_not_recreate_refresh_status() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid config");
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let stale_plan = transfer_plan.get(&origin).expect("initial transfer plan");
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let snapshot = active_member_snapshot(origin.clone(), 2);
    let metadata = zone_metadata_for(&snapshot);

    transfer_plan.remove(&origin);
    assert!(!record_success_if_current_plan(
        &refresh_registry,
        &transfer_plan,
        &stale_plan,
        &metadata,
    ));

    assert!(
        !refresh_registry
            .snapshots_by_zone()
            .contains_key(&origin.canonical_key())
    );
}

#[test]
fn ixfr_current_metrics_require_successful_confirmation() {
    let config = ServerConfig::from_toml_str(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [[zones]]
            name = "example.test."
            primaries = ["192.0.2.53:53"]
        "#,
    )
    .expect("valid config");
    let origin = DomainName::from_absolute_str("example.test.").unwrap();

    let make_current_zone = || {
        let zones = ZoneStore::new();
        zones.insert_snapshot(ZoneSnapshot::active(
            origin.clone(),
            Some(7),
            vec![Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata_with_serial(7)],
            )],
        ));
        let current = zones
            .exact_snapshot_with_serial_for_transfer(&origin)
            .expect("current transfer snapshot");
        (zones, current)
    };

    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let plan = transfer_plan.get(&origin).expect("zone transfer plan");
    let secrets = SecretManager::from_config(&config).expect("secret manager");
    let secret_snapshot = secrets.current_snapshot().expect("secret snapshot");
    let (zones, current) = make_current_zone();
    let metrics = RuntimeMetrics::new();
    metrics.record_ixfr_started();
    let confirmed = match record_ixfr_current_confirmation(
        &metrics,
        confirm_current_zone_with_secret(
            &zones,
            &transfer_plan,
            &secrets,
            &plan,
            &secret_snapshot,
            &current,
        ),
    ) {
        Ok(metadata) => metadata,
        Err(_) => panic!("current snapshot confirmation failed"),
    };
    assert_eq!(confirmed.serial, Some(7));
    assert_eq!(metrics.snapshot().ixfr_started, 1);
    assert_eq!(metrics.snapshot().ixfr_succeeded, 1);
    assert_eq!(metrics.snapshot().ixfr_failed, 0);

    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let plan = transfer_plan.get(&origin).expect("zone transfer plan");
    let secrets = SecretManager::from_config(&config).expect("secret manager");
    let secret_snapshot = secrets.current_snapshot().expect("secret snapshot");
    let (zones, current) = make_current_zone();
    transfer_plan.remove(&origin);
    let metrics = RuntimeMetrics::new();
    metrics.record_ixfr_started();
    let stale = record_ixfr_current_confirmation(
        &metrics,
        confirm_current_zone_with_secret(
            &zones,
            &transfer_plan,
            &secrets,
            &plan,
            &secret_snapshot,
            &current,
        ),
    );
    assert!(matches!(
        stale,
        Err(CurrentZoneConfirmationError::Obsolete)
    ));
    assert_eq!(metrics.snapshot().ixfr_started, 1);
    assert_eq!(metrics.snapshot().ixfr_succeeded, 0);
    assert_eq!(metrics.snapshot().ixfr_failed, 1);

    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let plan = transfer_plan.get(&origin).expect("zone transfer plan");
    let secrets = SecretManager::from_config(&config).expect("secret manager");
    let secret_snapshot = secrets.current_snapshot().expect("secret snapshot");
    let (zones, current) = make_current_zone();
    assert!(zones.remove_zone(&origin));
    let metrics = RuntimeMetrics::new();
    metrics.record_ixfr_started();
    let missing = record_ixfr_current_confirmation(
        &metrics,
        confirm_current_zone_with_secret(
            &zones,
            &transfer_plan,
            &secrets,
            &plan,
            &secret_snapshot,
            &current,
        ),
    );
    assert!(matches!(
        missing,
        Err(CurrentZoneConfirmationError::Missing)
    ));
    assert_eq!(metrics.snapshot().ixfr_started, 1);
    assert_eq!(metrics.snapshot().ixfr_succeeded, 0);
    assert_eq!(metrics.snapshot().ixfr_failed, 1);

    let metrics = RuntimeMetrics::new();
    metrics.record_ixfr_started();
    let publication_failed = record_ixfr_current_confirmation(
        &metrics,
        Err(CurrentZoneConfirmationError::PublicationFailed(
            "injected publication failure".to_owned(),
        )),
    );
    assert!(matches!(
        publication_failed,
        Err(CurrentZoneConfirmationError::PublicationFailed(ref error))
            if error == "injected publication failure"
    ));
    assert_eq!(metrics.snapshot().ixfr_started, 1);
    assert_eq!(metrics.snapshot().ixfr_succeeded, 0);
    assert_eq!(metrics.snapshot().ixfr_failed, 1);
}

#[test]
fn ixfr_current_secret_rotation_records_failure_not_success() {
    let secret_root = unique_test_path("borondns-ixfr-current-secret-rotation", "dir");
    write_secret_store_manifest(
        &secret_root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "b2xkLXNlY3JldA=="
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
            primaries = ["192.0.2.53:53"]
            tsig_key = "dynamic-key."
        "#,
        secret_root.display(),
    ))
    .expect("valid secret-store config");
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let plan = transfer_plan.get(&origin).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        origin.clone(),
        Some(7),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(7)],
        )],
    ));
    let current = zones
        .exact_snapshot_with_serial_for_transfer(&origin)
        .expect("current transfer snapshot");
    let secrets = SecretManager::from_config(&config).expect("initial secret manager");
    let stale_snapshot = secrets.current_snapshot().expect("initial secret snapshot");

    write_secret_store_manifest(
        &secret_root,
        r#"
            [[tsig_keys]]
            name = "dynamic-key."
            algorithm = "hmac-sha256"
            secret = "bmV3LXNlY3JldA=="
        "#,
    );
    secrets.reload().expect("rotate secret generation");

    let metrics = RuntimeMetrics::new();
    metrics.record_ixfr_started();
    let confirmation = record_ixfr_current_confirmation(
        &metrics,
        confirm_current_zone_with_secret(
            &zones,
            &transfer_plan,
            &secrets,
            &plan,
            &stale_snapshot,
            &current,
        ),
    );
    assert!(matches!(
        confirmation,
        Err(CurrentZoneConfirmationError::Obsolete)
    ));
    assert_eq!(metrics.snapshot().ixfr_started, 1);
    assert_eq!(metrics.snapshot().ixfr_succeeded, 0);
    assert_eq!(metrics.snapshot().ixfr_failed, 1);

    let _ = std::fs::remove_dir_all(secret_root);
}

#[test]
fn refresh_pending_queue_coalesces_and_stays_bounded() {
    let mut pending = std::collections::VecDeque::new();
    let mut pending_keys = HashSet::new();
    let mut active_keys = HashSet::new();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();

    let _ = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        RefreshRequest::new(origin.clone(), Some(1), RefreshReason::Notify),
    );
    let _ = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        RefreshRequest::new(origin.clone(), Some(3), RefreshReason::ControlPlane),
    );

    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].requested_serial, Some(3));
    assert_eq!(pending[0].reason, RefreshReason::ControlPlane);

    let _ = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        RefreshRequest::new(origin, Some(4), RefreshReason::Notify),
    );
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].requested_serial, Some(4));
    assert_eq!(pending[0].reason, RefreshReason::Notify);

    pending.clear();
    pending_keys.clear();
    for index in 0..NOTIFY_REFRESH_QUEUE_CAPACITY {
        let _ = enqueue_pending_refresh_request(
            &mut pending,
            &mut pending_keys,
            &active_keys,
            RefreshRequest::new(
                DomainName::from_absolute_str(&format!("zone-{index}.example.")).unwrap(),
                None,
                RefreshReason::Notify,
            ),
        );
    }
    let _ = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        RefreshRequest::new(
            DomainName::from_absolute_str("overflow.example.").unwrap(),
            None,
            RefreshReason::Notify,
        ),
    );

    assert_eq!(pending.len(), NOTIFY_REFRESH_QUEUE_CAPACITY);
    assert!(!pending.iter().any(|request| request.zone.to_string() == "overflow.example."));

    let active_origin = DomainName::from_absolute_str("active.example.").unwrap();
    active_keys.insert(active_origin.canonical_key());
    let _ = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        RefreshRequest::new(active_origin.clone(), Some(9), RefreshReason::Notify),
    );

    assert_eq!(pending.len(), NOTIFY_REFRESH_QUEUE_CAPACITY);
    assert!(
        pending
            .iter()
            .any(|request| request.zone == active_origin && request.requested_serial == Some(9))
    );
}

#[test]
fn refresh_coalescing_preserves_unconditional_and_retry_provenance_in_both_orders() {
    let origin = DomainName::from_absolute_str("member.example.").unwrap();
    for catalog_first in [true, false] {
        let mut pending = std::collections::VecDeque::new();
        let mut pending_keys = HashSet::new();
        let active_keys = HashSet::new();
        let catalog = RefreshRequest::new(origin.clone(), None, RefreshReason::Catalog);
        let notify = RefreshRequest::new(origin.clone(), Some(42), RefreshReason::Notify);
        let (first, second) = if catalog_first {
            (catalog, notify)
        } else {
            (notify, catalog)
        };
        assert!(
            enqueue_pending_refresh_request(
                &mut pending,
                &mut pending_keys,
                &active_keys,
                first,
            )
            .is_none()
        );
        assert!(
            enqueue_pending_refresh_request(
                &mut pending,
                &mut pending_keys,
                &active_keys,
                second,
            )
            .is_none()
        );

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].requested_serial, None);
        assert_eq!(
            pending[0].retry_after_queue_drop,
            Some(RefreshReason::Catalog)
        );
    }
}

#[test]
fn evicted_coalesced_catalog_notify_is_rescheduled() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let mut pending = std::collections::VecDeque::new();
    let mut pending_keys = HashSet::new();
    let mut active_keys = HashSet::new();
    for index in 0..NOTIFY_REFRESH_QUEUE_CAPACITY - 1 {
        let filler = DomainName::from_absolute_str(&format!("filler-{index}.example.")).unwrap();
        assert!(
            enqueue_pending_refresh_request(
                &mut pending,
                &mut pending_keys,
                &active_keys,
                RefreshRequest::new(filler, Some(1), RefreshReason::Notify),
            )
            .is_none()
        );
    }
    let member = DomainName::from_absolute_str("member.example.").unwrap();
    registry.record_loading_start(&member);
    assert!(
        enqueue_pending_refresh_request(
            &mut pending,
            &mut pending_keys,
            &active_keys,
            RefreshRequest::new(member.clone(), None, RefreshReason::Catalog),
        )
        .is_none()
    );
    assert!(
        enqueue_pending_refresh_request(
            &mut pending,
            &mut pending_keys,
            &active_keys,
            RefreshRequest::new(member.clone(), Some(7), RefreshReason::Notify),
        )
        .is_none()
    );

    let active = DomainName::from_absolute_str("active.example.").unwrap();
    active_keys.insert(active.canonical_key());
    let dropped = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        RefreshRequest::new(active, Some(8), RefreshReason::Notify),
    )
    .expect("active follow-up evicts the coalesced tail request");
    assert_eq!(dropped.zone, member);
    assert_eq!(dropped.reason, RefreshReason::Notify);
    assert_eq!(
        dropped.retry_after_queue_drop,
        Some(RefreshReason::Catalog)
    );
    registry.defer_refresh_after_queue_drop(&dropped);
    assert_eq!(registry.start_due_refreshes(std::time::Instant::now()), vec![member]);
}

#[test]
fn catalog_refresh_dropped_at_pending_capacity_is_rescheduled() {
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let mut pending = std::collections::VecDeque::new();
    let mut pending_keys = HashSet::new();
    let active_keys = HashSet::new();

    for index in 0..NOTIFY_REFRESH_QUEUE_CAPACITY {
        let origin =
            DomainName::from_absolute_str(&format!("member-{index}.example.")).unwrap();
        refresh_registry.record_loading_start(&origin);
        assert!(
            enqueue_pending_refresh_request(
                &mut pending,
                &mut pending_keys,
                &active_keys,
                RefreshRequest::new(origin, None, RefreshReason::Catalog),
            )
            .is_none()
        );
    }

    let overflow = DomainName::from_absolute_str("overflow-member.example.").unwrap();
    refresh_registry.record_loading_start(&overflow);
    let dropped = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        RefreshRequest::new(overflow.clone(), None, RefreshReason::Catalog),
    )
    .expect("capacity-plus-one catalog refresh must leave the bounded queue");
    assert_eq!(dropped.zone, overflow);
    refresh_registry.defer_refresh_after_queue_drop(&dropped);

    let due = refresh_registry.start_due_refreshes(std::time::Instant::now());
    assert_eq!(due, vec![overflow.clone()]);

    let dropped_retry = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        RefreshRequest::new(overflow.clone(), None, RefreshReason::Scheduled),
    )
    .expect("scheduled retry must also leave a still-full bounded queue");
    refresh_registry.defer_refresh_after_queue_drop(&dropped_retry);
    let due_again = refresh_registry.start_due_refreshes(std::time::Instant::now());
    assert_eq!(due_again, vec![overflow.clone()]);

    let admitted = pending.pop_front().expect("full pending queue");
    pending_keys.remove(&admitted.zone.canonical_key());
    assert!(
        enqueue_pending_refresh_request(
            &mut pending,
            &mut pending_keys,
            &active_keys,
            RefreshRequest::new(overflow.clone(), None, RefreshReason::Scheduled),
        )
        .is_none()
    );
    assert!(pending.iter().any(|request| request.zone == overflow));
}

#[test]
fn lifecycle_fuzz_seed_recovers_from_overflow_and_completes_attempt() {
    let mut seed = Vec::new();
    seed.extend_from_slice(&[0, 0, 1]);
    seed.extend_from_slice(&[10, 0, 1]);
    for _ in 0..16 {
        seed.extend_from_slice(&[6, 1, 0]);
    }
    seed.extend_from_slice(&[3, 0, 1]);
    seed.extend_from_slice(&[6, 0, 1]);
    seed.extend_from_slice(&[7, 0, 2]);

    let stats = run_lifecycle_fuzz_sequence(&seed);
    assert_eq!(stats.overflow_drops, 1);
    assert_eq!(stats.filler_drains, NOTIFY_REFRESH_QUEUE_CAPACITY);
    assert!(stats.recovered_after_overflow);
    assert_eq!(stats.admissions_after_recovery, 1);
    assert_eq!(stats.completions_after_recovery, 1);
}

#[test]
fn lifecycle_fuzz_scheduled_drop_is_deferred_and_retries_after_drain() {
    let minimal_seed = [0, 0, 1, 10, 0, 1, 12, 0, 1];
    let minimal_stats = run_lifecycle_fuzz_sequence(&minimal_seed);
    assert_eq!(minimal_stats.overflow_drops, 1);
    assert_eq!(minimal_stats.scheduled_overflow_drops, 1);

    let mut retry_seed = minimal_seed.to_vec();
    for _ in 0..16 {
        retry_seed.extend_from_slice(&[6, 1, 0]);
    }
    retry_seed.extend_from_slice(&[12, 0, 1]);
    retry_seed.extend_from_slice(&[6, 0, 1]);
    retry_seed.extend_from_slice(&[7, 0, 2]);

    let retry_stats = run_lifecycle_fuzz_sequence(&retry_seed);
    assert_eq!(retry_stats.filler_drains, NOTIFY_REFRESH_QUEUE_CAPACITY);
    assert!(retry_stats.recovered_after_overflow);
    assert_eq!(retry_stats.scheduled_admissions_after_recovery, 1);
    assert_eq!(retry_stats.completions_after_recovery, 1);
}

#[test]
fn lifecycle_fuzz_models_notify_reservation_refresh_and_completion_suppression() {
    let seed = [
        0, 0, 0, // add zone 0 at modeled t=0
        4, 0, 0, // first NOTIFY is admitted
        4, 0, 0, // outer duplicate is suppressed
        6, 0, 0, // begin the queued refresh
        4, 0, 0, // active refresh suppresses NOTIFY
        7, 0, 0, // publish a valid SOA snapshot and complete the refresh
        4, 0, 0, // recent completion suppresses NOTIFY
        13, 1, 4, // advance modeled time by three seconds
        4, 0, 0, // dedup interval elapsed, so NOTIFY is admitted again
    ];

    let stats = run_lifecycle_fuzz_sequence(&seed);
    assert_eq!(stats.notify_signalled, 2);
    assert_eq!(stats.notify_deduplicated, 3);
}

#[test]
fn lifecycle_fuzz_models_failed_completion_suppression_window() {
    let seed = [
        0, 0, 0, // add zone 0 at modeled t=0
        4, 0, 0, // admit NOTIFY
        6, 0, 0, // begin refresh
        8, 0, 0, // fail at modeled t=0
        4, 0, 0, // recent failure suppresses NOTIFY
        13, 1, 4, // advance modeled time by three seconds
        4, 0, 0, // completion window elapsed
    ];

    let stats = run_lifecycle_fuzz_sequence(&seed);
    assert_eq!(stats.notify_signalled, 2);
    assert_eq!(stats.notify_deduplicated, 1);
}

#[test]
fn lifecycle_fuzz_models_failure_and_interruption_retry_deadlines() {
    let failed = [
        0, 0, 0, // add zone
        3, 0, 0, // queue catalog refresh
        6, 0, 0, // begin
        8, 0, 0, // fail; initial retry is one second
        12, 0, 0, // not due at t=0
        13, 1, 2, // advance modeled time by 1.5 seconds
        12, 0, 0, // due now
    ];
    let failed_stats = run_lifecycle_fuzz_sequence(&failed);
    assert_eq!(failed_stats.scheduled_admissions, 1);

    let interrupted = [
        0, 0, 0, // add zone
        3, 0, 0, // queue catalog refresh
        6, 0, 0, // begin
        9, 0, 0, // interrupt; retry is immediate at modeled t=0
        12, 0, 0, // due immediately
    ];
    let interrupted_stats = run_lifecycle_fuzz_sequence(&interrupted);
    assert_eq!(interrupted_stats.scheduled_admissions, 1);
}

#[test]
fn lifecycle_fuzz_rejects_pending_notify_from_removed_incarnation() {
    let seed = [
        0, 0, 0, // add incarnation A
        4, 0, 0, // internally queue A's NOTIFY
        1, 0, 0, // remove A
        0, 0, 0, // add incarnation B
        6, 0, 0, // dequeue must reject A's pending request
    ];

    let stats = run_lifecycle_fuzz_sequence(&seed);
    assert_eq!(stats.notify_signalled, 1);
    assert_eq!(stats.stale_pending_incarnation_drops, 1);
}

#[test]
fn lifecycle_fuzz_models_shutdown_queue_drop_and_expired_current_reactivation() {
    let seed = [
        0, 0, 0, // add zone
        4, 0, 0, // queue NOTIFY
        15, 0, 0, // close admission and discard queued work
        3, 0, 0, // queue a refresh
        6, 0, 0, // begin it
        7, 0, 2, // publish a serial-bearing ACTIVE snapshot
        16, 0, 0, // expire and confirm the retained snapshot current
    ];

    let stats = run_lifecycle_fuzz_sequence(&seed);
    assert_eq!(stats.shutdown_drops, 1);
    assert_eq!(stats.reactivations, 1);
}

#[test]
fn lifecycle_fuzz_reactivates_an_already_expired_control_view() {
    let seed = [
        0, 0, 0, // add zone
        3, 0, 0, // queue a refresh
        6, 0, 0, // begin it
        7, 0, 2, // publish a serial-bearing ACTIVE snapshot
        11, 0, 0, // expire it through the refresh registry
        16, 0, 0, // confirm the synthesized EXPIRED control view current
    ];

    let stats = run_lifecycle_fuzz_sequence(&seed);
    assert_eq!(stats.reactivations, 1);
}

#[tokio::test]
async fn catalog_snapshot_adds_member_transfer_plan_and_hides_catalog() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[tsig_keys]]
                name = "member-key."
                algorithm = "hmac-sha256"
                secret = "bWVtYmVyLXNlY3JldA=="

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                notify_sources = ["198.51.100.54"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "member-key."
            "#,
    )
    .expect("valid catalog config");
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let snapshot = ZoneSnapshot::active(
        catalog_origin.clone(),
        Some(7),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![vec![1, b'2']],
            ),
            Rrset::new(
                DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                RecordType::Ptr as u16,
                1,
                0,
                vec![member_origin.to_wire()],
            ),
        ],
    );
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin.clone());
    zones.insert_snapshot(snapshot.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, mut rx) = mpsc::channel(1);
    let metadata = zone_metadata_for(&snapshot);

    catalog_manager
        .apply_snapshot(
            snapshot.catalog_zone_view(),
            &metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    assert!(zones.find_published_zone(&catalog_origin).is_none());
    let member_plan = transfer_plan
        .get(&member_origin)
        .expect("member transfer plan");
    assert_eq!(
        member_plan
            .primaries
            .iter()
            .map(|primary| primary.addr)
            .collect::<Vec<_>>(),
        vec![SocketAddr::from((Ipv4Addr::new(10, 0, 0, 53), 53))]
    );
    assert_eq!(
        member_plan
            .tsig_key_name
            .as_ref()
            .expect("member TSIG key")
            .to_string(),
        "member-key."
    );
    assert!(notify_authority.is_authorized(&catalog_origin, 1, "192.0.2.53".parse().unwrap()));
    assert!(!notify_authority.is_authorized(&catalog_origin, 1, "198.51.100.53".parse().unwrap()));
    assert!(notify_authority.is_authorized(&member_origin, 1, "10.0.0.53".parse().unwrap()));
    assert!(notify_authority.is_authorized(&member_origin, 1, "198.51.100.54".parse().unwrap()));
    assert!(!notify_authority.is_authorized(&member_origin, 1, "192.0.2.53".parse().unwrap()));
    assert_eq!(
        zones
            .exact_snapshot_for_transfer(&member_origin)
            .expect("member zone loading snapshot")
            .metadata()
            .state,
        ZoneState::Loading
    );
    assert!(
        refresh_registry
            .snapshots_by_zone()
            .contains_key(&member_origin.canonical_key())
    );
    let request = rx.recv().await.expect("member refresh request");
    assert_eq!(request.zone, member_origin);
    assert_eq!(request.reason, super::RefreshReason::Catalog);
}

#[tokio::test]
async fn saturated_telemetry_cannot_hold_transfer_or_catalog_lifecycle_state() {
    let primary = spawn_signed_catalog_axfr_primary_with_member(
        "catalog.example.",
        "member.example.",
        7,
    )
    .await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["{primary}"]
                member_primaries = ["192.0.2.54:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."
            "#,
    ))
    .expect("valid catalog configuration");
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    refresh_registry.record_loading_start(&catalog_origin);
    let catalog_manager = CatalogManager::from_config(&config);
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (refresh_tx, mut refresh_rx) = mpsc::channel(4);
    let transfer_limit = Arc::new(tokio::sync::Semaphore::new(1));
    let (telemetry, _blocked_telemetry_rx) =
        ControlPlaneTelemetryClient::saturated_for_test();

    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        run_initial_zone_loads(
            zones.clone(),
            vec![catalog_origin.clone()],
            CatalogRuntime {
                manager: catalog_manager,
                transfer_plan: transfer_plan.clone(),
                refresh_registry: refresh_registry.clone(),
                notify_authority,
                refresh_tx: refresh_tx.downgrade(),
                secrets: SecretManager::from_config(&config)
                    .expect("test configuration loads secret snapshot"),
            },
            IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
            RuntimeMetrics::new(),
            InitialLoadSettings {
                axfr_timeout: std::time::Duration::from_secs(1),
                ixfr_timeout: std::time::Duration::from_secs(1),
                tcp_connect_timeout: std::time::Duration::from_secs(1),
                transfer_limit: transfer_limit.clone(),
                max_resident_transfer_tasks: 1,
                telemetry,
                admission: RefreshAdmission::new(),
            zone_persistence: None,
            },
        ),
    )
    .await
    .expect("a blocked telemetry worker must not stall initial catalog loading")
    .expect("initial catalog worker exits cleanly");

    assert_eq!(
        transfer_limit.available_permits(),
        1,
        "completed catalog work must release the global transfer slot"
    );
    let retry_attempt = refresh_registry
        .try_begin_attempt(&catalog_origin)
        .expect("completed catalog work must release zone refresh ownership");
    retry_attempt.finish();
    assert!(
        transfer_plan.get(&member_origin).is_some(),
        "catalog reconciliation must install the member transfer plan"
    );
    assert_eq!(
        zones
            .exact_zone_control_metadata(&member_origin)
            .expect("catalog reconciliation publishes member loading state")
            .state,
        ZoneState::Loading
    );
    let member_refresh = refresh_rx
        .try_recv()
        .expect("catalog reconciliation queues the member refresh");
    assert_eq!(member_refresh.zone, member_origin);
    assert_eq!(member_refresh.reason, RefreshReason::Catalog);
}

#[tokio::test]
async fn catalog_snapshot_reconciles_retained_and_removed_members() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[tsig_keys]]
                name = "member-key."
                algorithm = "hmac-sha256"
                secret = "bWVtYmVyLXNlY3JldA=="

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                notify_sources = ["198.51.100.54"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "member-key."
            "#,
    )
    .expect("valid catalog config");
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let alpha_origin = DomainName::from_absolute_str("alpha.example.").unwrap();
    let beta_origin = DomainName::from_absolute_str("beta.example.").unwrap();
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_tracker = NotifyRefreshTracker::with_refresh_registry_and_transfer_plan(
        std::time::Duration::from_secs(60),
        refresh_registry.clone(),
        transfer_plan.clone(),
    );
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(60));
    catalog_manager.attach_runtime_registries(notify_tracker.clone(), ixfr_cooldowns.clone());
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let metrics = RuntimeMetrics::new();
    let (tx, mut rx) = mpsc::channel(2);

    let initial_snapshot = catalog_snapshot_with_members(
        catalog_origin.clone(),
        7,
        &[alpha_origin.clone(), beta_origin.clone()],
    );
    zones.insert_snapshot(initial_snapshot.clone());
    let initial_metadata = zone_metadata_for(&initial_snapshot);
    catalog_manager
        .apply_snapshot(
            initial_snapshot.catalog_zone_view(),
            &initial_metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    assert!(transfer_plan.get(&alpha_origin).is_some());
    assert!(transfer_plan.get(&beta_origin).is_some());
    assert!(notify_authority.is_authorized(&alpha_origin, 1, "10.0.0.53".parse().unwrap()));
    assert!(notify_authority.is_authorized(&beta_origin, 1, "10.0.0.53".parse().unwrap()));
    assert!(
        refresh_registry
            .snapshots_by_zone()
            .contains_key(&alpha_origin.canonical_key())
    );
    assert!(
        refresh_registry
            .snapshots_by_zone()
            .contains_key(&beta_origin.canonical_key())
    );
    assert_eq!(rx.recv().await.expect("alpha refresh request").zone, alpha_origin);
    assert_eq!(rx.recv().await.expect("beta refresh request").zone, beta_origin);
    let _alpha_metric = metrics
        .record_zone_query_key(alpha_origin.canonical_key().as_str())
        .expect("full-detail metrics return a zone token");
    let beta_metric = metrics
        .record_zone_query_key(beta_origin.canonical_key().as_str())
        .expect("full-detail metrics return a zone token");

    let now = std::time::Instant::now();
    let primary = "10.0.0.53:53".parse().unwrap();
    let mut alpha_token = None;
    let mut beta_token = None;
    notify_tracker
        .record_after_enqueue(&alpha_origin, |token| {
            alpha_token = Some(token);
            Ok::<(), ()>(())
        })
        .unwrap();
    notify_tracker
        .record_after_enqueue(&beta_origin, |token| {
            beta_token = Some(token);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert!(alpha_token.as_ref().unwrap().commit());
    assert!(beta_token.as_ref().unwrap().commit());
    let mut incarnation_pending = std::collections::VecDeque::new();
    let mut incarnation_pending_keys = HashSet::new();
    let incarnation_active_keys = HashSet::new();
    assert!(
        enqueue_pending_refresh_request(
            &mut incarnation_pending,
            &mut incarnation_pending_keys,
            &incarnation_active_keys,
            RefreshRequest::new(beta_origin.clone(), Some(8), RefreshReason::Notify)
                .with_notify_dedup_token(beta_token.as_ref().unwrap().clone()),
        )
        .is_none()
    );
    ixfr_cooldowns.record_unsupported_at(&alpha_origin, primary, now);
    ixfr_cooldowns.record_unsupported_at(&beta_origin, primary, now);
    let removed_beta_plan = transfer_plan.get(&beta_origin).expect("initial beta plan");

    let updated_snapshot =
        catalog_snapshot_with_members(catalog_origin.clone(), 8, std::slice::from_ref(&alpha_origin));
    zones.insert_snapshot(updated_snapshot.clone());
    let updated_metadata = zone_metadata_for(&updated_snapshot);
    let parsed_updated = catalog_manager
        .parse_candidate_view(updated_snapshot.catalog_zone_view())
        .expect("valid bounded catalog snapshot")
        .expect("configured catalog has parsed members");
    catalog_manager
        .apply_parsed_snapshot(
            parsed_updated,
            &updated_metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
            &metrics,
            None,
        )
        .await;

    metrics.record_zone_query_response_rcode(&beta_metric, Rcode::NoError as u16);
    assert_eq!(
        metrics.zone_query_counts(),
        HashMap::from([(alpha_origin.canonical_key(), 1)]),
        "catalog removal prunes only the removed member's metrics"
    );
    assert!(
        metrics.zone_query_rcode_counts().is_empty(),
        "a stale in-flight token must not recreate a removed member metric"
    );

    assert!(transfer_plan.get(&alpha_origin).is_some());
    assert!(transfer_plan.get(&beta_origin).is_none());
    assert!(zones.contains_exact_zone_for_control(&alpha_origin));
    assert!(!zones.contains_exact_zone_for_control(&beta_origin));
    assert!(notify_authority.is_authorized(&alpha_origin, 1, "10.0.0.53".parse().unwrap()));
    assert!(!notify_authority.is_authorized(&beta_origin, 1, "10.0.0.53".parse().unwrap()));
    assert!(
        refresh_registry
            .snapshots_by_zone()
            .contains_key(&alpha_origin.canonical_key())
    );
    assert!(
        !refresh_registry
            .snapshots_by_zone()
            .contains_key(&beta_origin.canonical_key())
    );
    assert!(rx.try_recv().is_err());
    assert!(
        notify_tracker
            .last_signal_by_zone
            .lock()
            .unwrap()
            .contains_key(&alpha_origin.canonical_key())
    );
    assert!(
        !notify_tracker
            .last_signal_by_zone
            .lock()
            .unwrap()
            .contains_key(&beta_origin.canonical_key())
    );
    assert!(ixfr_cooldowns.is_disabled_at(&alpha_origin, primary, now));
    assert!(!ixfr_cooldowns.is_disabled_at(&beta_origin, primary, now));

    let readded_snapshot = catalog_snapshot_with_members(
        catalog_origin.clone(),
        9,
        &[alpha_origin.clone(), beta_origin.clone()],
    );
    zones.insert_snapshot(readded_snapshot.clone());
    let readded_metadata = zone_metadata_for(&readded_snapshot);
    catalog_manager
        .apply_snapshot(
            readded_snapshot.catalog_zone_view(),
            &readded_metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    assert_eq!(rx.recv().await.expect("re-added beta refresh").zone, beta_origin);

    assert!(
        !incarnation_pending[0].notify_incarnation_is_current(&refresh_registry),
        "the internally pending NOTIFY belongs to the removed incarnation"
    );
    let current_beta_plan = transfer_plan.get(&beta_origin).expect("re-added beta plan");
    let replaced_old_incarnation = enqueue_pending_refresh_request(
        &mut incarnation_pending,
        &mut incarnation_pending_keys,
        &incarnation_active_keys,
        RefreshRequest::new(beta_origin.clone(), None, RefreshReason::Catalog)
            .with_plan_generation(&current_beta_plan),
    )
    .expect("new-incarnation catalog work replaces the stale pending NOTIFY");
    assert!(replaced_old_incarnation.notify_dedup_token.is_some());
    assert_eq!(incarnation_pending.len(), 1);
    assert!(incarnation_pending[0].notify_dedup_token.is_none());
    assert!(incarnation_pending[0].notify_incarnation_is_current(&refresh_registry));
    assert!(incarnation_pending[0].plan_incarnation_is_current(&transfer_plan));

    let stale_request = RefreshRequest::new(
        beta_origin.clone(),
        Some(8),
        RefreshReason::Notify,
    )
    .with_notify_dedup_token(beta_token.expect("old beta token"));
    let mut pending = std::collections::VecDeque::new();
    let mut pending_keys = HashSet::new();
    let active_keys = HashSet::new();
    let rejected = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        stale_request,
    )
    .expect("old-incarnation NOTIFY is rejected");
    assert!(rejected.retry_after_queue_drop.is_none());
    assert!(pending.is_empty());

    ixfr_cooldowns.record_unsupported_if_current(
        &transfer_plan,
        &removed_beta_plan,
        primary,
    );
    let readded_beta_plan = transfer_plan.get(&beta_origin).expect("re-added beta plan");
    assert_ne!(removed_beta_plan.generation(), readded_beta_plan.generation());
    assert!(!ixfr_cooldowns.is_disabled_for_plan(&readded_beta_plan, primary));

    assert_eq!(
        notify_tracker.record_after_enqueue(&beta_origin, |_| Ok::<(), ()>(())),
        Ok(NotifyRefreshAction::Signalled)
    );
}

#[tokio::test]
async fn concurrent_catalog_member_migration_preserves_member_resources() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "a.catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."

                [[catalog_zones]]
                name = "b.catalog.example."
                catalog_primaries = ["192.0.2.54:53"]
                member_primaries = ["10.0.0.54:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."
            "#,
    )
    .expect("valid catalog config");
    let catalog_a = DomainName::from_absolute_str("a.catalog.example.").unwrap();
    let catalog_b = DomainName::from_absolute_str("b.catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let initial_a =
        catalog_snapshot_with_members(catalog_a.clone(), 7, std::slice::from_ref(&member_origin));
    let updated_a = catalog_snapshot_with_members(catalog_a.clone(), 8, &[]);
    let updated_b =
        catalog_snapshot_with_members(catalog_b.clone(), 7, std::slice::from_ref(&member_origin));
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_a.clone());
    zones.insert_loading_hidden(catalog_b.clone());
    zones.insert_snapshot(initial_a.clone());
    zones.insert_snapshot(updated_b.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, _rx) = mpsc::channel(4);
    let initial_a_metadata = zone_metadata_for(&initial_a);
    let updated_a_metadata = zone_metadata_for(&updated_a);
    let updated_b_metadata = zone_metadata_for(&updated_b);
    let refresh_tx = tx.downgrade();
    let refresh_tx_a = tx.downgrade();
    let refresh_tx_b = tx.downgrade();

    catalog_manager
        .apply_snapshot(
            initial_a.catalog_zone_view(),
            &initial_a_metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &refresh_tx,
        )
        .await;

    let ((), ()) = tokio::join!(
        catalog_manager.apply_snapshot(
            updated_a.catalog_zone_view(),
            &updated_a_metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &refresh_tx_a,
        ),
        catalog_manager.apply_snapshot(
            updated_b.catalog_zone_view(),
            &updated_b_metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &refresh_tx_b,
        )
    );

    assert!(transfer_plan.get(&member_origin).is_some());
    assert!(zones.contains_exact_zone_for_control(&member_origin));
    assert!(
        refresh_registry
            .snapshots_by_zone()
            .contains_key("member.example.")
    );
}

#[tokio::test]
async fn catalog_member_migration_add_seen_before_removal_is_ignored_as_a_clash() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "a.catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."

                [[catalog_zones]]
                name = "b.catalog.example."
                catalog_primaries = ["192.0.2.54:53"]
                member_primaries = ["10.0.0.54:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."
            "#,
    )
    .expect("valid catalog config");
    let catalog_a = DomainName::from_absolute_str("a.catalog.example.").unwrap();
    let catalog_b = DomainName::from_absolute_str("b.catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let initial_a =
        catalog_snapshot_with_members(catalog_a.clone(), 7, std::slice::from_ref(&member_origin));
    let updated_a = catalog_snapshot_with_members(catalog_a.clone(), 8, &[]);
    let updated_b =
        catalog_snapshot_with_members(catalog_b.clone(), 7, std::slice::from_ref(&member_origin));
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_a.clone());
    zones.insert_loading_hidden(catalog_b.clone());
    zones.insert_snapshot(initial_a.clone());
    zones.insert_snapshot(updated_b.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, _rx) = mpsc::channel(4);

    catalog_manager
        .apply_snapshot(
            initial_a.catalog_zone_view(),
            &zone_metadata_for(&initial_a),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    catalog_manager
        .apply_snapshot(
            updated_b.catalog_zone_view(),
            &zone_metadata_for(&updated_b),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    catalog_manager
        .apply_snapshot(
            updated_a.catalog_zone_view(),
            &zone_metadata_for(&updated_a),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    assert!(transfer_plan.get(&member_origin).is_none());
    assert!(!zones.contains_exact_zone_for_control(&member_origin));
    assert!(
        !refresh_registry
            .snapshots_by_zone()
            .contains_key("member.example.")
    );
}

#[tokio::test]
async fn overlapping_catalog_members_keep_first_applied_owner_until_removal() {
    for apply_a_first in [true, false] {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "Y2F0YWxvZy1zZWNyZXQ="

                [[tsig_keys]]
                name = "member-a-key."
                algorithm = "hmac-sha256"
                secret = "bWVtYmVyLWEtc2VjcmV0"

                [[tsig_keys]]
                name = "member-b-key."
                algorithm = "hmac-sha256"
                secret = "bWVtYmVyLWItc2VjcmV0"

                [[catalog_zones]]
                name = "a.catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "member-a-key."
                member_transfer_extensions = true

                [[catalog_zones]]
                name = "b.catalog.example."
                catalog_primaries = ["192.0.2.54:53"]
                member_primaries = ["10.0.0.54:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "member-b-key."
                member_transfer_extensions = true
            "#,
        )
        .expect("valid catalog config");
        let catalog_a = DomainName::from_absolute_str("a.catalog.example.").unwrap();
        let catalog_b = DomainName::from_absolute_str("b.catalog.example.").unwrap();
        let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
        let snapshot_a = catalog_snapshot_with_member_override(
            catalog_a.clone(),
            7,
            member_origin.clone(),
            [198, 51, 100, 10],
            5301,
            "member-a-key.",
            [203, 0, 113, 10],
        );
        let snapshot_b = catalog_snapshot_with_member_override(
            catalog_b.clone(),
            7,
            member_origin.clone(),
            [198, 51, 100, 20],
            5302,
            "member-b-key.",
            [203, 0, 113, 20],
        );
        let zones = ZoneStore::new();
        zones.insert_loading_hidden(catalog_a.clone());
        zones.insert_loading_hidden(catalog_b.clone());
        zones.insert_snapshot(snapshot_a.clone());
        zones.insert_snapshot(snapshot_b.clone());
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let catalog_manager = CatalogManager::from_config(&config);
        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
        );
        let notify_authority = NotifyAuthority::from_config_for_test(&config);
        let (tx, _rx) = mpsc::channel(16);

        let snapshots = if apply_a_first {
            [&snapshot_a, &snapshot_b]
        } else {
            [&snapshot_b, &snapshot_a]
        };
        for snapshot in snapshots {
            catalog_manager
                .apply_snapshot(
                    snapshot.catalog_zone_view(),
                    &zone_metadata_for(snapshot),
                    &zones,
                    &transfer_plan,
                    &refresh_registry,
                    &notify_authority,
                    &tx.downgrade(),
                )
                .await;
        }

        let (
            owner_catalog,
            owner_primary,
            owner_key,
            owner_notify,
            clash_notify,
            owner_empty,
            clash_snapshot,
            clash_catalog,
            clash_primary,
            clash_key,
        ) = if apply_a_first {
            (
                "a.catalog.example.",
                SocketAddr::from((Ipv4Addr::new(198, 51, 100, 10), 5301)),
                "member-a-key.",
                "203.0.113.10",
                "203.0.113.20",
                catalog_snapshot_with_members(catalog_a.clone(), 8, &[]),
                &snapshot_b,
                "b.catalog.example.",
                SocketAddr::from((Ipv4Addr::new(198, 51, 100, 20), 5302)),
                "member-b-key.",
            )
        } else {
            (
                "b.catalog.example.",
                SocketAddr::from((Ipv4Addr::new(198, 51, 100, 20), 5302)),
                "member-b-key.",
                "203.0.113.20",
                "203.0.113.10",
                catalog_snapshot_with_members(catalog_b.clone(), 8, &[]),
                &snapshot_a,
                "a.catalog.example.",
                SocketAddr::from((Ipv4Addr::new(198, 51, 100, 10), 5301)),
                "member-a-key.",
            )
        };
        assert_catalog_member_policy(
            &transfer_plan,
            &notify_authority,
            &member_origin,
            owner_primary,
            owner_key,
            owner_notify,
            clash_notify,
        );
        assert_eq!(
            catalog_manager
                .member_metrics()
                .iter()
                .map(|member| member.catalog_zone.to_string())
                .collect::<Vec<_>>(),
            vec![owner_catalog]
        );

        catalog_manager
            .apply_snapshot(
                owner_empty.catalog_zone_view(),
                &zone_metadata_for(&owner_empty),
                &zones,
                &transfer_plan,
                &refresh_registry,
                &notify_authority,
                &tx.downgrade(),
            )
            .await;

        assert!(transfer_plan.get(&member_origin).is_none());
        assert!(!zones.contains_exact_zone_for_control(&member_origin));
        assert_eq!(catalog_manager.member_metrics(), Vec::new());

        // A new update from the formerly clashing catalog is now a fresh add.
        catalog_manager
            .apply_snapshot(
                clash_snapshot.catalog_zone_view(),
                &zone_metadata_for(clash_snapshot),
                &zones,
                &transfer_plan,
                &refresh_registry,
                &notify_authority,
                &tx.downgrade(),
            )
            .await;

        assert_catalog_member_policy(
            &transfer_plan,
            &notify_authority,
            &member_origin,
            clash_primary,
            clash_key,
            clash_notify,
            owner_notify,
        );
        assert!(zones.contains_exact_zone_for_control(&member_origin));
        assert_eq!(
            catalog_manager
                .member_metrics()
                .iter()
                .map(|member| member.catalog_zone.to_string())
                .collect::<Vec<_>>(),
            vec![clash_catalog]
        );

        let clash_empty = if apply_a_first {
            catalog_snapshot_with_members(catalog_b.clone(), 8, &[])
        } else {
            catalog_snapshot_with_members(catalog_a.clone(), 8, &[])
        };
        catalog_manager
            .apply_snapshot(
                clash_empty.catalog_zone_view(),
                &zone_metadata_for(&clash_empty),
                &zones,
                &transfer_plan,
                &refresh_registry,
                &notify_authority,
                &tx.downgrade(),
            )
            .await;

        assert!(transfer_plan.get(&member_origin).is_none());
        assert!(!notify_authority.is_authorized(
            &member_origin,
            1,
            clash_notify.parse().unwrap()
        ));
        assert!(!zones.contains_exact_zone_for_control(&member_origin));
        assert!(
            !refresh_registry
                .snapshots_by_zone()
                .contains_key(&member_origin.canonical_key())
        );
        assert_eq!(catalog_manager.member_metrics(), Vec::new());
    }
}

#[tokio::test]
async fn later_lexicographically_smaller_catalog_cannot_take_over_existing_member() {
    let config = ServerConfig::from_toml_str(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [[tsig_keys]]
            name = "catalog-key."
            algorithm = "hmac-sha256"
            secret = "Y2F0YWxvZy1zZWNyZXQ="

            [[catalog_zones]]
            name = "a.catalog.example."
            catalog_primaries = ["192.0.2.53:53"]
            member_primaries = ["10.0.0.53:53"]
            catalog_tsig_key = "catalog-key."
            member_tsig_key = "catalog-key."

            [[catalog_zones]]
            name = "b.catalog.example."
            catalog_primaries = ["192.0.2.54:53"]
            member_primaries = ["10.0.0.54:53"]
            catalog_tsig_key = "catalog-key."
            member_tsig_key = "catalog-key."
        "#,
    )
    .expect("valid catalog config");
    let catalog_a = DomainName::from_absolute_str("a.catalog.example.").unwrap();
    let catalog_b = DomainName::from_absolute_str("b.catalog.example.").unwrap();
    let member = DomainName::from_absolute_str("member.example.").unwrap();
    let snapshot_a = catalog_snapshot_with_members(
        catalog_a.clone(),
        7,
        std::slice::from_ref(&member),
    );
    let snapshot_b = catalog_snapshot_with_members(
        catalog_b.clone(),
        7,
        std::slice::from_ref(&member),
    );
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_a);
    zones.insert_loading_hidden(catalog_b);
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, _rx) = mpsc::channel(8);

    for snapshot in [&snapshot_b, &snapshot_a] {
        catalog_manager
            .apply_snapshot(
                snapshot.catalog_zone_view(),
                &zone_metadata_for(snapshot),
                &zones,
                &transfer_plan,
                &refresh_registry,
                &notify_authority,
                &tx.downgrade(),
            )
            .await;
    }

    assert_eq!(
        transfer_plan.get(&member).expect("member plan").primaries[0].addr,
        "10.0.0.54:53".parse().unwrap(),
        "RFC 9432 name clashes retain the first-applied catalog instance"
    );
}

#[tokio::test]
async fn catalog_member_node_rename_resets_zone_state_and_plan_generation() {
    let config = ServerConfig::from_toml_str(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [[tsig_keys]]
            name = "catalog-key."
            algorithm = "hmac-sha256"
            secret = "Y2F0YWxvZy1zZWNyZXQ="

            [[catalog_zones]]
            name = "catalog.example."
            catalog_primaries = ["192.0.2.53:53"]
            member_primaries = ["10.0.0.53:53"]
            catalog_tsig_key = "catalog-key."
            member_tsig_key = "catalog-key."
        "#,
    )
    .expect("valid catalog config");
    let catalog = DomainName::from_absolute_str("catalog.example.").unwrap();
    let member = DomainName::from_absolute_str("member.example.").unwrap();
    let initial = catalog_snapshot_with_named_member(
        catalog.clone(),
        7,
        "old-node",
        member.clone(),
    );
    let renamed = catalog_snapshot_with_named_member(
        catalog.clone(),
        8,
        "new-node",
        member.clone(),
    );
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog);
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, _rx) = mpsc::channel(8);

    catalog_manager
        .apply_snapshot(
            initial.catalog_zone_view(),
            &zone_metadata_for(&initial),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    let old_generation = transfer_plan.get(&member).expect("member plan").generation();
    zones.insert_snapshot(active_member_snapshot(member.clone(), 42));

    catalog_manager
        .apply_snapshot(
            renamed.catalog_zone_view(),
            &zone_metadata_for(&renamed),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    let metadata = zones
        .zone_metadata()
        .into_iter()
        .find(|metadata| metadata.origin == member)
        .expect("renamed member remains provisioned");
    assert_eq!(metadata.state, ZoneState::Loading);
    assert_ne!(
        transfer_plan.get(&member).expect("replacement plan").generation(),
        old_generation,
        "member-node rename is a new zone lifecycle"
    );
}

#[tokio::test]
async fn retained_catalog_member_keeps_transfer_plan_generation_when_unchanged() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."
            "#,
    )
    .expect("valid catalog config");
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let snapshot =
        catalog_snapshot_with_members(catalog_origin.clone(), 7, std::slice::from_ref(&member_origin));
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin.clone());
    zones.insert_snapshot(snapshot.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, _rx) = mpsc::channel(4);
    let metadata = zone_metadata_for(&snapshot);

    catalog_manager
        .apply_snapshot(
            snapshot.catalog_zone_view(),
            &metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    let in_flight_plan = transfer_plan.get(&member_origin).expect("member transfer plan");

    catalog_manager
        .apply_snapshot(
            snapshot.catalog_zone_view(),
            &metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    assert!(transfer_plan.is_current_plan(&in_flight_plan));
}

#[tokio::test]
async fn catalog_member_migration_remove_then_add_resets_active_snapshot() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "a.catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."

                [[catalog_zones]]
                name = "b.catalog.example."
                catalog_primaries = ["192.0.2.54:53"]
                member_primaries = ["10.0.0.54:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."
            "#,
    )
    .expect("valid catalog config");
    let catalog_a = DomainName::from_absolute_str("a.catalog.example.").unwrap();
    let catalog_b = DomainName::from_absolute_str("b.catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let initial_a =
        catalog_snapshot_with_members(catalog_a.clone(), 7, std::slice::from_ref(&member_origin));
    let updated_a = catalog_snapshot_with_members(catalog_a.clone(), 8, &[]);
    let updated_b =
        catalog_snapshot_with_members(catalog_b.clone(), 7, std::slice::from_ref(&member_origin));
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_a.clone());
    zones.insert_loading_hidden(catalog_b.clone());
    zones.insert_snapshot(initial_a.clone());
    zones.insert_snapshot(updated_b.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, _rx) = mpsc::channel(4);

    catalog_manager
        .apply_snapshot(
            initial_a.catalog_zone_view(),
            &zone_metadata_for(&initial_a),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    let active_snapshot = active_member_snapshot(member_origin.clone(), 42);
    let active_metadata = zones
        .insert_snapshot_arc_for_transfer(Arc::new(active_snapshot))
        .expect("publish active member");
    refresh_registry.record_success_from_metadata(&active_metadata);

    catalog_manager
        .apply_snapshot(
            updated_a.catalog_zone_view(),
            &zone_metadata_for(&updated_a),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    catalog_manager
        .apply_snapshot(
            updated_b.catalog_zone_view(),
            &zone_metadata_for(&updated_b),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    let replacement = zones
        .exact_zone_control_metadata(&member_origin)
        .expect("member is re-added as a fresh lifecycle");
    assert_eq!(replacement.state, ZoneState::Loading);
    assert_eq!(replacement.serial, None);
    assert!(
        refresh_registry
            .snapshots_by_zone()
            .contains_key(&member_origin.canonical_key())
    );
}

#[tokio::test]
async fn catalog_member_later_readd_starts_loading_without_stale_restore() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "a.catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."

                [[catalog_zones]]
                name = "b.catalog.example."
                catalog_primaries = ["192.0.2.54:53"]
                member_primaries = ["10.0.0.54:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."
            "#,
    )
    .expect("valid catalog config");
    let catalog_a = DomainName::from_absolute_str("a.catalog.example.").unwrap();
    let catalog_b = DomainName::from_absolute_str("b.catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let initial_a =
        catalog_snapshot_with_members(catalog_a.clone(), 7, std::slice::from_ref(&member_origin));
    let updated_a = catalog_snapshot_with_members(catalog_a.clone(), 8, &[]);
    let updated_b =
        catalog_snapshot_with_members(catalog_b.clone(), 7, std::slice::from_ref(&member_origin));
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_a.clone());
    zones.insert_loading_hidden(catalog_b.clone());
    zones.insert_snapshot(initial_a.clone());
    zones.insert_snapshot(updated_b.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, _rx) = mpsc::channel(4);

    catalog_manager
        .apply_snapshot(
            initial_a.catalog_zone_view(),
            &zone_metadata_for(&initial_a),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    let active_snapshot = active_member_snapshot(member_origin.clone(), 42);
    let active_metadata = zones
        .insert_snapshot_arc_for_transfer(Arc::new(active_snapshot))
        .expect("publish active member");
    refresh_registry.record_success_from_metadata(&active_metadata);

    catalog_manager
        .apply_snapshot(
            updated_a.catalog_zone_view(),
            &zone_metadata_for(&updated_a),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    assert!(!zones.contains_exact_zone_for_control(&member_origin));

    catalog_manager
        .apply_snapshot(
            updated_b.catalog_zone_view(),
            &zone_metadata_for(&updated_b),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    let readded = zones
        .exact_zone_control_metadata(&member_origin)
        .expect("member re-added as loading");
    assert_eq!(readded.state, ZoneState::Loading);
    assert_eq!(readded.serial, None);
}

#[tokio::test]
async fn rejected_catalog_member_transfer_override_does_not_preserve_other_catalog_ownership() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "a.catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."

                [[catalog_zones]]
                name = "b.catalog.example."
                catalog_primaries = ["192.0.2.54:53"]
                member_primaries = ["10.0.0.54:53"]
                catalog_tsig_key = "catalog-key."
                member_transfer_extensions = true

                [catalog_zones.member_transfer_policy]
                unsigned_axfr = "allow-legacy-private"
            "#,
    )
    .expect("valid catalog config");
    let catalog_a = DomainName::from_absolute_str("a.catalog.example.").unwrap();
    let catalog_b = DomainName::from_absolute_str("b.catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let initial_a =
        catalog_snapshot_with_members(catalog_a.clone(), 7, std::slice::from_ref(&member_origin));
    let updated_a = catalog_snapshot_with_members(catalog_a.clone(), 8, &[]);
    let rejected_b = ZoneSnapshot::active(
        catalog_b.clone(),
        Some(7),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("version.b.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt("2")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("a.zones.b.catalog.example.").unwrap(),
                RecordType::Ptr as u16,
                1,
                0,
                vec![member_origin.to_wire()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("primaries.ext.a.zones.b.catalog.example.").unwrap(),
                RecordType::A as u16,
                1,
                0,
                vec![vec![203, 0, 113, 53]],
            ),
        ],
    );
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_a.clone());
    zones.insert_loading_hidden(catalog_b.clone());
    zones.insert_snapshot(initial_a.clone());
    zones.insert_snapshot(rejected_b.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, _rx) = mpsc::channel(4);

    catalog_manager
        .apply_snapshot(
            initial_a.catalog_zone_view(),
            &zone_metadata_for(&initial_a),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    catalog_manager
        .apply_snapshot(
            rejected_b.catalog_zone_view(),
            &zone_metadata_for(&rejected_b),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    catalog_manager
        .apply_snapshot(
            updated_a.catalog_zone_view(),
            &zone_metadata_for(&updated_a),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    assert!(transfer_plan.get(&member_origin).is_none());
    assert!(!zones.contains_exact_zone_for_control(&member_origin));
}

#[tokio::test]
async fn catalog_reconciliation_does_not_block_when_refresh_queue_is_full() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "a.catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."

                [[catalog_zones]]
                name = "b.catalog.example."
                catalog_primaries = ["192.0.2.54:53"]
                member_primaries = ["10.0.0.54:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."
            "#,
    )
    .expect("valid catalog config");
    let catalog_a = DomainName::from_absolute_str("a.catalog.example.").unwrap();
    let catalog_b = DomainName::from_absolute_str("b.catalog.example.").unwrap();
    let member_a = DomainName::from_absolute_str("a-member.example.").unwrap();
    let member_b = DomainName::from_absolute_str("b-member.example.").unwrap();
    let snapshot_a =
        catalog_snapshot_with_members(catalog_a.clone(), 7, std::slice::from_ref(&member_a));
    let snapshot_b =
        catalog_snapshot_with_members(catalog_b.clone(), 7, std::slice::from_ref(&member_b));
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_a.clone());
    zones.insert_loading_hidden(catalog_b.clone());
    zones.insert_snapshot(snapshot_a.clone());
    zones.insert_snapshot(snapshot_b.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, mut rx) = mpsc::channel(1);
    let queued_origin = DomainName::from_absolute_str("queued.example.").unwrap();
    tx.try_send(RefreshRequest::new(
        queued_origin.clone(),
        None,
        RefreshReason::Catalog,
    ))
    .expect("prefill refresh queue");
    let metadata_a = zone_metadata_for(&snapshot_a);
    let metadata_b = zone_metadata_for(&snapshot_b);
    let refresh_tx_a = tx.downgrade();
    let refresh_tx_b = tx.downgrade();

    let apply_both = async {
        tokio::join!(
            catalog_manager.apply_snapshot(
                snapshot_a.catalog_zone_view(),
                &metadata_a,
                &zones,
                &transfer_plan,
                &refresh_registry,
                &notify_authority,
                &refresh_tx_a,
            ),
            catalog_manager.apply_snapshot(
                snapshot_b.catalog_zone_view(),
                &metadata_b,
                &zones,
                &transfer_plan,
                &refresh_registry,
                &notify_authority,
                &refresh_tx_b,
            )
        );
    };
    let drain_after_both_reconcile = async {
        for member in [&member_a, &member_b] {
            for _ in 0..100 {
                if zones.contains_exact_zone_for_control(member) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(
                zones.contains_exact_zone_for_control(member),
                "catalog reconcile should publish {member} before refresh queue space is available"
            );
        }

        let mut queued_zones = Vec::new();
        for _ in 0..3 {
            queued_zones.push(
                rx.recv()
                    .await
                    .expect("queued refresh request")
                    .zone
                    .canonical_key(),
            );
        }
        queued_zones
    };

    let ((), queued_zones) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(apply_both, drain_after_both_reconcile)
    })
    .await
    .expect("full refresh queue must not block catalog reconciliation or drop member refreshes");

    assert!(zones.contains_exact_zone_for_control(&member_a));
    assert!(zones.contains_exact_zone_for_control(&member_b));
    assert!(queued_zones.contains(&queued_origin.canonical_key()));
    assert!(queued_zones.contains(&member_a.canonical_key()));
    assert!(queued_zones.contains(&member_b.canonical_key()));
}

#[tokio::test]
async fn catalog_snapshot_removes_non_text_roundtrippable_member_without_panic() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[tsig_keys]]
                name = "member-key."
                algorithm = "hmac-sha256"
                secret = "bWVtYmVyLXNlY3JldA=="

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "member-key."
            "#,
    )
    .expect("valid catalog config");
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let member_wire = vec![
        3, b'a', b'.', b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
    ];
    let (member_origin, consumed) = DomainName::parse(&member_wire, 0).unwrap();
    assert_eq!(consumed, member_wire.len());
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, mut rx) = mpsc::channel(1);

    let initial_snapshot =
        catalog_snapshot_with_member_wires(catalog_origin.clone(), 7, &[member_wire]);
    zones.insert_snapshot(initial_snapshot.clone());
    let initial_metadata = zone_metadata_for(&initial_snapshot);
    catalog_manager
        .apply_snapshot(
            initial_snapshot.catalog_zone_view(),
            &initial_metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    assert!(transfer_plan.get(&member_origin).is_some());
    assert_eq!(rx.recv().await.expect("member refresh request").zone, member_origin);

    let updated_snapshot = catalog_snapshot_with_member_wires(catalog_origin.clone(), 8, &[]);
    zones.insert_snapshot(updated_snapshot.clone());
    let updated_metadata = zone_metadata_for(&updated_snapshot);
    catalog_manager
        .apply_snapshot(
            updated_snapshot.catalog_zone_view(),
            &updated_metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    assert!(transfer_plan.get(&member_origin).is_none());
    assert!(!zones.contains_exact_zone_for_control(&member_origin));
    assert!(
        !refresh_registry
            .snapshots_by_zone()
            .contains_key(&member_origin.canonical_key())
    );
}

fn catalog_snapshot_with_members(
    catalog_origin: DomainName,
    serial: u32,
    members: &[DomainName],
) -> ZoneSnapshot {
    let member_wires = members
        .iter()
        .map(DomainName::to_wire)
        .collect::<Vec<_>>();
    catalog_snapshot_with_member_wires(catalog_origin, serial, &member_wires)
}

fn catalog_snapshot_with_member_wires(
    catalog_origin: DomainName,
    serial: u32,
    member_wires: &[Vec<u8>],
) -> ZoneSnapshot {
    let mut rrsets = vec![Rrset::new(
        DomainName::from_absolute_str(&format!("version.{catalog_origin}")).unwrap(),
        RecordType::Txt as u16,
        1,
        0,
        vec![catalog_txt("2")],
    )];
    for (index, member_wire) in member_wires.iter().enumerate() {
        rrsets.push(Rrset::new(
            DomainName::from_absolute_str(&format!("m{index}.zones.{catalog_origin}")).unwrap(),
            RecordType::Ptr as u16,
            1,
            0,
            vec![member_wire.clone()],
        ));
    }
    ZoneSnapshot::active(catalog_origin, Some(serial), rrsets)
}

fn catalog_snapshot_with_named_member(
    catalog_origin: DomainName,
    serial: u32,
    member_node_label: &str,
    member: DomainName,
) -> ZoneSnapshot {
    ZoneSnapshot::active(
        catalog_origin.clone(),
        Some(serial),
        vec![
            Rrset::new(
                DomainName::from_absolute_str(&format!("version.{catalog_origin}")).unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt("2")],
            ),
            Rrset::new(
                DomainName::from_absolute_str(&format!(
                    "{member_node_label}.zones.{catalog_origin}"
                ))
                .unwrap(),
                RecordType::Ptr as u16,
                1,
                0,
                vec![member.to_wire()],
            ),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn catalog_snapshot_with_member_override(
    catalog_origin: DomainName,
    serial: u32,
    member_origin: DomainName,
    primary: [u8; 4],
    port: u16,
    tsig_key: &str,
    notify_source: [u8; 4],
) -> ZoneSnapshot {
    ZoneSnapshot::active(
        catalog_origin.clone(),
        Some(serial),
        vec![
            Rrset::new(
                DomainName::from_absolute_str(&format!("version.{catalog_origin}")).unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt("2")],
            ),
            Rrset::new(
                DomainName::from_absolute_str(&format!("member.zones.{catalog_origin}"))
                    .unwrap(),
                RecordType::Ptr as u16,
                1,
                0,
                vec![member_origin.to_wire()],
            ),
            Rrset::new(
                DomainName::from_absolute_str(&format!(
                    "primaries.ext.member.zones.{catalog_origin}"
                ))
                .unwrap(),
                RecordType::A as u16,
                1,
                0,
                vec![primary.to_vec()],
            ),
            Rrset::new(
                DomainName::from_absolute_str(&format!(
                    "primaries.ext.member.zones.{catalog_origin}"
                ))
                .unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt(tsig_key)],
            ),
            Rrset::new(
                DomainName::from_absolute_str(&format!(
                    "_udns-xfr.ext.member.zones.{catalog_origin}"
                ))
                .unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt(&format!("transport=tcp;port={port}"))],
            ),
            Rrset::new(
                DomainName::from_absolute_str(&format!(
                    "_udns-notify.ext.member.zones.{catalog_origin}"
                ))
                .unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt(&format!(
                    "source={}",
                    Ipv4Addr::from(notify_source)
                ))],
            ),
        ],
    )
}

fn assert_catalog_member_policy(
    transfer_plan: &TransferPlan,
    notify_authority: &NotifyAuthority,
    member_origin: &DomainName,
    expected_primary: SocketAddr,
    expected_tsig_key: &str,
    expected_notify_source: &str,
    rejected_notify_source: &str,
) {
    let member_plan = transfer_plan
        .get(member_origin)
        .expect("member transfer plan");
    assert_eq!(member_plan.primaries[0].addr, expected_primary);
    assert_eq!(
        member_plan
            .tsig_key_name
            .as_ref()
            .expect("member TSIG key")
            .to_string(),
        expected_tsig_key
    );
    assert!(notify_authority.is_authorized(
        member_origin,
        1,
        expected_notify_source.parse().unwrap()
    ));
    assert!(!notify_authority.is_authorized(
        member_origin,
        1,
        rejected_notify_source.parse().unwrap()
    ));
    assert_eq!(
        notify_authority
            .tsig_key_for_notify(member_origin, 1)
            .expect("member NOTIFY TSIG key")
            .name
            .to_string(),
        expected_tsig_key
    );
}

fn active_member_snapshot(origin: DomainName, serial: u32) -> ZoneSnapshot {
    ZoneSnapshot::active(
        origin.clone(),
        Some(serial),
        vec![
            Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                300,
                vec![soa_rdata_with_serial(serial)],
            ),
            Rrset::new(
                origin,
                RecordType::Ns as u16,
                1,
                300,
                vec![ns_rdata_for_zone("example.test.")],
            ),
        ],
    )
}

fn catalog_member_snapshot_with_extensions(
    catalog_origin: &DomainName,
    member_origin: &DomainName,
    serial: u32,
    mut extensions: Vec<Rrset>,
) -> ZoneSnapshot {
    let mut rrsets = vec![
        Rrset::new(
            DomainName::from_absolute_str("version.catalog.example.").unwrap(),
            RecordType::Txt as u16,
            1,
            0,
            vec![catalog_txt("2")],
        ),
        Rrset::new(
            DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
            RecordType::Ptr as u16,
            1,
            0,
            vec![member_origin.to_wire()],
        ),
    ];
    rrsets.append(&mut extensions);
    ZoneSnapshot::active(catalog_origin.clone(), Some(serial), rrsets)
}

fn catalog_extension_transition_config() -> ServerConfig {
    ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[tsig_keys]]
                name = "fallback-key."
                algorithm = "hmac-sha256"
                secret = "ZmFsbGJhY2stc2VjcmV0"

                [[tsig_keys]]
                name = "override-key."
                algorithm = "hmac-sha256"
                secret = "b3ZlcnJpZGUtc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                notify_sources = ["198.51.100.54"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "fallback-key."
                member_transfer_extensions = true

                [[catalog_zones.member_transfer_primaries]]
                addr = "203.0.113.53:53"
                transport = "tcp"

                [[catalog_zones.member_transfer_primaries]]
                addr = "203.0.113.54:853"
                transport = "xot"
                server_name = "fallback-member.example"
                trust_anchors = ["/etc/borondns/member-ca.pem"]
            "#,
    )
    .expect("valid catalog extension transition config")
}

#[test]
fn legacy_catalog_member_transfer_policy_keeps_catalog_signed_but_members_unsigned() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."

                [catalog_zones.member_transfer_policy]
                unsigned_axfr = "allow-legacy-private"
            "#,
    )
    .expect("valid catalog config");
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");

    let catalog_plan = transfer_plan
        .get(&catalog_origin)
        .expect("catalog transfer plan");
    assert_eq!(
        catalog_plan
            .tsig_key_name
            .as_ref()
            .expect("catalog TSIG key")
            .to_string(),
        "catalog-key."
    );

    let member_plan = transfer_plan
        .catalog_member_plan(&catalog_origin, member_origin, None)
        .expect("member transfer plan");
    assert_eq!(
        member_plan
            .primaries
            .iter()
            .map(|primary| primary.addr)
            .collect::<Vec<_>>(),
        vec![SocketAddr::from((Ipv4Addr::new(10, 0, 0, 53), 53))]
    );
    assert!(member_plan.tsig_key_name.is_none());
}

#[test]
fn legacy_catalog_member_transfer_policy_rejects_public_unsigned_catalog_override() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."
                member_transfer_extensions = true

                [catalog_zones.member_transfer_policy]
                unsigned_axfr = "allow-legacy-private"
            "#,
    )
    .expect("valid catalog config");
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let transfer_override = borondns_core::catalog::CatalogMemberTransfer {
        primaries: vec![borondns_core::catalog::CatalogMemberPrimary {
            addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)),
        }],
        tsig_key_name: None,
        xfr: None,
        notify_sources: Vec::new(),
    };

    assert!(
        transfer_plan
            .catalog_member_plan(&catalog_origin, member_origin, Some(&transfer_override))
            .is_none()
    );
}

#[tokio::test]
async fn catalog_snapshot_applies_opt_in_member_transfer_extension() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[tsig_keys]]
                name = "fallback-key."
                algorithm = "hmac-sha256"
                secret = "ZmFsbGJhY2stc2VjcmV0"

                [[tsig_keys]]
                name = "override-key."
                algorithm = "hmac-sha256"
                secret = "b3ZlcnJpZGUtc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["203.0.113.53:53"]
                notify_sources = ["198.51.100.54"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "fallback-key."
                member_transfer_extensions = true
            "#,
    )
    .expect("valid catalog config");
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let snapshot = ZoneSnapshot::active(
        catalog_origin.clone(),
        Some(7),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt("2")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                RecordType::Ptr as u16,
                1,
                0,
                vec![member_origin.to_wire()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("primaries.ext.a.zones.catalog.example.").unwrap(),
                RecordType::A as u16,
                1,
                0,
                vec![vec![198, 51, 100, 53]],
            ),
            Rrset::new(
                DomainName::from_absolute_str("primaries.ext.a.zones.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt("override-key.")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("_udns-xfr.ext.a.zones.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt("transport=tcp;port=5300")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("_udns-notify.ext.a.zones.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt("source=198.51.100.55")],
            ),
        ],
    );
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin.clone());
    zones.insert_snapshot(snapshot.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, mut rx) = mpsc::channel(1);
    let metadata = zone_metadata_for(&snapshot);

    catalog_manager
        .apply_snapshot(
            snapshot.catalog_zone_view(),
            &metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    let member_plan = transfer_plan
        .get(&member_origin)
        .expect("member transfer plan");
    assert_eq!(
        member_plan
            .primaries
            .iter()
            .map(|primary| primary.addr)
            .collect::<Vec<_>>(),
        vec![SocketAddr::from((Ipv4Addr::new(198, 51, 100, 53), 5300))]
    );
    assert_eq!(
        member_plan
            .tsig_key_name
            .as_ref()
            .expect("override TSIG key")
            .to_string(),
        "override-key."
    );
    assert!(notify_authority.is_authorized(&member_origin, 1, "198.51.100.53".parse().unwrap()));
    assert!(notify_authority.is_authorized(&member_origin, 1, "198.51.100.54".parse().unwrap()));
    assert!(notify_authority.is_authorized(&member_origin, 1, "198.51.100.55".parse().unwrap()));
    assert!(!notify_authority.is_authorized(&member_origin, 1, "203.0.113.53".parse().unwrap()));
    assert_eq!(
        rx.recv().await.expect("member refresh request").zone,
        member_origin
    );
}

#[tokio::test]
async fn catalog_malformed_update_retains_valid_xot_and_tsig_then_absent_uses_fallback() {
    let config = catalog_extension_transition_config();
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let valid_snapshot = catalog_member_snapshot_with_extensions(
        &catalog_origin,
        &member_origin,
        7,
        vec![
            Rrset::new(
                DomainName::from_absolute_str("primaries.ext.a.zones.catalog.example.").unwrap(),
                RecordType::A as u16,
                1,
                0,
                vec![vec![198, 51, 100, 53]],
            ),
            Rrset::new(
                DomainName::from_absolute_str("primaries.ext.a.zones.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt("override-key.")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("_udns-xfr.ext.a.zones.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt(
                    "transport=xot;port=8853;server_name=override-member.example",
                )],
            ),
            Rrset::new(
                DomainName::from_absolute_str("_udns-notify.ext.a.zones.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt("source=198.51.100.55")],
            ),
        ],
    );
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin.clone());
    zones.insert_snapshot(valid_snapshot.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, mut rx) = mpsc::channel(4);

    catalog_manager
        .apply_snapshot(
            valid_snapshot.catalog_zone_view(),
            &zone_metadata_for(&valid_snapshot),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;
    assert_eq!(
        rx.recv().await.expect("initial member refresh").zone,
        member_origin
    );
    zones.insert_snapshot(active_member_snapshot(member_origin.clone(), 1));
    let valid_plan = transfer_plan.get(&member_origin).expect("valid member plan");
    let valid_generation = valid_plan.generation();
    assert_eq!(valid_plan.primaries.len(), 1);
    assert_eq!(
        valid_plan.primaries[0].transport,
        TransferTransportConfig::Xot
    );
    assert_eq!(valid_plan.primaries[0].addr.port(), 8853);
    assert_eq!(
        valid_plan.tsig_key_name.as_ref().map(ToString::to_string),
        Some("override-key.".to_owned())
    );

    let malformed_snapshot = catalog_member_snapshot_with_extensions(
        &catalog_origin,
        &member_origin,
        8,
        vec![Rrset::new(
            DomainName::from_absolute_str("_udns-xfr.ext.a.zones.catalog.example.").unwrap(),
            RecordType::Txt as u16,
            1,
            0,
            vec![catalog_txt("transport=udp;port=0")],
        )],
    );
    zones.insert_snapshot(malformed_snapshot.clone());
    catalog_manager
        .apply_snapshot(
            malformed_snapshot.catalog_zone_view(),
            &zone_metadata_for(&malformed_snapshot),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    let retained_plan = transfer_plan
        .get(&member_origin)
        .expect("retained valid member plan");
    assert_eq!(retained_plan.generation(), valid_generation);
    assert_eq!(retained_plan.primaries, valid_plan.primaries);
    assert_eq!(retained_plan.tsig_key_name, valid_plan.tsig_key_name);
    assert!(notify_authority.is_authorized(
        &member_origin,
        1,
        "198.51.100.53".parse().unwrap()
    ));
    assert!(notify_authority.is_authorized(
        &member_origin,
        1,
        "198.51.100.55".parse().unwrap()
    ));
    assert!(!notify_authority.is_authorized(
        &member_origin,
        1,
        "203.0.113.53".parse().unwrap()
    ));
    assert!(rx.try_recv().is_err());

    let absent_snapshot = catalog_member_snapshot_with_extensions(
        &catalog_origin,
        &member_origin,
        9,
        Vec::new(),
    );
    zones.insert_snapshot(absent_snapshot.clone());
    catalog_manager
        .apply_snapshot(
            absent_snapshot.catalog_zone_view(),
            &zone_metadata_for(&absent_snapshot),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    let fallback_plan = transfer_plan
        .get(&member_origin)
        .expect("static fallback member plan");
    assert_ne!(fallback_plan.generation(), valid_generation);
    assert_eq!(fallback_plan.primaries.len(), 2);
    assert_eq!(
        fallback_plan.tsig_key_name.as_ref().map(ToString::to_string),
        Some("fallback-key.".to_owned())
    );
    assert!(notify_authority.is_authorized(
        &member_origin,
        1,
        "203.0.113.53".parse().unwrap()
    ));
    assert!(!notify_authority.is_authorized(
        &member_origin,
        1,
        "198.51.100.53".parse().unwrap()
    ));
    assert!(!notify_authority.is_authorized(
        &member_origin,
        1,
        "198.51.100.55".parse().unwrap()
    ));
    assert_eq!(
        rx.recv().await.expect("fallback policy refresh").zone,
        member_origin
    );
}

#[tokio::test]
async fn catalog_new_member_with_malformed_extension_uses_static_fallback() {
    let config = catalog_extension_transition_config();
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    let malformed_snapshot = catalog_member_snapshot_with_extensions(
        &catalog_origin,
        &member_origin,
        7,
        vec![Rrset::new(
            DomainName::from_absolute_str("_udns-xfr.ext.a.zones.catalog.example.").unwrap(),
            RecordType::Txt as u16,
            1,
            0,
            vec![catalog_txt("transport=udp;port=0")],
        )],
    );
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin.clone());
    zones.insert_snapshot(malformed_snapshot.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, mut rx) = mpsc::channel(1);

    catalog_manager
        .apply_snapshot(
            malformed_snapshot.catalog_zone_view(),
            &zone_metadata_for(&malformed_snapshot),
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    let fallback_plan = transfer_plan
        .get(&member_origin)
        .expect("new malformed member fallback plan");
    assert_eq!(fallback_plan.primaries.len(), 2);
    assert_eq!(
        fallback_plan.tsig_key_name.as_ref().map(ToString::to_string),
        Some("fallback-key.".to_owned())
    );
    assert!(notify_authority.is_authorized(
        &member_origin,
        1,
        "203.0.113.53".parse().unwrap()
    ));
    assert_eq!(
        rx.recv().await.expect("new member fallback refresh").zone,
        member_origin
    );
}

#[tokio::test]
async fn catalog_snapshot_ignores_existing_catalog_zone_name_clash() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                primaries = ["192.0.2.53:53"]
                notify_sources = ["192.0.2.53"]
                tsig_key = "catalog-key."
            "#,
    )
    .expect("valid catalog config");
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let snapshot = ZoneSnapshot::active(
        catalog_origin.clone(),
        Some(7),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![vec![1, b'2']],
            ),
            Rrset::new(
                DomainName::from_absolute_str("clash.zones.catalog.example.").unwrap(),
                RecordType::Ptr as u16,
                1,
                0,
                vec![catalog_origin.to_wire()],
            ),
        ],
    );
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin.clone());
    zones.insert_snapshot(snapshot.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, mut rx) = mpsc::channel(1);
    let metadata = zone_metadata_for(&snapshot);

    catalog_manager
        .apply_snapshot(
            snapshot.catalog_zone_view(),
            &metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    assert!(transfer_plan.get(&catalog_origin).is_some());
    assert!(rx.try_recv().is_err());
    assert_eq!(catalog_manager.member_metrics(), Vec::new());
    assert!(captured.contains_all(&["catalog_member_name_clash", "zone=catalog.example.",]));
}

#[tokio::test]
async fn catalog_snapshot_enforces_member_zone_cap() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                primaries = ["192.0.2.53:53"]
                notify_sources = ["192.0.2.53"]
                tsig_key = "catalog-key."
                max_member_zones = 1
            "#,
    )
    .expect("valid catalog config");
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let alpha_origin = DomainName::from_absolute_str("alpha.example.").unwrap();
    let beta_origin = DomainName::from_absolute_str("beta.example.").unwrap();
    let snapshot = ZoneSnapshot::active(
        catalog_origin.clone(),
        Some(7),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![vec![1, b'2']],
            ),
            Rrset::new(
                DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                RecordType::Ptr as u16,
                1,
                0,
                vec![alpha_origin.to_wire()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("b.zones.catalog.example.").unwrap(),
                RecordType::Ptr as u16,
                1,
                0,
                vec![beta_origin.to_wire()],
            ),
        ],
    );
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin);
    zones.insert_snapshot(snapshot.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, mut rx) = mpsc::channel(2);
    let metadata = zone_metadata_for(&snapshot);

    catalog_manager
        .apply_snapshot(
            snapshot.catalog_zone_view(),
            &metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    assert!(transfer_plan.get(&alpha_origin).is_some());
    assert!(transfer_plan.get(&beta_origin).is_none());
    assert_eq!(
        rx.recv().await.expect("member refresh request").zone,
        alpha_origin
    );
    assert!(rx.try_recv().is_err());
    assert!(captured.contains_all(&[
        "catalog_member_limit_exceeded",
        "max_member_zones=1",
        "member_count=2",
        "dropped=1",
    ]));
}

#[tokio::test]
async fn catalog_member_cap_counts_only_accepted_members_after_clash_filter() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[zones]]
                name = "alpha.example."
                primaries = ["192.0.2.54:53"]

                [[catalog_zones]]
                name = "catalog.example."
                primaries = ["192.0.2.53:53"]
                tsig_key = "catalog-key."
                max_member_zones = 1
            "#,
    )
    .expect("valid catalog config");
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let alpha_origin = DomainName::from_absolute_str("alpha.example.").unwrap();
    let beta_origin = DomainName::from_absolute_str("beta.example.").unwrap();
    let snapshot = catalog_snapshot_with_members(
        catalog_origin.clone(),
        7,
        &[alpha_origin.clone(), beta_origin.clone()],
    );
    let zones = ZoneStore::new();
    zones.insert_loading_hidden(catalog_origin);
    zones.insert_loading(alpha_origin.clone());
    zones.insert_snapshot(snapshot.clone());
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let catalog_manager = CatalogManager::from_config(&config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
    let (tx, mut rx) = mpsc::channel(2);
    let metadata = zone_metadata_for(&snapshot);

    catalog_manager
        .apply_snapshot(
            snapshot.catalog_zone_view(),
            &metadata,
            &zones,
            &transfer_plan,
            &refresh_registry,
            &notify_authority,
            &tx.downgrade(),
        )
        .await;

    assert!(transfer_plan.get(&beta_origin).is_some());
    assert_eq!(
        rx.recv().await.expect("member refresh request").zone,
        beta_origin
    );
    assert!(rx.try_recv().is_err());
}

#[test]
fn metrics_rate_limiter_is_per_source_and_evicts_idle_sources() {
    let limiter = MetricsRateLimiter::from_config(HealthConfig {
        metrics_rate_limit_per_minute: 1,
        metrics_rate_limit_idle_seconds: 1,
        ..HealthConfig::default()
    });
    let now = std::time::Instant::now();
    let first: std::net::IpAddr = "192.0.2.10".parse().unwrap();
    let second: std::net::IpAddr = "192.0.2.11".parse().unwrap();

    assert_eq!(limiter.check_at(first, now), Ok(()));
    assert_eq!(limiter.check_at(first, now), Err(60));
    assert_eq!(limiter.check_at(second, now), Ok(()));
    assert_eq!(
        limiter.check_at(first, now + std::time::Duration::from_secs(2)),
        Ok(())
    );
}

#[test]
fn metrics_rate_limiter_two_source_rejection_flood_keeps_recency_queue_bounded() {
    let limiter = MetricsRateLimiter::from_config(HealthConfig {
        metrics_rate_limit_per_minute: 1,
        metrics_rate_limit_idle_seconds: 300,
        ..HealthConfig::default()
    });
    let now = std::time::Instant::now();
    let sentinel: std::net::IpAddr = "192.0.2.20".parse().unwrap();
    let flooder: std::net::IpAddr = "192.0.2.21".parse().unwrap();

    assert_eq!(limiter.check_at(sentinel, now), Ok(()));
    assert_eq!(limiter.check_at(flooder, now), Ok(()));
    for _ in 0..50_000 {
        assert_eq!(limiter.check_at(flooder, now), Err(60));
    }

    assert_eq!(limiter.state_sizes_for_test(), (2, 2));
}

#[test]
fn notify_authority_allows_primaries_and_notify_sources() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                notify_sources = ["198.51.100.53"]
            "#,
    )
    .expect("valid config");
    let authority = NotifyAuthority::from_config_for_test(&config);
    let zone = DomainName::from_absolute_str("example.test.").unwrap();

    assert!(authority.is_authorized(&zone, 1, "192.0.2.53".parse().unwrap()));
    assert!(authority.is_authorized(&zone, 1, "198.51.100.53".parse().unwrap()));
    assert!(!authority.is_authorized(&zone, 1, "203.0.113.53".parse().unwrap()));
    assert!(!authority.is_authorized(&zone, 255, "192.0.2.53".parse().unwrap()));
}

#[test]
fn catalog_notify_policy_applies_notify_only_override_and_clears_stale_tsig() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "override-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                catalog_tsig_key = "override-key."
                member_primaries = ["10.0.0.53:53"]

                [catalog_zones.member_transfer_policy]
                unsigned_axfr = "allow-legacy-private"
            "#,
    )
    .expect("valid catalog config");
    let authority = NotifyAuthority::from_config_for_test(&config);
    let catalog = &config.catalog_zones[0];
    let member = DomainName::from_absolute_str("member.example.").unwrap();
    let override_key = DomainName::from_absolute_str("override-key.").unwrap();

    authority.add_zone_from_catalog(
        &member,
        catalog,
        Some(&borondns_core::catalog::CatalogMemberTransfer {
            primaries: Vec::new(),
            tsig_key_name: Some(override_key),
            xfr: None,
            notify_sources: vec!["203.0.113.54".parse().unwrap()],
        }),
    );
    assert!(authority.is_authorized(&member, 1, "10.0.0.53".parse().unwrap()));
    assert!(authority.is_authorized(&member, 1, "203.0.113.54".parse().unwrap()));
    assert!(authority.tsig_key_for_notify(&member, 1).is_some());

    authority.add_zone_from_catalog(
        &member,
        catalog,
        Some(&borondns_core::catalog::CatalogMemberTransfer {
            primaries: Vec::new(),
            tsig_key_name: None,
            xfr: None,
            notify_sources: vec!["203.0.113.55".parse().unwrap()],
        }),
    );
    assert!(!authority.is_authorized(&member, 1, "203.0.113.54".parse().unwrap()));
    assert!(authority.is_authorized(&member, 1, "203.0.113.55".parse().unwrap()));
    assert!(authority.tsig_key_for_notify(&member, 1).is_none());
}

#[test]
fn explicit_transfer_primaries_feed_notify_authority_and_transfer_plan() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                notify_sources = ["198.51.100.53"]

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/borondns/ca.pem"]
            "#,
    )
    .expect("valid config");
    let zone = DomainName::from_absolute_str("example.test.").unwrap();

    let authority = NotifyAuthority::from_config_for_test(&config);
    assert!(authority.is_authorized(&zone, 1, "192.0.2.53".parse().unwrap()));
    assert!(authority.is_authorized(&zone, 1, "198.51.100.53".parse().unwrap()));

    let plan = TransferPlan::from_config(&config)
        .expect("transfer plan")
        .get(&zone)
        .expect("transfer plan");
    assert_eq!(plan.primaries.len(), 1);
    assert_eq!(plan.primaries[0].transport, TransferTransportConfig::Xot);
    assert_eq!(
        plan.primaries[0].server_name.as_deref(),
        Some("primary.example.test")
    );
}

#[test]
fn tsig_secret_file_feeds_notify_authority_and_transfer_plan() {
    let secret_file = unique_test_path("borondns-server-tsig-secret", "key");
    std::fs::write(&secret_file, b"dG9wc2VjcmV0\n").expect("write TSIG secret file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600))
            .expect("secure TSIG secret file mode");
    }
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret_file = "{}"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        secret_file.display()
    ))
    .expect("valid TSIG secret_file config");
    let zone = DomainName::from_absolute_str("example.test.").unwrap();
    let key_name = DomainName::from_absolute_str("transfer-key.").unwrap();

    let authority = NotifyAuthority::from_config_for_test(&config);
    assert!(authority.tsig_key_by_name(&key_name).is_some());
    assert!(authority.tsig_key_for_notify(&zone, 1).is_some());

    let plan = TransferPlan::from_config(&config)
        .expect("transfer plan")
        .get(&zone)
        .expect("zone transfer plan");
    assert!(plan.tsig_key_name.is_some());
    let _ = std::fs::remove_file(secret_file);
}

#[test]
fn transfer_plan_rotates_multi_primary_start_once_per_process() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = [
                    "192.0.2.53:53",
                    "192.0.2.54:53",
                    "192.0.2.55:53",
                ]
            "#,
    )
    .expect("valid config");
    let zone = DomainName::from_absolute_str("example.test.").unwrap();

    let plan = TransferPlan::from_config_with_primary_start(&config, |_| Ok(1))
        .expect("transfer plan")
        .get(&zone)
        .expect("zone transfer plan");

    assert_eq!(
        plan.primaries
            .iter()
            .map(|primary| primary.addr)
            .collect::<Vec<_>>(),
        vec![
            "192.0.2.54:53".parse().unwrap(),
            "192.0.2.55:53".parse().unwrap(),
            "192.0.2.53:53".parse().unwrap(),
        ]
    );

    let retained = plan.clone();
    assert_eq!(plan.primaries, retained.primaries);
}

#[test]
fn transfer_target_rotation_wraps_without_reordering_members() {
    let primaries = vec![
        TransferPrimaryConfig::tcp("192.0.2.53:53".parse().unwrap()),
        TransferPrimaryConfig::tcp("192.0.2.54:53".parse().unwrap()),
        TransferPrimaryConfig::tcp("192.0.2.55:53".parse().unwrap()),
    ];

    let rotated = rotate_transfer_targets(primaries, 5);

    assert_eq!(
        rotated
            .iter()
            .map(|primary| primary.addr)
            .collect::<Vec<_>>(),
        vec![
            "192.0.2.55:53".parse().unwrap(),
            "192.0.2.53:53".parse().unwrap(),
            "192.0.2.54:53".parse().unwrap(),
        ]
    );
}

#[test]
fn primary_start_index_uses_rejection_sampling_boundary() {
    assert_eq!(uniform_index_from_u64(0, 3), Some(0));
    assert_eq!(uniform_index_from_u64(1, 3), Some(1));
    assert_eq!(uniform_index_from_u64(2, 3), Some(2));
    assert_eq!(uniform_index_from_u64(u64::MAX - 1, 3), Some(2));
    assert_eq!(uniform_index_from_u64(u64::MAX, 3), None);
}

#[test]
fn notify_authority_rejects_unsigned_request_without_signing_the_response() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [tsig]
                fudge_seconds = 30

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
    )
    .expect("valid config");
    let authority = NotifyAuthority::from_config_for_test(&config);
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);

    let prepared = prepare_notify_packet(&packet, &authority, "192.0.2.53".parse().unwrap());

    let response = prepared
        .expect("NOTAUTH response")
        .immediate_response
        .expect("immediate NOTAUTH response");
    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    assert_eq!(u16::from_be_bytes([response[10], response[11]]), 0);
}

#[test]
fn ordinary_query_with_unknown_tsig_key_gets_badkey_response() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "known-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "known-key."
            "#,
    )
    .expect("valid config");
    let authority = NotifyAuthority::from_config_for_test(&config);
    let unknown_key = TsigKey::from_base64("unknown-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
    let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let signed = unknown_key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .unwrap();

    let prepared = prepare_query_tsig_packet(
        PreparedDnsMessage {
            packet: signed.message,
            response_tsig: None,
            immediate_response: None,
            tsig_authenticated: false,
            notify_policy_token: None,
        },
        &authority,
    );

    let response = prepared
        .immediate_response
        .expect("immediate BADKEY response");
    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
    assert_ne!(header.flags & 0x0100, 0, "BADKEY response must copy RD");
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, 0);
    assert_eq!(tsig.original_id, 0x1234);
    assert_eq!(tsig.error, TSIG_ERROR_BADKEY);
    assert!(tsig.other_data.is_empty());
    assert!(!prepared.tsig_authenticated);
}

#[test]
fn ordinary_query_with_bad_tsig_mac_gets_badsig_response() {
    let (authority, key) = tsig_notify_authority();
    let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let signed = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .unwrap();
    let bad = replace_final_tsig_mac(&signed.message, &[0xaa; 32]);

    let prepared = prepare_query_tsig_packet(
        PreparedDnsMessage {
            packet: bad,
            response_tsig: None,
            immediate_response: None,
            tsig_authenticated: false,
            notify_policy_token: None,
        },
        &authority,
    );

    let response = prepared.immediate_response.expect("TSIG error response");
    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    assert_ne!(
        u16::from_be_bytes([response[2], response[3]]) & 0x0100,
        0,
        "BADSIG response must copy RD"
    );
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.error, TSIG_ERROR_BADSIG);
}

#[test]
fn ordinary_query_with_too_short_tsig_mac_gets_formerr_without_tsig() {
    let (authority, key) = tsig_notify_authority();
    let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let signed = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .unwrap();
    let too_short_mac = &signed.mac[..key.algorithm.min_mac_len() - 1];
    let bad = replace_final_tsig_mac(&signed.message, too_short_mac);

    let prepared = prepare_query_tsig_packet(
        PreparedDnsMessage {
            packet: bad,
            response_tsig: None,
            immediate_response: None,
            tsig_authenticated: false,
            notify_policy_token: None,
        },
        &authority,
    );

    let response = prepared.immediate_response.expect("FORMERR response");
    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::FormErr as u16);
    assert_ne!(header.flags & 0x0100, 0, "FORMERR response must copy RD");
    assert_eq!(header.arcount, 0, "FORMERR must not include a TSIG RR");
}

#[test]
fn ordinary_query_with_overlong_tsig_mac_gets_formerr_without_tsig() {
    let (authority, key) = tsig_notify_authority();
    let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let signed = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .unwrap();
    let mut overlong_mac = signed.mac.clone();
    overlong_mac.push(0);
    let malformed = replace_final_tsig_mac(&signed.message, &overlong_mac);

    let prepared = prepare_query_tsig_packet(
        PreparedDnsMessage {
            packet: malformed,
            response_tsig: None,
            immediate_response: None,
            tsig_authenticated: false,
            notify_policy_token: None,
        },
        &authority,
    );

    let response = prepared.immediate_response.expect("FORMERR response");
    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::FormErr as u16);
    assert_eq!(header.arcount, 0, "FORMERR must not include a TSIG RR");
}

#[test]
fn ordinary_query_with_nonzero_request_tsig_error_gets_formerr_without_tsig() {
    let (authority, key) = tsig_notify_authority();
    let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let signed = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .unwrap();
    let malformed = replace_final_tsig_error(&signed.message, TSIG_ERROR_BADTIME);

    let prepared = prepare_query_tsig_packet(
        PreparedDnsMessage {
            packet: malformed,
            response_tsig: None,
            immediate_response: None,
            tsig_authenticated: false,
            notify_policy_token: None,
        },
        &authority,
    );

    let response = prepared.immediate_response.expect("FORMERR response");
    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::FormErr as u16);
    assert_eq!(header.arcount, 0, "FORMERR must not include a TSIG RR");
}

#[test]
fn ordinary_query_with_hmac_md5_tsig_gets_unsigned_badkey_response() {
    let (authority, key) = tsig_notify_authority();
    let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let signed = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .unwrap();
    let bad = replace_final_tsig_algorithm(&signed.message, "hmac-md5.sig-alg.reg.int.");

    let prepared = prepare_query_tsig_packet(
        PreparedDnsMessage {
            packet: bad,
            response_tsig: None,
            immediate_response: None,
            tsig_authenticated: false,
            notify_policy_token: None,
        },
        &authority,
    );

    let response = prepared.immediate_response.expect("TSIG error response");
    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, 0);
    assert_eq!(tsig.error, TSIG_ERROR_BADKEY);
    assert_eq!(tsig.algorithm, "hmac-md5.sig-alg.reg.int.");
    assert!(tsig.other_data.is_empty());
}

#[test]
fn ordinary_query_outside_tsig_fudge_gets_signed_badtime_echoing_request_time_and_fudge() {
    let (authority, key) = tsig_notify_authority();
    let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let request_fudge = 17;
    let signed = key.sign_request(&packet, 1, request_fudge).unwrap();
    let request_mac = signed.mac.clone();

    let prepared = prepare_query_tsig_packet(
        PreparedDnsMessage {
            packet: signed.message,
            response_tsig: None,
            immediate_response: None,
            tsig_authenticated: false,
            notify_policy_token: None,
        },
        &authority,
    );

    let response = prepared.immediate_response.expect("TSIG error response");
    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, key.algorithm.mac_len());
    assert_eq!(tsig.error, TSIG_ERROR_BADTIME);
    assert_eq!(tsig.time_signed, 1);
    assert_eq!(tsig.fudge, request_fudge);
    assert_eq!(tsig.other_data.len(), 6);
    assert_eq!(
        key.verify_response(&response, &request_mac, current_unix_time())
            .expect_err("authenticated BADTIME response"),
        TsigError::ResponseError(TSIG_ERROR_BADTIME)
    );
}
