#[test]
fn zsm_jitter_stays_within_ten_percent_bounds() {
    let interval = std::time::Duration::from_secs(100);

    assert_eq!(
        jitter_interval(interval, 0),
        std::time::Duration::from_secs(90)
    );
    assert_eq!(
        jitter_interval(interval, 10_000),
        std::time::Duration::from_secs(100)
    );
    assert_eq!(
        jitter_interval(interval, 20_000),
        std::time::Duration::from_secs(110)
    );
}

#[test]
fn refresh_registry_schedules_refresh_and_retry() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(10),
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        )],
    );

    registry.record_success_at(&zone_metadata_for(&snapshot), now);
    assert!(
        registry
            .start_due_refreshes(now + std::time::Duration::from_secs(3599))
            .is_empty()
    );
    assert_eq!(
        registry.start_due_refreshes(now + std::time::Duration::from_secs(3600)),
        vec![origin.clone()]
    );
    assert!(
        registry
            .start_due_refreshes(now + std::time::Duration::from_secs(3601))
            .is_empty()
    );

    registry.record_failure_at(
        &origin,
        Some(zone_metadata_for(&snapshot)),
        now + std::time::Duration::from_secs(3600),
    );
    assert!(
        registry
            .start_due_refreshes(now + std::time::Duration::from_secs(4199))
            .is_empty()
    );
    assert_eq!(
        registry.start_due_refreshes(now + std::time::Duration::from_secs(4200)),
        vec![origin]
    );
}

#[test]
fn refresh_registry_snapshots_scheduler_metrics() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(180),
    );
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        )],
    );

    registry.record_success_at_with_timestamp(&zone_metadata_for(&snapshot), now, 1_700_000_000);
    let status = registry
        .snapshots_by_zone()
        .remove(&origin.canonical_key())
        .expect("zone refresh status");
    assert_eq!(status.last_success_unix_secs, Some(1_700_000_000));
    assert_eq!(status.next_refresh_unix_secs, Some(1_700_003_600));
    assert_eq!(status.failures_since_success, 0);

    registry.record_failure_at_with_timestamp(
        &origin,
        Some(zone_metadata_for(&snapshot)),
        now + std::time::Duration::from_secs(3600),
        1_700_003_600,
    );
    let status = registry
        .snapshots_by_zone()
        .remove(&origin.canonical_key())
        .expect("zone refresh status");
    assert_eq!(status.last_success_unix_secs, Some(1_700_000_000));
    assert_eq!(status.next_refresh_unix_secs, Some(1_700_004_200));
    assert_eq!(status.failures_since_success, 1);

    registry.record_success_at_with_timestamp(
        &zone_metadata_for(&snapshot),
        now + std::time::Duration::from_secs(4200),
        1_700_004_200,
    );
    let status = registry
        .snapshots_by_zone()
        .remove(&origin.canonical_key())
        .expect("zone refresh status");
    assert_eq!(status.last_success_unix_secs, Some(1_700_004_200));
    assert_eq!(status.next_refresh_unix_secs, Some(1_700_007_800));
    assert_eq!(status.failures_since_success, 0);
}

#[test]
fn refresh_registry_clamps_soa_intervals_to_configured_bounds() {
    let registry = ZoneRefreshRegistry::without_jitter_with_max(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(1_000),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(180),
        std::time::Duration::from_secs(3600),
    );
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let mut snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        )],
    );
    snapshot.soa_timers = Some(SoaTimers {
        refresh: 10_000,
        retry: 10_000,
        expire: 86_400,
        minimum: 300,
    });

    registry.record_success_at_with_timestamp(&zone_metadata_for(&snapshot), now, 1_700_000_000);
    let status = registry
        .snapshots_by_zone()
        .remove(&origin.canonical_key())
        .expect("zone refresh status");
    assert_eq!(status.next_refresh_unix_secs, Some(1_700_001_000));

    registry.record_failure_at_with_timestamp(
        &origin,
        Some(zone_metadata_for(&snapshot)),
        now + std::time::Duration::from_secs(1_000),
        1_700_001_000,
    );
    let status = registry
        .snapshots_by_zone()
        .remove(&origin.canonical_key())
        .expect("zone refresh status");
    assert_eq!(status.next_refresh_unix_secs, Some(1_700_002_000));
    assert_eq!(status.failures_since_success, 1);
}

#[test]
fn refresh_registry_warns_when_soa_timers_approach_maximum_effective_interval() {
    let registry = ZoneRefreshRegistry::without_jitter_with_max(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(1_000),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(180),
        std::time::Duration::from_secs(3600),
    );
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let mut snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin,
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        )],
    );
    snapshot.soa_timers = Some(SoaTimers {
        refresh: 900,
        retry: 1_500,
        expire: 86_400,
        minimum: 300,
    });
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    registry.record_success_at_with_timestamp(&zone_metadata_for(&snapshot), now, 1_700_000_000);

    assert!(captured.contains_all(&[
        "SOA timer approaches configured maximum effective ZSM interval",
        "category=\"configuration_warning\"",
        "code=\"soa_timer_near_max_effective_interval\"",
        "zone=example.test.",
        "soa_field=\"refresh\"",
        "soa_value_secs=900",
        "max_effective_secs=1000",
        "threshold_percent=90",
    ]));
    assert!(captured.contains_all(&[
        "SOA timer approaches configured maximum effective ZSM interval",
        "category=\"configuration_warning\"",
        "code=\"soa_timer_near_max_effective_interval\"",
        "zone=example.test.",
        "soa_field=\"retry\"",
        "soa_value_secs=1500",
        "max_effective_secs=1000",
        "threshold_percent=90",
    ]));
}

#[test]
fn refresh_registry_emits_repeated_long_loading_warnings() {
    let registry = ZoneRefreshRegistry::without_jitter_with_max(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(86_400),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(300),
    );
    let zones = ZoneStore::new();
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("loading.test.").unwrap();
    zones.insert_loading(origin.clone());

    registry.record_loading_start_at(&origin, now);
    assert!(
        registry
            .loading_warnings_due(&zones, now + std::time::Duration::from_secs(299))
            .is_empty()
    );

    registry.record_failure_at_with_timestamp_and_cause(
        &origin,
        None,
        Some("AXFR failed for primary 192.0.2.53:53: timeout".to_owned()),
        now + std::time::Duration::from_secs(60),
        1_700_000_000,
    );
    let warnings = registry.loading_warnings_due(&zones, now + std::time::Duration::from_secs(300));
    assert_eq!(
        warnings,
        vec![LoadingWarning {
            zone: origin.clone(),
            elapsed_loading_secs: 300,
            last_failure_cause: "AXFR failed for primary 192.0.2.53:53: timeout".to_owned(),
            next_retry_unix_secs: Some(1_700_000_060),
        }]
    );
    assert!(
        registry
            .loading_warnings_due(&zones, now + std::time::Duration::from_secs(300))
            .is_empty()
    );

    let warnings = registry.loading_warnings_due(&zones, now + std::time::Duration::from_secs(600));
    assert_eq!(
        warnings,
        vec![LoadingWarning {
            zone: origin,
            elapsed_loading_secs: 600,
            last_failure_cause: "AXFR failed for primary 192.0.2.53:53: timeout".to_owned(),
            next_retry_unix_secs: Some(1_700_000_060),
        }]
    );
}

#[test]
fn refresh_registry_does_not_warn_for_active_refresh_failures() {
    let registry = ZoneRefreshRegistry::without_jitter_with_max(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(86_400),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(300),
    );
    let zones = ZoneStore::new();
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("active.test.").unwrap();
    let snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        )],
    );
    zones.insert_snapshot(snapshot.clone());

    registry.record_success_at(&zone_metadata_for(&snapshot), now);
    registry.record_failure_at_with_timestamp_and_cause(
        &origin,
        Some(zone_metadata_for(&snapshot)),
        Some("AXFR failed for primary 192.0.2.53:53: timeout".to_owned()),
        now + std::time::Duration::from_secs(60),
        1_700_000_000,
    );

    assert!(
        registry
            .loading_warnings_due(&zones, now + std::time::Duration::from_secs(3600))
            .is_empty()
    );
}

#[test]
fn long_loading_warning_log_contains_operator_fields() {
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    log_loading_warning(LoadingWarning {
        zone: DomainName::from_absolute_str("example.test.").unwrap(),
        elapsed_loading_secs: 3600,
        last_failure_cause: "AXFR failed for primary 192.0.2.53:53: timed out".to_owned(),
        next_retry_unix_secs: Some(1_700_003_600),
    });

    assert!(
        captured.contains_all(&[
            "zone remains in LOADING state beyond configured threshold",
            "category=\"transfer\"",
            "event=\"zone_loading_threshold_exceeded\"",
            "zone=example.test.",
            "elapsed_loading_secs=3600",
            "error=AXFR failed for primary 192.0.2.53:53: timed out",
            "next_retry_unix_secs=Some(1700003600)",
        ]),
        "{:?}",
        captured
            .lines
            .lock()
            .expect("captured events lock poisoned")
    );
}

#[test]
fn refresh_registry_applies_initial_load_exponential_backoff() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(180),
    );
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();

    registry.record_failure_at(&origin, None, now);
    assert!(
        registry
            .start_due_refreshes(now + std::time::Duration::from_secs(59))
            .is_empty()
    );
    assert_eq!(
        registry.start_due_refreshes(now + std::time::Duration::from_secs(60)),
        vec![origin.clone()]
    );

    registry.record_failure_at(&origin, None, now + std::time::Duration::from_secs(60));
    assert!(
        registry
            .start_due_refreshes(now + std::time::Duration::from_secs(179))
            .is_empty()
    );
    assert_eq!(
        registry.start_due_refreshes(now + std::time::Duration::from_secs(180)),
        vec![origin.clone()]
    );

    registry.record_failure_at(&origin, None, now + std::time::Duration::from_secs(180));
    assert!(
        registry
            .start_due_refreshes(now + std::time::Duration::from_secs(359))
            .is_empty()
    );
    assert_eq!(
        registry.start_due_refreshes(now + std::time::Duration::from_secs(360)),
        vec![origin]
    );
}

#[test]
fn refresh_registry_expires_zone_once() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        )],
    );

    registry.record_success_at(&zone_metadata_for(&snapshot), now);
    assert!(
        registry
            .expire_due_zones(now + std::time::Duration::from_secs(604799))
            .is_empty()
    );
    assert_eq!(
        registry.expire_due_zones(now + std::time::Duration::from_secs(604800)),
        vec![origin]
    );
    assert!(
        registry
            .expire_due_zones(now + std::time::Duration::from_secs(604801))
            .is_empty()
    );
}

#[test]
fn ixfr_cooldown_registry_disables_until_cooldown_expires() {
    let registry = IxfrCooldownRegistry::new(std::time::Duration::from_secs(60));
    let zone = DomainName::from_absolute_str("example.test.").unwrap();
    let primary = "192.0.2.53:53".parse().unwrap();
    let now = std::time::Instant::now();

    assert!(!registry.is_disabled_at(&zone, primary, now));
    registry.record_unsupported_at(&zone, primary, now);
    assert!(registry.is_disabled_at(&zone, primary, now + std::time::Duration::from_secs(59)));
    assert!(!registry.is_disabled_at(&zone, primary, now + std::time::Duration::from_secs(60)));
}

#[tokio::test]
async fn notify_refresh_worker_publishes_requested_refresh() {
    let primary = spawn_ixfr_mode2_primary_with_serial(2).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let zones = ZoneStore::new();
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(
        apex.clone(),
        Some(1),
        vec![Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(1)],
        )],
    ));
    let (tx, rx) = mpsc::channel(1);
    tx.send(RefreshRequest {
        zone: apex,
        requested_serial: Some(2),
        reason: super::RefreshReason::Notify,
    })
    .await
    .unwrap();
    drop(tx);
    let metrics = RuntimeMetrics::new();

    serve_refresh_requests(
        rx,
        zones.clone(),
        CatalogRuntime {
            manager: CatalogManager::from_config(&config),
            transfer_plan,
            refresh_registry: ZoneRefreshRegistry::without_jitter(
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
            ),
            notify_authority: NotifyAuthority::from_config_for_test(&config),
            refresh_tx: mpsc::channel(1).0.downgrade(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
        },
        IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
        metrics.clone(),
        RefreshWorkerSettings {
            axfr_timeout: std::time::Duration::from_secs(5),
            ixfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            transfer_limit: Arc::new(tokio::sync::Semaphore::new(4)),
            telemetry: ControlPlaneTelemetryReporter::disabled(),
        },
    )
    .await
    .unwrap();

    let snapshot = zones
        .exact_snapshot_for_transfer(&DomainName::from_absolute_str("example.test.").unwrap())
        .expect("published refreshed snapshot");
    assert_eq!(snapshot.metadata().state, ZoneState::Active);
    assert_eq!(snapshot.metadata().serial, Some(2));
    assert_eq!(
        metrics.snapshot(),
        super::RuntimeMetricsSnapshot {
            queries_received: 0,
            queries_truncated: 0,
            queries_cname_chain_limit: 0,
            queries_cname_loop: 0,
            axfr_started: 0,
            axfr_succeeded: 0,
            axfr_failed: 0,
            ixfr_started: 1,
            ixfr_succeeded: 1,
            ixfr_failed: 0,
            ..Default::default()
        }
    );
}

#[tokio::test]
async fn notify_refresh_worker_honors_transfer_concurrency_limit() {
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let alpha_primary = spawn_barrier_ixfr_mode2_primary("alpha.test.", barrier.clone()).await;
    let beta_primary = spawn_barrier_ixfr_mode2_primary("beta.test.", barrier.clone()).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [limits]
                max_concurrent_transfers = 2

                [[zones]]
                name = "alpha.test."
                primaries = ["{alpha_primary}"]

                [[zones]]
                name = "beta.test."
                primaries = ["{beta_primary}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let zones = ZoneStore::new();
    for zone in ["alpha.test.", "beta.test."] {
        let apex = DomainName::from_absolute_str(zone).unwrap();
        zones.insert_snapshot(ZoneSnapshot::active(
            apex.clone(),
            Some(1),
            vec![Rrset::new(
                apex.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata_with_serial(1)],
            )],
        ));
    }
    let (tx, rx) = mpsc::channel(2);
    for zone in ["alpha.test.", "beta.test."] {
        tx.send(RefreshRequest {
            zone: DomainName::from_absolute_str(zone).unwrap(),
            requested_serial: Some(2),
            reason: super::RefreshReason::Notify,
        })
        .await
        .unwrap();
    }
    drop(tx);

    let worker = tokio::spawn(serve_refresh_requests(
        rx,
        zones.clone(),
        CatalogRuntime {
            manager: CatalogManager::from_config(&config),
            transfer_plan,
            refresh_registry: ZoneRefreshRegistry::without_jitter(
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
            ),
            notify_authority: NotifyAuthority::from_config_for_test(&config),
            refresh_tx: mpsc::channel(1).0.downgrade(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
        },
        IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
        RuntimeMetrics::new(),
        RefreshWorkerSettings {
            axfr_timeout: std::time::Duration::from_secs(5),
            ixfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            transfer_limit: Arc::new(tokio::sync::Semaphore::new(2)),
            telemetry: ControlPlaneTelemetryReporter::disabled(),
        },
    ));

    tokio::time::timeout(std::time::Duration::from_secs(1), barrier.wait())
        .await
        .expect("both refresh transfers should start before either completes");
    worker.await.unwrap().unwrap();

    assert_eq!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("alpha.test.").unwrap())
            .expect("alpha zone")
            .metadata()
            .serial,
        Some(2)
    );
    assert_eq!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("beta.test.").unwrap())
            .expect("beta zone")
            .metadata()
            .serial,
        Some(2)
    );
}

#[tokio::test]
async fn refresh_skips_axfr_when_soa_poll_confirms_current_serial() {
    let (primary, peer_rx) = spawn_soa_primary_recording_peer(2).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [interfaces]
                transfer = ["127.0.0.2:0"]

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let plan = transfer_plan
        .get(&DomainName::from_absolute_str("example.test.").unwrap())
        .expect("zone transfer plan");
    let zones = ZoneStore::new();
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(
        apex.clone(),
        Some(2),
        vec![Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(2)],
        )],
    ));
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
        },
    )
    .await
    .expect("refresh success");
    let peer = tokio::time::timeout(std::time::Duration::from_secs(1), peer_rx)
        .await
        .expect("primary should observe SOA poll peer")
        .expect("SOA primary should send peer address");
    let expected_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    assert_eq!(metadata.serial, Some(2));
    assert_eq!(peer.ip(), expected_ip);
    assert!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("example.test.").unwrap())
            .expect("unchanged zone snapshot")
            .snapshot_for_transfer()
            .offline_oracle()
            .lookup(
                &DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            )
            .answers
            .is_empty()
    );
}

#[tokio::test]
async fn refresh_signs_axfr_query_when_zone_has_tsig_key() {
    let (primary, observed_query) = spawn_axfr_primary_recording_query(1).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [tsig]
                fudge_seconds = 30

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
                tsig_key = "transfer-key."
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    assert!(plan.tsig_key_name.is_some());
    assert_eq!(plan.tsig_fudge_seconds, 30);
    let zones = ZoneStore::new();
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
        },
    )
    .await
    .expect("refresh success");

    assert_eq!(metadata.serial, Some(1));
    let query = observed_query
        .lock()
        .expect("observed query lock poisoned")
        .clone()
        .expect("primary observed query");
    assert_eq!(query_qtype(&query), RecordType::Axfr as u16);
    assert_query_has_tsig(&query, "transfer-key.", "hmac-sha256.");
    assert_eq!(query_tsig_fudge(&query), 30);
}

#[tokio::test]
async fn refresh_xot_transfer_also_uses_tsig_when_configured() {
    let (primary, trust_anchor, observed_query) = spawn_xot_axfr_primary_recording_query(1).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[zones]]
                name = "example.test."
                tsig_key = "transfer-key."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    assert!(plan.tsig_key_name.is_some());
    assert_eq!(plan.primaries[0].transport, TransferTransportConfig::Xot);
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
        },
    )
    .await
    .expect("refresh success");

    assert_eq!(metadata.serial, Some(1));
    let query = observed_query
        .lock()
        .expect("observed query lock poisoned")
        .clone()
        .expect("primary observed query");
    assert_eq!(query_qtype(&query), RecordType::Axfr as u16);
    assert_query_has_tsig(&query, "transfer-key.", "hmac-sha256.");
}

#[test]
fn xot_transfer_logs_tls_session_establishment_and_close() {
    std::thread::spawn(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(async {
                let (primary, trust_anchor) = spawn_xot_axfr_primary_with_serial(1).await;
                let target = TransferPrimaryConfig {
                    addr: primary,
                    transport: TransferTransportConfig::Xot,
                    server_name: Some("primary.example.test".to_owned()),
                    xot_profile: None,
                    trust_anchors: vec![trust_anchor],
                    client_cert: None,
                    client_key: None,
                    client_key_pem: None,
                };
                let apex = DomainName::from_absolute_str("example.test.").unwrap();
                let captured = CapturedEvents::new();
                let subscriber = CapturingSubscriber::new(captured.clone());
                let _guard = tracing::subscriber::set_default(subscriber);

                let snapshot = super::transfer_axfr_from_target_with_tsig(
                    &target,
                    &apex,
                    1,
                    0x1234,
                    TransferSession::default_unsigned(),
                    std::time::Duration::from_secs(5),
                )
                .await
                .expect("XoT AXFR should succeed");

                assert_eq!(snapshot.serial, Some(1));
                assert!(captured.contains_all(&[
                    "XoT TLS session established",
                    "category=\"xot\"",
                    "event=\"xot_tls_session_established\"",
                    &format!("primary={primary}"),
                    "peer_ip=127.0.0.1",
                    "sni=primary.example.test",
                    "tls_version=TLSv1_",
                    "cipher_suite=TLS",
                ]));
                assert!(captured.contains_all(&[
                    "XoT TLS session closed",
                    "category=\"xot\"",
                    "event=\"xot_tls_session_closed\"",
                    &format!("primary={primary}"),
                    "peer_ip=127.0.0.1",
                    "sni=primary.example.test",
                    "duration_ms=",
                    "bytes=",
                    "bytes_in=",
                    "bytes_out=",
                ]));
            });
    })
    .join()
    .expect("XoT logging test thread");
}

#[tokio::test]
async fn refresh_xot_handshake_failure_does_not_retry_cleartext() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let primary = listener.local_addr().unwrap();
    let (accepted_tx, mut accepted_rx) = mpsc::channel(2);
    let accept_task = tokio::spawn(async move {
        for _ in 0..2 {
            if listener.accept().await.is_ok() {
                let _ = accepted_tx.send(()).await;
            }
        }
    });
    let (trust_anchor, _key_path) = write_self_signed_xot_cert_files();
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
        trust_anchor.display()
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(50),
            axfr_timeout: std::time::Duration::from_millis(50),
            tcp_connect_timeout: std::time::Duration::from_millis(50),
            reason: "test",
        },
    )
    .await;

    assert!(refresh_result.is_none());
    accepted_rx
        .recv()
        .await
        .expect("XoT should attempt one TLS connection");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), accepted_rx.recv())
            .await
            .is_err(),
        "XoT failure must not be retried as cleartext TCP"
    );
    accept_task.abort();
}

#[tokio::test]
async fn refresh_xot_rejects_certificate_name_mismatch_before_query() {
    let (primary, trust_anchor, mut query_seen) =
        spawn_xot_primary_detecting_query("other.example.test", true).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
        },
    )
    .await;

    assert!(refresh_result.is_none());
    let query_result =
        tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
    assert!(
        !matches!(query_result, Ok(Some(()))),
        "certificate name mismatch must abort before sending a DNS transfer query"
    );
    assert_eq!(metrics.snapshot().axfr_failed, 1);
}

#[tokio::test]
async fn refresh_xot_rejects_missing_dot_alpn_before_query() {
    let (primary, trust_anchor, mut query_seen) =
        spawn_xot_primary_detecting_query("primary.example.test", false).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
        },
    )
    .await;

    assert!(refresh_result.is_none());
    let query_result =
        tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
    assert!(
        !matches!(query_result, Ok(Some(()))),
        "missing ALPN dot must abort before sending a DNS transfer query"
    );
    assert_eq!(metrics.snapshot().axfr_failed, 1);
    assert!(captured.contains_all(&[
        "XoT ALPN negotiation failed",
        "category=\"xot\"",
        "event=\"xot_alpn_negotiation_failed\"",
        &format!("primary={primary}"),
        "peer_ip=127.0.0.1",
        "sni=primary.example.test",
        "error=\"missing negotiated dot ALPN\"",
    ]));
}

#[tokio::test]
async fn refresh_xot_rejects_tls12_only_primary_before_query() {
    let (primary, trust_anchor, mut query_seen) = spawn_xot_tls12_primary_detecting_query().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
        },
    )
    .await;

    assert!(refresh_result.is_none());
    let query_result =
        tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
    assert!(
        !matches!(query_result, Ok(Some(()))),
        "TLS 1.2-only XoT primaries must fail the formal profile before AXFR is sent"
    );
    assert_eq!(metrics.snapshot().axfr_failed, 1);
}

#[tokio::test]
async fn refresh_xot_rejects_untrusted_certificate_before_query() {
    let (cert_path, key_path) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    let (untrusted_anchor, _untrusted_key) =
        write_self_signed_xot_cert_files_for_name("untrusted.example.test");
    let (primary, mut query_seen) =
        spawn_xot_primary_detecting_query_with_cert_files(&cert_path, &key_path, true).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
        untrusted_anchor.display()
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
        },
    )
    .await;

    assert!(refresh_result.is_none());
    let query_result =
        tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
    assert!(
        !matches!(query_result, Ok(Some(()))),
        "untrusted XoT certificate must abort before sending a DNS transfer query"
    );
    assert_eq!(metrics.snapshot().axfr_failed, 1);
}

#[tokio::test]
async fn refresh_xot_rejects_expired_certificate_before_query() {
    let (cert_path, key_path) =
        write_expired_self_signed_xot_cert_files_for_name("primary.example.test");
    let (primary, mut query_seen) =
        spawn_xot_primary_detecting_query_with_cert_files(&cert_path, &key_path, true).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
        cert_path.display()
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
        },
    )
    .await;

    assert!(refresh_result.is_none());
    let query_result =
        tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
    assert!(
        !matches!(query_result, Ok(Some(()))),
        "expired XoT certificate must abort before sending a DNS transfer query"
    );
    assert_eq!(metrics.snapshot().axfr_failed, 1);
}

#[tokio::test]
async fn refresh_xot_uses_configured_client_certificate() {
    let (client_cert, client_key) =
        write_self_signed_xot_cert_files_for_name("oxidedns-client.example.test");
    let (primary, trust_anchor, mut query_seen) =
        spawn_xot_mtls_axfr_primary_with_serial(1, &client_cert).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
                client_cert = "{}"
                client_key = "{}"
            "#,
        client_cert.display(),
        client_key.display()
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
        },
    )
    .await
    .expect("mTLS XoT AXFR should publish a snapshot");

    assert_eq!(metadata.serial, Some(1));
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), query_seen.recv()).await,
        Ok(Some(()))
    );
    assert_eq!(metrics.snapshot().axfr_succeeded, 1);
}

#[tokio::test]
async fn refresh_xot_rejects_missing_client_certificate_before_query() {
    let (client_cert, _client_key) =
        write_self_signed_xot_cert_files_for_name("oxidedns-client.example.test");
    let (primary, trust_anchor, mut query_seen) =
        spawn_xot_mtls_axfr_primary_with_serial(1, &client_cert).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
        },
    )
    .await;

    assert!(refresh_result.is_none());
    let query_result =
        tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
    assert!(
        !matches!(query_result, Ok(Some(()))),
        "missing XoT client certificate must abort before sending a DNS transfer query"
    );
    assert_eq!(metrics.snapshot().axfr_failed, 1);
}

#[test]
fn runtime_config_validation_accepts_valid_xot_files() {
    let (trust_anchor, _key_path) = write_self_signed_xot_cert_files();
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
        trust_anchor.display()
    ))
    .expect("valid config");

    validate_runtime_config(&config).expect("xot tls files should validate");
}

#[test]
fn runtime_config_validation_accepts_inline_xot_client_key() {
    let (trust_anchor, key_path) =
        write_self_signed_xot_cert_files_for_name("primary.example.test");
    let key_pem = std::fs::read_to_string(&key_path).expect("read generated key PEM");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
                client_cert = "{}"
                client_key_pem = '''
{}'''
            "#,
        trust_anchor.display(),
        trust_anchor.display(),
        key_pem
    ))
    .expect("valid config with inline client key");

    validate_runtime_config(&config).expect("inline xot client key should validate");
}

#[test]
fn runtime_config_validation_rejects_malformed_inline_xot_client_key_without_leaking_it() {
    let (trust_anchor, _key_path) =
        write_self_signed_xot_cert_files_for_name("primary.example.test");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
                client_cert = "{}"
                client_key_pem = "inline-private-key-material"
            "#,
        trust_anchor.display(),
        trust_anchor.display(),
    ))
    .expect("schema-valid config with malformed inline client key");

    let error = validate_runtime_config(&config)
        .expect_err("malformed inline XoT client key should fail runtime validation");
    let message = error.to_string();
    assert!(message.contains("failed to parse inline private key PEM"));
    assert!(!message.contains("inline-private-key-material"));
}

#[test]
fn file_descriptor_limit_check_uses_srs_resource_formula() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [limits]
                max_tcp_connections = 20
                max_concurrent_transfers = 3

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid config");

    assert_eq!(required_file_descriptor_limit(&config), 246);
    validate_file_descriptor_limit_value(&config, 246).expect("exact required limit is enough");

    let error = validate_file_descriptor_limit_value(&config, 245)
        .expect_err("below required limit should fail");
    assert!(matches!(
        error,
        RuntimeError::InsufficientFileDescriptorLimit {
            current: 245,
            required: 246
        }
    ));
}

#[test]
fn runtime_config_warnings_report_expiring_xot_trust_anchors() {
    let (trust_anchor, _key_path) =
        write_expiring_self_signed_xot_cert_files_for_name("primary.example.test");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
        trust_anchor.display()
    ))
    .expect("valid config");

    let warnings = runtime_config_warnings_at(&config, 1_779_667_200)
        .expect("xot warning collection succeeds");

    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, "xot_trust_anchor_expiring_soon");
    assert!(
        warnings[0]
            .parameter
            .contains("zones[example.test.].transfer_primaries[192.0.2.53:853]")
    );
    assert!(warnings[0].message.contains("within 30 days"));
}

#[test]
fn runtime_config_validation_rejects_missing_xot_trust_anchor_file() {
    let missing_trust_anchor = unique_test_path("missing-xot-ca", "pem");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
        missing_trust_anchor.display()
    ))
    .expect("schema-valid config");

    let error = validate_runtime_config(&config).expect_err("missing trust anchor must fail");

    assert!(error.to_string().contains("failed to read XoT TLS file"));
}

#[test]
fn runtime_config_validation_rejects_malformed_xot_trust_anchor_file() {
    let trust_anchor = unique_test_path("malformed-xot-ca", "pem");
    std::fs::write(&trust_anchor, b"not a certificate").expect("write malformed trust anchor");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
        trust_anchor.display()
    ))
    .expect("schema-valid config");

    let error = validate_runtime_config(&config).expect_err("malformed trust anchor must fail");

    assert!(error.to_string().contains("did not contain certificates"));
}

#[tokio::test]
async fn runtime_rejects_invalid_xot_config_before_startup() {
    let missing_trust_anchor = unique_test_path("missing-runtime-xot-ca", "pem");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
        missing_trust_anchor.display()
    ))
    .expect("schema-valid config");

    let error = Runtime::new(config)
        .run_with_shutdown_signal(async { Ok("test") })
        .await
        .expect_err("runtime must reject invalid XoT TLS files before startup");

    assert!(matches!(error, RuntimeError::InvalidRuntimeConfig(_)));
}

#[tokio::test]
async fn refresh_axfr_uses_xot_tls_transport() {
    let (primary, trust_anchor) = spawn_xot_axfr_primary_with_serial(1).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
        },
    )
    .await
    .expect("XoT AXFR should publish a snapshot");

    assert_eq!(metadata.serial, Some(1));
    assert!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("example.test.").unwrap())
            .expect("published XoT zone")
            .snapshot_for_transfer()
            .offline_oracle()
            .lookup(
                &DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            )
            .answers
            .iter()
            .any(|answer| answer.rdata == vec![192, 0, 2, 10])
    );
    assert_eq!(metrics.snapshot().axfr_succeeded, 1);
}

#[tokio::test]
async fn refresh_uses_axfr_during_ixfr_disabled_cooldown() {
    let (primary, qtypes) = spawn_ixfr_notimp_then_axfr_primary().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let plan = transfer_plan
        .get(&DomainName::from_absolute_str("example.test.").unwrap())
        .expect("zone transfer plan");
    let zones = ZoneStore::new();
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(
        apex.clone(),
        Some(1),
        vec![Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(1)],
        )],
    ));
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
    let metrics = RuntimeMetrics::new();

    let first_metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        Some(2),
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
        },
    )
    .await
    .expect("first refresh succeeds via AXFR fallback");
    assert_eq!(first_metadata.serial, Some(2));

    let second_metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        Some(3),
        RefreshAttemptContext {
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            secrets: SecretManager::from_config(&config).expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
        },
    )
    .await
    .expect("second refresh skips IXFR and succeeds via AXFR");
    assert_eq!(second_metadata.serial, Some(3));

    assert_eq!(
        *qtypes.lock().expect("qtype log lock poisoned"),
        vec![
            RecordType::Ixfr as u16,
            RecordType::Axfr as u16,
            RecordType::Axfr as u16
        ]
    );
    assert_eq!(
        metrics.snapshot(),
        super::RuntimeMetricsSnapshot {
            queries_received: 0,
            queries_truncated: 0,
            queries_cname_chain_limit: 0,
            queries_cname_loop: 0,
            axfr_started: 2,
            axfr_succeeded: 2,
            axfr_failed: 0,
            ixfr_started: 1,
            ixfr_succeeded: 0,
            ixfr_failed: 1,
            ..Default::default()
        }
    );
}

#[tokio::test]
async fn scheduled_refresh_worker_expires_zone_and_enqueues_refresh() {
    let zones = ZoneStore::new();
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        )],
    );
    zones.insert_snapshot(snapshot.clone());
    registry.record_success_at(
        &zone_metadata_for(&snapshot),
        std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(604800))
            .unwrap(),
    );
    let (tx, mut rx) = mpsc::channel(1);
    let worker = tokio::spawn(serve_scheduled_refreshes(
        zones.clone(),
        registry,
        tx,
        std::time::Duration::from_millis(1),
    ));

    let request = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("scheduled refresh should be enqueued")
        .expect("scheduled refresh request");

    assert_eq!(request.zone, origin);
    assert_eq!(request.reason, super::RefreshReason::Scheduled);
    assert_eq!(
        zones
            .exact_snapshot_for_transfer(&origin)
            .expect("expired zone")
            .metadata()
            .state,
        ZoneState::Expired
    );
    worker.abort();
}

#[tokio::test]
async fn runtime_initial_load_publishes_zone_snapshot() {
    let primary = spawn_axfr_primary().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");

    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let runtime = Runtime::new(config);
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
    let metrics = RuntimeMetrics::new();
    runtime
        .load_initial_zones(
            &transfer_plan,
            &refresh_registry,
            &ixfr_cooldowns,
            4,
            &metrics,
        )
        .await;

    let snapshot = runtime
        .zones
        .exact_snapshot_for_transfer(&DomainName::from_absolute_str("example.test.").unwrap())
        .expect("published zone snapshot");
    assert_eq!(snapshot.metadata().state, ZoneState::Active);
    assert_eq!(
        metrics.snapshot(),
        super::RuntimeMetricsSnapshot {
            queries_received: 0,
            queries_truncated: 0,
            queries_cname_chain_limit: 0,
            queries_cname_loop: 0,
            axfr_started: 1,
            axfr_succeeded: 1,
            axfr_failed: 0,
            ixfr_started: 0,
            ixfr_succeeded: 0,
            ixfr_failed: 0,
            ..Default::default()
        }
    );
}

#[tokio::test]
async fn runtime_initial_load_honors_transfer_concurrency_limit() {
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let alpha_primary = spawn_barrier_axfr_primary("alpha.test.", barrier.clone()).await;
    let beta_primary = spawn_barrier_axfr_primary("beta.test.", barrier.clone()).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [limits]
                max_concurrent_transfers = 2

                [[zones]]
                name = "alpha.test."
                primaries = ["{alpha_primary}"]

                [[zones]]
                name = "beta.test."
                primaries = ["{beta_primary}"]
            "#
    ))
    .expect("valid config");

    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let runtime = Runtime::new(config);
    let zones = runtime.zones.clone();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
    let loader = tokio::spawn(async move {
        let metrics = RuntimeMetrics::new();
        runtime
            .load_initial_zones(
                &transfer_plan,
                &refresh_registry,
                &ixfr_cooldowns,
                2,
                &metrics,
            )
            .await;
    });

    tokio::time::timeout(std::time::Duration::from_secs(1), barrier.wait())
        .await
        .expect("both initial transfers should start before either completes");
    loader.await.unwrap();

    assert_eq!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("alpha.test.").unwrap())
            .expect("alpha zone")
            .metadata()
            .state,
        ZoneState::Active
    );
    assert_eq!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("beta.test.").unwrap())
            .expect("beta zone")
            .metadata()
            .state,
        ZoneState::Active
    );
}
