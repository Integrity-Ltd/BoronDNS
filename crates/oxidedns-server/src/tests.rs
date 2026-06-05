static TEST_PATH_COUNTER: AtomicUsize = AtomicUsize::new(0);

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use oxidedns_core::{
    ServerConfig,
    axfr::{IxfrResponse, frame_tcp_message},
    config::{
        HealthConfig, MetricsHotPathDetail, ObservabilityConfig, RrlConfig, TransferPrimaryConfig,
        TransferTransportConfig, UdpBackend, XdpConfig,
    },
    dns::{
        AnyResponseMode, ChaosQueryOutcome, DnsCookiePolicy, DnsCookieRequestStatus, DomainName,
        ExtendedDnsErrorsMode, Header, LookupMetrics, LookupTermination, Opcode, Rcode, RecordType,
        Transport, ZoneImageServeFailureReason,
    },
    tsig::{
        DEFAULT_TSIG_FUDGE_SECS, TSIG_ERROR_BADALG, TSIG_ERROR_BADKEY, TSIG_ERROR_BADSIG,
        TSIG_ERROR_BADTIME, TSIG_ERROR_BADTRUNC, TsigError, TsigKey,
    },
    zone::{ResourceRecord, Rrset, SoaTimers, ZoneMetadata, ZoneSnapshot, ZoneState, ZoneStore},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
};
use tokio_rustls::rustls::{RootCertStore, server::WebPkiClientVerifier, version};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use super::observability::{ObservabilityAuth, TransferMaterial};
use super::{
    BoundUdpListener, CatalogManager, CatalogRuntime, CatalogRuntimeConfig,
    ControlPlaneTelemetryReporter, CookiePrefixMetricSettings, DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
    DEFAULT_LATENCY_HISTOGRAM_BUCKETS, DnsCookieRuntimeSettings, DnsCookieSecretStore,
    HealthEndpointState, IxfrCooldownRegistry, LoadingWarning, MetricsRateLimiter, NotifyAuthority,
    NotifyLogLimiter, NotifyLogSummary, NotifyRefreshAction, NotifyRefreshTracker,
    NotifyTsigResult, PacketIo, PreparedDnsMessage, QueryLatencyCategory, QueryLatencyHistogram,
    QueryMetricObservation, QueryObservationOptions, QueryPipelineStage, RefreshAttemptContext,
    RefreshRequest, RefreshWorkerSettings, ResponseCacheCandidateCategory,
    ResponseCacheIneligibleReason, RrlCategory, RrlDecision, RrlLimiter, RrlSummary, Runtime,
    RuntimeError, RuntimeMetrics, RuntimeStatus, StdUdpBatchIo, TcpServerSettings, TransferError,
    TransferPlan, TransferSession, TransferTsig, UdpRuntime, UdpServerSettings,
    ZoneRefreshRegistry, bind_udp_listeners, dns_cookie_secret_fingerprint,
    dns_cookie_secret_store_from_config, drain_task_set, drain_tcp_connections,
    handle_tcp_connection, handle_tcp_connection_with_query_hook, jitter_interval, load_pem_certs,
    load_pem_private_key_from_file as load_pem_private_key, log_loading_warning,
    log_notify_log_summary, log_rrl_summary, metrics_body, observe_query_metrics,
    poll_soa_from_primary, poll_soa_from_primary_with_tsig, prepare_notify_packet,
    prepare_notify_packet_with_metrics, prepare_query_tsig_packet, query_id_from_random_bytes,
    record_query_lookup_metrics, record_query_response_metric,
    refresh_zone_metadata_from_primaries, required_file_descriptor_limit, response_category,
    response_opt_record, response_question_end, response_rcode, rotate_transfer_targets,
    rrl_truncated_response, runtime_config_warnings_at, serial_after, serve_health,
    serve_refresh_requests, serve_scheduled_refreshes, serve_tcp, serve_udp, sign_tsig_response,
    signal_notify_refresh, transfer_axfr_from_primary, transfer_ixfr_from_primary,
    transfer_query_id, uniform_index_from_u64, validate_file_descriptor_limit_value,
    validate_runtime_config, write_tcp_message,
};

#[test]
fn runtime_initializes_loading_zones() {
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
    .expect("valid config");

    let runtime = Runtime::new(config);
    assert_eq!(runtime.zone_count(), 1);
}

#[tokio::test]
async fn catalog_snapshot_adds_member_transfer_plan_and_hides_catalog() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

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
                member_primaries = ["198.51.100.53:53"]
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
    let notify_authority = NotifyAuthority::from_config(&config);
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
        vec![SocketAddr::from((Ipv4Addr::new(198, 51, 100, 53), 53))]
    );
    assert_eq!(
        member_plan
            .tsig_key
            .as_ref()
            .expect("member TSIG key")
            .name
            .to_string(),
        "member-key."
    );
    assert!(notify_authority.is_authorized(&catalog_origin, 1, "192.0.2.53".parse().unwrap()));
    assert!(!notify_authority.is_authorized(&catalog_origin, 1, "198.51.100.53".parse().unwrap()));
    assert!(notify_authority.is_authorized(&member_origin, 1, "198.51.100.53".parse().unwrap()));
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
async fn catalog_snapshot_applies_opt_in_member_transfer_extension() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

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
                DomainName::from_absolute_str("_udns-xfr.a.zones.catalog.example.").unwrap(),
                RecordType::Txt as u16,
                1,
                0,
                vec![catalog_txt("transport=tcp;port=5300")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("_udns-notify.a.zones.catalog.example.").unwrap(),
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
    let notify_authority = NotifyAuthority::from_config(&config);
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
            .tsig_key
            .as_ref()
            .expect("override TSIG key")
            .name
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
async fn catalog_snapshot_ignores_existing_catalog_zone_name_clash() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

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
    let notify_authority = NotifyAuthority::from_config(&config);
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
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

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
    let notify_authority = NotifyAuthority::from_config(&config);
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
fn notify_authority_allows_primaries_and_notify_sources() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                notify_sources = ["198.51.100.53"]
            "#,
    )
    .expect("valid config");
    let authority = NotifyAuthority::from_config(&config);
    let zone = DomainName::from_absolute_str("example.test.").unwrap();

    assert!(authority.is_authorized(&zone, 1, "192.0.2.53".parse().unwrap()));
    assert!(authority.is_authorized(&zone, 1, "198.51.100.53".parse().unwrap()));
    assert!(!authority.is_authorized(&zone, 1, "203.0.113.53".parse().unwrap()));
    assert!(!authority.is_authorized(&zone, 255, "192.0.2.53".parse().unwrap()));
}

#[test]
fn explicit_transfer_primaries_feed_notify_authority_and_transfer_plan() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."
                notify_sources = ["198.51.100.53"]

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
            "#,
    )
    .expect("valid config");
    let zone = DomainName::from_absolute_str("example.test.").unwrap();

    let authority = NotifyAuthority::from_config(&config);
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
fn transfer_plan_carries_out_of_zone_glue_tolerance() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [transfer]
                accept_out_of_zone_glue = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid config");
    let zone = DomainName::from_absolute_str("example.test.").unwrap();

    let plan = TransferPlan::from_config(&config)
        .expect("transfer plan")
        .get(&zone)
        .expect("transfer plan");

    assert!(plan.parse_options.accept_out_of_zone_glue);
}

#[test]
fn tsig_secret_file_feeds_notify_authority_and_transfer_plan() {
    let secret_file = unique_test_path("oxidedns-server-tsig-secret", "key");
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
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

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

    let authority = NotifyAuthority::from_config(&config);
    assert!(
        authority
            .tsig_keys_by_name
            .contains_key(&key_name.canonical_key())
    );
    assert!(
        authority
            .tsig_keys_by_zone
            .lock()
            .expect("notify authority zone TSIG lock poisoned")
            .contains_key(&zone.canonical_key())
    );

    let plan = TransferPlan::from_config(&config)
        .expect("transfer plan")
        .get(&zone)
        .expect("zone transfer plan");
    assert!(plan.tsig_key.is_some());
    let _ = std::fs::remove_file(secret_file);
}

#[test]
fn transfer_plan_rotates_multi_primary_start_once_per_process() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
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
fn notify_authority_rejects_missing_required_tsig_with_badkey_response() {
    let config = ServerConfig::from_toml_str(
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
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
    )
    .expect("valid config");
    let authority = NotifyAuthority::from_config(&config);
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);

    let prepared = prepare_notify_packet(&packet, &authority, "192.0.2.53".parse().unwrap());

    let response = prepared
        .expect("TSIG error response")
        .immediate_response
        .expect("immediate TSIG error response");
    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, 0);
    assert_eq!(tsig.original_id, 0x1234);
    assert_eq!(tsig.error, TSIG_ERROR_BADKEY);
    assert!(tsig.other_data.is_empty());
}

#[test]
fn ordinary_query_with_unknown_tsig_key_gets_badkey_response() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

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
    let authority = NotifyAuthority::from_config(&config);
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
        },
        &authority,
    );

    let response = prepared
        .immediate_response
        .expect("immediate BADKEY response");
    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
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
        },
        &authority,
    );

    let response = prepared.immediate_response.expect("TSIG error response");
    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.error, TSIG_ERROR_BADSIG);
}

#[test]
fn ordinary_query_with_too_short_tsig_mac_gets_badtrunc_response() {
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
        },
        &authority,
    );

    let response = prepared.immediate_response.expect("TSIG error response");
    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, 0);
    assert_eq!(tsig.error, TSIG_ERROR_BADTRUNC);
    assert!(tsig.other_data.is_empty());
}

#[test]
fn ordinary_query_with_hmac_md5_tsig_gets_badalg_response() {
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
        },
        &authority,
    );

    let response = prepared.immediate_response.expect("TSIG error response");
    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, 0);
    assert_eq!(tsig.error, TSIG_ERROR_BADALG);
    assert!(tsig.other_data.is_empty());
}

#[test]
fn ordinary_query_outside_tsig_fudge_gets_badtime_response_with_server_time() {
    let (authority, key) = tsig_notify_authority();
    let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let signed = key
        .sign_request(&packet, 1, DEFAULT_TSIG_FUDGE_SECS)
        .unwrap();

    let prepared = prepare_query_tsig_packet(
        PreparedDnsMessage {
            packet: signed.message,
            response_tsig: None,
            immediate_response: None,
            tsig_authenticated: false,
        },
        &authority,
    );

    let response = prepared.immediate_response.expect("TSIG error response");
    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, key.algorithm.mac_len());
    assert_eq!(tsig.error, TSIG_ERROR_BADTIME);
    assert_eq!(tsig.other_data.len(), 6);
}

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
    state.metrics.record_zone_query_key("example.test.");
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
    state.metrics.record_zone_query_key("example.test.");
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
                    max_member_zones: 10_000,
                },
            },
        )])),
        static_zone_keys: Arc::new(HashSet::from(["static.example.".to_owned()])),
        memberships_by_catalog: Arc::new(Mutex::new(HashMap::from([(
            "catalog.example.".to_owned(),
            HashSet::from(["alpha.example.".to_owned(), "static.example.".to_owned()]),
        )]))),
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
        trust_anchors: vec![cert_path.display().to_string()],
        client_cert: None,
        client_key_configured: false,
        inline_client_key_configured: false,
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
            HashSet::from(["alpha.example.".to_owned(), "static.example.".to_owned()]),
        )]))),
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
    metrics_state.record_zone_query_key(&active_zone_key);
    metrics_state.record_zone_query_key(&active_zone_key);
    metrics_state.record_query_received();
    metrics_state.record_query_received();
    metrics_state.record_query_truncated();
    metrics_state.record_query_cname_chain_limit();
    metrics_state.record_query_cname_loop();
    metrics_state.record_query_response_rcode(0);
    metrics_state.record_query_response_rcode(3);
    metrics_state.record_query_response_rcode(23);
    metrics_state.record_zone_query_response_rcode(&active_origin.canonical_key(), 0);
    metrics_state.record_zone_query_response_rcode(&active_origin.canonical_key(), 3);
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
            started_at: std::time::Instant::now(),
            graceful_shutdown_secs: 30,
            zone_shape_metrics_enabled: true,
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
            started_at: std::time::Instant::now(),
            graceful_shutdown_secs: 30,
            zone_shape_metrics_enabled: false,
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
            started_at: std::time::Instant::now(),
            graceful_shutdown_secs: 30,
            zone_shape_metrics_enabled: false,
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
    let runtime = Runtime::new(config);
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
    let runtime = Runtime::new(config);
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
    let runtime = Runtime::new(config);
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
    let runtime = Runtime::new(config);
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
    let runtime = Runtime::new(config);
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
    let runtime = Runtime::new(config);
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

#[test]
fn signed_notify_is_verified_stripped_and_response_signed() {
    let config = ServerConfig::from_toml_str(
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
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
    )
    .expect("valid config");
    let authority = NotifyAuthority::from_config(&config);
    let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
    let signed_notify = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("signed NOTIFY");

    let prepared = prepare_notify_packet(
        &signed_notify.message,
        &authority,
        "192.0.2.53".parse().unwrap(),
    )
    .expect("verified NOTIFY");

    assert_eq!(prepared.packet, packet);
    let response = notify_response(0x1234);
    let signed_response = sign_tsig_response(response.clone(), prepared.response_tsig)
        .expect("signed NOTIFY response");
    let response_tsig = parse_tsig_response_fields(&signed_response);
    assert_eq!(response_tsig.fudge, 30);
    let verified_response = key
        .verify_response(&signed_response, &signed_notify.mac, current_unix_time())
        .expect("verified NOTIFY response");
    assert_eq!(verified_response.message, response);
}

#[test]
fn authorized_notify_with_bad_tsig_mac_gets_badsig_response() {
    let (authority, key) = tsig_notify_authority();
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
    let signed_notify = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("signed NOTIFY");
    let mut bad_mac = signed_notify.mac.clone();
    bad_mac[0] ^= 0x01;
    let bad_notify = replace_final_tsig_mac(&signed_notify.message, &bad_mac);

    let prepared = prepare_notify_packet(&bad_notify, &authority, "192.0.2.53".parse().unwrap())
        .expect("TSIG error response");
    let response = prepared
        .immediate_response
        .expect("immediate TSIG error response");

    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, 0);
    assert_eq!(tsig.original_id, 0x1234);
    assert_eq!(tsig.error, TSIG_ERROR_BADSIG);
    assert!(tsig.other_data.is_empty());
}

#[test]
fn authorized_notify_with_too_short_tsig_mac_gets_badtrunc_response() {
    let (authority, key) = tsig_notify_authority();
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
    let signed_notify = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("signed NOTIFY");
    let too_short_mac = &signed_notify.mac[..key.algorithm.min_mac_len() - 1];
    let bad_notify = replace_final_tsig_mac(&signed_notify.message, too_short_mac);

    let prepared = prepare_notify_packet(&bad_notify, &authority, "192.0.2.53".parse().unwrap())
        .expect("TSIG error response");
    let response = prepared
        .immediate_response
        .expect("immediate TSIG error response");

    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, 0);
    assert_eq!(tsig.original_id, 0x1234);
    assert_eq!(tsig.error, TSIG_ERROR_BADTRUNC);
    assert!(tsig.other_data.is_empty());
}

#[test]
fn authorized_notify_with_hmac_md5_tsig_gets_badalg_response() {
    let (authority, key) = tsig_notify_authority();
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
    let signed_notify = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("signed NOTIFY");
    let bad_algorithm_notify =
        replace_final_tsig_algorithm(&signed_notify.message, "hmac-md5.sig-alg.reg.int.");

    let prepared = prepare_notify_packet(
        &bad_algorithm_notify,
        &authority,
        "192.0.2.53".parse().unwrap(),
    )
    .expect("TSIG error response");
    let response = prepared
        .immediate_response
        .expect("immediate TSIG error response");

    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, 0);
    assert_eq!(tsig.original_id, 0x1234);
    assert_eq!(tsig.error, TSIG_ERROR_BADALG);
    assert!(tsig.other_data.is_empty());
}

#[test]
fn authorized_notify_with_unknown_tsig_key_gets_badkey_response() {
    let (authority, key) = tsig_notify_authority();
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
    let signed_notify = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("signed NOTIFY");
    let bad_key_notify = replace_final_tsig_owner(&signed_notify.message, "unknown-key.");

    let prepared =
        prepare_notify_packet(&bad_key_notify, &authority, "192.0.2.53".parse().unwrap())
            .expect("TSIG error response");
    let response = prepared
        .immediate_response
        .expect("immediate TSIG error response");

    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, 0);
    assert_eq!(tsig.original_id, 0x1234);
    assert_eq!(tsig.error, TSIG_ERROR_BADKEY);
    assert!(tsig.other_data.is_empty());
}

#[test]
fn authorized_notify_with_algorithm_mismatch_gets_badkey_response() {
    let (authority, key) = tsig_notify_authority();
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
    let signed_notify = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("signed NOTIFY");
    let mismatched_algorithm_notify =
        replace_final_tsig_algorithm(&signed_notify.message, "hmac-sha1.");

    let prepared = prepare_notify_packet(
        &mismatched_algorithm_notify,
        &authority,
        "192.0.2.53".parse().unwrap(),
    )
    .expect("TSIG error response");
    let response = prepared
        .immediate_response
        .expect("immediate TSIG error response");

    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, 0);
    assert_eq!(tsig.original_id, 0x1234);
    assert_eq!(tsig.error, TSIG_ERROR_BADKEY);
    assert!(tsig.other_data.is_empty());
}

#[test]
fn authorized_notify_outside_tsig_fudge_gets_badtime_response_with_server_time() {
    let (authority, key) = tsig_notify_authority();
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
    let stale_notify = key
        .sign_request(&packet, 1, DEFAULT_TSIG_FUDGE_SECS)
        .expect("signed NOTIFY");

    let prepared = prepare_notify_packet(
        &stale_notify.message,
        &authority,
        "192.0.2.53".parse().unwrap(),
    )
    .expect("TSIG error response");
    let response = prepared
        .immediate_response
        .expect("immediate TSIG error response");

    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    let tsig = parse_tsig_response_fields(&response);
    assert_eq!(tsig.mac_len, key.algorithm.mac_len());
    assert_eq!(tsig.original_id, 0x1234);
    assert_eq!(tsig.error, TSIG_ERROR_BADTIME);
    assert_eq!(tsig.other_data.len(), 6);
}

#[test]
fn notify_tsig_verification_metrics_classify_results() {
    let (authority, key) = tsig_notify_authority();
    let metrics = RuntimeMetrics::new();
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);

    let unsigned_prepared = prepare_notify_packet_with_metrics(
        &packet,
        &authority,
        "192.0.2.53".parse().unwrap(),
        &metrics,
        &notify_log_limiter_for_test(),
    )
    .expect("TSIG error response");
    assert!(unsigned_prepared.immediate_response.is_some());

    let signed_notify = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("signed NOTIFY");
    let signed_prepared = prepare_notify_packet_with_metrics(
        &signed_notify.message,
        &authority,
        "192.0.2.53".parse().unwrap(),
        &metrics,
        &notify_log_limiter_for_test(),
    )
    .expect("verified NOTIFY");
    assert_eq!(signed_prepared.packet, packet);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.notify_received, 2);
    assert_eq!(snapshot.notify_tsig_badkey, 1);
    assert_eq!(snapshot.notify_tsig_ok, 1);
    assert_eq!(snapshot.notify_tsig_badsig, 0);
}

#[test]
fn notify_refresh_signalling_records_metrics() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
    let (refresh_tx, _refresh_rx) = mpsc::channel(2);
    let metrics = RuntimeMetrics::new();
    let zone = DomainName::from_absolute_str("example.test.").unwrap();
    let source = "192.0.2.53".parse().unwrap();

    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(1));
    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(1));

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.notify_refresh_signalled, 1);
    assert_eq!(snapshot.notify_refresh_deduplicated, 1);
}

#[test]
fn notify_refresh_tracker_deduplicates_within_interval() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
    let zone = DomainName::from_absolute_str("example.test.").unwrap();

    assert_eq!(tracker.record(&zone), NotifyRefreshAction::Signalled);
    assert_eq!(tracker.record(&zone), NotifyRefreshAction::Deduplicated);
}

#[test]
fn notify_refresh_tracker_allows_after_zero_interval() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::ZERO);
    let zone = DomainName::from_absolute_str("example.test.").unwrap();

    assert_eq!(tracker.record(&zone), NotifyRefreshAction::Signalled);
    assert_eq!(tracker.record(&zone), NotifyRefreshAction::Signalled);
}

#[tokio::test]
async fn drain_tcp_connections_returns_when_idle() {
    let active = Arc::new(AtomicUsize::new(0));

    assert!(
        drain_tcp_connections(
            active,
            std::time::Duration::from_millis(25),
            std::time::Duration::from_millis(1),
        )
        .await
    );
}

#[tokio::test]
async fn drain_tcp_connections_waits_for_active_connections_until_grace() {
    let active = Arc::new(AtomicUsize::new(1));
    let active_for_task = active.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        active_for_task.store(0, Ordering::Release);
    });

    assert!(
        drain_tcp_connections(
            active,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(1),
        )
        .await
    );
}

#[tokio::test]
async fn drain_tcp_connections_stops_after_grace_period() {
    let active = Arc::new(AtomicUsize::new(1));

    assert!(
        !drain_tcp_connections(
            active,
            std::time::Duration::from_millis(5),
            std::time::Duration::from_millis(1),
        )
        .await
    );
}

#[tokio::test]
async fn drain_task_set_waits_for_tasks_until_grace() {
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        Ok::<(), RuntimeError>(())
    });

    assert!(drain_task_set(&mut tasks, std::time::Duration::from_secs(1), "test task").await);
    assert!(tasks.is_empty());
}

#[tokio::test]
async fn drain_task_set_aborts_after_grace_period() {
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        Ok::<(), RuntimeError>(())
    });

    assert!(!drain_task_set(&mut tasks, std::time::Duration::from_millis(5), "test task").await);
    assert!(tasks.is_empty());
}

fn notify_refresh_tx() -> mpsc::Sender<RefreshRequest> {
    let (tx, _rx) = mpsc::channel(1);
    tx
}

fn current_zone_with_serial(apex: &DomainName, serial: u32) -> ZoneSnapshot {
    let current_soa = record(
        "example.test.",
        RecordType::Soa as u16,
        soa_rdata_with_serial(serial),
    );
    ZoneSnapshot::active(
        apex.clone(),
        Some(serial),
        vec![Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            current_soa.ttl,
            vec![current_soa.rdata],
        )],
    )
}

fn zone_metadata_for(snapshot: &ZoneSnapshot) -> ZoneMetadata {
    ZoneMetadata {
        origin: snapshot.origin.clone(),
        origin_key: Arc::from(snapshot.origin.canonical_key()),
        origin_name: Arc::from(snapshot.origin.to_string()),
        state: snapshot.state,
        serial: snapshot.serial,
        soa_timers: snapshot.soa_timers,
        shape: None,
        shape_histograms: None,
    }
}

fn catalog_txt(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    assert!(bytes.len() < 256);
    let mut rdata = vec![bytes.len() as u8];
    rdata.extend_from_slice(bytes);
    rdata
}

#[tokio::test]
async fn transfer_axfr_from_primary_reads_tcp_messages() {
    let primary = spawn_axfr_primary().await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let snapshot =
        transfer_axfr_from_primary(primary, &apex, 1, 0x1234, std::time::Duration::from_secs(5))
            .await
            .expect("AXFR transfer");

    assert_eq!(snapshot.state, ZoneState::Active);
    assert_eq!(snapshot.serial, Some(1));
    assert_eq!(
        snapshot
            .offline_oracle()
            .lookup(
                &DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            )
            .answers
            .len(),
        1
    );
}

#[tokio::test]
async fn tcp_connect_timeout_abandons_pending_connect_attempt() {
    let primary = "192.0.2.53:53".parse().unwrap();
    let error = super::tcp_connect_with_timeout(
        primary,
        std::time::Duration::from_millis(1),
        std::future::pending::<std::io::Result<()>>(),
    )
    .await
    .expect_err("pending TCP connect should time out");

    assert!(matches!(error, TransferError::Timeout { timeout_secs: 0 }));
}

#[tokio::test]
async fn transfer_axfr_enforces_ingestion_size_cap() {
    let primary = spawn_axfr_primary().await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let target = TransferPrimaryConfig::tcp(primary);

    let error = super::transfer_axfr_from_target_with_tsig(
        &target,
        &apex,
        1,
        0x1234,
        TransferSession::new(TransferTsig::unsigned(), 1),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect_err("AXFR transfer should exceed ingest cap");

    assert!(matches!(
        error,
        TransferError::IngestSizeLimit {
            protocol: "AXFR",
            limit_bytes: 1,
            ..
        }
    ));
}

#[tokio::test]
async fn transfer_ixfr_from_primary_accepts_mode2_axfr_fallback() {
    let primary = spawn_ixfr_mode2_primary_with_serial(2).await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let current_soa = record(
        "example.test.",
        RecordType::Soa as u16,
        soa_rdata_with_serial(1),
    );
    let current_zone = ZoneSnapshot::active(
        apex.clone(),
        Some(1),
        vec![Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![current_soa.rdata],
        )],
    );
    let response = transfer_ixfr_from_primary(
        primary,
        &apex,
        1,
        0x1234,
        &current_zone,
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("IXFR transfer");

    let IxfrResponse::Updated(snapshot) = response else {
        panic!("expected updated zone");
    };
    assert_eq!(snapshot.state, ZoneState::Active);
    assert_eq!(snapshot.serial, Some(2));
    assert_eq!(
        snapshot
            .offline_oracle()
            .lookup(
                &DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            )
            .answers
            .len(),
        1
    );
}

#[tokio::test]
async fn transfer_ixfr_enforces_ingestion_size_cap() {
    let primary = spawn_ixfr_mode2_primary_with_serial(2).await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let current_zone = current_zone_with_serial(&apex, 1);
    let target = TransferPrimaryConfig::tcp(primary);

    let error = super::transfer_ixfr_from_target_with_tsig(
        &target,
        &apex,
        1,
        0x1234,
        &current_zone,
        TransferSession::new(TransferTsig::unsigned(), 1),
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect_err("IXFR transfer should exceed ingest cap");

    assert!(matches!(
        error,
        TransferError::IngestSizeLimit {
            protocol: "IXFR",
            limit_bytes: 1,
            ..
        }
    ));
}

#[tokio::test]
async fn transfer_ixfr_from_primary_applies_mode1_incremental_diff() {
    let primary = spawn_ixfr_mode1_primary().await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let current_soa = record(
        "example.test.",
        RecordType::Soa as u16,
        soa_rdata_with_serial(1),
    );
    let old_a = record(
        "old.example.test.",
        RecordType::A as u16,
        vec![192, 0, 2, 1],
    );
    let current_zone = ZoneSnapshot::active(
        apex.clone(),
        Some(1),
        vec![
            Rrset::new(
                apex.clone(),
                RecordType::Soa as u16,
                1,
                current_soa.ttl,
                vec![current_soa.rdata],
            ),
            Rrset::new(
                apex.clone(),
                RecordType::Ns as u16,
                1,
                300,
                vec![ns_rdata_for_zone("example.test.")],
            ),
            Rrset::new(
                old_a.owner.clone(),
                old_a.rr_type,
                old_a.class,
                old_a.ttl,
                vec![old_a.rdata],
            ),
        ],
    );
    let response = transfer_ixfr_from_primary(
        primary,
        &apex,
        1,
        0x1234,
        &current_zone,
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("IXFR transfer");

    let IxfrResponse::Updated(snapshot) = response else {
        panic!("expected updated zone");
    };
    assert_eq!(snapshot.serial, Some(2));
    assert!(
        snapshot
            .offline_oracle()
            .lookup(
                &DomainName::from_absolute_str("old.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            )
            .answers
            .is_empty()
    );
    assert_eq!(
        snapshot
            .offline_oracle()
            .lookup(
                &DomainName::from_absolute_str("new.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            )
            .answers
            .len(),
        1
    );
}

#[tokio::test]
async fn poll_soa_from_primary_reads_udp_response() {
    let primary = spawn_soa_primary_with_serial(7).await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let serial =
        poll_soa_from_primary(primary, &apex, 1, 0x1234, std::time::Duration::from_secs(5))
            .await
            .expect("SOA poll");

    assert_eq!(serial, 7);
}

#[tokio::test]
async fn poll_soa_from_primary_ignores_udp_packet_from_unconnected_peer() {
    let primary = spawn_soa_primary_with_spoofed_malformed_packet(7).await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let serial =
        poll_soa_from_primary(primary, &apex, 1, 0x1234, std::time::Duration::from_secs(5))
            .await
            .expect("SOA poll should ignore the unconnected sender");

    assert_eq!(serial, 7);
}

#[tokio::test]
async fn poll_soa_from_primary_records_warning_evidence_for_malformed_response() {
    let primary = spawn_malformed_soa_primary().await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let error = poll_soa_from_primary(primary, &apex, 1, 0x1234, std::time::Duration::from_secs(5))
        .await
        .expect_err("malformed SOA poll response should fail");

    assert!(matches!(
        error,
        super::TransferError::Soa(oxidedns_core::axfr::SoaQueryError::MalformedMessage)
    ));
    assert!(captured.contains_all(&[
        "SOA poll response rejected",
        "zone=example.test.",
        &format!("primary={primary}"),
        "qid=4660",
        "SOA response message is malformed",
    ]));
}

#[tokio::test]
async fn poll_soa_from_primary_verifies_signed_tsig_response() {
    let primary = spawn_signed_soa_primary_with_serial(7).await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();

    let serial = poll_soa_from_primary_with_tsig(
        primary,
        &apex,
        1,
        0x1234,
        TransferTsig::new(Some(&key), DEFAULT_TSIG_FUDGE_SECS),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("signed SOA poll");

    assert_eq!(serial, 7);
}

#[tokio::test]
async fn soa_poll_binds_configured_transfer_source() {
    let (primary, peer_rx) = spawn_soa_primary_recording_peer(7).await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let transfer_source = "127.0.0.2:0".parse::<std::net::SocketAddr>().unwrap();

    let serial = super::poll_soa_from_primary_with_tsig_and_source(
        primary,
        &apex,
        1,
        0x1234,
        TransferTsig::unsigned(),
        Some(transfer_source),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("SOA poll");
    let peer = tokio::time::timeout(std::time::Duration::from_secs(1), peer_rx)
        .await
        .expect("primary should observe SOA poll peer")
        .expect("SOA primary should send peer address");
    let expected_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    assert_eq!(serial, 7);
    assert_eq!(peer.ip(), expected_ip);
    assert_ne!(peer.port(), 0);
}

#[tokio::test]
async fn concurrent_soa_polls_use_distinct_ephemeral_source_ports() {
    let (primary, peers_rx) = spawn_soa_primary_recording_two_peers(7).await;
    let left_apex = DomainName::from_absolute_str("example.test.").unwrap();
    let right_apex = left_apex.clone();

    let (left, right) = tokio::join!(
        poll_soa_from_primary(
            primary,
            &left_apex,
            1,
            0x1234,
            std::time::Duration::from_secs(5)
        ),
        poll_soa_from_primary(
            primary,
            &right_apex,
            1,
            0x5678,
            std::time::Duration::from_secs(5)
        )
    );

    assert_eq!(left.expect("left SOA poll"), 7);
    assert_eq!(right.expect("right SOA poll"), 7);
    let peers = tokio::time::timeout(std::time::Duration::from_secs(1), peers_rx)
        .await
        .expect("primary should observe both SOA poll peers")
        .expect("SOA primary should send peer addresses");

    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].ip(), peers[1].ip());
    assert_ne!(peers[0].port(), 0);
    assert_ne!(peers[1].port(), 0);
    assert_ne!(peers[0].port(), peers[1].port());
}

#[tokio::test]
async fn poll_soa_from_primary_rejects_unsigned_response_when_tsig_expected() {
    let primary = spawn_soa_primary_with_serial(7).await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();

    let error = poll_soa_from_primary_with_tsig(
        primary,
        &apex,
        1,
        0x1234,
        TransferTsig::new(Some(&key), DEFAULT_TSIG_FUDGE_SECS),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect_err("unsigned response must fail");

    assert!(matches!(
        error,
        super::TransferError::Tsig(oxidedns_core::tsig::TsigError::MissingTsig)
    ));
}

#[tokio::test]
async fn axfr_binds_configured_transfer_source() {
    let (primary, peer_rx) = spawn_axfr_primary_recording_peer(7).await;
    let target = TransferPrimaryConfig::tcp(primary);
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let transfer_source = "127.0.0.2:0".parse::<std::net::SocketAddr>().unwrap();

    let snapshot = super::transfer_axfr_from_target_with_tsig_and_source(
        &target,
        &apex,
        1,
        0x1234,
        TransferSession::default_unsigned(),
        Some(transfer_source),
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("AXFR transfer");
    let peer = tokio::time::timeout(std::time::Duration::from_secs(1), peer_rx)
        .await
        .expect("primary should observe AXFR peer")
        .expect("AXFR primary should send peer address");
    let expected_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    assert_eq!(snapshot.serial, Some(7));
    assert_eq!(peer.ip(), expected_ip);
    assert_ne!(peer.port(), 0);
}

#[test]
fn serial_after_handles_wraparound() {
    assert!(serial_after(2, 1));
    assert!(serial_after(0, u32::MAX));
    assert!(!serial_after(1, 1));
    assert!(!serial_after(1, 2));
    assert!(!serial_after(0x8000_0001, 1));
}

#[test]
fn transfer_query_id_uses_full_sixteen_bit_range() {
    assert_eq!(query_id_from_random_bytes([0x00, 0x00]), 0);
    assert_eq!(query_id_from_random_bytes([0xff, 0xff]), u16::MAX);
}

#[test]
fn transfer_query_id_reads_os_randomness() {
    transfer_query_id().expect("random query id");
}

#[test]
fn dns_cookie_secret_fingerprint_is_redacted_and_stable() {
    let secret = *b"0123456789abcdef";
    let fingerprint = dns_cookie_secret_fingerprint(&secret);

    assert_eq!(fingerprint.len(), 16);
    assert_eq!(fingerprint, dns_cookie_secret_fingerprint(&secret));
    assert_ne!(fingerprint, "3031323334353637");
}

#[test]
fn dns_cookie_secret_store_rotates_only_after_configured_interval() {
    let generated_at = std::time::Instant::now() - std::time::Duration::from_secs(61);
    let rotating = DnsCookieSecretStore::new_at(
        [1; 16],
        None,
        Some(std::time::Duration::from_secs(60)),
        generated_at,
    );
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let rotated = rotating.current_with_generator(|| Ok([2; 16]));
    let retained = rotating.current_with_generator(|| -> Result<[u8; 16], getrandom::Error> {
        panic!("secret generator should not be called before the next interval")
    });
    let disabled = DnsCookieSecretStore::new_at([3; 16], Some([2; 16]), None, generated_at);

    assert_eq!(rotated.current, [2; 16]);
    assert_eq!(rotated.previous, Some([1; 16]));
    assert_eq!(retained.current, [2; 16]);
    assert_eq!(retained.previous, Some([1; 16]));
    let disabled_current = disabled.current_with_generator(|| Ok([4; 16]));
    assert_eq!(disabled_current.current, [3; 16]);
    assert_eq!(disabled_current.previous, Some([2; 16]));
    assert!(captured.contains_all(&["DNS Cookie server secret rotated", "secret_fingerprint=",]));
}

#[test]
fn dns_cookie_secret_store_uses_configured_shared_secrets() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [cookie]
                policy = "lenient"
                server_secret = "00112233445566778899aabbccddeeff"
                previous_server_secret = "ffeeddccbbaa99887766554433221100"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid config");

    let store = dns_cookie_secret_store_from_config(
        &config,
        dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
    )
    .expect("configured DNS Cookie secret store");
    let secrets = store.current();

    assert_eq!(
        secrets.current,
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]
    );
    assert_eq!(
        secrets.previous,
        Some([
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ])
    );
}

#[tokio::test]
async fn control_plane_telemetry_posts_success_payload() {
    let (endpoint, received) = spawn_telemetry_endpoint("204 No Content").await;
    let reporter = control_plane_reporter_for_endpoint(endpoint);
    let metadata = telemetry_zone_metadata(
        Some(2026060401),
        Some(SoaTimers {
            refresh: 60,
            retry: 30,
            expire: 300,
            minimum: 300,
        }),
    );

    reporter.report_success(&metadata, "active", "notify").await;
    let request = received.await.expect("telemetry request");
    let body = telemetry_json_body(&request);

    assert!(request.starts_with("POST /secondary-nodes/node-a/transfer-events HTTP/1.1"));
    assert!(request.contains("authorization: Bearer token-a"));
    assert_eq!(body["zone_name"], "alpha.test.");
    assert_eq!(body["status"], "active");
    assert_eq!(body["serial"], "2026060401");
    assert_eq!(body["refresh_seconds"], 60);
    assert_eq!(body["retry_seconds"], 30);
}

#[tokio::test]
async fn control_plane_telemetry_posts_failure_payload_and_logs_rejection() {
    let (endpoint, received) = spawn_telemetry_endpoint("503 Service Unavailable").await;
    let reporter = control_plane_reporter_for_endpoint(endpoint);
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let origin = DomainName::from_absolute_str("alpha.test.").unwrap();

    reporter
        .report_failure(&origin, Some("   "), "initial")
        .await;
    let request = received.await.expect("telemetry request");
    let body = telemetry_json_body(&request);

    assert_eq!(body["zone_name"], "alpha.test.");
    assert_eq!(body["status"], "failed");
    assert_eq!(
        body["failure_reason"],
        "transfer failed without detailed cause"
    );
    assert!(captured.contains_all(&[
        "uDNS transfer telemetry report was rejected",
        "category=\"transfer\"",
        "status=503 Service Unavailable",
    ]));
}

#[test]
fn query_metrics_count_configured_zone_queries_only() {
    let zones = ZoneStore::new();
    let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(active_origin, Some(1), Vec::new()));
    zones.insert_loading(DomainName::from_absolute_str("loading.test.").unwrap());
    let metrics = RuntimeMetrics::new();

    observe_query_metrics(
        &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );
    observe_query_metrics(
        &query(b"\x03www\x07loading\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );
    observe_query_metrics(
        &query(b"\x07outside\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );
    let response = {
        let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        packet[2] |= 0x80;
        packet
    };
    observe_query_metrics(&response, &zones, &metrics, query_observation_options());

    assert_eq!(metrics.snapshot().queries_received, 3);
    let counts = metrics.zone_query_counts();
    assert_eq!(counts.get("example.test."), Some(&1));
    assert_eq!(counts.get("loading.test."), Some(&1));
    assert!(!counts.contains_key("outside.test."));
}

#[test]
fn reduced_hot_path_metrics_skip_mutex_backed_query_detail() {
    let zones = ZoneStore::new();
    let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(
        active_origin.clone(),
        Some(1),
        Vec::new(),
    ));
    let metrics = RuntimeMetrics::new_reduced_for_test();

    let observation = observe_query_metrics(
        &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );

    assert!(observation.is_query);
    assert!(observation.zone_key.is_none());
    assert_eq!(metrics.snapshot().queries_received, 1);
    assert!(metrics.zone_query_counts().is_empty());

    let mut truncated = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    truncated[2] |= 0x82;
    record_query_response_metric(&observation, &truncated, &metrics);

    assert_eq!(metrics.snapshot().queries_truncated, 1);
    assert!(metrics.query_rcode_counts().is_empty());
    assert!(metrics.zone_query_rcode_counts().is_empty());
    assert!(metrics.query_latency_histograms().is_empty());

    let prefix_settings = cookie_prefix_metrics_for_test();
    metrics.record_dns_cookie_status(
        DnsCookieRequestStatus::ClientCookieOnly,
        "192.0.2.10".parse().unwrap(),
        prefix_settings,
    );
    metrics.record_dns_cookie_badcookie();
    metrics.record_dns_cookie_badcookie_for_source("192.0.2.10".parse().unwrap(), prefix_settings);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.dns_cookie_client_only, 1);
    assert_eq!(snapshot.dns_cookie_badcookie, 1);
    assert!(metrics.dns_cookie_prefix_counts().is_empty());

    assert!(!metrics.pipeline_timing_enabled());
    metrics.record_query_pipeline_latency(
        QueryPipelineStage::Compose,
        QueryLatencyCategory::UdpDirect,
        std::time::Duration::from_micros(100),
    );
    metrics.record_response_cache_candidate(ResponseCacheCandidateCategory::Direct);
    metrics.record_response_cache_ineligible(ResponseCacheIneligibleReason::Cookie);

    assert!(metrics.query_pipeline_latency_histograms().is_empty());
    assert!(metrics.response_cache_candidate_counts().is_empty());
    assert!(metrics.response_cache_ineligible_counts().is_empty());
}

#[test]
fn off_hot_path_metrics_skip_per_query_counters() {
    let zones = ZoneStore::new();
    let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(active_origin, Some(1), Vec::new()));
    let metrics = RuntimeMetrics::new_with_settings(
        1,
        DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
        false,
        MetricsHotPathDetail::Off,
    );

    let observation = observe_query_metrics(
        &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );

    assert!(!observation.is_query);
    assert_eq!(metrics.snapshot().queries_received, 0);
    assert!(metrics.zone_query_counts().is_empty());

    let mut truncated = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    truncated[2] |= 0x82;
    record_query_response_metric(&observation, &truncated, &metrics);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.queries_truncated, 0);
    assert!(metrics.query_rcode_counts().is_empty());
    assert!(metrics.zone_query_rcode_counts().is_empty());
    assert!(metrics.query_latency_histograms().is_empty());
}

#[test]
fn query_metrics_count_response_rcodes_for_queries_only() {
    let zones = ZoneStore::new();
    let metrics = RuntimeMetrics::new();
    let observation = observe_query_metrics(
        &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );
    let non_query_observation =
        observe_query_metrics(&[0, 1, 2], &zones, &metrics, query_observation_options());
    let mut noerror = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    noerror[2] |= 0x80;
    let mut nxdomain = noerror.clone();
    nxdomain[3] |= 3;
    let mut truncated = noerror.clone();
    truncated[2] |= 0x02;
    let mut badvers = noerror.clone();
    badvers[11] = 1;
    badvers.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);

    record_query_response_metric(&observation, &noerror, &metrics);
    record_query_response_metric(&observation, &nxdomain, &metrics);
    record_query_response_metric(&observation, &truncated, &metrics);
    record_query_response_metric(&observation, &badvers, &metrics);
    record_query_response_metric(&non_query_observation, &truncated, &metrics);

    assert_eq!(metrics.snapshot().queries_truncated, 1);
    assert_eq!(metrics.snapshot().nsec3_iterations_exceed_cap, 0);
    let rcodes = metrics.query_rcode_counts();
    assert_eq!(rcodes.get(&0), Some(&2));
    assert_eq!(rcodes.get(&3), Some(&1));
    assert_eq!(rcodes.get(&16), Some(&1));
    assert_eq!(
        metrics
            .query_latency_histograms()
            .get(&QueryLatencyCategory::UdpDirect)
            .map(QueryLatencyHistogram::count),
        Some(4)
    );
}

#[test]
fn query_metrics_count_zone_response_rcodes_for_configured_zone_only() {
    let zones = ZoneStore::new();
    let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(active_origin, Some(1), Vec::new()));
    let metrics = RuntimeMetrics::new();
    let in_zone = observe_query_metrics(
        &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );
    let outside = observe_query_metrics(
        &query(b"\x07outside\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );
    let mut noerror = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    noerror[2] |= 0x80;
    let mut nxdomain = noerror.clone();
    nxdomain[3] |= 3;

    record_query_response_metric(&in_zone, &noerror, &metrics);
    record_query_response_metric(&in_zone, &nxdomain, &metrics);
    record_query_response_metric(&outside, &noerror, &metrics);

    let zone_rcodes = metrics.zone_query_rcode_counts();
    let zone_key = DomainName::from_absolute_str("example.test.")
        .unwrap()
        .canonical_key();
    assert_eq!(zone_rcodes.get(&(zone_key.clone(), 0)), Some(&1));
    assert_eq!(zone_rcodes.get(&(zone_key.clone(), 3)), Some(&1));
    assert!(!zone_rcodes.contains_key(&("outside.test.".to_owned(), 0)));
}

#[test]
fn zone_store_publishes_zone_image_for_active_snapshot() {
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            DomainName::from_absolute_str("www.example.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 10].to_vec()],
        )],
    ));
    let published = zones
        .find_published_zone(&DomainName::from_absolute_str("www.example.test.").unwrap())
        .expect("published zone");
    assert_eq!(published.origin(), &origin);
    assert_eq!(published.serial(), Some(1));
    let first = published.active_zone_image_ref();
    let second = published.active_zone_image_ref();

    assert!(std::ptr::eq(first, second));
}

#[test]
fn zone_store_replaces_published_zone_image_for_new_snapshot() {
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            DomainName::from_absolute_str("www.example.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 10].to_vec()],
        )],
    ));
    let old_published = zones
        .find_published_zone(&DomainName::from_absolute_str("www.example.test.").unwrap())
        .expect("old published zone");
    let old_snapshot = zones
        .exact_snapshot_for_transfer(&origin)
        .expect("old snapshot");
    let old_image = old_published.active_zone_image_ref();

    zones.insert_snapshot(ZoneSnapshot::active(
        origin.clone(),
        Some(2),
        vec![Rrset::new(
            DomainName::from_absolute_str("www.example.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 11].to_vec()],
        )],
    ));
    let new_published = zones
        .find_published_zone(&DomainName::from_absolute_str("www.example.test.").unwrap())
        .expect("new published zone");
    let new_snapshot = zones
        .exact_snapshot_for_transfer(&origin)
        .expect("new snapshot");
    let new_image = new_published.active_zone_image_ref();
    let new_image_again = new_published.active_zone_image_ref();

    assert_eq!(new_published.origin(), &origin);
    assert_eq!(new_published.serial(), Some(2));
    assert!(!Arc::ptr_eq(
        old_snapshot.snapshot_arc_for_transfer(),
        new_snapshot.snapshot_arc_for_transfer()
    ));
    assert!(!std::ptr::eq(old_image, new_image));
    assert!(std::ptr::eq(new_image, new_image_again));
}

#[test]
fn dns_cookie_prefix_metrics_use_rrl_prefixes_and_evict_at_cap() {
    let metrics = RuntimeMetrics::new_with_settings(
        1,
        DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
        false,
        MetricsHotPathDetail::Full,
    );
    let prefix_settings = cookie_prefix_metrics_for_test();

    metrics.record_dns_cookie_status(
        DnsCookieRequestStatus::ClientCookieOnly,
        "192.0.2.10".parse().unwrap(),
        prefix_settings,
    );
    metrics.record_dns_cookie_badcookie_for_source("192.0.2.10".parse().unwrap(), prefix_settings);
    metrics.record_dns_cookie_status(
        DnsCookieRequestStatus::ValidServerCookie,
        "198.51.100.25".parse().unwrap(),
        prefix_settings,
    );

    let samples = metrics.dns_cookie_prefix_counts();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].0.to_string(), "198.51.100.0/24");
    assert_eq!(samples[0].1.valid_server, 1);
}

#[test]
fn query_metrics_count_cname_termination_causes_for_queries_only() {
    let metrics = RuntimeMetrics::new();
    let observation = QueryMetricObservation {
        is_query: true,
        transport: Transport::Udp,
        started_at: std::time::Instant::now(),
        cookie_validated: false,
        zone_key: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let non_query_observation = QueryMetricObservation {
        is_query: false,
        transport: Transport::Udp,
        started_at: std::time::Instant::now(),
        cookie_validated: false,
        zone_key: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let chain_limit = LookupMetrics {
        termination: Some(LookupTermination::CnameChainLimit),
        nsec3_iterations_exceeded: false,
        zone_image_used: true,
        zone_image_direct_answer: false,
        zone_image_failure_reason: None,
    };
    let loop_detected = LookupMetrics {
        termination: Some(LookupTermination::CnameLoop),
        nsec3_iterations_exceeded: false,
        zone_image_used: true,
        zone_image_direct_answer: false,
        zone_image_failure_reason: None,
    };

    record_query_lookup_metrics(&observation, chain_limit, &metrics);
    record_query_lookup_metrics(&observation, loop_detected, &metrics);
    record_query_lookup_metrics(&non_query_observation, chain_limit, &metrics);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.queries_cname_chain_limit, 1);
    assert_eq!(snapshot.queries_cname_loop, 1);
}

#[test]
fn query_metrics_count_nsec3_cap_from_lookup_observation_only() {
    let metrics = RuntimeMetrics::new();
    let observation = QueryMetricObservation {
        is_query: true,
        transport: Transport::Udp,
        started_at: std::time::Instant::now(),
        cookie_validated: false,
        zone_key: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let non_query_observation = QueryMetricObservation {
        is_query: false,
        transport: Transport::Udp,
        started_at: std::time::Instant::now(),
        cookie_validated: false,
        zone_key: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let over_cap = LookupMetrics {
        termination: None,
        nsec3_iterations_exceeded: true,
        zone_image_used: true,
        zone_image_direct_answer: false,
        zone_image_failure_reason: None,
    };

    record_query_lookup_metrics(&observation, over_cap, &metrics);
    record_query_lookup_metrics(&non_query_observation, over_cap, &metrics);

    assert_eq!(metrics.snapshot().nsec3_iterations_exceed_cap, 1);
}

#[test]
fn query_metrics_count_zone_image_serve_hits_and_failures() {
    let metrics = RuntimeMetrics::new();
    let observation = QueryMetricObservation {
        is_query: true,
        transport: Transport::Udp,
        started_at: std::time::Instant::now(),
        cookie_validated: false,
        zone_key: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let zone_image_hit = LookupMetrics {
        termination: None,
        nsec3_iterations_exceeded: false,
        zone_image_used: true,
        zone_image_direct_answer: true,
        zone_image_failure_reason: None,
    };
    let zone_image_semantic_hit = LookupMetrics {
        termination: None,
        nsec3_iterations_exceeded: false,
        zone_image_used: true,
        zone_image_direct_answer: false,
        zone_image_failure_reason: None,
    };
    let failure = LookupMetrics {
        termination: None,
        nsec3_iterations_exceeded: false,
        zone_image_used: false,
        zone_image_direct_answer: false,
        zone_image_failure_reason: Some(ZoneImageServeFailureReason::ResponseBuildFailed),
    };

    record_query_lookup_metrics(&observation, zone_image_hit, &metrics);
    record_query_lookup_metrics(&observation, zone_image_semantic_hit, &metrics);
    record_query_lookup_metrics(&observation, failure, &metrics);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.zone_image_serve_hits, 2);
    assert_eq!(snapshot.zone_image_serve_direct_hits, 1);
    assert_eq!(snapshot.zone_image_serve_semantic_hits, 1);
    assert_eq!(snapshot.zone_image_serve_failures, 1);
    assert_eq!(
        snapshot.zone_image_serve_failure_reasons
            [ZoneImageServeFailureReason::ResponseBuildFailed.metric_index()],
        1
    );
}

#[test]
fn query_latency_histogram_uses_configured_buckets() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = RuntimeMetrics::new_with_settings(
        DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
        vec![0.001, 0.01],
        false,
        MetricsHotPathDetail::Full,
    );

    metrics.record_query_latency(
        QueryLatencyCategory::UdpDirect,
        std::time::Duration::from_micros(1_500),
    );

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );

    assert!(body.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"udp_direct\",le=\"0.001\"} 0"
        ));
    assert!(body.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"udp_direct\",le=\"0.01\"} 1"
        ));
    assert!(!body.contains("le=\"0.00025\""));
}

#[test]
fn opt_in_pipeline_metrics_report_cache_planning_counters() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = RuntimeMetrics::new_with_settings(
        DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
        vec![0.001, 0.01],
        true,
        MetricsHotPathDetail::Full,
    );

    metrics.record_query_pipeline_latency(
        QueryPipelineStage::Compose,
        QueryLatencyCategory::UdpDirect,
        std::time::Duration::from_micros(1_500),
    );
    metrics.record_response_cache_candidate(ResponseCacheCandidateCategory::Direct);
    metrics.record_response_cache_ineligible(ResponseCacheIneligibleReason::Cookie);

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );

    assert!(body.contains(
            "oxidedns_query_pipeline_duration_seconds_bucket{stage=\"compose\",query_category=\"udp_direct\",le=\"0.001\"} 0"
        ));
    assert!(body.contains(
            "oxidedns_query_pipeline_duration_seconds_bucket{stage=\"compose\",query_category=\"udp_direct\",le=\"0.01\"} 1"
        ));
    assert!(body.contains("oxidedns_response_cache_candidate_total{category=\"direct\"} 1"));
    assert!(body.contains("oxidedns_response_cache_ineligible_total{reason=\"cookie\"} 1"));
}

#[test]
fn pipeline_metrics_are_absent_by_default() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = RuntimeMetrics::new();

    metrics.record_response_cache_candidate(ResponseCacheCandidateCategory::Direct);
    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );

    assert!(!body.contains("oxidedns_query_pipeline_duration_seconds"));
    assert!(!body.contains("oxidedns_response_cache_candidate_total"));
}

#[test]
fn udp_mmsg_and_worker_metrics_are_reported() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = RuntimeMetrics::new();
    metrics.record_udp_mmsg_stats(super::std_udp_mmsg::StdUdpMmsgStats {
        receive_syscalls: 3,
        received_datagrams: 30,
        send_syscalls: 4,
        sent_datagrams: 28,
        send_partial_syscalls: 1,
        send_wouldblock_retries: 2,
    });
    metrics.record_udp_worker_receive_batch(1, 17);
    metrics.record_udp_worker_send_batch(1, 16);

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );

    assert!(body.contains("oxidedns_udp_mmsg_receive_syscalls_total 3"));
    assert!(body.contains("oxidedns_udp_mmsg_received_datagrams_total 30"));
    assert!(body.contains("oxidedns_udp_mmsg_send_syscalls_total 4"));
    assert!(body.contains("oxidedns_udp_mmsg_sent_datagrams_total 28"));
    assert!(body.contains("oxidedns_udp_mmsg_send_partial_syscalls_total 1"));
    assert!(body.contains("oxidedns_udp_mmsg_send_wouldblock_retries_total 2"));
    assert!(body.contains("oxidedns_udp_worker_received_datagrams_total{worker=\"1\"} 17"));
    assert!(body.contains("oxidedns_udp_worker_sent_datagrams_total{worker=\"1\"} 16"));
    assert!(!body.contains("oxidedns_udp_worker_sent_datagrams_total{worker=\"2\"}"));
}

#[test]
fn hot_path_detail_off_suppresses_udp_packet_counters() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = RuntimeMetrics::new_with_settings(
        DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
        DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
        false,
        MetricsHotPathDetail::Off,
    );
    metrics.record_query_received();
    metrics.record_udp_receive_batch(10);
    metrics.record_udp_send_batch(9);
    metrics.record_udp_mmsg_stats(super::std_udp_mmsg::StdUdpMmsgStats {
        receive_syscalls: 3,
        received_datagrams: 30,
        send_syscalls: 4,
        sent_datagrams: 28,
        send_partial_syscalls: 1,
        send_wouldblock_retries: 2,
    });
    metrics.record_udp_worker_receive_batch(1, 17);
    metrics.record_udp_worker_send_batch(1, 16);
    metrics.record_zone_image_serve_hit();
    metrics.record_zone_image_serve_direct_hit();
    metrics.record_zone_image_serve_semantic_hit();
    metrics.record_zone_image_serve_failure();
    metrics
        .record_zone_image_serve_failure_reason(ZoneImageServeFailureReason::ResponseBuildFailed);

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );

    assert!(body.contains("oxidedns_queries_received_total 0"));
    assert!(body.contains("oxidedns_udp_receive_batches_total 0"));
    assert!(body.contains("oxidedns_udp_received_datagrams_total 0"));
    assert!(body.contains("oxidedns_udp_send_batches_total 0"));
    assert!(body.contains("oxidedns_udp_sent_datagrams_total 0"));
    assert!(body.contains("oxidedns_udp_mmsg_receive_syscalls_total 0"));
    assert!(body.contains("oxidedns_zone_image_serve_hits_total 0"));
    assert!(body.contains("oxidedns_zone_image_serve_direct_hits_total 0"));
    assert!(body.contains("oxidedns_zone_image_serve_semantic_hits_total 0"));
    assert!(body.contains("oxidedns_zone_image_serve_failures_total 0"));
    assert!(body.contains(
        "oxidedns_zone_image_serve_failures_by_reason_total{reason=\"response_build_failed\"} 0"
    ));
    assert!(!body.contains("oxidedns_udp_worker_received_datagrams_total{worker=\"1\"}"));
    assert!(!body.contains("oxidedns_udp_worker_sent_datagrams_total{worker=\"1\"}"));
}

#[test]
fn rrl_limiter_slips_udp_query_responses() {
    let config = RrlConfig {
        positive_per_second: 1,
        slip: 2,
        ..RrlConfig::default()
    };
    let metrics = RuntimeMetrics::new();
    let limiter = RrlLimiter::from_config(&config, metrics.clone());
    let source = "192.0.2.1".parse().unwrap();
    let response = positive_query_response();

    assert!(matches!(
        limiter.apply(source, response.clone()),
        RrlDecision::Send(_)
    ));
    assert!(matches!(
        limiter.apply(source, response.clone()),
        RrlDecision::Drop
    ));
    let RrlDecision::Send(truncated) = limiter.apply(source, response) else {
        panic!("third limited response should slip as TC=1");
    };

    let header = Header::parse(&truncated).unwrap();
    assert_ne!(header.flags & 0x0200, 0);
    assert_eq!(header.qdcount, 1);
    assert_eq!(header.ancount, 0);
    assert_eq!(header.nscount, 0);
    assert_eq!(header.arcount, 0);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.rrl_subject, 3);
    assert_eq!(snapshot.rrl_dropped, 1);
    assert_eq!(snapshot.rrl_truncated, 1);
    assert_eq!(snapshot.rrl_tracked_keys, 1);
}

#[test]
fn rrl_periodic_summary_reports_aggregate_deltas() {
    let config = RrlConfig {
        positive_per_second: 0,
        slip: 2,
        ..RrlConfig::default()
    };
    let metrics = RuntimeMetrics::new();
    let limiter = RrlLimiter::from_config(&config, metrics.clone());
    let previous = metrics.snapshot();
    let source = "192.0.2.1".parse().unwrap();

    assert!(matches!(
        limiter.apply(source, positive_query_response()),
        RrlDecision::Drop
    ));
    assert!(matches!(
        limiter.apply(source, positive_query_response()),
        RrlDecision::Send(_)
    ));

    let summary = RrlSummary::from_snapshots(
        previous,
        metrics.snapshot(),
        limiter.rate_limited_key_count(),
    );
    assert_eq!(
        summary,
        RrlSummary {
            dropped_responses: 1,
            truncated_responses: 1,
            rate_limited_keys: 1,
            total_dropped_responses: 1,
            total_truncated_responses: 1,
        }
    );

    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    log_rrl_summary(summary, std::time::Duration::from_secs(60));

    assert!(captured.contains_all(&[
        "RRL periodic summary",
        "category=\"rrl\"",
        "event=\"rrl_periodic_summary\"",
        "dropped_responses=1",
        "truncated_responses=1",
        "rate_limited_keys=1",
    ]));
}

#[test]
fn rrl_allowlist_exempts_sources_from_accounting() {
    let config = RrlConfig {
        positive_per_second: 0,
        allowlist: vec!["192.0.2.0/24".to_owned()],
        ..RrlConfig::default()
    };
    let metrics = RuntimeMetrics::new();
    let limiter = RrlLimiter::from_config(&config, metrics.clone());
    let source = "192.0.2.99".parse().unwrap();

    assert!(matches!(
        limiter.apply(source, positive_query_response()),
        RrlDecision::Send(_)
    ));
    assert!(matches!(
        limiter.apply(source, positive_query_response()),
        RrlDecision::Send(_)
    ));

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.rrl_subject, 0);
    assert_eq!(snapshot.rrl_dropped, 0);
    assert_eq!(snapshot.rrl_tracked_keys, 0);
}

#[test]
fn notify_log_limiter_suppresses_repeats_and_summarizes() {
    let limiter = NotifyLogLimiter::new(std::time::Duration::from_secs(60));
    let zone = DomainName::from_absolute_str("example.test.").unwrap();
    let source = "192.0.2.10".parse().unwrap();
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    limiter.log_unauthorized(source, &zone);
    limiter.log_unauthorized(source, &zone);
    limiter.log_tsig_failure(source, &zone, &TsigError::MissingTsig);
    limiter.log_tsig_failure(source, &zone, &TsigError::MissingTsig);

    assert!(captured.contains_all(&[
        "unauthorized NOTIFY discarded",
        "category=\"notify\"",
        "event=\"notify_unauthorized_discard\"",
        "peer_ip=192.0.2.10",
        "source_prefix=192.0.2.0/24",
        "zone=example.test.",
    ]));
    assert!(captured.contains_all(&[
        "rejected NOTIFY with invalid TSIG",
        "category=\"notify\"",
        "event=\"notify_tsig_failure\"",
        "peer_ip=192.0.2.10",
        "source_prefix=192.0.2.0/24",
        "zone=example.test.",
    ]));

    let summary = limiter.take_summary();
    assert_eq!(
        summary,
        NotifyLogSummary {
            suppressed_unauthorized: 1,
            suppressed_tsig_failures: 1,
            distinct_source_prefixes: 1,
            total_suppressed: 2,
        }
    );
    log_notify_log_summary(summary, std::time::Duration::from_secs(60));
    assert!(captured.contains_all(&[
        "NOTIFY log rate-limit summary",
        "category=\"notify\"",
        "event=\"notify_log_rate_limit_summary\"",
        "suppressed_unauthorized=1",
        "suppressed_tsig_failures=1",
        "distinct_source_prefixes=1",
        "total_suppressed=2",
    ]));
}

#[test]
fn rrl_limiter_evicts_least_recent_key_at_capacity() {
    let config = RrlConfig {
        positive_per_second: 0,
        slip: 0,
        max_keys: 1,
        ipv4_prefix_len: 32,
        ..RrlConfig::default()
    };
    let metrics = RuntimeMetrics::new();
    let limiter = RrlLimiter::from_config(&config, metrics.clone());

    assert!(matches!(
        limiter.apply("192.0.2.1".parse().unwrap(), positive_query_response()),
        RrlDecision::Drop
    ));
    assert!(matches!(
        limiter.apply("192.0.2.2".parse().unwrap(), positive_query_response()),
        RrlDecision::Drop
    ));

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.rrl_subject, 2);
    assert_eq!(snapshot.rrl_dropped, 2);
    assert_eq!(snapshot.rrl_key_evictions, 1);
    assert_eq!(snapshot.rrl_tracked_keys, 1);
}

#[test]
fn rrl_response_categories_follow_srs_buckets() {
    assert_eq!(
        response_category(&positive_query_response()),
        Some(RrlCategory::Positive)
    );
    assert_eq!(
        response_category(&rcode_query_response(3)),
        Some(RrlCategory::NxDomain)
    );
    assert_eq!(
        response_category(&rcode_query_response(0)),
        Some(RrlCategory::NoData)
    );
    assert_eq!(
        response_category(&referral_query_response()),
        Some(RrlCategory::Referral)
    );
    assert_eq!(
        response_category(&rcode_query_response(2)),
        Some(RrlCategory::Error)
    );
    assert_eq!(response_category(&notify_response(0x1234)), None);
}

#[test]
fn rrl_truncated_response_preserves_question_and_opt() {
    let response = query_response_with_opt();
    let truncated = rrl_truncated_response(&response);

    let original_header = Header::parse(&response).unwrap();
    let original_question_end = response_question_end(&response, &original_header).unwrap();
    assert_eq!(
        &truncated[12..original_question_end],
        &response[12..original_question_end]
    );
    let header = Header::parse(&truncated).unwrap();
    assert_ne!(header.flags & 0x0200, 0);
    assert_eq!(header.ancount, 0);
    assert_eq!(header.nscount, 0);
    assert_eq!(header.arcount, 1);
    assert_eq!(
        response_opt_record(&truncated, &header),
        response_opt_record(&response, &original_header)
    );
}

#[tokio::test]
async fn udp_query_records_cname_chain_limit_metric() {
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("a.example.test.").unwrap(),
                RecordType::Cname as u16,
                1,
                300,
                vec![
                    DomainName::from_absolute_str("b.example.test.")
                        .unwrap()
                        .to_wire(),
                ],
            ),
            Rrset::new(
                DomainName::from_absolute_str("b.example.test.").unwrap(),
                RecordType::Cname as u16,
                1,
                300,
                vec![
                    DomainName::from_absolute_str("c.example.test.")
                        .unwrap()
                        .to_wire(),
                ],
            ),
        ],
    ));
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let server_metrics = metrics.clone();
    let server = tokio::spawn(serve_udp(
        socket,
        zones,
        UdpServerSettings {
            max_udp_payload: 1232,
            udp_batch_size: 1,
            udp_backend: UdpBackend::Std,
            udp_runtime: UdpRuntime::Tokio,
            udp_idle_strategy: Default::default(),
            xdp: XdpConfig::default(),
            max_cname_chain: 1,
            nsec3_max_iterations: 100,
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Minimal,
            nsid: Vec::new(),
            chaos_version: String::new(),
            chaos_hostname: String::new(),
            dns_cookie_secrets: dns_cookie_secret_store_for_test(),
            dns_cookie: dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics: cookie_prefix_metrics_for_test(),
            notify_authority: NotifyAuthority::default(),
            notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx: notify_refresh_tx(),
            notify_log_limiter: notify_log_limiter_for_test(),
            metrics: server_metrics,
            rrl: RrlLimiter::from_config(&RrlConfig::default(), metrics.clone()),
        },
    ));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(
            &query(b"\x01a\x07example\x04test\x00", RecordType::A as u16, 1),
            server_addr,
        )
        .await
        .unwrap();
    let mut response = [0u8; 512];
    let len = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.recv(&mut response),
    )
    .await
    .expect("UDP response")
    .unwrap();
    server.abort();

    let header = Header::parse(&response[..len]).unwrap();
    assert_eq!(
        response_rcode(&response[..len], &header),
        Rcode::ServFail as u16
    );
    assert_ne!(header.flags & 0x0400, 0);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
    assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
    assert!(len > 12);
    assert!(captured.contains_all(&[
        "CNAME chain limit reached",
        "qname=a.example.test.",
        "zone=example.test.",
        "reason=\"cname_chain_limit\"",
    ]));
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.queries_received, 1);
    assert_eq!(snapshot.queries_cname_chain_limit, 1);
    assert_eq!(snapshot.queries_cname_loop, 0);
}

#[tokio::test]
async fn std_udp_batch_io_drains_ready_datagrams_up_to_batch_size() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for byte in [1_u8, 2, 3, 4] {
        client.send_to(&[byte], server_addr).await.unwrap();
    }

    let mut packet_io = StdUdpBatchIo::new(socket, 3);
    let first_payloads = {
        let batch = tokio::time::timeout(std::time::Duration::from_secs(1), packet_io.recv_batch())
            .await
            .expect("first UDP batch")
            .unwrap();
        batch
            .iter()
            .map(|packet| packet.payload().to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(first_payloads, vec![vec![1], vec![2], vec![3]]);

    let second_payloads = {
        let batch = tokio::time::timeout(std::time::Duration::from_secs(1), packet_io.recv_batch())
            .await
            .expect("second UDP batch")
            .unwrap();
        batch
            .iter()
            .map(|packet| packet.payload().to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(second_payloads, vec![vec![4]]);
}

#[tokio::test]
async fn std_udp_reuseport_binds_multiple_workers_to_one_effective_port() {
    let listeners = match bind_udp_listeners(
        "127.0.0.1:0".parse().unwrap(),
        UdpBackend::Std,
        &XdpConfig::default(),
        2,
        Some(&[0, 1]),
        None,
        None,
        None,
    )
    .await
    {
        Ok(listeners) => listeners,
        Err(RuntimeError::BindUdp { source, .. })
            if source.kind() == std::io::ErrorKind::Unsupported =>
        {
            return;
        }
        Err(error) => panic!("unexpected SO_REUSEPORT bind error: {error:?}"),
    };

    assert_eq!(listeners.len(), 2);
    let mut observed = Vec::new();
    for listener in listeners {
        match listener {
            BoundUdpListener::Std {
                socket,
                worker_id,
                worker_count,
                cpu_affinity,
            } => observed.push((
                socket.local_addr().unwrap(),
                worker_id,
                worker_count,
                cpu_affinity,
            )),
            #[cfg(feature = "af-xdp")]
            BoundUdpListener::AfXdp(_) => panic!("standard backend must not bind AF_XDP"),
        }
    }

    assert_eq!(observed[0].0, observed[1].0);
    assert_eq!(observed[0].1, 0);
    assert_eq!(observed[1].1, 1);
    assert_eq!(observed[0].2, 2);
    assert_eq!(observed[1].2, 2);
    assert_eq!(observed[0].3, Some(0));
    assert_eq!(observed[1].3, Some(1));
}

#[tokio::test]
async fn udp_batch_listener_records_packet_io_metrics() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let mut settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
    settings.udp_batch_size = 4;
    let server = tokio::spawn(serve_udp(socket, zones, settings));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);

    for _ in 0..3 {
        client.send_to(&request, server_addr).await.unwrap();
    }
    for _ in 0..3 {
        let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("UDP response");
        assert_eq!(Header::parse(&response).unwrap().ancount, 1);
    }
    server.abort();

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.udp_received_datagrams, 3);
    assert_eq!(snapshot.udp_sent_datagrams, 3);
    assert!((1..=3).contains(&snapshot.udp_receive_batches));
    assert!((1..=3).contains(&snapshot.udp_send_batches));
}

#[tokio::test]
async fn udp_af_xdp_backend_selection_has_clean_fallback_or_preflight_error() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut settings = udp_settings_for_test(metrics, RrlConfig::default());
    settings.udp_backend = UdpBackend::AfXdp;

    let error = serve_udp(socket, zones, settings)
        .await
        .expect_err("AF_XDP backend requires feature support and interface configuration");

    #[cfg(not(feature = "af-xdp"))]
    match error {
        RuntimeError::UdpBackendUnavailable { backend, reason } => {
            assert_eq!(backend, "af_xdp");
            assert!(reason.contains("without the af-xdp feature"));
        }
        other => panic!("unexpected AF_XDP backend error: {other:?}"),
    }
    #[cfg(feature = "af-xdp")]
    match error {
        RuntimeError::Udp(error) => {
            assert!(error.to_string().contains("xdp.interface"));
        }
        other => panic!("unexpected AF_XDP backend error: {other:?}"),
    }
}

#[test]
fn cname_loop_warning_log_contains_operator_fields() {
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let zone = ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("a.example.test.").unwrap(),
                RecordType::Cname as u16,
                1,
                300,
                vec![
                    DomainName::from_absolute_str("b.example.test.")
                        .unwrap()
                        .to_wire(),
                ],
            ),
            Rrset::new(
                DomainName::from_absolute_str("b.example.test.").unwrap(),
                RecordType::Cname as u16,
                1,
                300,
                vec![
                    DomainName::from_absolute_str("a.example.test.")
                        .unwrap()
                        .to_wire(),
                ],
            ),
        ],
    );

    let lookup = zone.offline_oracle().lookup(
        &DomainName::from_absolute_str("a.example.test.").unwrap(),
        RecordType::A as u16,
        1,
    );

    assert_eq!(lookup.rcode, Rcode::ServFail);
    assert_eq!(lookup.termination, Some(LookupTermination::CnameLoop));
    assert!(captured.contains_all(&[
        "CNAME chain loop detected",
        "qname=a.example.test.",
        "zone=example.test.",
        "reason=\"cname_loop\"",
        "looping_target=a.example.test.",
    ]));
}

#[tokio::test]
async fn udp_rrl_slips_and_drops_limited_query_responses() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![Rrset::new(
            DomainName::from_absolute_str("www.example.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 10].to_vec()],
        )],
    ));
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let rrl_config = RrlConfig {
        positive_per_second: 1,
        slip: 2,
        ..RrlConfig::default()
    };
    let server_metrics = metrics.clone();
    let server = tokio::spawn(serve_udp(
        socket,
        zones,
        UdpServerSettings {
            max_udp_payload: 1232,
            udp_batch_size: 1,
            udp_backend: UdpBackend::Std,
            udp_runtime: UdpRuntime::Tokio,
            udp_idle_strategy: Default::default(),
            xdp: XdpConfig::default(),
            max_cname_chain: 8,
            nsec3_max_iterations: 100,
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Minimal,
            nsid: Vec::new(),
            chaos_version: String::new(),
            chaos_hostname: String::new(),
            dns_cookie_secrets: dns_cookie_secret_store_for_test(),
            dns_cookie: dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics: cookie_prefix_metrics_for_test(),
            notify_authority: NotifyAuthority::default(),
            notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx: notify_refresh_tx(),
            notify_log_limiter: notify_log_limiter_for_test(),
            metrics: server_metrics,
            rrl: RrlLimiter::from_config(&rrl_config, metrics.clone()),
        },
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);

    client.send_to(&query, server_addr).await.unwrap();
    let first = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
        .await
        .expect("first response");
    client.send_to(&query, server_addr).await.unwrap();
    let dropped = recv_udp_with_timeout(&client, std::time::Duration::from_millis(50)).await;
    client.send_to(&query, server_addr).await.unwrap();
    let slipped = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
        .await
        .expect("slipped truncated response");
    server.abort();

    assert_eq!(Header::parse(&first).unwrap().ancount, 1);
    assert!(dropped.is_none());
    let slipped_header = Header::parse(&slipped).unwrap();
    assert_ne!(slipped_header.flags & 0x0200, 0);
    assert_eq!(slipped_header.ancount, 0);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.rrl_subject, 3);
    assert_eq!(snapshot.rrl_dropped, 1);
    assert_eq!(snapshot.rrl_truncated, 1);
    assert_eq!(snapshot.queries_truncated, 1);
}

#[tokio::test]
async fn udp_tsig_authenticated_query_bypasses_rrl_and_signs_response() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let rrl_config = RrlConfig {
        positive_per_second: 0,
        slip: 0,
        ..RrlConfig::default()
    };
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[tsig_keys]]
                name = "query-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "query-key."
            "#,
    )
    .unwrap();
    let key = TsigKey::from_base64("query-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
    let signed_query = key
        .sign_request(
            &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
            current_unix_time(),
            DEFAULT_TSIG_FUDGE_SECS,
        )
        .unwrap();
    let server_metrics = metrics.clone();
    let server = tokio::spawn(serve_udp(
        socket,
        zones,
        UdpServerSettings {
            max_udp_payload: 1232,
            udp_batch_size: 1,
            udp_backend: UdpBackend::Std,
            udp_runtime: UdpRuntime::Tokio,
            udp_idle_strategy: Default::default(),
            xdp: XdpConfig::default(),
            max_cname_chain: 8,
            nsec3_max_iterations: 100,
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Minimal,
            nsid: Vec::new(),
            chaos_version: String::new(),
            chaos_hostname: String::new(),
            dns_cookie_secrets: dns_cookie_secret_store_for_test(),
            dns_cookie: dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics: cookie_prefix_metrics_for_test(),
            notify_authority: NotifyAuthority::from_config(&config),
            notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx: notify_refresh_tx(),
            notify_log_limiter: notify_log_limiter_for_test(),
            metrics: server_metrics,
            rrl: RrlLimiter::from_config(&rrl_config, metrics.clone()),
        },
    ));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&signed_query.message, server_addr)
        .await
        .unwrap();
    let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
        .await
        .expect("signed UDP response");
    server.abort();

    let verified = key
        .verify_response(&response, &signed_query.mac, current_unix_time())
        .expect("signed UDP query response verifies");
    let header = Header::parse(&verified.message).unwrap();
    assert_eq!(
        response_rcode(&verified.message, &header),
        Rcode::NoError as u16
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.queries_received, 1);
    assert_eq!(snapshot.rrl_subject, 0);
    assert_eq!(snapshot.rrl_dropped, 0);
}

#[tokio::test]
async fn udp_dns_cookie_client_cookie_only_returns_cookie_option() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let server = tokio::spawn(serve_udp(
        socket,
        zones,
        udp_settings_for_test(metrics.clone(), RrlConfig::default()),
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = cookie_query(&[1, 2, 3, 4, 5, 6, 7, 8]);

    client.send_to(&request, server_addr).await.unwrap();
    let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
        .await
        .expect("cookie response");
    server.abort();

    let cookie = response_cookie_option(&response).expect("COOKIE response option");
    assert_eq!(&cookie[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(cookie.len(), 24);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.dns_cookie_client_only, 1);
    assert_eq!(snapshot.dns_cookie_badcookie, 0);
}

#[tokio::test]
async fn udp_strict_dns_cookie_policy_returns_badcookie_for_client_cookie_only() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let mut settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
    settings.dns_cookie = dns_cookie_settings_for_test(DnsCookiePolicy::Strict);
    let server = tokio::spawn(serve_udp(socket, zones, settings));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = cookie_query(&[1, 2, 3, 4, 5, 6, 7, 8]);

    client.send_to(&request, server_addr).await.unwrap();
    let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
        .await
        .expect("BADCOOKIE response");
    server.abort();

    let header = Header::parse(&response).unwrap();
    assert_eq!(response_rcode(&response, &header), Rcode::BadCookie as u16);
    assert_eq!(header.ancount, 0);
    assert!(response_cookie_option(&response).is_some());
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.dns_cookie_client_only, 1);
    assert_eq!(snapshot.dns_cookie_badcookie, 1);
}

#[tokio::test]
async fn udp_valid_dns_cookie_bypasses_rrl_accounting() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let rrl_config = RrlConfig {
        positive_per_second: 1,
        slip: 2,
        ..RrlConfig::default()
    };
    let server = tokio::spawn(serve_udp(
        socket,
        zones,
        udp_settings_for_test(metrics.clone(), rrl_config),
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let learning_query = cookie_query(&[1, 2, 3, 4, 5, 6, 7, 8]);

    client.send_to(&learning_query, server_addr).await.unwrap();
    let learned = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
        .await
        .expect("learning response");
    let valid_cookie = response_cookie_option(&learned).expect("learned cookie");
    let valid_query = cookie_query(&valid_cookie);

    for _ in 0..3 {
        client.send_to(&valid_query, server_addr).await.unwrap();
        let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("valid-cookie response should not be RRL dropped");
        assert_eq!(Header::parse(&response).unwrap().ancount, 1);
    }
    server.abort();

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.rrl_subject, 1);
    assert_eq!(snapshot.rrl_dropped, 0);
    assert_eq!(snapshot.rrl_truncated, 0);
    assert_eq!(snapshot.dns_cookie_client_only, 1);
    assert_eq!(snapshot.dns_cookie_valid_server, 3);
}

#[tokio::test]
async fn udp_invalid_dns_cookie_remains_rrl_subject() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let rrl_config = RrlConfig {
        positive_per_second: 1,
        slip: 2,
        ..RrlConfig::default()
    };
    let server = tokio::spawn(serve_udp(
        socket,
        zones,
        udp_settings_for_test(metrics.clone(), rrl_config),
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut invalid_cookie = vec![1, 2, 3, 4, 5, 6, 7, 8];
    invalid_cookie.extend_from_slice(&[0; 16]);
    let invalid_query = cookie_query(&invalid_cookie);

    client.send_to(&invalid_query, server_addr).await.unwrap();
    let first = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
        .await
        .expect("first invalid-cookie response");
    client.send_to(&invalid_query, server_addr).await.unwrap();
    let second = recv_udp_with_timeout(&client, std::time::Duration::from_millis(50)).await;
    server.abort();

    assert_eq!(Header::parse(&first).unwrap().ancount, 1);
    assert!(second.is_none());
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.rrl_subject, 2);
    assert_eq!(snapshot.rrl_dropped, 1);
    assert_eq!(snapshot.dns_cookie_invalid_server, 2);
    assert_eq!(snapshot.dns_cookie_badcookie, 0);
}

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
            notify_authority: NotifyAuthority::from_config(&config),
            refresh_tx: mpsc::channel(1).0.downgrade(),
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
            notify_authority: NotifyAuthority::from_config(&config),
            refresh_tx: mpsc::channel(1).0.downgrade(),
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
    assert!(plan.tsig_key.is_some());
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
    assert!(plan.tsig_key.is_some());
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

#[tokio::test]
async fn tcp_connection_serves_authoritative_response() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            ),
        ],
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(&frame_tcp_message(&query(
            b"\x03www\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        )))
        .await
        .unwrap();

    let mut length_prefix = [0u8; 2];
    client.read_exact(&mut length_prefix).await.unwrap();
    let response_len = u16::from_be_bytes(length_prefix) as usize;
    let mut response = vec![0u8; response_len];
    client.read_exact(&mut response).await.unwrap();
    drop(client);
    server.await.unwrap();

    assert_eq!(response[3] & 0x0f, 0);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
}

#[tokio::test]
async fn tcp_connection_serves_back_to_back_framed_queries() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("mail.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 20].to_vec()],
            ),
        ],
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let first = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let mut second = query(b"\x04mail\x07example\x04test\x00", RecordType::A as u16, 1);
    second[0..2].copy_from_slice(&0x5678u16.to_be_bytes());
    let mut pipelined = frame_tcp_message(&first);
    pipelined.extend_from_slice(&frame_tcp_message(&second));
    client.write_all(&pipelined).await.unwrap();

    let first_response = read_framed_tcp_response(&mut client).await;
    let second_response = read_framed_tcp_response(&mut client).await;
    drop(client);
    server.await.unwrap();

    assert_eq!(Header::parse(&first_response).unwrap().id, 0x1234);
    assert_eq!(Header::parse(&second_response).unwrap().id, 0x5678);
    assert_eq!(
        u16::from_be_bytes([first_response[6], first_response[7]]),
        1
    );
    assert_eq!(
        u16::from_be_bytes([second_response[6], second_response[7]]),
        1
    );
}

#[tokio::test]
async fn tcp_connection_processes_later_query_while_first_response_is_delayed() {
    let zones = active_example_zone();
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let query_hook: super::TcpQueryHook = {
        let first_started = first_started.clone();
        let release_first = release_first.clone();
        Arc::new(move |query_id| {
            let first_started = first_started.clone();
            let release_first = release_first.clone();
            Box::pin(async move {
                if query_id == 0x1234 {
                    first_started.notify_one();
                    release_first.notified().await;
                }
            })
        })
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection_with_query_hook(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
            Some(query_hook),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let first = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let mut second = first.clone();
    second[0..2].copy_from_slice(&0x5678u16.to_be_bytes());
    let mut pipelined = frame_tcp_message(&first);
    pipelined.extend_from_slice(&frame_tcp_message(&second));
    client.write_all(&pipelined).await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), first_started.notified())
        .await
        .expect("first TCP query should reach the test pause");

    let first_available_response = read_framed_tcp_response(&mut client).await;
    assert_eq!(Header::parse(&first_available_response).unwrap().id, 0x5678);
    assert_eq!(
        u16::from_be_bytes([first_available_response[6], first_available_response[7]]),
        1
    );

    release_first.notify_one();
    let delayed_response = read_framed_tcp_response(&mut client).await;
    drop(client);
    server.await.unwrap();

    assert_eq!(Header::parse(&delayed_response).unwrap().id, 0x1234);
    assert_eq!(
        u16::from_be_bytes([delayed_response[6], delayed_response[7]]),
        1
    );
}

#[tokio::test]
async fn tcp_connection_closes_when_inflight_limit_stays_saturated() {
    let zones = active_example_zone();
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let query_hook: super::TcpQueryHook = {
        let first_started = first_started.clone();
        let release_first = release_first.clone();
        Arc::new(move |query_id| {
            let first_started = first_started.clone();
            let release_first = release_first.clone();
            Box::pin(async move {
                if query_id == 0x1234 {
                    first_started.notify_one();
                    release_first.notified().await;
                }
            })
        })
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection_with_query_hook(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            1,
            std::time::Duration::from_millis(25),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
            Some(query_hook),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let first = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let mut second = first.clone();
    second[0..2].copy_from_slice(&0x5678u16.to_be_bytes());
    let mut pipelined = frame_tcp_message(&first);
    pipelined.extend_from_slice(&frame_tcp_message(&second));
    client.write_all(&pipelined).await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), first_started.notified())
        .await
        .expect("first TCP query should hold the only in-flight permit");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    release_first.notify_one();

    let first_response = read_framed_tcp_response(&mut client).await;
    assert_eq!(Header::parse(&first_response).unwrap().id, 0x1234);

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("saturated TCP connection should close without answering the queued query")
        .unwrap();
    assert_eq!(read, 0);

    server.await.unwrap();
}

#[tokio::test]
async fn tcp_connection_closes_after_idle_timeout() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection(
            stream,
            zones,
            std::time::Duration::from_millis(25),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("idle timeout should close the connection")
        .unwrap();

    assert_eq!(read, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_connection_closes_after_read_timeout_mid_frame() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_millis(25),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0, 1]).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("read timeout should close the connection")
        .unwrap();

    assert_eq!(read, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_write_times_out_when_backpressured() {
    let (mut writer, _reader) = tokio::io::duplex(1);
    let response = vec![0u8; 4096];

    let completed = write_tcp_message(&mut writer, &response, std::time::Duration::from_millis(25))
        .await
        .unwrap();

    assert!(!completed);
}

#[tokio::test]
async fn tcp_connection_closes_on_zero_length_frame() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0, 0]).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("zero-length frame should close the connection")
        .unwrap();

    assert_eq!(read, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_listener_closes_connections_over_global_limit() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let source_counts = Arc::new(Mutex::new(HashMap::new()));
    let server = tokio::spawn(serve_tcp(
        listener,
        zones,
        TcpServerSettings {
            max_udp_payload: 1232,
            max_cname_chain: 8,
            nsec3_max_iterations: 100,
            idle_timeout: std::time::Duration::from_secs(30),
            read_timeout: std::time::Duration::from_secs(30),
            write_timeout: std::time::Duration::from_secs(30),
            max_connections: 1,
            max_connections_per_source: None,
            max_inflight_queries_per_connection: 64,
            inflight_limit_timeout: std::time::Duration::from_secs(30),
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Minimal,
            nsid: Vec::new(),
            chaos_version: String::new(),
            chaos_hostname: String::new(),
            dns_cookie_secrets: dns_cookie_secret_store_for_test(),
            dns_cookie: dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics: cookie_prefix_metrics_for_test(),
            notify_authority: NotifyAuthority::default(),
            notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx: notify_refresh_tx(),
            notify_log_limiter: notify_log_limiter_for_test(),
            metrics: RuntimeMetrics::new(),
            active_connections: active.clone(),
            active_connections_by_source: source_counts.clone(),
        },
    ));

    let first = TcpStream::connect(addr).await.unwrap();
    for _ in 0..100 {
        if active.load(Ordering::Acquire) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(active.load(Ordering::Acquire), 1);

    let mut second = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), second.read(&mut byte))
        .await
        .expect("over-limit connection should close promptly")
        .unwrap();

    assert_eq!(read, 0);
    assert_eq!(active.load(Ordering::Acquire), 1);
    drop(first);
    server.abort();
}

#[tokio::test]
async fn tcp_listener_closes_connections_over_per_source_limit() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let source_counts = Arc::new(Mutex::new(HashMap::new()));
    let server = tokio::spawn(serve_tcp(
        listener,
        zones,
        TcpServerSettings {
            max_udp_payload: 1232,
            max_cname_chain: 8,
            nsec3_max_iterations: 100,
            idle_timeout: std::time::Duration::from_secs(30),
            read_timeout: std::time::Duration::from_secs(30),
            write_timeout: std::time::Duration::from_secs(30),
            max_connections: 8,
            max_connections_per_source: Some(1),
            max_inflight_queries_per_connection: 64,
            inflight_limit_timeout: std::time::Duration::from_secs(30),
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Minimal,
            nsid: Vec::new(),
            chaos_version: String::new(),
            chaos_hostname: String::new(),
            dns_cookie_secrets: dns_cookie_secret_store_for_test(),
            dns_cookie: dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics: cookie_prefix_metrics_for_test(),
            notify_authority: NotifyAuthority::default(),
            notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx: notify_refresh_tx(),
            notify_log_limiter: notify_log_limiter_for_test(),
            metrics: RuntimeMetrics::new(),
            active_connections: active.clone(),
            active_connections_by_source: source_counts.clone(),
        },
    ));

    let first = TcpStream::connect(addr).await.unwrap();
    let loopback = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    for _ in 0..100 {
        if active.load(Ordering::Acquire) == 1
            && source_counts.lock().unwrap().get(&loopback).copied() == Some(1)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(active.load(Ordering::Acquire), 1);

    let mut second = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), second.read(&mut byte))
        .await
        .expect("per-source over-limit connection should close promptly")
        .unwrap();

    assert_eq!(read, 0);
    assert_eq!(active.load(Ordering::Acquire), 1);
    assert_eq!(
        source_counts.lock().unwrap().get(&loopback).copied(),
        Some(1)
    );
    drop(first);

    for _ in 0..100 {
        if active.load(Ordering::Acquire) == 0
            && !source_counts.lock().unwrap().contains_key(&loopback)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(active.load(Ordering::Acquire), 0);
    assert!(!source_counts.lock().unwrap().contains_key(&loopback));

    let third = TcpStream::connect(addr).await.unwrap();
    for _ in 0..100 {
        if active.load(Ordering::Acquire) == 1
            && source_counts.lock().unwrap().get(&loopback).copied() == Some(1)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(active.load(Ordering::Acquire), 1);
    drop(third);
    server.abort();
}

async fn spawn_axfr_primary() -> std::net::SocketAddr {
    spawn_axfr_primary_with_serial(1).await
}

async fn spawn_xot_axfr_primary_with_serial(serial: u32) -> (std::net::SocketAddr, String) {
    let (cert_path, key_path) = write_self_signed_xot_cert_files();

    let certs =
        load_pem_certs(cert_path.to_str().expect("utf-8 cert path")).expect("load generated cert");
    let key = load_pem_private_key(
        "127.0.0.1:0".parse().unwrap(),
        key_path.to_str().expect("utf-8 key path"),
    )
    .expect("load generated key");
    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server tls config");
    config.alpn_protocols = vec![b"dot".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();

        let header = Header::parse(&query).unwrap();
        assert_eq!(query_qtype(&query), RecordType::Axfr as u16);
        let response = axfr_response(header.id, serial);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });

    (addr, cert_path.display().to_string())
}

async fn spawn_xot_axfr_primary_recording_query(
    serial: u32,
) -> (std::net::SocketAddr, String, Arc<Mutex<Option<Vec<u8>>>>) {
    let (cert_path, key_path) = write_self_signed_xot_cert_files();

    let certs =
        load_pem_certs(cert_path.to_str().expect("utf-8 cert path")).expect("load generated cert");
    let key = load_pem_private_key(
        "127.0.0.1:0".parse().unwrap(),
        key_path.to_str().expect("utf-8 key path"),
    )
    .expect("load generated key");
    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server tls config");
    config.alpn_protocols = vec![b"dot".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let observed_query = Arc::new(Mutex::new(None));
    let observed_query_for_task = observed_query.clone();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();

        let header = Header::parse(&query).unwrap();
        let request_mac = extract_query_tsig_mac(&query);
        observed_query_for_task
            .lock()
            .expect("observed query lock poisoned")
            .replace(query);

        let response = axfr_response(header.id, serial);
        let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let response = key
            .sign_response(
                &response,
                &request_mac,
                current_unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap()
            .message;
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });

    (addr, cert_path.display().to_string(), observed_query)
}

async fn spawn_xot_mtls_axfr_primary_with_serial(
    serial: u32,
    client_trust_anchor: &std::path::Path,
) -> (std::net::SocketAddr, String, mpsc::Receiver<()>) {
    let (cert_path, key_path) = write_self_signed_xot_cert_files();

    let certs =
        load_pem_certs(cert_path.to_str().expect("utf-8 cert path")).expect("load generated cert");
    let key = load_pem_private_key(
        "127.0.0.1:0".parse().unwrap(),
        key_path.to_str().expect("utf-8 key path"),
    )
    .expect("load generated key");
    let mut client_roots = RootCertStore::empty();
    for cert in load_pem_certs(
        client_trust_anchor
            .to_str()
            .expect("utf-8 client cert path"),
    )
    .expect("load generated client cert")
    {
        client_roots.add(cert).expect("add client trust anchor");
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .expect("client certificate verifier");
    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .expect("server tls config");
    config.alpn_protocols = vec![b"dot".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (query_seen_tx, query_seen_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        let mut length_prefix = [0u8; 2];
        if stream.read_exact(&mut length_prefix).await.is_err() {
            return;
        }
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }

        let header = Header::parse(&query).unwrap();
        assert_eq!(query_qtype(&query), RecordType::Axfr as u16);
        let _ = query_seen_tx.send(()).await;
        let response = axfr_response(header.id, serial);
        let _ = stream.write_all(&frame_tcp_message(&response)).await;
    });

    (addr, cert_path.display().to_string(), query_seen_rx)
}

async fn spawn_xot_primary_detecting_query(
    cert_dns_name: &str,
    negotiate_dot_alpn: bool,
) -> (std::net::SocketAddr, String, mpsc::Receiver<()>) {
    let (cert_path, key_path) = write_self_signed_xot_cert_files_for_name(cert_dns_name);
    let (addr, query_seen_rx) = spawn_xot_primary_detecting_query_with_cert_files(
        &cert_path,
        &key_path,
        negotiate_dot_alpn,
    )
    .await;
    (addr, cert_path.display().to_string(), query_seen_rx)
}

async fn spawn_xot_primary_detecting_query_with_cert_files(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    negotiate_dot_alpn: bool,
) -> (std::net::SocketAddr, mpsc::Receiver<()>) {
    let certs =
        load_pem_certs(cert_path.to_str().expect("utf-8 cert path")).expect("load generated cert");
    let key = load_pem_private_key(
        "127.0.0.1:0".parse().unwrap(),
        key_path.to_str().expect("utf-8 key path"),
    )
    .expect("load generated key");
    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server tls config");
    if negotiate_dot_alpn {
        config.alpn_protocols = vec![b"dot".to_vec()];
    }
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (query_seen_tx, query_seen_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        let mut length_prefix = [0u8; 2];
        if matches!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                stream.read_exact(&mut length_prefix),
            )
            .await,
            Ok(Ok(_))
        ) {
            let _ = query_seen_tx.send(()).await;
        }
    });

    (addr, query_seen_rx)
}

async fn spawn_xot_tls12_primary_detecting_query()
-> (std::net::SocketAddr, String, mpsc::Receiver<()>) {
    let (cert_path, key_path) = write_self_signed_xot_cert_files();

    let certs =
        load_pem_certs(cert_path.to_str().expect("utf-8 cert path")).expect("load generated cert");
    let key = load_pem_private_key(
        "127.0.0.1:0".parse().unwrap(),
        key_path.to_str().expect("utf-8 key path"),
    )
    .expect("load generated key");
    let mut config =
        tokio_rustls::rustls::ServerConfig::builder_with_protocol_versions(&[&version::TLS12])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server tls config");
    config.alpn_protocols = vec![b"dot".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (query_seen_tx, query_seen_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        let mut length_prefix = [0u8; 2];
        if matches!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                stream.read_exact(&mut length_prefix),
            )
            .await,
            Ok(Ok(_))
        ) {
            let _ = query_seen_tx.send(()).await;
        }
    });

    (addr, cert_path.display().to_string(), query_seen_rx)
}

fn write_self_signed_xot_cert_files() -> (std::path::PathBuf, std::path::PathBuf) {
    write_self_signed_xot_cert_files_for_name("primary.example.test")
}

fn write_self_signed_xot_cert_files_for_name(
    dns_name: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec![dns_name.to_owned()])
        .expect("self-signed certificate");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    write_xot_cert_files(cert_pem, key_pem)
}

fn write_expired_self_signed_xot_cert_files_for_name(
    dns_name: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut params =
        rcgen::CertificateParams::new(vec![dns_name.to_owned()]).expect("certificate params");
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
    let cert = params
        .self_signed(&key_pair)
        .expect("expired self-signed certificate");
    write_xot_cert_files(cert.pem(), key_pair.serialize_pem())
}

fn write_expiring_self_signed_xot_cert_files_for_name(
    dns_name: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut params =
        rcgen::CertificateParams::new(vec![dns_name.to_owned()]).expect("certificate params");
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2026, 6, 1);
    let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
    let cert = params
        .self_signed(&key_pair)
        .expect("expiring self-signed certificate");
    write_xot_cert_files(cert.pem(), key_pair.serialize_pem())
}

fn write_xot_cert_files(
    cert_pem: String,
    key_pem: String,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert_path = unique_test_path("xot-primary", "pem");
    let key_path = unique_test_path("xot-primary-key", "pem");
    std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert pem");
    std::fs::write(&key_path, key_pem.as_bytes()).expect("write key pem");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure key mode");
    }
    (cert_path, key_path)
}

fn unique_test_path(prefix: &str, extension: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = TEST_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{counter}-{nanos}.{extension}",
        std::process::id()
    ))
}

async fn spawn_axfr_primary_with_serial(serial: u32) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();

        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert!(query.ends_with(&(1u16).to_be_bytes()));
        assert_eq!(
            &query[query.len() - 4..query.len() - 2],
            &(RecordType::Axfr as u16).to_be_bytes()
        );

        let response = axfr_response(header.id, serial);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_barrier_axfr_primary(
    zone: &'static str,
    barrier: Arc<tokio::sync::Barrier>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let query = read_primary_query(&mut stream).await;
        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        let (_, qname_len) = DomainName::parse(&query, 12).unwrap();
        let qtype_offset = 12 + qname_len;
        assert_eq!(
            u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]),
            RecordType::Axfr as u16
        );

        barrier.wait().await;

        let response = axfr_response_for_zone(header.id, zone, 1);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_blocked_axfr_primary() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (query_seen_tx, query_seen_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let query = read_primary_query(&mut stream).await;
        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        let (_, qname_len) = DomainName::parse(&query, 12).unwrap();
        let qtype_offset = 12 + qname_len;
        assert_eq!(
            u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]),
            RecordType::Axfr as u16
        );
        let _ = query_seen_tx.send(());
        let _ = release_rx.await;
    });
    (addr, query_seen_rx, release_tx)
}

async fn spawn_axfr_primary_recording_query(
    serial: u32,
) -> (std::net::SocketAddr, Arc<Mutex<Option<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let observed_query = Arc::new(Mutex::new(None));
    let observed_query_for_task = observed_query.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let query = read_primary_query(&mut stream).await;

        let header = Header::parse(&query).unwrap();
        let request_mac = extract_query_tsig_mac(&query);
        observed_query_for_task
            .lock()
            .expect("observed query lock poisoned")
            .replace(query.clone());

        let response = axfr_response(header.id, serial);
        let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let response = key
            .sign_response(
                &response,
                &request_mac,
                current_unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap()
            .message;
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    (addr, observed_query)
}

async fn spawn_axfr_primary_recording_peer(
    serial: u32,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<std::net::SocketAddr>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (peer_tx, peer_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, peer) = listener.accept().await.unwrap();
        let _ = peer_tx.send(peer);
        let query = read_primary_query(&mut stream).await;
        let header = Header::parse(&query).unwrap();
        let response = axfr_response(header.id, serial);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    (addr, peer_rx)
}

async fn spawn_ixfr_mode2_primary_with_serial(serial: u32) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();

        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.nscount, 1);
        assert_eq!(&query[26..28], &(RecordType::Ixfr as u16).to_be_bytes());

        let response = ixfr_mode2_response(header.id, serial);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_barrier_ixfr_mode2_primary(
    zone: &'static str,
    barrier: Arc<tokio::sync::Barrier>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let query = read_primary_query(&mut stream).await;
        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        let (_, qname_len) = DomainName::parse(&query, 12).unwrap();
        let qtype_offset = 12 + qname_len;
        assert_eq!(
            u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]),
            RecordType::Ixfr as u16
        );

        barrier.wait().await;

        let response = ixfr_mode2_response_for_zone(header.id, zone, 2);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_ixfr_mode1_primary() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();

        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.nscount, 1);
        assert_eq!(&query[26..28], &(RecordType::Ixfr as u16).to_be_bytes());

        let response = ixfr_mode1_response(header.id);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_ixfr_notimp_then_axfr_primary() -> (std::net::SocketAddr, Arc<Mutex<Vec<u16>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let qtypes = Arc::new(Mutex::new(Vec::new()));
    let qtypes_for_task = qtypes.clone();
    tokio::spawn(async move {
        for serial in [2, 3] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let query = read_primary_query(&mut stream).await;
            let header = Header::parse(&query).unwrap();
            let qtype = query_qtype(&query);
            qtypes_for_task
                .lock()
                .expect("qtype log lock poisoned")
                .push(qtype);
            if qtype == RecordType::Ixfr as u16 {
                let response = error_response(header.id, 4);
                stream
                    .write_all(&frame_tcp_message(&response))
                    .await
                    .unwrap();

                let (mut stream, _) = listener.accept().await.unwrap();
                let query = read_primary_query(&mut stream).await;
                let header = Header::parse(&query).unwrap();
                let qtype = query_qtype(&query);
                qtypes_for_task
                    .lock()
                    .expect("qtype log lock poisoned")
                    .push(qtype);
                assert_eq!(qtype, RecordType::Axfr as u16);
                let response = axfr_response(header.id, serial);
                stream
                    .write_all(&frame_tcp_message(&response))
                    .await
                    .unwrap();
            } else {
                assert_eq!(qtype, RecordType::Axfr as u16);
                let response = axfr_response(header.id, serial);
                stream
                    .write_all(&frame_tcp_message(&response))
                    .await
                    .unwrap();
            }
        }
    });
    (addr, qtypes)
}

async fn spawn_soa_primary_with_serial(serial: u32) -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        let response = soa_response(header.id, serial);
        socket.send_to(&response, peer).await.unwrap();
    });
    addr
}

async fn spawn_soa_primary_recording_peer(
    serial: u32,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<std::net::SocketAddr>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (peer_tx, peer_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let _ = peer_tx.send(peer);
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        let response = soa_response(header.id, serial);
        socket.send_to(&response, peer).await.unwrap();
    });
    (addr, peer_rx)
}

async fn spawn_soa_primary_recording_two_peers(
    serial: u32,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<Vec<std::net::SocketAddr>>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (peers_tx, peers_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let mut peers = Vec::new();
        for _ in 0..2 {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = &buffer[..len];
            let header = Header::parse(query).unwrap();
            assert_eq!(header.qdcount, 1);
            assert_eq!(query_qtype(query), RecordType::Soa as u16);

            peers.push(peer);
            let response = soa_response(header.id, serial);
            socket.send_to(&response, peer).await.unwrap();
        }
        let _ = peers_tx.send(peers);
    });
    (addr, peers_rx)
}

async fn spawn_soa_primary_with_spoofed_malformed_packet(serial: u32) -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        attacker.send_to(&[0], peer).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let response = soa_response(header.id, serial);
        socket.send_to(&response, peer).await.unwrap();
    });
    addr
}

async fn spawn_malformed_soa_primary() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        socket.send_to(&[0], peer).await.unwrap();
    });
    addr
}

async fn spawn_signed_soa_primary_with_serial(serial: u32) -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let mut buffer = vec![0u8; 1024];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.arcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        let request_mac = extract_query_tsig_mac(query);
        let response = soa_response(header.id, serial);
        let signed = key
            .sign_response(
                &response,
                &request_mac,
                current_unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        socket.send_to(&signed.message, peer).await.unwrap();
    });
    addr
}

fn axfr_response(qid: u16, serial: u32) -> Vec<u8> {
    axfr_response_for_zone(qid, "example.test.", serial)
}

fn axfr_response_for_zone(qid: u16, zone: &str, serial: u32) -> Vec<u8> {
    transfer_response_for_zone(qid, zone, RecordType::Axfr as u16, serial)
}

fn ixfr_mode2_response(qid: u16, serial: u32) -> Vec<u8> {
    ixfr_mode2_response_for_zone(qid, "example.test.", serial)
}

fn ixfr_mode2_response_for_zone(qid: u16, zone: &str, serial: u32) -> Vec<u8> {
    transfer_response_for_zone(qid, zone, RecordType::Ixfr as u16, serial)
}

fn transfer_response_for_zone(qid: u16, zone: &str, qtype: u16, serial: u32) -> Vec<u8> {
    let soa = record(zone, RecordType::Soa as u16, soa_rdata_with_serial(serial));
    let ns = record(zone, RecordType::Ns as u16, ns_rdata_for_zone(zone));
    let owner = format!("www.{zone}");
    let a = record(&owner, RecordType::A as u16, vec![192, 0, 2, 10]);
    let answers = vec![soa.clone(), ns, a, soa];
    let mut out = Vec::new();
    out.extend_from_slice(&qid.to_be_bytes());
    out.extend_from_slice(&0x8000u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&DomainName::from_absolute_str(zone).unwrap().to_wire());
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for answer in answers {
        out.extend_from_slice(&answer.owner.to_wire());
        out.extend_from_slice(&answer.rr_type.to_be_bytes());
        out.extend_from_slice(&answer.class.to_be_bytes());
        out.extend_from_slice(&answer.ttl.to_be_bytes());
        out.extend_from_slice(&(answer.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&answer.rdata);
    }
    out
}

async fn read_primary_query(stream: &mut TcpStream) -> Vec<u8> {
    let mut length_prefix = [0u8; 2];
    stream.read_exact(&mut length_prefix).await.unwrap();
    let query_len = u16::from_be_bytes(length_prefix) as usize;
    let mut query = vec![0u8; query_len];
    stream.read_exact(&mut query).await.unwrap();
    query
}

fn query_qtype(query: &[u8]) -> u16 {
    assert!(query.len() >= 28);
    u16::from_be_bytes([query[26], query[27]])
}

fn assert_query_has_tsig(query: &[u8], key_name: &str, algorithm_name: &str) {
    let header = Header::parse(query).unwrap();
    assert_eq!(header.arcount, 1);
    let original_id = header.id;
    let (question_name, question_len) = DomainName::parse(query, 12).unwrap();
    assert_eq!(
        question_name,
        DomainName::from_absolute_str("example.test.").unwrap()
    );
    let mut offset = 12 + question_len + 4;

    let (owner, owner_len) = DomainName::parse(query, offset).unwrap();
    assert_eq!(owner, DomainName::from_absolute_str(key_name).unwrap());
    offset += owner_len;
    assert_eq!(
        u16::from_be_bytes([query[offset], query[offset + 1]]),
        RecordType::Tsig as u16
    );
    assert_eq!(
        u16::from_be_bytes([query[offset + 2], query[offset + 3]]),
        255
    );
    assert_eq!(
        u32::from_be_bytes([
            query[offset + 4],
            query[offset + 5],
            query[offset + 6],
            query[offset + 7],
        ]),
        0
    );
    let rdlen = u16::from_be_bytes([query[offset + 8], query[offset + 9]]) as usize;
    offset += 10;
    let rdata_end = offset + rdlen;

    let (algorithm, algorithm_len) = DomainName::parse(query, offset).unwrap();
    assert_eq!(
        algorithm,
        DomainName::from_absolute_str(algorithm_name).unwrap()
    );
    offset += algorithm_len + 6 + 2;
    let mac_len = u16::from_be_bytes([query[offset], query[offset + 1]]) as usize;
    assert_eq!(mac_len, 32);
    offset += 2 + mac_len;
    assert_eq!(
        u16::from_be_bytes([query[offset], query[offset + 1]]),
        original_id
    );
    offset += 2;
    assert_eq!(u16::from_be_bytes([query[offset], query[offset + 1]]), 0);
    offset += 2;
    assert_eq!(u16::from_be_bytes([query[offset], query[offset + 1]]), 0);
    offset += 2;
    assert_eq!(offset, rdata_end);
    assert_eq!(offset, query.len());
}

fn extract_query_tsig_mac(query: &[u8]) -> Vec<u8> {
    let (_, question_len) = DomainName::parse(query, 12).unwrap();
    let mut offset = 12 + question_len + 4;
    let (_, owner_len) = DomainName::parse(query, offset).unwrap();
    offset += owner_len + 10;
    let (_, algorithm_len) = DomainName::parse(query, offset).unwrap();
    offset += algorithm_len + 6 + 2;
    let mac_len = u16::from_be_bytes([query[offset], query[offset + 1]]) as usize;
    offset += 2;
    query[offset..offset + mac_len].to_vec()
}

fn query_tsig_fudge(query: &[u8]) -> u16 {
    let (_, question_len) = DomainName::parse(query, 12).unwrap();
    let mut offset = 12 + question_len + 4;
    let (_, owner_len) = DomainName::parse(query, offset).unwrap();
    offset += owner_len + 10;
    let (_, algorithm_len) = DomainName::parse(query, offset).unwrap();
    offset += algorithm_len + 6;
    u16::from_be_bytes([query[offset], query[offset + 1]])
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn error_response(qid: u16, rcode: u8) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&qid.to_be_bytes());
    out.extend_from_slice(&(0x8000u16 | u16::from(rcode & 0x0f)).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn ixfr_mode1_response(qid: u16) -> Vec<u8> {
    let old_soa = record(
        "example.test.",
        RecordType::Soa as u16,
        soa_rdata_with_serial(1),
    );
    let new_soa = record(
        "example.test.",
        RecordType::Soa as u16,
        soa_rdata_with_serial(2),
    );
    let old_a = record(
        "old.example.test.",
        RecordType::A as u16,
        vec![192, 0, 2, 1],
    );
    let new_a = record(
        "new.example.test.",
        RecordType::A as u16,
        vec![192, 0, 2, 2],
    );
    let answers = vec![new_soa.clone(), old_soa, old_a, new_soa, new_a];
    let mut out = Vec::new();
    out.extend_from_slice(&qid.to_be_bytes());
    out.extend_from_slice(&0x8000u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(
        &DomainName::from_absolute_str("example.test.")
            .unwrap()
            .to_wire(),
    );
    out.extend_from_slice(&(RecordType::Ixfr as u16).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for answer in answers {
        out.extend_from_slice(&answer.owner.to_wire());
        out.extend_from_slice(&answer.rr_type.to_be_bytes());
        out.extend_from_slice(&answer.class.to_be_bytes());
        out.extend_from_slice(&answer.ttl.to_be_bytes());
        out.extend_from_slice(&(answer.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&answer.rdata);
    }
    out
}

fn soa_response(qid: u16, serial: u32) -> Vec<u8> {
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let soa = record(
        "example.test.",
        RecordType::Soa as u16,
        soa_rdata_with_serial(serial),
    );
    let mut out = Vec::new();
    out.extend_from_slice(&qid.to_be_bytes());
    out.extend_from_slice(&0x8000u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&apex.to_wire());
    out.extend_from_slice(&(RecordType::Soa as u16).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&soa.owner.to_wire());
    out.extend_from_slice(&soa.rr_type.to_be_bytes());
    out.extend_from_slice(&soa.class.to_be_bytes());
    out.extend_from_slice(&soa.ttl.to_be_bytes());
    out.extend_from_slice(&(soa.rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&soa.rdata);
    out
}

fn notify_packet(qid: u16, qname: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let qname = DomainName::from_absolute_str(qname).unwrap();
    let mut packet = Vec::new();
    packet.extend_from_slice(&qid.to_be_bytes());
    packet.extend_from_slice(&((Opcode::Notify as u16) << 11).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&qname.to_wire());
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());
    packet
}

fn tsig_notify_authority() -> (NotifyAuthority, TsigKey) {
    let config = ServerConfig::from_toml_str(
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
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
    )
    .expect("valid config");
    (
        NotifyAuthority::from_config(&config),
        TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap(),
    )
}

#[derive(Clone, Debug)]
struct CapturedEvents {
    lines: Arc<Mutex<Vec<String>>>,
}

impl CapturedEvents {
    fn new() -> Self {
        Self {
            lines: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn push(&self, line: String) {
        self.lines
            .lock()
            .expect("captured events lock poisoned")
            .push(line);
    }

    fn contains_all(&self, needles: &[&str]) -> bool {
        let lines = self.lines.lock().expect("captured events lock poisoned");
        lines
            .iter()
            .any(|line| needles.iter().all(|needle| line.contains(needle)))
    }
}

#[derive(Debug)]
struct CapturingSubscriber {
    events: CapturedEvents,
}

impl CapturingSubscriber {
    fn new(events: CapturedEvents) -> Self {
        Self { events }
    }
}

impl Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = EventLine::default();
        event.record(&mut visitor);
        self.events.push(visitor.line);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}

    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }
}

#[derive(Default)]
struct EventLine {
    line: String,
}

impl Visit for EventLine {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if !self.line.is_empty() {
            self.line.push(' ');
        }
        self.line.push_str(&format!("{}={:?}", field.name(), value));
    }
}

fn replace_final_tsig_mac(message: &[u8], replacement_mac: &[u8]) -> Vec<u8> {
    let mut out = message.to_vec();
    let mut offset = 12;
    let (_, qname_len) = DomainName::parse(&out, offset).unwrap();
    offset += qname_len + 4;
    let (_, owner_len) = DomainName::parse(&out, offset).unwrap();
    let rdlen_offset = offset + owner_len + 8;
    let rdata_offset = offset + owner_len + 10;
    let old_rdlen = u16::from_be_bytes([out[rdlen_offset], out[rdlen_offset + 1]]) as usize;
    let mut rdata_cursor = rdata_offset;
    let (_, algorithm_len) = DomainName::parse(&out, rdata_cursor).unwrap();
    rdata_cursor += algorithm_len + 6 + 2;
    let mac_len_offset = rdata_cursor;
    let old_mac_len = u16::from_be_bytes([out[mac_len_offset], out[mac_len_offset + 1]]) as usize;
    let mac_offset = mac_len_offset + 2;
    out.splice(
        mac_offset..mac_offset + old_mac_len,
        replacement_mac.iter().copied(),
    );
    out[mac_len_offset..mac_len_offset + 2]
        .copy_from_slice(&(replacement_mac.len() as u16).to_be_bytes());
    let new_rdlen = old_rdlen - old_mac_len + replacement_mac.len();
    out[rdlen_offset..rdlen_offset + 2].copy_from_slice(&(new_rdlen as u16).to_be_bytes());
    out
}

fn replace_final_tsig_owner(message: &[u8], replacement_owner: &str) -> Vec<u8> {
    let mut out = message.to_vec();
    let mut offset = 12;
    let (_, qname_len) = DomainName::parse(&out, offset).unwrap();
    offset += qname_len + 4;
    let (_, old_owner_len) = DomainName::parse(&out, offset).unwrap();
    let replacement_wire = DomainName::from_absolute_str(replacement_owner)
        .unwrap()
        .to_wire();
    out.splice(
        offset..offset + old_owner_len,
        replacement_wire.iter().copied(),
    );
    out
}

fn replace_final_tsig_algorithm(message: &[u8], replacement_algorithm: &str) -> Vec<u8> {
    let mut out = message.to_vec();
    let mut offset = 12;
    let (_, qname_len) = DomainName::parse(&out, offset).unwrap();
    offset += qname_len + 4;
    let (_, owner_len) = DomainName::parse(&out, offset).unwrap();
    let rdlen_offset = offset + owner_len + 8;
    let rdata_offset = offset + owner_len + 10;
    let old_rdlen = u16::from_be_bytes([out[rdlen_offset], out[rdlen_offset + 1]]) as usize;
    let (_, old_algorithm_len) = DomainName::parse(&out, rdata_offset).unwrap();
    let replacement_wire = DomainName::from_absolute_str(replacement_algorithm)
        .unwrap()
        .to_wire();
    out.splice(
        rdata_offset..rdata_offset + old_algorithm_len,
        replacement_wire.iter().copied(),
    );
    let new_rdlen = old_rdlen - old_algorithm_len + replacement_wire.len();
    out[rdlen_offset..rdlen_offset + 2].copy_from_slice(&(new_rdlen as u16).to_be_bytes());
    out
}

struct ParsedTsigResponseFields {
    fudge: u16,
    mac_len: usize,
    original_id: u16,
    error: u16,
    other_data: Vec<u8>,
}

fn parse_tsig_response_fields(response: &[u8]) -> ParsedTsigResponseFields {
    assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
    let mut offset = 12;
    let (_, qname_len) = DomainName::parse(response, offset).unwrap();
    offset += qname_len + 4;
    let (_, owner_len) = DomainName::parse(response, offset).unwrap();
    offset += owner_len;
    assert_eq!(
        u16::from_be_bytes([response[offset], response[offset + 1]]),
        RecordType::Tsig as u16
    );
    let rdlen = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
    offset += 10;
    let rdata_end = offset + rdlen;
    let (_, algorithm_len) = DomainName::parse(response, offset).unwrap();
    offset += algorithm_len + 6;
    let fudge = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    let mac_len = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2 + mac_len;
    let original_id = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    let error = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    let other_len = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2;
    assert_eq!(offset + other_len, rdata_end);
    ParsedTsigResponseFields {
        fudge,
        mac_len,
        original_id,
        error,
        other_data: response[offset..offset + other_len].to_vec(),
    }
}

fn notify_response(qid: u16) -> Vec<u8> {
    let qname = DomainName::from_absolute_str("example.test.").unwrap();
    let mut response = Vec::new();
    response.extend_from_slice(&qid.to_be_bytes());
    response
        .extend_from_slice(&(0x8000u16 | ((Opcode::Notify as u16) << 11) | 0x0400).to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&qname.to_wire());
    response.extend_from_slice(&(RecordType::Soa as u16).to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response
}

fn positive_query_response() -> Vec<u8> {
    let mut response = rcode_query_response(0);
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response
}

fn query_response_with_opt() -> Vec<u8> {
    let mut response = rcode_query_response(0);
    response[10..12].copy_from_slice(&1u16.to_be_bytes());
    response.push(0);
    response.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
    response.extend_from_slice(&1232u16.to_be_bytes());
    response.extend_from_slice(&0u32.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response
}

fn referral_query_response() -> Vec<u8> {
    let mut response = rcode_query_response(0);
    response[8..10].copy_from_slice(&1u16.to_be_bytes());
    let owner = DomainName::from_absolute_str("example.test.").unwrap();
    let target = DomainName::from_absolute_str("ns.example.test.").unwrap();
    response.extend_from_slice(&owner.to_wire());
    response.extend_from_slice(&(RecordType::Ns as u16).to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&300u32.to_be_bytes());
    response.extend_from_slice(&(target.to_wire().len() as u16).to_be_bytes());
    response.extend_from_slice(&target.to_wire());
    response
}

fn rcode_query_response(rcode: u8) -> Vec<u8> {
    let mut response = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    response[2..4].copy_from_slice(&(0x8400u16 | u16::from(rcode & 0x0f)).to_be_bytes());
    response
}

fn query(qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x1234u16.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(qname);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());
    packet
}

fn query_observation_options() -> QueryObservationOptions {
    QueryObservationOptions {
        transport: Transport::Udp,
        cookie_validated: false,
        parse_duration: None,
    }
}

fn active_example_zone() -> ZoneStore {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![Rrset::new(
            DomainName::from_absolute_str("www.example.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 10].to_vec()],
        )],
    ));
    zones
}

fn udp_settings_for_test(metrics: RuntimeMetrics, rrl_config: RrlConfig) -> UdpServerSettings {
    UdpServerSettings {
        max_udp_payload: 1232,
        udp_batch_size: 1,
        udp_backend: UdpBackend::Std,
        udp_runtime: UdpRuntime::Tokio,
        udp_idle_strategy: Default::default(),
        xdp: XdpConfig::default(),
        max_cname_chain: 8,
        nsec3_max_iterations: 100,
        edns_padding_block_size: 0,
        extended_dns_errors: ExtendedDnsErrorsMode::Off,
        any_response: AnyResponseMode::Minimal,
        nsid: Vec::new(),
        chaos_version: String::new(),
        chaos_hostname: String::new(),
        dns_cookie_secrets: dns_cookie_secret_store_for_test(),
        dns_cookie: dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
        cookie_prefix_metrics: cookie_prefix_metrics_for_test(),
        notify_authority: NotifyAuthority::default(),
        notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
        notify_refresh_tx: notify_refresh_tx(),
        notify_log_limiter: notify_log_limiter_for_test(),
        metrics: metrics.clone(),
        rrl: RrlLimiter::from_config(&rrl_config, metrics),
    }
}

fn notify_log_limiter_for_test() -> NotifyLogLimiter {
    NotifyLogLimiter::new(std::time::Duration::from_secs(60))
}

async fn spawn_telemetry_endpoint(
    status: &'static str,
) -> (std::net::SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let _ = request_tx.send(request);
        let response =
            format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (addr, request_rx)
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut header_end = None;
    let mut content_length = 0usize;
    loop {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await.unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if header_end.is_none()
            && let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
        {
            header_end = Some(position + 4);
            let headers = String::from_utf8_lossy(&request[..position]);
            for line in headers.lines() {
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    content_length = value.trim().parse().unwrap();
                }
            }
        }
        if let Some(end) = header_end
            && request.len() >= end + content_length
        {
            break;
        }
    }
    String::from_utf8(request).expect("telemetry request should be utf8")
}

fn control_plane_reporter_for_endpoint(
    endpoint: std::net::SocketAddr,
) -> ControlPlaneTelemetryReporter {
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [control_plane.telemetry]
                endpoint_url = "http://{endpoint}"
                node_id = "node-a"
                bearer_token = "token-a"
                timeout_secs = 5

                [[zones]]
                name = "alpha.test."
                primaries = ["192.0.2.53:53"]
            "#
    ))
    .expect("valid telemetry config");
    ControlPlaneTelemetryReporter::from_config(&config)
}

fn telemetry_zone_metadata(serial: Option<u32>, soa_timers: Option<SoaTimers>) -> ZoneMetadata {
    ZoneMetadata {
        origin: DomainName::from_absolute_str("alpha.test.").unwrap(),
        origin_key: Arc::from("alpha.test."),
        origin_name: Arc::from("alpha.test."),
        state: ZoneState::Active,
        serial,
        soa_timers,
        shape: None,
        shape_histograms: None,
    }
}

fn telemetry_json_body(request: &str) -> serde_json::Value {
    let body = request
        .split_once("\r\n\r\n")
        .expect("telemetry request should have headers")
        .1;
    serde_json::from_str(body).expect("telemetry request body should be JSON")
}

fn dns_cookie_settings_for_test(policy: DnsCookiePolicy) -> DnsCookieRuntimeSettings {
    DnsCookieRuntimeSettings {
        policy: Some(policy),
        past_window_secs: 3600,
        future_window_secs: 300,
        secret_rotation_interval: None,
    }
}

fn dns_cookie_secret_store_for_test() -> DnsCookieSecretStore {
    DnsCookieSecretStore::new([7; 16], None)
}

fn cookie_prefix_metrics_for_test() -> CookiePrefixMetricSettings {
    CookiePrefixMetricSettings {
        ipv4_prefix_len: 24,
        ipv6_prefix_len: 56,
    }
}

fn append_opt(packet: &mut Vec<u8>, payload_size: u16, ttl: u32, rdata: &[u8]) {
    packet[11] = packet[11].checked_add(1).unwrap();
    packet.push(0);
    packet.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
    packet.extend_from_slice(&payload_size.to_be_bytes());
    packet.extend_from_slice(&ttl.to_be_bytes());
    packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    packet.extend_from_slice(rdata);
}

fn edns_option(code: u16, data: &[u8]) -> Vec<u8> {
    let mut option = Vec::new();
    option.extend_from_slice(&code.to_be_bytes());
    option.extend_from_slice(&(data.len() as u16).to_be_bytes());
    option.extend_from_slice(data);
    option
}

fn cookie_query(cookie_data: &[u8]) -> Vec<u8> {
    let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    append_opt(&mut packet, 4096, 0, &edns_option(10, cookie_data));
    packet
}

fn response_cookie_option(response: &[u8]) -> Option<Vec<u8>> {
    let header = Header::parse(response).ok()?;
    let opt = response_opt_record(response, &header)?;
    let rdlength = u16::from_be_bytes([opt[9], opt[10]]) as usize;
    let rdata = opt.get(11..11 + rdlength)?;
    let mut offset = 0usize;
    while offset < rdata.len() {
        let option_code = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
        let option_len = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
        offset += 4;
        if option_code == 10 {
            return Some(rdata[offset..offset + option_len].to_vec());
        }
        offset += option_len;
    }
    None
}

async fn recv_udp_with_timeout(
    socket: &UdpSocket,
    timeout_duration: std::time::Duration,
) -> Option<Vec<u8>> {
    let mut response = vec![0u8; 512];
    let len = tokio::time::timeout(timeout_duration, socket.recv(&mut response))
        .await
        .ok()?
        .ok()?;
    response.truncate(len);
    Some(response)
}

async fn read_framed_tcp_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut length_prefix = [0u8; 2];
    stream.read_exact(&mut length_prefix).await.unwrap();
    let response_len = u16::from_be_bytes(length_prefix) as usize;
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response).await.unwrap();
    response
}

async fn spawn_runtime_with_bound_health(
    runtime: Runtime,
) -> (
    tokio::task::JoinHandle<Result<(), RuntimeError>>,
    std::net::SocketAddr,
) {
    spawn_runtime_with_bound_health_and_shutdown(
        runtime,
        std::future::pending::<Result<&'static str, std::io::Error>>(),
    )
    .await
}

async fn spawn_runtime_with_bound_health_and_shutdown(
    runtime: Runtime,
    shutdown_signal: impl Future<Output = Result<&'static str, std::io::Error>> + Send + 'static,
) -> (
    tokio::task::JoinHandle<Result<(), RuntimeError>>,
    std::net::SocketAddr,
) {
    let (health_bound_tx, health_bound_rx) = oneshot::channel();
    let server = tokio::spawn(
        runtime.run_with_shutdown_signal_inner(shutdown_signal, Some(health_bound_tx)),
    );
    let health_addr = tokio::time::timeout(std::time::Duration::from_secs(1), health_bound_rx)
        .await
        .expect("runtime did not bind health listener before timeout")
        .expect("runtime exited before binding health listener");
    (server, health_addr)
}

async fn http_request(addr: std::net::SocketAddr, method: &str, path: &str) -> String {
    String::from_utf8(http_request_with_headers(addr, method, path, &[]).await)
        .expect("HTTP response should be UTF-8")
}

async fn http_json(addr: std::net::SocketAddr, path: &str) -> serde_json::Value {
    let response = http_request(addr, "GET", path).await;
    json_body_from_ok_response(response)
}

async fn http_json_with_headers(
    addr: std::net::SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> serde_json::Value {
    let response = String::from_utf8(http_request_with_headers(addr, "GET", path, headers).await)
        .expect("HTTP response should be UTF-8");
    json_body_from_ok_response(response)
}

fn json_body_from_ok_response(response: String) -> serde_json::Value {
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "unexpected HTTP response: {response}"
    );
    let body = response
        .split_once("\r\n\r\n")
        .expect("HTTP response should have body")
        .1;
    serde_json::from_str(body).expect("observability response should be valid JSON")
}

async fn http_request_with_headers(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n"
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("Content-Length: 0\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

fn split_http_response(response: &[u8]) -> (&str, &[u8]) {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response should contain a header/body split")
        + 4;
    let headers = std::str::from_utf8(&response[..split]).expect("headers should be UTF-8");
    (headers, &response[split..])
}

async fn eventually_http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    timeout: std::time::Duration,
) -> String {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                let request = format!(
                    "{method} {path} HTTP/1.1\r\n\
                         Host: localhost\r\n\
                         Connection: close\r\n\
                         Content-Length: 0\r\n\
                         \r\n"
                );
                stream.write_all(request.as_bytes()).await.unwrap();

                let mut response = String::new();
                stream.read_to_string(&mut response).await.unwrap();
                return response;
            }
            Err(error) => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                assert!(
                    !remaining.is_zero(),
                    "HTTP endpoint {addr} did not accept connection before timeout: {error}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10).min(remaining)).await;
            }
        }
    }
}

async fn eventually_health_body(
    addr: std::net::SocketAddr,
    expected_body: &str,
    timeout: std::time::Duration,
) -> String {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "health endpoint {addr} did not return expected body {expected_body:?} before timeout"
        );
        let response = eventually_http_request(addr, "GET", "/healthz", remaining).await;
        if response.ends_with(expected_body) {
            return response;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn unused_udp_tcp_addr() -> std::net::SocketAddr {
    for _ in 0..32 {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        match UdpSocket::bind(addr).await {
            Ok(udp) => {
                drop(udp);
                drop(tcp);
                return addr;
            }
            Err(_) => {
                drop(tcp);
            }
        }
    }
    panic!("could not find an address free for both UDP and TCP");
}

fn health_state(zones: ZoneStore) -> HealthEndpointState {
    health_state_with_observability(zones, ObservabilityConfig::default())
}

fn health_state_with_observability(
    zones: ZoneStore,
    observability: ObservabilityConfig,
) -> HealthEndpointState {
    let observability_rate_limiter = MetricsRateLimiter::from_observability_config(&observability);
    let observability_auth =
        ObservabilityAuth::from_config(&observability).expect("observability auth config");
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
        metrics_rate_limiter: MetricsRateLimiter::default(),
        observability,
        observability_auth,
        observability_rate_limiter,
        transfer_materials: Vec::<TransferMaterial>::new(),
        started_at: std::time::Instant::now(),
        graceful_shutdown_secs: 30,
        zone_shape_metrics_enabled: false,
    }
}

fn record(owner: &str, rr_type: u16, rdata: Vec<u8>) -> ResourceRecord {
    ResourceRecord {
        owner: DomainName::from_absolute_str(owner).unwrap(),
        rr_type,
        class: 1,
        ttl: 300,
        rdata,
    }
}

fn soa_rdata() -> Vec<u8> {
    soa_rdata_with_serial(1)
}

fn ns_rdata_for_zone(zone: &str) -> Vec<u8> {
    DomainName::from_absolute_str(&format!("ns.{zone}"))
        .unwrap()
        .to_wire()
}

fn soa_rdata_with_serial(serial: u32) -> Vec<u8> {
    let mut rdata = b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec();
    let (_, consumed_mname) = DomainName::parse(&rdata, 0).unwrap();
    let (_, consumed_rname) = DomainName::parse(&rdata, consumed_mname).unwrap();
    let serial_offset = consumed_mname + consumed_rname;
    rdata[serial_offset..serial_offset + 4].copy_from_slice(&serial.to_be_bytes());
    rdata
}
