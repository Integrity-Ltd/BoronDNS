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
        "control-plane transfer telemetry report was rejected",
        "category=\"transfer\"",
        "status=503 Service Unavailable",
    ]));
}

#[tokio::test]
async fn control_plane_operations_poll_and_complete_with_node_auth() {
    let (endpoint, received) = spawn_operation_endpoint().await;
    let client = control_plane_operation_client_for_endpoint(endpoint);

    let operations = client.poll().await.expect("operation poll");
    assert_eq!(
        operations,
        vec![ControlPlaneOperation {
            id: 42,
            zone_name: "alpha.test.".to_owned(),
            operation: ControlPlaneOperationKind::Retry,
        }]
    );
    client
        .complete(42, ControlPlaneOperationCompletionStatus::Completed, None)
        .await;

    let requests = received.await.expect("operation requests");
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0].starts_with(
            "GET /secondary-nodes/node-a/operations?limit=20&lease_seconds=5 HTTP/1.1"
        ),
        "{}",
        requests[0]
    );
    assert!(requests[0].contains("authorization: Bearer token-a"));
    assert!(
        requests[1].starts_with("POST /secondary-nodes/node-a/operations/42/complete HTTP/1.1")
    );
    assert_eq!(telemetry_json_body(&requests[1])["status"], "completed");
}

#[tokio::test]
async fn control_plane_operations_pause_resume_and_queue_refresh() {
    let zones = ZoneStore::new();
    let origin = DomainName::from_absolute_str("alpha.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(origin.clone(), Some(1), Vec::new()));
    let (refresh_tx, mut refresh_rx) = mpsc::channel(4);
    let secrets = SecretManager::empty_for_test();
    let pause = ControlPlaneOperation {
        id: 1,
        zone_name: "alpha.test.".to_owned(),
        operation: ControlPlaneOperationKind::Pause,
    };
    execute_control_plane_operation(&pause, &zones, &refresh_tx, &[], &secrets)
        .expect("pause operation should apply");
    assert!(zones.is_hidden(&origin));

    let resume = ControlPlaneOperation {
        id: 2,
        zone_name: "alpha.test.".to_owned(),
        operation: ControlPlaneOperationKind::Resume,
    };
    execute_control_plane_operation(&resume, &zones, &refresh_tx, &[], &secrets)
        .expect("resume operation should apply");
    assert!(!zones.is_hidden(&origin));
    let refresh = refresh_rx.recv().await.expect("resume refresh request");
    assert_eq!(refresh.zone, origin);
    assert_eq!(refresh.requested_serial, None);
    assert_eq!(refresh.reason, RefreshReason::ControlPlane);
}

#[tokio::test]
async fn control_plane_republish_feed_refreshes_catalog_zones() {
    let zones = ZoneStore::new();
    let catalog = DomainName::from_absolute_str("catalog.test.").unwrap();
    zones.insert_loading_hidden(catalog.clone());
    let (refresh_tx, mut refresh_rx) = mpsc::channel(4);
    let secrets = SecretManager::empty_for_test();
    let operation = ControlPlaneOperation {
        id: 3,
        zone_name: "alpha.test.".to_owned(),
        operation: ControlPlaneOperationKind::RepublishFeed,
    };

    execute_control_plane_operation(
        &operation,
        &zones,
        &refresh_tx,
        std::slice::from_ref(&catalog),
        &secrets,
    )
    .expect("republish-feed operation should refresh catalog");

    let refresh = refresh_rx.recv().await.expect("catalog refresh request");
    assert_eq!(refresh.zone, catalog);
    assert_eq!(refresh.reason, RefreshReason::ControlPlane);
}

#[test]
fn control_plane_operation_parser_accepts_all_supported_operations() {
    for (kind, expected) in [
        ("retry", ControlPlaneOperationKind::Retry),
        ("pause", ControlPlaneOperationKind::Pause),
        ("resume", ControlPlaneOperationKind::Resume),
        ("republish_feed", ControlPlaneOperationKind::RepublishFeed),
        ("rotate_tsig", ControlPlaneOperationKind::RotateTsig),
    ] {
        let parsed = parse_control_plane_operation(&serde_json::json!({
            "id": 7,
            "zone_name": "alpha.test.",
            "operation": kind,
        }))
        .expect("operation parses");
        assert_eq!(parsed.operation, expected);
    }

    let error = parse_control_plane_operation(&serde_json::json!({
        "id": 8,
        "zone_name": "alpha.test.",
        "operation": "unsupported",
    }))
    .expect_err("unsupported operation is rejected");
    assert!(error.contains("unsupported operation kind unsupported"));
}

#[tokio::test]
async fn disabled_control_plane_operation_client_noops() {
    let client = ControlPlaneOperationClient {
        enabled: false,
        endpoint_url: None,
        node_id: None,
        bearer_token: None,
        poll_interval: std::time::Duration::from_secs(1),
        lease_seconds: 1,
        timeout: std::time::Duration::from_secs(1),
        client: reqwest::Client::new(),
    };

    assert!(!client.enabled());
    assert_eq!(
        ControlPlaneOperationCompletionStatus::Failed.as_str(),
        "failed"
    );
    assert!(client.poll().await.expect("disabled poll").is_empty());
    client
        .complete(
            99,
            ControlPlaneOperationCompletionStatus::Failed,
            Some("no-op"),
        )
        .await;
}

#[test]
fn control_plane_operation_client_honors_disabled_flag_with_credentials() {
    let config = ServerConfig::from_toml_str(
        r#"
            [server]
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []

            [control_plane.operations]
            enabled = false
            endpoint_url = "https://udns.example.test"
            node_id = "node-a"
            bearer_token = "token-a"

            [[zones]]
            name = "alpha.test."
            primaries = ["192.0.2.53:53"]
        "#,
    )
    .expect("disabled operations config with staged credentials should validate");
    let client = ControlPlaneOperationClient::from_config(&config);

    assert!(!client.enabled());
}

#[tokio::test]
async fn control_plane_retry_rotate_and_empty_feed_paths() {
    let zones = ZoneStore::new();
    let origin = DomainName::from_absolute_str("alpha.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(origin.clone(), Some(1), Vec::new()));
    let (refresh_tx, mut refresh_rx) = mpsc::channel(4);
    let secrets = SecretManager::empty_for_test();

    for (id, operation) in [
        (10, ControlPlaneOperationKind::Retry),
        (11, ControlPlaneOperationKind::RotateTsig),
    ] {
        execute_control_plane_operation(
            &ControlPlaneOperation {
                id,
                zone_name: "alpha.test.".to_owned(),
                operation,
            },
            &zones,
            &refresh_tx,
            &[],
            &secrets,
        )
        .expect("operation queues refresh");
        let refresh = refresh_rx.recv().await.expect("refresh request");
        assert_eq!(refresh.zone, origin);
        assert_eq!(refresh.reason, RefreshReason::ControlPlane);
    }

    execute_control_plane_operation(
        &ControlPlaneOperation {
            id: 12,
            zone_name: "alpha.test.".to_owned(),
            operation: ControlPlaneOperationKind::RepublishFeed,
        },
        &zones,
        &refresh_tx,
        &[],
        &secrets,
    )
    .expect("empty feed operation is a no-op");
    assert!(refresh_rx.try_recv().is_err());
}

#[test]
fn control_plane_operation_rejects_invalid_and_unknown_zones() {
    let zones = ZoneStore::new();
    let (refresh_tx, _refresh_rx) = mpsc::channel(1);
    let secrets = SecretManager::empty_for_test();

    let invalid = execute_control_plane_operation(
        &ControlPlaneOperation {
            id: 20,
            zone_name: "not absolute".to_owned(),
            operation: ControlPlaneOperationKind::Retry,
        },
        &zones,
        &refresh_tx,
        &[],
        &secrets,
    )
    .expect_err("invalid zone name is rejected");
    assert!(invalid.contains("operation zone_name not absolute is not absolute"));

    let unknown = execute_control_plane_operation(
        &ControlPlaneOperation {
            id: 21,
            zone_name: "missing.test.".to_owned(),
            operation: ControlPlaneOperationKind::Retry,
        },
        &zones,
        &refresh_tx,
        &[],
        &secrets,
    )
    .expect_err("unknown zone is rejected");
    assert!(unknown.contains("zone missing.test. is not configured"));
}
