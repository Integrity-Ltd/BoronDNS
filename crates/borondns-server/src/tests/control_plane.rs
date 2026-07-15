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

#[test]
fn control_plane_url_builder_keeps_node_id_in_one_path_segment() {
    let url = crate::control_plane_node_url(
        "https://control.example/api/v1",
        "node/../admin?scope=all#fragment",
        &["operations"],
    )
    .expect("URL construction");

    assert_eq!(
        url.as_str(),
        "https://control.example/api/v1/secondary-nodes/node%2F..%2Fadmin%3Fscope=all%23fragment/operations"
    );
    assert_eq!(url.query(), None);
    assert_eq!(url.fragment(), None);
}

#[tokio::test]
async fn control_plane_bearer_request_cannot_escape_node_path_segment() {
    let (endpoint, received) = spawn_telemetry_endpoint("204 No Content").await;
    let mut reporter = control_plane_reporter_for_endpoint(endpoint);
    reporter.node_id = Some(Arc::<str>::from("node/../admin?scope=all#fragment"));

    reporter
        .report_success(&telemetry_zone_metadata(Some(7), None), "active", "test")
        .await;
    let request = received.await.expect("telemetry request");
    assert!(request.starts_with(
        "POST /secondary-nodes/node%2F..%2Fadmin%3Fscope=all%23fragment/transfer-events HTTP/1.1"
    ));
    assert!(request.contains("authorization: Bearer token-a"));
    assert!(!request.starts_with("POST /secondary-nodes/node/../admin"));
}

#[test]
fn control_plane_clients_share_one_zeroizing_bearer_allocation() {
    let reporter = control_plane_reporter_for_endpoint("127.0.0.1:9".parse().unwrap());
    let cloned = reporter.clone();
    let original_secret = &reporter.bearer_token.as_ref().expect("bearer token").0;
    let cloned_secret = &cloned.bearer_token.as_ref().expect("cloned bearer token").0;
    assert!(Arc::ptr_eq(original_secret, cloned_secret));
    assert_eq!(original_secret.as_str(), "token-a");
}

#[tokio::test]
async fn control_plane_clients_do_not_follow_redirects() {
    let telemetry_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let telemetry_target_addr = telemetry_target.local_addr().unwrap();
    let telemetry_redirect =
        spawn_http_redirect_endpoint(format!("http://{telemetry_target_addr}/leak")).await;
    let reporter = control_plane_reporter_for_endpoint(telemetry_redirect);
    reporter
        .report_success(&telemetry_zone_metadata(Some(7), None), "active", "notify")
        .await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), telemetry_target.accept())
            .await
            .is_err(),
        "telemetry client must not send a redirected request"
    );

    let operations_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let operations_target_addr = operations_target.local_addr().unwrap();
    let operations_redirect =
        spawn_http_redirect_endpoint(format!("http://{operations_target_addr}/operations")).await;
    let client = control_plane_operation_client_for_endpoint(operations_redirect);
    let error = client
        .poll()
        .await
        .expect_err("redirect response is not an operation feed");
    assert!(error.contains("307 Temporary Redirect"));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), operations_target.accept())
            .await
            .is_err(),
        "operations client must not consume a redirected feed"
    );
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
async fn control_plane_telemetry_shutdown_drain_delivers_admitted_terminal_events() {
    let (endpoint, received) = spawn_telemetry_endpoints("204 No Content", 2).await;
    let reporter = control_plane_reporter_for_endpoint(endpoint);
    let (telemetry, receiver) = ControlPlaneTelemetryClient::new(true);
    let mut tasks = JoinSet::new();
    tasks.spawn(super::serve_control_plane_telemetry(
        reporter,
        receiver.expect("enabled telemetry receiver"),
    ));

    telemetry.report_success(
        &telemetry_zone_metadata(Some(7), None),
        "active",
        "notify",
    );
    telemetry.report_failure(
        &DomainName::from_absolute_str("failed.test.").unwrap(),
        Some("upstream reset"),
        "initial",
    );
    drop(telemetry);

    assert!(
        drain_task_set(
            &mut tasks,
            std::time::Duration::from_secs(2),
            "control-plane telemetry",
        )
        .await,
        "telemetry receiver drains after all admitted senders close"
    );
    let requests = received.await.expect("two drained telemetry requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(telemetry_json_body(&requests[0])["status"], "active");
    assert_eq!(telemetry_json_body(&requests[1])["status"], "failed");
}

#[tokio::test]
async fn control_plane_telemetry_shutdown_drain_remains_bounded_under_saturation() {
    let (endpoint, received) = spawn_telemetry_endpoints("204 No Content", 1).await;
    let reporter = control_plane_reporter_for_endpoint(endpoint);
    let (telemetry, receiver) = ControlPlaneTelemetryClient::saturated_for_test();

    telemetry.report_success(
        &telemetry_zone_metadata(Some(7), None),
        "active",
        "notify",
    );
    telemetry.report_failure(
        &DomainName::from_absolute_str("failed.test.").unwrap(),
        Some("upstream reset"),
        "initial",
    );
    drop(telemetry);

    let mut tasks = JoinSet::new();
    tasks.spawn(super::serve_control_plane_telemetry(reporter, receiver));
    assert!(
        drain_task_set(
            &mut tasks,
            std::time::Duration::from_secs(2),
            "control-plane telemetry",
        )
        .await,
        "bounded telemetry queue drains without waiting for dropped events"
    );
    let requests = received.await.expect("seeded saturated telemetry request");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        telemetry_json_body(&requests[0])["test"],
        "blocked telemetry worker"
    );
}

#[tokio::test]
async fn control_plane_operations_poll_and_complete_with_node_auth() {
    let (endpoint, received) = spawn_operation_endpoint().await;
    let client = control_plane_operation_client_for_endpoint(endpoint);

    let operations = client.poll().await.expect("operation poll");
    assert_eq!(
        operations,
        vec![PolledControlPlaneOperation::Valid(
            ControlPlaneOperation {
                id: 42,
                zone_name: "alpha.test.".to_owned(),
                operation: ControlPlaneOperationKind::Retry,
            }
        )]
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
async fn control_plane_poll_isolates_malformed_items_in_a_bounded_batch() {
    let body = serde_json::to_vec(&serde_json::json!([
        {"id": 1, "zone_name": "alpha.test.", "operation": "retry"},
        {"id": 2, "zone_name": "alpha.test.", "operation": "future_kind"},
        {"zone_name": "alpha.test.", "operation": "pause"},
        {"id": 3, "zone_name": "beta.test.", "operation": "resume"}
    ]))
    .unwrap();
    let endpoint = spawn_operation_poll_endpoint(body, None).await;
    let client = control_plane_operation_client_for_endpoint(endpoint);

    let operations = client.poll().await.expect("mixed operation batch");
    assert_eq!(operations.len(), 4);
    assert!(matches!(
        &operations[0],
        PolledControlPlaneOperation::Valid(ControlPlaneOperation { id: 1, .. })
    ));
    assert!(matches!(
        &operations[1],
        PolledControlPlaneOperation::Invalid { id: Some(2), .. }
    ));
    assert!(matches!(
        &operations[2],
        PolledControlPlaneOperation::Invalid { id: None, .. }
    ));
    assert!(matches!(
        &operations[3],
        PolledControlPlaneOperation::Valid(ControlPlaneOperation { id: 3, .. })
    ));
}

#[tokio::test]
async fn control_plane_poll_rejects_oversized_body_and_item_count() {
    let endpoint = spawn_operation_poll_endpoint(
        Vec::new(),
        Some(CONTROL_PLANE_RESPONSE_LIMIT_BYTES + 1),
    )
    .await;
    let client = control_plane_operation_client_for_endpoint(endpoint);
    let error = client
        .poll()
        .await
        .expect_err("declared oversized response must be rejected before allocation");
    assert!(error.contains("response exceeds"));

    let operations = (0..=CONTROL_PLANE_OPERATION_LIMIT)
        .map(|id| {
            serde_json::json!({
                "id": id,
                "zone_name": "alpha.test.",
                "operation": "retry"
            })
        })
        .collect::<Vec<_>>();
    let endpoint =
        spawn_operation_poll_endpoint(serde_json::to_vec(&operations).unwrap(), None).await;
    let client = control_plane_operation_client_for_endpoint(endpoint);
    let error = client
        .poll()
        .await
        .expect_err("server response must honor the requested item limit");
    assert!(error.contains("exceeding requested limit"));
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

#[test]
fn control_plane_visibility_operations_cannot_override_catalog_policy() {
    let zones = ZoneStore::new();
    let catalog = DomainName::from_absolute_str("catalog.test.").unwrap();
    zones.insert_loading_hidden(catalog.clone());
    let (refresh_tx, _refresh_rx) = mpsc::channel(1);
    let secrets = SecretManager::empty_for_test();

    for operation in [
        ControlPlaneOperationKind::Pause,
        ControlPlaneOperationKind::Resume,
    ] {
        let error = execute_control_plane_operation(
            &ControlPlaneOperation {
                id: 9,
                zone_name: catalog.to_string(),
                operation,
            },
            &zones,
            &refresh_tx,
            std::slice::from_ref(&catalog),
            &secrets,
        )
        .expect_err("catalog visibility is fixed by serve_catalog_zone policy");
        assert!(error.contains("cannot override serve_catalog_zone policy"));
        assert!(zones.is_hidden(&catalog));
    }
}

#[test]
fn failed_resume_enqueue_keeps_static_zone_hidden() {
    let zones = ZoneStore::new();
    let origin = DomainName::from_absolute_str("alpha.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(origin.clone(), Some(1), Vec::new()));
    zones.hide_zone(&origin);
    let (refresh_tx, _refresh_rx) = mpsc::channel(1);
    refresh_tx
        .try_send(RefreshRequest::new(
            DomainName::from_absolute_str("queued.test.").unwrap(),
            None,
            RefreshReason::ControlPlane,
        ))
        .expect("prefill control-plane refresh queue");
    let secrets = SecretManager::empty_for_test();

    let error = execute_control_plane_operation(
        &ControlPlaneOperation {
            id: 10,
            zone_name: origin.to_string(),
            operation: ControlPlaneOperationKind::Resume,
        },
        &zones,
        &refresh_tx,
        &[],
        &secrets,
    )
    .expect_err("full refresh queue must reject resume atomically");
    assert!(error.contains("refresh queue rejected"));
    assert!(zones.is_hidden(&origin));
}

#[test]
fn admitted_control_plane_refresh_is_rescheduled_after_internal_queue_drop() {
    let zones = ZoneStore::new();
    let origin = DomainName::from_absolute_str("alpha.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(origin.clone(), Some(1), Vec::new()));
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    );
    let now = std::time::Instant::now();
    registry.record_success_at(
        &telemetry_zone_metadata(
            Some(1),
            Some(SoaTimers {
                refresh: 3600,
                retry: 60,
                expire: 7200,
                minimum: 60,
            }),
        ),
        now,
    );
    let (refresh_tx, mut refresh_rx) = mpsc::channel(1);
    let secrets = SecretManager::empty_for_test();
    execute_control_plane_operation(
        &ControlPlaneOperation {
            id: 11,
            zone_name: origin.to_string(),
            operation: ControlPlaneOperationKind::Retry,
        },
        &zones,
        &refresh_tx,
        &[],
        &secrets,
    )
    .expect("outer queue admission makes the operation acknowledgeable");
    let control_request = refresh_rx
        .try_recv()
        .expect("admitted control-plane refresh request");

    let mut pending = std::collections::VecDeque::new();
    let mut pending_keys = HashSet::new();
    let active_keys = HashSet::new();
    for index in 0..NOTIFY_REFRESH_QUEUE_CAPACITY {
        let filler = DomainName::from_absolute_str(&format!("filler-{index}.test.")).unwrap();
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
    let dropped = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        control_request,
    )
    .expect("full internal queue drops the admitted control-plane request");
    assert_eq!(
        dropped.retry_after_queue_drop,
        Some(RefreshReason::ControlPlane)
    );
    registry.defer_refresh_after_queue_drop(&dropped);

    assert_eq!(
        registry.start_due_refreshes(std::time::Instant::now()),
        vec![origin]
    );
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
        client: control_plane_http_client(),
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
