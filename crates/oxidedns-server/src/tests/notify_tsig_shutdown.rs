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
    let authority = NotifyAuthority::from_config_for_test(&config);
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
