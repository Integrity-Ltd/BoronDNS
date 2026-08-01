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
        zone_image_stats: None,
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
async fn signed_axfr_completes_on_tsig_only_message_after_unsigned_terminating_soa() {
    let primary = spawn_axfr_primary_with_unsigned_terminator_and_tsig_only_terminal().await;
    let target = TransferPrimaryConfig::tcp(primary);
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();

    let snapshot = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        super::transfer_axfr_from_target_with_tsig(
            &target,
            &apex,
            1,
            0x1234,
            TransferSession::new(
                TransferTsig::new(Some(&key), DEFAULT_TSIG_FUDGE_SECS),
                DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT,
            ),
            std::time::Duration::from_secs(5),
        ),
    )
    .await
    .expect("AXFR should finish while the primary keeps the TCP stream open")
    .expect("signed AXFR transfer");

    assert_eq!(snapshot.state, ZoneState::Active);
    assert_eq!(snapshot.serial, Some(1));
}

#[tokio::test]
async fn signed_axfr_authenticates_error_response_before_using_rcode() {
    let primary = spawn_unsigned_transfer_error_primary(RecordType::Axfr, 5).await;
    let target = TransferPrimaryConfig::tcp(primary);
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();

    let error = super::transfer_axfr_from_target_with_tsig(
        &target,
        &apex,
        1,
        0x1234,
        TransferSession::new(
            TransferTsig::new(Some(&key), DEFAULT_TSIG_FUDGE_SECS),
            DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT,
        ),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect_err("unsigned REFUSED must not be accepted as an authenticated AXFR result");

    assert!(matches!(
        error,
        TransferError::Tsig(borondns_core::tsig::TsigError::MissingTsig)
    ), "unexpected AXFR error: {error:?}");
}

#[tokio::test]
async fn signed_ixfr_authenticates_error_response_before_using_rcode() {
    let primary = spawn_unsigned_transfer_error_primary(RecordType::Ixfr, 5).await;
    let target = TransferPrimaryConfig::tcp(primary);
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let current_zone = current_zone_with_serial(&apex, 1);
    let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();

    let error = super::transfer_ixfr_from_target_with_tsig(
        &target,
        &apex,
        1,
        0x1234,
        &current_zone,
        TransferSession::new(
            TransferTsig::new(Some(&key), DEFAULT_TSIG_FUDGE_SECS),
            DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT,
        ),
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect_err("unsigned REFUSED must not be accepted as an authenticated IXFR result");

    assert!(matches!(
        error,
        TransferError::Tsig(borondns_core::tsig::TsigError::MissingTsig)
    ), "unexpected IXFR error: {error:?}");
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
    let primary = spawn_ixfr_mode2_transfer_primary_with_serial(2).await;
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
    let primary = spawn_ixfr_mode2_transfer_primary_with_serial(2).await;
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

#[test]
fn transfer_ingest_tracker_enforces_message_count_cap() {
    let primary = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let mut ingest = TransferIngestTracker::new("IXFR", primary, u64::MAX);
    for _ in 0..DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT {
        ingest.record_message(0).expect("message below cap");
    }

    let error = ingest
        .record_message(0)
        .expect_err("message count cap should be enforced");
    assert!(matches!(
        error,
        TransferError::IngestMessageLimit {
            protocol: "IXFR",
            received_messages,
            limit_messages,
            ..
        } if received_messages == DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT + 1
            && limit_messages == DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT
    ));
}

#[test]
fn transfer_ingest_tracker_honors_explicit_large_zone_message_count_cap() {
    let primary = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let mut ingest =
        TransferIngestTracker::new("AXFR", primary, u64::MAX).with_message_limit(4_098);
    for _ in 0..4_098 {
        ingest
            .record_message(0)
            .expect("message remains below configured cap");
    }

    let error = ingest
        .record_message(0)
        .expect_err("configured cap remains enforced");
    assert!(matches!(
        error,
        TransferError::IngestMessageLimit {
            received_messages: 4_099,
            limit_messages: 4_098,
            ..
        }
    ));
}

#[test]
fn transfer_ingest_global_budget_releases_after_success() {
    let primary = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let budget = TransferIngestBudget::new(16);
    {
        let mut ingest =
            TransferIngestTracker::new("AXFR", primary, 16).with_ingest_budget(Some(&budget));
        ingest.record_message(16).expect("budget reservation");
        assert_eq!(budget.in_flight_bytes(), 16);
    }
    assert_eq!(budget.in_flight_bytes(), 0);

    let mut reuse =
        TransferIngestTracker::new("IXFR", primary, 16).with_ingest_budget(Some(&budget));
    reuse
        .record_message(16)
        .expect("released budget is reusable");
}

#[test]
fn concurrent_transfer_sessions_each_retain_the_full_per_session_allowance() {
    let primary = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let per_session_limit = 16;
    let budget = TransferIngestBudget::for_concurrent_sessions(per_session_limit, 2);
    let mut first = TransferIngestTracker::new("AXFR", primary, per_session_limit)
        .with_ingest_budget(Some(&budget));
    let mut second = TransferIngestTracker::new("IXFR", primary, per_session_limit)
        .with_ingest_budget(Some(&budget));

    first
        .record_message(per_session_limit as usize)
        .expect("first concurrent session may consume its full allowance");
    second
        .record_message(per_session_limit as usize)
        .expect("second concurrent session may consume its full allowance");

    assert_eq!(budget.in_flight_bytes(), per_session_limit * 2);
}

#[test]
fn derived_transfer_ingest_budget_saturates_instead_of_wrapping() {
    let primary = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let budget = TransferIngestBudget::for_concurrent_sessions(u64::MAX, 2);
    let mut ingest = TransferIngestTracker::new("AXFR", primary, u64::MAX)
        .with_ingest_budget(Some(&budget));

    ingest
        .record_message(1)
        .expect("overflow-safe derived aggregate budget remains usable");
    assert_eq!(budget.in_flight_bytes(), 1);
}

#[test]
fn transfer_ingest_global_budget_releases_after_error() {
    let primary = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let budget = TransferIngestBudget::new(10);
    let result = (|| {
        let mut first =
            TransferIngestTracker::new("AXFR", primary, 20).with_ingest_budget(Some(&budget));
        first.record_message(8)?;
        assert_eq!(budget.in_flight_bytes(), 8);

        let mut second =
            TransferIngestTracker::new("IXFR", primary, 20).with_ingest_budget(Some(&budget));
        second.record_message(3)
    })();

    assert!(matches!(
        result,
        Err(TransferError::IngestGlobalSizeLimit {
            requested_bytes: 3,
            in_flight_bytes: 8,
            limit_bytes: 10,
            ..
        })
    ));
    assert_eq!(budget.in_flight_bytes(), 0);
}

#[tokio::test]
async fn transfer_ingest_global_budget_releases_after_cancellation() {
    let primary = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let budget = TransferIngestBudget::new(10);
    let task_budget = budget.clone();
    let (reserved_tx, reserved_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut ingest =
            TransferIngestTracker::new("AXFR", primary, 10).with_ingest_budget(Some(&task_budget));
        ingest.record_message(10).expect("budget reservation");
        reserved_tx.send(()).expect("reservation observation");
        std::future::pending::<()>().await;
        drop(ingest);
    });

    reserved_rx.await.expect("reservation was acquired");
    assert_eq!(budget.in_flight_bytes(), 10);
    task.abort();
    assert!(task.await.expect_err("task was cancelled").is_cancelled());
    assert_eq!(budget.in_flight_bytes(), 0);
}

#[test]
fn transfer_ingest_message_allocation_is_capped_by_session_bytes() {
    let primary = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let mut ingest = TransferIngestTracker::new("AXFR", primary, 8);
    let error = ingest
        .record_message(9)
        .expect_err("one message cannot exceed the configured ingest cap");

    assert!(matches!(
        error,
        TransferError::IngestSizeLimit {
            received_bytes: 9,
            limit_bytes: 8,
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
async fn poll_soa_from_primary_ignores_wrong_qid_tc_response() {
    let primary = spawn_soa_primary_with_wrong_qid_truncated_then_serial(7).await;
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let serial =
        poll_soa_from_primary(primary, &apex, 1, 0x1234, std::time::Duration::from_secs(5))
            .await
            .expect("SOA poll should ignore wrong-qid TC response");

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
        super::TransferError::Soa(borondns_core::axfr::SoaQueryError::MalformedMessage)
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
async fn poll_soa_from_primary_discards_unsigned_response_then_accepts_signed_response() {
    let primary = spawn_invalid_then_signed_soa_primary(7, false).await;
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
    .expect("unsigned response must be discarded while waiting for a signed response");

    assert_eq!(serial, 7);
}

#[tokio::test]
async fn signed_soa_poll_verifies_udp_tc_before_tcp_retry() {
    let primary = spawn_truncated_udp_tcp_soa_primary(7).await;
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
    .expect("UDP TC response should retry the SOA poll over TCP");

    assert_eq!(serial, 7);
}

#[tokio::test]
async fn signed_soa_poll_discards_unsigned_udp_tc_without_tcp_retry() {
    let primary = spawn_invalid_then_signed_soa_primary(7, true).await;
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
    .expect("unsigned TC must be discarded before the signed UDP response");

    assert_eq!(serial, 7);
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

    assert_eq!(*rotated.current, [2; 16]);
    assert_eq!(rotated.previous.as_deref(), Some(&[1; 16]));
    assert_eq!(*retained.current, [2; 16]);
    assert_eq!(retained.previous.as_deref(), Some(&[1; 16]));
    let disabled_current = disabled.current_with_generator(|| Ok([4; 16]));
    assert_eq!(*disabled_current.current, [3; 16]);
    assert_eq!(disabled_current.previous.as_deref(), Some(&[2; 16]));
    assert!(captured.contains_all(&["DNS Cookie server secret rotated", "secret_fingerprint=",]));
}

#[test]
fn dns_cookie_secret_store_backs_off_after_rotation_failure() {
    let generated_at = std::time::Instant::now() - std::time::Duration::from_secs(61);
    let rotating = DnsCookieSecretStore::new_at(
        [1; 16],
        None,
        Some(std::time::Duration::from_secs(60)),
        generated_at,
    );

    let retained = rotating.current_with_generator(|| Err(getrandom::Error::UNSUPPORTED));
    let second = rotating.current_with_generator(|| -> Result<[u8; 16], getrandom::Error> {
        panic!("failed rotation should back off until the next interval")
    });

    assert_eq!(*retained.current, [1; 16]);
    assert_eq!(*second.current, [1; 16]);
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
        *secrets.current,
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]
    );
    assert_eq!(
        secrets.previous.as_deref(),
        Some(&[
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ])
    );
}

#[cfg(unix)]
#[test]
fn xot_private_key_loader_checks_world_mode_symlinks_and_regular_file() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let (cert_path, key_path) = write_self_signed_xot_cert_files();
    let addr = "192.0.2.53:853".parse().expect("valid test address");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o640))
        .expect("group-readable private key mode");
    load_pem_private_key(addr, key_path.to_str().expect("UTF-8 key path"))
        .expect("group-readable private key remains compatible with BDS-IF-CONF-004");

    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o604))
        .expect("world-readable private key mode");
    let error = load_pem_private_key(addr, key_path.to_str().expect("UTF-8 key path"))
        .expect_err("world-readable private key rejected");
    assert!(error.to_string().contains("must not be world-readable"));

    for mode in [0o602, 0o620] {
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(mode))
            .expect("writable-by-others private key mode");
        let error = load_pem_private_key(addr, key_path.to_str().expect("UTF-8 key path"))
            .expect_err("group- or world-writable private key rejected");
        assert!(
            error
                .to_string()
                .contains("must not be group- or world-writable"),
            "mode {mode:o}: {error}"
        );
    }

    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .expect("restore secure private key mode");
    let link = unique_test_path("borondns-xot-key-link", "pem");
    symlink(&key_path, &link).expect("create private key symlink");
    load_pem_private_key(addr, link.to_str().expect("UTF-8 link path"))
        .expect_err("private key symlink rejected");

    let directory = unique_test_path("borondns-xot-key-directory", "dir");
    std::fs::create_dir(&directory).expect("create private key directory");
    let error = load_pem_private_key(
        addr,
        directory.to_str().expect("UTF-8 directory path"),
    )
    .expect_err("private key directory rejected");
    assert!(error.to_string().contains("must be a regular file"));

    let _ = std::fs::remove_file(link);
    let _ = std::fs::remove_dir(directory);
    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(cert_path);
}

#[cfg(unix)]
#[test]
fn direct_xot_material_loader_enforces_exact_limit_and_growth_fence() {
    use std::{
        io::Write,
        os::unix::fs::PermissionsExt,
    };

    let limit = crate::transfer::MAX_DIRECT_XOT_TLS_MATERIAL_BYTES;
    let certificate_path = unique_test_path("borondns-direct-xot-material-limit", "pem");
    let certificate = std::fs::File::create(&certificate_path).expect("create TLS material file");
    certificate
        .set_len(limit as u64)
        .expect("size exact-limit TLS material file");
    drop(certificate);
    assert_eq!(
        crate::transfer::direct_xot_tls_material_len_after_open_for_test(
            certificate_path.to_str().expect("UTF-8 certificate path"),
            || {},
        )
        .expect("exact-limit direct XoT TLS material is accepted"),
        limit
    );

    std::fs::OpenOptions::new()
        .write(true)
        .open(&certificate_path)
        .expect("open TLS material for resize")
        .set_len((limit + 1) as u64)
        .expect("size over-limit TLS material file");
    let error = crate::transfer::direct_xot_tls_material_len_after_open_for_test(
        certificate_path.to_str().expect("UTF-8 certificate path"),
        || {},
    )
    .expect_err("one-byte-over direct XoT TLS material is rejected");
    assert!(error.to_string().contains(&limit.to_string()));
    assert!(error.to_string().contains("direct XoT material limit"));

    std::fs::OpenOptions::new()
        .write(true)
        .open(&certificate_path)
        .expect("open TLS material for exact-limit reset")
        .set_len(limit as u64)
        .expect("reset exact-limit TLS material file");
    let growth_path = certificate_path.clone();
    let error = crate::transfer::direct_xot_tls_material_len_after_open_for_test(
        certificate_path.to_str().expect("UTF-8 certificate path"),
        move || {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&growth_path)
                .expect("open captured TLS material for hostile append")
                .write_all(&[0])
                .expect("grow captured TLS material after metadata validation");
        },
    )
    .expect_err("bounded same-handle read rejects post-validation growth");
    assert!(error.to_string().contains("direct XoT material limit"));

    let private_key_path = unique_test_path("borondns-direct-xot-private-key-limit", "pem");
    let private_key = std::fs::File::create(&private_key_path).expect("create private-key file");
    private_key
        .set_len(limit as u64)
        .expect("size exact-limit private-key file");
    drop(private_key);
    std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))
        .expect("private key mode");
    let addr = "192.0.2.53:853".parse().expect("valid primary address");
    assert_eq!(
        crate::transfer::direct_xot_private_key_len_after_open_for_test(
            addr,
            private_key_path.to_str().expect("UTF-8 key path"),
            || {},
        )
        .expect("exact-limit direct XoT private key is accepted"),
        limit
    );
    std::fs::OpenOptions::new()
        .write(true)
        .open(&private_key_path)
        .expect("open private key for resize")
        .set_len((limit + 1) as u64)
        .expect("size over-limit private key file");
    let error = crate::transfer::direct_xot_private_key_len_after_open_for_test(
        addr,
        private_key_path.to_str().expect("UTF-8 key path"),
        || {},
    )
    .expect_err("one-byte-over direct XoT private key is rejected");
    assert!(error.to_string().contains("direct XoT material limit"));

    let _ = std::fs::remove_file(certificate_path);
    let _ = std::fs::remove_file(private_key_path);
}

#[cfg(unix)]
#[test]
fn direct_xot_material_loader_counts_repeated_files_against_profile_budget() {
    let file_limit = crate::transfer::MAX_DIRECT_XOT_TLS_MATERIAL_BYTES;
    let profile_limit =
        borondns_core::config::MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE;
    assert_eq!(profile_limit % file_limit, 0);

    let material_path = unique_test_path("borondns-direct-xot-aggregate", "pem");
    let material = std::fs::File::create(&material_path).expect("create aggregate material");
    material
        .set_len(file_limit as u64)
        .expect("size aggregate material");
    drop(material);
    let material_path = material_path.to_str().expect("UTF-8 material path");
    let repeated = vec![material_path; profile_limit / file_limit];
    let addr = "192.0.2.53:853".parse().expect("valid primary address");

    assert_eq!(
        crate::transfer::direct_xot_aggregate_material_len_for_test(addr, &repeated)
            .expect("exact aggregate profile limit is accepted"),
        profile_limit
    );

    let one_byte_path = unique_test_path("borondns-direct-xot-aggregate-plus-one", "pem");
    std::fs::write(&one_byte_path, [b'x']).expect("write one-byte aggregate material");
    let one_byte_path = one_byte_path.to_str().expect("UTF-8 one-byte path");
    let mut over_limit = repeated;
    over_limit.push(one_byte_path);
    let error = crate::transfer::direct_xot_aggregate_material_len_for_test(addr, &over_limit)
        .expect_err("one byte over aggregate profile limit is rejected");
    assert!(error.to_string().contains(&profile_limit.to_string()));
    assert!(error.to_string().contains("per-profile limit"));

    let _ = std::fs::remove_file(material_path);
    let _ = std::fs::remove_file(one_byte_path);
}

#[test]
fn direct_xot_inline_private_key_enforces_exact_limit_before_clone_or_file_io() {
    let limit = crate::transfer::MAX_DIRECT_XOT_TLS_MATERIAL_BYTES;
    let addr = "192.0.2.53:853".parse().expect("valid primary address");
    crate::transfer::validate_direct_xot_inline_private_key_size(addr, &vec![b'x'; limit])
        .expect("exact-limit inline private key is accepted by the size fence");
    let error =
        crate::transfer::validate_direct_xot_inline_private_key_size(addr, &vec![b'x'; limit + 1])
            .expect_err("one-byte-over inline private key is rejected");
    assert!(error.to_string().contains(&limit.to_string()));

    let mut config = ServerConfig::from_toml_str(
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
            trust_anchors = ["definitely-missing-anchor.pem"]
            client_cert = "definitely-missing-client.pem"
            client_key_pem = "placeholder"
        "#,
    )
    .expect("baseline inline XoT schema validates without reading material");
    config.zones[0].transfer_primaries[0].client_key_pem = Some(
        ConfigSecretString::from_plaintext("x".repeat(limit + 1)),
    );
    let error = Runtime::new(config)
        .expect_err("runtime rejects hostile inline key before reading missing files");
    let RuntimeError::InvalidRuntimeConfig(message) = error else {
        panic!("expected invalid runtime configuration, got {error}");
    };
    assert!(message.contains("inline client private key"));
    assert!(message.contains(&limit.to_string()));
    assert!(!message.contains("failed to read"));
}

#[cfg(unix)]
#[test]
fn xot_certificate_and_trust_anchor_loader_rejects_group_or_world_write_bits() {
    use std::os::unix::fs::PermissionsExt;

    let (cert_path, key_path) = write_self_signed_xot_cert_files();
    std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o644))
        .expect("world-readable certificate mode");
    load_pem_certs(cert_path.to_str().expect("UTF-8 certificate path"))
        .expect("public certificate may remain world-readable");

    for mode in [0o602, 0o620, 0o666] {
        std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(mode))
            .expect("writable-by-others certificate mode");
        let error = load_pem_certs(cert_path.to_str().expect("UTF-8 certificate path"))
            .expect_err("group- or world-writable certificate rejected");
        assert!(
            error
                .to_string()
                .contains("must not be group- or world-writable"),
            "mode {mode:o}: {error}"
        );
    }

    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(cert_path);
}
