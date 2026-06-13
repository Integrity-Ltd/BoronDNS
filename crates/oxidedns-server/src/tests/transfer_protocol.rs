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
async fn signed_soa_poll_retries_udp_tc_over_tcp_before_tsig_verification() {
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
