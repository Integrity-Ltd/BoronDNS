#[test]
fn signed_notify_is_verified_stripped_and_response_signed() {
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
fn udp_tsig_signing_honors_below_equal_and_above_ceiling_boundaries() {
    let key = Arc::new(
        TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap(),
    );
    let request = key
        .sign_request(
            &notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1),
            current_unix_time(),
            DEFAULT_TSIG_FUDGE_SECS,
        )
        .unwrap();
    let response_tsig = || ResponseTsig {
        key: Arc::clone(&key),
        request_mac: request.mac.clone(),
        fudge_seconds: DEFAULT_TSIG_FUDGE_SECS,
    };
    let base = notify_response(0x1234);
    let signed_base = sign_tsig_response(base.clone(), Some(response_tsig())).unwrap();
    let tsig_wire_len = signed_base.len() - base.len();

    for signed_len in [511usize, 512] {
        let response = notify_response_with_unknown_answer_len(signed_len - tsig_wire_len);
        let signed = sign_udp_tsig_response(response.clone(), Some(response_tsig()), 512).unwrap();
        assert_eq!(signed.len(), signed_len);
        let verified = key
            .verify_response(&signed, &request.mac, current_unix_time())
            .unwrap();
        assert_eq!(verified.message, response);
        assert_eq!(Header::parse(&verified.message).unwrap().flags & 0x0200, 0);
    }

    let response = notify_response_with_unknown_answer_len(513 - tsig_wire_len);
    let signed = sign_udp_tsig_response(response, Some(response_tsig()), 512).unwrap();
    assert!(signed.len() <= 512);
    let verified = key
        .verify_response(&signed, &request.mac, current_unix_time())
        .unwrap();
    let header = Header::parse(&verified.message).unwrap();
    assert_ne!(header.flags & 0x0200, 0);
    assert_eq!(response_rcode(&verified.message, &header), Rcode::NoError as u16);
    assert_eq!((header.qdcount, header.ancount, header.nscount, header.arcount), (1, 0, 0, 0));
}

fn notify_response_with_unknown_answer_len(target_len: usize) -> Vec<u8> {
    let mut response = notify_response(0x1234);
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    let fixed_answer_len = 11usize;
    let rdata_len = target_len
        .checked_sub(response.len() + fixed_answer_len)
        .expect("target response leaves room for an answer");
    response.push(0);
    response.extend_from_slice(&65_280u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u32.to_be_bytes());
    response.extend_from_slice(&(rdata_len as u16).to_be_bytes());
    response.resize(response.len() + rdata_len, 0xa5);
    assert_eq!(response.len(), target_len);
    response
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
fn authorized_notify_with_too_short_tsig_mac_gets_formerr_without_tsig() {
    let (authority, key) = tsig_notify_authority();
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
    let signed_notify = key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("signed NOTIFY");
    let too_short_mac = &signed_notify.mac[..key.algorithm.min_mac_len() - 1];
    let bad_notify = replace_final_tsig_mac(&signed_notify.message, too_short_mac);

    let prepared = prepare_notify_packet(&bad_notify, &authority, "192.0.2.53".parse().unwrap())
        .expect("FORMERR response");
    let response = prepared
        .immediate_response
        .expect("immediate FORMERR response");

    assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    assert_eq!(u16::from_be_bytes([response[10], response[11]]), 0);
}

#[test]
fn authorized_notify_with_hmac_md5_tsig_gets_unsigned_badkey_response() {
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
    assert_eq!(tsig.error, TSIG_ERROR_BADKEY);
    assert_eq!(tsig.algorithm, "hmac-md5.sig-alg.reg.int.");
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
    assert_eq!(tsig.algorithm, "hmac-sha256.");
    assert!(tsig.other_data.is_empty());
}

#[test]
fn catalog_notify_does_not_downgrade_after_dynamic_tsig_key_is_removed() {
    let root = unique_test_path("borondns-notify-dynamic-key", "dir");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "dynamic-member-key."
            algorithm = "hmac-sha256"
            secret = "ZHluYW1pYy1zZWNyZXQ="
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

            [[tsig_keys]]
            name = "catalog-key."
            algorithm = "hmac-sha256"
            secret = "Y2F0YWxvZy1zZWNyZXQ="

            [[catalog_zones]]
            name = "catalog.test."
            catalog_primaries = ["192.0.2.53:53"]
            member_primaries = ["10.0.0.53:53"]
            catalog_tsig_key = "catalog-key."
            member_tsig_key = "catalog-key."
            member_transfer_extensions = true
        "#,
        root.display()
    ))
    .expect("valid catalog secret-store config");
    let secrets = SecretManager::from_config(&config).expect("initial dynamic key snapshot");
    let authority = NotifyAuthority::from_config(&config, secrets.clone());
    let member = DomainName::from_absolute_str("member.test.").unwrap();
    let dynamic_key = DomainName::from_absolute_str("dynamic-member-key.").unwrap();
    authority.add_zone_from_catalog(&member, &config.catalog_zones[0], None);
    let original_key = authority
        .tsig_key_for_notify(&member, 1)
        .expect("catalog member starts with configured member key");
    let original_packet = notify_packet(0x1233, "member.test.", RecordType::Soa as u16, 1);
    let signed_original = original_key
        .sign_request(
            &original_packet,
            current_unix_time(),
            DEFAULT_TSIG_FUDGE_SECS,
        )
        .expect("signed NOTIFY under original policy");
    let prepared_original = prepare_notify_packet(
        &signed_original.message,
        &authority,
        "10.0.0.53".parse().unwrap(),
    )
    .expect("original policy authorizes signed NOTIFY");
    assert!(prepared_original.immediate_response.is_none());

    authority.add_zone_from_catalog(
        &member,
        &config.catalog_zones[0],
        Some(&borondns_core::catalog::CatalogMemberTransfer {
            primaries: Vec::new(),
            tsig_key_name: Some(dynamic_key),
            xfr: None,
            notify_sources: Vec::new(),
        }),
    );
    assert!(
        !authority.is_authorized_for_token(
            &member,
            1,
            "10.0.0.53".parse().unwrap(),
            prepared_original.notify_policy_token.as_ref(),
        ),
        "a prepared NOTIFY cannot cross a catalog TSIG policy generation change"
    );
    assert!(authority.tsig_key_for_notify(&member, 1).is_some());

    write_secret_store_manifest(&root, "");
    secrets
        .reload()
        .expect("unreferenced dynamic key removal reloads");
    assert!(authority.tsig_key_for_notify(&member, 1).is_none());

    let packet = notify_packet(0x1234, "member.test.", RecordType::Soa as u16, 1);
    let prepared = prepare_notify_packet(&packet, &authority, "10.0.0.53".parse().unwrap())
        .expect("missing required TSIG key returns a rejection");
    let response = prepared
        .immediate_response
        .expect("missing required TSIG key cannot fall through as unsigned");
    assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
    assert!(!prepared.tsig_authenticated);

    let _ = std::fs::remove_dir_all(root);
}

fn write_private_notify_secret(root: &std::path::Path, name: &str, secret: &str) {
    std::fs::create_dir_all(root).expect("create NOTIFY secret root");
    let path = root.join(name);
    std::fs::write(&path, secret).expect("write NOTIFY secret generation");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private NOTIFY secret mode");
    }
}

fn write_notify_secret_manifest(root: &std::path::Path, secret_file: &str) {
    write_notify_secret_manifest_with_algorithm(root, secret_file, "hmac-sha256");
}

fn write_notify_secret_manifest_with_algorithm(
    root: &std::path::Path,
    secret_file: &str,
    algorithm: &str,
) {
    write_secret_store_manifest(
        root,
        &format!(
            r#"
                [[tsig_keys]]
                name = "rotating-key."
                algorithm = "{algorithm}"
                secret_file = "{secret_file}"
            "#,
        ),
    );
}

fn notify_reload_test_config(root: &std::path::Path) -> ServerConfig {
    ServerConfig::from_toml_str(&format!(
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
            primaries = ["127.0.0.1:53"]
            tsig_key = "rotating-key."
        "#,
        root.display()
    ))
    .expect("valid NOTIFY reload config")
}

fn active_notify_zone() -> ZoneStore {
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin,
            RecordType::Soa as u16,
            1,
            300,
            vec![soa_rdata()],
        )],
    ));
    zones
}

fn run_udp_notify_reload_case(
    rotated_secret: &str,
    rotated_algorithm: &str,
    expect_response: bool,
) {
    let root = unique_test_path("borondns-notify-udp-reload", "dir");
    write_private_notify_secret(&root, "first.b64", "bm90aWZ5LXNlY3JldC1h");
    write_private_notify_secret(&root, "second.b64", rotated_secret);
    write_notify_secret_manifest(&root, "first.b64");
    let config = notify_reload_test_config(&root);
    let secrets = SecretManager::from_config(&config).expect("initial UDP secret snapshot");
    let authority = NotifyAuthority::from_config(&config, secrets.clone());
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let initial_key = authority
        .tsig_key_for_notify(&origin, 1)
        .expect("initial UDP NOTIFY key");
    let packet = notify_packet(0x1241, "example.test.", RecordType::Soa as u16, 1);
    let signed = initial_key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("sign UDP NOTIFY before reload");
    let mut settings = udp_settings_for_test(RuntimeMetrics::new(), RrlConfig::default());
    settings.notify_authority = authority.clone();
    let (notify_tx, _notify_rx) = tokio::sync::mpsc::channel(1);
    settings.notify_refresh_tx = notify_tx;
    let hook = || {
        write_notify_secret_manifest_with_algorithm(&root, "second.b64", rotated_algorithm);
        secrets.reload().expect("reload UDP NOTIFY secret");
        let current_key = authority
            .tsig_key_for_notify(&origin, 1)
            .expect("reloaded UDP NOTIFY key");
        assert!(
            !Arc::ptr_eq(&initial_key, &current_key),
            "provenance-only reload must replace the parsed key Arc"
        );
    };
    let response = handle_udp_datagram_with_prepared_hook(
        &signed.message,
        "127.0.0.1:53000".parse().unwrap(),
        &active_notify_zone(),
        &settings,
        &hook,
    );

    assert_eq!(response.is_some(), expect_response);
    if let Some(response) = response {
        Header::parse(&response.response).expect("valid UDP NOTIFY response header");
        assert_eq!(response.response[3] & 0x0f, Rcode::NoError as u8);
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn udp_prepared_notify_survives_same_material_provenance_reload() {
    run_udp_notify_reload_case("bm90aWZ5LXNlY3JldC1h", "hmac-sha256", true);
}

#[test]
fn udp_prepared_notify_rejects_changed_secret_reload() {
    run_udp_notify_reload_case("bm90aWZ5LXNlY3JldC1i", "hmac-sha256", false);
}

#[test]
fn udp_prepared_notify_rejects_changed_algorithm_reload() {
    run_udp_notify_reload_case("bm90aWZ5LXNlY3JldC1h", "hmac-sha512", false);
}

async fn run_tcp_notify_reload_case(rotated_secret: &str, expect_response: bool) {
    let root = unique_test_path("borondns-notify-tcp-reload", "dir");
    write_private_notify_secret(&root, "first.b64", "bm90aWZ5LXNlY3JldC1h");
    write_private_notify_secret(&root, "second.b64", rotated_secret);
    write_notify_secret_manifest(&root, "first.b64");
    let config = notify_reload_test_config(&root);
    let secrets = SecretManager::from_config(&config).expect("initial TCP secret snapshot");
    let authority = NotifyAuthority::from_config(&config, secrets.clone());
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let initial_key = authority
        .tsig_key_for_notify(&origin, 1)
        .expect("initial TCP NOTIFY key");
    let packet = notify_packet(0x1242, "example.test.", RecordType::Soa as u16, 1);
    let signed = initial_key
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("sign TCP NOTIFY before reload");
    let hook: super::TcpQueryHook = {
        let root = root.clone();
        let secrets = secrets.clone();
        let authority = authority.clone();
        let origin = origin.clone();
        let initial_key = initial_key.clone();
        Arc::new(move |_query_id| {
            let root = root.clone();
            let secrets = secrets.clone();
            let authority = authority.clone();
            let origin = origin.clone();
            let initial_key = initial_key.clone();
            Box::pin(async move {
                write_notify_secret_manifest(&root, "second.b64");
                secrets.reload().expect("reload TCP NOTIFY secret");
                let current_key = authority
                    .tsig_key_for_notify(&origin, 1)
                    .expect("reloaded TCP NOTIFY key");
                assert!(
                    !Arc::ptr_eq(&initial_key, &current_key),
                    "provenance-only reload must replace the parsed key Arc"
                );
            })
        })
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (notify_tx, _notify_rx) = tokio::sync::mpsc::channel(1);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection_with_query_hook(
            stream,
            active_notify_zone(),
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            8,
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
            authority,
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_tx,
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
            Some(hook),
        )
        .await
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(&frame_tcp_message(&signed.message))
        .await
        .unwrap();
    if expect_response {
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_framed_tcp_response(&mut client),
        )
        .await
        .expect("same-material reload must retain the prepared TCP response");
        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
    } else {
        let mut frame_len = [0u8; 2];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                client.read_exact(&mut frame_len),
            )
            .await
            .is_err(),
            "changed secret must discard the prepared TCP NOTIFY"
        );
    }
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("TCP reload-race server must stop after client EOF")
        .expect("TCP reload-race server task")
        .expect("TCP reload-race connection");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn tcp_prepared_notify_survives_same_material_provenance_reload() {
    run_tcp_notify_reload_case("bm90aWZ5LXNlY3JldC1h", true).await;
}

#[tokio::test]
async fn tcp_prepared_notify_rejects_changed_secret_reload() {
    run_tcp_notify_reload_case("bm90aWZ5LXNlY3JldC1i", false).await;
}

#[test]
fn prepared_notify_is_rejected_after_same_name_tsig_secret_rotation() {
    let root = unique_test_path("borondns-notify-rotated-key", "dir");
    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "rotating-key."
            algorithm = "hmac-sha256"
            secret = "bm90aWZ5LXNlY3JldC1h"
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
            tsig_key = "rotating-key."
        "#,
        root.display()
    ))
    .expect("valid rotating-key config");
    let secrets = SecretManager::from_config(&config).expect("initial secret snapshot");
    let authority = NotifyAuthority::from_config(&config, secrets.clone());
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let source = "192.0.2.53".parse().unwrap();
    let key_a = authority
        .tsig_key_for_notify(&origin, 1)
        .expect("initial NOTIFY key");
    let packet = notify_packet(0x1240, "example.test.", RecordType::Soa as u16, 1);
    let signed_a = key_a
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("NOTIFY signed with secret A");
    let prepared_a = prepare_notify_packet(&signed_a.message, &authority, source)
        .expect("NOTIFY verifies under secret A");
    assert!(prepared_a.immediate_response.is_none());
    assert!(authority.is_authorized_for_token(
        &origin,
        1,
        source,
        prepared_a.notify_policy_token.as_ref(),
    ));

    write_secret_store_manifest(
        &root,
        r#"
            [[tsig_keys]]
            name = "rotating-key."
            algorithm = "hmac-sha256"
            secret = "bm90aWZ5LXNlY3JldC1i"
        "#,
    );
    secrets.reload().expect("rotate same-name TSIG secret");

    assert!(
        !authority.is_authorized_for_token(
            &origin,
            1,
            source,
            prepared_a.notify_policy_token.as_ref(),
        ),
        "final authorization must reject a token verified with replaced key material"
    );

    let key_b = authority
        .tsig_key_for_notify(&origin, 1)
        .expect("rotated NOTIFY key");
    let signed_b = key_b
        .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
        .expect("NOTIFY signed with secret B");
    let prepared_b = prepare_notify_packet(&signed_b.message, &authority, source)
        .expect("NOTIFY verifies under secret B");
    assert!(authority.is_authorized_for_token(
        &origin,
        1,
        source,
        prepared_b.notify_policy_token.as_ref(),
    ));

    let _ = std::fs::remove_dir_all(root);
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
    assert_eq!(tsig.algorithm, "hmac-sha1.");
    assert!(tsig.other_data.is_empty());
}

#[test]
fn authorized_notify_outside_tsig_fudge_gets_badtime_response_with_server_time() {
    let (authority, key) = tsig_notify_authority();
    let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
    let request_fudge = 19;
    let stale_notify = key
        .sign_request(&packet, 1, request_fudge)
        .expect("signed NOTIFY");
    let request_mac = stale_notify.mac.clone();

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
    assert_eq!(tsig.time_signed, 1);
    assert_eq!(tsig.fudge, request_fudge);
    assert_eq!(tsig.other_data.len(), 6);
    assert_eq!(
        key.verify_response(&response, &request_mac, current_unix_time())
            .expect_err("authenticated BADTIME response"),
        TsigError::ResponseError(TSIG_ERROR_BADTIME)
    );
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
fn outer_pending_notify_burst_is_atomically_deduplicated() {
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
fn failed_outer_reservation_hands_concurrent_follower_admission() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
    let zone = DomainName::from_absolute_str("concurrent.example.test.").unwrap();
    let (refresh_tx, mut refresh_rx) = mpsc::channel(1);
    refresh_tx
        .try_send(RefreshRequest::new(
            DomainName::from_absolute_str("prefill.example.test.").unwrap(),
            None,
            RefreshReason::Notify,
        ))
        .unwrap();

    let (outer_failed_tx, outer_failed_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let first_tracker = tracker.clone();
    let first_zone = zone.clone();
    let first_refresh_tx = refresh_tx.clone();
    let first = std::thread::spawn(move || {
        first_tracker.record_after_enqueue(&first_zone, |token| {
            let result = first_refresh_tx
                .try_send(
                    RefreshRequest::new(first_zone.clone(), Some(1), RefreshReason::Notify)
                        .with_notify_dedup_token(token),
                )
                .map_err(|_| ());
            assert!(result.is_err(), "prefill keeps the first outer send full");
            outer_failed_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            result
        })
    });
    outer_failed_rx.recv().unwrap();
    let prefill = refresh_rx.try_recv().expect("free outer queue capacity");
    assert_eq!(prefill.zone.to_string(), "prefill.example.test.");

    let (follower_started_tx, follower_started_rx) = std::sync::mpsc::channel();
    let (follower_result_tx, follower_result_rx) = std::sync::mpsc::channel();
    let follower_tracker = tracker.clone();
    let follower_zone = zone.clone();
    let follower_refresh_tx = refresh_tx.clone();
    let follower = std::thread::spawn(move || {
        follower_started_tx.send(()).unwrap();
        let result = follower_tracker.record_after_enqueue(&follower_zone, |token| {
            follower_refresh_tx
                .try_send(
                    RefreshRequest::new(
                        follower_zone.clone(),
                        Some(2),
                        RefreshReason::Notify,
                    )
                    .with_notify_dedup_token(token),
                )
                .map_err(|_| ())
        });
        follower_result_tx.send(result).unwrap();
        result
    });
    follower_started_rx.recv().unwrap();
    let follower_completed_while_reservation_was_pending = follower_result_rx
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_ok();
    release_tx.send(()).unwrap();

    assert_eq!(first.join().unwrap(), Err(()));
    assert!(
        !follower_completed_while_reservation_was_pending,
        "a follower must wait for the reserving outer send to commit or roll back"
    );
    assert_eq!(
        follower.join().unwrap(),
        Ok(NotifyRefreshAction::Signalled),
        "the follower must observe rollback instead of a transient reservation"
    );
    let queued = refresh_rx
        .try_recv()
        .expect("concurrent follower occupies freed outer capacity");
    assert_eq!(queued.zone, zone);
    assert_eq!(queued.requested_serial, Some(2));
}

#[test]
fn notify_refresh_tracker_deduplicates_within_interval() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
    let zone = DomainName::from_absolute_str("example.test.").unwrap();
    let mut token = None;

    assert_eq!(
        tracker.record_after_enqueue(&zone, |reservation| {
            token = Some(reservation);
            Ok::<(), ()>(())
        }),
        Ok(NotifyRefreshAction::Signalled)
    );
    token
        .expect("outer admission creates a dedup reservation")
        .commit();
    assert_eq!(
        tracker.record_after_enqueue(&zone, |_| Ok::<(), ()>(())),
        Ok(NotifyRefreshAction::Deduplicated)
    );
}

#[test]
fn notify_refresh_tracker_suppresses_an_active_refresh_until_it_finishes() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    );
    let zone = DomainName::from_absolute_str("example.test.").unwrap();
    registry.record_loading_start(&zone);
    let attempt = registry
        .try_begin_attempt(&zone)
        .expect("zone refresh becomes active");
    let tracker = NotifyRefreshTracker::with_refresh_registry(
        std::time::Duration::from_secs(60),
        registry,
    );

    assert_eq!(
        tracker.record_after_enqueue(&zone, |_| -> Result<(), ()> {
            panic!("active refresh must suppress outer admission")
        }),
        Ok(NotifyRefreshAction::Deduplicated)
    );
    attempt.finish();
    assert_eq!(
        tracker.record_after_enqueue(&zone, |_| Ok::<(), ()>(())),
        Ok(NotifyRefreshAction::Signalled)
    );
}

#[test]
fn notify_refresh_tracker_preserves_one_newer_serial_follow_up_during_active_refresh() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    );
    let metadata = telemetry_zone_metadata(Some(10), None);
    let zone = metadata.origin.clone();
    registry.record_success_at(&metadata, std::time::Instant::now());
    let attempt = registry
        .try_begin_attempt(&zone)
        .expect("zone refresh becomes active");
    let tracker = NotifyRefreshTracker::with_refresh_registry(
        std::time::Duration::from_secs(60),
        registry.clone(),
    );
    let mut follow_up = None;

    assert_eq!(
        tracker.record_after_enqueue_serial(&zone, Some(11), |token| {
            follow_up = Some(
                RefreshRequest::new(zone.clone(), Some(11), RefreshReason::Notify)
                    .with_notify_dedup_token(token),
            );
            Ok::<(), ()>(())
        }),
        Ok(NotifyRefreshAction::Signalled)
    );
    assert_eq!(
        tracker.record_after_enqueue_serial(&zone, Some(11), |_| -> Result<(), ()> {
            panic!("duplicate newer serial must coalesce behind the active refresh")
        }),
        Ok(NotifyRefreshAction::Deduplicated)
    );
    assert_eq!(
        tracker.record_after_enqueue_serial(&zone, Some(10), |_| -> Result<(), ()> {
            panic!("current serial must remain suppressed during the active refresh")
        }),
        Ok(NotifyRefreshAction::Deduplicated)
    );

    attempt.finish();
    let follow_up = follow_up.expect("newer serial is retained for post-completion processing");
    assert_eq!(follow_up.requested_serial, Some(11));
    assert!(follow_up.notify_incarnation_is_current(&registry));
}

#[test]
fn notify_refresh_tracker_allows_newer_serial_immediately_after_completion() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    );
    let metadata = telemetry_zone_metadata(Some(20), None);
    let zone = metadata.origin.clone();
    let now = std::time::Instant::now();
    registry.record_success_at(&metadata, now);
    let tracker = NotifyRefreshTracker::with_refresh_registry(
        std::time::Duration::from_secs(60),
        registry,
    );

    assert_eq!(
        tracker.record_after_enqueue_serial_at(&zone, Some(21), now, |_| Ok::<(), ()>(())),
        Ok(NotifyRefreshAction::Signalled)
    );
    assert_eq!(
        tracker.record_after_enqueue_serial_at(&zone, Some(21), now, |_| -> Result<(), ()> {
            panic!("same post-completion serial must deduplicate")
        }),
        Ok(NotifyRefreshAction::Deduplicated)
    );
    assert_eq!(
        tracker.record_after_enqueue_serial_at(&zone, Some(22), now, |_| Ok::<(), ()>(())),
        Ok(NotifyRefreshAction::Signalled)
    );
}

#[test]
fn notify_refresh_tracker_suppresses_recent_completion_and_allows_after_window() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    );
    let metadata = telemetry_zone_metadata(
        Some(1),
        Some(SoaTimers {
            refresh: 60,
            retry: 60,
            expire: 3600,
            minimum: 60,
        }),
    );
    let zone = metadata.origin.clone();
    let now = std::time::Instant::now();
    registry.record_success_at(&metadata, now);
    let tracker = NotifyRefreshTracker::with_refresh_registry(
        std::time::Duration::from_secs(60),
        registry.clone(),
    );

    assert_eq!(
        tracker.record_after_enqueue(&zone, |_| -> Result<(), ()> {
            panic!("recent completion must suppress outer admission")
        }),
        Ok(NotifyRefreshAction::Deduplicated)
    );

    registry.record_success_at(
        &metadata,
        now.checked_sub(std::time::Duration::from_secs(61))
            .expect("test Instant supports a one-minute subtraction"),
    );
    assert_eq!(
        tracker.record_after_enqueue(&zone, |_| Ok::<(), ()>(())),
        Ok(NotifyRefreshAction::Signalled)
    );
}

#[test]
fn notify_refresh_tracker_suppresses_recent_failed_attempt_completion() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    );
    let zone = DomainName::from_absolute_str("failed.test.").unwrap();
    registry.record_loading_start(&zone);
    let attempt = registry
        .try_begin_attempt(&zone)
        .expect("zone refresh becomes active");
    attempt.record_failure(None, Some("test failure".to_owned()));
    let tracker = NotifyRefreshTracker::with_refresh_registry(
        std::time::Duration::from_secs(60),
        registry,
    );

    assert_eq!(
        tracker.record_after_enqueue(&zone, |_| -> Result<(), ()> {
            panic!("recent failed attempt completion must suppress outer admission")
        }),
        Ok(NotifyRefreshAction::Deduplicated)
    );
}

#[test]
fn notify_refresh_tracker_accepts_maximum_safe_dedup_interval() {
    let maximum = std::time::Duration::from_secs(MAX_RUNTIME_DURATION_SECS);
    let tracker = NotifyRefreshTracker::new(maximum);
    let zone = DomainName::from_absolute_str("maximum.test.").unwrap();
    let mut token = None;
    tracker
        .record_after_enqueue(&zone, |reservation| {
            token = Some(reservation);
            Ok::<(), ()>(())
        })
        .expect("maximum-interval reservation");
    let token = token.expect("outer reservation token");
    let signalled_at = token.signalled_at;
    assert!(token.commit());

    tracker.prune_expired_at(runtime_deadline(
        signalled_at,
        maximum - std::time::Duration::from_secs(1),
    ));
    assert_eq!(
        tracker
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .len(),
        1
    );
    tracker.prune_expired_at(runtime_deadline(signalled_at, maximum));
    assert!(
        tracker
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .is_empty()
    );
}

#[test]
fn notify_refresh_tracker_allows_after_zero_interval() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::ZERO);
    let zone = DomainName::from_absolute_str("example.test.").unwrap();

    assert_eq!(
        tracker.record_after_enqueue(&zone, |_| Ok::<(), ()>(())),
        Ok(NotifyRefreshAction::Signalled)
    );
    assert_eq!(
        tracker.record_after_enqueue(&zone, |_| Ok::<(), ()>(())),
        Ok(NotifyRefreshAction::Signalled)
    );
}

#[test]
fn stale_notify_dedup_token_cannot_rollback_newer_commit() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::ZERO);
    let zone = DomainName::from_absolute_str("example.test.").unwrap();
    let mut tokens = Vec::new();

    assert_eq!(
        tracker.record_after_enqueue(&zone, |token| {
            tokens.push(token);
            Ok::<(), ()>(())
        }),
        Ok(NotifyRefreshAction::Signalled)
    );
    assert_eq!(
        tracker.record_after_enqueue(&zone, |token| {
            tokens.push(token);
            Ok::<(), ()>(())
        }),
        Ok(NotifyRefreshAction::Signalled)
    );
    tokens[0].commit();
    tokens[1].commit();

    tokens[0].rollback();
    let zone_key = zone.canonical_key();
    let latest_token_id = tracker
        .last_signal_by_zone
        .lock()
        .expect("NOTIFY refresh tracker lock poisoned")
        .get(&zone_key)
        .expect("newer commit survives stale rollback")
        .token_id;
    assert_eq!(latest_token_id, tokens[1].token_id);

    tokens[1].rollback();
    assert!(
        !tracker
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .contains_key(&zone_key)
    );
}

#[test]
fn notify_dedup_tracker_retains_all_live_keys_and_purges_removed_or_expired_zones() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
    let started_at = std::time::Instant::now();
    let count = 16 * 1024 + 4096;
    let mut committed = Vec::with_capacity(count);

    for index in 0..count {
        let zone = DomainName::from_absolute_str(&format!("member-{index}.catalog.test.")).unwrap();
        let mut token = None;
        assert_eq!(
            tracker.record_after_enqueue(&zone, |reservation| {
                token = Some(reservation);
                Ok::<(), ()>(())
            }),
            Ok(NotifyRefreshAction::Signalled)
        );
        let token = token.expect("outer reservation");
        token.commit();
        committed.push((zone, token));
    }

    assert_eq!(
        tracker
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .len(),
        count
    );
    let (first_zone, first_token) = &committed[0];
    assert_eq!(
        tracker.record_after_enqueue(first_zone, |_| Ok::<(), ()>(())),
        Ok(NotifyRefreshAction::Deduplicated)
    );
    assert_eq!(
        tracker
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .get(&first_zone.canonical_key())
            .expect("oldest live commitment is retained")
            .token_id,
        first_token.token_id
    );

    for (zone, _) in committed.iter().take(4096) {
        tracker.remove_zone(zone);
    }
    assert_eq!(
        tracker
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .len(),
        count - 4096
    );

    tracker.prune_expired_at(started_at + std::time::Duration::from_secs(61));

    assert_eq!(
        tracker
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .len(),
        0
    );
}

#[tokio::test]
async fn supervised_registry_cleanup_removes_expired_runtime_entries() {
    let notify = NotifyRefreshTracker::new(std::time::Duration::from_millis(1));
    let cooldown = IxfrCooldownRegistry::new(std::time::Duration::from_millis(1));
    let zone = DomainName::from_absolute_str("cleanup.test.").unwrap();
    let primary = "192.0.2.53:53".parse().unwrap();
    let mut token = None;
    notify
        .record_after_enqueue(&zone, |reservation| {
            token = Some(reservation);
            Ok::<(), ()>(())
        })
        .expect("outer reservation");
    token.expect("outer reservation token").commit();
    cooldown.record_unsupported(&zone, primary);

    let cleanup = tokio::spawn(serve_runtime_registry_cleanup(
        notify.clone(),
        cooldown.clone(),
        std::time::Duration::from_millis(1),
    ));
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let notify_empty = notify
                .last_signal_by_zone
                .lock()
                .expect("NOTIFY refresh tracker lock poisoned")
                .is_empty();
            let cooldown_empty = cooldown
                .disabled_until
                .lock()
                .expect("IXFR cooldown registry lock poisoned")
                .is_empty();
            if notify_empty && cooldown_empty {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("supervised registry cleanup removes expired entries");
    cleanup.abort();
    let _ = cleanup.await;
}

#[test]
fn dropped_notify_does_not_commit_dedup_state() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
    let (refresh_tx, mut refresh_rx) = mpsc::channel(1);
    let metrics = RuntimeMetrics::new();
    let zone = DomainName::from_absolute_str("example.test.").unwrap();
    let source = "192.0.2.53".parse().unwrap();

    refresh_tx
        .try_send(RefreshRequest::new(
            DomainName::from_absolute_str("queued.test.").unwrap(),
            None,
            RefreshReason::Notify,
        ))
        .expect("prefill refresh channel");
    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(2));
    let _ = refresh_rx.try_recv().expect("drain prefilled request");
    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(2));

    let admitted = refresh_rx.try_recv().expect("second NOTIFY must be admitted");
    assert_eq!(admitted.zone, zone);
    assert_eq!(admitted.preferred_primary_ip, Some(source));
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.notify_refresh_signalled, 1);
    assert_eq!(snapshot.notify_refresh_deduplicated, 0);
}

#[test]
fn failed_newer_outer_enqueue_restores_older_queued_notify_reservation() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
    let (refresh_tx, mut refresh_rx) = mpsc::channel(1);
    let metrics = RuntimeMetrics::new();
    let zone = DomainName::from_absolute_str("replacement.example.test.").unwrap();
    let source = "192.0.2.53".parse().unwrap();

    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(2));
    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(3));

    let older = refresh_rx
        .try_recv()
        .expect("the older NOTIFY remains in the full outer queue");
    assert_eq!(older.requested_serial, Some(2));
    let mut pending = std::collections::VecDeque::new();
    let mut pending_keys = HashSet::new();
    assert!(
        enqueue_pending_refresh_request(
            &mut pending,
            &mut pending_keys,
            &HashSet::new(),
            older,
        )
        .is_none(),
        "failed newer replacement must not invalidate older queued work"
    );

    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(2));
    assert!(
        refresh_rx.try_recv().is_err(),
        "restored and committed older token still deduplicates its serial"
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.notify_refresh_signalled, 1);
    assert_eq!(snapshot.notify_refresh_deduplicated, 1);
}

#[test]
fn failed_newer_replacement_restores_exact_token_without_clobbering_later_commit() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
    let zone = DomainName::from_absolute_str("token-order.example.test.").unwrap();
    let mut older = None;
    tracker
        .record_after_enqueue_serial(&zone, Some(2), |token| {
            older = Some(token);
            Ok::<(), ()>(())
        })
        .expect("older reservation succeeds");
    assert_eq!(
        tracker.record_after_enqueue_serial(&zone, Some(3), |_| Err::<(), _>(())),
        Err(())
    );
    let older = older.expect("older token captured");
    assert!(older.commit(), "failed replacement restores exact older token");

    let mut latest = None;
    assert_eq!(
        tracker.record_after_enqueue_serial(&zone, Some(4), |token| {
            latest = Some(token);
            Ok::<(), ()>(())
        }),
        Ok(NotifyRefreshAction::Signalled)
    );
    older.rollback();
    assert!(
        latest.expect("latest token captured").commit(),
        "stale restored token rollback must not erase a later replacement"
    );
}

#[test]
fn rolled_back_older_outer_reservation_does_not_erase_newer_replacement() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
    let (refresh_tx, mut refresh_rx) = mpsc::channel(2);
    let metrics = RuntimeMetrics::new();
    let zone = DomainName::from_absolute_str("example.test.").unwrap();
    let source = "192.0.2.53".parse().unwrap();

    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(2));
    let admitted = refresh_rx
        .try_recv()
        .expect("first NOTIFY reaches the outer refresh queue");
    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(3));
    let newer = refresh_rx
        .try_recv()
        .expect("a provably newer NOTIFY replaces the outer reservation");

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
        admitted,
    )
    .expect("saturated internal queue drops the admitted NOTIFY");
    dropped.rollback_notify_dedup_after_queue_drop();

    let admitted_filler = pending.pop_front().expect("saturated pending queue");
    pending_keys.remove(&admitted_filler.zone.canonical_key());
    assert!(
        enqueue_pending_refresh_request(
            &mut pending,
            &mut pending_keys,
            &active_keys,
            newer,
        )
        .is_none()
    );

    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(3));
    assert!(
        refresh_rx.try_recv().is_err(),
        "internal admission commits dedup state"
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.notify_refresh_signalled, 2);
    assert_eq!(snapshot.notify_refresh_deduplicated, 1);
}

#[test]
fn coalesced_notify_churn_retains_only_current_rollback_token() {
    const COALESCE_COUNT: u32 = 50_000;

    let tracker = NotifyRefreshTracker::new(std::time::Duration::ZERO);
    let zone = DomainName::from_absolute_str("coalesced.test.").unwrap();
    let mut pending = std::collections::VecDeque::new();
    let mut pending_keys = HashSet::new();
    let active_keys = HashSet::new();

    for serial in 1..=COALESCE_COUNT {
        let mut request = None;
        assert_eq!(
            tracker.record_after_enqueue(&zone, |token| {
                request = Some(
                    RefreshRequest::new(zone.clone(), Some(serial), RefreshReason::Notify)
                        .with_notify_dedup_token(token),
                );
                Ok::<(), ()>(())
            }),
            Ok(NotifyRefreshAction::Signalled)
        );
        assert!(
            enqueue_pending_refresh_request(
                &mut pending,
                &mut pending_keys,
                &active_keys,
                request.expect("zero-interval NOTIFY reservation"),
            )
            .is_none()
        );
    }

    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].retained_notify_dedup_token_count(), 1);
    let retained = pending
        .front()
        .and_then(|request| request.notify_dedup_token.as_ref())
        .expect("coalesced request retains its current rollback token");
    assert_eq!(
        tracker
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .get(&zone.canonical_key())
            .expect("latest coalesced NOTIFY remains committed")
            .token_id,
        retained.token_id
    );

    pending
        .pop_front()
        .expect("coalesced request")
        .rollback_notify_dedup_after_queue_drop();
    assert!(
        tracker
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .is_empty(),
        "dropping the coalesced request rolls back its one current commitment"
    );
}

#[test]
fn evicted_coalesced_newer_notify_is_recovered_at_latest_serial() {
    let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
    let (refresh_tx, mut refresh_rx) = mpsc::channel(2);
    let metrics = RuntimeMetrics::new();
    let zone = DomainName::from_absolute_str("alpha.test.").unwrap();
    let source = "192.0.2.53".parse().unwrap();
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    );
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
        std::time::Instant::now(),
    );

    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(2));
    let reserved = refresh_rx
        .try_recv()
        .expect("NOTIFY reaches the outer refresh queue");
    let mut pending = std::collections::VecDeque::new();
    let mut pending_keys = HashSet::new();
    let mut active_keys = HashSet::new();
    for index in 0..NOTIFY_REFRESH_QUEUE_CAPACITY - 1 {
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
    assert!(
        enqueue_pending_refresh_request(
            &mut pending,
            &mut pending_keys,
            &active_keys,
            reserved,
        )
        .is_none()
    );

    signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(3));
    let follower = refresh_rx
        .try_recv()
        .expect("provably newer NOTIFY reaches the coalescing queue");
    assert!(
        enqueue_pending_refresh_request(
            &mut pending,
            &mut pending_keys,
            &active_keys,
            follower,
        )
        .is_none(),
        "newer NOTIFY coalesces into the existing zone follow-up"
    );
    assert_eq!(pending.back().unwrap().requested_serial, Some(3));

    let active = DomainName::from_absolute_str("active.test.").unwrap();
    active_keys.insert(active.canonical_key());
    let dropped = enqueue_pending_refresh_request(
        &mut pending,
        &mut pending_keys,
        &active_keys,
        RefreshRequest::new(active, Some(4), RefreshReason::Notify),
    )
    .expect("active-zone follow-up evicts the committed tail request");
    assert_eq!(dropped.zone, zone);
    assert_eq!(
        dropped.retry_after_queue_drop,
        Some(RefreshReason::Notify)
    );
    dropped.rollback_notify_dedup_after_queue_drop();
    registry.defer_refresh_after_queue_drop(&dropped);

    assert_eq!(
        registry.start_due_refreshes(std::time::Instant::now()),
        vec![zone]
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.notify_refresh_signalled, 2);
    assert_eq!(snapshot.notify_refresh_deduplicated, 0);
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
async fn drain_tcp_connections_handles_unrepresentable_grace_without_panicking() {
    let active = Arc::new(AtomicUsize::new(1));
    assert!(
        !drain_tcp_connections(
            active,
            std::time::Duration::MAX,
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
    assert_eq!(
        tasks.len(),
        1,
        "deadline expiry aborts without extending the deadline to reap"
    );
}

#[tokio::test]
async fn runtime_task_panic_is_fatal_to_supervision() {
    let mut tasks = tokio::task::JoinSet::<Result<(), RuntimeError>>::new();
    tasks.spawn(async { panic!("injected listener panic") });

    let error = handle_runtime_task_result("listener", tasks.join_next().await)
        .expect_err("a supervised task panic must terminate the runtime");
    assert!(matches!(
        error,
        RuntimeError::RuntimeTask {
            task_set: "listener",
            ..
        }
    ));
}
