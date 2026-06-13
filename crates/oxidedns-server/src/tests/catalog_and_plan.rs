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

#[test]
fn runtime_initializes_catalog_zones_with_serve_policy() {
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

    let runtime = Runtime::new(config);

    assert_eq!(runtime.zone_count(), 2);
    assert!(runtime.zones.is_hidden(&hidden_catalog));
    assert!(!runtime.zones.is_hidden(&visible_catalog));
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
async fn catalog_snapshot_reconciles_retained_and_removed_members() {
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
    let notify_authority = NotifyAuthority::from_config_for_test(&config);
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

    let updated_snapshot =
        catalog_snapshot_with_members(catalog_origin.clone(), 8, std::slice::from_ref(&alpha_origin));
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
}

#[tokio::test]
async fn concurrent_catalog_member_migration_preserves_member_resources() {
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
                name = "a.catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."

                [[catalog_zones]]
                name = "b.catalog.example."
                catalog_primaries = ["192.0.2.54:53"]
                member_primaries = ["10.0.0.54:53"]
                catalog_tsig_key = "catalog-key."
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
async fn catalog_reconciliation_does_not_block_when_refresh_queue_is_full() {
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
                name = "a.catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["10.0.0.53:53"]
                catalog_tsig_key = "catalog-key."

                [[catalog_zones]]
                name = "b.catalog.example."
                catalog_primaries = ["192.0.2.54:53"]
                member_primaries = ["10.0.0.54:53"]
                catalog_tsig_key = "catalog-key."
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
    tx.try_send(RefreshRequest {
        zone: queued_origin.clone(),
        requested_serial: None,
        reason: RefreshReason::Catalog,
    })
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

#[test]
fn legacy_catalog_member_transfer_policy_keeps_catalog_signed_but_members_unsigned() {
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
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

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
    let transfer_override = oxidedns_core::catalog::CatalogMemberTransfer {
        primaries: vec![oxidedns_core::catalog::CatalogMemberPrimary {
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
    let authority = NotifyAuthority::from_config_for_test(&config);
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
    let authority = NotifyAuthority::from_config_for_test(&config);
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
