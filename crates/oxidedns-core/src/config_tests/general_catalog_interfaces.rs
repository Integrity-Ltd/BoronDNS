    #[test]
    fn parses_minimal_valid_config() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.server.listen_udp.len(), 1);
        assert_eq!(
            config.server.listen_tcp,
            vec![
                SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)),
                SocketAddr::from((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53)),
            ]
        );
        assert_eq!(config.server.log_level, "info");
        assert_eq!(config.server.log_format, LogFormatConfig::Json);
        assert_eq!(config.server.nsid, "");
        assert_eq!(config.process.run_as_user, None);
        assert!(config.process.disable_core_dumps);
        assert!(config.process.no_new_privileges);
        assert_eq!(config.logging.max_entry_length_bytes, 16_384);
        assert!(config.interfaces.dns.is_none());
        assert!(config.interfaces.mgmt.is_empty());
        assert!(config.interfaces.transfer.is_empty());
        assert!(config.interfaces.notify.is_empty());
        assert_eq!(config.udp_listeners(), config.server.listen_udp);
        assert_eq!(config.tcp_listeners(), config.server.listen_tcp);
        assert!(config.health_listeners().is_empty());
        assert_eq!(config.health.metrics_rate_limit_per_minute, 60);
        assert_eq!(config.health.metrics_rate_limit_idle_seconds, 300);
        assert_eq!(config.health.max_connections, DEFAULT_HEALTH_MAX_CONNECTIONS);
        assert_eq!(
            config.metrics.latency_histogram_buckets_seconds(),
            vec![
                0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.1
            ]
        );
        assert_eq!(config.metrics.hot_path_detail, MetricsHotPathDetail::Full);
        assert!(!config.metrics.pipeline_timing_enabled);
        assert!(!config.metrics.zone_shape_enabled);
        assert_eq!(config.cookie.policy, CookiePolicyConfig::Lenient);
        assert_eq!(config.cookie.timestamp_past_tolerance_seconds, 3600);
        assert_eq!(config.cookie.timestamp_future_tolerance_seconds, 300);
        assert!(config.rrl.enabled);
        assert_eq!(config.rrl.ipv4_prefix_len, 24);
        assert_eq!(config.rrl.ipv6_prefix_len, 56);
        assert_eq!(config.rrl.positive_per_second, 20);
        assert_eq!(config.rrl.nxdomain_per_second, 5);
        assert_eq!(config.rrl.nodata_per_second, 10);
        assert_eq!(config.rrl.referral_per_second, 10);
        assert_eq!(config.rrl.error_per_second, 5);
        assert_eq!(config.rrl.slip, 2);
        assert_eq!(config.rrl.max_keys, 100_000);
        assert_eq!(config.tsig.fudge_seconds, DEFAULT_TSIG_FUDGE_SECS);
        assert_eq!(config.query.any_response, AnyResponseConfig::Minimal);
        assert_eq!(config.query.any_response_mode(), AnyResponseMode::Minimal);
        assert_eq!(config.zones[0].class, "IN");
        assert_eq!(config.limits.max_udp_payload, 1232);
        assert_eq!(config.limits.udp_batch_size, 1);
        assert_eq!(config.limits.udp_reuseport_workers, 1);
        assert!(config.limits.udp_worker_cpu_affinity.is_none());
        assert_eq!(config.limits.udp_runtime, UdpRuntime::Tokio);
        assert_eq!(config.limits.udp_idle_strategy, UdpIdleStrategy::Park);
        assert_eq!(config.limits.udp_socket_receive_buffer_bytes, None);
        assert_eq!(config.limits.udp_socket_send_buffer_bytes, None);
        assert_eq!(
            config.limits.udp_socket_max_pacing_rate_bytes_per_second,
            None
        );
        assert_eq!(config.limits.udp_backend, UdpBackend::Std);
        assert_eq!(config.xdp, XdpConfig::default());
        assert_eq!(config.limits.max_cname_chain, 8);
        assert_eq!(config.limits.tcp_idle_timeout_secs, 30);
        assert_eq!(config.limits.tcp_read_timeout_secs, 30);
        assert_eq!(config.limits.tcp_write_timeout_secs, 30);
        assert_eq!(config.limits.tcp_connect_timeout_secs, 10);
        assert_eq!(config.limits.max_tcp_connections, 1024);
        assert_eq!(config.limits.max_tcp_connections_per_source, None);
        assert_eq!(config.limits.max_tcp_inflight_queries_per_connection, 64);
        assert_eq!(config.limits.tcp_inflight_limit_timeout_secs, None);
        assert_eq!(config.limits.graceful_shutdown_secs, 30);
        assert_eq!(config.limits.edns_padding_block_size, 0);
        assert_eq!(config.limits.ixfr_timeout_secs, 60);
        assert_eq!(config.limits.ixfr_disabled_cooldown_secs, 3600);
        assert_eq!(
            config.limits.max_transfer_ingest_bytes,
            4 * 1024 * 1024 * 1024
        );
        assert_eq!(config.limits.notify_dedup_secs, 1);
        assert_eq!(config.limits.notify_log_rate_window_secs, 60);
        assert_eq!(config.limits.notify_log_max_keys, 100_000);
        assert_eq!(config.limits.max_concurrent_transfers, 4);
        assert_eq!(config.limits.zsm_min_interval_secs, 60);
        assert_eq!(config.limits.zsm_max_interval_secs, 86_400);
        assert_eq!(config.limits.zsm_initial_retry_secs, 60);
        assert_eq!(config.limits.zsm_initial_retry_max_secs, 3600);
        assert_eq!(config.limits.zsm_loading_warning_threshold_secs, 3600);
        assert_eq!(
            config.zones[0].transfer_targets(),
            vec![TransferPrimaryConfig::tcp(SocketAddr::from((
                Ipv4Addr::new(192, 0, 2, 53),
                53
            )))]
        );
    }

    #[test]
    fn parses_and_redacts_control_plane_telemetry_config() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [control_plane.telemetry]
                endpoint_url = "https://udns.example.internal/api/v1"
                node_id = "11111111-1111-1111-1111-111111111111"
                bearer_token = "secret-node-token"

                [control_plane.operations]
                enabled = true
                endpoint_url = "https://udns.example.internal/api/v1"
                node_id = "11111111-1111-1111-1111-111111111111"
                bearer_token = "secret-operation-token"
                poll_interval_secs = 2
                lease_seconds = 30

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid telemetry config");

        assert!(config.control_plane.telemetry.enabled());
        assert!(config.control_plane.operations.enabled());
        let redacted = config.to_redacted_toml().expect("redacted config");
        assert!(redacted.contains("bearer_token = \"<redacted>\""));
        assert!(!redacted.contains("secret-node-token"));
        assert!(!redacted.contains("secret-operation-token"));
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret-node-token"));
        assert!(!debug.contains("secret-operation-token"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn rejects_partial_control_plane_telemetry_config() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [control_plane.telemetry]
                endpoint_url = "https://udns.example.internal/api/v1"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("partial telemetry config should fail");

        assert!(error.to_string().contains("must be set together"));
    }

    #[test]
    fn control_plane_node_ids_are_strict_opaque_segments() {
        let parse = |section: &str, node_id: &str| {
            let enabled = if section == "operations" {
                "enabled = true"
            } else {
                ""
            };
            ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [control_plane.{section}]
                    {enabled}
                    endpoint_url = "https://udns.example.internal/api/v1"
                    node_id = "{node_id}"
                    bearer_token = "token-a"

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ))
        };

        for node_id in ["node-a", "node.a_1", "11111111-1111-1111-1111-111111111111"] {
            assert!(parse("operations", node_id).is_ok(), "rejected {node_id:?}");
        }
        for section in ["telemetry", "operations"] {
            for node_id in [
                "", ".", "..", ".hidden", "node/a", "node?admin", "node#fragment",
                "node%2fadmin", "node%252fadmin", "node\\nadmin", "node admin", "nøde",
            ] {
                let error = parse(section, node_id)
                    .expect_err(&format!("accepted unsafe node ID {node_id:?}"));
                assert!(
                    error.to_string().contains("must match [A-Za-z0-9]"),
                    "unexpected error for {section} {node_id:?}: {error}"
                );
            }
        }
    }

    #[test]
    fn rejects_enabled_control_plane_operations_without_credentials() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [control_plane.operations]
                enabled = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("enabled operations config without credentials should fail");

        assert!(
            error
                .to_string()
                .contains("must be set when operations polling is enabled")
        );
    }

    #[test]
    fn control_plane_http_requires_explicit_loopback_only_override() {
        let base = |endpoint: &str, override_line: &str| {
            ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [control_plane.operations]
                    enabled = true
                    endpoint_url = "{endpoint}"
                    {override_line}
                    node_id = "node-a"
                    bearer_token = "token-a"

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ))
        };

        assert!(base("http://127.0.0.1:8080/api/v1", "").is_err());
        assert!(
            base(
                "http://127.0.0.1:8080/api/v1",
                "allow_insecure_loopback_http = true"
            )
            .is_ok()
        );
        assert!(
            base(
                "http://[::1]:8080/api/v1",
                "allow_insecure_loopback_http = true"
            )
            .is_ok()
        );
        assert!(
            base(
                "http://192.0.2.1:8080/api/v1",
                "allow_insecure_loopback_http = true"
            )
            .is_err()
        );
        assert!(
            base(
                "http://127.0.0.1.example:8080/api/v1",
                "allow_insecure_loopback_http = true"
            )
            .is_err()
        );
        assert!(base("https://udns.example.internal/api/v1", "").is_ok());
        for endpoint in [
            "https://",
            "https://user@udns.example.internal/api/v1",
            "https://udns.example.internal/api/v1?redirect=1",
            "https://udns.example.internal/api/v1#operations",
            "ftp://udns.example.internal/api/v1",
        ] {
            assert!(base(endpoint, "").is_err(), "accepted {endpoint}");
        }
        assert!(
            base(
                "http://127.0.0.1:99999/api/v1",
                "allow_insecure_loopback_http = true"
            )
            .is_err()
        );
    }

    #[test]
    fn parses_catalog_zone_without_static_zones() {
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
                max_member_zones = 42
            "#,
        )
        .expect("valid catalog-only config");

        assert!(config.zones.is_empty());
        assert_eq!(config.catalog_zones.len(), 1);
        assert!(!config.catalog_zones[0].serve_catalog_zone);
        assert_eq!(
            config.catalog_zones[0].transfer_target_addrs(),
            vec![SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53))]
        );
        assert_eq!(
            config.catalog_zones[0].member_transfer_target_addrs(),
            vec![SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53))]
        );
        assert_eq!(config.catalog_zones[0].max_member_zones, 42);
    }

    #[test]
    fn rejects_duplicate_zone_apexes_case_insensitively() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]

                [[zones]]
                name = "EXAMPLE.TEST."
                primaries = ["192.0.2.54:53"]
            "#,
        )
        .expect_err("duplicate zone apexes must fail validation");

        assert!(error.to_string().contains("duplicate configured zone apex"));
    }

    #[test]
    fn rejects_static_zone_and_catalog_zone_apex_clash() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]

                [[catalog_zones]]
                name = "example.test."
                primaries = ["192.0.2.54:53"]
                notify_sources = ["192.0.2.54"]
                tsig_key = "catalog-key."
            "#,
        )
        .expect_err("static zone and catalog apex clash must fail validation");

        assert!(error.to_string().contains("duplicate configured zone apex"));
    }

    #[test]
    fn rejects_invalid_catalog_zone_names_before_runtime_startup() {
        for (name, expected) in [
            ("", "catalog zone name must not be empty"),
            (
                "example",
                "must be an absolute DNS name ending with '.'",
            ),
            ("a..b.", "is not a valid DNS name"),
        ] {
            let toml = format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]
                    listen_tcp = []

                    [[tsig_keys]]
                    name = "catalog-key."
                    algorithm = "hmac-sha256"
                    secret = "dG9wc2VjcmV0"

                    [[catalog_zones]]
                    name = "{name}"
                    primaries = ["192.0.2.53:53"]
                    tsig_key = "catalog-key."
                "#
            );
            let error = ServerConfig::from_toml_str(&toml)
                .expect_err("invalid catalog zone name is rejected by validation");

            assert!(
                error.to_string().contains(expected),
                "expected {expected:?} in {error}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_catalog_zone_class() {
        let error = ServerConfig::from_toml_str(
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
                class = "CH"
                primaries = ["192.0.2.53:53"]
                tsig_key = "catalog-key."
            "#,
        )
        .expect_err("catalog zones only support IN");

        assert!(
            error
                .to_string()
                .contains("uses unsupported class CH; only IN is currently allowed")
        );
    }

    #[test]
    fn parses_split_catalog_and_member_transfer_policy() {
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
                max_member_zones = 42
            "#,
        )
        .expect("valid split catalog config");

        let catalog = &config.catalog_zones[0];
        assert!(catalog.primaries.is_empty());
        assert_eq!(
            catalog.catalog_transfer_target_addrs(),
            vec![SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53))]
        );
        assert_eq!(
            catalog.member_transfer_target_addrs(),
            vec![SocketAddr::from((Ipv4Addr::new(198, 51, 100, 53), 53))]
        );
        assert_eq!(catalog.catalog_tsig_key_name(), Some("catalog-key."));
        assert_eq!(catalog.member_tsig_key_name(), Some("member-key."));
        assert_eq!(catalog.all_transfer_targets().len(), 2);
    }

    #[test]
    fn default_catalog_member_transfer_policy_inherits_catalog_tsig() {
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
                tsig_key = "catalog-key."
            "#,
        )
        .expect("valid default catalog member transfer policy");

        let catalog = &config.catalog_zones[0];
        assert_eq!(catalog.catalog_tsig_key_name(), Some("catalog-key."));
        assert_eq!(catalog.member_tsig_key_name(), Some("catalog-key."));
        assert_eq!(
            catalog.member_transfer_policy.unsigned_axfr,
            CatalogMemberUnsignedAxfrPolicy::Deny
        );
    }

    #[test]
    fn legacy_catalog_member_transfer_policy_allows_unsigned_member_axfr_only() {
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
        .expect("valid legacy unsigned member transfer policy");

        let catalog = &config.catalog_zones[0];
        assert_eq!(catalog.catalog_tsig_key_name(), Some("catalog-key."));
        assert_eq!(catalog.member_tsig_key_name(), None);
        assert!(catalog.member_transfer_allows_unsigned_axfr());
        assert!(
            config
                .configuration_warnings()
                .iter()
                .any(|warning| warning.code == "catalog_member_unsigned_axfr_allowed")
        );
    }

    #[test]
    fn legacy_catalog_member_transfer_policy_rejects_public_unsigned_member_primary() {
        let error = ServerConfig::from_toml_str(
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
                member_primaries = ["203.0.113.53:53"]
                catalog_tsig_key = "catalog-key."

                [catalog_zones.member_transfer_policy]
                unsigned_axfr = "allow-legacy-private"
            "#,
        )
        .expect_err("legacy unsigned member AXFR is private-only");

        assert!(
            error
                .to_string()
                .contains("allows legacy unsigned member AXFR")
        );
    }

    #[test]
    fn catalog_member_transfer_policy_deny_requires_member_tsig_key() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [transfer]
                require_tsig = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["192.0.2.53:53"]
                member_primaries = ["203.0.113.53:53"]
                catalog_tsig_key = "catalog-key."
            "#,
        )
        .expect_err("deny-unsigned member transfers require a member TSIG key");

        assert!(
            error
                .to_string()
                .contains("requires member_tsig_key or shared tsig_key")
        );
    }

    #[test]
    fn rejects_split_catalog_policy_with_missing_member_key() {
        let error = ServerConfig::from_toml_str(
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
                member_primaries = ["198.51.100.53:53"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "missing-key."
            "#,
        )
        .expect_err("missing member key is invalid");

        assert!(
            error
                .to_string()
                .contains("references unknown member_tsig_key missing-key.")
        );
    }

    #[test]
    fn rejects_zero_catalog_member_zone_cap() {
        let error = ServerConfig::from_toml_str(
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
                tsig_key = "catalog-key."
                max_member_zones = 0
            "#,
        )
        .expect_err("zero catalog member cap is invalid");

        assert!(error.to_string().contains("max_member_zones"));
    }

    #[test]
    fn rejects_catalog_zone_without_tsig_key() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[catalog_zones]]
                name = "catalog.example."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("catalog TSIG is mandatory");

        assert!(
            error
                .to_string()
                .contains("catalog-zone transfers must be TSIG-authenticated")
        );
    }

    #[test]
    fn parses_process_run_as_user() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [process]
                run_as_user = "oxidedns"
                disable_core_dumps = false
                no_new_privileges = false

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid process config");

        assert_eq!(config.process.run_as_user.as_deref(), Some("oxidedns"));
        assert!(!config.process.disable_core_dumps);
        assert!(!config.process.no_new_privileges);
    }

    #[test]
    fn rejects_empty_process_run_as_user() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [process]
                run_as_user = "   "

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("empty run_as_user must fail validation");

        assert!(
            error
                .to_string()
                .contains("process.run_as_user must not be empty"),
            "{error}"
        );
    }

    #[test]
    fn parses_logging_configuration() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [logging]
                max_entry_length_bytes = 4096

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.logging.max_entry_length_bytes, 4096);
    }

    #[test]
    fn parses_three_srs_interface_roles() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = ["127.0.0.1:5301"]
                health = "127.0.0.1:8081"

                [interfaces]
                dns = [
                    { address = "127.0.0.2:5300", name = "eth-dns" },
                    "[::1]:5300",
                ]
                mgmt = ["127.0.0.3:9443"]
                transfer = ["127.0.0.4:0", "[::1]:0"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(
            config.interfaces.dns,
            Some(vec![
                InterfaceEndpoint::new(
                    "127.0.0.2:5300".parse::<SocketAddr>().unwrap(),
                    Some("eth-dns".to_owned()),
                ),
                InterfaceEndpoint::new("[::1]:5300".parse::<SocketAddr>().unwrap(), None),
            ])
        );
        assert_eq!(
            config.interfaces.mgmt,
            vec!["127.0.0.3:9443".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            config.interfaces.transfer,
            vec![
                "127.0.0.4:0".parse::<SocketAddr>().unwrap(),
                "[::1]:0".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert_eq!(
            config.dns_udp_listeners(),
            vec![
                "127.0.0.2:5300".parse::<SocketAddr>().unwrap(),
                "[::1]:5300".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert_eq!(config.dns_tcp_listeners(), config.dns_udp_listeners());
        assert_eq!(
            config.udp_listeners(),
            vec![
                "127.0.0.2:5300".parse::<SocketAddr>().unwrap(),
                "[::1]:5300".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert_eq!(
            config.health_listeners(),
            vec!["127.0.0.1:8081".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            config.transfer_source(),
            Some("127.0.0.4:0".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn health_listeners_use_srs_precedence() {
        let explicit = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                health = "127.0.0.1:8081"

                [interfaces]
                mgmt = ["127.0.0.2:9443"]

                [health]
                bind_address = "127.0.0.3"
                bind_port = 8083
                default_port = 8084

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");
        assert_eq!(
            explicit.health_listeners(),
            vec!["127.0.0.3:8083".parse::<SocketAddr>().unwrap()]
        );

        let mgmt = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [interfaces]
                mgmt = ["127.0.0.2:9443", "[::1]:9443"]

                [health]
                default_port = 8084

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");
        assert_eq!(
            mgmt.health_listeners(),
            vec![
                "127.0.0.2:8084".parse::<SocketAddr>().unwrap(),
                "[::1]:8084".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn rejects_invalid_srs_interface_roles() {
        for (label, config, expected) in [
            (
                "empty dns",
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [interfaces]
                    dns = []

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
                "interfaces.dns must contain at least one listener",
            ),
            (
                "empty dns interface name",
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [interfaces]
                    dns = [{ address = "127.0.0.2:5300", name = " " }]

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
                "interfaces.dns interface name must not be empty",
            ),
            (
                "fixed transfer source port",
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [interfaces]
                    transfer = ["127.0.0.2:5353"]

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
                "interfaces.transfer source 127.0.0.2:5353 must use port 0",
            ),
            (
                "duplicate transfer family",
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [interfaces]
                    transfer = ["127.0.0.2:0", "127.0.0.3:0"]

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
                "interfaces.transfer must contain at most one IPv4 source",
            ),
            (
                "partial explicit health bind",
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [health]
                    bind_address = "127.0.0.1"

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
                "health.bind_address and health.bind_port must be configured together",
            ),
            (
                "transfer family mismatch",
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [interfaces]
                    transfer = ["127.0.0.2:0"]

                    [[zones]]
                    name = "example.test."
                    primaries = ["[2001:db8::53]:53"]
                "#,
                "has no IPv6 transfer source",
            ),
        ] {
            let error = ServerConfig::from_toml_str(config).expect_err(label);
            assert!(error.to_string().contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn rejects_unknown_configuration_keys() {
        for (label, config, expected) in [
            (
                "top-level",
                r#"
                    unexpected = true

                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
                "unknown field",
            ),
            (
                "nested",
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]
                    listen_quic = ["127.0.0.1:853"]

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
                "unknown field",
            ),
            (
                "dns endpoint",
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [interfaces]
                    dns = [{ address = "127.0.0.2:5300", nic = "eth0" }]

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
                "did not match any variant",
            ),
        ] {
            let error = ServerConfig::from_toml_str(config).expect_err(label);
            assert!(error.to_string().contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn warns_when_dns_and_mgmt_interfaces_overlap_unintentionally() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [interfaces]
                dns = ["0.0.0.0:5300"]
                mgmt = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");
        assert!(
            config
                .configuration_warnings()
                .iter()
                .any(|warning| warning.code == "interfaces_dns_mgmt_overlap")
        );

        let intentional = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [interfaces]
                dns = ["127.0.0.1:5300"]
                mgmt = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");
        assert!(
            !intentional
                .configuration_warnings()
                .iter()
                .any(|warning| warning.code == "interfaces_dns_mgmt_overlap")
        );
    }

    #[test]
    fn rejects_notify_interface_listeners_under_three_role_model() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = ["127.0.0.1:5301"]

                [interfaces]
                notify = ["127.0.0.1:5302", "[::1]:5302"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("notify interface is not a fourth role");

        assert!(
            error
                .to_string()
                .contains("interfaces.notify is not part of the three-role interface model"),
            "{error}"
        );
    }

    #[test]
    fn rejects_notify_interface_even_when_it_overlaps_with_dns_listeners() {
        for (label, config) in [
            (
                "udp exact",
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]
                    listen_tcp = []

                    [interfaces]
                    notify = ["127.0.0.1:5300"]

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ),
            (
                "tcp wildcard",
                r#"
                    [server]
                    listen_udp = []
                    listen_tcp = ["0.0.0.0:5300"]

                    [interfaces]
                    notify = ["127.0.0.1:5300"]

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ),
            (
                "interfaces dns exact",
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]
                    listen_tcp = []

                    [interfaces]
                    dns = ["127.0.0.2:5300"]
                    notify = ["127.0.0.2:5300"]

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ),
        ] {
            let error = ServerConfig::from_toml_str(config).expect_err(label);
            assert!(
                error
                    .to_string()
                    .contains("interfaces.notify is not part of the three-role interface model"),
                "{label}: {error}"
            );
        }
    }

    #[test]
    fn rejects_obsolete_xot_interface_key() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [interfaces]
                xot = ["127.0.0.1:853"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("obsolete interface key must fail validation");

        assert!(error.to_string().contains("interfaces.xot is obsolete"));
    }

    #[test]
    fn reports_suspicious_but_valid_configuration_warnings() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [cookie]
                policy = "disabled"

                [rrl]
                allowlist = ["0.0.0.0/0", "::/0"]

                [limits]
                tcp_idle_timeout_secs = 121
                max_transfer_ingest_bytes = 1048575

                [tsig]
                fudge_seconds = 61

                [[tsig_keys]]
                name = "legacy-key."
                algorithm = "hmac-sha1"
                secret = "c2VjcmV0LWtleQ=="

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "legacy-key."
            "#,
        )
        .expect("suspicious but valid config");

        let warnings = config.configuration_warnings();
        let codes = warnings
            .iter()
            .map(|warning| warning.code)
            .collect::<Vec<_>>();

        assert!(codes.contains(&"dns_cookies_disabled"));
        assert_eq!(
            codes
                .iter()
                .filter(|code| **code == "rrl_global_allowlist")
                .count(),
            2
        );
        assert!(codes.contains(&"tcp_idle_timeout_large"));
        assert!(codes.contains(&"tsig_fudge_large"));
        assert!(codes.contains(&"transfer_ingest_cap_low"));
        assert!(codes.contains(&"tsig_hmac_sha1"));
    }

    #[test]
    fn parses_tsig_fudge_seconds() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [tsig]
                fudge_seconds = 30

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.tsig.fudge_seconds, 30);
    }

    #[test]
    fn parses_transfer_policy_settings() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [transfer]
                require_tsig = false

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert!(!config.transfer.require_tsig);
        assert!(
            config
                .configuration_warnings()
                .iter()
                .any(|warning| warning.code == "zone_transfer_unauthenticated")
        );
    }

    #[test]
    fn secret_store_allows_runtime_tsig_key_references() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [secret_store]
                path = "/etc/oxidedns/secrets.d/current"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "runtime-key."
            "#,
        )
        .expect("secret-store-backed TSIG reference is valid at config parse time");

        assert_eq!(
            config.secret_store.path.as_deref(),
            Some(std::path::Path::new("/etc/oxidedns/secrets.d/current"))
        );
        assert_eq!(config.zones[0].tsig_key.as_deref(), Some("runtime-key."));
    }

    #[test]
    fn rejects_removed_out_of_zone_glue_transfer_setting() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [transfer]
                accept_out_of_zone_glue = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("removed out-of-zone glue tolerance knob must be rejected");

        assert!(error.to_string().contains("accept_out_of_zone_glue"));
    }
