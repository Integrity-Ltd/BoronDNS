    #[test]
    fn parses_full_any_response_policy() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [query]
                any_response = "full"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.query.any_response, AnyResponseConfig::Full);
        assert_eq!(config.query.any_response_mode(), AnyResponseMode::Full);
    }

    #[test]
    fn rejects_invalid_any_response_policy() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [query]
                any_response = "hinfo"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("invalid any-response policy must fail");

        assert!(error.to_string().contains("any_response"));
    }

    #[test]
    fn parses_custom_cname_chain_limit() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_cname_chain = 4

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.max_cname_chain, 4);
    }

    #[test]
    fn rejects_zero_cname_chain_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_cname_chain = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero CNAME chain limit must fail");

        assert!(error.to_string().contains("max_cname_chain"));
    }

    #[test]
    fn parses_custom_tcp_idle_timeout() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                tcp_idle_timeout_secs = 5
                tcp_read_timeout_secs = 6
                tcp_write_timeout_secs = 7
                tcp_connect_timeout_secs = 8

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.tcp_idle_timeout_secs, 5);
        assert_eq!(config.limits.tcp_read_timeout_secs, 6);
        assert_eq!(config.limits.tcp_write_timeout_secs, 7);
        assert_eq!(config.limits.tcp_connect_timeout_secs, 8);
    }

    #[test]
    fn rejects_zero_tcp_idle_timeout() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                tcp_idle_timeout_secs = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero TCP idle timeout must fail");

        assert!(error.to_string().contains("tcp_idle_timeout_secs"));
    }

    #[test]
    fn rejects_zero_tcp_read_or_write_timeout() {
        for (key, expected) in [
            ("tcp_read_timeout_secs", "tcp_read_timeout_secs"),
            ("tcp_write_timeout_secs", "tcp_write_timeout_secs"),
            ("tcp_connect_timeout_secs", "tcp_connect_timeout_secs"),
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_tcp = ["127.0.0.1:5300"]

                    [limits]
                    {key} = 0

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("zero TCP read/write timeout must fail");

            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn parses_custom_tcp_connection_limit() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                max_tcp_connections = 16
                max_tcp_connections_per_source = 2
                max_tcp_inflight_queries_per_connection = 4
                tcp_inflight_limit_timeout_secs = 9

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.max_tcp_connections, 16);
        assert_eq!(config.limits.max_tcp_connections_per_source, Some(2));
        assert_eq!(config.limits.max_tcp_inflight_queries_per_connection, 4);
        assert_eq!(config.limits.tcp_inflight_limit_timeout_secs, Some(9));
    }

    #[test]
    fn rejects_zero_tcp_connection_limit() {
        for (key, expected) in [
            ("max_tcp_connections", "max_tcp_connections"),
            (
                "max_tcp_connections_per_source",
                "max_tcp_connections_per_source",
            ),
            (
                "max_tcp_inflight_queries_per_connection",
                "max_tcp_inflight_queries_per_connection",
            ),
            (
                "tcp_inflight_limit_timeout_secs",
                "tcp_inflight_limit_timeout_secs",
            ),
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_tcp = ["127.0.0.1:5300"]

                    [limits]
                    {key} = 0

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("zero TCP limit must fail");

            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn accepts_tcp_inflight_query_limit_at_tokio_capacity_boundaries() {
        for limit in [1, MAX_TOKIO_SEMAPHORE_PERMITS] {
            let config = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_tcp = ["127.0.0.1:5300"]

                    [limits]
                    max_tcp_inflight_queries_per_connection = {limit}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect("Tokio-safe TCP in-flight capacity must validate");

            assert_eq!(
                config.limits.max_tcp_inflight_queries_per_connection,
                limit
            );
        }
    }

    #[test]
    fn rejects_tcp_inflight_query_limit_above_tokio_capacity() {
        let first_invalid = MAX_TOKIO_SEMAPHORE_PERMITS
            .checked_add(1)
            .expect("Tokio semaphore maximum leaves room for an invalid boundary");
        let error = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                max_tcp_inflight_queries_per_connection = {first_invalid}

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#
        ))
        .expect_err("first capacity above Tokio's bound must fail validation");

        let message = error.to_string();
        assert!(message.contains("max_tcp_inflight_queries_per_connection"));
        assert!(message.contains("must not exceed"));
    }

    #[test]
    fn rejects_usize_max_tcp_inflight_query_limit_when_programmatically_mutated() {
        let mut config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("baseline config validates");
        config.limits.max_tcp_inflight_queries_per_connection = usize::MAX;

        let error = config
            .validate()
            .expect_err("usize::MAX would panic Tokio's bounded primitives");
        assert!(
            error
                .to_string()
                .contains("max_tcp_inflight_queries_per_connection")
        );
    }

    #[test]
    fn parses_notify_timing_limits() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                notify_dedup_secs = 3
                notify_log_rate_window_secs = 12
                notify_log_max_keys = 1234

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.notify_dedup_secs, 3);
        assert_eq!(config.limits.notify_log_rate_window_secs, 12);
        assert_eq!(config.limits.notify_log_max_keys, 1234);
    }

    #[test]
    fn rejects_zero_notify_timing_limits() {
        for (key, expected) in [
            ("notify_dedup_secs", "notify_dedup_secs"),
            ("notify_log_rate_window_secs", "notify_log_rate_window_secs"),
            ("notify_log_max_keys", "notify_log_max_keys"),
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [limits]
                    {key} = 0

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("zero NOTIFY timing limit must fail");

            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn parses_custom_graceful_shutdown_limit() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                graceful_shutdown_secs = 10

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.graceful_shutdown_secs, 10);
    }

    #[test]
    fn rejects_zero_graceful_shutdown_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_tcp = ["127.0.0.1:5300"]

                [limits]
                graceful_shutdown_secs = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero graceful shutdown limit must fail");

        assert!(error.to_string().contains("graceful_shutdown_secs"));
    }

    #[test]
    fn accepts_maximum_safe_runtime_durations() {
        let max = MAX_RUNTIME_DURATION_SECS;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                tcp_idle_timeout_secs = {max}
                tcp_read_timeout_secs = {max}
                tcp_write_timeout_secs = {max}
                tcp_connect_timeout_secs = {max}
                tcp_inflight_limit_timeout_secs = {max}
                graceful_shutdown_secs = {max}
                axfr_timeout_secs = {max}
                ixfr_timeout_secs = {max}
                ixfr_disabled_cooldown_secs = {max}
                notify_dedup_secs = {max}
                notify_log_rate_window_secs = {max}
                zsm_min_interval_secs = {max}
                zsm_max_interval_secs = {max}
                zsm_initial_retry_secs = {max}
                zsm_initial_retry_max_secs = {max}
                zsm_loading_warning_threshold_secs = {max}

                [health]
                metrics_rate_limit_idle_seconds = {max}

                [observability]
                rate_limit_idle_seconds = {max}

                [rrl]
                summary_log_interval_secs = {max}

                [cookie]
                secret_rotation_interval_secs = {max}

                [control_plane.telemetry]
                timeout_secs = {max}

                [control_plane.operations]
                poll_interval_secs = {max}
                lease_seconds = {max}
                timeout_secs = {max}

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#
        ))
        .expect("documented maximum runtime durations are valid");

        assert_eq!(config.limits.graceful_shutdown_secs, max);
        assert_eq!(config.control_plane.operations.poll_interval_secs, max);
        assert_eq!(config.cookie.secret_rotation_interval_secs, max);
    }

    #[test]
    fn rejects_runtime_durations_above_safe_maximum() {
        let over = MAX_RUNTIME_DURATION_SECS + 1;
        let limit_cases = [
            ("tcp_idle_timeout_secs", "tcp_idle_timeout_secs = {over}"),
            ("tcp_read_timeout_secs", "tcp_read_timeout_secs = {over}"),
            ("tcp_write_timeout_secs", "tcp_write_timeout_secs = {over}"),
            (
                "tcp_connect_timeout_secs",
                "tcp_connect_timeout_secs = {over}",
            ),
            (
                "tcp_inflight_limit_timeout_secs",
                "tcp_inflight_limit_timeout_secs = {over}",
            ),
            ("graceful_shutdown_secs", "graceful_shutdown_secs = {over}"),
            ("axfr_timeout_secs", "axfr_timeout_secs = {over}"),
            ("ixfr_timeout_secs", "ixfr_timeout_secs = {over}"),
            (
                "ixfr_disabled_cooldown_secs",
                "ixfr_disabled_cooldown_secs = {over}",
            ),
            ("notify_dedup_secs", "notify_dedup_secs = {over}"),
            (
                "notify_log_rate_window_secs",
                "notify_log_rate_window_secs = {over}",
            ),
            (
                "zsm_min_interval_secs",
                "zsm_min_interval_secs = {over}\nzsm_max_interval_secs = {over}",
            ),
            ("zsm_max_interval_secs", "zsm_max_interval_secs = {over}"),
            (
                "zsm_initial_retry_secs",
                "zsm_initial_retry_secs = {over}\nzsm_initial_retry_max_secs = {over}",
            ),
            (
                "zsm_initial_retry_max_secs",
                "zsm_initial_retry_max_secs = {over}",
            ),
            (
                "zsm_loading_warning_threshold_secs",
                "zsm_loading_warning_threshold_secs = {over}",
            ),
        ];
        for (expected, snippet) in limit_cases {
            let snippet = snippet.replace("{over}", &over.to_string());
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [limits]
                    {snippet}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("over-bound runtime duration must fail validation");
            let rendered = error.to_string();
            assert!(rendered.contains(expected), "unexpected error: {rendered}");
            assert!(rendered.contains("must not exceed"), "unexpected error: {rendered}");
        }

        for (section, parameter) in [
            ("health", "metrics_rate_limit_idle_seconds"),
            ("observability", "rate_limit_idle_seconds"),
            ("rrl", "summary_log_interval_secs"),
            ("cookie", "secret_rotation_interval_secs"),
            ("control_plane.telemetry", "timeout_secs"),
            ("control_plane.operations", "poll_interval_secs"),
            ("control_plane.operations", "lease_seconds"),
            ("control_plane.operations", "timeout_secs"),
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [{section}]
                    {parameter} = {over}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("over-bound runtime duration must fail validation");
            let rendered = error.to_string();
            assert!(rendered.contains(parameter), "unexpected error: {rendered}");
            assert!(rendered.contains("must not exceed"), "unexpected error: {rendered}");
        }
    }

    #[test]
    fn rejects_edns_padding_without_encrypted_query_listener() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                edns_padding_block_size = 128

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("plaintext-only query listeners cannot emit RFC 7830 padding");

        let rendered = error.to_string();
        assert!(rendered.contains("edns_padding_block_size"));
        assert!(rendered.contains("encrypted DNS query transport"));
    }

    #[test]
    fn rejects_one_octet_edns_padding_block_size() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                edns_padding_block_size = 1

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("one-octet padding block is not useful");

        assert!(error.to_string().contains("edns_padding_block_size"));
    }

    #[test]
    fn parses_custom_zsm_intervals() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                zsm_min_interval_secs = 120
                zsm_max_interval_secs = 86400
                zsm_initial_retry_secs = 30
                zsm_initial_retry_max_secs = 900
                zsm_loading_warning_threshold_secs = 1200

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.zsm_min_interval_secs, 120);
        assert_eq!(config.limits.zsm_max_interval_secs, 86_400);
        assert_eq!(config.limits.zsm_initial_retry_secs, 30);
        assert_eq!(config.limits.zsm_initial_retry_max_secs, 900);
        assert_eq!(config.limits.zsm_loading_warning_threshold_secs, 1200);
    }

    #[test]
    fn parses_custom_ixfr_disabled_cooldown() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                ixfr_disabled_cooldown_secs = 300

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.ixfr_disabled_cooldown_secs, 300);
    }

    #[test]
    fn rejects_zero_ixfr_disabled_cooldown() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                ixfr_disabled_cooldown_secs = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero IXFR disabled cooldown must fail");

        assert!(error.to_string().contains("ixfr_disabled_cooldown_secs"));
    }

    #[test]
    fn parses_custom_transfer_concurrency_limit() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_concurrent_transfers = 2

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.max_concurrent_transfers, 2);
    }

    #[test]
    fn parses_custom_transfer_ingest_size_cap() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_transfer_ingest_bytes = 104857600

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.max_transfer_ingest_bytes, 104_857_600);
    }

    #[test]
    fn parses_custom_transfer_ingest_message_cap() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_transfer_ingest_messages = 1000000

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.max_transfer_ingest_messages, 1_000_000);
    }

    #[test]
    fn rejects_zero_transfer_concurrency_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_concurrent_transfers = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero transfer concurrency limit must fail");

        assert!(error.to_string().contains("max_concurrent_transfers"));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn rejects_transfer_concurrency_above_tokio_semaphore_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_concurrent_transfers = 18446744073709551615

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("overlarge transfer concurrency would panic Semaphore::new");

        assert!(error.to_string().contains("max_concurrent_transfers"));
        assert!(error.to_string().contains("must not exceed"));
    }

    #[test]
    fn rejects_zero_transfer_ingest_size_cap() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_transfer_ingest_bytes = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero transfer ingest size cap must fail");

        assert!(error.to_string().contains("max_transfer_ingest_bytes"));
    }

    #[test]
    fn rejects_zero_transfer_ingest_message_cap() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_transfer_ingest_messages = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero transfer ingest message cap must fail");

        assert!(
            error
                .to_string()
                .contains("max_transfer_ingest_messages")
        );
    }
