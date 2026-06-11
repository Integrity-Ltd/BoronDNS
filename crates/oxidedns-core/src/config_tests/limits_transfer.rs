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
    fn parses_notify_timing_limits() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                notify_dedup_secs = 3
                notify_log_rate_window_secs = 12

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.limits.notify_dedup_secs, 3);
        assert_eq!(config.limits.notify_log_rate_window_secs, 12);
    }

    #[test]
    fn rejects_zero_notify_timing_limits() {
        for (key, expected) in [
            ("notify_dedup_secs", "notify_dedup_secs"),
            ("notify_log_rate_window_secs", "notify_log_rate_window_secs"),
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
    fn parses_custom_edns_padding_block_size() {
        let config = ServerConfig::from_toml_str(
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
        .expect("valid config");

        assert_eq!(config.limits.edns_padding_block_size, 128);
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

