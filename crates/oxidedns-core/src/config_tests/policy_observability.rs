    #[test]
    fn parses_rrl_configuration() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [rrl]
                enabled = false
                ipv4_prefix_len = 28
                ipv6_prefix_len = 64
                positive_per_second = 3
                nxdomain_per_second = 4
                nodata_per_second = 5
                referral_per_second = 6
                error_per_second = 7
                slip = 1
                max_keys = 9
                summary_log_interval_secs = 30
                allowlist = ["127.0.0.1", "192.0.2.0/24", "2001:db8::/48"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert!(!config.rrl.enabled);
        assert_eq!(config.rrl.ipv4_prefix_len, 28);
        assert_eq!(config.rrl.ipv6_prefix_len, 64);
        assert_eq!(config.rrl.positive_per_second, 3);
        assert_eq!(config.rrl.nxdomain_per_second, 4);
        assert_eq!(config.rrl.nodata_per_second, 5);
        assert_eq!(config.rrl.referral_per_second, 6);
        assert_eq!(config.rrl.error_per_second, 7);
        assert_eq!(config.rrl.slip, 1);
        assert_eq!(config.rrl.max_keys, 9);
        assert_eq!(config.rrl.summary_log_interval_secs, 30);
        assert_eq!(config.rrl.allowlist.len(), 3);
    }

    #[test]
    fn rejects_invalid_rrl_configuration() {
        for (key, value, expected) in [
            ("ipv4_prefix_len", "33", "ipv4_prefix_len"),
            ("ipv6_prefix_len", "129", "ipv6_prefix_len"),
            ("max_keys", "0", "max_keys"),
            (
                "summary_log_interval_secs",
                "0",
                "summary_log_interval_secs",
            ),
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [rrl]
                    {key} = {value}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("invalid RRL setting must fail");

            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn rejects_invalid_rrl_allowlist_prefix() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [rrl]
                allowlist = ["192.0.2.0/33"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("invalid allowlist prefix must fail");

        assert!(error.to_string().contains("rrl.allowlist"));
    }

    #[test]
    fn parses_non_json_log_formats() {
        for (format, expected) in [
            ("logfmt", LogFormatConfig::Logfmt),
            ("plain", LogFormatConfig::Plain),
        ] {
            let config = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]
                    log_level = "debug"
                    log_format = "{format}"

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect("valid config");

            assert_eq!(config.server.log_level, "debug");
            assert_eq!(config.server.log_format, expected);
        }
    }

    #[test]
    fn parses_configured_nsid() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                nsid = "dns-bud-1"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.server.nsid, "dns-bud-1");
    }

    #[test]
    fn rejects_oversized_nsid() {
        let nsid = "x".repeat(256);
        let error = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                nsid = "{nsid}"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#
        ))
        .expect_err("oversized NSID must fail validation");

        assert!(
            error.to_string().contains("server.nsid"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parses_dns_cookie_policy_configuration() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [cookie]
                policy = "strict"
                server_secret = "00112233445566778899aabbccddeeff"
                previous_server_secret = "ffeeddccbbaa99887766554433221100"
                timestamp_past_tolerance_seconds = 1800
                timestamp_future_tolerance_seconds = 60

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.cookie.policy, CookiePolicyConfig::Strict);
        assert_eq!(
            config.cookie.server_secret_bytes().expect("server secret"),
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
        assert_eq!(
            config
                .cookie
                .previous_server_secret_bytes()
                .expect("previous server secret"),
            Some([
                0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00,
            ])
        );
        assert_eq!(config.cookie.timestamp_past_tolerance_seconds, 1800);
        assert_eq!(config.cookie.timestamp_future_tolerance_seconds, 60);
        let dumped = config.to_redacted_toml().expect("redacted config");
        assert!(!dumped.contains("00112233445566778899aabbccddeeff"));
        assert!(!dumped.contains("ffeeddccbbaa99887766554433221100"));
        assert!(dumped.contains("server_secret = \"<redacted>\""));
        assert!(dumped.contains("previous_server_secret = \"<redacted>\""));
    }

    #[test]
    fn parses_disabled_dns_cookie_policy() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [cookie]
                policy = "disabled"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.cookie.policy, CookiePolicyConfig::Disabled);
    }

    #[test]
    fn parses_health_rate_limit_configuration() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [health]
                metrics_rate_limit_per_minute = 120
                metrics_rate_limit_idle_seconds = 45

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid health config");

        assert_eq!(config.health.metrics_rate_limit_per_minute, 120);
        assert_eq!(config.health.metrics_rate_limit_idle_seconds, 45);
    }

    #[test]
    fn parses_metrics_latency_histogram_buckets() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [metrics]
                latency_histogram_buckets = [0.0002, 0.001, 0.01]
                hot_path_detail = "reduced"
                pipeline_timing_enabled = true
                zone_shape_enabled = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid metrics config");

        assert_eq!(
            config.metrics.latency_histogram_buckets_seconds(),
            vec![0.0002, 0.001, 0.01]
        );
        assert_eq!(
            config.metrics.hot_path_detail,
            MetricsHotPathDetail::Reduced
        );
        assert!(config.metrics.pipeline_timing_enabled);
        assert!(config.metrics.zone_shape_enabled);
    }

    #[test]
    fn parses_metrics_hot_path_detail_off() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [metrics]
                hot_path_detail = "off"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid metrics config");

        assert_eq!(config.metrics.hot_path_detail, MetricsHotPathDetail::Off);
    }

    #[test]
    fn parses_observability_configuration() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [observability]
                enabled = true
                path_prefix = "/obs/v1"
                rate_limit_per_minute = 30
                rate_limit_idle_seconds = 120
                include_filesystems = false
                include_process_resources = false
                include_time_sync_status = false
                include_certificate_status = false
                include_zone_detail = false
                include_config_summary = false
                bearer_token_file = "/etc/oxidedns/observability.token"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid observability config");

        assert!(config.observability.enabled);
        assert_eq!(config.observability.path_prefix, "/obs/v1");
        assert_eq!(config.observability.rate_limit_per_minute, 30);
        assert_eq!(config.observability.rate_limit_idle_seconds, 120);
        assert!(!config.observability.include_filesystems);
        assert!(!config.observability.include_process_resources);
        assert!(!config.observability.include_time_sync_status);
        assert!(!config.observability.include_certificate_status);
        assert!(!config.observability.include_zone_detail);
        assert!(!config.observability.include_config_summary);
        assert_eq!(
            config.observability.bearer_token_file.as_deref(),
            Some(Path::new("/etc/oxidedns/observability.token"))
        );
    }

    #[test]
    fn rejects_invalid_observability_configuration() {
        for (case, expected) in [
            ("path_prefix = \"obs\"", "absolute HTTP path"),
            ("path_prefix = \"/obs/\"", "must not end with '/'"),
            ("path_prefix = \"/../obs\"", "must not contain"),
            (
                "path_prefix = \"/metrics\"",
                "conflicts with a built-in management route",
            ),
            ("rate_limit_per_minute = 0", "rate_limit_per_minute"),
            ("rate_limit_idle_seconds = 0", "rate_limit_idle_seconds"),
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [observability]
                    {case}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("invalid observability config must fail");

            assert!(
                error.to_string().contains(expected),
                "{case} produced {error}"
            );
        }
    }

    #[test]
    fn rejects_invalid_latency_histogram_buckets() {
        for (case, expected) in [
            (
                "latency_histogram_buckets = []",
                "must contain at least one bucket",
            ),
            (
                "latency_histogram_buckets = [0.001, 0.001]",
                "must be strictly increasing",
            ),
            (
                "latency_histogram_buckets = [0.0, 0.001]",
                "positive finite seconds",
            ),
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [metrics]
                    {case}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#
            ))
            .expect_err("invalid metrics bucket config must fail");

            assert!(
                error.to_string().contains(expected),
                "{case} produced {error}"
            );
        }
    }

    #[test]
    fn rejects_zero_health_rate_limit_configuration() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [health]
                metrics_rate_limit_per_minute = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero metrics rate limit must fail");

        assert!(
            error
                .to_string()
                .contains("health.metrics_rate_limit_per_minute")
        );
    }

    #[test]
    fn rejects_zero_health_rate_limit_idle_seconds() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [health]
                metrics_rate_limit_idle_seconds = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero metrics rate-limit idle timeout must fail");

        assert!(
            error
                .to_string()
                .contains("health.metrics_rate_limit_idle_seconds")
        );
    }

    #[test]
    fn rejects_too_small_log_entry_length_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [logging]
                max_entry_length_bytes = 64

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("too-small log entry length limit must fail");

        assert!(error.to_string().contains("logging.max_entry_length_bytes"));
    }

    #[test]
    fn rejects_dns_cookie_tolerance_outside_serial_arithmetic_window() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [cookie]
                timestamp_past_tolerance_seconds = 2147483648

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("oversized tolerance must fail");

        assert!(
            error
                .to_string()
                .contains("cookie.timestamp_past_tolerance_seconds")
        );
    }

    #[test]
    fn rejects_invalid_dns_cookie_shared_secret_configuration() {
        let invalid_hex = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [cookie]
                server_secret = "not-hex"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("invalid cookie secret should fail");
        assert!(
            invalid_hex
                .to_string()
                .contains("cookie.server_secret must be exactly 32 hexadecimal characters")
        );

        let previous_without_current = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [cookie]
                previous_server_secret = "00112233445566778899aabbccddeeff"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("previous cookie secret without current should fail");
        assert!(
            previous_without_current
                .to_string()
                .contains("cookie.previous_server_secret requires cookie.server_secret")
        );

        let random_rotation_with_shared_secret = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [cookie]
                server_secret = "00112233445566778899aabbccddeeff"
                secret_rotation_interval_secs = 60

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("random rotation with configured shared secret should fail");
        assert!(
            random_rotation_with_shared_secret
                .to_string()
                .contains("cookie.secret_rotation_interval_secs cannot be used")
        );
    }

    #[test]
    fn rejects_invalid_log_format() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                log_format = "syslog"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("invalid log format must fail");

        assert!(error.to_string().contains("log_format"));
    }

    #[test]
    fn rejects_relative_zone_name() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test"
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("relative zone must fail");

        assert!(error.to_string().contains("absolute DNS name"));
    }
