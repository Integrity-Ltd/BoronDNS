    #[test]
    fn parses_edns_and_dnssec_settings() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [edns]
                extended_dns_errors = "minimal"

                [dnssec]
                nsec3_max_iterations = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(
            config.edns.extended_dns_errors,
            ExtendedDnsErrorsConfig::Minimal
        );
        assert_eq!(
            config.edns.extended_dns_errors_mode(),
            ExtendedDnsErrorsMode::Minimal
        );
        assert_eq!(config.dnssec.nsec3_max_iterations, 0);
    }

    #[test]
    fn parses_chaos_settings_and_warns_on_precise_version() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [chaos]
                version = "1.2.3"
                hostname = "bud-anycast-1"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(config.chaos.version, "1.2.3");
        assert_eq!(config.chaos.hostname, "bud-anycast-1");
        assert!(
            config
                .configuration_warnings()
                .iter()
                .any(|warning| warning.code == "chaos_version_discloses_build")
        );
    }

    #[test]
    fn rejects_oversized_chaos_txt_values() {
        let oversized = "x".repeat(256);
        let error = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [chaos]
                version = "{oversized}"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#
        ))
        .expect_err("oversized CHAOS version should be rejected");

        assert!(error.to_string().contains("chaos.version"));
    }

    #[test]
    fn warns_on_large_nsec3_iteration_cap() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [dnssec]
                nsec3_max_iterations = 101

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
                .any(|warning| warning.code == "nsec3_iterations_large")
        );
    }

    #[test]
    fn transfer_require_tsig_rejects_unsigned_zone() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [transfer]
                require_tsig = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("require_tsig rejects unsigned zone");

        assert!(error.to_string().contains("transfer.require_tsig is true"));
    }

    #[test]
    fn transfer_require_tsig_accepts_signed_zone() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [transfer]
                require_tsig = true

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
        .expect("signed zone satisfies require_tsig");

        assert!(config.transfer.require_tsig);
    }

    #[test]
    fn rejects_zero_tsig_fudge_seconds() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [tsig]
                fudge_seconds = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero TSIG fudge is invalid");

        assert!(error.to_string().contains("tsig.fudge_seconds"));
    }

    #[test]
    fn parses_explicit_tcp_transfer_primary_config() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:53"
                transport = "tcp"
            "#,
        )
        .expect("valid config");

        assert!(config.zones[0].primaries.is_empty());
        assert_eq!(config.zones[0].transfer_primaries.len(), 1);
        assert_eq!(
            config.zones[0].transfer_primaries[0].transport,
            TransferTransportConfig::Tcp
        );
        assert_eq!(
            config.zones[0].transfer_targets(),
            config.zones[0].transfer_primaries
        );
    }

    #[test]
    fn parses_xot_transfer_primary_config() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
                client_cert = "/etc/oxidedns/client.pem"
                client_key = "/etc/oxidedns/client.key"
            "#,
        )
        .expect("valid config");

        let target = &config.zones[0].transfer_primaries[0];
        assert_eq!(
            target.addr,
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 853))
        );
        assert_eq!(target.transport, TransferTransportConfig::Xot);
        assert_eq!(target.server_name.as_deref(), Some("primary.example.test"));
        assert_eq!(target.trust_anchors, vec!["/etc/oxidedns/ca.pem"]);
        assert_eq!(
            target.client_cert.as_deref(),
            Some("/etc/oxidedns/client.pem")
        );
        assert_eq!(
            target.client_key.as_deref(),
            Some("/etc/oxidedns/client.key")
        );
        assert!(target.client_key_pem.is_none());
    }

    #[test]
    fn parses_xot_transfer_primary_with_inline_client_key() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
                client_cert = "/etc/oxidedns/client.pem"
                client_key_pem = '''
                -----BEGIN PRIVATE KEY-----
                inline-private-key-material
                -----END PRIVATE KEY-----
                '''
            "#,
        )
        .expect("valid config with inline XoT client key");

        let target = &config.zones[0].transfer_primaries[0];
        assert_eq!(
            target.client_cert.as_deref(),
            Some("/etc/oxidedns/client.pem")
        );
        assert!(target.client_key.is_none());
        assert!(
            target
                .client_key_pem
                .as_deref()
                .expect("inline key")
                .contains("inline-private-key-material")
        );
        assert!(!format!("{config:?}").contains("inline-private-key-material"));

        let dumped = config.to_redacted_toml().expect("redacted TOML dump");
        assert!(dumped.contains("client_key_pem = \"<redacted>\""));
        assert!(dumped.contains("client_cert = \"/etc/oxidedns/client.pem\""));
        assert!(!dumped.contains("inline-private-key-material"));
    }

    #[test]
    fn rejects_zone_without_transfer_primary() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
            "#,
        )
        .expect_err("missing transfer primary must fail");

        assert!(error.to_string().contains("requires at least one primary"));
    }

    #[test]
    fn rejects_mixed_legacy_and_explicit_transfer_primaries() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]

                [[zones.transfer_primaries]]
                addr = "192.0.2.54:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
            "#,
        )
        .expect_err("mixed primary forms must fail");

        assert!(error.to_string().contains("must not mix legacy primaries"));
    }

    #[test]
    fn rejects_xot_transfer_primary_without_server_name() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
            "#,
        )
        .expect_err("xot server name is required");

        assert!(error.to_string().contains("requires server_name"));
    }

    #[test]
    fn rejects_xot_transfer_primary_without_trust_anchor() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
            "#,
        )
        .expect_err("xot trust anchor is required");

        assert!(
            error
                .to_string()
                .contains("requires at least one trust_anchors")
        );
    }

    #[test]
    fn rejects_xot_transfer_primary_with_unpaired_client_key_material() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
                client_cert = "/etc/oxidedns/client.pem"
            "#,
        )
        .expect_err("xot client certificate and key must be paired");

        assert!(error.to_string().contains("exactly one"));
    }

    #[test]
    fn rejects_xot_transfer_primary_with_both_client_key_sources() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
                client_cert = "/etc/oxidedns/client.pem"
                client_key = "/etc/oxidedns/client.key"
                client_key_pem = "inline-private-key-material"
            "#,
        )
        .expect_err("xot client key sources must be mutually exclusive");

        assert!(error.to_string().contains("exactly one"));
        assert!(!error.to_string().contains("inline-private-key-material"));
    }

    #[test]
    fn rejects_xot_transfer_primary_inline_client_key_without_certificate() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
                client_key_pem = "inline-private-key-material"
            "#,
        )
        .expect_err("xot inline client key requires client certificate");

        assert!(error.to_string().contains("exactly one"));
        assert!(!error.to_string().contains("inline-private-key-material"));
    }

    #[test]
    fn rejects_tcp_transfer_primary_with_xot_fields() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:53"
                transport = "tcp"
                server_name = "primary.example.test"
            "#,
        )
        .expect_err("tcp target must not accept tls fields");

        assert!(error.to_string().contains("must not set XoT TLS fields"));
    }

    #[test]
    fn rejects_xot_server_name_with_trailing_root_label() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test."
                trust_anchors = ["/etc/oxidedns/ca.pem"]
            "#,
        )
        .expect_err("xot server name should use SNI form");

        assert!(error.to_string().contains("without a trailing root label"));
    }

    #[test]
    fn defaults_dns_listeners_when_omitted() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        let expected = vec![
            SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)),
            SocketAddr::from((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53)),
        ];
        assert_eq!(config.server.listen_udp, expected);
        assert_eq!(config.server.listen_tcp, expected);
    }

    #[test]
    fn preserves_explicit_high_port_listeners() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = ["127.0.0.1:5301", "[::1]:5301"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(
            config.server.listen_udp,
            vec![SocketAddr::from(([127, 0, 0, 1], 5300))]
        );
        assert_eq!(
            config.server.listen_tcp,
            vec![
                SocketAddr::from(([127, 0, 0, 1], 5301)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 5301)),
            ]
        );
    }

    #[test]
    fn rejects_explicitly_empty_dns_listeners() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = []
                listen_tcp = []

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("explicitly empty listeners must fail");

        assert!(
            error
                .to_string()
                .contains("at least one UDP or TCP listener")
        );
    }
