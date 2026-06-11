    #[test]
    fn parses_hmac_sha256_tsig_key_and_zone_reference() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret = "c2VjcmV0LWtleQ=="

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        )
        .expect("valid TSIG config");

        assert_eq!(config.tsig_keys.len(), 1);
        assert_eq!(config.zones[0].tsig_key.as_deref(), Some("transfer-key."));
        assert!(!format!("{config:?}").contains("c2VjcmV0LWtleQ=="));
    }

    #[test]
    fn parses_tsig_secret_file_key_and_zone_reference() {
        let secret_file = write_secret_file("c2VjcmV0LWtleQ==\n", 0o600);
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

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

        assert_eq!(config.tsig_keys.len(), 1);
        assert_eq!(
            config.tsig_keys[0].secret_file.as_deref(),
            Some(secret_file.to_str().expect("utf-8 temp path"))
        );
        assert_eq!(config.zones[0].tsig_key.as_deref(), Some("transfer-key."));
        let _ = std::fs::remove_file(secret_file);
    }

    #[test]
    fn redacted_toml_dump_preserves_shape_without_secret_material() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                nsid = "dns-bud-1"

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret = "c2VjcmV0LWtleQ=="

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        )
        .expect("valid TSIG config");

        let dumped = config.to_redacted_toml().expect("redacted TOML dump");

        assert!(dumped.contains("[[tsig_keys]]"));
        assert!(dumped.contains("name = \"transfer-key.\""));
        assert!(dumped.contains("secret = \"<redacted>\""));
        assert!(dumped.contains("nsid = \"dns-bud-1\""));
        assert!(!dumped.contains("c2VjcmV0LWtleQ=="));
    }

    #[test]
    fn redacted_toml_dump_scrubs_split_catalog_xot_inline_keys() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "Y2F0YWxvZy1zZWNyZXQ="

                [[catalog_zones]]
                name = "catalog.example."
                catalog_tsig_key = "catalog-key."

                [[catalog_zones.catalog_transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "catalog-primary.example"
                trust_anchors = ["/etc/oxidedns/catalog-ca.pem"]
                client_cert = "/etc/oxidedns/catalog-client.pem"
                client_key_pem = "catalog-inline-private-key"

                [[catalog_zones.member_transfer_primaries]]
                addr = "198.51.100.53:853"
                transport = "xot"
                server_name = "member-primary.example"
                trust_anchors = ["/etc/oxidedns/member-ca.pem"]
                client_cert = "/etc/oxidedns/member-client.pem"
                client_key_pem = "member-inline-private-key"
            "#,
        )
        .expect("valid split catalog XoT config");

        let dumped = config.to_redacted_toml().expect("redacted TOML dump");

        assert_eq!(dumped.matches("client_key_pem = \"<redacted>\"").count(), 2);
        assert!(!dumped.contains("catalog-inline-private-key"));
        assert!(!dumped.contains("member-inline-private-key"));
        assert!(!dumped.contains("Y2F0YWxvZy1zZWNyZXQ="));
    }

    #[test]
    fn redacted_toml_dump_preserves_tsig_secret_file_path() {
        let secret_file = write_secret_file("c2VjcmV0LWtleQ==\n", 0o600);
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

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

        let dumped = config.to_redacted_toml().expect("redacted TOML dump");

        assert!(dumped.contains("[[tsig_keys]]"));
        assert!(dumped.contains(&format!("secret_file = \"{}\"", secret_file.display())));
        assert!(!dumped.contains("secret = \"<redacted>\""));
        assert!(!dumped.contains("c2VjcmV0LWtleQ=="));
        let _ = std::fs::remove_file(secret_file);
    }

    #[test]
    fn parses_hmac_sha1_tsig_key_and_zone_reference() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha1"
                secret = "c2VjcmV0LWtleQ=="

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        )
        .expect("valid HMAC-SHA1 TSIG config");

        assert_eq!(config.tsig_keys[0].algorithm, "hmac-sha1");
        assert_eq!(config.zones[0].tsig_key.as_deref(), Some("transfer-key."));
    }

    #[test]
    fn parses_hmac_sha384_and_sha512_tsig_keys() {
        for algorithm in ["hmac-sha384", "hmac-sha512"] {
            let config = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]

                    [[tsig_keys]]
                    name = "transfer-key."
                    algorithm = "{algorithm}"
                    secret = "c2VjcmV0LWtleQ=="

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                    tsig_key = "transfer-key."
                "#
            ))
            .expect("valid HMAC-SHA TSIG config");

            assert_eq!(config.tsig_keys[0].algorithm, algorithm);
            assert_eq!(config.zones[0].tsig_key.as_deref(), Some("transfer-key."));
        }
    }

    #[test]
    fn rejects_invalid_tsig_secret_without_leaking_it() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret = "not base64"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        )
        .expect_err("invalid TSIG secret must fail");
        let message = error.to_string();

        assert!(message.contains("invalid TSIG key transfer-key."));
        assert!(!message.contains("not base64"));
    }

    #[test]
    fn rejects_tsig_key_with_both_inline_and_file_secret_sources() {
        let secret_file = write_secret_file("c2VjcmV0LWtleQ==\n", 0o600);
        let error = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret = "c2VjcmV0LWtleQ=="
                secret_file = "{}"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
            secret_file.display()
        ))
        .expect_err("duplicate TSIG secret sources must fail");

        assert!(
            error
                .to_string()
                .contains("must set exactly one of secret or secret_file")
        );
        assert!(!error.to_string().contains("c2VjcmV0LWtleQ=="));
        let _ = std::fs::remove_file(secret_file);
    }

    #[test]
    fn rejects_tsig_key_without_secret_source() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        )
        .expect_err("missing TSIG secret source must fail");

        assert!(
            error
                .to_string()
                .contains("must set exactly one of secret or secret_file")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_tsig_secret_file() {
        let secret_file = write_secret_file("c2VjcmV0LWtleQ==\n", 0o604);
        let error = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

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
        .expect_err("world-readable TSIG secret file must fail");

        assert!(error.to_string().contains("must not be world-readable"));
        assert!(!error.to_string().contains("c2VjcmV0LWtleQ=="));
        let _ = std::fs::remove_file(secret_file);
    }

    #[test]
    fn rejects_missing_tsig_secret_file_without_leaking_material() {
        let secret_file = unique_test_path("oxidedns-missing-tsig-secret");
        let error = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

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
        .expect_err("missing TSIG secret file must fail");

        assert!(matches!(error, ConfigError::ReadSecretFile { .. }));
        assert!(!error.to_string().contains("c2VjcmV0LWtleQ=="));
    }

    #[test]
    fn rejects_unknown_zone_tsig_key_reference() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "missing-key."
            "#,
        )
        .expect_err("unknown TSIG key reference must fail");

        assert!(error.to_string().contains("unknown TSIG key"));
    }

    #[test]
    fn rejects_hmac_md5_tsig_key_algorithm() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-md5.sig-alg.reg.int."
                secret = "c2VjcmV0LWtleQ=="

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
        )
        .expect_err("HMAC-MD5 must be rejected");

        assert!(error.to_string().contains("hmac-md5.sig-alg.reg.int"));
    }

