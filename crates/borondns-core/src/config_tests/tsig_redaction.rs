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
    fn primary_config_enforces_exact_limit_and_same_handle_growth_fence() {
        use std::io::Write;

        let limit = MAX_SERVER_CONFIG_BYTES;
        let path = unique_test_path("borondns-primary-config-limit");
        std::fs::write(&path, vec![b'#'; limit]).expect("write exact-limit config");
        assert_eq!(
            config_len_after_open_for_test(&path, || {})
                .expect("exact-limit primary config is accepted"),
            limit
        );

        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open config for over-limit append")
            .write_all(b"#")
            .expect("append one over-limit byte");
        let error = config_len_after_open_for_test(&path, || {})
            .expect_err("one-byte-over primary config is rejected");
        assert!(error.to_string().contains(&limit.to_string()));

        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open config for exact-limit reset")
            .set_len(limit as u64)
            .expect("reset exact-limit config");
        let growth_path = path.clone();
        let error = config_len_after_open_for_test(&path, move || {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&growth_path)
                .expect("open captured config")
                .write_all(b"#")
                .expect("grow config after metadata validation");
        })
        .expect_err("same-handle bounded read rejects config growth");
        assert!(error.to_string().contains(&limit.to_string()));

        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn static_tsig_secret_file_enforces_exact_limit_and_growth_fence() {
        use std::{
            io::Write,
            os::unix::fs::PermissionsExt,
        };

        let limit = MAX_TSIG_SECRET_FILE_BYTES;
        let path = unique_test_path("borondns-static-tsig-secret-limit");
        std::fs::write(&path, vec![b'A'; limit]).expect("write exact-limit TSIG secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secure exact-limit TSIG secret mode");
        assert_eq!(
            static_tsig_secret_len_after_open_for_test(
                path.to_str().expect("UTF-8 secret path"),
                || {},
            )
            .expect("exact-limit TSIG secret is accepted"),
            limit
        );

        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open TSIG secret for over-limit append")
            .write_all(b"A")
            .expect("append one over-limit byte");
        let error = static_tsig_secret_len_after_open_for_test(
            path.to_str().expect("UTF-8 secret path"),
            || {},
        )
        .expect_err("one-byte-over TSIG secret is rejected");
        assert!(error.to_string().contains(&limit.to_string()));

        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open TSIG secret for exact-limit reset")
            .set_len(limit as u64)
            .expect("reset exact-limit TSIG secret");
        let growth_path = path.clone();
        let error = static_tsig_secret_len_after_open_for_test(
            path.to_str().expect("UTF-8 secret path"),
            move || {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&growth_path)
                    .expect("open captured TSIG secret")
                    .write_all(b"A")
                    .expect("grow TSIG secret after metadata validation");
            },
        )
        .expect_err("bounded same-handle TSIG read rejects post-validation growth");
        assert!(error.to_string().contains(&limit.to_string()));

        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn static_tsig_aggregate_budget_counts_repeated_files_at_exact_and_plus_one() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_test_path("borondns-static-tsig-aggregate");
        std::fs::write(&path, vec![b'A'; MAX_TSIG_SECRET_FILE_BYTES])
            .expect("write repeated static TSIG material");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private static TSIG material mode");
        let repetitions =
            MAX_TSIG_ENCODED_BYTES_PER_SNAPSHOT / MAX_TSIG_SECRET_FILE_BYTES;
        let entries = (0..repetitions)
            .map(|index| {
                format!(
                    "[[tsig_keys]]\nname = \"key-{index}.\"\nalgorithm = \"hmac-sha256\"\nsecret_file = {:?}\n",
                    path.display().to_string()
                )
            })
            .collect::<String>();
        ServerConfig::from_toml_str(&format!(
            "[server]\nlisten_udp = [\"127.0.0.1:5300\"]\nlisten_tcp = []\n{entries}[[zones]]\nname = \"example.test.\"\nprimaries = [\"192.0.2.53:53\"]\n"
        ))
        .expect("exact repeated-file static TSIG budget is accepted");

        let error = ServerConfig::from_toml_str(&format!(
            "[server]\nlisten_udp = [\"127.0.0.1:5300\"]\nlisten_tcp = []\n{entries}[[tsig_keys]]\nname = \"over.\"\nalgorithm = \"hmac-sha256\"\nsecret = \"A\"\n[[zones]]\nname = \"example.test.\"\nprimaries = [\"192.0.2.53:53\"]\n"
        ))
        .expect_err("one encoded byte over static TSIG aggregate is rejected");
        assert!(error.to_string().contains("aggregate encoded TSIG material"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn static_tsig_key_count_is_bounded() {
        let entries = (0..=MAX_TSIG_KEYS_PER_SNAPSHOT)
            .map(|index| {
                format!(
                    "[[tsig_keys]]\nname = \"key-{index}.\"\nalgorithm = \"hmac-sha256\"\nsecret = \"YQ==\"\n"
                )
            })
            .collect::<String>();
        let error = ServerConfig::from_toml_str(&format!(
            "[server]\nlisten_udp = [\"127.0.0.1:5300\"]\nlisten_tcp = []\n{entries}[[zones]]\nname = \"example.test.\"\nprimaries = [\"192.0.2.53:53\"]\n"
        ))
        .expect_err("static TSIG key count above snapshot limit is rejected");
        assert!(error
            .to_string()
            .contains(&MAX_TSIG_KEYS_PER_SNAPSHOT.to_string()), "{error}");
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
                trust_anchors = ["/etc/borondns/catalog-ca.pem"]
                client_cert = "/etc/borondns/catalog-client.pem"
                client_key_pem = "catalog-inline-private-key"

                [[catalog_zones.member_transfer_primaries]]
                addr = "198.51.100.53:853"
                transport = "xot"
                server_name = "member-primary.example"
                trust_anchors = ["/etc/borondns/member-ca.pem"]
                client_cert = "/etc/borondns/member-client.pem"
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
    fn accepts_group_readable_but_rejects_readable_or_writable_by_others_tsig_secret_file() {
        use std::os::unix::fs::PermissionsExt;

        let secret_file = write_secret_file("c2VjcmV0LWtleQ==\n", 0o640);
        let config_text = format!(
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
        );
        ServerConfig::from_toml_str(&config_text)
            .expect("group-readable TSIG secret remains compatible with ODS-IF-CONF-004");

        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o604))
            .expect("world-readable TSIG secret mode");
        let error = ServerConfig::from_toml_str(&config_text)
            .expect_err("world-readable TSIG secret file must fail");

        assert!(error.to_string().contains("must not be world-readable"));
        assert!(!error.to_string().contains("c2VjcmV0LWtleQ=="));

        for mode in [0o602, 0o620] {
            std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(mode))
                .expect("writable-by-others TSIG secret mode");
            let error = ServerConfig::from_toml_str(&config_text)
                .expect_err("group- or world-writable TSIG secret file must fail");
            assert!(
                error
                    .to_string()
                    .contains("must not be group- or world-writable"),
                "mode {mode:o}: {error}"
            );
        }
        let _ = std::fs::remove_file(secret_file);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_tsig_secret_symlinks_and_non_regular_files() {
        use std::os::unix::fs::symlink;

        let target = write_secret_file("c2VjcmV0LWtleQ==\n", 0o600);
        let link = unique_test_path("borondns-tsig-secret-link");
        symlink(&target, &link).expect("create TSIG secret symlink");
        let linked = TsigKeyConfig {
            name: "transfer-key.".to_owned(),
            algorithm: "hmac-sha256".to_owned(),
            secret: None,
            secret_file: Some(link.display().to_string()),
        };
        assert!(
            linked.secret_base64().is_err(),
            "a final-component symlink must not be followed"
        );

        let directory = unique_test_path("borondns-tsig-secret-directory");
        std::fs::create_dir(&directory).expect("create non-regular secret path");
        let non_regular = TsigKeyConfig {
            name: "transfer-key.".to_owned(),
            algorithm: "hmac-sha256".to_owned(),
            secret: None,
            secret_file: Some(directory.display().to_string()),
        };
        let error = non_regular
            .secret_base64()
            .expect_err("non-regular TSIG secret must fail");
        assert!(error.to_string().contains("must be a regular file"));

        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(target);
        let _ = std::fs::remove_dir(directory);
    }

    #[test]
    fn rejects_missing_tsig_secret_file_without_leaking_material() {
        let secret_file = unique_test_path("borondns-missing-tsig-secret");
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
    #[test]
    fn malformed_secret_fields_do_not_survive_in_parse_error_output_or_chain() {
        for (label, source, sentinel) in [
            (
                "bearer token",
                "[control_plane.telemetry]\nbearer_token = \"BEARER_TOKEN_SENTINEL",
                "BEARER_TOKEN_SENTINEL",
            ),
            (
                "TSIG secret",
                "[[tsig_keys]]\nsecret = \"TSIG_SECRET_SENTINEL",
                "TSIG_SECRET_SENTINEL",
            ),
            (
                "inline client key",
                "[[zones]]\n[[zones.transfer_primaries]]\nclient_key_pem = \"INLINE_CLIENT_KEY_SENTINEL",
                "INLINE_CLIENT_KEY_SENTINEL",
            ),
        ] {
            let Err(error) = ServerConfig::from_toml_str(source) else {
                panic!("malformed {label} must fail");
            };
            assert!(matches!(error, ConfigError::Parse(_)));

            let mut rendered = format!("{error}\n{error:?}");
            let mut current: &dyn std::error::Error = &error;
            while let Some(source) = current.source() {
                rendered.push('\n');
                rendered.push_str(&source.to_string());
                current = source;
            }
            assert!(
                !rendered.contains(sentinel),
                "{label} leaked through the sanitized error: {rendered}"
            );
        }
    }
