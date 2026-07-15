    #[test]
    fn rejects_zero_zsm_intervals() {
        for (key, expected) in [
            ("zsm_min_interval_secs", "zsm_min_interval_secs"),
            ("zsm_max_interval_secs", "zsm_max_interval_secs"),
            ("zsm_initial_retry_secs", "zsm_initial_retry_secs"),
            (
                "zsm_loading_warning_threshold_secs",
                "zsm_loading_warning_threshold_secs",
            ),
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
            .expect_err("zero ZSM interval must fail");

            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn rejects_zsm_max_interval_below_min_interval() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                zsm_min_interval_secs = 120
                zsm_max_interval_secs = 119

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("ZSM max interval below min interval must fail");

        assert!(error.to_string().contains("zsm_max_interval_secs"));
    }

    #[test]
    fn rejects_initial_retry_max_below_initial_retry() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                zsm_initial_retry_secs = 60
                zsm_initial_retry_max_secs = 59

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("retry max below initial retry must fail");

        assert!(error.to_string().contains("zsm_initial_retry_max_secs"));
    }
