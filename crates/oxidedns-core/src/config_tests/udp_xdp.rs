    #[test]
    fn rejects_too_small_udp_payload_limit() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_udp_payload = 511

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("small UDP limit must fail");

        assert!(error.to_string().contains("max_udp_payload"));
    }

    #[test]
    fn parses_custom_udp_batch_size() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_batch_size = 32

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("custom UDP batch size is valid");

        assert_eq!(config.limits.udp_batch_size, 32);
    }

    #[test]
    fn parses_udp_reuseport_worker_settings() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_batch_size = 32
                udp_reuseport_workers = 4
                udp_worker_cpu_affinity = [0, 1, 2, 3]
                udp_runtime = "dedicated"
                udp_idle_strategy = "spin"
                udp_socket_receive_buffer_bytes = 4194304
                udp_socket_send_buffer_bytes = 4194304
                udp_socket_max_pacing_rate_bytes_per_second = 75000000

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("custom UDP worker settings are valid");

        assert_eq!(config.limits.udp_batch_size, 32);
        assert_eq!(config.limits.udp_reuseport_workers, 4);
        assert_eq!(
            config.limits.udp_worker_cpu_affinity.as_deref(),
            Some([0, 1, 2, 3].as_slice())
        );
        assert_eq!(config.limits.udp_runtime, UdpRuntime::Dedicated);
        assert_eq!(config.limits.udp_idle_strategy, UdpIdleStrategy::Spin);
        assert_eq!(
            config.limits.udp_socket_receive_buffer_bytes,
            Some(4_194_304)
        );
        assert_eq!(config.limits.udp_socket_send_buffer_bytes, Some(4_194_304));
        assert_eq!(
            config.limits.udp_socket_max_pacing_rate_bytes_per_second,
            Some(75_000_000)
        );
    }

    #[test]
    fn rejects_zero_udp_reuseport_workers() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_reuseport_workers = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero UDP worker count must fail");

        assert!(error.to_string().contains("udp_reuseport_workers"));
    }

    #[test]
    fn rejects_udp_worker_cpu_affinity_length_mismatch() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_reuseport_workers = 4
                udp_worker_cpu_affinity = [0, 1]
                udp_runtime = "dedicated"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("CPU affinity list must match UDP worker count");

        assert!(error.to_string().contains("udp_worker_cpu_affinity"));
    }

    #[test]
    fn rejects_udp_worker_cpu_affinity_index_outside_cpu_set() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_reuseport_workers = 1
                udp_worker_cpu_affinity = [9999]
                udp_runtime = "dedicated"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("out-of-range CPU affinity index must fail before CPU_SET");

        assert!(error.to_string().contains("below 1024"));
    }

    #[test]
    fn rejects_udp_worker_cpu_affinity_without_dedicated_runtime() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_reuseport_workers = 2
                udp_worker_cpu_affinity = [0, 1]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("CPU affinity requires dedicated UDP runtime");

        assert!(error.to_string().contains("udp_runtime"));
    }

    #[test]
    fn accepts_af_xdp_with_multiple_queue_workers() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_backend = "af_xdp"
                udp_reuseport_workers = 2

                [xdp]
                interface = "lo"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("AF_XDP queue workers are valid configuration");

        assert_eq!(config.limits.udp_backend, UdpBackend::AfXdp);
        assert_eq!(config.limits.udp_reuseport_workers, 2);
    }

    #[test]
    fn rejects_af_xdp_with_dedicated_udp_runtime() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_backend = "af_xdp"
                udp_runtime = "dedicated"

                [xdp]
                interface = "lo"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("AF_XDP uses its own packet worker model");

        assert!(error.to_string().contains("udp_runtime"));
    }

    #[test]
    fn parses_udp_backend_selection() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_backend = "af_xdp"

                [xdp]
                interface = "lo"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("AF_XDP UDP backend selection is valid configuration");

        assert_eq!(config.limits.udp_backend, UdpBackend::AfXdp);
        assert_eq!(config.xdp.interface.as_deref(), Some("lo"));
        assert_eq!(
            config.xdp.redirect_object.as_deref(),
            Some(Path::new("target/oxidedns-xdp-redirect.bpf.o"))
        );
    }

    #[test]
    fn parses_xdp_tuning_settings() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [xdp]
                interface = "eth0"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                mode = "drv"
                queue_id = 2
                umem_frame_count = 8192
                rx_ring_size = 2048
                tx_ring_size = 2048
                fill_ring_size = 4096
                completion_ring_size = 2048
                batch_size = 128
                rx_drain_passes = 4
                tx_wakeup_interval = 4
                zero_copy = "require"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("XDP tuning settings are valid configuration");

        assert_eq!(config.xdp.interface.as_deref(), Some("eth0"));
        assert_eq!(
            config.xdp.redirect_object.as_deref(),
            Some(Path::new("target/oxidedns-xdp-redirect.bpf.o"))
        );
        assert_eq!(config.xdp.mode, XdpMode::Drv);
        assert_eq!(config.xdp.queue_id, 2);
        assert_eq!(config.xdp.umem_frame_count, 8192);
        assert_eq!(config.xdp.rx_ring_size, 2048);
        assert_eq!(config.xdp.tx_ring_size, 2048);
        assert_eq!(config.xdp.fill_ring_size, 4096);
        assert_eq!(config.xdp.completion_ring_size, 2048);
        assert_eq!(config.xdp.batch_size, 128);
        assert_eq!(config.xdp.rx_drain_passes, 4);
        assert_eq!(config.xdp.tx_wakeup_interval, 4);
        assert_eq!(config.xdp.zero_copy, XdpZeroCopyMode::Require);
    }

    #[test]
    fn parses_explicit_xdp_queue_ids() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [xdp]
                interface = "eth0"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                queue_ids = [3, 17, 41]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("explicit XDP queue ids are valid configuration");

        assert_eq!(config.xdp.queue_ids, vec![3, 17, 41]);
    }

    #[test]
    fn rejects_duplicate_xdp_queue_ids() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [xdp]
                queue_ids = [3, 17, 3]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("duplicate XDP queue ids should be rejected");

        assert!(error.to_string().contains("xdp.queue_ids"));
    }

    #[test]
    fn rejects_xdp_queue_id_with_explicit_queue_ids() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [xdp]
                queue_id = 2
                queue_ids = [3, 17]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("xdp.queue_id is ambiguous with xdp.queue_ids");

        assert!(error.to_string().contains("xdp.queue_id"));
    }

    #[test]
    fn rejects_zero_xdp_rx_drain_passes() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [xdp]
                rx_drain_passes = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero XDP RX drain pass count should be rejected");

        assert!(error.to_string().contains("xdp.rx_drain_passes"));
    }

    #[test]
    fn rejects_zero_xdp_tx_wakeup_interval() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [xdp]
                tx_wakeup_interval = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero XDP TX wakeup interval should be rejected");

        assert!(error.to_string().contains("xdp.tx_wakeup_interval"));
    }

    #[test]
    fn rejects_af_xdp_backend_without_interface() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_backend = "af_xdp"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("AF_XDP backend must name an interface");

        assert!(error.to_string().contains("xdp.interface"));
    }

    #[test]
    fn rejects_af_xdp_backend_without_redirect_object() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_backend = "af_xdp"

                [xdp]
                interface = "lo"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("AF_XDP backend must name a redirect object");

        assert!(error.to_string().contains("xdp.redirect_object"));
    }

    #[test]
    fn rejects_zero_xdp_ring_size() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [xdp]
                rx_ring_size = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero XDP ring size must fail");

        assert!(error.to_string().contains("xdp.rx_ring_size"));
    }

    #[test]
    fn rejects_non_power_of_two_xdp_ring_size() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [xdp]
                tx_ring_size = 1536

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("non-power-of-two XDP ring size must fail");

        assert!(error.to_string().contains("xdp.tx_ring_size"));
    }

    #[test]
    fn rejects_zero_udp_batch_size() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_batch_size = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero UDP batch size must fail");

        assert!(error.to_string().contains("udp_batch_size"));
    }

    #[test]
    fn rejects_zero_udp_socket_pacing_rate() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                udp_socket_max_pacing_rate_bytes_per_second = 0

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("zero UDP socket pacing rate must fail");

        assert!(
            error
                .to_string()
                .contains("udp_socket_max_pacing_rate_bytes_per_second")
        );
    }
