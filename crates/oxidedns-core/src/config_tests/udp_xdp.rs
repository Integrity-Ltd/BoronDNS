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
    fn accepts_maximum_udp_batch_size() {
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [limits]
                udp_batch_size = {MAX_UDP_BATCH_SIZE}

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        ))
        .expect("maximum bounded UDP batch is valid");

        assert_eq!(config.limits.udp_batch_size, MAX_UDP_BATCH_SIZE);
    }

    #[test]
    fn rejects_udp_batch_size_above_ceiling_and_usize_max() {
        for batch_size in [MAX_UDP_BATCH_SIZE.saturating_add(1), usize::MAX] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]
                    listen_tcp = []

                    [limits]
                    udp_batch_size = {batch_size}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ))
            .expect_err("allocation-amplifying UDP batch must fail validation");

            let message = error.to_string();
            assert!(message.contains("udp_batch_size"));
            assert!(message.contains(&MAX_UDP_BATCH_SIZE.to_string()));
        }
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
    fn accepts_maximum_udp_reuseport_workers() {
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [limits]
                udp_reuseport_workers = {MAX_UDP_REUSEPORT_WORKERS}

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        ))
        .expect("documented maximum UDP worker count is valid");

        assert_eq!(
            config.limits.udp_reuseport_workers,
            MAX_UDP_REUSEPORT_WORKERS
        );
    }

    #[test]
    fn rejects_udp_reuseport_workers_above_ceiling_and_usize_max() {
        for workers in [
            MAX_UDP_REUSEPORT_WORKERS.saturating_add(1),
            usize::MAX,
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["127.0.0.1:5300"]
                    listen_tcp = []

                    [limits]
                    udp_reuseport_workers = {workers}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ))
            .expect_err("pathological UDP worker count must fail validation");

            let message = error.to_string();
            assert!(message.contains("udp_reuseport_workers"));
            assert!(message.contains(&MAX_UDP_REUSEPORT_WORKERS.to_string()));
        }
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
    fn rejects_af_xdp_wildcard_udp_listeners() {
        for listener in ["0.0.0.0:5300", "[::]:5300"] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["{listener}"]
                    listen_tcp = []

                    [limits]
                    udp_backend = "af_xdp"

                    [xdp]
                    interface = "eth0"
                    redirect_object = "target/oxidedns-xdp-redirect.bpf.o"

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ))
            .expect_err("AF_XDP wildcard listener must be rejected");

            assert!(error.to_string().contains("concrete local IP address"));
        }
    }

    #[test]
    fn rejects_af_xdp_without_exactly_one_udp_listener() {
        for listeners in [
            "listen_udp = []",
            "listen_udp = [\"192.0.2.1:5300\", \"192.0.2.2:5300\"]",
        ] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    {listeners}
                    listen_tcp = ["127.0.0.1:5300"]

                    [limits]
                    udp_backend = "af_xdp"

                    [xdp]
                    interface = "eth0"
                    redirect_object = "target/oxidedns-xdp-redirect.bpf.o"

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ))
            .expect_err("AF_XDP must have one redirectable UDP listener");

            assert!(error.to_string().contains("exactly one UDP listener"));
        }
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
                tx_wakeup_interval = 1
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
        assert_eq!(config.xdp.tx_wakeup_interval, 1);
        assert_eq!(config.xdp.zero_copy, XdpZeroCopyMode::Require);
    }

    #[test]
    fn accepts_maximum_bounded_xdp_allocations_for_one_queue() {
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []

                [limits]
                udp_backend = "af_xdp"
                udp_reuseport_workers = 1

                [xdp]
                interface = "eth0"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                umem_frame_count = {MAX_XDP_UMEM_FRAME_COUNT}
                rx_ring_size = {MAX_XDP_RING_SIZE}
                tx_ring_size = {MAX_XDP_RING_SIZE}
                fill_ring_size = {MAX_XDP_RING_SIZE}
                completion_ring_size = {MAX_XDP_RING_SIZE}
                batch_size = {MAX_XDP_BATCH_SIZE}

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        ))
        .expect("one maximum-size AF_XDP queue remains within aggregate memory bound");

        assert_eq!(config.xdp.umem_frame_count, MAX_XDP_UMEM_FRAME_COUNT);
        assert_eq!(config.xdp.rx_ring_size, MAX_XDP_RING_SIZE);
        assert_eq!(config.xdp.batch_size, MAX_XDP_BATCH_SIZE);
    }

    #[test]
    fn rejects_xdp_umem_frame_count_above_ceiling_and_u32_extreme() {
        for frame_count in [MAX_XDP_UMEM_FRAME_COUNT + 1, u32::MAX] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["192.0.2.1:5300"]
                    listen_tcp = []

                    [limits]
                    udp_backend = "af_xdp"

                    [xdp]
                    interface = "eth0"
                    redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                    umem_frame_count = {frame_count}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ))
            .expect_err("allocation-amplifying UMEM must fail validation");

            let message = error.to_string();
            assert!(message.contains("xdp.umem_frame_count"));
            assert!(message.contains(&MAX_XDP_UMEM_FRAME_COUNT.to_string()));
        }
    }

    #[test]
    fn rejects_each_xdp_ring_above_ceiling_and_huge_power_of_two() {
        for parameter in [
            "rx_ring_size",
            "tx_ring_size",
            "fill_ring_size",
            "completion_ring_size",
        ] {
            for ring_size in [MAX_XDP_RING_SIZE + 1, 1_u32 << 31] {
                let error = ServerConfig::from_toml_str(&format!(
                    r#"
                        [server]
                        listen_udp = ["192.0.2.1:5300"]
                        listen_tcp = []

                        [limits]
                        udp_backend = "af_xdp"

                        [xdp]
                        interface = "eth0"
                        redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                        {parameter} = {ring_size}

                        [[zones]]
                        name = "example.test."
                        primaries = ["192.0.2.53:53"]
                    "#,
                ))
                .expect_err("allocation-amplifying ring must fail validation");

                let message = error.to_string();
                assert!(message.contains(&format!("xdp.{parameter}")));
                assert!(message.contains(&MAX_XDP_RING_SIZE.to_string()));
            }
        }
    }

    #[test]
    fn rejects_xdp_batch_above_ceiling_and_usize_max() {
        for batch_size in [MAX_XDP_BATCH_SIZE + 1, usize::MAX] {
            let error = ServerConfig::from_toml_str(&format!(
                r#"
                    [server]
                    listen_udp = ["192.0.2.1:5300"]
                    listen_tcp = []

                    [limits]
                    udp_backend = "af_xdp"

                    [xdp]
                    interface = "eth0"
                    redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                    batch_size = {batch_size}

                    [[zones]]
                    name = "example.test."
                    primaries = ["192.0.2.53:53"]
                "#,
            ))
            .expect_err("allocation-amplifying XDP batch must fail validation");

            let message = error.to_string();
            assert!(message.contains("xdp.batch_size"));
            assert!(message.contains(&MAX_XDP_BATCH_SIZE.to_string()));
        }
    }

    #[test]
    fn rejects_xdp_completion_ring_smaller_than_effective_batch() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []

                [limits]
                udp_backend = "af_xdp"

                [xdp]
                interface = "eth0"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                rx_ring_size = 8
                tx_ring_size = 8
                completion_ring_size = 1
                batch_size = 8

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("completion ring cannot hold one effective TX batch");

        let message = error.to_string();
        assert!(message.contains("xdp.completion_ring_size"));
        assert!(message.contains("effective AF_XDP batch size 8"));
    }

    #[test]
    fn rejects_hostile_cross_queue_xdp_memory_shape() {
        let error = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []

                [limits]
                udp_backend = "af_xdp"
                udp_reuseport_workers = 32

                [xdp]
                interface = "eth0"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                umem_frame_count = {MAX_XDP_UMEM_FRAME_COUNT}
                rx_ring_size = {MAX_XDP_RING_SIZE}
                tx_ring_size = {MAX_XDP_RING_SIZE}
                fill_ring_size = {MAX_XDP_RING_SIZE}
                completion_ring_size = {MAX_XDP_RING_SIZE}
                batch_size = {MAX_XDP_BATCH_SIZE}

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        ))
        .expect_err("aggregate AF_XDP allocation above the host budget must fail");

        let message = error.to_string();
        assert!(message.contains("estimated aggregate AF_XDP memory"));
        assert!(message.contains(&MAX_XDP_ESTIMATED_MEMORY_BYTES.to_string()));
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
        assert_eq!(config.xdp.effective_queue_ids(1).unwrap(), vec![3, 17, 41]);
        assert_eq!(config.xdp.effective_queue_count(1), 3);
    }

    #[test]
    fn accepts_last_af_xdp_redirect_map_queue() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []

                [limits]
                udp_backend = "af_xdp"
                udp_reuseport_workers = 1

                [xdp]
                interface = "eth0"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                queue_ids = [63]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("last redirect-map queue is valid");

        assert_eq!(config.xdp.effective_queue_ids(1).unwrap(), vec![63]);
    }

    #[test]
    fn rejects_af_xdp_queue_at_redirect_map_capacity() {
        let error = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []

                [limits]
                udp_backend = "af_xdp"
                udp_reuseport_workers = 1

                [xdp]
                interface = "eth0"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                queue_ids = [{XDP_REDIRECT_MAP_CAPACITY}]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        ))
        .expect_err("queue outside the redirect map must fail validation");

        assert!(error.to_string().contains("queue id"));
        assert!(error.to_string().contains("redirect map capacity"));
    }

    #[test]
    fn rejects_af_xdp_contiguous_queue_range_past_redirect_map() {
        let error = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []

                [limits]
                udp_backend = "af_xdp"
                udp_reuseport_workers = 2

                [xdp]
                interface = "eth0"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                queue_id = 63

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect_err("contiguous range must fit the redirect map");

        assert!(error.to_string().contains("queue id 64"));
    }

    #[test]
    fn rejects_explicit_af_xdp_queue_list_larger_than_redirect_map() {
        let queue_ids = (0..=XDP_REDIRECT_MAP_CAPACITY)
            .map(|queue| queue.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let error = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []

                [limits]
                udp_backend = "af_xdp"
                udp_reuseport_workers = 1

                [xdp]
                interface = "eth0"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                queue_ids = [{queue_ids}]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        ))
        .expect_err("oversized explicit queue list must fail validation");

        assert!(error.to_string().contains("queue count"));
        assert!(error.to_string().contains("redirect map capacity"));
    }

    #[test]
    fn ebpf_redirect_map_capacity_matches_host_configuration_contract() {
        let ebpf_source = include_str!("../../../oxidedns-server-ebpf/src/lib.rs");
        assert!(ebpf_source.contains(&format!(
            "const XDP_REDIRECT_MAP_CAPACITY: u32 = {XDP_REDIRECT_MAP_CAPACITY};"
        )));
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
    fn rejects_unsafe_af_xdp_tx_wakeup_intervals() {
        for interval in [0, 2, 8] {
        let error = ServerConfig::from_toml_str(
            &format!(r#"
                [server]
                listen_udp = ["192.0.2.1:5300"]

                [limits]
                udp_backend = "af_xdp"

                [xdp]
                interface = "eth0"
                redirect_object = "target/oxidedns-xdp-redirect.bpf.o"
                tx_wakeup_interval = {interval}

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#),
        )
        .expect_err("unsafe XDP TX wakeup interval should be rejected");

        assert!(error.to_string().contains("xdp.tx_wakeup_interval"));
        assert!(error.to_string().contains("must be 1"));
        }
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
