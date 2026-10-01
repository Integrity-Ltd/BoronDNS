#[tokio::test]
async fn xdp_runtime_workers_observe_publication_expiry_hide_and_removal() {
    let allowed = rustix::thread::sched_getaffinity(None).unwrap();
    let cpus = (0..rustix::thread::CpuSet::MAX_CPU)
        .filter(|&cpu| allowed.is_set(cpu))
        .take(2)
        .map(|cpu| vec![cpu])
        .collect::<Vec<_>>();
    let groups = crate::xdp_runtime::QueueRuntimes::new(&cpus, cpus.len() * 2)
        .unwrap()
        .unwrap();
    let zones = active_example_zone();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let settings = udp_settings_for_test(
        RuntimeMetrics::new(),
        RrlConfig {
            enabled: false,
            ..RrlConfig::default()
        },
    );
    let peer = "192.0.2.1:53000".parse().unwrap();
    let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let mut workers = JoinSet::new();
    let mut requests = Vec::new();
    for group in 0..cpus.len() {
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, oneshot::Sender<Vec<u8>>)>(1);
        requests.push(tx);
        let zones = zones.clone();
        let settings = settings.clone();
        workers.spawn_on(
            async move {
                while let Some((packet, reply)) = rx.recv().await {
                    let response = handle_udp_datagram_with_prepared_hook(
                        &packet,
                        peer,
                        &zones,
                        &settings,
                        &|| {},
                    )
                    .unwrap()
                    .response
                    .into_owned();
                    reply.send(response).unwrap();
                }
            },
            groups.handle(group * 2).unwrap(),
        );
    }
    for phase in 0..8 {
        match phase {
            1 | 3 | 7 => zones.insert_snapshot(ZoneSnapshot::active(
                origin.clone(),
                Some(phase),
                vec![Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10 + phase as u8]],
                )],
            )),
            2 => assert!(zones.expire_zone(&origin)),
            4 => zones.hide_zone(&origin),
            5 => zones.show_zone(&origin),
            6 => assert!(zones.remove_zone(&origin)),
            _ => {}
        }
        let expected =
            handle_udp_datagram_with_prepared_hook(&packet, peer, &zones, &settings, &|| {})
                .unwrap()
                .response
                .into_owned();
        let rcode = match phase {
            2 => Rcode::ServFail,
            4 | 6 => Rcode::Refused,
            _ => Rcode::NoError,
        };
        assert_eq!(expected[3] & 0x0f, rcode as u8, "phase {phase}");
        for request in &requests {
            let (tx, rx) = oneshot::channel();
            request.send((packet.clone(), tx)).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), rx)
                    .await
                    .unwrap()
                    .unwrap(),
                expected,
                "phase {phase}"
            );
        }
    }
    let mut malformed = packet;
    malformed.push(0xff);
    for request in &requests {
        let (tx, rx) = oneshot::channel();
        request.send((malformed.clone(), tx)).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }
    drop(requests);
    while let Some(result) = tokio::time::timeout(Duration::from_secs(3), workers.join_next())
        .await
        .unwrap()
    {
        result.unwrap();
    }
}

#[tokio::test]
async fn xdp_runtime_rejects_moving_kernel_fallback_registration() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let listener = BoundUdpListener::AfXdpKernelFallback {
        socket: Arc::new(socket),
        worker_id: 2,
        worker_count: 3,
    };
    assert!(listener.reregister_xdp_runtime().is_err());
    UdpSocket::bind(address)
        .await
        .expect("rejected listener must release its socket");
}

#[cfg(feature = "experimental-xdp-group-loop")]
#[tokio::test]
#[ignore = "requires opt-in disposable VM, root and isolated two-queue veth; may panic vulnerable kernels"]
async fn xdp_group_veth_serves_after_idle_observes_publication_and_shuts_down() {
    use borondns_core::config::{XdpMode, XdpZeroCopyMode};
    // A network namespace shares the host kernel. This fixture triggered an
    // xsk_destruct_skb panic on GX10's 6.17.0-1014-nvidia COPY/veth path.
    // Never repeat it on a physical benchmark host, even with --ignored.
    assert_eq!(
        std::env::var("BORONDNS_DISPOSABLE_VM").as_deref(),
        Ok("1"),
        "this kernel-facing fixture requires an explicitly disposable VM"
    );
    assert!(
        std::process::Command::new("systemd-detect-virt")
            .args(["--vm", "--quiet"])
            .status()
            .is_ok_and(|status| status.success()),
        "COPY/veth fixture refused: VM detection failed; a container/netns is not sufficient"
    );
    let metrics = RuntimeMetrics::new();
    let mut settings = udp_settings_for_test(
        metrics.clone(),
        RrlConfig {
            enabled: false,
            ..Default::default()
        },
    );
    settings.xdp.interface = Some("brdns-test".to_owned());
    settings.xdp.redirect_object = Some(std::env::var_os("BORONDNS_BPF_CONTROL").unwrap().into());
    settings.xdp.mode = XdpMode::Drv;
    settings.xdp.zero_copy = XdpZeroCopyMode::Disable;
    settings.xdp.queue_ids = vec![0, 1];
    settings.xdp.worker_cpu_groups = vec![vec![rustix::thread::sched_getcpu()]];
    settings.xdp.umem_frame_count = 1024;
    settings.xdp.rx_ring_size = 256;
    settings.xdp.tx_ring_size = 256;
    settings.xdp.fill_ring_size = 256;
    settings.xdp.completion_ring_size = 256;
    let mut listeners = bind_udp_listeners(
        "192.0.2.53:0".parse().unwrap(),
        UdpBackend::AfXdp,
        &settings.xdp,
        2,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        listeners.len(),
        2,
        "one group owner and one kernel fallback"
    );
    drop(listeners.pop()); // no kernel fallback may answer this fixture
    let listener = listeners.pop().unwrap();
    let port = match &listener {
        BoundUdpListener::AfXdpGroup {
            packet_ios,
            worker_id,
            worker_count,
        } => {
            assert_eq!((*worker_id, *worker_count, packet_ios.len()), (0, 3, 2));
            packet_ios[0].local_addr().unwrap().port()
        }
        _ => panic!("feature must select the group owner"),
    };
    let zones = active_example_zone();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let admission = Arc::new(AtomicBool::new(true));
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(serve_bound_udp_until(
        listener,
        zones.clone(),
        settings.clone(),
        admission.clone(),
        async move { rx.await.unwrap() },
    ));
    let request = query(b"\x03www\x07example\x04test\0", RecordType::A as u16, 1);
    let client = std::env::var_os("BORONDNS_GROUP_CLIENT").unwrap();
    for phase in 0..4 {
        match phase {
            1 => zones.insert_snapshot(ZoneSnapshot::active(
                origin.clone(),
                Some(2),
                vec![Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    1,
                    1,
                    300,
                    vec![vec![192, 0, 2, 99]],
                )],
            )),
            2 => assert!(zones.expire_zone(&origin)),
            3 => assert!(zones.remove_zone(&origin)),
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        let expected = handle_udp_datagram_with_prepared_hook(
            &request,
            "192.0.2.1:53000".parse().unwrap(),
            &zones,
            &settings,
            &|| {},
        )
        .unwrap()
        .response
        .into_owned();
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let args = [port.to_string(), hex(&request), hex(&expected)];
        let executable = client.clone();
        let result = tokio::task::spawn_blocking(move || {
            std::process::Command::new("python3")
                .arg(executable)
                .args(args)
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            result.status.success(),
            "phase {phase}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        println!("phase {phase}: {}", String::from_utf8_lossy(&result.stdout));
    }
    assert_eq!(metrics.snapshot().udp_received_datagrams, 80);
    let mut worker_packets = 0;
    for worker in 0..2 {
        let (batches, packets) = metrics.af_xdp_worker_receive_stats_for_test(worker);
        println!("queue worker {worker}: batches={batches}, packets={packets}");
        assert!(
            batches > 0 && packets > 0,
            "queue worker {worker} did not receive fixture traffic: batches={batches}, packets={packets}"
        );
        worker_packets += packets;
    }
    assert_eq!(worker_packets, 80, "per-queue receive accounting changed");
    admission.store(false, Ordering::Release);
    tx.send(tokio::time::Instant::now() + Duration::from_millis(100))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
