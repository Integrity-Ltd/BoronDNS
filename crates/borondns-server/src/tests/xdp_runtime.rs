#[tokio::test]
async fn xdp_runtime_workers_observe_publication_expiry_hide_and_removal() {
    let allowed = rustix::thread::sched_getaffinity(None).unwrap();
    let cpus = (0..rustix::thread::CpuSet::MAX_CPU)
        .filter(|&cpu| allowed.is_set(cpu)).take(2).map(|cpu| vec![cpu]).collect::<Vec<_>>();
    let groups = crate::xdp_runtime::QueueRuntimes::new(&cpus, cpus.len() * 2).unwrap().unwrap();
    let zones = active_example_zone();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let settings = udp_settings_for_test(RuntimeMetrics::new(), RrlConfig { enabled: false, ..RrlConfig::default() });
    let peer = "192.0.2.1:53000".parse().unwrap();
    let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let mut workers = JoinSet::new();
    let mut requests = Vec::new();
    for group in 0..cpus.len() {
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, oneshot::Sender<Vec<u8>>)>(1);
        requests.push(tx);
        let zones = zones.clone();
        let settings = settings.clone();
        workers.spawn_on(async move {
            while let Some((packet, reply)) = rx.recv().await {
                let response = handle_udp_datagram_with_prepared_hook(&packet, peer, &zones, &settings, &|| {}).unwrap().response;
                reply.send(response).unwrap();
            }
        }, groups.handle(group * 2).unwrap());
    }
    for phase in 0..8 {
        match phase {
            1 | 3 | 7 => zones.insert_snapshot(ZoneSnapshot::active(
                origin.clone(), Some(phase), vec![Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16, 1, 300, vec![vec![192,0,2,10 + phase as u8]],
                )],
            )),
            2 => assert!(zones.expire_zone(&origin)),
            4 => zones.hide_zone(&origin),
            5 => zones.show_zone(&origin),
            6 => assert!(zones.remove_zone(&origin)),
            _ => {},
        }
        let expected = handle_udp_datagram_with_prepared_hook(&packet, peer, &zones, &settings, &|| {}).unwrap().response;
        let rcode = match phase { 2 => Rcode::ServFail, 4 | 6 => Rcode::Refused, _ => Rcode::NoError };
        assert_eq!(expected[3] & 0x0f, rcode as u8, "phase {phase}");
        for request in &requests {
            let (tx, rx) = oneshot::channel();
            request.send((packet.clone(), tx)).await.unwrap();
            assert_eq!(tokio::time::timeout(Duration::from_secs(3), rx).await.unwrap().unwrap(), expected, "phase {phase}");
        }
    }
    let mut malformed = packet;
    malformed.push(0xff);
    for request in &requests {
        let (tx, rx) = oneshot::channel();
        request.send((malformed.clone(), tx)).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(3), rx).await.unwrap().unwrap();
        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }
    drop(requests);
    while let Some(result) = tokio::time::timeout(Duration::from_secs(3), workers.join_next()).await.unwrap() {
        result.unwrap();
    }
}

#[tokio::test]
async fn xdp_runtime_rejects_moving_kernel_fallback_registration() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let listener = BoundUdpListener::AfXdpKernelFallback {
        socket: Arc::new(socket), worker_id: 2, worker_count: 3,
    };
    assert!(listener.reregister_xdp_runtime().is_err());
    UdpSocket::bind(address).await.expect("rejected listener must release its socket");
}
