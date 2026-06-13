#[tokio::test]
async fn tcp_connection_serves_authoritative_response() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            ),
        ],
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(&frame_tcp_message(&query(
            b"\x03www\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        )))
        .await
        .unwrap();

    let mut length_prefix = [0u8; 2];
    client.read_exact(&mut length_prefix).await.unwrap();
    let response_len = u16::from_be_bytes(length_prefix) as usize;
    let mut response = vec![0u8; response_len];
    client.read_exact(&mut response).await.unwrap();
    drop(client);
    server.await.unwrap();

    assert_eq!(response[3] & 0x0f, 0);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
}

#[test]
fn tcp_accept_errors_classify_transient_resource_and_fatal_cases() {
    assert_eq!(
        classify_tcp_accept_error(&std::io::Error::from(std::io::ErrorKind::ConnectionAborted)),
        TcpAcceptErrorAction::Continue
    );
    assert_eq!(
        classify_tcp_accept_error(&std::io::Error::from(std::io::ErrorKind::Interrupted)),
        TcpAcceptErrorAction::Continue
    );
    assert_eq!(
        classify_tcp_accept_error(&std::io::Error::from_raw_os_error(24)),
        TcpAcceptErrorAction::Backoff(std::time::Duration::from_millis(50))
    );
    assert_eq!(
        classify_tcp_accept_error(&std::io::Error::from_raw_os_error(9)),
        TcpAcceptErrorAction::Fatal
    );
}

#[tokio::test]
async fn tcp_connection_serves_back_to_back_framed_queries() {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("mail.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 20].to_vec()],
            ),
        ],
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let first = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let mut second = query(b"\x04mail\x07example\x04test\x00", RecordType::A as u16, 1);
    second[0..2].copy_from_slice(&0x5678u16.to_be_bytes());
    let mut pipelined = frame_tcp_message(&first);
    pipelined.extend_from_slice(&frame_tcp_message(&second));
    client.write_all(&pipelined).await.unwrap();

    let first_response = read_framed_tcp_response(&mut client).await;
    let second_response = read_framed_tcp_response(&mut client).await;
    drop(client);
    server.await.unwrap();

    assert_eq!(Header::parse(&first_response).unwrap().id, 0x1234);
    assert_eq!(Header::parse(&second_response).unwrap().id, 0x5678);
    assert_eq!(
        u16::from_be_bytes([first_response[6], first_response[7]]),
        1
    );
    assert_eq!(
        u16::from_be_bytes([second_response[6], second_response[7]]),
        1
    );
}

#[tokio::test]
async fn tcp_connection_processes_later_query_while_first_response_is_delayed() {
    let zones = active_example_zone();
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let query_hook: super::TcpQueryHook = {
        let first_started = first_started.clone();
        let release_first = release_first.clone();
        Arc::new(move |query_id| {
            let first_started = first_started.clone();
            let release_first = release_first.clone();
            Box::pin(async move {
                if query_id == 0x1234 {
                    first_started.notify_one();
                    release_first.notified().await;
                }
            })
        })
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection_with_query_hook(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
            Some(query_hook),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let first = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let mut second = first.clone();
    second[0..2].copy_from_slice(&0x5678u16.to_be_bytes());
    let mut pipelined = frame_tcp_message(&first);
    pipelined.extend_from_slice(&frame_tcp_message(&second));
    client.write_all(&pipelined).await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), first_started.notified())
        .await
        .expect("first TCP query should reach the test pause");

    let first_available_response = read_framed_tcp_response(&mut client).await;
    assert_eq!(Header::parse(&first_available_response).unwrap().id, 0x5678);
    assert_eq!(
        u16::from_be_bytes([first_available_response[6], first_available_response[7]]),
        1
    );

    release_first.notify_one();
    let delayed_response = read_framed_tcp_response(&mut client).await;
    drop(client);
    server.await.unwrap();

    assert_eq!(Header::parse(&delayed_response).unwrap().id, 0x1234);
    assert_eq!(
        u16::from_be_bytes([delayed_response[6], delayed_response[7]]),
        1
    );
}

#[tokio::test]
async fn tcp_connection_closes_when_inflight_limit_stays_saturated() {
    let zones = active_example_zone();
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let query_hook: super::TcpQueryHook = {
        let first_started = first_started.clone();
        let release_first = release_first.clone();
        Arc::new(move |query_id| {
            let first_started = first_started.clone();
            let release_first = release_first.clone();
            Box::pin(async move {
                if query_id == 0x1234 {
                    first_started.notify_one();
                    release_first.notified().await;
                }
            })
        })
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection_with_query_hook(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            1,
            std::time::Duration::from_millis(25),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
            Some(query_hook),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let first = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    let mut second = first.clone();
    second[0..2].copy_from_slice(&0x5678u16.to_be_bytes());
    let mut pipelined = frame_tcp_message(&first);
    pipelined.extend_from_slice(&frame_tcp_message(&second));
    client.write_all(&pipelined).await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), first_started.notified())
        .await
        .expect("first TCP query should hold the only in-flight permit");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    release_first.notify_one();

    let first_response = read_framed_tcp_response(&mut client).await;
    assert_eq!(Header::parse(&first_response).unwrap().id, 0x1234);

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("saturated TCP connection should close without answering the queued query")
        .unwrap();
    assert_eq!(read, 0);

    server.await.unwrap();
}

#[tokio::test]
async fn tcp_connection_closes_after_idle_timeout() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection(
            stream,
            zones,
            std::time::Duration::from_millis(25),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("idle timeout should close the connection")
        .unwrap();

    assert_eq!(read, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_connection_closes_after_read_timeout_mid_frame() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_millis(25),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0, 1]).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("read timeout should close the connection")
        .unwrap();

    assert_eq!(read, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_write_times_out_when_backpressured() {
    let (mut writer, _reader) = tokio::io::duplex(1);
    let response = vec![0u8; 4096];

    let completed = write_tcp_message(&mut writer, &response, std::time::Duration::from_millis(25))
        .await
        .unwrap();

    assert!(!completed);
}

#[tokio::test]
async fn tcp_connection_closes_on_zero_length_frame() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_tcp_connection(
            stream,
            zones,
            std::time::Duration::from_secs(5),
            1232,
            8,
            100,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            64,
            std::time::Duration::from_secs(5),
            0,
            ExtendedDnsErrorsMode::Off,
            AnyResponseMode::Minimal,
            Vec::new(),
            String::new(),
            String::new(),
            dns_cookie_secret_store_for_test(),
            dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics_for_test(),
            NotifyAuthority::default(),
            NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx(),
            notify_log_limiter_for_test(),
            RuntimeMetrics::new(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0, 0]).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
        .await
        .expect("zero-length frame should close the connection")
        .unwrap();

    assert_eq!(read, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_listener_closes_connections_over_global_limit() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let source_counts = Arc::new(Mutex::new(HashMap::new()));
    let server = tokio::spawn(serve_tcp(
        listener,
        zones,
        TcpServerSettings {
            max_udp_payload: 1232,
            max_cname_chain: 8,
            nsec3_max_iterations: 100,
            idle_timeout: std::time::Duration::from_secs(30),
            read_timeout: std::time::Duration::from_secs(30),
            write_timeout: std::time::Duration::from_secs(30),
            max_connections: 1,
            max_connections_per_source: None,
            max_inflight_queries_per_connection: 64,
            inflight_limit_timeout: std::time::Duration::from_secs(30),
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Minimal,
            nsid: Vec::new(),
            chaos_version: String::new(),
            chaos_hostname: String::new(),
            dns_cookie_secrets: dns_cookie_secret_store_for_test(),
            dns_cookie: dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics: cookie_prefix_metrics_for_test(),
            notify_authority: NotifyAuthority::default(),
            notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx: notify_refresh_tx(),
            notify_log_limiter: notify_log_limiter_for_test(),
            metrics: RuntimeMetrics::new(),
            active_connections: active.clone(),
            active_connections_by_source: source_counts.clone(),
        },
    ));

    let first = TcpStream::connect(addr).await.unwrap();
    for _ in 0..100 {
        if active.load(Ordering::Acquire) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(active.load(Ordering::Acquire), 1);

    let mut second = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), second.read(&mut byte))
        .await
        .expect("over-limit connection should close promptly")
        .unwrap();

    assert_eq!(read, 0);
    assert_eq!(active.load(Ordering::Acquire), 1);
    drop(first);
    server.abort();
}

#[tokio::test]
async fn tcp_listener_closes_connections_over_per_source_limit() {
    let zones = ZoneStore::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let source_counts = Arc::new(Mutex::new(HashMap::new()));
    let server = tokio::spawn(serve_tcp(
        listener,
        zones,
        TcpServerSettings {
            max_udp_payload: 1232,
            max_cname_chain: 8,
            nsec3_max_iterations: 100,
            idle_timeout: std::time::Duration::from_secs(30),
            read_timeout: std::time::Duration::from_secs(30),
            write_timeout: std::time::Duration::from_secs(30),
            max_connections: 8,
            max_connections_per_source: Some(1),
            max_inflight_queries_per_connection: 64,
            inflight_limit_timeout: std::time::Duration::from_secs(30),
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Minimal,
            nsid: Vec::new(),
            chaos_version: String::new(),
            chaos_hostname: String::new(),
            dns_cookie_secrets: dns_cookie_secret_store_for_test(),
            dns_cookie: dns_cookie_settings_for_test(DnsCookiePolicy::Lenient),
            cookie_prefix_metrics: cookie_prefix_metrics_for_test(),
            notify_authority: NotifyAuthority::default(),
            notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
            notify_refresh_tx: notify_refresh_tx(),
            notify_log_limiter: notify_log_limiter_for_test(),
            metrics: RuntimeMetrics::new(),
            active_connections: active.clone(),
            active_connections_by_source: source_counts.clone(),
        },
    ));

    let first = TcpStream::connect(addr).await.unwrap();
    let loopback = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    for _ in 0..100 {
        if active.load(Ordering::Acquire) == 1
            && source_counts.lock().unwrap().get(&loopback).copied() == Some(1)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(active.load(Ordering::Acquire), 1);

    let mut second = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), second.read(&mut byte))
        .await
        .expect("per-source over-limit connection should close promptly")
        .unwrap();

    assert_eq!(read, 0);
    assert_eq!(active.load(Ordering::Acquire), 1);
    assert_eq!(
        source_counts.lock().unwrap().get(&loopback).copied(),
        Some(1)
    );
    drop(first);

    for _ in 0..100 {
        if active.load(Ordering::Acquire) == 0
            && !source_counts.lock().unwrap().contains_key(&loopback)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(active.load(Ordering::Acquire), 0);
    assert!(!source_counts.lock().unwrap().contains_key(&loopback));

    let third = TcpStream::connect(addr).await.unwrap();
    for _ in 0..100 {
        if active.load(Ordering::Acquire) == 1
            && source_counts.lock().unwrap().get(&loopback).copied() == Some(1)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(active.load(Ordering::Acquire), 1);
    drop(third);
    server.abort();
}
