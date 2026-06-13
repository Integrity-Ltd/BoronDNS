async fn spawn_axfr_primary() -> std::net::SocketAddr {
    spawn_axfr_primary_with_serial(1).await
}

async fn spawn_xot_axfr_primary_with_serial(serial: u32) -> (std::net::SocketAddr, String) {
    let (cert_path, key_path) = write_self_signed_xot_cert_files();

    let certs =
        load_pem_certs(cert_path.to_str().expect("utf-8 cert path")).expect("load generated cert");
    let key = load_pem_private_key(
        "127.0.0.1:0".parse().unwrap(),
        key_path.to_str().expect("utf-8 key path"),
    )
    .expect("load generated key");
    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server tls config");
    config.alpn_protocols = vec![b"dot".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();

        let header = Header::parse(&query).unwrap();
        assert_eq!(query_qtype(&query), RecordType::Axfr as u16);
        let response = axfr_response(header.id, serial);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });

    (addr, cert_path.display().to_string())
}

async fn spawn_xot_axfr_primary_recording_query(
    serial: u32,
) -> (std::net::SocketAddr, String, Arc<Mutex<Option<Vec<u8>>>>) {
    let (cert_path, key_path) = write_self_signed_xot_cert_files();

    let certs =
        load_pem_certs(cert_path.to_str().expect("utf-8 cert path")).expect("load generated cert");
    let key = load_pem_private_key(
        "127.0.0.1:0".parse().unwrap(),
        key_path.to_str().expect("utf-8 key path"),
    )
    .expect("load generated key");
    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server tls config");
    config.alpn_protocols = vec![b"dot".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let observed_query = Arc::new(Mutex::new(None));
    let observed_query_for_task = observed_query.clone();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();

        let header = Header::parse(&query).unwrap();
        let request_mac = extract_query_tsig_mac(&query);
        observed_query_for_task
            .lock()
            .expect("observed query lock poisoned")
            .replace(query);

        let response = axfr_response(header.id, serial);
        let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let response = key
            .sign_response(
                &response,
                &request_mac,
                current_unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap()
            .message;
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });

    (addr, cert_path.display().to_string(), observed_query)
}

async fn spawn_xot_mtls_axfr_primary_with_serial(
    serial: u32,
    client_trust_anchor: &std::path::Path,
) -> (std::net::SocketAddr, String, mpsc::Receiver<()>) {
    let (cert_path, key_path) = write_self_signed_xot_cert_files();

    let certs =
        load_pem_certs(cert_path.to_str().expect("utf-8 cert path")).expect("load generated cert");
    let key = load_pem_private_key(
        "127.0.0.1:0".parse().unwrap(),
        key_path.to_str().expect("utf-8 key path"),
    )
    .expect("load generated key");
    let mut client_roots = RootCertStore::empty();
    for cert in load_pem_certs(
        client_trust_anchor
            .to_str()
            .expect("utf-8 client cert path"),
    )
    .expect("load generated client cert")
    {
        client_roots.add(cert).expect("add client trust anchor");
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .expect("client certificate verifier");
    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .expect("server tls config");
    config.alpn_protocols = vec![b"dot".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (query_seen_tx, query_seen_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        let mut length_prefix = [0u8; 2];
        if stream.read_exact(&mut length_prefix).await.is_err() {
            return;
        }
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }

        let header = Header::parse(&query).unwrap();
        assert_eq!(query_qtype(&query), RecordType::Axfr as u16);
        let _ = query_seen_tx.send(()).await;
        let response = axfr_response(header.id, serial);
        let _ = stream.write_all(&frame_tcp_message(&response)).await;
    });

    (addr, cert_path.display().to_string(), query_seen_rx)
}

async fn spawn_xot_primary_detecting_query(
    cert_dns_name: &str,
    negotiate_dot_alpn: bool,
) -> (std::net::SocketAddr, String, mpsc::Receiver<()>) {
    let (cert_path, key_path) = write_self_signed_xot_cert_files_for_name(cert_dns_name);
    let (addr, query_seen_rx) = spawn_xot_primary_detecting_query_with_cert_files(
        &cert_path,
        &key_path,
        negotiate_dot_alpn,
    )
    .await;
    (addr, cert_path.display().to_string(), query_seen_rx)
}

async fn spawn_xot_primary_detecting_query_with_cert_files(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    negotiate_dot_alpn: bool,
) -> (std::net::SocketAddr, mpsc::Receiver<()>) {
    let certs =
        load_pem_certs(cert_path.to_str().expect("utf-8 cert path")).expect("load generated cert");
    let key = load_pem_private_key(
        "127.0.0.1:0".parse().unwrap(),
        key_path.to_str().expect("utf-8 key path"),
    )
    .expect("load generated key");
    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server tls config");
    if negotiate_dot_alpn {
        config.alpn_protocols = vec![b"dot".to_vec()];
    }
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (query_seen_tx, query_seen_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        let mut length_prefix = [0u8; 2];
        if matches!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                stream.read_exact(&mut length_prefix),
            )
            .await,
            Ok(Ok(_))
        ) {
            let _ = query_seen_tx.send(()).await;
        }
    });

    (addr, query_seen_rx)
}

async fn spawn_xot_tls12_primary_detecting_query()
-> (std::net::SocketAddr, String, mpsc::Receiver<()>) {
    let (cert_path, key_path) = write_self_signed_xot_cert_files();

    let certs =
        load_pem_certs(cert_path.to_str().expect("utf-8 cert path")).expect("load generated cert");
    let key = load_pem_private_key(
        "127.0.0.1:0".parse().unwrap(),
        key_path.to_str().expect("utf-8 key path"),
    )
    .expect("load generated key");
    let mut config =
        tokio_rustls::rustls::ServerConfig::builder_with_protocol_versions(&[&version::TLS12])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server tls config");
    config.alpn_protocols = vec![b"dot".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (query_seen_tx, query_seen_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        let mut length_prefix = [0u8; 2];
        if matches!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                stream.read_exact(&mut length_prefix),
            )
            .await,
            Ok(Ok(_))
        ) {
            let _ = query_seen_tx.send(()).await;
        }
    });

    (addr, cert_path.display().to_string(), query_seen_rx)
}

fn write_self_signed_xot_cert_files() -> (std::path::PathBuf, std::path::PathBuf) {
    write_self_signed_xot_cert_files_for_name("primary.example.test")
}

fn write_self_signed_xot_cert_files_for_name(
    dns_name: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = rcgen::generate_simple_self_signed(vec![dns_name.to_owned()])
        .expect("self-signed certificate");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    write_xot_cert_files(cert_pem, key_pem)
}

fn write_expired_self_signed_xot_cert_files_for_name(
    dns_name: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut params =
        rcgen::CertificateParams::new(vec![dns_name.to_owned()]).expect("certificate params");
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
    let cert = params
        .self_signed(&key_pair)
        .expect("expired self-signed certificate");
    write_xot_cert_files(cert.pem(), key_pair.serialize_pem())
}

fn write_expiring_self_signed_xot_cert_files_for_name(
    dns_name: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut params =
        rcgen::CertificateParams::new(vec![dns_name.to_owned()]).expect("certificate params");
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2026, 6, 1);
    let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
    let cert = params
        .self_signed(&key_pair)
        .expect("expiring self-signed certificate");
    write_xot_cert_files(cert.pem(), key_pair.serialize_pem())
}

fn write_xot_cert_files(
    cert_pem: String,
    key_pem: String,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert_path = unique_test_path("xot-primary", "pem");
    let key_path = unique_test_path("xot-primary-key", "pem");
    std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert pem");
    std::fs::write(&key_path, key_pem.as_bytes()).expect("write key pem");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure key mode");
    }
    (cert_path, key_path)
}

fn unique_test_path(prefix: &str, extension: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = TEST_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{counter}-{nanos}.{extension}",
        std::process::id()
    ))
}

async fn spawn_axfr_primary_with_serial(serial: u32) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();

        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert!(query.ends_with(&(1u16).to_be_bytes()));
        assert_eq!(
            &query[query.len() - 4..query.len() - 2],
            &(RecordType::Axfr as u16).to_be_bytes()
        );

        let response = axfr_response(header.id, serial);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_barrier_axfr_primary(
    zone: &'static str,
    barrier: Arc<tokio::sync::Barrier>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let query = read_primary_query(&mut stream).await;
        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        let (_, qname_len) = DomainName::parse(&query, 12).unwrap();
        let qtype_offset = 12 + qname_len;
        assert_eq!(
            u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]),
            RecordType::Axfr as u16
        );

        barrier.wait().await;

        let response = axfr_response_for_zone(header.id, zone, 1);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_blocked_axfr_primary() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (query_seen_tx, query_seen_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let query = read_primary_query(&mut stream).await;
        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        let (_, qname_len) = DomainName::parse(&query, 12).unwrap();
        let qtype_offset = 12 + qname_len;
        assert_eq!(
            u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]),
            RecordType::Axfr as u16
        );
        let _ = query_seen_tx.send(());
        let _ = release_rx.await;
    });
    (addr, query_seen_rx, release_tx)
}

async fn spawn_axfr_primary_recording_query(
    serial: u32,
) -> (std::net::SocketAddr, Arc<Mutex<Option<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let observed_query = Arc::new(Mutex::new(None));
    let observed_query_for_task = observed_query.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let query = read_primary_query(&mut stream).await;

        let header = Header::parse(&query).unwrap();
        let request_mac = extract_query_tsig_mac(&query);
        observed_query_for_task
            .lock()
            .expect("observed query lock poisoned")
            .replace(query.clone());

        let response = axfr_response(header.id, serial);
        let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let response = key
            .sign_response(
                &response,
                &request_mac,
                current_unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap()
            .message;
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    (addr, observed_query)
}

async fn spawn_signed_catalog_axfr_primary_with_member(
    catalog_zone: &'static str,
    member_zone: &'static str,
    serial: u32,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let query = read_primary_query(&mut stream).await;
        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.arcount, 1);
        let (_, qname_len) = DomainName::parse(&query, 12).unwrap();
        let qtype_offset = 12 + qname_len;
        assert_eq!(
            u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]),
            RecordType::Axfr as u16
        );

        let request_mac = extract_query_tsig_mac(&query);
        let response = catalog_axfr_response(catalog_zone, member_zone, header.id, serial);
        let key = TsigKey::from_base64("catalog-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let signed = key
            .sign_response(
                &response,
                &request_mac,
                current_unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        stream
            .write_all(&frame_tcp_message(&signed.message))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_axfr_primary_recording_peer(
    serial: u32,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<std::net::SocketAddr>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (peer_tx, peer_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, peer) = listener.accept().await.unwrap();
        let _ = peer_tx.send(peer);
        let query = read_primary_query(&mut stream).await;
        let header = Header::parse(&query).unwrap();
        let response = axfr_response(header.id, serial);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    (addr, peer_rx)
}

async fn spawn_ixfr_mode2_primary_with_serial(serial: u32) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();

        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.nscount, 1);
        assert_eq!(&query[26..28], &(RecordType::Ixfr as u16).to_be_bytes());

        let response = ixfr_mode2_response(header.id, serial);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_barrier_ixfr_mode2_primary(
    zone: &'static str,
    barrier: Arc<tokio::sync::Barrier>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let query = read_primary_query(&mut stream).await;
        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        let (_, qname_len) = DomainName::parse(&query, 12).unwrap();
        let qtype_offset = 12 + qname_len;
        assert_eq!(
            u16::from_be_bytes([query[qtype_offset], query[qtype_offset + 1]]),
            RecordType::Ixfr as u16
        );

        barrier.wait().await;

        let response = ixfr_mode2_response_for_zone(header.id, zone, 2);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_ixfr_mode1_primary() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();

        let header = Header::parse(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.nscount, 1);
        assert_eq!(&query[26..28], &(RecordType::Ixfr as u16).to_be_bytes());

        let response = ixfr_mode1_response(header.id);
        stream
            .write_all(&frame_tcp_message(&response))
            .await
            .unwrap();
    });
    addr
}

async fn spawn_ixfr_notimp_then_axfr_primary() -> (std::net::SocketAddr, Arc<Mutex<Vec<u16>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let qtypes = Arc::new(Mutex::new(Vec::new()));
    let qtypes_for_task = qtypes.clone();
    tokio::spawn(async move {
        for serial in [2, 3] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let query = read_primary_query(&mut stream).await;
            let header = Header::parse(&query).unwrap();
            let qtype = query_qtype(&query);
            qtypes_for_task
                .lock()
                .expect("qtype log lock poisoned")
                .push(qtype);
            if qtype == RecordType::Ixfr as u16 {
                let response = error_response(header.id, 4);
                stream
                    .write_all(&frame_tcp_message(&response))
                    .await
                    .unwrap();

                let (mut stream, _) = listener.accept().await.unwrap();
                let query = read_primary_query(&mut stream).await;
                let header = Header::parse(&query).unwrap();
                let qtype = query_qtype(&query);
                qtypes_for_task
                    .lock()
                    .expect("qtype log lock poisoned")
                    .push(qtype);
                assert_eq!(qtype, RecordType::Axfr as u16);
                let response = axfr_response(header.id, serial);
                stream
                    .write_all(&frame_tcp_message(&response))
                    .await
                    .unwrap();
            } else {
                assert_eq!(qtype, RecordType::Axfr as u16);
                let response = axfr_response(header.id, serial);
                stream
                    .write_all(&frame_tcp_message(&response))
                    .await
                    .unwrap();
            }
        }
    });
    (addr, qtypes)
}

async fn spawn_soa_primary_with_serial(serial: u32) -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        let response = soa_response(header.id, serial);
        socket.send_to(&response, peer).await.unwrap();
    });
    addr
}

async fn spawn_soa_primary_recording_peer(
    serial: u32,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<std::net::SocketAddr>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (peer_tx, peer_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let _ = peer_tx.send(peer);
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        let response = soa_response(header.id, serial);
        socket.send_to(&response, peer).await.unwrap();
    });
    (addr, peer_rx)
}

async fn spawn_soa_primary_recording_two_peers(
    serial: u32,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<Vec<std::net::SocketAddr>>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (peers_tx, peers_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let mut peers = Vec::new();
        for _ in 0..2 {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = &buffer[..len];
            let header = Header::parse(query).unwrap();
            assert_eq!(header.qdcount, 1);
            assert_eq!(query_qtype(query), RecordType::Soa as u16);

            peers.push(peer);
            let response = soa_response(header.id, serial);
            socket.send_to(&response, peer).await.unwrap();
        }
        let _ = peers_tx.send(peers);
    });
    (addr, peers_rx)
}

async fn spawn_soa_primary_with_spoofed_malformed_packet(serial: u32) -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        attacker.send_to(&[0], peer).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let response = soa_response(header.id, serial);
        socket.send_to(&response, peer).await.unwrap();
    });
    addr
}

async fn spawn_soa_primary_with_wrong_qid_truncated_then_serial(
    serial: u32,
) -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        let mut wrong_qid_tc = soa_response(header.id.wrapping_add(1), serial);
        let flags = u16::from_be_bytes([wrong_qid_tc[2], wrong_qid_tc[3]]) | 0x0200;
        wrong_qid_tc[2..4].copy_from_slice(&flags.to_be_bytes());
        socket.send_to(&wrong_qid_tc, peer).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let response = soa_response(header.id, serial);
        socket.send_to(&response, peer).await.unwrap();
    });
    addr
}

async fn spawn_malformed_soa_primary() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 512];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        socket.send_to(&[0], peer).await.unwrap();
    });
    addr
}

async fn spawn_signed_soa_primary_with_serial(serial: u32) -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let mut buffer = vec![0u8; 1024];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.arcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        let request_mac = extract_query_tsig_mac(query);
        let response = soa_response(header.id, serial);
        let signed = key
            .sign_response(
                &response,
                &request_mac,
                current_unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        socket.send_to(&signed.message, peer).await.unwrap();
    });
    addr
}

async fn spawn_truncated_udp_tcp_soa_primary(serial: u32) -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let mut buffer = vec![0u8; 1024];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let header = Header::parse(query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(query_qtype(query), RecordType::Soa as u16);

        let mut response = soa_response(header.id, serial);
        let flags = u16::from_be_bytes([response[2], response[3]]) | 0x0200;
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        socket.send_to(&response, peer).await.unwrap();

        let (mut stream, _) = listener.accept().await.unwrap();
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();
        let header = Header::parse(&query).unwrap();
        assert_eq!(query_qtype(&query), RecordType::Soa as u16);

        let request_mac = extract_query_tsig_mac(&query);
        let response = soa_response(header.id, serial);
        let signed = key
            .sign_response(
                &response,
                &request_mac,
                current_unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        stream
            .write_all(&frame_tcp_message(&signed.message))
            .await
            .unwrap();
    });
    addr
}

fn axfr_response(qid: u16, serial: u32) -> Vec<u8> {
    axfr_response_for_zone(qid, "example.test.", serial)
}

fn axfr_response_for_zone(qid: u16, zone: &str, serial: u32) -> Vec<u8> {
    transfer_response_for_zone(qid, zone, RecordType::Axfr as u16, serial)
}

fn catalog_axfr_response(catalog_zone: &str, member_zone: &str, qid: u16, serial: u32) -> Vec<u8> {
    let soa = record(
        catalog_zone,
        RecordType::Soa as u16,
        soa_rdata_with_serial(serial),
    );
    let ns = record(
        catalog_zone,
        RecordType::Ns as u16,
        ns_rdata_for_zone(catalog_zone),
    );
    let version = record(
        &format!("version.{catalog_zone}"),
        RecordType::Txt as u16,
        vec![1, b'2'],
    );
    let member = record(
        &format!("m0.zones.{catalog_zone}"),
        RecordType::Ptr as u16,
        DomainName::from_absolute_str(member_zone).unwrap().to_wire(),
    );
    let answers = vec![soa.clone(), ns, version, member, soa];
    let mut out = Vec::new();
    out.extend_from_slice(&qid.to_be_bytes());
    out.extend_from_slice(&0x8000u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(
        &DomainName::from_absolute_str(catalog_zone)
            .unwrap()
            .to_wire(),
    );
    out.extend_from_slice(&(RecordType::Axfr as u16).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for answer in answers {
        out.extend_from_slice(&answer.owner.to_wire());
        out.extend_from_slice(&answer.rr_type.to_be_bytes());
        out.extend_from_slice(&answer.class.to_be_bytes());
        out.extend_from_slice(&answer.ttl.to_be_bytes());
        out.extend_from_slice(&(answer.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&answer.rdata);
    }
    out
}

fn ixfr_mode2_response(qid: u16, serial: u32) -> Vec<u8> {
    ixfr_mode2_response_for_zone(qid, "example.test.", serial)
}

fn ixfr_mode2_response_for_zone(qid: u16, zone: &str, serial: u32) -> Vec<u8> {
    transfer_response_for_zone(qid, zone, RecordType::Ixfr as u16, serial)
}

fn transfer_response_for_zone(qid: u16, zone: &str, qtype: u16, serial: u32) -> Vec<u8> {
    let soa = record(zone, RecordType::Soa as u16, soa_rdata_with_serial(serial));
    let ns = record(zone, RecordType::Ns as u16, ns_rdata_for_zone(zone));
    let owner = format!("www.{zone}");
    let a = record(&owner, RecordType::A as u16, vec![192, 0, 2, 10]);
    let answers = vec![soa.clone(), ns, a, soa];
    let mut out = Vec::new();
    out.extend_from_slice(&qid.to_be_bytes());
    out.extend_from_slice(&0x8000u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&DomainName::from_absolute_str(zone).unwrap().to_wire());
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for answer in answers {
        out.extend_from_slice(&answer.owner.to_wire());
        out.extend_from_slice(&answer.rr_type.to_be_bytes());
        out.extend_from_slice(&answer.class.to_be_bytes());
        out.extend_from_slice(&answer.ttl.to_be_bytes());
        out.extend_from_slice(&(answer.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&answer.rdata);
    }
    out
}

async fn read_primary_query(stream: &mut TcpStream) -> Vec<u8> {
    let mut length_prefix = [0u8; 2];
    stream.read_exact(&mut length_prefix).await.unwrap();
    let query_len = u16::from_be_bytes(length_prefix) as usize;
    let mut query = vec![0u8; query_len];
    stream.read_exact(&mut query).await.unwrap();
    query
}

fn query_qtype(query: &[u8]) -> u16 {
    assert!(query.len() >= 28);
    u16::from_be_bytes([query[26], query[27]])
}

fn assert_query_has_tsig(query: &[u8], key_name: &str, algorithm_name: &str) {
    let header = Header::parse(query).unwrap();
    assert_eq!(header.arcount, 1);
    let original_id = header.id;
    let (question_name, question_len) = DomainName::parse(query, 12).unwrap();
    assert_eq!(
        question_name,
        DomainName::from_absolute_str("example.test.").unwrap()
    );
    let mut offset = 12 + question_len + 4;

    let (owner, owner_len) = DomainName::parse(query, offset).unwrap();
    assert_eq!(owner, DomainName::from_absolute_str(key_name).unwrap());
    offset += owner_len;
    assert_eq!(
        u16::from_be_bytes([query[offset], query[offset + 1]]),
        RecordType::Tsig as u16
    );
    assert_eq!(
        u16::from_be_bytes([query[offset + 2], query[offset + 3]]),
        255
    );
    assert_eq!(
        u32::from_be_bytes([
            query[offset + 4],
            query[offset + 5],
            query[offset + 6],
            query[offset + 7],
        ]),
        0
    );
    let rdlen = u16::from_be_bytes([query[offset + 8], query[offset + 9]]) as usize;
    offset += 10;
    let rdata_end = offset + rdlen;

    let (algorithm, algorithm_len) = DomainName::parse(query, offset).unwrap();
    assert_eq!(
        algorithm,
        DomainName::from_absolute_str(algorithm_name).unwrap()
    );
    offset += algorithm_len + 6 + 2;
    let mac_len = u16::from_be_bytes([query[offset], query[offset + 1]]) as usize;
    assert_eq!(mac_len, 32);
    offset += 2 + mac_len;
    assert_eq!(
        u16::from_be_bytes([query[offset], query[offset + 1]]),
        original_id
    );
    offset += 2;
    assert_eq!(u16::from_be_bytes([query[offset], query[offset + 1]]), 0);
    offset += 2;
    assert_eq!(u16::from_be_bytes([query[offset], query[offset + 1]]), 0);
    offset += 2;
    assert_eq!(offset, rdata_end);
    assert_eq!(offset, query.len());
}

fn extract_query_tsig_mac(query: &[u8]) -> Vec<u8> {
    let (_, question_len) = DomainName::parse(query, 12).unwrap();
    let mut offset = 12 + question_len + 4;
    let (_, owner_len) = DomainName::parse(query, offset).unwrap();
    offset += owner_len + 10;
    let (_, algorithm_len) = DomainName::parse(query, offset).unwrap();
    offset += algorithm_len + 6 + 2;
    let mac_len = u16::from_be_bytes([query[offset], query[offset + 1]]) as usize;
    offset += 2;
    query[offset..offset + mac_len].to_vec()
}

fn query_tsig_fudge(query: &[u8]) -> u16 {
    let (_, question_len) = DomainName::parse(query, 12).unwrap();
    let mut offset = 12 + question_len + 4;
    let (_, owner_len) = DomainName::parse(query, offset).unwrap();
    offset += owner_len + 10;
    let (_, algorithm_len) = DomainName::parse(query, offset).unwrap();
    offset += algorithm_len + 6;
    u16::from_be_bytes([query[offset], query[offset + 1]])
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn error_response(qid: u16, rcode: u8) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&qid.to_be_bytes());
    out.extend_from_slice(&(0x8000u16 | u16::from(rcode & 0x0f)).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn ixfr_mode1_response(qid: u16) -> Vec<u8> {
    let old_soa = record(
        "example.test.",
        RecordType::Soa as u16,
        soa_rdata_with_serial(1),
    );
    let new_soa = record(
        "example.test.",
        RecordType::Soa as u16,
        soa_rdata_with_serial(2),
    );
    let old_a = record(
        "old.example.test.",
        RecordType::A as u16,
        vec![192, 0, 2, 1],
    );
    let new_a = record(
        "new.example.test.",
        RecordType::A as u16,
        vec![192, 0, 2, 2],
    );
    let answers = vec![new_soa.clone(), old_soa, old_a, new_soa, new_a];
    let mut out = Vec::new();
    out.extend_from_slice(&qid.to_be_bytes());
    out.extend_from_slice(&0x8000u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(
        &DomainName::from_absolute_str("example.test.")
            .unwrap()
            .to_wire(),
    );
    out.extend_from_slice(&(RecordType::Ixfr as u16).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    for answer in answers {
        out.extend_from_slice(&answer.owner.to_wire());
        out.extend_from_slice(&answer.rr_type.to_be_bytes());
        out.extend_from_slice(&answer.class.to_be_bytes());
        out.extend_from_slice(&answer.ttl.to_be_bytes());
        out.extend_from_slice(&(answer.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&answer.rdata);
    }
    out
}

fn soa_response(qid: u16, serial: u32) -> Vec<u8> {
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let soa = record(
        "example.test.",
        RecordType::Soa as u16,
        soa_rdata_with_serial(serial),
    );
    let mut out = Vec::new();
    out.extend_from_slice(&qid.to_be_bytes());
    out.extend_from_slice(&0x8000u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&apex.to_wire());
    out.extend_from_slice(&(RecordType::Soa as u16).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&soa.owner.to_wire());
    out.extend_from_slice(&soa.rr_type.to_be_bytes());
    out.extend_from_slice(&soa.class.to_be_bytes());
    out.extend_from_slice(&soa.ttl.to_be_bytes());
    out.extend_from_slice(&(soa.rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&soa.rdata);
    out
}

fn notify_packet(qid: u16, qname: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let qname = DomainName::from_absolute_str(qname).unwrap();
    let mut packet = Vec::new();
    packet.extend_from_slice(&qid.to_be_bytes());
    packet.extend_from_slice(&((Opcode::Notify as u16) << 11).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&qname.to_wire());
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());
    packet
}

fn tsig_notify_authority() -> (NotifyAuthority, TsigKey) {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

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
    .expect("valid config");
    (
        NotifyAuthority::from_config_for_test(&config),
        TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap(),
    )
}

#[derive(Clone, Debug)]
struct CapturedEvents {
    lines: Arc<Mutex<Vec<String>>>,
}

impl CapturedEvents {
    fn new() -> Self {
        Self {
            lines: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn push(&self, line: String) {
        self.lines
            .lock()
            .expect("captured events lock poisoned")
            .push(line);
    }

    fn contains_all(&self, needles: &[&str]) -> bool {
        let lines = self.lines.lock().expect("captured events lock poisoned");
        lines
            .iter()
            .any(|line| needles.iter().all(|needle| line.contains(needle)))
    }
}

#[derive(Debug)]
struct CapturingSubscriber {
    events: CapturedEvents,
}

impl CapturingSubscriber {
    fn new(events: CapturedEvents) -> Self {
        Self { events }
    }
}

impl Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = EventLine::default();
        event.record(&mut visitor);
        self.events.push(visitor.line);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}

    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }
}

#[derive(Default)]
struct EventLine {
    line: String,
}

impl Visit for EventLine {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if !self.line.is_empty() {
            self.line.push(' ');
        }
        self.line.push_str(&format!("{}={:?}", field.name(), value));
    }
}

fn replace_final_tsig_mac(message: &[u8], replacement_mac: &[u8]) -> Vec<u8> {
    let mut out = message.to_vec();
    let mut offset = 12;
    let (_, qname_len) = DomainName::parse(&out, offset).unwrap();
    offset += qname_len + 4;
    let (_, owner_len) = DomainName::parse(&out, offset).unwrap();
    let rdlen_offset = offset + owner_len + 8;
    let rdata_offset = offset + owner_len + 10;
    let old_rdlen = u16::from_be_bytes([out[rdlen_offset], out[rdlen_offset + 1]]) as usize;
    let mut rdata_cursor = rdata_offset;
    let (_, algorithm_len) = DomainName::parse(&out, rdata_cursor).unwrap();
    rdata_cursor += algorithm_len + 6 + 2;
    let mac_len_offset = rdata_cursor;
    let old_mac_len = u16::from_be_bytes([out[mac_len_offset], out[mac_len_offset + 1]]) as usize;
    let mac_offset = mac_len_offset + 2;
    out.splice(
        mac_offset..mac_offset + old_mac_len,
        replacement_mac.iter().copied(),
    );
    out[mac_len_offset..mac_len_offset + 2]
        .copy_from_slice(&(replacement_mac.len() as u16).to_be_bytes());
    let new_rdlen = old_rdlen - old_mac_len + replacement_mac.len();
    out[rdlen_offset..rdlen_offset + 2].copy_from_slice(&(new_rdlen as u16).to_be_bytes());
    out
}

fn replace_final_tsig_owner(message: &[u8], replacement_owner: &str) -> Vec<u8> {
    let mut out = message.to_vec();
    let mut offset = 12;
    let (_, qname_len) = DomainName::parse(&out, offset).unwrap();
    offset += qname_len + 4;
    let (_, old_owner_len) = DomainName::parse(&out, offset).unwrap();
    let replacement_wire = DomainName::from_absolute_str(replacement_owner)
        .unwrap()
        .to_wire();
    out.splice(
        offset..offset + old_owner_len,
        replacement_wire.iter().copied(),
    );
    out
}

fn replace_final_tsig_algorithm(message: &[u8], replacement_algorithm: &str) -> Vec<u8> {
    let mut out = message.to_vec();
    let mut offset = 12;
    let (_, qname_len) = DomainName::parse(&out, offset).unwrap();
    offset += qname_len + 4;
    let (_, owner_len) = DomainName::parse(&out, offset).unwrap();
    let rdlen_offset = offset + owner_len + 8;
    let rdata_offset = offset + owner_len + 10;
    let old_rdlen = u16::from_be_bytes([out[rdlen_offset], out[rdlen_offset + 1]]) as usize;
    let (_, old_algorithm_len) = DomainName::parse(&out, rdata_offset).unwrap();
    let replacement_wire = DomainName::from_absolute_str(replacement_algorithm)
        .unwrap()
        .to_wire();
    out.splice(
        rdata_offset..rdata_offset + old_algorithm_len,
        replacement_wire.iter().copied(),
    );
    let new_rdlen = old_rdlen - old_algorithm_len + replacement_wire.len();
    out[rdlen_offset..rdlen_offset + 2].copy_from_slice(&(new_rdlen as u16).to_be_bytes());
    out
}

struct ParsedTsigResponseFields {
    fudge: u16,
    mac_len: usize,
    original_id: u16,
    error: u16,
    other_data: Vec<u8>,
}

fn parse_tsig_response_fields(response: &[u8]) -> ParsedTsigResponseFields {
    assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
    let mut offset = 12;
    let (_, qname_len) = DomainName::parse(response, offset).unwrap();
    offset += qname_len + 4;
    let (_, owner_len) = DomainName::parse(response, offset).unwrap();
    offset += owner_len;
    assert_eq!(
        u16::from_be_bytes([response[offset], response[offset + 1]]),
        RecordType::Tsig as u16
    );
    let rdlen = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
    offset += 10;
    let rdata_end = offset + rdlen;
    let (_, algorithm_len) = DomainName::parse(response, offset).unwrap();
    offset += algorithm_len + 6;
    let fudge = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    let mac_len = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2 + mac_len;
    let original_id = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    let error = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    let other_len = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2;
    assert_eq!(offset + other_len, rdata_end);
    ParsedTsigResponseFields {
        fudge,
        mac_len,
        original_id,
        error,
        other_data: response[offset..offset + other_len].to_vec(),
    }
}

fn notify_response(qid: u16) -> Vec<u8> {
    let qname = DomainName::from_absolute_str("example.test.").unwrap();
    let mut response = Vec::new();
    response.extend_from_slice(&qid.to_be_bytes());
    response
        .extend_from_slice(&(0x8000u16 | ((Opcode::Notify as u16) << 11) | 0x0400).to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&qname.to_wire());
    response.extend_from_slice(&(RecordType::Soa as u16).to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response
}

fn positive_query_response() -> Vec<u8> {
    let mut response = rcode_query_response(0);
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response
}

fn query_response_with_opt() -> Vec<u8> {
    let mut response = rcode_query_response(0);
    response[10..12].copy_from_slice(&1u16.to_be_bytes());
    response.push(0);
    response.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
    response.extend_from_slice(&1232u16.to_be_bytes());
    response.extend_from_slice(&0u32.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response
}

fn referral_query_response() -> Vec<u8> {
    let mut response = rcode_query_response(0);
    response[8..10].copy_from_slice(&1u16.to_be_bytes());
    let owner = DomainName::from_absolute_str("example.test.").unwrap();
    let target = DomainName::from_absolute_str("ns.example.test.").unwrap();
    response.extend_from_slice(&owner.to_wire());
    response.extend_from_slice(&(RecordType::Ns as u16).to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&300u32.to_be_bytes());
    response.extend_from_slice(&(target.to_wire().len() as u16).to_be_bytes());
    response.extend_from_slice(&target.to_wire());
    response
}

fn rcode_query_response(rcode: u8) -> Vec<u8> {
    let mut response = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    response[2..4].copy_from_slice(&(0x8400u16 | u16::from(rcode & 0x0f)).to_be_bytes());
    response
}

fn query(qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x1234u16.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(qname);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());
    packet
}

fn query_observation_options() -> QueryObservationOptions {
    QueryObservationOptions {
        transport: Transport::Udp,
        cookie_validated: false,
        parse_duration: None,
    }
}

fn active_example_zone() -> ZoneStore {
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![Rrset::new(
            DomainName::from_absolute_str("www.example.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 10].to_vec()],
        )],
    ));
    zones
}

fn udp_settings_for_test(metrics: RuntimeMetrics, rrl_config: RrlConfig) -> UdpServerSettings {
    UdpServerSettings {
        max_udp_payload: 1232,
        udp_batch_size: 1,
        udp_backend: UdpBackend::Std,
        udp_runtime: UdpRuntime::Tokio,
        udp_idle_strategy: Default::default(),
        xdp: XdpConfig::default(),
        max_cname_chain: 8,
        nsec3_max_iterations: 100,
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
        metrics: metrics.clone(),
        rrl: RrlLimiter::from_config(&rrl_config, metrics),
    }
}

fn notify_log_limiter_for_test() -> NotifyLogLimiter {
    NotifyLogLimiter::new(std::time::Duration::from_secs(60), 100_000)
}

async fn spawn_telemetry_endpoint(
    status: &'static str,
) -> (std::net::SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let _ = request_tx.send(request);
        let response =
            format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (addr, request_rx)
}

async fn spawn_operation_endpoint() -> (std::net::SocketAddr, oneshot::Receiver<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut requests = Vec::new();
        for index in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            requests.push(request);
            if index == 0 {
                let body = r#"[{"id":42,"zone_name":"alpha.test.","operation":"retry"}]"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            } else {
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        }
        let _ = request_tx.send(requests);
    });
    (addr, request_rx)
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut header_end = None;
    let mut content_length = 0usize;
    loop {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await.unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if header_end.is_none()
            && let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
        {
            header_end = Some(position + 4);
            let headers = String::from_utf8_lossy(&request[..position]);
            for line in headers.lines() {
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    content_length = value.trim().parse().unwrap();
                }
            }
        }
        if let Some(end) = header_end
            && request.len() >= end + content_length
        {
            break;
        }
    }
    String::from_utf8(request).expect("telemetry request should be utf8")
}

fn control_plane_reporter_for_endpoint(
    endpoint: std::net::SocketAddr,
) -> ControlPlaneTelemetryReporter {
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [control_plane.telemetry]
                endpoint_url = "http://{endpoint}"
                node_id = "node-a"
                bearer_token = "token-a"
                timeout_secs = 5

                [[zones]]
                name = "alpha.test."
                primaries = ["192.0.2.53:53"]
            "#
    ))
    .expect("valid telemetry config");
    ControlPlaneTelemetryReporter::from_config(&config)
}

fn control_plane_operation_client_for_endpoint(
    endpoint: std::net::SocketAddr,
) -> ControlPlaneOperationClient {
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [control_plane.operations]
                enabled = true
                endpoint_url = "http://{endpoint}"
                node_id = "node-a"
                bearer_token = "token-a"
                poll_interval_secs = 1
                lease_seconds = 5
                timeout_secs = 5

                [[zones]]
                name = "alpha.test."
                primaries = ["192.0.2.53:53"]
            "#
    ))
    .expect("valid operations config");
    ControlPlaneOperationClient::from_config(&config)
}

fn telemetry_zone_metadata(serial: Option<u32>, soa_timers: Option<SoaTimers>) -> ZoneMetadata {
    ZoneMetadata {
        origin: DomainName::from_absolute_str("alpha.test.").unwrap(),
        origin_key: Arc::from("alpha.test."),
        origin_name: Arc::from("alpha.test."),
        state: ZoneState::Active,
        serial,
        soa_timers,
        shape: None,
        shape_histograms: None,
    }
}

fn telemetry_json_body(request: &str) -> serde_json::Value {
    let body = request
        .split_once("\r\n\r\n")
        .expect("telemetry request should have headers")
        .1;
    serde_json::from_str(body).expect("telemetry request body should be JSON")
}

fn dns_cookie_settings_for_test(policy: DnsCookiePolicy) -> DnsCookieRuntimeSettings {
    DnsCookieRuntimeSettings {
        policy: Some(policy),
        past_window_secs: 3600,
        future_window_secs: 300,
        secret_rotation_interval: None,
    }
}

fn dns_cookie_secret_store_for_test() -> DnsCookieSecretStore {
    DnsCookieSecretStore::new([7; 16], None)
}

fn cookie_prefix_metrics_for_test() -> CookiePrefixMetricSettings {
    CookiePrefixMetricSettings {
        ipv4_prefix_len: 24,
        ipv6_prefix_len: 56,
    }
}

fn append_opt(packet: &mut Vec<u8>, payload_size: u16, ttl: u32, rdata: &[u8]) {
    packet[11] = packet[11].checked_add(1).unwrap();
    packet.push(0);
    packet.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
    packet.extend_from_slice(&payload_size.to_be_bytes());
    packet.extend_from_slice(&ttl.to_be_bytes());
    packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    packet.extend_from_slice(rdata);
}

fn edns_option(code: u16, data: &[u8]) -> Vec<u8> {
    let mut option = Vec::new();
    option.extend_from_slice(&code.to_be_bytes());
    option.extend_from_slice(&(data.len() as u16).to_be_bytes());
    option.extend_from_slice(data);
    option
}

fn cookie_query(cookie_data: &[u8]) -> Vec<u8> {
    let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    append_opt(&mut packet, 4096, 0, &edns_option(10, cookie_data));
    packet
}

fn response_cookie_option(response: &[u8]) -> Option<Vec<u8>> {
    let header = Header::parse(response).ok()?;
    let opt = response_opt_record(response, &header)?;
    let rdlength = u16::from_be_bytes([opt[9], opt[10]]) as usize;
    let rdata = opt.get(11..11 + rdlength)?;
    let mut offset = 0usize;
    while offset < rdata.len() {
        let option_code = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
        let option_len = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
        offset += 4;
        if option_code == 10 {
            return Some(rdata[offset..offset + option_len].to_vec());
        }
        offset += option_len;
    }
    None
}

async fn recv_udp_with_timeout(
    socket: &UdpSocket,
    timeout_duration: std::time::Duration,
) -> Option<Vec<u8>> {
    let mut response = vec![0u8; 512];
    let len = tokio::time::timeout(timeout_duration, socket.recv(&mut response))
        .await
        .ok()?
        .ok()?;
    response.truncate(len);
    Some(response)
}

async fn read_framed_tcp_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut length_prefix = [0u8; 2];
    stream.read_exact(&mut length_prefix).await.unwrap();
    let response_len = u16::from_be_bytes(length_prefix) as usize;
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response).await.unwrap();
    response
}

async fn spawn_runtime_with_bound_health(
    runtime: Runtime,
) -> (
    tokio::task::JoinHandle<Result<(), RuntimeError>>,
    std::net::SocketAddr,
) {
    spawn_runtime_with_bound_health_and_shutdown(
        runtime,
        std::future::pending::<Result<&'static str, std::io::Error>>(),
    )
    .await
}

async fn spawn_runtime_with_bound_health_and_shutdown(
    runtime: Runtime,
    shutdown_signal: impl Future<Output = Result<&'static str, std::io::Error>> + Send + 'static,
) -> (
    tokio::task::JoinHandle<Result<(), RuntimeError>>,
    std::net::SocketAddr,
) {
    let (health_bound_tx, health_bound_rx) = oneshot::channel();
    let server = tokio::spawn(
        runtime.run_with_shutdown_signal_inner(shutdown_signal, Some(health_bound_tx)),
    );
    let health_addr = tokio::time::timeout(std::time::Duration::from_secs(1), health_bound_rx)
        .await
        .expect("runtime did not bind health listener before timeout")
        .expect("runtime exited before binding health listener");
    (server, health_addr)
}

async fn http_request(addr: std::net::SocketAddr, method: &str, path: &str) -> String {
    String::from_utf8(http_request_with_headers(addr, method, path, &[]).await)
        .expect("HTTP response should be UTF-8")
}

async fn http_json(addr: std::net::SocketAddr, path: &str) -> serde_json::Value {
    let response = http_request(addr, "GET", path).await;
    json_body_from_ok_response(response)
}

async fn http_json_with_headers(
    addr: std::net::SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> serde_json::Value {
    let response = String::from_utf8(http_request_with_headers(addr, "GET", path, headers).await)
        .expect("HTTP response should be UTF-8");
    json_body_from_ok_response(response)
}

fn json_body_from_ok_response(response: String) -> serde_json::Value {
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "unexpected HTTP response: {response}"
    );
    let body = response
        .split_once("\r\n\r\n")
        .expect("HTTP response should have body")
        .1;
    serde_json::from_str(body).expect("observability response should be valid JSON")
}

async fn http_request_with_headers(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n"
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("Content-Length: 0\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

fn split_http_response(response: &[u8]) -> (&str, &[u8]) {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response should contain a header/body split")
        + 4;
    let headers = std::str::from_utf8(&response[..split]).expect("headers should be UTF-8");
    (headers, &response[split..])
}

async fn eventually_http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    timeout: std::time::Duration,
) -> String {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                let request = format!(
                    "{method} {path} HTTP/1.1\r\n\
                         Host: localhost\r\n\
                         Connection: close\r\n\
                         Content-Length: 0\r\n\
                         \r\n"
                );
                stream.write_all(request.as_bytes()).await.unwrap();

                let mut response = String::new();
                stream.read_to_string(&mut response).await.unwrap();
                return response;
            }
            Err(error) => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                assert!(
                    !remaining.is_zero(),
                    "HTTP endpoint {addr} did not accept connection before timeout: {error}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10).min(remaining)).await;
            }
        }
    }
}

async fn eventually_health_body(
    addr: std::net::SocketAddr,
    expected_body: &str,
    timeout: std::time::Duration,
) -> String {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "health endpoint {addr} did not return expected body {expected_body:?} before timeout"
        );
        let response = eventually_http_request(addr, "GET", "/healthz", remaining).await;
        if response.ends_with(expected_body) {
            return response;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn unused_udp_tcp_addr() -> std::net::SocketAddr {
    for _ in 0..32 {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        match UdpSocket::bind(addr).await {
            Ok(udp) => {
                drop(udp);
                drop(tcp);
                return addr;
            }
            Err(_) => {
                drop(tcp);
            }
        }
    }
    panic!("could not find an address free for both UDP and TCP");
}

fn health_state(zones: ZoneStore) -> HealthEndpointState {
    health_state_with_observability(zones, ObservabilityConfig::default())
}

fn health_state_with_observability(
    zones: ZoneStore,
    observability: ObservabilityConfig,
) -> HealthEndpointState {
    let observability_rate_limiter = MetricsRateLimiter::from_observability_config(&observability);
    let observability_auth =
        ObservabilityAuth::from_config(&observability).expect("observability auth config");
    HealthEndpointState {
        zones,
        runtime_status: RuntimeStatus::new(),
        metrics: RuntimeMetrics::new(),
        catalog_manager: CatalogManager::default(),
        refresh_registry: ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        ),
        metrics_rate_limiter: MetricsRateLimiter::default(),
        observability,
        observability_auth,
        observability_rate_limiter,
        transfer_materials: Vec::<TransferMaterial>::new(),
        started_at: std::time::Instant::now(),
        graceful_shutdown_secs: 30,
        zone_shape_metrics_enabled: false,
    }
}

fn record(owner: &str, rr_type: u16, rdata: Vec<u8>) -> ResourceRecord {
    ResourceRecord {
        owner: DomainName::from_absolute_str(owner).unwrap(),
        rr_type,
        class: 1,
        ttl: 300,
        rdata,
    }
}

fn soa_rdata() -> Vec<u8> {
    soa_rdata_with_serial(1)
}

fn ns_rdata_for_zone(zone: &str) -> Vec<u8> {
    DomainName::from_absolute_str(&format!("ns.{zone}"))
        .unwrap()
        .to_wire()
}

fn soa_rdata_with_serial(serial: u32) -> Vec<u8> {
    let mut rdata = b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec();
    let (_, consumed_mname) = DomainName::parse(&rdata, 0).unwrap();
    let (_, consumed_rname) = DomainName::parse(&rdata, consumed_mname).unwrap();
    let serial_offset = consumed_mname + consumed_rname;
    rdata[serial_offset..serial_offset + 4].copy_from_slice(&serial.to_be_bytes());
    rdata
}
