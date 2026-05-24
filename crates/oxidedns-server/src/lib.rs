use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
};
use tracing::{debug, info, warn};
use oxidedns_core::{
    ServerConfig,
    axfr::{self, AxfrError},
    dns::{
        AnswerOptions, AnyResponseMode, DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS, DatagramAction,
        DomainName, Transport, answer_message,
    },
    zone::{ZoneSnapshot, ZoneStore},
};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("failed to bind UDP listener {addr}: {source}")]
    BindUdp {
        addr: std::net::SocketAddr,
        source: std::io::Error,
    },

    #[error("failed to bind TCP listener {addr}: {source}")]
    BindTcp {
        addr: std::net::SocketAddr,
        source: std::io::Error,
    },

    #[error("UDP listener failed: {0}")]
    Udp(std::io::Error),

    #[error("TCP listener failed: {0}")]
    Tcp(std::io::Error),

    #[error("shutdown signal failed: {0}")]
    ShutdownSignal(std::io::Error),
}

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("failed to connect to AXFR primary {addr}: {source}")]
    ConnectTcp {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("AXFR TCP I/O with primary {addr} failed: {source}")]
    Io {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("AXFR session timed out after {timeout_secs} seconds")]
    Timeout { timeout_secs: u64 },

    #[error("AXFR response validation failed: {0}")]
    Axfr(#[from] AxfrError),
}

#[derive(Debug)]
pub struct Runtime {
    config: ServerConfig,
    zones: ZoneStore,
}

impl Runtime {
    pub fn new(config: ServerConfig) -> Self {
        let zones = ZoneStore::new();
        for zone in &config.zones {
            zones.insert_loading(
                DomainName::from_absolute_str(&zone.name)
                    .expect("configuration validation rejects invalid zone names"),
            );
        }

        Self { config, zones }
    }

    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }

    pub async fn run(self) -> Result<(), RuntimeError> {
        self.load_initial_zones().await;

        info!(
            udp_listeners = self.config.server.listen_udp.len(),
            tcp_listeners = self.config.server.listen_tcp.len(),
            zones = self.zones.len(),
            "OxideDNS runtime initialized"
        );

        let mut listeners = JoinSet::new();
        for addr in &self.config.server.listen_udp {
            let socket = UdpSocket::bind(addr)
                .await
                .map_err(|source| RuntimeError::BindUdp {
                    addr: *addr,
                    source,
                })?;
            let zones = self.zones.clone();
            let max_udp_payload = self.config.limits.max_udp_payload;
            let max_cname_chain = self.config.limits.max_cname_chain;
            let edns_padding_block_size = self.config.limits.edns_padding_block_size;
            let any_response = self.config.query.any_response_mode();
            listeners.spawn(async move {
                serve_udp(
                    socket,
                    zones,
                    max_udp_payload,
                    max_cname_chain,
                    edns_padding_block_size,
                    any_response,
                )
                .await
            });
        }
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        for addr in &self.config.server.listen_tcp {
            let listener =
                TcpListener::bind(addr)
                    .await
                    .map_err(|source| RuntimeError::BindTcp {
                        addr: *addr,
                        source,
                    })?;
            let zones = self.zones.clone();
            let max_udp_payload = self.config.limits.max_udp_payload;
            let max_cname_chain = self.config.limits.max_cname_chain;
            let tcp_idle_timeout = Duration::from_secs(self.config.limits.tcp_idle_timeout_secs);
            let tcp_read_timeout = Duration::from_secs(self.config.limits.tcp_read_timeout_secs);
            let tcp_write_timeout = Duration::from_secs(self.config.limits.tcp_write_timeout_secs);
            let max_tcp_connections = self.config.limits.max_tcp_connections;
            let edns_padding_block_size = self.config.limits.edns_padding_block_size;
            let any_response = self.config.query.any_response_mode();
            let tcp_connections = tcp_connections.clone();
            let tcp_settings = TcpServerSettings {
                max_udp_payload,
                max_cname_chain,
                idle_timeout: tcp_idle_timeout,
                read_timeout: tcp_read_timeout,
                write_timeout: tcp_write_timeout,
                max_connections: max_tcp_connections,
                edns_padding_block_size,
                any_response,
                active_connections: tcp_connections,
            };
            listeners.spawn(async move { serve_tcp(listener, zones, tcp_settings).await });
        }

        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(RuntimeError::ShutdownSignal)?;
                info!("shutdown signal received");
            }
            result = listeners.join_next(), if !listeners.is_empty() => {
                match result {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(error))) => return Err(error),
                    Some(Err(error)) => {
                        warn!(%error, "UDP listener task failed");
                    }
                }
            }
        }

        Ok(())
    }

    async fn load_initial_zones(&self) {
        for zone in &self.config.zones {
            let zone_apex = DomainName::from_absolute_str(&zone.name)
                .expect("configuration validation rejects invalid zone names");
            let qclass = 1;
            let mut loaded = false;

            for primary in &zone.primaries {
                let qid = transfer_query_id(&zone_apex, *primary);
                match transfer_axfr_from_primary(
                    *primary,
                    &zone_apex,
                    qclass,
                    qid,
                    Duration::from_secs(self.config.limits.axfr_timeout_secs),
                )
                .await
                {
                    Ok(snapshot) => {
                        let serial = snapshot.serial;
                        self.zones.insert_snapshot(snapshot);
                        info!(zone = %zone_apex, %primary, ?serial, "initial AXFR completed");
                        loaded = true;
                        break;
                    }
                    Err(error) => {
                        warn!(zone = %zone_apex, %primary, %error, "initial AXFR failed");
                    }
                }
            }

            if !loaded {
                warn!(zone = %zone_apex, "zone remains in LOADING state");
            }
        }
    }
}

pub async fn transfer_axfr_from_primary(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    timeout_duration: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    tokio::time::timeout(timeout_duration, async {
        transfer_axfr_from_primary_inner(primary, zone_apex, qclass, qid).await
    })
    .await
    .map_err(|_| TransferError::Timeout {
        timeout_secs: timeout_duration.as_secs(),
    })?
}

async fn transfer_axfr_from_primary_inner(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
) -> Result<ZoneSnapshot, TransferError> {
    let mut stream =
        TcpStream::connect(primary)
            .await
            .map_err(|source| TransferError::ConnectTcp {
                addr: primary,
                source,
            })?;

    let query = axfr::frame_tcp_message(&axfr::build_axfr_query(qid, zone_apex, qclass));
    stream
        .write_all(&query)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary,
            source,
        })?;

    let mut messages = Vec::new();
    loop {
        let mut length_prefix = [0u8; 2];
        match stream.read_exact(&mut length_prefix).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return axfr::parse_axfr_response(qid, zone_apex, qclass, &messages)
                    .map_err(TransferError::Axfr);
            }
            Err(source) => {
                return Err(TransferError::Io {
                    addr: primary,
                    source,
                });
            }
        }

        let message_len = u16::from_be_bytes(length_prefix) as usize;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message).await.map_err(|source| {
            if source.kind() == std::io::ErrorKind::UnexpectedEof {
                TransferError::Axfr(AxfrError::MissingTerminatingSoa)
            } else {
                TransferError::Io {
                    addr: primary,
                    source,
                }
            }
        })?;
        messages.push(message);

        match axfr::parse_axfr_response(qid, zone_apex, qclass, &messages) {
            Ok(snapshot) => return Ok(snapshot),
            Err(AxfrError::MissingTerminatingSoa) => {}
            Err(error) => return Err(TransferError::Axfr(error)),
        }
    }
}

fn transfer_query_id(zone_apex: &DomainName, primary: SocketAddr) -> u16 {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hash = since_epoch as u64 ^ primary.port() as u64;
    for byte in zone_apex.canonical_key().bytes() {
        hash = hash.wrapping_mul(16_777_619) ^ byte as u64;
    }
    (hash & 0xffff) as u16
}

async fn serve_udp(
    socket: UdpSocket,
    zones: ZoneStore,
    max_udp_payload: u16,
    max_cname_chain: usize,
    edns_padding_block_size: u16,
    any_response: AnyResponseMode,
) -> Result<(), RuntimeError> {
    let local_addr = socket.local_addr().map_err(RuntimeError::Udp)?;
    info!(%local_addr, "UDP listener bound");

    let mut buffer = vec![0u8; 4096];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buffer)
            .await
            .map_err(RuntimeError::Udp)?;
        match answer_message(
            &buffer[..len],
            &zones,
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload,
                max_cname_chain,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size,
                any_response,
            },
        ) {
            DatagramAction::Discard => {
                debug!(%peer, bytes = len, "discarded DNS datagram");
            }
            DatagramAction::Respond(response) => {
                socket
                    .send_to(&response, peer)
                    .await
                    .map_err(RuntimeError::Udp)?;
            }
        }
    }
}

async fn serve_tcp(
    listener: TcpListener,
    zones: ZoneStore,
    settings: TcpServerSettings,
) -> Result<(), RuntimeError> {
    let local_addr = listener.local_addr().map_err(RuntimeError::Tcp)?;
    info!(%local_addr, "TCP listener bound");

    loop {
        let (stream, peer) = listener.accept().await.map_err(RuntimeError::Tcp)?;
        let Some(connection_permit) = try_acquire_tcp_connection_slot(
            settings.active_connections.clone(),
            settings.max_connections,
        ) else {
            warn!(
                %peer,
                active_connections = settings.active_connections.load(Ordering::Relaxed),
                limit = settings.max_connections,
                "TCP connection limit reached; closing accepted connection"
            );
            drop(stream);
            continue;
        };

        let zones = zones.clone();
        let settings = settings.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(error) = handle_tcp_connection(
                stream,
                zones,
                settings.idle_timeout,
                settings.max_udp_payload,
                settings.max_cname_chain,
                settings.read_timeout,
                settings.write_timeout,
                settings.edns_padding_block_size,
                settings.any_response,
            )
            .await
            {
                warn!(%peer, %error, "TCP connection failed");
            }
        });
    }
}

#[derive(Clone)]
struct TcpServerSettings {
    max_udp_payload: u16,
    max_cname_chain: usize,
    idle_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    max_connections: usize,
    edns_padding_block_size: u16,
    any_response: AnyResponseMode,
    active_connections: Arc<AtomicUsize>,
}

struct TcpConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for TcpConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Release);
    }
}

fn try_acquire_tcp_connection_slot(
    active: Arc<AtomicUsize>,
    limit: usize,
) -> Option<TcpConnectionPermit> {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < limit).then_some(current + 1)
        })
        .ok()
        .map(|_| TcpConnectionPermit { active })
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection(
    mut stream: TcpStream,
    zones: ZoneStore,
    idle_timeout: Duration,
    max_udp_payload: u16,
    max_cname_chain: usize,
    read_timeout: Duration,
    write_timeout: Duration,
    edns_padding_block_size: u16,
    any_response: AnyResponseMode,
) -> Result<(), RuntimeError> {
    while let Some(packet) = read_tcp_message(&mut stream, idle_timeout, read_timeout).await? {
        match answer_message(
            &packet,
            &zones,
            AnswerOptions {
                transport: Transport::Tcp,
                max_udp_payload,
                max_cname_chain,
                tcp_keepalive_timeout_secs: idle_timeout.as_secs(),
                edns_padding_block_size,
                any_response,
            },
        ) {
            DatagramAction::Discard => {
                debug!(bytes = packet.len(), "discarded DNS-over-TCP message");
            }
            DatagramAction::Respond(response) => {
                match tokio::time::timeout(
                    write_timeout,
                    stream.write_all(&frame_dns_tcp_message(&response)),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(RuntimeError::Tcp(error)),
                    Err(_) => return Ok(()),
                }
            }
        }
    }

    Ok(())
}

async fn read_tcp_message(
    stream: &mut TcpStream,
    idle_timeout: Duration,
    read_timeout: Duration,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    let Some(first_len_byte) = read_tcp_byte(stream, idle_timeout).await? else {
        return Ok(None);
    };
    let Some(second_len_byte) = read_tcp_byte(stream, read_timeout).await? else {
        return Ok(None);
    };
    let message_len = u16::from_be_bytes([first_len_byte, second_len_byte]) as usize;
    if message_len == 0 {
        warn!("zero-length DNS-over-TCP frame received; closing connection");
        return Ok(None);
    }

    let mut message = vec![0u8; message_len];
    match tokio::time::timeout(read_timeout, stream.read_exact(&mut message)).await {
        Ok(Ok(_)) => Ok(Some(message)),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Ok(Err(error)) => Err(RuntimeError::Tcp(error)),
        Err(_) => Ok(None),
    }
}

async fn read_tcp_byte(
    stream: &mut TcpStream,
    idle_timeout: Duration,
) -> Result<Option<u8>, RuntimeError> {
    match tokio::time::timeout(idle_timeout, stream.read_u8()).await {
        Ok(Ok(byte)) => Ok(Some(byte)),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Ok(Err(error)) => Err(RuntimeError::Tcp(error)),
        Err(_) => Ok(None),
    }
}

fn frame_dns_tcp_message(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&(message.len() as u16).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use oxidedns_core::{
        ServerConfig,
        axfr::frame_tcp_message,
        dns::{AnyResponseMode, DomainName, Header, RecordType},
        zone::{ResourceRecord, Rrset, ZoneSnapshot, ZoneState, ZoneStore},
    };

    use super::{
        Runtime, TcpServerSettings, handle_tcp_connection, serve_tcp, transfer_axfr_from_primary,
    };

    #[test]
    fn runtime_initializes_loading_zones() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        let runtime = Runtime::new(config);
        assert_eq!(runtime.zone_count(), 1);
    }

    #[tokio::test]
    async fn transfer_axfr_from_primary_reads_tcp_messages() {
        let primary = spawn_axfr_primary().await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let snapshot = transfer_axfr_from_primary(
            primary,
            &apex,
            1,
            0x1234,
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("AXFR transfer");

        assert_eq!(snapshot.state, ZoneState::Active);
        assert_eq!(
            snapshot
                .lookup(
                    &DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn runtime_initial_load_publishes_zone_snapshot() {
        let primary = spawn_axfr_primary().await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");

        let runtime = Runtime::new(config);
        runtime.load_initial_zones().await;

        let snapshot = runtime
            .zones
            .get("example.test.")
            .expect("published zone snapshot");
        assert_eq!(snapshot.state, ZoneState::Active);
    }

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
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                0,
                AnyResponseMode::Minimal,
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
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                0,
                AnyResponseMode::Minimal,
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
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                0,
                AnyResponseMode::Minimal,
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
                std::time::Duration::from_millis(25),
                std::time::Duration::from_secs(5),
                0,
                AnyResponseMode::Minimal,
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
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                0,
                AnyResponseMode::Minimal,
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
        let server = tokio::spawn(serve_tcp(
            listener,
            zones,
            TcpServerSettings {
                max_udp_payload: 1232,
                max_cname_chain: 8,
                idle_timeout: std::time::Duration::from_secs(30),
                read_timeout: std::time::Duration::from_secs(30),
                write_timeout: std::time::Duration::from_secs(30),
                max_connections: 1,
                edns_padding_block_size: 0,
                any_response: AnyResponseMode::Minimal,
                active_connections: active.clone(),
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

    async fn spawn_axfr_primary() -> std::net::SocketAddr {
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

            let response = axfr_response(header.id);
            stream
                .write_all(&frame_tcp_message(&response))
                .await
                .unwrap();
        });
        addr
    }

    fn axfr_response(qid: u16) -> Vec<u8> {
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let answers = vec![soa.clone(), a, soa];
        let mut out = Vec::new();
        out.extend_from_slice(&qid.to_be_bytes());
        out.extend_from_slice(&0x8000u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
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

    async fn read_framed_tcp_response(stream: &mut TcpStream) -> Vec<u8> {
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let response_len = u16::from_be_bytes(length_prefix) as usize;
        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response).await.unwrap();
        response
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
        b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()
    }
}
