use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use borondns_core::{
    axfr::frame_tcp_message,
    dns::{Rcode, RecordType},
    tsig::{DEFAULT_TSIG_FUDGE_SECS, TsigError, TsigKey, message_has_tsig},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
};
use tracing::{info, warn};

use crate::{
    scenario::{Scenario, ScenarioError, ZoneKind},
    wire::{AxfrMessageStream, ParsedQuery, WireError, parse_query, single_answer_response},
};

const MAX_CONNECTIONS: usize = 65_535;

#[derive(Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub message_bytes: usize,
    pub max_connections: usize,
    pub tsig_key: Option<TsigKey>,
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("max_connections {0} is outside 1..=65535")]
    InvalidConnections(usize),
    #[error("configured DNS message target {0} is outside 512..=64000")]
    InvalidMessageBytes(usize),
    #[error("failed to bind {transport} listener at {addr}: {source}")]
    Bind {
        transport: &'static str,
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("DNS I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Scenario(#[from] ScenarioError),
    #[error(transparent)]
    Tsig(#[from] TsigError),
    #[error("signed DNS TCP message exceeded the 65,535-byte frame limit")]
    SignedFrameTooLong,
}

#[derive(Debug, Default)]
struct ServerStatsInner {
    queries: AtomicU64,
    soa_answers: AtomicU64,
    axfr_completed: AtomicU64,
    axfr_messages: AtomicU64,
    axfr_records: AtomicU64,
    rejected: AtomicU64,
    tcp_overload_drops: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct ServerStats {
    pub queries: u64,
    pub soa_answers: u64,
    pub axfr_completed: u64,
    pub axfr_messages: u64,
    pub axfr_records: u64,
    pub rejected: u64,
    pub tcp_overload_drops: u64,
}

impl ServerStatsInner {
    fn snapshot(&self) -> ServerStats {
        ServerStats {
            queries: self.queries.load(Ordering::Relaxed),
            soa_answers: self.soa_answers.load(Ordering::Relaxed),
            axfr_completed: self.axfr_completed.load(Ordering::Relaxed),
            axfr_messages: self.axfr_messages.load(Ordering::Relaxed),
            axfr_records: self.axfr_records.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            tcp_overload_drops: self.tcp_overload_drops.load(Ordering::Relaxed),
        }
    }
}

pub struct BoundServer {
    tcp: TcpListener,
    udp: UdpSocket,
    scenario: Arc<Scenario>,
    message_bytes: usize,
    connections: Arc<Semaphore>,
    tsig_key: Option<Arc<TsigKey>>,
    stats: Arc<ServerStatsInner>,
    local_addr: SocketAddr,
}

impl BoundServer {
    pub async fn bind(scenario: Scenario, config: ServerConfig) -> Result<Self, ServerError> {
        if !(1..=MAX_CONNECTIONS).contains(&config.max_connections) {
            return Err(ServerError::InvalidConnections(config.max_connections));
        }
        if !(512..=64_000).contains(&config.message_bytes) {
            return Err(ServerError::InvalidMessageBytes(config.message_bytes));
        }

        let tcp = TcpListener::bind(config.listen)
            .await
            .map_err(|source| ServerError::Bind {
                transport: "TCP",
                addr: config.listen,
                source,
            })?;
        let local_addr = tcp.local_addr()?;
        let udp = UdpSocket::bind(local_addr)
            .await
            .map_err(|source| ServerError::Bind {
                transport: "UDP",
                addr: local_addr,
                source,
            })?;

        Ok(Self {
            tcp,
            udp,
            scenario: Arc::new(scenario),
            message_bytes: config.message_bytes,
            connections: Arc::new(Semaphore::new(config.max_connections)),
            tsig_key: config.tsig_key.map(Arc::new),
            stats: Arc::new(ServerStatsInner::default()),
            local_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stats(&self) -> ServerStats {
        self.stats.snapshot()
    }

    pub async fn run_until<F>(self, shutdown: F) -> Result<ServerStats, ServerError>
    where
        F: Future<Output = ()>,
    {
        let Self {
            tcp,
            udp,
            scenario,
            message_bytes,
            connections,
            tsig_key,
            stats,
            local_addr,
        } = self;
        info!(
            event = "boron_gen_listening",
            listen = %local_addr,
            message_bytes,
            max_connections = connections.available_permits(),
            tsig = tsig_key.is_some(),
            "BoronGen synthetic primary is ready"
        );

        tokio::pin!(shutdown);
        let tcp_loop = tcp_accept_loop(
            tcp,
            scenario.clone(),
            message_bytes,
            connections,
            tsig_key.clone(),
            stats.clone(),
        );
        let udp_loop = udp_receive_loop(udp, scenario, tsig_key, stats.clone());
        tokio::pin!(tcp_loop);
        tokio::pin!(udp_loop);

        tokio::select! {
            result = &mut tcp_loop => result?,
            result = &mut udp_loop => result?,
            () = &mut shutdown => {}
        }
        let snapshot = stats.snapshot();
        info!(
            event = "boron_gen_stopped",
            queries = snapshot.queries,
            axfr_completed = snapshot.axfr_completed,
            axfr_messages = snapshot.axfr_messages,
            axfr_records = snapshot.axfr_records,
            rejected = snapshot.rejected,
            "BoronGen stopped"
        );
        Ok(snapshot)
    }
}

pub async fn serve(scenario: Scenario, config: ServerConfig) -> Result<ServerStats, ServerError> {
    BoundServer::bind(scenario, config)
        .await?
        .run_until(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}

async fn tcp_accept_loop(
    listener: TcpListener,
    scenario: Arc<Scenario>,
    message_bytes: usize,
    connections: Arc<Semaphore>,
    tsig_key: Option<Arc<TsigKey>>,
    stats: Arc<ServerStatsInner>,
) -> Result<(), ServerError> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            stats.tcp_overload_drops.fetch_add(1, Ordering::Relaxed);
            warn!(
                event = "boron_gen_tcp_overload",
                peer_ip = %peer.ip(),
                peer_port = peer.port(),
                "dropping connection at configured concurrency limit"
            );
            drop(stream);
            continue;
        };
        let scenario = scenario.clone();
        let tsig_key = tsig_key.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_tcp(
                stream,
                peer,
                &scenario,
                message_bytes,
                tsig_key.as_deref(),
                &stats,
            )
            .await
            {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                warn!(
                    event = "boron_gen_tcp_request_failed",
                    peer_ip = %peer.ip(),
                    peer_port = peer.port(),
                    error = %error,
                    "BoronGen TCP request failed"
                );
            }
        });
    }
}

async fn udp_receive_loop(
    socket: UdpSocket,
    scenario: Arc<Scenario>,
    tsig_key: Option<Arc<TsigKey>>,
    stats: Arc<ServerStatsInner>,
) -> Result<(), ServerError> {
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        let response = match prepare_query(&buffer[..length], tsig_key.as_deref()) {
            Ok(authenticated) => {
                stats.queries.fetch_add(1, Ordering::Relaxed);
                answer_single_query(
                    &scenario,
                    &authenticated.query,
                    tsig_key.as_deref(),
                    authenticated.request_mac.as_deref(),
                )
            }
            Err(error) => Err(error),
        };
        match response {
            Ok(response) => {
                socket.send_to(&response, peer).await?;
            }
            Err(error) => {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                warn!(
                    event = "boron_gen_udp_request_failed",
                    peer_ip = %peer.ip(),
                    peer_port = peer.port(),
                    error = %error,
                    "BoronGen UDP request failed"
                );
            }
        }
    }
}

async fn handle_tcp(
    mut stream: TcpStream,
    peer: SocketAddr,
    scenario: &Scenario,
    message_bytes: usize,
    tsig_key: Option<&TsigKey>,
    stats: &ServerStatsInner,
) -> Result<(), ServerError> {
    let mut length_prefix = [0u8; 2];
    stream.read_exact(&mut length_prefix).await?;
    let query_len = u16::from_be_bytes(length_prefix) as usize;
    let mut query_wire = vec![0u8; query_len];
    stream.read_exact(&mut query_wire).await?;
    let authenticated = prepare_query(&query_wire, tsig_key)?;
    stats.queries.fetch_add(1, Ordering::Relaxed);
    let query = authenticated.query;
    let request_mac = authenticated.request_mac;

    let Some(zone) = scenario.locate_zone(&query.qname) else {
        let response = sign_single_response(
            single_answer_response(&query, None, Rcode::NotAuth)?,
            tsig_key,
            request_mac.as_deref(),
        )?;
        write_tcp_message(&mut stream, &response).await?;
        return Ok(());
    };
    if query.qclass != 1 {
        let response = sign_single_response(
            single_answer_response(&query, None, Rcode::Refused)?,
            tsig_key,
            request_mac.as_deref(),
        )?;
        write_tcp_message(&mut stream, &response).await?;
        return Ok(());
    }

    match query.qtype {
        qtype if qtype == RecordType::Soa as u16 || qtype == RecordType::Ixfr as u16 => {
            let soa = scenario.soa(zone)?;
            let response = sign_single_response(
                single_answer_response(&query, Some(&soa), Rcode::NoError)?,
                tsig_key,
                request_mac.as_deref(),
            )?;
            write_tcp_message(&mut stream, &response).await?;
            stats.soa_answers.fetch_add(1, Ordering::Relaxed);
        }
        qtype if qtype == RecordType::Axfr as u16 => {
            stream_axfr(
                &mut stream,
                peer,
                scenario,
                zone,
                query,
                message_bytes,
                tsig_key,
                request_mac.as_deref(),
                stats,
            )
            .await?;
        }
        _ => {
            let response = sign_single_response(
                single_answer_response(&query, None, Rcode::NotImp)?,
                tsig_key,
                request_mac.as_deref(),
            )?;
            write_tcp_message(&mut stream, &response).await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn stream_axfr(
    stream: &mut TcpStream,
    peer: SocketAddr,
    scenario: &Scenario,
    zone: ZoneKind,
    query: ParsedQuery,
    message_bytes: usize,
    tsig_key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
    stats: &ServerStatsInner,
) -> Result<(), ServerError> {
    let expected_records = match zone {
        ZoneKind::Catalog => scenario.manifest().catalog_axfr_records,
        ZoneKind::Member(_) => scenario.manifest().member_axfr_records_each,
    };
    let mut messages = AxfrMessageStream::new(query, scenario.records(zone)?, message_bytes)?;
    let mut prior_mac = None;
    let mut message_count = 0u64;
    while let Some(message) = messages.next_message() {
        let mut message = message?;
        if let Some(key) = tsig_key {
            let signed = if let Some(prior_mac) = prior_mac.as_deref() {
                key.sign_tcp_response_continuation(
                    &message,
                    prior_mac,
                    unix_time(),
                    DEFAULT_TSIG_FUDGE_SECS,
                )?
            } else {
                key.sign_response(
                    &message,
                    request_mac.ok_or(TsigError::MissingTsig)?,
                    unix_time(),
                    DEFAULT_TSIG_FUDGE_SECS,
                )?
            };
            prior_mac = Some(signed.mac);
            message = signed.message;
        }
        write_tcp_message(stream, &message).await?;
        message_count += 1;
    }
    stats.axfr_completed.fetch_add(1, Ordering::Relaxed);
    stats
        .axfr_messages
        .fetch_add(message_count, Ordering::Relaxed);
    stats
        .axfr_records
        .fetch_add(expected_records, Ordering::Relaxed);
    info!(
        event = "boron_gen_axfr_complete",
        peer_ip = %peer.ip(),
        peer_port = peer.port(),
        ?zone,
        records = expected_records,
        messages = message_count,
        "synthetic AXFR completed"
    );
    Ok(())
}

struct AuthenticatedQuery {
    query: ParsedQuery,
    request_mac: Option<Vec<u8>>,
}

fn prepare_query(
    message: &[u8],
    tsig_key: Option<&TsigKey>,
) -> Result<AuthenticatedQuery, ServerError> {
    match tsig_key {
        Some(key) => {
            let verified = key.verify_request(message, unix_time())?;
            Ok(AuthenticatedQuery {
                query: parse_query(&verified.message)?,
                request_mac: Some(verified.mac),
            })
        }
        None => {
            if message_has_tsig(message)? {
                return Err(TsigError::KeyMismatch.into());
            }
            Ok(AuthenticatedQuery {
                query: parse_query(message)?,
                request_mac: None,
            })
        }
    }
}

fn answer_single_query(
    scenario: &Scenario,
    query: &ParsedQuery,
    tsig_key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
) -> Result<Vec<u8>, ServerError> {
    let Some(zone) = scenario.locate_zone(&query.qname) else {
        return sign_single_response(
            single_answer_response(query, None, Rcode::NotAuth)?,
            tsig_key,
            request_mac,
        );
    };
    if query.qtype != RecordType::Soa as u16 || query.qclass != 1 {
        return sign_single_response(
            single_answer_response(query, None, Rcode::Refused)?,
            tsig_key,
            request_mac,
        );
    }
    let soa = scenario.soa(zone)?;
    sign_single_response(
        single_answer_response(query, Some(&soa), Rcode::NoError)?,
        tsig_key,
        request_mac,
    )
}

fn sign_single_response(
    response: Vec<u8>,
    tsig_key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
) -> Result<Vec<u8>, ServerError> {
    let Some(key) = tsig_key else {
        return Ok(response);
    };
    Ok(key
        .sign_response(
            &response,
            request_mac.ok_or(TsigError::MissingTsig)?,
            unix_time(),
            DEFAULT_TSIG_FUDGE_SECS,
        )?
        .message)
}

async fn write_tcp_message(stream: &mut TcpStream, message: &[u8]) -> Result<(), ServerError> {
    let framed = frame_tcp_message(message).map_err(|_| ServerError::SignedFrameTooLong)?;
    stream.write_all(&framed).await?;
    Ok(())
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use borondns_core::{
        axfr::{
            IxfrResponse, build_axfr_query, build_ixfr_query_from_soa_view, parse_axfr_response,
            parse_ixfr_response,
        },
        dns::DomainName,
        tsig::TsigKey,
    };
    use tokio::sync::oneshot;

    use super::*;
    use crate::scenario::{ContentProfile, ScenarioConfig};

    fn test_key() -> TsigKey {
        TsigKey::from_base64(
            "transfer-key.",
            "hmac-sha256",
            "c2VjcmV0LWZvci1ib3Jvbi1nZW4=",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn signed_axfr_and_unchanged_ixfr_round_trip_through_production_parsers() {
        let scenario = Scenario::new(ScenarioConfig {
            profile: ContentProfile::RegistryNsec3,
            names_per_zone: 113,
            nsec3_records_per_zone: 97,
            ..ScenarioConfig::default()
        })
        .unwrap();
        let origin = scenario.zone_origin(0).unwrap();
        let server = BoundServer::bind(
            scenario,
            ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                message_bytes: 1_500,
                max_connections: 2,
                tsig_key: Some(test_key()),
            },
        )
        .await
        .unwrap();
        let address = server.local_addr();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let client_key = test_key();
        let query = client_key
            .sign_request(
                &build_axfr_query(0x5151, &origin, 1),
                unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(&frame_tcp_message(&query.message).unwrap())
            .await
            .unwrap();
        let mut messages = Vec::new();
        loop {
            let mut prefix = [0u8; 2];
            match stream.read_exact(&mut prefix).await {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => panic!("read response prefix: {error}"),
            }
            let mut message = vec![0u8; u16::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut message).await.unwrap();
            messages.push(message);
        }
        assert!(messages.len() > 1);
        let unsigned = client_key
            .verify_tcp_response_stream_owned(messages, &query.mac, unix_time())
            .unwrap();
        let snapshot = parse_axfr_response(0x5151, &origin, 1, &unsigned).unwrap();
        assert_eq!(snapshot.serial, Some(1));

        let current_soa = snapshot.soa_record_view(1).unwrap();
        let ixfr_query = client_key
            .sign_request(
                &build_ixfr_query_from_soa_view(0x5252, &origin, 1, current_soa).unwrap(),
                unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(&frame_tcp_message(&ixfr_query.message).unwrap())
            .await
            .unwrap();
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        let mut message = vec![0u8; u16::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut message).await.unwrap();
        let unsigned = client_key
            .verify_tcp_response_stream_owned(vec![message], &ixfr_query.mac, unix_time())
            .unwrap();
        let response = parse_ixfr_response(0x5252, &origin, 1, &snapshot, &unsigned).unwrap();
        assert_eq!(response, IxfrResponse::Current);

        let _ = shutdown_tx.send(());
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn unsigned_udp_soa_is_answered_for_formula_member_zone() {
        let scenario = Scenario::new(ScenarioConfig {
            zones: 3,
            ..ScenarioConfig::default()
        })
        .unwrap();
        let zone = scenario.zone_origin(2).unwrap();
        let server = BoundServer::bind(
            scenario,
            ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                message_bytes: 4_096,
                max_connections: 1,
                tsig_key: None,
            },
        )
        .await
        .unwrap();
        let address = server.local_addr();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = borondns_core::axfr::build_soa_query(9, &zone, 1);
        socket.send_to(&query, address).await.unwrap();
        let mut response = [0u8; 2_048];
        let (length, _) = socket.recv_from(&mut response).await.unwrap();
        let serial =
            borondns_core::axfr::parse_soa_response(9, &zone, 1, &response[..length]).unwrap();
        assert_eq!(serial, 1);

        let _ = shutdown_tx.send(());
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connection_limit_is_validated_before_listener_allocation() {
        let scenario = Scenario::new(ScenarioConfig::default()).unwrap();
        for max_connections in [0, MAX_CONNECTIONS + 1] {
            let result = BoundServer::bind(
                scenario.clone(),
                ServerConfig {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    message_bytes: 4_096,
                    max_connections,
                    tsig_key: None,
                },
            )
            .await;
            assert!(matches!(
                result,
                Err(ServerError::InvalidConnections(value)) if value == max_connections
            ));
        }
    }

    #[test]
    fn test_key_name_is_absolute() {
        assert_eq!(
            test_key().name,
            DomainName::from_absolute_str("transfer-key.").unwrap()
        );
    }
}
