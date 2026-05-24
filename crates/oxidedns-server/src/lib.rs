use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc},
    task::JoinSet,
};
use tracing::{debug, info, warn};
use oxidedns_core::{
    ServerConfig,
    axfr::{self, AxfrError, IxfrResponse},
    config::ZoneConfig,
    dns::{
        AnswerOptions, AnyResponseMode, DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS, DatagramAction,
        DomainName, Header, LookupResult, LookupTermination, Opcode, Question, RecordType,
        Transport, answer_message_with_notify_hooks_and_query_observer,
    },
    tsig::{DEFAULT_TSIG_FUDGE_SECS, TsigError, TsigKey},
    zone::{SoaTimers, ZoneSnapshot, ZoneState, ZoneStore},
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

    #[error("failed to bind health listener {addr}: {source}")]
    BindHealth {
        addr: std::net::SocketAddr,
        source: std::io::Error,
    },

    #[error("UDP listener failed: {0}")]
    Udp(std::io::Error),

    #[error("TCP listener failed: {0}")]
    Tcp(std::io::Error),

    #[error("health listener failed: {0}")]
    Health(std::io::Error),

    #[error("shutdown signal failed: {0}")]
    ShutdownSignal(std::io::Error),
}

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("failed to bind outbound UDP socket for primary {addr}: {source}")]
    BindUdp {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("failed to connect to TCP primary {addr}: {source}")]
    ConnectTcp {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("DNS transfer I/O with primary {addr} failed: {source}")]
    Io {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("AXFR session timed out after {timeout_secs} seconds")]
    Timeout { timeout_secs: u64 },

    #[error("AXFR response validation failed: {0}")]
    Axfr(#[from] AxfrError),

    #[error("IXFR response validation failed: {0}")]
    Ixfr(#[from] axfr::IxfrError),

    #[error("SOA poll response validation failed: {0}")]
    Soa(#[from] axfr::SoaQueryError),

    #[error("failed to generate random DNS query ID: {0}")]
    RandomQueryId(getrandom::Error),

    #[error("failed to sign transfer query with TSIG: {0}")]
    Tsig(#[from] TsigError),
}

#[derive(Debug)]
pub struct Runtime {
    config: ServerConfig,
    zones: ZoneStore,
}

const NOTIFY_REFRESH_QUEUE_CAPACITY: usize = 1024;
const ZSM_SCHEDULER_TICK: Duration = Duration::from_secs(1);
const RUNTIME_STATUS_RUNNING: u8 = 0;
const RUNTIME_STATUS_DRAINING: u8 = 1;
const RUNTIME_STATUS_UNHEALTHY: u8 = 2;

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
        self.run_with_shutdown_signal(wait_for_shutdown_signal())
            .await
    }

    async fn run_with_shutdown_signal(
        self,
        shutdown_signal: impl Future<Output = Result<&'static str, std::io::Error>>,
    ) -> Result<(), RuntimeError> {
        tokio::pin!(shutdown_signal);
        let transfer_plan = TransferPlan::from_config(&self.config);
        let refresh_registry = ZoneRefreshRegistry::new(
            Duration::from_secs(self.config.limits.zsm_min_interval_secs),
            Duration::from_secs(self.config.limits.zsm_initial_retry_secs),
            Duration::from_secs(self.config.limits.zsm_initial_retry_max_secs),
        );
        let ixfr_cooldowns = IxfrCooldownRegistry::new(Duration::from_secs(
            self.config.limits.ixfr_disabled_cooldown_secs,
        ));
        let metrics = RuntimeMetrics::new();
        let transfer_limit = Arc::new(Semaphore::new(self.config.limits.max_concurrent_transfers));

        info!(
            udp_listeners = self.config.server.listen_udp.len(),
            tcp_listeners = self.config.server.listen_tcp.len(),
            zones = self.zones.len(),
            "OxideDNS runtime initialized"
        );

        let mut listeners = JoinSet::new();
        let mut health_listeners = JoinSet::new();
        let mut refresh_workers = JoinSet::new();
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let shutdown_grace = Duration::from_secs(self.config.limits.graceful_shutdown_secs);
        let runtime_status = RuntimeStatus::new();
        let notify_authority = NotifyAuthority::from_config(&self.config);
        let notify_refresh =
            NotifyRefreshTracker::new(Duration::from_secs(self.config.limits.notify_dedup_secs));
        let (notify_refresh_tx, notify_refresh_rx) = mpsc::channel(NOTIFY_REFRESH_QUEUE_CAPACITY);
        refresh_workers.spawn(run_initial_zone_loads(
            self.zones.clone(),
            self.config.zones.clone(),
            transfer_plan.clone(),
            refresh_registry.clone(),
            ixfr_cooldowns.clone(),
            metrics.clone(),
            InitialLoadSettings {
                axfr_timeout: Duration::from_secs(self.config.limits.axfr_timeout_secs),
                ixfr_timeout: Duration::from_secs(self.config.limits.ixfr_timeout_secs),
                transfer_limit: transfer_limit.clone(),
            },
        ));
        refresh_workers.spawn(serve_refresh_requests(
            notify_refresh_rx,
            self.zones.clone(),
            transfer_plan.clone(),
            refresh_registry.clone(),
            ixfr_cooldowns.clone(),
            metrics.clone(),
            RefreshWorkerSettings {
                axfr_timeout: Duration::from_secs(self.config.limits.axfr_timeout_secs),
                ixfr_timeout: Duration::from_secs(self.config.limits.ixfr_timeout_secs),
                transfer_limit: transfer_limit.clone(),
            },
        ));
        listeners.spawn(serve_scheduled_refreshes(
            self.zones.clone(),
            refresh_registry.clone(),
            notify_refresh_tx.clone(),
            ZSM_SCHEDULER_TICK,
        ));
        if let Some(addr) = self.config.server.health {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|source| RuntimeError::BindHealth { addr, source })?;
            health_listeners.spawn(serve_health(
                listener,
                HealthEndpointState {
                    zones: self.zones.clone(),
                    runtime_status: runtime_status.clone(),
                    metrics: metrics.clone(),
                    refresh_registry: refresh_registry.clone(),
                },
            ));
        }
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
            let notify_authority = notify_authority.clone();
            let notify_refresh = notify_refresh.clone();
            let notify_refresh_tx = notify_refresh_tx.clone();
            let metrics = metrics.clone();
            let udp_settings = UdpServerSettings {
                max_udp_payload,
                max_cname_chain,
                edns_padding_block_size,
                any_response,
                notify_authority,
                notify_refresh,
                notify_refresh_tx,
                metrics,
            };
            listeners.spawn(async move { serve_udp(socket, zones, udp_settings).await });
        }
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
                notify_authority: notify_authority.clone(),
                notify_refresh: notify_refresh.clone(),
                notify_refresh_tx: notify_refresh_tx.clone(),
                metrics: metrics.clone(),
                active_connections: tcp_connections,
            };
            listeners.spawn(async move { serve_tcp(listener, zones, tcp_settings).await });
        }

        loop {
            tokio::select! {
                signal = &mut shutdown_signal => {
                    let signal = signal.map_err(RuntimeError::ShutdownSignal)?;
                    info!(
                        signal,
                        grace_secs = shutdown_grace.as_secs(),
                        active_tcp_connections = tcp_connections.load(Ordering::Acquire),
                        "shutdown signal received; draining runtime"
                    );
                    runtime_status.mark_draining();
                    abort_task_set(&mut listeners, "listener").await;
                    drop(notify_refresh_tx);
                    let (tcp_drained, refresh_drained) = tokio::join!(
                        drain_tcp_connections(
                            tcp_connections.clone(),
                            shutdown_grace,
                            Duration::from_millis(50),
                        ),
                        drain_task_set(&mut refresh_workers, shutdown_grace, "refresh transfer")
                    );
                    if tcp_drained {
                        info!("TCP connection drain completed");
                    } else {
                        warn!(
                            active_tcp_connections = tcp_connections.load(Ordering::Acquire),
                            "shutdown grace period elapsed with active TCP connections"
                        );
                    }
                    if refresh_drained {
                        info!("refresh transfer drain completed");
                    } else {
                        warn!("shutdown grace period elapsed with active refresh transfers");
                    }
                    abort_task_set(&mut health_listeners, "health listener").await;
                    break;
                }
                result = listeners.join_next(), if !listeners.is_empty() => {
                    handle_runtime_task_result("listener", result)?;
                }
                result = refresh_workers.join_next(), if !refresh_workers.is_empty() => {
                    handle_runtime_task_result("refresh transfer", result)?;
                }
                result = health_listeners.join_next(), if !health_listeners.is_empty() => {
                    handle_runtime_task_result("health listener", result)?;
                }
            }

            if listeners.is_empty() && refresh_workers.is_empty() && health_listeners.is_empty() {
                break;
            }
        }

        Ok(())
    }

    #[cfg(test)]
    async fn load_initial_zones(
        &self,
        transfer_plan: &TransferPlan,
        refresh_registry: &ZoneRefreshRegistry,
        ixfr_cooldowns: &IxfrCooldownRegistry,
        max_concurrent_transfers: usize,
        metrics: &RuntimeMetrics,
    ) {
        run_initial_zone_loads(
            self.zones.clone(),
            self.config.zones.clone(),
            transfer_plan.clone(),
            refresh_registry.clone(),
            ixfr_cooldowns.clone(),
            metrics.clone(),
            InitialLoadSettings {
                axfr_timeout: Duration::from_secs(self.config.limits.axfr_timeout_secs),
                ixfr_timeout: Duration::from_secs(self.config.limits.ixfr_timeout_secs),
                transfer_limit: Arc::new(Semaphore::new(max_concurrent_transfers)),
            },
        )
        .await
        .expect("initial zone load worker does not return runtime errors");
    }
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<&'static str, std::io::Error> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result?;
            Ok("SIGINT")
        }
        _ = terminate.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> Result<&'static str, std::io::Error> {
    tokio::signal::ctrl_c().await?;
    Ok("SIGINT")
}

fn handle_runtime_task_result(
    task_set: &'static str,
    result: Option<Result<Result<(), RuntimeError>, tokio::task::JoinError>>,
) -> Result<(), RuntimeError> {
    match result {
        Some(Ok(Ok(()))) | None => Ok(()),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(error)) => {
            warn!(%error, task_set, "runtime task failed");
            Ok(())
        }
    }
}

async fn abort_task_set(tasks: &mut JoinSet<Result<(), RuntimeError>>, task_set: &'static str) {
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!(%error, task_set, "runtime task returned error during shutdown");
            }
            Err(error) if error.is_cancelled() => {
                debug!(task_set, "runtime task cancelled during shutdown");
            }
            Err(error) => {
                warn!(%error, task_set, "runtime task failed during shutdown");
            }
        }
    }
}

async fn drain_task_set(
    tasks: &mut JoinSet<Result<(), RuntimeError>>,
    grace: Duration,
    task_set: &'static str,
) -> bool {
    if tasks.is_empty() {
        return true;
    }

    let drained = tokio::time::timeout(grace, async {
        let mut clean = true;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    clean = false;
                    warn!(%error, task_set, "runtime task returned error while draining");
                }
                Err(error) => {
                    clean = false;
                    warn!(%error, task_set, "runtime task failed while draining");
                }
            }
        }
        clean
    })
    .await;

    match drained {
        Ok(clean) => clean,
        Err(_) => {
            tasks.abort_all();
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        warn!(%error, task_set, "runtime task returned error after drain timeout");
                    }
                    Err(error) if error.is_cancelled() => {
                        debug!(task_set, "runtime task cancelled after drain timeout");
                    }
                    Err(error) => {
                        warn!(%error, task_set, "runtime task failed after drain timeout");
                    }
                }
            }
            false
        }
    }
}

async fn drain_tcp_connections(
    active_connections: Arc<AtomicUsize>,
    grace: Duration,
    poll_interval: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        if active_connections.load(Ordering::Acquire) == 0 {
            return true;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::time::sleep(poll_interval.min(remaining)).await;
    }
}

pub async fn transfer_axfr_from_primary(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    timeout_duration: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    transfer_axfr_from_primary_with_tsig(primary, zone_apex, qclass, qid, None, timeout_duration)
        .await
}

async fn transfer_axfr_from_primary_with_tsig(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    tsig_key: Option<&TsigKey>,
    timeout_duration: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    tokio::time::timeout(timeout_duration, async {
        transfer_axfr_from_primary_inner(primary, zone_apex, qclass, qid, tsig_key).await
    })
    .await
    .map_err(|_| TransferError::Timeout {
        timeout_secs: timeout_duration.as_secs(),
    })?
}

pub async fn poll_soa_from_primary(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    timeout_duration: Duration,
) -> Result<u32, TransferError> {
    poll_soa_from_primary_with_tsig(primary, zone_apex, qclass, qid, None, timeout_duration).await
}

async fn poll_soa_from_primary_with_tsig(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    tsig_key: Option<&TsigKey>,
    timeout_duration: Duration,
) -> Result<u32, TransferError> {
    tokio::time::timeout(timeout_duration, async {
        poll_soa_from_primary_inner(primary, zone_apex, qclass, qid, tsig_key).await
    })
    .await
    .map_err(|_| TransferError::Timeout {
        timeout_secs: timeout_duration.as_secs(),
    })?
}

async fn poll_soa_from_primary_inner(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    tsig_key: Option<&TsigKey>,
) -> Result<u32, TransferError> {
    let socket = UdpSocket::bind(outbound_udp_bind_addr(primary))
        .await
        .map_err(|source| TransferError::BindUdp {
            addr: primary,
            source,
        })?;
    socket
        .connect(primary)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary,
            source,
        })?;

    let query = maybe_sign_transfer_query(axfr::build_soa_query(qid, zone_apex, qclass), tsig_key)?;
    socket
        .send(&query.message)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary,
            source,
        })?;

    let mut buffer = vec![0u8; 512];
    let len = socket
        .recv(&mut buffer)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary,
            source,
        })?;

    let response =
        maybe_verify_transfer_response(&buffer[..len], tsig_key, query.request_mac.as_deref())?;
    axfr::parse_soa_response(qid, zone_apex, qclass, &response).map_err(TransferError::Soa)
}

pub async fn transfer_ixfr_from_primary(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    current_zone: &ZoneSnapshot,
    timeout_duration: Duration,
) -> Result<IxfrResponse, TransferError> {
    transfer_ixfr_from_primary_with_tsig(
        primary,
        zone_apex,
        qclass,
        qid,
        current_zone,
        None,
        timeout_duration,
    )
    .await
}

async fn transfer_ixfr_from_primary_with_tsig(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    current_zone: &ZoneSnapshot,
    tsig_key: Option<&TsigKey>,
    timeout_duration: Duration,
) -> Result<IxfrResponse, TransferError> {
    tokio::time::timeout(timeout_duration, async {
        transfer_ixfr_from_primary_inner(primary, zone_apex, qclass, qid, current_zone, tsig_key)
            .await
    })
    .await
    .map_err(|_| TransferError::Timeout {
        timeout_secs: timeout_duration.as_secs(),
    })?
}

async fn transfer_ixfr_from_primary_inner(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    current_zone: &ZoneSnapshot,
    tsig_key: Option<&TsigKey>,
) -> Result<IxfrResponse, TransferError> {
    let mut stream =
        TcpStream::connect(primary)
            .await
            .map_err(|source| TransferError::ConnectTcp {
                addr: primary,
                source,
            })?;

    let current_soa = current_zone
        .soa_record(qclass)
        .ok_or(axfr::IxfrError::InvalidCurrentSoa)?;
    let query = maybe_sign_transfer_query(
        axfr::build_ixfr_query(qid, zone_apex, qclass, &current_soa)?,
        tsig_key,
    )?;
    let framed_query = axfr::frame_tcp_message(&query.message);
    stream
        .write_all(&framed_query)
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
                let verified_messages = maybe_verify_tcp_transfer_messages(
                    &messages,
                    tsig_key,
                    query.request_mac.as_deref(),
                )?;
                return axfr::parse_ixfr_response(
                    qid,
                    zone_apex,
                    qclass,
                    current_zone,
                    &verified_messages,
                )
                .map_err(TransferError::Ixfr);
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
                TransferError::Ixfr(axfr::IxfrError::IncompleteResponse)
            } else {
                TransferError::Io {
                    addr: primary,
                    source,
                }
            }
        })?;
        messages.push(message);

        match axfr::parse_ixfr_response(qid, zone_apex, qclass, current_zone, &messages) {
            Ok(_) => {
                match maybe_verify_tcp_transfer_messages(
                    &messages,
                    tsig_key,
                    query.request_mac.as_deref(),
                ) {
                    Ok(verified_messages) => {
                        return axfr::parse_ixfr_response(
                            qid,
                            zone_apex,
                            qclass,
                            current_zone,
                            &verified_messages,
                        )
                        .map_err(TransferError::Ixfr);
                    }
                    Err(TransferError::Tsig(TsigError::MissingTerminalTsig)) => {}
                    Err(error) => return Err(error),
                }
            }
            Err(axfr::IxfrError::IncompleteResponse)
            | Err(axfr::IxfrError::Axfr(AxfrError::MissingTerminatingSoa)) => {}
            Err(error) => return Err(TransferError::Ixfr(error)),
        }
    }
}

fn outbound_udp_bind_addr(primary: SocketAddr) -> SocketAddr {
    match primary {
        SocketAddr::V4(_) => "0.0.0.0:0"
            .parse()
            .expect("hard-coded IPv4 wildcard socket address is valid"),
        SocketAddr::V6(_) => "[::]:0"
            .parse()
            .expect("hard-coded IPv6 wildcard socket address is valid"),
    }
}

struct TransferQuery {
    message: Vec<u8>,
    request_mac: Option<Vec<u8>>,
}

fn maybe_sign_transfer_query(
    query: Vec<u8>,
    tsig_key: Option<&TsigKey>,
) -> Result<TransferQuery, TransferError> {
    let Some(tsig_key) = tsig_key else {
        return Ok(TransferQuery {
            message: query,
            request_mac: None,
        });
    };

    let signed = tsig_key.sign_request(&query, tsig_time_signed(), DEFAULT_TSIG_FUDGE_SECS)?;
    Ok(TransferQuery {
        message: signed.message,
        request_mac: Some(signed.mac),
    })
}

fn maybe_verify_transfer_response(
    message: &[u8],
    tsig_key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
) -> Result<Vec<u8>, TransferError> {
    let (Some(tsig_key), Some(request_mac)) = (tsig_key, request_mac) else {
        return Ok(message.to_vec());
    };

    let verified = tsig_key.verify_response(message, request_mac, tsig_time_signed())?;
    Ok(verified.message)
}

fn maybe_verify_tcp_transfer_messages(
    messages: &[Vec<u8>],
    tsig_key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>, TransferError> {
    let (Some(tsig_key), Some(request_mac)) = (tsig_key, request_mac) else {
        return Ok(messages.to_vec());
    };

    tsig_key
        .verify_tcp_response_stream(messages, request_mac, tsig_time_signed())
        .map_err(TransferError::Tsig)
}

fn tsig_time_signed() -> u64 {
    unix_timestamp_seconds()
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn transfer_axfr_from_primary_inner(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    tsig_key: Option<&TsigKey>,
) -> Result<ZoneSnapshot, TransferError> {
    let mut stream =
        TcpStream::connect(primary)
            .await
            .map_err(|source| TransferError::ConnectTcp {
                addr: primary,
                source,
            })?;

    let query =
        maybe_sign_transfer_query(axfr::build_axfr_query(qid, zone_apex, qclass), tsig_key)?;
    let framed_query = axfr::frame_tcp_message(&query.message);
    stream
        .write_all(&framed_query)
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
                let verified_messages = maybe_verify_tcp_transfer_messages(
                    &messages,
                    tsig_key,
                    query.request_mac.as_deref(),
                )?;
                return axfr::parse_axfr_response(qid, zone_apex, qclass, &verified_messages)
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
            Ok(_) => {
                match maybe_verify_tcp_transfer_messages(
                    &messages,
                    tsig_key,
                    query.request_mac.as_deref(),
                ) {
                    Ok(verified_messages) => {
                        return axfr::parse_axfr_response(
                            qid,
                            zone_apex,
                            qclass,
                            &verified_messages,
                        )
                        .map_err(TransferError::Axfr);
                    }
                    Err(TransferError::Tsig(TsigError::MissingTerminalTsig)) => {}
                    Err(error) => return Err(error),
                }
            }
            Err(AxfrError::MissingTerminatingSoa) => {}
            Err(error) => return Err(TransferError::Axfr(error)),
        }
    }
}

fn transfer_query_id() -> Result<u16, TransferError> {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).map_err(TransferError::RandomQueryId)?;
    Ok(query_id_from_random_bytes(bytes))
}

fn query_id_from_random_bytes(bytes: [u8; 2]) -> u16 {
    u16::from_be_bytes(bytes)
}

async fn serve_udp(
    socket: UdpSocket,
    zones: ZoneStore,
    settings: UdpServerSettings,
) -> Result<(), RuntimeError> {
    let local_addr = socket.local_addr().map_err(RuntimeError::Udp)?;
    info!(%local_addr, "UDP listener bound");

    let mut buffer = vec![0u8; 4096];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buffer)
            .await
            .map_err(RuntimeError::Udp)?;
        let peer_ip = peer.ip();
        let Some(prepared) =
            prepare_notify_packet(&buffer[..len], &settings.notify_authority, peer_ip)
        else {
            debug!(%peer, bytes = len, "discarded DNS datagram");
            continue;
        };
        let query_metrics = observe_query_metrics(&prepared.packet, &zones, &settings.metrics);
        match answer_message_with_notify_hooks_and_query_observer(
            &prepared.packet,
            &zones,
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: settings.max_udp_payload,
                max_cname_chain: settings.max_cname_chain,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: settings.edns_padding_block_size,
                any_response: settings.any_response,
            },
            |qname, qclass| {
                let authorized = settings
                    .notify_authority
                    .is_authorized(qname, qclass, peer_ip);
                if !authorized {
                    warn!(%peer_ip, zone = %qname, "unauthorized NOTIFY discarded");
                }
                authorized
            },
            |qname, _qclass, serial| {
                signal_notify_refresh(
                    &settings.notify_refresh,
                    &settings.notify_refresh_tx,
                    qname,
                    peer_ip,
                    serial,
                )
            },
            |lookup| {
                record_query_termination_metric(query_metrics, lookup, &settings.metrics);
            },
        ) {
            DatagramAction::Discard => {
                debug!(%peer, bytes = len, "discarded DNS datagram");
            }
            DatagramAction::Respond(response) => {
                record_query_response_metric(query_metrics, &response, &settings.metrics);
                let response = match sign_notify_response(response, prepared.response_tsig) {
                    Ok(response) => response,
                    Err(error) => {
                        warn!(%peer, %error, "failed to sign NOTIFY response");
                        continue;
                    }
                };
                socket
                    .send_to(&response, peer)
                    .await
                    .map_err(RuntimeError::Udp)?;
            }
        }
    }
}

#[derive(Clone, Copy)]
struct QueryMetricObservation {
    is_query: bool,
}

fn observe_query_metrics(
    packet: &[u8],
    zones: &ZoneStore,
    metrics: &RuntimeMetrics,
) -> QueryMetricObservation {
    let Ok(header) = Header::parse(packet) else {
        return QueryMetricObservation { is_query: false };
    };
    if header.is_response() || header.opcode() != Some(Opcode::Query) {
        return QueryMetricObservation { is_query: false };
    }

    metrics.record_query_received();
    if header.qdcount != 1 {
        return QueryMetricObservation { is_query: true };
    }
    let Ok(question) = Question::parse(packet) else {
        return QueryMetricObservation { is_query: true };
    };
    if let Some(zone) = zones.find_zone(&question.qname) {
        metrics.record_zone_query(&zone.origin);
    }
    QueryMetricObservation { is_query: true }
}

fn record_query_response_metric(
    observation: QueryMetricObservation,
    response: &[u8],
    metrics: &RuntimeMetrics,
) {
    if !observation.is_query {
        return;
    }
    let Ok(header) = Header::parse(response) else {
        return;
    };
    if header.flags & 0x0200 != 0 {
        metrics.record_query_truncated();
    }
    metrics.record_query_response_rcode(response_rcode(response, &header));
}

fn record_query_termination_metric(
    observation: QueryMetricObservation,
    lookup: &LookupResult,
    metrics: &RuntimeMetrics,
) {
    if !observation.is_query {
        return;
    }
    match lookup.termination {
        Some(LookupTermination::CnameChainLimit) => metrics.record_query_cname_chain_limit(),
        Some(LookupTermination::CnameLoop) => metrics.record_query_cname_loop(),
        None => {}
    }
}

fn response_rcode(response: &[u8], header: &Header) -> u16 {
    let base_rcode = header.flags & 0x000f;
    base_rcode | response_extended_rcode(response, header).unwrap_or_default()
}

fn response_extended_rcode(response: &[u8], header: &Header) -> Option<u16> {
    let mut offset = 12;
    for _ in 0..header.qdcount {
        let (_, consumed) = DomainName::parse(response, offset).ok()?;
        offset = offset.checked_add(consumed)?.checked_add(4)?;
        if offset > response.len() {
            return None;
        }
    }
    for count in [header.ancount, header.nscount] {
        for _ in 0..count {
            offset = skip_response_record(response, offset)?;
        }
    }
    for _ in 0..header.arcount {
        let (_, consumed) = DomainName::parse(response, offset).ok()?;
        offset = offset.checked_add(consumed)?;
        if offset + 10 > response.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let ttl = u32::from_be_bytes([
            response[offset + 4],
            response[offset + 5],
            response[offset + 6],
            response[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset = offset.checked_add(10)?.checked_add(rdlength)?;
        if offset > response.len() {
            return None;
        }
        if rr_type == RecordType::Opt as u16 {
            return Some(((ttl >> 24) as u16) << 4);
        }
    }
    None
}

fn skip_response_record(response: &[u8], offset: usize) -> Option<usize> {
    let (_, consumed) = DomainName::parse(response, offset).ok()?;
    let offset = offset.checked_add(consumed)?;
    if offset + 10 > response.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
    let offset = offset.checked_add(10)?.checked_add(rdlength)?;
    (offset <= response.len()).then_some(offset)
}

#[derive(Clone)]
struct UdpServerSettings {
    max_udp_payload: u16,
    max_cname_chain: usize,
    edns_padding_block_size: u16,
    any_response: AnyResponseMode,
    notify_authority: NotifyAuthority,
    notify_refresh: NotifyRefreshTracker,
    notify_refresh_tx: mpsc::Sender<RefreshRequest>,
    metrics: RuntimeMetrics,
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
                settings.notify_authority,
                settings.notify_refresh,
                settings.notify_refresh_tx,
                settings.metrics,
                peer.ip(),
            )
            .await
            {
                warn!(%peer, %error, "TCP connection failed");
            }
        });
    }
}

async fn serve_health(
    listener: TcpListener,
    state: HealthEndpointState,
) -> Result<(), RuntimeError> {
    let local_addr = listener.local_addr().map_err(RuntimeError::Health)?;
    info!(%local_addr, "health listener bound");

    axum::serve(listener, health_router(state))
        .await
        .map_err(RuntimeError::Health)
}

fn health_router(state: HealthEndpointState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn healthz(State(state): State<HealthEndpointState>) -> Response {
    match state.runtime_status.status() {
        RuntimeStatusValue::Running if state.zones.has_active_zone() => {
            plain_text(StatusCode::OK, "ready\n")
        }
        RuntimeStatusValue::Running => plain_text(StatusCode::SERVICE_UNAVAILABLE, "starting\n"),
        RuntimeStatusValue::Draining => plain_text(StatusCode::SERVICE_UNAVAILABLE, "draining\n"),
        RuntimeStatusValue::Unhealthy => plain_text(StatusCode::SERVICE_UNAVAILABLE, "unhealthy\n"),
    }
}

async fn readyz(State(state): State<HealthEndpointState>) -> Response {
    if state.runtime_status.is_running() && state.zones.has_active_zone() {
        plain_text(StatusCode::OK, "ready\n")
    } else {
        plain_text(StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

async fn metrics(State(state): State<HealthEndpointState>) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics_body(&state.zones, &state.metrics, &state.refresh_registry),
    )
        .into_response()
}

fn metrics_body(
    zones: &ZoneStore,
    metrics: &RuntimeMetrics,
    refresh_registry: &ZoneRefreshRegistry,
) -> String {
    let snapshot = metrics.snapshot();
    let mut body = format!(
        "# HELP oxidedns_zones_total Configured zones.\n\
         # TYPE oxidedns_zones_total gauge\n\
         oxidedns_zones_total {}\n\
         # HELP oxidedns_zones_active Active zones.\n\
         # TYPE oxidedns_zones_active gauge\n\
         oxidedns_zones_active {}\n\
         # HELP oxidedns_queries_received_total Query messages received.\n\
         # TYPE oxidedns_queries_received_total counter\n\
         oxidedns_queries_received_total {}\n\
         # HELP oxidedns_queries_truncated_total Query responses emitted with the TC bit set.\n\
         # TYPE oxidedns_queries_truncated_total counter\n\
         oxidedns_queries_truncated_total {}\n\
         # HELP oxidedns_queries_cname_chain_limit_total Query responses terminated by the CNAME chain limit.\n\
         # TYPE oxidedns_queries_cname_chain_limit_total counter\n\
         oxidedns_queries_cname_chain_limit_total {}\n\
         # HELP oxidedns_queries_cname_loop_total Query responses terminated by CNAME loop detection.\n\
         # TYPE oxidedns_queries_cname_loop_total counter\n\
         oxidedns_queries_cname_loop_total {}\n\
         # HELP oxidedns_transfer_sessions_started_total Transfer sessions started.\n\
         # TYPE oxidedns_transfer_sessions_started_total counter\n\
         oxidedns_transfer_sessions_started_total{{protocol=\"axfr\"}} {}\n\
         oxidedns_transfer_sessions_started_total{{protocol=\"ixfr\"}} {}\n\
         # HELP oxidedns_transfer_sessions_completed_total Transfer sessions completed successfully.\n\
         # TYPE oxidedns_transfer_sessions_completed_total counter\n\
         oxidedns_transfer_sessions_completed_total{{protocol=\"axfr\"}} {}\n\
         oxidedns_transfer_sessions_completed_total{{protocol=\"ixfr\"}} {}\n\
         # HELP oxidedns_transfer_sessions_failed_total Transfer sessions failed.\n\
         # TYPE oxidedns_transfer_sessions_failed_total counter\n\
         oxidedns_transfer_sessions_failed_total{{protocol=\"axfr\"}} {}\n\
         oxidedns_transfer_sessions_failed_total{{protocol=\"ixfr\"}} {}\n",
        zones.len(),
        zones.active_count(),
        snapshot.queries_received,
        snapshot.queries_truncated,
        snapshot.queries_cname_chain_limit,
        snapshot.queries_cname_loop,
        snapshot.axfr_started,
        snapshot.ixfr_started,
        snapshot.axfr_succeeded,
        snapshot.ixfr_succeeded,
        snapshot.axfr_failed,
        snapshot.ixfr_failed,
    );
    append_query_rcode_metrics(&mut body, metrics);
    append_zone_status_metrics(&mut body, zones);
    append_zone_scheduler_metrics(&mut body, zones, refresh_registry);
    append_zone_query_metrics(&mut body, zones, metrics);
    body
}

fn append_query_rcode_metrics(body: &mut String, metrics: &RuntimeMetrics) {
    let rcode_counts = metrics.query_rcode_counts();
    body.push_str(
        "# HELP oxidedns_query_responses_total Query responses by DNS RCODE.\n\
         # TYPE oxidedns_query_responses_total counter\n",
    );
    for rcode in known_rcodes() {
        let count = rcode_counts.get(rcode).copied().unwrap_or_default();
        body.push_str(&format!(
            "oxidedns_query_responses_total{{rcode=\"{}\"}} {count}\n",
            rcode_label(*rcode)
        ));
    }

    let mut other_rcodes = rcode_counts
        .keys()
        .copied()
        .filter(|rcode| !known_rcodes().contains(rcode))
        .collect::<Vec<_>>();
    other_rcodes.sort_unstable();
    for rcode in other_rcodes {
        let count = rcode_counts.get(&rcode).copied().unwrap_or_default();
        body.push_str(&format!(
            "oxidedns_query_responses_total{{rcode=\"{rcode}\"}} {count}\n"
        ));
    }
}

fn known_rcodes() -> &'static [u16] {
    &[0, 1, 2, 3, 4, 5, 9, 16, 22]
}

fn rcode_label(rcode: u16) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        9 => "NOTAUTH",
        16 => "BADVERS",
        22 => "BADTRUNC",
        _ => "UNKNOWN",
    }
}

fn append_zone_status_metrics(body: &mut String, zones: &ZoneStore) {
    body.push_str(
        "# HELP oxidedns_zone_state Zone state, exposed as 1 for the current state and 0 for other states.\n\
         # TYPE oxidedns_zone_state gauge\n",
    );
    for snapshot in zones.snapshots() {
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        for (state, value) in zone_state_samples(snapshot.state) {
            body.push_str(&format!(
                "oxidedns_zone_state{{zone=\"{zone}\",state=\"{state}\"}} {value}\n"
            ));
        }
    }

    body.push_str(
        "# HELP oxidedns_zone_soa_serial Current held SOA serial for zones with transferred data.\n\
         # TYPE oxidedns_zone_soa_serial gauge\n",
    );
    for snapshot in zones.snapshots() {
        if let Some(serial) = snapshot.serial {
            let zone = prometheus_label_value(&snapshot.origin.to_string());
            body.push_str(&format!(
                "oxidedns_zone_soa_serial{{zone=\"{zone}\"}} {serial}\n"
            ));
        }
    }
}

fn append_zone_scheduler_metrics(
    body: &mut String,
    zones: &ZoneStore,
    refresh_registry: &ZoneRefreshRegistry,
) {
    let statuses = refresh_registry.snapshots_by_zone();

    body.push_str(
        "# HELP oxidedns_zone_last_success_timestamp_seconds Unix timestamp of the most recent successful refresh or transfer.\n\
         # TYPE oxidedns_zone_last_success_timestamp_seconds gauge\n",
    );
    for snapshot in zones.snapshots() {
        let Some(status) = statuses.get(&snapshot.origin.canonical_key()) else {
            continue;
        };
        let Some(last_success) = status.last_success_unix_secs else {
            continue;
        };
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        body.push_str(&format!(
            "oxidedns_zone_last_success_timestamp_seconds{{zone=\"{zone}\"}} {last_success}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_zone_next_refresh_timestamp_seconds Unix timestamp of the next scheduled refresh attempt.\n\
         # TYPE oxidedns_zone_next_refresh_timestamp_seconds gauge\n",
    );
    for snapshot in zones.snapshots() {
        let Some(status) = statuses.get(&snapshot.origin.canonical_key()) else {
            continue;
        };
        let Some(next_refresh) = status.next_refresh_unix_secs else {
            continue;
        };
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        body.push_str(&format!(
            "oxidedns_zone_next_refresh_timestamp_seconds{{zone=\"{zone}\"}} {next_refresh}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_zone_refresh_failures_since_success Refresh failures since the most recent successful refresh or transfer.\n\
         # TYPE oxidedns_zone_refresh_failures_since_success gauge\n",
    );
    for snapshot in zones.snapshots() {
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        let failures = statuses
            .get(&snapshot.origin.canonical_key())
            .map_or(0, |status| status.failures_since_success);
        body.push_str(&format!(
            "oxidedns_zone_refresh_failures_since_success{{zone=\"{zone}\"}} {failures}\n"
        ));
    }
}

fn append_zone_query_metrics(body: &mut String, zones: &ZoneStore, metrics: &RuntimeMetrics) {
    let query_counts = metrics.zone_query_counts();
    body.push_str(
        "# HELP oxidedns_zone_queries_total Queries received for each configured zone.\n\
         # TYPE oxidedns_zone_queries_total counter\n",
    );
    for snapshot in zones.snapshots() {
        let zone_key = snapshot.origin.canonical_key();
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        let count = query_counts.get(&zone_key).copied().unwrap_or_default();
        body.push_str(&format!(
            "oxidedns_zone_queries_total{{zone=\"{zone}\"}} {count}\n"
        ));
    }
}

fn zone_state_samples(state: ZoneState) -> [(&'static str, u8); 3] {
    [
        ("loading", u8::from(state == ZoneState::Loading)),
        ("active", u8::from(state == ZoneState::Active)),
        ("expired", u8::from(state == ZoneState::Expired)),
    ]
}

fn prometheus_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn plain_text(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

#[derive(Clone)]
struct HealthEndpointState {
    zones: ZoneStore,
    runtime_status: RuntimeStatus,
    metrics: RuntimeMetrics,
    refresh_registry: ZoneRefreshRegistry,
}

#[derive(Clone, Debug)]
struct RuntimeStatus {
    value: Arc<AtomicU8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeStatusValue {
    Running,
    Draining,
    Unhealthy,
}

impl RuntimeStatus {
    fn new() -> Self {
        Self {
            value: Arc::new(AtomicU8::new(RUNTIME_STATUS_RUNNING)),
        }
    }

    fn mark_draining(&self) {
        self.value.store(RUNTIME_STATUS_DRAINING, Ordering::Release);
    }

    #[cfg(test)]
    fn mark_unhealthy(&self) {
        self.value
            .store(RUNTIME_STATUS_UNHEALTHY, Ordering::Release);
    }

    fn is_running(&self) -> bool {
        self.status() == RuntimeStatusValue::Running
    }

    fn status(&self) -> RuntimeStatusValue {
        match self.value.load(Ordering::Acquire) {
            RUNTIME_STATUS_RUNNING => RuntimeStatusValue::Running,
            RUNTIME_STATUS_DRAINING => RuntimeStatusValue::Draining,
            RUNTIME_STATUS_UNHEALTHY => RuntimeStatusValue::Unhealthy,
            _ => RuntimeStatusValue::Unhealthy,
        }
    }
}

#[derive(Clone, Debug)]
struct RuntimeMetrics {
    inner: Arc<RuntimeMetricsInner>,
}

#[derive(Debug, Default)]
struct RuntimeMetricsInner {
    queries_received: AtomicU64,
    queries_truncated: AtomicU64,
    queries_cname_chain_limit: AtomicU64,
    queries_cname_loop: AtomicU64,
    axfr_started: AtomicU64,
    axfr_succeeded: AtomicU64,
    axfr_failed: AtomicU64,
    ixfr_started: AtomicU64,
    ixfr_succeeded: AtomicU64,
    ixfr_failed: AtomicU64,
    query_rcodes: Mutex<HashMap<u16, u64>>,
    zone_queries: Mutex<HashMap<String, u64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeMetricsSnapshot {
    queries_received: u64,
    queries_truncated: u64,
    queries_cname_chain_limit: u64,
    queries_cname_loop: u64,
    axfr_started: u64,
    axfr_succeeded: u64,
    axfr_failed: u64,
    ixfr_started: u64,
    ixfr_succeeded: u64,
    ixfr_failed: u64,
}

impl RuntimeMetrics {
    fn new() -> Self {
        Self {
            inner: Arc::new(RuntimeMetricsInner::default()),
        }
    }

    fn record_axfr_started(&self) {
        self.inner.axfr_started.fetch_add(1, Ordering::Relaxed);
    }

    fn record_axfr_succeeded(&self) {
        self.inner.axfr_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    fn record_axfr_failed(&self) {
        self.inner.axfr_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn record_ixfr_started(&self) {
        self.inner.ixfr_started.fetch_add(1, Ordering::Relaxed);
    }

    fn record_ixfr_succeeded(&self) {
        self.inner.ixfr_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    fn record_ixfr_failed(&self) {
        self.inner.ixfr_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn record_query_received(&self) {
        self.inner.queries_received.fetch_add(1, Ordering::Relaxed);
    }

    fn record_query_truncated(&self) {
        self.inner.queries_truncated.fetch_add(1, Ordering::Relaxed);
    }

    fn record_query_cname_chain_limit(&self) {
        self.inner
            .queries_cname_chain_limit
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_query_cname_loop(&self) {
        self.inner
            .queries_cname_loop
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_query_response_rcode(&self, rcode: u16) {
        let mut rcodes = self
            .inner
            .query_rcodes
            .lock()
            .expect("runtime metrics RCODE counter lock poisoned");
        let counter = rcodes.entry(rcode).or_default();
        *counter = counter.saturating_add(1);
    }

    fn query_rcode_counts(&self) -> HashMap<u16, u64> {
        self.inner
            .query_rcodes
            .lock()
            .expect("runtime metrics RCODE counter lock poisoned")
            .clone()
    }

    fn record_zone_query(&self, zone: &DomainName) {
        let mut query_counts = self
            .inner
            .zone_queries
            .lock()
            .expect("runtime metrics query counter lock poisoned");
        let counter = query_counts.entry(zone.canonical_key()).or_default();
        *counter = counter.saturating_add(1);
    }

    fn zone_query_counts(&self) -> HashMap<String, u64> {
        self.inner
            .zone_queries
            .lock()
            .expect("runtime metrics query counter lock poisoned")
            .clone()
    }

    fn snapshot(&self) -> RuntimeMetricsSnapshot {
        RuntimeMetricsSnapshot {
            queries_received: self.inner.queries_received.load(Ordering::Relaxed),
            queries_truncated: self.inner.queries_truncated.load(Ordering::Relaxed),
            queries_cname_chain_limit: self.inner.queries_cname_chain_limit.load(Ordering::Relaxed),
            queries_cname_loop: self.inner.queries_cname_loop.load(Ordering::Relaxed),
            axfr_started: self.inner.axfr_started.load(Ordering::Relaxed),
            axfr_succeeded: self.inner.axfr_succeeded.load(Ordering::Relaxed),
            axfr_failed: self.inner.axfr_failed.load(Ordering::Relaxed),
            ixfr_started: self.inner.ixfr_started.load(Ordering::Relaxed),
            ixfr_succeeded: self.inner.ixfr_succeeded.load(Ordering::Relaxed),
            ixfr_failed: self.inner.ixfr_failed.load(Ordering::Relaxed),
        }
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
    notify_authority: NotifyAuthority,
    notify_refresh: NotifyRefreshTracker,
    notify_refresh_tx: mpsc::Sender<RefreshRequest>,
    metrics: RuntimeMetrics,
    active_connections: Arc<AtomicUsize>,
}

struct TcpConnectionPermit {
    active: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
struct ZoneTransferPlan {
    origin: DomainName,
    qclass: u16,
    primaries: Vec<SocketAddr>,
    tsig_key: Option<Arc<TsigKey>>,
}

#[derive(Debug, Clone)]
struct TransferPlan {
    zones_by_key: Arc<HashMap<String, ZoneTransferPlan>>,
}

impl TransferPlan {
    fn from_config(config: &ServerConfig) -> Self {
        let tsig_keys = config
            .tsig_keys
            .iter()
            .map(|key| {
                let key = TsigKey::from_base64(&key.name, &key.algorithm, &key.secret)
                    .expect("configuration validation rejects invalid TSIG keys");
                (key.name.canonical_key(), Arc::new(key))
            })
            .collect::<HashMap<_, _>>();
        let zones_by_key = config
            .zones
            .iter()
            .map(|zone| {
                let origin = DomainName::from_absolute_str(&zone.name)
                    .expect("configuration validation rejects invalid zone names");
                let tsig_key = zone.tsig_key.as_ref().map(|name| {
                    let name = DomainName::from_absolute_str(name)
                        .expect("configuration validation rejects invalid TSIG key references");
                    tsig_keys
                        .get(&name.canonical_key())
                        .expect("configuration validation rejects unknown TSIG key references")
                        .clone()
                });
                (
                    origin.canonical_key(),
                    ZoneTransferPlan {
                        origin,
                        qclass: 1,
                        primaries: zone.primaries.clone(),
                        tsig_key,
                    },
                )
            })
            .collect();

        Self {
            zones_by_key: Arc::new(zones_by_key),
        }
    }

    fn get(&self, origin: &DomainName) -> Option<ZoneTransferPlan> {
        self.zones_by_key.get(&origin.canonical_key()).cloned()
    }
}

#[derive(Debug)]
struct RefreshRequest {
    zone: DomainName,
    requested_serial: Option<u32>,
    reason: RefreshReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshReason {
    Notify,
    Scheduled,
}

impl RefreshReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Notify => "notify",
            Self::Scheduled => "scheduled",
        }
    }
}

#[derive(Debug, Clone)]
struct ZoneRefreshRegistry {
    min_interval: Duration,
    initial_retry: Duration,
    initial_retry_max: Duration,
    jitter: Jitter,
    statuses: Arc<Mutex<HashMap<String, ZoneRefreshStatus>>>,
}

#[derive(Debug, Clone)]
struct IxfrCooldownRegistry {
    cooldown: Duration,
    disabled_until: Arc<Mutex<HashMap<IxfrCooldownKey, Instant>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IxfrCooldownKey {
    zone: String,
    primary: SocketAddr,
}

#[derive(Debug, Clone)]
struct Jitter {
    state: Arc<Mutex<u64>>,
    enabled: bool,
}

impl Jitter {
    fn new(seed: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(seed.max(1))),
            enabled: true,
        }
    }

    #[cfg(test)]
    fn none() -> Self {
        Self {
            state: Arc::new(Mutex::new(1)),
            enabled: false,
        }
    }

    fn apply(&self, interval: Duration) -> Duration {
        if !self.enabled || interval.is_zero() {
            return interval;
        }
        let sample = self.next_u64();
        jitter_interval(interval, sample)
    }

    fn next_u64(&self) -> u64 {
        let mut state = self.state.lock().expect("ZSM jitter state lock poisoned");
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }
}

#[derive(Debug, Clone)]
struct ZoneRefreshStatus {
    origin: DomainName,
    soa_timers: Option<SoaTimers>,
    last_success_unix_secs: Option<u64>,
    next_refresh: Option<Instant>,
    next_refresh_unix_secs: Option<u64>,
    expire_at: Option<Instant>,
    initial_failure_count: u32,
    failures_since_success: u64,
    in_progress: bool,
    expired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ZoneRefreshStatusSnapshot {
    last_success_unix_secs: Option<u64>,
    next_refresh_unix_secs: Option<u64>,
    failures_since_success: u64,
}

impl IxfrCooldownRegistry {
    fn new(cooldown: Duration) -> Self {
        Self {
            cooldown,
            disabled_until: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn is_disabled(&self, zone: &DomainName, primary: SocketAddr) -> bool {
        self.is_disabled_at(zone, primary, Instant::now())
    }

    fn is_disabled_at(&self, zone: &DomainName, primary: SocketAddr, now: Instant) -> bool {
        self.disabled_until
            .lock()
            .expect("IXFR cooldown registry lock poisoned")
            .get(&IxfrCooldownKey::new(zone, primary))
            .is_some_and(|disabled_until| *disabled_until > now)
    }

    fn record_unsupported(&self, zone: &DomainName, primary: SocketAddr) {
        self.record_unsupported_at(zone, primary, Instant::now());
    }

    fn record_unsupported_at(&self, zone: &DomainName, primary: SocketAddr, now: Instant) {
        self.disabled_until
            .lock()
            .expect("IXFR cooldown registry lock poisoned")
            .insert(IxfrCooldownKey::new(zone, primary), now + self.cooldown);
    }
}

impl IxfrCooldownKey {
    fn new(zone: &DomainName, primary: SocketAddr) -> Self {
        Self {
            zone: zone.canonical_key(),
            primary,
        }
    }
}

impl ZoneRefreshRegistry {
    fn new(min_interval: Duration, initial_retry: Duration, initial_retry_max: Duration) -> Self {
        Self {
            min_interval,
            initial_retry,
            initial_retry_max,
            jitter: Jitter::new(jitter_seed()),
            statuses: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    fn without_jitter(
        min_interval: Duration,
        initial_retry: Duration,
        initial_retry_max: Duration,
    ) -> Self {
        Self {
            min_interval,
            initial_retry,
            initial_retry_max,
            jitter: Jitter::none(),
            statuses: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn record_success(&self, snapshot: &ZoneSnapshot) {
        self.record_success_at(snapshot, Instant::now());
    }

    fn record_success_at(&self, snapshot: &ZoneSnapshot, now: Instant) {
        self.record_success_at_with_timestamp(snapshot, now, unix_timestamp_seconds());
    }

    fn record_success_at_with_timestamp(
        &self,
        snapshot: &ZoneSnapshot,
        now: Instant,
        unix_secs: u64,
    ) {
        let timers = snapshot.soa_timers;
        let refresh_interval = timers.map(|timers| self.effective_interval(timers.refresh));
        let next_refresh = refresh_interval.map(|interval| now + interval);
        let next_refresh_unix_secs =
            refresh_interval.map(|interval| unix_secs.saturating_add(interval.as_secs()));
        let expire_at = timers.map(|timers| now + Duration::from_secs(timers.expire as u64));
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        statuses.insert(
            snapshot.origin.canonical_key(),
            ZoneRefreshStatus {
                origin: snapshot.origin.clone(),
                soa_timers: timers,
                last_success_unix_secs: Some(unix_secs),
                next_refresh,
                next_refresh_unix_secs,
                expire_at,
                initial_failure_count: 0,
                failures_since_success: 0,
                in_progress: false,
                expired: false,
            },
        );
    }

    fn record_failure(&self, origin: &DomainName, current: Option<Arc<ZoneSnapshot>>) {
        self.record_failure_at(origin, current, Instant::now());
    }

    fn record_failure_at(
        &self,
        origin: &DomainName,
        current: Option<Arc<ZoneSnapshot>>,
        now: Instant,
    ) {
        self.record_failure_at_with_timestamp(origin, current, now, unix_timestamp_seconds());
    }

    fn record_failure_at_with_timestamp(
        &self,
        origin: &DomainName,
        current: Option<Arc<ZoneSnapshot>>,
        now: Instant,
        unix_secs: u64,
    ) {
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        let status = statuses
            .entry(origin.canonical_key())
            .or_insert_with(|| ZoneRefreshStatus {
                origin: origin.clone(),
                soa_timers: current.as_ref().and_then(|snapshot| snapshot.soa_timers),
                last_success_unix_secs: None,
                next_refresh: None,
                next_refresh_unix_secs: None,
                expire_at: None,
                initial_failure_count: 0,
                failures_since_success: 0,
                in_progress: false,
                expired: false,
            });

        if let Some(snapshot) = current {
            status.soa_timers = snapshot.soa_timers;
            status.expired = snapshot.state == oxidedns_core::zone::ZoneState::Expired;
        }
        let retry = if let Some(timers) = status.soa_timers {
            status.initial_failure_count = 0;
            self.effective_interval(timers.retry)
        } else {
            let retry = self.initial_retry_delay(status.initial_failure_count);
            status.initial_failure_count = status.initial_failure_count.saturating_add(1);
            retry
        };
        status.next_refresh = Some(now + retry);
        status.next_refresh_unix_secs = Some(unix_secs.saturating_add(retry.as_secs()));
        status.failures_since_success = status.failures_since_success.saturating_add(1);
        status.in_progress = false;
    }

    fn start_due_refreshes(&self, now: Instant) -> Vec<DomainName> {
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        statuses
            .values_mut()
            .filter_map(|status| {
                if status.in_progress || status.next_refresh.is_none_or(|next| next > now) {
                    return None;
                }
                status.in_progress = true;
                Some(status.origin.clone())
            })
            .collect()
    }

    fn expire_due_zones(&self, now: Instant) -> Vec<DomainName> {
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        statuses
            .values_mut()
            .filter_map(|status| {
                if status.expired || status.expire_at.is_none_or(|expire_at| expire_at > now) {
                    return None;
                }
                status.expired = true;
                Some(status.origin.clone())
            })
            .collect()
    }

    fn cancel_in_progress(&self, origin: &DomainName) {
        if let Some(status) = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned")
            .get_mut(&origin.canonical_key())
        {
            status.in_progress = false;
        }
    }

    fn effective_interval(&self, seconds: u32) -> Duration {
        self.jitter
            .apply(Duration::from_secs(seconds as u64).max(self.min_interval))
    }

    fn initial_retry_delay(&self, failure_count: u32) -> Duration {
        let multiplier = 1u32.checked_shl(failure_count.min(31)).unwrap_or(u32::MAX);
        let interval = self
            .initial_retry
            .saturating_mul(multiplier)
            .min(self.initial_retry_max);
        self.jitter.apply(interval)
    }

    fn snapshots_by_zone(&self) -> HashMap<String, ZoneRefreshStatusSnapshot> {
        self.statuses
            .lock()
            .expect("zone refresh registry lock poisoned")
            .iter()
            .map(|(zone, status)| {
                (
                    zone.clone(),
                    ZoneRefreshStatusSnapshot {
                        last_success_unix_secs: status.last_success_unix_secs,
                        next_refresh_unix_secs: status.next_refresh_unix_secs,
                        failures_since_success: status.failures_since_success,
                    },
                )
            })
            .collect()
    }
}

fn jitter_interval(interval: Duration, sample: u64) -> Duration {
    let millis = interval.as_millis();
    if millis == 0 {
        return interval;
    }
    let spread = (millis / 10).max(1);
    let offset = (sample as u128) % (spread * 2 + 1);
    let jittered = if offset <= spread {
        millis.saturating_sub(spread - offset)
    } else {
        millis + (offset - spread)
    };

    Duration::from_millis(jittered.min(u64::MAX as u128) as u64)
}

fn jitter_seed() -> u64 {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (since_epoch as u64) ^ ((since_epoch >> 64) as u64)
}

#[derive(Debug, Clone, Default)]
struct NotifyAuthority {
    sources_by_zone: Arc<HashMap<String, HashSet<IpAddr>>>,
    tsig_keys_by_zone: Arc<HashMap<String, Arc<TsigKey>>>,
}

impl NotifyAuthority {
    fn from_config(config: &ServerConfig) -> Self {
        let mut sources_by_zone = HashMap::new();
        let tsig_keys = config
            .tsig_keys
            .iter()
            .map(|key| {
                let key = TsigKey::from_base64(&key.name, &key.algorithm, &key.secret)
                    .expect("configuration validation rejects invalid TSIG keys");
                (key.name.canonical_key(), Arc::new(key))
            })
            .collect::<HashMap<_, _>>();
        let mut tsig_keys_by_zone = HashMap::new();
        for zone in &config.zones {
            let origin = DomainName::from_absolute_str(&zone.name)
                .expect("configuration validation rejects invalid zone names");
            let mut sources = zone
                .primaries
                .iter()
                .map(|primary| primary.ip())
                .collect::<HashSet<_>>();
            sources.extend(zone.notify_sources.iter().copied());
            sources_by_zone.insert(origin.canonical_key(), sources);
            if let Some(tsig_key) = &zone.tsig_key {
                let key_name = DomainName::from_absolute_str(tsig_key)
                    .expect("configuration validation rejects invalid TSIG key references");
                let key = tsig_keys
                    .get(&key_name.canonical_key())
                    .expect("configuration validation rejects unknown TSIG key references")
                    .clone();
                tsig_keys_by_zone.insert(origin.canonical_key(), key);
            }
        }

        Self {
            sources_by_zone: Arc::new(sources_by_zone),
            tsig_keys_by_zone: Arc::new(tsig_keys_by_zone),
        }
    }

    fn is_authorized(&self, qname: &DomainName, qclass: u16, source: IpAddr) -> bool {
        qclass == 1
            && self
                .sources_by_zone
                .get(&qname.canonical_key())
                .is_some_and(|sources| sources.contains(&source))
    }

    fn tsig_key_for_notify(&self, qname: &DomainName, qclass: u16) -> Option<Arc<TsigKey>> {
        if qclass != 1 {
            return None;
        }
        self.tsig_keys_by_zone.get(&qname.canonical_key()).cloned()
    }
}

struct PreparedDnsMessage {
    packet: Vec<u8>,
    response_tsig: Option<ResponseTsig>,
}

struct ResponseTsig {
    key: Arc<TsigKey>,
    request_mac: Vec<u8>,
}

fn prepare_notify_packet(
    packet: &[u8],
    notify_authority: &NotifyAuthority,
    source: IpAddr,
) -> Option<PreparedDnsMessage> {
    let unsigned = || PreparedDnsMessage {
        packet: packet.to_vec(),
        response_tsig: None,
    };

    let header = match Header::parse(packet) {
        Ok(header) => header,
        Err(_) => return Some(unsigned()),
    };
    if header.is_response() || header.opcode() != Some(Opcode::Notify) {
        return Some(unsigned());
    }

    let question = match Question::parse(packet) {
        Ok(question) => question,
        Err(_) => return Some(unsigned()),
    };
    let Some(key) = notify_authority.tsig_key_for_notify(&question.qname, question.qclass) else {
        return Some(unsigned());
    };

    match key.verify_request(packet, tsig_time_signed()) {
        Ok(verified) => Some(PreparedDnsMessage {
            packet: verified.message,
            response_tsig: Some(ResponseTsig {
                key,
                request_mac: verified.mac,
            }),
        }),
        Err(error) => {
            warn!(%source, zone = %question.qname, %error, "rejected NOTIFY with invalid TSIG");
            None
        }
    }
}

fn sign_notify_response(
    response: Vec<u8>,
    response_tsig: Option<ResponseTsig>,
) -> Result<Vec<u8>, TsigError> {
    let Some(response_tsig) = response_tsig else {
        return Ok(response);
    };

    Ok(response_tsig
        .key
        .sign_response(
            &response,
            &response_tsig.request_mac,
            tsig_time_signed(),
            DEFAULT_TSIG_FUDGE_SECS,
        )?
        .message)
}

#[derive(Debug, Clone)]
struct NotifyRefreshTracker {
    dedup_interval: Duration,
    last_signal_by_zone: Arc<Mutex<HashMap<String, Instant>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyRefreshAction {
    Signalled,
    Deduplicated,
}

impl NotifyRefreshTracker {
    fn new(dedup_interval: Duration) -> Self {
        Self {
            dedup_interval,
            last_signal_by_zone: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn record(&self, qname: &DomainName) -> NotifyRefreshAction {
        let now = Instant::now();
        let mut last_signal_by_zone = self
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned");
        let zone = qname.canonical_key();
        if let Some(last_signal) = last_signal_by_zone.get(&zone)
            && now.duration_since(*last_signal) < self.dedup_interval
        {
            return NotifyRefreshAction::Deduplicated;
        }

        last_signal_by_zone.insert(zone, now);
        NotifyRefreshAction::Signalled
    }
}

fn signal_notify_refresh(
    notify_refresh: &NotifyRefreshTracker,
    notify_refresh_tx: &mpsc::Sender<RefreshRequest>,
    qname: &DomainName,
    source: IpAddr,
    soa_serial: Option<u32>,
) {
    match notify_refresh.record(qname) {
        NotifyRefreshAction::Signalled => {
            info!(
                %source,
                zone = %qname,
                ?soa_serial,
                action = "refresh_signalled",
                "accepted NOTIFY"
            );
            match notify_refresh_tx.try_send(RefreshRequest {
                zone: qname.clone(),
                requested_serial: soa_serial,
                reason: RefreshReason::Notify,
            }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        %source,
                        zone = %qname,
                        "NOTIFY refresh queue full; refresh request dropped"
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!(
                        %source,
                        zone = %qname,
                        "NOTIFY refresh queue closed; refresh request dropped"
                    );
                }
            }
        }
        NotifyRefreshAction::Deduplicated => {
            info!(
                %source,
                zone = %qname,
                ?soa_serial,
                action = "deduplicated",
                "accepted NOTIFY"
            );
        }
    }
}

async fn serve_refresh_requests(
    mut refresh_rx: mpsc::Receiver<RefreshRequest>,
    zones: ZoneStore,
    transfer_plan: TransferPlan,
    refresh_registry: ZoneRefreshRegistry,
    ixfr_cooldowns: IxfrCooldownRegistry,
    metrics: RuntimeMetrics,
    settings: RefreshWorkerSettings,
) -> Result<(), RuntimeError> {
    let mut transfers = JoinSet::new();

    loop {
        tokio::select! {
            result = transfers.join_next(), if !transfers.is_empty() => {
                if let Some(Err(error)) = result {
                    warn!(%error, "refresh transfer task failed");
                }
            }
            request = refresh_rx.recv() => {
                let Some(request) = request else {
                    break;
                };

                let Some(plan) = transfer_plan.get(&request.zone) else {
                    let zone = &request.zone;
                    warn!(zone = %zone, "accepted NOTIFY for zone without transfer plan");
                    refresh_registry.cancel_in_progress(zone);
                    continue;
                };

                if notify_serial_is_current(&zones, &request) {
                    let zone = &request.zone;
                    if let Some(snapshot) = zones.find_exact_zone(zone) {
                        refresh_registry.record_success(&snapshot);
                    } else {
                        refresh_registry.cancel_in_progress(zone);
                    }
                    info!(
                        zone = %zone,
                        requested_serial = ?request.requested_serial,
                        action = "refresh_skipped_current",
                        "NOTIFY serial is not newer than active zone"
                    );
                    continue;
                }

                let transfer_permit = settings.transfer_limit
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("transfer semaphore is not closed");
                let axfr_timeout = settings.axfr_timeout;
                let ixfr_timeout = settings.ixfr_timeout;
                let zones = zones.clone();
                let refresh_registry = refresh_registry.clone();
                let ixfr_cooldowns = ixfr_cooldowns.clone();
                let metrics = metrics.clone();
                transfers.spawn(async move {
                    let _transfer_permit = transfer_permit;
                    match refresh_zone_from_primaries(
                        &zones,
                        &plan,
                        request.requested_serial,
                        RefreshAttemptContext {
                            ixfr_cooldowns: &ixfr_cooldowns,
                            metrics: &metrics,
                            ixfr_timeout,
                            axfr_timeout,
                            reason: request.reason.as_str(),
                        },
                    )
                    .await
                    {
                        Some(snapshot) => refresh_registry.record_success(&snapshot),
                        None => refresh_registry
                            .record_failure(&request.zone, zones.find_exact_zone(&request.zone)),
                    }
                });
            }
        }
    }

    while let Some(result) = transfers.join_next().await {
        if let Err(error) = result {
            warn!(%error, "refresh transfer task failed");
        }
    }

    Ok(())
}

#[derive(Clone)]
struct RefreshWorkerSettings {
    axfr_timeout: Duration,
    ixfr_timeout: Duration,
    transfer_limit: Arc<Semaphore>,
}

#[derive(Clone)]
struct InitialLoadSettings {
    axfr_timeout: Duration,
    ixfr_timeout: Duration,
    transfer_limit: Arc<Semaphore>,
}

#[derive(Clone, Copy)]
struct RefreshAttemptContext<'a> {
    ixfr_cooldowns: &'a IxfrCooldownRegistry,
    metrics: &'a RuntimeMetrics,
    ixfr_timeout: Duration,
    axfr_timeout: Duration,
    reason: &'a str,
}

async fn run_initial_zone_loads(
    zones: ZoneStore,
    configured_zones: Vec<ZoneConfig>,
    transfer_plan: TransferPlan,
    refresh_registry: ZoneRefreshRegistry,
    ixfr_cooldowns: IxfrCooldownRegistry,
    metrics: RuntimeMetrics,
    settings: InitialLoadSettings,
) -> Result<(), RuntimeError> {
    let mut transfers = JoinSet::new();

    for zone in configured_zones {
        let zone_apex = DomainName::from_absolute_str(&zone.name)
            .expect("configuration validation rejects invalid zone names");
        let plan = transfer_plan
            .get(&zone_apex)
            .expect("configuration validation builds a transfer plan for each zone");
        let zones = zones.clone();
        let refresh_registry = refresh_registry.clone();
        let ixfr_cooldowns = ixfr_cooldowns.clone();
        let metrics = metrics.clone();
        let axfr_timeout = settings.axfr_timeout;
        let ixfr_timeout = settings.ixfr_timeout;
        let transfer_permit = settings
            .transfer_limit
            .clone()
            .acquire_owned()
            .await
            .expect("transfer semaphore is not closed");

        transfers.spawn(async move {
            let _transfer_permit = transfer_permit;
            if let Some(snapshot) = refresh_zone_from_primaries(
                &zones,
                &plan,
                None,
                RefreshAttemptContext {
                    ixfr_cooldowns: &ixfr_cooldowns,
                    metrics: &metrics,
                    ixfr_timeout,
                    axfr_timeout,
                    reason: "initial",
                },
            )
            .await
            {
                refresh_registry.record_success(&snapshot);
            } else {
                let zone_apex = &plan.origin;
                refresh_registry.record_failure(zone_apex, zones.find_exact_zone(zone_apex));
                warn!(zone = %zone_apex, "zone remains in LOADING state");
            }
        });
    }

    while let Some(result) = transfers.join_next().await {
        if let Err(error) = result {
            warn!(%error, "initial zone transfer task failed");
        }
    }

    Ok(())
}

async fn serve_scheduled_refreshes(
    zones: ZoneStore,
    refresh_registry: ZoneRefreshRegistry,
    refresh_tx: mpsc::Sender<RefreshRequest>,
    tick: Duration,
) -> Result<(), RuntimeError> {
    let mut interval = tokio::time::interval(tick);
    loop {
        interval.tick().await;
        let now = Instant::now();
        for zone in refresh_registry.expire_due_zones(now) {
            if zones.expire_zone(&zone) {
                warn!(zone = %zone, "zone expired");
            }
        }

        for zone in refresh_registry.start_due_refreshes(now) {
            match refresh_tx.try_send(RefreshRequest {
                zone: zone.clone(),
                requested_serial: None,
                reason: RefreshReason::Scheduled,
            }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    refresh_registry.cancel_in_progress(&zone);
                    warn!(zone = %zone, "refresh queue full; scheduled refresh deferred");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    refresh_registry.cancel_in_progress(&zone);
                    warn!(zone = %zone, "refresh queue closed; scheduled refresh stopped");
                    return Ok(());
                }
            }
        }
    }
}

fn notify_serial_is_current(zones: &ZoneStore, request: &RefreshRequest) -> bool {
    let Some(requested_serial) = request.requested_serial else {
        return false;
    };
    let Some(snapshot) = zones.find_exact_zone(&request.zone) else {
        return false;
    };
    let Some(current_serial) = snapshot.serial else {
        return false;
    };

    !serial_after(requested_serial, current_serial)
}

fn serial_after(candidate: u32, current: u32) -> bool {
    candidate != current && candidate.wrapping_sub(current) < 0x8000_0000
}

fn ixfr_error_disables_ixfr(error: &TransferError) -> bool {
    matches!(
        error,
        TransferError::Ixfr(axfr::IxfrError::ErrorRcode(1 | 4))
    )
}

async fn refresh_zone_from_primaries(
    zones: &ZoneStore,
    plan: &ZoneTransferPlan,
    primary_serial_hint: Option<u32>,
    context: RefreshAttemptContext<'_>,
) -> Option<ZoneSnapshot> {
    let current_snapshot = zones
        .find_exact_zone(&plan.origin)
        .filter(|snapshot| snapshot.serial.is_some());
    let current_serial = current_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.serial);

    if let (Some(snapshot), Some(current_serial), Some(primary_serial)) =
        (&current_snapshot, current_serial, primary_serial_hint)
    {
        if !serial_after(primary_serial, current_serial) {
            info!(
                zone = %plan.origin,
                current_serial,
                primary_serial,
                reason = %context.reason,
                "SOA serial hint confirmed zone current"
            );
            return Some((**snapshot).clone());
        }

        info!(
            zone = %plan.origin,
            current_serial,
            primary_serial,
            reason = %context.reason,
            "SOA serial hint found newer primary serial"
        );
    }

    for primary in &plan.primaries {
        if primary_serial_hint.is_none()
            && let (Some(snapshot), Some(current_serial)) = (&current_snapshot, current_serial)
        {
            let qid = match transfer_query_id() {
                Ok(qid) => qid,
                Err(error) => {
                    warn!(
                        zone = %plan.origin,
                        %primary,
                        %error,
                        reason = %context.reason,
                        "SOA poll failed"
                    );
                    continue;
                }
            };
            match poll_soa_from_primary_with_tsig(
                *primary,
                &plan.origin,
                plan.qclass,
                qid,
                plan.tsig_key.as_deref(),
                context.axfr_timeout,
            )
            .await
            {
                Ok(primary_serial) if !serial_after(primary_serial, current_serial) => {
                    info!(
                        zone = %plan.origin,
                        %primary,
                        current_serial,
                        primary_serial,
                        reason = %context.reason,
                        "SOA poll confirmed zone current"
                    );
                    return Some((**snapshot).clone());
                }
                Ok(primary_serial) => {
                    info!(
                        zone = %plan.origin,
                        %primary,
                        current_serial,
                        primary_serial,
                        reason = %context.reason,
                        "SOA poll found newer primary serial"
                    );
                }
                Err(error) => {
                    warn!(
                        zone = %plan.origin,
                        %primary,
                        %error,
                        reason = %context.reason,
                        "SOA poll failed"
                    );
                    continue;
                }
            }
        }

        if let Some(current_snapshot) = &current_snapshot {
            if context.ixfr_cooldowns.is_disabled(&plan.origin, *primary) {
                info!(
                    zone = %plan.origin,
                    %primary,
                    reason = %context.reason,
                    "IXFR disabled cooldown active; using AXFR"
                );
            } else {
                let qid = match transfer_query_id() {
                    Ok(qid) => qid,
                    Err(error) => {
                        warn!(
                            zone = %plan.origin,
                            %primary,
                            %error,
                            reason = %context.reason,
                            "IXFR failed"
                        );
                        continue;
                    }
                };
                context.metrics.record_ixfr_started();
                match transfer_ixfr_from_primary_with_tsig(
                    *primary,
                    &plan.origin,
                    plan.qclass,
                    qid,
                    current_snapshot,
                    plan.tsig_key.as_deref(),
                    context.ixfr_timeout,
                )
                .await
                {
                    Ok(IxfrResponse::Updated(snapshot)) => {
                        context.metrics.record_ixfr_succeeded();
                        let serial = snapshot.serial;
                        zones.insert_snapshot(snapshot.clone());
                        info!(
                            zone = %plan.origin,
                            %primary,
                            ?serial,
                            reason = %context.reason,
                            "IXFR completed"
                        );
                        return Some(snapshot);
                    }
                    Ok(IxfrResponse::Current) => {
                        context.metrics.record_ixfr_succeeded();
                        info!(
                            zone = %plan.origin,
                            %primary,
                            current_serial,
                            reason = %context.reason,
                            "IXFR confirmed zone current"
                        );
                        return Some((**current_snapshot).clone());
                    }
                    Err(error) => {
                        context.metrics.record_ixfr_failed();
                        if ixfr_error_disables_ixfr(&error) {
                            context
                                .ixfr_cooldowns
                                .record_unsupported(&plan.origin, *primary);
                        }
                        warn!(
                            zone = %plan.origin,
                            %primary,
                            %error,
                            reason = %context.reason,
                            "IXFR failed; falling back to AXFR"
                        );
                    }
                }
            }
        }

        let qid = match transfer_query_id() {
            Ok(qid) => qid,
            Err(error) => {
                warn!(
                    zone = %plan.origin,
                    %primary,
                    %error,
                    reason = %context.reason,
                    "AXFR failed"
                );
                continue;
            }
        };
        context.metrics.record_axfr_started();
        match transfer_axfr_from_primary_with_tsig(
            *primary,
            &plan.origin,
            plan.qclass,
            qid,
            plan.tsig_key.as_deref(),
            context.axfr_timeout,
        )
        .await
        {
            Ok(snapshot) => {
                context.metrics.record_axfr_succeeded();
                let serial = snapshot.serial;
                zones.insert_snapshot(snapshot.clone());
                info!(
                    zone = %plan.origin,
                    %primary,
                    ?serial,
                    reason = %context.reason,
                    "AXFR completed"
                );
                return Some(snapshot);
            }
            Err(error) => {
                context.metrics.record_axfr_failed();
                warn!(
                    zone = %plan.origin,
                    %primary,
                    %error,
                    reason = %context.reason,
                    "AXFR failed"
                );
            }
        }
    }

    None
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
    notify_authority: NotifyAuthority,
    notify_refresh: NotifyRefreshTracker,
    notify_refresh_tx: mpsc::Sender<RefreshRequest>,
    metrics: RuntimeMetrics,
    peer_ip: IpAddr,
) -> Result<(), RuntimeError> {
    while let Some(packet) = read_tcp_message(&mut stream, idle_timeout, read_timeout).await? {
        let Some(prepared) = prepare_notify_packet(&packet, &notify_authority, peer_ip) else {
            debug!(bytes = packet.len(), "discarded DNS-over-TCP message");
            continue;
        };
        let query_metrics = observe_query_metrics(&prepared.packet, &zones, &metrics);
        match answer_message_with_notify_hooks_and_query_observer(
            &prepared.packet,
            &zones,
            AnswerOptions {
                transport: Transport::Tcp,
                max_udp_payload,
                max_cname_chain,
                tcp_keepalive_timeout_secs: idle_timeout.as_secs(),
                edns_padding_block_size,
                any_response,
            },
            |qname, qclass| {
                let authorized = notify_authority.is_authorized(qname, qclass, peer_ip);
                if !authorized {
                    warn!(%peer_ip, zone = %qname, "unauthorized NOTIFY discarded");
                }
                authorized
            },
            |qname, _qclass, serial| {
                signal_notify_refresh(&notify_refresh, &notify_refresh_tx, qname, peer_ip, serial)
            },
            |lookup| record_query_termination_metric(query_metrics, lookup, &metrics),
        ) {
            DatagramAction::Discard => {
                debug!(bytes = packet.len(), "discarded DNS-over-TCP message");
            }
            DatagramAction::Respond(response) => {
                record_query_response_metric(query_metrics, &response, &metrics);
                let response = match sign_notify_response(response, prepared.response_tsig) {
                    Ok(response) => response,
                    Err(error) => {
                        warn!(%peer_ip, %error, "failed to sign NOTIFY response");
                        continue;
                    }
                };
                if !write_tcp_message(&mut stream, &response, write_timeout).await? {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

async fn write_tcp_message<W>(
    stream: &mut W,
    message: &[u8],
    write_timeout: Duration,
) -> Result<bool, RuntimeError>
where
    W: AsyncWrite + Unpin,
{
    match tokio::time::timeout(
        write_timeout,
        stream.write_all(&frame_dns_tcp_message(message)),
    )
    .await
    {
        Ok(Ok(())) => Ok(true),
        Ok(Err(error)) => Err(RuntimeError::Tcp(error)),
        Err(_) => Ok(false),
    }
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
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
        sync::{mpsc, oneshot},
    };
    use oxidedns_core::{
        ServerConfig,
        axfr::{IxfrResponse, frame_tcp_message},
        dns::{AnyResponseMode, DomainName, Header, LookupTermination, Opcode, RecordType},
        tsig::{DEFAULT_TSIG_FUDGE_SECS, TsigKey},
        zone::{ResourceRecord, Rrset, ZoneSnapshot, ZoneState, ZoneStore},
    };

    use super::{
        HealthEndpointState, IxfrCooldownRegistry, NotifyAuthority, NotifyRefreshAction,
        NotifyRefreshTracker, QueryMetricObservation, RefreshAttemptContext, RefreshRequest,
        RefreshWorkerSettings, Runtime, RuntimeError, RuntimeMetrics, RuntimeStatus,
        TcpServerSettings, TransferPlan, UdpServerSettings, ZoneRefreshRegistry, drain_task_set,
        drain_tcp_connections, handle_tcp_connection, jitter_interval, observe_query_metrics,
        poll_soa_from_primary, poll_soa_from_primary_with_tsig, prepare_notify_packet,
        query_id_from_random_bytes, record_query_response_metric, record_query_termination_metric,
        refresh_zone_from_primaries, serial_after, serve_health, serve_refresh_requests,
        serve_scheduled_refreshes, serve_tcp, serve_udp, sign_notify_response,
        transfer_axfr_from_primary, transfer_ixfr_from_primary, transfer_query_id,
        write_tcp_message,
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

    #[test]
    fn notify_authority_allows_primaries_and_notify_sources() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                notify_sources = ["198.51.100.53"]
            "#,
        )
        .expect("valid config");
        let authority = NotifyAuthority::from_config(&config);
        let zone = DomainName::from_absolute_str("example.test.").unwrap();

        assert!(authority.is_authorized(&zone, 1, "192.0.2.53".parse().unwrap()));
        assert!(authority.is_authorized(&zone, 1, "198.51.100.53".parse().unwrap()));
        assert!(!authority.is_authorized(&zone, 1, "203.0.113.53".parse().unwrap()));
        assert!(!authority.is_authorized(&zone, 255, "192.0.2.53".parse().unwrap()));
    }

    #[test]
    fn notify_authority_requires_tsig_for_configured_zone() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

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
        let authority = NotifyAuthority::from_config(&config);
        let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);

        let prepared = prepare_notify_packet(&packet, &authority, "192.0.2.53".parse().unwrap());

        assert!(prepared.is_none());
    }

    #[tokio::test]
    async fn health_endpoint_reports_starting_until_zone_active() {
        let zones = ZoneStore::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_health(listener, health_state(zones.clone())));

        let starting = http_request(addr, "GET", "/healthz").await;
        assert!(starting.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(starting.ends_with("starting\n"));

        zones.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            Vec::new(),
        ));

        let ready = http_request(addr, "GET", "/healthz").await;
        assert!(ready.starts_with("HTTP/1.1 200 OK"));
        assert!(ready.ends_with("ready\n"));

        server.abort();
    }

    #[tokio::test]
    async fn health_endpoint_handles_readyz_metrics_404_and_405() {
        let zones = ZoneStore::new();
        let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
        zones.insert_snapshot(ZoneSnapshot::active(
            active_origin.clone(),
            Some(1),
            vec![Rrset::new(
                active_origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            )],
        ));
        zones.insert_loading(DomainName::from_absolute_str("loading.test.").unwrap());
        let metrics_state = RuntimeMetrics::new();
        metrics_state.record_axfr_started();
        metrics_state.record_axfr_succeeded();
        metrics_state.record_zone_query(&active_origin);
        metrics_state.record_zone_query(&active_origin);
        metrics_state.record_query_received();
        metrics_state.record_query_received();
        metrics_state.record_query_truncated();
        metrics_state.record_query_cname_chain_limit();
        metrics_state.record_query_cname_loop();
        metrics_state.record_query_response_rcode(0);
        metrics_state.record_query_response_rcode(3);
        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        );
        let refresh_now = std::time::Instant::now();
        let refresh_unix = 1_700_000_000;
        refresh_registry.record_success_at_with_timestamp(
            zones
                .find_exact_zone(&active_origin)
                .as_ref()
                .expect("active snapshot"),
            refresh_now,
            refresh_unix,
        );
        refresh_registry.record_failure_at_with_timestamp(
            &DomainName::from_absolute_str("loading.test.").unwrap(),
            None,
            refresh_now,
            refresh_unix,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_health(
            listener,
            HealthEndpointState {
                zones,
                runtime_status: RuntimeStatus::new(),
                metrics: metrics_state,
                refresh_registry,
            },
        ));

        let ready = http_request(addr, "GET", "/readyz").await;
        assert!(ready.starts_with("HTTP/1.1 200 OK"));
        assert!(ready.ends_with("ready\n"));

        let metrics = http_request(addr, "GET", "/metrics").await;
        assert!(metrics.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics.contains("content-type: text/plain; version=0.0.4; charset=utf-8"));
        assert!(metrics.contains("oxidedns_zones_total 2"));
        assert!(metrics.contains("oxidedns_zones_active 1"));
        assert!(metrics.contains("oxidedns_queries_received_total 2"));
        assert!(metrics.contains("oxidedns_queries_truncated_total 1"));
        assert!(metrics.contains("oxidedns_queries_cname_chain_limit_total 1"));
        assert!(metrics.contains("oxidedns_queries_cname_loop_total 1"));
        assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"NOERROR\"} 1"));
        assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"SERVFAIL\"} 0"));
        assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"NXDOMAIN\"} 1"));
        assert!(metrics.contains("oxidedns_transfer_sessions_started_total{protocol=\"axfr\"} 1"));
        assert!(metrics.contains("oxidedns_transfer_sessions_started_total{protocol=\"ixfr\"} 0"));
        assert!(metrics.contains("oxidedns_transfer_sessions_completed_total{protocol=\"axfr\"} 1"));
        assert!(metrics.contains("oxidedns_transfer_sessions_failed_total{protocol=\"axfr\"} 0"));
        assert!(metrics.contains("oxidedns_zone_state{zone=\"example.test.\",state=\"active\"} 1"));
        assert!(metrics.contains("oxidedns_zone_state{zone=\"example.test.\",state=\"loading\"} 0"));
        assert!(metrics.contains("oxidedns_zone_state{zone=\"loading.test.\",state=\"loading\"} 1"));
        assert!(!metrics.contains("oxidedns_zone_soa_serial{zone=\"loading.test.\"}"));
        assert!(metrics.contains("oxidedns_zone_soa_serial{zone=\"example.test.\"} 1"));
        assert!(metrics.contains(
            "oxidedns_zone_last_success_timestamp_seconds{zone=\"example.test.\"} 1700000000"
        ));
        assert!(metrics.contains(
            "oxidedns_zone_next_refresh_timestamp_seconds{zone=\"example.test.\"} 1700003600"
        ));
        assert!(
            !metrics.contains("oxidedns_zone_last_success_timestamp_seconds{zone=\"loading.test.\"}")
        );
        assert!(metrics.contains(
            "oxidedns_zone_next_refresh_timestamp_seconds{zone=\"loading.test.\"} 1700000060"
        ));
        assert!(
            metrics.contains("oxidedns_zone_refresh_failures_since_success{zone=\"example.test.\"} 0")
        );
        assert!(
            metrics.contains("oxidedns_zone_refresh_failures_since_success{zone=\"loading.test.\"} 1")
        );
        assert!(metrics.contains("oxidedns_zone_queries_total{zone=\"example.test.\"} 2"));
        assert!(metrics.contains("oxidedns_zone_queries_total{zone=\"loading.test.\"} 0"));

        let missing = http_request(addr, "GET", "/missing").await;
        assert!(missing.starts_with("HTTP/1.1 404 Not Found"));

        let method_not_allowed = http_request(addr, "POST", "/metrics").await;
        assert!(method_not_allowed.starts_with("HTTP/1.1 405 Method Not Allowed"));

        server.abort();
    }

    #[tokio::test]
    async fn health_endpoint_reports_draining_and_unready_during_shutdown() {
        let zones = ZoneStore::new();
        zones.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            Vec::new(),
        ));
        let runtime_status = RuntimeStatus::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_health(
            listener,
            HealthEndpointState {
                zones,
                runtime_status: runtime_status.clone(),
                metrics: RuntimeMetrics::new(),
                refresh_registry: ZoneRefreshRegistry::without_jitter(
                    std::time::Duration::from_secs(60),
                    std::time::Duration::from_secs(60),
                    std::time::Duration::from_secs(3600),
                ),
            },
        ));

        runtime_status.mark_draining();

        let health = http_request(addr, "GET", "/healthz").await;
        assert!(health.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(health.ends_with("draining\n"));

        let ready = http_request(addr, "GET", "/readyz").await;
        assert!(ready.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(ready.ends_with("not ready\n"));

        runtime_status.mark_unhealthy();
        let unhealthy = http_request(addr, "GET", "/healthz").await;
        assert!(unhealthy.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(unhealthy.ends_with("unhealthy\n"));

        server.abort();
    }

    #[tokio::test]
    async fn runtime_binds_health_while_initial_transfer_is_in_progress() {
        let (primary, query_seen, release_primary) = spawn_blocked_axfr_primary().await;
        let udp_addr = unused_udp_addr().await;
        let health_addr = unused_tcp_addr().await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["{udp_addr}"]
                health = "{health_addr}"

                [limits]
                axfr_timeout_secs = 5
                graceful_shutdown_secs = 1

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");
        let runtime = Runtime::new(config);
        let server = tokio::spawn(runtime.run());

        tokio::time::timeout(std::time::Duration::from_secs(1), query_seen)
            .await
            .expect("initial transfer should start")
            .expect("primary should observe initial transfer query");

        let health = eventually_http_request(
            health_addr,
            "GET",
            "/healthz",
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(health.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(health.ends_with("starting\n"));

        let _ = release_primary.send(());
        server.abort();
    }

    #[tokio::test]
    async fn runtime_reports_draining_until_initial_transfer_releases() {
        let (primary, query_seen, release_primary) = spawn_blocked_axfr_primary().await;
        let udp_addr = unused_udp_addr().await;
        let health_addr = unused_tcp_addr().await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["{udp_addr}"]
                health = "{health_addr}"

                [limits]
                axfr_timeout_secs = 5
                graceful_shutdown_secs = 2

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");
        let runtime = Runtime::new(config);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(runtime.run_with_shutdown_signal(async move {
            shutdown_rx.await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Interrupted, "test shutdown dropped")
            })
        }));

        tokio::time::timeout(std::time::Duration::from_secs(1), query_seen)
            .await
            .expect("initial transfer should start")
            .expect("primary should observe initial transfer query");
        let starting =
            eventually_health_body(health_addr, "starting\n", std::time::Duration::from_secs(1))
                .await;
        assert!(starting.starts_with("HTTP/1.1 503 Service Unavailable"));

        shutdown_tx
            .send("SIGTERM")
            .expect("runtime receives shutdown");
        let draining =
            eventually_health_body(health_addr, "draining\n", std::time::Duration::from_secs(1))
                .await;
        assert!(draining.starts_with("HTTP/1.1 503 Service Unavailable"));

        let _ = release_primary.send(());
        tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .expect("runtime should finish after transfer release")
            .expect("runtime task should join")
            .expect("runtime should shut down cleanly");
    }

    #[tokio::test]
    async fn runtime_keeps_serving_after_initial_transfer_completes() {
        let primary = spawn_axfr_primary().await;
        let udp_addr = unused_udp_addr().await;
        let health_addr = unused_tcp_addr().await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["{udp_addr}"]
                health = "{health_addr}"

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");
        let runtime = Runtime::new(config);
        let server = tokio::spawn(runtime.run());

        let ready =
            eventually_health_body(health_addr, "ready\n", std::time::Duration::from_secs(1)).await;
        assert!(ready.starts_with("HTTP/1.1 200 OK"));

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        let still_ready = eventually_http_request(
            health_addr,
            "GET",
            "/healthz",
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(still_ready.starts_with("HTTP/1.1 200 OK"));
        assert!(still_ready.ends_with("ready\n"));

        server.abort();
    }

    #[test]
    fn signed_notify_is_verified_stripped_and_response_signed() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

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
        let authority = NotifyAuthority::from_config(&config);
        let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
        let signed_notify = key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed NOTIFY");

        let prepared = prepare_notify_packet(
            &signed_notify.message,
            &authority,
            "192.0.2.53".parse().unwrap(),
        )
        .expect("verified NOTIFY");

        assert_eq!(prepared.packet, packet);
        let response = notify_response(0x1234);
        let signed_response = sign_notify_response(response.clone(), prepared.response_tsig)
            .expect("signed NOTIFY response");
        let verified_response = key
            .verify_response(&signed_response, &signed_notify.mac, current_unix_time())
            .expect("verified NOTIFY response");
        assert_eq!(verified_response.message, response);
    }

    #[test]
    fn notify_refresh_tracker_deduplicates_within_interval() {
        let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
        let zone = DomainName::from_absolute_str("example.test.").unwrap();

        assert_eq!(tracker.record(&zone), NotifyRefreshAction::Signalled);
        assert_eq!(tracker.record(&zone), NotifyRefreshAction::Deduplicated);
    }

    #[test]
    fn notify_refresh_tracker_allows_after_zero_interval() {
        let tracker = NotifyRefreshTracker::new(std::time::Duration::ZERO);
        let zone = DomainName::from_absolute_str("example.test.").unwrap();

        assert_eq!(tracker.record(&zone), NotifyRefreshAction::Signalled);
        assert_eq!(tracker.record(&zone), NotifyRefreshAction::Signalled);
    }

    #[tokio::test]
    async fn drain_tcp_connections_returns_when_idle() {
        let active = Arc::new(AtomicUsize::new(0));

        assert!(
            drain_tcp_connections(
                active,
                std::time::Duration::from_millis(25),
                std::time::Duration::from_millis(1),
            )
            .await
        );
    }

    #[tokio::test]
    async fn drain_tcp_connections_waits_for_active_connections_until_grace() {
        let active = Arc::new(AtomicUsize::new(1));
        let active_for_task = active.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            active_for_task.store(0, Ordering::Release);
        });

        assert!(
            drain_tcp_connections(
                active,
                std::time::Duration::from_secs(1),
                std::time::Duration::from_millis(1),
            )
            .await
        );
    }

    #[tokio::test]
    async fn drain_tcp_connections_stops_after_grace_period() {
        let active = Arc::new(AtomicUsize::new(1));

        assert!(
            !drain_tcp_connections(
                active,
                std::time::Duration::from_millis(5),
                std::time::Duration::from_millis(1),
            )
            .await
        );
    }

    #[tokio::test]
    async fn drain_task_set_waits_for_tasks_until_grace() {
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            Ok::<(), RuntimeError>(())
        });

        assert!(drain_task_set(&mut tasks, std::time::Duration::from_secs(1), "test task").await);
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn drain_task_set_aborts_after_grace_period() {
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            Ok::<(), RuntimeError>(())
        });

        assert!(
            !drain_task_set(&mut tasks, std::time::Duration::from_millis(5), "test task").await
        );
        assert!(tasks.is_empty());
    }

    fn notify_refresh_tx() -> mpsc::Sender<RefreshRequest> {
        let (tx, _rx) = mpsc::channel(1);
        tx
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
        assert_eq!(snapshot.serial, Some(1));
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
    async fn transfer_ixfr_from_primary_accepts_mode2_axfr_fallback() {
        let primary = spawn_ixfr_mode2_primary_with_serial(2).await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(1),
        );
        let current_zone = ZoneSnapshot::active(
            apex.clone(),
            Some(1),
            vec![Rrset::new(
                apex.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![current_soa.rdata],
            )],
        );
        let response = transfer_ixfr_from_primary(
            primary,
            &apex,
            1,
            0x1234,
            &current_zone,
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("IXFR transfer");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert_eq!(snapshot.state, ZoneState::Active);
        assert_eq!(snapshot.serial, Some(2));
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
    async fn transfer_ixfr_from_primary_applies_mode1_incremental_diff() {
        let primary = spawn_ixfr_mode1_primary().await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(1),
        );
        let old_a = record(
            "old.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let current_zone = ZoneSnapshot::active(
            apex.clone(),
            Some(1),
            vec![
                Rrset::new(
                    apex.clone(),
                    RecordType::Soa as u16,
                    1,
                    current_soa.ttl,
                    vec![current_soa.rdata],
                ),
                Rrset::new(
                    old_a.owner.clone(),
                    old_a.rr_type,
                    old_a.class,
                    old_a.ttl,
                    vec![old_a.rdata],
                ),
            ],
        );
        let response = transfer_ixfr_from_primary(
            primary,
            &apex,
            1,
            0x1234,
            &current_zone,
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("IXFR transfer");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert_eq!(snapshot.serial, Some(2));
        assert!(
            snapshot
                .lookup(
                    &DomainName::from_absolute_str("old.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers
                .is_empty()
        );
        assert_eq!(
            snapshot
                .lookup(
                    &DomainName::from_absolute_str("new.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn poll_soa_from_primary_reads_udp_response() {
        let primary = spawn_soa_primary_with_serial(7).await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let serial =
            poll_soa_from_primary(primary, &apex, 1, 0x1234, std::time::Duration::from_secs(5))
                .await
                .expect("SOA poll");

        assert_eq!(serial, 7);
    }

    #[tokio::test]
    async fn poll_soa_from_primary_verifies_signed_tsig_response() {
        let primary = spawn_signed_soa_primary_with_serial(7).await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();

        let serial = poll_soa_from_primary_with_tsig(
            primary,
            &apex,
            1,
            0x1234,
            Some(&key),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("signed SOA poll");

        assert_eq!(serial, 7);
    }

    #[tokio::test]
    async fn poll_soa_from_primary_rejects_unsigned_response_when_tsig_expected() {
        let primary = spawn_soa_primary_with_serial(7).await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let key = TsigKey::from_base64("transfer-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();

        let error = poll_soa_from_primary_with_tsig(
            primary,
            &apex,
            1,
            0x1234,
            Some(&key),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect_err("unsigned response must fail");

        assert!(matches!(
            error,
            super::TransferError::Tsig(oxidedns_core::tsig::TsigError::MissingTsig)
        ));
    }

    #[test]
    fn serial_after_handles_wraparound() {
        assert!(serial_after(2, 1));
        assert!(serial_after(0, u32::MAX));
        assert!(!serial_after(1, 1));
        assert!(!serial_after(1, 2));
        assert!(!serial_after(0x8000_0001, 1));
    }

    #[test]
    fn transfer_query_id_uses_full_sixteen_bit_range() {
        assert_eq!(query_id_from_random_bytes([0x00, 0x00]), 0);
        assert_eq!(query_id_from_random_bytes([0xff, 0xff]), u16::MAX);
    }

    #[test]
    fn transfer_query_id_reads_os_randomness() {
        transfer_query_id().expect("random query id");
    }

    #[test]
    fn query_metrics_count_configured_zone_queries_only() {
        let zones = ZoneStore::new();
        let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
        zones.insert_snapshot(ZoneSnapshot::active(active_origin, Some(1), Vec::new()));
        zones.insert_loading(DomainName::from_absolute_str("loading.test.").unwrap());
        let metrics = RuntimeMetrics::new();

        observe_query_metrics(
            &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
            &zones,
            &metrics,
        );
        observe_query_metrics(
            &query(b"\x03www\x07loading\x04test\x00", RecordType::A as u16, 1),
            &zones,
            &metrics,
        );
        observe_query_metrics(
            &query(b"\x07outside\x04test\x00", RecordType::A as u16, 1),
            &zones,
            &metrics,
        );
        let response = {
            let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
            packet[2] |= 0x80;
            packet
        };
        observe_query_metrics(&response, &zones, &metrics);

        assert_eq!(metrics.snapshot().queries_received, 3);
        let counts = metrics.zone_query_counts();
        assert_eq!(counts.get("example.test."), Some(&1));
        assert_eq!(counts.get("loading.test."), Some(&1));
        assert!(!counts.contains_key("outside.test."));
    }

    #[test]
    fn query_metrics_count_response_rcodes_for_queries_only() {
        let zones = ZoneStore::new();
        let metrics = RuntimeMetrics::new();
        let observation = observe_query_metrics(
            &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
            &zones,
            &metrics,
        );
        let non_query_observation = observe_query_metrics(&[0, 1, 2], &zones, &metrics);
        let mut noerror = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        noerror[2] |= 0x80;
        let mut nxdomain = noerror.clone();
        nxdomain[3] |= 3;
        let mut truncated = noerror.clone();
        truncated[2] |= 0x02;
        let mut badvers = noerror.clone();
        badvers[11] = 1;
        badvers.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);

        record_query_response_metric(observation, &noerror, &metrics);
        record_query_response_metric(observation, &nxdomain, &metrics);
        record_query_response_metric(observation, &truncated, &metrics);
        record_query_response_metric(observation, &badvers, &metrics);
        record_query_response_metric(non_query_observation, &truncated, &metrics);

        assert_eq!(metrics.snapshot().queries_truncated, 1);
        let rcodes = metrics.query_rcode_counts();
        assert_eq!(rcodes.get(&0), Some(&2));
        assert_eq!(rcodes.get(&3), Some(&1));
        assert_eq!(rcodes.get(&16), Some(&1));
    }

    #[test]
    fn query_metrics_count_cname_termination_causes_for_queries_only() {
        let metrics = RuntimeMetrics::new();
        let observation = QueryMetricObservation { is_query: true };
        let non_query_observation = QueryMetricObservation { is_query: false };
        let chain_limit = oxidedns_core::dns::LookupResult::positive_records_with_termination(
            Vec::new(),
            LookupTermination::CnameChainLimit,
        );
        let loop_detected = oxidedns_core::dns::LookupResult::positive_records_with_termination(
            Vec::new(),
            LookupTermination::CnameLoop,
        );

        record_query_termination_metric(observation, &chain_limit, &metrics);
        record_query_termination_metric(observation, &loop_detected, &metrics);
        record_query_termination_metric(non_query_observation, &chain_limit, &metrics);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.queries_cname_chain_limit, 1);
        assert_eq!(snapshot.queries_cname_loop, 1);
    }

    #[tokio::test]
    async fn udp_query_records_cname_chain_limit_metric() {
        let zones = ZoneStore::new();
        zones.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![
                        DomainName::from_absolute_str("b.example.test.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("b.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![
                        DomainName::from_absolute_str("c.example.test.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
            ],
        ));
        let metrics = RuntimeMetrics::new();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let server_metrics = metrics.clone();
        let server = tokio::spawn(serve_udp(
            socket,
            zones,
            UdpServerSettings {
                max_udp_payload: 1232,
                max_cname_chain: 1,
                edns_padding_block_size: 0,
                any_response: AnyResponseMode::Minimal,
                notify_authority: NotifyAuthority::default(),
                notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
                notify_refresh_tx: notify_refresh_tx(),
                metrics: server_metrics,
            },
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(
                &query(b"\x01a\x07example\x04test\x00", RecordType::A as u16, 1),
                server_addr,
            )
            .await
            .unwrap();
        let mut response = [0u8; 512];
        let len = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv(&mut response),
        )
        .await
        .expect("UDP response")
        .unwrap();
        server.abort();

        assert_eq!(response[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert!(len > 12);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.queries_received, 1);
        assert_eq!(snapshot.queries_cname_chain_limit, 1);
        assert_eq!(snapshot.queries_cname_loop, 0);
    }

    #[test]
    fn zsm_jitter_stays_within_ten_percent_bounds() {
        let interval = std::time::Duration::from_secs(100);

        assert_eq!(
            jitter_interval(interval, 0),
            std::time::Duration::from_secs(90)
        );
        assert_eq!(
            jitter_interval(interval, 10_000),
            std::time::Duration::from_secs(100)
        );
        assert_eq!(
            jitter_interval(interval, 20_000),
            std::time::Duration::from_secs(110)
        );
    }

    #[test]
    fn refresh_registry_schedules_refresh_and_retry() {
        let registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(10),
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
        );
        let now = std::time::Instant::now();
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            )],
        );

        registry.record_success_at(&snapshot, now);
        assert!(
            registry
                .start_due_refreshes(now + std::time::Duration::from_secs(3599))
                .is_empty()
        );
        assert_eq!(
            registry.start_due_refreshes(now + std::time::Duration::from_secs(3600)),
            vec![origin.clone()]
        );
        assert!(
            registry
                .start_due_refreshes(now + std::time::Duration::from_secs(3601))
                .is_empty()
        );

        registry.record_failure_at(
            &origin,
            Some(Arc::new(snapshot)),
            now + std::time::Duration::from_secs(3600),
        );
        assert!(
            registry
                .start_due_refreshes(now + std::time::Duration::from_secs(4199))
                .is_empty()
        );
        assert_eq!(
            registry.start_due_refreshes(now + std::time::Duration::from_secs(4200)),
            vec![origin]
        );
    }

    #[test]
    fn refresh_registry_snapshots_scheduler_metrics() {
        let registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(180),
        );
        let now = std::time::Instant::now();
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            )],
        );

        registry.record_success_at_with_timestamp(&snapshot, now, 1_700_000_000);
        let status = registry
            .snapshots_by_zone()
            .remove(&origin.canonical_key())
            .expect("zone refresh status");
        assert_eq!(status.last_success_unix_secs, Some(1_700_000_000));
        assert_eq!(status.next_refresh_unix_secs, Some(1_700_003_600));
        assert_eq!(status.failures_since_success, 0);

        registry.record_failure_at_with_timestamp(
            &origin,
            Some(Arc::new(snapshot.clone())),
            now + std::time::Duration::from_secs(3600),
            1_700_003_600,
        );
        let status = registry
            .snapshots_by_zone()
            .remove(&origin.canonical_key())
            .expect("zone refresh status");
        assert_eq!(status.last_success_unix_secs, Some(1_700_000_000));
        assert_eq!(status.next_refresh_unix_secs, Some(1_700_004_200));
        assert_eq!(status.failures_since_success, 1);

        registry.record_success_at_with_timestamp(
            &snapshot,
            now + std::time::Duration::from_secs(4200),
            1_700_004_200,
        );
        let status = registry
            .snapshots_by_zone()
            .remove(&origin.canonical_key())
            .expect("zone refresh status");
        assert_eq!(status.last_success_unix_secs, Some(1_700_004_200));
        assert_eq!(status.next_refresh_unix_secs, Some(1_700_007_800));
        assert_eq!(status.failures_since_success, 0);
    }

    #[test]
    fn refresh_registry_applies_initial_load_exponential_backoff() {
        let registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(180),
        );
        let now = std::time::Instant::now();
        let origin = DomainName::from_absolute_str("example.test.").unwrap();

        registry.record_failure_at(&origin, None, now);
        assert!(
            registry
                .start_due_refreshes(now + std::time::Duration::from_secs(59))
                .is_empty()
        );
        assert_eq!(
            registry.start_due_refreshes(now + std::time::Duration::from_secs(60)),
            vec![origin.clone()]
        );

        registry.record_failure_at(&origin, None, now + std::time::Duration::from_secs(60));
        assert!(
            registry
                .start_due_refreshes(now + std::time::Duration::from_secs(179))
                .is_empty()
        );
        assert_eq!(
            registry.start_due_refreshes(now + std::time::Duration::from_secs(180)),
            vec![origin.clone()]
        );

        registry.record_failure_at(&origin, None, now + std::time::Duration::from_secs(180));
        assert!(
            registry
                .start_due_refreshes(now + std::time::Duration::from_secs(359))
                .is_empty()
        );
        assert_eq!(
            registry.start_due_refreshes(now + std::time::Duration::from_secs(360)),
            vec![origin]
        );
    }

    #[test]
    fn refresh_registry_expires_zone_once() {
        let registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
        );
        let now = std::time::Instant::now();
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            )],
        );

        registry.record_success_at(&snapshot, now);
        assert!(
            registry
                .expire_due_zones(now + std::time::Duration::from_secs(604799))
                .is_empty()
        );
        assert_eq!(
            registry.expire_due_zones(now + std::time::Duration::from_secs(604800)),
            vec![origin]
        );
        assert!(
            registry
                .expire_due_zones(now + std::time::Duration::from_secs(604801))
                .is_empty()
        );
    }

    #[test]
    fn ixfr_cooldown_registry_disables_until_cooldown_expires() {
        let registry = IxfrCooldownRegistry::new(std::time::Duration::from_secs(60));
        let zone = DomainName::from_absolute_str("example.test.").unwrap();
        let primary = "192.0.2.53:53".parse().unwrap();
        let now = std::time::Instant::now();

        assert!(!registry.is_disabled_at(&zone, primary, now));
        registry.record_unsupported_at(&zone, primary, now);
        assert!(registry.is_disabled_at(&zone, primary, now + std::time::Duration::from_secs(59)));
        assert!(!registry.is_disabled_at(&zone, primary, now + std::time::Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn notify_refresh_worker_publishes_requested_refresh() {
        let primary = spawn_ixfr_mode2_primary_with_serial(2).await;
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
        let transfer_plan = TransferPlan::from_config(&config);
        let zones = ZoneStore::new();
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        zones.insert_snapshot(ZoneSnapshot::active(
            apex.clone(),
            Some(1),
            vec![Rrset::new(
                apex.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata_with_serial(1)],
            )],
        ));
        let (tx, rx) = mpsc::channel(1);
        tx.send(RefreshRequest {
            zone: apex,
            requested_serial: Some(2),
            reason: super::RefreshReason::Notify,
        })
        .await
        .unwrap();
        drop(tx);
        let metrics = RuntimeMetrics::new();

        serve_refresh_requests(
            rx,
            zones.clone(),
            transfer_plan,
            ZoneRefreshRegistry::without_jitter(
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
            ),
            IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
            metrics.clone(),
            RefreshWorkerSettings {
                axfr_timeout: std::time::Duration::from_secs(5),
                ixfr_timeout: std::time::Duration::from_secs(5),
                transfer_limit: Arc::new(tokio::sync::Semaphore::new(4)),
            },
        )
        .await
        .unwrap();

        let snapshot = zones
            .get("example.test.")
            .expect("published refreshed snapshot");
        assert_eq!(snapshot.state, ZoneState::Active);
        assert_eq!(snapshot.serial, Some(2));
        assert_eq!(
            metrics.snapshot(),
            super::RuntimeMetricsSnapshot {
                queries_received: 0,
                queries_truncated: 0,
                queries_cname_chain_limit: 0,
                queries_cname_loop: 0,
                axfr_started: 0,
                axfr_succeeded: 0,
                axfr_failed: 0,
                ixfr_started: 1,
                ixfr_succeeded: 1,
                ixfr_failed: 0,
            }
        );
    }

    #[tokio::test]
    async fn notify_refresh_worker_honors_transfer_concurrency_limit() {
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let alpha_primary = spawn_barrier_ixfr_mode2_primary("alpha.test.", barrier.clone()).await;
        let beta_primary = spawn_barrier_ixfr_mode2_primary("beta.test.", barrier.clone()).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_concurrent_transfers = 2

                [[zones]]
                name = "alpha.test."
                primaries = ["{alpha_primary}"]

                [[zones]]
                name = "beta.test."
                primaries = ["{beta_primary}"]
            "#
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config);
        let zones = ZoneStore::new();
        for zone in ["alpha.test.", "beta.test."] {
            let apex = DomainName::from_absolute_str(zone).unwrap();
            zones.insert_snapshot(ZoneSnapshot::active(
                apex.clone(),
                Some(1),
                vec![Rrset::new(
                    apex.clone(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata_with_serial(1)],
                )],
            ));
        }
        let (tx, rx) = mpsc::channel(2);
        for zone in ["alpha.test.", "beta.test."] {
            tx.send(RefreshRequest {
                zone: DomainName::from_absolute_str(zone).unwrap(),
                requested_serial: Some(2),
                reason: super::RefreshReason::Notify,
            })
            .await
            .unwrap();
        }
        drop(tx);

        let worker = tokio::spawn(serve_refresh_requests(
            rx,
            zones.clone(),
            transfer_plan,
            ZoneRefreshRegistry::without_jitter(
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
            ),
            IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
            RuntimeMetrics::new(),
            RefreshWorkerSettings {
                axfr_timeout: std::time::Duration::from_secs(5),
                ixfr_timeout: std::time::Duration::from_secs(5),
                transfer_limit: Arc::new(tokio::sync::Semaphore::new(2)),
            },
        ));

        tokio::time::timeout(std::time::Duration::from_secs(1), barrier.wait())
            .await
            .expect("both refresh transfers should start before either completes");
        worker.await.unwrap().unwrap();

        assert_eq!(
            zones.get("alpha.test.").expect("alpha zone").serial,
            Some(2)
        );
        assert_eq!(zones.get("beta.test.").expect("beta zone").serial, Some(2));
    }

    #[tokio::test]
    async fn refresh_skips_axfr_when_soa_poll_confirms_current_serial() {
        let primary = spawn_soa_primary_with_serial(2).await;
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
        let transfer_plan = TransferPlan::from_config(&config);
        let plan = transfer_plan
            .get(&DomainName::from_absolute_str("example.test.").unwrap())
            .expect("zone transfer plan");
        let zones = ZoneStore::new();
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        zones.insert_snapshot(ZoneSnapshot::active(
            apex.clone(),
            Some(2),
            vec![Rrset::new(
                apex.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata_with_serial(2)],
            )],
        ));
        let metrics = RuntimeMetrics::new();
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

        let snapshot = refresh_zone_from_primaries(
            &zones,
            &plan,
            None,
            RefreshAttemptContext {
                ixfr_cooldowns: &ixfr_cooldowns,
                metrics: &metrics,
                ixfr_timeout: std::time::Duration::from_secs(5),
                axfr_timeout: std::time::Duration::from_secs(5),
                reason: "test",
            },
        )
        .await
        .expect("refresh success");

        assert_eq!(snapshot.serial, Some(2));
        assert!(
            zones
                .get("example.test.")
                .expect("unchanged zone snapshot")
                .lookup(
                    &DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers
                .is_empty()
        );
    }

    #[tokio::test]
    async fn refresh_signs_axfr_query_when_zone_has_tsig_key() {
        let (primary, observed_query) = spawn_axfr_primary_recording_query(1).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
                tsig_key = "transfer-key."
            "#
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config);
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        assert!(plan.tsig_key.is_some());
        let zones = ZoneStore::new();
        let metrics = RuntimeMetrics::new();
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

        let snapshot = refresh_zone_from_primaries(
            &zones,
            &plan,
            None,
            RefreshAttemptContext {
                ixfr_cooldowns: &ixfr_cooldowns,
                metrics: &metrics,
                ixfr_timeout: std::time::Duration::from_secs(5),
                axfr_timeout: std::time::Duration::from_secs(5),
                reason: "test",
            },
        )
        .await
        .expect("refresh success");

        assert_eq!(snapshot.serial, Some(1));
        let query = observed_query
            .lock()
            .expect("observed query lock poisoned")
            .clone()
            .expect("primary observed query");
        assert_eq!(query_qtype(&query), RecordType::Axfr as u16);
        assert_query_has_tsig(&query, "transfer-key.", "hmac-sha256.");
    }

    #[tokio::test]
    async fn refresh_uses_axfr_during_ixfr_disabled_cooldown() {
        let (primary, qtypes) = spawn_ixfr_notimp_then_axfr_primary().await;
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
        let transfer_plan = TransferPlan::from_config(&config);
        let plan = transfer_plan
            .get(&DomainName::from_absolute_str("example.test.").unwrap())
            .expect("zone transfer plan");
        let zones = ZoneStore::new();
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        zones.insert_snapshot(ZoneSnapshot::active(
            apex.clone(),
            Some(1),
            vec![Rrset::new(
                apex.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata_with_serial(1)],
            )],
        ));
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
        let metrics = RuntimeMetrics::new();

        let first = refresh_zone_from_primaries(
            &zones,
            &plan,
            Some(2),
            RefreshAttemptContext {
                ixfr_cooldowns: &ixfr_cooldowns,
                metrics: &metrics,
                ixfr_timeout: std::time::Duration::from_secs(5),
                axfr_timeout: std::time::Duration::from_secs(5),
                reason: "test",
            },
        )
        .await
        .expect("first refresh succeeds via AXFR fallback");
        assert_eq!(first.serial, Some(2));

        let second = refresh_zone_from_primaries(
            &zones,
            &plan,
            Some(3),
            RefreshAttemptContext {
                ixfr_cooldowns: &ixfr_cooldowns,
                metrics: &metrics,
                ixfr_timeout: std::time::Duration::from_secs(5),
                axfr_timeout: std::time::Duration::from_secs(5),
                reason: "test",
            },
        )
        .await
        .expect("second refresh skips IXFR and succeeds via AXFR");
        assert_eq!(second.serial, Some(3));

        assert_eq!(
            *qtypes.lock().expect("qtype log lock poisoned"),
            vec![
                RecordType::Ixfr as u16,
                RecordType::Axfr as u16,
                RecordType::Axfr as u16
            ]
        );
        assert_eq!(
            metrics.snapshot(),
            super::RuntimeMetricsSnapshot {
                queries_received: 0,
                queries_truncated: 0,
                queries_cname_chain_limit: 0,
                queries_cname_loop: 0,
                axfr_started: 2,
                axfr_succeeded: 2,
                axfr_failed: 0,
                ixfr_started: 1,
                ixfr_succeeded: 0,
                ixfr_failed: 1,
            }
        );
    }

    #[tokio::test]
    async fn scheduled_refresh_worker_expires_zone_and_enqueues_refresh() {
        let zones = ZoneStore::new();
        let registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
        );
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            )],
        );
        zones.insert_snapshot(snapshot.clone());
        registry.record_success_at(
            &snapshot,
            std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(604800))
                .unwrap(),
        );
        let (tx, mut rx) = mpsc::channel(1);
        let worker = tokio::spawn(serve_scheduled_refreshes(
            zones.clone(),
            registry,
            tx,
            std::time::Duration::from_millis(1),
        ));

        let request = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("scheduled refresh should be enqueued")
            .expect("scheduled refresh request");

        assert_eq!(request.zone, origin);
        assert_eq!(request.reason, super::RefreshReason::Scheduled);
        assert_eq!(
            zones.find_exact_zone(&origin).expect("expired zone").state,
            ZoneState::Expired
        );
        worker.abort();
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

        let transfer_plan = TransferPlan::from_config(&config);
        let runtime = Runtime::new(config);
        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
        );
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
        let metrics = RuntimeMetrics::new();
        runtime
            .load_initial_zones(
                &transfer_plan,
                &refresh_registry,
                &ixfr_cooldowns,
                4,
                &metrics,
            )
            .await;

        let snapshot = runtime
            .zones
            .get("example.test.")
            .expect("published zone snapshot");
        assert_eq!(snapshot.state, ZoneState::Active);
        assert_eq!(
            metrics.snapshot(),
            super::RuntimeMetricsSnapshot {
                queries_received: 0,
                queries_truncated: 0,
                queries_cname_chain_limit: 0,
                queries_cname_loop: 0,
                axfr_started: 1,
                axfr_succeeded: 1,
                axfr_failed: 0,
                ixfr_started: 0,
                ixfr_succeeded: 0,
                ixfr_failed: 0,
            }
        );
    }

    #[tokio::test]
    async fn runtime_initial_load_honors_transfer_concurrency_limit() {
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let alpha_primary = spawn_barrier_axfr_primary("alpha.test.", barrier.clone()).await;
        let beta_primary = spawn_barrier_axfr_primary("beta.test.", barrier.clone()).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [limits]
                max_concurrent_transfers = 2

                [[zones]]
                name = "alpha.test."
                primaries = ["{alpha_primary}"]

                [[zones]]
                name = "beta.test."
                primaries = ["{beta_primary}"]
            "#
        ))
        .expect("valid config");

        let transfer_plan = TransferPlan::from_config(&config);
        let runtime = Runtime::new(config);
        let zones = runtime.zones.clone();
        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
        );
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
        let loader = tokio::spawn(async move {
            let metrics = RuntimeMetrics::new();
            runtime
                .load_initial_zones(
                    &transfer_plan,
                    &refresh_registry,
                    &ixfr_cooldowns,
                    2,
                    &metrics,
                )
                .await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(1), barrier.wait())
            .await
            .expect("both initial transfers should start before either completes");
        loader.await.unwrap();

        assert_eq!(
            zones.get("alpha.test.").expect("alpha zone").state,
            ZoneState::Active
        );
        assert_eq!(
            zones.get("beta.test.").expect("beta zone").state,
            ZoneState::Active
        );
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
                NotifyAuthority::default(),
                NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
                notify_refresh_tx(),
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
                NotifyAuthority::default(),
                NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
                notify_refresh_tx(),
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
                NotifyAuthority::default(),
                NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
                notify_refresh_tx(),
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
                std::time::Duration::from_millis(25),
                std::time::Duration::from_secs(5),
                0,
                AnyResponseMode::Minimal,
                NotifyAuthority::default(),
                NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
                notify_refresh_tx(),
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

        let completed =
            write_tcp_message(&mut writer, &response, std::time::Duration::from_millis(25))
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
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                0,
                AnyResponseMode::Minimal,
                NotifyAuthority::default(),
                NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
                notify_refresh_tx(),
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
                notify_authority: NotifyAuthority::default(),
                notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
                notify_refresh_tx: notify_refresh_tx(),
                metrics: RuntimeMetrics::new(),
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
        spawn_axfr_primary_with_serial(1).await
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

            let response = axfr_response(header.id, serial);
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

            let response = axfr_response_for_zone(header.id, zone, 2);
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

    fn axfr_response(qid: u16, serial: u32) -> Vec<u8> {
        axfr_response_for_zone(qid, "example.test.", serial)
    }

    fn axfr_response_for_zone(qid: u16, zone: &str, serial: u32) -> Vec<u8> {
        let soa = record(zone, RecordType::Soa as u16, soa_rdata_with_serial(serial));
        let owner = format!("www.{zone}");
        let a = record(&owner, RecordType::A as u16, vec![192, 0, 2, 10]);
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

    fn notify_response(qid: u16) -> Vec<u8> {
        let qname = DomainName::from_absolute_str("example.test.").unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&qid.to_be_bytes());
        response.extend_from_slice(
            &(0x8000u16 | ((Opcode::Notify as u16) << 11) | 0x0400).to_be_bytes(),
        );
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&qname.to_wire());
        response.extend_from_slice(&(RecordType::Soa as u16).to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
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

    async fn read_framed_tcp_response(stream: &mut TcpStream) -> Vec<u8> {
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let response_len = u16::from_be_bytes(length_prefix) as usize;
        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response).await.unwrap();
        response
    }

    async fn http_request(addr: std::net::SocketAddr, method: &str, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
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
        response
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

    async fn unused_tcp_addr() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    async fn unused_udp_addr() -> std::net::SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        addr
    }

    fn health_state(zones: ZoneStore) -> HealthEndpointState {
        HealthEndpointState {
            zones,
            runtime_status: RuntimeStatus::new(),
            metrics: RuntimeMetrics::new(),
            refresh_registry: ZoneRefreshRegistry::without_jitter(
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(3600),
            ),
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

    fn soa_rdata_with_serial(serial: u32) -> Vec<u8> {
        let mut rdata = b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec();
        let (_, consumed_mname) = DomainName::parse(&rdata, 0).unwrap();
        let (_, consumed_rname) = DomainName::parse(&rdata, consumed_mname).unwrap();
        let serial_offset = consumed_mname + consumed_rname;
        rdata[serial_offset..serial_offset + 4].copy_from_slice(&serial.to_be_bytes());
        rdata
    }
}
