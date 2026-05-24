use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinSet,
};
use tracing::{debug, info, warn};
use oxidedns_core::{
    ServerConfig,
    axfr::{self, AxfrError},
    dns::{
        AnswerOptions, AnyResponseMode, DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS, DatagramAction,
        DomainName, Transport, answer_message_with_notify_hooks,
    },
    zone::{SoaTimers, ZoneSnapshot, ZoneStore},
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

const NOTIFY_REFRESH_QUEUE_CAPACITY: usize = 1024;
const ZSM_SCHEDULER_TICK: Duration = Duration::from_secs(1);

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
        let transfer_plan = TransferPlan::from_config(&self.config);
        let refresh_registry = ZoneRefreshRegistry::new(
            Duration::from_secs(self.config.limits.zsm_min_interval_secs),
            Duration::from_secs(self.config.limits.zsm_initial_retry_secs),
            Duration::from_secs(self.config.limits.zsm_initial_retry_max_secs),
        );
        self.load_initial_zones(&refresh_registry).await;

        info!(
            udp_listeners = self.config.server.listen_udp.len(),
            tcp_listeners = self.config.server.listen_tcp.len(),
            zones = self.zones.len(),
            "OxideDNS runtime initialized"
        );

        let mut listeners = JoinSet::new();
        let notify_authority = NotifyAuthority::from_config(&self.config);
        let notify_refresh =
            NotifyRefreshTracker::new(Duration::from_secs(self.config.limits.notify_dedup_secs));
        let (notify_refresh_tx, notify_refresh_rx) = mpsc::channel(NOTIFY_REFRESH_QUEUE_CAPACITY);
        listeners.spawn(serve_refresh_requests(
            notify_refresh_rx,
            self.zones.clone(),
            transfer_plan.clone(),
            refresh_registry.clone(),
            Duration::from_secs(self.config.limits.axfr_timeout_secs),
        ));
        listeners.spawn(serve_scheduled_refreshes(
            self.zones.clone(),
            refresh_registry.clone(),
            notify_refresh_tx.clone(),
            ZSM_SCHEDULER_TICK,
        ));
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
            let udp_settings = UdpServerSettings {
                max_udp_payload,
                max_cname_chain,
                edns_padding_block_size,
                any_response,
                notify_authority,
                notify_refresh,
                notify_refresh_tx,
            };
            listeners.spawn(async move { serve_udp(socket, zones, udp_settings).await });
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
                notify_authority: notify_authority.clone(),
                notify_refresh: notify_refresh.clone(),
                notify_refresh_tx: notify_refresh_tx.clone(),
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

    async fn load_initial_zones(&self, refresh_registry: &ZoneRefreshRegistry) {
        for zone in &self.config.zones {
            let zone_apex = DomainName::from_absolute_str(&zone.name)
                .expect("configuration validation rejects invalid zone names");
            let plan = ZoneTransferPlan {
                origin: zone_apex,
                qclass: 1,
                primaries: zone.primaries.clone(),
            };

            if let Some(snapshot) = refresh_zone_from_primaries(
                &self.zones,
                &plan,
                Duration::from_secs(self.config.limits.axfr_timeout_secs),
                "initial",
            )
            .await
            {
                refresh_registry.record_success(&snapshot);
            } else {
                let zone_apex = &plan.origin;
                refresh_registry.record_failure(zone_apex, self.zones.find_exact_zone(zone_apex));
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
        match answer_message_with_notify_hooks(
            &buffer[..len],
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

#[derive(Clone)]
struct UdpServerSettings {
    max_udp_payload: u16,
    max_cname_chain: usize,
    edns_padding_block_size: u16,
    any_response: AnyResponseMode,
    notify_authority: NotifyAuthority,
    notify_refresh: NotifyRefreshTracker,
    notify_refresh_tx: mpsc::Sender<RefreshRequest>,
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
                peer.ip(),
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
    notify_authority: NotifyAuthority,
    notify_refresh: NotifyRefreshTracker,
    notify_refresh_tx: mpsc::Sender<RefreshRequest>,
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
}

#[derive(Debug, Clone)]
struct TransferPlan {
    zones_by_key: Arc<HashMap<String, ZoneTransferPlan>>,
}

impl TransferPlan {
    fn from_config(config: &ServerConfig) -> Self {
        let zones_by_key = config
            .zones
            .iter()
            .map(|zone| {
                let origin = DomainName::from_absolute_str(&zone.name)
                    .expect("configuration validation rejects invalid zone names");
                (
                    origin.canonical_key(),
                    ZoneTransferPlan {
                        origin,
                        qclass: 1,
                        primaries: zone.primaries.clone(),
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
    statuses: Arc<Mutex<HashMap<String, ZoneRefreshStatus>>>,
}

#[derive(Debug, Clone)]
struct ZoneRefreshStatus {
    origin: DomainName,
    soa_timers: Option<SoaTimers>,
    next_refresh: Option<Instant>,
    expire_at: Option<Instant>,
    initial_failure_count: u32,
    in_progress: bool,
    expired: bool,
}

impl ZoneRefreshRegistry {
    fn new(min_interval: Duration, initial_retry: Duration, initial_retry_max: Duration) -> Self {
        Self {
            min_interval,
            initial_retry,
            initial_retry_max,
            statuses: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn record_success(&self, snapshot: &ZoneSnapshot) {
        self.record_success_at(snapshot, Instant::now());
    }

    fn record_success_at(&self, snapshot: &ZoneSnapshot, now: Instant) {
        let timers = snapshot.soa_timers;
        let next_refresh = timers.map(|timers| now + self.effective_interval(timers.refresh));
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
                next_refresh,
                expire_at,
                initial_failure_count: 0,
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
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        let status = statuses
            .entry(origin.canonical_key())
            .or_insert_with(|| ZoneRefreshStatus {
                origin: origin.clone(),
                soa_timers: current.as_ref().and_then(|snapshot| snapshot.soa_timers),
                next_refresh: None,
                expire_at: None,
                initial_failure_count: 0,
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
        Duration::from_secs(seconds as u64).max(self.min_interval)
    }

    fn initial_retry_delay(&self, failure_count: u32) -> Duration {
        let multiplier = 1u32.checked_shl(failure_count.min(31)).unwrap_or(u32::MAX);
        self.initial_retry
            .saturating_mul(multiplier)
            .min(self.initial_retry_max)
    }
}

#[derive(Debug, Clone, Default)]
struct NotifyAuthority {
    sources_by_zone: Arc<HashMap<String, HashSet<IpAddr>>>,
}

impl NotifyAuthority {
    fn from_config(config: &ServerConfig) -> Self {
        let mut sources_by_zone = HashMap::new();
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
        }

        Self {
            sources_by_zone: Arc::new(sources_by_zone),
        }
    }

    fn is_authorized(&self, qname: &DomainName, qclass: u16, source: IpAddr) -> bool {
        qclass == 1
            && self
                .sources_by_zone
                .get(&qname.canonical_key())
                .is_some_and(|sources| sources.contains(&source))
    }
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
    axfr_timeout: Duration,
) -> Result<(), RuntimeError> {
    while let Some(request) = refresh_rx.recv().await {
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

        match refresh_zone_from_primaries(&zones, &plan, axfr_timeout, request.reason.as_str())
            .await
        {
            Some(snapshot) => refresh_registry.record_success(&snapshot),
            None => {
                refresh_registry.record_failure(&request.zone, zones.find_exact_zone(&request.zone))
            }
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

async fn refresh_zone_from_primaries(
    zones: &ZoneStore,
    plan: &ZoneTransferPlan,
    axfr_timeout: Duration,
    reason: &str,
) -> Option<ZoneSnapshot> {
    for primary in &plan.primaries {
        let qid = transfer_query_id(&plan.origin, *primary);
        match transfer_axfr_from_primary(*primary, &plan.origin, plan.qclass, qid, axfr_timeout)
            .await
        {
            Ok(snapshot) => {
                let serial = snapshot.serial;
                zones.insert_snapshot(snapshot.clone());
                info!(
                    zone = %plan.origin,
                    %primary,
                    ?serial,
                    %reason,
                    "AXFR completed"
                );
                return Some(snapshot);
            }
            Err(error) => {
                warn!(
                    zone = %plan.origin,
                    %primary,
                    %error,
                    %reason,
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
    peer_ip: IpAddr,
) -> Result<(), RuntimeError> {
    while let Some(packet) = read_tcp_message(&mut stream, idle_timeout, read_timeout).await? {
        match answer_message_with_notify_hooks(
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
        sync::mpsc,
    };
    use oxidedns_core::{
        ServerConfig,
        axfr::frame_tcp_message,
        dns::{AnyResponseMode, DomainName, Header, RecordType},
        zone::{ResourceRecord, Rrset, ZoneSnapshot, ZoneState, ZoneStore},
    };

    use super::{
        NotifyAuthority, NotifyRefreshAction, NotifyRefreshTracker, RefreshRequest, Runtime,
        TcpServerSettings, TransferPlan, ZoneRefreshRegistry, handle_tcp_connection, serial_after,
        serve_refresh_requests, serve_scheduled_refreshes, serve_tcp, transfer_axfr_from_primary,
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

    #[test]
    fn serial_after_handles_wraparound() {
        assert!(serial_after(2, 1));
        assert!(serial_after(0, u32::MAX));
        assert!(!serial_after(1, 1));
        assert!(!serial_after(1, 2));
        assert!(!serial_after(0x8000_0001, 1));
    }

    #[test]
    fn refresh_registry_schedules_refresh_and_retry() {
        let registry = ZoneRefreshRegistry::new(
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
    fn refresh_registry_applies_initial_load_exponential_backoff() {
        let registry = ZoneRefreshRegistry::new(
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
        let registry = ZoneRefreshRegistry::new(
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

    #[tokio::test]
    async fn notify_refresh_worker_publishes_requested_refresh() {
        let primary = spawn_axfr_primary_with_serial(2).await;
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

        serve_refresh_requests(
            rx,
            zones.clone(),
            transfer_plan,
            ZoneRefreshRegistry::new(
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
            ),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();

        let snapshot = zones
            .get("example.test.")
            .expect("published refreshed snapshot");
        assert_eq!(snapshot.state, ZoneState::Active);
        assert_eq!(snapshot.serial, Some(2));
    }

    #[tokio::test]
    async fn scheduled_refresh_worker_expires_zone_and_enqueues_refresh() {
        let zones = ZoneStore::new();
        let registry = ZoneRefreshRegistry::new(
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

        let runtime = Runtime::new(config);
        let refresh_registry = ZoneRefreshRegistry::new(
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
        );
        runtime.load_initial_zones(&refresh_registry).await;

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
                NotifyAuthority::default(),
                NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
                notify_refresh_tx(),
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

    fn axfr_response(qid: u16, serial: u32) -> Vec<u8> {
        let soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(serial),
        );
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
