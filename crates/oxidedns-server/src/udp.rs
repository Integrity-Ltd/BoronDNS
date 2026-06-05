use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use oxidedns_core::{
    config::{UdpBackend, UdpIdleStrategy, UdpRuntime, XdpConfig},
    dns::{
        AnswerOptions, AnyResponseMode, ChaosOptions, DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
        DatagramAction, DnsCookieContext, DnsCookieRequestStatus, DomainName,
        ExtendedDnsErrorsMode, Header, LookupMetrics, LookupTermination, Opcode, Question, Rcode,
        RecordType, Transport, ZoneImageProvider,
        answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image,
        chaos_query_observation, default_zone_image_provider, dns_cookie_request_status,
        request_has_valid_dns_server_cookie,
    },
    zone::ZoneStore,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};
use tracing::{debug, info, warn};

#[cfg(feature = "af-xdp")]
use crate::af_xdp;
use crate::{
    CookiePrefixMetricSettings, DnsCookieRuntimeSettings, DnsCookieSecretStore, NotifyAuthority,
    NotifyLogLimiter, NotifyRefreshTracker, QueryLatencyCategory, QueryPipelineStage,
    RefreshRequest, ResponseCacheCandidateCategory, ResponseCacheIneligibleReason, RrlDecision,
    RrlLimiter, RuntimeError, RuntimeMetrics, dns_cookie_context,
    prepare_notify_packet_with_metrics, prepare_query_tsig_packet, response_opt_record,
    response_question_end, response_record_type, sign_tsig_response, signal_notify_refresh,
    std_udp_mmsg, std_udp_socket,
};

pub(crate) enum BoundUdpListener {
    Std {
        socket: UdpSocket,
        worker_id: usize,
        worker_count: usize,
        cpu_affinity: Option<usize>,
    },
    #[cfg(feature = "af-xdp")]
    AfXdp(af_xdp::AfXdpPacketIo),
}

pub(crate) async fn bind_udp_listeners(
    addr: SocketAddr,
    backend: UdpBackend,
    xdp: &XdpConfig,
    worker_count: usize,
    cpu_affinity: Option<&[usize]>,
    socket_receive_buffer_bytes: Option<usize>,
    socket_send_buffer_bytes: Option<usize>,
) -> Result<Vec<BoundUdpListener>, RuntimeError> {
    match backend {
        UdpBackend::Std => bind_std_udp_listeners(
            addr,
            worker_count,
            cpu_affinity,
            socket_receive_buffer_bytes,
            socket_send_buffer_bytes,
        )
        .map_err(|source| RuntimeError::BindUdp { addr, source }),
        UdpBackend::AfXdp => {
            let socket = UdpSocket::bind(addr)
                .await
                .map_err(|source| RuntimeError::BindUdp { addr, source })?;
            bind_af_xdp_udp_listener(socket, xdp).map(|listener| vec![listener])
        }
    }
}

fn bind_std_udp_listeners(
    addr: SocketAddr,
    worker_count: usize,
    cpu_affinity: Option<&[usize]>,
    socket_receive_buffer_bytes: Option<usize>,
    socket_send_buffer_bytes: Option<usize>,
) -> std::io::Result<Vec<BoundUdpListener>> {
    let worker_count = worker_count.max(1);
    let reuseport = worker_count > 1;
    let mut listeners = Vec::with_capacity(worker_count);
    let mut bind_addr = addr;
    for worker_id in 0..worker_count {
        let socket = std_udp_socket::bind(
            bind_addr,
            reuseport,
            socket_receive_buffer_bytes,
            socket_send_buffer_bytes,
        )?;
        if worker_id == 0 {
            bind_addr = socket.local_addr()?;
        }
        listeners.push(BoundUdpListener::Std {
            socket,
            worker_id,
            worker_count,
            cpu_affinity: cpu_affinity.and_then(|cpus| cpus.get(worker_id)).copied(),
        });
    }
    Ok(listeners)
}

#[cfg(not(feature = "af-xdp"))]
fn bind_af_xdp_udp_listener(
    _socket: UdpSocket,
    _xdp: &XdpConfig,
) -> Result<BoundUdpListener, RuntimeError> {
    Err(RuntimeError::UdpBackendUnavailable {
        backend: "af_xdp",
        reason: "oxidedns-server was built without the af-xdp feature",
    })
}

#[cfg(feature = "af-xdp")]
fn bind_af_xdp_udp_listener(
    socket: UdpSocket,
    xdp: &XdpConfig,
) -> Result<BoundUdpListener, RuntimeError> {
    af_xdp::AfXdpPacketIo::bind(socket, xdp)
        .map(BoundUdpListener::AfXdp)
        .map_err(RuntimeError::Udp)
}

pub(crate) async fn serve_bound_udp(
    listener: BoundUdpListener,
    zones: ZoneStore,
    settings: UdpServerSettings,
) -> Result<(), RuntimeError> {
    match listener {
        BoundUdpListener::Std {
            socket,
            worker_id,
            worker_count,
            cpu_affinity,
        } => {
            if settings.udp_runtime == UdpRuntime::Dedicated {
                return serve_dedicated_std_udp_worker(
                    socket,
                    zones,
                    settings,
                    worker_id,
                    worker_count,
                    cpu_affinity,
                )
                .await;
            }
            let packet_io = StdUdpBatchIo::new(socket, settings.udp_batch_size);
            serve_udp_packet_io(packet_io, zones, settings, worker_id, worker_count).await
        }
        #[cfg(feature = "af-xdp")]
        BoundUdpListener::AfXdp(packet_io) => {
            serve_udp_packet_io(packet_io, zones, settings, 0, 1).await
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn serve_udp(
    socket: UdpSocket,
    zones: ZoneStore,
    settings: UdpServerSettings,
) -> Result<(), RuntimeError> {
    match settings.udp_backend {
        UdpBackend::Std => {
            let packet_io = StdUdpBatchIo::new(socket, settings.udp_batch_size);
            serve_udp_packet_io(packet_io, zones, settings, 0, 1).await
        }
        UdpBackend::AfXdp => serve_af_xdp_udp(socket, zones, settings).await,
    }
}

#[cfg(not(feature = "af-xdp"))]
#[cfg_attr(not(test), allow(dead_code))]
async fn serve_af_xdp_udp(
    _socket: UdpSocket,
    _zones: ZoneStore,
    settings: UdpServerSettings,
) -> Result<(), RuntimeError> {
    let _xdp = &settings.xdp;
    Err(RuntimeError::UdpBackendUnavailable {
        backend: "af_xdp",
        reason: "oxidedns-server was built without the af-xdp feature",
    })
}

#[cfg(feature = "af-xdp")]
#[cfg_attr(not(test), allow(dead_code))]
async fn serve_af_xdp_udp(
    socket: UdpSocket,
    zones: ZoneStore,
    settings: UdpServerSettings,
) -> Result<(), RuntimeError> {
    let packet_io =
        af_xdp::AfXdpPacketIo::bind(socket, &settings.xdp).map_err(RuntimeError::Udp)?;
    serve_udp_packet_io(packet_io, zones, settings, 0, 1).await
}

async fn serve_udp_packet_io<I>(
    mut packet_io: I,
    zones: ZoneStore,
    settings: UdpServerSettings,
    udp_worker_id: usize,
    udp_worker_count: usize,
) -> Result<(), RuntimeError>
where
    I: PacketIo,
{
    let local_addr = packet_io.local_addr().map_err(RuntimeError::Udp)?;
    info!(%local_addr, udp_worker_id, udp_worker_count, "UDP listener bound");

    loop {
        let outbound = {
            let inbound = packet_io.recv_batch().await.map_err(RuntimeError::Udp)?;
            settings.metrics.record_udp_receive_batch(inbound.len());

            let mut outbound = Vec::with_capacity(inbound.len());
            for packet in inbound {
                if let Some(response) =
                    handle_udp_datagram(packet.payload(), packet.peer, &zones, &settings)
                {
                    outbound.push(response.with_target(packet.target()));
                }
            }
            outbound
        };
        packet_io
            .send_batch(&outbound, &settings.metrics)
            .await
            .map_err(RuntimeError::Udp)?;
    }
}

async fn serve_dedicated_std_udp_worker(
    socket: UdpSocket,
    zones: ZoneStore,
    settings: UdpServerSettings,
    worker_id: usize,
    worker_count: usize,
    cpu_affinity: Option<usize>,
) -> Result<(), RuntimeError> {
    let socket = socket.into_std().map_err(RuntimeError::Udp)?;
    socket.set_nonblocking(true).map_err(RuntimeError::Udp)?;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (result_tx, result_rx) = oneshot::channel();
    let thread_stop = stop.clone();
    let thread_name = format!("oxidedns-udp-{worker_id}");
    let handle = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            let result = run_dedicated_std_udp_worker(
                socket,
                zones,
                settings,
                thread_stop,
                worker_id,
                worker_count,
                cpu_affinity,
            );
            let _ = result_tx.send(result);
        })
        .map_err(RuntimeError::Udp)?;
    let thread = handle.thread().clone();
    let mut guard = DedicatedUdpWorkerGuard {
        stop,
        thread,
        handle: Some(handle),
    };

    let result = match result_rx.await {
        Ok(result) => result,
        Err(_) => Err(RuntimeError::Udp(std::io::Error::other(
            "dedicated UDP worker exited without reporting status",
        ))),
    };
    if let Some(handle) = guard.handle.take()
        && handle.join().is_err()
    {
        return Err(RuntimeError::Udp(std::io::Error::other(
            "dedicated UDP worker panicked",
        )));
    }
    result
}

struct DedicatedUdpWorkerGuard {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::Thread,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for DedicatedUdpWorkerGuard {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        self.thread.unpark();
    }
}

fn run_dedicated_std_udp_worker(
    socket: std::net::UdpSocket,
    zones: ZoneStore,
    settings: UdpServerSettings,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker_id: usize,
    worker_count: usize,
    cpu_affinity: Option<usize>,
) -> Result<(), RuntimeError> {
    if let Some(cpu) = cpu_affinity {
        std_udp_socket::pin_current_thread_to_cpu(cpu).map_err(RuntimeError::Udp)?;
        info!(
            worker_id,
            worker_count, cpu, "dedicated UDP worker CPU affinity applied"
        );
    }
    let local_addr = socket.local_addr().map_err(RuntimeError::Udp)?;
    info!(%local_addr, worker_id, worker_count, "dedicated UDP worker bound");

    let batch_size = settings.udp_batch_size.max(1);
    let mut inbound = (0..batch_size)
        .map(|_| UdpInbound::new())
        .collect::<Vec<_>>();
    let mut outbound = Vec::with_capacity(batch_size);
    let mut packet_io = std_udp_mmsg::StdUdpMmsg::new(batch_size);
    let mut idle_spins = 0usize;

    while !stop.load(std::sync::atomic::Ordering::Acquire) {
        let active = match packet_io.recv_batch(&socket, &mut inbound) {
            Ok(0) => {
                idle_dedicated_udp_worker(&mut idle_spins, settings.udp_idle_strategy);
                continue;
            }
            Ok(active) => active,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                idle_dedicated_udp_worker(&mut idle_spins, settings.udp_idle_strategy);
                continue;
            }
            Err(error) => return Err(RuntimeError::Udp(error)),
        };
        idle_spins = 0;
        settings.metrics.record_udp_receive_batch(active);
        settings
            .metrics
            .record_udp_worker_receive_batch(worker_id, active);

        outbound.clear();
        for packet in &inbound[..active] {
            if let Some(response) =
                handle_udp_datagram(packet.payload(), packet.peer, &zones, &settings)
            {
                outbound.push(response.with_target(packet.target()));
            }
        }
        send_std_udp_batch(
            &mut packet_io,
            &socket,
            &outbound,
            worker_id,
            &settings.metrics,
        )?;
        settings
            .metrics
            .record_udp_mmsg_stats(packet_io.take_stats());
    }

    Ok(())
}

fn send_std_udp_batch(
    packet_io: &mut std_udp_mmsg::StdUdpMmsg,
    socket: &std::net::UdpSocket,
    outbound: &[UdpOutbound],
    worker_id: usize,
    metrics: &RuntimeMetrics,
) -> Result<(), RuntimeError> {
    if outbound.is_empty() {
        return Ok(());
    }

    if !metrics.pipeline_timing_enabled() {
        let sent = packet_io
            .send_batch(socket, outbound)
            .map_err(RuntimeError::Udp)?;
        metrics.record_udp_send_batch(sent);
        metrics.record_udp_worker_send_batch(worker_id, sent);
        return Ok(());
    }

    let send_started = outbound
        .iter()
        .map(|packet| packet.query_metrics.as_ref().map(|_| Instant::now()))
        .collect::<Vec<_>>();
    let sent = packet_io
        .send_batch(socket, outbound)
        .map_err(RuntimeError::Udp)?;

    for (packet, started) in outbound.iter().zip(send_started).take(sent) {
        if let (Some(query_metrics), Some(started)) = (&packet.query_metrics, started) {
            record_query_send_metric(query_metrics, &packet.response, metrics, started.elapsed());
        }
    }
    metrics.record_udp_send_batch(sent);
    metrics.record_udp_worker_send_batch(worker_id, sent);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn send_std_udp_batch_fallback(
    socket: &std::net::UdpSocket,
    outbound: &[UdpOutbound],
) -> std::io::Result<usize> {
    let mut sent = 0usize;
    for packet in outbound {
        let peer = match packet.target {
            UdpPacketTarget::Socket(peer) => peer,
            #[cfg(feature = "af-xdp")]
            UdpPacketTarget::AfXdp { .. } => {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "standard UDP backend cannot send AF_XDP packet target",
                ));
            }
        };
        let mut send_ok = false;
        for _ in 0..64 {
            match socket.send_to(&packet.response, peer) {
                Ok(_) => {
                    send_ok = true;
                    break;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                }
                Err(error) => return Err(error),
            }
        }
        if !send_ok {
            continue;
        }
        sent += 1;
    }
    Ok(sent)
}

fn idle_dedicated_udp_worker(idle_spins: &mut usize, strategy: UdpIdleStrategy) {
    match strategy {
        UdpIdleStrategy::Spin => std::hint::spin_loop(),
        UdpIdleStrategy::Park => {
            if *idle_spins < 64 {
                *idle_spins += 1;
                std::hint::spin_loop();
            } else {
                *idle_spins = 0;
                std::thread::park_timeout(Duration::from_micros(50));
            }
        }
    }
}

pub(crate) trait PacketIo {
    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    async fn recv_batch(&mut self) -> std::io::Result<&[UdpInbound]>;

    async fn send_batch(
        &mut self,
        outbound: &[UdpOutbound],
        metrics: &RuntimeMetrics,
    ) -> std::io::Result<()>;
}

pub(crate) struct StdUdpBatchIo {
    socket: UdpSocket,
    batch_size: usize,
    inbound: Vec<UdpInbound>,
}

pub(crate) struct UdpInbound {
    pub(crate) buffer: Vec<u8>,
    pub(crate) len: usize,
    pub(crate) peer: SocketAddr,
    pub(crate) target: UdpPacketTarget,
}

pub(crate) struct UdpOutbound {
    pub(crate) response: Vec<u8>,
    pub(crate) target: UdpPacketTarget,
    pub(crate) query_metrics: Option<QueryMetricObservation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpPacketTarget {
    Socket(SocketAddr),
    #[cfg(feature = "af-xdp")]
    AfXdp {
        frame_index: usize,
    },
}

impl StdUdpBatchIo {
    pub(crate) fn new(socket: UdpSocket, batch_size: usize) -> Self {
        let batch_size = batch_size.max(1);
        let inbound = (0..batch_size).map(|_| UdpInbound::new()).collect();
        Self {
            socket,
            batch_size,
            inbound,
        }
    }
}

impl PacketIo for StdUdpBatchIo {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    async fn recv_batch(&mut self) -> std::io::Result<&[UdpInbound]> {
        let (len, peer) = self.socket.recv_from(&mut self.inbound[0].buffer).await?;
        self.inbound[0].len = len;
        self.inbound[0].peer = peer;
        self.inbound[0].target = UdpPacketTarget::Socket(peer);
        let mut active = 1;

        while active < self.batch_size {
            match self.socket.try_recv_from(&mut self.inbound[active].buffer) {
                Ok((len, peer)) => {
                    self.inbound[active].len = len;
                    self.inbound[active].peer = peer;
                    self.inbound[active].target = UdpPacketTarget::Socket(peer);
                    active += 1;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        Ok(&self.inbound[..active])
    }

    #[allow(clippy::infallible_destructuring_match)]
    async fn send_batch(
        &mut self,
        outbound: &[UdpOutbound],
        metrics: &RuntimeMetrics,
    ) -> std::io::Result<()> {
        if outbound.is_empty() {
            return Ok(());
        }

        let mut sent = 0usize;
        for packet in outbound {
            let send_started = metrics
                .pipeline_timing_enabled()
                .then(|| packet.query_metrics.as_ref().map(|_| Instant::now()))
                .flatten();
            let peer = match packet.target {
                UdpPacketTarget::Socket(peer) => peer,
                #[cfg(feature = "af-xdp")]
                UdpPacketTarget::AfXdp { .. } => {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "standard UDP backend cannot send AF_XDP packet target",
                    ));
                }
            };
            self.socket.send_to(&packet.response, peer).await?;
            sent += 1;
            if let (Some(query_metrics), Some(started)) = (&packet.query_metrics, send_started) {
                record_query_send_metric(
                    query_metrics,
                    &packet.response,
                    metrics,
                    started.elapsed(),
                );
            }
        }
        metrics.record_udp_send_batch(sent);
        Ok(())
    }
}

impl UdpInbound {
    pub(crate) fn new() -> Self {
        Self {
            buffer: vec![0; UDP_PACKET_BUFFER_LEN],
            len: 0,
            peer: SocketAddr::from(([0, 0, 0, 0], 0)),
            target: UdpPacketTarget::Socket(SocketAddr::from(([0, 0, 0, 0], 0))),
        }
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.buffer[..self.len]
    }

    pub(crate) fn target(&self) -> UdpPacketTarget {
        self.target
    }
}

impl UdpOutbound {
    fn with_target(mut self, target: UdpPacketTarget) -> Self {
        self.target = target;
        self
    }
}

pub(crate) const UDP_PACKET_BUFFER_LEN: usize = 4096;

fn handle_udp_datagram(
    packet: &[u8],
    peer: SocketAddr,
    zones: &ZoneStore,
    settings: &UdpServerSettings,
) -> Option<UdpOutbound> {
    let peer_ip = peer.ip();
    let parse_started = settings.metrics.start_pipeline_timer();
    let Some(prepared) = prepare_notify_packet_with_metrics(
        packet,
        &settings.notify_authority,
        peer_ip,
        &settings.metrics,
        &settings.notify_log_limiter,
    ) else {
        debug!(
            peer_ip = %peer.ip(),
            peer_port = peer.port(),
            transport = "udp",
            bytes = packet.len(),
            "discarded DNS datagram"
        );
        return None;
    };
    let prepared = prepare_query_tsig_packet(prepared, &settings.notify_authority);
    let parse_duration = parse_started.map(|started| started.elapsed());
    if let Some(response) = prepared.immediate_response {
        return Some(UdpOutbound {
            response,
            target: UdpPacketTarget::Socket(peer),
            query_metrics: None,
        });
    }
    let dns_cookie_secrets = settings
        .dns_cookie
        .policy
        .is_some()
        .then(|| settings.dns_cookie_secrets.current());
    let dns_cookie = dns_cookie_secrets
        .as_ref()
        .and_then(|secrets| dns_cookie_context(peer_ip, secrets, settings.dns_cookie));
    let cookie_validated = dns_cookie
        .is_some_and(|context| request_has_valid_dns_server_cookie(&prepared.packet, context));
    let query_metrics = observe_query_metrics(
        &prepared.packet,
        zones,
        &settings.metrics,
        QueryObservationOptions {
            transport: Transport::Udp,
            cookie_validated,
            parse_duration,
        },
    );
    let query_tsig_authenticated = prepared.tsig_authenticated || prepared.response_tsig.is_some();
    let query_cache_ineligible = response_cache_ineligible_reason(
        query_tsig_authenticated,
        dns_cookie.is_some(),
        settings.rrl.enabled() && !query_tsig_authenticated && !cookie_validated,
        settings.edns_padding_block_size,
    );
    let dns_cookie_metrics = observe_dns_cookie_metrics(
        &prepared.packet,
        dns_cookie,
        peer_ip,
        settings.cookie_prefix_metrics,
        &settings.metrics,
    );
    let chaos = ChaosOptions {
        version: &settings.chaos_version,
        hostname: &settings.chaos_hostname,
    };
    let chaos_observation = chaos_query_observation(&prepared.packet, &settings.nsid, chaos);
    let compose_started = settings.metrics.start_pipeline_timer();
    let answer_options = AnswerOptions {
        transport: Transport::Udp,
        max_udp_payload: settings.max_udp_payload,
        max_cname_chain: settings.max_cname_chain,
        nsec3_max_iterations: settings.nsec3_max_iterations,
        tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
        edns_padding_block_size: settings.edns_padding_block_size,
        extended_dns_errors: settings.extended_dns_errors,
        any_response: settings.any_response,
        nsid: &settings.nsid,
        chaos,
        dns_cookie,
    };
    let notify_authorized = |qname: &DomainName, qclass| {
        let authorized = settings
            .notify_authority
            .is_authorized(qname, qclass, peer_ip);
        if !authorized {
            settings.metrics.record_notify_unauthorized();
            settings.notify_log_limiter.log_unauthorized(peer_ip, qname);
        }
        authorized
    };
    let notify_accepted = |qname: &DomainName, _qclass, serial| {
        signal_notify_refresh(
            &settings.notify_refresh,
            &settings.notify_refresh_tx,
            &settings.metrics,
            qname,
            peer_ip,
            serial,
        )
    };
    let lookup_observed = |lookup_metrics| {
        record_query_lookup_metrics(&query_metrics, lookup_metrics, &settings.metrics);
    };
    let action = answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        &prepared.packet,
        zones,
        answer_options,
        notify_authorized,
        notify_accepted,
        lookup_observed,
        &default_zone_image_provider as ZoneImageProvider<'_>,
    );
    let mut query_metrics = query_metrics;
    query_metrics.compose_duration = compose_started.map(|started| started.elapsed());
    match action {
        DatagramAction::Discard => {
            debug!(
                peer_ip = %peer.ip(),
                peer_port = peer.port(),
                transport = "udp",
                bytes = packet.len(),
                "discarded DNS datagram"
            );
            None
        }
        DatagramAction::Respond(response) => {
            record_chaos_query_if_observed(
                chaos_observation.as_ref(),
                &response,
                &settings.metrics,
                peer_ip,
                "udp",
            );
            let response = match sign_tsig_response(response, prepared.response_tsig) {
                Ok(response) => response,
                Err(error) => {
                    warn!(
                        peer_ip = %peer.ip(),
                        peer_port = peer.port(),
                        transport = "udp",
                        %error,
                        "failed to sign TSIG response"
                    );
                    return None;
                }
            };
            let rrl_decision = if prepared.tsig_authenticated || cookie_validated {
                RrlDecision::Send(response)
            } else {
                settings.rrl.apply(peer_ip, response)
            };
            match rrl_decision {
                RrlDecision::Send(response) => {
                    record_dns_cookie_badcookie_if_emitted(
                        dns_cookie_metrics,
                        &response,
                        &settings.metrics,
                        peer_ip,
                        settings.cookie_prefix_metrics,
                    );
                    record_query_response_metric(&query_metrics, &response, &settings.metrics);
                    record_response_cache_metric(
                        &query_metrics,
                        &response,
                        &settings.metrics,
                        query_cache_ineligible,
                    );
                    Some(UdpOutbound {
                        response,
                        target: UdpPacketTarget::Socket(peer),
                        query_metrics: query_metrics.is_query.then_some(query_metrics),
                    })
                }
                RrlDecision::Drop => None,
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct QueryMetricObservation {
    pub(crate) is_query: bool,
    pub(crate) transport: Transport,
    pub(crate) started_at: Instant,
    pub(crate) cookie_validated: bool,
    pub(crate) zone_key: Option<Arc<str>>,
    pub(crate) parse_duration: Option<Duration>,
    pub(crate) lookup_duration: Option<Duration>,
    pub(crate) compose_duration: Option<Duration>,
}

#[derive(Clone, Copy)]
pub(crate) struct QueryObservationOptions {
    pub(crate) transport: Transport,
    pub(crate) cookie_validated: bool,
    pub(crate) parse_duration: Option<Duration>,
}

pub(crate) fn observe_query_metrics(
    packet: &[u8],
    zones: &ZoneStore,
    metrics: &RuntimeMetrics,
    options: QueryObservationOptions,
) -> QueryMetricObservation {
    let started_at = Instant::now();
    let lookup_started = metrics.start_pipeline_timer();
    let not_query = || QueryMetricObservation {
        is_query: false,
        transport: options.transport,
        started_at,
        cookie_validated: false,
        zone_key: None,
        parse_duration: options.parse_duration,
        lookup_duration: lookup_started.map(|started| started.elapsed()),
        compose_duration: None,
    };
    if !metrics.hot_path_counters_enabled() {
        return not_query();
    }
    let observed_query = |zone_key| QueryMetricObservation {
        is_query: true,
        transport: options.transport,
        started_at,
        cookie_validated: options.cookie_validated,
        zone_key,
        parse_duration: options.parse_duration,
        lookup_duration: lookup_started.map(|started| started.elapsed()),
        compose_duration: None,
    };
    let Ok(header) = Header::parse(packet) else {
        return not_query();
    };
    if header.is_response() || header.opcode() != Some(Opcode::Query) {
        return not_query();
    }

    metrics.record_query_received();
    if !metrics.hot_path_detail_enabled() {
        return observed_query(None);
    }
    if header.qdcount != 1 {
        return observed_query(None);
    }
    let Ok(question) = Question::parse(packet) else {
        return observed_query(None);
    };
    if let Some(published_zone) = zones.find_published_zone_with_ascii_lowercase_hint(
        &question.qname,
        question.qname_ascii_lowercase(),
    ) {
        metrics.record_zone_query_key(published_zone.origin_key());
        return observed_query(Some(published_zone.origin_key_arc()));
    }
    observed_query(None)
}

pub(crate) fn observe_dns_cookie_metrics(
    packet: &[u8],
    context: Option<DnsCookieContext>,
    source: IpAddr,
    prefix_settings: CookiePrefixMetricSettings,
    metrics: &RuntimeMetrics,
) -> Option<DnsCookieRequestStatus> {
    let context = context?;
    let status = dns_cookie_request_status(packet, Some(context))?;
    metrics.record_dns_cookie_status(status, source, prefix_settings);
    Some(status)
}

pub(crate) fn record_dns_cookie_badcookie_if_emitted(
    status: Option<DnsCookieRequestStatus>,
    response: &[u8],
    metrics: &RuntimeMetrics,
    peer_ip: IpAddr,
    prefix_settings: CookiePrefixMetricSettings,
) {
    let Some(
        reason @ (DnsCookieRequestStatus::ClientCookieOnly
        | DnsCookieRequestStatus::InvalidServerCookie),
    ) = status
    else {
        return;
    };
    let Ok(header) = Header::parse(response) else {
        return;
    };
    if response_rcode(response, &header) != Rcode::BadCookie as u16 {
        return;
    }
    metrics.record_dns_cookie_badcookie();
    metrics.record_dns_cookie_badcookie_for_source(peer_ip, prefix_settings);
    debug!(
        category = "cookie",
        %peer_ip,
        reason = ?reason,
        "DNS Cookie BADCOOKIE response emitted"
    );
}

pub(crate) fn record_chaos_query_if_observed(
    observation: Option<&oxidedns_core::dns::ChaosQueryObservation>,
    response: &[u8],
    metrics: &RuntimeMetrics,
    peer_ip: IpAddr,
    transport: &'static str,
) {
    let Some(observation) = observation else {
        return;
    };
    metrics.record_chaos_query(observation.outcome);
    let rcode = Header::parse(response)
        .ok()
        .map(|header| response_rcode(response, &header))
        .unwrap_or_default();
    debug!(
        category = "chaos",
        %peer_ip,
        transport,
        qname = %observation.qname,
        qtype = observation.qtype,
        outcome = observation.outcome.label(),
        rcode,
        "CHAOS-class query handled"
    );
}

pub(crate) fn record_query_response_metric(
    observation: &QueryMetricObservation,
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
    let rcode = response_rcode(response, &header);
    metrics.record_query_response_rcode(rcode);
    if let Some(zone_key) = &observation.zone_key {
        metrics.record_zone_query_response_rcode(zone_key, rcode);
    }
    metrics.record_query_latency(
        query_latency_category(observation, response, &header),
        observation.started_at.elapsed(),
    );
}

pub(crate) fn record_query_send_metric(
    observation: &QueryMetricObservation,
    response: &[u8],
    metrics: &RuntimeMetrics,
    duration: Duration,
) {
    if !observation.is_query || !metrics.pipeline_timing_enabled() {
        return;
    }
    let Ok(header) = Header::parse(response) else {
        return;
    };
    metrics.record_query_pipeline_latency(
        QueryPipelineStage::Send,
        query_latency_category(observation, response, &header),
        duration,
    );
}

pub(crate) fn record_response_cache_metric(
    observation: &QueryMetricObservation,
    response: &[u8],
    metrics: &RuntimeMetrics,
    ineligible: Option<ResponseCacheIneligibleReason>,
) {
    if !observation.is_query || !metrics.pipeline_timing_enabled() {
        return;
    }
    let Ok(header) = Header::parse(response) else {
        metrics.record_response_cache_ineligible(ResponseCacheIneligibleReason::Other);
        return;
    };
    let category = query_latency_category(observation, response, &header);
    if let Some(duration) = observation.parse_duration {
        metrics.record_query_pipeline_latency(QueryPipelineStage::Parse, category, duration);
    }
    if let Some(duration) = observation.lookup_duration {
        metrics.record_query_pipeline_latency(QueryPipelineStage::Lookup, category, duration);
    }
    if let Some(duration) = observation.compose_duration {
        metrics.record_query_pipeline_latency(QueryPipelineStage::Compose, category, duration);
    }

    if header.flags & 0x0200 != 0 {
        metrics.record_response_cache_ineligible(ResponseCacheIneligibleReason::Truncated);
        return;
    }
    if let Some(reason) = ineligible {
        metrics.record_response_cache_ineligible(reason);
        return;
    }
    metrics.record_response_cache_candidate(response_cache_candidate_category(response, &header));
}

pub(crate) fn response_cache_ineligible_reason(
    tsig_authenticated: bool,
    dns_cookie_enabled: bool,
    rrl_subject: bool,
    edns_padding_block_size: u16,
) -> Option<ResponseCacheIneligibleReason> {
    if tsig_authenticated {
        return Some(ResponseCacheIneligibleReason::Tsig);
    }
    if dns_cookie_enabled {
        return Some(ResponseCacheIneligibleReason::Cookie);
    }
    if rrl_subject {
        return Some(ResponseCacheIneligibleReason::Rrl);
    }
    if edns_padding_block_size > 0 {
        return Some(ResponseCacheIneligibleReason::EdnsPadding);
    }
    None
}

fn response_cache_candidate_category(
    response: &[u8],
    header: &Header,
) -> ResponseCacheCandidateCategory {
    if response_contains_type(
        response,
        header,
        &[
            RecordType::Ds as u16,
            RecordType::Rrsig as u16,
            RecordType::Nsec as u16,
            RecordType::Dnskey as u16,
            RecordType::Nsec3 as u16,
        ],
    ) {
        return ResponseCacheCandidateCategory::Dnssec;
    }
    if response_rcode(response, header) == Rcode::NxDomain as u16 || header.ancount == 0 {
        return ResponseCacheCandidateCategory::Negative;
    }
    if response_answer_contains_type(
        response,
        header,
        &[RecordType::Cname as u16, RecordType::Dname as u16],
    ) {
        return ResponseCacheCandidateCategory::Cname;
    }
    ResponseCacheCandidateCategory::Direct
}

fn query_latency_category(
    observation: &QueryMetricObservation,
    response: &[u8],
    header: &Header,
) -> QueryLatencyCategory {
    if observation.cookie_validated {
        return QueryLatencyCategory::CookieValidated;
    }
    if response_has_dnssec_augmentation(response, header) {
        return QueryLatencyCategory::DnssecAugmented;
    }
    let cname_chain = response_answer_contains_type(
        response,
        header,
        &[RecordType::Cname as u16, RecordType::Dname as u16],
    );
    match (observation.transport, cname_chain) {
        (Transport::Udp, false) => QueryLatencyCategory::UdpDirect,
        (Transport::Udp, true) => QueryLatencyCategory::UdpCnameChain,
        (Transport::Tcp, false) => QueryLatencyCategory::TcpDirect,
        (Transport::Tcp, true) => QueryLatencyCategory::TcpCnameChain,
    }
}

fn response_has_dnssec_augmentation(response: &[u8], header: &Header) -> bool {
    let Some(opt) = response_opt_record(response, header) else {
        return false;
    };
    if opt.len() < 9 {
        return false;
    }
    let ttl = u32::from_be_bytes([opt[5], opt[6], opt[7], opt[8]]);
    ttl & 0x8000 != 0
}

fn response_answer_contains_type(response: &[u8], header: &Header, types: &[u16]) -> bool {
    let Some(mut offset) = response_question_end(response, header) else {
        return false;
    };
    for _ in 0..header.ancount {
        let Some((rr_type, next)) = response_record_type(response, offset) else {
            return false;
        };
        if types.contains(&rr_type) {
            return true;
        }
        offset = next;
    }
    false
}

fn response_contains_type(response: &[u8], header: &Header, types: &[u16]) -> bool {
    let Some(mut offset) = response_question_end(response, header) else {
        return false;
    };
    for count in [header.ancount, header.nscount, header.arcount] {
        for _ in 0..count {
            let Some((rr_type, next)) = response_record_type(response, offset) else {
                return false;
            };
            if rr_type != RecordType::Opt as u16 && types.contains(&rr_type) {
                return true;
            }
            offset = next;
        }
    }
    false
}

pub(crate) fn record_query_lookup_metrics(
    observation: &QueryMetricObservation,
    lookup: LookupMetrics,
    metrics: &RuntimeMetrics,
) {
    if !observation.is_query {
        return;
    }
    if lookup.zone_image_used {
        metrics.record_zone_image_serve_hit();
        if lookup.zone_image_direct_answer {
            metrics.record_zone_image_serve_direct_hit();
        } else {
            metrics.record_zone_image_serve_semantic_hit();
        }
    } else if let Some(reason) = lookup.zone_image_failure_reason {
        metrics.record_zone_image_serve_failure();
        metrics.record_zone_image_serve_failure_reason(reason);
    }
    match lookup.termination {
        Some(LookupTermination::CnameChainLimit) => metrics.record_query_cname_chain_limit(),
        Some(LookupTermination::CnameLoop) => metrics.record_query_cname_loop(),
        Some(LookupTermination::MalformedDname) => {}
        None => {}
    }
    if lookup.nsec3_iterations_exceeded {
        metrics.record_nsec3_iterations_exceed_cap();
    }
}

pub(crate) fn response_rcode(response: &[u8], header: &Header) -> u16 {
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

pub(crate) fn skip_response_record(response: &[u8], offset: usize) -> Option<usize> {
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
pub(crate) struct UdpServerSettings {
    pub(crate) max_udp_payload: u16,
    pub(crate) udp_batch_size: usize,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) udp_backend: UdpBackend,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) udp_runtime: UdpRuntime,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) udp_idle_strategy: UdpIdleStrategy,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) xdp: XdpConfig,
    pub(crate) max_cname_chain: usize,
    pub(crate) nsec3_max_iterations: u16,
    pub(crate) edns_padding_block_size: u16,
    pub(crate) extended_dns_errors: ExtendedDnsErrorsMode,
    pub(crate) any_response: AnyResponseMode,
    pub(crate) nsid: Vec<u8>,
    pub(crate) chaos_version: String,
    pub(crate) chaos_hostname: String,
    pub(crate) dns_cookie_secrets: DnsCookieSecretStore,
    pub(crate) dns_cookie: DnsCookieRuntimeSettings,
    pub(crate) cookie_prefix_metrics: CookiePrefixMetricSettings,
    pub(crate) notify_authority: NotifyAuthority,
    pub(crate) notify_refresh: NotifyRefreshTracker,
    pub(crate) notify_refresh_tx: mpsc::Sender<RefreshRequest>,
    pub(crate) notify_log_limiter: NotifyLogLimiter,
    pub(crate) metrics: RuntimeMetrics,
    pub(crate) rrl: RrlLimiter,
}
