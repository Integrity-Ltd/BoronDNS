use std::{
    collections::HashMap,
    future::Future,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use borondns_core::{
    config::{MAX_UDP_BATCH_SIZE, UdpBackend, UdpIdleStrategy, UdpRuntime, XdpConfig},
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

const ERRNO_EBADF: i32 = 9;
const ERRNO_EPERM: i32 = 1;
const ERRNO_EINVAL: i32 = 22;
const ERRNO_EMSGSIZE: i32 = 90;
const ERRNO_ENETUNREACH: i32 = 101;
const ERRNO_ENOBUFS: i32 = 105;
const ERRNO_ECONNREFUSED: i32 = 111;
const ERRNO_EHOSTUNREACH: i32 = 113;
const ERRNO_ENOMEM: i32 = 12;
const ERRNO_EBUSY: i32 = 16;
const UDP_RESOURCE_BACKOFF: Duration = Duration::from_millis(50);

pub(super) fn bounded_udp_batch_size(batch_size: usize) -> usize {
    batch_size.clamp(1, MAX_UDP_BATCH_SIZE)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpIoErrorAction {
    Continue,
    Backoff(Duration),
    Fatal,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum BoundUdpListener {
    Std {
        socket: UdpSocket,
        worker_id: usize,
        worker_count: usize,
        cpu_affinity: Option<usize>,
    },
    #[cfg(feature = "af-xdp")]
    AfXdp {
        packet_io: af_xdp::AfXdpPacketIo,
        worker_id: usize,
        worker_count: usize,
    },
    #[cfg(feature = "af-xdp")]
    AfXdpKernelFallback {
        socket: Arc<UdpSocket>,
        worker_id: usize,
        worker_count: usize,
    },
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn bind_udp_listeners(
    addr: SocketAddr,
    backend: UdpBackend,
    xdp: &XdpConfig,
    worker_count: usize,
    cpu_affinity: Option<&[usize]>,
    socket_receive_buffer_bytes: Option<usize>,
    socket_send_buffer_bytes: Option<usize>,
    socket_max_pacing_rate_bytes_per_second: Option<usize>,
) -> Result<Vec<BoundUdpListener>, RuntimeError> {
    match backend {
        UdpBackend::Std => bind_std_udp_listeners(
            addr,
            worker_count,
            cpu_affinity,
            socket_receive_buffer_bytes,
            socket_send_buffer_bytes,
            socket_max_pacing_rate_bytes_per_second,
        )
        .map_err(|source| RuntimeError::BindUdp { addr, source }),
        UdpBackend::AfXdp => {
            let socket = UdpSocket::bind(addr)
                .await
                .map_err(|source| RuntimeError::BindUdp { addr, source })?;
            bind_af_xdp_udp_listeners(socket, xdp, worker_count)
        }
    }
}

fn bind_std_udp_listeners(
    addr: SocketAddr,
    worker_count: usize,
    cpu_affinity: Option<&[usize]>,
    socket_receive_buffer_bytes: Option<usize>,
    socket_send_buffer_bytes: Option<usize>,
    socket_max_pacing_rate_bytes_per_second: Option<usize>,
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
            socket_max_pacing_rate_bytes_per_second,
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

pub(crate) fn classify_udp_send_error(error: &std::io::Error) -> UdpIoErrorAction {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::Interrupted => UdpIoErrorAction::Continue,
        _ => match error.raw_os_error() {
            Some(ERRNO_ENOBUFS | ERRNO_ENOMEM) => UdpIoErrorAction::Backoff(UDP_RESOURCE_BACKOFF),
            Some(
                ERRNO_ECONNREFUSED | ERRNO_EHOSTUNREACH | ERRNO_ENETUNREACH | ERRNO_EMSGSIZE
                | ERRNO_EPERM | ERRNO_EBUSY,
            ) => UdpIoErrorAction::Continue,
            Some(ERRNO_EBADF | ERRNO_EINVAL) => UdpIoErrorAction::Fatal,
            _ => UdpIoErrorAction::Fatal,
        },
    }
}

pub(crate) fn classify_udp_recv_error(error: &std::io::Error) -> UdpIoErrorAction {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::Interrupted => UdpIoErrorAction::Continue,
        _ => match error.raw_os_error() {
            Some(ERRNO_ENOBUFS | ERRNO_ENOMEM) => UdpIoErrorAction::Backoff(UDP_RESOURCE_BACKOFF),
            Some(ERRNO_EBADF | ERRNO_EINVAL) => UdpIoErrorAction::Fatal,
            _ => UdpIoErrorAction::Fatal,
        },
    }
}

#[cfg(not(feature = "af-xdp"))]
fn bind_af_xdp_udp_listeners(
    _socket: UdpSocket,
    _xdp: &XdpConfig,
    _worker_count: usize,
) -> Result<Vec<BoundUdpListener>, RuntimeError> {
    Err(RuntimeError::UdpBackendUnavailable {
        backend: "af_xdp",
        reason: "borondns-server was built without the af-xdp feature",
    })
}

#[cfg(feature = "af-xdp")]
fn bind_af_xdp_udp_listeners(
    socket: UdpSocket,
    xdp: &XdpConfig,
    worker_count: usize,
) -> Result<Vec<BoundUdpListener>, RuntimeError> {
    let worker_count = worker_count.max(1);
    af_xdp::AfXdpPacketIo::bind_queues(socket, xdp, worker_count)
        .map(|packet_ios| {
            let xsk_worker_count = packet_ios.len();
            let worker_count = xsk_worker_count.saturating_add(1);
            let fallback_socket = packet_ios
                .first()
                .expect("AF_XDP bind always produces at least one queue")
                .kernel_fallback_socket();
            let mut listeners = packet_ios
                .into_iter()
                .enumerate()
                .map(|(worker_id, packet_io)| BoundUdpListener::AfXdp {
                    packet_io,
                    worker_id,
                    worker_count,
                })
                .collect::<Vec<_>>();
            listeners.push(BoundUdpListener::AfXdpKernelFallback {
                socket: fallback_socket,
                worker_id: xsk_worker_count,
                worker_count,
            });
            listeners
        })
        .map_err(RuntimeError::Udp)
}

pub(crate) async fn serve_bound_udp_until<S>(
    listener: BoundUdpListener,
    zones: ZoneStore,
    settings: UdpServerSettings,
    admission_open: Arc<AtomicBool>,
    shutdown: S,
) -> Result<(), RuntimeError>
where
    S: Future<Output = tokio::time::Instant>,
{
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
                    DedicatedUdpWorkerIdentity {
                        worker_id,
                        worker_count,
                        cpu_affinity,
                    },
                    admission_open,
                    shutdown,
                )
                .await;
            }
            let packet_io = StdUdpBatchIo::new(socket, settings.udp_batch_size);
            serve_udp_packet_io_until(
                packet_io,
                zones,
                settings,
                worker_id,
                worker_count,
                admission_open,
                shutdown,
            )
            .await
        }
        #[cfg(feature = "af-xdp")]
        BoundUdpListener::AfXdp {
            packet_io,
            worker_id,
            worker_count,
        } => {
            serve_udp_packet_io_until(
                packet_io,
                zones,
                settings,
                worker_id,
                worker_count,
                admission_open,
                shutdown,
            )
            .await
        }
        #[cfg(feature = "af-xdp")]
        BoundUdpListener::AfXdpKernelFallback {
            socket,
            worker_id,
            worker_count,
        } => {
            let packet_io = StdUdpBatchIo::from_shared(socket, settings.udp_batch_size);
            serve_udp_packet_io_until(
                packet_io,
                zones,
                settings,
                worker_id,
                worker_count,
                admission_open,
                shutdown,
            )
            .await
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
        reason: "borondns-server was built without the af-xdp feature",
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
    packet_io: I,
    zones: ZoneStore,
    settings: UdpServerSettings,
    udp_worker_id: usize,
    udp_worker_count: usize,
) -> Result<(), RuntimeError>
where
    I: PacketIo,
{
    serve_udp_packet_io_until(
        packet_io,
        zones,
        settings,
        udp_worker_id,
        udp_worker_count,
        Arc::new(AtomicBool::new(true)),
        std::future::pending(),
    )
    .await
}

pub(crate) async fn serve_udp_packet_io_until<I, S>(
    mut packet_io: I,
    zones: ZoneStore,
    settings: UdpServerSettings,
    udp_worker_id: usize,
    udp_worker_count: usize,
    admission_open: Arc<AtomicBool>,
    shutdown: S,
) -> Result<(), RuntimeError>
where
    I: PacketIo,
    S: Future<Output = tokio::time::Instant>,
{
    tokio::pin!(shutdown);
    let local_addr = packet_io.local_addr().map_err(RuntimeError::Udp)?;
    info!(%local_addr, udp_worker_id, udp_worker_count, "UDP listener bound");
    let mut outbound = Vec::with_capacity(bounded_udp_batch_size(settings.udp_batch_size));
    let is_af_xdp = packet_io.is_af_xdp();
    let benchmark_fixed_response = is_af_xdp && benchmark_af_xdp_fixed_response_enabled();
    if benchmark_fixed_response {
        warn!(
            udp_worker_id,
            "AF_XDP benchmark fixed-response mode is enabled"
        );
    }

    loop {
        if !admission_open.load(Ordering::Acquire) {
            return Ok(());
        }
        let pending_send_result = tokio::select! {
            biased;
            _deadline = &mut shutdown => return Ok(()),
            result = packet_io.service_pending_send(&admission_open, &settings.metrics) => result,
        };
        if let Err(error) = pending_send_result {
            if !admission_open.load(Ordering::Acquire) {
                return Ok(());
            }
            match classify_udp_send_error(&error) {
                UdpIoErrorAction::Continue => {
                    settings.metrics.record_udp_send_error();
                    debug!(
                        %error,
                        udp_worker_id,
                        "pending UDP send work remains retryable"
                    );
                    continue;
                }
                UdpIoErrorAction::Backoff(duration) => {
                    settings.metrics.record_udp_send_error();
                    warn!(
                        %error,
                        udp_worker_id,
                        backoff_ms = duration.as_millis(),
                        "pending UDP send work is under resource pressure; backing off"
                    );
                    tokio::select! {
                        biased;
                        _deadline = &mut shutdown => return Ok(()),
                        () = tokio::time::sleep(duration) => {}
                    }
                    continue;
                }
                UdpIoErrorAction::Fatal => return Err(RuntimeError::Udp(error)),
            }
        }
        {
            let received = tokio::select! {
                biased;
                _deadline = &mut shutdown => return Ok(()),
                received = packet_io.recv_batch(&admission_open) => received,
            };
            let inbound = match received {
                Ok(inbound) => inbound,
                Err(_) if !admission_open.load(Ordering::Acquire) => return Ok(()),
                Err(error) => match classify_udp_recv_error(&error) {
                    UdpIoErrorAction::Continue => {
                        settings.metrics.record_udp_receive_error();
                        debug!(%error, udp_worker_id, "transient UDP receive error ignored");
                        continue;
                    }
                    UdpIoErrorAction::Backoff(duration) => {
                        settings.metrics.record_udp_receive_error();
                        warn!(
                            %error,
                            udp_worker_id,
                            backoff_ms = duration.as_millis(),
                            "UDP receive resource pressure; backing off"
                        );
                        tokio::time::sleep(duration).await;
                        continue;
                    }
                    UdpIoErrorAction::Fatal => return Err(RuntimeError::Udp(error)),
                },
            };
            settings.metrics.record_udp_receive_batch(inbound.len());
            if is_af_xdp {
                settings
                    .metrics
                    .record_af_xdp_worker_receive_batch(udp_worker_id, inbound.len());
            }
            record_udp_worker_source_ports(&settings.metrics, udp_worker_id, inbound);
            outbound.clear();

            for packet in inbound {
                if !udp_inbound_has_reply_port(packet) {
                    continue;
                }
                if benchmark_fixed_response {
                    outbound.push(UdpOutbound::benchmark_fixed_response(packet.target()));
                } else if let Some(response) =
                    handle_udp_datagram(packet.payload(), packet.peer, &zones, &settings)
                {
                    outbound.push(response.with_target(packet.target()));
                }
            }
        };
        let send = packet_io.send_batch(&outbound, &settings.metrics, udp_worker_id);
        tokio::pin!(send);
        let send_result = tokio::select! {
            biased;
            deadline = &mut shutdown => {
                match tokio::time::timeout_at(deadline, &mut send).await {
                    Ok(result) => result,
                    Err(_) => {
                        warn!(
                            udp_worker_id,
                            "UDP shutdown deadline elapsed with an in-flight batch"
                        );
                        return Ok(());
                    }
                }
            }
            result = &mut send => result,
        };
        let (queued, send_error) = match send_result {
            Ok(queued) => (queued, None),
            Err(error) => {
                let (queued, error) = error.into_parts();
                (queued, Some(error))
            }
        };
        // AF_XDP records admission synchronously in its cancellation-safe
        // guard. Standard packet I/O records here after either a complete
        // success or an error that followed partial successful sends.
        if !is_af_xdp {
            settings.metrics.record_udp_send_batch(queued);
        }
        if let Some(error) = send_error {
            match classify_udp_send_error(&error) {
                UdpIoErrorAction::Continue => {
                    settings.metrics.record_udp_send_error();
                    debug!(%error, udp_worker_id, "UDP send error ignored");
                }
                UdpIoErrorAction::Backoff(duration) => {
                    settings.metrics.record_udp_send_error();
                    warn!(
                        %error,
                        udp_worker_id,
                        backoff_ms = duration.as_millis(),
                        "UDP send resource pressure; backing off"
                    );
                    tokio::time::sleep(duration).await;
                }
                UdpIoErrorAction::Fatal => return Err(RuntimeError::Udp(error)),
            }
        }
    }
}

fn record_udp_worker_source_ports(
    metrics: &RuntimeMetrics,
    worker_id: usize,
    inbound: &[UdpInbound],
) {
    if inbound.is_empty() || !metrics.hot_path_counters_enabled() {
        return;
    }

    let mut source_ports: HashMap<u16, u64> = HashMap::with_capacity(inbound.len().min(64));
    for packet in inbound {
        *source_ports.entry(packet.peer.port()).or_insert(0) += 1;
    }
    metrics.record_udp_worker_source_ports(worker_id, source_ports);
}

fn udp_inbound_has_reply_port(packet: &UdpInbound) -> bool {
    if packet.peer.port() != 0 {
        return true;
    }
    debug!(
        peer_ip = %packet.peer.ip(),
        transport = "udp",
        bytes = packet.len,
        "discarded UDP datagram without a reply port"
    );
    false
}

async fn serve_dedicated_std_udp_worker<S>(
    socket: UdpSocket,
    zones: ZoneStore,
    settings: UdpServerSettings,
    identity: DedicatedUdpWorkerIdentity,
    admission_open: Arc<AtomicBool>,
    shutdown: S,
) -> Result<(), RuntimeError>
where
    S: Future<Output = tokio::time::Instant>,
{
    let socket = socket.into_std().map_err(RuntimeError::Udp)?;
    socket.set_nonblocking(true).map_err(RuntimeError::Udp)?;
    let control = Arc::new(DedicatedUdpWorkerControl::new());
    let (result_tx, result_rx) = oneshot::channel();
    let thread_control = control.clone();
    let thread_admission_open = admission_open.clone();
    let thread_name = format!("borondns-udp-{}", identity.worker_id);
    let handle = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            let result = run_dedicated_std_udp_worker(
                socket,
                zones,
                settings,
                thread_control,
                thread_admission_open,
                identity,
            );
            let _ = result_tx.send(result);
        })
        .map_err(RuntimeError::Udp)?;
    let thread = handle.thread().clone();
    let mut guard = DedicatedUdpWorkerGuard {
        control,
        thread,
        handle: Some(handle),
    };

    tokio::pin!(shutdown);
    let mut result_rx = result_rx;
    let worker_result = tokio::select! {
        result = &mut result_rx => result,
        deadline = &mut shutdown => {
            guard.request_shutdown(deadline);
            match tokio::time::timeout_at(deadline, &mut result_rx).await {
                Ok(result) => result,
                Err(_) => {
                    warn!(worker_id = identity.worker_id, "dedicated UDP shutdown deadline elapsed; detaching stopped worker");
                    guard.detach();
                    return Ok(());
                }
            }
        }
    };
    let result = match worker_result {
        Ok(result) => result,
        Err(_) => Err(RuntimeError::Udp(std::io::Error::other(
            "dedicated UDP worker exited without reporting status",
        ))),
    };
    guard.join()?;
    result
}

#[derive(Clone, Copy)]
struct DedicatedUdpWorkerIdentity {
    worker_id: usize,
    worker_count: usize,
    cpu_affinity: Option<usize>,
}

struct DedicatedUdpWorkerControl {
    stop: AtomicBool,
    deadline: Mutex<Option<Instant>>,
    #[cfg(test)]
    after_receive_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl DedicatedUdpWorkerControl {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            deadline: Mutex::new(None),
            #[cfg(test)]
            after_receive_hook: Mutex::new(None),
        }
    }

    fn request_shutdown(&self, deadline: tokio::time::Instant) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        *self.deadline.lock().expect("dedicated UDP deadline mutex") =
            Some(Instant::now() + remaining);
        self.stop.store(true, Ordering::Release);
    }

    fn stop_requested(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn deadline_elapsed(&self) -> bool {
        self.deadline
            .lock()
            .expect("dedicated UDP deadline mutex")
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    #[cfg(test)]
    fn set_after_receive_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .after_receive_hook
            .lock()
            .expect("dedicated UDP after-receive hook mutex") = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn run_after_receive_hook(&self) {
        if let Some(hook) = self
            .after_receive_hook
            .lock()
            .expect("dedicated UDP after-receive hook mutex")
            .take()
        {
            hook();
        }
    }
}

struct DedicatedUdpWorkerGuard {
    control: Arc<DedicatedUdpWorkerControl>,
    thread: std::thread::Thread,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl DedicatedUdpWorkerGuard {
    fn request_shutdown(&self, deadline: tokio::time::Instant) {
        self.control.request_shutdown(deadline);
        self.thread.unpark();
    }

    fn join(&mut self) -> Result<(), RuntimeError> {
        if let Some(handle) = self.handle.take()
            && handle.join().is_err()
        {
            return Err(RuntimeError::Udp(std::io::Error::other(
                "dedicated UDP worker panicked",
            )));
        }
        Ok(())
    }

    fn detach(&mut self) {
        let _ = self.handle.take();
    }
}

impl Drop for DedicatedUdpWorkerGuard {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.request_shutdown(tokio::time::Instant::now());
            if self
                .handle
                .as_ref()
                .is_some_and(|handle| handle.is_finished())
            {
                if self.join().is_err() {
                    warn!("dedicated UDP worker panicked while shutting down");
                }
            } else {
                self.detach();
            }
        }
    }
}

#[cfg(test)]
mod dedicated_worker_ownership_tests {
    use std::{
        sync::{Arc, atomic::Ordering, mpsc},
        time::Duration,
    };

    use super::{DedicatedUdpWorkerControl, DedicatedUdpWorkerGuard};

    #[test]
    fn dropping_dedicated_worker_guard_requests_stop_without_blocking() {
        let control = Arc::new(DedicatedUdpWorkerControl::new());
        let (exited_tx, exited_rx) = mpsc::channel();
        let thread_control = control.clone();
        let handle = std::thread::spawn(move || {
            while !thread_control.stop.load(Ordering::Acquire) {
                std::thread::park();
            }
            let _ = exited_tx.send(());
        });
        let thread = handle.thread().clone();
        let guard = DedicatedUdpWorkerGuard {
            control,
            thread,
            handle: Some(handle),
        };

        drop(guard);
        exited_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detached worker observes stop request");
    }

    #[test]
    fn dropping_dedicated_worker_guard_never_waits_for_unresponsive_thread() {
        let control = Arc::new(DedicatedUdpWorkerControl::new());
        let (exited_tx, exited_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            let _ = exited_tx.send(());
        });
        let thread = handle.thread().clone();
        let guard = DedicatedUdpWorkerGuard {
            control,
            thread,
            handle: Some(handle),
        };

        let started = std::time::Instant::now();
        drop(guard);
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "guard drop must detach instead of joining an unresponsive worker"
        );
        exited_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detached test worker eventually exits");
    }
}

fn run_dedicated_std_udp_worker(
    socket: std::net::UdpSocket,
    zones: ZoneStore,
    settings: UdpServerSettings,
    control: Arc<DedicatedUdpWorkerControl>,
    admission_open: Arc<AtomicBool>,
    identity: DedicatedUdpWorkerIdentity,
) -> Result<(), RuntimeError> {
    let DedicatedUdpWorkerIdentity {
        worker_id,
        worker_count,
        cpu_affinity,
    } = identity;
    if let Some(cpu) = cpu_affinity {
        std_udp_socket::pin_current_thread_to_cpu(cpu).map_err(RuntimeError::Udp)?;
        info!(
            worker_id,
            worker_count, cpu, "dedicated UDP worker CPU affinity applied"
        );
    }
    let local_addr = socket.local_addr().map_err(RuntimeError::Udp)?;
    info!(%local_addr, worker_id, worker_count, "dedicated UDP worker bound");

    let batch_size = bounded_udp_batch_size(settings.udp_batch_size);
    let mut inbound = (0..batch_size)
        .map(|_| UdpInbound::new())
        .collect::<Vec<_>>();
    let mut outbound = Vec::with_capacity(batch_size);
    let mut packet_io = std_udp_mmsg::StdUdpMmsg::new(batch_size);
    let mut idle_spins = 0usize;

    let result = (|| {
        while !control.stop_requested() && admission_open.load(Ordering::Acquire) {
            let received = packet_io.recv_batch(&socket, &mut inbound);
            #[cfg(test)]
            control.run_after_receive_hook();
            let active = match received {
                Ok(0) => {
                    idle_dedicated_udp_worker(&mut idle_spins, settings.udp_idle_strategy);
                    continue;
                }
                Ok(active) => active,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    idle_dedicated_udp_worker(&mut idle_spins, settings.udp_idle_strategy);
                    continue;
                }
                Err(error) => match classify_udp_recv_error(&error) {
                    UdpIoErrorAction::Continue => {
                        settings.metrics.record_udp_receive_error();
                        debug!(%error, worker_id, "transient UDP receive error ignored");
                        continue;
                    }
                    UdpIoErrorAction::Backoff(duration) => {
                        settings.metrics.record_udp_receive_error();
                        warn!(
                            %error,
                            worker_id,
                            backoff_ms = duration.as_millis(),
                            "UDP receive resource pressure; backing off"
                        );
                        std::thread::sleep(duration);
                        continue;
                    }
                    UdpIoErrorAction::Fatal => return Err(RuntimeError::Udp(error)),
                },
            };
            // A nonblocking receive can race the admission boundary. As with the
            // Tokio and AF_XDP adapters, do not publish or process the batch until
            // a post-receive acquire has linearized it before that boundary.
            if ensure_udp_admission_open(&admission_open).is_err() {
                return Ok(());
            }
            idle_spins = 0;
            settings.metrics.record_udp_receive_batch(active);
            settings
                .metrics
                .record_udp_worker_receive_batch(worker_id, active);

            outbound.clear();
            for packet in &inbound[..active] {
                if !udp_inbound_has_reply_port(packet) {
                    continue;
                }
                if let Some(response) =
                    handle_udp_datagram(packet.payload(), packet.peer, &zones, &settings)
                {
                    outbound.push(response.with_target(packet.target()));
                }
            }
            if control.stop_requested() && control.deadline_elapsed() {
                return Ok(());
            }
            let send_result = send_std_udp_batch(
                &mut packet_io,
                &socket,
                &outbound,
                worker_id,
                &settings.metrics,
            );
            settings
                .metrics
                .record_udp_mmsg_stats(packet_io.take_stats());
            send_result?;
        }

        Ok(())
    })();
    // Receive-side observations can remain pending when shutdown closes an
    // idle worker, the post-receive admission fence rejects a batch, or an
    // error/deadline exits before the normal post-send drain. The post-send
    // `take_stats` above leaves this final drain empty on the ordinary path.
    settings
        .metrics
        .record_udp_mmsg_stats(packet_io.take_stats());
    result
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum DedicatedUdpAfterReceiveTestAction {
    CloseAdmission,
    ExpireDeadline,
}

#[cfg(test)]
pub(crate) fn run_dedicated_std_udp_worker_after_one_receive_for_test(
    socket: std::net::UdpSocket,
    zones: ZoneStore,
    settings: UdpServerSettings,
    admission_open: Arc<AtomicBool>,
    action: DedicatedUdpAfterReceiveTestAction,
) -> Result<(), RuntimeError> {
    socket.set_nonblocking(true).map_err(RuntimeError::Udp)?;
    let control = Arc::new(DedicatedUdpWorkerControl::new());
    match action {
        DedicatedUdpAfterReceiveTestAction::CloseAdmission => {
            let admission_open = admission_open.clone();
            control.set_after_receive_hook(move || {
                admission_open.store(false, Ordering::Release);
            });
        }
        DedicatedUdpAfterReceiveTestAction::ExpireDeadline => {
            let weak_control = Arc::downgrade(&control);
            control.set_after_receive_hook(move || {
                weak_control
                    .upgrade()
                    .expect("dedicated UDP test control remains live")
                    .request_shutdown(tokio::time::Instant::now());
            });
        }
    }
    run_dedicated_std_udp_worker(
        socket,
        zones,
        settings,
        control,
        admission_open,
        DedicatedUdpWorkerIdentity {
            worker_id: 0,
            worker_count: 1,
            cpu_affinity: None,
        },
    )
}

pub(crate) fn send_std_udp_batch(
    packet_io: &mut std_udp_mmsg::StdUdpMmsg,
    socket: &std::net::UdpSocket,
    outbound: &[UdpOutbound],
    worker_id: usize,
    metrics: &RuntimeMetrics,
) -> Result<(), RuntimeError> {
    send_std_udp_batch_with_backoff(
        packet_io,
        socket,
        outbound,
        worker_id,
        metrics,
        std::thread::sleep,
    )
}

#[cfg(test)]
pub(crate) fn send_std_udp_batch_with_backoff_for_test(
    packet_io: &mut std_udp_mmsg::StdUdpMmsg,
    socket: &std::net::UdpSocket,
    outbound: &[UdpOutbound],
    worker_id: usize,
    metrics: &RuntimeMetrics,
    backoff: impl FnMut(Duration),
) -> Result<(), RuntimeError> {
    send_std_udp_batch_with_backoff(packet_io, socket, outbound, worker_id, metrics, backoff)
}

fn send_std_udp_batch_with_backoff(
    packet_io: &mut std_udp_mmsg::StdUdpMmsg,
    socket: &std::net::UdpSocket,
    outbound: &[UdpOutbound],
    worker_id: usize,
    metrics: &RuntimeMetrics,
    mut backoff: impl FnMut(Duration),
) -> Result<(), RuntimeError> {
    if outbound.is_empty() {
        return Ok(());
    }

    let send_started = metrics.pipeline_timing_enabled().then(|| {
        outbound
            .iter()
            .map(|packet| packet.query_metrics.as_ref().map(|_| Instant::now()))
            .collect::<Vec<_>>()
    });
    let (sent_indices, send_error) = match packet_io.send_batch_with_successes(socket, outbound) {
        Ok(sent_indices) => (sent_indices, None),
        Err(error) => {
            let (sent_indices, error) = error.into_parts();
            (sent_indices, Some(error))
        }
    };

    if let Some(send_started) = send_started {
        for index in sent_indices.iter().copied() {
            let packet = &outbound[index];
            let started = send_started[index];
            if let (Some(query_metrics), Some(started)) = (&packet.query_metrics, started) {
                record_query_send_metric(
                    query_metrics,
                    &packet.response,
                    metrics,
                    started.elapsed(),
                );
            }
        }
    }
    metrics.record_udp_send_batch(sent_indices.len());
    metrics.record_udp_worker_send_batch(worker_id, sent_indices.len());
    if let Some(error) = send_error {
        match classify_udp_send_error(&error) {
            UdpIoErrorAction::Continue => {
                metrics.record_udp_send_error();
                debug!(%error, worker_id, "UDP send error ignored");
            }
            UdpIoErrorAction::Backoff(duration) => {
                metrics.record_udp_send_error();
                warn!(
                    %error,
                    worker_id,
                    backoff_ms = duration.as_millis(),
                    "UDP send resource pressure; backing off"
                );
                backoff(duration);
            }
            UdpIoErrorAction::Fatal => return Err(RuntimeError::Udp(error)),
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn send_std_udp_batch_fallback_with_successes(
    socket: &std::net::UdpSocket,
    outbound: &[UdpOutbound],
) -> Result<Vec<usize>, std_udp_mmsg::StdUdpMmsgSendError> {
    let mut sent_indices = Vec::new();
    for (index, packet) in outbound.iter().enumerate() {
        let peer = match packet.target {
            UdpPacketTarget::Socket(peer) => peer,
            #[cfg(feature = "af-xdp")]
            UdpPacketTarget::AfXdp { .. } => {
                return Err(std_udp_mmsg::StdUdpMmsgSendError::new(
                    std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "standard UDP backend cannot send AF_XDP packet target",
                    ),
                    sent_indices,
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
                Err(error) => match classify_udp_send_error(&error) {
                    UdpIoErrorAction::Continue => {
                        if error.kind() == ErrorKind::WouldBlock
                            || error.kind() == ErrorKind::Interrupted
                        {
                            std::thread::yield_now();
                            continue;
                        }
                        break;
                    }
                    UdpIoErrorAction::Backoff(duration) => {
                        std::thread::sleep(duration);
                        break;
                    }
                    UdpIoErrorAction::Fatal => {
                        return Err(std_udp_mmsg::StdUdpMmsgSendError::new(error, sent_indices));
                    }
                },
            }
        }
        if !send_ok {
            continue;
        }
        sent_indices.push(index);
    }
    Ok(sent_indices)
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

    fn is_af_xdp(&self) -> bool {
        false
    }

    /// Services send-side work that must complete before the backend can
    /// safely block for another receive batch.
    ///
    /// Backends without deferred send work keep the default no-op. Keeping
    /// this operation separate from `recv_batch` preserves the provenance of
    /// any error and lets the worker publish send telemetry before retrying.
    async fn service_pending_send(
        &mut self,
        _admission_open: &AtomicBool,
        _metrics: &RuntimeMetrics,
    ) -> std::io::Result<()> {
        Ok(())
    }

    async fn recv_batch(&mut self, admission_open: &AtomicBool) -> std::io::Result<&[UdpInbound]>;

    async fn send_batch(
        &mut self,
        outbound: &[UdpOutbound],
        metrics: &RuntimeMetrics,
        worker_id: usize,
    ) -> Result<usize, PacketIoSendError>;
}

#[derive(Debug)]
pub(crate) struct PacketIoSendError {
    error: std::io::Error,
    queued: usize,
}

impl PacketIoSendError {
    pub(crate) fn new(error: std::io::Error, queued: usize) -> Self {
        Self { error, queued }
    }

    fn into_parts(self) -> (usize, std::io::Error) {
        (self.queued, self.error)
    }
}

pub(crate) struct StdUdpBatchIo {
    socket: Arc<UdpSocket>,
    batch_size: usize,
    inbound: Vec<UdpInbound>,
    #[cfg(test)]
    recv_waiting_signal: Option<Arc<tokio::sync::Notify>>,
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
    #[cfg(feature = "af-xdp")]
    pub(crate) benchmark_fixed_response: bool,
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
        Self::from_shared(Arc::new(socket), batch_size)
    }

    pub(crate) fn from_shared(socket: Arc<UdpSocket>, batch_size: usize) -> Self {
        let batch_size = bounded_udp_batch_size(batch_size);
        let inbound = (0..batch_size).map(|_| UdpInbound::new()).collect();
        Self {
            socket,
            batch_size,
            inbound,
            #[cfg(test)]
            recv_waiting_signal: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_recv_waiting_signal(mut self, signal: Arc<tokio::sync::Notify>) -> Self {
        self.recv_waiting_signal = Some(signal);
        self
    }
}

impl PacketIo for StdUdpBatchIo {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    async fn recv_batch(&mut self, admission_open: &AtomicBool) -> std::io::Result<&[UdpInbound]> {
        if !admission_open.load(Ordering::Acquire) {
            return Err(std::io::Error::from(ErrorKind::Interrupted));
        }
        #[cfg(test)]
        if let Some(signal) = &self.recv_waiting_signal {
            signal.notify_one();
        }
        let (len, peer) = self.socket.recv_from(&mut self.inbound[0].buffer).await?;
        // The readiness wake and the admission boundary can race. Linearize
        // admission after the receive completes, before publishing this first
        // datagram as an admitted userspace batch.
        ensure_udp_admission_open(admission_open)?;
        self.inbound[0].len = len;
        self.inbound[0].peer = peer;
        self.inbound[0].target = UdpPacketTarget::Socket(peer);
        let mut active = 1;

        while active < self.batch_size && admission_open.load(Ordering::Acquire) {
            match self.socket.try_recv_from(&mut self.inbound[active].buffer) {
                Ok((len, peer)) => {
                    // A close may race the optimistic loop condition. Consume
                    // and discard that datagram, but return the userspace batch
                    // that was already admitted before the boundary.
                    if ensure_udp_admission_open(admission_open).is_err() {
                        break;
                    }
                    self.inbound[active].len = len;
                    self.inbound[active].peer = peer;
                    self.inbound[active].target = UdpPacketTarget::Socket(peer);
                    active += 1;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => match classify_udp_recv_error(&error) {
                    UdpIoErrorAction::Continue => break,
                    UdpIoErrorAction::Backoff(duration) => {
                        warn!(
                            %error,
                            backoff_ms = duration.as_millis(),
                            "UDP receive resource pressure while draining batch; backing off"
                        );
                        tokio::time::sleep(duration).await;
                        break;
                    }
                    UdpIoErrorAction::Fatal => return Err(error),
                },
            }
        }

        Ok(&self.inbound[..active])
    }

    #[allow(clippy::infallible_destructuring_match)]
    async fn send_batch(
        &mut self,
        outbound: &[UdpOutbound],
        metrics: &RuntimeMetrics,
        _worker_id: usize,
    ) -> Result<usize, PacketIoSendError> {
        if outbound.is_empty() {
            return Ok(0);
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
                    return Err(PacketIoSendError::new(
                        std::io::Error::new(
                            ErrorKind::InvalidInput,
                            "standard UDP backend cannot send AF_XDP packet target",
                        ),
                        sent,
                    ));
                }
            };
            #[cfg(feature = "af-xdp")]
            if packet.benchmark_fixed_response {
                return Err(PacketIoSendError::new(
                    std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "standard UDP backend cannot send AF_XDP benchmark fixed response",
                    ),
                    sent,
                ));
            }
            match self.socket.send_to(&packet.response, peer).await {
                Ok(_) => {
                    sent += 1;
                    if let (Some(query_metrics), Some(started)) =
                        (&packet.query_metrics, send_started)
                    {
                        record_query_send_metric(
                            query_metrics,
                            &packet.response,
                            metrics,
                            started.elapsed(),
                        );
                    }
                }
                Err(error) => match classify_udp_send_error(&error) {
                    UdpIoErrorAction::Continue => {
                        metrics.record_udp_send_error();
                        debug!(%error, "UDP send error ignored");
                    }
                    UdpIoErrorAction::Backoff(duration) => {
                        metrics.record_udp_send_error();
                        warn!(
                            %error,
                            backoff_ms = duration.as_millis(),
                            "UDP send resource pressure; backing off"
                        );
                        tokio::time::sleep(duration).await;
                    }
                    UdpIoErrorAction::Fatal => {
                        return Err(PacketIoSendError::new(error, sent));
                    }
                },
            }
        }
        Ok(sent)
    }
}

pub(crate) fn ensure_udp_admission_open(admission_open: &AtomicBool) -> std::io::Result<()> {
    if admission_open.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(std::io::Error::from(ErrorKind::Interrupted))
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

    #[cfg(feature = "af-xdp")]
    fn benchmark_fixed_response(target: UdpPacketTarget) -> Self {
        Self {
            response: Vec::new(),
            target,
            query_metrics: None,
            benchmark_fixed_response: true,
        }
    }

    #[cfg(not(feature = "af-xdp"))]
    fn benchmark_fixed_response(_target: UdpPacketTarget) -> Self {
        unreachable!("AF_XDP fixed-response benchmark requires the af-xdp feature")
    }
}

pub(crate) const UDP_PACKET_BUFFER_LEN: usize = 4096;

#[cfg(feature = "af-xdp")]
fn benchmark_af_xdp_fixed_response_enabled() -> bool {
    // Benchmark-only diagnostic: bypass DNS parsing/composition and measure the
    // AF_XDP userspace frame lifecycle with a valid fixed positive response.
    std::env::var_os("BORONDNS_BENCH_AF_XDP_FIXED_RESPONSE").is_some()
}

#[cfg(not(feature = "af-xdp"))]
fn benchmark_af_xdp_fixed_response_enabled() -> bool {
    false
}

fn handle_udp_datagram(
    packet: &[u8],
    peer: SocketAddr,
    zones: &ZoneStore,
    settings: &UdpServerSettings,
) -> Option<UdpOutbound> {
    handle_udp_datagram_with_optional_prepared_hook(packet, peer, zones, settings, None)
}

#[cfg(test)]
pub(crate) fn handle_udp_datagram_with_prepared_hook(
    packet: &[u8],
    peer: SocketAddr,
    zones: &ZoneStore,
    settings: &UdpServerSettings,
    prepared_hook: &dyn Fn(),
) -> Option<UdpOutbound> {
    handle_udp_datagram_with_optional_prepared_hook(
        packet,
        peer,
        zones,
        settings,
        Some(prepared_hook),
    )
}

fn handle_udp_datagram_with_optional_prepared_hook(
    packet: &[u8],
    peer: SocketAddr,
    zones: &ZoneStore,
    settings: &UdpServerSettings,
    prepared_hook: Option<&dyn Fn()>,
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
            #[cfg(feature = "af-xdp")]
            benchmark_fixed_response: false,
        });
    }
    if let Some(prepared_hook) = prepared_hook {
        prepared_hook();
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
        let authorized = settings.notify_authority.is_authorized_for_token(
            qname,
            qclass,
            peer_ip,
            prepared.notify_policy_token.as_ref(),
        );
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
                        #[cfg(feature = "af-xdp")]
                        benchmark_fixed_response: false,
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
    pub(crate) started_at: Option<Instant>,
    pub(crate) cookie_validated: bool,
    pub(crate) zone_metric: Option<crate::health_metrics::ZoneMetricToken>,
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
    let lookup_started = metrics.start_pipeline_timer();
    let not_query = || QueryMetricObservation {
        is_query: false,
        transport: options.transport,
        started_at: None,
        cookie_validated: false,
        zone_metric: None,
        parse_duration: options.parse_duration,
        lookup_duration: lookup_started.map(|started| started.elapsed()),
        compose_duration: None,
    };
    if !metrics.hot_path_counters_enabled() {
        return not_query();
    }
    let started_at = Instant::now();
    let observed_query = |zone_metric| QueryMetricObservation {
        is_query: true,
        transport: options.transport,
        started_at: Some(started_at),
        cookie_validated: options.cookie_validated,
        zone_metric,
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
        return observed_query(metrics.record_published_zone_query(zones, &published_zone));
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
    observation: Option<&borondns_core::dns::ChaosQueryObservation>,
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
    if let Some(zone_metric) = &observation.zone_metric {
        metrics.record_zone_query_response_rcode(zone_metric, rcode);
    }
    if let Some(started_at) = observation.started_at {
        metrics.record_query_latency(
            query_latency_category(observation, response, &header),
            started_at.elapsed(),
        );
    }
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
