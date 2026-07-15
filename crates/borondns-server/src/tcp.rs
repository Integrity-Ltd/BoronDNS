use std::{
    collections::HashMap,
    future::Future,
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use borondns_core::{
    dns::{
        AnswerOptions, AnyResponseMode, ChaosOptions, DatagramAction, DomainName,
        ExtendedDnsErrorsMode, Header, Transport, ZoneImageProvider,
        answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image,
        chaos_query_observation, default_zone_image_provider, request_has_valid_dns_server_cookie,
    },
    zone::ZoneStore,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinSet,
};
use tracing::{debug, info, warn};

use crate::{
    CookiePrefixMetricSettings, DnsCookieRuntimeSettings, DnsCookieSecretStore, NotifyAuthority,
    NotifyLogLimiter, NotifyRefreshTracker, QueryMetricObservation, QueryObservationOptions,
    RefreshRequest, RuntimeError, RuntimeMetrics, dns_cookie_context, observe_dns_cookie_metrics,
    observe_query_metrics, prepare_notify_packet_with_metrics, prepare_query_tsig_packet,
    record_chaos_query_if_observed, record_dns_cookie_badcookie_if_emitted,
    record_query_lookup_metrics, record_query_response_metric, record_query_send_metric,
    record_response_cache_metric, response_cache_ineligible_reason, sign_tsig_response,
    signal_notify_refresh,
};

const ERRNO_EMFILE: i32 = 24;
const ERRNO_ENFILE: i32 = 23;
const ERRNO_ENOBUFS: i32 = 105;
const ERRNO_ENOMEM: i32 = 12;

#[cfg(test)]
pub(crate) async fn serve_tcp(
    listener: TcpListener,
    zones: ZoneStore,
    settings: TcpServerSettings,
) -> Result<(), RuntimeError> {
    serve_tcp_until(listener, zones, settings, std::future::pending()).await
}

pub(crate) async fn serve_tcp_until<F>(
    listener: TcpListener,
    zones: ZoneStore,
    settings: TcpServerSettings,
    graceful_stop: F,
) -> Result<(), RuntimeError>
where
    F: Future<Output = ()> + Send,
{
    let local_addr = listener.local_addr().map_err(RuntimeError::Tcp)?;
    info!(%local_addr, "TCP listener bound");
    let mut connections = JoinSet::new();
    let (connection_shutdown_tx, connection_shutdown_rx) = watch::channel(false);
    tokio::pin!(graceful_stop);

    loop {
        // Completed JoinSet entries retain their task allocation until joined.
        // Drain every completion already ready before polling accept so a
        // continuously readable listener cannot grow an unbounded completed
        // task backlog through the biased shutdown-first select below.
        reap_ready_tcp_connections(&mut connections, local_addr);
        let accepted = tokio::select! {
            biased;
            () = &mut graceful_stop => break,
            accepted = listener.accept() => accepted,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(%local_addr, %error, "TCP connection task failed");
                }
                continue;
            }
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => match classify_tcp_accept_error(&error) {
                TcpAcceptErrorAction::Continue => {
                    debug!(%local_addr, %error, "transient TCP accept error");
                    continue;
                }
                TcpAcceptErrorAction::Backoff(delay) => {
                    warn!(%local_addr, %error, "resource pressure during TCP accept; backing off");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                TcpAcceptErrorAction::Fatal => return Err(RuntimeError::Tcp(error)),
            },
        };
        let connection_permit = match try_acquire_tcp_connection_slot(
            settings.active_connections.clone(),
            settings.active_connections_by_source.clone(),
            peer.ip(),
            settings.max_connections,
            settings.max_connections_per_source,
        ) {
            Ok(permit) => permit,
            Err(TcpConnectionLimitExceeded::Global) => {
                warn!(
                    peer_ip = %peer.ip(),
                    peer_port = peer.port(),
                    transport = "tcp",
                    active_connections = settings.active_connections.load(Ordering::Relaxed),
                    limit = settings.max_connections,
                    "TCP connection limit reached; closing accepted connection"
                );
                drop(stream);
                continue;
            }
            Err(TcpConnectionLimitExceeded::Source { active, limit }) => {
                info!(
                    peer_ip = %peer.ip(),
                    peer_port = peer.port(),
                    transport = "tcp",
                    source_active_connections = active,
                    limit,
                    "TCP per-source connection limit reached; closing accepted connection"
                );
                drop(stream);
                continue;
            }
        };

        let zones = zones.clone();
        let settings = settings.clone();
        let connection_shutdown = connection_shutdown_rx.clone();
        connections.spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(error) = handle_tcp_connection_until(
                stream,
                zones,
                settings.idle_timeout,
                settings.max_udp_payload,
                settings.max_cname_chain,
                settings.nsec3_max_iterations,
                settings.read_timeout,
                settings.write_timeout,
                settings.max_inflight_queries_per_connection,
                settings.inflight_limit_timeout,
                settings.edns_padding_block_size,
                settings.extended_dns_errors,
                settings.any_response,
                settings.nsid,
                settings.chaos_version,
                settings.chaos_hostname,
                settings.dns_cookie_secrets,
                settings.dns_cookie,
                settings.cookie_prefix_metrics,
                settings.notify_authority,
                settings.notify_refresh,
                settings.notify_refresh_tx,
                settings.notify_log_limiter,
                settings.metrics,
                peer.ip(),
                connection_shutdown,
            )
            .await
            {
                warn!(
                    peer_ip = %peer.ip(),
                    peer_port = peer.port(),
                    transport = "tcp",
                    %error,
                    "TCP connection failed"
                );
            }
        });
    }

    let _ = connection_shutdown_tx.send(true);
    drop(listener);
    info!(
        %local_addr,
        active_connections = connections.len(),
        "TCP listener stopped; draining established connections"
    );
    while let Some(completed) = connections.join_next().await {
        if let Err(error) = completed {
            warn!(%local_addr, %error, "TCP connection task failed during drain");
        }
    }
    info!(%local_addr, "TCP established connection drain completed");
    Ok(())
}

fn reap_ready_tcp_connections(connections: &mut JoinSet<()>, local_addr: SocketAddr) -> usize {
    let mut reaped = 0usize;
    while let Some(completed) = connections.try_join_next() {
        if let Err(error) = completed {
            warn!(%local_addr, %error, "TCP connection task failed");
        }
        reaped = reaped.saturating_add(1);
    }
    reaped
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpAcceptErrorAction {
    Continue,
    Backoff(Duration),
    Fatal,
}

pub(crate) fn classify_tcp_accept_error(error: &io::Error) -> TcpAcceptErrorAction {
    match error.kind() {
        ErrorKind::ConnectionAborted | ErrorKind::Interrupted => TcpAcceptErrorAction::Continue,
        _ if is_tcp_accept_resource_pressure(error) => {
            TcpAcceptErrorAction::Backoff(Duration::from_millis(50))
        }
        _ => TcpAcceptErrorAction::Fatal,
    }
}

fn is_tcp_accept_resource_pressure(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(ERRNO_EMFILE | ERRNO_ENFILE | ERRNO_ENOBUFS | ERRNO_ENOMEM)
    )
}

#[derive(Clone)]
pub(crate) struct TcpServerSettings {
    pub(crate) max_udp_payload: u16,
    pub(crate) max_cname_chain: usize,
    pub(crate) nsec3_max_iterations: u16,
    pub(crate) idle_timeout: Duration,
    pub(crate) read_timeout: Duration,
    pub(crate) write_timeout: Duration,
    pub(crate) max_connections: usize,
    pub(crate) max_connections_per_source: Option<usize>,
    pub(crate) max_inflight_queries_per_connection: usize,
    pub(crate) inflight_limit_timeout: Duration,
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
    pub(crate) active_connections: Arc<AtomicUsize>,
    pub(crate) active_connections_by_source: TcpSourceConnectionCounts,
}

struct TcpConnectionPermit {
    active: Arc<AtomicUsize>,
    source_counts: Option<TcpSourceConnectionCounts>,
    peer_ip: IpAddr,
}

pub(crate) type TcpSourceConnectionCounts = Arc<Mutex<HashMap<IpAddr, usize>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpConnectionLimitExceeded {
    Global,
    Source { active: usize, limit: usize },
}

pub(crate) type TcpQueryHook =
    Arc<dyn Fn(u16) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + Sync + 'static>;
impl Drop for TcpConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Release);
        let Some(source_counts) = &self.source_counts else {
            return;
        };
        let mut counts = source_counts
            .lock()
            .expect("TCP source connection counter lock poisoned");
        if let Some(count) = counts.get_mut(&self.peer_ip) {
            if *count <= 1 {
                counts.remove(&self.peer_ip);
            } else {
                *count -= 1;
            }
        }
    }
}

fn try_acquire_tcp_connection_slot(
    active: Arc<AtomicUsize>,
    source_counts: TcpSourceConnectionCounts,
    peer_ip: IpAddr,
    limit: usize,
    source_limit: Option<usize>,
) -> Result<TcpConnectionPermit, TcpConnectionLimitExceeded> {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < limit).then_some(current + 1)
        })
        .map_err(|_| TcpConnectionLimitExceeded::Global)?;

    if let Some(source_limit) = source_limit {
        let mut counts = source_counts
            .lock()
            .expect("TCP source connection counter lock poisoned");
        let source_active = counts.get(&peer_ip).copied().unwrap_or(0);
        if source_active >= source_limit {
            active.fetch_sub(1, Ordering::Release);
            return Err(TcpConnectionLimitExceeded::Source {
                active: source_active,
                limit: source_limit,
            });
        }
        counts.insert(peer_ip, source_active + 1);
        Ok(TcpConnectionPermit {
            active,
            source_counts: Some(source_counts.clone()),
            peer_ip,
        })
    } else {
        Ok(TcpConnectionPermit {
            active,
            source_counts: None,
            peer_ip,
        })
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) async fn handle_tcp_connection(
    stream: TcpStream,
    zones: ZoneStore,
    idle_timeout: Duration,
    max_udp_payload: u16,
    max_cname_chain: usize,
    nsec3_max_iterations: u16,
    read_timeout: Duration,
    write_timeout: Duration,
    max_inflight_queries_per_connection: usize,
    inflight_limit_timeout: Duration,
    edns_padding_block_size: u16,
    extended_dns_errors: ExtendedDnsErrorsMode,
    any_response: AnyResponseMode,
    nsid: Vec<u8>,
    chaos_version: String,
    chaos_hostname: String,
    dns_cookie_secrets: DnsCookieSecretStore,
    dns_cookie: DnsCookieRuntimeSettings,
    cookie_prefix_metrics: CookiePrefixMetricSettings,
    notify_authority: NotifyAuthority,
    notify_refresh: NotifyRefreshTracker,
    notify_refresh_tx: mpsc::Sender<RefreshRequest>,
    notify_log_limiter: NotifyLogLimiter,
    metrics: RuntimeMetrics,
    peer_ip: IpAddr,
) -> Result<(), RuntimeError> {
    handle_tcp_connection_with_query_hook(
        stream,
        zones,
        idle_timeout,
        max_udp_payload,
        max_cname_chain,
        nsec3_max_iterations,
        read_timeout,
        write_timeout,
        max_inflight_queries_per_connection,
        inflight_limit_timeout,
        edns_padding_block_size,
        extended_dns_errors,
        any_response,
        nsid,
        chaos_version,
        chaos_hostname,
        dns_cookie_secrets,
        dns_cookie,
        cookie_prefix_metrics,
        notify_authority,
        notify_refresh,
        notify_refresh_tx,
        notify_log_limiter,
        metrics,
        peer_ip,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_tcp_connection_until(
    stream: TcpStream,
    zones: ZoneStore,
    idle_timeout: Duration,
    max_udp_payload: u16,
    max_cname_chain: usize,
    nsec3_max_iterations: u16,
    read_timeout: Duration,
    write_timeout: Duration,
    max_inflight_queries_per_connection: usize,
    inflight_limit_timeout: Duration,
    edns_padding_block_size: u16,
    extended_dns_errors: ExtendedDnsErrorsMode,
    any_response: AnyResponseMode,
    nsid: Vec<u8>,
    chaos_version: String,
    chaos_hostname: String,
    dns_cookie_secrets: DnsCookieSecretStore,
    dns_cookie: DnsCookieRuntimeSettings,
    cookie_prefix_metrics: CookiePrefixMetricSettings,
    notify_authority: NotifyAuthority,
    notify_refresh: NotifyRefreshTracker,
    notify_refresh_tx: mpsc::Sender<RefreshRequest>,
    notify_log_limiter: NotifyLogLimiter,
    metrics: RuntimeMetrics,
    peer_ip: IpAddr,
    connection_shutdown: watch::Receiver<bool>,
) -> Result<(), RuntimeError> {
    handle_tcp_connection_with_query_hook_until(
        stream,
        zones,
        idle_timeout,
        max_udp_payload,
        max_cname_chain,
        nsec3_max_iterations,
        read_timeout,
        write_timeout,
        max_inflight_queries_per_connection,
        inflight_limit_timeout,
        edns_padding_block_size,
        extended_dns_errors,
        any_response,
        nsid,
        chaos_version,
        chaos_hostname,
        dns_cookie_secrets,
        dns_cookie,
        cookie_prefix_metrics,
        notify_authority,
        notify_refresh,
        notify_refresh_tx,
        notify_log_limiter,
        metrics,
        peer_ip,
        None,
        Some(connection_shutdown),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) async fn handle_tcp_connection_with_query_hook(
    stream: TcpStream,
    zones: ZoneStore,
    idle_timeout: Duration,
    max_udp_payload: u16,
    max_cname_chain: usize,
    nsec3_max_iterations: u16,
    read_timeout: Duration,
    write_timeout: Duration,
    max_inflight_queries_per_connection: usize,
    inflight_limit_timeout: Duration,
    edns_padding_block_size: u16,
    extended_dns_errors: ExtendedDnsErrorsMode,
    any_response: AnyResponseMode,
    nsid: Vec<u8>,
    chaos_version: String,
    chaos_hostname: String,
    dns_cookie_secrets: DnsCookieSecretStore,
    dns_cookie: DnsCookieRuntimeSettings,
    cookie_prefix_metrics: CookiePrefixMetricSettings,
    notify_authority: NotifyAuthority,
    notify_refresh: NotifyRefreshTracker,
    notify_refresh_tx: mpsc::Sender<RefreshRequest>,
    notify_log_limiter: NotifyLogLimiter,
    metrics: RuntimeMetrics,
    peer_ip: IpAddr,
    query_hook: Option<TcpQueryHook>,
) -> Result<(), RuntimeError> {
    handle_tcp_connection_with_query_hook_until(
        stream,
        zones,
        idle_timeout,
        max_udp_payload,
        max_cname_chain,
        nsec3_max_iterations,
        read_timeout,
        write_timeout,
        max_inflight_queries_per_connection,
        inflight_limit_timeout,
        edns_padding_block_size,
        extended_dns_errors,
        any_response,
        nsid,
        chaos_version,
        chaos_hostname,
        dns_cookie_secrets,
        dns_cookie,
        cookie_prefix_metrics,
        notify_authority,
        notify_refresh,
        notify_refresh_tx,
        notify_log_limiter,
        metrics,
        peer_ip,
        query_hook,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection_with_query_hook_until(
    stream: TcpStream,
    zones: ZoneStore,
    idle_timeout: Duration,
    max_udp_payload: u16,
    max_cname_chain: usize,
    nsec3_max_iterations: u16,
    read_timeout: Duration,
    write_timeout: Duration,
    max_inflight_queries_per_connection: usize,
    inflight_limit_timeout: Duration,
    edns_padding_block_size: u16,
    extended_dns_errors: ExtendedDnsErrorsMode,
    any_response: AnyResponseMode,
    nsid: Vec<u8>,
    chaos_version: String,
    chaos_hostname: String,
    dns_cookie_secrets: DnsCookieSecretStore,
    dns_cookie: DnsCookieRuntimeSettings,
    cookie_prefix_metrics: CookiePrefixMetricSettings,
    notify_authority: NotifyAuthority,
    notify_refresh: NotifyRefreshTracker,
    notify_refresh_tx: mpsc::Sender<RefreshRequest>,
    notify_log_limiter: NotifyLogLimiter,
    metrics: RuntimeMetrics,
    peer_ip: IpAddr,
    query_hook: Option<TcpQueryHook>,
    mut connection_shutdown: Option<watch::Receiver<bool>>,
) -> Result<(), RuntimeError> {
    let (mut reader, writer) = stream.into_split();
    let inflight = Arc::new(Semaphore::new(max_inflight_queries_per_connection));
    let (response_tx, response_rx) = mpsc::channel(max_inflight_queries_per_connection);
    let writer_metrics = metrics.clone();
    let read_queries = async move {
        let mut query_tasks = JoinSet::new();
        let mut read_error = None;

        while !response_tx.is_closed() {
            let permit_result = tokio::select! {
                biased;
                result = tokio::time::timeout(
                    inflight_limit_timeout,
                    inflight.clone().acquire_owned(),
                ) => result,
                () = wait_for_connection_shutdown(&mut connection_shutdown) => break,
            };
            let permit = match permit_result {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => break,
                Err(_) => {
                    info!(
                        %peer_ip,
                        transport = "tcp",
                        limit = max_inflight_queries_per_connection,
                        timeout_secs = inflight_limit_timeout.as_secs(),
                        "TCP connection remained at in-flight query limit; closing connection"
                    );
                    break;
                }
            };

            // The first frame-length octet completing into user space is the
            // deterministic admission boundary. Once it has been read, finish
            // that frame even if graceful stop arrives; once graceful stop
            // wins this select, perform no opportunistic socket read and
            // accept no frame that only existed in the kernel receive queue.
            let first_len_byte =
                read_tcp_frame_admission(&mut reader, idle_timeout, &mut connection_shutdown)
                    .await?;
            let Some(first_len_byte) = first_len_byte else {
                drop(permit);
                break;
            };
            let packet = match read_tcp_message_after_first_len_byte(
                &mut reader,
                first_len_byte,
                read_timeout,
            )
            .await
            {
                Ok(Some(packet)) => packet,
                Ok(None) => {
                    drop(permit);
                    break;
                }
                Err(error) => {
                    drop(permit);
                    read_error = Some(error);
                    break;
                }
            };

            query_tasks.spawn(handle_tcp_packet(
                packet,
                zones.clone(),
                idle_timeout,
                max_udp_payload,
                max_cname_chain,
                nsec3_max_iterations,
                edns_padding_block_size,
                extended_dns_errors,
                any_response,
                nsid.clone(),
                chaos_version.clone(),
                chaos_hostname.clone(),
                dns_cookie_secrets.clone(),
                dns_cookie,
                cookie_prefix_metrics,
                notify_authority.clone(),
                notify_refresh.clone(),
                notify_refresh_tx.clone(),
                notify_log_limiter.clone(),
                metrics.clone(),
                peer_ip,
                response_tx.clone(),
                permit,
                query_hook.clone(),
            ));

            if connection_shutdown
                .as_mut()
                .is_some_and(|shutdown| *shutdown.borrow_and_update())
            {
                break;
            }

            while let Some(join_result) = query_tasks.try_join_next() {
                if let Err(error) = join_result {
                    warn!(%peer_ip, %error, "TCP query task failed");
                }
            }
        }

        drop(response_tx);
        while let Some(join_result) = query_tasks.join_next().await {
            if let Err(error) = join_result {
                warn!(%peer_ip, %error, "TCP query task failed");
            }
        }

        read_error.map_or(Ok(()), Err)
    };
    let writer = write_tcp_responses(writer, response_rx, write_timeout, writer_metrics);
    coordinate_tcp_io(read_queries, writer).await
}

async fn coordinate_tcp_io<R, W>(read_queries: R, writer: W) -> Result<(), RuntimeError>
where
    R: Future<Output = Result<(), RuntimeError>>,
    W: Future<Output = Result<(), RuntimeError>>,
{
    tokio::pin!(read_queries);
    tokio::pin!(writer);
    tokio::select! {
        biased;
        read_result = &mut read_queries => {
            // EOF and graceful shutdown stop admission, but already-admitted
            // query tasks retain their permits and may still enqueue responses.
            // Drain those responses before completing the connection.
            writer.await?;
            read_result
        }
        writer_result = &mut writer => {
            // A failed or timed-out writer can no longer make progress. Returning
            // drops the read future and its JoinSet, promptly cancelling socket
            // admission and every query task that still owns an in-flight permit.
            writer_result
        }
    }
}

async fn wait_for_connection_shutdown(receiver: &mut Option<watch::Receiver<bool>>) {
    let Some(receiver) = receiver else {
        std::future::pending::<()>().await;
        return;
    };
    loop {
        if *receiver.borrow_and_update() {
            return;
        }
        if receiver.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

pub(crate) async fn read_tcp_frame_admission<R>(
    stream: &mut R,
    idle_timeout: Duration,
    connection_shutdown: &mut Option<watch::Receiver<bool>>,
) -> Result<Option<u8>, RuntimeError>
where
    R: AsyncRead + Unpin,
{
    tokio::select! {
        biased;
        () = wait_for_connection_shutdown(connection_shutdown) => Ok(None),
        result = read_tcp_byte(stream, idle_timeout) => result,
    }
}

struct TcpResponse {
    response: Vec<u8>,
    query_observation: Option<QueryMetricObservation>,
    permit: OwnedSemaphorePermit,
}

async fn write_tcp_responses(
    mut writer: impl AsyncWrite + Unpin,
    mut responses: mpsc::Receiver<TcpResponse>,
    write_timeout: Duration,
    metrics: RuntimeMetrics,
) -> Result<(), RuntimeError> {
    while let Some(response) = responses.recv().await {
        let TcpResponse {
            response,
            query_observation,
            permit,
        } = response;
        let send_started = metrics.start_pipeline_timer();
        if !write_tcp_message(&mut writer, &response, write_timeout).await? {
            return Ok(());
        }
        if let (Some(started), Some(observation)) = (send_started, query_observation.as_ref()) {
            record_query_send_metric(observation, &response, &metrics, started.elapsed());
        }
        drop(permit);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_packet(
    packet: Vec<u8>,
    zones: ZoneStore,
    idle_timeout: Duration,
    max_udp_payload: u16,
    max_cname_chain: usize,
    nsec3_max_iterations: u16,
    edns_padding_block_size: u16,
    extended_dns_errors: ExtendedDnsErrorsMode,
    any_response: AnyResponseMode,
    nsid: Vec<u8>,
    chaos_version: String,
    chaos_hostname: String,
    dns_cookie_secrets: DnsCookieSecretStore,
    dns_cookie: DnsCookieRuntimeSettings,
    cookie_prefix_metrics: CookiePrefixMetricSettings,
    notify_authority: NotifyAuthority,
    notify_refresh: NotifyRefreshTracker,
    notify_refresh_tx: mpsc::Sender<RefreshRequest>,
    notify_log_limiter: NotifyLogLimiter,
    metrics: RuntimeMetrics,
    peer_ip: IpAddr,
    response_tx: mpsc::Sender<TcpResponse>,
    permit: OwnedSemaphorePermit,
    query_hook: Option<TcpQueryHook>,
) {
    let query_id = Header::parse(&packet).ok().map(|header| header.id);

    let parse_started = metrics.start_pipeline_timer();
    let Some(prepared) = prepare_notify_packet_with_metrics(
        &packet,
        &notify_authority,
        peer_ip,
        &metrics,
        &notify_log_limiter,
    ) else {
        debug!(
            %peer_ip,
            transport = "tcp",
            bytes = packet.len(),
            "discarded DNS-over-TCP message"
        );
        return;
    };
    let prepared = prepare_query_tsig_packet(prepared, &notify_authority);
    let parse_duration = parse_started.map(|started| started.elapsed());
    if let Some(response) = prepared.immediate_response {
        if let (Some(hook), Some(query_id)) = (&query_hook, query_id) {
            hook(query_id).await;
        }
        let _ = response_tx
            .send(TcpResponse {
                response,
                query_observation: None,
                permit,
            })
            .await;
        return;
    }
    if let (Some(hook), Some(query_id)) = (&query_hook, query_id) {
        // This boundary is after cryptographic preparation but before final
        // policy authorization resolves concurrent snapshot replacement.
        hook(query_id).await;
    }
    let secrets = dns_cookie_secrets.current();
    let dns_cookie = dns_cookie_context(peer_ip, &secrets, dns_cookie);
    let cookie_validated = dns_cookie
        .is_some_and(|context| request_has_valid_dns_server_cookie(&prepared.packet, context));
    let query_metrics = observe_query_metrics(
        &prepared.packet,
        &zones,
        &metrics,
        QueryObservationOptions {
            transport: Transport::Tcp,
            cookie_validated,
            parse_duration,
        },
    );
    let query_tsig_authenticated = prepared.tsig_authenticated || prepared.response_tsig.is_some();
    let query_cache_ineligible = response_cache_ineligible_reason(
        query_tsig_authenticated,
        dns_cookie.is_some(),
        false,
        edns_padding_block_size,
    );
    let dns_cookie_metrics = observe_dns_cookie_metrics(
        &prepared.packet,
        dns_cookie,
        peer_ip,
        cookie_prefix_metrics,
        &metrics,
    );
    let chaos = ChaosOptions {
        version: &chaos_version,
        hostname: &chaos_hostname,
    };
    let chaos_observation = chaos_query_observation(&prepared.packet, &nsid, chaos);
    let compose_started = metrics.start_pipeline_timer();
    let answer_options = AnswerOptions {
        transport: Transport::Tcp,
        max_udp_payload,
        max_cname_chain,
        nsec3_max_iterations,
        tcp_keepalive_timeout_secs: idle_timeout.as_secs(),
        edns_padding_block_size,
        extended_dns_errors,
        any_response,
        nsid: &nsid,
        chaos,
        dns_cookie,
    };
    let notify_authorized = |qname: &DomainName, qclass| {
        let authorized = notify_authority.is_authorized_for_token(
            qname,
            qclass,
            peer_ip,
            prepared.notify_policy_token.as_ref(),
        );
        if !authorized {
            metrics.record_notify_unauthorized();
            notify_log_limiter.log_unauthorized(peer_ip, qname);
        }
        authorized
    };
    let notify_accepted = |qname: &DomainName, _qclass, serial| {
        signal_notify_refresh(
            &notify_refresh,
            &notify_refresh_tx,
            &metrics,
            qname,
            peer_ip,
            serial,
        )
    };
    let lookup_observed =
        |lookup_metrics| record_query_lookup_metrics(&query_metrics, lookup_metrics, &metrics);
    let action = answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        &prepared.packet,
        &zones,
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
                %peer_ip,
                transport = "tcp",
                bytes = packet.len(),
                "discarded DNS-over-TCP message"
            );
        }
        DatagramAction::Respond(response) => {
            record_chaos_query_if_observed(
                chaos_observation.as_ref(),
                &response,
                &metrics,
                peer_ip,
                "tcp",
            );
            record_dns_cookie_badcookie_if_emitted(
                dns_cookie_metrics,
                &response,
                &metrics,
                peer_ip,
                cookie_prefix_metrics,
            );
            record_query_response_metric(&query_metrics, &response, &metrics);
            let response = match sign_tsig_response(response, prepared.response_tsig) {
                Ok(response) => response,
                Err(error) => {
                    warn!(
                        %peer_ip,
                        transport = "tcp",
                        %error,
                        "failed to sign TSIG response"
                    );
                    return;
                }
            };
            record_response_cache_metric(
                &query_metrics,
                &response,
                &metrics,
                query_cache_ineligible,
            );
            let _ = response_tx
                .send(TcpResponse {
                    response,
                    query_observation: Some(query_metrics),
                    permit,
                })
                .await;
        }
    }
}

pub(crate) async fn write_tcp_message<W>(
    stream: &mut W,
    message: &[u8],
    write_timeout: Duration,
) -> Result<bool, RuntimeError>
where
    W: AsyncWrite + Unpin,
{
    let framed = frame_dns_tcp_message(message)?;
    match tokio::time::timeout(write_timeout, stream.write_all(&framed)).await {
        Ok(Ok(())) => Ok(true),
        Ok(Err(error)) => Err(RuntimeError::Tcp(error)),
        Err(_) => Ok(false),
    }
}

pub(crate) async fn read_tcp_message_after_first_len_byte<R>(
    stream: &mut R,
    first_len_byte: u8,
    read_timeout: Duration,
) -> Result<Option<Vec<u8>>, RuntimeError>
where
    R: AsyncRead + Unpin,
{
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

async fn read_tcp_byte<R>(
    stream: &mut R,
    idle_timeout: Duration,
) -> Result<Option<u8>, RuntimeError>
where
    R: AsyncRead + Unpin,
{
    match tokio::time::timeout(idle_timeout, stream.read_u8()).await {
        Ok(Ok(byte)) => Ok(Some(byte)),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Ok(Err(error)) => Err(RuntimeError::Tcp(error)),
        Err(_) => Ok(None),
    }
}

fn frame_dns_tcp_message(message: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let len = u16::try_from(message.len()).map_err(|_| {
        RuntimeError::Tcp(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS-over-TCP response exceeds 65535-byte frame limit",
        ))
    })?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    Ok(framed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn completed_connection_churn_is_reaped_to_a_bounded_join_set() {
        let local_addr: SocketAddr = "127.0.0.1:53".parse().expect("static socket address");
        let mut connections = JoinSet::new();
        let mut maximum_resident = 0usize;

        for _ in 0..10_000 {
            connections.spawn(async {});
            maximum_resident = maximum_resident.max(connections.len());
            while reap_ready_tcp_connections(&mut connections, local_addr) == 0 {
                tokio::task::yield_now().await;
            }
            assert!(connections.is_empty());
        }

        assert_eq!(maximum_resident, 1);
    }

    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                let _ = signal.send(());
            }
        }
    }

    struct BackpressuredWriter;

    impl AsyncWrite for BackpressuredWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buffer: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Pending
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct FailingWriter;

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buffer: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "deterministic test writer failure",
            )))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    async fn assert_writer_termination_cancels_reader(
        writer: impl AsyncWrite + Unpin,
        expect_error: bool,
    ) {
        let inflight = Arc::new(Semaphore::new(2));
        let response_permit = inflight
            .clone()
            .acquire_owned()
            .await
            .expect("test response permit");
        let (response_tx, response_rx) = mpsc::channel(1);
        response_tx
            .send(TcpResponse {
                response: vec![0; 12],
                query_observation: None,
                permit: response_permit,
            })
            .await
            .expect("queue deterministic test response");
        drop(response_tx);

        let iterations = Arc::new(AtomicUsize::new(0));
        let query_iterations = iterations.clone();
        let query_permit = inflight
            .clone()
            .acquire_owned()
            .await
            .expect("test query-task permit");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
        let mut query_tasks = JoinSet::new();
        query_tasks.spawn(async move {
            let _permit = query_permit;
            let _cancelled = DropSignal(Some(cancelled_tx));
            let _ = started_tx.send(());
            loop {
                query_iterations.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        });
        started_rx.await.expect("continuing query task must start");
        let reader = async move {
            let _query_tasks = query_tasks;
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok(())
        };
        let writer = write_tcp_responses(
            writer,
            response_rx,
            Duration::from_millis(20),
            RuntimeMetrics::new(),
        );

        let result =
            tokio::time::timeout(Duration::from_secs(1), coordinate_tcp_io(reader, writer))
                .await
                .expect("writer termination must stop the connection promptly");
        assert_eq!(result.is_err(), expect_error);
        cancelled_rx
            .await
            .expect("dropping the reader JoinSet must abort its continuing query task");
        assert_eq!(
            inflight.available_permits(),
            2,
            "writer termination releases response and query-task ownership"
        );
        let stopped_at = iterations.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            iterations.load(Ordering::Relaxed),
            stopped_at,
            "the reader task must consume no CPU after writer death"
        );
    }

    #[tokio::test]
    async fn backpressured_writer_timeout_cancels_continuing_reader() {
        assert_writer_termination_cancels_reader(BackpressuredWriter, false).await;
    }

    #[tokio::test]
    async fn failed_writer_cancels_continuing_reader() {
        assert_writer_termination_cancels_reader(FailingWriter, true).await;
    }

    fn tcp_server_settings_for_drain_test(
        active_connections: Arc<AtomicUsize>,
    ) -> TcpServerSettings {
        let (notify_refresh_tx, _notify_refresh_rx) = mpsc::channel(1);
        TcpServerSettings {
            max_udp_payload: 1232,
            max_cname_chain: 8,
            nsec3_max_iterations: 100,
            idle_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            max_connections: 8,
            max_connections_per_source: None,
            max_inflight_queries_per_connection: 8,
            inflight_limit_timeout: Duration::from_secs(30),
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Minimal,
            nsid: Vec::new(),
            chaos_version: String::new(),
            chaos_hostname: String::new(),
            dns_cookie_secrets: DnsCookieSecretStore::new([7; 16], None),
            dns_cookie: DnsCookieRuntimeSettings {
                policy: None,
                past_window_secs: 3600,
                future_window_secs: 300,
                secret_rotation_interval: None,
            },
            cookie_prefix_metrics: CookiePrefixMetricSettings {
                ipv4_prefix_len: 24,
                ipv6_prefix_len: 56,
            },
            notify_authority: NotifyAuthority::default(),
            notify_refresh: NotifyRefreshTracker::new(Duration::from_secs(1)),
            notify_refresh_tx,
            notify_log_limiter: NotifyLogLimiter::new(Duration::from_secs(60), 1_024),
            metrics: RuntimeMetrics::new(),
            active_connections,
            active_connections_by_source: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[test]
    fn tcp_frame_rejects_messages_above_dns_tcp_limit() {
        let oversized = vec![0u8; usize::from(u16::MAX) + 1];
        let error = frame_dns_tcp_message(&oversized).expect_err("oversized TCP DNS message");

        assert!(matches!(error, RuntimeError::Tcp(_)));
    }

    #[test]
    fn tcp_frame_prefixes_exact_message_length() {
        let framed = frame_dns_tcp_message(&[1, 2, 3, 4]).expect("valid TCP DNS message");

        assert_eq!(&framed[..2], &4u16.to_be_bytes());
        assert_eq!(&framed[2..], &[1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn tcp_connection_join_set_drains_or_cancels_with_its_owner() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let mut drain_owner = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            connections.spawn(async move {
                let _ = started_tx.send(());
                let _ = finish_rx.await;
            });
            while connections.join_next().await.is_some() {}
        });

        started_rx.await.expect("connection task should start");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut drain_owner)
                .await
                .is_err(),
            "drain owner must retain and await an established connection"
        );
        finish_tx.send(()).expect("connection task should be alive");
        tokio::time::timeout(Duration::from_secs(1), drain_owner)
            .await
            .expect("connection drain should finish")
            .expect("drain owner should not fail");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
        let force_cancel_owner = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            connections.spawn(async move {
                let _drop_signal = DropSignal(Some(cancelled_tx));
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            });
            while connections.join_next().await.is_some() {}
        });

        started_rx.await.expect("connection task should start");
        force_cancel_owner.abort();
        let _ = force_cancel_owner.await;
        tokio::time::timeout(Duration::from_secs(1), cancelled_rx)
            .await
            .expect("aborting the owner should cancel its connection tasks")
            .expect("connection task should emit its drop signal");
    }

    #[tokio::test]
    async fn graceful_stop_closes_listener_and_idle_established_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let active_connections = Arc::new(AtomicUsize::new(0));
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_tcp_until(
            listener,
            ZoneStore::new(),
            tcp_server_settings_for_drain_test(active_connections.clone()),
            async move {
                let _ = stop_rx.await;
            },
        ));

        let mut established = TcpStream::connect(addr).await.unwrap();
        for _ in 0..100 {
            if active_connections.load(Ordering::Acquire) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(active_connections.load(Ordering::Acquire), 1);

        stop_tx.send(()).expect("TCP server should await stop");
        let listener_closed = async {
            while let Ok(probe) = TcpStream::connect(addr).await {
                drop(probe);
                tokio::task::yield_now().await;
            }
        };
        tokio::time::timeout(Duration::from_secs(1), listener_closed)
            .await
            .expect("graceful stop should close the TCP listener");
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("server should stop idle established connection reads")
            .expect("TCP server task should not fail")
            .expect("TCP server should stop cleanly");
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(1), established.read(&mut byte))
            .await
            .expect("idle established connection should close promptly");
        assert!(matches!(closed, Ok(0) | Err(_)));
        assert_eq!(active_connections.load(Ordering::Acquire), 0);
    }
}
