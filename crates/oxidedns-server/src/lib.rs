#![deny(unsafe_code)]

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    future::Future,
    io::Write,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod privilege;
mod process_hardening;
mod process_signals;
mod resource_limits;

use axum::{
    Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use flate2::{Compression, write::GzEncoder};
use oxidedns_core::{
    ConfigWarning, ServerConfig,
    axfr::{self, AxfrError, IxfrResponse},
    catalog::{CatalogError, parse_catalog_members},
    config::{
        CatalogZoneConfig, CookieConfig, CookiePolicyConfig, HealthConfig, RrlConfig,
        TransferPrimaryConfig, TransferTransportConfig, ZoneConfig,
    },
    dns::{
        AnswerOptions, AnyResponseMode, ChaosOptions, ChaosQueryOutcome,
        DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS, DatagramAction, DnsCookieContext, DnsCookiePolicy,
        DnsCookieRequestStatus, DomainName, ExtendedDnsErrorsMode, Header, LookupResult,
        LookupTermination, Opcode, Question, Rcode, RecordType, Transport,
        answer_message_with_notify_hooks_and_query_observer, chaos_query_observation,
        dns_cookie_request_status, request_has_valid_dns_server_cookie,
    },
    tsig::{
        DEFAULT_TSIG_FUDGE_SECS, TSIG_ERROR_BADALG, TSIG_ERROR_BADKEY, TSIG_ERROR_BADSIG,
        TSIG_ERROR_BADTIME, TSIG_ERROR_BADTRUNC, TsigError, TsigErrorResponseFields, TsigKey,
        append_unsigned_tsig_error, extract_tsig_mac, message_tsig_key, message_tsig_owner_name,
        sign_tsig_error_response,
    },
    zone::{SoaTimers, ZoneSnapshot, ZoneState, ZoneStore},
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinSet,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    },
};
use tracing::{debug, error, info, warn};
use x509_parser::parse_x509_certificate;

// ODS-NFR-MAINT-004 principal functional requirement references for runtime
// transport, NOTIFY, zone refresh scheduling, XoT, and response-rate limiting:
// - ODS-FR-TCP-001 ODS-FR-TCP-002 ODS-FR-TCP-003 ODS-FR-TCP-004
// - ODS-FR-TCP-005 ODS-FR-TCP-006 ODS-FR-TCP-007 ODS-FR-TCP-008
// - ODS-FR-TCP-009 ODS-FR-TCP-010 ODS-FR-TCP-011
// - ODS-FR-NOTIFY-001 ODS-FR-NOTIFY-002 ODS-FR-NOTIFY-003
// - ODS-FR-NOTIFY-004 ODS-FR-NOTIFY-005 ODS-FR-NOTIFY-006
// - ODS-FR-NOTIFY-007 ODS-FR-NOTIFY-008 ODS-FR-NOTIFY-009
// - ODS-FR-NOTIFY-010 ODS-FR-NOTIFY-011
// - ODS-FR-ZSM-001 ODS-FR-ZSM-002 ODS-FR-ZSM-003 ODS-FR-ZSM-004
// - ODS-FR-ZSM-005 ODS-FR-ZSM-006 ODS-FR-ZSM-007 ODS-FR-ZSM-008
// - ODS-FR-ZSM-009 ODS-FR-ZSM-010 ODS-FR-ZSM-011 ODS-FR-ZSM-012
// - ODS-FR-ZSM-013 ODS-FR-ZSM-014
// - ODS-FR-XOT-001 ODS-FR-XOT-002 ODS-FR-XOT-003 ODS-FR-XOT-004
// - ODS-FR-XOT-005 ODS-FR-XOT-006 ODS-FR-XOT-007 ODS-FR-XOT-008
// - ODS-FR-XOT-009 ODS-FR-XOT-010 ODS-FR-XOT-011 ODS-FR-XOT-012
// - ODS-FR-RRL-001 ODS-FR-RRL-002 ODS-FR-RRL-003 ODS-FR-RRL-004
// - ODS-FR-RRL-005 ODS-FR-RRL-006 ODS-FR-RRL-007 ODS-FR-RRL-008
// - ODS-FR-RRL-009 ODS-FR-RRL-010 ODS-FR-RRL-011 ODS-FR-RRL-012
pub const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_COMMIT: &str = env!("OXIDEDNS_BUILD_COMMIT");
pub const BUILD_RUST_VERSION: &str = env!("OXIDEDNS_BUILD_RUST_VERSION");
pub const BUILD_TIMESTAMP: &str = env!("OXIDEDNS_BUILD_TIMESTAMP");
const EDNS_EXTENDED_DNS_ERROR_OPTION: u16 = 15;
const EDE_UNSUPPORTED_NSEC3_ITERATIONS: u16 = 27;

#[cfg(unix)]
pub use process_signals::install_process_signal_dispositions;

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

    #[error("invalid runtime configuration: {0}")]
    InvalidRuntimeConfig(String),

    #[error("failed to generate DNS Cookie server secret: {0}")]
    DnsCookieSecret(getrandom::Error),

    #[error("failed to randomize primary rotation: {0}")]
    PrimaryRotationRandom(getrandom::Error),

    #[error(
        "file-descriptor rlimit is insufficient for configured connection limits: current {current}, required {required}"
    )]
    InsufficientFileDescriptorLimit { current: u64, required: u64 },

    #[error("failed to inspect file-descriptor rlimit: {0}")]
    FileDescriptorLimit(std::io::Error),

    #[error("failed to apply process hardening: {0}")]
    ProcessHardening(std::io::Error),

    #[error("{0}")]
    PrivilegeDrop(String),
}

impl From<privilege::PrivilegeError> for RuntimeError {
    fn from(error: privilege::PrivilegeError) -> Self {
        Self::PrivilegeDrop(error.to_string())
    }
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

    #[error("failed to bind outbound TCP socket {source_addr} for primary {addr}: {source}")]
    BindTcp {
        addr: SocketAddr,
        source_addr: SocketAddr,
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

    #[error("XoT TLS configuration for primary {addr} is invalid: {message}")]
    XotConfig { addr: SocketAddr, message: String },

    #[error("failed to read XoT TLS file {path}: {source}")]
    ReadTlsFile {
        path: String,
        source: std::io::Error,
    },

    #[error("failed XoT TLS handshake with primary {addr}: {source}")]
    TlsHandshake {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("XoT primary {addr} did not negotiate ALPN dot")]
    XotAlpn { addr: SocketAddr },

    #[error(
        "{protocol} session from primary {addr} exceeded configured ingestion size cap at {received_bytes} octets (limit {limit_bytes})"
    )]
    IngestSizeLimit {
        protocol: &'static str,
        addr: SocketAddr,
        received_bytes: u64,
        limit_bytes: u64,
    },
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
const XOT_TRUST_ANCHOR_EXPIRY_WARNING_SECS: i64 = 30 * 24 * 60 * 60;
const SOA_TIMER_NEAR_MAX_WARNING_PERCENT: u64 = 90;

impl Runtime {
    pub fn new(config: ServerConfig) -> Self {
        let zones = ZoneStore::new();
        for zone in &config.zones {
            zones.insert_loading(
                DomainName::from_absolute_str(&zone.name)
                    .expect("configuration validation rejects invalid zone names"),
            );
        }
        for catalog_zone in &config.catalog_zones {
            let origin = DomainName::from_absolute_str(&catalog_zone.name)
                .expect("configuration validation rejects invalid catalog zone names");
            if catalog_zone.serve_catalog_zone {
                zones.insert_loading(origin);
            } else {
                zones.insert_loading_hidden(origin);
            }
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
        self.run_with_shutdown_signal_inner(shutdown_signal, None)
            .await
    }

    async fn run_with_shutdown_signal_inner(
        self,
        shutdown_signal: impl Future<Output = Result<&'static str, std::io::Error>>,
        mut health_bound: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<(), RuntimeError> {
        validate_runtime_config(&self.config)
            .map_err(|error| RuntimeError::InvalidRuntimeConfig(error.to_string()))?;
        validate_file_descriptor_limit(&self.config)?;
        let run_as_user = privilege::configured_run_as_user(&self.config)?;
        tokio::pin!(shutdown_signal);
        let transfer_plan = TransferPlan::from_config(&self.config)?;
        let catalog_manager = CatalogManager::from_config(&self.config);
        let refresh_registry = ZoneRefreshRegistry::new(
            Duration::from_secs(self.config.limits.zsm_min_interval_secs),
            Duration::from_secs(self.config.limits.zsm_max_interval_secs),
            Duration::from_secs(self.config.limits.zsm_initial_retry_secs),
            Duration::from_secs(self.config.limits.zsm_initial_retry_max_secs),
            Duration::from_secs(self.config.limits.zsm_loading_warning_threshold_secs),
        );
        for zone in &self.config.zones {
            let origin = DomainName::from_absolute_str(&zone.name)
                .expect("configuration validation rejects invalid zone names");
            refresh_registry.record_loading_start(&origin);
        }
        for catalog_zone in &self.config.catalog_zones {
            let origin = DomainName::from_absolute_str(&catalog_zone.name)
                .expect("configuration validation rejects invalid catalog zone names");
            refresh_registry.record_loading_start(&origin);
        }
        let ixfr_cooldowns = IxfrCooldownRegistry::new(Duration::from_secs(
            self.config.limits.ixfr_disabled_cooldown_secs,
        ));
        let metrics = RuntimeMetrics::new_with_settings(
            self.config.rrl.max_keys,
            self.config.metrics.latency_histogram_buckets_seconds(),
            self.config.metrics.pipeline_timing_enabled,
        );
        let startup_warning_count = self.config.configuration_warnings().len().saturating_add(
            runtime_config_warnings(&self.config)
                .map_err(|error| RuntimeError::InvalidRuntimeConfig(error.to_string()))?
                .len(),
        );
        metrics.set_configuration_warnings(startup_warning_count as u64);
        let transfer_limit = Arc::new(Semaphore::new(self.config.limits.max_concurrent_transfers));

        info!(
            udp_listeners = self.config.udp_listeners().len(),
            tcp_listeners = self.config.tcp_listeners().len(),
            zones = self.zones.len(),
            "OxideDNS runtime initialized"
        );

        let mut listeners = JoinSet::new();
        let mut health_listeners = JoinSet::new();
        let mut refresh_workers = JoinSet::new();
        let mut background_tasks = JoinSet::new();
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let tcp_source_connections = Arc::new(Mutex::new(HashMap::new()));
        let shutdown_grace = Duration::from_secs(self.config.limits.graceful_shutdown_secs);
        let runtime_status = RuntimeStatus::new();
        let notify_authority = NotifyAuthority::from_config(&self.config);
        let notify_refresh =
            NotifyRefreshTracker::new(Duration::from_secs(self.config.limits.notify_dedup_secs));
        let notify_log_limiter = NotifyLogLimiter::new(Duration::from_secs(
            self.config.limits.notify_log_rate_window_secs,
        ));
        let (notify_refresh_tx, notify_refresh_rx) = mpsc::channel(NOTIFY_REFRESH_QUEUE_CAPACITY);
        let rrl = RrlLimiter::from_config(&self.config.rrl, metrics.clone());
        let dns_cookie = dns_cookie_settings(&self.config.cookie);
        let cookie_prefix_metrics = CookiePrefixMetricSettings {
            ipv4_prefix_len: self.config.rrl.ipv4_prefix_len,
            ipv6_prefix_len: self.config.rrl.ipv6_prefix_len,
        };
        let dns_cookie_secret = dns_cookie_secret().map_err(RuntimeError::DnsCookieSecret)?;
        let dns_cookie_secrets =
            DnsCookieSecretStore::new(dns_cookie_secret, dns_cookie.secret_rotation_interval);
        if dns_cookie.policy.is_some() {
            info!(
                category = "cookie",
                secret_fingerprint = %dns_cookie_secret_fingerprint(&dns_cookie_secret),
                rotation_interval_secs = dns_cookie.secret_rotation_interval.map(|duration| duration.as_secs()).unwrap_or(0),
                "DNS Cookie server secret generated"
            );
        }
        let mut health_shutdown = Vec::new();
        let mut bound_health_listeners = Vec::new();
        for addr in self.config.health_listeners() {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|source| RuntimeError::BindHealth { addr, source })?;
            if let Some(health_bound) = health_bound.take() {
                let _ = health_bound.send(listener.local_addr().map_err(RuntimeError::Health)?);
            }
            let (health_shutdown_tx, health_shutdown_rx) = oneshot::channel();
            health_shutdown.push(health_shutdown_tx);
            bound_health_listeners.push((listener, health_shutdown_rx));
        }
        let mut bound_udp_sockets = Vec::new();
        for addr in self.config.udp_listeners() {
            let socket = UdpSocket::bind(addr)
                .await
                .map_err(|source| RuntimeError::BindUdp { addr, source })?;
            bound_udp_sockets.push(socket);
        }
        let mut bound_tcp_listeners = Vec::new();
        for addr in self.config.tcp_listeners() {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|source| RuntimeError::BindTcp { addr, source })?;
            bound_tcp_listeners.push(listener);
        }
        let disabled_core_dumps =
            process_hardening::disable_core_dumps_if_configured(&self.config.process)
                .map_err(RuntimeError::ProcessHardening)?;
        if let Some(identity) = run_as_user {
            privilege::drop_to_user(&identity)?;
            process_hardening::disable_core_dumps_if_configured(&self.config.process)
                .map_err(RuntimeError::ProcessHardening)?;
            info!(
                user = %identity.name,
                uid = identity.uid,
                gid = identity.gid,
                "dropped process privileges"
            );
        }
        if disabled_core_dumps {
            info!("disabled process core dumps");
        }
        if process_hardening::apply_no_new_privileges_if_configured(&self.config.process)
            .map_err(RuntimeError::ProcessHardening)?
        {
            info!("enabled process no-new-privileges hardening");
        }

        background_tasks.spawn(serve_notify_log_summaries(
            notify_log_limiter.clone(),
            Duration::from_secs(self.config.limits.notify_log_rate_window_secs),
        ));
        if self.config.rrl.enabled {
            background_tasks.spawn(serve_rrl_summary_logs(
                rrl.clone(),
                metrics.clone(),
                Duration::from_secs(self.config.rrl.summary_log_interval_secs),
            ));
        }
        refresh_workers.spawn(run_initial_zone_loads(
            self.zones.clone(),
            transfer_plan.initial_origins(),
            CatalogRuntime {
                manager: catalog_manager.clone(),
                transfer_plan: transfer_plan.clone(),
                refresh_registry: refresh_registry.clone(),
                notify_authority: notify_authority.clone(),
                refresh_tx: notify_refresh_tx.downgrade(),
            },
            ixfr_cooldowns.clone(),
            metrics.clone(),
            InitialLoadSettings {
                axfr_timeout: Duration::from_secs(self.config.limits.axfr_timeout_secs),
                ixfr_timeout: Duration::from_secs(self.config.limits.ixfr_timeout_secs),
                tcp_connect_timeout: Duration::from_secs(
                    self.config.limits.tcp_connect_timeout_secs,
                ),
                transfer_limit: transfer_limit.clone(),
            },
        ));
        refresh_workers.spawn(serve_refresh_requests(
            notify_refresh_rx,
            self.zones.clone(),
            CatalogRuntime {
                manager: catalog_manager.clone(),
                transfer_plan: transfer_plan.clone(),
                refresh_registry: refresh_registry.clone(),
                notify_authority: notify_authority.clone(),
                refresh_tx: notify_refresh_tx.downgrade(),
            },
            ixfr_cooldowns.clone(),
            metrics.clone(),
            RefreshWorkerSettings {
                axfr_timeout: Duration::from_secs(self.config.limits.axfr_timeout_secs),
                ixfr_timeout: Duration::from_secs(self.config.limits.ixfr_timeout_secs),
                tcp_connect_timeout: Duration::from_secs(
                    self.config.limits.tcp_connect_timeout_secs,
                ),
                transfer_limit: transfer_limit.clone(),
            },
        ));
        listeners.spawn(serve_scheduled_refreshes(
            self.zones.clone(),
            refresh_registry.clone(),
            notify_refresh_tx.clone(),
            ZSM_SCHEDULER_TICK,
        ));
        for (listener, health_shutdown_rx) in bound_health_listeners {
            health_listeners.spawn(serve_health(
                listener,
                HealthEndpointState {
                    zones: self.zones.clone(),
                    runtime_status: runtime_status.clone(),
                    metrics: metrics.clone(),
                    catalog_manager: catalog_manager.clone(),
                    refresh_registry: refresh_registry.clone(),
                    metrics_rate_limiter: MetricsRateLimiter::from_config(self.config.health),
                    started_at: Instant::now(),
                    graceful_shutdown_secs: self.config.limits.graceful_shutdown_secs,
                    zone_shape_metrics_enabled: self.config.metrics.zone_shape_enabled,
                },
                async move {
                    let _ = health_shutdown_rx.await;
                },
            ));
        }
        for socket in bound_udp_sockets {
            let zones = self.zones.clone();
            let max_udp_payload = self.config.limits.max_udp_payload;
            let max_cname_chain = self.config.limits.max_cname_chain;
            let nsec3_max_iterations = self.config.dnssec.nsec3_max_iterations;
            let edns_padding_block_size = self.config.limits.edns_padding_block_size;
            let extended_dns_errors = self.config.edns.extended_dns_errors_mode();
            let any_response = self.config.query.any_response_mode();
            let nsid = self.config.server.nsid.as_bytes().to_vec();
            let chaos_version = self.config.chaos.version.clone();
            let chaos_hostname = self.config.chaos.hostname.clone();
            let notify_authority = notify_authority.clone();
            let notify_refresh = notify_refresh.clone();
            let notify_refresh_tx = notify_refresh_tx.clone();
            let notify_log_limiter = notify_log_limiter.clone();
            let metrics = metrics.clone();
            let rrl = rrl.clone();
            let udp_settings = UdpServerSettings {
                max_udp_payload,
                max_cname_chain,
                nsec3_max_iterations,
                edns_padding_block_size,
                extended_dns_errors,
                any_response,
                nsid,
                chaos_version,
                chaos_hostname,
                dns_cookie_secrets: dns_cookie_secrets.clone(),
                dns_cookie,
                cookie_prefix_metrics,
                notify_authority,
                notify_refresh,
                notify_refresh_tx,
                notify_log_limiter,
                metrics,
                rrl,
            };
            listeners.spawn(async move { serve_udp(socket, zones, udp_settings).await });
        }
        for listener in bound_tcp_listeners {
            let zones = self.zones.clone();
            let max_udp_payload = self.config.limits.max_udp_payload;
            let max_cname_chain = self.config.limits.max_cname_chain;
            let nsec3_max_iterations = self.config.dnssec.nsec3_max_iterations;
            let tcp_idle_timeout = Duration::from_secs(self.config.limits.tcp_idle_timeout_secs);
            let tcp_read_timeout = Duration::from_secs(self.config.limits.tcp_read_timeout_secs);
            let tcp_write_timeout = Duration::from_secs(self.config.limits.tcp_write_timeout_secs);
            let max_tcp_connections = self.config.limits.max_tcp_connections;
            let max_tcp_connections_per_source = self.config.limits.max_tcp_connections_per_source;
            let max_tcp_inflight_queries_per_connection =
                self.config.limits.max_tcp_inflight_queries_per_connection;
            let tcp_inflight_limit_timeout = Duration::from_secs(
                self.config
                    .limits
                    .tcp_inflight_limit_timeout_secs
                    .unwrap_or(self.config.limits.tcp_read_timeout_secs),
            );
            let edns_padding_block_size = self.config.limits.edns_padding_block_size;
            let extended_dns_errors = self.config.edns.extended_dns_errors_mode();
            let any_response = self.config.query.any_response_mode();
            let nsid = self.config.server.nsid.as_bytes().to_vec();
            let chaos_version = self.config.chaos.version.clone();
            let chaos_hostname = self.config.chaos.hostname.clone();
            let tcp_connections = tcp_connections.clone();
            let tcp_source_connections = tcp_source_connections.clone();
            let tcp_settings = TcpServerSettings {
                max_udp_payload,
                max_cname_chain,
                nsec3_max_iterations,
                idle_timeout: tcp_idle_timeout,
                read_timeout: tcp_read_timeout,
                write_timeout: tcp_write_timeout,
                max_connections: max_tcp_connections,
                max_connections_per_source: max_tcp_connections_per_source,
                max_inflight_queries_per_connection: max_tcp_inflight_queries_per_connection,
                inflight_limit_timeout: tcp_inflight_limit_timeout,
                edns_padding_block_size,
                extended_dns_errors,
                any_response,
                nsid,
                chaos_version,
                chaos_hostname,
                dns_cookie_secrets: dns_cookie_secrets.clone(),
                dns_cookie,
                cookie_prefix_metrics,
                notify_authority: notify_authority.clone(),
                notify_refresh: notify_refresh.clone(),
                notify_refresh_tx: notify_refresh_tx.clone(),
                notify_log_limiter: notify_log_limiter.clone(),
                metrics: metrics.clone(),
                active_connections: tcp_connections,
                active_connections_by_source: tcp_source_connections,
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
                    abort_task_set(&mut background_tasks, "background").await;
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
                    for health_shutdown in health_shutdown.drain(..) {
                        let _ = health_shutdown.send(());
                    }
                    let health_drained =
                        drain_task_set(&mut health_listeners, shutdown_grace, "health listener")
                            .await;
                    if health_drained {
                        info!("health listener drain completed");
                    } else {
                        warn!("shutdown grace period elapsed with active health connections");
                    }
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
                result = background_tasks.join_next(), if !background_tasks.is_empty() => {
                    handle_runtime_task_result("background", result)?;
                }
            }

            if listeners.is_empty() && refresh_workers.is_empty() && health_listeners.is_empty() {
                abort_task_set(&mut background_tasks, "background").await;
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
            transfer_plan.initial_origins(),
            CatalogRuntime {
                manager: CatalogManager::from_config(&self.config),
                transfer_plan: transfer_plan.clone(),
                refresh_registry: refresh_registry.clone(),
                notify_authority: NotifyAuthority::from_config(&self.config),
                refresh_tx: mpsc::channel(1).0.downgrade(),
            },
            ixfr_cooldowns.clone(),
            metrics.clone(),
            InitialLoadSettings {
                axfr_timeout: Duration::from_secs(self.config.limits.axfr_timeout_secs),
                ixfr_timeout: Duration::from_secs(self.config.limits.ixfr_timeout_secs),
                tcp_connect_timeout: Duration::from_secs(
                    self.config.limits.tcp_connect_timeout_secs,
                ),
                transfer_limit: Arc::new(Semaphore::new(max_concurrent_transfers)),
            },
        )
        .await
        .expect("initial zone load worker does not return runtime errors");
    }
}

pub fn validate_runtime_config(config: &ServerConfig) -> Result<(), TransferError> {
    for (_zone_name, primary) in transfer_targets_with_names(config) {
        if primary.transport == TransferTransportConfig::Xot {
            validate_xot_transfer_target(&primary)?;
        }
    }
    Ok(())
}

fn validate_file_descriptor_limit(config: &ServerConfig) -> Result<(), RuntimeError> {
    let required = required_file_descriptor_limit(config);
    let current = resource_limits::current_file_descriptor_limit()
        .map_err(RuntimeError::FileDescriptorLimit)?;
    if current >= required {
        Ok(())
    } else {
        Err(RuntimeError::InsufficientFileDescriptorLimit { current, required })
    }
}

fn required_file_descriptor_limit(config: &ServerConfig) -> u64 {
    let tcp_connections = config.limits.max_tcp_connections as u64;
    let outbound_transfers = config.limits.max_concurrent_transfers as u64;
    2 * (tcp_connections + outbound_transfers + 100)
}

#[cfg(test)]
fn validate_file_descriptor_limit_value(
    config: &ServerConfig,
    current: u64,
) -> Result<(), RuntimeError> {
    let required = required_file_descriptor_limit(config);
    if current >= required {
        Ok(())
    } else {
        Err(RuntimeError::InsufficientFileDescriptorLimit { current, required })
    }
}

pub fn runtime_config_warnings(config: &ServerConfig) -> Result<Vec<ConfigWarning>, TransferError> {
    runtime_config_warnings_at(config, current_unix_time_secs_i64())
}

fn runtime_config_warnings_at(
    config: &ServerConfig,
    now_unix_secs: i64,
) -> Result<Vec<ConfigWarning>, TransferError> {
    let mut warnings = Vec::new();
    for (zone_name, primary) in transfer_targets_with_names(config) {
        if primary.transport != TransferTransportConfig::Xot {
            continue;
        }
        warnings.extend(xot_trust_anchor_expiry_warnings(
            &zone_name,
            &primary,
            now_unix_secs,
        )?);
    }
    Ok(warnings)
}

fn transfer_targets_with_names(config: &ServerConfig) -> Vec<(String, TransferPrimaryConfig)> {
    config
        .zones
        .iter()
        .flat_map(|zone| {
            zone.transfer_targets()
                .into_iter()
                .map(|primary| (zone.name.clone(), primary))
        })
        .chain(config.catalog_zones.iter().flat_map(|zone| {
            zone.transfer_targets()
                .into_iter()
                .map(|primary| (zone.name.clone(), primary))
        }))
        .collect()
}

fn xot_trust_anchor_expiry_warnings(
    zone_name: &str,
    primary: &TransferPrimaryConfig,
    now_unix_secs: i64,
) -> Result<Vec<ConfigWarning>, TransferError> {
    let mut warnings = Vec::new();
    let warning_deadline = now_unix_secs.saturating_add(XOT_TRUST_ANCHOR_EXPIRY_WARNING_SECS);
    for trust_anchor in &primary.trust_anchors {
        let certs = load_pem_certs_for_primary(primary.addr, trust_anchor)?;
        for (index, cert) in certs.iter().enumerate() {
            let (_, parsed) = parse_x509_certificate(cert.as_ref()).map_err(|error| {
                TransferError::XotConfig {
                    addr: primary.addr,
                    message: format!(
                        "failed to parse trust anchor certificate {trust_anchor:?}: {error}"
                    ),
                }
            })?;
            let not_after = parsed.validity().not_after.timestamp();
            if not_after <= warning_deadline {
                warnings.push(ConfigWarning {
                    code: "xot_trust_anchor_expiring_soon",
                    parameter: format!(
                        "zones[{zone_name}].transfer_primaries[{}].trust_anchors[{trust_anchor}][{index}]",
                        primary.addr
                    ),
                    message: format!(
                        "XoT trust anchor expires at Unix timestamp {not_after}, within 30 days of process startup"
                    ),
                });
            }
        }
    }
    Ok(warnings)
}

fn current_unix_time_secs_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or_default()
}

fn validate_xot_transfer_target(primary: &TransferPrimaryConfig) -> Result<(), TransferError> {
    let server_name = primary
        .server_name
        .as_deref()
        .ok_or_else(|| TransferError::XotConfig {
            addr: primary.addr,
            message: "server_name is required".to_owned(),
        })?;
    ServerName::try_from(server_name.to_owned()).map_err(|error| TransferError::XotConfig {
        addr: primary.addr,
        message: format!("invalid XoT server_name {server_name:?}: {error}"),
    })?;
    build_xot_client_config(primary).map(|_| ())
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

async fn serve_rrl_summary_logs(
    rrl: RrlLimiter,
    metrics: RuntimeMetrics,
    interval: Duration,
) -> Result<(), RuntimeError> {
    let mut previous = metrics.snapshot();
    loop {
        tokio::time::sleep(interval).await;
        let current = metrics.snapshot();
        let summary = RrlSummary::from_snapshots(previous, current, rrl.rate_limited_key_count());
        log_rrl_summary(summary, interval);
        previous = current;
    }
}

async fn serve_notify_log_summaries(
    limiter: NotifyLogLimiter,
    interval: Duration,
) -> Result<(), RuntimeError> {
    loop {
        tokio::time::sleep(interval).await;
        let summary = limiter.take_summary();
        if summary.total_suppressed > 0 {
            log_notify_log_summary(summary, interval);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RrlSummary {
    dropped_responses: u64,
    truncated_responses: u64,
    rate_limited_keys: u64,
    total_dropped_responses: u64,
    total_truncated_responses: u64,
}

impl RrlSummary {
    fn from_snapshots(
        previous: RuntimeMetricsSnapshot,
        current: RuntimeMetricsSnapshot,
        rate_limited_keys: u64,
    ) -> Self {
        Self {
            dropped_responses: current.rrl_dropped.saturating_sub(previous.rrl_dropped),
            truncated_responses: current.rrl_truncated.saturating_sub(previous.rrl_truncated),
            rate_limited_keys,
            total_dropped_responses: current.rrl_dropped,
            total_truncated_responses: current.rrl_truncated,
        }
    }
}

fn log_rrl_summary(summary: RrlSummary, interval: Duration) {
    info!(
        category = "rrl",
        event = "rrl_periodic_summary",
        interval_secs = interval.as_secs(),
        dropped_responses = summary.dropped_responses,
        truncated_responses = summary.truncated_responses,
        rate_limited_keys = summary.rate_limited_keys,
        total_dropped_responses = summary.total_dropped_responses,
        total_truncated_responses = summary.total_truncated_responses,
        "RRL periodic summary"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NotifyLogSummary {
    suppressed_unauthorized: u64,
    suppressed_tsig_failures: u64,
    distinct_source_prefixes: u64,
    total_suppressed: u64,
}

fn log_notify_log_summary(summary: NotifyLogSummary, interval: Duration) {
    info!(
        category = "notify",
        event = "notify_log_rate_limit_summary",
        interval_secs = interval.as_secs(),
        suppressed_unauthorized = summary.suppressed_unauthorized,
        suppressed_tsig_failures = summary.suppressed_tsig_failures,
        distinct_source_prefixes = summary.distinct_source_prefixes,
        total_suppressed = summary.total_suppressed,
        "NOTIFY log rate-limit summary"
    );
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
    transfer_axfr_from_primary_with_tsig(
        primary,
        zone_apex,
        qclass,
        qid,
        TransferSession::default_unsigned(),
        timeout_duration,
    )
    .await
}

async fn transfer_axfr_from_primary_with_tsig(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    session: TransferSession<'_>,
    timeout_duration: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    let target = TransferPrimaryConfig::tcp(primary);
    transfer_axfr_from_target_with_tsig(&target, zone_apex, qclass, qid, session, timeout_duration)
        .await
}

async fn transfer_axfr_from_target_with_tsig(
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    session: TransferSession<'_>,
    timeout_duration: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    transfer_axfr_from_target_with_tsig_and_source(
        primary,
        zone_apex,
        qclass,
        qid,
        session,
        None,
        timeout_duration,
        timeout_duration,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn transfer_axfr_from_target_with_tsig_and_source(
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    session: TransferSession<'_>,
    transfer_source: Option<SocketAddr>,
    timeout_duration: Duration,
    connect_timeout: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    let session = session.with_transfer_source(transfer_source);
    tokio::time::timeout(timeout_duration, async {
        transfer_axfr_from_primary_inner(primary, zone_apex, qclass, qid, session, connect_timeout)
            .await
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
    poll_soa_from_primary_with_tsig(
        primary,
        zone_apex,
        qclass,
        qid,
        TransferTsig::unsigned(),
        timeout_duration,
    )
    .await
}

async fn poll_soa_from_primary_with_tsig(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    tsig: TransferTsig<'_>,
    timeout_duration: Duration,
) -> Result<u32, TransferError> {
    poll_soa_from_primary_with_tsig_and_source(
        primary,
        zone_apex,
        qclass,
        qid,
        tsig,
        None,
        timeout_duration,
    )
    .await
}

async fn poll_soa_from_primary_with_tsig_and_source(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    tsig: TransferTsig<'_>,
    transfer_source: Option<SocketAddr>,
    timeout_duration: Duration,
) -> Result<u32, TransferError> {
    tokio::time::timeout(timeout_duration, async {
        poll_soa_from_primary_inner(primary, zone_apex, qclass, qid, tsig, transfer_source).await
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
    tsig: TransferTsig<'_>,
    transfer_source: Option<SocketAddr>,
) -> Result<u32, TransferError> {
    let socket = UdpSocket::bind(outbound_udp_bind_addr(primary, transfer_source))
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

    let query = maybe_sign_transfer_query(axfr::build_soa_query(qid, zone_apex, qclass), tsig)?;
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
        maybe_verify_transfer_response(&buffer[..len], tsig.key, query.request_mac.as_deref())?;
    match axfr::parse_soa_response(qid, zone_apex, qclass, &response) {
        Ok(serial) => Ok(serial),
        Err(error) => {
            warn!(
                zone = %zone_apex,
                %primary,
                qid,
                %error,
                "SOA poll response rejected"
            );
            Err(TransferError::Soa(error))
        }
    }
}

enum TransferStream {
    Tcp(TcpStream),
    Xot(XotTransferStream),
}

struct XotTransferStream {
    stream: Box<TlsStream<TcpStream>>,
    session: XotSessionLog,
}

struct XotSessionLog {
    addr: SocketAddr,
    sni: String,
    started_at: Instant,
    bytes_in: u64,
    bytes_out: u64,
}

impl TransferStream {
    async fn write_all(&mut self, buffer: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(buffer).await,
            Self::Xot(stream) => stream.write_all(buffer).await,
        }
    }

    async fn read_exact(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read_exact(buffer).await,
            Self::Xot(stream) => stream.read_exact(buffer).await,
        }
    }
}

impl XotTransferStream {
    fn new(stream: TlsStream<TcpStream>, addr: SocketAddr, sni: String) -> Self {
        Self {
            stream: Box::new(stream),
            session: XotSessionLog {
                addr,
                sni,
                started_at: Instant::now(),
                bytes_in: 0,
                bytes_out: 0,
            },
        }
    }

    async fn write_all(&mut self, buffer: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(buffer).await?;
        self.session.bytes_out = self.session.bytes_out.saturating_add(buffer.len() as u64);
        Ok(())
    }

    async fn read_exact(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.stream.read_exact(buffer).await?;
        self.session.bytes_in = self.session.bytes_in.saturating_add(read as u64);
        Ok(read)
    }
}

impl Drop for XotSessionLog {
    fn drop(&mut self) {
        let duration_ms = duration_millis_u64(self.started_at.elapsed());
        let bytes = self.bytes_in.saturating_add(self.bytes_out);
        info!(
            category = "xot",
            event = "xot_tls_session_closed",
            primary = %self.addr,
            peer_ip = %self.addr.ip(),
            sni = %self.sni,
            duration_ms,
            bytes,
            bytes_in = self.bytes_in,
            bytes_out = self.bytes_out,
            "XoT TLS session closed"
        );
    }
}

async fn connect_tcp_stream(
    primary: SocketAddr,
    transfer_source: Option<SocketAddr>,
    connect_timeout: Duration,
) -> Result<TcpStream, TransferError> {
    let socket = match primary {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|source| TransferError::ConnectTcp {
        addr: primary,
        source,
    })?;

    if let Some(source_addr) =
        transfer_source.filter(|source| source.is_ipv4() == primary.is_ipv4())
    {
        socket
            .bind(source_addr)
            .map_err(|source| TransferError::BindTcp {
                addr: primary,
                source_addr,
                source,
            })?;
    }

    tcp_connect_with_timeout(primary, connect_timeout, socket.connect(primary)).await
}

async fn tcp_connect_with_timeout<T, F>(
    primary: SocketAddr,
    connect_timeout: Duration,
    connect: F,
) -> Result<T, TransferError>
where
    F: Future<Output = std::io::Result<T>>,
{
    tokio::time::timeout(connect_timeout, connect)
        .await
        .map_err(|_| TransferError::Timeout {
            timeout_secs: connect_timeout.as_secs(),
        })?
        .map_err(|source| TransferError::ConnectTcp {
            addr: primary,
            source,
        })
}

async fn connect_transfer_stream(
    primary: &TransferPrimaryConfig,
    transfer_source: Option<SocketAddr>,
    connect_timeout: Duration,
) -> Result<TransferStream, TransferError> {
    match primary.transport {
        TransferTransportConfig::Tcp => {
            let tcp = connect_tcp_stream(primary.addr, transfer_source, connect_timeout).await?;
            Ok(TransferStream::Tcp(tcp))
        }
        TransferTransportConfig::Xot => {
            connect_xot_stream(primary, transfer_source, connect_timeout).await
        }
    }
}

async fn connect_xot_stream(
    primary: &TransferPrimaryConfig,
    transfer_source: Option<SocketAddr>,
    connect_timeout: Duration,
) -> Result<TransferStream, TransferError> {
    let sni = primary
        .server_name
        .as_deref()
        .ok_or_else(|| TransferError::XotConfig {
            addr: primary.addr,
            message: "missing server_name".to_owned(),
        })?
        .to_owned();
    let server_name =
        ServerName::try_from(sni.clone()).map_err(|error| TransferError::XotConfig {
            addr: primary.addr,
            message: format!("invalid server_name {sni:?}: {error}"),
        })?;

    let mut client_config = build_xot_client_config(primary)?;
    client_config.alpn_protocols = vec![b"dot".to_vec()];
    let tcp = connect_tcp_stream(primary.addr, transfer_source, connect_timeout).await?;
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = match connector.connect(server_name, tcp).await {
        Ok(stream) => stream,
        Err(source) => {
            warn!(
                category = "xot",
                event = "xot_tls_handshake_failed",
                primary = %primary.addr,
                peer_ip = %primary.addr.ip(),
                sni = %sni,
                error = %source,
                "XoT TLS handshake failed"
            );
            return Err(TransferError::TlsHandshake {
                addr: primary.addr,
                source,
            });
        }
    };
    if stream.get_ref().1.alpn_protocol() != Some(b"dot".as_slice()) {
        warn!(
            category = "xot",
            event = "xot_alpn_negotiation_failed",
            primary = %primary.addr,
            peer_ip = %primary.addr.ip(),
            sni = %sni,
            error = "missing negotiated dot ALPN",
            "XoT ALPN negotiation failed"
        );
        return Err(TransferError::XotAlpn { addr: primary.addr });
    }
    let tls_version = stream
        .get_ref()
        .1
        .protocol_version()
        .map(|version| format!("{version:?}"))
        .unwrap_or_else(|| "unknown".to_owned());
    let cipher_suite = stream
        .get_ref()
        .1
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_else(|| "unknown".to_owned());
    info!(
        category = "xot",
        event = "xot_tls_session_established",
        primary = %primary.addr,
        peer_ip = %primary.addr.ip(),
        sni = %sni,
        tls_version = %tls_version,
        cipher_suite = %cipher_suite,
        "XoT TLS session established"
    );
    Ok(TransferStream::Xot(XotTransferStream::new(
        stream,
        primary.addr,
        sni,
    )))
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn build_xot_client_config(primary: &TransferPrimaryConfig) -> Result<ClientConfig, TransferError> {
    let mut roots = RootCertStore::empty();
    for trust_anchor in &primary.trust_anchors {
        let certs = load_pem_certs_for_primary(primary.addr, trust_anchor)?;
        if certs.is_empty() {
            return Err(TransferError::XotConfig {
                addr: primary.addr,
                message: format!("trust anchor file {trust_anchor:?} did not contain certificates"),
            });
        }
        for cert in certs {
            roots.add(cert).map_err(|error| TransferError::XotConfig {
                addr: primary.addr,
                message: format!("failed to add trust anchor {trust_anchor:?}: {error}"),
            })?;
        }
    }
    if roots.is_empty() {
        return Err(TransferError::XotConfig {
            addr: primary.addr,
            message: "at least one trust anchor is required".to_owned(),
        });
    }

    let builder = ClientConfig::builder().with_root_certificates(roots);
    match (
        &primary.client_cert,
        &primary.client_key,
        &primary.client_key_pem,
    ) {
        (Some(cert_path), Some(key_path), None) => {
            validate_private_key_file_mode(primary.addr, key_path)?;
            let certs = load_pem_certs(cert_path)?;
            let key = load_pem_private_key_from_file(primary.addr, key_path)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|error| TransferError::XotConfig {
                    addr: primary.addr,
                    message: format!("invalid XoT client certificate/key pair: {error}"),
                })
        }
        (Some(cert_path), None, Some(key_pem)) => {
            let certs = load_pem_certs(cert_path)?;
            let key = load_pem_private_key_from_inline(primary.addr, key_pem)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|error| TransferError::XotConfig {
                    addr: primary.addr,
                    message: format!("invalid XoT client certificate/key pair: {error}"),
                })
        }
        (None, None, None) => Ok(builder.with_no_client_auth()),
        _ => Err(TransferError::XotConfig {
            addr: primary.addr,
            message: "client_cert and exactly one of client_key or client_key_pem must be configured together".to_owned(),
        }),
    }
}

fn load_pem_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TransferError> {
    let pem = std::fs::read(path).map_err(|source| TransferError::ReadTlsFile {
        path: path.to_owned(),
        source,
    })?;
    CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TransferError::XotConfig {
            addr: "0.0.0.0:0"
                .parse()
                .expect("hard-coded placeholder socket address is valid"),
            message: format!("failed to parse certificate PEM file {path:?}: {error}"),
        })
}

fn load_pem_private_key_from_file(
    addr: SocketAddr,
    path: &str,
) -> Result<PrivateKeyDer<'static>, TransferError> {
    let pem = std::fs::read(path).map_err(|source| TransferError::ReadTlsFile {
        path: path.to_owned(),
        source,
    })?;
    PrivateKeyDer::from_pem_slice(&pem).map_err(|error| TransferError::XotConfig {
        addr,
        message: format!("failed to parse private key PEM file {path:?}: {error}"),
    })
}

fn load_pem_private_key_from_inline(
    addr: SocketAddr,
    key_pem: &str,
) -> Result<PrivateKeyDer<'static>, TransferError> {
    PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|error| TransferError::XotConfig {
        addr,
        message: format!("failed to parse inline private key PEM: {error}"),
    })
}

fn load_pem_certs_for_primary(
    addr: SocketAddr,
    path: &str,
) -> Result<Vec<CertificateDer<'static>>, TransferError> {
    let certs = load_pem_certs(path).map_err(|error| match error {
        TransferError::XotConfig { message, .. } => TransferError::XotConfig { addr, message },
        other => other,
    })?;
    if certs.is_empty() {
        return Err(TransferError::XotConfig {
            addr,
            message: format!("certificate file {path:?} did not contain certificates"),
        });
    }
    Ok(certs)
}

#[cfg(unix)]
fn validate_private_key_file_mode(addr: SocketAddr, path: &str) -> Result<(), TransferError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path).map_err(|source| TransferError::ReadTlsFile {
        path: path.to_owned(),
        source,
    })?;
    if metadata.permissions().mode() & 0o007 != 0 {
        return Err(TransferError::XotConfig {
            addr,
            message: format!("private key file {path:?} must not be readable by other users"),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_file_mode(_addr: SocketAddr, _path: &str) -> Result<(), TransferError> {
    Ok(())
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
        TransferSession::default_unsigned(),
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
    session: TransferSession<'_>,
    timeout_duration: Duration,
) -> Result<IxfrResponse, TransferError> {
    let target = TransferPrimaryConfig::tcp(primary);
    transfer_ixfr_from_target_with_tsig(
        &target,
        zone_apex,
        qclass,
        qid,
        current_zone,
        session,
        timeout_duration,
        timeout_duration,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn transfer_ixfr_from_target_with_tsig(
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    current_zone: &ZoneSnapshot,
    session: TransferSession<'_>,
    timeout_duration: Duration,
    connect_timeout: Duration,
) -> Result<IxfrResponse, TransferError> {
    tokio::time::timeout(timeout_duration, async {
        transfer_ixfr_from_primary_inner(
            primary,
            zone_apex,
            qclass,
            qid,
            current_zone,
            session,
            connect_timeout,
        )
        .await
    })
    .await
    .map_err(|_| TransferError::Timeout {
        timeout_secs: timeout_duration.as_secs(),
    })?
}

async fn transfer_ixfr_from_primary_inner(
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    current_zone: &ZoneSnapshot,
    session: TransferSession<'_>,
    connect_timeout: Duration,
) -> Result<IxfrResponse, TransferError> {
    let mut stream =
        connect_transfer_stream(primary, session.transfer_source, connect_timeout).await?;

    let current_soa = current_zone
        .soa_record(qclass)
        .ok_or(axfr::IxfrError::InvalidCurrentSoa)?;
    let query = maybe_sign_transfer_query(
        axfr::build_ixfr_query(qid, zone_apex, qclass, &current_soa)?,
        session.tsig,
    )?;
    let framed_query = axfr::frame_tcp_message(&query.message);
    stream
        .write_all(&framed_query)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary.addr,
            source,
        })?;

    let mut messages = Vec::new();
    let mut ingest = TransferIngestTracker::new("IXFR", primary.addr, session.max_ingest_bytes);
    loop {
        let mut length_prefix = [0u8; 2];
        match stream.read_exact(&mut length_prefix).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                let verified_messages = maybe_verify_tcp_transfer_messages(
                    &messages,
                    session.tsig.key,
                    query.request_mac.as_deref(),
                )?;
                return axfr::parse_ixfr_response_with_options(
                    qid,
                    zone_apex,
                    qclass,
                    current_zone,
                    &verified_messages,
                    session.parse_options,
                )
                .map_err(TransferError::Ixfr);
            }
            Err(source) => {
                return Err(TransferError::Io {
                    addr: primary.addr,
                    source,
                });
            }
        }

        let message_len = u16::from_be_bytes(length_prefix) as usize;
        ingest.record_message(message_len)?;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message).await.map_err(|source| {
            if source.kind() == std::io::ErrorKind::UnexpectedEof {
                TransferError::Ixfr(axfr::IxfrError::IncompleteResponse)
            } else {
                TransferError::Io {
                    addr: primary.addr,
                    source,
                }
            }
        })?;
        messages.push(message);

        match axfr::parse_ixfr_response_with_options(
            qid,
            zone_apex,
            qclass,
            current_zone,
            &messages,
            session.parse_options,
        ) {
            Ok(_) => {
                match maybe_verify_tcp_transfer_messages(
                    &messages,
                    session.tsig.key,
                    query.request_mac.as_deref(),
                ) {
                    Ok(verified_messages) => {
                        return axfr::parse_ixfr_response_with_options(
                            qid,
                            zone_apex,
                            qclass,
                            current_zone,
                            &verified_messages,
                            session.parse_options,
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

fn outbound_udp_bind_addr(primary: SocketAddr, transfer_source: Option<SocketAddr>) -> SocketAddr {
    transfer_source
        .filter(|source| source.is_ipv4() == primary.is_ipv4())
        .unwrap_or_else(|| match primary {
            SocketAddr::V4(_) => "0.0.0.0:0"
                .parse()
                .expect("hard-coded IPv4 wildcard socket address is valid"),
            SocketAddr::V6(_) => "[::]:0"
                .parse()
                .expect("hard-coded IPv6 wildcard socket address is valid"),
        })
}

struct TransferQuery {
    message: Vec<u8>,
    request_mac: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
struct TransferTsig<'a> {
    key: Option<&'a TsigKey>,
    fudge_seconds: u16,
}

impl<'a> TransferTsig<'a> {
    fn new(key: Option<&'a TsigKey>, fudge_seconds: u16) -> Self {
        Self { key, fudge_seconds }
    }

    fn unsigned() -> Self {
        Self::new(None, DEFAULT_TSIG_FUDGE_SECS)
    }
}

#[derive(Clone, Copy)]
struct TransferSession<'a> {
    tsig: TransferTsig<'a>,
    max_ingest_bytes: u64,
    transfer_source: Option<SocketAddr>,
    parse_options: axfr::TransferParseOptions,
}

impl<'a> TransferSession<'a> {
    fn new(tsig: TransferTsig<'a>, max_ingest_bytes: u64) -> Self {
        Self {
            tsig,
            max_ingest_bytes,
            transfer_source: None,
            parse_options: axfr::TransferParseOptions::default(),
        }
    }

    fn default_unsigned() -> Self {
        Self::new(TransferTsig::unsigned(), default_transfer_ingest_bytes())
    }

    fn with_transfer_source(mut self, transfer_source: Option<SocketAddr>) -> Self {
        self.transfer_source = transfer_source;
        self
    }

    fn with_parse_options(mut self, parse_options: axfr::TransferParseOptions) -> Self {
        self.parse_options = parse_options;
        self
    }
}

fn default_transfer_ingest_bytes() -> u64 {
    4 * 1024 * 1024 * 1024
}

struct TransferIngestTracker {
    protocol: &'static str,
    addr: SocketAddr,
    limit_bytes: u64,
    received_bytes: u64,
}

impl TransferIngestTracker {
    fn new(protocol: &'static str, addr: SocketAddr, limit_bytes: u64) -> Self {
        Self {
            protocol,
            addr,
            limit_bytes,
            received_bytes: 0,
        }
    }

    fn record_message(&mut self, message_len: usize) -> Result<(), TransferError> {
        let next = self.received_bytes.saturating_add(message_len as u64);
        if next > self.limit_bytes {
            return Err(TransferError::IngestSizeLimit {
                protocol: self.protocol,
                addr: self.addr,
                received_bytes: next,
                limit_bytes: self.limit_bytes,
            });
        }
        self.received_bytes = next;
        Ok(())
    }
}

fn maybe_sign_transfer_query(
    query: Vec<u8>,
    tsig: TransferTsig<'_>,
) -> Result<TransferQuery, TransferError> {
    let Some(tsig_key) = tsig.key else {
        return Ok(TransferQuery {
            message: query,
            request_mac: None,
        });
    };

    let signed = tsig_key.sign_request(&query, tsig_time_signed(), tsig.fudge_seconds)?;
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
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    session: TransferSession<'_>,
    connect_timeout: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    let mut stream =
        connect_transfer_stream(primary, session.transfer_source, connect_timeout).await?;

    let query =
        maybe_sign_transfer_query(axfr::build_axfr_query(qid, zone_apex, qclass), session.tsig)?;
    let framed_query = axfr::frame_tcp_message(&query.message);
    stream
        .write_all(&framed_query)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary.addr,
            source,
        })?;

    let mut messages = Vec::new();
    let mut saw_initial_soa = false;
    let mut ingest = TransferIngestTracker::new("AXFR", primary.addr, session.max_ingest_bytes);
    loop {
        let mut length_prefix = [0u8; 2];
        match stream.read_exact(&mut length_prefix).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                let verified_messages = maybe_verify_tcp_transfer_messages(
                    &messages,
                    session.tsig.key,
                    query.request_mac.as_deref(),
                )?;
                return axfr::parse_axfr_response_with_options(
                    qid,
                    zone_apex,
                    qclass,
                    &verified_messages,
                    session.parse_options,
                )
                .map_err(TransferError::Axfr);
            }
            Err(source) => {
                return Err(TransferError::Io {
                    addr: primary.addr,
                    source,
                });
            }
        }

        let message_len = u16::from_be_bytes(length_prefix) as usize;
        ingest.record_message(message_len)?;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message).await.map_err(|source| {
            if source.kind() == std::io::ErrorKind::UnexpectedEof {
                TransferError::Axfr(AxfrError::MissingTerminatingSoa)
            } else {
                TransferError::Io {
                    addr: primary.addr,
                    source,
                }
            }
        })?;
        let apex_soa_count = axfr::axfr_response_message_apex_soa_count(
            qid,
            zone_apex,
            qclass,
            &message,
            !saw_initial_soa,
        )
        .map_err(TransferError::Axfr)?;
        if apex_soa_count > 0 {
            let complete = saw_initial_soa || apex_soa_count >= 2;
            saw_initial_soa = true;
            if complete {
                messages.push(message);
                match maybe_verify_tcp_transfer_messages(
                    &messages,
                    session.tsig.key,
                    query.request_mac.as_deref(),
                ) {
                    Ok(verified_messages) => {
                        return axfr::parse_axfr_response_with_options(
                            qid,
                            zone_apex,
                            qclass,
                            &verified_messages,
                            session.parse_options,
                        )
                        .map_err(TransferError::Axfr);
                    }
                    Err(TransferError::Tsig(TsigError::MissingTerminalTsig)) => {}
                    Err(error) => return Err(error),
                }
                continue;
            }
        }
        messages.push(message);
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

fn dns_cookie_secret() -> Result<[u8; 16], getrandom::Error> {
    let mut secret = [0u8; 16];
    getrandom::fill(&mut secret)?;
    Ok(secret)
}

fn dns_cookie_secret_fingerprint(secret: &[u8; 16]) -> String {
    let digest = Sha256::digest(secret);
    lower_hex(&digest[..8])
}

#[derive(Clone)]
struct DnsCookieSecretStore {
    inner: Arc<Mutex<DnsCookieSecretState>>,
    rotation_interval: Option<Duration>,
}

struct DnsCookieSecretState {
    current: [u8; 16],
    generated_at: Instant,
}

impl DnsCookieSecretStore {
    fn new(current: [u8; 16], rotation_interval: Option<Duration>) -> Self {
        Self::new_at(current, rotation_interval, Instant::now())
    }

    fn new_at(
        current: [u8; 16],
        rotation_interval: Option<Duration>,
        generated_at: Instant,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DnsCookieSecretState {
                current,
                generated_at,
            })),
            rotation_interval,
        }
    }

    fn current(&self) -> [u8; 16] {
        self.current_with_generator(dns_cookie_secret)
    }

    fn current_with_generator(
        &self,
        generate_secret: impl FnOnce() -> Result<[u8; 16], getrandom::Error>,
    ) -> [u8; 16] {
        let mut state = self
            .inner
            .lock()
            .expect("DNS Cookie secret store lock poisoned");
        if self
            .rotation_interval
            .is_some_and(|interval| state.generated_at.elapsed() >= interval)
        {
            match generate_secret() {
                Ok(secret) => {
                    state.current = secret;
                    state.generated_at = Instant::now();
                    info!(
                        category = "cookie",
                        secret_fingerprint = %dns_cookie_secret_fingerprint(&state.current),
                        "DNS Cookie server secret rotated"
                    );
                }
                Err(error) => {
                    warn!(
                        category = "cookie",
                        %error,
                        "DNS Cookie server secret rotation failed; retaining previous secret"
                    );
                }
            }
        }
        state.current
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn current_unix_time_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as u32)
        .unwrap_or_default()
}

#[derive(Clone, Copy)]
struct DnsCookieRuntimeSettings {
    policy: Option<DnsCookiePolicy>,
    past_window_secs: u32,
    future_window_secs: u32,
    secret_rotation_interval: Option<Duration>,
}

#[derive(Clone, Copy)]
struct CookiePrefixMetricSettings {
    ipv4_prefix_len: u8,
    ipv6_prefix_len: u8,
}

fn dns_cookie_settings(config: &CookieConfig) -> DnsCookieRuntimeSettings {
    let policy = match config.policy {
        CookiePolicyConfig::Disabled => None,
        CookiePolicyConfig::Lenient => Some(DnsCookiePolicy::Lenient),
        CookiePolicyConfig::Strict => Some(DnsCookiePolicy::Strict),
    };
    DnsCookieRuntimeSettings {
        policy,
        past_window_secs: config.timestamp_past_tolerance_seconds,
        future_window_secs: config.timestamp_future_tolerance_seconds,
        secret_rotation_interval: (config.secret_rotation_interval_secs > 0)
            .then(|| Duration::from_secs(config.secret_rotation_interval_secs)),
    }
}

fn dns_cookie_context<'a>(
    peer_ip: IpAddr,
    secret: &'a [u8; 16],
    settings: DnsCookieRuntimeSettings,
) -> Option<DnsCookieContext<'a>> {
    let mut context = DnsCookieContext::new(peer_ip, secret, current_unix_time_secs());
    context.policy = settings.policy?;
    context.past_window_secs = settings.past_window_secs;
    context.future_window_secs = settings.future_window_secs;
    Some(context)
}

fn cookie_metric_prefix(source: IpAddr, settings: CookiePrefixMetricSettings) -> IpPrefix {
    let prefix_len = match source {
        IpAddr::V4(_) => settings.ipv4_prefix_len,
        IpAddr::V6(_) => settings.ipv6_prefix_len,
    };
    IpPrefix::new(source, prefix_len)
}

#[derive(Clone, Debug)]
struct RrlLimiter {
    inner: Arc<Mutex<RrlState>>,
    metrics: RuntimeMetrics,
}

impl RrlLimiter {
    fn from_config(config: &RrlConfig, metrics: RuntimeMetrics) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RrlState::from_config(config))),
            metrics,
        }
    }

    fn apply(&self, source: IpAddr, response: Vec<u8>) -> RrlDecision {
        let Some(category) = response_category(&response) else {
            return RrlDecision::Send(response);
        };
        let mut state = self.inner.lock().expect("RRL state lock poisoned");
        state.apply(source, category, response, &self.metrics)
    }

    fn rate_limited_key_count(&self) -> u64 {
        self.inner
            .lock()
            .expect("RRL state lock poisoned")
            .rate_limited_key_count()
    }

    fn enabled(&self) -> bool {
        self.inner.lock().expect("RRL state lock poisoned").enabled
    }
}

#[derive(Debug)]
enum RrlDecision {
    Send(Vec<u8>),
    Drop,
}

#[derive(Debug)]
struct RrlState {
    enabled: bool,
    ipv4_prefix_len: u8,
    ipv6_prefix_len: u8,
    rates: RrlRates,
    slip: u32,
    max_keys: usize,
    allowlist: Vec<IpPrefix>,
    buckets: HashMap<RrlKey, RrlBucket>,
    lru: VecDeque<RrlKey>,
}

impl RrlState {
    fn from_config(config: &RrlConfig) -> Self {
        Self {
            enabled: config.enabled,
            ipv4_prefix_len: config.ipv4_prefix_len,
            ipv6_prefix_len: config.ipv6_prefix_len,
            rates: RrlRates {
                positive: config.positive_per_second,
                nxdomain: config.nxdomain_per_second,
                nodata: config.nodata_per_second,
                referral: config.referral_per_second,
                error: config.error_per_second,
            },
            slip: config.slip,
            max_keys: config.max_keys,
            allowlist: config
                .allowlist
                .iter()
                .map(|prefix| IpPrefix::parse(prefix).expect("validated RRL allowlist prefix"))
                .collect(),
            buckets: HashMap::new(),
            lru: VecDeque::new(),
        }
    }

    fn apply(
        &mut self,
        source: IpAddr,
        category: RrlCategory,
        response: Vec<u8>,
        metrics: &RuntimeMetrics,
    ) -> RrlDecision {
        if !self.enabled || self.allowlist.iter().any(|prefix| prefix.contains(source)) {
            return RrlDecision::Send(response);
        }

        metrics.record_rrl_subject();
        let key = RrlKey::new(source, self.prefix_len(source), category);
        let rate = self.rates.for_category(category);
        if !self.buckets.contains_key(&key) {
            self.evict_one_if_needed(metrics);
            self.buckets.insert(key, RrlBucket::new(rate));
            metrics.set_rrl_tracked_keys(self.tracked_keys());
        }
        self.touch_lru(key);

        let Some(bucket) = self.buckets.get_mut(&key) else {
            return RrlDecision::Send(response);
        };
        if bucket.take_token(rate) {
            return RrlDecision::Send(response);
        }

        if bucket.limited_count == 0 {
            warn!(
                ?key,
                rate,
                slip = self.slip,
                "RRL accounting key entered rate-limited state"
            );
        }
        bucket.limited_count = bucket.limited_count.saturating_add(1);
        if self.slip > 0 && bucket.limited_count.is_multiple_of(u64::from(self.slip)) {
            metrics.record_rrl_truncated();
            RrlDecision::Send(rrl_truncated_response(&response))
        } else {
            metrics.record_rrl_dropped();
            RrlDecision::Drop
        }
    }

    fn prefix_len(&self, source: IpAddr) -> u8 {
        match source {
            IpAddr::V4(_) => self.ipv4_prefix_len,
            IpAddr::V6(_) => self.ipv6_prefix_len,
        }
    }

    fn evict_one_if_needed(&mut self, metrics: &RuntimeMetrics) {
        if self.buckets.len() < self.max_keys {
            return;
        }
        while let Some(key) = self.lru.pop_front() {
            if self.buckets.remove(&key).is_some() {
                metrics.record_rrl_key_evicted();
                metrics.set_rrl_tracked_keys(self.tracked_keys());
                return;
            }
        }
    }

    fn touch_lru(&mut self, key: RrlKey) {
        self.lru.retain(|candidate| *candidate != key);
        self.lru.push_back(key);
    }

    fn tracked_keys(&self) -> u64 {
        self.buckets.len() as u64
    }

    fn rate_limited_key_count(&self) -> u64 {
        let now = Instant::now();
        self.buckets
            .iter()
            .filter(|(key, bucket)| {
                bucket.limited_count > 0
                    && !bucket.would_have_token(self.rates.for_category(key.category), now)
            })
            .count() as u64
    }
}

#[derive(Debug, Clone, Copy)]
struct RrlRates {
    positive: u32,
    nxdomain: u32,
    nodata: u32,
    referral: u32,
    error: u32,
}

impl RrlRates {
    fn for_category(self, category: RrlCategory) -> u32 {
        match category {
            RrlCategory::Positive => self.positive,
            RrlCategory::NxDomain => self.nxdomain,
            RrlCategory::NoData => self.nodata,
            RrlCategory::Referral => self.referral,
            RrlCategory::Error => self.error,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RrlBucket {
    tokens: f64,
    last_refill: Instant,
    limited_count: u64,
}

impl RrlBucket {
    fn new(rate: u32) -> Self {
        Self {
            tokens: f64::from(rate),
            last_refill: Instant::now(),
            limited_count: 0,
        }
    }

    fn take_token(&mut self, rate: u32) -> bool {
        if rate > 0 {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_refill).as_secs_f64();
            self.tokens = (self.tokens + elapsed * f64::from(rate)).min(f64::from(rate));
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn would_have_token(self, rate: u32, now: Instant) -> bool {
        let tokens = if rate > 0 {
            let elapsed = now.duration_since(self.last_refill).as_secs_f64();
            (self.tokens + elapsed * f64::from(rate)).min(f64::from(rate))
        } else {
            self.tokens
        };
        tokens >= 1.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RrlKey {
    prefix: IpPrefix,
    category: RrlCategory,
}

impl RrlKey {
    fn new(source: IpAddr, prefix_len: u8, category: RrlCategory) -> Self {
        Self {
            prefix: IpPrefix::new(source, prefix_len),
            category,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RrlCategory {
    Positive,
    NxDomain,
    NoData,
    Referral,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpPrefix {
    V4 { network: u32, len: u8 },
    V6 { network: u128, len: u8 },
}

impl IpPrefix {
    fn parse(value: &str) -> Option<Self> {
        let (addr, len) = match value.split_once('/') {
            Some((addr, len)) => {
                let addr = addr.parse::<IpAddr>().ok()?;
                let len = len.parse::<u8>().ok()?;
                (addr, len)
            }
            None => {
                let addr = value.parse::<IpAddr>().ok()?;
                let len = match addr {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                (addr, len)
            }
        };
        Some(Self::new(addr, len))
    }

    fn new(addr: IpAddr, len: u8) -> Self {
        match addr {
            IpAddr::V4(addr) => {
                let len = len.min(32);
                let network = u32::from(addr) & prefix_mask_v4(len);
                Self::V4 { network, len }
            }
            IpAddr::V6(addr) => {
                let len = len.min(128);
                let network = u128::from(addr) & prefix_mask_v6(len);
                Self::V6 { network, len }
            }
        }
    }

    fn contains(self, addr: IpAddr) -> bool {
        match (self, addr) {
            (Self::V4 { network, len }, IpAddr::V4(addr)) => {
                u32::from(addr) & prefix_mask_v4(len) == network
            }
            (Self::V6 { network, len }, IpAddr::V6(addr)) => {
                u128::from(addr) & prefix_mask_v6(len) == network
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 { network, len } => {
                write!(formatter, "{}/{}", std::net::Ipv4Addr::from(*network), len)
            }
            Self::V6 { network, len } => {
                write!(formatter, "{}/{}", std::net::Ipv6Addr::from(*network), len)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct NotifyLogLimiter {
    inner: Arc<Mutex<NotifyLogState>>,
}

impl NotifyLogLimiter {
    fn new(window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(NotifyLogState::new(window))),
        }
    }

    fn log_unauthorized(&self, source: IpAddr, zone: &DomainName) {
        self.log_event(NotifyLogCategory::Unauthorized, source, zone, None);
    }

    fn log_tsig_failure(&self, source: IpAddr, zone: &DomainName, error: &TsigError) {
        self.log_event(
            NotifyLogCategory::TsigFailure,
            source,
            zone,
            Some(error.to_string()),
        );
    }

    fn log_event(
        &self,
        category: NotifyLogCategory,
        source: IpAddr,
        zone: &DomainName,
        error: Option<String>,
    ) {
        let zone_key = zone.canonical_key();
        let decision = self
            .inner
            .lock()
            .expect("NOTIFY log limiter lock poisoned")
            .observe(category, source, zone_key);
        if decision == NotifyLogDecision::Suppress {
            return;
        }
        match category {
            NotifyLogCategory::Unauthorized => {
                warn!(
                    category = "notify",
                    event = "notify_unauthorized_discard",
                    peer_ip = %source,
                    source_prefix = %notify_log_prefix(source),
                    zone = %zone,
                    "unauthorized NOTIFY discarded"
                );
            }
            NotifyLogCategory::TsigFailure => {
                warn!(
                    category = "notify",
                    event = "notify_tsig_failure",
                    peer_ip = %source,
                    source_prefix = %notify_log_prefix(source),
                    zone = %zone,
                    error = %error.as_deref().unwrap_or("TSIG verification failed"),
                    "rejected NOTIFY with invalid TSIG"
                );
            }
        }
    }

    fn take_summary(&self) -> NotifyLogSummary {
        self.inner
            .lock()
            .expect("NOTIFY log limiter lock poisoned")
            .take_summary()
    }
}

#[derive(Debug)]
struct NotifyLogState {
    window: Duration,
    keys: HashMap<NotifyLogKey, Instant>,
    suppressed_unauthorized: u64,
    suppressed_tsig_failures: u64,
    suppressed_prefixes: HashSet<IpPrefix>,
}

impl NotifyLogState {
    fn new(window: Duration) -> Self {
        Self {
            window,
            keys: HashMap::new(),
            suppressed_unauthorized: 0,
            suppressed_tsig_failures: 0,
            suppressed_prefixes: HashSet::new(),
        }
    }

    fn observe(
        &mut self,
        category: NotifyLogCategory,
        source: IpAddr,
        zone: String,
    ) -> NotifyLogDecision {
        let now = Instant::now();
        self.expire_old_keys(now);
        let prefix = notify_log_prefix(source);
        let key = NotifyLogKey {
            prefix,
            zone,
            category,
        };
        if let std::collections::hash_map::Entry::Vacant(entry) = self.keys.entry(key) {
            entry.insert(now);
            return NotifyLogDecision::Emit;
        }

        match category {
            NotifyLogCategory::Unauthorized => {
                self.suppressed_unauthorized = self.suppressed_unauthorized.saturating_add(1);
            }
            NotifyLogCategory::TsigFailure => {
                self.suppressed_tsig_failures = self.suppressed_tsig_failures.saturating_add(1);
            }
        }
        self.suppressed_prefixes.insert(prefix);
        NotifyLogDecision::Suppress
    }

    fn expire_old_keys(&mut self, now: Instant) {
        let window = self.window;
        self.keys
            .retain(|_, first_seen| now.duration_since(*first_seen) < window);
    }

    fn take_summary(&mut self) -> NotifyLogSummary {
        let summary = NotifyLogSummary {
            suppressed_unauthorized: self.suppressed_unauthorized,
            suppressed_tsig_failures: self.suppressed_tsig_failures,
            distinct_source_prefixes: self.suppressed_prefixes.len() as u64,
            total_suppressed: self
                .suppressed_unauthorized
                .saturating_add(self.suppressed_tsig_failures),
        };
        self.suppressed_unauthorized = 0;
        self.suppressed_tsig_failures = 0;
        self.suppressed_prefixes.clear();
        summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NotifyLogKey {
    prefix: IpPrefix,
    zone: String,
    category: NotifyLogCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NotifyLogCategory {
    Unauthorized,
    TsigFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyLogDecision {
    Emit,
    Suppress,
}

fn notify_log_prefix(source: IpAddr) -> IpPrefix {
    let prefix_len = match source {
        IpAddr::V4(_) => 24,
        IpAddr::V6(_) => 56,
    };
    IpPrefix::new(source, prefix_len)
}

fn prefix_mask_v4(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len) }
}

fn prefix_mask_v6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    }
}

fn response_category(response: &[u8]) -> Option<RrlCategory> {
    let header = Header::parse(response).ok()?;
    if !header.is_response() || header.opcode() != Some(Opcode::Query) {
        return None;
    }
    let rcode = response_rcode(response, &header);
    match rcode {
        0 if header.ancount > 0 => Some(RrlCategory::Positive),
        0 if response_has_authority_ns(response, &header) => Some(RrlCategory::Referral),
        0 => Some(RrlCategory::NoData),
        3 => Some(RrlCategory::NxDomain),
        _ => Some(RrlCategory::Error),
    }
}

fn response_has_authority_ns(response: &[u8], header: &Header) -> bool {
    let Some(mut offset) = response_question_end(response, header) else {
        return false;
    };
    for _ in 0..header.ancount {
        let Some(next) = skip_response_record(response, offset) else {
            return false;
        };
        offset = next;
    }
    for _ in 0..header.nscount {
        let Some((rr_type, next)) = response_record_type(response, offset) else {
            return false;
        };
        if rr_type == RecordType::Ns as u16 {
            return true;
        }
        offset = next;
    }
    false
}

fn response_question_end(response: &[u8], header: &Header) -> Option<usize> {
    let mut offset = 12;
    for _ in 0..header.qdcount {
        let (_, consumed) = DomainName::parse(response, offset).ok()?;
        offset = offset.checked_add(consumed)?.checked_add(4)?;
        if offset > response.len() {
            return None;
        }
    }
    Some(offset)
}

fn response_record_type(response: &[u8], offset: usize) -> Option<(u16, usize)> {
    let (_, consumed) = DomainName::parse(response, offset).ok()?;
    let header_offset = offset.checked_add(consumed)?;
    if header_offset + 10 > response.len() {
        return None;
    }
    let rr_type = u16::from_be_bytes([response[header_offset], response[header_offset + 1]]);
    let rdlength =
        u16::from_be_bytes([response[header_offset + 8], response[header_offset + 9]]) as usize;
    let next = header_offset.checked_add(10)?.checked_add(rdlength)?;
    (next <= response.len()).then_some((rr_type, next))
}

fn rrl_truncated_response(response: &[u8]) -> Vec<u8> {
    let Ok(header) = Header::parse(response) else {
        return response.to_vec();
    };
    let question_end = response_question_end(response, &header).unwrap_or(12);
    let opt = response_opt_record(response, &header);
    let mut out = Vec::with_capacity(question_end + opt.map_or(0, |opt| opt.len()));
    out.extend_from_slice(&response[..2]);
    out.extend_from_slice(&(header.flags | 0x0200).to_be_bytes());
    out.extend_from_slice(&header.qdcount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(u16::from(opt.is_some())).to_be_bytes());
    if question_end > 12 && question_end <= response.len() {
        out.extend_from_slice(&response[12..question_end]);
    }
    if let Some(opt) = opt {
        out.extend_from_slice(opt);
    }
    out
}

fn response_opt_record<'a>(response: &'a [u8], header: &Header) -> Option<&'a [u8]> {
    let mut offset = response_question_end(response, header)?;
    for count in [header.ancount, header.nscount] {
        for _ in 0..count {
            offset = skip_response_record(response, offset)?;
        }
    }
    for _ in 0..header.arcount {
        let start = offset;
        let (rr_type, next) = response_record_type(response, offset)?;
        if rr_type == RecordType::Opt as u16 {
            return Some(&response[start..next]);
        }
        offset = next;
    }
    None
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
        let parse_started = settings.metrics.start_pipeline_timer();
        let Some(prepared) = prepare_notify_packet_with_metrics(
            &buffer[..len],
            &settings.notify_authority,
            peer_ip,
            &settings.metrics,
            &settings.notify_log_limiter,
        ) else {
            debug!(
                peer_ip = %peer.ip(),
                peer_port = peer.port(),
                transport = "udp",
                bytes = len,
                "discarded DNS datagram"
            );
            continue;
        };
        let prepared = prepare_query_tsig_packet(prepared, &settings.notify_authority);
        let parse_duration = parse_started.map(|started| started.elapsed());
        if let Some(response) = prepared.immediate_response {
            socket
                .send_to(&response, peer)
                .await
                .map_err(RuntimeError::Udp)?;
            continue;
        }
        let dns_cookie_secret = settings.dns_cookie_secrets.current();
        let dns_cookie = dns_cookie_context(peer_ip, &dns_cookie_secret, settings.dns_cookie);
        let cookie_validated = dns_cookie
            .is_some_and(|context| request_has_valid_dns_server_cookie(&prepared.packet, context));
        let query_metrics = observe_query_metrics(
            &prepared.packet,
            &zones,
            &settings.metrics,
            Transport::Udp,
            cookie_validated,
            parse_duration,
        );
        let query_tsig_authenticated =
            prepared.tsig_authenticated || prepared.response_tsig.is_some();
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
        let action = answer_message_with_notify_hooks_and_query_observer(
            &prepared.packet,
            &zones,
            AnswerOptions {
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
            },
            |qname, qclass| {
                let authorized = settings
                    .notify_authority
                    .is_authorized(qname, qclass, peer_ip);
                if !authorized {
                    settings.metrics.record_notify_unauthorized();
                    settings.notify_log_limiter.log_unauthorized(peer_ip, qname);
                }
                authorized
            },
            |qname, _qclass, serial| {
                signal_notify_refresh(
                    &settings.notify_refresh,
                    &settings.notify_refresh_tx,
                    &settings.metrics,
                    qname,
                    peer_ip,
                    serial,
                )
            },
            |lookup| {
                record_query_termination_metric(&query_metrics, lookup, &settings.metrics);
            },
        );
        let mut query_metrics = query_metrics;
        query_metrics.compose_duration = compose_started.map(|started| started.elapsed());
        match action {
            DatagramAction::Discard => {
                debug!(
                    peer_ip = %peer.ip(),
                    peer_port = peer.port(),
                    transport = "udp",
                    bytes = len,
                    "discarded DNS datagram"
                );
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
                        continue;
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
                        let send_started = settings.metrics.start_pipeline_timer();
                        socket
                            .send_to(&response, peer)
                            .await
                            .map_err(RuntimeError::Udp)?;
                        if let Some(started) = send_started {
                            record_query_send_metric(
                                &query_metrics,
                                &response,
                                &settings.metrics,
                                started.elapsed(),
                            );
                        }
                    }
                    RrlDecision::Drop => {}
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct QueryMetricObservation {
    is_query: bool,
    transport: Transport,
    started_at: Instant,
    cookie_validated: bool,
    zone_key: Option<String>,
    parse_duration: Option<Duration>,
    lookup_duration: Option<Duration>,
    compose_duration: Option<Duration>,
}

fn observe_query_metrics(
    packet: &[u8],
    zones: &ZoneStore,
    metrics: &RuntimeMetrics,
    transport: Transport,
    cookie_validated: bool,
    parse_duration: Option<Duration>,
) -> QueryMetricObservation {
    let started_at = Instant::now();
    let lookup_started = metrics.start_pipeline_timer();
    let not_query = || QueryMetricObservation {
        is_query: false,
        transport,
        started_at,
        cookie_validated: false,
        zone_key: None,
        parse_duration,
        lookup_duration: lookup_started.map(|started| started.elapsed()),
        compose_duration: None,
    };
    let observed_query = |zone_key| QueryMetricObservation {
        is_query: true,
        transport,
        started_at,
        cookie_validated,
        zone_key,
        parse_duration,
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
    if header.qdcount != 1 {
        return observed_query(None);
    }
    let Ok(question) = Question::parse(packet) else {
        return observed_query(None);
    };
    if let Some(zone) = zones.find_zone(&question.qname) {
        metrics.record_zone_query(&zone.origin);
        return observed_query(Some(zone.origin.canonical_key()));
    }
    observed_query(None)
}

fn observe_dns_cookie_metrics(
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

fn record_dns_cookie_badcookie_if_emitted(
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

fn record_chaos_query_if_observed(
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

fn record_query_response_metric(
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
    if response_has_ede_info_code(response, &header, EDE_UNSUPPORTED_NSEC3_ITERATIONS) {
        metrics.record_nsec3_iterations_exceed_cap();
    }
    metrics.record_query_latency(
        query_latency_category(observation, response, &header),
        observation.started_at.elapsed(),
    );
}

fn record_query_send_metric(
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

fn record_response_cache_metric(
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

fn response_cache_ineligible_reason(
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

fn response_has_ede_info_code(response: &[u8], header: &Header, expected_info_code: u16) -> bool {
    let Some(opt) = response_opt_record(response, header) else {
        return false;
    };
    if opt.len() < 11 {
        return false;
    }
    let rdlength = u16::from_be_bytes([opt[9], opt[10]]) as usize;
    let end = 11 + rdlength;
    if opt.len() < end {
        return false;
    }

    let mut offset = 11usize;
    while offset + 4 <= end {
        let option_code = u16::from_be_bytes([opt[offset], opt[offset + 1]]);
        let option_len = u16::from_be_bytes([opt[offset + 2], opt[offset + 3]]) as usize;
        offset += 4;
        if offset + option_len > end {
            return false;
        }
        if option_code == EDNS_EXTENDED_DNS_ERROR_OPTION && option_len >= 2 {
            let info_code = u16::from_be_bytes([opt[offset], opt[offset + 1]]);
            if info_code == expected_info_code {
                return true;
            }
        }
        offset += option_len;
    }

    false
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

fn record_query_termination_metric(
    observation: &QueryMetricObservation,
    lookup: &LookupResult,
    metrics: &RuntimeMetrics,
) {
    if !observation.is_query {
        return;
    }
    match lookup.termination {
        Some(LookupTermination::CnameChainLimit) => metrics.record_query_cname_chain_limit(),
        Some(LookupTermination::CnameLoop) => metrics.record_query_cname_loop(),
        Some(LookupTermination::MalformedDname) => {}
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
    rrl: RrlLimiter,
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
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(error) = handle_tcp_connection(
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
}

async fn serve_health(
    listener: TcpListener,
    state: HealthEndpointState,
    shutdown_signal: impl Future<Output = ()> + Send + 'static,
) -> Result<(), RuntimeError> {
    let local_addr = listener.local_addr().map_err(RuntimeError::Health)?;
    info!(%local_addr, "health listener bound");

    axum::serve(
        listener,
        health_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal)
    .await
    .map_err(RuntimeError::Health)
}

fn health_router(state: HealthEndpointState) -> Router {
    Router::new()
        .route(
            "/livez",
            get(livez)
                .head(health_method_not_allowed)
                .fallback(health_method_not_allowed),
        )
        .route(
            "/healthz",
            get(healthz)
                .head(health_method_not_allowed)
                .fallback(health_method_not_allowed),
        )
        .route(
            "/readyz",
            get(readyz)
                .head(health_method_not_allowed)
                .fallback(health_method_not_allowed),
        )
        .route(
            "/metrics",
            get(metrics)
                .head(health_method_not_allowed)
                .fallback(health_method_not_allowed),
        )
        .fallback(health_not_found)
        .with_state(state)
}

async fn health_method_not_allowed(uri: Uri) -> Response {
    json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        format!(
            "{{\"error\":\"method_not_allowed\",\"path\":\"{}\"}}",
            json_string(uri.path())
        ),
    )
}

async fn health_not_found(uri: Uri) -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        format!(
            "{{\"error\":\"not_found\",\"path\":\"{}\"}}",
            json_string(uri.path())
        ),
    )
}

async fn livez(State(state): State<HealthEndpointState>) -> Response {
    json_response(
        StatusCode::OK,
        format!(
            "{{\"status\":\"alive\",\"version\":\"{}\",\"uptime_seconds\":{}}}",
            env!("CARGO_PKG_VERSION"),
            state.started_at.elapsed().as_secs()
        ),
    )
}

async fn healthz(State(state): State<HealthEndpointState>) -> Response {
    readiness_response(&state)
}

async fn readyz(State(state): State<HealthEndpointState>) -> Response {
    readiness_response(&state)
}

async fn metrics(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<HealthEndpointState>,
) -> Response {
    if let Err(retry_after_seconds) = state.metrics_rate_limiter.check(peer.ip()) {
        return rate_limited_response(retry_after_seconds);
    }

    let body = metrics_body(
        &state.zones,
        &state.metrics,
        &state.catalog_manager,
        &state.refresh_registry,
        state.started_at.elapsed().as_secs(),
        state.zone_shape_metrics_enabled,
    );
    if accepts_gzip(&headers) {
        match gzip_bytes(body.as_bytes()) {
            Ok(compressed) => {
                return (
                    StatusCode::OK,
                    [
                        (
                            header::CONTENT_TYPE,
                            "text/plain; version=0.0.4; charset=utf-8",
                        ),
                        (header::CONTENT_ENCODING, "gzip"),
                        (header::VARY, "accept-encoding"),
                    ],
                    compressed,
                )
                    .into_response();
            }
            Err(error) => {
                warn!(%error, "failed to gzip metrics response");
            }
        }
    }

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

fn rate_limited_response(retry_after_seconds: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::RETRY_AFTER, retry_after_seconds.to_string()),
        ],
        format!("{{\"error\":\"rate_limited\",\"retry_after_seconds\":{retry_after_seconds}}}"),
    )
        .into_response()
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(accept_encoding_value_allows_gzip)
}

fn accept_encoding_value_allows_gzip(value: &str) -> bool {
    value.split(',').any(|encoding| {
        let mut parts = encoding.split(';').map(str::trim);
        if !parts
            .next()
            .is_some_and(|token| token.eq_ignore_ascii_case("gzip"))
        {
            return false;
        }

        for parameter in parts {
            let Some((name, value)) = parameter.split_once('=') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case("q")
                && value
                    .trim()
                    .parse::<f32>()
                    .is_ok_and(|quality| quality <= 0.0)
            {
                return false;
            }
        }

        true
    })
}

fn gzip_bytes(body: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body)?;
    encoder.finish()
}

fn metrics_body(
    zones: &ZoneStore,
    metrics: &RuntimeMetrics,
    catalog_manager: &CatalogManager,
    refresh_registry: &ZoneRefreshRegistry,
    uptime_seconds: u64,
    zone_shape_metrics_enabled: bool,
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
         # HELP oxidedns_rrl_responses_subject_total UDP query responses subject to RRL accounting.\n\
         # TYPE oxidedns_rrl_responses_subject_total counter\n\
         oxidedns_rrl_responses_subject_total {}\n\
         # HELP oxidedns_rrl_responses_dropped_total UDP query responses dropped by RRL.\n\
         # TYPE oxidedns_rrl_responses_dropped_total counter\n\
         oxidedns_rrl_responses_dropped_total {}\n\
         # HELP oxidedns_rrl_responses_truncated_total UDP query responses emitted as truncated by RRL.\n\
         # TYPE oxidedns_rrl_responses_truncated_total counter\n\
         oxidedns_rrl_responses_truncated_total {}\n\
         # HELP oxidedns_rrl_keys_tracked RRL accounting keys currently tracked.\n\
         # TYPE oxidedns_rrl_keys_tracked gauge\n\
         oxidedns_rrl_keys_tracked {}\n\
         # HELP oxidedns_rrl_key_evictions_total RRL accounting keys evicted due to the configured cap.\n\
         # TYPE oxidedns_rrl_key_evictions_total counter\n\
         oxidedns_rrl_key_evictions_total {}\n\
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
        snapshot.rrl_subject,
        snapshot.rrl_dropped,
        snapshot.rrl_truncated,
        snapshot.rrl_tracked_keys,
        snapshot.rrl_key_evictions,
        snapshot.axfr_started,
        snapshot.ixfr_started,
        snapshot.axfr_succeeded,
        snapshot.ixfr_succeeded,
        snapshot.axfr_failed,
        snapshot.ixfr_failed,
    );
    append_build_info_metric(&mut body);
    append_query_rcode_metrics(&mut body, metrics);
    append_query_latency_metrics(&mut body, metrics);
    append_query_pipeline_latency_metrics(&mut body, metrics);
    append_response_cache_candidate_metrics(&mut body, metrics);
    append_dns_cookie_metrics(&mut body, snapshot);
    append_dns_cookie_prefix_metrics(&mut body, metrics);
    append_configuration_warning_metrics(&mut body, snapshot);
    append_dnssec_metrics(&mut body, snapshot);
    append_chaos_metrics(&mut body, snapshot);
    append_notify_metrics(&mut body, snapshot);
    append_tsig_metrics(&mut body, snapshot);
    append_catalog_member_metrics(&mut body, catalog_manager);
    append_zone_status_metrics(&mut body, zones, uptime_seconds);
    if zone_shape_metrics_enabled {
        append_zone_shape_metrics(&mut body, zones);
    }
    append_zone_scheduler_metrics(&mut body, zones, refresh_registry);
    append_zone_query_metrics(&mut body, zones, metrics);
    body
}

fn append_build_info_metric(body: &mut String) {
    let version = prometheus_label_value(BUILD_VERSION);
    let commit = prometheus_label_value(BUILD_COMMIT);
    let rust_version = prometheus_label_value(BUILD_RUST_VERSION);
    let build_timestamp = prometheus_label_value(BUILD_TIMESTAMP);
    body.push_str(
        "# HELP oxidedns_secondary_build_info Build metadata embedded in the OxideDNS binary.\n\
         # TYPE oxidedns_secondary_build_info gauge\n",
    );
    body.push_str(&format!(
        "oxidedns_secondary_build_info{{version=\"{version}\",commit=\"{commit}\",rust_version=\"{rust_version}\",build_timestamp=\"{build_timestamp}\"}} 1\n"
    ));
}

fn append_query_rcode_metrics(body: &mut String, metrics: &RuntimeMetrics) {
    let rcode_counts = metrics.query_rcode_counts();
    body.push_str(
        "# HELP oxidedns_query_responses_total Query responses by DNS RCODE.\n\
         # TYPE oxidedns_query_responses_total counter\n\
         # HELP oxidedns_secondary_query_responses_total Query responses by DNS RCODE.\n\
         # TYPE oxidedns_secondary_query_responses_total counter\n",
    );
    for rcode in known_rcodes() {
        let count = rcode_counts.get(rcode).copied().unwrap_or_default();
        let label = rcode_label(*rcode);
        body.push_str(&format!(
            "oxidedns_query_responses_total{{rcode=\"{label}\"}} {count}\n"
        ));
        body.push_str(&format!(
            "oxidedns_secondary_query_responses_total{{rcode=\"{label}\"}} {count}\n"
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
        body.push_str(&format!(
            "oxidedns_secondary_query_responses_total{{rcode=\"{rcode}\"}} {count}\n"
        ));
    }
}

fn append_query_latency_metrics(body: &mut String, metrics: &RuntimeMetrics) {
    let histograms = metrics.query_latency_histograms();
    let latency_buckets = metrics.latency_buckets();
    body.push_str(
        "# HELP oxidedns_secondary_query_duration_seconds Query response latency in seconds.\n\
         # TYPE oxidedns_secondary_query_duration_seconds histogram\n",
    );
    for category in QueryLatencyCategory::ALL {
        let histogram = histograms
            .get(&category)
            .cloned()
            .unwrap_or_else(|| QueryLatencyHistogram::new(latency_buckets.len()));
        let label = category.label();
        let mut cumulative = 0u64;
        for (index, bucket) in latency_buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(histogram.buckets[index]);
            body.push_str(&format!(
                "oxidedns_secondary_query_duration_seconds_bucket{{query_category=\"{label}\",le=\"{}\"}} {cumulative}\n",
                latency_bucket_label(*bucket)
            ));
        }
        cumulative = cumulative.saturating_add(histogram.buckets[latency_buckets.len()]);
        body.push_str(&format!(
            "oxidedns_secondary_query_duration_seconds_bucket{{query_category=\"{label}\",le=\"+Inf\"}} {cumulative}\n"
        ));
        body.push_str(&format!(
            "oxidedns_secondary_query_duration_seconds_sum{{query_category=\"{label}\"}} {:.9}\n",
            histogram.sum_seconds
        ));
        body.push_str(&format!(
            "oxidedns_secondary_query_duration_seconds_count{{query_category=\"{label}\"}} {}\n",
            histogram.count()
        ));
    }
}

fn append_query_pipeline_latency_metrics(body: &mut String, metrics: &RuntimeMetrics) {
    if !metrics.pipeline_timing_enabled() {
        return;
    }
    let histograms = metrics.query_pipeline_latency_histograms();
    let latency_buckets = metrics.latency_buckets();
    body.push_str(
        "# HELP oxidedns_query_pipeline_duration_seconds Query pipeline stage latency in seconds.\n\
         # TYPE oxidedns_query_pipeline_duration_seconds histogram\n",
    );
    for stage in QueryPipelineStage::ALL {
        for category in QueryLatencyCategory::ALL {
            let histogram = histograms
                .get(&QueryPipelineKey { stage, category })
                .cloned()
                .unwrap_or_else(|| QueryLatencyHistogram::new(latency_buckets.len()));
            let stage_label = stage.label();
            let category_label = category.label();
            let mut cumulative = 0u64;
            for (index, bucket) in latency_buckets.iter().enumerate() {
                cumulative = cumulative.saturating_add(histogram.buckets[index]);
                body.push_str(&format!(
                    "oxidedns_query_pipeline_duration_seconds_bucket{{stage=\"{stage_label}\",query_category=\"{category_label}\",le=\"{}\"}} {cumulative}\n",
                    latency_bucket_label(*bucket)
                ));
            }
            cumulative = cumulative.saturating_add(histogram.buckets[latency_buckets.len()]);
            body.push_str(&format!(
                "oxidedns_query_pipeline_duration_seconds_bucket{{stage=\"{stage_label}\",query_category=\"{category_label}\",le=\"+Inf\"}} {cumulative}\n"
            ));
            body.push_str(&format!(
                "oxidedns_query_pipeline_duration_seconds_sum{{stage=\"{stage_label}\",query_category=\"{category_label}\"}} {:.9}\n",
                histogram.sum_seconds
            ));
            body.push_str(&format!(
                "oxidedns_query_pipeline_duration_seconds_count{{stage=\"{stage_label}\",query_category=\"{category_label}\"}} {}\n",
                histogram.count()
            ));
        }
    }
}

fn append_response_cache_candidate_metrics(body: &mut String, metrics: &RuntimeMetrics) {
    if !metrics.pipeline_timing_enabled() {
        return;
    }
    let candidates = metrics.response_cache_candidate_counts();
    let ineligible = metrics.response_cache_ineligible_counts();
    body.push_str(
        "# HELP oxidedns_response_cache_candidate_total Query responses that look reusable by response-cache category.\n\
         # TYPE oxidedns_response_cache_candidate_total counter\n",
    );
    for category in ResponseCacheCandidateCategory::ALL {
        let label = category.label();
        let count = candidates.get(&category).copied().unwrap_or_default();
        body.push_str(&format!(
            "oxidedns_response_cache_candidate_total{{category=\"{label}\"}} {count}\n"
        ));
    }
    body.push_str(
        "# HELP oxidedns_response_cache_ineligible_total Query responses excluded from response-cache candidacy by reason.\n\
         # TYPE oxidedns_response_cache_ineligible_total counter\n",
    );
    for reason in ResponseCacheIneligibleReason::ALL {
        let label = reason.label();
        let count = ineligible.get(&reason).copied().unwrap_or_default();
        body.push_str(&format!(
            "oxidedns_response_cache_ineligible_total{{reason=\"{label}\"}} {count}\n"
        ));
    }
}

fn latency_bucket_label(bucket: f64) -> String {
    let formatted = format!("{bucket:.5}");
    formatted
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

fn append_configuration_warning_metrics(body: &mut String, snapshot: RuntimeMetricsSnapshot) {
    body.push_str(
        "# HELP oxidedns_secondary_configuration_warnings_total Suspicious but valid configuration warnings detected at startup.\n\
         # TYPE oxidedns_secondary_configuration_warnings_total gauge\n",
    );
    body.push_str(&format!(
        "oxidedns_secondary_configuration_warnings_total {}\n",
        snapshot.configuration_warnings
    ));
}

fn append_dnssec_metrics(body: &mut String, snapshot: RuntimeMetricsSnapshot) {
    body.push_str(
        "# HELP oxidedns_dnssec_nsec3_iterations_exceed_cap_total DNSSEC negative responses that omitted NSEC3 denial proofs because the zone iteration count exceeded dnssec.nsec3_max_iterations.\n\
         # TYPE oxidedns_dnssec_nsec3_iterations_exceed_cap_total counter\n",
    );
    body.push_str(&format!(
        "oxidedns_dnssec_nsec3_iterations_exceed_cap_total {}\n",
        snapshot.nsec3_iterations_exceed_cap
    ));
}

fn append_chaos_metrics(body: &mut String, snapshot: RuntimeMetricsSnapshot) {
    body.push_str(
        "# HELP oxidedns_chaos_queries_total CHAOS-class query outcomes.\n\
         # TYPE oxidedns_chaos_queries_total counter\n",
    );
    for (outcome, count) in [
        (ChaosQueryOutcome::Answered, snapshot.chaos_answered),
        (
            ChaosQueryOutcome::MissingValue,
            snapshot.chaos_missing_value,
        ),
        (
            ChaosQueryOutcome::UnrecognizedName,
            snapshot.chaos_unrecognized_name,
        ),
        (ChaosQueryOutcome::NonTxt, snapshot.chaos_non_txt),
    ] {
        body.push_str(&format!(
            "oxidedns_chaos_queries_total{{outcome=\"{}\"}} {count}\n",
            outcome.label()
        ));
    }
}

fn append_notify_metrics(body: &mut String, snapshot: RuntimeMetricsSnapshot) {
    body.push_str(
        "# HELP oxidedns_notify_messages_received_total NOTIFY request messages received.\n\
         # TYPE oxidedns_notify_messages_received_total counter\n",
    );
    body.push_str(&format!(
        "oxidedns_notify_messages_received_total {}\n",
        snapshot.notify_received
    ));
    body.push_str(
        "# HELP oxidedns_notify_messages_unauthorized_total NOTIFY request messages discarded due to unauthorized source IP.\n\
         # TYPE oxidedns_notify_messages_unauthorized_total counter\n",
    );
    body.push_str(&format!(
        "oxidedns_notify_messages_unauthorized_total {}\n",
        snapshot.notify_unauthorized
    ));
    body.push_str(
        "# HELP oxidedns_notify_refresh_actions_total Accepted NOTIFY messages by refresh action.\n\
         # TYPE oxidedns_notify_refresh_actions_total counter\n",
    );
    body.push_str(&format!(
        "oxidedns_notify_refresh_actions_total{{action=\"signalled\"}} {}\n",
        snapshot.notify_refresh_signalled
    ));
    body.push_str(&format!(
        "oxidedns_notify_refresh_actions_total{{action=\"deduplicated\"}} {}\n",
        snapshot.notify_refresh_deduplicated
    ));
}

fn append_tsig_metrics(body: &mut String, snapshot: RuntimeMetricsSnapshot) {
    body.push_str(
        "# HELP oxidedns_tsig_notify_verifications_total Authorized NOTIFY TSIG verification outcomes.\n\
         # TYPE oxidedns_tsig_notify_verifications_total counter\n",
    );
    for (result, count) in [
        ("ok", snapshot.notify_tsig_ok),
        ("badkey", snapshot.notify_tsig_badkey),
        ("badsig", snapshot.notify_tsig_badsig),
        ("badtime", snapshot.notify_tsig_badtime),
        ("badalg", snapshot.notify_tsig_badalg),
        ("badtrunc", snapshot.notify_tsig_badtrunc),
    ] {
        body.push_str(&format!(
            "oxidedns_tsig_notify_verifications_total{{result=\"{result}\"}} {count}\n"
        ));
    }
}

fn append_catalog_member_metrics(body: &mut String, catalog_manager: &CatalogManager) {
    body.push_str(
        "# HELP oxidedns_catalog_member_info Current RFC 9432 catalog membership known to this process.\n\
         # TYPE oxidedns_catalog_member_info gauge\n",
    );
    for member in catalog_manager.member_metrics() {
        let catalog_zone = prometheus_label_value(&member.catalog_zone.to_string());
        let zone = prometheus_label_value(&member.member_zone.to_string());
        let managed = if member.managed { "true" } else { "false" };
        body.push_str(&format!(
            "oxidedns_catalog_member_info{{catalog_zone=\"{catalog_zone}\",zone=\"{zone}\",managed=\"{managed}\"}} 1\n"
        ));
    }
}

fn append_dns_cookie_metrics(body: &mut String, snapshot: RuntimeMetricsSnapshot) {
    body.push_str(
        "# HELP oxidedns_dns_cookie_queries_total DNS Cookie request cases.\n\
         # TYPE oxidedns_dns_cookie_queries_total counter\n",
    );
    for (status, count) in [
        (
            DnsCookieRequestStatus::NoCookie,
            snapshot.dns_cookie_no_cookie,
        ),
        (
            DnsCookieRequestStatus::ClientCookieOnly,
            snapshot.dns_cookie_client_only,
        ),
        (
            DnsCookieRequestStatus::ValidServerCookie,
            snapshot.dns_cookie_valid_server,
        ),
        (
            DnsCookieRequestStatus::InvalidServerCookie,
            snapshot.dns_cookie_invalid_server,
        ),
    ] {
        body.push_str(&format!(
            "oxidedns_dns_cookie_queries_total{{case=\"{}\"}} {count}\n",
            dns_cookie_status_label(status)
        ));
    }
    body.push_str(
        "# HELP oxidedns_dns_cookie_badcookie_responses_total BADCOOKIE responses emitted for DNS Cookie enforcement.\n\
         # TYPE oxidedns_dns_cookie_badcookie_responses_total counter\n",
    );
    body.push_str(&format!(
        "oxidedns_dns_cookie_badcookie_responses_total {}\n",
        snapshot.dns_cookie_badcookie
    ));
}

fn append_dns_cookie_prefix_metrics(body: &mut String, metrics: &RuntimeMetrics) {
    body.push_str(
        "# HELP oxidedns_dns_cookie_queries_by_prefix_total DNS Cookie request cases by source prefix.\n\
         # TYPE oxidedns_dns_cookie_queries_by_prefix_total counter\n\
         # HELP oxidedns_dns_cookie_badcookie_responses_by_prefix_total BADCOOKIE responses emitted by source prefix.\n\
         # TYPE oxidedns_dns_cookie_badcookie_responses_by_prefix_total counter\n",
    );
    for (prefix, counters) in metrics.dns_cookie_prefix_counts() {
        let source_prefix = prometheus_label_value(&prefix.to_string());
        for (status, count) in [
            (DnsCookieRequestStatus::NoCookie, counters.no_cookie),
            (
                DnsCookieRequestStatus::ClientCookieOnly,
                counters.client_only,
            ),
            (
                DnsCookieRequestStatus::ValidServerCookie,
                counters.valid_server,
            ),
            (
                DnsCookieRequestStatus::InvalidServerCookie,
                counters.invalid_server,
            ),
        ] {
            body.push_str(&format!(
                "oxidedns_dns_cookie_queries_by_prefix_total{{source_prefix=\"{source_prefix}\",case=\"{}\"}} {count}\n",
                dns_cookie_status_label(status)
            ));
        }
        body.push_str(&format!(
            "oxidedns_dns_cookie_badcookie_responses_by_prefix_total{{source_prefix=\"{source_prefix}\"}} {}\n",
            counters.badcookie
        ));
    }
}

fn dns_cookie_status_label(status: DnsCookieRequestStatus) -> &'static str {
    match status {
        DnsCookieRequestStatus::NoCookie => "no_cookie",
        DnsCookieRequestStatus::ClientCookieOnly => "client_only",
        DnsCookieRequestStatus::ValidServerCookie => "valid_server",
        DnsCookieRequestStatus::InvalidServerCookie => "invalid_server",
    }
}

fn known_rcodes() -> &'static [u16] {
    &[0, 1, 2, 3, 4, 5, 9, 16, 22, 23]
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
        23 => "BADCOOKIE",
        _ => "UNKNOWN",
    }
}

fn append_zone_status_metrics(body: &mut String, zones: &ZoneStore, uptime_seconds: u64) {
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
        "# HELP oxidedns_secondary_zone_state Zone state, exposed as 1 for the current state and 0 for other states.\n\
         # TYPE oxidedns_secondary_zone_state gauge\n",
    );
    for snapshot in zones.snapshots() {
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        for (state, value) in zone_state_samples(snapshot.state) {
            body.push_str(&format!(
                "oxidedns_secondary_zone_state{{zone=\"{zone}\",state=\"{state}\"}} {value}\n"
            ));
        }
    }

    body.push_str(
        "# HELP oxidedns_zone_loading_seconds Seconds the zone has been in LOADING state during this process uptime.\n\
         # TYPE oxidedns_zone_loading_seconds gauge\n",
    );
    for snapshot in zones.snapshots() {
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        let loading_seconds = zone_loading_seconds(snapshot.state, uptime_seconds);
        body.push_str(&format!(
            "oxidedns_zone_loading_seconds{{zone=\"{zone}\"}} {loading_seconds}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_secondary_zone_loading_seconds Seconds the zone has been in LOADING state during this process uptime.\n\
         # TYPE oxidedns_secondary_zone_loading_seconds gauge\n",
    );
    for snapshot in zones.snapshots() {
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        let loading_seconds = zone_loading_seconds(snapshot.state, uptime_seconds);
        body.push_str(&format!(
            "oxidedns_secondary_zone_loading_seconds{{zone=\"{zone}\"}} {loading_seconds}\n"
        ));
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

    body.push_str(
        "# HELP oxidedns_secondary_zone_soa_serial Current held SOA serial for zones with transferred data.\n\
         # TYPE oxidedns_secondary_zone_soa_serial gauge\n",
    );
    for snapshot in zones.snapshots() {
        if let Some(serial) = snapshot.serial {
            let zone = prometheus_label_value(&snapshot.origin.to_string());
            body.push_str(&format!(
                "oxidedns_secondary_zone_soa_serial{{zone=\"{zone}\"}} {serial}\n"
            ));
        }
    }
}

fn zone_loading_seconds(state: ZoneState, uptime_seconds: u64) -> u64 {
    if state == ZoneState::Loading {
        uptime_seconds
    } else {
        0
    }
}

fn append_zone_shape_metrics(body: &mut String, zones: &ZoneStore) {
    body.push_str(
        "# HELP oxidedns_zone_shape_rrsets RRsets held in each active zone snapshot.\n\
         # TYPE oxidedns_zone_shape_rrsets gauge\n\
         # HELP oxidedns_zone_shape_rdata_records RDATA records held in each active zone snapshot.\n\
         # TYPE oxidedns_zone_shape_rdata_records gauge\n\
         # HELP oxidedns_zone_shape_single_rdata_rrsets RRsets with exactly one RDATA record in each active zone snapshot.\n\
         # TYPE oxidedns_zone_shape_single_rdata_rrsets gauge\n\
         # HELP oxidedns_zone_shape_multi_rdata_rrsets RRsets with more than one RDATA record in each active zone snapshot.\n\
         # TYPE oxidedns_zone_shape_multi_rdata_rrsets gauge\n\
         # HELP oxidedns_zone_shape_spilled_rdata_rrsets RRsets whose SmallVec RDATA storage spilled to the heap in each active zone snapshot.\n\
         # TYPE oxidedns_zone_shape_spilled_rdata_rrsets gauge\n\
         # HELP oxidedns_zone_shape_max_rdata_per_rrset Maximum RDATA records in one RRset for each active zone snapshot.\n\
         # TYPE oxidedns_zone_shape_max_rdata_per_rrset gauge\n\
         # HELP oxidedns_zone_shape_owner_names Owner names present in each active zone snapshot.\n\
         # TYPE oxidedns_zone_shape_owner_names gauge\n\
         # HELP oxidedns_zone_shape_empty_non_terminal_names Empty non-terminal names indexed in each active zone snapshot.\n\
         # TYPE oxidedns_zone_shape_empty_non_terminal_names gauge\n\
         # HELP oxidedns_zone_shape_rdata_payload_bytes RDATA payload bytes held in each active zone snapshot.\n\
         # TYPE oxidedns_zone_shape_rdata_payload_bytes gauge\n\
         # HELP oxidedns_zone_shape_name_key_logical_bytes Logical canonical-name key bytes referenced by zone indexes before interning.\n\
         # TYPE oxidedns_zone_shape_name_key_logical_bytes gauge\n\
         # HELP oxidedns_zone_shape_name_key_unique_bytes Unique canonical-name key bytes retained by zone indexes after interning.\n\
         # TYPE oxidedns_zone_shape_name_key_unique_bytes gauge\n\
         # HELP oxidedns_zone_shape_name_key_deduplicated_bytes Logical canonical-name key bytes avoided by zone index interning.\n\
         # TYPE oxidedns_zone_shape_name_key_deduplicated_bytes gauge\n",
    );

    for snapshot in zones.snapshots() {
        if snapshot.state != ZoneState::Active {
            continue;
        }
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        let shape = snapshot.shape_summary();
        for (metric, value) in [
            ("oxidedns_zone_shape_rrsets", shape.rrset_count),
            ("oxidedns_zone_shape_rdata_records", shape.rdata_count),
            (
                "oxidedns_zone_shape_single_rdata_rrsets",
                shape.single_rdata_rrset_count,
            ),
            (
                "oxidedns_zone_shape_multi_rdata_rrsets",
                shape.multi_rdata_rrset_count,
            ),
            (
                "oxidedns_zone_shape_spilled_rdata_rrsets",
                shape.spilled_rdata_rrset_count,
            ),
            (
                "oxidedns_zone_shape_max_rdata_per_rrset",
                shape.max_rdata_per_rrset,
            ),
            ("oxidedns_zone_shape_owner_names", shape.owner_name_count),
            (
                "oxidedns_zone_shape_empty_non_terminal_names",
                shape.empty_non_terminal_name_count,
            ),
            (
                "oxidedns_zone_shape_rdata_payload_bytes",
                shape.rdata_payload_bytes,
            ),
            (
                "oxidedns_zone_shape_name_key_logical_bytes",
                shape.name_key_logical_bytes,
            ),
            (
                "oxidedns_zone_shape_name_key_unique_bytes",
                shape.name_key_unique_bytes,
            ),
            (
                "oxidedns_zone_shape_name_key_deduplicated_bytes",
                shape.name_key_deduplicated_bytes,
            ),
        ] {
            body.push_str(&format!("{metric}{{zone=\"{zone}\"}} {value}\n"));
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
        "# HELP oxidedns_secondary_zone_last_refresh_seconds Unix timestamp of the most recent successful refresh or transfer.\n\
         # TYPE oxidedns_secondary_zone_last_refresh_seconds gauge\n",
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
            "oxidedns_secondary_zone_last_refresh_seconds{{zone=\"{zone}\"}} {last_success}\n"
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
        "# HELP oxidedns_secondary_zone_next_refresh_seconds Unix timestamp of the next scheduled refresh attempt.\n\
         # TYPE oxidedns_secondary_zone_next_refresh_seconds gauge\n",
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
            "oxidedns_secondary_zone_next_refresh_seconds{{zone=\"{zone}\"}} {next_refresh}\n"
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

    body.push_str(
        "# HELP oxidedns_secondary_zone_refresh_failures Refresh failures since the most recent successful refresh or transfer.\n\
         # TYPE oxidedns_secondary_zone_refresh_failures gauge\n",
    );
    for snapshot in zones.snapshots() {
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        let failures = statuses
            .get(&snapshot.origin.canonical_key())
            .map_or(0, |status| status.failures_since_success);
        body.push_str(&format!(
            "oxidedns_secondary_zone_refresh_failures{{zone=\"{zone}\"}} {failures}\n"
        ));
    }
}

fn append_zone_query_metrics(body: &mut String, zones: &ZoneStore, metrics: &RuntimeMetrics) {
    let query_counts = metrics.zone_query_counts();
    let rcode_counts = metrics.zone_query_rcode_counts();
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

    body.push_str(
        "# HELP oxidedns_secondary_queries_total Queries received for each configured zone.\n\
         # TYPE oxidedns_secondary_queries_total counter\n",
    );
    for snapshot in zones.snapshots() {
        let zone_key = snapshot.origin.canonical_key();
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        let count = query_counts.get(&zone_key).copied().unwrap_or_default();
        body.push_str(&format!(
            "oxidedns_secondary_queries_total{{zone=\"{zone}\"}} {count}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_zone_query_responses_total Query responses by configured zone and DNS RCODE.\n\
         # TYPE oxidedns_zone_query_responses_total counter\n",
    );
    for snapshot in zones.snapshots() {
        let zone_key = snapshot.origin.canonical_key();
        let zone = prometheus_label_value(&snapshot.origin.to_string());
        append_zone_rcode_metrics(
            body,
            "oxidedns_zone_query_responses_total",
            &zone_key,
            &zone,
            &rcode_counts,
        );
        append_zone_rcode_metrics(
            body,
            "oxidedns_secondary_query_responses_total",
            &zone_key,
            &zone,
            &rcode_counts,
        );
    }
}

fn append_zone_rcode_metrics(
    body: &mut String,
    metric: &str,
    zone_key: &str,
    zone: &str,
    rcode_counts: &HashMap<(String, u16), u64>,
) {
    for rcode in known_rcodes() {
        let count = rcode_counts
            .get(&(zone_key.to_owned(), *rcode))
            .copied()
            .unwrap_or_default();
        body.push_str(&format!(
            "{metric}{{zone=\"{zone}\",rcode=\"{}\"}} {count}\n",
            rcode_label(*rcode)
        ));
    }

    let mut other_rcodes = rcode_counts
        .keys()
        .filter_map(|(sample_zone, rcode)| {
            (sample_zone == zone_key && !known_rcodes().contains(rcode)).then_some(*rcode)
        })
        .collect::<Vec<_>>();
    other_rcodes.sort_unstable();
    for rcode in other_rcodes {
        let count = rcode_counts
            .get(&(zone_key.to_owned(), rcode))
            .copied()
            .unwrap_or_default();
        body.push_str(&format!(
            "{metric}{{zone=\"{zone}\",rcode=\"{rcode}\"}} {count}\n"
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

fn readiness_response(state: &HealthEndpointState) -> Response {
    let counts = ZoneCounts::from_store(&state.zones);
    match state.runtime_status.status() {
        RuntimeStatusValue::Running if counts.active > 0 => json_response(
            StatusCode::OK,
            format!(
                "{{\"status\":\"ready\",\"version\":\"{}\",\"zones_active\":{},\"zones_loading\":{},\"zones_expired\":{}}}",
                env!("CARGO_PKG_VERSION"),
                counts.active,
                counts.loading,
                counts.expired
            ),
        ),
        RuntimeStatusValue::Running => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "{{\"status\":\"not-ready\",\"reason\":\"{}\",\"version\":\"{}\",\"zones_active\":{},\"zones_loading\":{},\"zones_expired\":{}}}",
                counts.not_ready_reason(),
                env!("CARGO_PKG_VERSION"),
                counts.active,
                counts.loading,
                counts.expired
            ),
        ),
        RuntimeStatusValue::Draining => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "{{\"status\":\"draining\",\"version\":\"{}\",\"grace_period_remaining_seconds\":{}}}",
                env!("CARGO_PKG_VERSION"),
                state.graceful_shutdown_remaining_secs()
            ),
        ),
        RuntimeStatusValue::Unhealthy => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "{{\"status\":\"unhealthy\",\"version\":\"{}\"}}",
                env!("CARGO_PKG_VERSION")
            ),
        ),
    }
}

fn json_response(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ZoneCounts {
    active: usize,
    loading: usize,
    expired: usize,
}

impl ZoneCounts {
    fn from_store(zones: &ZoneStore) -> Self {
        let mut counts = Self::default();
        for snapshot in zones.snapshots() {
            match snapshot.state {
                ZoneState::Loading => counts.loading += 1,
                ZoneState::Active => counts.active += 1,
                ZoneState::Expired => counts.expired += 1,
            }
        }
        counts
    }

    fn not_ready_reason(&self) -> &'static str {
        if self.loading > 0 {
            "loading"
        } else if self.expired > 0 {
            "expired"
        } else {
            "no_active_zones"
        }
    }
}

#[derive(Clone)]
struct HealthEndpointState {
    zones: ZoneStore,
    runtime_status: RuntimeStatus,
    metrics: RuntimeMetrics,
    catalog_manager: CatalogManager,
    refresh_registry: ZoneRefreshRegistry,
    metrics_rate_limiter: MetricsRateLimiter,
    started_at: Instant,
    graceful_shutdown_secs: u64,
    zone_shape_metrics_enabled: bool,
}

impl HealthEndpointState {
    fn graceful_shutdown_remaining_secs(&self) -> u64 {
        let Some(elapsed) = self.runtime_status.draining_elapsed() else {
            return self.graceful_shutdown_secs;
        };
        self.graceful_shutdown_secs
            .saturating_sub(elapsed.as_secs())
    }
}

const MAX_METRICS_RATE_LIMIT_SOURCES: usize = 4096;

#[derive(Clone, Debug)]
struct MetricsRateLimiter {
    limit_per_minute: u32,
    idle_timeout: Duration,
    inner: Arc<Mutex<MetricsRateLimitState>>,
}

impl Default for MetricsRateLimiter {
    fn default() -> Self {
        Self::from_config(HealthConfig::default())
    }
}

impl MetricsRateLimiter {
    fn from_config(config: HealthConfig) -> Self {
        Self {
            limit_per_minute: config.metrics_rate_limit_per_minute,
            idle_timeout: Duration::from_secs(config.metrics_rate_limit_idle_seconds),
            inner: Arc::new(Mutex::new(MetricsRateLimitState::default())),
        }
    }

    fn check(&self, source: IpAddr) -> Result<(), u64> {
        self.check_at(source, Instant::now())
    }

    fn check_at(&self, source: IpAddr, now: Instant) -> Result<(), u64> {
        let mut state = self.inner.lock().expect("metrics limiter mutex poisoned");
        if let Some(idle_cutoff) = now.checked_sub(self.idle_timeout) {
            state.evict_idle(idle_cutoff);
        }
        if !state.entries.contains_key(&source) {
            state.evict_lru_until_below(MAX_METRICS_RATE_LIMIT_SOURCES);
        }

        let result = {
            let entry = state
                .entries
                .entry(source)
                .or_insert(MetricsRateLimitEntry {
                    tokens: self.limit_per_minute as f64,
                    last_refill: now,
                    last_seen: now,
                });
            let elapsed = now.saturating_duration_since(entry.last_refill);
            let refill = elapsed.as_secs_f64() * f64::from(self.limit_per_minute) / 60.0;
            entry.tokens = (entry.tokens + refill).min(f64::from(self.limit_per_minute));
            entry.last_refill = now;
            entry.last_seen = now;

            if entry.tokens >= 1.0 {
                entry.tokens -= 1.0;
                Ok(())
            } else {
                let seconds_until_token =
                    ((1.0 - entry.tokens) * 60.0 / f64::from(self.limit_per_minute)).ceil();
                Err((seconds_until_token as u64).max(1))
            }
        };
        state.lru.push_back((source, now));
        result
    }
}

#[derive(Debug, Default)]
struct MetricsRateLimitState {
    entries: HashMap<IpAddr, MetricsRateLimitEntry>,
    lru: VecDeque<(IpAddr, Instant)>,
}

impl MetricsRateLimitState {
    fn evict_idle(&mut self, cutoff: Instant) {
        while let Some((source, seen_at)) = self.lru.front().copied() {
            match self.entries.get(&source) {
                Some(entry) if entry.last_seen != seen_at => {
                    self.lru.pop_front();
                }
                Some(entry) if entry.last_seen <= cutoff => {
                    self.lru.pop_front();
                    self.entries.remove(&source);
                }
                Some(_) => break,
                None => {
                    self.lru.pop_front();
                }
            }
        }
    }

    fn evict_lru_until_below(&mut self, cap: usize) {
        while self.entries.len() >= cap {
            let Some((source, seen_at)) = self.lru.pop_front() else {
                self.entries.clear();
                break;
            };
            if self
                .entries
                .get(&source)
                .is_some_and(|entry| entry.last_seen == seen_at)
            {
                self.entries.remove(&source);
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct MetricsRateLimitEntry {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

#[derive(Clone, Debug)]
struct RuntimeStatus {
    value: Arc<AtomicU8>,
    draining_since: Arc<Mutex<Option<Instant>>>,
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
            draining_since: Arc::new(Mutex::new(None)),
        }
    }

    fn mark_draining(&self) {
        *self
            .draining_since
            .lock()
            .expect("runtime status lock poisoned") = Some(Instant::now());
        self.value.store(RUNTIME_STATUS_DRAINING, Ordering::Release);
    }

    #[cfg(test)]
    fn mark_unhealthy(&self) {
        self.value
            .store(RUNTIME_STATUS_UNHEALTHY, Ordering::Release);
    }

    fn status(&self) -> RuntimeStatusValue {
        match self.value.load(Ordering::Acquire) {
            RUNTIME_STATUS_RUNNING => RuntimeStatusValue::Running,
            RUNTIME_STATUS_DRAINING => RuntimeStatusValue::Draining,
            RUNTIME_STATUS_UNHEALTHY => RuntimeStatusValue::Unhealthy,
            _ => RuntimeStatusValue::Unhealthy,
        }
    }

    fn draining_elapsed(&self) -> Option<Duration> {
        self.draining_since
            .lock()
            .expect("runtime status lock poisoned")
            .as_ref()
            .map(Instant::elapsed)
    }
}

#[derive(Clone, Debug)]
struct RuntimeMetrics {
    inner: Arc<RuntimeMetricsInner>,
}

const DEFAULT_COOKIE_PREFIX_METRIC_LIMIT: usize = 100_000;
#[cfg(test)]
const DEFAULT_LATENCY_HISTOGRAM_BUCKETS: [f64; 9] = [
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.1,
];

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
    notify_received: AtomicU64,
    notify_unauthorized: AtomicU64,
    notify_refresh_signalled: AtomicU64,
    notify_refresh_deduplicated: AtomicU64,
    notify_tsig_ok: AtomicU64,
    notify_tsig_badkey: AtomicU64,
    notify_tsig_badsig: AtomicU64,
    notify_tsig_badtime: AtomicU64,
    notify_tsig_badalg: AtomicU64,
    notify_tsig_badtrunc: AtomicU64,
    rrl_subject: AtomicU64,
    rrl_dropped: AtomicU64,
    rrl_truncated: AtomicU64,
    rrl_tracked_keys: AtomicU64,
    rrl_key_evictions: AtomicU64,
    dns_cookie_no_cookie: AtomicU64,
    dns_cookie_client_only: AtomicU64,
    dns_cookie_valid_server: AtomicU64,
    dns_cookie_invalid_server: AtomicU64,
    dns_cookie_badcookie: AtomicU64,
    configuration_warnings: AtomicU64,
    nsec3_iterations_exceed_cap: AtomicU64,
    chaos_answered: AtomicU64,
    chaos_missing_value: AtomicU64,
    chaos_unrecognized_name: AtomicU64,
    chaos_non_txt: AtomicU64,
    dns_cookie_prefixes: Mutex<CookiePrefixMetrics>,
    query_rcodes: Mutex<HashMap<u16, u64>>,
    zone_queries: Mutex<HashMap<String, u64>>,
    zone_query_rcodes: Mutex<HashMap<(String, u16), u64>>,
    latency_buckets: Vec<f64>,
    query_latency: Mutex<HashMap<QueryLatencyCategory, QueryLatencyHistogram>>,
    pipeline_timing_enabled: bool,
    query_pipeline_latency: Mutex<HashMap<QueryPipelineKey, QueryLatencyHistogram>>,
    response_cache_candidates: Mutex<HashMap<ResponseCacheCandidateCategory, u64>>,
    response_cache_ineligible: Mutex<HashMap<ResponseCacheIneligibleReason, u64>>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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
    notify_received: u64,
    notify_unauthorized: u64,
    notify_refresh_signalled: u64,
    notify_refresh_deduplicated: u64,
    notify_tsig_ok: u64,
    notify_tsig_badkey: u64,
    notify_tsig_badsig: u64,
    notify_tsig_badtime: u64,
    notify_tsig_badalg: u64,
    notify_tsig_badtrunc: u64,
    rrl_subject: u64,
    rrl_dropped: u64,
    rrl_truncated: u64,
    rrl_tracked_keys: u64,
    rrl_key_evictions: u64,
    dns_cookie_no_cookie: u64,
    dns_cookie_client_only: u64,
    dns_cookie_valid_server: u64,
    dns_cookie_invalid_server: u64,
    dns_cookie_badcookie: u64,
    configuration_warnings: u64,
    nsec3_iterations_exceed_cap: u64,
    chaos_answered: u64,
    chaos_missing_value: u64,
    chaos_unrecognized_name: u64,
    chaos_non_txt: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CookiePrefixCounters {
    no_cookie: u64,
    client_only: u64,
    valid_server: u64,
    invalid_server: u64,
    badcookie: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum QueryLatencyCategory {
    UdpDirect,
    UdpCnameChain,
    TcpDirect,
    TcpCnameChain,
    DnssecAugmented,
    CookieValidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct QueryPipelineKey {
    stage: QueryPipelineStage,
    category: QueryLatencyCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum QueryPipelineStage {
    Parse,
    Lookup,
    Compose,
    Send,
}

impl QueryPipelineStage {
    const ALL: [Self; 4] = [Self::Parse, Self::Lookup, Self::Compose, Self::Send];

    fn label(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Lookup => "lookup",
            Self::Compose => "compose",
            Self::Send => "send",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum ResponseCacheCandidateCategory {
    Direct,
    Negative,
    Cname,
    Dnssec,
}

impl ResponseCacheCandidateCategory {
    const ALL: [Self; 4] = [Self::Direct, Self::Negative, Self::Cname, Self::Dnssec];

    fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Negative => "negative",
            Self::Cname => "cname",
            Self::Dnssec => "dnssec",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum ResponseCacheIneligibleReason {
    Cookie,
    Tsig,
    Rrl,
    Truncated,
    EdnsPadding,
    Other,
}

impl ResponseCacheIneligibleReason {
    const ALL: [Self; 6] = [
        Self::Cookie,
        Self::Tsig,
        Self::Rrl,
        Self::Truncated,
        Self::EdnsPadding,
        Self::Other,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Cookie => "cookie",
            Self::Tsig => "tsig",
            Self::Rrl => "rrl",
            Self::Truncated => "truncated",
            Self::EdnsPadding => "edns_padding",
            Self::Other => "other",
        }
    }
}

impl QueryLatencyCategory {
    const ALL: [Self; 6] = [
        Self::UdpDirect,
        Self::UdpCnameChain,
        Self::TcpDirect,
        Self::TcpCnameChain,
        Self::DnssecAugmented,
        Self::CookieValidated,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::UdpDirect => "udp_direct",
            Self::UdpCnameChain => "udp_cname_chain",
            Self::TcpDirect => "tcp_direct",
            Self::TcpCnameChain => "tcp_cname_chain",
            Self::DnssecAugmented => "dnssec_augmented",
            Self::CookieValidated => "cookie_validated",
        }
    }
}

#[derive(Debug, Clone)]
struct QueryLatencyHistogram {
    buckets: Vec<u64>,
    sum_seconds: f64,
}

impl QueryLatencyHistogram {
    fn new(bucket_count: usize) -> Self {
        Self {
            buckets: vec![0; bucket_count + 1],
            sum_seconds: 0.0,
        }
    }

    fn record(&mut self, duration: Duration, latency_buckets: &[f64]) {
        let seconds = duration.as_secs_f64();
        let bucket_index = latency_buckets
            .iter()
            .position(|bucket| seconds <= *bucket)
            .unwrap_or(latency_buckets.len());
        self.buckets[bucket_index] = self.buckets[bucket_index].saturating_add(1);
        self.sum_seconds += seconds;
    }

    fn count(&self) -> u64 {
        self.buckets.iter().copied().sum()
    }
}

#[derive(Debug)]
struct CookiePrefixMetrics {
    max_prefixes: usize,
    counts: HashMap<IpPrefix, CookiePrefixCounters>,
    lru: VecDeque<IpPrefix>,
}

impl Default for CookiePrefixMetrics {
    fn default() -> Self {
        Self::new(DEFAULT_COOKIE_PREFIX_METRIC_LIMIT)
    }
}

impl CookiePrefixMetrics {
    fn new(max_prefixes: usize) -> Self {
        Self {
            max_prefixes: max_prefixes.max(1),
            counts: HashMap::new(),
            lru: VecDeque::new(),
        }
    }

    fn record_status(&mut self, prefix: IpPrefix, status: DnsCookieRequestStatus) {
        self.ensure_prefix(prefix);
        let Some(counters) = self.counts.get_mut(&prefix) else {
            return;
        };
        match status {
            DnsCookieRequestStatus::NoCookie => {
                counters.no_cookie = counters.no_cookie.saturating_add(1)
            }
            DnsCookieRequestStatus::ClientCookieOnly => {
                counters.client_only = counters.client_only.saturating_add(1);
            }
            DnsCookieRequestStatus::ValidServerCookie => {
                counters.valid_server = counters.valid_server.saturating_add(1);
            }
            DnsCookieRequestStatus::InvalidServerCookie => {
                counters.invalid_server = counters.invalid_server.saturating_add(1);
            }
        }
    }

    fn record_badcookie(&mut self, prefix: IpPrefix) {
        self.ensure_prefix(prefix);
        if let Some(counters) = self.counts.get_mut(&prefix) {
            counters.badcookie = counters.badcookie.saturating_add(1);
        }
    }

    fn samples(&self) -> Vec<(IpPrefix, CookiePrefixCounters)> {
        let mut samples = self
            .counts
            .iter()
            .map(|(prefix, counters)| (*prefix, *counters))
            .collect::<Vec<_>>();
        samples.sort_unstable_by_key(|(prefix, _)| prefix.to_string());
        samples
    }

    fn ensure_prefix(&mut self, prefix: IpPrefix) {
        if self.counts.contains_key(&prefix) {
            self.touch_lru(prefix);
            return;
        }
        self.evict_one_if_needed();
        self.counts.insert(prefix, CookiePrefixCounters::default());
        self.touch_lru(prefix);
    }

    fn evict_one_if_needed(&mut self) {
        if self.counts.len() < self.max_prefixes {
            return;
        }
        while let Some(prefix) = self.lru.pop_front() {
            if self.counts.remove(&prefix).is_some() {
                return;
            }
        }
    }

    fn touch_lru(&mut self, prefix: IpPrefix) {
        self.lru.retain(|candidate| *candidate != prefix);
        self.lru.push_back(prefix);
    }
}

impl RuntimeMetrics {
    #[cfg(test)]
    fn new() -> Self {
        Self::new_with_settings(
            DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
            DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
            false,
        )
    }

    fn new_with_settings(
        cookie_prefix_limit: usize,
        latency_buckets: Vec<f64>,
        pipeline_timing_enabled: bool,
    ) -> Self {
        Self {
            inner: Arc::new(RuntimeMetricsInner {
                dns_cookie_prefixes: Mutex::new(CookiePrefixMetrics::new(cookie_prefix_limit)),
                latency_buckets,
                pipeline_timing_enabled,
                ..RuntimeMetricsInner::default()
            }),
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

    fn record_notify_received(&self) {
        self.inner.notify_received.fetch_add(1, Ordering::Relaxed);
    }

    fn record_notify_unauthorized(&self) {
        self.inner
            .notify_unauthorized
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_notify_refresh_action(&self, action: NotifyRefreshAction) {
        match action {
            NotifyRefreshAction::Signalled => self
                .inner
                .notify_refresh_signalled
                .fetch_add(1, Ordering::Relaxed),
            NotifyRefreshAction::Deduplicated => self
                .inner
                .notify_refresh_deduplicated
                .fetch_add(1, Ordering::Relaxed),
        };
    }

    fn record_notify_tsig_result(&self, result: NotifyTsigResult) {
        match result {
            NotifyTsigResult::Ok => self.inner.notify_tsig_ok.fetch_add(1, Ordering::Relaxed),
            NotifyTsigResult::BadKey => self
                .inner
                .notify_tsig_badkey
                .fetch_add(1, Ordering::Relaxed),
            NotifyTsigResult::BadSig => self
                .inner
                .notify_tsig_badsig
                .fetch_add(1, Ordering::Relaxed),
            NotifyTsigResult::BadTime => self
                .inner
                .notify_tsig_badtime
                .fetch_add(1, Ordering::Relaxed),
            NotifyTsigResult::BadAlg => self
                .inner
                .notify_tsig_badalg
                .fetch_add(1, Ordering::Relaxed),
            NotifyTsigResult::BadTrunc => self
                .inner
                .notify_tsig_badtrunc
                .fetch_add(1, Ordering::Relaxed),
        };
    }

    fn record_rrl_subject(&self) {
        self.inner.rrl_subject.fetch_add(1, Ordering::Relaxed);
    }

    fn record_rrl_dropped(&self) {
        self.inner.rrl_dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn record_rrl_truncated(&self) {
        self.inner.rrl_truncated.fetch_add(1, Ordering::Relaxed);
    }

    fn set_rrl_tracked_keys(&self, count: u64) {
        self.inner.rrl_tracked_keys.store(count, Ordering::Relaxed);
    }

    fn record_rrl_key_evicted(&self) {
        self.inner.rrl_key_evictions.fetch_add(1, Ordering::Relaxed);
    }

    fn record_dns_cookie_status(
        &self,
        status: DnsCookieRequestStatus,
        source: IpAddr,
        prefix_settings: CookiePrefixMetricSettings,
    ) {
        let counter = match status {
            DnsCookieRequestStatus::NoCookie => &self.inner.dns_cookie_no_cookie,
            DnsCookieRequestStatus::ClientCookieOnly => &self.inner.dns_cookie_client_only,
            DnsCookieRequestStatus::ValidServerCookie => &self.inner.dns_cookie_valid_server,
            DnsCookieRequestStatus::InvalidServerCookie => &self.inner.dns_cookie_invalid_server,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.inner
            .dns_cookie_prefixes
            .lock()
            .expect("runtime metrics DNS Cookie prefix counter lock poisoned")
            .record_status(cookie_metric_prefix(source, prefix_settings), status);
    }

    fn record_dns_cookie_badcookie(&self) {
        self.inner
            .dns_cookie_badcookie
            .fetch_add(1, Ordering::Relaxed);
    }

    fn set_configuration_warnings(&self, count: u64) {
        self.inner
            .configuration_warnings
            .store(count, Ordering::Relaxed);
    }

    fn record_nsec3_iterations_exceed_cap(&self) {
        self.inner
            .nsec3_iterations_exceed_cap
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_chaos_query(&self, outcome: ChaosQueryOutcome) {
        let counter = match outcome {
            ChaosQueryOutcome::Answered => &self.inner.chaos_answered,
            ChaosQueryOutcome::MissingValue => &self.inner.chaos_missing_value,
            ChaosQueryOutcome::UnrecognizedName => &self.inner.chaos_unrecognized_name,
            ChaosQueryOutcome::NonTxt => &self.inner.chaos_non_txt,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn record_dns_cookie_badcookie_for_source(
        &self,
        source: IpAddr,
        prefix_settings: CookiePrefixMetricSettings,
    ) {
        self.inner
            .dns_cookie_prefixes
            .lock()
            .expect("runtime metrics DNS Cookie prefix counter lock poisoned")
            .record_badcookie(cookie_metric_prefix(source, prefix_settings));
    }

    fn dns_cookie_prefix_counts(&self) -> Vec<(IpPrefix, CookiePrefixCounters)> {
        self.inner
            .dns_cookie_prefixes
            .lock()
            .expect("runtime metrics DNS Cookie prefix counter lock poisoned")
            .samples()
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

    fn record_zone_query_response_rcode(&self, zone_key: &str, rcode: u16) {
        let mut rcodes = self
            .inner
            .zone_query_rcodes
            .lock()
            .expect("runtime metrics per-zone RCODE counter lock poisoned");
        let counter = rcodes.entry((zone_key.to_owned(), rcode)).or_default();
        *counter = counter.saturating_add(1);
    }

    fn record_query_latency(&self, category: QueryLatencyCategory, duration: Duration) {
        let latency_buckets = self.inner.latency_buckets.as_slice();
        let mut histograms = self
            .inner
            .query_latency
            .lock()
            .expect("runtime metrics query latency histogram lock poisoned");
        histograms
            .entry(category)
            .or_insert_with(|| QueryLatencyHistogram::new(latency_buckets.len()))
            .record(duration, latency_buckets);
    }

    fn pipeline_timing_enabled(&self) -> bool {
        self.inner.pipeline_timing_enabled
    }

    fn start_pipeline_timer(&self) -> Option<Instant> {
        self.pipeline_timing_enabled().then(Instant::now)
    }

    fn record_query_pipeline_latency(
        &self,
        stage: QueryPipelineStage,
        category: QueryLatencyCategory,
        duration: Duration,
    ) {
        if !self.pipeline_timing_enabled() {
            return;
        }
        let latency_buckets = self.inner.latency_buckets.as_slice();
        let mut histograms = self
            .inner
            .query_pipeline_latency
            .lock()
            .expect("runtime metrics query pipeline latency histogram lock poisoned");
        histograms
            .entry(QueryPipelineKey { stage, category })
            .or_insert_with(|| QueryLatencyHistogram::new(latency_buckets.len()))
            .record(duration, latency_buckets);
    }

    fn record_response_cache_candidate(&self, category: ResponseCacheCandidateCategory) {
        if !self.pipeline_timing_enabled() {
            return;
        }
        let mut candidates = self
            .inner
            .response_cache_candidates
            .lock()
            .expect("runtime metrics response-cache candidate lock poisoned");
        let counter = candidates.entry(category).or_default();
        *counter = counter.saturating_add(1);
    }

    fn record_response_cache_ineligible(&self, reason: ResponseCacheIneligibleReason) {
        if !self.pipeline_timing_enabled() {
            return;
        }
        let mut ineligible = self
            .inner
            .response_cache_ineligible
            .lock()
            .expect("runtime metrics response-cache ineligible lock poisoned");
        let counter = ineligible.entry(reason).or_default();
        *counter = counter.saturating_add(1);
    }

    fn query_rcode_counts(&self) -> HashMap<u16, u64> {
        self.inner
            .query_rcodes
            .lock()
            .expect("runtime metrics RCODE counter lock poisoned")
            .clone()
    }

    fn zone_query_rcode_counts(&self) -> HashMap<(String, u16), u64> {
        self.inner
            .zone_query_rcodes
            .lock()
            .expect("runtime metrics per-zone RCODE counter lock poisoned")
            .clone()
    }

    fn query_latency_histograms(&self) -> HashMap<QueryLatencyCategory, QueryLatencyHistogram> {
        self.inner
            .query_latency
            .lock()
            .expect("runtime metrics query latency histogram lock poisoned")
            .clone()
    }

    fn query_pipeline_latency_histograms(
        &self,
    ) -> HashMap<QueryPipelineKey, QueryLatencyHistogram> {
        self.inner
            .query_pipeline_latency
            .lock()
            .expect("runtime metrics query pipeline latency histogram lock poisoned")
            .clone()
    }

    fn response_cache_candidate_counts(&self) -> HashMap<ResponseCacheCandidateCategory, u64> {
        self.inner
            .response_cache_candidates
            .lock()
            .expect("runtime metrics response-cache candidate lock poisoned")
            .clone()
    }

    fn response_cache_ineligible_counts(&self) -> HashMap<ResponseCacheIneligibleReason, u64> {
        self.inner
            .response_cache_ineligible
            .lock()
            .expect("runtime metrics response-cache ineligible lock poisoned")
            .clone()
    }

    fn latency_buckets(&self) -> Vec<f64> {
        self.inner.latency_buckets.clone()
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
            notify_received: self.inner.notify_received.load(Ordering::Relaxed),
            notify_unauthorized: self.inner.notify_unauthorized.load(Ordering::Relaxed),
            notify_refresh_signalled: self.inner.notify_refresh_signalled.load(Ordering::Relaxed),
            notify_refresh_deduplicated: self
                .inner
                .notify_refresh_deduplicated
                .load(Ordering::Relaxed),
            notify_tsig_ok: self.inner.notify_tsig_ok.load(Ordering::Relaxed),
            notify_tsig_badkey: self.inner.notify_tsig_badkey.load(Ordering::Relaxed),
            notify_tsig_badsig: self.inner.notify_tsig_badsig.load(Ordering::Relaxed),
            notify_tsig_badtime: self.inner.notify_tsig_badtime.load(Ordering::Relaxed),
            notify_tsig_badalg: self.inner.notify_tsig_badalg.load(Ordering::Relaxed),
            notify_tsig_badtrunc: self.inner.notify_tsig_badtrunc.load(Ordering::Relaxed),
            rrl_subject: self.inner.rrl_subject.load(Ordering::Relaxed),
            rrl_dropped: self.inner.rrl_dropped.load(Ordering::Relaxed),
            rrl_truncated: self.inner.rrl_truncated.load(Ordering::Relaxed),
            rrl_tracked_keys: self.inner.rrl_tracked_keys.load(Ordering::Relaxed),
            rrl_key_evictions: self.inner.rrl_key_evictions.load(Ordering::Relaxed),
            dns_cookie_no_cookie: self.inner.dns_cookie_no_cookie.load(Ordering::Relaxed),
            dns_cookie_client_only: self.inner.dns_cookie_client_only.load(Ordering::Relaxed),
            dns_cookie_valid_server: self.inner.dns_cookie_valid_server.load(Ordering::Relaxed),
            dns_cookie_invalid_server: self.inner.dns_cookie_invalid_server.load(Ordering::Relaxed),
            dns_cookie_badcookie: self.inner.dns_cookie_badcookie.load(Ordering::Relaxed),
            configuration_warnings: self.inner.configuration_warnings.load(Ordering::Relaxed),
            nsec3_iterations_exceed_cap: self
                .inner
                .nsec3_iterations_exceed_cap
                .load(Ordering::Relaxed),
            chaos_answered: self.inner.chaos_answered.load(Ordering::Relaxed),
            chaos_missing_value: self.inner.chaos_missing_value.load(Ordering::Relaxed),
            chaos_unrecognized_name: self.inner.chaos_unrecognized_name.load(Ordering::Relaxed),
            chaos_non_txt: self.inner.chaos_non_txt.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyTsigResult {
    Ok,
    BadKey,
    BadSig,
    BadTime,
    BadAlg,
    BadTrunc,
}

#[derive(Clone)]
struct TcpServerSettings {
    max_udp_payload: u16,
    max_cname_chain: usize,
    nsec3_max_iterations: u16,
    idle_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    max_connections: usize,
    max_connections_per_source: Option<usize>,
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
    active_connections: Arc<AtomicUsize>,
    active_connections_by_source: TcpSourceConnectionCounts,
}

struct TcpConnectionPermit {
    active: Arc<AtomicUsize>,
    source_counts: Option<TcpSourceConnectionCounts>,
    peer_ip: IpAddr,
}

type TcpSourceConnectionCounts = Arc<Mutex<HashMap<IpAddr, usize>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpConnectionLimitExceeded {
    Global,
    Source { active: usize, limit: usize },
}

type TcpQueryHook =
    Arc<dyn Fn(u16) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + Sync + 'static>;

#[derive(Debug, Clone)]
struct ZoneTransferPlan {
    origin: DomainName,
    qclass: u16,
    primaries: Vec<TransferPrimaryConfig>,
    tsig_key: Option<Arc<TsigKey>>,
    tsig_fudge_seconds: u16,
    max_transfer_ingest_bytes: u64,
    parse_options: axfr::TransferParseOptions,
    transfer_sources: Vec<SocketAddr>,
}

impl ZoneTransferPlan {
    fn transfer_source_for(&self, primary: SocketAddr) -> Option<SocketAddr> {
        self.transfer_sources
            .iter()
            .copied()
            .find(|source| source.is_ipv4() == primary.is_ipv4())
    }

    fn for_member_origin(&self, origin: DomainName) -> Self {
        Self {
            origin,
            qclass: self.qclass,
            primaries: self.primaries.clone(),
            tsig_key: self.tsig_key.clone(),
            tsig_fudge_seconds: self.tsig_fudge_seconds,
            max_transfer_ingest_bytes: self.max_transfer_ingest_bytes,
            parse_options: self.parse_options,
            transfer_sources: self.transfer_sources.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct TransferPlan {
    zones_by_key: Arc<Mutex<HashMap<String, ZoneTransferPlan>>>,
}

impl TransferPlan {
    fn from_config(config: &ServerConfig) -> Result<Self, RuntimeError> {
        Self::from_config_with_primary_start(config, random_primary_start_index)
    }

    fn from_config_with_primary_start(
        config: &ServerConfig,
        primary_start_index: impl Fn(usize) -> Result<usize, getrandom::Error>,
    ) -> Result<Self, RuntimeError> {
        let tsig_keys = config
            .tsig_keys
            .iter()
            .map(|key| {
                let secret = key
                    .secret_base64()
                    .expect("configuration validation rejects invalid TSIG key secret sources");
                let key = TsigKey::from_base64(&key.name, &key.algorithm, &secret)
                    .expect("configuration validation rejects invalid TSIG keys");
                (key.name.canonical_key(), Arc::new(key))
            })
            .collect::<HashMap<_, _>>();
        let mut zones_by_key = HashMap::new();
        for zone in &config.zones {
            let plan = transfer_plan_from_zone_config(
                zone,
                &tsig_keys,
                config.tsig.fudge_seconds,
                config.limits.max_transfer_ingest_bytes,
                axfr::TransferParseOptions {
                    accept_out_of_zone_glue: config.transfer.accept_out_of_zone_glue,
                },
                &config.interfaces.transfer,
                &primary_start_index,
            )?;
            zones_by_key.insert(plan.origin.canonical_key(), plan);
        }
        for catalog_zone in &config.catalog_zones {
            let plan = transfer_plan_from_catalog_zone_config(
                catalog_zone,
                &tsig_keys,
                config.tsig.fudge_seconds,
                config.limits.max_transfer_ingest_bytes,
                axfr::TransferParseOptions {
                    accept_out_of_zone_glue: config.transfer.accept_out_of_zone_glue,
                },
                &config.interfaces.transfer,
                &primary_start_index,
            )?;
            zones_by_key.insert(plan.origin.canonical_key(), plan);
        }

        Ok(Self {
            zones_by_key: Arc::new(Mutex::new(zones_by_key)),
        })
    }

    fn get(&self, origin: &DomainName) -> Option<ZoneTransferPlan> {
        self.zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .get(&origin.canonical_key())
            .cloned()
    }

    fn insert(&self, plan: ZoneTransferPlan) {
        self.zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .insert(plan.origin.canonical_key(), plan);
    }

    fn remove(&self, origin: &DomainName) {
        self.zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .remove(&origin.canonical_key());
    }

    fn initial_origins(&self) -> Vec<DomainName> {
        let mut origins = self
            .zones_by_key
            .lock()
            .expect("transfer plan lock poisoned")
            .values()
            .map(|plan| plan.origin.clone())
            .collect::<Vec<_>>();
        origins.sort_by_key(|origin| origin.canonical_key());
        origins
    }
}

fn transfer_plan_from_zone_config(
    zone: &ZoneConfig,
    tsig_keys: &HashMap<String, Arc<TsigKey>>,
    tsig_fudge_seconds: u16,
    max_transfer_ingest_bytes: u64,
    parse_options: axfr::TransferParseOptions,
    transfer_sources: &[SocketAddr],
    primary_start_index: &impl Fn(usize) -> Result<usize, getrandom::Error>,
) -> Result<ZoneTransferPlan, RuntimeError> {
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
    let primaries = zone.transfer_targets();
    let primary_start =
        primary_start_index(primaries.len()).map_err(RuntimeError::PrimaryRotationRandom)?;
    let primaries = rotate_transfer_targets(primaries, primary_start);
    Ok(ZoneTransferPlan {
        origin,
        qclass: 1,
        primaries,
        tsig_key,
        tsig_fudge_seconds,
        max_transfer_ingest_bytes,
        parse_options,
        transfer_sources: transfer_sources.to_vec(),
    })
}

fn transfer_plan_from_catalog_zone_config(
    zone: &CatalogZoneConfig,
    tsig_keys: &HashMap<String, Arc<TsigKey>>,
    tsig_fudge_seconds: u16,
    max_transfer_ingest_bytes: u64,
    parse_options: axfr::TransferParseOptions,
    transfer_sources: &[SocketAddr],
    primary_start_index: &impl Fn(usize) -> Result<usize, getrandom::Error>,
) -> Result<ZoneTransferPlan, RuntimeError> {
    let zone = ZoneConfig {
        name: zone.name.clone(),
        class: zone.class.clone(),
        primaries: zone.primaries.clone(),
        transfer_primaries: zone.transfer_primaries.clone(),
        notify_sources: zone.notify_sources.clone(),
        tsig_key: zone.tsig_key.clone(),
    };
    transfer_plan_from_zone_config(
        &zone,
        tsig_keys,
        tsig_fudge_seconds,
        max_transfer_ingest_bytes,
        parse_options,
        transfer_sources,
        primary_start_index,
    )
}

fn rotate_transfer_targets(
    primaries: Vec<TransferPrimaryConfig>,
    start_index: usize,
) -> Vec<TransferPrimaryConfig> {
    if primaries.len() <= 1 {
        return primaries;
    }

    let start_index = start_index % primaries.len();
    primaries
        .iter()
        .cycle()
        .skip(start_index)
        .take(primaries.len())
        .cloned()
        .collect()
}

fn random_primary_start_index(primary_count: usize) -> Result<usize, getrandom::Error> {
    if primary_count <= 1 {
        return Ok(0);
    }

    loop {
        let sample = random_u64()?;
        if let Some(index) = uniform_index_from_u64(sample, primary_count) {
            return Ok(index);
        }
    }
}

fn random_u64() -> Result<u64, getrandom::Error> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn uniform_index_from_u64(sample: u64, primary_count: usize) -> Option<usize> {
    if primary_count == 0 {
        return None;
    }
    if primary_count == 1 {
        return Some(0);
    }

    let primary_count = primary_count as u128;
    let sample = u128::from(sample);
    let sample_space = u128::from(u64::MAX) + 1;
    let accepted_samples = (sample_space / primary_count) * primary_count;
    if sample >= accepted_samples {
        return None;
    }

    Some((sample % primary_count) as usize)
}

#[derive(Debug)]
struct RefreshRequest {
    zone: DomainName,
    requested_serial: Option<u32>,
    reason: RefreshReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshReason {
    Catalog,
    Notify,
    Scheduled,
}

impl RefreshReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Catalog => "catalog",
            Self::Notify => "notify",
            Self::Scheduled => "scheduled",
        }
    }
}

#[derive(Debug, Clone)]
struct CatalogManager {
    catalogs_by_key: Arc<HashMap<String, CatalogRuntimeConfig>>,
    static_zone_keys: Arc<HashSet<String>>,
    memberships_by_catalog: Arc<Mutex<HashMap<String, HashSet<String>>>>,
}

impl Default for CatalogManager {
    fn default() -> Self {
        Self {
            catalogs_by_key: Arc::new(HashMap::new()),
            static_zone_keys: Arc::new(HashSet::new()),
            memberships_by_catalog: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatalogMemberMetric {
    catalog_zone: DomainName,
    member_zone: DomainName,
    managed: bool,
}

#[derive(Debug, Clone)]
struct CatalogRuntime {
    manager: CatalogManager,
    transfer_plan: TransferPlan,
    refresh_registry: ZoneRefreshRegistry,
    notify_authority: NotifyAuthority,
    refresh_tx: mpsc::WeakSender<RefreshRequest>,
}

#[derive(Debug, Clone)]
struct CatalogRuntimeConfig {
    origin: DomainName,
    config: CatalogZoneConfig,
}

impl CatalogManager {
    fn from_config(config: &ServerConfig) -> Self {
        let catalogs_by_key = config
            .catalog_zones
            .iter()
            .map(|catalog| {
                let origin = DomainName::from_absolute_str(&catalog.name)
                    .expect("configuration validation rejects invalid catalog zone names");
                (
                    origin.canonical_key(),
                    CatalogRuntimeConfig {
                        origin,
                        config: catalog.clone(),
                    },
                )
            })
            .collect();
        let static_zone_keys = config
            .zones
            .iter()
            .map(|zone| {
                DomainName::from_absolute_str(&zone.name)
                    .expect("configuration validation rejects invalid zone names")
                    .canonical_key()
            })
            .collect();

        Self {
            catalogs_by_key: Arc::new(catalogs_by_key),
            static_zone_keys: Arc::new(static_zone_keys),
            memberships_by_catalog: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn is_catalog(&self, origin: &DomainName) -> bool {
        self.catalogs_by_key.contains_key(&origin.canonical_key())
    }

    fn member_metrics(&self) -> Vec<CatalogMemberMetric> {
        let memberships = self
            .memberships_by_catalog
            .lock()
            .expect("catalog membership lock poisoned");
        let mut samples = Vec::new();
        for (catalog_key, member_keys) in memberships.iter() {
            let Some(catalog_zone) = DomainName::from_absolute_str(catalog_key).ok() else {
                continue;
            };
            for member_key in member_keys {
                let Some(member_zone) = DomainName::from_absolute_str(member_key).ok() else {
                    continue;
                };
                samples.push(CatalogMemberMetric {
                    catalog_zone: catalog_zone.clone(),
                    member_zone,
                    managed: !self.static_zone_keys.contains(member_key),
                });
            }
        }
        samples.sort_by(|left, right| {
            left.catalog_zone
                .canonical_key()
                .cmp(&right.catalog_zone.canonical_key())
                .then_with(|| {
                    left.member_zone
                        .canonical_key()
                        .cmp(&right.member_zone.canonical_key())
                })
        });
        samples
    }

    async fn apply_snapshot(
        &self,
        snapshot: &ZoneSnapshot,
        zones: &ZoneStore,
        transfer_plan: &TransferPlan,
        refresh_registry: &ZoneRefreshRegistry,
        notify_authority: &NotifyAuthority,
        refresh_tx: &mpsc::WeakSender<RefreshRequest>,
    ) {
        let Some(catalog) = self.catalogs_by_key.get(&snapshot.origin.canonical_key()) else {
            return;
        };

        if catalog.config.serve_catalog_zone {
            zones.show_zone(&catalog.origin);
        } else {
            zones.hide_zone(&catalog.origin);
        }

        let mut members = match parse_catalog_members(snapshot) {
            Ok(members) => members,
            Err(error) => {
                log_catalog_error(&error);
                return;
            }
        };
        let member_count = members.len();
        if member_count > catalog.config.max_member_zones {
            let dropped = member_count - catalog.config.max_member_zones;
            members.truncate(catalog.config.max_member_zones);
            error!(
                category = "transfer",
                event = "catalog_member_limit_exceeded",
                catalog_zone = %catalog.origin,
                max_member_zones = catalog.config.max_member_zones,
                member_count,
                dropped,
                "catalog member zone limit exceeded; dropping excess catalog members"
            );
        }

        let catalog_key = catalog.origin.canonical_key();
        let mut members_by_key = HashMap::new();
        for member in members {
            members_by_key.insert(member.zone.canonical_key(), member.zone);
        }
        let new_member_keys = members_by_key.keys().cloned().collect::<HashSet<_>>();
        let old_member_keys = self
            .memberships_by_catalog
            .lock()
            .expect("catalog membership lock poisoned")
            .get(&catalog_key)
            .cloned()
            .unwrap_or_default();

        let Some(catalog_plan) = transfer_plan.get(&catalog.origin) else {
            warn!(
                category = "transfer",
                event = "catalog_without_transfer_plan",
                zone = %catalog.origin,
                "catalog zone has no transfer plan"
            );
            return;
        };

        let mut added = new_member_keys
            .difference(&old_member_keys)
            .cloned()
            .collect::<Vec<_>>();
        added.sort();
        for member_key in added {
            let Some(member_origin) = members_by_key.get(&member_key).cloned() else {
                continue;
            };
            if self.static_zone_keys.contains(&member_key) {
                warn!(
                    category = "transfer",
                    event = "catalog_member_static_zone_clash",
                    catalog_zone = %catalog.origin,
                    zone = %member_origin,
                    "catalog member zone already has static configuration; keeping static configuration"
                );
                continue;
            }
            transfer_plan.insert(catalog_plan.for_member_origin(member_origin.clone()));
            notify_authority.add_zone_from_catalog(&member_origin, &catalog.config);
            if zones.find_exact_zone(&member_origin).is_none() {
                zones.insert_loading(member_origin.clone());
                refresh_registry.record_loading_start(&member_origin);
            }
            let Some(refresh_tx) = refresh_tx.upgrade() else {
                warn!(
                    category = "transfer",
                    event = "catalog_member_refresh_queue_closed",
                    catalog_zone = %catalog.origin,
                    zone = %member_origin,
                    "catalog member refresh queue closed"
                );
                continue;
            };
            if refresh_tx
                .send(RefreshRequest {
                    zone: member_origin.clone(),
                    requested_serial: None,
                    reason: RefreshReason::Catalog,
                })
                .await
                .is_err()
            {
                warn!(
                    category = "transfer",
                    event = "catalog_member_refresh_queue_closed",
                    catalog_zone = %catalog.origin,
                    zone = %member_origin,
                    "catalog member refresh queue closed"
                );
            } else {
                info!(
                    category = "transfer",
                    event = "catalog_member_added",
                    catalog_zone = %catalog.origin,
                    zone = %member_origin,
                    "added catalog-managed member zone"
                );
            }
        }

        let mut removed = old_member_keys
            .difference(&new_member_keys)
            .cloned()
            .collect::<Vec<_>>();
        removed.sort();
        for member_key in removed {
            if self.static_zone_keys.contains(&member_key) {
                continue;
            }
            let member_origin = DomainName::from_absolute_str(&member_key)
                .expect("canonical zone key is an absolute DNS name");
            transfer_plan.remove(&member_origin);
            notify_authority.remove_zone(&member_origin);
            refresh_registry.remove_zone(&member_origin);
            zones.remove_zone(&member_origin);
            info!(
                category = "transfer",
                event = "catalog_member_removed",
                catalog_zone = %catalog.origin,
                zone = %member_origin,
                "removed catalog-managed member zone"
            );
        }

        self.memberships_by_catalog
            .lock()
            .expect("catalog membership lock poisoned")
            .insert(catalog_key, new_member_keys);
    }
}

fn log_catalog_error(error: &CatalogError) {
    warn!(
        category = "transfer",
        event = "catalog_processing_failed",
        error = %error,
        "catalog zone update was not applied"
    );
}

#[derive(Debug, Clone)]
struct ZoneRefreshRegistry {
    min_interval: Duration,
    max_interval: Duration,
    initial_retry: Duration,
    initial_retry_max: Duration,
    loading_warning_threshold: Duration,
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
    loading_since: Option<Instant>,
    next_loading_warning: Option<Instant>,
    last_failure_cause: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadingWarning {
    zone: DomainName,
    elapsed_loading_secs: u64,
    last_failure_cause: String,
    next_retry_unix_secs: Option<u64>,
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
    fn new(
        min_interval: Duration,
        max_interval: Duration,
        initial_retry: Duration,
        initial_retry_max: Duration,
        loading_warning_threshold: Duration,
    ) -> Self {
        Self {
            min_interval,
            max_interval,
            initial_retry,
            initial_retry_max,
            loading_warning_threshold,
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
        Self::without_jitter_with_max(
            min_interval,
            Duration::from_secs(86_400),
            initial_retry,
            initial_retry_max,
            Duration::from_secs(3600),
        )
    }

    #[cfg(test)]
    fn without_jitter_with_max(
        min_interval: Duration,
        max_interval: Duration,
        initial_retry: Duration,
        initial_retry_max: Duration,
        loading_warning_threshold: Duration,
    ) -> Self {
        Self {
            min_interval,
            max_interval,
            initial_retry,
            initial_retry_max,
            loading_warning_threshold,
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
        if let Some(timers) = timers {
            self.warn_near_max_soa_timers(&snapshot.origin, timers);
        }
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
                loading_since: None,
                next_loading_warning: None,
                last_failure_cause: None,
                initial_failure_count: 0,
                failures_since_success: 0,
                in_progress: false,
                expired: false,
            },
        );
    }

    fn record_loading_start(&self, origin: &DomainName) {
        self.record_loading_start_at(origin, Instant::now());
    }

    fn record_loading_start_at(&self, origin: &DomainName, now: Instant) {
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        statuses
            .entry(origin.canonical_key())
            .or_insert_with(|| ZoneRefreshStatus {
                origin: origin.clone(),
                soa_timers: None,
                last_success_unix_secs: None,
                next_refresh: None,
                next_refresh_unix_secs: None,
                expire_at: None,
                loading_since: Some(now),
                next_loading_warning: Some(now + self.loading_warning_threshold),
                last_failure_cause: None,
                initial_failure_count: 0,
                failures_since_success: 0,
                in_progress: false,
                expired: false,
            });
    }

    fn record_failure_with_cause(
        &self,
        origin: &DomainName,
        current: Option<Arc<ZoneSnapshot>>,
        failure_cause: Option<String>,
    ) {
        self.record_failure_at_with_cause(origin, current, failure_cause, Instant::now());
    }

    #[cfg(test)]
    fn record_failure_at(
        &self,
        origin: &DomainName,
        current: Option<Arc<ZoneSnapshot>>,
        now: Instant,
    ) {
        self.record_failure_at_with_cause(origin, current, None, now);
    }

    fn record_failure_at_with_cause(
        &self,
        origin: &DomainName,
        current: Option<Arc<ZoneSnapshot>>,
        failure_cause: Option<String>,
        now: Instant,
    ) {
        self.record_failure_at_with_timestamp_and_cause(
            origin,
            current,
            failure_cause,
            now,
            unix_timestamp_seconds(),
        );
    }

    #[cfg(test)]
    fn record_failure_at_with_timestamp(
        &self,
        origin: &DomainName,
        current: Option<Arc<ZoneSnapshot>>,
        now: Instant,
        unix_secs: u64,
    ) {
        self.record_failure_at_with_timestamp_and_cause(origin, current, None, now, unix_secs);
    }

    fn record_failure_at_with_timestamp_and_cause(
        &self,
        origin: &DomainName,
        current: Option<Arc<ZoneSnapshot>>,
        failure_cause: Option<String>,
        now: Instant,
        unix_secs: u64,
    ) {
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        let failure_keeps_zone_loading = current
            .as_ref()
            .is_none_or(|snapshot| snapshot.state == ZoneState::Loading);
        let status = statuses
            .entry(origin.canonical_key())
            .or_insert_with(|| ZoneRefreshStatus {
                origin: origin.clone(),
                soa_timers: current.as_ref().and_then(|snapshot| snapshot.soa_timers),
                last_success_unix_secs: None,
                next_refresh: None,
                next_refresh_unix_secs: None,
                expire_at: None,
                loading_since: None,
                next_loading_warning: None,
                last_failure_cause: None,
                initial_failure_count: 0,
                failures_since_success: 0,
                in_progress: false,
                expired: false,
            });

        if let Some(snapshot) = current {
            status.soa_timers = snapshot.soa_timers;
            status.expired = snapshot.state == ZoneState::Expired;
        }
        if failure_keeps_zone_loading && status.loading_since.is_none() {
            status.loading_since = Some(now);
            status.next_loading_warning = Some(now + self.loading_warning_threshold);
        }
        if let Some(failure_cause) = failure_cause {
            status.last_failure_cause = Some(failure_cause);
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

    fn loading_warnings_due(&self, zones: &ZoneStore, now: Instant) -> Vec<LoadingWarning> {
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        statuses
            .values_mut()
            .filter_map(|status| {
                if status
                    .next_loading_warning
                    .is_none_or(|warning_at| warning_at > now)
                {
                    return None;
                }
                let snapshot = zones.find_exact_zone(&status.origin)?;
                if snapshot.state != ZoneState::Loading {
                    status.loading_since = None;
                    status.next_loading_warning = None;
                    return None;
                }
                let loading_since = status.loading_since?;
                let elapsed_loading_secs = now.saturating_duration_since(loading_since).as_secs();
                status.next_loading_warning = Some(now + self.loading_warning_threshold);
                Some(LoadingWarning {
                    zone: status.origin.clone(),
                    elapsed_loading_secs,
                    last_failure_cause: status
                        .last_failure_cause
                        .clone()
                        .unwrap_or_else(|| "none recorded".to_owned()),
                    next_retry_unix_secs: status.next_refresh_unix_secs,
                })
            })
            .collect()
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

    fn remove_zone(&self, origin: &DomainName) {
        self.statuses
            .lock()
            .expect("zone refresh registry lock poisoned")
            .remove(&origin.canonical_key());
    }

    fn effective_interval(&self, seconds: u32) -> Duration {
        let interval = Duration::from_secs(seconds as u64)
            .max(self.min_interval)
            .min(self.max_interval);
        self.jitter.apply(interval)
    }

    fn warn_near_max_soa_timers(&self, origin: &DomainName, timers: SoaTimers) {
        self.warn_near_max_soa_timer(origin, "refresh", timers.refresh);
        self.warn_near_max_soa_timer(origin, "retry", timers.retry);
    }

    fn warn_near_max_soa_timer(&self, origin: &DomainName, field: &'static str, seconds: u32) {
        let max_effective_secs = self.max_interval.as_secs();
        if max_effective_secs == 0 {
            return;
        }
        let threshold_secs = max_effective_secs
            .saturating_mul(SOA_TIMER_NEAR_MAX_WARNING_PERCENT)
            .div_ceil(100);
        if (seconds as u64) < threshold_secs {
            return;
        }

        warn!(
            category = "configuration_warning",
            code = "soa_timer_near_max_effective_interval",
            zone = %origin,
            soa_field = field,
            soa_value_secs = seconds,
            max_effective_secs,
            threshold_percent = SOA_TIMER_NEAR_MAX_WARNING_PERCENT,
            "SOA timer approaches configured maximum effective ZSM interval"
        );
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

#[derive(Debug, Clone)]
struct NotifyAuthority {
    sources_by_zone: Arc<Mutex<HashMap<String, HashSet<IpAddr>>>>,
    tsig_keys_by_name: Arc<HashMap<String, Arc<TsigKey>>>,
    tsig_keys_by_zone: Arc<Mutex<HashMap<String, Arc<TsigKey>>>>,
    tsig_fudge_seconds: u16,
}

impl Default for NotifyAuthority {
    fn default() -> Self {
        Self {
            sources_by_zone: Arc::new(Mutex::new(HashMap::new())),
            tsig_keys_by_name: Arc::new(HashMap::new()),
            tsig_keys_by_zone: Arc::new(Mutex::new(HashMap::new())),
            tsig_fudge_seconds: DEFAULT_TSIG_FUDGE_SECS,
        }
    }
}

impl NotifyAuthority {
    fn from_config(config: &ServerConfig) -> Self {
        let mut sources_by_zone = HashMap::new();
        let tsig_keys = config
            .tsig_keys
            .iter()
            .map(|key| {
                let secret = key
                    .secret_base64()
                    .expect("configuration validation rejects invalid TSIG key secret sources");
                let key = TsigKey::from_base64(&key.name, &key.algorithm, &secret)
                    .expect("configuration validation rejects invalid TSIG keys");
                (key.name.canonical_key(), Arc::new(key))
            })
            .collect::<HashMap<_, _>>();
        let mut tsig_keys_by_zone = HashMap::new();
        for zone in &config.zones {
            let origin = DomainName::from_absolute_str(&zone.name)
                .expect("configuration validation rejects invalid zone names");
            let sources = notify_sources_for_zone(zone);
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
        for catalog_zone in &config.catalog_zones {
            let origin = DomainName::from_absolute_str(&catalog_zone.name)
                .expect("configuration validation rejects invalid catalog zone names");
            let sources = notify_sources_for_catalog_zone(catalog_zone);
            sources_by_zone.insert(origin.canonical_key(), sources);
            if let Some(tsig_key) = &catalog_zone.tsig_key {
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
            sources_by_zone: Arc::new(Mutex::new(sources_by_zone)),
            tsig_keys_by_name: Arc::new(tsig_keys),
            tsig_keys_by_zone: Arc::new(Mutex::new(tsig_keys_by_zone)),
            tsig_fudge_seconds: config.tsig.fudge_seconds,
        }
    }

    fn is_authorized(&self, qname: &DomainName, qclass: u16, source: IpAddr) -> bool {
        qclass == 1
            && self
                .sources_by_zone
                .lock()
                .expect("notify authority source lock poisoned")
                .get(&qname.canonical_key())
                .is_some_and(|sources| sources.contains(&source))
    }

    fn tsig_key_for_notify(&self, qname: &DomainName, qclass: u16) -> Option<Arc<TsigKey>> {
        if qclass != 1 {
            return None;
        }
        self.tsig_keys_by_zone
            .lock()
            .expect("notify authority zone TSIG lock poisoned")
            .get(&qname.canonical_key())
            .cloned()
    }

    fn tsig_key_by_name(&self, key_name: &DomainName) -> Option<Arc<TsigKey>> {
        self.tsig_keys_by_name
            .get(&key_name.canonical_key())
            .cloned()
    }

    fn add_zone_from_catalog(&self, origin: &DomainName, catalog: &CatalogZoneConfig) {
        self.sources_by_zone
            .lock()
            .expect("notify authority source lock poisoned")
            .insert(
                origin.canonical_key(),
                notify_sources_for_catalog_zone(catalog),
            );
        if let Some(tsig_key) = &catalog.tsig_key {
            let key_name = DomainName::from_absolute_str(tsig_key)
                .expect("configuration validation rejects invalid TSIG key references");
            if let Some(key) = self.tsig_keys_by_name.get(&key_name.canonical_key()) {
                self.tsig_keys_by_zone
                    .lock()
                    .expect("notify authority zone TSIG lock poisoned")
                    .insert(origin.canonical_key(), key.clone());
            }
        }
    }

    fn remove_zone(&self, origin: &DomainName) {
        let key = origin.canonical_key();
        self.sources_by_zone
            .lock()
            .expect("notify authority source lock poisoned")
            .remove(&key);
        self.tsig_keys_by_zone
            .lock()
            .expect("notify authority zone TSIG lock poisoned")
            .remove(&key);
    }
}

fn notify_sources_for_zone(zone: &ZoneConfig) -> HashSet<IpAddr> {
    let mut sources = zone
        .transfer_target_addrs()
        .into_iter()
        .map(|primary| primary.ip())
        .collect::<HashSet<_>>();
    sources.extend(zone.notify_sources.iter().copied());
    sources
}

fn notify_sources_for_catalog_zone(zone: &CatalogZoneConfig) -> HashSet<IpAddr> {
    let mut sources = zone
        .transfer_target_addrs()
        .into_iter()
        .map(|primary| primary.ip())
        .collect::<HashSet<_>>();
    sources.extend(zone.notify_sources.iter().copied());
    sources
}

struct PreparedDnsMessage {
    packet: Vec<u8>,
    response_tsig: Option<ResponseTsig>,
    immediate_response: Option<Vec<u8>>,
    tsig_authenticated: bool,
}

struct ResponseTsig {
    key: Arc<TsigKey>,
    request_mac: Vec<u8>,
    fudge_seconds: u16,
}

#[cfg(test)]
fn prepare_notify_packet(
    packet: &[u8],
    notify_authority: &NotifyAuthority,
    source: IpAddr,
) -> Option<PreparedDnsMessage> {
    prepare_notify_packet_with_optional_metrics(packet, notify_authority, source, None, None)
}

fn prepare_notify_packet_with_metrics(
    packet: &[u8],
    notify_authority: &NotifyAuthority,
    source: IpAddr,
    metrics: &RuntimeMetrics,
    notify_log_limiter: &NotifyLogLimiter,
) -> Option<PreparedDnsMessage> {
    prepare_notify_packet_with_optional_metrics(
        packet,
        notify_authority,
        source,
        Some(metrics),
        Some(notify_log_limiter),
    )
}

fn prepare_notify_packet_with_optional_metrics(
    packet: &[u8],
    notify_authority: &NotifyAuthority,
    source: IpAddr,
    metrics: Option<&RuntimeMetrics>,
    notify_log_limiter: Option<&NotifyLogLimiter>,
) -> Option<PreparedDnsMessage> {
    let unsigned = || PreparedDnsMessage {
        packet: packet.to_vec(),
        response_tsig: None,
        immediate_response: None,
        tsig_authenticated: false,
    };

    let header = match Header::parse(packet) {
        Ok(header) => header,
        Err(_) => return Some(unsigned()),
    };
    if header.is_response() || header.opcode() != Some(Opcode::Notify) {
        return Some(unsigned());
    }
    if let Some(metrics) = metrics {
        metrics.record_notify_received();
    }

    let question = match Question::parse(packet) {
        Ok(question) => question,
        Err(_) => return Some(unsigned()),
    };
    let Some(key) = notify_authority.tsig_key_for_notify(&question.qname, question.qclass) else {
        return Some(unsigned());
    };
    let authorized = notify_authority.is_authorized(&question.qname, question.qclass, source);
    if !authorized {
        return Some(unsigned());
    }

    match key.verify_request(packet, tsig_time_signed()) {
        Ok(verified) => {
            if let Some(metrics) = metrics {
                metrics.record_notify_tsig_result(NotifyTsigResult::Ok);
            }
            Some(PreparedDnsMessage {
                packet: verified.message,
                response_tsig: Some(ResponseTsig {
                    key,
                    request_mac: verified.mac,
                    fudge_seconds: notify_authority.tsig_fudge_seconds,
                }),
                immediate_response: None,
                tsig_authenticated: true,
            })
        }
        Err(error) => {
            if let Some(metrics) = metrics
                && let Some(result) = notify_tsig_result(&error)
            {
                metrics.record_notify_tsig_result(result);
            }
            if let Some(notify_log_limiter) = notify_log_limiter {
                notify_log_limiter.log_tsig_failure(source, &question.qname, &error);
            } else {
                warn!(
                    category = "notify",
                    event = "notify_tsig_failure",
                    peer_ip = %source,
                    zone = %question.qname,
                    %error,
                    "rejected NOTIFY with invalid TSIG"
                );
            }
            tsig_error_response(
                packet,
                &header,
                &question,
                &key,
                &error,
                notify_authority.tsig_fudge_seconds,
            )
            .map(|response| PreparedDnsMessage {
                packet: packet.to_vec(),
                response_tsig: None,
                immediate_response: Some(response),
                tsig_authenticated: false,
            })
        }
    }
}

fn prepare_query_tsig_packet(
    prepared: PreparedDnsMessage,
    notify_authority: &NotifyAuthority,
) -> PreparedDnsMessage {
    if prepared.immediate_response.is_some() || prepared.response_tsig.is_some() {
        return prepared;
    }

    let header = match Header::parse(&prepared.packet) {
        Ok(header) => header,
        Err(_) => return prepared,
    };
    if header.is_response() || header.opcode() != Some(Opcode::Query) {
        return prepared;
    }

    let message_key = match message_tsig_key(&prepared.packet) {
        Ok(Some(message_key)) => message_key,
        Ok(None) => return prepared,
        Err(TsigError::MisplacedTsig | TsigError::MalformedTsig) => {
            return PreparedDnsMessage {
                immediate_response: basic_error_response(&prepared.packet, &header, Rcode::FormErr),
                ..prepared
            };
        }
        Err(error @ TsigError::UnsupportedAlgorithm(_)) => {
            let question = match Question::parse(&prepared.packet) {
                Ok(question) => question,
                Err(_) => return prepared,
            };
            let Some(key) = message_tsig_owner_name(&prepared.packet)
                .ok()
                .flatten()
                .and_then(|key_name| notify_authority.tsig_key_by_name(&key_name))
            else {
                return prepared;
            };
            return PreparedDnsMessage {
                immediate_response: tsig_error_response(
                    &prepared.packet,
                    &header,
                    &question,
                    &key,
                    &error,
                    notify_authority.tsig_fudge_seconds,
                ),
                ..prepared
            };
        }
        Err(_) => return prepared,
    };

    let question = match Question::parse(&prepared.packet) {
        Ok(question) => question,
        Err(_) => return prepared,
    };

    let Some(key) = notify_authority.tsig_key_by_name(&message_key.name) else {
        let unsigned_error_key =
            TsigKey::for_unsigned_error(message_key.name, message_key.algorithm);
        return PreparedDnsMessage {
            immediate_response: tsig_error_response(
                &prepared.packet,
                &header,
                &question,
                &unsigned_error_key,
                &TsigError::KeyMismatch,
                notify_authority.tsig_fudge_seconds,
            ),
            ..prepared
        };
    };

    match key.verify_request(&prepared.packet, tsig_time_signed()) {
        Ok(verified) => PreparedDnsMessage {
            packet: verified.message,
            response_tsig: Some(ResponseTsig {
                key,
                request_mac: verified.mac,
                fudge_seconds: notify_authority.tsig_fudge_seconds,
            }),
            immediate_response: None,
            tsig_authenticated: true,
        },
        Err(error) => PreparedDnsMessage {
            immediate_response: tsig_error_response(
                &prepared.packet,
                &header,
                &question,
                &key,
                &error,
                notify_authority.tsig_fudge_seconds,
            ),
            ..prepared
        },
    }
}

fn basic_error_response(packet: &[u8], header: &Header, rcode: Rcode) -> Option<Vec<u8>> {
    let question = Question::parse(packet).ok();
    let mut response = Vec::new();
    response.extend_from_slice(&header.id.to_be_bytes());
    response.extend_from_slice(&(0x8000u16 | (header.flags & 0x7800) | rcode as u16).to_be_bytes());
    if let Some(question) = question {
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&question.qname.to_wire());
        response.extend_from_slice(&question.qtype.to_be_bytes());
        response.extend_from_slice(&question.qclass.to_be_bytes());
    } else {
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
    }
    Some(response)
}

fn notify_tsig_result(error: &TsigError) -> Option<NotifyTsigResult> {
    match error {
        TsigError::InvalidMac => Some(NotifyTsigResult::BadSig),
        TsigError::BadTrunc => Some(NotifyTsigResult::BadTrunc),
        TsigError::UnsupportedAlgorithm(_) => Some(NotifyTsigResult::BadAlg),
        TsigError::MissingTsig | TsigError::KeyMismatch | TsigError::AlgorithmMismatch => {
            Some(NotifyTsigResult::BadKey)
        }
        TsigError::TimeOutsideFudge => Some(NotifyTsigResult::BadTime),
        _ => None,
    }
}

fn tsig_error_response(
    packet: &[u8],
    header: &Header,
    question: &Question,
    key: &TsigKey,
    error: &TsigError,
    tsig_fudge_seconds: u16,
) -> Option<Vec<u8>> {
    let now = tsig_time_signed();
    let mut response = Vec::new();
    response.extend_from_slice(&header.id.to_be_bytes());
    response.extend_from_slice(
        &(0x8000u16 | (header.flags & 0x7800) | Rcode::NotAuth as u16).to_be_bytes(),
    );
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&question.qname.to_wire());
    response.extend_from_slice(&question.qtype.to_be_bytes());
    response.extend_from_slice(&question.qclass.to_be_bytes());

    match error {
        TsigError::InvalidMac => append_unsigned_tsig_error(
            &response,
            key,
            now,
            tsig_fudge_seconds,
            header.id,
            TSIG_ERROR_BADSIG,
            &[],
        )
        .ok(),
        TsigError::BadTrunc => append_unsigned_tsig_error(
            &response,
            key,
            now,
            tsig_fudge_seconds,
            header.id,
            TSIG_ERROR_BADTRUNC,
            &[],
        )
        .ok(),
        TsigError::UnsupportedAlgorithm(_) => append_unsigned_tsig_error(
            &response,
            key,
            now,
            tsig_fudge_seconds,
            header.id,
            TSIG_ERROR_BADALG,
            &[],
        )
        .ok(),
        TsigError::MissingTsig | TsigError::KeyMismatch | TsigError::AlgorithmMismatch => {
            append_unsigned_tsig_error(
                &response,
                key,
                now,
                tsig_fudge_seconds,
                header.id,
                TSIG_ERROR_BADKEY,
                &[],
            )
            .ok()
        }
        TsigError::TimeOutsideFudge => {
            let request_mac = extract_tsig_mac(packet).ok()?;
            sign_tsig_error_response(
                &response,
                key,
                TsigErrorResponseFields {
                    request_mac: &request_mac,
                    time_signed: now,
                    fudge: tsig_fudge_seconds,
                    original_id: header.id,
                    error: TSIG_ERROR_BADTIME,
                    other_data: &u48_bytes(now),
                },
            )
            .ok()
            .map(|signed| signed.message)
        }
        _ => None,
    }
}

fn u48_bytes(value: u64) -> Vec<u8> {
    let value = value & 0x0000_ffff_ffff_ffff;
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&((value >> 32) as u16).to_be_bytes());
    out.extend_from_slice(&(value as u32).to_be_bytes());
    out
}

fn sign_tsig_response(
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
            response_tsig.fudge_seconds,
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
    metrics: &RuntimeMetrics,
    qname: &DomainName,
    source: IpAddr,
    soa_serial: Option<u32>,
) {
    let action = notify_refresh.record(qname);
    metrics.record_notify_refresh_action(action);
    match action {
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
    catalog_runtime: CatalogRuntime,
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

                let Some(plan) = catalog_runtime.transfer_plan.get(&request.zone) else {
                    let zone = &request.zone;
                    warn!(zone = %zone, "accepted NOTIFY for zone without transfer plan");
                    catalog_runtime.refresh_registry.cancel_in_progress(zone);
                    continue;
                };

                if notify_serial_is_current(&zones, &request) {
                    let zone = &request.zone;
                    if let Some(snapshot) = zones.find_exact_zone(zone) {
                        catalog_runtime.refresh_registry.record_success(&snapshot);
                    } else {
                        catalog_runtime.refresh_registry.cancel_in_progress(zone);
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
                let tcp_connect_timeout = settings.tcp_connect_timeout;
                let zones = zones.clone();
                let catalog_runtime = catalog_runtime.clone();
                let ixfr_cooldowns = ixfr_cooldowns.clone();
                let metrics = metrics.clone();
                transfers.spawn(async move {
                    let _transfer_permit = transfer_permit;
                    let outcome = refresh_zone_from_primaries_with_outcome(
                        &zones,
                        &plan,
                        request.requested_serial,
                        RefreshAttemptContext {
                            ixfr_cooldowns: &ixfr_cooldowns,
                            metrics: &metrics,
                            ixfr_timeout,
                            axfr_timeout,
                            tcp_connect_timeout,
                            reason: request.reason.as_str(),
                        },
                    )
                    .await;
                    match outcome.snapshot {
                        Some(snapshot) => {
                            catalog_runtime.refresh_registry.record_success(&snapshot);
                            if catalog_runtime.manager.is_catalog(&snapshot.origin) {
                                catalog_runtime
                                    .manager
                                    .apply_snapshot(
                                        &snapshot,
                                        &zones,
                                        &catalog_runtime.transfer_plan,
                                        &catalog_runtime.refresh_registry,
                                        &catalog_runtime.notify_authority,
                                        &catalog_runtime.refresh_tx,
                                    )
                                    .await;
                            }
                        }
                        None => catalog_runtime.refresh_registry.record_failure_with_cause(
                            &request.zone,
                            zones.find_exact_zone(&request.zone),
                            outcome.failure_cause,
                        ),
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
    tcp_connect_timeout: Duration,
    transfer_limit: Arc<Semaphore>,
}

#[derive(Clone)]
struct InitialLoadSettings {
    axfr_timeout: Duration,
    ixfr_timeout: Duration,
    tcp_connect_timeout: Duration,
    transfer_limit: Arc<Semaphore>,
}

#[derive(Clone, Copy)]
struct RefreshAttemptContext<'a> {
    ixfr_cooldowns: &'a IxfrCooldownRegistry,
    metrics: &'a RuntimeMetrics,
    ixfr_timeout: Duration,
    axfr_timeout: Duration,
    tcp_connect_timeout: Duration,
    reason: &'a str,
}

#[derive(Debug)]
struct RefreshZoneOutcome {
    snapshot: Option<ZoneSnapshot>,
    failure_cause: Option<String>,
}

impl RefreshZoneOutcome {
    fn success(snapshot: ZoneSnapshot) -> Self {
        Self {
            snapshot: Some(snapshot),
            failure_cause: None,
        }
    }

    fn failure(failure_cause: Option<String>) -> Self {
        Self {
            snapshot: None,
            failure_cause,
        }
    }
}

async fn run_initial_zone_loads(
    zones: ZoneStore,
    initial_origins: Vec<DomainName>,
    catalog_runtime: CatalogRuntime,
    ixfr_cooldowns: IxfrCooldownRegistry,
    metrics: RuntimeMetrics,
    settings: InitialLoadSettings,
) -> Result<(), RuntimeError> {
    let mut transfers = JoinSet::new();

    for zone_apex in initial_origins {
        let plan = catalog_runtime
            .transfer_plan
            .get(&zone_apex)
            .expect("configuration validation builds a transfer plan for each zone");
        let zones = zones.clone();
        let catalog_runtime = catalog_runtime.clone();
        let ixfr_cooldowns = ixfr_cooldowns.clone();
        let metrics = metrics.clone();
        let axfr_timeout = settings.axfr_timeout;
        let ixfr_timeout = settings.ixfr_timeout;
        let tcp_connect_timeout = settings.tcp_connect_timeout;
        let transfer_permit = settings
            .transfer_limit
            .clone()
            .acquire_owned()
            .await
            .expect("transfer semaphore is not closed");

        transfers.spawn(async move {
            let _transfer_permit = transfer_permit;
            let outcome = refresh_zone_from_primaries_with_outcome(
                &zones,
                &plan,
                None,
                RefreshAttemptContext {
                    ixfr_cooldowns: &ixfr_cooldowns,
                    metrics: &metrics,
                    ixfr_timeout,
                    axfr_timeout,
                    tcp_connect_timeout,
                    reason: "initial",
                },
            )
            .await;
            match outcome.snapshot {
                Some(snapshot) => {
                    catalog_runtime.refresh_registry.record_success(&snapshot);
                    if catalog_runtime.manager.is_catalog(&snapshot.origin) {
                        catalog_runtime
                            .manager
                            .apply_snapshot(
                                &snapshot,
                                &zones,
                                &catalog_runtime.transfer_plan,
                                &catalog_runtime.refresh_registry,
                                &catalog_runtime.notify_authority,
                                &catalog_runtime.refresh_tx,
                            )
                            .await;
                    }
                }
                None => {
                    let zone_apex = &plan.origin;
                    catalog_runtime.refresh_registry.record_failure_with_cause(
                        zone_apex,
                        zones.find_exact_zone(zone_apex),
                        outcome.failure_cause,
                    );
                    warn!(zone = %zone_apex, "zone remains in LOADING state");
                }
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
        for warning in refresh_registry.loading_warnings_due(&zones, now) {
            log_loading_warning(warning);
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

fn log_loading_warning(warning: LoadingWarning) {
    warn!(
        category = "transfer",
        event = "zone_loading_threshold_exceeded",
        zone = %warning.zone,
        elapsed_loading_secs = warning.elapsed_loading_secs,
        error = %warning.last_failure_cause,
        next_retry_unix_secs = ?warning.next_retry_unix_secs,
        "zone remains in LOADING state beyond configured threshold"
    );
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

#[cfg(test)]
async fn refresh_zone_from_primaries(
    zones: &ZoneStore,
    plan: &ZoneTransferPlan,
    primary_serial_hint: Option<u32>,
    context: RefreshAttemptContext<'_>,
) -> Option<ZoneSnapshot> {
    refresh_zone_from_primaries_with_outcome(zones, plan, primary_serial_hint, context)
        .await
        .snapshot
}

async fn refresh_zone_from_primaries_with_outcome(
    zones: &ZoneStore,
    plan: &ZoneTransferPlan,
    primary_serial_hint: Option<u32>,
    context: RefreshAttemptContext<'_>,
) -> RefreshZoneOutcome {
    let current_snapshot = zones
        .find_exact_zone(&plan.origin)
        .filter(|snapshot| snapshot.serial.is_some());
    let current_serial = current_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.serial);
    let mut last_failure_cause = None;

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
            return RefreshZoneOutcome::success((**snapshot).clone());
        }

        info!(
            zone = %plan.origin,
            current_serial,
            primary_serial,
            reason = %context.reason,
            "SOA serial hint found newer primary serial"
        );
    }

    for primary_target in &plan.primaries {
        let primary = primary_target.addr;
        let transfer_source = plan.transfer_source_for(primary);

        if primary_target.transport == TransferTransportConfig::Tcp
            && primary_serial_hint.is_none()
            && let (Some(snapshot), Some(current_serial)) = (&current_snapshot, current_serial)
        {
            let qid = match transfer_query_id() {
                Ok(qid) => qid,
                Err(error) => {
                    last_failure_cause =
                        Some(format!("SOA poll failed for primary {primary}: {error}"));
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
            match poll_soa_from_primary_with_tsig_and_source(
                primary,
                &plan.origin,
                plan.qclass,
                qid,
                TransferTsig::new(plan.tsig_key.as_deref(), plan.tsig_fudge_seconds),
                transfer_source,
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
                    return RefreshZoneOutcome::success((**snapshot).clone());
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
                    last_failure_cause =
                        Some(format!("SOA poll failed for primary {primary}: {error}"));
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
            if context.ixfr_cooldowns.is_disabled(&plan.origin, primary) {
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
                        last_failure_cause = Some(format!(
                            "failed to generate IXFR query ID for primary {primary}: {error}"
                        ));
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
                match transfer_ixfr_from_target_with_tsig(
                    primary_target,
                    &plan.origin,
                    plan.qclass,
                    qid,
                    current_snapshot,
                    TransferSession::new(
                        TransferTsig::new(plan.tsig_key.as_deref(), plan.tsig_fudge_seconds),
                        plan.max_transfer_ingest_bytes,
                    )
                    .with_transfer_source(transfer_source)
                    .with_parse_options(plan.parse_options),
                    context.ixfr_timeout,
                    context.tcp_connect_timeout,
                )
                .await
                {
                    Ok(IxfrResponse::Updated(snapshot)) => {
                        context.metrics.record_ixfr_succeeded();
                        let serial = snapshot.serial;
                        zones.insert_snapshot((*snapshot).clone());
                        info!(
                            zone = %plan.origin,
                            %primary,
                            ?serial,
                            reason = %context.reason,
                            "IXFR completed"
                        );
                        return RefreshZoneOutcome::success(*snapshot);
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
                        return RefreshZoneOutcome::success((**current_snapshot).clone());
                    }
                    Err(error) => {
                        context.metrics.record_ixfr_failed();
                        if ixfr_error_disables_ixfr(&error) {
                            context
                                .ixfr_cooldowns
                                .record_unsupported(&plan.origin, primary);
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
                last_failure_cause = Some(format!(
                    "failed to generate AXFR query ID for primary {primary}: {error}"
                ));
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
        match transfer_axfr_from_target_with_tsig_and_source(
            primary_target,
            &plan.origin,
            plan.qclass,
            qid,
            TransferSession::new(
                TransferTsig::new(plan.tsig_key.as_deref(), plan.tsig_fudge_seconds),
                plan.max_transfer_ingest_bytes,
            )
            .with_parse_options(plan.parse_options),
            transfer_source,
            context.axfr_timeout,
            context.tcp_connect_timeout,
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
                return RefreshZoneOutcome::success(snapshot);
            }
            Err(error) => {
                last_failure_cause = Some(format!("AXFR failed for primary {primary}: {error}"));
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

    RefreshZoneOutcome::failure(last_failure_cause)
}

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
async fn handle_tcp_connection(
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
async fn handle_tcp_connection_with_query_hook(
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
    let (mut reader, writer) = stream.into_split();
    let inflight = Arc::new(Semaphore::new(max_inflight_queries_per_connection));
    let (response_tx, response_rx) = mpsc::channel(max_inflight_queries_per_connection);
    let writer_task = tokio::spawn(write_tcp_responses(
        writer,
        response_rx,
        write_timeout,
        metrics.clone(),
    ));
    let mut query_tasks = JoinSet::new();

    while !response_tx.is_closed() {
        let permit =
            match tokio::time::timeout(inflight_limit_timeout, inflight.clone().acquire_owned())
                .await
            {
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

        let Some(packet) = read_tcp_message(&mut reader, idle_timeout, read_timeout).await? else {
            drop(permit);
            break;
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
    match writer_task.await {
        Ok(result) => result?,
        Err(error) => warn!(%peer_ip, %error, "TCP writer task failed"),
    }

    Ok(())
}

struct TcpResponse {
    response: Vec<u8>,
    query_observation: Option<QueryMetricObservation>,
    permit: OwnedSemaphorePermit,
}

async fn write_tcp_responses(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
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
    let dns_cookie_secret = dns_cookie_secrets.current();
    let dns_cookie = dns_cookie_context(peer_ip, &dns_cookie_secret, dns_cookie);
    let cookie_validated = dns_cookie
        .is_some_and(|context| request_has_valid_dns_server_cookie(&prepared.packet, context));
    let query_metrics = observe_query_metrics(
        &prepared.packet,
        &zones,
        &metrics,
        Transport::Tcp,
        cookie_validated,
        parse_duration,
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
    let action = answer_message_with_notify_hooks_and_query_observer(
        &prepared.packet,
        &zones,
        AnswerOptions {
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
        },
        |qname, qclass| {
            let authorized = notify_authority.is_authorized(qname, qclass, peer_ip);
            if !authorized {
                metrics.record_notify_unauthorized();
                notify_log_limiter.log_unauthorized(peer_ip, qname);
            }
            authorized
        },
        |qname, _qclass, serial| {
            signal_notify_refresh(
                &notify_refresh,
                &notify_refresh_tx,
                &metrics,
                qname,
                peer_ip,
                serial,
            )
        },
        |lookup| record_query_termination_metric(&query_metrics, lookup, &metrics),
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
            if let (Some(hook), Some(query_id)) = (&query_hook, query_id) {
                hook(query_id).await;
            }
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

async fn read_tcp_message<R>(
    stream: &mut R,
    idle_timeout: Duration,
    read_timeout: Duration,
) -> Result<Option<Vec<u8>>, RuntimeError>
where
    R: AsyncRead + Unpin,
{
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

fn frame_dns_tcp_message(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&(message.len() as u16).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

#[cfg(test)]
mod tests {
    static TEST_PATH_COUNTER: AtomicUsize = AtomicUsize::new(0);

    use std::{
        collections::{HashMap, HashSet},
        net::IpAddr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use oxidedns_core::{
        ServerConfig,
        axfr::{IxfrResponse, frame_tcp_message},
        config::{HealthConfig, RrlConfig, TransferPrimaryConfig, TransferTransportConfig},
        dns::{
            AnyResponseMode, ChaosQueryOutcome, DnsCookiePolicy, DnsCookieRequestStatus,
            DomainName, ExtendedDnsErrorsMode, Header, LookupTermination, Opcode, Rcode,
            RecordType, Transport,
        },
        tsig::{
            DEFAULT_TSIG_FUDGE_SECS, TSIG_ERROR_BADALG, TSIG_ERROR_BADKEY, TSIG_ERROR_BADSIG,
            TSIG_ERROR_BADTIME, TSIG_ERROR_BADTRUNC, TsigError, TsigKey,
        },
        zone::{ResourceRecord, Rrset, SoaTimers, ZoneSnapshot, ZoneState, ZoneStore},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
        sync::{mpsc, oneshot},
    };
    use tokio_rustls::rustls::{RootCertStore, server::WebPkiClientVerifier};
    use tracing::{
        Event, Metadata, Subscriber,
        field::{Field, Visit},
        span::{Attributes, Id, Record},
        subscriber::Interest,
    };

    use super::{
        CatalogManager, CatalogRuntime, CookiePrefixMetricSettings,
        DEFAULT_COOKIE_PREFIX_METRIC_LIMIT, DEFAULT_LATENCY_HISTOGRAM_BUCKETS,
        DnsCookieRuntimeSettings, DnsCookieSecretStore, EDE_UNSUPPORTED_NSEC3_ITERATIONS,
        EDNS_EXTENDED_DNS_ERROR_OPTION, HealthEndpointState, IxfrCooldownRegistry, LoadingWarning,
        MetricsRateLimiter, NotifyAuthority, NotifyLogLimiter, NotifyLogSummary,
        NotifyRefreshAction, NotifyRefreshTracker, NotifyTsigResult, PreparedDnsMessage,
        QueryLatencyCategory, QueryLatencyHistogram, QueryMetricObservation, QueryPipelineStage,
        RefreshAttemptContext, RefreshRequest, RefreshWorkerSettings,
        ResponseCacheCandidateCategory, ResponseCacheIneligibleReason, RrlCategory, RrlDecision,
        RrlLimiter, RrlSummary, Runtime, RuntimeError, RuntimeMetrics, RuntimeStatus,
        TcpServerSettings, TransferError, TransferPlan, TransferSession, TransferTsig,
        UdpServerSettings, ZoneRefreshRegistry, dns_cookie_secret_fingerprint, drain_task_set,
        drain_tcp_connections, handle_tcp_connection, handle_tcp_connection_with_query_hook,
        jitter_interval, load_pem_certs, load_pem_private_key_from_file as load_pem_private_key,
        log_loading_warning, log_notify_log_summary, log_rrl_summary, metrics_body,
        observe_query_metrics, poll_soa_from_primary, poll_soa_from_primary_with_tsig,
        prepare_notify_packet, prepare_notify_packet_with_metrics, prepare_query_tsig_packet,
        query_id_from_random_bytes, record_query_response_metric, record_query_termination_metric,
        refresh_zone_from_primaries, required_file_descriptor_limit, response_category,
        response_opt_record, response_question_end, response_rcode, rotate_transfer_targets,
        rrl_truncated_response, runtime_config_warnings_at, serial_after, serve_health,
        serve_refresh_requests, serve_scheduled_refreshes, serve_tcp, serve_udp,
        sign_tsig_response, signal_notify_refresh, transfer_axfr_from_primary,
        transfer_ixfr_from_primary, transfer_query_id, uniform_index_from_u64,
        validate_file_descriptor_limit_value, validate_runtime_config, write_tcp_message,
    };

    #[test]
    fn runtime_initializes_loading_zones() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

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
    async fn catalog_snapshot_adds_member_transfer_plan_and_hides_catalog() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                primaries = ["192.0.2.53:53"]
                notify_sources = ["192.0.2.53"]
                tsig_key = "catalog-key."
            "#,
        )
        .expect("valid catalog config");
        let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
        let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog_origin.clone(),
            Some(7),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![vec![1, b'2']],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![member_origin.to_wire()],
                ),
            ],
        );
        let zones = ZoneStore::new();
        zones.insert_loading_hidden(catalog_origin.clone());
        zones.insert_snapshot(snapshot.clone());
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let catalog_manager = CatalogManager::from_config(&config);
        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
        );
        let notify_authority = NotifyAuthority::from_config(&config);
        let (tx, mut rx) = mpsc::channel(1);

        catalog_manager
            .apply_snapshot(
                &snapshot,
                &zones,
                &transfer_plan,
                &refresh_registry,
                &notify_authority,
                &tx.downgrade(),
            )
            .await;

        assert!(zones.find_zone(&catalog_origin).is_none());
        assert!(transfer_plan.get(&member_origin).is_some());
        assert_eq!(
            zones
                .find_exact_zone(&member_origin)
                .expect("member zone loading snapshot")
                .state,
            ZoneState::Loading
        );
        assert!(
            refresh_registry
                .snapshots_by_zone()
                .contains_key(&member_origin.canonical_key())
        );
        let request = rx.recv().await.expect("member refresh request");
        assert_eq!(request.zone, member_origin);
        assert_eq!(request.reason, super::RefreshReason::Catalog);
    }

    #[tokio::test]
    async fn catalog_snapshot_enforces_member_zone_cap() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                primaries = ["192.0.2.53:53"]
                notify_sources = ["192.0.2.53"]
                tsig_key = "catalog-key."
                max_member_zones = 1
            "#,
        )
        .expect("valid catalog config");
        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
        let alpha_origin = DomainName::from_absolute_str("alpha.example.").unwrap();
        let beta_origin = DomainName::from_absolute_str("beta.example.").unwrap();
        let snapshot = ZoneSnapshot::active(
            catalog_origin.clone(),
            Some(7),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("version.catalog.example.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    0,
                    vec![vec![1, b'2']],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![alpha_origin.to_wire()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("b.zones.catalog.example.").unwrap(),
                    RecordType::Ptr as u16,
                    1,
                    0,
                    vec![beta_origin.to_wire()],
                ),
            ],
        );
        let zones = ZoneStore::new();
        zones.insert_loading_hidden(catalog_origin);
        zones.insert_snapshot(snapshot.clone());
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let catalog_manager = CatalogManager::from_config(&config);
        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
        );
        let notify_authority = NotifyAuthority::from_config(&config);
        let (tx, mut rx) = mpsc::channel(2);

        catalog_manager
            .apply_snapshot(
                &snapshot,
                &zones,
                &transfer_plan,
                &refresh_registry,
                &notify_authority,
                &tx.downgrade(),
            )
            .await;

        assert!(transfer_plan.get(&alpha_origin).is_some());
        assert!(transfer_plan.get(&beta_origin).is_none());
        assert_eq!(
            rx.recv().await.expect("member refresh request").zone,
            alpha_origin
        );
        assert!(rx.try_recv().is_err());
        assert!(captured.contains_all(&[
            "catalog_member_limit_exceeded",
            "max_member_zones=1",
            "member_count=2",
            "dropped=1",
        ]));
    }

    #[test]
    fn metrics_rate_limiter_is_per_source_and_evicts_idle_sources() {
        let limiter = MetricsRateLimiter::from_config(HealthConfig {
            metrics_rate_limit_per_minute: 1,
            metrics_rate_limit_idle_seconds: 1,
            ..HealthConfig::default()
        });
        let now = std::time::Instant::now();
        let first: std::net::IpAddr = "192.0.2.10".parse().unwrap();
        let second: std::net::IpAddr = "192.0.2.11".parse().unwrap();

        assert_eq!(limiter.check_at(first, now), Ok(()));
        assert_eq!(limiter.check_at(first, now), Err(60));
        assert_eq!(limiter.check_at(second, now), Ok(()));
        assert_eq!(
            limiter.check_at(first, now + std::time::Duration::from_secs(2)),
            Ok(())
        );
    }

    #[test]
    fn notify_authority_allows_primaries_and_notify_sources() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

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
    fn explicit_transfer_primaries_feed_notify_authority_and_transfer_plan() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."
                notify_sources = ["198.51.100.53"]

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["/etc/oxidedns/ca.pem"]
            "#,
        )
        .expect("valid config");
        let zone = DomainName::from_absolute_str("example.test.").unwrap();

        let authority = NotifyAuthority::from_config(&config);
        assert!(authority.is_authorized(&zone, 1, "192.0.2.53".parse().unwrap()));
        assert!(authority.is_authorized(&zone, 1, "198.51.100.53".parse().unwrap()));

        let plan = TransferPlan::from_config(&config)
            .expect("transfer plan")
            .get(&zone)
            .expect("transfer plan");
        assert_eq!(plan.primaries.len(), 1);
        assert_eq!(plan.primaries[0].transport, TransferTransportConfig::Xot);
        assert_eq!(
            plan.primaries[0].server_name.as_deref(),
            Some("primary.example.test")
        );
    }

    #[test]
    fn transfer_plan_carries_out_of_zone_glue_tolerance() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [transfer]
                accept_out_of_zone_glue = true

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");
        let zone = DomainName::from_absolute_str("example.test.").unwrap();

        let plan = TransferPlan::from_config(&config)
            .expect("transfer plan")
            .get(&zone)
            .expect("transfer plan");

        assert!(plan.parse_options.accept_out_of_zone_glue);
    }

    #[test]
    fn tsig_secret_file_feeds_notify_authority_and_transfer_plan() {
        let secret_file = unique_test_path("oxidedns-server-tsig-secret", "key");
        std::fs::write(&secret_file, b"dG9wc2VjcmV0\n").expect("write TSIG secret file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600))
                .expect("secure TSIG secret file mode");
        }
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[tsig_keys]]
                name = "transfer-key."
                algorithm = "hmac-sha256"
                secret_file = "{}"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "transfer-key."
            "#,
            secret_file.display()
        ))
        .expect("valid TSIG secret_file config");
        let zone = DomainName::from_absolute_str("example.test.").unwrap();
        let key_name = DomainName::from_absolute_str("transfer-key.").unwrap();

        let authority = NotifyAuthority::from_config(&config);
        assert!(
            authority
                .tsig_keys_by_name
                .contains_key(&key_name.canonical_key())
        );
        assert!(
            authority
                .tsig_keys_by_zone
                .lock()
                .expect("notify authority zone TSIG lock poisoned")
                .contains_key(&zone.canonical_key())
        );

        let plan = TransferPlan::from_config(&config)
            .expect("transfer plan")
            .get(&zone)
            .expect("zone transfer plan");
        assert!(plan.tsig_key.is_some());
        let _ = std::fs::remove_file(secret_file);
    }

    #[test]
    fn transfer_plan_rotates_multi_primary_start_once_per_process() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]

                [[zones]]
                name = "example.test."
                primaries = [
                    "192.0.2.53:53",
                    "192.0.2.54:53",
                    "192.0.2.55:53",
                ]
            "#,
        )
        .expect("valid config");
        let zone = DomainName::from_absolute_str("example.test.").unwrap();

        let plan = TransferPlan::from_config_with_primary_start(&config, |_| Ok(1))
            .expect("transfer plan")
            .get(&zone)
            .expect("zone transfer plan");

        assert_eq!(
            plan.primaries
                .iter()
                .map(|primary| primary.addr)
                .collect::<Vec<_>>(),
            vec![
                "192.0.2.54:53".parse().unwrap(),
                "192.0.2.55:53".parse().unwrap(),
                "192.0.2.53:53".parse().unwrap(),
            ]
        );

        let retained = plan.clone();
        assert_eq!(plan.primaries, retained.primaries);
    }

    #[test]
    fn transfer_target_rotation_wraps_without_reordering_members() {
        let primaries = vec![
            TransferPrimaryConfig::tcp("192.0.2.53:53".parse().unwrap()),
            TransferPrimaryConfig::tcp("192.0.2.54:53".parse().unwrap()),
            TransferPrimaryConfig::tcp("192.0.2.55:53".parse().unwrap()),
        ];

        let rotated = rotate_transfer_targets(primaries, 5);

        assert_eq!(
            rotated
                .iter()
                .map(|primary| primary.addr)
                .collect::<Vec<_>>(),
            vec![
                "192.0.2.55:53".parse().unwrap(),
                "192.0.2.53:53".parse().unwrap(),
                "192.0.2.54:53".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn primary_start_index_uses_rejection_sampling_boundary() {
        assert_eq!(uniform_index_from_u64(0, 3), Some(0));
        assert_eq!(uniform_index_from_u64(1, 3), Some(1));
        assert_eq!(uniform_index_from_u64(2, 3), Some(2));
        assert_eq!(uniform_index_from_u64(u64::MAX - 1, 3), Some(2));
        assert_eq!(uniform_index_from_u64(u64::MAX, 3), None);
    }

    #[test]
    fn notify_authority_rejects_missing_required_tsig_with_badkey_response() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [tsig]
                fudge_seconds = 30

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

        let response = prepared
            .expect("TSIG error response")
            .immediate_response
            .expect("immediate TSIG error response");
        assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, 0);
        assert_eq!(tsig.original_id, 0x1234);
        assert_eq!(tsig.error, TSIG_ERROR_BADKEY);
        assert!(tsig.other_data.is_empty());
    }

    #[test]
    fn ordinary_query_with_unknown_tsig_key_gets_badkey_response() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[tsig_keys]]
                name = "known-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "known-key."
            "#,
        )
        .expect("valid config");
        let authority = NotifyAuthority::from_config(&config);
        let unknown_key =
            TsigKey::from_base64("unknown-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let signed = unknown_key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();

        let prepared = prepare_query_tsig_packet(
            PreparedDnsMessage {
                packet: signed.message,
                response_tsig: None,
                immediate_response: None,
                tsig_authenticated: false,
            },
            &authority,
        );

        let response = prepared
            .immediate_response
            .expect("immediate BADKEY response");
        let header = Header::parse(&response).unwrap();
        assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, 0);
        assert_eq!(tsig.original_id, 0x1234);
        assert_eq!(tsig.error, TSIG_ERROR_BADKEY);
        assert!(tsig.other_data.is_empty());
        assert!(!prepared.tsig_authenticated);
    }

    #[test]
    fn ordinary_query_with_bad_tsig_mac_gets_badsig_response() {
        let (authority, key) = tsig_notify_authority();
        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let signed = key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let bad = replace_final_tsig_mac(&signed.message, &[0xaa; 32]);

        let prepared = prepare_query_tsig_packet(
            PreparedDnsMessage {
                packet: bad,
                response_tsig: None,
                immediate_response: None,
                tsig_authenticated: false,
            },
            &authority,
        );

        let response = prepared.immediate_response.expect("TSIG error response");
        assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.error, TSIG_ERROR_BADSIG);
    }

    #[test]
    fn ordinary_query_with_too_short_tsig_mac_gets_badtrunc_response() {
        let (authority, key) = tsig_notify_authority();
        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let signed = key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let too_short_mac = &signed.mac[..key.algorithm.min_mac_len() - 1];
        let bad = replace_final_tsig_mac(&signed.message, too_short_mac);

        let prepared = prepare_query_tsig_packet(
            PreparedDnsMessage {
                packet: bad,
                response_tsig: None,
                immediate_response: None,
                tsig_authenticated: false,
            },
            &authority,
        );

        let response = prepared.immediate_response.expect("TSIG error response");
        let header = Header::parse(&response).unwrap();
        assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, 0);
        assert_eq!(tsig.error, TSIG_ERROR_BADTRUNC);
        assert!(tsig.other_data.is_empty());
    }

    #[test]
    fn ordinary_query_with_hmac_md5_tsig_gets_badalg_response() {
        let (authority, key) = tsig_notify_authority();
        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let signed = key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let bad = replace_final_tsig_algorithm(&signed.message, "hmac-md5.sig-alg.reg.int.");

        let prepared = prepare_query_tsig_packet(
            PreparedDnsMessage {
                packet: bad,
                response_tsig: None,
                immediate_response: None,
                tsig_authenticated: false,
            },
            &authority,
        );

        let response = prepared.immediate_response.expect("TSIG error response");
        let header = Header::parse(&response).unwrap();
        assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, 0);
        assert_eq!(tsig.error, TSIG_ERROR_BADALG);
        assert!(tsig.other_data.is_empty());
    }

    #[test]
    fn ordinary_query_outside_tsig_fudge_gets_badtime_response_with_server_time() {
        let (authority, key) = tsig_notify_authority();
        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let signed = key
            .sign_request(&packet, 1, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();

        let prepared = prepare_query_tsig_packet(
            PreparedDnsMessage {
                packet: signed.message,
                response_tsig: None,
                immediate_response: None,
                tsig_authenticated: false,
            },
            &authority,
        );

        let response = prepared.immediate_response.expect("TSIG error response");
        let header = Header::parse(&response).unwrap();
        assert_eq!(response_rcode(&response, &header), Rcode::NotAuth as u16);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, key.algorithm.mac_len());
        assert_eq!(tsig.error, TSIG_ERROR_BADTIME);
        assert_eq!(tsig.other_data.len(), 6);
    }

    #[tokio::test]
    async fn health_endpoint_reports_starting_until_zone_active() {
        let zones = ZoneStore::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_health(
            listener,
            health_state(zones.clone()),
            std::future::pending(),
        ));

        let livez = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            http_request(addr, "GET", "/livez"),
        )
        .await
        .expect("/livez should answer within SRS health bound");
        assert!(livez.starts_with("HTTP/1.1 200 OK"));
        assert!(livez.contains("content-type: application/json"));
        assert!(livez.contains(r#""status":"alive""#));

        let starting = http_request(addr, "GET", "/healthz").await;
        assert!(starting.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(starting.contains("content-type: application/json"));
        assert!(starting.ends_with(
            r#"{"status":"not-ready","reason":"no_active_zones","version":"0.1.2","zones_active":0,"zones_loading":0,"zones_expired":0}"#
        ));

        zones.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            Vec::new(),
        ));

        let ready = http_request(addr, "GET", "/healthz").await;
        assert!(ready.starts_with("HTTP/1.1 200 OK"));
        assert!(ready.ends_with(
            r#"{"status":"ready","version":"0.1.2","zones_active":1,"zones_loading":0,"zones_expired":0}"#
        ));

        server.abort();
    }

    #[tokio::test]
    async fn health_endpoint_exits_on_graceful_shutdown_signal() {
        let zones = ZoneStore::new();
        zones.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            Vec::new(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(serve_health(listener, health_state(zones), async move {
            let _ = shutdown_rx.await;
        }));

        let ready = http_request(addr, "GET", "/healthz").await;
        assert!(ready.starts_with("HTTP/1.1 200 OK"));
        assert!(ready.ends_with(
            r#"{"status":"ready","version":"0.1.2","zones_active":1,"zones_loading":0,"zones_expired":0}"#
        ));

        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .expect("health listener did not stop after graceful shutdown signal")
            .expect("health listener task panicked")
            .expect("health listener returned an error");
    }

    #[test]
    fn metrics_body_reports_loading_duration_seconds() {
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

        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        );
        let metrics = metrics_body(
            &zones,
            &RuntimeMetrics::new(),
            &CatalogManager::default(),
            &refresh_registry,
            3600,
            false,
        );

        assert!(metrics.contains("oxidedns_zone_loading_seconds{zone=\"example.test.\"} 0"));
        assert!(metrics.contains("oxidedns_zone_loading_seconds{zone=\"loading.test.\"} 3600"));
        assert!(
            metrics.contains("oxidedns_secondary_zone_loading_seconds{zone=\"example.test.\"} 0")
        );
        assert!(
            metrics
                .contains("oxidedns_secondary_zone_loading_seconds{zone=\"loading.test.\"} 3600")
        );
        assert!(!metrics.contains("oxidedns_zone_shape_rrsets"));
    }

    #[test]
    fn metrics_body_reports_catalog_membership() {
        let zones = ZoneStore::new();
        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        );
        let catalog_manager = CatalogManager {
            catalogs_by_key: Arc::new(HashMap::new()),
            static_zone_keys: Arc::new(HashSet::from(["static.example.".to_owned()])),
            memberships_by_catalog: Arc::new(Mutex::new(HashMap::from([(
                "catalog.example.".to_owned(),
                HashSet::from(["alpha.example.".to_owned(), "static.example.".to_owned()]),
            )]))),
        };

        let metrics = metrics_body(
            &zones,
            &RuntimeMetrics::new(),
            &catalog_manager,
            &refresh_registry,
            0,
            false,
        );

        assert!(metrics.contains(
            "oxidedns_catalog_member_info{catalog_zone=\"catalog.example.\",zone=\"alpha.example.\",managed=\"true\"} 1"
        ));
        assert!(metrics.contains(
            "oxidedns_catalog_member_info{catalog_zone=\"catalog.example.\",zone=\"static.example.\",managed=\"false\"} 1"
        ));
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
        metrics_state.record_query_response_rcode(23);
        metrics_state.record_zone_query_response_rcode(&active_origin.canonical_key(), 0);
        metrics_state.record_zone_query_response_rcode(&active_origin.canonical_key(), 3);
        metrics_state.record_query_latency(
            QueryLatencyCategory::UdpDirect,
            std::time::Duration::from_micros(250),
        );
        metrics_state.record_query_latency(
            QueryLatencyCategory::TcpCnameChain,
            std::time::Duration::from_millis(3),
        );
        metrics_state.set_configuration_warnings(4);
        metrics_state.record_notify_received();
        metrics_state.record_notify_unauthorized();
        metrics_state.record_notify_refresh_action(NotifyRefreshAction::Signalled);
        metrics_state.record_notify_refresh_action(NotifyRefreshAction::Deduplicated);
        metrics_state.record_notify_tsig_result(NotifyTsigResult::Ok);
        metrics_state.record_notify_tsig_result(NotifyTsigResult::BadKey);
        metrics_state.record_notify_tsig_result(NotifyTsigResult::BadSig);
        metrics_state.record_notify_tsig_result(NotifyTsigResult::BadTime);
        metrics_state.record_notify_tsig_result(NotifyTsigResult::BadAlg);
        metrics_state.record_notify_tsig_result(NotifyTsigResult::BadTrunc);
        let cookie_prefix_metrics = cookie_prefix_metrics_for_test();
        metrics_state.record_dns_cookie_status(
            DnsCookieRequestStatus::NoCookie,
            "192.0.2.10".parse().unwrap(),
            cookie_prefix_metrics,
        );
        metrics_state.record_dns_cookie_status(
            DnsCookieRequestStatus::ClientCookieOnly,
            "192.0.2.10".parse().unwrap(),
            cookie_prefix_metrics,
        );
        metrics_state.record_dns_cookie_status(
            DnsCookieRequestStatus::ValidServerCookie,
            "2001:db8::10".parse().unwrap(),
            cookie_prefix_metrics,
        );
        metrics_state.record_dns_cookie_status(
            DnsCookieRequestStatus::InvalidServerCookie,
            "2001:db8::10".parse().unwrap(),
            cookie_prefix_metrics,
        );
        metrics_state.record_dns_cookie_badcookie();
        metrics_state.record_dns_cookie_badcookie_for_source(
            "192.0.2.10".parse().unwrap(),
            cookie_prefix_metrics,
        );
        metrics_state.record_nsec3_iterations_exceed_cap();
        metrics_state.record_chaos_query(ChaosQueryOutcome::Answered);
        metrics_state.record_chaos_query(ChaosQueryOutcome::MissingValue);
        metrics_state.record_chaos_query(ChaosQueryOutcome::UnrecognizedName);
        metrics_state.record_chaos_query(ChaosQueryOutcome::NonTxt);
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
                catalog_manager: CatalogManager::default(),
                refresh_registry,
                metrics_rate_limiter: MetricsRateLimiter::default(),
                started_at: std::time::Instant::now(),
                graceful_shutdown_secs: 30,
                zone_shape_metrics_enabled: true,
            },
            std::future::pending(),
        ));

        let ready = http_request(addr, "GET", "/readyz").await;
        assert!(ready.starts_with("HTTP/1.1 200 OK"));
        assert!(ready.ends_with(
            r#"{"status":"ready","version":"0.1.2","zones_active":1,"zones_loading":1,"zones_expired":0}"#
        ));

        let metrics = http_request(addr, "GET", "/metrics").await;
        assert!(metrics.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics.contains("content-type: text/plain; version=0.0.4; charset=utf-8"));
        assert!(!metrics.contains("content-encoding: gzip"));
        assert!(metrics.contains("oxidedns_zones_total 2"));
        assert!(metrics.contains("oxidedns_zones_active 1"));
        assert!(metrics.contains("oxidedns_queries_received_total 2"));
        assert!(metrics.contains("oxidedns_queries_truncated_total 1"));
        assert!(metrics.contains("oxidedns_queries_cname_chain_limit_total 1"));
        assert!(metrics.contains("oxidedns_queries_cname_loop_total 1"));
        assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"NOERROR\"} 1"));
        assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"SERVFAIL\"} 0"));
        assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"NXDOMAIN\"} 1"));
        assert!(metrics.contains("oxidedns_query_responses_total{rcode=\"BADCOOKIE\"} 1"));
        assert!(metrics.contains("oxidedns_secondary_query_responses_total{rcode=\"NOERROR\"} 1"));
        assert!(
            metrics.contains("oxidedns_secondary_query_responses_total{rcode=\"BADCOOKIE\"} 1")
        );
        assert!(metrics.contains("oxidedns_secondary_build_info{version=\"0.1.2\",commit=\""));
        assert!(metrics.contains("rust_version=\"rustc "));
        assert!(metrics.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"udp_direct\",le=\"0.0001\"} 0"
        ));
        assert!(metrics.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"udp_direct\",le=\"0.00025\"} 1"
        ));
        assert!(metrics.contains(
            "oxidedns_secondary_query_duration_seconds_sum{query_category=\"udp_direct\"} 0.000250000"
        ));
        assert!(metrics.contains(
            "oxidedns_secondary_query_duration_seconds_count{query_category=\"udp_direct\"} 1"
        ));
        assert!(metrics.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"tcp_cname_chain\",le=\"0.0025\"} 0"
        ));
        assert!(metrics.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"tcp_cname_chain\",le=\"0.005\"} 1"
        ));
        assert!(metrics.contains("oxidedns_dns_cookie_queries_total{case=\"no_cookie\"} 1"));
        assert!(metrics.contains("oxidedns_dns_cookie_queries_total{case=\"client_only\"} 1"));
        assert!(metrics.contains("oxidedns_dns_cookie_queries_total{case=\"valid_server\"} 1"));
        assert!(metrics.contains("oxidedns_dns_cookie_queries_total{case=\"invalid_server\"} 1"));
        assert!(metrics.contains("oxidedns_dns_cookie_badcookie_responses_total 1"));
        assert!(metrics.contains(
            "oxidedns_dns_cookie_queries_by_prefix_total{source_prefix=\"192.0.2.0/24\",case=\"no_cookie\"} 1"
        ));
        assert!(metrics.contains(
            "oxidedns_dns_cookie_queries_by_prefix_total{source_prefix=\"192.0.2.0/24\",case=\"client_only\"} 1"
        ));
        assert!(metrics.contains(
            "oxidedns_dns_cookie_queries_by_prefix_total{source_prefix=\"2001:db8::/56\",case=\"valid_server\"} 1"
        ));
        assert!(metrics.contains(
            "oxidedns_dns_cookie_badcookie_responses_by_prefix_total{source_prefix=\"192.0.2.0/24\"} 1"
        ));
        assert!(metrics.contains("oxidedns_secondary_configuration_warnings_total 4"));
        assert!(metrics.contains("oxidedns_dnssec_nsec3_iterations_exceed_cap_total 1"));
        assert!(metrics.contains("oxidedns_chaos_queries_total{outcome=\"answered\"} 1"));
        assert!(metrics.contains("oxidedns_chaos_queries_total{outcome=\"missing_value\"} 1"));
        assert!(metrics.contains("oxidedns_chaos_queries_total{outcome=\"unrecognized_name\"} 1"));
        assert!(metrics.contains("oxidedns_chaos_queries_total{outcome=\"non_txt\"} 1"));
        assert!(metrics.contains("oxidedns_transfer_sessions_started_total{protocol=\"axfr\"} 1"));
        assert!(metrics.contains("oxidedns_transfer_sessions_started_total{protocol=\"ixfr\"} 0"));
        assert!(
            metrics.contains("oxidedns_transfer_sessions_completed_total{protocol=\"axfr\"} 1")
        );
        assert!(metrics.contains("oxidedns_transfer_sessions_failed_total{protocol=\"axfr\"} 0"));
        assert!(metrics.contains("oxidedns_notify_messages_received_total 1"));
        assert!(metrics.contains("oxidedns_notify_messages_unauthorized_total 1"));
        assert!(metrics.contains("oxidedns_notify_refresh_actions_total{action=\"signalled\"} 1"));
        assert!(
            metrics.contains("oxidedns_notify_refresh_actions_total{action=\"deduplicated\"} 1")
        );
        assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"ok\"} 1"));
        assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"badkey\"} 1"));
        assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"badsig\"} 1"));
        assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"badtime\"} 1"));
        assert!(metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"badalg\"} 1"));
        assert!(
            metrics.contains("oxidedns_tsig_notify_verifications_total{result=\"badtrunc\"} 1")
        );
        assert!(metrics.contains("oxidedns_zone_state{zone=\"example.test.\",state=\"active\"} 1"));
        assert!(
            metrics.contains("oxidedns_zone_state{zone=\"example.test.\",state=\"loading\"} 0")
        );
        assert!(
            metrics.contains("oxidedns_zone_state{zone=\"loading.test.\",state=\"loading\"} 1")
        );
        assert!(metrics.contains("oxidedns_zone_loading_seconds{zone=\"example.test.\"} 0"));
        assert!(metrics.contains("oxidedns_zone_loading_seconds{zone=\"loading.test.\"} "));
        assert!(
            metrics.contains(
                "oxidedns_secondary_zone_state{zone=\"example.test.\",state=\"active\"} 1"
            )
        );
        assert!(
            metrics.contains(
                "oxidedns_secondary_zone_state{zone=\"example.test.\",state=\"loading\"} 0"
            )
        );
        assert!(
            metrics.contains(
                "oxidedns_secondary_zone_state{zone=\"loading.test.\",state=\"loading\"} 1"
            )
        );
        assert!(
            metrics.contains("oxidedns_secondary_zone_loading_seconds{zone=\"example.test.\"} 0")
        );
        assert!(
            metrics.contains("oxidedns_secondary_zone_loading_seconds{zone=\"loading.test.\"} ")
        );
        assert!(!metrics.contains("oxidedns_zone_soa_serial{zone=\"loading.test.\"}"));
        assert!(metrics.contains("oxidedns_zone_soa_serial{zone=\"example.test.\"} 1"));
        assert!(!metrics.contains("oxidedns_secondary_zone_soa_serial{zone=\"loading.test.\"}"));
        assert!(metrics.contains("oxidedns_secondary_zone_soa_serial{zone=\"example.test.\"} 1"));
        assert!(metrics.contains("oxidedns_zone_shape_rrsets{zone=\"example.test.\"} 1"));
        assert!(metrics.contains("oxidedns_zone_shape_rdata_records{zone=\"example.test.\"} 1"));
        assert!(
            metrics.contains("oxidedns_zone_shape_single_rdata_rrsets{zone=\"example.test.\"} 1")
        );
        assert!(
            metrics.contains("oxidedns_zone_shape_multi_rdata_rrsets{zone=\"example.test.\"} 0")
        );
        assert!(
            metrics.contains("oxidedns_zone_shape_spilled_rdata_rrsets{zone=\"example.test.\"} 0")
        );
        assert!(
            metrics.contains("oxidedns_zone_shape_max_rdata_per_rrset{zone=\"example.test.\"} 1")
        );
        assert!(metrics.contains("oxidedns_zone_shape_owner_names{zone=\"example.test.\"} 1"));
        assert!(
            metrics
                .contains("oxidedns_zone_shape_empty_non_terminal_names{zone=\"example.test.\"} 0")
        );
        assert!(metrics.contains(
            "oxidedns_zone_shape_name_key_deduplicated_bytes{zone=\"example.test.\"} 13"
        ));
        assert!(!metrics.contains("oxidedns_zone_shape_rrsets{zone=\"loading.test.\"}"));
        assert!(metrics.contains(
            "oxidedns_zone_last_success_timestamp_seconds{zone=\"example.test.\"} 1700000000"
        ));
        assert!(metrics.contains(
            "oxidedns_secondary_zone_last_refresh_seconds{zone=\"example.test.\"} 1700000000"
        ));
        assert!(metrics.contains(
            "oxidedns_zone_next_refresh_timestamp_seconds{zone=\"example.test.\"} 1700003600"
        ));
        assert!(metrics.contains(
            "oxidedns_secondary_zone_next_refresh_seconds{zone=\"example.test.\"} 1700003600"
        ));
        assert!(
            !metrics
                .contains("oxidedns_zone_last_success_timestamp_seconds{zone=\"loading.test.\"}")
        );
        assert!(
            !metrics
                .contains("oxidedns_secondary_zone_last_refresh_seconds{zone=\"loading.test.\"}")
        );
        assert!(metrics.contains(
            "oxidedns_zone_next_refresh_timestamp_seconds{zone=\"loading.test.\"} 1700000060"
        ));
        assert!(metrics.contains(
            "oxidedns_secondary_zone_next_refresh_seconds{zone=\"loading.test.\"} 1700000060"
        ));
        assert!(
            metrics
                .contains("oxidedns_zone_refresh_failures_since_success{zone=\"example.test.\"} 0")
        );
        assert!(
            metrics
                .contains("oxidedns_zone_refresh_failures_since_success{zone=\"loading.test.\"} 1")
        );
        assert!(
            metrics.contains("oxidedns_secondary_zone_refresh_failures{zone=\"example.test.\"} 0")
        );
        assert!(
            metrics.contains("oxidedns_secondary_zone_refresh_failures{zone=\"loading.test.\"} 1")
        );
        assert!(metrics.contains("oxidedns_zone_queries_total{zone=\"example.test.\"} 2"));
        assert!(metrics.contains("oxidedns_zone_queries_total{zone=\"loading.test.\"} 0"));
        assert!(metrics.contains("oxidedns_secondary_queries_total{zone=\"example.test.\"} 2"));
        assert!(metrics.contains("oxidedns_secondary_queries_total{zone=\"loading.test.\"} 0"));
        assert!(metrics.contains(
            "oxidedns_zone_query_responses_total{zone=\"example.test.\",rcode=\"NOERROR\"} 1"
        ));
        assert!(metrics.contains(
            "oxidedns_zone_query_responses_total{zone=\"example.test.\",rcode=\"NXDOMAIN\"} 1"
        ));
        assert!(metrics.contains(
            "oxidedns_secondary_query_responses_total{zone=\"example.test.\",rcode=\"NOERROR\"} 1"
        ));
        assert!(metrics.contains(
            "oxidedns_secondary_query_responses_total{zone=\"loading.test.\",rcode=\"NOERROR\"} 0"
        ));

        let compressed_metrics =
            http_request_with_headers(addr, "GET", "/metrics", &[("Accept-Encoding", "gzip")])
                .await;
        let (compressed_headers, compressed_body) = split_http_response(&compressed_metrics);
        assert!(compressed_headers.starts_with("HTTP/1.1 200 OK"));
        assert!(
            compressed_headers.contains("content-type: text/plain; version=0.0.4; charset=utf-8")
        );
        assert!(compressed_headers.contains("content-encoding: gzip"));
        assert!(compressed_headers.contains("vary: accept-encoding"));
        let mut decoder = flate2::read::GzDecoder::new(compressed_body);
        let mut decoded_metrics = String::new();
        std::io::Read::read_to_string(&mut decoder, &mut decoded_metrics).unwrap();
        assert!(decoded_metrics.contains("oxidedns_zones_total 2"));
        assert!(decoded_metrics.contains("oxidedns_secondary_build_info{version=\"0.1.2\""));
        assert!(decoded_metrics.contains(
            "oxidedns_secondary_query_duration_seconds_count{query_category=\"udp_direct\"} 1"
        ));

        let gzip_disallowed =
            http_request_with_headers(addr, "GET", "/metrics", &[("Accept-Encoding", "gzip;q=0")])
                .await;
        let (gzip_disallowed_headers, gzip_disallowed_body) = split_http_response(&gzip_disallowed);
        assert!(gzip_disallowed_headers.starts_with("HTTP/1.1 200 OK"));
        assert!(!gzip_disallowed_headers.contains("content-encoding: gzip"));
        let gzip_disallowed_body = std::str::from_utf8(gzip_disallowed_body).unwrap();
        assert!(gzip_disallowed_body.contains("oxidedns_zones_total 2"));

        let missing = http_request(addr, "GET", "/missing").await;
        assert!(missing.starts_with("HTTP/1.1 404 Not Found"));
        assert!(missing.ends_with(r#"{"error":"not_found","path":"/missing"}"#));

        for method in ["HEAD", "POST"] {
            for path in ["/livez", "/healthz", "/readyz", "/metrics"] {
                let method_not_allowed = http_request(addr, method, path).await;
                assert!(method_not_allowed.starts_with("HTTP/1.1 405 Method Not Allowed"));
                assert!(method_not_allowed.contains("content-type: application/json"));
                if method == "POST" {
                    assert!(method_not_allowed.ends_with(&format!(
                        r#"{{"error":"method_not_allowed","path":"{path}"}}"#
                    )));
                }
            }
        }

        server.abort();
    }

    #[tokio::test]
    async fn metrics_endpoint_rate_limits_per_source_without_limiting_health() {
        let zones = ZoneStore::new();
        zones.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            Vec::new(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_health(
            listener,
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
                metrics_rate_limiter: MetricsRateLimiter::from_config(HealthConfig {
                    metrics_rate_limit_per_minute: 1,
                    metrics_rate_limit_idle_seconds: 300,
                    ..HealthConfig::default()
                }),
                started_at: std::time::Instant::now(),
                graceful_shutdown_secs: 30,
                zone_shape_metrics_enabled: false,
            },
            std::future::pending(),
        ));

        let first = http_request(addr, "GET", "/metrics").await;
        assert!(first.starts_with("HTTP/1.1 200 OK"));

        let limited = http_request(addr, "GET", "/metrics").await;
        assert!(limited.starts_with("HTTP/1.1 429 Too Many Requests"));
        assert!(limited.contains("content-type: application/json"));
        assert!(limited.contains("retry-after: 60"));
        assert!(limited.ends_with(r#"{"error":"rate_limited","retry_after_seconds":60}"#));

        let livez = http_request(addr, "GET", "/livez").await;
        assert!(livez.starts_with("HTTP/1.1 200 OK"));
        let readyz = http_request(addr, "GET", "/readyz").await;
        assert!(readyz.starts_with("HTTP/1.1 200 OK"));

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
                catalog_manager: CatalogManager::default(),
                refresh_registry: ZoneRefreshRegistry::without_jitter(
                    std::time::Duration::from_secs(60),
                    std::time::Duration::from_secs(60),
                    std::time::Duration::from_secs(3600),
                ),
                metrics_rate_limiter: MetricsRateLimiter::default(),
                started_at: std::time::Instant::now(),
                graceful_shutdown_secs: 30,
                zone_shape_metrics_enabled: false,
            },
            std::future::pending(),
        ));

        runtime_status.mark_draining();

        let health = http_request(addr, "GET", "/healthz").await;
        assert!(health.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(health.ends_with(
            r#"{"status":"draining","version":"0.1.2","grace_period_remaining_seconds":30}"#
        ));

        let livez = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            http_request(addr, "GET", "/livez"),
        )
        .await
        .expect("/livez should remain responsive while draining");
        assert!(livez.starts_with("HTTP/1.1 200 OK"));

        let ready = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            http_request(addr, "GET", "/readyz"),
        )
        .await
        .expect("/readyz should answer within SRS health bound while draining");
        assert!(ready.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(ready.ends_with(
            r#"{"status":"draining","version":"0.1.2","grace_period_remaining_seconds":30}"#
        ));

        runtime_status.mark_unhealthy();
        let unhealthy = http_request(addr, "GET", "/healthz").await;
        assert!(unhealthy.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(unhealthy.ends_with(r#"{"status":"unhealthy","version":"0.1.2"}"#));

        server.abort();
    }

    #[tokio::test]
    async fn runtime_binds_health_while_initial_transfer_is_in_progress() {
        let (primary, query_seen, release_primary) = spawn_blocked_axfr_primary().await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []
                health = "127.0.0.1:0"

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
        let (server, health_addr) = spawn_runtime_with_bound_health(runtime).await;

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
        assert!(health.ends_with(
            r#"{"status":"not-ready","reason":"loading","version":"0.1.2","zones_active":0,"zones_loading":1,"zones_expired":0}"#
        ));

        let _ = release_primary.send(());
        server.abort();
    }

    #[tokio::test]
    async fn runtime_does_not_open_health_listener_when_unconfigured() {
        let (primary, query_seen, release_primary) = spawn_blocked_axfr_primary().await;
        let udp_addr = unused_udp_addr().await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["{udp_addr}"]
                listen_tcp = []

                [limits]
                axfr_timeout_secs = 5
                graceful_shutdown_secs = 1

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");
        assert_eq!(config.server.health, None);
        let runtime = Runtime::new(config);
        let server = tokio::spawn(runtime.run());

        tokio::time::timeout(std::time::Duration::from_secs(1), query_seen)
            .await
            .expect("initial transfer should start")
            .expect("primary should observe initial transfer query");

        let connection = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            TcpStream::connect(udp_addr),
        )
        .await
        .expect("TCP connect attempt should finish promptly");
        assert!(
            connection.is_err(),
            "health endpoint must not listen when server.health is unset"
        );

        let _ = release_primary.send(());
        server.abort();
    }

    #[tokio::test]
    async fn runtime_binds_health_on_management_interface() {
        let (primary, query_seen, release_primary) = spawn_blocked_axfr_primary().await;
        let health_port = unused_udp_tcp_addr().await.port();
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []

                [interfaces]
                mgmt = ["127.0.0.1:9443"]

                [health]
                default_port = {health_port}

                [limits]
                axfr_timeout_secs = 5
                graceful_shutdown_secs = 1

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");
        assert_eq!(config.server.health, None);
        assert_eq!(
            config.health_listeners(),
            vec![
                format!("127.0.0.1:{health_port}")
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
            ]
        );
        let runtime = Runtime::new(config);
        let (server, health_addr) = spawn_runtime_with_bound_health(runtime).await;
        assert_eq!(health_addr.port(), health_port);

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
        assert!(health.ends_with(
            r#"{"status":"not-ready","reason":"loading","version":"0.1.2","zones_active":0,"zones_loading":1,"zones_expired":0}"#
        ));

        let _ = release_primary.send(());
        server.abort();
    }

    #[tokio::test]
    async fn runtime_reports_draining_until_initial_transfer_releases() {
        let (primary, query_seen, release_primary) = spawn_blocked_axfr_primary().await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []
                health = "127.0.0.1:0"

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
        let (server, health_addr) =
            spawn_runtime_with_bound_health_and_shutdown(runtime, async move {
                shutdown_rx.await.map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::Interrupted, "test shutdown dropped")
                })
            })
            .await;

        tokio::time::timeout(std::time::Duration::from_secs(1), query_seen)
            .await
            .expect("initial transfer should start")
            .expect("primary should observe initial transfer query");
        let starting = eventually_health_body(
            health_addr,
            r#"{"status":"not-ready","reason":"loading","version":"0.1.2","zones_active":0,"zones_loading":1,"zones_expired":0}"#,
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(starting.starts_with("HTTP/1.1 503 Service Unavailable"));

        shutdown_tx
            .send("SIGTERM")
            .expect("runtime receives shutdown");
        let draining = eventually_health_body(
            health_addr,
            r#"{"status":"draining","version":"0.1.2","grace_period_remaining_seconds":2}"#,
            std::time::Duration::from_secs(1),
        )
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
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []
                health = "127.0.0.1:0"

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");
        let runtime = Runtime::new(config);
        let (server, health_addr) = spawn_runtime_with_bound_health(runtime).await;

        let ready = eventually_health_body(
            health_addr,
            r#"{"status":"ready","version":"0.1.2","zones_active":1,"zones_loading":0,"zones_expired":0}"#,
            std::time::Duration::from_secs(1),
        )
        .await;
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
        assert!(still_ready.ends_with(
            r#"{"status":"ready","version":"0.1.2","zones_active":1,"zones_loading":0,"zones_expired":0}"#
        ));

        server.abort();
    }

    #[tokio::test]
    async fn runtime_serves_queries_and_notify_on_configured_dns_interface() {
        let primary = spawn_axfr_primary().await;
        let dns_addr = unused_udp_tcp_addr().await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = []
                listen_tcp = []
                health = "127.0.0.1:0"

                [interfaces]
                dns = ["{dns_addr}"]

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
                notify_sources = ["127.0.0.1"]
            "#
        ))
        .expect("valid config");
        let runtime = Runtime::new(config);
        let (server, health_addr) = spawn_runtime_with_bound_health(runtime).await;

        let ready = eventually_health_body(
            health_addr,
            r#"{"status":"ready","version":"0.1.2","zones_active":1,"zones_loading":0,"zones_expired":0}"#,
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(ready.starts_with("HTTP/1.1 200 OK"));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        client.send_to(&request, dns_addr).await.unwrap();
        let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("query response on DNS interface");
        let header = Header::parse(&response).unwrap();
        assert_eq!(header.id, 0x1234);
        assert_eq!(header.ancount, 1);
        assert_eq!(response_rcode(&response, &header), Rcode::NoError as u16);

        let notify = notify_packet(0x5678, "example.test.", RecordType::Soa as u16, 1);
        client.send_to(&notify, dns_addr).await.unwrap();
        let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("NOTIFY response on DNS interface");
        let header = Header::parse(&response).unwrap();
        assert_eq!(header.id, 0x5678);
        assert_eq!(response_rcode(&response, &header), Rcode::NoError as u16);

        let mut tcp_client = TcpStream::connect(dns_addr).await.unwrap();
        let tcp_notify = notify_packet(0x6789, "example.test.", RecordType::Soa as u16, 1);
        tcp_client
            .write_all(&frame_tcp_message(&tcp_notify))
            .await
            .unwrap();
        let response = read_framed_tcp_response(&mut tcp_client).await;
        let header = Header::parse(&response).unwrap();
        assert_eq!(header.id, 0x6789);
        assert_eq!(response_rcode(&response, &header), Rcode::NoError as u16);

        server.abort();
    }

    #[test]
    fn signed_notify_is_verified_stripped_and_response_signed() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [tsig]
                fudge_seconds = 30

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
        let signed_response = sign_tsig_response(response.clone(), prepared.response_tsig)
            .expect("signed NOTIFY response");
        let response_tsig = parse_tsig_response_fields(&signed_response);
        assert_eq!(response_tsig.fudge, 30);
        let verified_response = key
            .verify_response(&signed_response, &signed_notify.mac, current_unix_time())
            .expect("verified NOTIFY response");
        assert_eq!(verified_response.message, response);
    }

    #[test]
    fn authorized_notify_with_bad_tsig_mac_gets_badsig_response() {
        let (authority, key) = tsig_notify_authority();
        let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
        let signed_notify = key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed NOTIFY");
        let mut bad_mac = signed_notify.mac.clone();
        bad_mac[0] ^= 0x01;
        let bad_notify = replace_final_tsig_mac(&signed_notify.message, &bad_mac);

        let prepared =
            prepare_notify_packet(&bad_notify, &authority, "192.0.2.53".parse().unwrap())
                .expect("TSIG error response");
        let response = prepared
            .immediate_response
            .expect("immediate TSIG error response");

        assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, 0);
        assert_eq!(tsig.original_id, 0x1234);
        assert_eq!(tsig.error, TSIG_ERROR_BADSIG);
        assert!(tsig.other_data.is_empty());
    }

    #[test]
    fn authorized_notify_with_too_short_tsig_mac_gets_badtrunc_response() {
        let (authority, key) = tsig_notify_authority();
        let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
        let signed_notify = key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed NOTIFY");
        let too_short_mac = &signed_notify.mac[..key.algorithm.min_mac_len() - 1];
        let bad_notify = replace_final_tsig_mac(&signed_notify.message, too_short_mac);

        let prepared =
            prepare_notify_packet(&bad_notify, &authority, "192.0.2.53".parse().unwrap())
                .expect("TSIG error response");
        let response = prepared
            .immediate_response
            .expect("immediate TSIG error response");

        assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, 0);
        assert_eq!(tsig.original_id, 0x1234);
        assert_eq!(tsig.error, TSIG_ERROR_BADTRUNC);
        assert!(tsig.other_data.is_empty());
    }

    #[test]
    fn authorized_notify_with_hmac_md5_tsig_gets_badalg_response() {
        let (authority, key) = tsig_notify_authority();
        let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
        let signed_notify = key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed NOTIFY");
        let bad_algorithm_notify =
            replace_final_tsig_algorithm(&signed_notify.message, "hmac-md5.sig-alg.reg.int.");

        let prepared = prepare_notify_packet(
            &bad_algorithm_notify,
            &authority,
            "192.0.2.53".parse().unwrap(),
        )
        .expect("TSIG error response");
        let response = prepared
            .immediate_response
            .expect("immediate TSIG error response");

        assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, 0);
        assert_eq!(tsig.original_id, 0x1234);
        assert_eq!(tsig.error, TSIG_ERROR_BADALG);
        assert!(tsig.other_data.is_empty());
    }

    #[test]
    fn authorized_notify_with_unknown_tsig_key_gets_badkey_response() {
        let (authority, key) = tsig_notify_authority();
        let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
        let signed_notify = key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed NOTIFY");
        let bad_key_notify = replace_final_tsig_owner(&signed_notify.message, "unknown-key.");

        let prepared =
            prepare_notify_packet(&bad_key_notify, &authority, "192.0.2.53".parse().unwrap())
                .expect("TSIG error response");
        let response = prepared
            .immediate_response
            .expect("immediate TSIG error response");

        assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, 0);
        assert_eq!(tsig.original_id, 0x1234);
        assert_eq!(tsig.error, TSIG_ERROR_BADKEY);
        assert!(tsig.other_data.is_empty());
    }

    #[test]
    fn authorized_notify_with_algorithm_mismatch_gets_badkey_response() {
        let (authority, key) = tsig_notify_authority();
        let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
        let signed_notify = key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed NOTIFY");
        let mismatched_algorithm_notify =
            replace_final_tsig_algorithm(&signed_notify.message, "hmac-sha1.");

        let prepared = prepare_notify_packet(
            &mismatched_algorithm_notify,
            &authority,
            "192.0.2.53".parse().unwrap(),
        )
        .expect("TSIG error response");
        let response = prepared
            .immediate_response
            .expect("immediate TSIG error response");

        assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, 0);
        assert_eq!(tsig.original_id, 0x1234);
        assert_eq!(tsig.error, TSIG_ERROR_BADKEY);
        assert!(tsig.other_data.is_empty());
    }

    #[test]
    fn authorized_notify_outside_tsig_fudge_gets_badtime_response_with_server_time() {
        let (authority, key) = tsig_notify_authority();
        let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);
        let stale_notify = key
            .sign_request(&packet, 1, DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed NOTIFY");

        let prepared = prepare_notify_packet(
            &stale_notify.message,
            &authority,
            "192.0.2.53".parse().unwrap(),
        )
        .expect("TSIG error response");
        let response = prepared
            .immediate_response
            .expect("immediate TSIG error response");

        assert_eq!(response[3] & 0x0f, Rcode::NotAuth as u8);
        let tsig = parse_tsig_response_fields(&response);
        assert_eq!(tsig.mac_len, key.algorithm.mac_len());
        assert_eq!(tsig.original_id, 0x1234);
        assert_eq!(tsig.error, TSIG_ERROR_BADTIME);
        assert_eq!(tsig.other_data.len(), 6);
    }

    #[test]
    fn notify_tsig_verification_metrics_classify_results() {
        let (authority, key) = tsig_notify_authority();
        let metrics = RuntimeMetrics::new();
        let packet = notify_packet(0x1234, "example.test.", RecordType::Soa as u16, 1);

        let unsigned_prepared = prepare_notify_packet_with_metrics(
            &packet,
            &authority,
            "192.0.2.53".parse().unwrap(),
            &metrics,
            &notify_log_limiter_for_test(),
        )
        .expect("TSIG error response");
        assert!(unsigned_prepared.immediate_response.is_some());

        let signed_notify = key
            .sign_request(&packet, current_unix_time(), DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed NOTIFY");
        let signed_prepared = prepare_notify_packet_with_metrics(
            &signed_notify.message,
            &authority,
            "192.0.2.53".parse().unwrap(),
            &metrics,
            &notify_log_limiter_for_test(),
        )
        .expect("verified NOTIFY");
        assert_eq!(signed_prepared.packet, packet);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.notify_received, 2);
        assert_eq!(snapshot.notify_tsig_badkey, 1);
        assert_eq!(snapshot.notify_tsig_ok, 1);
        assert_eq!(snapshot.notify_tsig_badsig, 0);
    }

    #[test]
    fn notify_refresh_signalling_records_metrics() {
        let tracker = NotifyRefreshTracker::new(std::time::Duration::from_secs(60));
        let (refresh_tx, _refresh_rx) = mpsc::channel(2);
        let metrics = RuntimeMetrics::new();
        let zone = DomainName::from_absolute_str("example.test.").unwrap();
        let source = "192.0.2.53".parse().unwrap();

        signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(1));
        signal_notify_refresh(&tracker, &refresh_tx, &metrics, &zone, source, Some(1));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.notify_refresh_signalled, 1);
        assert_eq!(snapshot.notify_refresh_deduplicated, 1);
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

    fn current_zone_with_serial(apex: &DomainName, serial: u32) -> ZoneSnapshot {
        let current_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(serial),
        );
        ZoneSnapshot::active(
            apex.clone(),
            Some(serial),
            vec![Rrset::new(
                apex.clone(),
                RecordType::Soa as u16,
                1,
                current_soa.ttl,
                vec![current_soa.rdata],
            )],
        )
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
    async fn tcp_connect_timeout_abandons_pending_connect_attempt() {
        let primary = "192.0.2.53:53".parse().unwrap();
        let error = super::tcp_connect_with_timeout(
            primary,
            std::time::Duration::from_millis(1),
            std::future::pending::<std::io::Result<()>>(),
        )
        .await
        .expect_err("pending TCP connect should time out");

        assert!(matches!(error, TransferError::Timeout { timeout_secs: 0 }));
    }

    #[tokio::test]
    async fn transfer_axfr_enforces_ingestion_size_cap() {
        let primary = spawn_axfr_primary().await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let target = TransferPrimaryConfig::tcp(primary);

        let error = super::transfer_axfr_from_target_with_tsig(
            &target,
            &apex,
            1,
            0x1234,
            TransferSession::new(TransferTsig::unsigned(), 1),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect_err("AXFR transfer should exceed ingest cap");

        assert!(matches!(
            error,
            TransferError::IngestSizeLimit {
                protocol: "AXFR",
                limit_bytes: 1,
                ..
            }
        ));
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
    async fn transfer_ixfr_enforces_ingestion_size_cap() {
        let primary = spawn_ixfr_mode2_primary_with_serial(2).await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_zone = current_zone_with_serial(&apex, 1);
        let target = TransferPrimaryConfig::tcp(primary);

        let error = super::transfer_ixfr_from_target_with_tsig(
            &target,
            &apex,
            1,
            0x1234,
            &current_zone,
            TransferSession::new(TransferTsig::unsigned(), 1),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect_err("IXFR transfer should exceed ingest cap");

        assert!(matches!(
            error,
            TransferError::IngestSizeLimit {
                protocol: "IXFR",
                limit_bytes: 1,
                ..
            }
        ));
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
                    apex.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![ns_rdata_for_zone("example.test.")],
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
    async fn poll_soa_from_primary_ignores_udp_packet_from_unconnected_peer() {
        let primary = spawn_soa_primary_with_spoofed_malformed_packet(7).await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let serial =
            poll_soa_from_primary(primary, &apex, 1, 0x1234, std::time::Duration::from_secs(5))
                .await
                .expect("SOA poll should ignore the unconnected sender");

        assert_eq!(serial, 7);
    }

    #[tokio::test]
    async fn poll_soa_from_primary_records_warning_evidence_for_malformed_response() {
        let primary = spawn_malformed_soa_primary().await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let error =
            poll_soa_from_primary(primary, &apex, 1, 0x1234, std::time::Duration::from_secs(5))
                .await
                .expect_err("malformed SOA poll response should fail");

        assert!(matches!(
            error,
            super::TransferError::Soa(oxidedns_core::axfr::SoaQueryError::MalformedMessage)
        ));
        assert!(captured.contains_all(&[
            "SOA poll response rejected",
            "zone=example.test.",
            &format!("primary={primary}"),
            "qid=4660",
            "SOA response message is malformed",
        ]));
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
            TransferTsig::new(Some(&key), DEFAULT_TSIG_FUDGE_SECS),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("signed SOA poll");

        assert_eq!(serial, 7);
    }

    #[tokio::test]
    async fn soa_poll_binds_configured_transfer_source() {
        let (primary, peer_rx) = spawn_soa_primary_recording_peer(7).await;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let transfer_source = "127.0.0.2:0".parse::<std::net::SocketAddr>().unwrap();

        let serial = super::poll_soa_from_primary_with_tsig_and_source(
            primary,
            &apex,
            1,
            0x1234,
            TransferTsig::unsigned(),
            Some(transfer_source),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("SOA poll");
        let peer = tokio::time::timeout(std::time::Duration::from_secs(1), peer_rx)
            .await
            .expect("primary should observe SOA poll peer")
            .expect("SOA primary should send peer address");
        let expected_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();

        assert_eq!(serial, 7);
        assert_eq!(peer.ip(), expected_ip);
        assert_ne!(peer.port(), 0);
    }

    #[tokio::test]
    async fn concurrent_soa_polls_use_distinct_ephemeral_source_ports() {
        let (primary, peers_rx) = spawn_soa_primary_recording_two_peers(7).await;
        let left_apex = DomainName::from_absolute_str("example.test.").unwrap();
        let right_apex = left_apex.clone();

        let (left, right) = tokio::join!(
            poll_soa_from_primary(
                primary,
                &left_apex,
                1,
                0x1234,
                std::time::Duration::from_secs(5)
            ),
            poll_soa_from_primary(
                primary,
                &right_apex,
                1,
                0x5678,
                std::time::Duration::from_secs(5)
            )
        );

        assert_eq!(left.expect("left SOA poll"), 7);
        assert_eq!(right.expect("right SOA poll"), 7);
        let peers = tokio::time::timeout(std::time::Duration::from_secs(1), peers_rx)
            .await
            .expect("primary should observe both SOA poll peers")
            .expect("SOA primary should send peer addresses");

        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].ip(), peers[1].ip());
        assert_ne!(peers[0].port(), 0);
        assert_ne!(peers[1].port(), 0);
        assert_ne!(peers[0].port(), peers[1].port());
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
            TransferTsig::new(Some(&key), DEFAULT_TSIG_FUDGE_SECS),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect_err("unsigned response must fail");

        assert!(matches!(
            error,
            super::TransferError::Tsig(oxidedns_core::tsig::TsigError::MissingTsig)
        ));
    }

    #[tokio::test]
    async fn axfr_binds_configured_transfer_source() {
        let (primary, peer_rx) = spawn_axfr_primary_recording_peer(7).await;
        let target = TransferPrimaryConfig::tcp(primary);
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let transfer_source = "127.0.0.2:0".parse::<std::net::SocketAddr>().unwrap();

        let snapshot = super::transfer_axfr_from_target_with_tsig_and_source(
            &target,
            &apex,
            1,
            0x1234,
            TransferSession::default_unsigned(),
            Some(transfer_source),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("AXFR transfer");
        let peer = tokio::time::timeout(std::time::Duration::from_secs(1), peer_rx)
            .await
            .expect("primary should observe AXFR peer")
            .expect("AXFR primary should send peer address");
        let expected_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();

        assert_eq!(snapshot.serial, Some(7));
        assert_eq!(peer.ip(), expected_ip);
        assert_ne!(peer.port(), 0);
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
    fn dns_cookie_secret_fingerprint_is_redacted_and_stable() {
        let secret = *b"0123456789abcdef";
        let fingerprint = dns_cookie_secret_fingerprint(&secret);

        assert_eq!(fingerprint.len(), 16);
        assert_eq!(fingerprint, dns_cookie_secret_fingerprint(&secret));
        assert_ne!(fingerprint, "3031323334353637");
    }

    #[test]
    fn dns_cookie_secret_store_rotates_only_after_configured_interval() {
        let generated_at = std::time::Instant::now() - std::time::Duration::from_secs(61);
        let rotating = DnsCookieSecretStore::new_at(
            [1; 16],
            Some(std::time::Duration::from_secs(60)),
            generated_at,
        );
        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let rotated = rotating.current_with_generator(|| Ok([2; 16]));
        let retained = rotating.current_with_generator(|| -> Result<[u8; 16], getrandom::Error> {
            panic!("secret generator should not be called before the next interval")
        });
        let disabled = DnsCookieSecretStore::new_at([3; 16], None, generated_at);

        assert_eq!(rotated, [2; 16]);
        assert_eq!(retained, [2; 16]);
        assert_eq!(disabled.current_with_generator(|| Ok([4; 16])), [3; 16]);
        assert!(
            captured.contains_all(&["DNS Cookie server secret rotated", "secret_fingerprint=",])
        );
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
            Transport::Udp,
            false,
            None,
        );
        observe_query_metrics(
            &query(b"\x03www\x07loading\x04test\x00", RecordType::A as u16, 1),
            &zones,
            &metrics,
            Transport::Udp,
            false,
            None,
        );
        observe_query_metrics(
            &query(b"\x07outside\x04test\x00", RecordType::A as u16, 1),
            &zones,
            &metrics,
            Transport::Udp,
            false,
            None,
        );
        let response = {
            let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
            packet[2] |= 0x80;
            packet
        };
        observe_query_metrics(&response, &zones, &metrics, Transport::Udp, false, None);

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
            Transport::Udp,
            false,
            None,
        );
        let non_query_observation =
            observe_query_metrics(&[0, 1, 2], &zones, &metrics, Transport::Udp, false, None);
        let mut noerror = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        noerror[2] |= 0x80;
        let mut nxdomain = noerror.clone();
        nxdomain[3] |= 3;
        let mut truncated = noerror.clone();
        truncated[2] |= 0x02;
        let mut badvers = noerror.clone();
        badvers[11] = 1;
        badvers.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);
        let mut nsec3_ede = noerror.clone();
        nsec3_ede[11] = 1;
        nsec3_ede.extend_from_slice(&[
            0,
            0,
            41,
            4,
            208,
            0,
            0,
            0,
            0,
            0,
            6,
            0,
            EDNS_EXTENDED_DNS_ERROR_OPTION as u8,
            0,
            2,
            0,
            EDE_UNSUPPORTED_NSEC3_ITERATIONS as u8,
        ]);

        record_query_response_metric(&observation, &noerror, &metrics);
        record_query_response_metric(&observation, &nxdomain, &metrics);
        record_query_response_metric(&observation, &truncated, &metrics);
        record_query_response_metric(&observation, &badvers, &metrics);
        record_query_response_metric(&observation, &nsec3_ede, &metrics);
        record_query_response_metric(&non_query_observation, &truncated, &metrics);

        assert_eq!(metrics.snapshot().queries_truncated, 1);
        assert_eq!(metrics.snapshot().nsec3_iterations_exceed_cap, 1);
        let rcodes = metrics.query_rcode_counts();
        assert_eq!(rcodes.get(&0), Some(&3));
        assert_eq!(rcodes.get(&3), Some(&1));
        assert_eq!(rcodes.get(&16), Some(&1));
        assert_eq!(
            metrics
                .query_latency_histograms()
                .get(&QueryLatencyCategory::UdpDirect)
                .map(QueryLatencyHistogram::count),
            Some(5)
        );
    }

    #[test]
    fn query_metrics_count_zone_response_rcodes_for_configured_zone_only() {
        let zones = ZoneStore::new();
        let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
        zones.insert_snapshot(ZoneSnapshot::active(active_origin, Some(1), Vec::new()));
        let metrics = RuntimeMetrics::new();
        let in_zone = observe_query_metrics(
            &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
            &zones,
            &metrics,
            Transport::Udp,
            false,
            None,
        );
        let outside = observe_query_metrics(
            &query(b"\x07outside\x04test\x00", RecordType::A as u16, 1),
            &zones,
            &metrics,
            Transport::Udp,
            false,
            None,
        );
        let mut noerror = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        noerror[2] |= 0x80;
        let mut nxdomain = noerror.clone();
        nxdomain[3] |= 3;

        record_query_response_metric(&in_zone, &noerror, &metrics);
        record_query_response_metric(&in_zone, &nxdomain, &metrics);
        record_query_response_metric(&outside, &noerror, &metrics);

        let zone_rcodes = metrics.zone_query_rcode_counts();
        let zone_key = DomainName::from_absolute_str("example.test.")
            .unwrap()
            .canonical_key();
        assert_eq!(zone_rcodes.get(&(zone_key.clone(), 0)), Some(&1));
        assert_eq!(zone_rcodes.get(&(zone_key.clone(), 3)), Some(&1));
        assert!(!zone_rcodes.contains_key(&("outside.test.".to_owned(), 0)));
    }

    #[test]
    fn dns_cookie_prefix_metrics_use_rrl_prefixes_and_evict_at_cap() {
        let metrics =
            RuntimeMetrics::new_with_settings(1, DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(), false);
        let prefix_settings = cookie_prefix_metrics_for_test();

        metrics.record_dns_cookie_status(
            DnsCookieRequestStatus::ClientCookieOnly,
            "192.0.2.10".parse().unwrap(),
            prefix_settings,
        );
        metrics
            .record_dns_cookie_badcookie_for_source("192.0.2.10".parse().unwrap(), prefix_settings);
        metrics.record_dns_cookie_status(
            DnsCookieRequestStatus::ValidServerCookie,
            "198.51.100.25".parse().unwrap(),
            prefix_settings,
        );

        let samples = metrics.dns_cookie_prefix_counts();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].0.to_string(), "198.51.100.0/24");
        assert_eq!(samples[0].1.valid_server, 1);
    }

    #[test]
    fn query_metrics_count_cname_termination_causes_for_queries_only() {
        let metrics = RuntimeMetrics::new();
        let observation = QueryMetricObservation {
            is_query: true,
            transport: Transport::Udp,
            started_at: std::time::Instant::now(),
            cookie_validated: false,
            zone_key: None,
            parse_duration: None,
            lookup_duration: None,
            compose_duration: None,
        };
        let non_query_observation = QueryMetricObservation {
            is_query: false,
            transport: Transport::Udp,
            started_at: std::time::Instant::now(),
            cookie_validated: false,
            zone_key: None,
            parse_duration: None,
            lookup_duration: None,
            compose_duration: None,
        };
        let chain_limit = oxidedns_core::dns::LookupResult::positive_records_with_termination(
            Vec::new(),
            LookupTermination::CnameChainLimit,
        );
        let loop_detected = oxidedns_core::dns::LookupResult::positive_records_with_termination(
            Vec::new(),
            LookupTermination::CnameLoop,
        );

        record_query_termination_metric(&observation, &chain_limit, &metrics);
        record_query_termination_metric(&observation, &loop_detected, &metrics);
        record_query_termination_metric(&non_query_observation, &chain_limit, &metrics);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.queries_cname_chain_limit, 1);
        assert_eq!(snapshot.queries_cname_loop, 1);
    }

    #[test]
    fn query_latency_histogram_uses_configured_buckets() {
        let zones = ZoneStore::new();
        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        );
        let metrics = RuntimeMetrics::new_with_settings(
            DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
            vec![0.001, 0.01],
            false,
        );

        metrics.record_query_latency(
            QueryLatencyCategory::UdpDirect,
            std::time::Duration::from_micros(1_500),
        );

        let body = metrics_body(
            &zones,
            &metrics,
            &CatalogManager::default(),
            &refresh_registry,
            0,
            false,
        );

        assert!(body.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"udp_direct\",le=\"0.001\"} 0"
        ));
        assert!(body.contains(
            "oxidedns_secondary_query_duration_seconds_bucket{query_category=\"udp_direct\",le=\"0.01\"} 1"
        ));
        assert!(!body.contains("le=\"0.00025\""));
    }

    #[test]
    fn opt_in_pipeline_metrics_report_cache_planning_counters() {
        let zones = ZoneStore::new();
        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        );
        let metrics = RuntimeMetrics::new_with_settings(
            DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
            vec![0.001, 0.01],
            true,
        );

        metrics.record_query_pipeline_latency(
            QueryPipelineStage::Compose,
            QueryLatencyCategory::UdpDirect,
            std::time::Duration::from_micros(1_500),
        );
        metrics.record_response_cache_candidate(ResponseCacheCandidateCategory::Direct);
        metrics.record_response_cache_ineligible(ResponseCacheIneligibleReason::Cookie);

        let body = metrics_body(
            &zones,
            &metrics,
            &CatalogManager::default(),
            &refresh_registry,
            0,
            false,
        );

        assert!(body.contains(
            "oxidedns_query_pipeline_duration_seconds_bucket{stage=\"compose\",query_category=\"udp_direct\",le=\"0.001\"} 0"
        ));
        assert!(body.contains(
            "oxidedns_query_pipeline_duration_seconds_bucket{stage=\"compose\",query_category=\"udp_direct\",le=\"0.01\"} 1"
        ));
        assert!(body.contains("oxidedns_response_cache_candidate_total{category=\"direct\"} 1"));
        assert!(body.contains("oxidedns_response_cache_ineligible_total{reason=\"cookie\"} 1"));
    }

    #[test]
    fn pipeline_metrics_are_absent_by_default() {
        let zones = ZoneStore::new();
        let refresh_registry = ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        );
        let metrics = RuntimeMetrics::new();

        metrics.record_response_cache_candidate(ResponseCacheCandidateCategory::Direct);
        let body = metrics_body(
            &zones,
            &metrics,
            &CatalogManager::default(),
            &refresh_registry,
            0,
            false,
        );

        assert!(!body.contains("oxidedns_query_pipeline_duration_seconds"));
        assert!(!body.contains("oxidedns_response_cache_candidate_total"));
    }

    #[test]
    fn rrl_limiter_slips_udp_query_responses() {
        let config = RrlConfig {
            positive_per_second: 1,
            slip: 2,
            ..RrlConfig::default()
        };
        let metrics = RuntimeMetrics::new();
        let limiter = RrlLimiter::from_config(&config, metrics.clone());
        let source = "192.0.2.1".parse().unwrap();
        let response = positive_query_response();

        assert!(matches!(
            limiter.apply(source, response.clone()),
            RrlDecision::Send(_)
        ));
        assert!(matches!(
            limiter.apply(source, response.clone()),
            RrlDecision::Drop
        ));
        let RrlDecision::Send(truncated) = limiter.apply(source, response) else {
            panic!("third limited response should slip as TC=1");
        };

        let header = Header::parse(&truncated).unwrap();
        assert_ne!(header.flags & 0x0200, 0);
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 0);
        assert_eq!(header.nscount, 0);
        assert_eq!(header.arcount, 0);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.rrl_subject, 3);
        assert_eq!(snapshot.rrl_dropped, 1);
        assert_eq!(snapshot.rrl_truncated, 1);
        assert_eq!(snapshot.rrl_tracked_keys, 1);
    }

    #[test]
    fn rrl_periodic_summary_reports_aggregate_deltas() {
        let config = RrlConfig {
            positive_per_second: 0,
            slip: 2,
            ..RrlConfig::default()
        };
        let metrics = RuntimeMetrics::new();
        let limiter = RrlLimiter::from_config(&config, metrics.clone());
        let previous = metrics.snapshot();
        let source = "192.0.2.1".parse().unwrap();

        assert!(matches!(
            limiter.apply(source, positive_query_response()),
            RrlDecision::Drop
        ));
        assert!(matches!(
            limiter.apply(source, positive_query_response()),
            RrlDecision::Send(_)
        ));

        let summary = RrlSummary::from_snapshots(
            previous,
            metrics.snapshot(),
            limiter.rate_limited_key_count(),
        );
        assert_eq!(
            summary,
            RrlSummary {
                dropped_responses: 1,
                truncated_responses: 1,
                rate_limited_keys: 1,
                total_dropped_responses: 1,
                total_truncated_responses: 1,
            }
        );

        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        log_rrl_summary(summary, std::time::Duration::from_secs(60));

        assert!(captured.contains_all(&[
            "RRL periodic summary",
            "category=\"rrl\"",
            "event=\"rrl_periodic_summary\"",
            "dropped_responses=1",
            "truncated_responses=1",
            "rate_limited_keys=1",
        ]));
    }

    #[test]
    fn rrl_allowlist_exempts_sources_from_accounting() {
        let config = RrlConfig {
            positive_per_second: 0,
            allowlist: vec!["192.0.2.0/24".to_owned()],
            ..RrlConfig::default()
        };
        let metrics = RuntimeMetrics::new();
        let limiter = RrlLimiter::from_config(&config, metrics.clone());
        let source = "192.0.2.99".parse().unwrap();

        assert!(matches!(
            limiter.apply(source, positive_query_response()),
            RrlDecision::Send(_)
        ));
        assert!(matches!(
            limiter.apply(source, positive_query_response()),
            RrlDecision::Send(_)
        ));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.rrl_subject, 0);
        assert_eq!(snapshot.rrl_dropped, 0);
        assert_eq!(snapshot.rrl_tracked_keys, 0);
    }

    #[test]
    fn notify_log_limiter_suppresses_repeats_and_summarizes() {
        let limiter = NotifyLogLimiter::new(std::time::Duration::from_secs(60));
        let zone = DomainName::from_absolute_str("example.test.").unwrap();
        let source = "192.0.2.10".parse().unwrap();
        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        limiter.log_unauthorized(source, &zone);
        limiter.log_unauthorized(source, &zone);
        limiter.log_tsig_failure(source, &zone, &TsigError::MissingTsig);
        limiter.log_tsig_failure(source, &zone, &TsigError::MissingTsig);

        assert!(captured.contains_all(&[
            "unauthorized NOTIFY discarded",
            "category=\"notify\"",
            "event=\"notify_unauthorized_discard\"",
            "peer_ip=192.0.2.10",
            "source_prefix=192.0.2.0/24",
            "zone=example.test.",
        ]));
        assert!(captured.contains_all(&[
            "rejected NOTIFY with invalid TSIG",
            "category=\"notify\"",
            "event=\"notify_tsig_failure\"",
            "peer_ip=192.0.2.10",
            "source_prefix=192.0.2.0/24",
            "zone=example.test.",
        ]));

        let summary = limiter.take_summary();
        assert_eq!(
            summary,
            NotifyLogSummary {
                suppressed_unauthorized: 1,
                suppressed_tsig_failures: 1,
                distinct_source_prefixes: 1,
                total_suppressed: 2,
            }
        );
        log_notify_log_summary(summary, std::time::Duration::from_secs(60));
        assert!(captured.contains_all(&[
            "NOTIFY log rate-limit summary",
            "category=\"notify\"",
            "event=\"notify_log_rate_limit_summary\"",
            "suppressed_unauthorized=1",
            "suppressed_tsig_failures=1",
            "distinct_source_prefixes=1",
            "total_suppressed=2",
        ]));
    }

    #[test]
    fn rrl_limiter_evicts_least_recent_key_at_capacity() {
        let config = RrlConfig {
            positive_per_second: 0,
            slip: 0,
            max_keys: 1,
            ipv4_prefix_len: 32,
            ..RrlConfig::default()
        };
        let metrics = RuntimeMetrics::new();
        let limiter = RrlLimiter::from_config(&config, metrics.clone());

        assert!(matches!(
            limiter.apply("192.0.2.1".parse().unwrap(), positive_query_response()),
            RrlDecision::Drop
        ));
        assert!(matches!(
            limiter.apply("192.0.2.2".parse().unwrap(), positive_query_response()),
            RrlDecision::Drop
        ));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.rrl_subject, 2);
        assert_eq!(snapshot.rrl_dropped, 2);
        assert_eq!(snapshot.rrl_key_evictions, 1);
        assert_eq!(snapshot.rrl_tracked_keys, 1);
    }

    #[test]
    fn rrl_response_categories_follow_srs_buckets() {
        assert_eq!(
            response_category(&positive_query_response()),
            Some(RrlCategory::Positive)
        );
        assert_eq!(
            response_category(&rcode_query_response(3)),
            Some(RrlCategory::NxDomain)
        );
        assert_eq!(
            response_category(&rcode_query_response(0)),
            Some(RrlCategory::NoData)
        );
        assert_eq!(
            response_category(&referral_query_response()),
            Some(RrlCategory::Referral)
        );
        assert_eq!(
            response_category(&rcode_query_response(2)),
            Some(RrlCategory::Error)
        );
        assert_eq!(response_category(&notify_response(0x1234)), None);
    }

    #[test]
    fn rrl_truncated_response_preserves_question_and_opt() {
        let response = query_response_with_opt();
        let truncated = rrl_truncated_response(&response);

        let original_header = Header::parse(&response).unwrap();
        let original_question_end = response_question_end(&response, &original_header).unwrap();
        assert_eq!(
            &truncated[12..original_question_end],
            &response[12..original_question_end]
        );
        let header = Header::parse(&truncated).unwrap();
        assert_ne!(header.flags & 0x0200, 0);
        assert_eq!(header.ancount, 0);
        assert_eq!(header.nscount, 0);
        assert_eq!(header.arcount, 1);
        assert_eq!(
            response_opt_record(&truncated, &header),
            response_opt_record(&response, &original_header)
        );
    }

    #[tokio::test]
    async fn udp_query_records_cname_chain_limit_metric() {
        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
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
                metrics: server_metrics,
                rrl: RrlLimiter::from_config(&RrlConfig::default(), metrics.clone()),
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

        let header = Header::parse(&response[..len]).unwrap();
        assert_eq!(
            response_rcode(&response[..len], &header),
            Rcode::ServFail as u16
        );
        assert_ne!(header.flags & 0x0400, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
        assert!(len > 12);
        assert!(captured.contains_all(&[
            "CNAME chain limit reached",
            "qname=a.example.test.",
            "zone=example.test.",
            "reason=\"cname_chain_limit\"",
        ]));
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.queries_received, 1);
        assert_eq!(snapshot.queries_cname_chain_limit, 1);
        assert_eq!(snapshot.queries_cname_loop, 0);
    }

    #[test]
    fn cname_loop_warning_log_contains_operator_fields() {
        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        let zone = ZoneSnapshot::active(
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
                        DomainName::from_absolute_str("a.example.test.")
                            .unwrap()
                            .to_wire(),
                    ],
                ),
            ],
        );

        let lookup = zone.lookup(
            &DomainName::from_absolute_str("a.example.test.").unwrap(),
            RecordType::A as u16,
            1,
        );

        assert_eq!(lookup.rcode, Rcode::ServFail);
        assert_eq!(lookup.termination, Some(LookupTermination::CnameLoop));
        assert!(captured.contains_all(&[
            "CNAME chain loop detected",
            "qname=a.example.test.",
            "zone=example.test.",
            "reason=\"cname_loop\"",
            "looping_target=a.example.test.",
        ]));
    }

    #[tokio::test]
    async fn udp_rrl_slips_and_drops_limited_query_responses() {
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
        let metrics = RuntimeMetrics::new();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let rrl_config = RrlConfig {
            positive_per_second: 1,
            slip: 2,
            ..RrlConfig::default()
        };
        let server_metrics = metrics.clone();
        let server = tokio::spawn(serve_udp(
            socket,
            zones,
            UdpServerSettings {
                max_udp_payload: 1232,
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
                metrics: server_metrics,
                rrl: RrlLimiter::from_config(&rrl_config, metrics.clone()),
            },
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);

        client.send_to(&query, server_addr).await.unwrap();
        let first = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("first response");
        client.send_to(&query, server_addr).await.unwrap();
        let dropped = recv_udp_with_timeout(&client, std::time::Duration::from_millis(50)).await;
        client.send_to(&query, server_addr).await.unwrap();
        let slipped = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("slipped truncated response");
        server.abort();

        assert_eq!(Header::parse(&first).unwrap().ancount, 1);
        assert!(dropped.is_none());
        let slipped_header = Header::parse(&slipped).unwrap();
        assert_ne!(slipped_header.flags & 0x0200, 0);
        assert_eq!(slipped_header.ancount, 0);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.rrl_subject, 3);
        assert_eq!(snapshot.rrl_dropped, 1);
        assert_eq!(snapshot.rrl_truncated, 1);
        assert_eq!(snapshot.queries_truncated, 1);
    }

    #[tokio::test]
    async fn udp_tsig_authenticated_query_bypasses_rrl_and_signs_response() {
        let zones = active_example_zone();
        let metrics = RuntimeMetrics::new();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let rrl_config = RrlConfig {
            positive_per_second: 0,
            slip: 0,
            ..RrlConfig::default()
        };
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[tsig_keys]]
                name = "query-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
                tsig_key = "query-key."
            "#,
        )
        .unwrap();
        let key = TsigKey::from_base64("query-key.", "hmac-sha256", "dG9wc2VjcmV0").unwrap();
        let signed_query = key
            .sign_request(
                &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
                current_unix_time(),
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        let server_metrics = metrics.clone();
        let server = tokio::spawn(serve_udp(
            socket,
            zones,
            UdpServerSettings {
                max_udp_payload: 1232,
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
                notify_authority: NotifyAuthority::from_config(&config),
                notify_refresh: NotifyRefreshTracker::new(std::time::Duration::from_secs(1)),
                notify_refresh_tx: notify_refresh_tx(),
                notify_log_limiter: notify_log_limiter_for_test(),
                metrics: server_metrics,
                rrl: RrlLimiter::from_config(&rrl_config, metrics.clone()),
            },
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&signed_query.message, server_addr)
            .await
            .unwrap();
        let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("signed UDP response");
        server.abort();

        let verified = key
            .verify_response(&response, &signed_query.mac, current_unix_time())
            .expect("signed UDP query response verifies");
        let header = Header::parse(&verified.message).unwrap();
        assert_eq!(
            response_rcode(&verified.message, &header),
            Rcode::NoError as u16
        );
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.queries_received, 1);
        assert_eq!(snapshot.rrl_subject, 0);
        assert_eq!(snapshot.rrl_dropped, 0);
    }

    #[tokio::test]
    async fn udp_dns_cookie_client_cookie_only_returns_cookie_option() {
        let zones = active_example_zone();
        let metrics = RuntimeMetrics::new();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let server = tokio::spawn(serve_udp(
            socket,
            zones,
            udp_settings_for_test(metrics.clone(), RrlConfig::default()),
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = cookie_query(&[1, 2, 3, 4, 5, 6, 7, 8]);

        client.send_to(&request, server_addr).await.unwrap();
        let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("cookie response");
        server.abort();

        let cookie = response_cookie_option(&response).expect("COOKIE response option");
        assert_eq!(&cookie[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(cookie.len(), 24);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.dns_cookie_client_only, 1);
        assert_eq!(snapshot.dns_cookie_badcookie, 0);
    }

    #[tokio::test]
    async fn udp_strict_dns_cookie_policy_returns_badcookie_for_client_cookie_only() {
        let zones = active_example_zone();
        let metrics = RuntimeMetrics::new();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let mut settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
        settings.dns_cookie = dns_cookie_settings_for_test(DnsCookiePolicy::Strict);
        let server = tokio::spawn(serve_udp(socket, zones, settings));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = cookie_query(&[1, 2, 3, 4, 5, 6, 7, 8]);

        client.send_to(&request, server_addr).await.unwrap();
        let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("BADCOOKIE response");
        server.abort();

        let header = Header::parse(&response).unwrap();
        assert_eq!(response_rcode(&response, &header), Rcode::BadCookie as u16);
        assert_eq!(header.ancount, 0);
        assert!(response_cookie_option(&response).is_some());
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.dns_cookie_client_only, 1);
        assert_eq!(snapshot.dns_cookie_badcookie, 1);
    }

    #[tokio::test]
    async fn udp_valid_dns_cookie_bypasses_rrl_accounting() {
        let zones = active_example_zone();
        let metrics = RuntimeMetrics::new();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let rrl_config = RrlConfig {
            positive_per_second: 1,
            slip: 2,
            ..RrlConfig::default()
        };
        let server = tokio::spawn(serve_udp(
            socket,
            zones,
            udp_settings_for_test(metrics.clone(), rrl_config),
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let learning_query = cookie_query(&[1, 2, 3, 4, 5, 6, 7, 8]);

        client.send_to(&learning_query, server_addr).await.unwrap();
        let learned = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("learning response");
        let valid_cookie = response_cookie_option(&learned).expect("learned cookie");
        let valid_query = cookie_query(&valid_cookie);

        for _ in 0..3 {
            client.send_to(&valid_query, server_addr).await.unwrap();
            let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
                .await
                .expect("valid-cookie response should not be RRL dropped");
            assert_eq!(Header::parse(&response).unwrap().ancount, 1);
        }
        server.abort();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.rrl_subject, 1);
        assert_eq!(snapshot.rrl_dropped, 0);
        assert_eq!(snapshot.rrl_truncated, 0);
        assert_eq!(snapshot.dns_cookie_client_only, 1);
        assert_eq!(snapshot.dns_cookie_valid_server, 3);
    }

    #[tokio::test]
    async fn udp_invalid_dns_cookie_remains_rrl_subject() {
        let zones = active_example_zone();
        let metrics = RuntimeMetrics::new();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let rrl_config = RrlConfig {
            positive_per_second: 1,
            slip: 2,
            ..RrlConfig::default()
        };
        let server = tokio::spawn(serve_udp(
            socket,
            zones,
            udp_settings_for_test(metrics.clone(), rrl_config),
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut invalid_cookie = vec![1, 2, 3, 4, 5, 6, 7, 8];
        invalid_cookie.extend_from_slice(&[0; 16]);
        let invalid_query = cookie_query(&invalid_cookie);

        client.send_to(&invalid_query, server_addr).await.unwrap();
        let first = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("first invalid-cookie response");
        client.send_to(&invalid_query, server_addr).await.unwrap();
        let second = recv_udp_with_timeout(&client, std::time::Duration::from_millis(50)).await;
        server.abort();

        assert_eq!(Header::parse(&first).unwrap().ancount, 1);
        assert!(second.is_none());
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.rrl_subject, 2);
        assert_eq!(snapshot.rrl_dropped, 1);
        assert_eq!(snapshot.dns_cookie_invalid_server, 2);
        assert_eq!(snapshot.dns_cookie_badcookie, 0);
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
    fn refresh_registry_clamps_soa_intervals_to_configured_bounds() {
        let registry = ZoneRefreshRegistry::without_jitter_with_max(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(1_000),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(180),
            std::time::Duration::from_secs(3600),
        );
        let now = std::time::Instant::now();
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let mut snapshot = ZoneSnapshot::active(
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
        snapshot.soa_timers = Some(SoaTimers {
            refresh: 10_000,
            retry: 10_000,
            expire: 86_400,
            minimum: 300,
        });

        registry.record_success_at_with_timestamp(&snapshot, now, 1_700_000_000);
        let status = registry
            .snapshots_by_zone()
            .remove(&origin.canonical_key())
            .expect("zone refresh status");
        assert_eq!(status.next_refresh_unix_secs, Some(1_700_001_000));

        registry.record_failure_at_with_timestamp(
            &origin,
            Some(Arc::new(snapshot)),
            now + std::time::Duration::from_secs(1_000),
            1_700_001_000,
        );
        let status = registry
            .snapshots_by_zone()
            .remove(&origin.canonical_key())
            .expect("zone refresh status");
        assert_eq!(status.next_refresh_unix_secs, Some(1_700_002_000));
        assert_eq!(status.failures_since_success, 1);
    }

    #[test]
    fn refresh_registry_warns_when_soa_timers_approach_maximum_effective_interval() {
        let registry = ZoneRefreshRegistry::without_jitter_with_max(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(1_000),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(180),
            std::time::Duration::from_secs(3600),
        );
        let now = std::time::Instant::now();
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let mut snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(1),
            vec![Rrset::new(
                origin,
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            )],
        );
        snapshot.soa_timers = Some(SoaTimers {
            refresh: 900,
            retry: 1_500,
            expire: 86_400,
            minimum: 300,
        });
        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        registry.record_success_at_with_timestamp(&snapshot, now, 1_700_000_000);

        assert!(captured.contains_all(&[
            "SOA timer approaches configured maximum effective ZSM interval",
            "category=\"configuration_warning\"",
            "code=\"soa_timer_near_max_effective_interval\"",
            "zone=example.test.",
            "soa_field=\"refresh\"",
            "soa_value_secs=900",
            "max_effective_secs=1000",
            "threshold_percent=90",
        ]));
        assert!(captured.contains_all(&[
            "SOA timer approaches configured maximum effective ZSM interval",
            "category=\"configuration_warning\"",
            "code=\"soa_timer_near_max_effective_interval\"",
            "zone=example.test.",
            "soa_field=\"retry\"",
            "soa_value_secs=1500",
            "max_effective_secs=1000",
            "threshold_percent=90",
        ]));
    }

    #[test]
    fn refresh_registry_emits_repeated_long_loading_warnings() {
        let registry = ZoneRefreshRegistry::without_jitter_with_max(
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(86_400),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(300),
        );
        let zones = ZoneStore::new();
        let now = std::time::Instant::now();
        let origin = DomainName::from_absolute_str("loading.test.").unwrap();
        zones.insert_loading(origin.clone());

        registry.record_loading_start_at(&origin, now);
        assert!(
            registry
                .loading_warnings_due(&zones, now + std::time::Duration::from_secs(299))
                .is_empty()
        );

        registry.record_failure_at_with_timestamp_and_cause(
            &origin,
            None,
            Some("AXFR failed for primary 192.0.2.53:53: timeout".to_owned()),
            now + std::time::Duration::from_secs(60),
            1_700_000_000,
        );
        let warnings =
            registry.loading_warnings_due(&zones, now + std::time::Duration::from_secs(300));
        assert_eq!(
            warnings,
            vec![LoadingWarning {
                zone: origin.clone(),
                elapsed_loading_secs: 300,
                last_failure_cause: "AXFR failed for primary 192.0.2.53:53: timeout".to_owned(),
                next_retry_unix_secs: Some(1_700_000_060),
            }]
        );
        assert!(
            registry
                .loading_warnings_due(&zones, now + std::time::Duration::from_secs(300))
                .is_empty()
        );

        let warnings =
            registry.loading_warnings_due(&zones, now + std::time::Duration::from_secs(600));
        assert_eq!(
            warnings,
            vec![LoadingWarning {
                zone: origin,
                elapsed_loading_secs: 600,
                last_failure_cause: "AXFR failed for primary 192.0.2.53:53: timeout".to_owned(),
                next_retry_unix_secs: Some(1_700_000_060),
            }]
        );
    }

    #[test]
    fn refresh_registry_does_not_warn_for_active_refresh_failures() {
        let registry = ZoneRefreshRegistry::without_jitter_with_max(
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(86_400),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(300),
        );
        let zones = ZoneStore::new();
        let now = std::time::Instant::now();
        let origin = DomainName::from_absolute_str("active.test.").unwrap();
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

        registry.record_success_at(&snapshot, now);
        registry.record_failure_at_with_timestamp_and_cause(
            &origin,
            Some(Arc::new(snapshot)),
            Some("AXFR failed for primary 192.0.2.53:53: timeout".to_owned()),
            now + std::time::Duration::from_secs(60),
            1_700_000_000,
        );

        assert!(
            registry
                .loading_warnings_due(&zones, now + std::time::Duration::from_secs(3600))
                .is_empty()
        );
    }

    #[test]
    fn long_loading_warning_log_contains_operator_fields() {
        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        log_loading_warning(LoadingWarning {
            zone: DomainName::from_absolute_str("example.test.").unwrap(),
            elapsed_loading_secs: 3600,
            last_failure_cause: "AXFR failed for primary 192.0.2.53:53: timed out".to_owned(),
            next_retry_unix_secs: Some(1_700_003_600),
        });

        assert!(
            captured.contains_all(&[
                "zone remains in LOADING state beyond configured threshold",
                "category=\"transfer\"",
                "event=\"zone_loading_threshold_exceeded\"",
                "zone=example.test.",
                "elapsed_loading_secs=3600",
                "error=AXFR failed for primary 192.0.2.53:53: timed out",
                "next_retry_unix_secs=Some(1700003600)",
            ]),
            "{:?}",
            captured
                .lines
                .lock()
                .expect("captured events lock poisoned")
        );
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
                listen_tcp = []

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
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
            CatalogRuntime {
                manager: CatalogManager::from_config(&config),
                transfer_plan,
                refresh_registry: ZoneRefreshRegistry::without_jitter(
                    std::time::Duration::ZERO,
                    std::time::Duration::ZERO,
                    std::time::Duration::ZERO,
                ),
                notify_authority: NotifyAuthority::from_config(&config),
                refresh_tx: mpsc::channel(1).0.downgrade(),
            },
            IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
            metrics.clone(),
            RefreshWorkerSettings {
                axfr_timeout: std::time::Duration::from_secs(5),
                ixfr_timeout: std::time::Duration::from_secs(5),
                tcp_connect_timeout: std::time::Duration::from_secs(5),
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
                ..Default::default()
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
                listen_tcp = []

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
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
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
            CatalogRuntime {
                manager: CatalogManager::from_config(&config),
                transfer_plan,
                refresh_registry: ZoneRefreshRegistry::without_jitter(
                    std::time::Duration::ZERO,
                    std::time::Duration::ZERO,
                    std::time::Duration::ZERO,
                ),
                notify_authority: NotifyAuthority::from_config(&config),
                refresh_tx: mpsc::channel(1).0.downgrade(),
            },
            IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
            RuntimeMetrics::new(),
            RefreshWorkerSettings {
                axfr_timeout: std::time::Duration::from_secs(5),
                ixfr_timeout: std::time::Duration::from_secs(5),
                tcp_connect_timeout: std::time::Duration::from_secs(5),
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
        let (primary, peer_rx) = spawn_soa_primary_recording_peer(2).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [interfaces]
                transfer = ["127.0.0.2:0"]

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
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
                tcp_connect_timeout: std::time::Duration::from_secs(5),
                reason: "test",
            },
        )
        .await
        .expect("refresh success");
        let peer = tokio::time::timeout(std::time::Duration::from_secs(1), peer_rx)
            .await
            .expect("primary should observe SOA poll peer")
            .expect("SOA primary should send peer address");
        let expected_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();

        assert_eq!(snapshot.serial, Some(2));
        assert_eq!(peer.ip(), expected_ip);
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
                listen_tcp = []

                [tsig]
                fudge_seconds = 30

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
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        assert!(plan.tsig_key.is_some());
        assert_eq!(plan.tsig_fudge_seconds, 30);
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
                tcp_connect_timeout: std::time::Duration::from_secs(5),
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
        assert_eq!(query_tsig_fudge(&query), 30);
    }

    #[tokio::test]
    async fn refresh_xot_transfer_also_uses_tsig_when_configured() {
        let (primary, trust_anchor, observed_query) =
            spawn_xot_axfr_primary_recording_query(1).await;
        let config = ServerConfig::from_toml_str(&format!(
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
                tsig_key = "transfer-key."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        assert!(plan.tsig_key.is_some());
        assert_eq!(plan.primaries[0].transport, TransferTransportConfig::Xot);
        let zones = ZoneStore::new();
        zones.insert_loading(apex);
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
                tcp_connect_timeout: std::time::Duration::from_secs(5),
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
    async fn xot_transfer_logs_tls_session_establishment_and_close() {
        let (primary, trust_anchor) = spawn_xot_axfr_primary_with_serial(1).await;
        let target = TransferPrimaryConfig {
            addr: primary,
            transport: TransferTransportConfig::Xot,
            server_name: Some("primary.example.test".to_owned()),
            trust_anchors: vec![trust_anchor],
            client_cert: None,
            client_key: None,
            client_key_pem: None,
        };
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let snapshot = super::transfer_axfr_from_target_with_tsig(
            &target,
            &apex,
            1,
            0x1234,
            TransferSession::default_unsigned(),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("XoT AXFR should succeed");

        assert_eq!(snapshot.serial, Some(1));
        assert!(captured.contains_all(&[
            "XoT TLS session established",
            "category=\"xot\"",
            "event=\"xot_tls_session_established\"",
            &format!("primary={primary}"),
            "peer_ip=127.0.0.1",
            "sni=primary.example.test",
            "tls_version=TLSv1_",
            "cipher_suite=TLS",
        ]));
        assert!(captured.contains_all(&[
            "XoT TLS session closed",
            "category=\"xot\"",
            "event=\"xot_tls_session_closed\"",
            &format!("primary={primary}"),
            "peer_ip=127.0.0.1",
            "sni=primary.example.test",
            "duration_ms=",
            "bytes=",
            "bytes_in=",
            "bytes_out=",
        ]));
    }

    #[tokio::test]
    async fn refresh_xot_handshake_failure_does_not_retry_cleartext() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary = listener.local_addr().unwrap();
        let (accepted_tx, mut accepted_rx) = mpsc::channel(2);
        let accept_task = tokio::spawn(async move {
            for _ in 0..2 {
                if listener.accept().await.is_ok() {
                    let _ = accepted_tx.send(()).await;
                }
            }
        });
        let (trust_anchor, _key_path) = write_self_signed_xot_cert_files();
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
            trust_anchor.display()
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        let zones = ZoneStore::new();
        zones.insert_loading(apex);
        let metrics = RuntimeMetrics::new();
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

        let snapshot = refresh_zone_from_primaries(
            &zones,
            &plan,
            None,
            RefreshAttemptContext {
                ixfr_cooldowns: &ixfr_cooldowns,
                metrics: &metrics,
                ixfr_timeout: std::time::Duration::from_millis(50),
                axfr_timeout: std::time::Duration::from_millis(50),
                tcp_connect_timeout: std::time::Duration::from_millis(50),
                reason: "test",
            },
        )
        .await;

        assert!(snapshot.is_none());
        accepted_rx
            .recv()
            .await
            .expect("XoT should attempt one TLS connection");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), accepted_rx.recv())
                .await
                .is_err(),
            "XoT failure must not be retried as cleartext TCP"
        );
        accept_task.abort();
    }

    #[tokio::test]
    async fn refresh_xot_rejects_certificate_name_mismatch_before_query() {
        let (primary, trust_anchor, mut query_seen) =
            spawn_xot_primary_detecting_query("other.example.test", true).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        let zones = ZoneStore::new();
        zones.insert_loading(apex);
        let metrics = RuntimeMetrics::new();
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

        let snapshot = refresh_zone_from_primaries(
            &zones,
            &plan,
            None,
            RefreshAttemptContext {
                ixfr_cooldowns: &ixfr_cooldowns,
                metrics: &metrics,
                ixfr_timeout: std::time::Duration::from_millis(100),
                axfr_timeout: std::time::Duration::from_millis(100),
                tcp_connect_timeout: std::time::Duration::from_millis(100),
                reason: "test",
            },
        )
        .await;

        assert!(snapshot.is_none());
        let query_result =
            tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
        assert!(
            !matches!(query_result, Ok(Some(()))),
            "certificate name mismatch must abort before sending a DNS transfer query"
        );
        assert_eq!(metrics.snapshot().axfr_failed, 1);
    }

    #[tokio::test]
    async fn refresh_xot_rejects_missing_dot_alpn_before_query() {
        let (primary, trust_anchor, mut query_seen) =
            spawn_xot_primary_detecting_query("primary.example.test", false).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        let zones = ZoneStore::new();
        zones.insert_loading(apex);
        let metrics = RuntimeMetrics::new();
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
        let captured = CapturedEvents::new();
        let subscriber = CapturingSubscriber::new(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let snapshot = refresh_zone_from_primaries(
            &zones,
            &plan,
            None,
            RefreshAttemptContext {
                ixfr_cooldowns: &ixfr_cooldowns,
                metrics: &metrics,
                ixfr_timeout: std::time::Duration::from_millis(100),
                axfr_timeout: std::time::Duration::from_millis(100),
                tcp_connect_timeout: std::time::Duration::from_millis(100),
                reason: "test",
            },
        )
        .await;

        assert!(snapshot.is_none());
        let query_result =
            tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
        assert!(
            !matches!(query_result, Ok(Some(()))),
            "missing ALPN dot must abort before sending a DNS transfer query"
        );
        assert_eq!(metrics.snapshot().axfr_failed, 1);
        assert!(captured.contains_all(&[
            "XoT ALPN negotiation failed",
            "category=\"xot\"",
            "event=\"xot_alpn_negotiation_failed\"",
            &format!("primary={primary}"),
            "peer_ip=127.0.0.1",
            "sni=primary.example.test",
            "error=\"missing negotiated dot ALPN\"",
        ]));
    }

    #[tokio::test]
    async fn refresh_xot_rejects_untrusted_certificate_before_query() {
        let (cert_path, key_path) =
            write_self_signed_xot_cert_files_for_name("primary.example.test");
        let (untrusted_anchor, _untrusted_key) =
            write_self_signed_xot_cert_files_for_name("untrusted.example.test");
        let (primary, mut query_seen) =
            spawn_xot_primary_detecting_query_with_cert_files(&cert_path, &key_path, true).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
            untrusted_anchor.display()
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        let zones = ZoneStore::new();
        zones.insert_loading(apex);
        let metrics = RuntimeMetrics::new();
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

        let snapshot = refresh_zone_from_primaries(
            &zones,
            &plan,
            None,
            RefreshAttemptContext {
                ixfr_cooldowns: &ixfr_cooldowns,
                metrics: &metrics,
                ixfr_timeout: std::time::Duration::from_millis(100),
                axfr_timeout: std::time::Duration::from_millis(100),
                tcp_connect_timeout: std::time::Duration::from_millis(100),
                reason: "test",
            },
        )
        .await;

        assert!(snapshot.is_none());
        let query_result =
            tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
        assert!(
            !matches!(query_result, Ok(Some(()))),
            "untrusted XoT certificate must abort before sending a DNS transfer query"
        );
        assert_eq!(metrics.snapshot().axfr_failed, 1);
    }

    #[tokio::test]
    async fn refresh_xot_rejects_expired_certificate_before_query() {
        let (cert_path, key_path) =
            write_expired_self_signed_xot_cert_files_for_name("primary.example.test");
        let (primary, mut query_seen) =
            spawn_xot_primary_detecting_query_with_cert_files(&cert_path, &key_path, true).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
            cert_path.display()
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        let zones = ZoneStore::new();
        zones.insert_loading(apex);
        let metrics = RuntimeMetrics::new();
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

        let snapshot = refresh_zone_from_primaries(
            &zones,
            &plan,
            None,
            RefreshAttemptContext {
                ixfr_cooldowns: &ixfr_cooldowns,
                metrics: &metrics,
                ixfr_timeout: std::time::Duration::from_millis(100),
                axfr_timeout: std::time::Duration::from_millis(100),
                tcp_connect_timeout: std::time::Duration::from_millis(100),
                reason: "test",
            },
        )
        .await;

        assert!(snapshot.is_none());
        let query_result =
            tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
        assert!(
            !matches!(query_result, Ok(Some(()))),
            "expired XoT certificate must abort before sending a DNS transfer query"
        );
        assert_eq!(metrics.snapshot().axfr_failed, 1);
    }

    #[tokio::test]
    async fn refresh_xot_uses_configured_client_certificate() {
        let (client_cert, client_key) =
            write_self_signed_xot_cert_files_for_name("oxidedns-client.example.test");
        let (primary, trust_anchor, mut query_seen) =
            spawn_xot_mtls_axfr_primary_with_serial(1, &client_cert).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
                client_cert = "{}"
                client_key = "{}"
            "#,
            client_cert.display(),
            client_key.display()
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        let zones = ZoneStore::new();
        zones.insert_loading(apex);
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
                tcp_connect_timeout: std::time::Duration::from_secs(5),
                reason: "test",
            },
        )
        .await
        .expect("mTLS XoT AXFR should publish a snapshot");

        assert_eq!(snapshot.serial, Some(1));
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), query_seen.recv()).await,
            Ok(Some(()))
        );
        assert_eq!(metrics.snapshot().axfr_succeeded, 1);
    }

    #[tokio::test]
    async fn refresh_xot_rejects_missing_client_certificate_before_query() {
        let (client_cert, _client_key) =
            write_self_signed_xot_cert_files_for_name("oxidedns-client.example.test");
        let (primary, trust_anchor, mut query_seen) =
            spawn_xot_mtls_axfr_primary_with_serial(1, &client_cert).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        let zones = ZoneStore::new();
        zones.insert_loading(apex);
        let metrics = RuntimeMetrics::new();
        let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

        let snapshot = refresh_zone_from_primaries(
            &zones,
            &plan,
            None,
            RefreshAttemptContext {
                ixfr_cooldowns: &ixfr_cooldowns,
                metrics: &metrics,
                ixfr_timeout: std::time::Duration::from_millis(100),
                axfr_timeout: std::time::Duration::from_millis(100),
                tcp_connect_timeout: std::time::Duration::from_millis(100),
                reason: "test",
            },
        )
        .await;

        assert!(snapshot.is_none());
        let query_result =
            tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
        assert!(
            !matches!(query_result, Ok(Some(()))),
            "missing XoT client certificate must abort before sending a DNS transfer query"
        );
        assert_eq!(metrics.snapshot().axfr_failed, 1);
    }

    #[test]
    fn runtime_config_validation_accepts_valid_xot_files() {
        let (trust_anchor, _key_path) = write_self_signed_xot_cert_files();
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
            trust_anchor.display()
        ))
        .expect("valid config");

        validate_runtime_config(&config).expect("xot tls files should validate");
    }

    #[test]
    fn runtime_config_validation_accepts_inline_xot_client_key() {
        let (trust_anchor, key_path) =
            write_self_signed_xot_cert_files_for_name("primary.example.test");
        let key_pem = std::fs::read_to_string(&key_path).expect("read generated key PEM");
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
                client_cert = "{}"
                client_key_pem = '''
{}'''
            "#,
            trust_anchor.display(),
            trust_anchor.display(),
            key_pem
        ))
        .expect("valid config with inline client key");

        validate_runtime_config(&config).expect("inline xot client key should validate");
    }

    #[test]
    fn runtime_config_validation_rejects_malformed_inline_xot_client_key_without_leaking_it() {
        let (trust_anchor, _key_path) =
            write_self_signed_xot_cert_files_for_name("primary.example.test");
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
                client_cert = "{}"
                client_key_pem = "inline-private-key-material"
            "#,
            trust_anchor.display(),
            trust_anchor.display(),
        ))
        .expect("schema-valid config with malformed inline client key");

        let error = validate_runtime_config(&config)
            .expect_err("malformed inline XoT client key should fail runtime validation");
        let message = error.to_string();
        assert!(message.contains("failed to parse inline private key PEM"));
        assert!(!message.contains("inline-private-key-material"));
    }

    #[test]
    fn file_descriptor_limit_check_uses_srs_resource_formula() {
        let config = ServerConfig::from_toml_str(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [limits]
                max_tcp_connections = 20
                max_concurrent_transfers = 3

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
        )
        .expect("valid config");

        assert_eq!(required_file_descriptor_limit(&config), 246);
        validate_file_descriptor_limit_value(&config, 246).expect("exact required limit is enough");

        let error = validate_file_descriptor_limit_value(&config, 245)
            .expect_err("below required limit should fail");
        assert!(matches!(
            error,
            RuntimeError::InsufficientFileDescriptorLimit {
                current: 245,
                required: 246
            }
        ));
    }

    #[test]
    fn runtime_config_warnings_report_expiring_xot_trust_anchors() {
        let (trust_anchor, _key_path) =
            write_expiring_self_signed_xot_cert_files_for_name("primary.example.test");
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
            trust_anchor.display()
        ))
        .expect("valid config");

        let warnings = runtime_config_warnings_at(&config, 1_779_667_200)
            .expect("xot warning collection succeeds");

        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "xot_trust_anchor_expiring_soon");
        assert!(
            warnings[0]
                .parameter
                .contains("zones[example.test.].transfer_primaries[192.0.2.53:853]")
        );
        assert!(warnings[0].message.contains("within 30 days"));
    }

    #[test]
    fn runtime_config_validation_rejects_missing_xot_trust_anchor_file() {
        let missing_trust_anchor = unique_test_path("missing-xot-ca", "pem");
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
            missing_trust_anchor.display()
        ))
        .expect("schema-valid config");

        let error = validate_runtime_config(&config).expect_err("missing trust anchor must fail");

        assert!(error.to_string().contains("failed to read XoT TLS file"));
    }

    #[test]
    fn runtime_config_validation_rejects_malformed_xot_trust_anchor_file() {
        let trust_anchor = unique_test_path("malformed-xot-ca", "pem");
        std::fs::write(&trust_anchor, b"not a certificate").expect("write malformed trust anchor");
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
            trust_anchor.display()
        ))
        .expect("schema-valid config");

        let error = validate_runtime_config(&config).expect_err("malformed trust anchor must fail");

        assert!(error.to_string().contains("did not contain certificates"));
    }

    #[tokio::test]
    async fn runtime_rejects_invalid_xot_config_before_startup() {
        let missing_trust_anchor = unique_test_path("missing-runtime-xot-ca", "pem");
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{}"]
            "#,
            missing_trust_anchor.display()
        ))
        .expect("schema-valid config");

        let error = Runtime::new(config)
            .run_with_shutdown_signal(async { Ok("test") })
            .await
            .expect_err("runtime must reject invalid XoT TLS files before startup");

        assert!(matches!(error, RuntimeError::InvalidRuntimeConfig(_)));
    }

    #[tokio::test]
    async fn refresh_axfr_uses_xot_tls_transport() {
        let (primary, trust_anchor) = spawn_xot_axfr_primary_with_serial(1).await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&apex).expect("zone transfer plan");
        let zones = ZoneStore::new();
        zones.insert_loading(apex);
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
                tcp_connect_timeout: std::time::Duration::from_secs(5),
                reason: "test",
            },
        )
        .await
        .expect("XoT AXFR should publish a snapshot");

        assert_eq!(snapshot.serial, Some(1));
        assert!(
            zones
                .get("example.test.")
                .expect("published XoT zone")
                .lookup(
                    &DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers
                .iter()
                .any(|answer| answer.rdata == vec![192, 0, 2, 10])
        );
        assert_eq!(metrics.snapshot().axfr_succeeded, 1);
    }

    #[tokio::test]
    async fn refresh_uses_axfr_during_ixfr_disabled_cooldown() {
        let (primary, qtypes) = spawn_ixfr_notimp_then_axfr_primary().await;
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");
        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
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
                tcp_connect_timeout: std::time::Duration::from_secs(5),
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
                tcp_connect_timeout: std::time::Duration::from_secs(5),
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
                ..Default::default()
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
                listen_tcp = []

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
        ))
        .expect("valid config");

        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
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
                ..Default::default()
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
                listen_tcp = []

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

        let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
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

    async fn spawn_axfr_primary() -> std::net::SocketAddr {
        spawn_axfr_primary_with_serial(1).await
    }

    async fn spawn_xot_axfr_primary_with_serial(serial: u32) -> (std::net::SocketAddr, String) {
        let (cert_path, key_path) = write_self_signed_xot_cert_files();

        let certs = load_pem_certs(cert_path.to_str().expect("utf-8 cert path"))
            .expect("load generated cert");
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

        let certs = load_pem_certs(cert_path.to_str().expect("utf-8 cert path"))
            .expect("load generated cert");
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

        let certs = load_pem_certs(cert_path.to_str().expect("utf-8 cert path"))
            .expect("load generated cert");
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
        let certs = load_pem_certs(cert_path.to_str().expect("utf-8 cert path"))
            .expect("load generated cert");
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

    fn axfr_response(qid: u16, serial: u32) -> Vec<u8> {
        axfr_response_for_zone(qid, "example.test.", serial)
    }

    fn axfr_response_for_zone(qid: u16, zone: &str, serial: u32) -> Vec<u8> {
        transfer_response_for_zone(qid, zone, RecordType::Axfr as u16, serial)
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
            NotifyAuthority::from_config(&config),
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
        let old_mac_len =
            u16::from_be_bytes([out[mac_len_offset], out[mac_len_offset + 1]]) as usize;
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
        NotifyLogLimiter::new(std::time::Duration::from_secs(60))
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

    async fn unused_udp_addr() -> std::net::SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        addr
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
}
