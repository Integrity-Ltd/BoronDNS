#![deny(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "af-xdp")]
mod af_xdp;
mod build_info;
mod config_validation;
mod dns_cookie;
mod errors;
mod health_metrics;
mod observability;
mod privilege;
mod process_hardening;
mod process_signals;
mod rate_limit;
mod resource_limits;
mod runtime_status;
mod secret_store;
mod shutdown;
mod std_udp_mmsg;
mod std_udp_socket;
mod tcp;
mod transfer;
mod transfer_plan;
mod udp;

#[cfg(test)]
use oxidedns_core::config::UdpRuntime;
use oxidedns_core::{
    ServerConfig,
    axfr::{self, IxfrResponse},
    catalog::{CatalogError, CatalogMember, CatalogMemberTransfer, parse_catalog_members},
    config::{CatalogZoneConfig, TransferTransportConfig, ZoneConfig},
    dns::{DomainName, Header, Opcode, Question, Rcode},
    tsig::{
        DEFAULT_TSIG_FUDGE_SECS, TSIG_ERROR_BADALG, TSIG_ERROR_BADKEY, TSIG_ERROR_BADSIG,
        TSIG_ERROR_BADTIME, TSIG_ERROR_BADTRUNC, TsigError, TsigErrorResponseFields, TsigKey,
        append_unsigned_tsig_error, extract_tsig_mac, message_tsig_key, message_tsig_owner_name,
        sign_tsig_error_response,
    },
    zone::{CatalogZoneView, SoaTimers, ZoneMetadata, ZoneSnapshot, ZoneState, ZoneStore},
};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, mpsc, oneshot},
    task::JoinSet,
};
use tracing::{error, info, warn};

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

#[cfg(unix)]
pub use process_signals::install_process_signal_dispositions;

pub use build_info::{BUILD_COMMIT, BUILD_RUST_VERSION, BUILD_TIMESTAMP, BUILD_VERSION};
use config_validation::validate_file_descriptor_limit;
#[cfg(test)]
use config_validation::{
    required_file_descriptor_limit, runtime_config_warnings_at,
    validate_file_descriptor_limit_value,
};
pub use config_validation::{runtime_config_warnings, validate_runtime_config};
use dns_cookie::{
    CookiePrefixMetricSettings, DnsCookieRuntimeSettings, DnsCookieSecretStore,
    cookie_metric_prefix, dns_cookie_context, dns_cookie_secret, dns_cookie_secret_fingerprint,
    dns_cookie_settings,
};
pub use errors::{RuntimeError, TransferError};
#[cfg(any(feature = "af-xdp", test))]
pub(crate) use health_metrics::AfXdpPacketIoStats;
#[cfg(test)]
use health_metrics::{
    DEFAULT_COOKIE_PREFIX_METRIC_LIMIT, DEFAULT_LATENCY_HISTOGRAM_BUCKETS, QueryLatencyHistogram,
    metrics_body,
};
use health_metrics::{HealthEndpointState, MetricsRateLimiter, RuntimeMetrics, serve_health};
pub(crate) use health_metrics::{
    QueryLatencyCategory, QueryPipelineStage, ResponseCacheCandidateCategory,
    ResponseCacheIneligibleReason, RuntimeMetricsSnapshot,
};
use observability::{ObservabilityAuth, TransferMaterial};
use rate_limit::{
    IpPrefix, NotifyLogLimiter, RrlDecision, RrlLimiter, response_opt_record,
    response_question_end, response_record_type, serve_notify_log_summaries,
    serve_rrl_summary_logs,
};
#[cfg(test)]
use rate_limit::{
    NotifyLogSummary, RrlCategory, RrlSummary, log_notify_log_summary, log_rrl_summary,
    response_category, rrl_truncated_response,
};
use runtime_status::{RuntimeStatus, RuntimeStatusValue};
use secret_store::SecretManager;
use shutdown::{
    abort_task_set, drain_task_set, drain_tcp_connections, handle_runtime_task_result,
    wait_for_shutdown_signal,
};
#[cfg(test)]
use tcp::{
    TcpQueryHook, handle_tcp_connection, handle_tcp_connection_with_query_hook, write_tcp_message,
};
use tcp::{TcpServerSettings, serve_tcp};
use transfer::{
    TransferSession, TransferTsig, poll_soa_from_primary_with_tsig_and_source,
    transfer_axfr_from_target_with_tsig_and_source, transfer_ixfr_from_target_with_tsig,
    transfer_query_id, tsig_time_signed, unix_timestamp_seconds,
};
pub(crate) use transfer::{build_xot_client_config, load_pem_certs_for_primary};
#[cfg(test)]
use transfer::{
    load_pem_certs, load_pem_private_key_from_file, poll_soa_from_primary_with_tsig,
    query_id_from_random_bytes, tcp_connect_with_timeout, transfer_axfr_from_target_with_tsig,
};
pub use transfer::{poll_soa_from_primary, transfer_axfr_from_primary, transfer_ixfr_from_primary};
use transfer_plan::{TransferPlan, ZoneTransferPlan};
#[cfg(test)]
use transfer_plan::{rotate_transfer_targets, uniform_index_from_u64};
#[cfg(any(test, feature = "af-xdp"))]
pub(crate) use udp::PacketIo;
#[cfg(feature = "af-xdp")]
pub(crate) use udp::UDP_PACKET_BUFFER_LEN;
#[cfg(test)]
use udp::{BoundUdpListener, StdUdpBatchIo, serve_udp};
use udp::{
    QueryMetricObservation, QueryObservationOptions, UdpServerSettings, bind_udp_listeners,
    observe_dns_cookie_metrics, observe_query_metrics, record_chaos_query_if_observed,
    record_dns_cookie_badcookie_if_emitted, record_query_lookup_metrics,
    record_query_response_metric, record_query_send_metric, record_response_cache_metric,
    response_cache_ineligible_reason, serve_bound_udp,
};
pub(crate) use udp::{UdpInbound, UdpOutbound, UdpPacketTarget};
pub(crate) use udp::{response_rcode, skip_response_record};

#[derive(Debug)]
pub struct Runtime {
    config: ServerConfig,
    zones: ZoneStore,
}

const NOTIFY_REFRESH_QUEUE_CAPACITY: usize = 1024;
const ZSM_SCHEDULER_TICK: Duration = Duration::from_secs(1);
const SOA_TIMER_NEAR_MAX_WARNING_PERCENT: u64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyTsigResult {
    Ok,
    BadKey,
    BadSig,
    BadTime,
    BadAlg,
    BadTrunc,
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
        let secrets = SecretManager::from_config(&self.config)
            .map_err(|error| RuntimeError::InvalidRuntimeConfig(error.to_string()))?;
        let (tsig_key_count, xot_profile_count) = secrets.snapshot_counts();
        info!(
            category = "secret_store",
            tsig_keys = tsig_key_count,
            xot_profiles = xot_profile_count,
            "loaded secret snapshot"
        );
        let transfer_plan = TransferPlan::from_config(&self.config)?;
        let observability_auth = ObservabilityAuth::from_config(&self.config.observability)
            .map_err(|source| {
                RuntimeError::InvalidRuntimeConfig(format!(
                    "failed to read observability bearer token file: {source}"
                ))
            })?;
        let transfer_materials = TransferMaterial::from_config(&self.config);
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
            self.config.metrics.hot_path_detail,
        );
        let startup_warning_count = self.config.configuration_warnings().len().saturating_add(
            runtime_config_warnings(&self.config)
                .map_err(|error| RuntimeError::InvalidRuntimeConfig(error.to_string()))?
                .len(),
        );
        metrics.set_configuration_warnings(startup_warning_count as u64);
        let transfer_limit = Arc::new(Semaphore::new(self.config.limits.max_concurrent_transfers));
        let control_plane_telemetry = ControlPlaneTelemetryReporter::from_config(&self.config);

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
        let notify_authority = NotifyAuthority::from_config(&self.config, secrets.clone());
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
        let dns_cookie_secrets = dns_cookie_secret_store_from_config(&self.config, dns_cookie)?;
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
        let mut bound_udp_listeners = Vec::new();
        for addr in self.config.udp_listeners() {
            let mut listeners = bind_udp_listeners(
                addr,
                self.config.limits.udp_backend,
                &self.config.xdp,
                self.config.limits.udp_reuseport_workers,
                self.config.limits.udp_worker_cpu_affinity.as_deref(),
                self.config.limits.udp_socket_receive_buffer_bytes,
                self.config.limits.udp_socket_send_buffer_bytes,
                self.config
                    .limits
                    .udp_socket_max_pacing_rate_bytes_per_second,
            )
            .await?;
            bound_udp_listeners.append(&mut listeners);
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
                secrets: secrets.clone(),
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
                telemetry: control_plane_telemetry.clone(),
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
                secrets: secrets.clone(),
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
                telemetry: control_plane_telemetry,
            },
        ));
        listeners.spawn(serve_scheduled_refreshes(
            self.zones.clone(),
            refresh_registry.clone(),
            notify_refresh_tx.clone(),
            ZSM_SCHEDULER_TICK,
        ));
        let control_plane_operations = ControlPlaneOperationClient::from_config(&self.config);
        if control_plane_operations.enabled() {
            let catalog_origins = self
                .config
                .catalog_zones
                .iter()
                .map(|catalog| {
                    DomainName::from_absolute_str(&catalog.name)
                        .expect("configuration validation rejects invalid catalog zone names")
                })
                .collect::<Vec<_>>();
            listeners.spawn(serve_control_plane_operations(
                control_plane_operations,
                self.zones.clone(),
                notify_refresh_tx.clone(),
                catalog_origins,
                secrets.clone(),
            ));
        }
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
                    observability: self.config.observability.clone(),
                    observability_auth: observability_auth.clone(),
                    observability_rate_limiter: MetricsRateLimiter::from_observability_config(
                        &self.config.observability,
                    ),
                    transfer_materials: transfer_materials.clone(),
                    started_at: Instant::now(),
                    graceful_shutdown_secs: self.config.limits.graceful_shutdown_secs,
                    zone_shape_metrics_enabled: self.config.metrics.zone_shape_enabled,
                },
                async move {
                    let _ = health_shutdown_rx.await;
                },
            ));
        }
        for udp_listener in bound_udp_listeners {
            let zones = self.zones.clone();
            let max_udp_payload = self.config.limits.max_udp_payload;
            let udp_batch_size = self.config.limits.udp_batch_size;
            let udp_backend = self.config.limits.udp_backend;
            let udp_runtime = self.config.limits.udp_runtime;
            let udp_idle_strategy = self.config.limits.udp_idle_strategy;
            let xdp = self.config.xdp.clone();
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
                udp_batch_size,
                udp_backend,
                udp_runtime,
                udp_idle_strategy,
                xdp,
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
            listeners
                .spawn(async move { serve_bound_udp(udp_listener, zones, udp_settings).await });
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
                notify_authority: NotifyAuthority::from_config_for_test(&self.config),
                refresh_tx: mpsc::channel(1).0.downgrade(),
                secrets: SecretManager::from_config(&self.config)
                    .expect("test configuration loads secret snapshot"),
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
                telemetry: ControlPlaneTelemetryReporter::disabled(),
            },
        )
        .await
        .expect("initial zone load worker does not return runtime errors");
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
    Catalog,
    ControlPlane,
    Notify,
    Scheduled,
}

impl RefreshReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Catalog => "catalog",
            Self::ControlPlane => "control_plane",
            Self::Notify => "notify",
            Self::Scheduled => "scheduled",
        }
    }
}

#[derive(Debug, Clone)]
struct CatalogManager {
    catalogs_by_key: Arc<HashMap<String, CatalogRuntimeConfig>>,
    static_zone_keys: Arc<HashSet<String>>,
    memberships_by_catalog: Arc<Mutex<HashMap<String, HashMap<String, DomainName>>>>,
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
    secrets: SecretManager,
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

    fn is_catalog_key(&self, origin_key: &str) -> bool {
        self.catalogs_by_key.contains_key(origin_key)
    }

    fn member_metrics(&self) -> Vec<CatalogMemberMetric> {
        let memberships = self
            .memberships_by_catalog
            .lock()
            .expect("catalog membership lock poisoned");
        let mut samples = Vec::new();
        for (catalog_key, members_by_key) in memberships.iter() {
            let Some(catalog_zone) = DomainName::from_absolute_str(catalog_key).ok() else {
                continue;
            };
            for (member_key, member_zone) in members_by_key {
                samples.push(CatalogMemberMetric {
                    catalog_zone: catalog_zone.clone(),
                    member_zone: member_zone.clone(),
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

    #[allow(clippy::too_many_arguments)]
    async fn apply_snapshot(
        &self,
        catalog_view: CatalogZoneView<'_>,
        metadata: &ZoneMetadata,
        zones: &ZoneStore,
        transfer_plan: &TransferPlan,
        refresh_registry: &ZoneRefreshRegistry,
        notify_authority: &NotifyAuthority,
        refresh_tx: &mpsc::WeakSender<RefreshRequest>,
    ) {
        debug_assert_eq!(&metadata.origin, catalog_view.origin());
        let Some(catalog) = self.catalogs_by_key.get(metadata.origin_key.as_ref()) else {
            return;
        };

        if catalog.config.serve_catalog_zone {
            zones.show_zone(&catalog.origin);
        } else {
            zones.hide_zone(&catalog.origin);
        }

        let mut members = match parse_catalog_members(catalog_view) {
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
        let (old_members_by_key, old_member_keys, other_catalog_member_keys) = {
            let memberships = self
                .memberships_by_catalog
                .lock()
                .expect("catalog membership lock poisoned");
            let old_members_by_key = memberships.get(&catalog_key).cloned().unwrap_or_default();
            let old_member_keys = old_members_by_key.keys().cloned().collect::<HashSet<_>>();
            let other_catalog_member_keys = memberships
                .iter()
                .filter(|(known_catalog_key, _)| *known_catalog_key != &catalog_key)
                .flat_map(|(_, members_by_key)| members_by_key.keys().cloned())
                .collect::<HashSet<_>>();
            (
                old_members_by_key,
                old_member_keys,
                other_catalog_member_keys,
            )
        };
        let mut members_by_key = HashMap::<String, CatalogMember>::new();
        for member in members {
            let member_key = member.zone.canonical_key();
            if self.catalogs_by_key.contains_key(&member_key)
                || other_catalog_member_keys.contains(&member_key)
            {
                error!(
                    category = "transfer",
                    event = "catalog_member_name_clash",
                    catalog_zone = %catalog.origin,
                    zone = %member.zone,
                    "catalog member zone clashes with an existing catalog zone; ignoring incoming member"
                );
                continue;
            }
            members_by_key.insert(member_key, member);
        }
        let new_member_keys = members_by_key.keys().cloned().collect::<HashSet<_>>();

        if transfer_plan.get(&catalog.origin).is_none() {
            warn!(
                category = "transfer",
                event = "catalog_without_transfer_plan",
                zone = %catalog.origin,
                "catalog zone has no transfer plan"
            );
            return;
        }

        let mut added = new_member_keys
            .difference(&old_member_keys)
            .cloned()
            .collect::<Vec<_>>();
        added.sort();
        for member_key in added {
            let Some(member) = members_by_key.get(&member_key) else {
                continue;
            };
            let member_origin = member.zone.clone();
            if self.static_zone_keys.contains(&member_key) {
                error!(
                    category = "transfer",
                    event = "catalog_member_name_clash",
                    catalog_zone = %catalog.origin,
                    zone = %member_origin,
                    "catalog member zone already has static configuration; ignoring incoming member"
                );
                continue;
            }
            let transfer_override = catalog
                .config
                .member_transfer_extensions
                .then_some(member.transfer.as_ref())
                .flatten();
            let Some(member_plan) = transfer_plan.catalog_member_plan(
                &catalog.origin,
                member_origin.clone(),
                transfer_override,
            ) else {
                warn!(
                    category = "transfer",
                    event = "catalog_without_valid_member_transfer_plan",
                    catalog_zone = %catalog.origin,
                    zone = %member_origin,
                    "catalog zone has no valid member transfer plan"
                );
                continue;
            };
            transfer_plan.insert(member_plan);
            notify_authority.add_zone_from_catalog(
                &member_origin,
                &catalog.config,
                transfer_override,
            );
            if !zones.contains_exact_zone_for_control(&member_origin) {
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

        let mut retained = new_member_keys
            .intersection(&old_member_keys)
            .cloned()
            .collect::<Vec<_>>();
        retained.sort();
        for member_key in retained {
            if self.static_zone_keys.contains(&member_key) {
                continue;
            }
            let Some(member) = members_by_key.get(&member_key) else {
                continue;
            };
            let transfer_override = catalog
                .config
                .member_transfer_extensions
                .then_some(member.transfer.as_ref())
                .flatten();
            let Some(member_plan) = transfer_plan.catalog_member_plan(
                &catalog.origin,
                member.zone.clone(),
                transfer_override,
            ) else {
                warn!(
                    category = "transfer",
                    event = "catalog_member_transfer_override_rejected",
                    catalog_zone = %catalog.origin,
                    zone = %member.zone,
                    "catalog member transfer override was not applied; retaining existing transfer plan"
                );
                continue;
            };
            transfer_plan.insert(member_plan);
            notify_authority.add_zone_from_catalog(
                &member.zone,
                &catalog.config,
                transfer_override,
            );
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
            let Some(member_origin) = old_members_by_key.get(&member_key).cloned() else {
                warn!(
                    category = "transfer",
                    event = "catalog_member_remove_missing_previous_origin",
                    catalog_zone = %catalog.origin,
                    zone_key = %member_key,
                    "catalog membership was missing previous member origin; skipping removal"
                );
                continue;
            };
            let still_owned_by_other_catalog = self
                .memberships_by_catalog
                .lock()
                .expect("catalog membership lock poisoned")
                .iter()
                .filter(|(known_catalog_key, _)| *known_catalog_key != &catalog_key)
                .any(|(_, members_by_key)| members_by_key.contains_key(&member_key));
            if still_owned_by_other_catalog {
                continue;
            }
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
            .insert(
                catalog_key,
                members_by_key
                    .into_iter()
                    .map(|(key, member)| (key, member.zone))
                    .collect(),
            );
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

    #[cfg(test)]
    fn record_success_at(&self, metadata: &ZoneMetadata, now: Instant) {
        self.record_success_at_with_timestamp(metadata, now, unix_timestamp_seconds());
    }

    #[cfg(test)]
    fn record_success_at_with_timestamp(
        &self,
        metadata: &ZoneMetadata,
        now: Instant,
        unix_secs: u64,
    ) {
        self.record_success_metadata_at_with_timestamp(metadata, now, unix_secs);
    }

    fn record_success_from_metadata(&self, metadata: &ZoneMetadata) {
        self.record_success_metadata_at_with_timestamp(
            metadata,
            Instant::now(),
            unix_timestamp_seconds(),
        );
    }

    fn record_success_metadata_at_with_timestamp(
        &self,
        metadata: &ZoneMetadata,
        now: Instant,
        unix_secs: u64,
    ) {
        let timers = metadata.soa_timers;
        if let Some(timers) = timers {
            self.warn_near_max_soa_timers(&metadata.origin, timers);
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
            metadata.origin_key.to_string(),
            ZoneRefreshStatus {
                origin: metadata.origin.clone(),
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
        current: Option<ZoneMetadata>,
        failure_cause: Option<String>,
    ) {
        self.record_failure_at_with_cause(origin, current, failure_cause, Instant::now());
    }

    #[cfg(test)]
    fn record_failure_at(&self, origin: &DomainName, current: Option<ZoneMetadata>, now: Instant) {
        self.record_failure_at_with_cause(origin, current, None, now);
    }

    fn record_failure_at_with_cause(
        &self,
        origin: &DomainName,
        current: Option<ZoneMetadata>,
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
        current: Option<ZoneMetadata>,
        now: Instant,
        unix_secs: u64,
    ) {
        self.record_failure_at_with_timestamp_and_cause(origin, current, None, now, unix_secs);
    }

    fn record_failure_at_with_timestamp_and_cause(
        &self,
        origin: &DomainName,
        current: Option<ZoneMetadata>,
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
            .is_none_or(|metadata| metadata.state == ZoneState::Loading);
        let status = statuses
            .entry(origin.canonical_key())
            .or_insert_with(|| ZoneRefreshStatus {
                origin: origin.clone(),
                soa_timers: current.as_ref().and_then(|metadata| metadata.soa_timers),
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

        if let Some(metadata) = current {
            status.soa_timers = metadata.soa_timers;
            status.expired = metadata.state == ZoneState::Expired;
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
                let metadata = zones.exact_zone_control_metadata(&status.origin)?;
                if metadata.state != ZoneState::Loading {
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

fn dns_cookie_secret_store_from_config(
    config: &ServerConfig,
    settings: DnsCookieRuntimeSettings,
) -> Result<DnsCookieSecretStore, RuntimeError> {
    let configured_current = config
        .cookie
        .server_secret_bytes()
        .map_err(|error| RuntimeError::InvalidRuntimeConfig(error.to_string()))?;
    let configured_previous = config
        .cookie
        .previous_server_secret_bytes()
        .map_err(|error| RuntimeError::InvalidRuntimeConfig(error.to_string()))?;

    if let Some(current) = configured_current {
        if settings.policy.is_some() {
            info!(
                category = "cookie",
                secret_fingerprint = %dns_cookie_secret_fingerprint(&current),
                previous_secret_fingerprint = configured_previous
                    .as_ref()
                    .map(dns_cookie_secret_fingerprint)
                    .unwrap_or_else(|| "none".to_owned()),
                "DNS Cookie shared Server Secret configured"
            );
        }
        return Ok(DnsCookieSecretStore::configured(
            current,
            configured_previous,
        ));
    }

    let current = dns_cookie_secret().map_err(RuntimeError::DnsCookieSecret)?;
    let store = DnsCookieSecretStore::new(current, settings.secret_rotation_interval);
    if settings.policy.is_some() {
        info!(
            category = "cookie",
            secret_fingerprint = %dns_cookie_secret_fingerprint(&current),
            rotation_interval_secs = settings.secret_rotation_interval.map(|duration| duration.as_secs()).unwrap_or(0),
            "DNS Cookie server secret generated"
        );
    }
    Ok(store)
}

#[derive(Debug, Clone)]
struct NotifyAuthority {
    sources_by_zone: Arc<Mutex<HashMap<String, HashSet<IpAddr>>>>,
    secrets: SecretManager,
    tsig_key_names_by_zone: Arc<Mutex<HashMap<String, DomainName>>>,
    tsig_fudge_seconds: u16,
}

impl Default for NotifyAuthority {
    fn default() -> Self {
        Self {
            sources_by_zone: Arc::new(Mutex::new(HashMap::new())),
            secrets: SecretManager::empty_for_test(),
            tsig_key_names_by_zone: Arc::new(Mutex::new(HashMap::new())),
            tsig_fudge_seconds: DEFAULT_TSIG_FUDGE_SECS,
        }
    }
}

impl NotifyAuthority {
    fn from_config(config: &ServerConfig, secrets: SecretManager) -> Self {
        let mut sources_by_zone = HashMap::new();
        let mut tsig_key_names_by_zone = HashMap::new();
        for zone in &config.zones {
            let origin = DomainName::from_absolute_str(&zone.name)
                .expect("configuration validation rejects invalid zone names");
            let sources = notify_sources_for_zone(zone);
            sources_by_zone.insert(origin.canonical_key(), sources);
            if let Some(tsig_key) = &zone.tsig_key {
                let key_name = DomainName::from_absolute_str(tsig_key)
                    .expect("configuration validation rejects invalid TSIG key references");
                tsig_key_names_by_zone.insert(origin.canonical_key(), key_name);
            }
        }
        for catalog_zone in &config.catalog_zones {
            let origin = DomainName::from_absolute_str(&catalog_zone.name)
                .expect("configuration validation rejects invalid catalog zone names");
            let sources = notify_sources_for_catalog_zone(catalog_zone);
            sources_by_zone.insert(origin.canonical_key(), sources);
            if let Some(tsig_key) = catalog_zone.catalog_tsig_key_name() {
                let key_name = DomainName::from_absolute_str(tsig_key)
                    .expect("configuration validation rejects invalid TSIG key references");
                tsig_key_names_by_zone.insert(origin.canonical_key(), key_name);
            }
        }

        Self {
            sources_by_zone: Arc::new(Mutex::new(sources_by_zone)),
            secrets,
            tsig_key_names_by_zone: Arc::new(Mutex::new(tsig_key_names_by_zone)),
            tsig_fudge_seconds: config.tsig.fudge_seconds,
        }
    }

    #[cfg(test)]
    fn from_config_for_test(config: &ServerConfig) -> Self {
        let secrets =
            SecretManager::from_config(config).expect("test configuration loads secret snapshot");
        Self::from_config(config, secrets)
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
        self.tsig_key_names_by_zone
            .lock()
            .expect("notify authority zone TSIG lock poisoned")
            .get(&qname.canonical_key())
            .and_then(|key_name| self.secrets.tsig_key(key_name))
    }

    fn tsig_key_by_name(&self, key_name: &DomainName) -> Option<Arc<TsigKey>> {
        self.secrets.tsig_key(key_name)
    }

    fn add_zone_from_catalog(
        &self,
        origin: &DomainName,
        catalog: &CatalogZoneConfig,
        transfer_override: Option<&CatalogMemberTransfer>,
    ) {
        self.sources_by_zone
            .lock()
            .expect("notify authority source lock poisoned")
            .insert(
                origin.canonical_key(),
                notify_sources_for_catalog_member_zone(catalog, transfer_override),
            );
        let tsig_key_name = transfer_override
            .and_then(|transfer| transfer.tsig_key_name.as_ref().cloned())
            .or_else(|| {
                catalog
                    .member_tsig_key_name()
                    .and_then(|name| DomainName::from_absolute_str(name).ok())
            });
        if let Some(key_name) = tsig_key_name {
            self.tsig_key_names_by_zone
                .lock()
                .expect("notify authority zone TSIG lock poisoned")
                .insert(origin.canonical_key(), key_name);
        }
    }

    fn remove_zone(&self, origin: &DomainName) {
        let key = origin.canonical_key();
        self.sources_by_zone
            .lock()
            .expect("notify authority source lock poisoned")
            .remove(&key);
        self.tsig_key_names_by_zone
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
        .catalog_transfer_target_addrs()
        .into_iter()
        .map(|primary| primary.ip())
        .collect::<HashSet<_>>();
    sources.extend(zone.notify_sources.iter().copied());
    sources
}

fn notify_sources_for_catalog_member_zone(
    zone: &CatalogZoneConfig,
    transfer_override: Option<&CatalogMemberTransfer>,
) -> HashSet<IpAddr> {
    let mut sources = HashSet::new();
    if let Some(transfer_override) = transfer_override
        && !transfer_override.primaries.is_empty()
    {
        sources.extend(
            transfer_override
                .primaries
                .iter()
                .map(|primary| primary.addr),
        );
        sources.extend(transfer_override.notify_sources.iter().copied());
    } else {
        sources.extend(
            zone.member_transfer_target_addrs()
                .into_iter()
                .map(|primary| primary.ip()),
        );
    }
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

#[derive(Clone)]
struct ControlPlaneTelemetryReporter {
    endpoint_url: Option<Arc<str>>,
    node_id: Option<Arc<str>>,
    bearer_token: Option<Arc<str>>,
    timeout: Duration,
    client: reqwest::Client,
}

impl ControlPlaneTelemetryReporter {
    #[cfg(test)]
    fn disabled() -> Self {
        Self {
            endpoint_url: None,
            node_id: None,
            bearer_token: None,
            timeout: Duration::from_secs(5),
            client: reqwest::Client::new(),
        }
    }

    fn from_config(config: &ServerConfig) -> Self {
        let telemetry = &config.control_plane.telemetry;
        Self {
            endpoint_url: telemetry
                .endpoint_url
                .as_ref()
                .map(|value| Arc::<str>::from(value.trim().trim_end_matches('/').to_owned())),
            node_id: telemetry
                .node_id
                .as_ref()
                .map(|value| Arc::<str>::from(value.trim().to_owned())),
            bearer_token: telemetry
                .bearer_token
                .as_ref()
                .map(|value| Arc::<str>::from(value.trim().to_owned())),
            timeout: Duration::from_secs(telemetry.timeout_secs),
            client: reqwest::Client::new(),
        }
    }

    fn enabled(&self) -> bool {
        self.endpoint_url.is_some() && self.node_id.is_some() && self.bearer_token.is_some()
    }

    async fn report_success(&self, metadata: &ZoneMetadata, status: &'static str, reason: &str) {
        if !self.enabled() {
            return;
        }
        let mut body = serde_json::json!({
            "zone_name": metadata.origin.to_string(),
            "status": status,
            "transfer_mode": "axfr_ixfr",
            "message": format!("OxideDNS transfer {status} during {reason} refresh"),
        });
        if let Some(serial) = metadata.serial {
            body["serial"] = serde_json::Value::String(serial.to_string());
        }
        if let Some(timers) = metadata.soa_timers {
            body["refresh_seconds"] = serde_json::Value::from(timers.refresh);
            body["retry_seconds"] = serde_json::Value::from(timers.retry);
        }
        self.post(body).await;
    }

    async fn report_failure(&self, origin: &DomainName, failure_cause: Option<&str>, reason: &str) {
        if !self.enabled() {
            return;
        }
        let failure_reason = failure_cause
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("transfer failed without detailed cause");
        self.post(serde_json::json!({
            "zone_name": origin.to_string(),
            "status": "failed",
            "transfer_mode": "axfr_ixfr",
            "failure_reason": failure_reason,
            "message": format!("OxideDNS transfer failed during {reason} refresh"),
        }))
        .await;
    }

    async fn post(&self, body: serde_json::Value) {
        let (Some(endpoint_url), Some(node_id), Some(bearer_token)) = (
            self.endpoint_url.as_deref(),
            self.node_id.as_deref(),
            self.bearer_token.as_deref(),
        ) else {
            return;
        };
        let url = format!("{endpoint_url}/secondary-nodes/{node_id}/transfer-events");
        match self
            .client
            .post(url)
            .bearer_auth(bearer_token)
            .timeout(self.timeout)
            .json(&body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => warn!(
                category = "transfer",
                status = %response.status(),
                "control-plane transfer telemetry report was rejected"
            ),
            Err(error) => warn!(
                category = "transfer",
                %error,
                "failed to send control-plane transfer telemetry report"
            ),
        }
    }
}

#[derive(Clone)]
struct ControlPlaneOperationClient {
    endpoint_url: Option<Arc<str>>,
    node_id: Option<Arc<str>>,
    bearer_token: Option<Arc<str>>,
    poll_interval: Duration,
    lease_seconds: u64,
    timeout: Duration,
    client: reqwest::Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControlPlaneOperation {
    id: i64,
    zone_name: String,
    operation: ControlPlaneOperationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlPlaneOperationKind {
    Retry,
    Pause,
    Resume,
    RepublishFeed,
    RotateTsig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlPlaneOperationCompletionStatus {
    Completed,
    Failed,
}

impl ControlPlaneOperationCompletionStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

impl ControlPlaneOperationClient {
    fn from_config(config: &ServerConfig) -> Self {
        let operations = &config.control_plane.operations;
        Self {
            endpoint_url: operations
                .endpoint_url
                .as_ref()
                .map(|value| Arc::<str>::from(value.trim().trim_end_matches('/').to_owned())),
            node_id: operations
                .node_id
                .as_ref()
                .map(|value| Arc::<str>::from(value.trim().to_owned())),
            bearer_token: operations
                .bearer_token
                .as_ref()
                .map(|value| Arc::<str>::from(value.trim().to_owned())),
            poll_interval: Duration::from_secs(operations.poll_interval_secs),
            lease_seconds: operations.lease_seconds,
            timeout: Duration::from_secs(operations.timeout_secs),
            client: reqwest::Client::new(),
        }
    }

    fn enabled(&self) -> bool {
        self.endpoint_url.is_some() && self.node_id.is_some() && self.bearer_token.is_some()
    }

    async fn poll(&self) -> Result<Vec<ControlPlaneOperation>, String> {
        let (Some(endpoint_url), Some(node_id), Some(bearer_token)) = (
            self.endpoint_url.as_deref(),
            self.node_id.as_deref(),
            self.bearer_token.as_deref(),
        ) else {
            return Ok(Vec::new());
        };
        let url = format!(
            "{endpoint_url}/secondary-nodes/{node_id}/operations?limit=20&lease_seconds={}",
            self.lease_seconds
        );
        let response = self
            .client
            .get(url)
            .bearer_auth(bearer_token)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "control-plane operation poll returned {}",
                response.status()
            ));
        }
        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|error| error.to_string())?;
        let operations = body
            .as_array()
            .ok_or_else(|| "control-plane operation poll returned non-array JSON".to_owned())?
            .iter()
            .map(parse_control_plane_operation)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(operations)
    }

    async fn complete(
        &self,
        operation_id: i64,
        status: ControlPlaneOperationCompletionStatus,
        failure_reason: Option<&str>,
    ) {
        let (Some(endpoint_url), Some(node_id), Some(bearer_token)) = (
            self.endpoint_url.as_deref(),
            self.node_id.as_deref(),
            self.bearer_token.as_deref(),
        ) else {
            return;
        };
        let mut body = serde_json::json!({ "status": status.as_str() });
        if let Some(failure_reason) = failure_reason {
            body["failure_reason"] = serde_json::Value::String(failure_reason.to_owned());
        }
        let url =
            format!("{endpoint_url}/secondary-nodes/{node_id}/operations/{operation_id}/complete");
        match self
            .client
            .post(url)
            .bearer_auth(bearer_token)
            .timeout(self.timeout)
            .json(&body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => warn!(
                category = "control_plane",
                operation_id,
                status = %response.status(),
                "control-plane operation completion was rejected"
            ),
            Err(error) => warn!(
                category = "control_plane",
                operation_id,
                %error,
                "failed to complete control-plane operation"
            ),
        }
    }
}

fn parse_control_plane_operation(
    value: &serde_json::Value,
) -> Result<ControlPlaneOperation, String> {
    let id = value
        .get("id")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| "operation id missing or invalid".to_owned())?;
    let zone_name = value
        .get("zone_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "operation zone_name missing or invalid".to_owned())?
        .to_owned();
    let operation = value
        .get("operation")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "operation kind missing or invalid".to_owned())
        .and_then(parse_control_plane_operation_kind)?;
    Ok(ControlPlaneOperation {
        id,
        zone_name,
        operation,
    })
}

fn parse_control_plane_operation_kind(value: &str) -> Result<ControlPlaneOperationKind, String> {
    match value {
        "retry" => Ok(ControlPlaneOperationKind::Retry),
        "pause" => Ok(ControlPlaneOperationKind::Pause),
        "resume" => Ok(ControlPlaneOperationKind::Resume),
        "republish_feed" => Ok(ControlPlaneOperationKind::RepublishFeed),
        "rotate_tsig" => Ok(ControlPlaneOperationKind::RotateTsig),
        _ => Err(format!("unsupported operation kind {value}")),
    }
}

async fn serve_control_plane_operations(
    client: ControlPlaneOperationClient,
    zones: ZoneStore,
    refresh_tx: mpsc::Sender<RefreshRequest>,
    catalog_origins: Vec<DomainName>,
    secrets: SecretManager,
) -> Result<(), RuntimeError> {
    let mut interval = tokio::time::interval(client.poll_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let operations = match client.poll().await {
            Ok(operations) => operations,
            Err(error) => {
                warn!(
                    category = "control_plane",
                    %error,
                    "failed to poll control-plane operations"
                );
                continue;
            }
        };
        for operation in operations {
            match execute_control_plane_operation(
                &operation,
                &zones,
                &refresh_tx,
                &catalog_origins,
                &secrets,
            ) {
                Ok(()) => {
                    client
                        .complete(
                            operation.id,
                            ControlPlaneOperationCompletionStatus::Completed,
                            None,
                        )
                        .await;
                }
                Err(error) => {
                    client
                        .complete(
                            operation.id,
                            ControlPlaneOperationCompletionStatus::Failed,
                            Some(&error),
                        )
                        .await;
                }
            }
        }
    }
}

fn execute_control_plane_operation(
    operation: &ControlPlaneOperation,
    zones: &ZoneStore,
    refresh_tx: &mpsc::Sender<RefreshRequest>,
    catalog_origins: &[DomainName],
    secrets: &SecretManager,
) -> Result<(), String> {
    let origin = DomainName::from_absolute_str(&operation.zone_name).map_err(|_| {
        format!(
            "operation zone_name {} is not absolute",
            operation.zone_name
        )
    })?;
    match operation.operation {
        ControlPlaneOperationKind::Retry => {
            require_known_control_zone(zones, &origin)?;
            enqueue_control_plane_refresh(refresh_tx, origin, RefreshReason::ControlPlane)
        }
        ControlPlaneOperationKind::Pause => {
            require_known_control_zone(zones, &origin)?;
            zones.hide_zone(&origin);
            info!(
                zone = %origin,
                operation_id = operation.id,
                "paused control-plane managed zone serving"
            );
            Ok(())
        }
        ControlPlaneOperationKind::Resume => {
            require_known_control_zone(zones, &origin)?;
            zones.show_zone(&origin);
            enqueue_control_plane_refresh(refresh_tx, origin, RefreshReason::ControlPlane)
        }
        ControlPlaneOperationKind::RepublishFeed => {
            reload_secret_snapshot(secrets)?;
            if catalog_origins.is_empty() {
                return Ok(());
            }
            for catalog_origin in catalog_origins {
                enqueue_control_plane_refresh(
                    refresh_tx,
                    catalog_origin.clone(),
                    RefreshReason::ControlPlane,
                )?;
            }
            Ok(())
        }
        ControlPlaneOperationKind::RotateTsig => {
            require_known_control_zone(zones, &origin)?;
            reload_secret_snapshot(secrets)?;
            enqueue_control_plane_refresh(refresh_tx, origin, RefreshReason::ControlPlane)
        }
    }
}

fn reload_secret_snapshot(secrets: &SecretManager) -> Result<(), String> {
    secrets.reload().map_err(|error| error.to_string())?;
    let (tsig_keys, xot_profiles) = secrets.snapshot_counts();
    info!(
        category = "secret_store",
        tsig_keys, xot_profiles, "reloaded secret snapshot"
    );
    Ok(())
}

fn require_known_control_zone(zones: &ZoneStore, origin: &DomainName) -> Result<(), String> {
    if zones.contains_exact_zone_for_control(origin) {
        Ok(())
    } else {
        Err(format!(
            "zone {origin} is not configured on this OxideDNS node"
        ))
    }
}

fn enqueue_control_plane_refresh(
    refresh_tx: &mpsc::Sender<RefreshRequest>,
    zone: DomainName,
    reason: RefreshReason,
) -> Result<(), String> {
    refresh_tx
        .try_send(RefreshRequest {
            zone,
            requested_serial: None,
            reason,
        })
        .map_err(|error| format!("refresh queue rejected control-plane operation: {error}"))
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
                    if let Some(metadata) = zones.exact_zone_control_metadata(zone) {
                        catalog_runtime.refresh_registry.record_success_from_metadata(&metadata);
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
                let telemetry = settings.telemetry.clone();
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
                            secrets: catalog_runtime.secrets.clone(),
                            ixfr_timeout,
                            axfr_timeout,
                            tcp_connect_timeout,
                            reason: request.reason.as_str(),
                        },
                    )
                    .await;
                    match outcome.success {
                        Some(success) => {
                            let (metadata, updated_snapshot) =
                                success.into_metadata_and_updated_snapshot();
                            catalog_runtime
                                .refresh_registry
                                .record_success_from_metadata(&metadata);
                            let telemetry_status = if updated_snapshot.is_some() {
                                "success"
                            } else {
                                "skipped"
                            };
                            telemetry
                                .report_success(&metadata, telemetry_status, request.reason.as_str())
                                .await;
                            if let Some(snapshot) = updated_snapshot
                                .as_deref()
                                .filter(|_| {
                                    catalog_runtime.manager.is_catalog_key(metadata.origin_key.as_ref())
                                })
                            {
                                catalog_runtime
                                    .manager
                                    .apply_snapshot(
                                        snapshot.catalog_zone_view(),
                                        &metadata,
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
                            telemetry
                                .report_failure(
                                    &request.zone,
                                    outcome.failure_cause.as_deref(),
                                    request.reason.as_str(),
                                )
                                .await;
                            catalog_runtime.refresh_registry.record_failure_with_cause(
                                &request.zone,
                                zones.exact_zone_control_metadata(&request.zone),
                                outcome.failure_cause,
                            );
                        }
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
    telemetry: ControlPlaneTelemetryReporter,
}

#[derive(Clone)]
struct InitialLoadSettings {
    axfr_timeout: Duration,
    ixfr_timeout: Duration,
    tcp_connect_timeout: Duration,
    transfer_limit: Arc<Semaphore>,
    telemetry: ControlPlaneTelemetryReporter,
}

#[derive(Clone)]
struct RefreshAttemptContext<'a> {
    ixfr_cooldowns: &'a IxfrCooldownRegistry,
    metrics: &'a RuntimeMetrics,
    secrets: SecretManager,
    ixfr_timeout: Duration,
    axfr_timeout: Duration,
    tcp_connect_timeout: Duration,
    reason: &'a str,
}

#[derive(Debug)]
struct RefreshZoneOutcome {
    success: Option<RefreshZoneSuccess>,
    failure_cause: Option<String>,
}

#[derive(Debug)]
enum RefreshZoneSuccess {
    Current(ZoneMetadata),
    Updated {
        snapshot: Arc<ZoneSnapshot>,
        metadata: ZoneMetadata,
    },
}

impl RefreshZoneOutcome {
    fn current(metadata: ZoneMetadata) -> Self {
        Self {
            success: Some(RefreshZoneSuccess::Current(metadata)),
            failure_cause: None,
        }
    }

    fn updated(snapshot: Arc<ZoneSnapshot>, metadata: ZoneMetadata) -> Self {
        Self {
            success: Some(RefreshZoneSuccess::Updated { snapshot, metadata }),
            failure_cause: None,
        }
    }

    fn failure(failure_cause: Option<String>) -> Self {
        Self {
            success: None,
            failure_cause,
        }
    }
}

impl RefreshZoneSuccess {
    fn into_metadata_and_updated_snapshot(self) -> (ZoneMetadata, Option<Arc<ZoneSnapshot>>) {
        match self {
            Self::Current(metadata) => (metadata, None),
            Self::Updated { snapshot, metadata } => (metadata, Some(snapshot)),
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
        let telemetry = settings.telemetry.clone();
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
                    secrets: catalog_runtime.secrets.clone(),
                    ixfr_timeout,
                    axfr_timeout,
                    tcp_connect_timeout,
                    reason: "initial",
                },
            )
            .await;
            match outcome.success {
                Some(success) => {
                    let (metadata, updated_snapshot) = success.into_metadata_and_updated_snapshot();
                    catalog_runtime
                        .refresh_registry
                        .record_success_from_metadata(&metadata);
                    let telemetry_status = if updated_snapshot.is_some() {
                        "success"
                    } else {
                        "skipped"
                    };
                    telemetry
                        .report_success(&metadata, telemetry_status, "initial")
                        .await;
                    if let Some(snapshot) = updated_snapshot.as_deref().filter(|_| {
                        catalog_runtime
                            .manager
                            .is_catalog_key(metadata.origin_key.as_ref())
                    }) {
                        catalog_runtime
                            .manager
                            .apply_snapshot(
                                snapshot.catalog_zone_view(),
                                &metadata,
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
                    telemetry
                        .report_failure(zone_apex, outcome.failure_cause.as_deref(), "initial")
                        .await;
                    catalog_runtime.refresh_registry.record_failure_with_cause(
                        zone_apex,
                        zones.exact_zone_control_metadata(zone_apex),
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
    let Some(metadata) = zones.exact_zone_control_metadata(&request.zone) else {
        return false;
    };
    let Some(current_serial) = metadata.serial else {
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

fn resolve_plan_tsig_key(
    plan: &ZoneTransferPlan,
    secrets: &SecretManager,
) -> Result<Option<Arc<TsigKey>>, TransferError> {
    let Some(key_name) = &plan.tsig_key_name else {
        return Ok(None);
    };
    secrets
        .tsig_key(key_name)
        .map(Some)
        .ok_or_else(|| TransferError::MissingTsigKey {
            key_name: key_name.to_string(),
        })
}

fn resolve_transfer_primary(
    primary: &oxidedns_core::config::TransferPrimaryConfig,
    secrets: &SecretManager,
) -> Result<oxidedns_core::config::TransferPrimaryConfig, TransferError> {
    let Some(profile_name) = primary.xot_profile.as_deref() else {
        return Ok(primary.clone());
    };
    let profile = secrets
        .xot_profile(profile_name)
        .ok_or_else(|| TransferError::XotConfig {
            addr: primary.addr,
            message: format!(
                "XoT profile {profile_name:?} is not loaded in the current secret snapshot"
            ),
        })?;
    let mut resolved = primary.clone();
    resolved.xot_profile = None;
    resolved.trust_anchors = profile.trust_anchors;
    resolved.client_cert = profile.client_cert;
    resolved.client_key = profile.client_key;
    resolved.client_key_pem = profile
        .client_key_pem
        .as_ref()
        .map(|secret| secret.expose_secret().to_owned());
    Ok(resolved)
}

#[cfg(test)]
async fn refresh_zone_metadata_from_primaries(
    zones: &ZoneStore,
    plan: &ZoneTransferPlan,
    primary_serial_hint: Option<u32>,
    context: RefreshAttemptContext<'_>,
) -> Option<ZoneMetadata> {
    let outcome =
        refresh_zone_from_primaries_with_outcome(zones, plan, primary_serial_hint, context).await;
    outcome.success.map(|success| match success {
        RefreshZoneSuccess::Current(metadata) | RefreshZoneSuccess::Updated { metadata, .. } => {
            metadata
        }
    })
}

async fn refresh_zone_from_primaries_with_outcome(
    zones: &ZoneStore,
    plan: &ZoneTransferPlan,
    primary_serial_hint: Option<u32>,
    context: RefreshAttemptContext<'_>,
) -> RefreshZoneOutcome {
    let mut current_metadata = zones
        .exact_zone_control_metadata(&plan.origin)
        .filter(|metadata| metadata.serial.is_some());
    let current_serial = current_metadata
        .as_ref()
        .and_then(|metadata| metadata.serial);
    let mut last_failure_cause = None;

    if let (Some(current_serial), Some(primary_serial)) = (current_serial, primary_serial_hint) {
        if !serial_after(primary_serial, current_serial) {
            info!(
                zone = %plan.origin,
                current_serial,
                primary_serial,
                reason = %context.reason,
                "SOA serial hint confirmed zone current"
            );
            if let Some(metadata) = current_metadata.take() {
                return RefreshZoneOutcome::current(metadata);
            }
            last_failure_cause = Some("current zone disappeared after SOA serial hint".to_string());
            warn!(
                zone = %plan.origin,
                reason = %context.reason,
                "SOA serial hint matched a zone that is no longer present; continuing refresh"
            );
        } else {
            info!(
                zone = %plan.origin,
                current_serial,
                primary_serial,
                reason = %context.reason,
                "SOA serial hint found newer primary serial"
            );
        }
    }

    for configured_primary in &plan.primaries {
        let primary_target = match resolve_transfer_primary(configured_primary, &context.secrets) {
            Ok(primary) => primary,
            Err(error) => {
                let primary = configured_primary.addr;
                last_failure_cause = Some(format!(
                    "XoT profile resolution failed for primary {primary}: {error}"
                ));
                warn!(
                    zone = %plan.origin,
                    %primary,
                    %error,
                    reason = %context.reason,
                    "XoT profile resolution failed"
                );
                continue;
            }
        };
        let primary = primary_target.addr;
        let transfer_source = plan.transfer_source_for(primary);
        let tsig_key = match resolve_plan_tsig_key(plan, &context.secrets) {
            Ok(key) => key,
            Err(error) => {
                last_failure_cause = Some(format!(
                    "transfer key resolution failed for primary {primary}: {error}"
                ));
                warn!(
                    zone = %plan.origin,
                    %primary,
                    %error,
                    reason = %context.reason,
                    "transfer key resolution failed"
                );
                continue;
            }
        };

        if primary_target.transport == TransferTransportConfig::Tcp
            && primary_serial_hint.is_none()
            && let Some(current_serial) = current_serial
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
                TransferTsig::new(tsig_key.as_deref(), plan.tsig_fudge_seconds),
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
                    if let Some(metadata) = current_metadata.take() {
                        return RefreshZoneOutcome::current(metadata);
                    }
                    last_failure_cause =
                        Some("current zone disappeared after SOA poll".to_string());
                    warn!(
                        zone = %plan.origin,
                        %primary,
                        reason = %context.reason,
                        "SOA poll matched a zone that is no longer present; continuing refresh"
                    );
                    continue;
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

        if current_serial.is_some() {
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
                if let Some(current) = zones.exact_snapshot_with_serial_for_transfer(&plan.origin) {
                    let current_serial = current
                        .metadata()
                        .serial
                        .expect("IXFR current snapshot metadata has a serial");
                    context.metrics.record_ixfr_started();
                    match transfer_ixfr_from_target_with_tsig(
                        &primary_target,
                        &plan.origin,
                        plan.qclass,
                        qid,
                        current.snapshot_for_transfer(),
                        TransferSession::new(
                            TransferTsig::new(tsig_key.as_deref(), plan.tsig_fudge_seconds),
                            plan.max_transfer_ingest_bytes,
                        )
                        .with_transfer_source(transfer_source),
                        context.ixfr_timeout,
                        context.tcp_connect_timeout,
                    )
                    .await
                    {
                        Ok(IxfrResponse::Updated(snapshot)) => {
                            let snapshot: Arc<ZoneSnapshot> = Arc::from(snapshot);
                            match zones.insert_snapshot_arc_for_transfer(snapshot.clone()) {
                                Ok(metadata) => {
                                    context.metrics.record_ixfr_succeeded();
                                    let serial = metadata.serial;
                                    info!(
                                        zone = %plan.origin,
                                        %primary,
                                        ?serial,
                                        reason = %context.reason,
                                        "IXFR completed"
                                    );
                                    return RefreshZoneOutcome::updated(snapshot, metadata);
                                }
                                Err(error) => {
                                    context.metrics.record_ixfr_failed();
                                    warn!(
                                        zone = %plan.origin,
                                        %primary,
                                        %error,
                                        reason = %context.reason,
                                        "IXFR publication failed; falling back to AXFR"
                                    );
                                }
                            }
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
                            return RefreshZoneOutcome::current(current.into_metadata());
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
                } else {
                    warn!(
                        zone = %plan.origin,
                        %primary,
                        reason = %context.reason,
                        "IXFR skipped because current zone is no longer present; falling back to AXFR"
                    );
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
            &primary_target,
            &plan.origin,
            plan.qclass,
            qid,
            TransferSession::new(
                TransferTsig::new(tsig_key.as_deref(), plan.tsig_fudge_seconds),
                plan.max_transfer_ingest_bytes,
            ),
            transfer_source,
            context.axfr_timeout,
            context.tcp_connect_timeout,
        )
        .await
        {
            Ok(snapshot) => {
                let snapshot = Arc::new(snapshot);
                match zones.insert_snapshot_arc_for_transfer(snapshot.clone()) {
                    Ok(metadata) => {
                        context.metrics.record_axfr_succeeded();
                        let serial = metadata.serial;
                        info!(
                            zone = %plan.origin,
                            %primary,
                            ?serial,
                            reason = %context.reason,
                            "AXFR completed"
                        );
                        return RefreshZoneOutcome::updated(snapshot, metadata);
                    }
                    Err(error) => {
                        last_failure_cause = Some(format!(
                            "AXFR publication failed for primary {primary}: {error}"
                        ));
                        context.metrics.record_axfr_failed();
                        warn!(
                            zone = %plan.origin,
                            %primary,
                            %error,
                            reason = %context.reason,
                            "AXFR publication failed"
                        );
                    }
                }
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

#[cfg(test)]
mod tests;
