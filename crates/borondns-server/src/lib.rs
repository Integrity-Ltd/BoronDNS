#![deny(unsafe_code)]

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, Weak as StdWeak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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
mod zone_persistence;

use borondns_core::{
    ServerConfig,
    axfr::{self, IxfrResponse},
    catalog::{
        CatalogError, CatalogMember, CatalogMemberTransfer, ParsedCatalogMembers,
        parse_catalog_members_bounded_with_filter,
    },
    config::{CatalogZoneConfig, ConfigSecretString, MAX_RUNTIME_DURATION_SECS, ZoneConfig},
    dns::{DomainName, Header, Opcode, Question, Rcode},
    tsig::{
        DEFAULT_TSIG_FUDGE_SECS, TSIG_ERROR_BADKEY, TSIG_ERROR_BADSIG, TSIG_ERROR_BADTIME,
        TSIG_ERROR_BADTRUNC, TsigError, TsigErrorResponseFields, TsigKey, TsigMessageKey,
        append_unsigned_tsig_error_for_message_key, message_tsig_key, message_tsig_request_data,
        sign_tsig_error_response,
    },
    zone::{
        CatalogZoneView, SoaTimers, TransferZoneSnapshot, ZoneMetadata,
        ZoneOverlayCompactionOutcome, ZoneSnapshot, ZoneState, ZoneStore,
    },
};
#[cfg(any(test, feature = "fuzzing"))]
use borondns_core::{dns::RecordType, zone::Rrset};
use tokio::{
    net::TcpListener,
    sync::{Mutex as AsyncMutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::{Id as TaskId, JoinError, JoinSet},
};
use tracing::{error, info, warn};
use zeroize::Zeroizing;
use zone_persistence::ZonePersistence;

// BDS-NFR-MAINT-004 principal functional requirement references for runtime
// transport, NOTIFY, zone refresh scheduling, XoT, and response-rate limiting:
// - BDS-FR-TCP-001 BDS-FR-TCP-002 BDS-FR-TCP-003 BDS-FR-TCP-004
// - BDS-FR-TCP-005 BDS-FR-TCP-006 BDS-FR-TCP-007 BDS-FR-TCP-008
// - BDS-FR-TCP-009 BDS-FR-TCP-010 BDS-FR-TCP-011
// - BDS-FR-NOTIFY-001 BDS-FR-NOTIFY-002 BDS-FR-NOTIFY-003
// - BDS-FR-NOTIFY-004 BDS-FR-NOTIFY-005 BDS-FR-NOTIFY-006
// - BDS-FR-NOTIFY-007 BDS-FR-NOTIFY-008 BDS-FR-NOTIFY-009
// - BDS-FR-NOTIFY-010 BDS-FR-NOTIFY-011
// - BDS-FR-ZSM-001 BDS-FR-ZSM-002 BDS-FR-ZSM-003 BDS-FR-ZSM-004
// - BDS-FR-ZSM-005 BDS-FR-ZSM-006 BDS-FR-ZSM-007 BDS-FR-ZSM-008
// - BDS-FR-ZSM-009 BDS-FR-ZSM-010 BDS-FR-ZSM-011 BDS-FR-ZSM-012
// - BDS-FR-ZSM-013 BDS-FR-ZSM-014
// - BDS-FR-XOT-001 BDS-FR-XOT-002 BDS-FR-XOT-003 BDS-FR-XOT-004
// - BDS-FR-XOT-005 BDS-FR-XOT-006 BDS-FR-XOT-007 BDS-FR-XOT-008
// - BDS-FR-XOT-009 BDS-FR-XOT-010 BDS-FR-XOT-011 BDS-FR-XOT-012
// - BDS-FR-RRL-001 BDS-FR-RRL-002 BDS-FR-RRL-003 BDS-FR-RRL-004
// - BDS-FR-RRL-005 BDS-FR-RRL-006 BDS-FR-RRL-007 BDS-FR-RRL-008
// - BDS-FR-RRL-009 BDS-FR-RRL-010 BDS-FR-RRL-011 BDS-FR-RRL-012

#[cfg(unix)]
pub use process_signals::install_process_signal_dispositions;

pub use build_info::{BUILD_COMMIT, BUILD_RUST_VERSION, BUILD_TIMESTAMP, BUILD_VERSION};
#[cfg(test)]
use config_validation::runtime_config_warnings_with_secrets_at;
#[cfg(test)]
use config_validation::{
    required_file_descriptor_limit, runtime_config_warnings_at,
    validate_file_descriptor_limit_value,
};
pub use config_validation::{runtime_config_warnings, validate_runtime_config};
use config_validation::{runtime_config_warnings_with_secrets, validate_file_descriptor_limit};
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
#[cfg(test)]
use health_metrics::{
    serve_health_with_connection_timeouts, serve_health_with_request_read_timeout,
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
    abort_task_set_until, drain_task_set_until, handle_runtime_task_result,
    wait_for_shutdown_signal,
};
#[cfg(test)]
use shutdown::{drain_task_set, drain_tcp_connections};
#[cfg(test)]
use tcp::serve_tcp;
#[cfg(test)]
use tcp::{
    TcpAcceptErrorAction, TcpQueryHook, classify_tcp_accept_error, handle_tcp_connection,
    handle_tcp_connection_until, handle_tcp_connection_with_query_hook, read_tcp_frame_admission,
    read_tcp_message_after_first_len_byte, write_tcp_message,
};
use tcp::{TcpServerSettings, serve_tcp_until};
#[cfg(test)]
use transfer::{
    DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT, TransferIngestBudget, TransferIngestTracker,
    load_pem_certs, load_pem_private_key_from_file, poll_soa_from_primary_with_tsig,
    poll_soa_from_primary_with_tsig_and_source, query_id_from_random_bytes,
    tcp_connect_with_timeout, transfer_axfr_from_target_with_tsig,
};
use transfer::{
    TransferSession, TransferTsig, poll_soa_from_target_with_tsig_and_source,
    transfer_axfr_from_target_with_tsig_and_source, transfer_ixfr_from_target_with_tsig,
    transfer_query_id, tsig_time_signed, unix_timestamp_seconds,
};
pub(crate) use transfer::{build_xot_client_config, load_pem_certs_for_primary};
pub use transfer::{poll_soa_from_primary, transfer_axfr_from_primary, transfer_ixfr_from_primary};

pub fn validate_secret_store_config(config: &ServerConfig) -> Result<(), String> {
    SecretManager::from_config(config)
        .map(|_| ())
        .map_err(|error| error.to_string())
}
use transfer_plan::{TransferPlan, ZoneTransferPlan};
#[cfg(test)]
use transfer_plan::{rotate_transfer_targets, uniform_index_from_u64};
#[cfg(feature = "af-xdp")]
pub(crate) use udp::UDP_PACKET_BUFFER_LEN;
#[cfg(test)]
use udp::{
    BoundUdpListener, StdUdpBatchIo, handle_udp_datagram_with_prepared_hook, send_std_udp_batch,
    serve_udp, serve_udp_packet_io_until,
};
#[cfg(any(test, feature = "af-xdp"))]
pub(crate) use udp::{PacketIo, PacketIoSendError};
use udp::{
    QueryMetricObservation, QueryObservationOptions, UdpServerSettings, bind_udp_listeners,
    observe_dns_cookie_metrics, observe_query_metrics, record_chaos_query_if_observed,
    record_dns_cookie_badcookie_if_emitted, record_query_lookup_metrics,
    record_query_response_metric, record_query_send_metric, record_response_cache_metric,
    response_cache_ineligible_reason, serve_bound_udp_until,
};
pub(crate) use udp::{UdpInbound, UdpOutbound, UdpPacketTarget};
pub(crate) use udp::{response_rcode, skip_response_record};

#[derive(Debug)]
pub struct Runtime {
    config: ServerConfig,
    zones: ZoneStore,
    zone_persistence: Option<ZonePersistence>,
    restored_zone_unix_secs: HashMap<String, u64>,
}

const NOTIFY_REFRESH_QUEUE_CAPACITY: usize = 1024;
const TRANSFER_TASK_BACKLOG_MULTIPLIER: usize = 4;
const ZSM_SCHEDULER_TICK: Duration = Duration::from_secs(1);
const SOA_TIMER_NEAR_MAX_WARNING_PERCENT: u64 = 90;
const RUNTIME_REGISTRY_PRUNE_INTERVAL: u64 = 256;
const CONTROL_PLANE_OPERATION_LIMIT: usize = 20;
const CONTROL_PLANE_RESPONSE_LIMIT_BYTES: usize = 256 * 1024;
const CONTROL_PLANE_TELEMETRY_QUEUE_CAPACITY: usize = 1024;

/// Builds a non-panicking monotonic deadline without shortening representable
/// wire-derived SOA timers. Operator timers are capped during validation; the
/// one-year fallback is used only when the platform cannot represent the
/// requested deadline at all.
fn runtime_deadline_with_effective_duration(
    now: Instant,
    requested: Duration,
) -> (Instant, Duration) {
    if let Some(deadline) = now.checked_add(requested) {
        return (deadline, requested);
    }
    let fallback = Duration::from_secs(MAX_RUNTIME_DURATION_SECS);
    now.checked_add(fallback)
        .map_or((now, Duration::ZERO), |deadline| (deadline, fallback))
}

fn runtime_deadline(now: Instant, duration: Duration) -> Instant {
    runtime_deadline_with_effective_duration(now, duration).0
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

impl Runtime {
    pub fn new(config: ServerConfig) -> Result<Self, RuntimeError> {
        // `ServerConfig` is public and can be mutated after parsing. Validate
        // before parsing names or constructing any runtime state so malformed
        // programmatic configurations return an ordinary startup error rather
        // than reaching the infallible-name assertions below.
        config
            .validate()
            .map_err(|error| RuntimeError::InvalidRuntimeConfig(error.to_string()))?;
        validate_runtime_config(&config)
            .map_err(|error| RuntimeError::InvalidRuntimeConfig(error.to_string()))?;
        let zones = ZoneStore::with_publication_policy(config.zone_publication.policy());
        let zone_persistence = config.server.zone_cache_directory.clone().map(|directory| {
            // The cache stores canonical uncompressed owner names, while
            // transfer accounting sees compressed DNS wire names. Bound
            // the worst RFC name-compression expansion without imposing a
            // new, lower zone-size ceiling.
            ZonePersistence::new(
                directory,
                config.limits.max_transfer_ingest_bytes.saturating_mul(128),
            )
        });
        let mut visible_origins = config
            .zones
            .iter()
            .map(|zone| {
                DomainName::from_absolute_str(&zone.name)
                    .expect("configuration validation rejects invalid zone names")
            })
            .collect::<Vec<_>>();
        let mut hidden_origins = Vec::new();
        let mut restored_zone_unix_secs = HashMap::new();
        for catalog_zone in &config.catalog_zones {
            let origin = DomainName::from_absolute_str(&catalog_zone.name)
                .expect("configuration validation rejects invalid catalog zone names");
            if catalog_zone.serve_catalog_zone {
                visible_origins.push(origin);
            } else {
                hidden_origins.push(origin);
            }
        }
        if let Some(persistence) = &zone_persistence {
            for origin in &visible_origins {
                match persistence.restore(origin, 1) {
                    Ok(Some(restored)) => {
                        zones
                            .insert_restored_snapshot(restored.snapshot, false)
                            .map_err(|error| {
                                RuntimeError::InvalidRuntimeConfig(format!(
                                    "persisted last-good zone {} cannot be published: {error}",
                                    origin
                                ))
                            })?;
                        restored_zone_unix_secs
                            .insert(origin.canonical_key(), restored.persisted_unix_secs);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(zone = %origin, %error, "persisted last-good zone rejected; starting in LOADING state")
                    }
                }
            }
            for origin in &hidden_origins {
                match persistence.restore(origin, 1) {
                    Ok(Some(restored)) => {
                        zones.insert_restored_snapshot(restored.snapshot, true).map_err(|error| {
                            RuntimeError::InvalidRuntimeConfig(format!(
                                "persisted last-good catalog zone {} cannot be published: {error}",
                                origin
                            ))
                        })?;
                        restored_zone_unix_secs
                            .insert(origin.canonical_key(), restored.persisted_unix_secs);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(zone = %origin, %error, "persisted last-good catalog zone rejected; starting in LOADING state")
                    }
                }
            }
        }
        visible_origins.retain(|origin| !zones.contains_exact_zone_for_control(origin));
        hidden_origins.retain(|origin| !zones.contains_exact_zone_for_control(origin));
        zones.insert_loading_batch(&visible_origins, &hidden_origins);

        Ok(Self {
            config,
            zones,
            zone_persistence,
            restored_zone_unix_secs,
        })
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
        // Runtime can be embedded with a programmatically constructed or
        // subsequently mutated ServerConfig, so repeat schema validation before
        // binding listeners or constructing capacity-bounded Tokio primitives.
        self.config
            .validate()
            .map_err(|error| RuntimeError::InvalidRuntimeConfig(error.to_string()))?;
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
            self.restore_refresh_status_or_record_loading(&refresh_registry, &origin);
        }
        for catalog_zone in &self.config.catalog_zones {
            let origin = DomainName::from_absolute_str(&catalog_zone.name)
                .expect("configuration validation rejects invalid catalog zone names");
            self.restore_refresh_status_or_record_loading(&refresh_registry, &origin);
        }
        let ixfr_cooldowns = IxfrCooldownRegistry::new(Duration::from_secs(
            self.config.limits.ixfr_disabled_cooldown_secs,
        ));
        let metrics = RuntimeMetrics::try_new_with_settings(
            self.config.rrl.max_keys,
            self.config.metrics.latency_histogram_buckets_seconds(),
            self.config.metrics.pipeline_timing_enabled,
            self.config.metrics.hot_path_detail,
        )
        .map_err(RuntimeError::InvalidRuntimeConfig)?;
        let startup_warning_count = self.config.configuration_warnings().len().saturating_add(
            runtime_config_warnings_with_secrets(&self.config, &secrets)
                .map_err(|error| RuntimeError::InvalidRuntimeConfig(error.to_string()))?
                .len(),
        );
        metrics.set_configuration_warnings(startup_warning_count as u64);
        let transfer_limit = Arc::new(Semaphore::new(self.config.limits.max_concurrent_transfers));
        let max_resident_transfer_tasks =
            max_resident_transfer_tasks(self.config.limits.max_concurrent_transfers);
        let control_plane_telemetry_reporter =
            ControlPlaneTelemetryReporter::from_config(&self.config);
        let (control_plane_telemetry, control_plane_telemetry_rx) =
            ControlPlaneTelemetryClient::new(control_plane_telemetry_reporter.enabled());

        info!(
            udp_listeners = self.config.udp_listeners().len(),
            tcp_listeners = self.config.tcp_listeners().len(),
            zones = self.zones.len(),
            "BoronDNS runtime initialized"
        );

        let mut listeners = JoinSet::new();
        let mut udp_listeners = JoinSet::new();
        let mut tcp_listeners = JoinSet::new();
        let mut health_listeners = JoinSet::new();
        let mut refresh_workers = JoinSet::new();
        let mut background_tasks = JoinSet::new();
        let mut telemetry_tasks = JoinSet::new();
        if let Some(control_plane_telemetry_rx) = control_plane_telemetry_rx {
            telemetry_tasks.spawn(serve_control_plane_telemetry(
                control_plane_telemetry_reporter,
                control_plane_telemetry_rx,
            ));
        }
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let tcp_source_connections = Arc::new(Mutex::new(HashMap::new()));
        let shutdown_grace = Duration::from_secs(self.config.limits.graceful_shutdown_secs);
        let runtime_status = RuntimeStatus::new();
        let notify_authority = NotifyAuthority::from_config(&self.config, secrets.clone());
        let notify_refresh = NotifyRefreshTracker::with_refresh_registry_and_transfer_plan(
            Duration::from_secs(self.config.limits.notify_dedup_secs),
            refresh_registry.clone(),
            transfer_plan.clone(),
        );
        catalog_manager.attach_runtime_registries(notify_refresh.clone(), ixfr_cooldowns.clone());
        // Reconcile a restored catalog before scheduling any network refreshes.
        // This reconstructs member transfer plans and restores their own
        // last-good snapshots, so an unavailable primary cannot turn a whole
        // catalog deployment into a cold start.
        let (startup_catalog_tx, startup_catalog_rx) = mpsc::channel(1);
        let startup_catalog_weak = startup_catalog_tx.downgrade();
        drop(startup_catalog_tx);
        drop(startup_catalog_rx);
        for configured_catalog in &self.config.catalog_zones {
            let origin = DomainName::from_absolute_str(&configured_catalog.name)
                .expect("configuration validation rejects invalid catalog zone names");
            let Some(restored) = self.zones.exact_snapshot_for_transfer(&origin) else {
                continue;
            };
            if restored.metadata().state != ZoneState::Active {
                continue;
            }
            let parsed = catalog_manager
                .parse_candidate_snapshot(restored.snapshot_for_transfer())
                .map_err(|error| {
                    RuntimeError::InvalidRuntimeConfig(format!(
                        "restored catalog zone {origin} failed catalog validation: {error}"
                    ))
                })?;
            if let Some(parsed) = parsed {
                let metadata = restored.into_metadata();
                catalog_manager
                    .apply_parsed_snapshot(
                        parsed,
                        &metadata,
                        &self.zones,
                        &transfer_plan,
                        &refresh_registry,
                        &notify_authority,
                        &startup_catalog_weak,
                        &metrics,
                        self.zone_persistence.as_ref(),
                    )
                    .await;
            }
        }
        let notify_log_limiter = NotifyLogLimiter::new(
            Duration::from_secs(self.config.limits.notify_log_rate_window_secs),
            self.config.limits.notify_log_max_keys,
        );
        let (notify_refresh_tx, notify_refresh_rx) = mpsc::channel(NOTIFY_REFRESH_QUEUE_CAPACITY);
        let rrl = RrlLimiter::from_config(&self.config.rrl, metrics.clone());
        let dns_cookie = dns_cookie_settings(&self.config.cookie);
        let cookie_prefix_metrics = CookiePrefixMetricSettings {
            ipv4_prefix_len: self.config.rrl.ipv4_prefix_len,
            ipv6_prefix_len: self.config.rrl.ipv6_prefix_len,
        };
        let dns_cookie_secrets = dns_cookie_secret_store_from_config(&self.config, dns_cookie)?;
        let mut health_shutdown = Vec::new();
        let health_connection_slots = Arc::new(Semaphore::new(self.config.health.max_connections));
        let mut udp_shutdown = Vec::new();
        let udp_admission_open = Arc::new(AtomicBool::new(true));
        let refresh_admission = RefreshAdmission::new();
        let mut tcp_shutdown = Vec::new();
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
        background_tasks.spawn(serve_runtime_registry_cleanup(
            notify_refresh.clone(),
            ixfr_cooldowns.clone(),
            ZSM_SCHEDULER_TICK,
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
                max_resident_transfer_tasks,
                telemetry: control_plane_telemetry.clone(),
                admission: refresh_admission.clone(),
                zone_persistence: self.zone_persistence.clone(),
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
                max_resident_transfer_tasks,
                telemetry: control_plane_telemetry,
                admission: refresh_admission.clone(),
                zone_persistence: self.zone_persistence.clone(),
            },
        ));
        listeners.spawn(serve_scheduled_refreshes(
            self.zones.clone(),
            refresh_registry.clone(),
            transfer_plan.clone(),
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
                transfer_plan.clone(),
                notify_refresh_tx.clone(),
                catalog_origins,
                secrets.clone(),
            ));
        }
        let metrics_rate_limiter = MetricsRateLimiter::from_config(self.config.health);
        let observability_rate_limiter =
            MetricsRateLimiter::from_observability_config(&self.config.observability);
        for (listener, health_shutdown_rx) in bound_health_listeners {
            health_listeners.spawn(serve_health(
                listener,
                HealthEndpointState {
                    zones: self.zones.clone(),
                    runtime_status: runtime_status.clone(),
                    metrics: metrics.clone(),
                    catalog_manager: catalog_manager.clone(),
                    refresh_registry: refresh_registry.clone(),
                    metrics_rate_limiter: metrics_rate_limiter.clone(),
                    observability: self.config.observability.clone(),
                    observability_auth: observability_auth.clone(),
                    observability_rate_limiter: observability_rate_limiter.clone(),
                    transfer_materials: transfer_materials.clone(),
                    secrets: secrets.clone(),
                    started_at: Instant::now(),
                    graceful_shutdown_secs: self.config.limits.graceful_shutdown_secs,
                    zone_shape_metrics_enabled: self.config.metrics.zone_shape_enabled,
                    connection_slots: health_connection_slots.clone(),
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
            let (udp_shutdown_tx, udp_shutdown_rx) = oneshot::channel();
            udp_shutdown.push(udp_shutdown_tx);
            let udp_admission_open = udp_admission_open.clone();
            udp_listeners.spawn(async move {
                serve_bound_udp_until(
                    udp_listener,
                    zones,
                    udp_settings,
                    udp_admission_open,
                    async move {
                        udp_shutdown_rx
                            .await
                            .unwrap_or_else(|_| tokio::time::Instant::now())
                    },
                )
                .await
            });
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
            let (tcp_shutdown_tx, tcp_shutdown_rx) = oneshot::channel();
            tcp_shutdown.push(tcp_shutdown_tx);
            tcp_listeners.spawn(async move {
                serve_tcp_until(listener, zones, tcp_settings, async move {
                    let _ = tcp_shutdown_rx.await;
                })
                .await
            });
        }

        loop {
            tokio::select! {
                signal = &mut shutdown_signal => {
                    let signal = signal.map_err(RuntimeError::ShutdownSignal)?;
                    let shutdown_started = tokio::time::Instant::now();
                    let shutdown_deadline = shutdown_started
                        .checked_add(shutdown_grace)
                        .unwrap_or(shutdown_started);
                    info!(
                        signal,
                        grace_secs = shutdown_grace.as_secs(),
                        active_tcp_connections = tcp_connections.load(Ordering::Acquire),
                        "shutdown signal received; draining runtime"
                    );
                    runtime_status.mark_draining();
                    udp_admission_open.store(false, Ordering::Release);
                    refresh_admission.close();
                    for udp_shutdown in udp_shutdown.drain(..) {
                        let _ = udp_shutdown.send(shutdown_deadline);
                    }
                    for tcp_shutdown in tcp_shutdown.drain(..) {
                        let _ = tcp_shutdown.send(());
                    }
                    abort_task_set_until(&mut listeners, shutdown_deadline, "listener").await;
                    abort_task_set_until(
                        &mut background_tasks,
                        shutdown_deadline,
                        "background",
                    )
                    .await;
                    drop(notify_refresh_tx);
                    let (udp_drained, tcp_drained, refresh_drained) = tokio::join!(
                        drain_task_set_until(
                            &mut udp_listeners,
                            shutdown_deadline,
                            "UDP listener",
                        ),
                        drain_task_set_until(
                            &mut tcp_listeners,
                            shutdown_deadline,
                            "TCP listener",
                        ),
                        drain_task_set_until(
                            &mut refresh_workers,
                            shutdown_deadline,
                            "refresh transfer",
                        )
                    );
                    if udp_drained {
                        info!("UDP in-flight batch drain completed");
                    } else {
                        warn!("shutdown grace period elapsed with an active UDP batch");
                    }
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
                    let telemetry_drained =
                        drain_task_set_until(
                            &mut telemetry_tasks,
                            shutdown_deadline,
                            "control-plane telemetry",
                        )
                        .await;
                    if telemetry_drained {
                        info!("control-plane telemetry drain completed");
                    } else {
                        warn!("shutdown grace period elapsed with queued control-plane telemetry");
                    }
                    for health_shutdown in health_shutdown.drain(..) {
                        let _ = health_shutdown.send(());
                    }
                    let health_drained =
                        drain_task_set_until(
                            &mut health_listeners,
                            shutdown_deadline,
                            "health listener",
                        )
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
                result = udp_listeners.join_next(), if !udp_listeners.is_empty() => {
                    handle_runtime_task_result("UDP listener", result)?;
                }
                result = tcp_listeners.join_next(), if !tcp_listeners.is_empty() => {
                    handle_runtime_task_result("TCP listener", result)?;
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
                result = telemetry_tasks.join_next(), if !telemetry_tasks.is_empty() => {
                    handle_runtime_task_result("control-plane telemetry", result)?;
                }
            }

            if listeners.is_empty()
                && udp_listeners.is_empty()
                && tcp_listeners.is_empty()
                && refresh_workers.is_empty()
                && health_listeners.is_empty()
            {
                let cleanup_started = tokio::time::Instant::now();
                let cleanup_deadline = cleanup_started
                    .checked_add(shutdown_grace)
                    .unwrap_or(cleanup_started);
                abort_task_set_until(&mut background_tasks, cleanup_deadline, "background").await;
                abort_task_set_until(
                    &mut telemetry_tasks,
                    cleanup_deadline,
                    "control-plane telemetry",
                )
                .await;
                break;
            }
        }

        Ok(())
    }

    fn restore_refresh_status_or_record_loading(
        &self,
        refresh_registry: &ZoneRefreshRegistry,
        origin: &DomainName,
    ) {
        let Some(persisted_unix_secs) = self
            .restored_zone_unix_secs
            .get(origin.canonical_key().as_str())
            .copied()
        else {
            refresh_registry.record_loading_start(origin);
            return;
        };
        let Some(metadata) = self.zones.exact_zone_metadata(origin) else {
            refresh_registry.record_loading_start(origin);
            return;
        };
        let elapsed = unix_timestamp_seconds().saturating_sub(persisted_unix_secs);
        let now = Instant::now();
        let transfer_time = now.checked_sub(Duration::from_secs(elapsed)).unwrap_or(now);
        refresh_registry.record_success_metadata_at_with_timestamp(
            &metadata,
            transfer_time,
            persisted_unix_secs,
        );
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
                max_resident_transfer_tasks: max_resident_transfer_tasks(max_concurrent_transfers),
                telemetry: ControlPlaneTelemetryClient::disabled(),
                admission: RefreshAdmission::new(),
                zone_persistence: self.zone_persistence.clone(),
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
    preferred_primary_ip: Option<IpAddr>,
    reason: RefreshReason,
    retry_after_queue_drop: Option<RefreshReason>,
    notify_dedup_token: Option<NotifyDedupToken>,
    plan_generation: Option<u64>,
}

impl RefreshRequest {
    fn new(zone: DomainName, requested_serial: Option<u32>, reason: RefreshReason) -> Self {
        Self {
            zone,
            requested_serial,
            preferred_primary_ip: None,
            reason,
            retry_after_queue_drop: matches!(
                reason,
                RefreshReason::Catalog | RefreshReason::ControlPlane | RefreshReason::Scheduled
            )
            .then_some(reason),
            notify_dedup_token: None,
            plan_generation: None,
        }
    }

    fn with_notify_dedup_token(mut self, token: NotifyDedupToken) -> Self {
        self.plan_generation = token.plan_generation;
        self.notify_dedup_token = Some(token);
        self
    }

    fn with_preferred_primary_ip(mut self, source: IpAddr) -> Self {
        self.preferred_primary_ip = Some(source);
        self
    }

    fn with_plan_generation(mut self, plan: &ZoneTransferPlan) -> Self {
        self.plan_generation = Some(plan.generation());
        self
    }

    fn with_plan_generation_value(mut self, generation: u64) -> Self {
        self.plan_generation = Some(generation);
        self
    }

    fn notify_incarnation_is_current(&self, registry: &ZoneRefreshRegistry) -> bool {
        self.notify_dedup_token.as_ref().is_none_or(|token| {
            token
                .refresh_generation
                .is_none_or(|generation| registry.is_current_generation(&self.zone, generation))
        })
    }

    fn plan_incarnation_is_current(&self, transfer_plan: &TransferPlan) -> bool {
        self.plan_generation.is_none_or(|generation| {
            transfer_plan
                .get(&self.zone)
                .is_some_and(|plan| plan.generation() == generation)
        })
    }

    fn incarnation_is_current(
        &self,
        registry: &ZoneRefreshRegistry,
        transfer_plan: &TransferPlan,
    ) -> bool {
        self.notify_incarnation_is_current(registry)
            && self.plan_incarnation_is_current(transfer_plan)
    }

    fn rollback_notify_dedup_after_queue_drop(&self) {
        if let Some(token) = &self.notify_dedup_token {
            token.rollback();
        }
    }

    fn commit_notify_dedup_after_queue_admission_at(&mut self, now: Instant) -> bool {
        let Some(token) = self.notify_dedup_token.take() else {
            return true;
        };
        if !token.commit_at(now) {
            return false;
        }
        self.notify_dedup_token = Some(token);
        // Once a NOTIFY is admitted internally it may still be evicted to
        // retain an active-zone follow-up. Preserve that committed signal as
        // an immediate scheduler retry; outer-only reservations remain None.
        if self.retry_after_queue_drop.is_none() {
            self.retry_after_queue_drop = Some(RefreshReason::Notify);
        }
        true
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn retained_notify_dedup_token_count(&self) -> usize {
        self.notify_dedup_token.iter().count()
    }
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

fn enqueue_pending_refresh_request(
    pending_requests: &mut VecDeque<RefreshRequest>,
    pending_keys: &mut HashSet<String>,
    active_keys: &HashSet<String>,
    request: RefreshRequest,
) -> Option<RefreshRequest> {
    enqueue_pending_refresh_request_at(
        pending_requests,
        pending_keys,
        active_keys,
        request,
        Instant::now(),
    )
}

fn enqueue_pending_refresh_request_at(
    pending_requests: &mut VecDeque<RefreshRequest>,
    pending_keys: &mut HashSet<String>,
    active_keys: &HashSet<String>,
    mut request: RefreshRequest,
    now: Instant,
) -> Option<RefreshRequest> {
    let key = request.zone.canonical_key();
    if pending_keys.contains(&key) {
        if let Some(existing) = pending_requests
            .iter_mut()
            .find(|queued| queued.zone.canonical_key() == key)
        {
            if !request.commit_notify_dedup_after_queue_admission_at(now) {
                return Some(request);
            }
            if let (Some(existing_generation), Some(incoming_generation)) =
                (existing.plan_generation, request.plan_generation)
                && existing_generation != incoming_generation
            {
                if incoming_generation > existing_generation {
                    return Some(std::mem::replace(existing, request));
                }
                return Some(request);
            }
            merge_refresh_request(existing, request);
        }
        return None;
    }
    if pending_requests.len() >= NOTIFY_REFRESH_QUEUE_CAPACITY {
        if active_keys.contains(&key) {
            if !request.commit_notify_dedup_after_queue_admission_at(now) {
                return Some(request);
            }
            let Some(evicted) = pending_requests.pop_back() else {
                return Some(request);
            };
            let evicted_key = evicted.zone.canonical_key();
            pending_keys.remove(&evicted_key);
            warn!(
                zone = %evicted.zone,
                reason = %evicted.reason.as_str(),
                retained_zone = %request.zone,
                retained_reason = %request.reason.as_str(),
                queue_capacity = NOTIFY_REFRESH_QUEUE_CAPACITY,
                "pending refresh request evicted to retain active-zone follow-up"
            );
            pending_keys.insert(key);
            pending_requests.push_back(request);
            return Some(evicted);
        } else {
            warn!(
                zone = %request.zone,
                reason = %request.reason.as_str(),
                queue_capacity = NOTIFY_REFRESH_QUEUE_CAPACITY,
                "refresh request dropped because internal pending queue is full"
            );
            return Some(request);
        }
    }
    if !request.commit_notify_dedup_after_queue_admission_at(now) {
        return Some(request);
    }
    pending_keys.insert(key);
    pending_requests.push_back(request);
    None
}

fn validated_refresh_plan(
    request: &RefreshRequest,
    registry: &ZoneRefreshRegistry,
    transfer_plan: &TransferPlan,
) -> Option<ZoneTransferPlan> {
    if !request.notify_incarnation_is_current(registry) {
        return None;
    }
    let plan = transfer_plan.get(&request.zone)?;
    if request
        .plan_generation
        .is_some_and(|generation| plan.generation() != generation)
    {
        return None;
    }
    Some(plan)
}

async fn begin_validated_refresh_attempt(
    request: &RefreshRequest,
    registry: &ZoneRefreshRegistry,
    transfer_plan: &TransferPlan,
    plan: &ZoneTransferPlan,
) -> Option<ZoneRefreshAttempt> {
    if !request.incarnation_is_current(registry, transfer_plan)
        || !transfer_plan.is_current_plan(plan)
    {
        return None;
    }
    let attempt = registry.begin_attempt(&request.zone).await;
    if !request.incarnation_is_current(registry, transfer_plan)
        || !transfer_plan.is_current_plan(plan)
    {
        attempt.discard_obsolete();
        return None;
    }
    Some(attempt)
}

async fn acquire_transfer_permit_for_current_plan(
    transfer_plan: &TransferPlan,
    plan: &ZoneTransferPlan,
    transfer_limit: Arc<Semaphore>,
) -> Option<OwnedSemaphorePermit> {
    let permit = tokio::select! {
        biased;
        () = plan.cancelled() => return None,
        permit = transfer_limit.acquire_owned() => permit.ok()?,
    };
    transfer_plan.is_current_plan(plan).then_some(permit)
}

#[cfg(test)]
fn record_success_if_current_plan(
    refresh_registry: &ZoneRefreshRegistry,
    transfer_plan: &TransferPlan,
    plan: &ZoneTransferPlan,
    metadata: &ZoneMetadata,
) -> bool {
    if transfer_plan.is_current_plan(plan) {
        refresh_registry.record_success_from_metadata(metadata);
        true
    } else {
        warn!(
            zone = %plan.origin,
            "refresh success ignored because zone no longer has the same transfer plan"
        );
        false
    }
}

fn record_attempt_success_if_current_plan(
    attempt: &mut ZoneRefreshAttempt,
    transfer_plan: &TransferPlan,
    plan: &ZoneTransferPlan,
    metadata: &ZoneMetadata,
) -> bool {
    if transfer_plan.is_current_plan(plan) {
        attempt.record_success(metadata)
    } else {
        warn!(
            zone = %plan.origin,
            "refresh success ignored because zone no longer has the same transfer plan"
        );
        false
    }
}

fn merge_refresh_request(existing: &mut RefreshRequest, mut incoming: RefreshRequest) {
    existing.requested_serial = match (existing.requested_serial, incoming.requested_serial) {
        (Some(existing_serial), Some(incoming_serial))
            if serial_after(incoming_serial, existing_serial) =>
        {
            Some(incoming_serial)
        }
        (Some(existing_serial), Some(_)) => Some(existing_serial),
        // A missing serial means the request is unconditional. Coalescing must
        // never weaken catalog reconciliation or an operator/scheduler retry
        // into a serial-skippable NOTIFY.
        _ => None,
    };
    existing.retry_after_queue_drop = match (
        existing.retry_after_queue_drop,
        incoming.retry_after_queue_drop,
    ) {
        (Some(RefreshReason::Catalog), _) | (_, Some(RefreshReason::Catalog)) => {
            Some(RefreshReason::Catalog)
        }
        (Some(reason), _) | (_, Some(reason)) => Some(reason),
        (None, None) => None,
    };
    if incoming.notify_dedup_token.is_some() {
        existing.notify_dedup_token = incoming.notify_dedup_token.take();
        existing.plan_generation = incoming.plan_generation;
        existing.preferred_primary_ip = incoming.preferred_primary_ip;
    } else if incoming.reason != RefreshReason::Notify {
        // A catalog/control-plane/scheduled request belongs to the current
        // lifecycle and is independently retryable. Do not let a previously
        // queued NOTIFY token make the merged request stale after remove/readd.
        existing.notify_dedup_token = None;
        existing.plan_generation = incoming.plan_generation;
        existing.preferred_primary_ip = None;
    }
    existing.reason = incoming.reason;
}

// Catalog/refresh lock hierarchy:
//
// 1. `CatalogManager::reconcile_lock` is the outer catalog mutation lock. While
//    it is held, the membership/desired-membership/member-owner mutexes are
//    acquired one at a time and released before another such mutex is taken.
//    The guard is dropped before awaiting a refresh-queue send.
// 2. A zone refresh takes the per-zone `AsyncMutex` before `statuses`. The
//    `ownerships` mutex is held only long enough to obtain that per-zone lock;
//    it is never held while waiting for the per-zone lock or taking `statuses`.
// 3. NOTIFY admission may take `statuses` and then `last_signal_by_zone` for
//    its synchronous reservation/enqueue transaction. No path may acquire
//    `statuses` while holding `last_signal_by_zone`; catalog removal drops the
//    status lock before removing a NOTIFY reservation.
// 4. The catalog's notify/IXFR option mutexes may call into their contained
//    tracker/registry while held. Their inner locks never acquire the option
//    mutexes, so that direction must not be reversed.
//
// Ordinary `std::sync::Mutex` guards must never cross an `.await` point. New
// nested acquisitions must extend this order explicitly rather than relying on
// call-site inspection.
#[derive(Debug, Clone)]
struct CatalogManager {
    catalogs_by_key: Arc<HashMap<String, CatalogRuntimeConfig>>,
    static_zone_keys: Arc<HashSet<String>>,
    memberships_by_catalog: Arc<Mutex<HashMap<String, HashMap<String, DomainName>>>>,
    desired_memberships_by_catalog: Arc<Mutex<HashMap<String, HashMap<String, CatalogMember>>>>,
    member_owners_by_key: Arc<Mutex<HashMap<String, String>>>,
    notify_refresh_registry: Arc<Mutex<Option<NotifyRefreshTracker>>>,
    ixfr_cooldown_registry: Arc<Mutex<Option<IxfrCooldownRegistry>>>,
    reconcile_lock: Arc<AsyncMutex<()>>,
}

impl Default for CatalogManager {
    fn default() -> Self {
        Self {
            catalogs_by_key: Arc::new(HashMap::new()),
            static_zone_keys: Arc::new(HashSet::new()),
            memberships_by_catalog: Arc::new(Mutex::new(HashMap::new())),
            desired_memberships_by_catalog: Arc::new(Mutex::new(HashMap::new())),
            member_owners_by_key: Arc::new(Mutex::new(HashMap::new())),
            notify_refresh_registry: Arc::new(Mutex::new(None)),
            ixfr_cooldown_registry: Arc::new(Mutex::new(None)),
            reconcile_lock: Arc::new(AsyncMutex::new(())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogMemberMetric {
    pub(crate) catalog_zone: DomainName,
    pub(crate) member_zone: DomainName,
    pub(crate) managed: bool,
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
            desired_memberships_by_catalog: Arc::new(Mutex::new(HashMap::new())),
            member_owners_by_key: Arc::new(Mutex::new(HashMap::new())),
            notify_refresh_registry: Arc::new(Mutex::new(None)),
            ixfr_cooldown_registry: Arc::new(Mutex::new(None)),
            reconcile_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    fn attach_runtime_registries(
        &self,
        notify_refresh: NotifyRefreshTracker,
        ixfr_cooldowns: IxfrCooldownRegistry,
    ) {
        *self
            .notify_refresh_registry
            .lock()
            .expect("catalog NOTIFY refresh registry lock poisoned") = Some(notify_refresh);
        *self
            .ixfr_cooldown_registry
            .lock()
            .expect("catalog IXFR cooldown registry lock poisoned") = Some(ixfr_cooldowns);
    }

    fn remove_member_notify_registry_entry(&self, origin: &DomainName) {
        if let Some(notify_refresh) = self
            .notify_refresh_registry
            .lock()
            .expect("catalog NOTIFY refresh registry lock poisoned")
            .as_ref()
        {
            notify_refresh.remove_zone(origin);
        }
    }

    fn reconcile_member_ixfr_registry_entries(
        &self,
        removed_origins: &[DomainName],
        changed_plans: &[(DomainName, u64)],
    ) {
        if let Some(ixfr_cooldowns) = self
            .ixfr_cooldown_registry
            .lock()
            .expect("catalog IXFR cooldown registry lock poisoned")
            .as_ref()
        {
            let _ = ixfr_cooldowns.reconcile_catalog_generations(removed_origins, changed_plans);
        }
    }

    fn is_catalog_key(&self, origin_key: &str) -> bool {
        self.catalogs_by_key.contains_key(origin_key)
    }

    fn parse_candidate_snapshot(
        &self,
        snapshot: &ZoneSnapshot,
    ) -> Result<Option<ParsedCatalogMembers>, CatalogError> {
        self.parse_candidate_view(snapshot.catalog_zone_view())
    }

    fn parse_candidate_view(
        &self,
        catalog_view: CatalogZoneView<'_>,
    ) -> Result<Option<ParsedCatalogMembers>, CatalogError> {
        let Some(catalog) = self
            .catalogs_by_key
            .get(catalog_view.origin().canonical_key().as_str())
        else {
            return Ok(None);
        };
        parse_catalog_members_bounded_with_filter(
            catalog_view,
            catalog.config.max_member_zones,
            |member| {
                let member_key = member.canonical_key();
                if self.catalogs_by_key.contains_key(&member_key) {
                    error!(
                        category = "transfer",
                        event = "catalog_member_name_clash",
                        catalog_zone = %catalog.origin,
                        zone = %member,
                        "catalog member zone clashes with an existing catalog zone; ignoring incoming member"
                    );
                    false
                } else if self.static_zone_keys.contains(&member_key) {
                    error!(
                        category = "transfer",
                        event = "catalog_member_name_clash",
                        catalog_zone = %catalog.origin,
                        zone = %member,
                        "catalog member zone already has static configuration; ignoring incoming member"
                    );
                    false
                } else {
                    true
                }
            },
        )
        .map(Some)
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
    async fn apply_parsed_snapshot(
        &self,
        parsed: ParsedCatalogMembers,
        metadata: &ZoneMetadata,
        zones: &ZoneStore,
        transfer_plan: &TransferPlan,
        refresh_registry: &ZoneRefreshRegistry,
        notify_authority: &NotifyAuthority,
        refresh_tx: &mpsc::WeakSender<RefreshRequest>,
        metrics: &RuntimeMetrics,
        zone_persistence: Option<&ZonePersistence>,
    ) {
        let Some(catalog) = self.catalogs_by_key.get(metadata.origin_key.as_ref()) else {
            return;
        };
        let ParsedCatalogMembers { members, dropped } = parsed;
        let retained_member_count = members.len();

        let catalog_key = catalog.origin.canonical_key();
        let mut members_by_key = HashMap::<String, CatalogMember>::new();
        for member in members {
            let member_key = member.zone.canonical_key();
            if self.catalogs_by_key.contains_key(&member_key) {
                error!(
                    category = "transfer",
                    event = "catalog_member_name_clash",
                    catalog_zone = %catalog.origin,
                    zone = %member.zone,
                    "catalog member zone clashes with an existing catalog zone; ignoring incoming member"
                );
                continue;
            }
            if self.static_zone_keys.contains(&member_key) {
                error!(
                    category = "transfer",
                    event = "catalog_member_name_clash",
                    catalog_zone = %catalog.origin,
                    zone = %member.zone,
                    "catalog member zone already has static configuration; ignoring incoming member"
                );
                continue;
            }
            members_by_key.insert(member_key, member);
        }
        if dropped > 0 {
            error!(
                category = "transfer",
                event = "catalog_member_limit_exceeded",
                catalog_zone = %catalog.origin,
                max_member_zones = catalog.config.max_member_zones,
                member_count = retained_member_count.saturating_add(dropped),
                dropped,
                "catalog member zone limit exceeded; dropping excess catalog members"
            );
        }
        if transfer_plan.get(&catalog.origin).is_none() {
            warn!(
                category = "transfer",
                event = "catalog_without_transfer_plan",
                zone = %catalog.origin,
                "catalog zone has no transfer plan"
            );
            return;
        }

        let mut new_member_keys = HashSet::<String>::new();
        for (member_key, member) in &members_by_key {
            let extensions_enabled = catalog.config.member_transfer_extensions;
            let malformed_extension = extensions_enabled && member.transfer.is_malformed();
            let transfer_override = extensions_enabled
                .then_some(member.transfer.valid())
                .flatten();
            let has_valid_plan = (malformed_extension && transfer_plan.get(&member.zone).is_some())
                || transfer_plan
                    .catalog_member_plan(&catalog.origin, member.zone.clone(), transfer_override)
                    .is_some();
            if has_valid_plan {
                new_member_keys.insert(member_key.clone());
            } else {
                warn!(
                    category = "transfer",
                    event = "catalog_without_valid_member_transfer_plan",
                    catalog_zone = %catalog.origin,
                    zone = %member.zone,
                    "catalog zone has no valid member transfer plan"
                );
            }
        }

        let candidate_members_by_key = members_by_key
            .iter()
            .filter(|(key, _)| new_member_keys.contains(*key))
            .map(|(key, member)| (key.clone(), member.clone()))
            .collect::<HashMap<_, _>>();

        let reconcile_guard = self.reconcile_lock.lock().await;

        // RFC 9432 section 5.2 gives ownership to the already configured
        // instance. A later catalog listing the same member is a name clash
        // and must be ignored; catalog-name ordering is not a migration rule.
        let existing_owners = self
            .member_owners_by_key
            .lock()
            .expect("catalog member owner lock poisoned")
            .clone();
        let mut desired_members_by_key = HashMap::new();
        for (member_key, member) in candidate_members_by_key {
            if existing_owners
                .get(&member_key)
                .is_some_and(|owner| owner != &catalog_key)
            {
                error!(
                    category = "transfer",
                    event = "catalog_member_name_clash",
                    catalog_zone = %catalog.origin,
                    zone = %member.zone,
                    "catalog member zone is already managed by another catalog; ignoring incoming instance"
                );
                continue;
            }
            desired_members_by_key.insert(member_key, member);
        }
        let new_member_keys = desired_members_by_key
            .keys()
            .cloned()
            .collect::<HashSet<_>>();

        let previous_desired_members = self
            .desired_memberships_by_catalog
            .lock()
            .expect("catalog desired membership lock poisoned")
            .insert(catalog_key.clone(), desired_members_by_key.clone())
            .unwrap_or_default();

        let (old_members_by_key, old_member_keys) = {
            let memberships = self
                .memberships_by_catalog
                .lock()
                .expect("catalog membership lock poisoned");
            let old_members_by_key = memberships.get(&catalog_key).cloned().unwrap_or_default();
            let old_member_keys = old_members_by_key.keys().cloned().collect::<HashSet<_>>();
            (old_members_by_key, old_member_keys)
        };

        let mut pending_catalog_refreshes = Vec::<(DomainName, DomainName, u64)>::new();
        let mut removed_ixfr_members = Vec::<DomainName>::new();
        let mut loading_members = Vec::<DomainName>::new();
        let mut changed_ixfr_members = Vec::<(DomainName, u64)>::new();
        let mut accepted_members_by_key = HashMap::<String, DomainName>::new();
        for (member_key, member) in &desired_members_by_key {
            accepted_members_by_key.insert(member_key.clone(), member.zone.clone());
        }

        let mut affected_member_keys = old_member_keys
            .union(&new_member_keys)
            .cloned()
            .collect::<Vec<_>>();
        affected_member_keys.sort();
        for member_key in affected_member_keys {
            let Some(owner_member) = desired_members_by_key.get(&member_key).cloned() else {
                let member_origin = old_members_by_key
                    .get(&member_key)
                    .cloned()
                    .or_else(|| DomainName::from_absolute_str(&member_key).ok());
                self.member_owners_by_key
                    .lock()
                    .expect("catalog member owner lock poisoned")
                    .remove(&member_key);
                let Some(member_origin) = member_origin else {
                    warn!(
                        category = "transfer",
                        event = "catalog_member_remove_missing_previous_origin",
                        catalog_zone = %catalog.origin,
                        zone_key = %member_key,
                        "catalog membership was missing previous member origin; skipping removal"
                    );
                    continue;
                };
                transfer_plan.remove(&member_origin);
                notify_authority.remove_zone(&member_origin);
                // NOTIFY admission locks refresh status before its reservation.
                // Remove status first so an already-authorized concurrent packet
                // either linearizes before cleanup or observes a missing lifecycle.
                refresh_registry.remove_zone(&member_origin);
                self.remove_member_notify_registry_entry(&member_origin);
                removed_ixfr_members.push(member_origin.clone());
                info!(
                    category = "transfer",
                    event = "catalog_member_removed",
                    catalog_zone = %catalog.origin,
                    zone = %member_origin,
                    "removed catalog-managed member zone"
                );
                continue;
            };

            let owner_catalog = catalog;
            let member_node_changed =
                previous_desired_members
                    .get(&member_key)
                    .is_some_and(|previous| {
                        previous.member_node.canonical_key()
                            != owner_member.member_node.canonical_key()
                    });
            if member_node_changed {
                // RFC 9432 sections 5.4 and 5.6 require a member-node rename
                // to be processed as remove/reset followed by a fresh add.
                transfer_plan.remove(&owner_member.zone);
                notify_authority.remove_zone(&owner_member.zone);
                refresh_registry.remove_zone(&owner_member.zone);
                self.remove_member_notify_registry_entry(&owner_member.zone);
                removed_ixfr_members.push(owner_member.zone.clone());
                info!(
                    category = "transfer",
                    event = "catalog_member_node_changed",
                    catalog_zone = %owner_catalog.origin,
                    zone = %owner_member.zone,
                    member_node = %owner_member.member_node,
                    "catalog member node changed; reset associated zone state before re-adding"
                );
            }
            let extensions_enabled = owner_catalog.config.member_transfer_extensions;
            let malformed_extension = extensions_enabled && owner_member.transfer.is_malformed();
            let transfer_override = extensions_enabled
                .then_some(owner_member.transfer.valid())
                .flatten();
            let existing_plan = transfer_plan.get(&owner_member.zone);
            let retain_existing_policy = malformed_extension && existing_plan.is_some();

            let (plan_changed, current_plan, owner_changed) = if retain_existing_policy {
                warn!(
                    category = "transfer",
                    event = "catalog_member_malformed_transfer_extension_retained",
                    catalog_zone = %owner_catalog.origin,
                    zone = %owner_member.zone,
                    "catalog member transfer extension is malformed; retaining the last valid transfer and NOTIFY policy"
                );
                (false, existing_plan, false)
            } else {
                if malformed_extension {
                    warn!(
                        category = "transfer",
                        event = "catalog_member_malformed_transfer_extension_fallback",
                        catalog_zone = %owner_catalog.origin,
                        zone = %owner_member.zone,
                        "new catalog member transfer extension is malformed; using the configured static fallback policy"
                    );
                }
                let Some(member_plan) = transfer_plan.catalog_member_plan(
                    &owner_catalog.origin,
                    owner_member.zone.clone(),
                    transfer_override,
                ) else {
                    warn!(
                        category = "transfer",
                        event = "catalog_member_transfer_override_rejected",
                        catalog_zone = %owner_catalog.origin,
                        zone = %owner_member.zone,
                        "catalog owner transfer override was rejected; retaining existing policy"
                    );
                    continue;
                };

                let plan_changed =
                    transfer_plan.insert_preserving_generation_if_unchanged(member_plan);
                let current_plan = transfer_plan.get(&owner_member.zone);
                notify_authority.add_zone_from_catalog(
                    &owner_member.zone,
                    &owner_catalog.config,
                    transfer_override,
                );
                let canonical_owner_key = owner_catalog.origin.canonical_key();
                let previous_owner = self
                    .member_owners_by_key
                    .lock()
                    .expect("catalog member owner lock poisoned")
                    .insert(member_key.clone(), canonical_owner_key.clone());
                let owner_changed = previous_owner.as_deref() != Some(canonical_owner_key.as_str());
                (plan_changed, current_plan, owner_changed)
            };
            if plan_changed && let Some(current_plan) = current_plan.as_ref() {
                changed_ixfr_members.push((current_plan.origin.clone(), current_plan.generation()));
            }
            let mut zone_missing =
                member_node_changed || !zones.contains_exact_zone_for_control(&owner_member.zone);
            if zone_missing
                && !member_node_changed
                && let Some(persistence) = zone_persistence
            {
                match persistence.restore(&owner_member.zone, 1) {
                    Ok(Some(restored_zone)) => {
                        match zones.insert_restored_snapshot(restored_zone.snapshot, false) {
                            Ok(restored_metadata) => {
                                zone_missing = false;
                                let elapsed = unix_timestamp_seconds()
                                    .saturating_sub(restored_zone.persisted_unix_secs);
                                let now = Instant::now();
                                let transfer_time =
                                    now.checked_sub(Duration::from_secs(elapsed)).unwrap_or(now);
                                refresh_registry.record_success_metadata_at_with_timestamp(
                                    &restored_metadata,
                                    transfer_time,
                                    restored_zone.persisted_unix_secs,
                                );
                                info!(
                                    category = "transfer",
                                    event = "catalog_member_last_good_restored",
                                    catalog_zone = %owner_catalog.origin,
                                    zone = %owner_member.zone,
                                    serial = ?restored_metadata.serial,
                                    "restored catalog member last-good zone"
                                );
                            }
                            Err(error) => warn!(
                                catalog_zone = %owner_catalog.origin,
                                zone = %owner_member.zone,
                                %error,
                                "persisted catalog member could not be published"
                            ),
                        }
                    }
                    Ok(None) => {}
                    Err(error) => warn!(
                        catalog_zone = %owner_catalog.origin,
                        zone = %owner_member.zone,
                        %error,
                        "persisted catalog member rejected; starting in LOADING state"
                    ),
                }
            }
            if zone_missing {
                loading_members.push(owner_member.zone.clone());
                refresh_registry.record_loading_start(&owner_member.zone);
            }
            if zone_missing || plan_changed {
                if let Some(current_plan) = current_plan {
                    pending_catalog_refreshes.push((
                        owner_member.zone.clone(),
                        owner_catalog.origin.clone(),
                        current_plan.generation(),
                    ));
                }
            } else if owner_changed {
                info!(
                    category = "transfer",
                    event = "catalog_member_owner_changed",
                    catalog_zone = %owner_catalog.origin,
                    zone = %owner_member.zone,
                    "catalog member policy ownership changed without a transfer-plan change"
                );
            }
        }

        // Keep catalog visibility in the same one-shot directory publication as
        // member additions/removals. The catalog origin comes from the carried
        // transfer metadata boundary validated above; do not reopen or clone the
        // transferred snapshot merely to recover it here.
        let mut visible_catalogs = Vec::new();
        let mut hidden_catalogs = Vec::new();
        if catalog.config.serve_catalog_zone {
            visible_catalogs.push(metadata.origin.clone());
        } else {
            hidden_catalogs.push(metadata.origin.clone());
        }
        zones.apply_atomic_directory_update(
            &loading_members,
            &removed_ixfr_members,
            &visible_catalogs,
            &hidden_catalogs,
        );
        metrics.remove_zone_metrics(zones, &removed_ixfr_members);

        self.reconcile_member_ixfr_registry_entries(&removed_ixfr_members, &changed_ixfr_members);

        self.memberships_by_catalog
            .lock()
            .expect("catalog membership lock poisoned")
            .insert(catalog_key.clone(), accepted_members_by_key.clone());
        drop(reconcile_guard);
        let Some(refresh_tx) = refresh_tx.upgrade() else {
            for (member_origin, owner_catalog_origin, _) in pending_catalog_refreshes {
                warn!(
                    category = "transfer",
                    event = "catalog_member_refresh_queue_closed",
                    catalog_zone = %owner_catalog_origin,
                    zone = %member_origin,
                    "catalog member refresh queue closed"
                );
            }
            return;
        };
        for (member_origin, owner_catalog_origin, plan_generation) in pending_catalog_refreshes {
            if refresh_tx
                .send(
                    RefreshRequest::new(member_origin.clone(), None, RefreshReason::Catalog)
                        .with_plan_generation_value(plan_generation),
                )
                .await
                .is_err()
            {
                warn!(
                    category = "transfer",
                    event = "catalog_member_refresh_queue_closed",
                    catalog_zone = %owner_catalog_origin,
                    zone = %member_origin,
                    "catalog member refresh queue closed"
                );
                continue;
            }
            info!(
                category = "transfer",
                event = "catalog_member_added",
                catalog_zone = %owner_catalog_origin,
                zone = %member_origin,
                "added catalog-managed member zone"
            );
        }
    }

    #[cfg(test)]
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
        let Some(parsed) = self
            .parse_candidate_view(catalog_view)
            .expect("test catalog snapshot parses")
        else {
            return;
        };
        self.apply_parsed_snapshot(
            parsed,
            metadata,
            zones,
            transfer_plan,
            refresh_registry,
            notify_authority,
            refresh_tx,
            &RuntimeMetrics::new(),
            None,
        )
        .await;
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
    ownerships: Arc<Mutex<HashMap<String, StdWeak<AsyncMutex<()>>>>>,
    ownership_insertions: Arc<AtomicU64>,
    next_generation: Arc<AtomicU64>,
}

struct ZoneRefreshAttempt {
    registry: ZoneRefreshRegistry,
    origin: DomainName,
    generation: u64,
    created_status: bool,
    _ownership: OwnedMutexGuard<()>,
    finished: bool,
}

#[derive(Debug, Clone)]
struct IxfrCooldownRegistry {
    cooldown: Duration,
    disabled_until: Arc<Mutex<HashMap<IxfrCooldownKey, Instant>>>,
    insertions: Arc<AtomicU64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IxfrCooldownKey {
    zone: String,
    primary: SocketAddr,
    plan_generation: u64,
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
    generation: u64,
    origin: DomainName,
    soa_timers: Option<SoaTimers>,
    last_refresh_completion_at: Option<Instant>,
    last_success_unix_secs: Option<u64>,
    last_success_serial: Option<u32>,
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
            insertions: Arc::new(AtomicU64::new(0)),
        }
    }

    #[cfg(test)]
    fn is_disabled_at(&self, zone: &DomainName, primary: SocketAddr, now: Instant) -> bool {
        self.is_disabled_for_generation_at(zone, primary, 0, now)
    }

    fn is_disabled_for_plan(&self, plan: &ZoneTransferPlan, primary: SocketAddr) -> bool {
        self.is_disabled_for_generation_at(&plan.origin, primary, plan.generation(), Instant::now())
    }

    fn is_disabled_for_generation_at(
        &self,
        zone: &DomainName,
        primary: SocketAddr,
        plan_generation: u64,
        now: Instant,
    ) -> bool {
        let key = IxfrCooldownKey::new(zone, primary, plan_generation);
        let mut disabled_until = self
            .disabled_until
            .lock()
            .expect("IXFR cooldown registry lock poisoned");
        match disabled_until.get(&key).copied() {
            Some(until) if until > now => true,
            Some(_) => {
                disabled_until.remove(&key);
                false
            }
            None => false,
        }
    }

    #[cfg(test)]
    fn record_unsupported(&self, zone: &DomainName, primary: SocketAddr) {
        self.record_unsupported_at(zone, primary, Instant::now());
    }

    #[cfg(test)]
    fn record_unsupported_at(&self, zone: &DomainName, primary: SocketAddr, now: Instant) {
        self.record_unsupported_for_generation_at(zone, primary, 0, now);
    }

    fn record_unsupported_if_current(
        &self,
        transfer_plan: &TransferPlan,
        plan: &ZoneTransferPlan,
        primary: SocketAddr,
    ) {
        let _ = transfer_plan.if_current_plan(plan, || {
            self.record_unsupported_for_generation_at(
                &plan.origin,
                primary,
                plan.generation(),
                Instant::now(),
            );
        });
    }

    fn record_unsupported_for_generation_at(
        &self,
        zone: &DomainName,
        primary: SocketAddr,
        plan_generation: u64,
        now: Instant,
    ) {
        let insertion = self
            .insertions
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let mut disabled_until = self
            .disabled_until
            .lock()
            .expect("IXFR cooldown registry lock poisoned");
        if insertion.is_multiple_of(RUNTIME_REGISTRY_PRUNE_INTERVAL) {
            disabled_until.retain(|_, until| *until > now);
        }
        let key = IxfrCooldownKey::new(zone, primary, plan_generation);
        disabled_until.insert(key, runtime_deadline(now, self.cooldown));
    }

    #[cfg(test)]
    fn remove_zone(&self, zone: &DomainName) {
        let _ = self.remove_zones(std::slice::from_ref(zone));
    }

    #[cfg(test)]
    fn remove_zones(&self, zones: &[DomainName]) -> (usize, usize) {
        self.reconcile_catalog_generations(zones, &[])
    }

    #[cfg(test)]
    fn retain_zone_generation(&self, zone: &DomainName, plan_generation: u64) -> (usize, usize) {
        self.reconcile_catalog_generations(&[], &[(zone.clone(), plan_generation)])
    }

    fn reconcile_catalog_generations(
        &self,
        removed_zones: &[DomainName],
        changed_plans: &[(DomainName, u64)],
    ) -> (usize, usize) {
        if removed_zones.is_empty() && changed_plans.is_empty() {
            return (0, 0);
        }
        let removed_zones = removed_zones
            .iter()
            .map(DomainName::canonical_key)
            .collect::<HashSet<_>>();
        let changed_plans = changed_plans
            .iter()
            .map(|(zone, generation)| (zone.canonical_key(), *generation))
            .collect::<HashMap<_, _>>();
        let mut visited = 0usize;
        let mut removed = 0usize;
        self.disabled_until
            .lock()
            .expect("IXFR cooldown registry lock poisoned")
            .retain(|key, _| {
                visited = visited.saturating_add(1);
                let retain = !removed_zones.contains(&key.zone)
                    && changed_plans
                        .get(&key.zone)
                        .is_none_or(|generation| key.plan_generation == *generation);
                removed = removed.saturating_add(usize::from(!retain));
                retain
            });
        (visited, removed)
    }

    fn prune_expired_at(&self, now: Instant) {
        self.disabled_until
            .lock()
            .expect("IXFR cooldown registry lock poisoned")
            .retain(|_, until| *until > now);
    }
}

impl IxfrCooldownKey {
    fn new(zone: &DomainName, primary: SocketAddr, plan_generation: u64) -> Self {
        Self {
            zone: zone.canonical_key(),
            primary,
            plan_generation,
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
            ownerships: Arc::new(Mutex::new(HashMap::new())),
            ownership_insertions: Arc::new(AtomicU64::new(0)),
            next_generation: Arc::new(AtomicU64::new(1)),
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
            ownerships: Arc::new(Mutex::new(HashMap::new())),
            ownership_insertions: Arc::new(AtomicU64::new(0)),
            next_generation: Arc::new(AtomicU64::new(1)),
        }
    }

    fn ownership_for(&self, origin: &DomainName) -> Arc<AsyncMutex<()>> {
        let key = origin.canonical_key();
        let mut ownerships = self
            .ownerships
            .lock()
            .expect("zone refresh ownership map lock poisoned");
        if let Some(ownership) = ownerships.get(&key).and_then(StdWeak::upgrade) {
            return ownership;
        }
        let insertion = self
            .ownership_insertions
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        if insertion.is_multiple_of(RUNTIME_REGISTRY_PRUNE_INTERVAL) {
            ownerships.retain(|_, ownership| ownership.upgrade().is_some());
        }
        let ownership = Arc::new(AsyncMutex::new(()));
        ownerships.insert(key, Arc::downgrade(&ownership));
        ownership
    }

    async fn begin_attempt(&self, origin: &DomainName) -> ZoneRefreshAttempt {
        let ownership = self.ownership_for(origin).lock_owned().await;
        let (generation, created_status) = self.mark_attempt_started(origin);
        ZoneRefreshAttempt {
            registry: self.clone(),
            origin: origin.clone(),
            generation,
            created_status,
            _ownership: ownership,
            finished: false,
        }
    }

    #[cfg(test)]
    async fn begin_registered_attempt(&self, origin: &DomainName) -> Option<ZoneRefreshAttempt> {
        let ownership = self.ownership_for(origin).lock_owned().await;
        let generation = {
            let mut statuses = self
                .statuses
                .lock()
                .expect("zone refresh registry lock poisoned");
            let status = statuses.get_mut(&origin.canonical_key())?;
            status.in_progress = true;
            status.generation
        };
        Some(ZoneRefreshAttempt {
            registry: self.clone(),
            origin: origin.clone(),
            generation,
            created_status: false,
            _ownership: ownership,
            finished: false,
        })
    }

    #[cfg(test)]
    fn try_begin_attempt(&self, origin: &DomainName) -> Option<ZoneRefreshAttempt> {
        let ownership = self.ownership_for(origin).try_lock_owned().ok()?;
        if self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned")
            .get(&origin.canonical_key())
            .is_some_and(|status| status.in_progress)
        {
            return None;
        }
        let (generation, created_status) = self.mark_attempt_started(origin);
        Some(ZoneRefreshAttempt {
            registry: self.clone(),
            origin: origin.clone(),
            generation,
            created_status,
            _ownership: ownership,
            finished: false,
        })
    }

    fn try_begin_attempt_for_generation(
        &self,
        origin: &DomainName,
        expected_generation: u64,
    ) -> Option<ZoneRefreshAttempt> {
        let ownership = self.ownership_for(origin).try_lock_owned().ok()?;
        let generation = {
            let mut statuses = self
                .statuses
                .lock()
                .expect("zone refresh registry lock poisoned");
            let status = statuses.get_mut(&origin.canonical_key())?;
            if status.generation != expected_generation || status.in_progress {
                return None;
            }
            status.in_progress = true;
            status.generation
        };
        Some(ZoneRefreshAttempt {
            registry: self.clone(),
            origin: origin.clone(),
            generation,
            created_status: false,
            _ownership: ownership,
            finished: false,
        })
    }

    fn fresh_generation(&self) -> u64 {
        self.next_generation.fetch_add(1, Ordering::Relaxed)
    }

    fn mark_attempt_started(&self, origin: &DomainName) -> (u64, bool) {
        let now = Instant::now();
        let fresh_generation = self.fresh_generation();
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        let created_status = !statuses.contains_key(&origin.canonical_key());
        let status = statuses
            .entry(origin.canonical_key())
            .or_insert_with(|| ZoneRefreshStatus {
                generation: fresh_generation,
                origin: origin.clone(),
                soa_timers: None,
                last_refresh_completion_at: None,
                last_success_unix_secs: None,
                last_success_serial: None,
                next_refresh: None,
                next_refresh_unix_secs: None,
                expire_at: None,
                loading_since: Some(now),
                next_loading_warning: Some(runtime_deadline(now, self.loading_warning_threshold)),
                last_failure_cause: None,
                initial_failure_count: 0,
                failures_since_success: 0,
                in_progress: false,
                expired: false,
            });
        status.in_progress = true;
        (status.generation, created_status)
    }

    fn defer_interrupted_attempt(&self, origin: &DomainName, generation: u64) {
        self.defer_interrupted_attempt_at(
            origin,
            generation,
            Instant::now(),
            unix_timestamp_seconds(),
        );
    }

    fn defer_interrupted_attempt_at(
        &self,
        origin: &DomainName,
        generation: u64,
        now: Instant,
        unix_secs: u64,
    ) {
        if let Some(status) = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned")
            .get_mut(&origin.canonical_key())
            .filter(|status| status.generation == generation)
        {
            status.in_progress = false;
            status.next_refresh = Some(now);
            status.next_refresh_unix_secs = Some(unix_secs);
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

    #[cfg(test)]
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
        let _ = self.record_success_metadata_at_with_timestamp_and_progress(
            metadata, now, unix_secs, false, None,
        );
    }

    fn record_success_metadata_at_with_timestamp_and_progress(
        &self,
        metadata: &ZoneMetadata,
        now: Instant,
        unix_secs: u64,
        in_progress: bool,
        expected_generation: Option<u64>,
    ) -> bool {
        let timers = metadata.soa_timers;
        if let Some(timers) = timers {
            self.warn_near_max_soa_timers(&metadata.origin, timers);
        }
        let refresh_interval = timers.map(|timers| self.effective_interval(timers.refresh));
        let refresh_deadline = refresh_interval
            .map(|interval| runtime_deadline_with_effective_duration(now, interval));
        let next_refresh = refresh_deadline.map(|(deadline, _)| deadline);
        let next_refresh_unix_secs =
            refresh_deadline.map(|(_, effective)| unix_secs.saturating_add(effective.as_secs()));
        let expire_at =
            timers.map(|timers| runtime_deadline(now, Duration::from_secs(timers.expire as u64)));
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        let key = metadata.origin_key.to_string();
        if let Some(expected_generation) = expected_generation
            && statuses
                .get(&key)
                .is_none_or(|status| status.generation != expected_generation)
        {
            return false;
        }
        let generation = statuses
            .get(&key)
            .map_or_else(|| self.fresh_generation(), |status| status.generation);
        statuses.insert(
            key,
            ZoneRefreshStatus {
                generation,
                origin: metadata.origin.clone(),
                soa_timers: timers,
                last_refresh_completion_at: Some(now),
                last_success_unix_secs: Some(unix_secs),
                last_success_serial: metadata.serial,
                next_refresh,
                next_refresh_unix_secs,
                expire_at,
                loading_since: None,
                next_loading_warning: None,
                last_failure_cause: None,
                initial_failure_count: 0,
                failures_since_success: 0,
                in_progress,
                expired: false,
            },
        );
        true
    }

    fn record_loading_start(&self, origin: &DomainName) {
        self.record_loading_start_at(origin, Instant::now());
    }

    fn record_loading_start_at(&self, origin: &DomainName, now: Instant) {
        let fresh_generation = self.fresh_generation();
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        statuses
            .entry(origin.canonical_key())
            .or_insert_with(|| ZoneRefreshStatus {
                generation: fresh_generation,
                origin: origin.clone(),
                soa_timers: None,
                last_refresh_completion_at: None,
                last_success_unix_secs: None,
                last_success_serial: None,
                next_refresh: None,
                next_refresh_unix_secs: None,
                expire_at: None,
                loading_since: Some(now),
                next_loading_warning: Some(runtime_deadline(now, self.loading_warning_threshold)),
                last_failure_cause: None,
                initial_failure_count: 0,
                failures_since_success: 0,
                in_progress: false,
                expired: false,
            });
    }

    fn defer_refresh_after_queue_drop(&self, request: &RefreshRequest) {
        self.defer_refresh_after_queue_drop_at(request, Instant::now(), unix_timestamp_seconds());
    }

    fn defer_refresh_after_queue_drop_at(
        &self,
        request: &RefreshRequest,
        now: Instant,
        unix_secs: u64,
    ) {
        let Some(retry_reason) = request.retry_after_queue_drop else {
            return;
        };
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        let Some(status) = statuses.get_mut(&request.zone.canonical_key()) else {
            warn!(
                zone = %request.zone,
                reason = retry_reason.as_str(),
                "refresh queue drop had no zone refresh status to defer"
            );
            return;
        };
        status.in_progress = false;
        if matches!(
            retry_reason,
            RefreshReason::Catalog | RefreshReason::ControlPlane | RefreshReason::Notify
        ) {
            status.next_refresh = Some(now);
            status.next_refresh_unix_secs = Some(unix_secs);
        }
    }

    #[cfg(test)]
    fn record_failure_at(&self, origin: &DomainName, current: Option<ZoneMetadata>, now: Instant) {
        self.record_failure_at_with_cause(origin, current, None, now);
    }

    #[cfg(test)]
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

    #[cfg(test)]
    fn record_failure_at_with_timestamp_and_cause(
        &self,
        origin: &DomainName,
        current: Option<ZoneMetadata>,
        failure_cause: Option<String>,
        now: Instant,
        unix_secs: u64,
    ) {
        let _ = self.record_failure_at_with_timestamp_cause_and_generation(
            origin,
            current,
            failure_cause,
            now,
            unix_secs,
            None,
        );
    }

    fn record_failure_at_with_timestamp_cause_and_generation(
        &self,
        origin: &DomainName,
        current: Option<ZoneMetadata>,
        failure_cause: Option<String>,
        now: Instant,
        unix_secs: u64,
        expected_generation: Option<u64>,
    ) -> bool {
        let key = origin.canonical_key();
        let fresh_generation = self.fresh_generation();
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        if let Some(expected_generation) = expected_generation
            && statuses
                .get(&key)
                .is_none_or(|status| status.generation != expected_generation)
        {
            return false;
        }
        let failure_keeps_zone_loading = current
            .as_ref()
            .is_none_or(|metadata| metadata.state == ZoneState::Loading);
        let status = statuses.entry(key).or_insert_with(|| ZoneRefreshStatus {
            generation: fresh_generation,
            origin: origin.clone(),
            soa_timers: current.as_ref().and_then(|metadata| metadata.soa_timers),
            last_refresh_completion_at: None,
            last_success_unix_secs: None,
            last_success_serial: current.as_ref().and_then(|metadata| metadata.serial),
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
            status.next_loading_warning =
                Some(runtime_deadline(now, self.loading_warning_threshold));
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
        let (next_refresh, effective_retry) = runtime_deadline_with_effective_duration(now, retry);
        status.next_refresh = Some(next_refresh);
        status.next_refresh_unix_secs = Some(unix_secs.saturating_add(effective_retry.as_secs()));
        status.failures_since_success = status.failures_since_success.saturating_add(1);
        status.last_refresh_completion_at = Some(now);
        status.in_progress = false;
        true
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
                status.next_loading_warning =
                    Some(runtime_deadline(now, self.loading_warning_threshold));
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

    fn expire_due_zones(&self, zones: &ZoneStore, now: Instant) -> Vec<DomainName> {
        self.expire_due_zones_with_hooks(zones, now, |_| {}, |_| {})
    }

    fn expire_due_zones_with_hooks(
        &self,
        zones: &ZoneStore,
        now: Instant,
        mut before_attempt: impl FnMut(&DomainName),
        mut before_publication: impl FnMut(&DomainName),
    ) -> Vec<DomainName> {
        let candidates = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned")
            .values()
            .filter(|status| {
                !status.in_progress
                    && !status.expired
                    && status.expire_at.is_some_and(|expire_at| expire_at <= now)
            })
            .map(|status| (status.origin.clone(), status.generation))
            .collect::<Vec<_>>();
        let mut expired = Vec::new();
        for (origin, generation) in candidates {
            before_attempt(&origin);
            let Some(attempt) = self.try_begin_attempt_for_generation(&origin, generation) else {
                continue;
            };
            let Some(current_snapshot) = zones.exact_snapshot_for_transfer(&origin) else {
                attempt.finish();
                continue;
            };
            let still_due = self
                .statuses
                .lock()
                .expect("zone refresh registry lock poisoned")
                .get(&origin.canonical_key())
                .is_some_and(|status| {
                    status.generation == generation
                        && !status.expired
                        && status.expire_at.is_some_and(|expire_at| expire_at <= now)
                });
            if still_due {
                before_publication(&origin);
            }
            let did_expire = if still_due {
                let mut statuses = self
                    .statuses
                    .lock()
                    .expect("zone refresh registry lock poisoned");
                if let Some(status) = statuses.get_mut(&origin.canonical_key()).filter(|status| {
                    status.generation == generation
                        && !status.expired
                        && status.expire_at.is_some_and(|expire_at| expire_at <= now)
                }) && zones.expire_zone_if_snapshot(&current_snapshot)
                {
                    status.expired = true;
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if did_expire {
                expired.push(origin.clone());
            }
            attempt.finish();
        }
        expired
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

    fn cancel_in_progress_if_generation(&self, origin: &DomainName, generation: u64) {
        if let Some(status) = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned")
            .get_mut(&origin.canonical_key())
            .filter(|status| status.generation == generation)
        {
            status.in_progress = false;
        }
    }

    fn is_current_generation(&self, origin: &DomainName, generation: u64) -> bool {
        self.statuses
            .lock()
            .expect("zone refresh registry lock poisoned")
            .get(&origin.canonical_key())
            .is_some_and(|status| status.generation == generation)
    }

    fn remove_zone(&self, origin: &DomainName) {
        let key = origin.canonical_key();
        self.statuses
            .lock()
            .expect("zone refresh registry lock poisoned")
            .remove(&key);
        let mut ownerships = self
            .ownerships
            .lock()
            .expect("zone refresh ownership map lock poisoned");
        if ownerships
            .get(&key)
            .is_some_and(|ownership| ownership.upgrade().is_none())
        {
            ownerships.remove(&key);
        }
    }

    fn remove_zone_if_generation(&self, origin: &DomainName, generation: u64) {
        let mut statuses = self
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        let key = origin.canonical_key();
        if statuses
            .get(&key)
            .is_some_and(|status| status.generation == generation)
        {
            statuses.remove(&key);
        }
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

impl ZoneRefreshAttempt {
    fn record_success(&mut self, metadata: &ZoneMetadata) -> bool {
        self.record_success_at(metadata, Instant::now(), unix_timestamp_seconds())
    }

    fn record_success_at(&mut self, metadata: &ZoneMetadata, now: Instant, unix_secs: u64) -> bool {
        debug_assert_eq!(self.origin.canonical_key(), metadata.origin_key.as_ref());
        self.registry
            .record_success_metadata_at_with_timestamp_and_progress(
                metadata,
                now,
                unix_secs,
                true,
                Some(self.generation),
            )
    }

    fn record_failure(self, current: Option<ZoneMetadata>, failure_cause: Option<String>) {
        self.record_failure_at(
            current,
            failure_cause,
            Instant::now(),
            unix_timestamp_seconds(),
        );
    }

    fn record_failure_at(
        mut self,
        current: Option<ZoneMetadata>,
        failure_cause: Option<String>,
        now: Instant,
        unix_secs: u64,
    ) {
        let _ = self
            .registry
            .record_failure_at_with_timestamp_cause_and_generation(
                &self.origin,
                current,
                failure_cause,
                now,
                unix_secs,
                Some(self.generation),
            );
        self.finished = true;
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn interrupt_at(mut self, now: Instant, unix_secs: u64) {
        self.registry
            .defer_interrupted_attempt_at(&self.origin, self.generation, now, unix_secs);
        self.finished = true;
    }

    fn finish(mut self) {
        self.registry
            .cancel_in_progress_if_generation(&self.origin, self.generation);
        self.finished = true;
    }

    fn discard_obsolete(mut self) {
        if self.created_status {
            self.registry
                .remove_zone_if_generation(&self.origin, self.generation);
        } else {
            self.registry
                .defer_interrupted_attempt(&self.origin, self.generation);
        }
        self.finished = true;
    }
}

impl Drop for ZoneRefreshAttempt {
    fn drop(&mut self) {
        if !self.finished {
            self.registry
                .defer_interrupted_attempt(&self.origin, self.generation);
        }
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
    policies_by_zone: Arc<Mutex<HashMap<String, NotifyZonePolicy>>>,
    next_policy_generation: Arc<AtomicU64>,
    secrets: SecretManager,
    tsig_fudge_seconds: u16,
}

#[derive(Debug, Clone)]
struct NotifyZonePolicy {
    sources: HashSet<IpAddr>,
    tsig_key_name: Option<DomainName>,
    generation: u64,
}

#[derive(Clone)]
struct NotifyPolicyToken {
    generation: u64,
    tsig_key_name: Option<DomainName>,
    verified_tsig_material_identity: Option<[u8; 32]>,
}

enum NotifyTsigAuthorization {
    Unauthorized,
    Unsigned(NotifyPolicyToken),
    Key {
        key: Arc<TsigKey>,
        token: NotifyPolicyToken,
    },
    RequiredKeyUnavailable(DomainName),
}

impl Default for NotifyAuthority {
    fn default() -> Self {
        Self {
            policies_by_zone: Arc::new(Mutex::new(HashMap::new())),
            next_policy_generation: Arc::new(AtomicU64::new(1)),
            secrets: SecretManager::empty_for_test(),
            tsig_fudge_seconds: DEFAULT_TSIG_FUDGE_SECS,
        }
    }
}

impl NotifyAuthority {
    fn from_config(config: &ServerConfig, secrets: SecretManager) -> Self {
        let mut policies_by_zone = HashMap::new();
        let mut next_policy_generation = 1u64;
        for zone in &config.zones {
            let origin = DomainName::from_absolute_str(&zone.name)
                .expect("configuration validation rejects invalid zone names");
            let sources = notify_sources_for_zone(zone);
            let tsig_key_name = zone.tsig_key.as_ref().map(|tsig_key| {
                DomainName::from_absolute_str(tsig_key)
                    .expect("configuration validation rejects invalid TSIG key references")
            });
            policies_by_zone.insert(
                origin.canonical_key(),
                NotifyZonePolicy {
                    sources,
                    tsig_key_name,
                    generation: next_policy_generation,
                },
            );
            next_policy_generation = next_policy_generation.saturating_add(1);
        }
        for catalog_zone in &config.catalog_zones {
            let origin = DomainName::from_absolute_str(&catalog_zone.name)
                .expect("configuration validation rejects invalid catalog zone names");
            let sources = notify_sources_for_catalog_zone(catalog_zone);
            let tsig_key_name = catalog_zone.catalog_tsig_key_name().map(|tsig_key| {
                DomainName::from_absolute_str(tsig_key)
                    .expect("configuration validation rejects invalid TSIG key references")
            });
            policies_by_zone.insert(
                origin.canonical_key(),
                NotifyZonePolicy {
                    sources,
                    tsig_key_name,
                    generation: next_policy_generation,
                },
            );
            next_policy_generation = next_policy_generation.saturating_add(1);
        }

        Self {
            policies_by_zone: Arc::new(Mutex::new(policies_by_zone)),
            next_policy_generation: Arc::new(AtomicU64::new(next_policy_generation)),
            secrets,
            tsig_fudge_seconds: config.tsig.fudge_seconds,
        }
    }

    #[cfg(test)]
    fn from_config_for_test(config: &ServerConfig) -> Self {
        let secrets =
            SecretManager::from_config(config).expect("test configuration loads secret snapshot");
        Self::from_config(config, secrets)
    }

    #[cfg(test)]
    fn is_authorized(&self, qname: &DomainName, qclass: u16, source: IpAddr) -> bool {
        qclass == 1
            && self
                .policies_by_zone
                .lock()
                .expect("notify authority policy lock poisoned")
                .get(&qname.canonical_key())
                .is_some_and(|policy| policy.sources.contains(&source))
    }

    fn is_authorized_for_token(
        &self,
        qname: &DomainName,
        qclass: u16,
        source: IpAddr,
        token: Option<&NotifyPolicyToken>,
    ) -> bool {
        let Some(token) = token else {
            return false;
        };
        qclass == 1
            && self
                .policies_by_zone
                .lock()
                .expect("notify authority policy lock poisoned")
                .get(&qname.canonical_key())
                .is_some_and(|policy| {
                    policy.sources.contains(&source)
                        && policy.generation == token.generation
                        && policy.tsig_key_name == token.tsig_key_name
                        && match (&policy.tsig_key_name, token.verified_tsig_material_identity) {
                            (None, None) => true,
                            (Some(key_name), Some(verified_identity)) => self
                                .secrets
                                .tsig_key_with_material_identity(key_name)
                                .is_some_and(|(_, current_identity)| {
                                    current_identity == verified_identity
                                }),
                            (None, Some(_)) | (Some(_), None) => false,
                        }
                })
    }

    #[cfg(test)]
    fn tsig_key_for_notify(&self, qname: &DomainName, qclass: u16) -> Option<Arc<TsigKey>> {
        if qclass != 1 {
            return None;
        }
        let key_name = self
            .policies_by_zone
            .lock()
            .expect("notify authority policy lock poisoned")
            .get(&qname.canonical_key())
            .and_then(|policy| policy.tsig_key_name.clone());
        key_name.and_then(|key_name| self.secrets.tsig_key(&key_name))
    }

    fn notify_tsig_authorization(
        &self,
        qname: &DomainName,
        qclass: u16,
        source: IpAddr,
    ) -> NotifyTsigAuthorization {
        if qclass != 1 {
            return NotifyTsigAuthorization::Unauthorized;
        }
        let token = {
            let policies = self
                .policies_by_zone
                .lock()
                .expect("notify authority policy lock poisoned");
            let Some(policy) = policies.get(&qname.canonical_key()) else {
                return NotifyTsigAuthorization::Unauthorized;
            };
            if !policy.sources.contains(&source) {
                return NotifyTsigAuthorization::Unauthorized;
            }
            NotifyPolicyToken {
                generation: policy.generation,
                tsig_key_name: policy.tsig_key_name.clone(),
                verified_tsig_material_identity: None,
            }
        };
        let Some(key_name) = token.tsig_key_name.clone() else {
            return NotifyTsigAuthorization::Unsigned(token);
        };
        match self.secrets.tsig_key_with_material_identity(&key_name) {
            Some((key, material_identity)) => {
                let token = NotifyPolicyToken {
                    verified_tsig_material_identity: Some(material_identity),
                    ..token
                };
                NotifyTsigAuthorization::Key { key, token }
            }
            None => NotifyTsigAuthorization::RequiredKeyUnavailable(key_name),
        }
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
        let generation = self.next_policy_generation.fetch_add(1, Ordering::AcqRel);
        let tsig_key_name = transfer_override
            .and_then(|transfer| transfer.tsig_key_name.as_ref().cloned())
            .or_else(|| {
                catalog
                    .member_tsig_key_name()
                    .and_then(|name| DomainName::from_absolute_str(name).ok())
            });
        self.policies_by_zone
            .lock()
            .expect("notify authority policy lock poisoned")
            .insert(
                origin.canonical_key(),
                NotifyZonePolicy {
                    sources: notify_sources_for_catalog_member_zone(catalog, transfer_override),
                    tsig_key_name,
                    generation,
                },
            );
    }

    fn remove_zone(&self, origin: &DomainName) {
        self.policies_by_zone
            .lock()
            .expect("notify authority policy lock poisoned")
            .remove(&origin.canonical_key());
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
    if let Some(transfer_override) = transfer_override {
        if transfer_override.primaries.is_empty() {
            sources.extend(
                zone.member_transfer_target_addrs()
                    .into_iter()
                    .map(|primary| primary.ip()),
            );
        } else {
            sources.extend(
                transfer_override
                    .primaries
                    .iter()
                    .map(|primary| primary.addr),
            );
        }
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
    notify_policy_token: Option<NotifyPolicyToken>,
}

#[derive(Clone)]
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
        notify_policy_token: None,
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
    let (key, notify_policy_token) = match notify_authority.notify_tsig_authorization(
        &question.qname,
        question.qclass,
        source,
    ) {
        NotifyTsigAuthorization::Unauthorized => return Some(unsigned()),
        NotifyTsigAuthorization::Unsigned(token) => {
            return Some(PreparedDnsMessage {
                notify_policy_token: Some(token),
                ..unsigned()
            });
        }
        NotifyTsigAuthorization::Key { key, token } => (key, token),
        NotifyTsigAuthorization::RequiredKeyUnavailable(key_name) => {
            if let Some(metrics) = metrics {
                metrics.record_notify_tsig_result(NotifyTsigResult::BadKey);
            }
            warn!(
                category = "notify",
                event = "notify_tsig_key_unavailable",
                peer_ip = %source,
                zone = %question.qname,
                tsig_key = %key_name,
                "rejected NOTIFY because its required TSIG key is unavailable"
            );
            return basic_error_response(packet, &header, Rcode::NotAuth).map(|response| {
                PreparedDnsMessage {
                    packet: packet.to_vec(),
                    response_tsig: None,
                    immediate_response: Some(response),
                    tsig_authenticated: false,
                    notify_policy_token: None,
                }
            });
        }
    };

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
                notify_policy_token: Some(notify_policy_token),
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
                notify_policy_token: None,
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
        Err(_) => return prepared,
    };

    let question = match Question::parse(&prepared.packet) {
        Ok(question) => question,
        Err(_) => return prepared,
    };

    if message_key.algorithm.is_none() {
        return PreparedDnsMessage {
            immediate_response: unsigned_tsig_error_response(
                &header,
                &question,
                &message_key,
                notify_authority.tsig_fudge_seconds,
                TSIG_ERROR_BADKEY,
            ),
            ..prepared
        };
    }

    let Some(key) = notify_authority.tsig_key_by_name(&message_key.name) else {
        return PreparedDnsMessage {
            immediate_response: unsigned_tsig_error_response(
                &header,
                &question,
                &message_key,
                notify_authority.tsig_fudge_seconds,
                TSIG_ERROR_BADKEY,
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
            notify_policy_token: prepared.notify_policy_token,
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
    response.extend_from_slice(&(0x8000u16 | (header.flags & 0x7900) | rcode as u16).to_be_bytes());
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
    if matches!(error, TsigError::MisplacedTsig | TsigError::MalformedTsig) {
        return basic_error_response(packet, header, Rcode::FormErr);
    }

    let now = tsig_time_signed();
    let response = tsig_notauth_response(header, question);
    let request_data = message_tsig_request_data(packet).ok().flatten();

    match error {
        TsigError::InvalidMac => request_data.as_ref().and_then(|request| {
            unsigned_tsig_error_response(
                header,
                question,
                &request.key,
                tsig_fudge_seconds,
                TSIG_ERROR_BADSIG,
            )
        }),
        TsigError::MissingTsig => Some(response),
        TsigError::UnsupportedAlgorithm(_)
        | TsigError::KeyMismatch
        | TsigError::AlgorithmMismatch => request_data.as_ref().and_then(|request| {
            unsigned_tsig_error_response(
                header,
                question,
                &request.key,
                tsig_fudge_seconds,
                TSIG_ERROR_BADKEY,
            )
        }),
        TsigError::BadTrunc => {
            let request = request_data.as_ref()?;
            sign_tsig_error_response(
                &response,
                key,
                TsigErrorResponseFields {
                    request_mac: &request.mac,
                    time_signed: request.time_signed,
                    fudge: request.fudge,
                    original_id: request.original_id,
                    error: TSIG_ERROR_BADTRUNC,
                    other_data: &[],
                },
            )
            .ok()
            .map(|signed| signed.message)
        }
        TsigError::TimeOutsideFudge => {
            let request = request_data.as_ref()?;
            sign_tsig_error_response(
                &response,
                key,
                TsigErrorResponseFields {
                    request_mac: &request.mac,
                    time_signed: request.time_signed,
                    fudge: request.fudge,
                    original_id: request.original_id,
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

fn tsig_notauth_response(header: &Header, question: &Question) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&header.id.to_be_bytes());
    response.extend_from_slice(
        &(0x8000u16 | (header.flags & 0x7900) | Rcode::NotAuth as u16).to_be_bytes(),
    );
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&question.qname.to_wire());
    response.extend_from_slice(&question.qtype.to_be_bytes());
    response.extend_from_slice(&question.qclass.to_be_bytes());
    response
}

fn unsigned_tsig_error_response(
    header: &Header,
    question: &Question,
    key: &TsigMessageKey,
    fudge: u16,
    error: u16,
) -> Option<Vec<u8>> {
    append_unsigned_tsig_error_for_message_key(
        &tsig_notauth_response(header, question),
        key,
        tsig_time_signed(),
        fudge,
        header.id,
        error,
        &[],
    )
    .ok()
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

fn sign_udp_tsig_response(
    response: Vec<u8>,
    response_tsig: Option<ResponseTsig>,
    udp_ceiling: usize,
) -> Result<Vec<u8>, TsigError> {
    let Some(response_tsig) = response_tsig else {
        return Ok(response);
    };

    let time_signed = tsig_time_signed();
    let signed = response_tsig.key.sign_response(
        &response,
        &response_tsig.request_mac,
        time_signed,
        response_tsig.fudge_seconds,
    )?;
    if signed.message.len() <= udp_ceiling {
        return Ok(signed.message);
    }

    let truncated = tsig_udp_truncated_response(&response)?;
    let signed = response_tsig.key.sign_response(
        &truncated,
        &response_tsig.request_mac,
        time_signed,
        response_tsig.fudge_seconds,
    )?;
    if signed.message.len() > udp_ceiling {
        return Err(TsigError::MalformedMessage);
    }
    Ok(signed.message)
}

fn tsig_udp_truncated_response(response: &[u8]) -> Result<Vec<u8>, TsigError> {
    let header = Header::parse(response).map_err(|_| TsigError::MalformedMessage)?;
    let question = if header.qdcount == 1 {
        Some(Question::parse(response).map_err(|_| TsigError::MalformedMessage)?)
    } else {
        None
    };
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&header.id.to_be_bytes());
    truncated.extend_from_slice(&((header.flags & !0x000f) | 0x0200).to_be_bytes());
    truncated.extend_from_slice(&u16::from(question.is_some()).to_be_bytes());
    truncated.extend_from_slice(&0u16.to_be_bytes());
    truncated.extend_from_slice(&0u16.to_be_bytes());
    truncated.extend_from_slice(&0u16.to_be_bytes());
    if let Some(question) = question {
        truncated.extend_from_slice(&question.qname.to_wire());
        truncated.extend_from_slice(&question.qtype.to_be_bytes());
        truncated.extend_from_slice(&question.qclass.to_be_bytes());
    }
    Ok(truncated)
}

#[derive(Debug, Clone)]
struct NotifyRefreshTracker {
    dedup_interval: Duration,
    last_signal_by_zone: Arc<Mutex<HashMap<String, NotifyDedupCommit>>>,
    refresh_registry: Option<ZoneRefreshRegistry>,
    transfer_plan: Option<TransferPlan>,
    commits: Arc<AtomicU64>,
    next_token_id: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy)]
struct NotifyDedupCommit {
    signalled_at: Instant,
    token_id: u64,
    refresh_generation: Option<u64>,
    plan_generation: Option<u64>,
    requested_serial: Option<u32>,
}

#[derive(Clone)]
struct NotifyDedupToken {
    last_signal_by_zone: Arc<Mutex<HashMap<String, NotifyDedupCommit>>>,
    commits: Arc<AtomicU64>,
    dedup_interval: Duration,
    zone: String,
    signalled_at: Instant,
    token_id: u64,
    refresh_generation: Option<u64>,
    plan_generation: Option<u64>,
    requested_serial: Option<u32>,
}

impl std::fmt::Debug for NotifyDedupToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NotifyDedupToken")
            .field("zone", &self.zone)
            .field("signalled_at", &self.signalled_at)
            .field("token_id", &self.token_id)
            .field("refresh_generation", &self.refresh_generation)
            .field("plan_generation", &self.plan_generation)
            .field("requested_serial", &self.requested_serial)
            .finish_non_exhaustive()
    }
}

impl NotifyDedupToken {
    /// Reports whether this outer-admission reservation is still the tracker
    /// entry responsible for suppressing this zone. The reservation is made
    /// before the outer queue send so concurrent bursts are suppressed; exact
    /// token rollback removes it if either bounded queue later drops the work.
    #[cfg(test)]
    fn commit(&self) -> bool {
        self.commit_at(Instant::now())
    }

    fn commit_at(&self, now: Instant) -> bool {
        let commit_count = self.commits.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let mut last_signal_by_zone = self
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned");
        if !self.dedup_interval.is_zero()
            && commit_count.is_multiple_of(RUNTIME_REGISTRY_PRUNE_INTERVAL)
        {
            last_signal_by_zone.retain(|_, commit| {
                now.saturating_duration_since(commit.signalled_at) < self.dedup_interval
            });
        }
        last_signal_by_zone.get(&self.zone).is_some_and(|commit| {
            commit.token_id == self.token_id
                && commit.refresh_generation == self.refresh_generation
                && commit.plan_generation == self.plan_generation
                && commit.requested_serial == self.requested_serial
        })
    }

    fn rollback(&self) {
        let mut last_signal_by_zone = self
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned");
        if last_signal_by_zone.get(&self.zone).is_some_and(|commit| {
            commit.token_id == self.token_id
                && commit.refresh_generation == self.refresh_generation
                && commit.plan_generation == self.plan_generation
                && commit.requested_serial == self.requested_serial
        }) {
            last_signal_by_zone.remove(&self.zone);
        }
    }
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
            refresh_registry: None,
            transfer_plan: None,
            commits: Arc::new(AtomicU64::new(0)),
            next_token_id: Arc::new(AtomicU64::new(1)),
        }
    }

    #[cfg(test)]
    fn with_refresh_registry(
        dedup_interval: Duration,
        refresh_registry: ZoneRefreshRegistry,
    ) -> Self {
        Self {
            refresh_registry: Some(refresh_registry),
            ..Self::new(dedup_interval)
        }
    }

    fn with_refresh_registry_and_transfer_plan(
        dedup_interval: Duration,
        refresh_registry: ZoneRefreshRegistry,
        transfer_plan: TransferPlan,
    ) -> Self {
        Self {
            refresh_registry: Some(refresh_registry),
            transfer_plan: Some(transfer_plan),
            ..Self::new(dedup_interval)
        }
    }

    #[cfg(test)]
    fn record_after_enqueue<E>(
        &self,
        qname: &DomainName,
        enqueue: impl FnOnce(NotifyDedupToken) -> Result<(), E>,
    ) -> Result<NotifyRefreshAction, E> {
        self.record_after_enqueue_serial_at(qname, None, Instant::now(), enqueue)
    }

    fn record_after_enqueue_serial<E>(
        &self,
        qname: &DomainName,
        requested_serial: Option<u32>,
        enqueue: impl FnOnce(NotifyDedupToken) -> Result<(), E>,
    ) -> Result<NotifyRefreshAction, E> {
        self.record_after_enqueue_serial_at(qname, requested_serial, Instant::now(), enqueue)
    }

    fn record_after_enqueue_serial_at<E>(
        &self,
        qname: &DomainName,
        requested_serial: Option<u32>,
        now: Instant,
        enqueue: impl FnOnce(NotifyDedupToken) -> Result<(), E>,
    ) -> Result<NotifyRefreshAction, E> {
        let zone = qname.canonical_key();
        let plan_generation = if let Some(transfer_plan) = self.transfer_plan.as_ref() {
            let Some(plan) = transfer_plan.get(qname) else {
                return Ok(NotifyRefreshAction::Deduplicated);
            };
            Some(plan.generation())
        } else {
            None
        };
        // Keep the refresh-status lock through reservation and the synchronous
        // outer try_send. This gives attempt start/completion, catalog removal,
        // and NOTIFY admission one observable order.
        let refresh_statuses = self.refresh_registry.as_ref().map(|registry| {
            registry
                .statuses
                .lock()
                .expect("zone refresh registry lock poisoned")
        });
        let refresh_generation = if let Some(statuses) = refresh_statuses.as_ref() {
            let Some(status) = statuses.get(&zone) else {
                return Ok(NotifyRefreshAction::Deduplicated);
            };
            let active_or_recent = status.in_progress
                || status
                    .last_refresh_completion_at
                    .is_some_and(|completed_at| {
                        now.saturating_duration_since(completed_at) < self.dedup_interval
                    });
            if active_or_recent
                && requested_serial.is_none_or(|requested_serial| {
                    status.last_success_serial.is_some_and(|current_serial| {
                        !serial_after(requested_serial, current_serial)
                    })
                })
            {
                return Ok(NotifyRefreshAction::Deduplicated);
            }
            Some(status.generation)
        } else {
            None
        };
        let token_id = self.next_token_id.fetch_add(1, Ordering::Relaxed);
        let mut last_signal_by_zone = self
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned");
        let previous_signal = last_signal_by_zone.get(&zone).copied();
        if let Some(last_signal) = previous_signal
            && last_signal.refresh_generation == refresh_generation
            && last_signal.plan_generation == plan_generation
            && notify_serial_covers(last_signal.requested_serial, requested_serial)
            && now.saturating_duration_since(last_signal.signalled_at) < self.dedup_interval
        {
            return Ok(NotifyRefreshAction::Deduplicated);
        }
        last_signal_by_zone.insert(
            zone.clone(),
            NotifyDedupCommit {
                signalled_at: now,
                token_id,
                refresh_generation,
                plan_generation,
                requested_serial,
            },
        );

        let token = NotifyDedupToken {
            last_signal_by_zone: self.last_signal_by_zone.clone(),
            commits: self.commits.clone(),
            dedup_interval: self.dedup_interval,
            zone,
            signalled_at: now,
            token_id,
            refresh_generation,
            plan_generation,
            requested_serial,
        };
        match enqueue(token.clone()) {
            Ok(()) => Ok(NotifyRefreshAction::Signalled),
            Err(error) => {
                if last_signal_by_zone.get(&token.zone).is_some_and(|commit| {
                    commit.token_id == token.token_id
                        && commit.refresh_generation == token.refresh_generation
                        && commit.plan_generation == token.plan_generation
                        && commit.requested_serial == token.requested_serial
                }) {
                    if let Some(previous_signal) = previous_signal {
                        last_signal_by_zone.insert(token.zone.clone(), previous_signal);
                    } else {
                        last_signal_by_zone.remove(&token.zone);
                    }
                }
                Err(error)
            }
        }
    }

    fn remove_zone(&self, zone: &DomainName) {
        self.last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .remove(&zone.canonical_key());
    }

    fn prune_expired_at(&self, now: Instant) {
        self.last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .retain(|_, commit| {
                now.saturating_duration_since(commit.signalled_at) < self.dedup_interval
            });
    }
}

fn notify_serial_covers(existing: Option<u32>, incoming: Option<u32>) -> bool {
    match (existing, incoming) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(existing), Some(incoming)) => !serial_after(incoming, existing),
    }
}

async fn serve_runtime_registry_cleanup(
    notify_refresh: NotifyRefreshTracker,
    ixfr_cooldowns: IxfrCooldownRegistry,
    tick: Duration,
) -> Result<(), RuntimeError> {
    let mut interval = tokio::time::interval(tick);
    loop {
        interval.tick().await;
        let now = Instant::now();
        notify_refresh.prune_expired_at(now);
        ixfr_cooldowns.prune_expired_at(now);
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
    match notify_refresh.record_after_enqueue_serial(qname, soa_serial, |token| {
        notify_refresh_tx
            .try_send(
                RefreshRequest::new(qname.clone(), soa_serial, RefreshReason::Notify)
                    .with_notify_dedup_token(token)
                    .with_preferred_primary_ip(source),
            )
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => mpsc::error::TrySendError::Full(()),
                mpsc::error::TrySendError::Closed(_) => mpsc::error::TrySendError::Closed(()),
            })
    }) {
        Ok(NotifyRefreshAction::Signalled) => {
            metrics.record_notify_refresh_action(NotifyRefreshAction::Signalled);
            info!(
                %source,
                zone = %qname,
                ?soa_serial,
                action = "refresh_signalled",
                "accepted NOTIFY"
            );
        }
        Ok(NotifyRefreshAction::Deduplicated) => {
            metrics.record_notify_refresh_action(NotifyRefreshAction::Deduplicated);
            info!(
                %source,
                zone = %qname,
                ?soa_serial,
                action = "deduplicated",
                "accepted NOTIFY"
            );
        }
        Err(mpsc::error::TrySendError::Full(())) => {
            warn!(
                %source,
                zone = %qname,
                "NOTIFY refresh queue full; refresh request dropped"
            );
        }
        Err(mpsc::error::TrySendError::Closed(())) => {
            warn!(
                %source,
                zone = %qname,
                "NOTIFY refresh queue closed; refresh request dropped"
            );
        }
    }
}

#[derive(Clone)]
struct SharedSecret(Arc<Zeroizing<String>>);

impl SharedSecret {
    fn new(secret: String) -> Self {
        Self(Arc::new(Zeroizing::new(secret)))
    }

    fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

fn control_plane_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("control-plane HTTP client configuration is valid")
}

fn control_plane_node_url(
    endpoint_url: &str,
    node_id: &str,
    suffix: &[&str],
) -> Result<reqwest::Url, String> {
    let mut url = reqwest::Url::parse(endpoint_url)
        .map_err(|error| format!("invalid control-plane endpoint URL: {error}"))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| "control-plane endpoint URL cannot be a base URL".to_owned())?;
        segments.pop_if_empty();
        segments.push("secondary-nodes");
        segments.push(node_id);
        for segment in suffix {
            segments.push(segment);
        }
    }
    Ok(url)
}

#[derive(Clone)]
struct ControlPlaneTelemetryReporter {
    endpoint_url: Option<Arc<str>>,
    node_id: Option<Arc<str>>,
    bearer_token: Option<SharedSecret>,
    timeout: Duration,
    client: reqwest::Client,
}

#[derive(Clone)]
struct ControlPlaneTelemetryClient {
    sender: Option<mpsc::Sender<serde_json::Value>>,
}

impl ControlPlaneTelemetryClient {
    fn new(enabled: bool) -> (Self, Option<mpsc::Receiver<serde_json::Value>>) {
        if !enabled {
            return (Self::disabled(), None);
        }
        let (sender, receiver) = mpsc::channel(CONTROL_PLANE_TELEMETRY_QUEUE_CAPACITY);
        (
            Self {
                sender: Some(sender),
            },
            Some(receiver),
        )
    }

    fn disabled() -> Self {
        Self { sender: None }
    }

    #[cfg(test)]
    fn saturated_for_test() -> (Self, mpsc::Receiver<serde_json::Value>) {
        let (sender, receiver) = mpsc::channel(1);
        sender
            .try_send(serde_json::json!({"test": "blocked telemetry worker"}))
            .expect("test telemetry queue starts empty");
        (
            Self {
                sender: Some(sender),
            },
            receiver,
        )
    }

    fn report_success(&self, metadata: &ZoneMetadata, status: &'static str, reason: &str) {
        let mut body = serde_json::json!({
            "zone_name": metadata.origin.to_string(),
            "status": status,
            "transfer_mode": "axfr_ixfr",
            "message": format!("BoronDNS transfer {status} during {reason} refresh"),
        });
        if let Some(serial) = metadata.serial {
            body["serial"] = serde_json::Value::String(serial.to_string());
        }
        if let Some(timers) = metadata.soa_timers {
            body["refresh_seconds"] = serde_json::Value::from(timers.refresh);
            body["retry_seconds"] = serde_json::Value::from(timers.retry);
        }
        self.try_send(body);
    }

    fn report_failure(&self, origin: &DomainName, failure_cause: Option<&str>, reason: &str) {
        let failure_reason = failure_cause
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("transfer failed without detailed cause");
        self.try_send(serde_json::json!({
            "zone_name": origin.to_string(),
            "status": "failed",
            "transfer_mode": "axfr_ixfr",
            "failure_reason": failure_reason,
            "message": format!("BoronDNS transfer failed during {reason} refresh"),
        }));
    }

    fn try_send(&self, body: serde_json::Value) {
        let Some(sender) = &self.sender else {
            return;
        };
        match sender.try_send(body) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => warn!(
                category = "transfer",
                "control-plane telemetry queue full; dropping best-effort transfer event"
            ),
            Err(mpsc::error::TrySendError::Closed(_)) => warn!(
                category = "transfer",
                "control-plane telemetry queue closed; dropping best-effort transfer event"
            ),
        }
    }
}

async fn serve_control_plane_telemetry(
    reporter: ControlPlaneTelemetryReporter,
    mut receiver: mpsc::Receiver<serde_json::Value>,
) -> Result<(), RuntimeError> {
    while let Some(body) = receiver.recv().await {
        reporter.post(body).await;
    }
    Ok(())
}

impl ControlPlaneTelemetryReporter {
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
                .map(|value| SharedSecret::new(value.trim().to_owned())),
            timeout: Duration::from_secs(telemetry.timeout_secs),
            client: control_plane_http_client(),
        }
    }

    fn enabled(&self) -> bool {
        self.endpoint_url.is_some() && self.node_id.is_some() && self.bearer_token.is_some()
    }

    #[cfg(test)]
    async fn report_success(&self, metadata: &ZoneMetadata, status: &'static str, reason: &str) {
        if !self.enabled() {
            return;
        }
        let mut body = serde_json::json!({
            "zone_name": metadata.origin.to_string(),
            "status": status,
            "transfer_mode": "axfr_ixfr",
            "message": format!("BoronDNS transfer {status} during {reason} refresh"),
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

    #[cfg(test)]
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
            "message": format!("BoronDNS transfer failed during {reason} refresh"),
        }))
        .await;
    }

    async fn post(&self, body: serde_json::Value) {
        let (Some(endpoint_url), Some(node_id), Some(bearer_token)) = (
            self.endpoint_url.as_deref(),
            self.node_id.as_deref(),
            self.bearer_token.as_ref().map(SharedSecret::expose_secret),
        ) else {
            return;
        };
        let url = match control_plane_node_url(endpoint_url, node_id, &["transfer-events"]) {
            Ok(url) => url,
            Err(error) => {
                warn!(
                    category = "transfer",
                    %error,
                    "failed to construct control-plane transfer telemetry URL"
                );
                return;
            }
        };
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
    enabled: bool,
    endpoint_url: Option<Arc<str>>,
    node_id: Option<Arc<str>>,
    bearer_token: Option<SharedSecret>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolledControlPlaneOperation {
    Valid(ControlPlaneOperation),
    Invalid { id: Option<i64>, error: String },
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
            enabled: operations.enabled,
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
                .map(|value| SharedSecret::new(value.trim().to_owned())),
            poll_interval: Duration::from_secs(operations.poll_interval_secs),
            lease_seconds: operations.lease_seconds,
            timeout: Duration::from_secs(operations.timeout_secs),
            client: control_plane_http_client(),
        }
    }

    fn enabled(&self) -> bool {
        self.enabled
            && self.endpoint_url.is_some()
            && self.node_id.is_some()
            && self.bearer_token.is_some()
    }

    async fn poll(&self) -> Result<Vec<PolledControlPlaneOperation>, String> {
        let (Some(endpoint_url), Some(node_id), Some(bearer_token)) = (
            self.endpoint_url.as_deref(),
            self.node_id.as_deref(),
            self.bearer_token.as_ref().map(SharedSecret::expose_secret),
        ) else {
            return Ok(Vec::new());
        };
        let mut url = control_plane_node_url(endpoint_url, node_id, &["operations"])?;
        url.query_pairs_mut()
            .append_pair("limit", "20")
            .append_pair("lease_seconds", &self.lease_seconds.to_string());
        let mut response = self
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
        if response
            .content_length()
            .is_some_and(|length| length > CONTROL_PLANE_RESPONSE_LIMIT_BYTES as u64)
        {
            return Err(format!(
                "control-plane operation response exceeds {CONTROL_PLANE_RESPONSE_LIMIT_BYTES} byte limit"
            ));
        }
        let mut response_bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
            if response_bytes.len().saturating_add(chunk.len()) > CONTROL_PLANE_RESPONSE_LIMIT_BYTES
            {
                return Err(format!(
                    "control-plane operation response exceeds {CONTROL_PLANE_RESPONSE_LIMIT_BYTES} byte limit"
                ));
            }
            response_bytes.extend_from_slice(&chunk);
        }
        let body = serde_json::from_slice::<serde_json::Value>(&response_bytes)
            .map_err(|error| error.to_string())?;
        let operation_values = body
            .as_array()
            .ok_or_else(|| "control-plane operation poll returned non-array JSON".to_owned())?;
        if operation_values.len() > CONTROL_PLANE_OPERATION_LIMIT {
            return Err(format!(
                "control-plane operation poll returned {} items, exceeding requested limit {CONTROL_PLANE_OPERATION_LIMIT}",
                operation_values.len()
            ));
        }
        let operations = operation_values
            .iter()
            .map(|value| match parse_control_plane_operation(value) {
                Ok(operation) => PolledControlPlaneOperation::Valid(operation),
                Err(error) => PolledControlPlaneOperation::Invalid {
                    id: value.get("id").and_then(serde_json::Value::as_i64),
                    error,
                },
            })
            .collect();
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
            self.bearer_token.as_ref().map(SharedSecret::expose_secret),
        ) else {
            return;
        };
        let mut body = serde_json::json!({ "status": status.as_str() });
        if let Some(failure_reason) = failure_reason {
            body["failure_reason"] = serde_json::Value::String(failure_reason.to_owned());
        }
        let operation_id = operation_id.to_string();
        let url = match control_plane_node_url(
            endpoint_url,
            node_id,
            &["operations", operation_id.as_str(), "complete"],
        ) {
            Ok(url) => url,
            Err(error) => {
                warn!(
                    category = "control_plane",
                    operation_id,
                    %error,
                    "failed to construct control-plane operation completion URL"
                );
                return;
            }
        };
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
    transfer_plan: TransferPlan,
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
            let operation = match operation {
                PolledControlPlaneOperation::Valid(operation) => operation,
                PolledControlPlaneOperation::Invalid { id, error } => {
                    warn!(
                        category = "control_plane",
                        operation_id = ?id,
                        %error,
                        "rejected malformed control-plane operation"
                    );
                    if let Some(id) = id {
                        client
                            .complete(
                                id,
                                ControlPlaneOperationCompletionStatus::Failed,
                                Some(&error),
                            )
                            .await;
                    }
                    continue;
                }
            };
            match execute_control_plane_operation_with_transfer_plan(
                &operation,
                &zones,
                &transfer_plan,
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

fn execute_control_plane_operation_with_transfer_plan(
    operation: &ControlPlaneOperation,
    zones: &ZoneStore,
    transfer_plan: &TransferPlan,
    refresh_tx: &mpsc::Sender<RefreshRequest>,
    catalog_origins: &[DomainName],
    secrets: &SecretManager,
) -> Result<(), String> {
    execute_control_plane_operation_inner(
        operation,
        zones,
        Some(transfer_plan),
        refresh_tx,
        catalog_origins,
        secrets,
    )
}

#[cfg(test)]
fn execute_control_plane_operation(
    operation: &ControlPlaneOperation,
    zones: &ZoneStore,
    refresh_tx: &mpsc::Sender<RefreshRequest>,
    catalog_origins: &[DomainName],
    secrets: &SecretManager,
) -> Result<(), String> {
    execute_control_plane_operation_inner(
        operation,
        zones,
        None,
        refresh_tx,
        catalog_origins,
        secrets,
    )
}

fn execute_control_plane_operation_inner(
    operation: &ControlPlaneOperation,
    zones: &ZoneStore,
    transfer_plan: Option<&TransferPlan>,
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
            enqueue_control_plane_refresh(
                transfer_plan,
                refresh_tx,
                origin,
                RefreshReason::ControlPlane,
            )
        }
        ControlPlaneOperationKind::Pause => {
            require_known_control_zone(zones, &origin)?;
            reject_catalog_visibility_operation(&origin, catalog_origins)?;
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
            reject_catalog_visibility_operation(&origin, catalog_origins)?;
            enqueue_control_plane_refresh(
                transfer_plan,
                refresh_tx,
                origin.clone(),
                RefreshReason::ControlPlane,
            )?;
            zones.show_zone(&origin);
            Ok(())
        }
        ControlPlaneOperationKind::RepublishFeed => {
            reload_secret_snapshot(secrets)?;
            if catalog_origins.is_empty() {
                return Ok(());
            }
            for catalog_origin in catalog_origins {
                enqueue_control_plane_refresh(
                    transfer_plan,
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
            enqueue_control_plane_refresh(
                transfer_plan,
                refresh_tx,
                origin,
                RefreshReason::ControlPlane,
            )
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
            "zone {origin} is not configured on this BoronDNS node"
        ))
    }
}

fn reject_catalog_visibility_operation(
    origin: &DomainName,
    catalog_origins: &[DomainName],
) -> Result<(), String> {
    if catalog_origins
        .iter()
        .any(|catalog| catalog.canonical_key() == origin.canonical_key())
    {
        Err(format!(
            "zone {origin} is a catalog zone; pause/resume cannot override serve_catalog_zone policy"
        ))
    } else {
        Ok(())
    }
}

fn enqueue_control_plane_refresh(
    transfer_plan: Option<&TransferPlan>,
    refresh_tx: &mpsc::Sender<RefreshRequest>,
    zone: DomainName,
    reason: RefreshReason,
) -> Result<(), String> {
    let mut request = RefreshRequest::new(zone.clone(), None, reason);
    if let Some(transfer_plan) = transfer_plan {
        let plan = transfer_plan
            .get(&zone)
            .ok_or_else(|| format!("zone {zone} has no current transfer plan"))?;
        request = request.with_plan_generation(&plan);
    }
    refresh_tx
        .try_send(request)
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
    // Keep draining the bounded mpsc channel even when resident transfer tasks
    // are capped; catalog apply_snapshot can enqueue through the same channel.
    let mut pending_requests = VecDeque::<RefreshRequest>::new();
    let mut pending_keys = HashSet::<String>::new();
    let mut active_keys = HashSet::<String>::new();
    let mut transfer_task_keys = HashMap::<TaskId, String>::new();
    let mut refresh_rx_open = true;
    let max_resident_transfer_tasks = settings.max_resident_transfer_tasks.max(1);

    loop {
        if !settings.admission.is_open() && refresh_rx_open {
            refresh_rx.close();
            refresh_rx_open = false;
            for request in pending_requests.drain(..) {
                discard_refresh_after_admission_close(&catalog_runtime, request);
            }
            pending_keys.clear();
            while let Ok(request) = refresh_rx.try_recv() {
                discard_refresh_after_admission_close(&catalog_runtime, request);
            }
        }

        while settings.admission.is_open() && transfers.len() < max_resident_transfer_tasks {
            let mut validated_request = None;
            for _ in 0..pending_requests.len() {
                let Some(candidate) = pending_requests.pop_front() else {
                    break;
                };
                let candidate_key = candidate.zone.canonical_key();
                let Some(plan) = validated_refresh_plan(
                    &candidate,
                    &catalog_runtime.refresh_registry,
                    &catalog_runtime.transfer_plan,
                ) else {
                    pending_keys.remove(&candidate_key);
                    candidate.rollback_notify_dedup_after_queue_drop();
                    warn!(
                        zone = %candidate.zone,
                        reason = %candidate.reason.as_str(),
                        "discarded pending refresh from an obsolete zone incarnation"
                    );
                    continue;
                };
                if active_keys.contains(&candidate_key) {
                    pending_requests.push_back(candidate);
                } else {
                    validated_request = Some((candidate, plan));
                    break;
                }
            }
            let Some((request, plan)) = validated_request else {
                break;
            };
            let request_key = request.zone.canonical_key();
            let Some(admission_guard) = settings.admission.admit() else {
                discard_refresh_after_admission_close(&catalog_runtime, request);
                break;
            };
            pending_keys.remove(&request_key);
            active_keys.insert(request_key.clone());

            let axfr_timeout = settings.axfr_timeout;
            let ixfr_timeout = settings.ixfr_timeout;
            let tcp_connect_timeout = settings.tcp_connect_timeout;
            let telemetry = settings.telemetry.clone();
            let transfer_limit = settings.transfer_limit.clone();
            let zone_persistence = settings.zone_persistence.clone();
            let zone_persistence_for_catalog = zone_persistence.clone();
            let zones = zones.clone();
            let catalog_runtime = catalog_runtime.clone();
            let ixfr_cooldowns = ixfr_cooldowns.clone();
            let metrics = metrics.clone();
            let task_key = request_key.clone();
            let task = transfers.spawn(async move {
                // `plan` is the exact incarnation validated at dequeue. Never
                // re-fetch here: a remove/readd between dequeue and the first
                // poll must make this work item obsolete, not silently bind
                // the stale request to the replacement plan.
                let Some(mut attempt) = begin_validated_refresh_attempt(
                    &request,
                    &catalog_runtime.refresh_registry,
                    &catalog_runtime.transfer_plan,
                    &plan,
                )
                .await
                else {
                    return request_key;
                };

                let Some(transfer_permit) = acquire_transfer_permit_for_current_plan(
                    &catalog_runtime.transfer_plan,
                    &plan,
                    transfer_limit,
                )
                .await
                else {
                    attempt.discard_obsolete();
                    return request_key;
                };
                if !request.incarnation_is_current(
                    &catalog_runtime.refresh_registry,
                    &catalog_runtime.transfer_plan,
                ) {
                    attempt.discard_obsolete();
                    return request_key;
                }
                let outcome = tokio::select! {
                    biased;
                    () = plan.cancelled() => RefreshZoneOutcome::obsolete(),
                    outcome = refresh_zone_from_primaries_with_outcome_preferring(
                        &zones,
                        &plan,
                        request.requested_serial,
                        request.preferred_primary_ip,
                        &catalog_runtime.manager,
                        RefreshAttemptContext {
                            ixfr_cooldowns: &ixfr_cooldowns,
                            metrics: &metrics,
                            transfer_plan: catalog_runtime.transfer_plan.clone(),
                            secrets: catalog_runtime.secrets.clone(),
                            ixfr_timeout,
                            axfr_timeout,
                            tcp_connect_timeout,
                            reason: request.reason.as_str(),
                            zone_persistence,
                        },
                    ) => outcome,
                };
                // Network transfer concurrency ends with the transfer itself.
                // Catalog reconciliation and best-effort telemetry must never
                // retain a global transfer slot.
                drop(transfer_permit);
                if outcome.obsolete {
                    attempt.discard_obsolete();
                    return request_key;
                }
                match outcome.success {
                    Some(success) => {
                        let (metadata, updated, catalog_members) = success.into_parts();
                        if !record_attempt_success_if_current_plan(
                            &mut attempt,
                            &catalog_runtime.transfer_plan,
                            &plan,
                            &metadata,
                        ) {
                            return request_key;
                        }
                        let telemetry_status = if updated { "success" } else { "skipped" };
                        if let Some(catalog_members) = catalog_members {
                            catalog_runtime
                                .manager
                                .apply_parsed_snapshot(
                                    catalog_members,
                                    &metadata,
                                    &zones,
                                    &catalog_runtime.transfer_plan,
                                    &catalog_runtime.refresh_registry,
                                    &catalog_runtime.notify_authority,
                                    &catalog_runtime.refresh_tx,
                                    &metrics,
                                    zone_persistence_for_catalog.as_ref(),
                                )
                                .await;
                        }
                        attempt.finish();
                        telemetry.report_success(
                            &metadata,
                            telemetry_status,
                            request.reason.as_str(),
                        );
                    }
                    None => {
                        let telemetry_failure_cause = outcome.failure_cause.clone();
                        attempt.record_failure(
                            zones.exact_zone_control_metadata(&request.zone),
                            outcome.failure_cause,
                        );
                        telemetry.report_failure(
                            &request.zone,
                            telemetry_failure_cause.as_deref(),
                            request.reason.as_str(),
                        );
                    }
                }
                request_key
            });
            transfer_task_keys.insert(task.id(), task_key);
            drop(admission_guard);
        }

        if !refresh_rx_open && pending_requests.is_empty() && transfers.is_empty() {
            break;
        }

        tokio::select! {
            () = settings.admission.closed(), if refresh_rx_open => {
                // The next loop iteration closes and drains the outer channel
                // before waiting only for work admitted before shutdown.
            }
            result = transfers.join_next_with_id(), if !transfers.is_empty() => {
                if let Some(result) = result {
                    retire_refresh_transfer_task(
                        result,
                        &mut transfer_task_keys,
                        &mut active_keys,
                    );
                }
            }
            request = refresh_rx.recv(), if refresh_rx_open => {
                if let Some(request) = request {
                    if !request.incarnation_is_current(
                        &catalog_runtime.refresh_registry,
                        &catalog_runtime.transfer_plan,
                    ) {
                        request.rollback_notify_dedup_after_queue_drop();
                        warn!(
                            zone = %request.zone,
                            reason = %request.reason.as_str(),
                            "discarded outer refresh from an obsolete zone incarnation"
                        );
                    } else if let Some(dropped) = enqueue_pending_refresh_request(
                        &mut pending_requests,
                        &mut pending_keys,
                        &active_keys,
                        request,
                    ) {
                        dropped.rollback_notify_dedup_after_queue_drop();
                        if dropped.incarnation_is_current(
                            &catalog_runtime.refresh_registry,
                            &catalog_runtime.transfer_plan,
                        ) {
                            catalog_runtime
                                .refresh_registry
                                .defer_refresh_after_queue_drop(&dropped);
                        }
                    }
                } else {
                    refresh_rx_open = false;
                }
            }
        }
    }

    while let Some(result) = transfers.join_next_with_id().await {
        retire_refresh_transfer_task(result, &mut transfer_task_keys, &mut active_keys);
    }

    Ok(())
}

fn retire_refresh_transfer_task(
    result: Result<(TaskId, String), JoinError>,
    transfer_task_keys: &mut HashMap<TaskId, String>,
    active_keys: &mut HashSet<String>,
) {
    match result {
        Ok((task_id, returned_key)) => {
            let tracked_key = transfer_task_keys.remove(&task_id);
            debug_assert!(
                tracked_key.as_ref().is_none_or(|key| key == &returned_key),
                "refresh task returned a different zone key than its admission record"
            );
            active_keys.remove(tracked_key.as_deref().unwrap_or(&returned_key));
        }
        Err(error) => {
            let task_id = error.id();
            if let Some(failed_key) = transfer_task_keys.remove(&task_id) {
                // ZoneRefreshAttempt's Drop implementation immediately makes
                // the failed incarnation due again. Retire only that task's
                // admission marker; unrelated transfers remain active.
                active_keys.remove(&failed_key);
                warn!(zone_key = %failed_key, %error, "refresh transfer task failed");
            } else {
                warn!(%error, "untracked refresh transfer task failed");
            }
        }
    }
}

fn discard_refresh_after_admission_close(
    catalog_runtime: &CatalogRuntime,
    request: RefreshRequest,
) {
    request.rollback_notify_dedup_after_queue_drop();
    if request.incarnation_is_current(
        &catalog_runtime.refresh_registry,
        &catalog_runtime.transfer_plan,
    ) {
        catalog_runtime
            .refresh_registry
            .defer_refresh_after_queue_drop(&request);
    }
}

#[derive(Clone)]
struct RefreshAdmission {
    closed: Arc<Semaphore>,
    open: Arc<Mutex<bool>>,
}

impl RefreshAdmission {
    fn new() -> Self {
        Self {
            // No permits are ever added: closing the semaphore is a durable,
            // race-free broadcast that wakes every admission waiter.
            closed: Arc::new(Semaphore::new(0)),
            open: Arc::new(Mutex::new(true)),
        }
    }

    fn is_open(&self) -> bool {
        *self.open.lock().expect("refresh admission lock poisoned")
    }

    fn admit(&self) -> Option<std::sync::MutexGuard<'_, bool>> {
        let guard = self.open.lock().expect("refresh admission lock poisoned");
        (*guard).then_some(guard)
    }

    fn close(&self) {
        *self.open.lock().expect("refresh admission lock poisoned") = false;
        self.closed.close();
    }

    async fn closed(&self) {
        let _ = self.closed.acquire().await;
    }
}

#[derive(Clone)]
struct RefreshWorkerSettings {
    axfr_timeout: Duration,
    ixfr_timeout: Duration,
    tcp_connect_timeout: Duration,
    transfer_limit: Arc<Semaphore>,
    max_resident_transfer_tasks: usize,
    telemetry: ControlPlaneTelemetryClient,
    admission: RefreshAdmission,
    zone_persistence: Option<ZonePersistence>,
}

#[derive(Clone)]
struct InitialLoadSettings {
    axfr_timeout: Duration,
    ixfr_timeout: Duration,
    tcp_connect_timeout: Duration,
    transfer_limit: Arc<Semaphore>,
    max_resident_transfer_tasks: usize,
    telemetry: ControlPlaneTelemetryClient,
    admission: RefreshAdmission,
    zone_persistence: Option<ZonePersistence>,
}

#[derive(Clone)]
struct RefreshAttemptContext<'a> {
    ixfr_cooldowns: &'a IxfrCooldownRegistry,
    metrics: &'a RuntimeMetrics,
    transfer_plan: TransferPlan,
    secrets: SecretManager,
    ixfr_timeout: Duration,
    axfr_timeout: Duration,
    tcp_connect_timeout: Duration,
    reason: &'a str,
    zone_persistence: Option<ZonePersistence>,
}

#[derive(Debug)]
struct RefreshZoneOutcome {
    success: Option<RefreshZoneSuccess>,
    failure_cause: Option<String>,
    obsolete: bool,
}

async fn persist_last_good_before_publication(
    persistence: &Option<ZonePersistence>,
    snapshot: Arc<ZoneSnapshot>,
) -> Result<(), String> {
    let Some(persistence) = persistence.clone() else {
        return Ok(());
    };
    tokio::task::spawn_blocking(move || persistence.persist(&snapshot))
        .await
        .map_err(|error| format!("zone-cache writer task failed: {error}"))?
        .map_err(|error| error.to_string())
}

enum CurrentZoneConfirmationError {
    Missing,
    Obsolete,
    PublicationFailed(String),
}

fn record_ixfr_current_confirmation(
    metrics: &RuntimeMetrics,
    confirmation: Result<ZoneMetadata, CurrentZoneConfirmationError>,
) -> Result<ZoneMetadata, CurrentZoneConfirmationError> {
    match confirmation {
        Ok(metadata) => {
            metrics.record_ixfr_succeeded();
            Ok(metadata)
        }
        Err(error) => {
            metrics.record_ixfr_failed();
            Err(error)
        }
    }
}

#[cfg(any(test, feature = "fuzzing"))]
fn confirm_current_zone(
    zones: &ZoneStore,
    transfer_plan: &TransferPlan,
    plan: &ZoneTransferPlan,
    current: &TransferZoneSnapshot,
) -> Result<ZoneMetadata, CurrentZoneConfirmationError> {
    match transfer_plan.if_current_plan(plan, || zones.activate_zone_if_snapshot(current)) {
        None => Err(CurrentZoneConfirmationError::Obsolete),
        Some(Ok(Some(metadata))) => Ok(metadata),
        Some(Ok(None)) => Err(CurrentZoneConfirmationError::Missing),
        Some(Err(error)) => Err(CurrentZoneConfirmationError::PublicationFailed(
            error.to_string(),
        )),
    }
}

fn if_current_plan_and_secret<R>(
    transfer_plan: &TransferPlan,
    secrets: &SecretManager,
    plan: &ZoneTransferPlan,
    snapshot: &Arc<secret_store::SecretSnapshot>,
    action: impl FnOnce() -> R,
) -> Option<R> {
    transfer_plan
        .if_current_plan(plan, || secrets.if_current_snapshot(snapshot, action))
        .flatten()
}

fn confirm_current_zone_with_secret(
    zones: &ZoneStore,
    transfer_plan: &TransferPlan,
    secrets: &SecretManager,
    plan: &ZoneTransferPlan,
    snapshot: &Arc<secret_store::SecretSnapshot>,
    current: &TransferZoneSnapshot,
) -> Result<ZoneMetadata, CurrentZoneConfirmationError> {
    match if_current_plan_and_secret(transfer_plan, secrets, plan, snapshot, || {
        zones.activate_zone_if_snapshot(current)
    }) {
        None => Err(CurrentZoneConfirmationError::Obsolete),
        Some(Ok(Some(metadata))) => Ok(metadata),
        Some(Ok(None)) => Err(CurrentZoneConfirmationError::Missing),
        Some(Err(error)) => Err(CurrentZoneConfirmationError::PublicationFailed(
            error.to_string(),
        )),
    }
}

fn confirm_current_zone_for_serial_with_secret(
    zones: &ZoneStore,
    transfer_plan: &TransferPlan,
    secrets: &SecretManager,
    plan: &ZoneTransferPlan,
    snapshot: &Arc<secret_store::SecretSnapshot>,
    expected_serial: u32,
) -> Result<ZoneMetadata, CurrentZoneConfirmationError> {
    let Some(current) = zones
        .exact_snapshot_with_serial_for_transfer(&plan.origin)
        .filter(|current| current.metadata().serial == Some(expected_serial))
    else {
        return Err(CurrentZoneConfirmationError::Missing);
    };
    confirm_current_zone_with_secret(zones, transfer_plan, secrets, plan, snapshot, &current)
}

#[derive(Debug)]
enum RefreshZoneSuccess {
    Current(ZoneMetadata),
    Updated {
        metadata: ZoneMetadata,
        catalog_members: Option<ParsedCatalogMembers>,
    },
}

impl RefreshZoneOutcome {
    fn current(metadata: ZoneMetadata) -> Self {
        Self {
            success: Some(RefreshZoneSuccess::Current(metadata)),
            failure_cause: None,
            obsolete: false,
        }
    }

    fn updated(metadata: ZoneMetadata, catalog_members: Option<ParsedCatalogMembers>) -> Self {
        Self {
            success: Some(RefreshZoneSuccess::Updated {
                metadata,
                catalog_members,
            }),
            failure_cause: None,
            obsolete: false,
        }
    }

    fn failure(failure_cause: Option<String>) -> Self {
        Self {
            success: None,
            failure_cause,
            obsolete: false,
        }
    }

    fn obsolete() -> Self {
        Self {
            success: None,
            failure_cause: None,
            obsolete: true,
        }
    }
}

impl RefreshZoneSuccess {
    fn into_parts(self) -> (ZoneMetadata, bool, Option<ParsedCatalogMembers>) {
        match self {
            Self::Current(metadata) => (metadata, false, None),
            Self::Updated {
                metadata,
                catalog_members,
            } => (metadata, true, catalog_members),
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
    let mut initial_origins = initial_origins.into_iter();
    let max_resident_transfer_tasks = settings.max_resident_transfer_tasks.max(1);

    loop {
        while settings.admission.is_open() && transfers.len() < max_resident_transfer_tasks {
            let Some(zone_apex) = initial_origins.next() else {
                break;
            };
            let Some(admission_guard) = settings.admission.admit() else {
                break;
            };
            let zones = zones.clone();
            let catalog_runtime = catalog_runtime.clone();
            let ixfr_cooldowns = ixfr_cooldowns.clone();
            let metrics = metrics.clone();
            let axfr_timeout = settings.axfr_timeout;
            let ixfr_timeout = settings.ixfr_timeout;
            let tcp_connect_timeout = settings.tcp_connect_timeout;
            let telemetry = settings.telemetry.clone();
            let transfer_limit = settings.transfer_limit.clone();
            let zone_persistence = settings.zone_persistence.clone();
            let zone_persistence_for_catalog = zone_persistence.clone();

            transfers.spawn(async move {
                let Some(plan) = catalog_runtime.transfer_plan.get(&zone_apex) else {
                    warn!(zone = %zone_apex, "initial load skipped because transfer plan was removed");
                    return;
                };
                let mut attempt = catalog_runtime
                    .refresh_registry
                    .begin_attempt(&zone_apex)
                    .await;
                if !catalog_runtime.transfer_plan.is_current_plan(&plan) {
                    attempt.discard_obsolete();
                    return;
                }
                let Some(transfer_permit) = acquire_transfer_permit_for_current_plan(
                    &catalog_runtime.transfer_plan,
                    &plan,
                    transfer_limit,
                )
                .await
                else {
                    attempt.discard_obsolete();
                    return;
                };
                let outcome = tokio::select! {
                    biased;
                    () = plan.cancelled() => RefreshZoneOutcome::obsolete(),
                    outcome = refresh_zone_from_primaries_with_outcome(
                        &zones,
                        &plan,
                        None,
                        &catalog_runtime.manager,
                        RefreshAttemptContext {
                            ixfr_cooldowns: &ixfr_cooldowns,
                            metrics: &metrics,
                            transfer_plan: catalog_runtime.transfer_plan.clone(),
                            secrets: catalog_runtime.secrets.clone(),
                            ixfr_timeout,
                            axfr_timeout,
                            tcp_connect_timeout,
                            reason: "initial",
                            zone_persistence,
                        },
                    ) => outcome,
                };
                // Do not let catalog reconciliation or telemetry consume a
                // transfer slot after the wire transfer has completed.
                drop(transfer_permit);
                if outcome.obsolete {
                    attempt.discard_obsolete();
                    return;
                }
                match outcome.success {
                    Some(success) => {
                        let (metadata, updated, catalog_members) = success.into_parts();
                        if !record_attempt_success_if_current_plan(
                            &mut attempt,
                            &catalog_runtime.transfer_plan,
                            &plan,
                            &metadata,
                        ) {
                            return;
                        }
                        let telemetry_status = if updated {
                            "success"
                        } else {
                            "skipped"
                        };
                        if let Some(catalog_members) = catalog_members {
                            catalog_runtime
                                .manager
                                .apply_parsed_snapshot(
                                    catalog_members,
                                    &metadata,
                                    &zones,
                                    &catalog_runtime.transfer_plan,
                                    &catalog_runtime.refresh_registry,
                                    &catalog_runtime.notify_authority,
                                    &catalog_runtime.refresh_tx,
                                    &metrics,
                                    zone_persistence_for_catalog.as_ref(),
                                )
                                .await;
                        }
                        attempt.finish();
                        telemetry.report_success(&metadata, telemetry_status, "initial");
                    }
                    None => {
                        let zone_apex = &plan.origin;
                        let telemetry_failure_cause = outcome.failure_cause.clone();
                        attempt.record_failure(
                            zones.exact_zone_control_metadata(zone_apex),
                            outcome.failure_cause,
                        );
                        telemetry.report_failure(
                            zone_apex,
                            telemetry_failure_cause.as_deref(),
                            "initial",
                        );
                        warn!(zone = %zone_apex, "zone remains in LOADING state");
                    }
                }
            });
            drop(admission_guard);
        }

        let wait_for_admission_close = settings.admission.is_open();
        if transfers.is_empty() && (!wait_for_admission_close || initial_origins.len() == 0) {
            break;
        }

        tokio::select! {
            () = settings.admission.closed(), if wait_for_admission_close => {
                // Stop admitting the still-unstarted origin iterator. Tasks
                // already resident continue under the graceful deadline.
            }
            result = transfers.join_next(), if !transfers.is_empty() => {
                if let Some(Err(error)) = result {
                    warn!(%error, "initial zone transfer task failed");
                }
            }
        }
    }

    Ok(())
}

fn max_resident_transfer_tasks(max_concurrent_transfers: usize) -> usize {
    max_concurrent_transfers
        .saturating_mul(TRANSFER_TASK_BACKLOG_MULTIPLIER)
        .max(1)
}

async fn serve_scheduled_refreshes(
    zones: ZoneStore,
    refresh_registry: ZoneRefreshRegistry,
    transfer_plan: TransferPlan,
    refresh_tx: mpsc::Sender<RefreshRequest>,
    tick: Duration,
) -> Result<(), RuntimeError> {
    let mut interval = tokio::time::interval(tick);
    loop {
        interval.tick().await;
        let now = Instant::now();
        for zone in refresh_registry.expire_due_zones(&zones, now) {
            warn!(zone = %zone, "zone expired");
        }
        for warning in refresh_registry.loading_warnings_due(&zones, now) {
            log_loading_warning(warning);
        }

        for zone in refresh_registry.start_due_refreshes(now) {
            let Some(plan) = transfer_plan.get(&zone) else {
                refresh_registry.cancel_in_progress(&zone);
                continue;
            };
            match refresh_tx.try_send(
                RefreshRequest::new(zone.clone(), None, RefreshReason::Scheduled)
                    .with_plan_generation(&plan),
            ) {
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

fn serial_after(candidate: u32, current: u32) -> bool {
    candidate != current && candidate.wrapping_sub(current) < 0x8000_0000
}

fn ixfr_error_disables_ixfr(error: &TransferError) -> bool {
    matches!(
        error,
        TransferError::Ixfr(axfr::IxfrError::ErrorRcode(1 | 4))
            | TransferError::Ixfr(axfr::IxfrError::ErrorRcodeWithEde { rcode: 1 | 4, .. })
    )
}

#[cfg(test)]
fn resolve_plan_tsig_key(
    plan: &ZoneTransferPlan,
    secrets: &SecretManager,
) -> Result<Option<Arc<TsigKey>>, TransferError> {
    let snapshot = secrets
        .current_snapshot()
        .map_err(|error| TransferError::MissingTsigKey {
            key_name: format!("secret snapshot unavailable: {error}"),
        })?;
    resolve_plan_tsig_key_from_snapshot(plan, &snapshot)
}

fn resolve_plan_tsig_key_from_snapshot(
    plan: &ZoneTransferPlan,
    snapshot: &secret_store::SecretSnapshot,
) -> Result<Option<Arc<TsigKey>>, TransferError> {
    let Some(key_name) = &plan.tsig_key_name else {
        return Ok(None);
    };
    snapshot
        .tsig_key(key_name)
        .map(Some)
        .ok_or_else(|| TransferError::MissingTsigKey {
            key_name: key_name.to_string(),
        })
}

struct ResolvedTransferPrimary {
    config: borondns_core::config::TransferPrimaryConfig,
    xot_client_config: Option<transfer::XotClientConfig>,
}

impl std::ops::Deref for ResolvedTransferPrimary {
    type Target = borondns_core::config::TransferPrimaryConfig;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

#[cfg(test)]
fn resolve_transfer_primary(
    primary: &borondns_core::config::TransferPrimaryConfig,
    secrets: &SecretManager,
) -> Result<ResolvedTransferPrimary, TransferError> {
    let snapshot = secrets
        .current_snapshot()
        .map_err(|error| TransferError::XotConfig {
            addr: primary.addr,
            message: format!("secret snapshot unavailable: {error}"),
        })?;
    resolve_transfer_primary_from_snapshot(primary, &snapshot)
}

fn resolve_transfer_primary_from_snapshot(
    primary: &borondns_core::config::TransferPrimaryConfig,
    snapshot: &secret_store::SecretSnapshot,
) -> Result<ResolvedTransferPrimary, TransferError> {
    let Some(profile_name) = primary.xot_profile.as_deref() else {
        return Ok(ResolvedTransferPrimary {
            config: primary.clone(),
            xot_client_config: None,
        });
    };
    let profile = snapshot
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
        .map(|secret| ConfigSecretString::from_plaintext(secret.expose_secret()));
    Ok(ResolvedTransferPrimary {
        config: resolved,
        xot_client_config: Some(profile.client_config),
    })
}

struct ResolvedTransferCredentials {
    primary: ResolvedTransferPrimary,
    tsig_key: Option<Arc<TsigKey>>,
    _snapshot: Arc<secret_store::SecretSnapshot>,
}

fn resolve_transfer_credentials_from_snapshot(
    primary: &borondns_core::config::TransferPrimaryConfig,
    plan: &ZoneTransferPlan,
    snapshot: Arc<secret_store::SecretSnapshot>,
) -> Result<ResolvedTransferCredentials, TransferError> {
    let primary = resolve_transfer_primary_from_snapshot(primary, &snapshot)?;
    let tsig_key = resolve_plan_tsig_key_from_snapshot(plan, &snapshot)?;
    Ok(ResolvedTransferCredentials {
        primary,
        tsig_key,
        _snapshot: snapshot,
    })
}

#[cfg(test)]
fn resolve_transfer_credentials_with_hook(
    primary: &borondns_core::config::TransferPrimaryConfig,
    plan: &ZoneTransferPlan,
    secrets: &SecretManager,
    after_primary_resolution: impl FnOnce(),
) -> Result<ResolvedTransferCredentials, TransferError> {
    let snapshot = secrets
        .current_snapshot()
        .map_err(|error| TransferError::XotConfig {
            addr: primary.addr,
            message: format!("secret snapshot unavailable: {error}"),
        })?;
    let primary = resolve_transfer_primary_from_snapshot(primary, &snapshot)?;
    after_primary_resolution();
    let tsig_key = resolve_plan_tsig_key_from_snapshot(plan, &snapshot)?;
    Ok(ResolvedTransferCredentials {
        primary,
        tsig_key,
        _snapshot: snapshot,
    })
}

#[cfg(test)]
async fn refresh_zone_metadata_from_primaries(
    zones: &ZoneStore,
    plan: &ZoneTransferPlan,
    primary_serial_hint: Option<u32>,
    context: RefreshAttemptContext<'_>,
) -> Option<ZoneMetadata> {
    let catalog_manager = CatalogManager::default();
    let outcome = refresh_zone_from_primaries_with_outcome(
        zones,
        plan,
        primary_serial_hint,
        &catalog_manager,
        context,
    )
    .await;
    outcome.success.map(|success| match success {
        RefreshZoneSuccess::Current(metadata) | RefreshZoneSuccess::Updated { metadata, .. } => {
            metadata
        }
    })
}

fn schedule_zone_overlay_compaction(zones: &ZoneStore, origin: &DomainName) {
    if !zones.overlay_compaction_due(origin) {
        return;
    }
    let zones = zones.clone();
    let origin = origin.clone();
    tokio::task::spawn_blocking(move || match zones.compact_overlay_if_due(&origin) {
        Ok(ZoneOverlayCompactionOutcome::Compacted {
            remaining_dirty_owners,
        }) => {
            info!(
                category = "transfer",
                event = "zone_overlay_compaction_completed",
                zone = %origin,
                remaining_dirty_owners,
                "large-zone IXFR overlay compaction completed"
            );
            if zones.overlay_compaction_due(&origin) {
                warn!(
                    category = "transfer",
                    event = "zone_overlay_compaction_still_due",
                    zone = %origin,
                    remaining_dirty_owners,
                    "zone changed faster than the bounded compaction passes; a later transfer will retry"
                );
            }
        }
        Ok(
            ZoneOverlayCompactionOutcome::NotNeeded
            | ZoneOverlayCompactionOutcome::AlreadyRunning
            | ZoneOverlayCompactionOutcome::Obsolete,
        ) => {}
        Err(error) => warn!(
            category = "transfer",
            event = "zone_overlay_compaction_failed",
            zone = %origin,
            %error,
            "large-zone IXFR overlay compaction failed; current serving snapshot remains active"
        ),
    });
}

#[cfg(test)]
async fn refresh_zone_metadata_from_primaries_preferring(
    zones: &ZoneStore,
    plan: &ZoneTransferPlan,
    primary_serial_hint: Option<u32>,
    preferred_primary_ip: IpAddr,
    context: RefreshAttemptContext<'_>,
) -> Option<ZoneMetadata> {
    let catalog_manager = CatalogManager::default();
    let outcome = refresh_zone_from_primaries_with_outcome_preferring(
        zones,
        plan,
        primary_serial_hint,
        Some(preferred_primary_ip),
        &catalog_manager,
        context,
    )
    .await;
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
    catalog_manager: &CatalogManager,
    context: RefreshAttemptContext<'_>,
) -> RefreshZoneOutcome {
    refresh_zone_from_primaries_with_outcome_preferring(
        zones,
        plan,
        primary_serial_hint,
        None,
        catalog_manager,
        context,
    )
    .await
}

async fn refresh_zone_from_primaries_with_outcome_preferring(
    zones: &ZoneStore,
    plan: &ZoneTransferPlan,
    primary_serial_hint: Option<u32>,
    preferred_primary_ip: Option<IpAddr>,
    catalog_manager: &CatalogManager,
    context: RefreshAttemptContext<'_>,
) -> RefreshZoneOutcome {
    let snapshot = match context.secrets.current_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return RefreshZoneOutcome::failure(Some(format!(
                "secret snapshot unavailable: {error}"
            )));
        }
    };
    let cancellation_snapshot = snapshot.clone();
    tokio::select! {
        biased;
        () = cancellation_snapshot.cancelled() => RefreshZoneOutcome::obsolete(),
        outcome = refresh_zone_from_primaries_with_snapshot(
            zones,
            plan,
            primary_serial_hint,
            preferred_primary_ip,
            catalog_manager,
            context,
            snapshot,
        ) => outcome,
    }
}

async fn refresh_zone_from_primaries_with_snapshot(
    zones: &ZoneStore,
    plan: &ZoneTransferPlan,
    _notify_serial_hint: Option<u32>,
    preferred_primary_ip: Option<IpAddr>,
    catalog_manager: &CatalogManager,
    context: RefreshAttemptContext<'_>,
    secret_snapshot: Arc<secret_store::SecretSnapshot>,
) -> RefreshZoneOutcome {
    let current_serial = zones
        .exact_zone_control_metadata(&plan.origin)
        .and_then(|metadata| metadata.serial);
    let mut last_failure_cause = None;
    let mut equal_primary_confirmed = false;
    let mut newer_primary_observed = false;
    let transfer_ingest_budget = context.transfer_plan.ingest_budget();

    let primaries = plan
        .primaries
        .iter()
        .filter(|primary| {
            preferred_primary_ip.is_some_and(|preferred| primary.addr.ip() == preferred)
        })
        .chain(plan.primaries.iter().filter(|primary| {
            preferred_primary_ip.is_none_or(|preferred| primary.addr.ip() != preferred)
        }));

    'primary: for configured_primary in primaries {
        let credentials = match resolve_transfer_credentials_from_snapshot(
            configured_primary,
            plan,
            secret_snapshot.clone(),
        ) {
            Ok(credentials) => credentials,
            Err(error) => {
                let primary = configured_primary.addr;
                last_failure_cause = Some(format!(
                    "transfer credential resolution failed for primary {primary}: {error}"
                ));
                warn!(
                    zone = %plan.origin,
                    %primary,
                    %error,
                    reason = %context.reason,
                    "transfer credential resolution failed"
                );
                continue;
            }
        };
        let primary_target = credentials.primary;
        let tsig_key = credentials.tsig_key;
        let primary = primary_target.addr;
        let transfer_source = plan.transfer_source_for(primary);

        if let Some(current_serial) = current_serial {
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
            match poll_soa_from_target_with_tsig_and_source(
                &primary_target,
                &plan.origin,
                plan.qclass,
                qid,
                TransferTsig::new(tsig_key.as_deref(), plan.tsig_fudge_seconds),
                transfer_source,
                primary_target.xot_client_config.as_ref(),
                context.axfr_timeout,
                context.tcp_connect_timeout,
            )
            .await
            {
                Ok(primary_serial) if primary_serial == current_serial => {
                    equal_primary_confirmed = true;
                    info!(
                        zone = %plan.origin,
                        %primary,
                        current_serial,
                        primary_serial,
                        reason = %context.reason,
                        "SOA poll matched the current zone serial; checking remaining primaries"
                    );
                    continue;
                }
                Ok(primary_serial) if serial_after(primary_serial, current_serial) => {
                    newer_primary_observed = true;
                    info!(
                        zone = %plan.origin,
                        %primary,
                        current_serial,
                        primary_serial,
                        reason = %context.reason,
                        "SOA poll found newer primary serial"
                    );
                }
                Ok(primary_serial) => {
                    last_failure_cause = Some(format!(
                        "SOA poll found older or serial-arithmetic-ambiguous primary {primary}: current serial {current_serial}, primary serial {primary_serial}"
                    ));
                    warn!(
                        zone = %plan.origin,
                        %primary,
                        current_serial,
                        primary_serial,
                        reason = %context.reason,
                        "SOA poll found stale primary serial; checking remaining primaries"
                    );
                    continue;
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
            if context.ixfr_cooldowns.is_disabled_for_plan(plan, primary) {
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
                        continue 'primary;
                    }
                };
                if let Some(current) = zones.exact_snapshot_with_serial_for_transfer(&plan.origin) {
                    let current_serial = current
                        .metadata()
                        .serial
                        .expect("IXFR current snapshot metadata has a serial");
                    context.metrics.record_ixfr_started();
                    let ixfr_started = Instant::now();
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
                        .with_max_ingest_messages(plan.max_transfer_ingest_messages)
                        .with_ingest_budget(&transfer_ingest_budget)
                        .with_transfer_source(transfer_source)
                        .with_xot_client_config(primary_target.xot_client_config.as_ref()),
                        context.ixfr_timeout,
                        context.tcp_connect_timeout,
                    )
                    .await
                    {
                        Ok(IxfrResponse::Updated(snapshot)) => {
                            let snapshot: Arc<ZoneSnapshot> = Arc::from(snapshot);
                            let catalog_members = match catalog_manager
                                .parse_candidate_snapshot(&snapshot)
                            {
                                Ok(parsed) => Some(parsed),
                                Err(error) => {
                                    context.metrics.record_ixfr_failed();
                                    log_catalog_error(&error);
                                    warn!(
                                        zone = %plan.origin,
                                        %primary,
                                        reason = %context.reason,
                                        "IXFR catalog validation failed before publication; falling back to AXFR"
                                    );
                                    None
                                }
                            };
                            if let Some(catalog_members) = catalog_members {
                                if let Err(error) = persist_last_good_before_publication(
                                    &context.zone_persistence,
                                    snapshot.clone(),
                                )
                                .await
                                {
                                    context.metrics.record_ixfr_failed();
                                    warn!(
                                        zone = %plan.origin,
                                        %primary,
                                        %error,
                                        reason = %context.reason,
                                        "IXFR last-good persistence failed before publication; falling back to AXFR"
                                    );
                                    continue;
                                }
                                match context
                                    .transfer_plan
                                    .if_current_plan(plan, || {
                                        context.secrets.if_current_snapshot(
                                            &secret_snapshot,
                                            || {
                                                zones.insert_snapshot_arc_for_transfer(
                                                    snapshot.clone(),
                                                )
                                            },
                                        )
                                    })
                                    .flatten()
                                {
                                    None => {
                                        warn!(
                                            zone = %plan.origin,
                                            %primary,
                                            reason = %context.reason,
                                            "IXFR result discarded because zone no longer has a transfer plan"
                                        );
                                        return RefreshZoneOutcome::obsolete();
                                    }
                                    Some(Ok(metadata)) => {
                                        context.metrics.record_ixfr_succeeded();
                                        let serial = metadata.serial;
                                        let elapsed_seconds = ixfr_started.elapsed().as_secs_f64();
                                        let generations = serial
                                            .map(|serial| serial.wrapping_sub(current_serial));
                                        schedule_zone_overlay_compaction(zones, &metadata.origin);
                                        info!(
                                            zone = %plan.origin,
                                            %primary,
                                            ?serial,
                                            from_serial = current_serial,
                                            ?generations,
                                            elapsed_seconds,
                                            reason = %context.reason,
                                            "IXFR completed"
                                        );
                                        return RefreshZoneOutcome::updated(
                                            metadata,
                                            catalog_members,
                                        );
                                    }
                                    Some(Err(error)) => {
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
                        }
                        Ok(IxfrResponse::Current) => {
                            let confirmation = record_ixfr_current_confirmation(
                                context.metrics,
                                confirm_current_zone_with_secret(
                                    zones,
                                    &context.transfer_plan,
                                    &context.secrets,
                                    plan,
                                    &secret_snapshot,
                                    &current,
                                ),
                            );
                            let cached_metadata = current.into_metadata();
                            match confirmation {
                                Ok(metadata) => {
                                    debug_assert_eq!(
                                        cached_metadata.origin_key,
                                        metadata.origin_key
                                    );
                                    debug_assert_eq!(cached_metadata.serial, metadata.serial);
                                    info!(
                                        zone = %plan.origin,
                                        %primary,
                                        current_serial,
                                        reason = %context.reason,
                                        "IXFR confirmed zone current"
                                    );
                                    return RefreshZoneOutcome::current(metadata);
                                }
                                Err(CurrentZoneConfirmationError::Obsolete) => {
                                    warn!(
                                        zone = %plan.origin,
                                        %primary,
                                        reason = %context.reason,
                                        "IXFR current result discarded because zone no longer has the same transfer plan"
                                    );
                                    return RefreshZoneOutcome::obsolete();
                                }
                                Err(CurrentZoneConfirmationError::Missing) => {
                                    warn!(
                                        zone = %plan.origin,
                                        %primary,
                                        reason = %context.reason,
                                        "current zone disappeared after IXFR"
                                    );
                                }
                                Err(CurrentZoneConfirmationError::PublicationFailed(error)) => {
                                    warn!(
                                        zone = %plan.origin,
                                        %primary,
                                        reason = %context.reason,
                                        %error,
                                        "failed to reactivate current zone after IXFR"
                                    );
                                }
                            }
                        }
                        Err(error) => {
                            context.metrics.record_ixfr_failed();
                            if ixfr_error_disables_ixfr(&error) {
                                context.ixfr_cooldowns.record_unsupported_if_current(
                                    &context.transfer_plan,
                                    plan,
                                    primary,
                                );
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
            )
            .with_max_ingest_messages(plan.max_transfer_ingest_messages)
            .with_ingest_budget(&transfer_ingest_budget)
            .with_xot_client_config(primary_target.xot_client_config.as_ref()),
            transfer_source,
            context.axfr_timeout,
            context.tcp_connect_timeout,
        )
        .await
        {
            Ok(snapshot) => {
                info!(
                    event = "zone_transfer_publication_phase",
                    phase = "axfr_snapshot_received",
                    zone = %plan.origin,
                    %primary,
                    reason = %context.reason,
                    "zone transfer publication phase"
                );
                let snapshot = Arc::new(snapshot);
                let catalog_members = match catalog_manager.parse_candidate_snapshot(&snapshot) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        context.metrics.record_axfr_failed();
                        last_failure_cause = Some(format!(
                            "AXFR returned an invalid catalog snapshot from primary {primary}: {error}"
                        ));
                        log_catalog_error(&error);
                        warn!(
                            zone = %plan.origin,
                            %primary,
                            reason = %context.reason,
                            "AXFR catalog validation failed before publication"
                        );
                        continue;
                    }
                };
                info!(
                    event = "zone_transfer_publication_phase",
                    phase = "axfr_snapshot_validated",
                    zone = %plan.origin,
                    %primary,
                    reason = %context.reason,
                    "zone transfer publication phase"
                );
                if let Err(error) = persist_last_good_before_publication(
                    &context.zone_persistence,
                    snapshot.clone(),
                )
                .await
                {
                    last_failure_cause = Some(format!(
                        "AXFR last-good persistence failed for primary {primary}: {error}"
                    ));
                    context.metrics.record_axfr_failed();
                    warn!(
                        zone = %plan.origin,
                        %primary,
                        %error,
                        reason = %context.reason,
                        "AXFR last-good persistence failed before publication"
                    );
                    continue;
                }
                match context
                    .transfer_plan
                    .if_current_plan(plan, || {
                        context.secrets.if_current_snapshot(&secret_snapshot, || {
                            zones.insert_snapshot_arc_for_transfer(snapshot.clone())
                        })
                    })
                    .flatten()
                {
                    None => {
                        warn!(
                            zone = %plan.origin,
                            %primary,
                            reason = %context.reason,
                            "AXFR result discarded because zone no longer has a transfer plan"
                        );
                        return RefreshZoneOutcome::obsolete();
                    }
                    Some(Ok(metadata)) => {
                        context.metrics.record_axfr_succeeded();
                        let serial = metadata.serial;
                        schedule_zone_overlay_compaction(zones, &metadata.origin);
                        info!(
                            zone = %plan.origin,
                            %primary,
                            ?serial,
                            reason = %context.reason,
                            "AXFR completed"
                        );
                        return RefreshZoneOutcome::updated(metadata, catalog_members);
                    }
                    Some(Err(error)) => {
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

    if equal_primary_confirmed && !newer_primary_observed {
        let current_serial =
            current_serial.expect("equal SOA confirmation requires current serial");
        match confirm_current_zone_for_serial_with_secret(
            zones,
            &context.transfer_plan,
            &context.secrets,
            plan,
            &secret_snapshot,
            current_serial,
        ) {
            Ok(metadata) => return RefreshZoneOutcome::current(metadata),
            Err(CurrentZoneConfirmationError::Obsolete) => {
                warn!(
                    zone = %plan.origin,
                    reason = %context.reason,
                    "SOA current confirmations discarded because zone no longer has the same transfer plan"
                );
                return RefreshZoneOutcome::obsolete();
            }
            Err(CurrentZoneConfirmationError::Missing) => {
                last_failure_cause =
                    Some("current zone disappeared after all equal SOA confirmations".to_owned());
            }
            Err(CurrentZoneConfirmationError::PublicationFailed(error)) => {
                last_failure_cause = Some(format!(
                    "failed to reactivate current zone after equal SOA confirmations: {error}"
                ));
            }
        }
    }

    RefreshZoneOutcome::failure(last_failure_cause)
}

#[cfg(any(test, feature = "fuzzing"))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct LifecycleFuzzStats {
    overflow_drops: usize,
    filler_drains: usize,
    admissions_after_recovery: usize,
    scheduled_overflow_drops: usize,
    scheduled_admissions: usize,
    scheduled_admissions_after_recovery: usize,
    completions_after_recovery: usize,
    notify_signalled: usize,
    notify_deduplicated: usize,
    stale_pending_incarnation_drops: usize,
    shutdown_drops: usize,
    reactivations: usize,
    recovered_after_overflow: bool,
}

#[cfg(any(test, feature = "fuzzing"))]
fn lifecycle_soa_rdata(serial: u32) -> Vec<u8> {
    let mut rdata = b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec();
    let (_, consumed_mname) =
        DomainName::parse(&rdata, 0).expect("static lifecycle SOA MNAME is valid");
    let (_, consumed_rname) =
        DomainName::parse(&rdata, consumed_mname).expect("static lifecycle SOA RNAME is valid");
    let serial_offset = consumed_mname + consumed_rname;
    rdata[serial_offset..serial_offset + 4].copy_from_slice(&serial.to_be_bytes());
    rdata
}

#[cfg(any(test, feature = "fuzzing"))]
fn run_lifecycle_fuzz_sequence(data: &[u8]) -> LifecycleFuzzStats {
    const ZONE_COUNT: usize = 4;
    const MAX_OPERATIONS: usize = 512;
    const MAX_OVERFLOW_PROBES: usize = 4;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("lifecycle fuzz runtime builds");

    let config = ServerConfig::from_toml_str(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [[zones]]
            name = "zone0.lifecycle-fuzz."
            primaries = ["192.0.2.1:53"]
            [[zones]]
            name = "zone1.lifecycle-fuzz."
            primaries = ["192.0.2.2:53"]
            [[zones]]
            name = "zone2.lifecycle-fuzz."
            primaries = ["192.0.2.3:53"]
            [[zones]]
            name = "zone3.lifecycle-fuzz."
            primaries = ["192.0.2.4:53"]
        "#,
    )
    .expect("static lifecycle fuzz config is valid");
    let transfer_plan = TransferPlan::from_config_with_primary_start(&config, |_| Ok(0))
        .expect("static lifecycle fuzz transfer plan is valid");
    let zones = config
        .zones
        .iter()
        .map(|zone| DomainName::from_absolute_str(&zone.name).expect("static zone name is valid"))
        .collect::<Vec<_>>();
    let templates = zones
        .iter()
        .map(|zone| transfer_plan.get(zone).expect("configured plan exists"))
        .collect::<Vec<_>>();
    for zone in &zones {
        transfer_plan.remove(zone);
    }
    let store = ZoneStore::new();
    let registry = ZoneRefreshRegistry::new(
        Duration::ZERO,
        Duration::from_secs(86_400),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(60),
    );
    let notify_tracker = NotifyRefreshTracker::with_refresh_registry_and_transfer_plan(
        Duration::from_secs(2),
        registry.clone(),
        transfer_plan.clone(),
    );

    // Keep deterministic seeds for every production source across the exact
    // dequeue-validation -> attempt-owned -> transfer-permit-wait boundary.
    // Random operations then extend these cases, but even a tiny fuzz input
    // invokes the production validation and permit acquisition functions and
    // proves removal cancels pending work before obsolete network I/O.
    let boundary_origin = &zones[0];
    for reason in [
        RefreshReason::Catalog,
        RefreshReason::Scheduled,
        RefreshReason::ControlPlane,
        RefreshReason::Notify,
    ] {
        transfer_plan.insert(templates[0].clone());
        store.insert_loading(boundary_origin.clone());
        registry.record_loading_start_at(boundary_origin, Instant::now());
        let current_plan = transfer_plan
            .get(boundary_origin)
            .expect("boundary seed plan exists");
        let request = if reason == RefreshReason::Notify {
            let mut request = None;
            let action = notify_tracker.record_after_enqueue_serial_at(
                boundary_origin,
                Some(2),
                Instant::now(),
                |token| {
                    request = Some(
                        RefreshRequest::new(boundary_origin.clone(), Some(2), reason)
                            .with_notify_dedup_token(token),
                    );
                    Ok::<(), ()>(())
                },
            );
            assert_eq!(action, Ok(NotifyRefreshAction::Signalled));
            request.expect("NOTIFY boundary request is captured")
        } else {
            RefreshRequest::new(boundary_origin.clone(), None, reason)
                .with_plan_generation(&current_plan)
        };
        let captured_plan = validated_refresh_plan(&request, &registry, &transfer_plan)
            .expect("boundary seed validates at dequeue");
        let attempt = runtime
            .block_on(begin_validated_refresh_attempt(
                &request,
                &registry,
                &transfer_plan,
                &captured_plan,
            ))
            .expect("boundary seed owns a validated production attempt before permit wait");
        let transfer_limit = Arc::new(Semaphore::new(0));
        let permit_result = runtime.block_on(async {
            tokio::join!(
                acquire_transfer_permit_for_current_plan(
                    &transfer_plan,
                    &captured_plan,
                    transfer_limit.clone(),
                ),
                async {
                    tokio::task::yield_now().await;
                    transfer_plan.remove(boundary_origin);
                }
            )
            .0
        });
        assert!(permit_result.is_none());
        assert_eq!(transfer_limit.available_permits(), 0);
        registry.remove_zone(boundary_origin);
        notify_tracker.remove_zone(boundary_origin);
        store.remove_zone(boundary_origin);
        transfer_plan.insert(templates[0].clone());
        store.insert_loading(boundary_origin.clone());
        registry.record_loading_start_at(boundary_origin, Instant::now());

        assert!(!request.incarnation_is_current(&registry, &transfer_plan));
        assert!(!transfer_plan.is_current_plan(&captured_plan));
        assert!(captured_plan.is_cancelled());
        attempt.discard_obsolete();
        transfer_plan.remove(boundary_origin);
        registry.remove_zone(boundary_origin);
        notify_tracker.remove_zone(boundary_origin);
        store.remove_zone(boundary_origin);
    }

    // Seed both expiration/catalog interleavings with the same generation and
    // compare-and-publish boundaries used by production. The first removal is
    // before attempt acquisition; the second remove/re-add is after due
    // validation but before directory publication.
    for remove_before_attempt in [true, false] {
        transfer_plan.insert(templates[0].clone());
        store.insert_loading(boundary_origin.clone());
        registry.record_loading_start_at(boundary_origin, Instant::now());
        let snapshot = Arc::new(ZoneSnapshot::active(
            boundary_origin.clone(),
            Some(1),
            vec![Rrset::new(
                boundary_origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![lifecycle_soa_rdata(1)],
            )],
        ));
        let metadata = store
            .insert_snapshot_arc_for_transfer(snapshot)
            .expect("expiration boundary seed publishes");
        let mut attempt = runtime.block_on(registry.begin_attempt(boundary_origin));
        assert!(attempt.record_success_at(&metadata, Instant::now(), 1_700_000_000));
        attempt.finish();
        let expiry = runtime_deadline(Instant::now(), Duration::from_secs(604_800));
        let transitioned = std::cell::Cell::new(false);
        let expired = registry.expire_due_zones_with_hooks(
            &store,
            expiry,
            |_| {
                if remove_before_attempt && !transitioned.get() {
                    transitioned.set(true);
                    transfer_plan.remove(boundary_origin);
                    registry.remove_zone(boundary_origin);
                    notify_tracker.remove_zone(boundary_origin);
                    store.remove_zone(boundary_origin);
                }
            },
            |_| {
                if !remove_before_attempt && !transitioned.get() {
                    transitioned.set(true);
                    transfer_plan.remove(boundary_origin);
                    registry.remove_zone(boundary_origin);
                    notify_tracker.remove_zone(boundary_origin);
                    store.remove_zone(boundary_origin);
                    transfer_plan.insert(templates[0].clone());
                    registry.record_loading_start_at(boundary_origin, Instant::now());
                    store.insert_loading(boundary_origin.clone());
                }
            },
        );
        assert!(transitioned.get());
        assert!(expired.is_empty());
        if remove_before_attempt {
            assert!(
                !registry
                    .statuses
                    .lock()
                    .expect("refresh registry lock poisoned")
                    .contains_key(&boundary_origin.canonical_key())
            );
        } else {
            let status = registry
                .statuses
                .lock()
                .expect("refresh registry lock poisoned")
                .get(&boundary_origin.canonical_key())
                .cloned()
                .expect("replacement refresh status exists");
            assert!(!status.expired);
            assert!(!status.in_progress);
            assert_eq!(
                store
                    .exact_zone_control_metadata(boundary_origin)
                    .expect("replacement zone exists")
                    .state,
                ZoneState::Loading
            );
        }
        transfer_plan.remove(boundary_origin);
        registry.remove_zone(boundary_origin);
        notify_tracker.remove_zone(boundary_origin);
        store.remove_zone(boundary_origin);
    }
    let modeled_start = Instant::now();
    let mut modeled_now = modeled_start;
    let mut desired = [false; ZONE_COUNT];
    let mut pending = VecDeque::new();
    let mut pending_keys = HashSet::new();
    let mut active_keys = HashSet::new();
    let mut attempts: [Option<(ZoneRefreshAttempt, Option<ZoneTransferPlan>)>; ZONE_COUNT] =
        std::array::from_fn(|_| None);
    let mut stats = LifecycleFuzzStats::default();
    let mut overflow_probes = 0usize;

    for operation in data.chunks(3).take(MAX_OPERATIONS) {
        let opcode = operation.first().copied().unwrap_or(0) % 17;
        let index = operation.get(1).copied().unwrap_or(0) as usize % ZONE_COUNT;
        let serial = u32::from(operation.get(2).copied().unwrap_or(0)).saturating_add(1);
        modeled_now = runtime_deadline(
            modeled_now,
            Duration::from_millis(u64::from(operation.get(2).copied().unwrap_or(0) % 5) * 750),
        );
        let modeled_unix_secs = 1_700_000_000u64.saturating_add(
            modeled_now
                .saturating_duration_since(modeled_start)
                .as_secs(),
        );
        let origin = &zones[index];
        match opcode {
            0 => {
                transfer_plan.insert(templates[index].clone());
                store.insert_loading(origin.clone());
                registry.record_loading_start_at(origin, modeled_now);
                desired[index] = true;
            }
            1 => {
                transfer_plan.remove(origin);
                registry.remove_zone(origin);
                notify_tracker.remove_zone(origin);
                store.remove_zone(origin);
                desired[index] = false;
            }
            2 if desired[index] => {
                transfer_plan.insert(templates[index].clone());
                if let Some(plan) = transfer_plan.get(origin)
                    && let Some(dropped) = enqueue_pending_refresh_request_at(
                        &mut pending,
                        &mut pending_keys,
                        &active_keys,
                        RefreshRequest::new(origin.clone(), None, RefreshReason::Catalog)
                            .with_plan_generation(&plan),
                        modeled_now,
                    )
                {
                    dropped.rollback_notify_dedup_after_queue_drop();
                    stats.overflow_drops = stats.overflow_drops.saturating_add(1);
                    if dropped.incarnation_is_current(&registry, &transfer_plan) {
                        registry.defer_refresh_after_queue_drop_at(
                            &dropped,
                            modeled_now,
                            modeled_unix_secs,
                        );
                    }
                }
            }
            3..=5 if desired[index] => {
                let reason = match opcode {
                    3 => RefreshReason::Catalog,
                    4 => RefreshReason::Notify,
                    _ if serial.is_multiple_of(2) => RefreshReason::Scheduled,
                    _ => RefreshReason::ControlPlane,
                };
                let requested_serial = (reason == RefreshReason::Notify).then_some(serial);
                let request = if reason == RefreshReason::Notify {
                    let mut request = None;
                    let action = notify_tracker.record_after_enqueue_serial_at(
                        origin,
                        requested_serial,
                        modeled_now,
                        |token| {
                            request = Some(
                                RefreshRequest::new(origin.clone(), requested_serial, reason)
                                    .with_notify_dedup_token(token),
                            );
                            Ok::<(), ()>(())
                        },
                    );
                    match action {
                        Ok(NotifyRefreshAction::Signalled) => {
                            stats.notify_signalled = stats.notify_signalled.saturating_add(1);
                            request
                        }
                        Ok(NotifyRefreshAction::Deduplicated) => {
                            stats.notify_deduplicated = stats.notify_deduplicated.saturating_add(1);
                            None
                        }
                        Err(()) => unreachable!("modeled lifecycle enqueue cannot fail"),
                    }
                } else {
                    Some(
                        RefreshRequest::new(origin.clone(), requested_serial, reason)
                            .with_plan_generation(
                                &transfer_plan
                                    .get(origin)
                                    .expect("desired plan remains present"),
                            ),
                    )
                };
                if let Some(request) = request {
                    let was_full = pending.len() >= NOTIFY_REFRESH_QUEUE_CAPACITY;
                    if let Some(dropped) = enqueue_pending_refresh_request_at(
                        &mut pending,
                        &mut pending_keys,
                        &active_keys,
                        request,
                        modeled_now,
                    ) {
                        dropped.rollback_notify_dedup_after_queue_drop();
                        if dropped.incarnation_is_current(&registry, &transfer_plan) {
                            registry.defer_refresh_after_queue_drop_at(
                                &dropped,
                                modeled_now,
                                modeled_unix_secs,
                            );
                        }
                    } else if stats.recovered_after_overflow && !was_full {
                        stats.admissions_after_recovery =
                            stats.admissions_after_recovery.saturating_add(1);
                    }
                }
            }
            6 => {
                let mut processed_modeled_request = false;
                if attempts[index].is_none()
                    && let Some(position) = pending
                        .iter()
                        .position(|request| request.zone.canonical_key() == origin.canonical_key())
                    && let Some(request) = pending.remove(position)
                {
                    processed_modeled_request = true;
                    pending_keys.remove(&request.zone.canonical_key());
                    if let Some(plan) = validated_refresh_plan(&request, &registry, &transfer_plan)
                        && let Some(attempt) = runtime.block_on(begin_validated_refresh_attempt(
                            &request,
                            &registry,
                            &transfer_plan,
                            &plan,
                        ))
                    {
                        active_keys.insert(origin.canonical_key());
                        attempts[index] = Some((attempt, Some(plan)));
                    } else {
                        stats.stale_pending_incarnation_drops =
                            stats.stale_pending_incarnation_drops.saturating_add(1);
                    }
                }
                if !processed_modeled_request {
                    for _ in 0..64 {
                        let Some(position) = pending.iter().position(|request| {
                            request.zone.canonical_key().starts_with("filler-")
                        }) else {
                            break;
                        };
                        let filler = pending
                            .remove(position)
                            .expect("located lifecycle filler remains queued");
                        pending_keys.remove(&filler.zone.canonical_key());
                        stats.filler_drains = stats.filler_drains.saturating_add(1);
                    }
                    if stats.overflow_drops > 0 && pending.len() < NOTIFY_REFRESH_QUEUE_CAPACITY {
                        stats.recovered_after_overflow = true;
                    }
                }
            }
            7 => {
                if let Some((mut attempt, plan)) = attempts[index].take() {
                    let snapshot = Arc::new(ZoneSnapshot::active(
                        origin.clone(),
                        Some(serial),
                        vec![Rrset::new(
                            origin.clone(),
                            RecordType::Soa as u16,
                            1,
                            3600,
                            vec![lifecycle_soa_rdata(serial)],
                        )],
                    ));
                    if let Some(plan) = plan {
                        let published = transfer_plan.if_current_plan(&plan, || {
                            store.insert_snapshot_arc_for_transfer(snapshot)
                        });
                        if let Some(Ok(metadata)) = published
                            && transfer_plan.is_current_plan(&plan)
                            && attempt.record_success_at(&metadata, modeled_now, modeled_unix_secs)
                            && stats.recovered_after_overflow
                        {
                            stats.completions_after_recovery =
                                stats.completions_after_recovery.saturating_add(1);
                        }
                    }
                    attempt.finish();
                    active_keys.remove(&origin.canonical_key());
                }
            }
            8 => {
                if let Some((attempt, plan)) = attempts[index].take() {
                    if plan
                        .as_ref()
                        .is_some_and(|plan| transfer_plan.is_current_plan(plan))
                    {
                        attempt.record_failure_at(
                            store.exact_zone_control_metadata(origin),
                            Some("fuzzed failure".to_owned()),
                            modeled_now,
                            modeled_unix_secs,
                        );
                    } else {
                        attempt.discard_obsolete();
                    }
                    active_keys.remove(&origin.canonical_key());
                }
            }
            9 => {
                if let Some((attempt, _)) = attempts[index].take() {
                    attempt.interrupt_at(modeled_now, modeled_unix_secs);
                }
                active_keys.remove(&origin.canonical_key());
            }
            10 => {
                // Filling the real 1,024-entry queue is intentionally expensive.
                // Repeating that operation adds no new state-machine coverage and
                // let libFuzzer synthesize multi-second units during the first long
                // campaign. Keep enough probes to cover full, partially drained,
                // and refilled states without rewarding unbounded repetition.
                if overflow_probes < MAX_OVERFLOW_PROBES {
                    overflow_probes += 1;
                    let missing = NOTIFY_REFRESH_QUEUE_CAPACITY.saturating_sub(pending.len());
                    for filler in 0..missing {
                        let filler = DomainName::from_absolute_str(&format!(
                            "filler-{filler}.lifecycle-fuzz."
                        ))
                        .expect("generated filler name is valid");
                        let _ = enqueue_pending_refresh_request_at(
                            &mut pending,
                            &mut pending_keys,
                            &active_keys,
                            RefreshRequest::new(filler, Some(1), RefreshReason::Notify),
                            modeled_now,
                        );
                    }
                    let overflow_plan = transfer_plan.get(origin);
                    if let Some(plan) = overflow_plan
                        && let Some(dropped) = enqueue_pending_refresh_request_at(
                            &mut pending,
                            &mut pending_keys,
                            &active_keys,
                            RefreshRequest::new(origin.clone(), None, RefreshReason::Catalog)
                                .with_plan_generation(&plan),
                            modeled_now,
                        )
                    {
                        dropped.rollback_notify_dedup_after_queue_drop();
                        stats.overflow_drops = stats.overflow_drops.saturating_add(1);
                        if dropped.incarnation_is_current(&registry, &transfer_plan) {
                            registry.defer_refresh_after_queue_drop_at(
                                &dropped,
                                modeled_now,
                                modeled_unix_secs,
                            );
                        }
                    }
                }
            }
            11 => {
                let _ = registry.expire_due_zones(
                    &store,
                    runtime_deadline(modeled_now, Duration::from_secs(u32::MAX as u64)),
                );
            }
            12 => {
                for due in registry.start_due_refreshes(modeled_now) {
                    let was_full = pending.len() >= NOTIFY_REFRESH_QUEUE_CAPACITY;
                    let Some(plan) = transfer_plan.get(&due) else {
                        registry.cancel_in_progress(&due);
                        continue;
                    };
                    if let Some(dropped) = enqueue_pending_refresh_request_at(
                        &mut pending,
                        &mut pending_keys,
                        &active_keys,
                        RefreshRequest::new(due.clone(), None, RefreshReason::Scheduled)
                            .with_plan_generation(&plan),
                        modeled_now,
                    ) {
                        dropped.rollback_notify_dedup_after_queue_drop();
                        stats.scheduled_overflow_drops =
                            stats.scheduled_overflow_drops.saturating_add(1);
                        if dropped.incarnation_is_current(&registry, &transfer_plan) {
                            registry.defer_refresh_after_queue_drop_at(
                                &dropped,
                                modeled_now,
                                modeled_unix_secs,
                            );
                        }
                    } else {
                        stats.scheduled_admissions = stats.scheduled_admissions.saturating_add(1);
                        if stats.recovered_after_overflow && !was_full {
                            stats.scheduled_admissions_after_recovery =
                                stats.scheduled_admissions_after_recovery.saturating_add(1);
                        }
                    }
                }
            }
            13 => {
                if let Some((attempt, _)) = attempts[index].take() {
                    attempt.finish();
                    active_keys.remove(&origin.canonical_key());
                }
            }
            14 => {
                transfer_plan.remove(origin);
                registry.remove_zone(origin);
                notify_tracker.remove_zone(origin);
                store.remove_zone(origin);
                transfer_plan.insert(templates[index].clone());
                store.insert_loading(origin.clone());
                registry.record_loading_start_at(origin, modeled_now);
                desired[index] = true;
            }
            15 => {
                for request in pending.drain(..) {
                    stats.shutdown_drops = stats.shutdown_drops.saturating_add(1);
                    request.rollback_notify_dedup_after_queue_drop();
                    if request.incarnation_is_current(&registry, &transfer_plan) {
                        registry.defer_refresh_after_queue_drop_at(
                            &request,
                            modeled_now,
                            modeled_unix_secs,
                        );
                    }
                }
                pending_keys.clear();
                for attempt in &mut attempts {
                    if let Some((attempt, _)) = attempt.take() {
                        attempt.interrupt_at(modeled_now, modeled_unix_secs);
                    }
                }
                active_keys.clear();
            }
            _ => {
                if let Some(plan) = transfer_plan.get(origin)
                    && let Some(current) = store.exact_snapshot_with_serial_for_transfer(origin)
                {
                    // An EXPIRED transfer view carries a synthesized control
                    // snapshot whose state matches the directory. It is not the
                    // installed ACTIVE snapshot that activation deliberately
                    // retains, so pointer identity is meaningful only when the
                    // captured view was already ACTIVE.
                    let retained_active = (current.metadata().state == ZoneState::Active)
                        .then(|| current.snapshot_arc_for_transfer().clone());
                    if current.metadata().state == ZoneState::Active {
                        assert!(store.expire_zone_if_snapshot(&current));
                    }
                    let expired = store
                        .exact_snapshot_with_serial_for_transfer(origin)
                        .expect("expired serial snapshot remains retained");
                    if let Ok(metadata) =
                        confirm_current_zone(&store, &transfer_plan, &plan, &expired)
                    {
                        stats.reactivations = stats.reactivations.saturating_add(1);
                        assert_eq!(metadata.state, ZoneState::Active);
                        let reactivated = store
                            .exact_snapshot_with_serial_for_transfer(origin)
                            .expect("current confirmation reactivates retained snapshot");
                        assert_eq!(reactivated.metadata().serial, expired.metadata().serial);
                        if let Some(retained) = retained_active {
                            assert!(Arc::ptr_eq(
                                &retained,
                                reactivated.snapshot_arc_for_transfer()
                            ));
                        }
                    }
                }
            }
        }

        assert!(pending.len() <= NOTIFY_REFRESH_QUEUE_CAPACITY);
        assert_eq!(pending.len(), pending_keys.len());
        let retained_notify_tokens = pending
            .iter()
            .map(RefreshRequest::retained_notify_dedup_token_count)
            .sum::<usize>();
        assert!(retained_notify_tokens <= pending.len());
        for request in &pending {
            assert!(pending_keys.contains(&request.zone.canonical_key()));
        }
        let notify_keys = notify_tracker
            .last_signal_by_zone
            .lock()
            .expect("NOTIFY refresh tracker lock poisoned")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert!(notify_keys.len() <= desired.iter().filter(|desired| **desired).count());
        for notify_key in notify_keys {
            assert!(zones.iter().enumerate().any(|(zone_index, zone)| {
                desired[zone_index] && zone.canonical_key() == notify_key
            }));
        }
        let statuses = registry.snapshots_by_zone();
        for (zone_index, zone) in zones.iter().enumerate() {
            if desired[zone_index] {
                assert!(transfer_plan.get(zone).is_some());
                assert!(store.contains_exact_zone_for_control(zone));
                assert!(statuses.contains_key(&zone.canonical_key()));
            } else {
                assert!(transfer_plan.get(zone).is_none());
                assert!(!store.contains_exact_zone_for_control(zone));
                assert!(!statuses.contains_key(&zone.canonical_key()));
            }
        }
    }
    stats
}

/// Exercise the real refresh registry, transfer-plan generations, bounded
/// request coalescing, and stale-attempt completion with a compact operation
/// stream. This API exists only for the out-of-tree cargo-fuzz harness.
#[cfg(feature = "fuzzing")]
pub fn fuzz_lifecycle_sequence(data: &[u8]) {
    let _ = run_lifecycle_fuzz_sequence(data);
}

#[cfg(test)]
mod tests;
