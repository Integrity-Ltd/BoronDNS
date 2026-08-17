static TEST_PATH_COUNTER: AtomicUsize = AtomicUsize::new(0);

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use borondns_core::{
    ServerConfig,
    axfr::{IxfrResponse, frame_tcp_message as try_frame_tcp_message},
    config::{
        ConfigSecretString, DEFAULT_HEALTH_MAX_CONNECTIONS, HealthConfig,
        LatencyHistogramBucketSeconds, MAX_LATENCY_HISTOGRAM_BUCKETS, MAX_RUNTIME_DURATION_SECS,
        MAX_UDP_BATCH_SIZE, MetricsHotPathDetail, ObservabilityConfig, RrlConfig,
        TransferPrimaryConfig, TransferTransportConfig, UdpBackend, UdpRuntime, XdpConfig,
    },
    dns::{
        AnyResponseMode, ChaosQueryOutcome, DnsCookiePolicy, DnsCookieRequestStatus, DomainName,
        ExtendedDnsErrorsMode, Header, LookupMetrics, LookupTermination, Opcode, Rcode, RecordType,
        Transport, ZoneImageServeFailureReason,
    },
    tsig::{
        DEFAULT_TSIG_FUDGE_SECS, TSIG_ERROR_BADKEY, TSIG_ERROR_BADSIG, TSIG_ERROR_BADTIME,
        TsigError, TsigKey,
    },
    zone::{ResourceRecord, Rrset, SoaTimers, ZoneMetadata, ZoneSnapshot, ZoneState, ZoneStore},
};

fn frame_tcp_message(message: &[u8]) -> Vec<u8> {
    try_frame_tcp_message(message).expect("test DNS message fits TCP frame")
}
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    sync::{Notify, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
};
use tokio_rustls::rustls::{RootCertStore, server::WebPkiClientVerifier, version};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use super::observability::{
    MAX_OBSERVABILITY_BEARER_TOKEN_BYTES, ObservabilityAuth, ObservabilityAuthError,
    TransferMaterial, observability_token_len_after_open_for_test,
};
use super::udp::{
    UdpIoErrorAction, bounded_udp_batch_size, classify_udp_recv_error, classify_udp_send_error,
};
use super::zone_persistence::ZonePersistence;
use super::{
    BoundUdpListener, CONTROL_PLANE_OPERATION_LIMIT, CONTROL_PLANE_RESPONSE_LIMIT_BYTES,
    CatalogManager, CatalogRuntime, CatalogRuntimeConfig, ControlPlaneOperation,
    ControlPlaneOperationClient, ControlPlaneOperationCompletionStatus, ControlPlaneOperationKind,
    ControlPlaneTelemetryClient, ControlPlaneTelemetryReporter, CookiePrefixMetricSettings,
    CurrentZoneConfirmationError, DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
    DEFAULT_LATENCY_HISTOGRAM_BUCKETS, DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT,
    DnsCookieRuntimeSettings, DnsCookieSecretStore, HealthEndpointState, InitialLoadSettings,
    IxfrCooldownKey, IxfrCooldownRegistry, LoadingWarning, MetricsRateLimiter,
    NOTIFY_REFRESH_QUEUE_CAPACITY, NotifyAuthority, NotifyLogLimiter, NotifyLogSummary,
    NotifyRefreshAction, NotifyRefreshTracker, NotifyTsigResult, PacketIo, PacketIoSendError,
    PolledControlPlaneOperation, PreparedDnsMessage, QueryLatencyCategory, QueryLatencyHistogram,
    QueryMetricObservation, QueryObservationOptions, QueryPipelineStage,
    RUNTIME_REGISTRY_PRUNE_INTERVAL, RefreshAdmission, RefreshAttemptContext, RefreshReason,
    RefreshRequest, RefreshWorkerSettings, ResponseCacheCandidateCategory,
    ResponseCacheIneligibleReason, ResponseTsig, RrlCategory, RrlDecision, RrlLimiter, RrlSummary,
    Runtime, RuntimeError, RuntimeMetrics, RuntimeStatus, SecretManager, StdUdpBatchIo,
    TcpAcceptErrorAction, TcpServerSettings, TransferError, TransferIngestBudget,
    TransferIngestBudgetSnapshot, TransferIngestTracker, TransferPlan, TransferSession,
    TransferTsig, UdpInbound, UdpOutbound, UdpPacketTarget, UdpServerSettings, ZoneRefreshRegistry,
    acquire_transfer_permit_for_current_plan, begin_validated_refresh_attempt, bind_udp_listeners,
    classify_tcp_accept_error, confirm_current_zone_with_secret, control_plane_http_client,
    dns_cookie_secret_fingerprint, dns_cookie_secret_store_from_config, drain_task_set,
    drain_tcp_connections, enqueue_pending_refresh_request, execute_control_plane_operation,
    handle_runtime_task_result, handle_tcp_connection, handle_tcp_connection_until,
    handle_tcp_connection_with_query_hook, handle_udp_datagram_with_prepared_hook, jitter_interval,
    load_pem_certs, load_pem_private_key_from_file as load_pem_private_key, log_loading_warning,
    log_notify_log_summary, log_rrl_summary, metrics_body, observe_query_metrics,
    parse_control_plane_operation, poll_soa_from_primary, poll_soa_from_primary_with_tsig,
    prepare_notify_packet, prepare_notify_packet_with_metrics, prepare_query_tsig_packet,
    query_id_from_random_bytes, read_tcp_frame_admission, read_tcp_message_after_first_len_byte,
    record_ixfr_current_confirmation, record_query_lookup_metrics, record_query_response_metric,
    record_success_if_current_plan, refresh_zone_from_primaries_with_outcome,
    refresh_zone_metadata_from_primaries, refresh_zone_metadata_from_primaries_preferring,
    required_file_descriptor_limit, resolve_plan_tsig_key, resolve_transfer_credentials_with_hook,
    resolve_transfer_primary, response_category, response_opt_record, response_question_end,
    response_rcode, retire_refresh_transfer_task, rotate_transfer_targets, rrl_truncated_response,
    run_initial_zone_loads, run_lifecycle_fuzz_sequence, runtime_config_warnings_at,
    runtime_config_warnings_with_secrets_at, runtime_deadline,
    runtime_deadline_with_effective_duration, send_std_udp_batch, serial_after,
    serve_bound_udp_until, serve_health, serve_health_with_connection_timeouts,
    serve_health_with_request_read_timeout, serve_refresh_requests, serve_runtime_registry_cleanup,
    serve_scheduled_refreshes, serve_tcp, serve_udp, serve_udp_packet_io_until, sign_tsig_response,
    sign_udp_tsig_response, signal_notify_refresh, transfer_axfr_from_primary,
    transfer_ixfr_from_primary, transfer_query_id, uniform_index_from_u64,
    validate_file_descriptor_limit_value, validate_runtime_config, validated_refresh_plan,
    write_tcp_message,
};

include!("tests/catalog_and_plan.rs");
include!("tests/health_observability_runtime.rs");
include!("tests/notify_tsig_shutdown.rs");
include!("tests/transfer_protocol.rs");
include!("tests/control_plane.rs");
include!("tests/metrics_rrl_udp.rs");
include!("tests/refresh_xot_runtime.rs");
include!("tests/secret_store.rs");
include!("tests/tcp.rs");
include!("tests/support.rs");
