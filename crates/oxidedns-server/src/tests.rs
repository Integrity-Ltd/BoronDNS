static TEST_PATH_COUNTER: AtomicUsize = AtomicUsize::new(0);

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use oxidedns_core::{
    ServerConfig,
    axfr::{IxfrResponse, frame_tcp_message},
    config::{
        HealthConfig, MetricsHotPathDetail, ObservabilityConfig, RrlConfig, TransferPrimaryConfig,
        TransferTransportConfig, UdpBackend, XdpConfig,
    },
    dns::{
        AnyResponseMode, ChaosQueryOutcome, DnsCookiePolicy, DnsCookieRequestStatus, DomainName,
        ExtendedDnsErrorsMode, Header, LookupMetrics, LookupTermination, Opcode, Rcode, RecordType,
        Transport, ZoneImageServeFailureReason,
    },
    tsig::{
        DEFAULT_TSIG_FUDGE_SECS, TSIG_ERROR_BADALG, TSIG_ERROR_BADKEY, TSIG_ERROR_BADSIG,
        TSIG_ERROR_BADTIME, TSIG_ERROR_BADTRUNC, TsigError, TsigKey,
    },
    zone::{ResourceRecord, Rrset, SoaTimers, ZoneMetadata, ZoneSnapshot, ZoneState, ZoneStore},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
};
use tokio_rustls::rustls::{RootCertStore, server::WebPkiClientVerifier, version};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use super::observability::{ObservabilityAuth, TransferMaterial};
use super::{
    BoundUdpListener, CatalogManager, CatalogRuntime, CatalogRuntimeConfig, ControlPlaneOperation,
    ControlPlaneOperationClient, ControlPlaneOperationCompletionStatus, ControlPlaneOperationKind,
    ControlPlaneTelemetryReporter, CookiePrefixMetricSettings, DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
    DEFAULT_LATENCY_HISTOGRAM_BUCKETS, DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT,
    DnsCookieRuntimeSettings, DnsCookieSecretStore, HealthEndpointState, IxfrCooldownRegistry,
    LoadingWarning, MetricsRateLimiter, NotifyAuthority, NotifyLogLimiter, NotifyLogSummary,
    NotifyRefreshAction, NotifyRefreshTracker, NotifyTsigResult, PacketIo, PreparedDnsMessage,
    QueryLatencyCategory, QueryLatencyHistogram, QueryMetricObservation, QueryObservationOptions,
    QueryPipelineStage, RefreshAttemptContext, RefreshReason, RefreshRequest,
    RefreshWorkerSettings, ResponseCacheCandidateCategory, ResponseCacheIneligibleReason,
    RrlCategory, RrlDecision, RrlLimiter, RrlSummary, Runtime, RuntimeError, RuntimeMetrics,
    RuntimeStatus, SecretManager, StdUdpBatchIo, TcpAcceptErrorAction, TcpServerSettings,
    TransferError, TransferIngestTracker, TransferPlan, TransferSession, TransferTsig, UdpRuntime,
    UdpServerSettings, ZoneRefreshRegistry, bind_udp_listeners, classify_tcp_accept_error,
    dns_cookie_secret_fingerprint, dns_cookie_secret_store_from_config, drain_task_set,
    drain_tcp_connections, execute_control_plane_operation, handle_tcp_connection,
    handle_tcp_connection_with_query_hook, jitter_interval, load_pem_certs,
    load_pem_private_key_from_file as load_pem_private_key, log_loading_warning,
    log_notify_log_summary, log_rrl_summary, metrics_body, observe_query_metrics,
    parse_control_plane_operation, poll_soa_from_primary, poll_soa_from_primary_with_tsig,
    prepare_notify_packet, prepare_notify_packet_with_metrics, prepare_query_tsig_packet,
    query_id_from_random_bytes, record_query_lookup_metrics, record_query_response_metric,
    refresh_zone_metadata_from_primaries, required_file_descriptor_limit, resolve_plan_tsig_key,
    resolve_transfer_primary, response_category, response_opt_record, response_question_end,
    response_rcode, rotate_transfer_targets, rrl_truncated_response, runtime_config_warnings_at,
    serial_after, serve_health, serve_refresh_requests, serve_scheduled_refreshes, serve_tcp,
    serve_udp, sign_tsig_response, signal_notify_refresh, transfer_axfr_from_primary,
    transfer_ixfr_from_primary, transfer_query_id, uniform_index_from_u64,
    validate_file_descriptor_limit_value, validate_runtime_config, write_tcp_message,
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
