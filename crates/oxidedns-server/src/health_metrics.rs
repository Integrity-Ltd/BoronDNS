use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io::Write,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use flate2::{Compression, write::GzEncoder};
use oxidedns_core::{
    config::{HealthConfig, MetricsHotPathDetail},
    dns::{ChaosQueryOutcome, DnsCookieRequestStatus, ZoneImageServeFailureReason},
    zone::{ZoneShapeHistogramBucket, ZoneState, ZoneStore},
};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::{
    BUILD_COMMIT, BUILD_RUST_VERSION, BUILD_TIMESTAMP, BUILD_VERSION, CatalogManager,
    CookiePrefixMetricSettings, IpPrefix, NotifyRefreshAction, NotifyTsigResult, RuntimeError,
    RuntimeStatus, RuntimeStatusValue, ZoneRefreshRegistry, cookie_metric_prefix, std_udp_mmsg,
};

pub(crate) async fn serve_health(
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

pub(crate) fn metrics_body(
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
    append_udp_packet_io_metrics(&mut body, snapshot);
    append_udp_mmsg_metrics(&mut body, metrics);
    append_udp_worker_packet_io_metrics(&mut body, metrics);
    append_query_rcode_metrics(&mut body, metrics);
    append_query_latency_metrics(&mut body, metrics);
    append_query_pipeline_latency_metrics(&mut body, metrics);
    append_response_cache_candidate_metrics(&mut body, metrics);
    append_dns_cookie_metrics(&mut body, snapshot);
    append_dns_cookie_prefix_metrics(&mut body, metrics);
    append_configuration_warning_metrics(&mut body, snapshot);
    append_dnssec_metrics(&mut body, snapshot);
    append_zone_image_serve_metrics(&mut body, snapshot);
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

fn append_udp_packet_io_metrics(body: &mut String, snapshot: RuntimeMetricsSnapshot) {
    body.push_str(
        "# HELP oxidedns_udp_receive_batches_total UDP receive batches processed by the standard socket listener.\n\
         # TYPE oxidedns_udp_receive_batches_total counter\n\
         # HELP oxidedns_udp_received_datagrams_total UDP datagrams received by the standard socket listener.\n\
         # TYPE oxidedns_udp_received_datagrams_total counter\n\
         # HELP oxidedns_udp_send_batches_total UDP send batches emitted by the standard socket listener.\n\
         # TYPE oxidedns_udp_send_batches_total counter\n\
         # HELP oxidedns_udp_sent_datagrams_total UDP datagrams sent by the standard socket listener.\n\
         # TYPE oxidedns_udp_sent_datagrams_total counter\n",
    );
    body.push_str(&format!(
        "oxidedns_udp_receive_batches_total {}\n\
         oxidedns_udp_received_datagrams_total {}\n\
         oxidedns_udp_send_batches_total {}\n\
         oxidedns_udp_sent_datagrams_total {}\n",
        snapshot.udp_receive_batches,
        snapshot.udp_received_datagrams,
        snapshot.udp_send_batches,
        snapshot.udp_sent_datagrams,
    ));
}

fn append_udp_mmsg_metrics(body: &mut String, metrics: &RuntimeMetrics) {
    body.push_str(
        "# HELP oxidedns_udp_mmsg_receive_syscalls_total Linux recvmmsg syscalls issued by dedicated UDP workers.\n\
         # TYPE oxidedns_udp_mmsg_receive_syscalls_total counter\n\
         # HELP oxidedns_udp_mmsg_received_datagrams_total UDP datagrams returned by Linux recvmmsg dedicated-worker calls.\n\
         # TYPE oxidedns_udp_mmsg_received_datagrams_total counter\n\
         # HELP oxidedns_udp_mmsg_send_syscalls_total Linux sendmmsg syscalls issued by dedicated UDP workers.\n\
         # TYPE oxidedns_udp_mmsg_send_syscalls_total counter\n\
         # HELP oxidedns_udp_mmsg_sent_datagrams_total UDP datagrams accepted by Linux sendmmsg dedicated-worker calls.\n\
         # TYPE oxidedns_udp_mmsg_sent_datagrams_total counter\n\
         # HELP oxidedns_udp_mmsg_send_partial_syscalls_total Linux sendmmsg calls that accepted fewer datagrams than requested.\n\
         # TYPE oxidedns_udp_mmsg_send_partial_syscalls_total counter\n\
         # HELP oxidedns_udp_mmsg_send_wouldblock_retries_total Dedicated UDP worker sendmmsg WouldBlock retry attempts.\n\
         # TYPE oxidedns_udp_mmsg_send_wouldblock_retries_total counter\n",
    );
    body.push_str(&format!(
        "oxidedns_udp_mmsg_receive_syscalls_total {}\n\
         oxidedns_udp_mmsg_received_datagrams_total {}\n\
         oxidedns_udp_mmsg_send_syscalls_total {}\n\
         oxidedns_udp_mmsg_sent_datagrams_total {}\n\
         oxidedns_udp_mmsg_send_partial_syscalls_total {}\n\
         oxidedns_udp_mmsg_send_wouldblock_retries_total {}\n",
        metrics
            .inner
            .udp_mmsg_receive_syscalls
            .load(Ordering::Relaxed),
        metrics
            .inner
            .udp_mmsg_received_datagrams
            .load(Ordering::Relaxed),
        metrics.inner.udp_mmsg_send_syscalls.load(Ordering::Relaxed),
        metrics
            .inner
            .udp_mmsg_sent_datagrams
            .load(Ordering::Relaxed),
        metrics
            .inner
            .udp_mmsg_send_partial_syscalls
            .load(Ordering::Relaxed),
        metrics
            .inner
            .udp_mmsg_send_wouldblock_retries
            .load(Ordering::Relaxed),
    ));
}

fn append_udp_worker_packet_io_metrics(body: &mut String, metrics: &RuntimeMetrics) {
    body.push_str(
        "# HELP oxidedns_udp_worker_receive_batches_total UDP receive batches processed per worker slot.\n\
         # TYPE oxidedns_udp_worker_receive_batches_total counter\n\
         # HELP oxidedns_udp_worker_received_datagrams_total UDP datagrams received per worker slot.\n\
         # TYPE oxidedns_udp_worker_received_datagrams_total counter\n\
         # HELP oxidedns_udp_worker_send_batches_total UDP send batches emitted per worker slot.\n\
         # TYPE oxidedns_udp_worker_send_batches_total counter\n\
         # HELP oxidedns_udp_worker_sent_datagrams_total UDP datagrams sent per worker slot.\n\
         # TYPE oxidedns_udp_worker_sent_datagrams_total counter\n",
    );
    for worker_id in 0..UDP_WORKER_METRIC_SLOTS {
        let receive_batches =
            metrics.inner.udp_worker_receive_batches[worker_id].load(Ordering::Relaxed);
        let received_datagrams =
            metrics.inner.udp_worker_received_datagrams[worker_id].load(Ordering::Relaxed);
        let send_batches = metrics.inner.udp_worker_send_batches[worker_id].load(Ordering::Relaxed);
        let sent_datagrams =
            metrics.inner.udp_worker_sent_datagrams[worker_id].load(Ordering::Relaxed);
        if receive_batches == 0
            && received_datagrams == 0
            && send_batches == 0
            && sent_datagrams == 0
        {
            continue;
        }
        body.push_str(&format!(
            "oxidedns_udp_worker_receive_batches_total{{worker=\"{worker_id}\"}} {receive_batches}\n\
             oxidedns_udp_worker_received_datagrams_total{{worker=\"{worker_id}\"}} {received_datagrams}\n\
             oxidedns_udp_worker_send_batches_total{{worker=\"{worker_id}\"}} {send_batches}\n\
             oxidedns_udp_worker_sent_datagrams_total{{worker=\"{worker_id}\"}} {sent_datagrams}\n",
        ));
    }
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

fn append_zone_image_serve_metrics(body: &mut String, snapshot: RuntimeMetricsSnapshot) {
    body.push_str(
        "# HELP oxidedns_zone_image_serve_hits_total Query responses served by the immutable zone image path.\n\
         # TYPE oxidedns_zone_image_serve_hits_total counter\n\
         # HELP oxidedns_zone_image_serve_direct_hits_total Query responses served by the direct-answer immutable zone image path.\n\
         # TYPE oxidedns_zone_image_serve_direct_hits_total counter\n\
         # HELP oxidedns_zone_image_serve_semantic_hits_total Query responses served by the semantic immutable zone image path.\n\
         # TYPE oxidedns_zone_image_serve_semantic_hits_total counter\n\
         # HELP oxidedns_zone_image_serve_failures_total Queries that could not be answered by the immutable zone image path while zone image serving was enabled.\n\
         # TYPE oxidedns_zone_image_serve_failures_total counter\n\
         # HELP oxidedns_zone_image_serve_failures_by_reason_total Queries that could not be answered by the immutable zone image path by failure reason.\n\
         # TYPE oxidedns_zone_image_serve_failures_by_reason_total counter\n",
    );
    body.push_str(&format!(
        "oxidedns_zone_image_serve_hits_total {}\n\
         oxidedns_zone_image_serve_direct_hits_total {}\n\
         oxidedns_zone_image_serve_semantic_hits_total {}\n\
         oxidedns_zone_image_serve_failures_total {}\n",
        snapshot.zone_image_serve_hits,
        snapshot.zone_image_serve_direct_hits,
        snapshot.zone_image_serve_semantic_hits,
        snapshot.zone_image_serve_failures,
    ));
    for reason in ZoneImageServeFailureReason::ALL {
        body.push_str(&format!(
            "oxidedns_zone_image_serve_failures_by_reason_total{{reason=\"{}\"}} {}\n",
            reason.metric_label(),
            snapshot.zone_image_serve_failure_reasons[reason.metric_index()]
        ));
    }
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
    let zone_metadata = zones.zone_metadata();

    body.push_str(
        "# HELP oxidedns_zone_state Zone state, exposed as 1 for the current state and 0 for other states.\n\
         # TYPE oxidedns_zone_state gauge\n",
    );
    for metadata in &zone_metadata {
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        for (state, value) in zone_state_samples(metadata.state) {
            body.push_str(&format!(
                "oxidedns_zone_state{{zone=\"{zone}\",state=\"{state}\"}} {value}\n"
            ));
        }
    }

    body.push_str(
        "# HELP oxidedns_secondary_zone_state Zone state, exposed as 1 for the current state and 0 for other states.\n\
         # TYPE oxidedns_secondary_zone_state gauge\n",
    );
    for metadata in &zone_metadata {
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        for (state, value) in zone_state_samples(metadata.state) {
            body.push_str(&format!(
                "oxidedns_secondary_zone_state{{zone=\"{zone}\",state=\"{state}\"}} {value}\n"
            ));
        }
    }

    body.push_str(
        "# HELP oxidedns_zone_loading_seconds Seconds the zone has been in LOADING state during this process uptime.\n\
         # TYPE oxidedns_zone_loading_seconds gauge\n",
    );
    for metadata in &zone_metadata {
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        let loading_seconds = zone_loading_seconds(metadata.state, uptime_seconds);
        body.push_str(&format!(
            "oxidedns_zone_loading_seconds{{zone=\"{zone}\"}} {loading_seconds}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_secondary_zone_loading_seconds Seconds the zone has been in LOADING state during this process uptime.\n\
         # TYPE oxidedns_secondary_zone_loading_seconds gauge\n",
    );
    for metadata in &zone_metadata {
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        let loading_seconds = zone_loading_seconds(metadata.state, uptime_seconds);
        body.push_str(&format!(
            "oxidedns_secondary_zone_loading_seconds{{zone=\"{zone}\"}} {loading_seconds}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_zone_soa_serial Current held SOA serial for zones with transferred data.\n\
         # TYPE oxidedns_zone_soa_serial gauge\n",
    );
    for metadata in &zone_metadata {
        if let Some(serial) = metadata.serial {
            let zone = prometheus_label_value(metadata.origin_name.as_ref());
            body.push_str(&format!(
                "oxidedns_zone_soa_serial{{zone=\"{zone}\"}} {serial}\n"
            ));
        }
    }

    body.push_str(
        "# HELP oxidedns_secondary_zone_soa_serial Current held SOA serial for zones with transferred data.\n\
         # TYPE oxidedns_secondary_zone_soa_serial gauge\n",
    );
    for metadata in &zone_metadata {
        if let Some(serial) = metadata.serial {
            let zone = prometheus_label_value(metadata.origin_name.as_ref());
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
         # TYPE oxidedns_zone_shape_name_key_deduplicated_bytes gauge\n\
         # HELP oxidedns_zone_shape_child_name_fanout_names Owner or empty non-terminal names grouped by immediate child-name fan-out.\n\
         # TYPE oxidedns_zone_shape_child_name_fanout_names gauge\n\
         # HELP oxidedns_zone_shape_rrsets_per_owner_names Owner names grouped by RRset count.\n\
         # TYPE oxidedns_zone_shape_rrsets_per_owner_names gauge\n\
         # HELP oxidedns_zone_shape_rdata_records_per_rrset RRsets grouped by RDATA record count.\n\
         # TYPE oxidedns_zone_shape_rdata_records_per_rrset gauge\n\
         # HELP oxidedns_zone_shape_rdata_payload_bytes_per_rrset RRsets grouped by total RDATA payload bytes.\n\
         # TYPE oxidedns_zone_shape_rdata_payload_bytes_per_rrset gauge\n",
    );

    for metadata in zones.zone_metadata() {
        if metadata.state != ZoneState::Active {
            continue;
        }
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        let Some(shape) = metadata.shape else {
            continue;
        };
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

        let Some(histograms) = metadata.shape_histograms.as_ref() else {
            continue;
        };
        append_zone_shape_histogram_metrics(
            body,
            "oxidedns_zone_shape_child_name_fanout_names",
            &zone,
            &histograms.child_name_fanout_names,
        );
        append_zone_shape_histogram_metrics(
            body,
            "oxidedns_zone_shape_rrsets_per_owner_names",
            &zone,
            &histograms.rrsets_per_owner_name,
        );
        append_zone_shape_histogram_metrics(
            body,
            "oxidedns_zone_shape_rdata_records_per_rrset",
            &zone,
            &histograms.rdata_records_per_rrset,
        );
        append_zone_shape_histogram_metrics(
            body,
            "oxidedns_zone_shape_rdata_payload_bytes_per_rrset",
            &zone,
            &histograms.rdata_payload_bytes_per_rrset,
        );
    }
}

fn append_zone_shape_histogram_metrics(
    body: &mut String,
    metric: &str,
    zone: &str,
    buckets: &[ZoneShapeHistogramBucket],
) {
    for bucket in buckets {
        body.push_str(&format!(
            "{metric}{{zone=\"{zone}\",bucket=\"{}\"}} {}\n",
            bucket.bucket, bucket.count
        ));
    }
}

fn append_zone_scheduler_metrics(
    body: &mut String,
    zones: &ZoneStore,
    refresh_registry: &ZoneRefreshRegistry,
) {
    let statuses = refresh_registry.snapshots_by_zone();
    let zone_metadata = zones.zone_metadata();

    body.push_str(
        "# HELP oxidedns_zone_last_success_timestamp_seconds Unix timestamp of the most recent successful refresh or transfer.\n\
         # TYPE oxidedns_zone_last_success_timestamp_seconds gauge\n",
    );
    for metadata in &zone_metadata {
        let Some(status) = statuses.get(metadata.origin_key.as_ref()) else {
            continue;
        };
        let Some(last_success) = status.last_success_unix_secs else {
            continue;
        };
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        body.push_str(&format!(
            "oxidedns_zone_last_success_timestamp_seconds{{zone=\"{zone}\"}} {last_success}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_secondary_zone_last_refresh_seconds Unix timestamp of the most recent successful refresh or transfer.\n\
         # TYPE oxidedns_secondary_zone_last_refresh_seconds gauge\n",
    );
    for metadata in &zone_metadata {
        let Some(status) = statuses.get(metadata.origin_key.as_ref()) else {
            continue;
        };
        let Some(last_success) = status.last_success_unix_secs else {
            continue;
        };
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        body.push_str(&format!(
            "oxidedns_secondary_zone_last_refresh_seconds{{zone=\"{zone}\"}} {last_success}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_zone_next_refresh_timestamp_seconds Unix timestamp of the next scheduled refresh attempt.\n\
         # TYPE oxidedns_zone_next_refresh_timestamp_seconds gauge\n",
    );
    for metadata in &zone_metadata {
        let Some(status) = statuses.get(metadata.origin_key.as_ref()) else {
            continue;
        };
        let Some(next_refresh) = status.next_refresh_unix_secs else {
            continue;
        };
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        body.push_str(&format!(
            "oxidedns_zone_next_refresh_timestamp_seconds{{zone=\"{zone}\"}} {next_refresh}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_secondary_zone_next_refresh_seconds Unix timestamp of the next scheduled refresh attempt.\n\
         # TYPE oxidedns_secondary_zone_next_refresh_seconds gauge\n",
    );
    for metadata in &zone_metadata {
        let Some(status) = statuses.get(metadata.origin_key.as_ref()) else {
            continue;
        };
        let Some(next_refresh) = status.next_refresh_unix_secs else {
            continue;
        };
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        body.push_str(&format!(
            "oxidedns_secondary_zone_next_refresh_seconds{{zone=\"{zone}\"}} {next_refresh}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_zone_refresh_failures_since_success Refresh failures since the most recent successful refresh or transfer.\n\
         # TYPE oxidedns_zone_refresh_failures_since_success gauge\n",
    );
    for metadata in &zone_metadata {
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        let failures = statuses
            .get(metadata.origin_key.as_ref())
            .map_or(0, |status| status.failures_since_success);
        body.push_str(&format!(
            "oxidedns_zone_refresh_failures_since_success{{zone=\"{zone}\"}} {failures}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_secondary_zone_refresh_failures Refresh failures since the most recent successful refresh or transfer.\n\
         # TYPE oxidedns_secondary_zone_refresh_failures gauge\n",
    );
    for metadata in &zone_metadata {
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        let failures = statuses
            .get(metadata.origin_key.as_ref())
            .map_or(0, |status| status.failures_since_success);
        body.push_str(&format!(
            "oxidedns_secondary_zone_refresh_failures{{zone=\"{zone}\"}} {failures}\n"
        ));
    }
}

fn append_zone_query_metrics(body: &mut String, zones: &ZoneStore, metrics: &RuntimeMetrics) {
    let query_counts = metrics.zone_query_counts();
    let rcode_counts = metrics.zone_query_rcode_counts();
    let zone_metadata = zones.zone_metadata();
    body.push_str(
        "# HELP oxidedns_zone_queries_total Queries received for each configured zone.\n\
         # TYPE oxidedns_zone_queries_total counter\n",
    );
    for metadata in &zone_metadata {
        let zone_key = metadata.origin_key.as_ref();
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        let count = query_counts.get(zone_key).copied().unwrap_or_default();
        body.push_str(&format!(
            "oxidedns_zone_queries_total{{zone=\"{zone}\"}} {count}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_secondary_queries_total Queries received for each configured zone.\n\
         # TYPE oxidedns_secondary_queries_total counter\n",
    );
    for metadata in &zone_metadata {
        let zone_key = metadata.origin_key.as_ref();
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        let count = query_counts.get(zone_key).copied().unwrap_or_default();
        body.push_str(&format!(
            "oxidedns_secondary_queries_total{{zone=\"{zone}\"}} {count}\n"
        ));
    }

    body.push_str(
        "# HELP oxidedns_zone_query_responses_total Query responses by configured zone and DNS RCODE.\n\
         # TYPE oxidedns_zone_query_responses_total counter\n",
    );
    for metadata in &zone_metadata {
        let zone_key = metadata.origin_key.as_ref();
        let zone = prometheus_label_value(metadata.origin_name.as_ref());
        append_zone_rcode_metrics(
            body,
            "oxidedns_zone_query_responses_total",
            zone_key,
            &zone,
            &rcode_counts,
        );
        append_zone_rcode_metrics(
            body,
            "oxidedns_secondary_query_responses_total",
            zone_key,
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
        for metadata in zones.zone_metadata() {
            match metadata.state {
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
pub(crate) struct HealthEndpointState {
    pub(crate) zones: ZoneStore,
    pub(crate) runtime_status: RuntimeStatus,
    pub(crate) metrics: RuntimeMetrics,
    pub(crate) catalog_manager: CatalogManager,
    pub(crate) refresh_registry: ZoneRefreshRegistry,
    pub(crate) metrics_rate_limiter: MetricsRateLimiter,
    pub(crate) started_at: Instant,
    pub(crate) graceful_shutdown_secs: u64,
    pub(crate) zone_shape_metrics_enabled: bool,
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
pub(crate) struct MetricsRateLimiter {
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
    pub(crate) fn from_config(config: HealthConfig) -> Self {
        Self {
            limit_per_minute: config.metrics_rate_limit_per_minute,
            idle_timeout: Duration::from_secs(config.metrics_rate_limit_idle_seconds),
            inner: Arc::new(Mutex::new(MetricsRateLimitState::default())),
        }
    }

    pub(crate) fn check(&self, source: IpAddr) -> Result<(), u64> {
        self.check_at(source, Instant::now())
    }

    pub(crate) fn check_at(&self, source: IpAddr, now: Instant) -> Result<(), u64> {
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
pub(crate) struct RuntimeMetrics {
    inner: Arc<RuntimeMetricsInner>,
}

pub(crate) const DEFAULT_COOKIE_PREFIX_METRIC_LIMIT: usize = 100_000;
const UDP_WORKER_METRIC_SLOTS: usize = 32;
#[cfg(test)]
pub(crate) const DEFAULT_LATENCY_HISTOGRAM_BUCKETS: [f64; 9] = [
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.1,
];

#[derive(Debug, Default)]
struct RuntimeMetricsInner {
    pub(crate) queries_received: AtomicU64,
    pub(crate) queries_truncated: AtomicU64,
    pub(crate) queries_cname_chain_limit: AtomicU64,
    pub(crate) queries_cname_loop: AtomicU64,
    pub(crate) udp_receive_batches: AtomicU64,
    pub(crate) udp_received_datagrams: AtomicU64,
    pub(crate) udp_send_batches: AtomicU64,
    pub(crate) udp_sent_datagrams: AtomicU64,
    udp_mmsg_receive_syscalls: AtomicU64,
    udp_mmsg_received_datagrams: AtomicU64,
    udp_mmsg_send_syscalls: AtomicU64,
    udp_mmsg_sent_datagrams: AtomicU64,
    udp_mmsg_send_partial_syscalls: AtomicU64,
    udp_mmsg_send_wouldblock_retries: AtomicU64,
    udp_worker_receive_batches: [AtomicU64; UDP_WORKER_METRIC_SLOTS],
    udp_worker_received_datagrams: [AtomicU64; UDP_WORKER_METRIC_SLOTS],
    udp_worker_send_batches: [AtomicU64; UDP_WORKER_METRIC_SLOTS],
    udp_worker_sent_datagrams: [AtomicU64; UDP_WORKER_METRIC_SLOTS],
    pub(crate) axfr_started: AtomicU64,
    pub(crate) axfr_succeeded: AtomicU64,
    pub(crate) axfr_failed: AtomicU64,
    pub(crate) ixfr_started: AtomicU64,
    pub(crate) ixfr_succeeded: AtomicU64,
    pub(crate) ixfr_failed: AtomicU64,
    pub(crate) notify_received: AtomicU64,
    pub(crate) notify_unauthorized: AtomicU64,
    pub(crate) notify_refresh_signalled: AtomicU64,
    pub(crate) notify_refresh_deduplicated: AtomicU64,
    pub(crate) notify_tsig_ok: AtomicU64,
    pub(crate) notify_tsig_badkey: AtomicU64,
    pub(crate) notify_tsig_badsig: AtomicU64,
    pub(crate) notify_tsig_badtime: AtomicU64,
    pub(crate) notify_tsig_badalg: AtomicU64,
    pub(crate) notify_tsig_badtrunc: AtomicU64,
    pub(crate) rrl_subject: AtomicU64,
    pub(crate) rrl_dropped: AtomicU64,
    pub(crate) rrl_truncated: AtomicU64,
    pub(crate) rrl_tracked_keys: AtomicU64,
    pub(crate) rrl_key_evictions: AtomicU64,
    pub(crate) dns_cookie_no_cookie: AtomicU64,
    pub(crate) dns_cookie_client_only: AtomicU64,
    pub(crate) dns_cookie_valid_server: AtomicU64,
    pub(crate) dns_cookie_invalid_server: AtomicU64,
    pub(crate) dns_cookie_badcookie: AtomicU64,
    pub(crate) configuration_warnings: AtomicU64,
    pub(crate) nsec3_iterations_exceed_cap: AtomicU64,
    pub(crate) zone_image_serve_hits: AtomicU64,
    pub(crate) zone_image_serve_direct_hits: AtomicU64,
    pub(crate) zone_image_serve_semantic_hits: AtomicU64,
    pub(crate) zone_image_serve_failures: AtomicU64,
    pub(crate) zone_image_serve_failure_reasons: [AtomicU64; ZoneImageServeFailureReason::COUNT],
    pub(crate) chaos_answered: AtomicU64,
    pub(crate) chaos_missing_value: AtomicU64,
    pub(crate) chaos_unrecognized_name: AtomicU64,
    pub(crate) chaos_non_txt: AtomicU64,
    dns_cookie_prefixes: Mutex<CookiePrefixMetrics>,
    query_rcodes: Mutex<HashMap<u16, u64>>,
    zone_queries: Mutex<HashMap<String, u64>>,
    zone_query_rcodes: Mutex<HashMap<(String, u16), u64>>,
    latency_buckets: Vec<f64>,
    query_latency: Mutex<HashMap<QueryLatencyCategory, QueryLatencyHistogram>>,
    pipeline_timing_enabled: bool,
    hot_path_detail: MetricsHotPathDetail,
    query_pipeline_latency: Mutex<HashMap<QueryPipelineKey, QueryLatencyHistogram>>,
    response_cache_candidates: Mutex<HashMap<ResponseCacheCandidateCategory, u64>>,
    response_cache_ineligible: Mutex<HashMap<ResponseCacheIneligibleReason, u64>>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeMetricsSnapshot {
    pub(crate) queries_received: u64,
    pub(crate) queries_truncated: u64,
    pub(crate) queries_cname_chain_limit: u64,
    pub(crate) queries_cname_loop: u64,
    pub(crate) udp_receive_batches: u64,
    pub(crate) udp_received_datagrams: u64,
    pub(crate) udp_send_batches: u64,
    pub(crate) udp_sent_datagrams: u64,
    pub(crate) axfr_started: u64,
    pub(crate) axfr_succeeded: u64,
    pub(crate) axfr_failed: u64,
    pub(crate) ixfr_started: u64,
    pub(crate) ixfr_succeeded: u64,
    pub(crate) ixfr_failed: u64,
    pub(crate) notify_received: u64,
    pub(crate) notify_unauthorized: u64,
    pub(crate) notify_refresh_signalled: u64,
    pub(crate) notify_refresh_deduplicated: u64,
    pub(crate) notify_tsig_ok: u64,
    pub(crate) notify_tsig_badkey: u64,
    pub(crate) notify_tsig_badsig: u64,
    pub(crate) notify_tsig_badtime: u64,
    pub(crate) notify_tsig_badalg: u64,
    pub(crate) notify_tsig_badtrunc: u64,
    pub(crate) rrl_subject: u64,
    pub(crate) rrl_dropped: u64,
    pub(crate) rrl_truncated: u64,
    pub(crate) rrl_tracked_keys: u64,
    pub(crate) rrl_key_evictions: u64,
    pub(crate) dns_cookie_no_cookie: u64,
    pub(crate) dns_cookie_client_only: u64,
    pub(crate) dns_cookie_valid_server: u64,
    pub(crate) dns_cookie_invalid_server: u64,
    pub(crate) dns_cookie_badcookie: u64,
    pub(crate) configuration_warnings: u64,
    pub(crate) nsec3_iterations_exceed_cap: u64,
    pub(crate) zone_image_serve_hits: u64,
    pub(crate) zone_image_serve_direct_hits: u64,
    pub(crate) zone_image_serve_semantic_hits: u64,
    pub(crate) zone_image_serve_failures: u64,
    pub(crate) zone_image_serve_failure_reasons: [u64; ZoneImageServeFailureReason::COUNT],
    pub(crate) chaos_answered: u64,
    pub(crate) chaos_missing_value: u64,
    pub(crate) chaos_unrecognized_name: u64,
    pub(crate) chaos_non_txt: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CookiePrefixCounters {
    pub(crate) no_cookie: u64,
    pub(crate) client_only: u64,
    pub(crate) valid_server: u64,
    pub(crate) invalid_server: u64,
    pub(crate) badcookie: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum QueryLatencyCategory {
    UdpDirect,
    UdpCnameChain,
    TcpDirect,
    TcpCnameChain,
    DnssecAugmented,
    CookieValidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct QueryPipelineKey {
    pub(crate) stage: QueryPipelineStage,
    pub(crate) category: QueryLatencyCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum QueryPipelineStage {
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
pub(crate) enum ResponseCacheCandidateCategory {
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
pub(crate) enum ResponseCacheIneligibleReason {
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
pub(crate) struct QueryLatencyHistogram {
    buckets: Vec<u64>,
    pub(crate) sum_seconds: f64,
}

impl QueryLatencyHistogram {
    pub(crate) fn new(bucket_count: usize) -> Self {
        Self {
            buckets: vec![0; bucket_count + 1],
            sum_seconds: 0.0,
        }
    }

    pub(crate) fn record(&mut self, duration: Duration, latency_buckets: &[f64]) {
        let seconds = duration.as_secs_f64();
        let bucket_index = latency_buckets
            .iter()
            .position(|bucket| seconds <= *bucket)
            .unwrap_or(latency_buckets.len());
        self.buckets[bucket_index] = self.buckets[bucket_index].saturating_add(1);
        self.sum_seconds += seconds;
    }

    pub(crate) fn count(&self) -> u64 {
        self.buckets.iter().copied().sum()
    }
}

#[derive(Debug)]
pub(crate) struct CookiePrefixMetrics {
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

    pub(crate) fn record_status(&mut self, prefix: IpPrefix, status: DnsCookieRequestStatus) {
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

    pub(crate) fn record_badcookie(&mut self, prefix: IpPrefix) {
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
    pub(crate) fn new() -> Self {
        Self::new_with_settings(
            DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
            DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
            false,
            MetricsHotPathDetail::Full,
        )
    }

    pub(crate) fn new_with_settings(
        cookie_prefix_limit: usize,
        latency_buckets: Vec<f64>,
        pipeline_timing_enabled: bool,
        hot_path_detail: MetricsHotPathDetail,
    ) -> Self {
        Self {
            inner: Arc::new(RuntimeMetricsInner {
                dns_cookie_prefixes: Mutex::new(CookiePrefixMetrics::new(cookie_prefix_limit)),
                latency_buckets,
                pipeline_timing_enabled,
                hot_path_detail,
                ..RuntimeMetricsInner::default()
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_reduced_for_test() -> Self {
        Self::new_with_settings(
            DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
            DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
            true,
            MetricsHotPathDetail::Reduced,
        )
    }

    pub(crate) fn record_axfr_started(&self) {
        self.inner.axfr_started.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_axfr_succeeded(&self) {
        self.inner.axfr_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_axfr_failed(&self) {
        self.inner.axfr_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_ixfr_started(&self) {
        self.inner.ixfr_started.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_ixfr_succeeded(&self) {
        self.inner.ixfr_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_ixfr_failed(&self) {
        self.inner.ixfr_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_query_received(&self) {
        self.inner.queries_received.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_query_truncated(&self) {
        self.inner.queries_truncated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_query_cname_chain_limit(&self) {
        self.inner
            .queries_cname_chain_limit
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_query_cname_loop(&self) {
        self.inner
            .queries_cname_loop
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_udp_receive_batch(&self, datagrams: usize) {
        self.inner
            .udp_receive_batches
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .udp_received_datagrams
            .fetch_add(datagrams as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_udp_send_batch(&self, datagrams: usize) {
        self.inner.udp_send_batches.fetch_add(1, Ordering::Relaxed);
        self.inner
            .udp_sent_datagrams
            .fetch_add(datagrams as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_udp_mmsg_stats(&self, stats: std_udp_mmsg::StdUdpMmsgStats) {
        if stats.receive_syscalls != 0 {
            self.inner
                .udp_mmsg_receive_syscalls
                .fetch_add(stats.receive_syscalls, Ordering::Relaxed);
        }
        if stats.received_datagrams != 0 {
            self.inner
                .udp_mmsg_received_datagrams
                .fetch_add(stats.received_datagrams, Ordering::Relaxed);
        }
        if stats.send_syscalls != 0 {
            self.inner
                .udp_mmsg_send_syscalls
                .fetch_add(stats.send_syscalls, Ordering::Relaxed);
        }
        if stats.sent_datagrams != 0 {
            self.inner
                .udp_mmsg_sent_datagrams
                .fetch_add(stats.sent_datagrams, Ordering::Relaxed);
        }
        if stats.send_partial_syscalls != 0 {
            self.inner
                .udp_mmsg_send_partial_syscalls
                .fetch_add(stats.send_partial_syscalls, Ordering::Relaxed);
        }
        if stats.send_wouldblock_retries != 0 {
            self.inner
                .udp_mmsg_send_wouldblock_retries
                .fetch_add(stats.send_wouldblock_retries, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_udp_worker_receive_batch(&self, worker_id: usize, datagrams: usize) {
        if let Some(counter) = self.inner.udp_worker_receive_batches.get(worker_id) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(counter) = self.inner.udp_worker_received_datagrams.get(worker_id) {
            counter.fetch_add(datagrams as u64, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_udp_worker_send_batch(&self, worker_id: usize, datagrams: usize) {
        if let Some(counter) = self.inner.udp_worker_send_batches.get(worker_id) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(counter) = self.inner.udp_worker_sent_datagrams.get(worker_id) {
            counter.fetch_add(datagrams as u64, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_notify_received(&self) {
        self.inner.notify_received.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_notify_unauthorized(&self) {
        self.inner
            .notify_unauthorized
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_notify_refresh_action(&self, action: NotifyRefreshAction) {
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

    pub(crate) fn record_notify_tsig_result(&self, result: NotifyTsigResult) {
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

    pub(crate) fn record_rrl_subject(&self) {
        self.inner.rrl_subject.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_rrl_dropped(&self) {
        self.inner.rrl_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_rrl_truncated(&self) {
        self.inner.rrl_truncated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_rrl_tracked_keys(&self, count: u64) {
        self.inner.rrl_tracked_keys.store(count, Ordering::Relaxed);
    }

    pub(crate) fn record_rrl_key_evicted(&self) {
        self.inner.rrl_key_evictions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dns_cookie_status(
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
        if !self.hot_path_detail_enabled() {
            return;
        }
        self.inner
            .dns_cookie_prefixes
            .lock()
            .expect("runtime metrics DNS Cookie prefix counter lock poisoned")
            .record_status(cookie_metric_prefix(source, prefix_settings), status);
    }

    pub(crate) fn record_dns_cookie_badcookie(&self) {
        self.inner
            .dns_cookie_badcookie
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_configuration_warnings(&self, count: u64) {
        self.inner
            .configuration_warnings
            .store(count, Ordering::Relaxed);
    }

    pub(crate) fn record_nsec3_iterations_exceed_cap(&self) {
        self.inner
            .nsec3_iterations_exceed_cap
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_zone_image_serve_hit(&self) {
        self.inner
            .zone_image_serve_hits
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_zone_image_serve_direct_hit(&self) {
        self.inner
            .zone_image_serve_direct_hits
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_zone_image_serve_semantic_hit(&self) {
        self.inner
            .zone_image_serve_semantic_hits
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_zone_image_serve_failure(&self) {
        self.inner
            .zone_image_serve_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_zone_image_serve_failure_reason(
        &self,
        reason: ZoneImageServeFailureReason,
    ) {
        self.inner.zone_image_serve_failure_reasons[reason.metric_index()]
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_chaos_query(&self, outcome: ChaosQueryOutcome) {
        let counter = match outcome {
            ChaosQueryOutcome::Answered => &self.inner.chaos_answered,
            ChaosQueryOutcome::MissingValue => &self.inner.chaos_missing_value,
            ChaosQueryOutcome::UnrecognizedName => &self.inner.chaos_unrecognized_name,
            ChaosQueryOutcome::NonTxt => &self.inner.chaos_non_txt,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dns_cookie_badcookie_for_source(
        &self,
        source: IpAddr,
        prefix_settings: CookiePrefixMetricSettings,
    ) {
        if !self.hot_path_detail_enabled() {
            return;
        }
        self.inner
            .dns_cookie_prefixes
            .lock()
            .expect("runtime metrics DNS Cookie prefix counter lock poisoned")
            .record_badcookie(cookie_metric_prefix(source, prefix_settings));
    }

    pub(crate) fn dns_cookie_prefix_counts(&self) -> Vec<(IpPrefix, CookiePrefixCounters)> {
        self.inner
            .dns_cookie_prefixes
            .lock()
            .expect("runtime metrics DNS Cookie prefix counter lock poisoned")
            .samples()
    }

    pub(crate) fn record_query_response_rcode(&self, rcode: u16) {
        if !self.hot_path_detail_enabled() {
            return;
        }
        let mut rcodes = self
            .inner
            .query_rcodes
            .lock()
            .expect("runtime metrics RCODE counter lock poisoned");
        let counter = rcodes.entry(rcode).or_default();
        *counter = counter.saturating_add(1);
    }

    pub(crate) fn record_zone_query_response_rcode(&self, zone_key: &str, rcode: u16) {
        if !self.hot_path_detail_enabled() {
            return;
        }
        let mut rcodes = self
            .inner
            .zone_query_rcodes
            .lock()
            .expect("runtime metrics per-zone RCODE counter lock poisoned");
        let counter = rcodes.entry((zone_key.to_owned(), rcode)).or_default();
        *counter = counter.saturating_add(1);
    }

    pub(crate) fn record_query_latency(&self, category: QueryLatencyCategory, duration: Duration) {
        if !self.hot_path_detail_enabled() {
            return;
        }
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

    pub(crate) fn pipeline_timing_enabled(&self) -> bool {
        self.inner.pipeline_timing_enabled && self.hot_path_detail_enabled()
    }

    pub(crate) fn start_pipeline_timer(&self) -> Option<Instant> {
        self.pipeline_timing_enabled().then(Instant::now)
    }

    pub(crate) fn hot_path_detail_enabled(&self) -> bool {
        self.inner.hot_path_detail == MetricsHotPathDetail::Full
    }

    pub(crate) fn record_query_pipeline_latency(
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

    pub(crate) fn record_response_cache_candidate(&self, category: ResponseCacheCandidateCategory) {
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

    pub(crate) fn record_response_cache_ineligible(&self, reason: ResponseCacheIneligibleReason) {
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

    pub(crate) fn query_rcode_counts(&self) -> HashMap<u16, u64> {
        self.inner
            .query_rcodes
            .lock()
            .expect("runtime metrics RCODE counter lock poisoned")
            .clone()
    }

    pub(crate) fn zone_query_rcode_counts(&self) -> HashMap<(String, u16), u64> {
        self.inner
            .zone_query_rcodes
            .lock()
            .expect("runtime metrics per-zone RCODE counter lock poisoned")
            .clone()
    }

    pub(crate) fn query_latency_histograms(
        &self,
    ) -> HashMap<QueryLatencyCategory, QueryLatencyHistogram> {
        self.inner
            .query_latency
            .lock()
            .expect("runtime metrics query latency histogram lock poisoned")
            .clone()
    }

    pub(crate) fn query_pipeline_latency_histograms(
        &self,
    ) -> HashMap<QueryPipelineKey, QueryLatencyHistogram> {
        self.inner
            .query_pipeline_latency
            .lock()
            .expect("runtime metrics query pipeline latency histogram lock poisoned")
            .clone()
    }

    pub(crate) fn response_cache_candidate_counts(
        &self,
    ) -> HashMap<ResponseCacheCandidateCategory, u64> {
        self.inner
            .response_cache_candidates
            .lock()
            .expect("runtime metrics response-cache candidate lock poisoned")
            .clone()
    }

    pub(crate) fn response_cache_ineligible_counts(
        &self,
    ) -> HashMap<ResponseCacheIneligibleReason, u64> {
        self.inner
            .response_cache_ineligible
            .lock()
            .expect("runtime metrics response-cache ineligible lock poisoned")
            .clone()
    }

    pub(crate) fn latency_buckets(&self) -> Vec<f64> {
        self.inner.latency_buckets.clone()
    }

    pub(crate) fn record_zone_query_key(&self, zone_key: &str) {
        if !self.hot_path_detail_enabled() {
            return;
        }
        let mut query_counts = self
            .inner
            .zone_queries
            .lock()
            .expect("runtime metrics query counter lock poisoned");
        if let Some(counter) = query_counts.get_mut(zone_key) {
            *counter = counter.saturating_add(1);
        } else {
            query_counts.insert(zone_key.to_owned(), 1);
        }
    }

    pub(crate) fn zone_query_counts(&self) -> HashMap<String, u64> {
        self.inner
            .zone_queries
            .lock()
            .expect("runtime metrics query counter lock poisoned")
            .clone()
    }

    pub(crate) fn snapshot(&self) -> RuntimeMetricsSnapshot {
        RuntimeMetricsSnapshot {
            queries_received: self.inner.queries_received.load(Ordering::Relaxed),
            queries_truncated: self.inner.queries_truncated.load(Ordering::Relaxed),
            queries_cname_chain_limit: self.inner.queries_cname_chain_limit.load(Ordering::Relaxed),
            queries_cname_loop: self.inner.queries_cname_loop.load(Ordering::Relaxed),
            udp_receive_batches: self.inner.udp_receive_batches.load(Ordering::Relaxed),
            udp_received_datagrams: self.inner.udp_received_datagrams.load(Ordering::Relaxed),
            udp_send_batches: self.inner.udp_send_batches.load(Ordering::Relaxed),
            udp_sent_datagrams: self.inner.udp_sent_datagrams.load(Ordering::Relaxed),
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
            zone_image_serve_hits: self.inner.zone_image_serve_hits.load(Ordering::Relaxed),
            zone_image_serve_direct_hits: self
                .inner
                .zone_image_serve_direct_hits
                .load(Ordering::Relaxed),
            zone_image_serve_semantic_hits: self
                .inner
                .zone_image_serve_semantic_hits
                .load(Ordering::Relaxed),
            zone_image_serve_failures: self.inner.zone_image_serve_failures.load(Ordering::Relaxed),
            zone_image_serve_failure_reasons: self
                .inner
                .zone_image_serve_failure_reasons
                .each_ref()
                .map(|counter| counter.load(Ordering::Relaxed)),
            chaos_answered: self.inner.chaos_answered.load(Ordering::Relaxed),
            chaos_missing_value: self.inner.chaos_missing_value.load(Ordering::Relaxed),
            chaos_unrecognized_name: self.inner.chaos_unrecognized_name.load(Ordering::Relaxed),
            chaos_non_txt: self.inner.chaos_non_txt.load(Ordering::Relaxed),
        }
    }
}
