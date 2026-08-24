#[cfg(target_os = "linux")]
const LINUX_ERRNO_EAGAIN: i32 = 11;
const LINUX_ERRNO_EBUSY: i32 = 16;
#[cfg(target_os = "linux")]
const LINUX_ERRNO_ENOBUFS: i32 = 105;

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
        query_observation_options(),
    );
    observe_query_metrics(
        &query(b"\x03www\x07loading\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );
    observe_query_metrics(
        &query(b"\x07outside\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );
    let response = {
        let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        packet[2] |= 0x80;
        packet
    };
    observe_query_metrics(&response, &zones, &metrics, query_observation_options());

    assert_eq!(metrics.snapshot().queries_received, 3);
    let counts = metrics.zone_query_counts();
    assert_eq!(counts.get("example.test."), Some(&1));
    assert_eq!(counts.get("loading.test."), Some(&1));
    assert!(!counts.contains_key("outside.test."));
}

#[test]
fn reduced_hot_path_metrics_skip_mutex_backed_query_detail() {
    let zones = ZoneStore::new();
    let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(
        active_origin.clone(),
        Some(1),
        Vec::new(),
    ));
    let metrics = RuntimeMetrics::new_reduced_for_test();

    let observation = observe_query_metrics(
        &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );

    assert!(observation.is_query);
    assert!(observation.zone_metric.is_none());
    assert_eq!(metrics.snapshot().queries_received, 1);
    assert!(metrics.zone_query_counts().is_empty());

    let mut truncated = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    truncated[2] |= 0x82;
    record_query_response_metric(&observation, &truncated, &metrics);

    assert_eq!(metrics.snapshot().queries_truncated, 1);
    assert!(metrics.query_rcode_counts().is_empty());
    assert!(metrics.zone_query_rcode_counts().is_empty());
    assert!(metrics.query_latency_histograms().is_empty());

    let prefix_settings = cookie_prefix_metrics_for_test();
    metrics.record_dns_cookie_status(
        DnsCookieRequestStatus::ClientCookieOnly,
        "192.0.2.10".parse().unwrap(),
        prefix_settings,
    );
    metrics.record_dns_cookie_badcookie();
    metrics.record_dns_cookie_badcookie_for_source("192.0.2.10".parse().unwrap(), prefix_settings);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.dns_cookie_client_only, 1);
    assert_eq!(snapshot.dns_cookie_badcookie, 1);
    assert!(metrics.dns_cookie_prefix_counts().is_empty());

    assert!(!metrics.pipeline_timing_enabled());
    metrics.record_query_pipeline_latency(
        QueryPipelineStage::Compose,
        QueryLatencyCategory::UdpDirect,
        std::time::Duration::from_micros(100),
    );
    metrics.record_response_cache_candidate(ResponseCacheCandidateCategory::Direct);
    metrics.record_response_cache_ineligible(ResponseCacheIneligibleReason::Cookie);

    assert!(metrics.query_pipeline_latency_histograms().is_empty());
    assert!(metrics.response_cache_candidate_counts().is_empty());
    assert!(metrics.response_cache_ineligible_counts().is_empty());
}

#[test]
fn off_hot_path_metrics_skip_per_query_counters() {
    let zones = ZoneStore::new();
    let active_origin = DomainName::from_absolute_str("example.test.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(active_origin, Some(1), Vec::new()));
    let metrics = RuntimeMetrics::new_with_settings(
        1,
        DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
        false,
        MetricsHotPathDetail::Off,
    );

    let observation = observe_query_metrics(
        &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );

    assert!(!observation.is_query);
    assert!(observation.started_at.is_none());
    assert_eq!(metrics.snapshot().queries_received, 0);
    assert!(metrics.zone_query_counts().is_empty());

    let mut truncated = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    truncated[2] |= 0x82;
    record_query_response_metric(&observation, &truncated, &metrics);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.queries_truncated, 0);
    assert!(metrics.query_rcode_counts().is_empty());
    assert!(metrics.zone_query_rcode_counts().is_empty());
    assert!(metrics.query_latency_histograms().is_empty());
}

#[test]
fn query_metrics_count_response_rcodes_for_queries_only() {
    let zones = ZoneStore::new();
    let metrics = RuntimeMetrics::new();
    let observation = observe_query_metrics(
        &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
    );
    let non_query_observation =
        observe_query_metrics(&[0, 1, 2], &zones, &metrics, query_observation_options());
    let mut noerror = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    noerror[2] |= 0x80;
    let mut nxdomain = noerror.clone();
    nxdomain[3] |= 3;
    let mut truncated = noerror.clone();
    truncated[2] |= 0x02;
    let mut badvers = noerror.clone();
    badvers[11] = 1;
    badvers.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);

    record_query_response_metric(&observation, &noerror, &metrics);
    record_query_response_metric(&observation, &nxdomain, &metrics);
    record_query_response_metric(&observation, &truncated, &metrics);
    record_query_response_metric(&observation, &badvers, &metrics);
    record_query_response_metric(&non_query_observation, &truncated, &metrics);

    assert_eq!(metrics.snapshot().queries_truncated, 1);
    assert_eq!(metrics.snapshot().nsec3_iterations_exceed_cap, 0);
    let rcodes = metrics.query_rcode_counts();
    assert_eq!(rcodes.get(&0), Some(&2));
    assert_eq!(rcodes.get(&3), Some(&1));
    assert_eq!(rcodes.get(&16), Some(&1));
    assert_eq!(
        metrics
            .query_latency_histograms()
            .get(&QueryLatencyCategory::UdpDirect)
            .map(QueryLatencyHistogram::count),
        Some(4)
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
        query_observation_options(),
    );
    let outside = observe_query_metrics(
        &query(b"\x07outside\x04test\x00", RecordType::A as u16, 1),
        &zones,
        &metrics,
        query_observation_options(),
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
fn snapshot_refresh_accepts_retained_published_zone_for_metrics() {
    let metrics = RuntimeMetrics::new();
    let zones = ZoneStore::new();
    let origin = DomainName::from_absolute_str("refreshed.example.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(origin.clone(), Some(1), Vec::new()));
    let retained_before_refresh = zones
        .find_published_zone(&origin)
        .expect("zone starts published");

    zones.insert_snapshot(ZoneSnapshot::active(origin.clone(), Some(2), Vec::new()));
    let current_after_refresh = zones
        .find_published_zone(&origin)
        .expect("refreshed zone remains published");
    assert_eq!(
        retained_before_refresh.incarnation(),
        current_after_refresh.incarnation(),
        "snapshot refresh preserves the lifecycle incarnation"
    );

    let token = metrics
        .record_published_zone_query(&zones, &retained_before_refresh)
        .expect("a retained handle from the same lifecycle remains admissible");
    metrics.record_zone_query_response_rcode(&token, 0);

    assert_eq!(
        metrics
            .zone_query_counts()
            .get("refreshed.example."),
        Some(&1)
    );
    assert_eq!(
        metrics
            .zone_query_rcode_counts()
            .get(&("refreshed.example.".to_owned(), 0)),
        Some(&1)
    );
}

#[test]
fn catalog_metric_pruning_rejects_inflight_records_from_removed_generation() {
    let metrics = RuntimeMetrics::new();
    let zones = ZoneStore::new();
    let removed = DomainName::from_absolute_str("removed.example.").unwrap();
    let current = DomainName::from_absolute_str("current.example.").unwrap();
    zones.insert_snapshot(ZoneSnapshot::active(removed.clone(), Some(1), Vec::new()));
    zones.insert_snapshot(ZoneSnapshot::active(current.clone(), Some(1), Vec::new()));
    let removed_incarnation = zones
        .find_published_zone(&removed)
        .expect("removed zone starts published");
    let current_incarnation = zones
        .find_published_zone(&current)
        .expect("current zone starts published");
    let removed_token = metrics
        .record_published_zone_query(&zones, &removed_incarnation)
        .expect("full metrics return a zone token");
    let current_token = metrics
        .record_published_zone_query(&zones, &current_incarnation)
        .expect("full metrics return a zone token");
    metrics.record_zone_query_response_rcode(&current_token, 0);
    zones.insert_snapshot(ZoneSnapshot::active(current.clone(), Some(2), Vec::new()));
    let refreshed_current_incarnation = zones
        .find_published_zone(&current)
        .expect("refreshed retained zone remains published");
    assert_eq!(
        current_incarnation.incarnation(),
        refreshed_current_incarnation.incarnation(),
        "snapshot refresh preserves the zone lifecycle incarnation"
    );
    let _refreshed_current_token = metrics
        .record_published_zone_query(&zones, &refreshed_current_incarnation)
        .expect("refreshed retained zone keeps metric admission");

    assert!(zones.remove_zone(&removed));
    metrics.remove_zone_metrics(&zones, std::slice::from_ref(&removed));
    assert!(
        metrics
            .record_published_zone_query(&zones, &removed_incarnation)
            .is_none(),
        "a query that retained the removed PublishedZone must not recreate its counters"
    );
    metrics.record_zone_query_response_rcode(&removed_token, 3);

    assert!(!metrics.zone_query_counts().contains_key("removed.example."));
    assert_eq!(metrics.zone_query_counts().get("current.example."), Some(&2));
    assert_eq!(
        metrics
            .zone_query_rcode_counts()
            .get(&("current.example.".to_owned(), 0)),
        Some(&1)
    );
    assert!(!metrics
        .zone_query_rcode_counts()
        .contains_key(&("removed.example.".to_owned(), 3)));

    zones.insert_snapshot(ZoneSnapshot::active(removed.clone(), Some(2), Vec::new()));
    let replacement_incarnation = zones
        .find_published_zone(&removed)
        .expect("replacement zone is published");
    assert_ne!(
        removed_incarnation.incarnation(),
        replacement_incarnation.incarnation()
    );
    let replacement_token = metrics
        .record_published_zone_query(&zones, &replacement_incarnation)
        .expect("replacement zone receives a fresh token");
    // A delayed prune from the old removal must not delete counters already
    // admitted for the currently published replacement incarnation.
    metrics.remove_zone_metrics(&zones, std::slice::from_ref(&removed));
    metrics.record_zone_query_response_rcode(&removed_token, 2);
    metrics.record_zone_query_response_rcode(&replacement_token, 0);

    let rcodes = metrics.zone_query_rcode_counts();
    assert_eq!(
        rcodes.get(&("removed.example.".to_owned(), 0)),
        Some(&1)
    );
    assert!(!rcodes.contains_key(&("removed.example.".to_owned(), 2)));
}

#[test]
fn zone_store_publishes_zone_image_for_active_snapshot() {
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            DomainName::from_absolute_str("www.example.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 10].to_vec()],
        )],
    ));
    let published = zones
        .find_published_zone(&DomainName::from_absolute_str("www.example.test.").unwrap())
        .expect("published zone");
    assert_eq!(published.origin(), &origin);
    assert_eq!(published.serial(), Some(1));
    let first = published.active_zone_image_ref();
    let second = published.active_zone_image_ref();

    assert!(std::ptr::eq(first, second));
}

#[test]
fn zone_store_replaces_published_zone_image_for_new_snapshot() {
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            DomainName::from_absolute_str("www.example.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 10].to_vec()],
        )],
    ));
    let old_published = zones
        .find_published_zone(&DomainName::from_absolute_str("www.example.test.").unwrap())
        .expect("old published zone");
    let old_snapshot = zones
        .exact_snapshot_for_transfer(&origin)
        .expect("old snapshot");
    let old_image = old_published.active_zone_image_ref();

    zones.insert_snapshot(ZoneSnapshot::active(
        origin.clone(),
        Some(2),
        vec![Rrset::new(
            DomainName::from_absolute_str("www.example.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 11].to_vec()],
        )],
    ));
    let new_published = zones
        .find_published_zone(&DomainName::from_absolute_str("www.example.test.").unwrap())
        .expect("new published zone");
    let new_snapshot = zones
        .exact_snapshot_for_transfer(&origin)
        .expect("new snapshot");
    let new_image = new_published.active_zone_image_ref();
    let new_image_again = new_published.active_zone_image_ref();

    assert_eq!(new_published.origin(), &origin);
    assert_eq!(new_published.serial(), Some(2));
    assert!(!Arc::ptr_eq(
        old_snapshot.snapshot_arc_for_transfer(),
        new_snapshot.snapshot_arc_for_transfer()
    ));
    assert!(!std::ptr::eq(old_image, new_image));
    assert!(std::ptr::eq(new_image, new_image_again));
}

#[test]
fn dns_cookie_prefix_metrics_use_rrl_prefixes_and_evict_at_cap() {
    let metrics = RuntimeMetrics::new_with_settings(
        1,
        DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
        false,
        MetricsHotPathDetail::Full,
    );
    let prefix_settings = cookie_prefix_metrics_for_test();

    metrics.record_dns_cookie_status(
        DnsCookieRequestStatus::ClientCookieOnly,
        "192.0.2.10".parse().unwrap(),
        prefix_settings,
    );
    metrics.record_dns_cookie_badcookie_for_source("192.0.2.10".parse().unwrap(), prefix_settings);
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
        started_at: Some(std::time::Instant::now()),
        cookie_validated: false,
        zone_metric: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let non_query_observation = QueryMetricObservation {
        is_query: false,
        transport: Transport::Udp,
        started_at: Some(std::time::Instant::now()),
        cookie_validated: false,
        zone_metric: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let chain_limit = LookupMetrics {
        termination: Some(LookupTermination::CnameChainLimit),
        nsec3_iterations_exceeded: false,
        zone_image_used: true,
        zone_image_direct_answer: false,
        zone_image_failure_reason: None,
    };
    let loop_detected = LookupMetrics {
        termination: Some(LookupTermination::CnameLoop),
        nsec3_iterations_exceeded: false,
        zone_image_used: true,
        zone_image_direct_answer: false,
        zone_image_failure_reason: None,
    };

    record_query_lookup_metrics(&observation, chain_limit, &metrics);
    record_query_lookup_metrics(&observation, loop_detected, &metrics);
    record_query_lookup_metrics(&non_query_observation, chain_limit, &metrics);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.queries_cname_chain_limit, 1);
    assert_eq!(snapshot.queries_cname_loop, 1);
}

#[test]
fn query_metrics_count_nsec3_cap_from_lookup_observation_only() {
    let metrics = RuntimeMetrics::new();
    let observation = QueryMetricObservation {
        is_query: true,
        transport: Transport::Udp,
        started_at: Some(std::time::Instant::now()),
        cookie_validated: false,
        zone_metric: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let non_query_observation = QueryMetricObservation {
        is_query: false,
        transport: Transport::Udp,
        started_at: Some(std::time::Instant::now()),
        cookie_validated: false,
        zone_metric: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let over_cap = LookupMetrics {
        termination: None,
        nsec3_iterations_exceeded: true,
        zone_image_used: true,
        zone_image_direct_answer: false,
        zone_image_failure_reason: None,
    };

    record_query_lookup_metrics(&observation, over_cap, &metrics);
    record_query_lookup_metrics(&non_query_observation, over_cap, &metrics);

    assert_eq!(metrics.snapshot().nsec3_iterations_exceed_cap, 1);
}

#[test]
fn query_metrics_count_zone_image_serve_hits_and_failures() {
    let metrics = RuntimeMetrics::new();
    let observation = QueryMetricObservation {
        is_query: true,
        transport: Transport::Udp,
        started_at: Some(std::time::Instant::now()),
        cookie_validated: false,
        zone_metric: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let zone_image_hit = LookupMetrics {
        termination: None,
        nsec3_iterations_exceeded: false,
        zone_image_used: true,
        zone_image_direct_answer: true,
        zone_image_failure_reason: None,
    };
    let zone_image_semantic_hit = LookupMetrics {
        termination: None,
        nsec3_iterations_exceeded: false,
        zone_image_used: true,
        zone_image_direct_answer: false,
        zone_image_failure_reason: None,
    };
    let failure = LookupMetrics {
        termination: None,
        nsec3_iterations_exceeded: false,
        zone_image_used: false,
        zone_image_direct_answer: false,
        zone_image_failure_reason: Some(ZoneImageServeFailureReason::ResponseBuildFailed),
    };

    record_query_lookup_metrics(&observation, zone_image_hit, &metrics);
    record_query_lookup_metrics(&observation, zone_image_semantic_hit, &metrics);
    record_query_lookup_metrics(&observation, failure, &metrics);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.zone_image_serve_hits, 2);
    assert_eq!(snapshot.zone_image_serve_direct_hits, 1);
    assert_eq!(snapshot.zone_image_serve_semantic_hits, 1);
    assert_eq!(snapshot.zone_image_serve_failures, 1);
    assert_eq!(
        snapshot.zone_image_serve_failure_reasons
            [ZoneImageServeFailureReason::ResponseBuildFailed.metric_index()],
        1
    );
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
        MetricsHotPathDetail::Full,
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
            "borondns_secondary_query_duration_seconds_bucket{query_category=\"udp_direct\",le=\"0.001\"} 0"
        ));
    assert!(body.contains(
            "borondns_secondary_query_duration_seconds_bucket{query_category=\"udp_direct\",le=\"0.01\"} 1"
        ));
    assert!(!body.contains("le=\"0.00025\""));
}

#[test]
fn runtime_metrics_defensively_rejects_histogram_cardinality_over_limit() {
    RuntimeMetrics::try_new_with_settings(
        DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
        vec![1.0; MAX_LATENCY_HISTOGRAM_BUCKETS],
        false,
        MetricsHotPathDetail::Full,
    )
    .expect("exact metrics histogram cardinality limit is accepted");

    let error = RuntimeMetrics::try_new_with_settings(
        DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
        vec![1.0; MAX_LATENCY_HISTOGRAM_BUCKETS + 1],
        false,
        MetricsHotPathDetail::Full,
    )
    .expect_err("metrics initialization rejects one bucket over the limit");
    assert!(error.contains(&MAX_LATENCY_HISTOGRAM_BUCKETS.to_string()));
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
        MetricsHotPathDetail::Full,
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
            "borondns_query_pipeline_duration_seconds_bucket{stage=\"compose\",query_category=\"udp_direct\",le=\"0.001\"} 0"
        ));
    assert!(body.contains(
            "borondns_query_pipeline_duration_seconds_bucket{stage=\"compose\",query_category=\"udp_direct\",le=\"0.01\"} 1"
        ));
    assert!(body.contains("borondns_response_cache_candidate_total{category=\"direct\"} 1"));
    assert!(body.contains("borondns_response_cache_ineligible_total{reason=\"cookie\"} 1"));
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

    assert!(!body.contains("borondns_query_pipeline_duration_seconds"));
    assert!(!body.contains("borondns_response_cache_candidate_total"));
}

#[test]
fn udp_mmsg_and_worker_metrics_are_reported() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = RuntimeMetrics::new();
    metrics.record_udp_mmsg_stats(super::std_udp_mmsg::StdUdpMmsgStats {
        receive_syscalls: 3,
        receive_wouldblock_syscalls: 5,
        receive_interrupted_syscalls: 1,
        received_datagrams: 30,
        send_syscalls: 4,
        sent_datagrams: 28,
        send_partial_syscalls: 1,
        send_wouldblock_retries: 2,
        send_interrupted_retries: 4,
        send_resource_backoff_retries: 3,
    });
    metrics.record_af_xdp_packet_io_stats(super::AfXdpPacketIoStats {
        rx_recv_calls: 11,
        rx_empty_recv_calls: 2,
        rx_received_packets: 100,
        rx_parse_errors: 3,
        tx_send_calls: 7,
        tx_queued_packets: 96,
        tx_empty_send_calls: 1,
        tx_wakeups: 4,
        tx_kick_successes: 3,
        tx_kick_transient_failures: 1,
        tx_delivery_failures: 2,
        tx_poll_write_calls: 1,
        tx_poll_write_ready: 1,
        completion_dequeues: 9,
        completed_packets: 88,
    });
    metrics.record_udp_worker_receive_batch(1, 17);
    metrics.record_udp_worker_send_batch(1, 16);
    metrics.record_udp_worker_source_ports(1, [(53000, 10), (53001, 7)]);
    metrics.record_udp_worker_source_ports(1, [(53000, 3)]);

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );

    assert!(body.contains("borondns_udp_mmsg_receive_syscalls_total 3"));
    assert!(body.contains("borondns_udp_mmsg_receive_wouldblock_syscalls_total 5"));
    assert!(body.contains("borondns_udp_mmsg_receive_interrupted_syscalls_total 1"));
    assert!(body.contains("borondns_udp_mmsg_received_datagrams_total 30"));
    assert!(body.contains("borondns_udp_mmsg_send_syscalls_total 4"));
    assert!(body.contains("borondns_udp_mmsg_sent_datagrams_total 28"));
    assert!(body.contains("borondns_udp_mmsg_send_partial_syscalls_total 1"));
    assert!(body.contains("borondns_udp_mmsg_send_wouldblock_retries_total 2"));
    assert!(body.contains("borondns_udp_mmsg_send_interrupted_retries_total 4"));
    assert!(body.contains("borondns_udp_mmsg_send_resource_backoff_retries_total 3"));
    assert!(body.contains("borondns_udp_worker_received_datagrams_total{worker=\"1\"} 17"));
    assert!(body.contains("borondns_udp_worker_sent_datagrams_total{worker=\"1\"} 16"));
    assert!(body.contains(
        "borondns_udp_worker_source_port_datagrams_total{worker=\"1\",source_port=\"53000\"} 13"
    ));
    assert!(body.contains(
        "borondns_udp_worker_source_port_datagrams_total{worker=\"1\",source_port=\"53001\"} 7"
    ));
    assert!(!body.contains("borondns_udp_worker_sent_datagrams_total{worker=\"2\"}"));
}

#[test]
fn af_xdp_packet_io_metrics_are_reported() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = RuntimeMetrics::new();
    metrics.record_af_xdp_packet_io_stats(super::AfXdpPacketIoStats {
        rx_recv_calls: 11,
        rx_empty_recv_calls: 2,
        rx_received_packets: 100,
        rx_parse_errors: 3,
        tx_send_calls: 7,
        tx_queued_packets: 96,
        tx_empty_send_calls: 1,
        tx_wakeups: 4,
        tx_kick_successes: 3,
        tx_kick_transient_failures: 1,
        tx_delivery_failures: 2,
        tx_poll_write_calls: 1,
        tx_poll_write_ready: 1,
        completion_dequeues: 9,
        completed_packets: 88,
    });
    metrics.record_af_xdp_worker_receive_batch(2, 19);
    metrics.record_af_xdp_worker_send_batch(2, 18);
    // The generic UDP counters span configured PacketIo backends. For AF_XDP,
    // the send count is transport admission rather than confirmed delivery.
    metrics.record_udp_receive_batch(19);
    metrics.record_udp_send_batch(18);

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );

    assert!(body.contains("borondns_af_xdp_rx_recv_calls_total 11"));
    assert!(body.contains("borondns_af_xdp_rx_empty_recv_calls_total 2"));
    assert!(body.contains("borondns_af_xdp_rx_received_packets_total 100"));
    assert!(body.contains("borondns_af_xdp_rx_parse_errors_total 3"));
    assert!(body.contains("borondns_af_xdp_tx_send_calls_total 7"));
    assert!(body.contains("borondns_af_xdp_tx_queued_packets_total 96"));
    assert!(body.contains("borondns_af_xdp_tx_empty_send_calls_total 1"));
    assert!(body.contains("borondns_af_xdp_tx_wakeups_total 4"));
    assert!(body.contains("borondns_af_xdp_tx_kick_successes_total 3"));
    assert!(body.contains("borondns_af_xdp_tx_kick_transient_failures_total 1"));
    assert!(body.contains("borondns_af_xdp_tx_delivery_failures_total 2"));
    assert!(body.contains("borondns_af_xdp_tx_poll_write_calls_total 1"));
    assert!(body.contains("borondns_af_xdp_tx_poll_write_ready_total 1"));
    assert!(body.contains("borondns_af_xdp_completion_dequeues_total 9"));
    assert!(body.contains("borondns_af_xdp_completed_packets_total 88"));
    assert!(body.contains("borondns_af_xdp_worker_received_packets_total{worker=\"2\"} 19"));
    assert!(body.contains("borondns_af_xdp_worker_sent_packets_total{worker=\"2\"} 18"));
    assert!(body.contains("borondns_udp_receive_batches_total 1"));
    assert!(body.contains("borondns_udp_received_datagrams_total 19"));
    assert!(body.contains("borondns_udp_send_batches_total 1"));
    assert!(body.contains("borondns_udp_sent_datagrams_total 18"));
    assert!(body.contains(
        "# HELP borondns_udp_receive_batches_total UDP receive batches returned by the configured packet-I/O backend."
    ));
    assert!(body.contains(
        "# HELP borondns_udp_sent_datagrams_total UDP datagrams accepted by the configured packet-I/O backend; AF_XDP counts TX-ring admission, not confirmed delivery."
    ));
    assert!(body.contains(
        "# HELP borondns_af_xdp_worker_send_batches_total AF_XDP batches with one or more packets admitted to TX rings per worker slot."
    ));
    assert!(body.contains(
        "# HELP borondns_af_xdp_worker_sent_packets_total AF_XDP packets admitted to TX rings per worker slot."
    ));
    assert!(!body.contains("borondns_af_xdp_worker_sent_packets_total{worker=\"3\"}"));
}

#[test]
fn af_xdp_kick_observation_is_exposed_without_a_batched_stats_flush() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = RuntimeMetrics::new();
    metrics.record_af_xdp_tx_kick_observation(false, true, false);

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );

    assert!(body.contains("borondns_af_xdp_tx_wakeups_total 1"));
    assert!(body.contains("borondns_af_xdp_tx_kick_transient_failures_total 1"));
    assert!(body.contains("borondns_af_xdp_tx_kick_successes_total 0"));
    assert!(body.contains("borondns_af_xdp_tx_delivery_failures_total 0"));
}

#[test]
fn zero_transport_admission_does_not_create_udp_send_batch_metrics() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = RuntimeMetrics::new();
    metrics.record_udp_send_batch(0);
    metrics.record_udp_worker_send_batch(1, 0);
    metrics.record_af_xdp_worker_send_batch(2, 0);

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );

    assert!(body.contains("borondns_udp_send_batches_total 0"));
    assert!(body.contains("borondns_udp_sent_datagrams_total 0"));
    assert!(!body.contains("borondns_udp_worker_send_batches_total{worker=\"1\"}"));
    assert!(!body.contains("borondns_af_xdp_worker_send_batches_total{worker=\"2\"}"));
}

#[test]
fn udp_io_errors_classify_transient_resource_destination_and_fatal_cases() {
    assert_eq!(
        classify_udp_send_error(&std::io::Error::from_raw_os_error(111)),
        UdpIoErrorAction::Continue
    );
    assert_eq!(
        classify_udp_send_error(&std::io::Error::from_raw_os_error(16)),
        UdpIoErrorAction::Continue
    );
    assert!(matches!(
        classify_udp_send_error(&std::io::Error::from_raw_os_error(105)),
        UdpIoErrorAction::Backoff(_)
    ));
    assert_eq!(
        classify_udp_send_error(&std::io::Error::from_raw_os_error(9)),
        UdpIoErrorAction::Fatal
    );
    assert!(matches!(
        classify_udp_recv_error(&std::io::Error::from_raw_os_error(12)),
        UdpIoErrorAction::Backoff(_)
    ));
    assert_eq!(
        classify_udp_recv_error(&std::io::Error::from_raw_os_error(22)),
        UdpIoErrorAction::Fatal
    );
}

#[test]
fn hot_path_detail_off_suppresses_udp_packet_counters() {
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let metrics = RuntimeMetrics::new_with_settings(
        DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
        DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
        false,
        MetricsHotPathDetail::Off,
    );
    metrics.record_query_received();
    metrics.record_udp_receive_batch(10);
    metrics.record_udp_send_batch(9);
    metrics.record_udp_mmsg_stats(super::std_udp_mmsg::StdUdpMmsgStats {
        receive_syscalls: 3,
        receive_wouldblock_syscalls: 5,
        receive_interrupted_syscalls: 1,
        received_datagrams: 30,
        send_syscalls: 4,
        sent_datagrams: 28,
        send_partial_syscalls: 1,
        send_wouldblock_retries: 2,
        send_interrupted_retries: 4,
        send_resource_backoff_retries: 3,
    });
    metrics.record_af_xdp_packet_io_stats(super::AfXdpPacketIoStats {
        rx_recv_calls: 11,
        rx_empty_recv_calls: 2,
        rx_received_packets: 100,
        rx_parse_errors: 3,
        tx_send_calls: 7,
        tx_queued_packets: 96,
        tx_empty_send_calls: 1,
        tx_wakeups: 4,
        tx_kick_successes: 3,
        tx_kick_transient_failures: 1,
        tx_delivery_failures: 2,
        tx_poll_write_calls: 1,
        tx_poll_write_ready: 1,
        completion_dequeues: 9,
        completed_packets: 88,
    });
    metrics.record_af_xdp_worker_receive_batch(2, 19);
    metrics.record_af_xdp_worker_send_batch(2, 18);
    metrics.record_udp_worker_receive_batch(1, 17);
    metrics.record_udp_worker_send_batch(1, 16);
    metrics.record_udp_worker_source_ports(1, [(53000, 17)]);
    metrics.record_zone_image_serve_hit();
    metrics.record_zone_image_serve_direct_hit();
    metrics.record_zone_image_serve_semantic_hit();
    metrics.record_zone_image_serve_failure();
    metrics
        .record_zone_image_serve_failure_reason(ZoneImageServeFailureReason::ResponseBuildFailed);

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );

    assert!(body.contains("borondns_queries_received_total 0"));
    assert!(body.contains("borondns_udp_receive_batches_total 0"));
    assert!(body.contains("borondns_udp_received_datagrams_total 0"));
    assert!(body.contains("borondns_udp_send_batches_total 0"));
    assert!(body.contains("borondns_udp_sent_datagrams_total 0"));
    assert!(body.contains("borondns_udp_mmsg_receive_syscalls_total 0"));
    assert!(body.contains("borondns_udp_mmsg_receive_wouldblock_syscalls_total 0"));
    assert!(body.contains("borondns_udp_mmsg_receive_interrupted_syscalls_total 0"));
    assert!(body.contains("borondns_udp_mmsg_send_wouldblock_retries_total 0"));
    assert!(body.contains("borondns_udp_mmsg_send_interrupted_retries_total 0"));
    assert!(body.contains("borondns_udp_mmsg_send_resource_backoff_retries_total 0"));
    assert!(body.contains("borondns_af_xdp_rx_recv_calls_total 11"));
    assert!(body.contains("borondns_af_xdp_tx_send_calls_total 7"));
    assert!(body.contains("borondns_af_xdp_completed_packets_total 88"));
    assert!(body.contains("borondns_af_xdp_worker_received_packets_total{worker=\"2\"} 19"));
    assert!(body.contains("borondns_af_xdp_worker_sent_packets_total{worker=\"2\"} 18"));
    assert!(body.contains("borondns_zone_image_serve_hits_total 0"));
    assert!(body.contains("borondns_zone_image_serve_direct_hits_total 0"));
    assert!(body.contains("borondns_zone_image_serve_semantic_hits_total 0"));
    assert!(body.contains("borondns_zone_image_serve_failures_total 0"));
    assert!(body.contains(
        "borondns_zone_image_serve_failures_by_reason_total{reason=\"response_build_failed\"} 0"
    ));
    assert!(!body.contains("borondns_udp_worker_received_datagrams_total{worker=\"1\"}"));
    assert!(!body.contains("borondns_udp_worker_sent_datagrams_total{worker=\"1\"}"));
    assert!(!body.contains("borondns_udp_worker_source_port_datagrams_total{worker=\"1\""));
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
#[ignore = "manual release-mode scaling evidence"]
fn metrics_and_rrl_recency_scaling_benchmark() {
    const TOUCHES: usize = 50_000;
    for cardinality in [1_000_usize, 10_000, 100_000] {
        let config = RrlConfig {
            max_keys: cardinality,
            ipv6_prefix_len: 128,
            positive_per_second: u32::MAX,
            ..RrlConfig::default()
        };
        let metrics = RuntimeMetrics::new();
        let limiter = RrlLimiter::from_config(&config, metrics);
        let response = positive_query_response();
        for index in 0..cardinality {
            let source = IpAddr::V6(std::net::Ipv6Addr::from(index as u128));
            let _ = limiter.apply(source, response.clone());
        }
        let started = std::time::Instant::now();
        for index in 0..TOUCHES {
            let source = IpAddr::V6(std::net::Ipv6Addr::from((index % cardinality) as u128));
            let _ = limiter.apply(source, response.clone());
        }
        let rrl_ns_per_touch = started.elapsed().as_nanos() / TOUCHES as u128;

        let metrics = RuntimeMetrics::new_with_settings(
            cardinality,
            DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
            false,
            MetricsHotPathDetail::Full,
        );
        let settings = CookiePrefixMetricSettings {
            ipv4_prefix_len: 32,
            ipv6_prefix_len: 128,
        };
        for index in 0..cardinality {
            let source = IpAddr::V6(std::net::Ipv6Addr::from(index as u128));
            metrics.record_dns_cookie_status(
                DnsCookieRequestStatus::NoCookie,
                source,
                settings,
            );
        }
        let started = std::time::Instant::now();
        for index in 0..TOUCHES {
            let source = IpAddr::V6(std::net::Ipv6Addr::from((index % cardinality) as u128));
            metrics.record_dns_cookie_status(
                DnsCookieRequestStatus::NoCookie,
                source,
                settings,
            );
        }
        let cookie_ns_per_touch = started.elapsed().as_nanos() / TOUCHES as u128;
        eprintln!(
            "recency_scaling cardinality={cardinality} rrl_ns_per_touch={rrl_ns_per_touch} cookie_ns_per_touch={cookie_ns_per_touch}"
        );
    }
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
    let limiter = NotifyLogLimiter::new(std::time::Duration::from_secs(60), 100);
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
fn notify_log_limiter_suppresses_new_keys_at_capacity() {
    let limiter = NotifyLogLimiter::new(std::time::Duration::from_secs(60), 1);
    let zone = DomainName::from_absolute_str("example.test.").unwrap();

    limiter.log_unauthorized("192.0.2.10".parse().unwrap(), &zone);
    limiter.log_unauthorized("198.51.100.10".parse().unwrap(), &zone);
    limiter.log_tsig_failure(
        "203.0.113.10".parse().unwrap(),
        &zone,
        &TsigError::MissingTsig,
    );

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
fn rrl_limiter_touch_keeps_recent_key_at_capacity() {
    let config = RrlConfig {
        positive_per_second: 0,
        slip: 0,
        max_keys: 2,
        ipv4_prefix_len: 32,
        ..RrlConfig::default()
    };
    let metrics = RuntimeMetrics::new();
    let limiter = RrlLimiter::from_config(&config, metrics.clone());

    for addr in ["192.0.2.1", "192.0.2.2", "192.0.2.1", "192.0.2.3"] {
        assert!(matches!(
            limiter.apply(addr.parse().unwrap(), positive_query_response()),
            RrlDecision::Drop
        ));
    }
    assert_eq!(metrics.snapshot().rrl_key_evictions, 1);

    assert!(matches!(
        limiter.apply("192.0.2.1".parse().unwrap(), positive_query_response()),
        RrlDecision::Drop
    ));
    assert_eq!(
        metrics.snapshot().rrl_key_evictions,
        1,
        "recently touched key should still be tracked"
    );

    assert!(matches!(
        limiter.apply("192.0.2.2".parse().unwrap(), positive_query_response()),
        RrlDecision::Drop
    ));
    assert_eq!(
        metrics.snapshot().rrl_key_evictions,
        2,
        "least-recent key should have been evicted before reinsertion"
    );
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
            udp_batch_size: 1,
            udp_backend: UdpBackend::Std,
            udp_runtime: UdpRuntime::Tokio,
            udp_idle_strategy: Default::default(),
            xdp: XdpConfig::default(),
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
fn udp_allocation_paths_defensively_bound_invalid_internal_batch_sizes() {
    assert_eq!(bounded_udp_batch_size(0), 1);
    assert_eq!(bounded_udp_batch_size(MAX_UDP_BATCH_SIZE), MAX_UDP_BATCH_SIZE);
    assert_eq!(
        bounded_udp_batch_size(MAX_UDP_BATCH_SIZE.saturating_add(1)),
        MAX_UDP_BATCH_SIZE
    );
    assert_eq!(bounded_udp_batch_size(usize::MAX), MAX_UDP_BATCH_SIZE);
}

#[tokio::test]
async fn std_udp_batch_io_drains_ready_datagrams_up_to_batch_size() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for byte in [1_u8, 2, 3, 4] {
        client.send_to(&[byte], server_addr).await.unwrap();
    }

    let mut packet_io = StdUdpBatchIo::new(socket, 3);
    let admission_open = AtomicBool::new(true);
    let first_payloads = {
        let batch = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            packet_io.recv_batch(&admission_open),
        )
        .await
        .expect("first UDP batch")
        .unwrap();
        batch
            .iter()
            .map(|packet| packet.payload().to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(first_payloads, vec![vec![1], vec![2], vec![3]]);

    let second_payloads = {
        let batch = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            packet_io.recv_batch(&admission_open),
        )
        .await
        .expect("second UDP batch")
        .unwrap();
        batch
            .iter()
            .map(|packet| packet.payload().to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(second_payloads, vec![vec![4]]);
}

#[derive(Clone, Copy, Debug)]
enum ControlledUdpIoError {
    Kind(std::io::ErrorKind),
    Busy,
}

impl ControlledUdpIoError {
    fn into_io_error(self) -> std::io::Error {
        match self {
            Self::Kind(kind) => std::io::Error::from(kind),
            Self::Busy => std::io::Error::from_raw_os_error(LINUX_ERRNO_EBUSY),
        }
    }

    fn record_af_xdp_kick_failure(self, metrics: &RuntimeMetrics) {
        metrics.record_af_xdp_tx_kick_observation(
            false,
            matches!(self, Self::Kind(std::io::ErrorKind::WouldBlock)),
            matches!(self, Self::Busy),
        );
    }
}

struct ControlledUdpPacketIo {
    inbound: Vec<UdpInbound>,
    recv_started: Arc<Notify>,
    release_recv: Arc<Notify>,
    send_started: Arc<Notify>,
    release_send: Arc<Notify>,
    recv_calls: Arc<AtomicUsize>,
    sends: Arc<AtomicUsize>,
    is_af_xdp: bool,
    send_error: Option<(usize, ControlledUdpIoError)>,
    pending_send_active: bool,
    pending_send_errors: VecDeque<ControlledUdpIoError>,
    pending_send_started: Arc<Notify>,
    release_pending_send: Arc<Notify>,
    pending_send_calls: Arc<AtomicUsize>,
    arm_pending_send_after_send: bool,
    record_send_error_as_kick: bool,
}

impl ControlledUdpPacketIo {
    fn new() -> Self {
        Self::with_inbound_count(1)
    }

    fn with_inbound_count(count: usize) -> Self {
        let peer = SocketAddr::from(([127, 0, 0, 1], 53000));
        let request = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let inbound = (0..count)
            .map(|_| {
                let mut packet = UdpInbound::new();
                packet.buffer[..request.len()].copy_from_slice(&request);
                packet.len = request.len();
                packet.peer = peer;
                packet.target = UdpPacketTarget::Socket(peer);
                packet
            })
            .collect();
        Self {
            inbound,
            recv_started: Arc::new(Notify::new()),
            release_recv: Arc::new(Notify::new()),
            send_started: Arc::new(Notify::new()),
            release_send: Arc::new(Notify::new()),
            recv_calls: Arc::new(AtomicUsize::new(0)),
            sends: Arc::new(AtomicUsize::new(0)),
            is_af_xdp: false,
            send_error: None,
            pending_send_active: false,
            pending_send_errors: VecDeque::new(),
            pending_send_started: Arc::new(Notify::new()),
            release_pending_send: Arc::new(Notify::new()),
            pending_send_calls: Arc::new(AtomicUsize::new(0)),
            arm_pending_send_after_send: false,
            record_send_error_as_kick: false,
        }
    }

    fn with_partial_af_xdp_send_error(
        mut self,
        queued: usize,
        kind: std::io::ErrorKind,
    ) -> Self {
        self.is_af_xdp = true;
        self.send_error = Some((queued, ControlledUdpIoError::Kind(kind)));
        self
    }

    fn with_recovering_af_xdp_send_error(
        mut self,
        queued: usize,
        error: ControlledUdpIoError,
        pending_send_errors: impl IntoIterator<Item = ControlledUdpIoError>,
    ) -> Self {
        self.is_af_xdp = true;
        self.send_error = Some((queued, error));
        self.pending_send_errors = pending_send_errors.into_iter().collect();
        self.arm_pending_send_after_send = true;
        self.record_send_error_as_kick = true;
        self
    }

    fn with_partial_std_send_error(
        mut self,
        queued: usize,
        kind: std::io::ErrorKind,
    ) -> Self {
        self.send_error = Some((queued, ControlledUdpIoError::Kind(kind)));
        self
    }

    fn with_peer_port(mut self, port: u16) -> Self {
        for packet in &mut self.inbound {
            packet.peer.set_port(port);
            packet.target = UdpPacketTarget::Socket(packet.peer);
        }
        self
    }
}

impl PacketIo for ControlledUdpPacketIo {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 53)))
    }

    fn is_af_xdp(&self) -> bool {
        self.is_af_xdp
    }

    async fn service_pending_send(
        &mut self,
        admission_open: &AtomicBool,
        metrics: &RuntimeMetrics,
    ) -> std::io::Result<()> {
        if !self.pending_send_active {
            return Ok(());
        }
        self.pending_send_calls.fetch_add(1, Ordering::AcqRel);
        self.pending_send_started.notify_one();
        self.release_pending_send.notified().await;
        if !admission_open.load(Ordering::Acquire) {
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }
        if let Some(error) = self.pending_send_errors.pop_front() {
            error.record_af_xdp_kick_failure(metrics);
            return Err(error.into_io_error());
        }
        metrics.record_af_xdp_tx_kick_observation(true, false, false);
        self.pending_send_active = false;
        Ok(())
    }

    async fn recv_batch(&mut self, admission_open: &AtomicBool) -> std::io::Result<&[UdpInbound]> {
        self.recv_calls.fetch_add(1, Ordering::AcqRel);
        self.recv_started.notify_one();
        self.release_recv.notified().await;
        if !admission_open.load(Ordering::Acquire) {
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }
        Ok(&self.inbound)
    }

    async fn send_batch(
        &mut self,
        outbound: &[UdpOutbound],
        metrics: &RuntimeMetrics,
        worker_id: usize,
    ) -> Result<usize, PacketIoSendError> {
        if outbound.is_empty() {
            return Ok(0);
        }
        self.send_started.notify_one();
        self.release_send.notified().await;
        let queued = self
            .send_error
            .map_or(outbound.len(), |(queued, _)| queued.min(outbound.len()));
        self.sends.fetch_add(queued, Ordering::AcqRel);
        if self.is_af_xdp {
            metrics.record_udp_send_batch(queued);
            metrics.record_af_xdp_worker_send_batch(worker_id, queued);
        }
        if let Some((_, error)) = self.send_error {
            if self.record_send_error_as_kick {
                error.record_af_xdp_kick_failure(metrics);
            }
            if self.arm_pending_send_after_send {
                self.pending_send_active = true;
            }
            return Err(PacketIoSendError::new(error.into_io_error(), queued));
        }
        Ok(queued)
    }
}

async fn assert_pending_af_xdp_send_recovery_preserves_provenance(error: ControlledUdpIoError) {
    let packet_io = ControlledUdpPacketIo::with_inbound_count(1)
        .with_recovering_af_xdp_send_error(1, error, [error, error]);
    let recv_started = packet_io.recv_started.clone();
    let release_recv = packet_io.release_recv.clone();
    let send_started = packet_io.send_started.clone();
    let release_send = packet_io.release_send.clone();
    let pending_send_started = packet_io.pending_send_started.clone();
    let release_pending_send = packet_io.release_pending_send.clone();
    let pending_send_calls = packet_io.pending_send_calls.clone();
    let recv_calls = packet_io.recv_calls.clone();
    let sends = packet_io.sends.clone();
    let admission_open = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
    let server = tokio::spawn(serve_udp_packet_io_until(
        packet_io,
        zones.clone(),
        settings,
        2,
        3,
        admission_open.clone(),
        async move { shutdown_rx.await.unwrap() },
    ));

    recv_started.notified().await;
    release_recv.notify_one();
    send_started.notified().await;
    release_send.notify_one();

    for expected_call in 1..=3 {
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            pending_send_started.notified(),
        )
        .await
        .expect("pending send service remains live and retryable");
        assert_eq!(pending_send_calls.load(Ordering::Acquire), expected_call);
        release_pending_send.notify_one();
    }

    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        recv_started.notified(),
    )
    .await
    .expect("worker returns to receive after the pending TX wake recovers");
    admission_open.store(false, Ordering::Release);
    shutdown_tx
        .send(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("recovered AF_XDP worker stops cleanly")
        .unwrap()
        .unwrap();

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.udp_send_errors, 3);
    assert_eq!(snapshot.udp_receive_errors, 0);
    assert_eq!(snapshot.udp_send_batches, 1);
    assert_eq!(snapshot.udp_sent_datagrams, 1);
    assert_eq!(recv_calls.load(Ordering::Acquire), 2);
    assert_eq!(sends.load(Ordering::Acquire), 1);
    assert_eq!(pending_send_calls.load(Ordering::Acquire), 3);
    assert_eq!(
        metrics.af_xdp_durable_send_stats_for_test(2),
        (0, 0, 0, 0, 1, 1)
    );

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        ),
        0,
        false,
    );
    assert!(body.contains("borondns_af_xdp_tx_wakeups_total 4"));
    assert!(body.contains("borondns_af_xdp_tx_kick_successes_total 1"));
    match error {
        ControlledUdpIoError::Kind(std::io::ErrorKind::WouldBlock) => {
            assert!(body.contains("borondns_af_xdp_tx_kick_transient_failures_total 3"));
            assert!(body.contains("borondns_af_xdp_tx_delivery_failures_total 0"));
        }
        ControlledUdpIoError::Busy => {
            assert!(body.contains("borondns_af_xdp_tx_kick_transient_failures_total 0"));
            assert!(body.contains("borondns_af_xdp_tx_delivery_failures_total 3"));
        }
        other => panic!("unexpected controlled AF_XDP send error: {other:?}"),
    }
}

#[tokio::test]
async fn af_xdp_pending_ebusy_stays_send_side_until_recovery() {
    assert_pending_af_xdp_send_recovery_preserves_provenance(ControlledUdpIoError::Busy).await;
}

#[tokio::test]
async fn af_xdp_pending_wouldblock_stays_send_side_until_recovery() {
    assert_pending_af_xdp_send_recovery_preserves_provenance(ControlledUdpIoError::Kind(
        std::io::ErrorKind::WouldBlock,
    ))
    .await;
}

#[tokio::test]
async fn af_xdp_worker_metric_uses_exact_tx_ring_admission_count_on_wakeup_error() {
    let packet_io = ControlledUdpPacketIo::with_inbound_count(3)
        .with_partial_af_xdp_send_error(1, std::io::ErrorKind::WouldBlock);
    let recv_started = packet_io.recv_started.clone();
    let release_recv = packet_io.release_recv.clone();
    let send_started = packet_io.send_started.clone();
    let release_send = packet_io.release_send.clone();
    let admission_open = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
    let server = tokio::spawn(serve_udp_packet_io_until(
        packet_io,
        zones.clone(),
        settings,
        2,
        3,
        admission_open.clone(),
        async move { shutdown_rx.await.unwrap() },
    ));

    recv_started.notified().await;
    release_recv.notify_one();
    send_started.notified().await;
    release_send.notify_one();
    recv_started.notified().await;
    admission_open.store(false, Ordering::Release);
    shutdown_tx
        .send(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("UDP worker stops after partial AF_XDP send error")
        .unwrap()
        .unwrap();

    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        ),
        0,
        false,
    );
    assert!(body.contains("borondns_af_xdp_worker_send_batches_total{worker=\"2\"} 1"));
    assert!(body.contains("borondns_af_xdp_worker_sent_packets_total{worker=\"2\"} 1"));
    assert!(!body.contains("borondns_af_xdp_worker_sent_packets_total{worker=\"2\"} 3"));
    assert!(body.contains("borondns_udp_send_batches_total 1"));
    assert!(body.contains("borondns_udp_sent_datagrams_total 1"));
}

#[tokio::test]
async fn udp_source_port_zero_is_discarded_before_processing_and_listener_stays_alive() {
    let packet_io = ControlledUdpPacketIo::new().with_peer_port(0);
    let recv_started = packet_io.recv_started.clone();
    let release_recv = packet_io.release_recv.clone();
    let recv_calls = packet_io.recv_calls.clone();
    let sends = packet_io.sends.clone();
    let admission_open = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let metrics = RuntimeMetrics::new();
    let settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
    let server = tokio::spawn(serve_udp_packet_io_until(
        packet_io,
        active_example_zone(),
        settings,
        0,
        1,
        admission_open.clone(),
        async move { shutdown_rx.await.unwrap() },
    ));

    recv_started.notified().await;
    release_recv.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(1), recv_started.notified())
        .await
        .expect("listener continues receiving after source-port-zero datagram");
    assert_eq!(sends.load(Ordering::Acquire), 0);
    assert_eq!(metrics.snapshot().queries_received, 0);

    admission_open.store(false, Ordering::Release);
    shutdown_tx
        .send(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .unwrap();
    release_recv.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("UDP listener stops cleanly")
        .unwrap()
        .unwrap();
    assert_eq!(recv_calls.load(Ordering::Acquire), 2);
    assert_eq!(sends.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn std_udp_partial_fatal_send_records_successes_exactly_once() {
    let packet_io = ControlledUdpPacketIo::with_inbound_count(3)
        .with_partial_std_send_error(1, std::io::ErrorKind::InvalidInput);
    let recv_started = packet_io.recv_started.clone();
    let release_recv = packet_io.release_recv.clone();
    let send_started = packet_io.send_started.clone();
    let release_send = packet_io.release_send.clone();
    let sends = packet_io.sends.clone();
    let metrics = RuntimeMetrics::new();
    let settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
    let server = tokio::spawn(serve_udp_packet_io_until(
        packet_io,
        active_example_zone(),
        settings,
        0,
        1,
        Arc::new(AtomicBool::new(true)),
        std::future::pending(),
    ));

    recv_started.notified().await;
    release_recv.notify_one();
    send_started.notified().await;
    release_send.notify_one();
    let error = tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("partial fatal standard send returns")
        .unwrap()
        .expect_err("fatal standard send stops the listener");
    assert!(matches!(error, RuntimeError::Udp(_)));
    assert_eq!(sends.load(Ordering::Acquire), 1);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.udp_send_batches, 1);
    assert_eq!(snapshot.udp_sent_datagrams, 1);
}

#[test]
fn dedicated_udp_partial_fatal_send_records_successes_exactly_once() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    socket.set_nonblocking(true).expect("nonblocking sender");
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .expect("receiver timeout");
    let receiver_addr = receiver.local_addr().expect("receiver address");
    let accepted_response = positive_query_response();
    let query_metrics = QueryMetricObservation {
        is_query: true,
        transport: Transport::Udp,
        started_at: None,
        cookie_validated: false,
        zone_metric: None,
        parse_duration: None,
        lookup_duration: None,
        compose_duration: None,
    };
    let outbound = vec![
        UdpOutbound {
            response: accepted_response.clone(),
            target: UdpPacketTarget::Socket(receiver_addr),
            query_metrics: Some(query_metrics.clone()),
            #[cfg(feature = "af-xdp")]
            benchmark_fixed_response: false,
        },
        UdpOutbound {
            response: positive_query_response(),
            target: UdpPacketTarget::Socket(SocketAddr::from(([127, 0, 0, 1], 0))),
            query_metrics: Some(query_metrics),
            #[cfg(feature = "af-xdp")]
            benchmark_fixed_response: false,
        },
    ];
    let mut packet_io = super::std_udp_mmsg::StdUdpMmsg::new(1);
    let metrics = RuntimeMetrics::new_with_settings(
        DEFAULT_COOKIE_PREFIX_METRIC_LIMIT,
        DEFAULT_LATENCY_HISTOGRAM_BUCKETS.to_vec(),
        true,
        MetricsHotPathDetail::Full,
    );

    let send_result = send_std_udp_batch(&mut packet_io, &socket, &outbound, 2, &metrics);
    metrics.record_udp_mmsg_stats(packet_io.take_stats());
    let error = send_result.expect_err("port-zero destination is fatal");
    match error {
        RuntimeError::Udp(error) => assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput),
        other => panic!("unexpected dedicated UDP error: {other}"),
    }
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.udp_send_batches, 1);
    assert_eq!(snapshot.udp_sent_datagrams, 1);
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );
    assert!(body.contains("borondns_udp_mmsg_send_syscalls_total 1"));
    assert!(body.contains("borondns_udp_mmsg_sent_datagrams_total 1"));
    assert!(body.contains("borondns_udp_worker_send_batches_total{worker=\"2\"} 1"));
    assert!(body.contains("borondns_udp_worker_sent_datagrams_total{worker=\"2\"} 1"));
    assert!(body.contains(
        "borondns_query_pipeline_duration_seconds_count{stage=\"send\",query_category=\"udp_direct\"} 1"
    ));
    let mut received = [0_u8; 512];
    let (received_len, _) = receiver
        .recv_from(&mut received)
        .expect("receive successful prefix datagram");
    assert_eq!(&received[..received_len], accepted_response);
}

#[cfg(target_os = "linux")]
#[test]
fn dedicated_udp_resource_pressure_records_error_and_backoffs_without_double_counting() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    let receiver_addr = receiver.local_addr().expect("receiver address");
    let outbound = vec![
        UdpOutbound {
            response: b"accepted".to_vec(),
            target: UdpPacketTarget::Socket(receiver_addr),
            query_metrics: None,
            #[cfg(feature = "af-xdp")]
            benchmark_fixed_response: false,
        },
        UdpOutbound {
            response: b"resource-pressure".to_vec(),
            target: UdpPacketTarget::Socket(receiver_addr),
            query_metrics: None,
            #[cfg(feature = "af-xdp")]
            benchmark_fixed_response: false,
        },
    ];
    let mut packet_io = super::std_udp_mmsg::StdUdpMmsg::new(4);
    packet_io.inject_sendmmsg_outcomes_for_test([
        Ok(1),
        Err(LINUX_ERRNO_ENOBUFS),
        Err(LINUX_ERRNO_ENOBUFS),
        Err(LINUX_ERRNO_ENOBUFS),
        Err(LINUX_ERRNO_ENOBUFS),
    ]);
    let metrics = RuntimeMetrics::new();
    let mut outer_backoffs = Vec::new();

    super::udp::send_std_udp_batch_with_backoff_for_test(
        &mut packet_io,
        &socket,
        &outbound,
        2,
        &metrics,
        |duration| outer_backoffs.push(duration),
    )
    .expect("resource-pressure send error is non-fatal");
    assert_eq!(outer_backoffs, vec![std::time::Duration::from_millis(50)]);
    assert_eq!(
        packet_io.injected_send_resource_backoffs_for_test(),
        [std::time::Duration::from_millis(50); 3]
    );
    metrics.record_udp_mmsg_stats(packet_io.take_stats());

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.udp_send_batches, 1);
    assert_eq!(snapshot.udp_sent_datagrams, 1);
    assert_eq!(snapshot.udp_send_errors, 1);
    let zones = ZoneStore::new();
    let refresh_registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(3600),
    );
    let body = metrics_body(
        &zones,
        &metrics,
        &CatalogManager::default(),
        &refresh_registry,
        0,
        false,
    );
    assert!(body.contains("borondns_udp_send_errors_total 1"));
    assert!(body.contains("borondns_udp_mmsg_send_syscalls_total 1"));
    assert!(body.contains("borondns_udp_mmsg_sent_datagrams_total 1"));
    assert!(body.contains("borondns_udp_mmsg_send_partial_syscalls_total 1"));
    assert!(body.contains("borondns_udp_mmsg_send_wouldblock_retries_total 0"));
    assert!(body.contains("borondns_udp_mmsg_send_interrupted_retries_total 0"));
    assert!(body.contains("borondns_udp_mmsg_send_resource_backoff_retries_total 3"));
    assert!(body.contains("borondns_udp_worker_sent_datagrams_total{worker=\"2\"} 1"));
}

#[cfg(target_os = "linux")]
#[test]
fn dedicated_udp_wouldblock_retry_exhaustion_surfaces_outer_send_error_without_backoff() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    let receiver_addr = receiver.local_addr().expect("receiver address");
    let outbound = vec![UdpOutbound {
        response: b"wouldblock".to_vec(),
        target: UdpPacketTarget::Socket(receiver_addr),
        query_metrics: None,
        #[cfg(feature = "af-xdp")]
        benchmark_fixed_response: false,
    }];
    let mut packet_io = super::std_udp_mmsg::StdUdpMmsg::new(4);
    packet_io.inject_sendmmsg_outcomes_for_test(std::iter::repeat_n(
        Err(LINUX_ERRNO_EAGAIN),
        256,
    ));
    let metrics = RuntimeMetrics::new();
    let mut outer_backoffs = Vec::new();

    super::udp::send_std_udp_batch_with_backoff_for_test(
        &mut packet_io,
        &socket,
        &outbound,
        2,
        &metrics,
        |duration| outer_backoffs.push(duration),
    )
    .expect("WouldBlock exhaustion is non-fatal to the dedicated worker");
    assert!(outer_backoffs.is_empty());
    metrics.record_udp_mmsg_stats(packet_io.take_stats());

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.udp_send_batches, 0);
    assert_eq!(snapshot.udp_sent_datagrams, 0);
    assert_eq!(snapshot.udp_send_errors, 1);
    let body = metrics_body(
        &ZoneStore::new(),
        &metrics,
        &CatalogManager::default(),
        &ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        ),
        0,
        false,
    );
    assert!(body.contains("borondns_udp_send_errors_total 1"));
    assert!(body.contains("borondns_udp_mmsg_send_wouldblock_retries_total 256"));
    assert!(body.contains("borondns_udp_mmsg_send_interrupted_retries_total 0"));
    assert!(body.contains("borondns_udp_mmsg_send_resource_backoff_retries_total 0"));
}

#[test]
fn dedicated_udp_idle_shutdown_flushes_one_wouldblock_receive() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind dedicated socket");
    let metrics = RuntimeMetrics::new();
    let settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());

    super::udp::run_dedicated_std_udp_worker_after_one_receive_for_test(
        socket,
        active_example_zone(),
        settings,
        Arc::new(AtomicBool::new(true)),
        super::udp::DedicatedUdpAfterReceiveTestAction::CloseAdmission,
    )
    .expect("idle dedicated worker stops after its first receive attempt");

    let body = metrics_body(
        &ZoneStore::new(),
        &metrics,
        &CatalogManager::default(),
        &ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        ),
        0,
        false,
    );
    assert!(body.contains("borondns_udp_mmsg_receive_syscalls_total 0"));
    assert!(body.contains("borondns_udp_mmsg_receive_wouldblock_syscalls_total 1"));
    assert!(body.contains("borondns_udp_mmsg_received_datagrams_total 0"));
    assert_eq!(metrics.snapshot().udp_receive_batches, 0);
}

#[test]
fn dedicated_udp_post_receive_admission_close_flushes_exact_receive_stats() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind dedicated socket");
    let server_addr = socket.local_addr().expect("dedicated socket address");
    let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind client socket");
    let request = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    client
        .send_to(&request, server_addr)
        .expect("queue one request before dedicated receive");
    let metrics = RuntimeMetrics::new();
    let settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());

    super::udp::run_dedicated_std_udp_worker_after_one_receive_for_test(
        socket,
        active_example_zone(),
        settings,
        Arc::new(AtomicBool::new(true)),
        super::udp::DedicatedUdpAfterReceiveTestAction::CloseAdmission,
    )
    .expect("post-receive admission fence stops dedicated worker");

    let body = metrics_body(
        &ZoneStore::new(),
        &metrics,
        &CatalogManager::default(),
        &ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        ),
        0,
        false,
    );
    assert!(body.contains("borondns_udp_mmsg_receive_syscalls_total 1"));
    assert!(body.contains("borondns_udp_mmsg_receive_wouldblock_syscalls_total 0"));
    assert!(body.contains("borondns_udp_mmsg_received_datagrams_total 1"));
    assert_eq!(metrics.snapshot().udp_receive_batches, 0);
}

#[test]
fn dedicated_udp_post_receive_deadline_flushes_without_double_counting() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind dedicated socket");
    let server_addr = socket.local_addr().expect("dedicated socket address");
    let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind client socket");
    let request = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    client
        .send_to(&request, server_addr)
        .expect("queue one request before dedicated receive");
    let metrics = RuntimeMetrics::new();
    let settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());

    super::udp::run_dedicated_std_udp_worker_after_one_receive_for_test(
        socket,
        active_example_zone(),
        settings,
        Arc::new(AtomicBool::new(true)),
        super::udp::DedicatedUdpAfterReceiveTestAction::ExpireDeadline,
    )
    .expect("expired post-receive deadline stops dedicated worker");

    let body = metrics_body(
        &ZoneStore::new(),
        &metrics,
        &CatalogManager::default(),
        &ZoneRefreshRegistry::without_jitter(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(3600),
        ),
        0,
        false,
    );
    assert!(body.contains("borondns_udp_mmsg_receive_syscalls_total 1"));
    assert!(body.contains("borondns_udp_mmsg_receive_wouldblock_syscalls_total 0"));
    assert!(body.contains("borondns_udp_mmsg_received_datagrams_total 1"));
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.udp_receive_batches, 1);
    assert_eq!(snapshot.udp_received_datagrams, 1);
    assert_eq!(snapshot.udp_send_batches, 0);
    assert_eq!(snapshot.udp_sent_datagrams, 0);
}

#[tokio::test]
async fn udp_shutdown_drains_userspace_batch_blocked_in_send() {
    let packet_io = ControlledUdpPacketIo::new();
    let recv_started = packet_io.recv_started.clone();
    let release_recv = packet_io.release_recv.clone();
    let send_started = packet_io.send_started.clone();
    let release_send = packet_io.release_send.clone();
    let recv_calls = packet_io.recv_calls.clone();
    let sends = packet_io.sends.clone();
    let admission_open = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let metrics = RuntimeMetrics::new();
    let settings = udp_settings_for_test(metrics, RrlConfig::default());
    let mut server = tokio::spawn(serve_udp_packet_io_until(
        packet_io,
        active_example_zone(),
        settings,
        0,
        1,
        admission_open.clone(),
        async move { shutdown_rx.await.unwrap() },
    ));

    recv_started.notified().await;
    release_recv.notify_one();
    send_started.notified().await;
    admission_open.store(false, Ordering::Release);
    shutdown_tx
        .send(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(!server.is_finished(), "in-flight send must be drained");
    release_send.notify_one();

    tokio::time::timeout(std::time::Duration::from_secs(1), &mut server)
        .await
        .expect("UDP drain completes")
        .unwrap()
        .unwrap();
    assert_eq!(recv_calls.load(Ordering::Acquire), 1);
    assert_eq!(sends.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn udp_shutdown_deadline_cancels_blocked_inflight_send() {
    let packet_io = ControlledUdpPacketIo::new();
    let recv_started = packet_io.recv_started.clone();
    let release_recv = packet_io.release_recv.clone();
    let send_started = packet_io.send_started.clone();
    let sends = packet_io.sends.clone();
    let admission_open = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let settings = udp_settings_for_test(RuntimeMetrics::new(), RrlConfig::default());
    let server = tokio::spawn(serve_udp_packet_io_until(
        packet_io,
        active_example_zone(),
        settings,
        0,
        1,
        admission_open.clone(),
        async move { shutdown_rx.await.unwrap() },
    ));

    recv_started.notified().await;
    release_recv.notify_one();
    send_started.notified().await;
    admission_open.store(false, Ordering::Release);
    shutdown_tx
        .send(tokio::time::Instant::now() + std::time::Duration::from_millis(25))
        .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("UDP deadline is enforced")
        .unwrap()
        .unwrap();
    assert_eq!(sends.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn udp_shutdown_rejects_datagram_queued_after_admission_boundary() {
    let packet_io = ControlledUdpPacketIo::new();
    let recv_started = packet_io.recv_started.clone();
    let release_recv = packet_io.release_recv.clone();
    let recv_calls = packet_io.recv_calls.clone();
    let sends = packet_io.sends.clone();
    let admission_open = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let settings = udp_settings_for_test(RuntimeMetrics::new(), RrlConfig::default());
    let server = tokio::spawn(serve_udp_packet_io_until(
        packet_io,
        active_example_zone(),
        settings,
        0,
        1,
        admission_open.clone(),
        async move { shutdown_rx.await.unwrap() },
    ));

    recv_started.notified().await;
    admission_open.store(false, Ordering::Release);
    shutdown_tx
        .send(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .unwrap();
    release_recv.notify_one();

    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("UDP listener observes shutdown")
        .unwrap()
        .unwrap();
    assert_eq!(recv_calls.load(Ordering::Acquire), 1);
    assert_eq!(sends.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn std_udp_post_wake_rejects_datagram_after_admission_boundary() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let recv_waiting = Arc::new(Notify::new());
    let mut packet_io =
        StdUdpBatchIo::new(server_socket, 4).with_recv_waiting_signal(recv_waiting.clone());
    let admission_open = Arc::new(AtomicBool::new(true));
    let task_admission_open = admission_open.clone();
    let recv_task = tokio::spawn(async move {
        packet_io
            .recv_batch(&task_admission_open)
            .await
            .map(|batch| batch.len())
            .map_err(|error| error.kind())
    });

    recv_waiting.notified().await;
    admission_open.store(false, Ordering::Release);
    client_socket
        .send_to(b"after-boundary", server_addr)
        .await
        .unwrap();

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), recv_task)
        .await
        .expect("standard UDP receive completes")
        .expect("standard UDP receive task");
    assert_eq!(outcome, Err(std::io::ErrorKind::Interrupted));
}

#[tokio::test]
async fn dedicated_std_udp_uses_shared_admission_boundary_and_shutdown_deadline() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let metrics = RuntimeMetrics::new();
    let mut settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
    settings.udp_runtime = UdpRuntime::Dedicated;
    settings.udp_batch_size = 4;
    let admission_open = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_bound_udp_until(
        BoundUdpListener::Std {
            socket: server_socket,
            worker_id: 0,
            worker_count: 1,
            cpu_affinity: None,
        },
        active_example_zone(),
        settings,
        admission_open.clone(),
        async move { shutdown_rx.await.unwrap() },
    ));
    let request = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);

    client_socket.send_to(&request, server_addr).await.unwrap();
    let response = recv_udp_with_timeout(&client_socket, std::time::Duration::from_secs(1))
        .await
        .expect("dedicated worker response before shutdown");
    assert_eq!(Header::parse(&response).unwrap().ancount, 1);

    admission_open.store(false, Ordering::Release);
    client_socket.send_to(&request, server_addr).await.unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(100);
    shutdown_tx.send(deadline).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("dedicated UDP owner obeys shutdown deadline")
        .unwrap()
        .unwrap();
    assert!(
        recv_udp_with_timeout(&client_socket, std::time::Duration::from_millis(50))
            .await
            .is_none(),
        "datagram queued after admission closed must not be processed"
    );
    assert_eq!(metrics.snapshot().udp_received_datagrams, 1);
}

#[cfg(feature = "af-xdp")]
#[tokio::test]
async fn af_xdp_kernel_fallback_serves_passed_packets_once_and_obeys_shutdown() {
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_socket.local_addr().unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let metrics = RuntimeMetrics::new();
    let mut settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
    settings.udp_backend = UdpBackend::AfXdp;
    settings.udp_batch_size = 4;
    let admission_open = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_bound_udp_until(
        BoundUdpListener::AfXdpKernelFallback {
            socket: server_socket,
            worker_id: 1,
            worker_count: 2,
        },
        active_example_zone(),
        settings,
        admission_open.clone(),
        async move { shutdown_rx.await.unwrap() },
    ));
    let request = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);

    client_socket.send_to(&request, server_addr).await.unwrap();
    let response = recv_udp_with_timeout(&client_socket, std::time::Duration::from_secs(1))
        .await
        .expect("kernel fallback response before shutdown");
    assert_eq!(Header::parse(&response).unwrap().ancount, 1);
    assert!(
        recv_udp_with_timeout(&client_socket, std::time::Duration::from_millis(30))
            .await
            .is_none(),
        "one kernel-passed query must produce exactly one response"
    );

    admission_open.store(false, Ordering::Release);
    client_socket.send_to(&request, server_addr).await.unwrap();
    shutdown_tx
        .send(tokio::time::Instant::now() + std::time::Duration::from_millis(100))
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("kernel fallback obeys the shared UDP shutdown deadline")
        .unwrap()
        .unwrap();
    assert!(
        recv_udp_with_timeout(&client_socket, std::time::Duration::from_millis(50))
            .await
            .is_none(),
        "kernel-passed datagram queued after admission closed must not be processed"
    );
    assert_eq!(metrics.snapshot().udp_received_datagrams, 1);
}

#[tokio::test]
async fn std_udp_reuseport_binds_multiple_workers_to_one_effective_port() {
    let listeners = match bind_udp_listeners(
        "127.0.0.1:0".parse().unwrap(),
        UdpBackend::Std,
        &XdpConfig::default(),
        2,
        Some(&[0, 1]),
        None,
        None,
        None,
    )
    .await
    {
        Ok(listeners) => listeners,
        Err(RuntimeError::BindUdp { source, .. })
            if source.kind() == std::io::ErrorKind::Unsupported =>
        {
            return;
        }
        Err(error) => panic!("unexpected SO_REUSEPORT bind error: {error:?}"),
    };

    assert_eq!(listeners.len(), 2);
    let mut observed = Vec::new();
    for listener in listeners {
        match listener {
            BoundUdpListener::Std {
                socket,
                worker_id,
                worker_count,
                cpu_affinity,
            } => observed.push((
                socket.local_addr().unwrap(),
                worker_id,
                worker_count,
                cpu_affinity,
            )),
            #[cfg(feature = "af-xdp")]
            BoundUdpListener::AfXdp { .. } => panic!("standard backend must not bind AF_XDP"),
            #[cfg(feature = "af-xdp")]
            BoundUdpListener::AfXdpKernelFallback { .. } => {
                panic!("standard backend must not bind an AF_XDP kernel fallback")
            }
        }
    }

    assert_eq!(observed[0].0, observed[1].0);
    assert_eq!(observed[0].1, 0);
    assert_eq!(observed[1].1, 1);
    assert_eq!(observed[0].2, 2);
    assert_eq!(observed[1].2, 2);
    assert_eq!(observed[0].3, Some(0));
    assert_eq!(observed[1].3, Some(1));
}

#[tokio::test]
async fn udp_batch_listener_records_packet_io_metrics() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let mut settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
    settings.udp_batch_size = 4;
    let server = tokio::spawn(serve_udp(socket, zones, settings));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);

    for _ in 0..3 {
        client.send_to(&request, server_addr).await.unwrap();
    }
    for _ in 0..3 {
        let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
            .await
            .expect("UDP response");
        assert_eq!(Header::parse(&response).unwrap().ancount, 1);
    }
    server.abort();

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.udp_received_datagrams, 3);
    assert_eq!(snapshot.udp_sent_datagrams, 3);
    assert!((1..=3).contains(&snapshot.udp_receive_batches));
    assert!((1..=3).contains(&snapshot.udp_send_batches));
}

#[tokio::test]
async fn udp_af_xdp_backend_selection_has_clean_fallback_or_preflight_error() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut settings = udp_settings_for_test(metrics, RrlConfig::default());
    settings.udp_backend = UdpBackend::AfXdp;

    let error = serve_udp(socket, zones, settings)
        .await
        .expect_err("AF_XDP backend requires feature support and interface configuration");

    #[cfg(not(feature = "af-xdp"))]
    match error {
        RuntimeError::UdpBackendUnavailable { backend, reason } => {
            assert_eq!(backend, "af_xdp");
            assert!(reason.contains("without the af-xdp feature"));
        }
        other => panic!("unexpected AF_XDP backend error: {other:?}"),
    }
    #[cfg(feature = "af-xdp")]
    match error {
        RuntimeError::Udp(error) => {
            assert!(error.to_string().contains("xdp.interface"));
        }
        other => panic!("unexpected AF_XDP backend error: {other:?}"),
    }
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

    let lookup = zone.offline_oracle().lookup(
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
            udp_batch_size: 1,
            udp_backend: UdpBackend::Std,
            udp_runtime: UdpRuntime::Tokio,
            udp_idle_strategy: Default::default(),
            xdp: XdpConfig::default(),
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
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
            udp_batch_size: 1,
            udp_backend: UdpBackend::Std,
            udp_runtime: UdpRuntime::Tokio,
            udp_idle_strategy: Default::default(),
            xdp: XdpConfig::default(),
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
            notify_authority: NotifyAuthority::from_config_for_test(&config),
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
async fn udp_invalid_tsig_errors_are_subject_to_rrl() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
    let mut invalid = key
        .sign_request(
            &query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
            current_unix_time(),
            DEFAULT_TSIG_FUDGE_SECS,
        )
        .unwrap()
        .message;
    invalid[31] ^= 1;
    let mut settings = udp_settings_for_test(
        metrics.clone(),
        RrlConfig {
            positive_per_second: 0,
            error_per_second: 1,
            slip: 0,
            ..RrlConfig::default()
        },
    );
    settings.notify_authority = NotifyAuthority::from_config_for_test(&config);
    let peer = "192.0.2.1:53000".parse().unwrap();

    let first = handle_udp_datagram_with_prepared_hook(&invalid, peer, &zones, &settings, &|| {})
        .expect("initial burst response");
    assert_eq!(response_category(&first.response), Some(RrlCategory::Error));
    assert!(
        handle_udp_datagram_with_prepared_hook(&invalid, peer, &zones, &settings, &|| {}).is_none()
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.rrl_subject, 2);
    assert_eq!(snapshot.rrl_dropped, 1);
}

#[tokio::test]
async fn udp_tsig_does_not_apply_configured_padding_on_plaintext_transport() {
    let zones = active_example_zone();
    let metrics = RuntimeMetrics::new();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
    let mut unsigned_query =
        query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
    append_opt(&mut unsigned_query, 512, 0, &edns_option(12, &[]));
    let signed_query = key
        .sign_request(
            &unsigned_query,
            current_unix_time(),
            DEFAULT_TSIG_FUDGE_SECS,
        )
        .unwrap();
    let mut settings = udp_settings_for_test(metrics.clone(), RrlConfig::default());
    settings.notify_authority = NotifyAuthority::from_config_for_test(&config);
    settings.edns_padding_block_size = 512;
    let server = tokio::spawn(serve_udp(socket, zones, settings));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&signed_query.message, server_addr)
        .await
        .unwrap();
    let response = recv_udp_with_timeout(&client, std::time::Duration::from_secs(1))
        .await
        .expect("signed UDP response");
    server.abort();

    assert!(
        response.len() <= 512,
        "TSIG response length {} exceeds the negotiated ceiling",
        response.len()
    );
    let verified = key
        .verify_response(&response, &signed_query.mac, current_unix_time())
        .expect("un-padded TSIG response verifies");
    let header = Header::parse(&verified.message).unwrap();
    assert_eq!(header.flags & 0x0200, 0);
    assert_eq!(response_rcode(&verified.message, &header), Rcode::NoError as u16);
    assert_eq!(header.qdcount, 1);
    assert_eq!(header.ancount, 1);
    assert_eq!(header.nscount, 0);
    assert_eq!(header.arcount, 1);
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
