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
fn runtime_deadlines_preserve_valid_soa_durations_and_fallback_only_on_overflow() {
    let now = std::time::Instant::now();
    let maximum = std::time::Duration::from_secs(MAX_RUNTIME_DURATION_SECS);
    let two_years = std::time::Duration::from_secs(2 * MAX_RUNTIME_DURATION_SECS);
    assert_eq!(
        runtime_deadline(now, std::time::Duration::MAX).duration_since(now),
        maximum
    );
    assert_eq!(
        runtime_deadline(now, two_years).duration_since(now),
        two_years
    );

    let registry = ZoneRefreshRegistry::without_jitter_with_max(
        std::time::Duration::ZERO,
        std::time::Duration::MAX,
        std::time::Duration::ZERO,
        std::time::Duration::MAX,
        std::time::Duration::MAX,
    );
    let metadata = telemetry_zone_metadata(
        Some(1),
        Some(SoaTimers {
            refresh: two_years.as_secs() as u32,
            retry: two_years.as_secs() as u32,
            expire: two_years.as_secs() as u32,
            minimum: 1,
        }),
    );
    registry.record_loading_start_at(&metadata.origin, now);
    {
        let statuses = registry
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        let status = statuses
            .get(&metadata.origin_key.to_string())
            .expect("loading status");
        assert_eq!(
            status
                .next_loading_warning
                .expect("loading warning deadline")
                .duration_since(now),
            maximum
        );
    }

    registry.record_success_at_with_timestamp(&metadata, now, 1_700_000_000);
    {
        let statuses = registry
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        let status = statuses
            .get(&metadata.origin_key.to_string())
            .expect("active status");
        assert_eq!(
            status
                .next_refresh
                .expect("refresh deadline")
                .duration_since(now),
            two_years
        );
        assert_eq!(
            status.next_refresh_unix_secs,
            Some(1_700_000_000 + two_years.as_secs())
        );
        assert_eq!(
            status
                .expire_at
                .expect("expiry deadline")
                .duration_since(now),
            two_years
        );
    }

    registry.record_failure_at_with_timestamp(
        &metadata.origin,
        Some(metadata.clone()),
        now,
        1_700_000_000,
    );
    let statuses = registry
        .statuses
        .lock()
        .expect("zone refresh registry lock poisoned");
    assert_eq!(
        statuses[metadata.origin_key.as_ref()]
            .next_refresh
            .expect("retry deadline")
            .duration_since(now),
        two_years
    );
    assert_eq!(
        statuses[metadata.origin_key.as_ref()].next_refresh_unix_secs,
        Some(1_700_000_000 + two_years.as_secs())
    );
}

#[test]
fn maximum_zsm_positive_jitter_keeps_monotonic_and_unix_deadlines_consistent() {
    const JITTER_MULTIPLIER: u64 = 6_364_136_223_846_793_005;
    const JITTER_INCREMENT: u64 = 1_442_695_040_888_963_407;

    fn state_before_sample(sample: u64) -> u64 {
        let mut inverse = 1u64;
        for _ in 0..6 {
            inverse =
                inverse.wrapping_mul(2u64.wrapping_sub(JITTER_MULTIPLIER.wrapping_mul(inverse)));
        }
        sample.wrapping_sub(JITTER_INCREMENT).wrapping_mul(inverse)
    }

    let configured_max = std::time::Duration::from_secs(MAX_RUNTIME_DURATION_SECS);
    let spread = configured_max.as_millis() / 10;
    let positive_sample = (spread * 2) as u64;
    let jittered = jitter_interval(configured_max, positive_sample);
    assert!(jittered > configured_max);
    let now = std::time::Instant::now();
    let unix_secs = 1_700_000_000;
    let (expected_deadline, effective) = runtime_deadline_with_effective_duration(now, jittered);
    assert_eq!(effective, jittered);

    let registry = ZoneRefreshRegistry::new(
        configured_max,
        configured_max,
        configured_max,
        configured_max,
        configured_max,
    );
    let metadata = telemetry_zone_metadata(
        Some(1),
        Some(SoaTimers {
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 1,
        }),
    );
    *registry
        .jitter
        .state
        .lock()
        .expect("ZSM jitter state lock poisoned") = state_before_sample(positive_sample);
    registry.record_success_at_with_timestamp(&metadata, now, unix_secs);
    {
        let statuses = registry
            .statuses
            .lock()
            .expect("zone refresh registry lock poisoned");
        let status = &statuses[metadata.origin_key.as_ref()];
        assert_eq!(status.next_refresh, Some(expected_deadline));
        assert_eq!(
            status.next_refresh_unix_secs,
            Some(unix_secs + effective.as_secs())
        );
    }

    *registry
        .jitter
        .state
        .lock()
        .expect("ZSM jitter state lock poisoned") = state_before_sample(positive_sample);
    registry.record_failure_at_with_timestamp(
        &metadata.origin,
        Some(metadata.clone()),
        now,
        unix_secs,
    );
    let statuses = registry
        .statuses
        .lock()
        .expect("zone refresh registry lock poisoned");
    let status = &statuses[metadata.origin_key.as_ref()];
    assert_eq!(status.next_refresh, Some(expected_deadline));
    assert_eq!(
        status.next_refresh_unix_secs,
        Some(unix_secs + effective.as_secs())
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

    registry.record_success_at(&zone_metadata_for(&snapshot), now);
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
        Some(zone_metadata_for(&snapshot)),
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
fn refresh_registry_loading_elapsed_tracks_the_current_zone_lifecycle() {
    let registry = ZoneRefreshRegistry::without_jitter(
        Duration::from_secs(10),
        Duration::from_secs(60),
        Duration::from_secs(180),
    );
    let process_started = Instant::now();
    let origin = DomainName::from_absolute_str("late.test.").unwrap();
    let zone_added = process_started + Duration::from_secs(100);
    registry.record_loading_start_at(&origin, zone_added);
    let loading_seconds = |now| {
        registry.snapshots_by_zone_at(now)[&origin.canonical_key()].loading_seconds
    };
    assert_eq!(loading_seconds(zone_added + Duration::from_secs(5)), 5);
    // Re-observing the same loading zone must not reset its interval.
    registry.record_loading_start_at(&origin, zone_added + Duration::from_secs(3));
    assert_eq!(loading_seconds(zone_added + Duration::from_secs(5)), 5);
    assert_eq!(loading_seconds(process_started), 0);

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
    registry.record_success_at_with_timestamp(
        &zone_metadata_for(&snapshot),
        zone_added + Duration::from_secs(5),
        1_700_000_000,
    );
    assert_eq!(loading_seconds(zone_added + Duration::from_secs(10)), 0);
    registry.remove_zone(&origin);
    let readded = zone_added + Duration::from_secs(50);
    registry.record_loading_start_at(&origin, readded);
    assert_eq!(loading_seconds(readded + Duration::from_secs(2)), 2);
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

    registry.record_success_at_with_timestamp(&zone_metadata_for(&snapshot), now, 1_700_000_000);
    let status = registry
        .snapshots_by_zone()
        .remove(&origin.canonical_key())
        .expect("zone refresh status");
    assert_eq!(status.last_success_unix_secs, Some(1_700_000_000));
    assert_eq!(status.next_refresh_unix_secs, Some(1_700_003_600));
    assert_eq!(status.failures_since_success, 0);

    registry.record_failure_at_with_timestamp(
        &origin,
        Some(zone_metadata_for(&snapshot)),
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
        &zone_metadata_for(&snapshot),
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
    let snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_timers(10_000, 10_000, 86_400, 300)],
        )],
    );

    registry.record_success_at_with_timestamp(&zone_metadata_for(&snapshot), now, 1_700_000_000);
    let status = registry
        .snapshots_by_zone()
        .remove(&origin.canonical_key())
        .expect("zone refresh status");
    assert_eq!(status.next_refresh_unix_secs, Some(1_700_001_000));

    registry.record_failure_at_with_timestamp(
        &origin,
        Some(zone_metadata_for(&snapshot)),
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
fn one_second_soa_warns_without_extending_expiry_or_spamming_refreshes() {
    let registry = ZoneRefreshRegistry::without_jitter_with_max(
        Duration::from_secs(60), Duration::from_secs(86_400),
        Duration::from_secs(60), Duration::from_secs(3600), Duration::from_secs(300),
    );
    let origin = DomainName::from_absolute_str("tiny-expiry.test.").unwrap();
    let snapshot = ZoneSnapshot::active(origin.clone(), Some(1), vec![Rrset::new(
        origin.clone(), RecordType::Soa as u16, 1, 86400,
        vec![soa_rdata_with_timers(1, 1, 1, 3600)],
    )]);
    let zones = ZoneStore::new();
    zones.insert_snapshot(snapshot.clone());
    let now = Instant::now();
    let captured = CapturedEvents::new();
    let _guard = tracing::subscriber::set_default(CapturingSubscriber::new(captured.clone()));
    registry.record_success_at(&zone_metadata_for(&snapshot), now);
    assert!(captured.contains_all(&[
        "code=\"soa_timers_clamped\"", "soa_refresh_secs=1", "soa_retry_secs=1",
        "effective_refresh_secs=60", "effective_retry_secs=60", "soa_expire_secs=1",
    ]));
    assert!(captured.contains_all(&[
        "code=\"soa_expiry_before_refresh_or_retry\"", "zone=tiny-expiry.test.",
        "SOA expiry may precede the next refresh or retry", "expiry is not extended",
    ]));
    let count = captured.lines.lock().unwrap().len();
    registry.record_success_at(&zone_metadata_for(&snapshot), now);
    assert_eq!(captured.lines.lock().unwrap().len(), count, "unchanged timers must not repeat warnings");
    assert!(registry.expire_due_zones(&zones, now + Duration::from_millis(999)).is_empty());
    assert_eq!(registry.expire_due_zones(&zones, now + Duration::from_secs(1)), vec![origin.clone()]);
    assert_eq!(zones.exact_zone_control_metadata(&origin).unwrap().state, ZoneState::Expired);
    assert!(captured.contains_all(&["event=\"zone_expired\"", "soa_expire_secs=1",
        "since_last_attempt_completion_secs=1", "retry_in_secs=59", "failures_since_success=0", "last_failure=\"none\""]));
    assert!(registry.start_due_refreshes(now + Duration::from_secs(59)).is_empty());
    assert_eq!(registry.start_due_refreshes(now + Duration::from_secs(60)), vec![origin]);
}

#[test]
fn expiry_log_distinguishes_last_success_from_a_recent_failed_attempt() {
    let registry = ZoneRefreshRegistry::without_jitter(Duration::from_secs(1), Duration::from_secs(1), Duration::from_secs(1));
    let origin = DomainName::from_absolute_str("expiry-log.test.").unwrap();
    let snapshot = ZoneSnapshot::active(origin.clone(), Some(1), vec![Rrset::new(
        origin.clone(), RecordType::Soa as u16, 1, 3600, vec![soa_rdata_with_timers(2, 1, 60, 300)],
    )]);
    let metadata = zone_metadata_for(&snapshot);
    let zones = ZoneStore::new();
    zones.insert_snapshot(snapshot);
    let now = Instant::now();
    registry.record_success_at_with_timestamp(&metadata, now, 1_700_000_000);
    registry.record_failure_at_with_timestamp_and_cause(&origin, Some(metadata),
        Some("test primary unreachable".to_owned()), now + Duration::from_secs(59), 1_700_000_059);
    let captured = CapturedEvents::new();
    let _guard = tracing::subscriber::set_default(CapturingSubscriber::new(captured.clone()));
    registry.expire_due_zones(&zones, now + Duration::from_secs(60));
    assert!(captured.contains_all(&["event=\"zone_expired\"", "last_success_unix_seconds=1700000000",
        "since_last_attempt_completion_secs=1", "failures_since_success=1", "last_failure=\"test primary unreachable\""]));
}

#[test]
fn soa_timer_warnings_cover_jitter_boundaries_and_timer_changes() {
    let mut registry = ZoneRefreshRegistry::without_jitter_with_max(
        Duration::from_secs(60), Duration::from_secs(86_400),
        Duration::from_secs(60), Duration::from_secs(3600), Duration::from_secs(300),
    );
    registry.jitter = crate::Jitter::new(42);
    let origin = DomainName::from_absolute_str("timer-boundary.test.").unwrap();
    let make = |refresh, retry, expire| ZoneSnapshot::active(origin.clone(), Some(1), vec![Rrset::new(
        origin.clone(), RecordType::Soa as u16, 1, 3600, vec![soa_rdata_with_timers(refresh, retry, expire, 300)],
    )]);
    let captured = CapturedEvents::new();
    let _guard = tracing::subscriber::set_default(CapturingSubscriber::new(captured.clone()));
    let now = Instant::now();
    // 60s + 10% jitter + 1s scheduler granularity; wire values are unchanged.
    registry.record_success_at(&zone_metadata_for(&make(60, 60, 68)), now);
    assert!(captured.lines.lock().unwrap().is_empty());
    for (refresh, retry, expire) in [(60, 60, 67), (60, 100, 110), (1, 1, 1)] {
        let count = captured.lines.lock().unwrap().len();
        registry.record_success_at(&zone_metadata_for(&make(refresh, retry, expire)), now);
        assert!(captured.lines.lock().unwrap().len() > count);
    }
    assert!(captured.contains_all(&["code=\"soa_expiry_before_refresh_or_retry\"", "refresh_upper_ms=67000", "retry_upper_ms=111000"]));
    // A corrected zone warns again if its timers later regress.
    registry.record_success_at(&zone_metadata_for(&make(3600, 600, 604800)), now);
    let count = captured.lines.lock().unwrap().len();
    registry.record_success_at(&zone_metadata_for(&make(1, 1, 1)), now);
    assert_eq!(captured.lines.lock().unwrap().len(), count + 2);
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
    let snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin,
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_timers(900, 1_500, 86_400, 300)],
        )],
    );
    let captured = CapturedEvents::new();
    let subscriber = CapturingSubscriber::new(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    registry.record_success_at_with_timestamp(&zone_metadata_for(&snapshot), now, 1_700_000_000);

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
    let warnings = registry.loading_warnings_due(&zones, now + std::time::Duration::from_secs(300));
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

    let warnings = registry.loading_warnings_due(&zones, now + std::time::Duration::from_secs(600));
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

    registry.record_success_at(&zone_metadata_for(&snapshot), now);
    registry.record_failure_at_with_timestamp_and_cause(
        &origin,
        Some(zone_metadata_for(&snapshot)),
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
    let zones = ZoneStore::new();

    registry.record_success_at(&zone_metadata_for(&snapshot), now);
    zones.insert_snapshot(snapshot);
    assert!(
        registry
            .expire_due_zones(&zones, now + std::time::Duration::from_secs(604799))
            .is_empty()
    );
    assert_eq!(
        registry.expire_due_zones(&zones, now + std::time::Duration::from_secs(604800)),
        vec![origin]
    );
    assert!(
        registry
            .expire_due_zones(&zones, now + std::time::Duration::from_secs(604801))
            .is_empty()
    );
}

#[test]
fn refresh_registry_expires_zone_while_refresh_is_in_progress() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("in-progress.example.test.").unwrap();
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
    let zones = ZoneStore::new();
    registry.record_success_at(&zone_metadata_for(&snapshot), now);
    zones.insert_snapshot(snapshot);
    assert_eq!(
        registry.start_due_refreshes(now + std::time::Duration::from_secs(3600)),
        vec![origin.clone()]
    );

    assert_eq!(
        registry.expire_due_zones(&zones, now + std::time::Duration::from_secs(604_800)),
        vec![origin.clone()]
    );
    assert_eq!(
        zones
            .exact_zone_control_metadata(&origin)
            .expect("expired zone remains registered")
            .state,
        ZoneState::Expired
    );
}

#[test]
fn expiration_candidate_removed_before_attempt_does_not_recreate_refresh_status() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("removed.example.test.").unwrap();
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
    let zones = ZoneStore::new();
    registry.record_success_at(&zone_metadata_for(&snapshot), now);
    zones.insert_snapshot(snapshot);

    let mut removed = false;
    let expired = registry.expire_due_zones_with_hooks(
        &zones,
        now + std::time::Duration::from_secs(604_800),
        |_| {
            if !removed {
                removed = true;
                registry.remove_zone(&origin);
                assert!(zones.remove_zone(&origin));
            }
        },
        |_| panic!("a removed expiration candidate must not reach publication"),
    );

    assert!(expired.is_empty());
    assert!(!zones.contains_exact_zone_for_control(&origin));
    assert!(
        !registry
            .statuses
            .lock()
            .unwrap()
            .contains_key(&origin.canonical_key()),
        "expiration must not recreate deprovisioned refresh state"
    );
}

#[test]
fn stale_expiration_cannot_expire_remove_readd_replacement() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let now = std::time::Instant::now();
    let origin = DomainName::from_absolute_str("replacement.example.test.").unwrap();
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
    let zones = ZoneStore::new();
    registry.record_success_at(&zone_metadata_for(&snapshot), now);
    zones.insert_snapshot(snapshot);

    let mut replaced = false;
    let expired = registry.expire_due_zones_with_hooks(
        &zones,
        now + std::time::Duration::from_secs(604_800),
        |_| {},
        |_| {
            if !replaced {
                replaced = true;
                registry.remove_zone(&origin);
                assert!(zones.remove_zone(&origin));
                registry.record_loading_start_at(&origin, now);
                zones.insert_loading(origin.clone());
            }
        },
    );

    assert!(expired.is_empty());
    assert_eq!(
        zones
            .exact_zone_control_metadata(&origin)
            .expect("replacement remains installed")
            .state,
        ZoneState::Loading
    );
    let statuses = registry.statuses.lock().unwrap();
    let replacement = statuses
        .get(&origin.canonical_key())
        .expect("replacement refresh status remains installed");
    assert!(!replacement.expired);
    assert!(!replacement.in_progress);
}

#[tokio::test]
async fn paused_same_zone_attempt_cannot_publish_after_a_newer_refresh() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let zones = ZoneStore::new();
    zones.insert_loading(origin.clone());
    registry.record_loading_start(&origin);

    let mut older = registry.begin_attempt(&origin).await;
    assert!(
        registry.try_begin_attempt(&origin).is_none(),
        "same-zone ownership must reject a concurrent publication attempt"
    );
    let (newer_acquired_tx, mut newer_acquired_rx) = oneshot::channel();
    let newer_registry = registry.clone();
    let newer_origin = origin.clone();
    let newer_zones = zones.clone();
    let newer = tokio::spawn(async move {
        let mut attempt = newer_registry.begin_attempt(&newer_origin).await;
        let _ = newer_acquired_tx.send(());
        let snapshot = ZoneSnapshot::active(
            newer_origin.clone(),
            Some(3),
            vec![Rrset::new(
                newer_origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata_with_serial(3)],
            )],
        );
        let metadata = zone_metadata_for(&snapshot);
        newer_zones.insert_snapshot(snapshot);
        attempt.record_success(&metadata);
        attempt.finish();
    });

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut newer_acquired_rx)
            .await
            .is_err(),
        "newer refresh must remain paused behind the older zone owner"
    );

    let older_snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(2),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(2)],
        )],
    );
    let older_metadata = zone_metadata_for(&older_snapshot);
    zones.insert_snapshot(older_snapshot);
    older.record_success(&older_metadata);
    older.finish();

    newer_acquired_rx
        .await
        .expect("newer refresh acquires ownership after older completion");
    newer.await.unwrap();
    assert_eq!(
        zones
            .exact_zone_control_metadata(&origin)
            .expect("newest publication remains active")
            .serial,
        Some(3)
    );
}

#[tokio::test]
async fn expiry_during_paused_refresh_is_reactivated_by_valid_publication() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let zones = ZoneStore::new();
    let base = std::time::Instant::now();
    let old_snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(1)],
        )],
    );
    registry.record_success_at(&zone_metadata_for(&old_snapshot), base);
    zones.insert_snapshot(old_snapshot);

    let old_expiry = base + std::time::Duration::from_secs(604_800);
    let mut refresh = registry.begin_attempt(&origin).await;
    assert_eq!(
        registry.expire_due_zones(&zones, old_expiry),
        vec![origin.clone()]
    );
    assert_eq!(
        zones
            .exact_zone_control_metadata(&origin)
            .expect("expired zone remains registered")
            .state,
        ZoneState::Expired
    );

    let new_snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(2),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(2)],
        )],
    );
    let new_metadata = zone_metadata_for(&new_snapshot);
    zones.insert_snapshot(new_snapshot);
    refresh.record_success_at(
        &new_metadata,
        base + std::time::Duration::from_secs(604_799),
        604_799,
    );
    refresh.finish();

    assert!(registry.expire_due_zones(&zones, old_expiry).is_empty());
    let metadata = zones
        .exact_zone_control_metadata(&origin)
        .expect("successful refresh remains published");
    assert_eq!(metadata.state, ZoneState::Active);
    assert_eq!(metadata.serial, Some(2));
}

#[tokio::test]
async fn panicked_zone_owner_is_immediately_rescheduled() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    registry.record_loading_start(&origin);
    let panic_registry = registry.clone();
    let panic_origin = origin.clone();

    let task = tokio::spawn(async move {
        let _attempt = panic_registry.begin_attempt(&panic_origin).await;
        panic!("deterministic transfer task panic");
    });
    assert!(task.await.expect_err("task must panic").is_panic());

    assert_eq!(
        registry.start_due_refreshes(std::time::Instant::now()),
        vec![origin]
    );
}

#[tokio::test]
async fn removed_zone_rejects_paused_attempt_success_without_requeue() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let origin = DomainName::from_absolute_str("removed-success.test.").unwrap();
    registry.record_loading_start(&origin);
    let mut attempt = registry.begin_attempt(&origin).await;
    let snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(2),
        vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(2)],
        )],
    );
    let metadata = zone_metadata_for(&snapshot);

    registry.remove_zone(&origin);
    assert!(!attempt.record_success(&metadata));
    attempt.finish();
    assert!(
        !registry
            .snapshots_by_zone()
            .contains_key(&origin.canonical_key())
    );
    assert!(
        registry
            .start_due_refreshes(std::time::Instant::now())
            .is_empty()
    );
}

#[tokio::test]
async fn removed_zone_rejects_paused_attempt_failure_without_requeue() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let origin = DomainName::from_absolute_str("removed-failure.test.").unwrap();
    registry.record_loading_start(&origin);
    let attempt = registry.begin_attempt(&origin).await;

    registry.remove_zone(&origin);
    attempt.record_failure(None, Some("paused failure".to_owned()));
    assert!(
        !registry
            .snapshots_by_zone()
            .contains_key(&origin.canonical_key())
    );
    assert!(
        registry
            .start_due_refreshes(std::time::Instant::now())
            .is_empty()
    );
}

#[tokio::test]
async fn stale_queued_refresh_cannot_reregister_removed_zone() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let origin = DomainName::from_absolute_str("stale-queued.test.").unwrap();
    registry.record_loading_start(&origin);
    registry.remove_zone(&origin);

    assert!(registry.begin_registered_attempt(&origin).await.is_none());
    assert!(
        !registry
            .snapshots_by_zone()
            .contains_key(&origin.canonical_key())
    );
    assert!(
        registry
            .start_due_refreshes(std::time::Instant::now())
            .is_empty()
    );
}

#[tokio::test]
async fn old_attempt_cannot_mutate_readded_zone_generation() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let origin = DomainName::from_absolute_str("reassigned.test.").unwrap();
    registry.record_loading_start(&origin);
    let mut old_attempt = registry.begin_attempt(&origin).await;
    let snapshot = ZoneSnapshot::active(origin.clone(), Some(9), Vec::new());
    let metadata = zone_metadata_for(&snapshot);

    registry.remove_zone(&origin);
    registry.record_loading_start(&origin);
    assert!(!old_attempt.record_success(&metadata));
    old_attempt.finish();

    assert!(
        registry
            .snapshots_by_zone()
            .contains_key(&origin.canonical_key())
    );
    assert!(
        registry
            .start_due_refreshes(std::time::Instant::now())
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

#[test]
fn ixfr_cooldown_clamps_extreme_deadline_without_panicking() {
    let registry = IxfrCooldownRegistry::new(std::time::Duration::MAX);
    let zone = DomainName::from_absolute_str("extreme.test.").unwrap();
    let primary = "192.0.2.53:53".parse().unwrap();
    let now = std::time::Instant::now();

    registry.record_unsupported_at(&zone, primary, now);
    let deadline = registry
        .disabled_until
        .lock()
        .expect("IXFR cooldown registry lock poisoned")[&IxfrCooldownKey::new(&zone, primary, 0)];
    assert_eq!(
        deadline.duration_since(now),
        std::time::Duration::from_secs(MAX_RUNTIME_DURATION_SECS)
    );
}

#[test]
fn ixfr_cooldown_registry_retains_all_live_keys_and_purges_removed_or_expired_zones() {
    let registry = IxfrCooldownRegistry::new(std::time::Duration::from_secs(60));
    let now = std::time::Instant::now();
    let primary: std::net::SocketAddr = "192.0.2.53:53".parse().unwrap();
    let count = 16 * 1024 + 4096;

    for index in 0..count {
        let zone = DomainName::from_absolute_str(&format!("member-{index}.catalog.test.")).unwrap();
        registry.record_unsupported_at(&zone, primary, now);
    }

    assert_eq!(
        registry
            .disabled_until
            .lock()
            .expect("IXFR cooldown registry lock poisoned")
            .len(),
        count
    );

    let first = DomainName::from_absolute_str("member-0.catalog.test.").unwrap();
    assert!(registry.is_disabled_at(&first, primary, now));
    for index in 0..4096 {
        let removed =
            DomainName::from_absolute_str(&format!("member-{index}.catalog.test.")).unwrap();
        registry.remove_zone(&removed);
    }
    assert!(!registry.is_disabled_at(&first, primary, now));
    assert_eq!(
        registry
            .disabled_until
            .lock()
            .expect("IXFR cooldown registry lock poisoned")
            .len(),
        count - 4096
    );

    registry.prune_expired_at(now + std::time::Duration::from_secs(60));

    assert_eq!(
        registry
            .disabled_until
            .lock()
            .expect("IXFR cooldown registry lock poisoned")
            .len(),
        0
    );
    let last =
        DomainName::from_absolute_str(&format!("member-{}.catalog.test.", count - 1)).unwrap();
    assert!(!registry.is_disabled_at(&last, primary, now));
    assert!(
        !registry
            .disabled_until
            .lock()
            .expect("IXFR cooldown registry lock poisoned")
            .contains_key(&IxfrCooldownKey::new(&last, primary, 0))
    );
}

#[test]
fn ixfr_bulk_catalog_cleanup_visits_each_live_key_once_at_20k_scale() {
    let registry = IxfrCooldownRegistry::new(std::time::Duration::from_secs(60));
    let now = std::time::Instant::now();
    let primary: std::net::SocketAddr = "192.0.2.53:53".parse().unwrap();
    let count = 20_000usize;
    let zones = (0..count)
        .map(|index| DomainName::from_absolute_str(&format!("bulk-{index}.catalog.test.")).unwrap())
        .collect::<Vec<_>>();
    for zone in &zones {
        registry.record_unsupported_at(zone, primary, now);
    }
    let removed_zones = zones.iter().step_by(2).cloned().collect::<Vec<_>>();
    let changed_plans = zones
        .iter()
        .skip(1)
        .step_by(2)
        .cloned()
        .map(|zone| (zone, 1))
        .collect::<Vec<_>>();

    let started = std::time::Instant::now();
    let (visited, removed) = registry.reconcile_catalog_generations(&removed_zones, &changed_plans);
    let elapsed = started.elapsed();

    assert_eq!(visited, count, "bulk cleanup performs one registry scan");
    assert_eq!(removed, count);
    assert!(registry.disabled_until.lock().unwrap().is_empty());
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "20k-key bulk cleanup unexpectedly took {elapsed:?}"
    );
}

#[test]
fn ixfr_retained_plan_generation_churn_keeps_one_live_generation() {
    let registry = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
    let now = std::time::Instant::now();
    let zone = DomainName::from_absolute_str("churn.catalog.test.").unwrap();
    let primary: std::net::SocketAddr = "192.0.2.53:53".parse().unwrap();

    for generation in 1..=20_000u64 {
        registry.record_unsupported_for_generation_at(&zone, primary, generation, now);
        let (visited, removed) = registry.retain_zone_generation(&zone, generation);
        assert!(visited <= 2);
        assert!(removed <= 1);
        assert_eq!(registry.disabled_until.lock().unwrap().len(), 1);
        assert!(registry.is_disabled_for_generation_at(&zone, primary, generation, now,));
    }
}

#[test]
fn refresh_ownership_registry_prunes_only_dead_catalog_churn_keys() {
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    let live = DomainName::from_absolute_str("live.catalog.test.").unwrap();
    let live_attempt = registry
        .try_begin_attempt(&live)
        .expect("first live attempt acquires ownership");
    registry.remove_zone(&live);

    for index in 0..4096 {
        let zone = DomainName::from_absolute_str(&format!("member-{index}.catalog.test.")).unwrap();
        let attempt = registry
            .try_begin_attempt(&zone)
            .expect("unique churn zone acquires ownership");
        registry.remove_zone(&zone);
        attempt.finish();
    }

    let ownerships = registry
        .ownerships
        .lock()
        .expect("zone refresh ownership map lock poisoned");
    assert!(
        ownerships.len() <= RUNTIME_REGISTRY_PRUNE_INTERVAL as usize,
        "dead weak ownerships are pruned on a bounded cadence"
    );
    assert!(
        ownerships
            .get(&live.canonical_key())
            .and_then(|ownership| ownership.upgrade())
            .is_some(),
        "pruning must retain a mutex held by a live attempt"
    );
    drop(ownerships);
    assert!(
        registry.try_begin_attempt(&live).is_none(),
        "retained live ownership continues to serialize the zone"
    );
    live_attempt.finish();
}

#[tokio::test]
async fn notify_refresh_worker_publishes_requested_refresh() {
    let primary = spawn_ixfr_mode2_primary_with_serial(2).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
    tx.send(RefreshRequest::new(
        apex,
        Some(2),
        super::RefreshReason::Notify,
    ))
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
            notify_authority: NotifyAuthority::from_config_for_test(&config),
            refresh_tx: mpsc::channel(1).0.downgrade(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
        },
        IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
        metrics.clone(),
        RefreshWorkerSettings {
            axfr_timeout: std::time::Duration::from_secs(5),
            ixfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            transfer_limit: Arc::new(tokio::sync::Semaphore::new(4)),
            max_resident_transfer_tasks: 16,
            telemetry: ControlPlaneTelemetryClient::disabled(),
            admission: RefreshAdmission::new(),
            zone_persistence: None,
        },
    )
    .await
    .unwrap();

    let snapshot = zones
        .exact_snapshot_for_transfer(&DomainName::from_absolute_str("example.test.").unwrap())
        .expect("published refreshed snapshot");
    assert_eq!(snapshot.metadata().state, ZoneState::Active);
    assert_eq!(snapshot.metadata().serial, Some(2));
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
async fn notify_refresh_worker_does_not_accept_serial_hint_as_confirmation() {
    let (primary, peer_rx) = spawn_soa_primary_recording_peer(2).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
        Some(2),
        vec![Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(2)],
        )],
    ));
    let (tx, rx) = mpsc::channel(1);
    tx.send(RefreshRequest::new(
        apex,
        Some(2),
        super::RefreshReason::Notify,
    ))
    .await
    .unwrap();
    drop(tx);

    serve_refresh_requests(
        rx,
        zones,
        CatalogRuntime {
            manager: CatalogManager::from_config(&config),
            transfer_plan,
            refresh_registry: ZoneRefreshRegistry::without_jitter(
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
            ),
            notify_authority: NotifyAuthority::from_config_for_test(&config),
            refresh_tx: mpsc::channel(1).0.downgrade(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
        },
        IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
        RuntimeMetrics::new(),
        RefreshWorkerSettings {
            axfr_timeout: std::time::Duration::from_secs(5),
            ixfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            transfer_limit: Arc::new(tokio::sync::Semaphore::new(4)),
            max_resident_transfer_tasks: 16,
            telemetry: ControlPlaneTelemetryClient::disabled(),
            admission: RefreshAdmission::new(),
            zone_persistence: None,
        },
    )
    .await
    .unwrap();

    tokio::time::timeout(std::time::Duration::from_millis(250), peer_rx)
        .await
        .expect("RFC 1996 requires the worker to validate the NOTIFY hint")
        .expect("SOA primary should observe a query");
}

#[tokio::test]
async fn notify_refresh_worker_honors_transfer_concurrency_limit() {
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let alpha_primary = spawn_barrier_ixfr_mode2_primary("alpha.test.", barrier.clone()).await;
    let beta_primary = spawn_barrier_ixfr_mode2_primary("beta.test.", barrier.clone()).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
        tx.send(RefreshRequest::new(
            DomainName::from_absolute_str(zone).unwrap(),
            Some(2),
            super::RefreshReason::Notify,
        ))
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
            notify_authority: NotifyAuthority::from_config_for_test(&config),
            refresh_tx: mpsc::channel(1).0.downgrade(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
        },
        IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
        RuntimeMetrics::new(),
        RefreshWorkerSettings {
            axfr_timeout: std::time::Duration::from_secs(5),
            ixfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            transfer_limit: Arc::new(tokio::sync::Semaphore::new(2)),
            max_resident_transfer_tasks: 8,
            telemetry: ControlPlaneTelemetryClient::disabled(),
            admission: RefreshAdmission::new(),
            zone_persistence: None,
        },
    ));

    tokio::time::timeout(std::time::Duration::from_secs(1), barrier.wait())
        .await
        .expect("both refresh transfers should start before either completes");
    worker.await.unwrap().unwrap();

    assert_eq!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("alpha.test.").unwrap())
            .expect("alpha zone")
            .metadata()
            .serial,
        Some(2)
    );
    assert_eq!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("beta.test.").unwrap())
            .expect("beta zone")
            .metadata()
            .serial,
        Some(2)
    );
}

#[tokio::test]
async fn notify_refresh_worker_drains_queue_while_transfer_permits_are_saturated() {
    let catalog_primary =
        spawn_signed_catalog_axfr_primary_with_member("catalog.example.", "member.example.", 2)
            .await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[tsig_keys]]
                name = "catalog-key."
                algorithm = "hmac-sha256"
                secret = "dG9wc2VjcmV0"

                [[catalog_zones]]
                name = "catalog.example."
                catalog_primaries = ["{catalog_primary}"]
                member_primaries = ["127.0.0.1:9"]
                catalog_tsig_key = "catalog-key."
                member_tsig_key = "catalog-key."

                [[zones]]
                name = "filler.test."
                primaries = ["127.0.0.1:9"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let zones = ZoneStore::new();
    let catalog_origin = DomainName::from_absolute_str("catalog.example.").unwrap();
    let filler_origin = DomainName::from_absolute_str("filler.test.").unwrap();
    let member_origin = DomainName::from_absolute_str("member.example.").unwrap();
    zones.insert_loading_hidden(catalog_origin.clone());
    zones.insert_loading(filler_origin.clone());
    let (tx, rx) = mpsc::channel(1);
    tx.send(RefreshRequest::new(
        catalog_origin,
        Some(2),
        super::RefreshReason::Notify,
    ))
    .await
    .unwrap();

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
            notify_authority: NotifyAuthority::from_config_for_test(&config),
            refresh_tx: mpsc::channel(1).0.downgrade(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
        },
        IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
        RuntimeMetrics::new(),
        RefreshWorkerSettings {
            axfr_timeout: std::time::Duration::from_millis(100),
            ixfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(50),
            transfer_limit: Arc::new(tokio::sync::Semaphore::new(1)),
            max_resident_transfer_tasks: 1,
            telemetry: ControlPlaneTelemetryClient::disabled(),
            admission: RefreshAdmission::new(),
            zone_persistence: None,
        },
    ));

    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        tx.send(RefreshRequest::new(
            filler_origin.clone(),
            Some(2),
            super::RefreshReason::Notify,
        )),
    )
    .await
    .expect("refresh worker should drain the bounded queue before transfer permits free")
    .expect("first filler refresh request queued");
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        tx.send(RefreshRequest::new(
            filler_origin,
            Some(3),
            super::RefreshReason::Notify,
        )),
    )
    .await
    .expect("refresh worker should drain a full queue while a catalog apply may enqueue")
    .expect("second filler refresh request queued");

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if zones.contains_exact_zone_for_control(&member_origin) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("catalog refresh should stage the member before enqueueing its refresh");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(tx);

    tokio::time::timeout(std::time::Duration::from_secs(3), worker)
        .await
        .expect("refresh worker should not deadlock on catalog member enqueue")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn closed_refresh_admission_discards_buffered_work_without_starting_a_transfer() {
    let config = ServerConfig::from_toml_str(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [[zones]]
            name = "shutdown-pending.test."
            primaries = ["192.0.2.53:53"]
        "#,
    )
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let origin = DomainName::from_absolute_str("shutdown-pending.test.").unwrap();
    let plan = transfer_plan.get(&origin).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(origin.clone());
    let registry = ZoneRefreshRegistry::without_jitter(
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    registry.record_loading_start(&origin);
    registry
        .statuses
        .lock()
        .expect("refresh status lock")
        .get_mut(&origin.canonical_key())
        .expect("loading refresh status")
        .in_progress = true;

    let (tx, rx) = mpsc::channel(1);
    let mut request = RefreshRequest::new(origin.clone(), Some(2), super::RefreshReason::Notify)
        .with_plan_generation(&plan);
    request.retry_after_queue_drop = Some(super::RefreshReason::Notify);
    tx.send(request)
        .await
        .expect("buffer refresh before shutdown");
    let admission = RefreshAdmission::new();
    admission.close();
    let metrics = RuntimeMetrics::new();

    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        serve_refresh_requests(
            rx,
            zones,
            CatalogRuntime {
                manager: CatalogManager::from_config(&config),
                transfer_plan,
                refresh_registry: registry.clone(),
                notify_authority: NotifyAuthority::from_config_for_test(&config),
                refresh_tx: mpsc::channel(1).0.downgrade(),
                secrets: SecretManager::from_config(&config)
                    .expect("test configuration loads secret snapshot"),
            },
            IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600)),
            metrics.clone(),
            RefreshWorkerSettings {
                axfr_timeout: std::time::Duration::from_secs(1),
                ixfr_timeout: std::time::Duration::from_secs(1),
                tcp_connect_timeout: std::time::Duration::from_secs(1),
                transfer_limit: Arc::new(tokio::sync::Semaphore::new(1)),
                max_resident_transfer_tasks: 1,
                telemetry: ControlPlaneTelemetryClient::disabled(),
                admission,
                zone_persistence: None,
            },
        ),
    )
    .await
    .expect("closed admission wakes and drains refresh worker")
    .expect("refresh worker exits cleanly");

    assert_eq!(metrics.snapshot().axfr_started, 0);
    assert_eq!(metrics.snapshot().ixfr_started, 0);
    let statuses = registry.statuses.lock().expect("refresh status lock");
    let status = statuses
        .get(&origin.canonical_key())
        .expect("refresh status retained for a future process start");
    assert!(!status.in_progress);
    assert!(status.next_refresh.is_some());
}

#[tokio::test]
async fn refresh_skips_axfr_when_soa_poll_confirms_current_serial() {
    let (primary, peer_rx) = spawn_soa_primary_recording_peer(2).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
    let snapshot = ZoneSnapshot::active(
        apex.clone(),
        Some(2),
        vec![Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(2)],
        )],
    );
    let cache = std::env::temp_dir().join(format!(
        "borondns-current-freshness-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let persistence = ZonePersistence::new(cache.clone(), 1024 * 1024);
    persistence.persist(&snapshot).unwrap();
    zones.insert_snapshot(snapshot);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
            zone_persistence: Some(persistence),
        },
    )
    .await
    .expect("refresh success");
    let peer = tokio::time::timeout(std::time::Duration::from_secs(1), peer_rx)
        .await
        .expect("primary should observe SOA poll peer")
        .expect("SOA primary should send peer address");
    let expected_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    assert_eq!(metadata.serial, Some(2));
    assert_eq!(peer.ip(), expected_ip);
    assert!(
        std::fs::read_dir(&cache)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.path().extension().is_some_and(|ext| ext == "fresh")),
        "equal-SOA current confirmation must durably renew cache freshness"
    );
    assert!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("example.test.").unwrap())
            .expect("unchanged zone snapshot")
            .snapshot_for_transfer()
            .offline_oracle()
            .lookup(
                &DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            )
            .answers
            .is_empty()
    );
    std::fs::remove_dir_all(cache).unwrap();
}

#[tokio::test]
async fn notify_serial_hint_still_requires_primary_soa_poll() {
    let (primary, peer_rx) = spawn_soa_primary_recording_peer(2).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        apex.clone(),
        Some(2),
        vec![Rrset::new(
            apex,
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(2)],
        )],
    ));
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        Some(2),
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "notify",
            zone_persistence: None,
        },
    )
    .await
    .expect("primary SOA confirms retained zone current");
    let peer = tokio::time::timeout(std::time::Duration::from_millis(250), peer_rx)
        .await
        .expect("RFC 1996 requires validating the NOTIFY hint with a primary query")
        .expect("SOA primary should send peer address");

    assert_eq!(metadata.serial, Some(2));
    assert_eq!(
        peer.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );
}

#[tokio::test]
async fn notify_refresh_polls_the_notifying_primary_first_then_checks_the_others() {
    let (stale_primary, stale_rx) = spawn_soa_primary_recording_peer_on("127.0.0.1:0", 10).await;
    let (notifying_primary, notifying_rx) =
        spawn_soa_primary_recording_peer_on("127.0.0.2:0", 10).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["{stale_primary}", "{notifying_primary}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config_with_primary_start(&config, |_| Ok(0))
        .expect("deterministic transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        apex.clone(),
        Some(10),
        vec![Rrset::new(
            apex,
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(10)],
        )],
    ));
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries_preferring(
        &zones,
        &plan,
        Some(10),
        notifying_primary.ip(),
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "notify",
            zone_persistence: None,
        },
    )
    .await
    .expect("notifying primary confirms zone current");

    tokio::time::timeout(std::time::Duration::from_millis(250), notifying_rx)
        .await
        .expect("notifying primary must receive the first SOA poll")
        .expect("notifying primary reports peer");
    tokio::time::timeout(std::time::Duration::from_millis(250), stale_rx)
        .await
        .expect("remaining primary must be checked after an equal SOA response")
        .expect("remaining primary reports peer");
    assert_eq!(metadata.serial, Some(10));
}

#[tokio::test]
async fn stale_first_primary_does_not_mask_a_newer_later_primary() {
    let (stale_primary, stale_rx) = spawn_soa_primary_recording_peer(9).await;
    let newer_primary = spawn_ixfr_mode2_primary_with_serial(11).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["{stale_primary}", "{newer_primary}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config_with_primary_start(&config, |_| Ok(0))
        .expect("deterministic transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        apex.clone(),
        Some(10),
        vec![Rrset::new(
            apex,
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(10)],
        )],
    ));
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan,
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await
    .expect("later primary refreshes the zone");

    tokio::time::timeout(std::time::Duration::from_secs(1), stale_rx)
        .await
        .expect("stale primary receives the first SOA poll")
        .expect("stale primary reports the peer");
    assert_eq!(metadata.serial, Some(11));
}

#[tokio::test]
async fn current_confirmation_crossing_expiry_keeps_serving_and_registry_in_sync() {
    let config = ServerConfig::from_toml_str(r#"
        [server]
        allow_non_rfc5936_cold_start = true
        [[zones]]
        name = "example.test."
        primaries = ["127.0.0.1:5301"]
    "#).unwrap();
    let transfer_plan = TransferPlan::from_config(&config).unwrap();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&origin).unwrap();
    let registry = ZoneRefreshRegistry::without_jitter(Duration::from_secs(1), Duration::from_secs(1), Duration::from_secs(1));
    let zones = ZoneStore::new();
    let snapshot = ZoneSnapshot::active(origin.clone(), Some(1), vec![Rrset::new(
        origin.clone(), RecordType::Soa as u16, 1, 3600, vec![soa_rdata_with_timers(2, 1, 60, 300)],
    )]);
    let now = Instant::now();
    registry.record_success_at(&zone_metadata_for(&snapshot), now - Duration::from_secs(60));
    zones.insert_snapshot(snapshot);
    let current = zones.exact_snapshot_for_transfer(&origin).unwrap();
    let mut attempt = registry.begin_attempt(&origin).await;
    let secrets = SecretManager::from_config(&config).unwrap();
    let secret_snapshot = secrets.current_snapshot().unwrap();
    let metrics = RuntimeMetrics::new();
    let cooldown = IxfrCooldownRegistry::new(Duration::from_secs(60));
    let metadata = {
        let context = RefreshAttemptContext {
            current_attempt: Some(&attempt), ixfr_cooldowns: &cooldown, metrics: &metrics,
            transfer_plan: transfer_plan.clone(), secrets,
            ixfr_timeout: Duration::from_secs(1), axfr_timeout: Duration::from_secs(1),
            tcp_connect_timeout: Duration::from_secs(1), reason: "test", zone_persistence: None,
        };
        let (entered_tx, entered_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        let confirmation = crate::confirm_current_after_freshness(
            &zones, &context, &plan, &secret_snapshot, &current, async {
                entered_tx.send(()).unwrap();
                resume_rx.await.unwrap();
                Ok(())
            },
        );
        tokio::pin!(confirmation);
        tokio::select! {
            _ = entered_rx => {},
            _ = &mut confirmation => panic!("freshness write must block"),
        }
        assert_eq!(registry.expire_due_zones(&zones, now), vec![origin.clone()]);
        assert_eq!(zones.exact_zone_control_metadata(&origin).unwrap().state, ZoneState::Expired);
        resume_tx.send(()).unwrap();
        confirmation.await.unwrap_or_else(|_| panic!("freshness confirmation should succeed"))
    };
    assert_eq!(zones.exact_zone_control_metadata(&origin).unwrap().state, ZoneState::Active,
        "a successful refresh must not leave the zone expired");
    let fresh_deadline = registry.statuses.lock().unwrap()[&origin.canonical_key()].expire_at.unwrap();
    assert!(fresh_deadline > now);
    // A slow outer worker must not acknowledge twice and renew genuine expiry.
    assert_eq!(registry.expire_due_zones(&zones, fresh_deadline), vec![origin.clone()]);
    assert!(crate::acknowledge_refresh_before_maintenance(&mut attempt, &transfer_plan, &plan, &metadata, async {}).await);
    let statuses = registry.statuses.lock().unwrap();
    assert!(statuses[&origin.canonical_key()].expired);
    assert_eq!(statuses[&origin.canonical_key()].expire_at, Some(fresh_deadline));
}

#[tokio::test]
async fn current_confirmation_rechecks_identity_and_failure_after_freshness_wait() {
    for mutation in ["plan", "secret", "snapshot", "generation", "write_failure", "already_obsolete"] {
        let mut config = ServerConfig::from_toml_str(r#"
            [server]
            allow_non_rfc5936_cold_start = true
            [[zones]]
            name = "example.test."
            primaries = ["127.0.0.1:5301"]
        "#).unwrap();
        let secret_root = unique_test_path("borondns-current-wait-secret", "dir");
        if mutation == "secret" {
            write_secret_store_manifest(&secret_root, "");
            config.secret_store.path = Some(secret_root.clone());
        }
        let transfer_plan = TransferPlan::from_config(&config).unwrap();
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = transfer_plan.get(&origin).unwrap();
        let registry = ZoneRefreshRegistry::without_jitter(Duration::from_secs(1), Duration::from_secs(1), Duration::from_secs(1));
        let zones = ZoneStore::new();
        let make = || ZoneSnapshot::active(origin.clone(), Some(1), vec![Rrset::new(
            origin.clone(), RecordType::Soa as u16, 1, 3600, vec![soa_rdata_with_timers(2, 1, 60, 300)],
        )]);
        let initial = make();
        registry.record_success_at(&zone_metadata_for(&initial), Instant::now() - Duration::from_secs(60));
        zones.insert_snapshot(initial);
        registry.expire_due_zones(&zones, Instant::now());
        let current = zones.exact_snapshot_for_transfer(&origin).unwrap();
        let attempt = registry.begin_attempt(&origin).await;
        let secrets = SecretManager::from_config(&config).unwrap();
        let secret_snapshot = secrets.current_snapshot().unwrap();
        let metrics = RuntimeMetrics::new();
        let cooldown = IxfrCooldownRegistry::new(Duration::from_secs(60));
        let context = RefreshAttemptContext {
            current_attempt: Some(&attempt), ixfr_cooldowns: &cooldown, metrics: &metrics,
            transfer_plan: transfer_plan.clone(), secrets: secrets.clone(),
            ixfr_timeout: Duration::from_secs(1), axfr_timeout: Duration::from_secs(1),
            tcp_connect_timeout: Duration::from_secs(1), reason: "test", zone_persistence: None,
        };
        let old_deadline = registry.statuses.lock().unwrap()[&origin.canonical_key()].expire_at;
        if mutation == "already_obsolete" { transfer_plan.remove(&origin); }
        let result = crate::confirm_current_after_freshness(&zones, &context, &plan, &secret_snapshot, &current, async {
            match mutation {
                "plan" => transfer_plan.remove(&origin),
                "secret" => {
                    write_secret_store_manifest(&secret_root, r#"
                        [[tsig_keys]]
                        name = "new-key."
                        algorithm = "hmac-sha256"
                        secret = "bmV3LXNlY3JldA=="
                    "#);
                    secrets.reload().unwrap();
                },
                "snapshot" => {
                    zones.remove_zone(&origin);
                    zones.insert_snapshot(make());
                    zones.expire_zone(&origin);
                },
                "generation" => {
                    registry.statuses.lock().unwrap().get_mut(&origin.canonical_key()).unwrap().generation += 1;
                },
                "write_failure" => return Err("injected freshness fsync failure".to_owned()),
                "already_obsolete" => panic!("obsolete confirmation must not start a disk write"),
                _ => unreachable!(),
            }
            Ok(())
        }).await;
        assert!(result.is_err(), "{mutation}");
        assert!(!attempt.current_acknowledged.load(Ordering::Relaxed));
        assert_eq!(zones.exact_zone_control_metadata(&origin).unwrap().state, ZoneState::Expired, "{mutation}");
        assert_eq!(registry.statuses.lock().unwrap()[&origin.canonical_key()].expire_at, old_deadline, "{mutation}");
        if mutation == "secret" { std::fs::remove_dir_all(secret_root).unwrap(); }
    }
}

#[tokio::test]
async fn blocked_or_cancelled_post_commit_maintenance_retains_bounded_fresh_expiry() {
    let config = ServerConfig::from_toml_str(r#"
        [server]
        allow_non_rfc5936_cold_start = true
        listen_udp = ["127.0.0.1:5300"]
        listen_tcp = []
        allow_non_rfc9210_single_transport = true
        [[zones]]
        name = "example.test."
        primaries = ["127.0.0.1:5301"]
    "#).unwrap();
    let transfer_plan = TransferPlan::from_config(&config).unwrap();
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&origin).unwrap();
    let registry = ZoneRefreshRegistry::without_jitter(std::time::Duration::ZERO, std::time::Duration::ZERO, std::time::Duration::ZERO);
    let now = Instant::now();
    let make_snapshot = |serial| ZoneSnapshot::active(origin.clone(), Some(serial), vec![Rrset::new(
        origin.clone(), RecordType::Soa as u16, 1, 3600, vec![soa_rdata_with_serial(serial)],
    )]);
    let initial = make_snapshot(1);
    let zones = ZoneStore::new();
    zones.insert_snapshot(initial.clone());
    registry.record_success_at(&zone_metadata_for(&initial), now - std::time::Duration::from_secs(604_800));
    let candidate = make_snapshot(2);
    let metadata = zone_metadata_for(&candidate);
    zones.insert_snapshot(candidate);
    let mut attempt = registry.begin_attempt(&origin).await;
    let (entered_tx, entered_rx) = oneshot::channel();
    let maintenance = tokio::spawn(async move {
        crate::acknowledge_refresh_before_maintenance(&mut attempt, &transfer_plan, &plan, &metadata, async {
            entered_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        }).await
    });
    entered_rx.await.unwrap();
    assert!(registry.expire_due_zones(&zones, now).is_empty(), "old deadline cannot expire newly acknowledged serial while sync is blocked");
    maintenance.abort();
    assert!(maintenance.await.unwrap_err().is_cancelled());
    assert!(registry.expire_due_zones(&zones, now + std::time::Duration::from_secs(60)).is_empty());
    assert_eq!(registry.expire_due_zones(&zones, now + std::time::Duration::from_secs(604_810)), vec![origin.clone()], "cancellation must not suppress genuine expiry forever");
    assert_eq!(zones.exact_zone_control_metadata(&origin).unwrap().state, ZoneState::Expired);
}

#[tokio::test]
async fn final_transfer_serial_is_checked_after_a_newer_soa_probe() {
    for use_ixfr in [false, true] {
        for final_serial in [99_u32, 102] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let primary = listener.local_addr().unwrap();
            let socket = UdpSocket::bind(primary).await.unwrap();
            let primary_task = tokio::spawn(async move {
                let mut request = [0_u8; 512];
                let (len, peer) = socket.recv_from(&mut request).await.unwrap();
                let header = Header::parse(&request[..len]).unwrap();
                assert_eq!(query_qtype(&request[..len]), RecordType::Soa as u16);
                socket.send_to(&soa_response(header.id, 101), peer).await.unwrap();
                let (mut stream, _) = listener.accept().await.unwrap();
                let query = read_primary_query(&mut stream).await;
                let header = Header::parse(&query).unwrap();
                let response = if use_ixfr {
                    assert_eq!(query_qtype(&query), RecordType::Ixfr as u16);
                    ixfr_mode2_response(header.id, final_serial)
                } else {
                    assert_eq!(query_qtype(&query), RecordType::Axfr as u16);
                    axfr_response(header.id, final_serial)
                };
                stream.write_all(&frame_tcp_message(&response)).await.unwrap();
            });
            let config = ServerConfig::from_toml_str(&format!(r#"
                [server]
                allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true
                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#)).unwrap();
            let transfer_plan = TransferPlan::from_config(&config).unwrap();
            let origin = DomainName::from_absolute_str("example.test.").unwrap();
            let plan = transfer_plan.get(&origin).unwrap();
            let zones = ZoneStore::new();
            let nameserver = DomainName::from_absolute_str("ns.example.test.").unwrap();
            let initial = ZoneSnapshot::active(origin.clone(), Some(100), vec![
                Rrset::new(origin.clone(), RecordType::Soa as u16, 1, 3600, vec![soa_rdata_with_serial(100)]),
                Rrset::new(origin.clone(), RecordType::Ns as u16, 1, 3600, vec![nameserver.to_wire()]),
                Rrset::new(nameserver, RecordType::A as u16, 1, 3600, vec![vec![192, 0, 2, 53]]),
            ]);
            zones.insert_snapshot(initial.clone());
            let cache = std::env::temp_dir().join(format!("borondns-final-serial-{}-{}", std::process::id(), unix_timestamp_nanos_for_tests()));
            let persistence = ZonePersistence::new(cache.clone(), 1024 * 1024);
            persistence.persist(&initial).unwrap();
            let metrics = RuntimeMetrics::new();
            let cooldown = IxfrCooldownRegistry::new(std::time::Duration::from_secs(60));
            if !use_ixfr { cooldown.record_unsupported_if_current(&transfer_plan, &plan, primary); }
            let result = refresh_zone_metadata_from_primaries(&zones, &plan, None, RefreshAttemptContext { current_attempt: None,
                ixfr_cooldowns: &cooldown, metrics: &metrics, transfer_plan,
                secrets: SecretManager::from_config(&config).unwrap(),
                ixfr_timeout: std::time::Duration::from_secs(1),
                axfr_timeout: std::time::Duration::from_secs(1),
                tcp_connect_timeout: std::time::Duration::from_secs(1),
                reason: "final SOA serial regression", zone_persistence: Some(persistence.clone()),
            }).await;
            primary_task.await.unwrap();
            let expected = if final_serial == 99 { 100 } else { 102 };
            assert_eq!(result.is_some(), final_serial == 102, "IXFR={use_ixfr}, candidate={final_serial}");
            assert_eq!(zones.exact_zone_control_metadata(&origin).unwrap().serial, Some(expected));
            assert_eq!(persistence.restore(&origin, 1).unwrap().unwrap().snapshot.serial(), Some(expected));
            std::fs::remove_dir_all(cache).unwrap();
        }
    }
}

fn unix_timestamp_nanos_for_tests() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
}

#[tokio::test]
async fn older_primary_serial_does_not_reactivate_an_expired_zone() {
    let primary = spawn_soa_primary_with_serial(6).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config_with_primary_start(&config, |_| Ok(0))
        .expect("deterministic transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        apex.clone(),
        Some(7),
        vec![Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(7)],
        )],
    ));
    assert!(zones.expire_zone(&apex));
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan,
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(1),
            axfr_timeout: std::time::Duration::from_secs(1),
            tcp_connect_timeout: std::time::Duration::from_secs(1),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await;

    assert!(result.is_none());
    assert_eq!(
        zones.exact_zone_control_metadata(&apex).unwrap().state,
        ZoneState::Expired
    );
}

#[tokio::test]
async fn notify_serial_hint_requires_soa_poll_over_xot_primary() {
    let (primary, trust_anchor, observed_qtype) = spawn_xot_soa_primary_recording_query(2).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                trust_anchors = ["{trust_anchor}"]
            "#
    ))
    .expect("valid XoT config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        apex.clone(),
        Some(2),
        vec![Rrset::new(
            apex,
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(2)],
        )],
    ));
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        Some(2),
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads XoT secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(1),
            axfr_timeout: std::time::Duration::from_secs(1),
            tcp_connect_timeout: std::time::Duration::from_secs(1),
            reason: "notify",
            zone_persistence: None,
        },
    )
    .await;
    let qtype = tokio::time::timeout(std::time::Duration::from_secs(1), observed_qtype)
        .await
        .expect("XoT primary should observe the validation query")
        .expect("XoT primary should report the query type");

    assert_eq!(qtype, RecordType::Soa as u16);
    assert_eq!(
        metadata.expect("XoT SOA poll confirms current").serial,
        Some(2)
    );
}

#[tokio::test]
async fn expired_zone_is_not_reactivated_by_unvalidated_notify_serial_hint() {
    let config = ServerConfig::from_toml_str(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [[zones]]
            name = "expired-current.test."
            primaries = ["192.0.2.53:53"]
        "#,
    )
    .expect("valid config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("expired-current.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        apex.clone(),
        Some(7),
        vec![Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata_with_serial(7)],
        )],
    ));
    assert!(zones.expire_zone(&apex));
    assert_eq!(
        zones.exact_zone_control_metadata(&apex).unwrap().state,
        ZoneState::Expired
    );
    assert!(zones.find_published_zone(&apex).is_some());
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        Some(7),
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(1),
            axfr_timeout: std::time::Duration::from_secs(1),
            tcp_connect_timeout: std::time::Duration::from_secs(1),
            reason: "notify",
            zone_persistence: None,
        },
    )
    .await;

    assert!(
        metadata.is_none(),
        "the unreachable primary did not confirm freshness"
    );
    let expired = zones
        .exact_snapshot_for_transfer(&apex)
        .expect("expired retained snapshot remains available for refresh");
    assert_eq!(expired.metadata().state, ZoneState::Expired);
    assert_eq!(expired.metadata().serial, Some(7));
    assert_eq!(zones.active_count(), 0);
}

#[tokio::test]
async fn malformed_catalog_axfr_is_rejected_before_publication_and_success() {
    let primary = spawn_signed_invalid_catalog_axfr_primary("catalog-invalid.test.", 2).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:5300"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [[tsig_keys]]
            name = "catalog-key."
            algorithm = "hmac-sha256"
            secret = "dG9wc2VjcmV0"

            [[catalog_zones]]
            name = "catalog-invalid.test."
            catalog_primaries = ["{primary}"]
            member_primaries = ["127.0.0.1:9"]
            catalog_tsig_key = "catalog-key."
            member_tsig_key = "catalog-key."
        "#
    ))
    .expect("valid catalog config");
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let origin = DomainName::from_absolute_str("catalog-invalid.test.").unwrap();
    let plan = transfer_plan.get(&origin).expect("catalog transfer plan");
    let zones = ZoneStore::new();
    zones.insert_snapshot(ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![Rrset::new(
            DomainName::from_absolute_str("version.catalog-invalid.test.").unwrap(),
            RecordType::Txt as u16,
            1,
            0,
            vec![vec![1, b'2']],
        )],
    ));
    let retained = zones
        .exact_snapshot_for_transfer(&origin)
        .expect("last known-good catalog snapshot")
        .snapshot_arc_for_transfer()
        .clone();
    let catalog_manager = CatalogManager::from_config(&config);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
    ixfr_cooldowns.record_unsupported_for_generation_at(
        &origin,
        primary,
        plan.generation(),
        std::time::Instant::now(),
    );

    let outcome = refresh_zone_from_primaries_with_outcome(
        &zones,
        &plan,
        Some(2),
        &catalog_manager,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan,
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(1),
            axfr_timeout: std::time::Duration::from_secs(1),
            tcp_connect_timeout: std::time::Duration::from_secs(1),
            reason: "notify",
            zone_persistence: None,
        },
    )
    .await;

    assert!(outcome.success.is_none());
    assert!(!outcome.obsolete);
    assert!(
        outcome
            .failure_cause
            .as_deref()
            .is_some_and(|cause| cause.contains("invalid catalog snapshot")),
        "unexpected catalog transfer failure: {:?}",
        outcome.failure_cause
    );
    let current = zones
        .exact_snapshot_for_transfer(&origin)
        .expect("last known-good catalog remains installed");
    assert_eq!(current.metadata().serial, Some(1));
    assert!(Arc::ptr_eq(&retained, current.snapshot_arc_for_transfer()));
    assert_eq!(metrics.snapshot().axfr_started, 1);
    assert_eq!(metrics.snapshot().axfr_succeeded, 0);
    assert_eq!(metrics.snapshot().axfr_failed, 1);
}

#[tokio::test]
async fn operator_retransfer_forces_same_serial_axfr_and_preserves_tsig_and_last_good() {
    for correct_secret in [true, false] {
        let (primary, observed_query) = spawn_axfr_primary_recording_query(2).await;
        let secret = if correct_secret { "dG9wc2VjcmV0" } else { "d3Jvbmc=" };
        let config = ServerConfig::from_toml_str(&format!(r#"
[server]
allow_non_rfc5936_cold_start = true
[tsig]
fudge_seconds = 30
[[tsig_keys]]
name = "transfer-key."
algorithm = "hmac-sha256"
secret = "{secret}"
[[zones]]
name = "example.test."
primaries = ["{primary}"]
tsig_key = "transfer-key."
"#)).unwrap();
        let plans = TransferPlan::from_config(&config).unwrap();
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let plan = plans.get(&origin).unwrap();
        let zones = ZoneStore::new();
        zones.insert_snapshot(ZoneSnapshot::active(origin.clone(), Some(2), vec![
            Rrset::new(origin.clone(), RecordType::Soa as u16, 1, 3600, vec![soa_rdata_with_serial(2)]),
            Rrset::new(origin.clone(), 65280, 1, 300, vec![b"last-good marker".to_vec()]),
        ]));
        let old = zones.exact_snapshot_for_transfer(&origin).unwrap();
        plan.request_axfr();
        let metrics = RuntimeMetrics::new();
        let cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));
        let outcome = refresh_zone_from_primaries_with_outcome(&zones, &plan, None, &CatalogManager::default(), RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &cooldowns, metrics: &metrics, transfer_plan: plans.clone(),
            secrets: SecretManager::from_config(&config).unwrap(),
            ixfr_timeout: std::time::Duration::from_secs(2), axfr_timeout: std::time::Duration::from_secs(2),
            tcp_connect_timeout: std::time::Duration::from_secs(2), reason: "operator-retransfer", zone_persistence: None,
        }).await;
        assert_eq!(outcome.success.is_some(), correct_secret, "{outcome:?}");
        let query = observed_query.lock().unwrap().clone().unwrap();
        assert_eq!(query_qtype(&query), RecordType::Axfr as u16, "must bypass SOA and IXFR for same serial");
        assert_query_has_tsig(&query, "transfer-key.", "hmac-sha256.");
        let current = zones.exact_snapshot_for_transfer(&origin).unwrap();
        assert_eq!(current.metadata().serial, Some(2));
        assert_eq!(Arc::ptr_eq(old.snapshot_arc_for_transfer(), current.snapshot_arc_for_transfer()), !correct_secret);
        assert!(!plan.take_requested_axfr(), "one-shot request consumed");
    }
}

#[tokio::test]
async fn refresh_signs_axfr_query_when_zone_has_tsig_key() {
    let (primary, observed_query) = spawn_axfr_primary_recording_query(1).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
    assert!(plan.tsig_key_name.is_some());
    assert_eq!(plan.tsig_fudge_seconds, 30);
    let zones = ZoneStore::new();
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await
    .expect("refresh success");

    assert_eq!(metadata.serial, Some(1));
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
    let (primary, trust_anchor, observed_query) = spawn_xot_axfr_primary_recording_query(1).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
    assert!(plan.tsig_key_name.is_some());
    assert_eq!(plan.primaries[0].transport, TransferTransportConfig::Xot);
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await
    .expect("refresh success");

    assert_eq!(metadata.serial, Some(1));
    let query = observed_query
        .lock()
        .expect("observed query lock poisoned")
        .clone()
        .expect("primary observed query");
    assert_eq!(query_qtype(&query), RecordType::Axfr as u16);
    assert_query_has_tsig(&query, "transfer-key.", "hmac-sha256.");
}

#[test]
fn xot_transfer_logs_tls_session_establishment_and_close() {
    std::thread::spawn(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(async {
                let (primary, trust_anchor) = spawn_xot_axfr_primary_with_serial(1).await;
                let target = TransferPrimaryConfig {
                    addr: primary,
                    transport: TransferTransportConfig::Xot,
                    server_name: Some("primary.example.test".to_owned()),
                    xot_profile: None,
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

                assert_eq!(snapshot.serial(), Some(1));
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
            });
    })
    .join()
    .expect("XoT logging test thread");
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
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(50),
            axfr_timeout: std::time::Duration::from_millis(50),
            tcp_connect_timeout: std::time::Duration::from_millis(50),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await;

    assert!(refresh_result.is_none());
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
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await;

    assert!(refresh_result.is_none());
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
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await;

    assert!(refresh_result.is_none());
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
async fn refresh_xot_rejects_tls12_only_primary_before_query() {
    let (primary, trust_anchor, mut query_seen) = spawn_xot_tls12_primary_detecting_query().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await;

    assert!(refresh_result.is_none());
    let query_result =
        tokio::time::timeout(std::time::Duration::from_millis(100), query_seen.recv()).await;
    assert!(
        !matches!(query_result, Ok(Some(()))),
        "TLS 1.2-only XoT primaries must fail the formal profile before AXFR is sent"
    );
    assert_eq!(metrics.snapshot().axfr_failed, 1);
}

#[tokio::test]
async fn refresh_xot_rejects_untrusted_certificate_before_query() {
    let (cert_path, key_path) = write_self_signed_xot_cert_files_for_name("primary.example.test");
    let (untrusted_anchor, _untrusted_key) =
        write_self_signed_xot_cert_files_for_name("untrusted.example.test");
    let (primary, mut query_seen) =
        spawn_xot_primary_detecting_query_with_cert_files(&cert_path, &key_path, true).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await;

    assert!(refresh_result.is_none());
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
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await;

    assert!(refresh_result.is_none());
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
        write_self_signed_xot_cert_files_for_name("borondns-client.example.test");
    let (primary, trust_anchor, mut query_seen) =
        spawn_xot_mtls_axfr_primary_with_serial(1, &client_cert).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await
    .expect("mTLS XoT AXFR should publish a snapshot");

    assert_eq!(metadata.serial, Some(1));
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), query_seen.recv()).await,
        Ok(Some(()))
    );
    assert_eq!(metrics.snapshot().axfr_succeeded, 1);
}

#[tokio::test]
async fn refresh_xot_rejects_missing_client_certificate_before_query() {
    let (client_cert, _client_key) =
        write_self_signed_xot_cert_files_for_name("borondns-client.example.test");
    let (primary, trust_anchor, mut query_seen) =
        spawn_xot_mtls_axfr_primary_with_serial(1, &client_cert).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let refresh_result = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_millis(100),
            axfr_timeout: std::time::Duration::from_millis(100),
            tcp_connect_timeout: std::time::Duration::from_millis(100),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await;

    assert!(refresh_result.is_none());
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
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
fn runtime_config_validation_accepts_xot_profile_primary() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                xot_profile = "customer-xot"
            "#,
    )
    .expect("schema-valid XoT profile config");

    validate_runtime_config(&config).expect("profile-backed XoT primary validates before secrets");
    let warnings = runtime_config_warnings_at(&config, 1_779_667_200)
        .expect("profile-backed XoT warning scan skips inline certificate parsing");
    assert!(warnings.is_empty());
}

#[test]
fn runtime_config_validation_rejects_malformed_inline_xot_client_key_without_leaking_it() {
    let (trust_anchor, _key_path) =
        write_self_signed_xot_cert_files_for_name("primary.example.test");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [limits]
                max_tcp_connections = 20
                max_concurrent_transfers = 3

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid config");

    assert_eq!(required_file_descriptor_limit(&config), 248);
    validate_file_descriptor_limit_value(&config, 248).expect("exact required limit is enough");

    let error = validate_file_descriptor_limit_value(&config, 247)
        .expect_err("below required limit should fail");
    assert!(matches!(
        error,
        RuntimeError::InsufficientFileDescriptorLimit {
            current: 247,
            required: 248
        }
    ));
}

#[test]
fn file_descriptor_limit_counts_udp_tcp_and_health_listener_shape() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300", "127.0.0.1:5301"]
                listen_tcp = ["127.0.0.1:5300"]
                health = "127.0.0.1:8080"

                [limits]
                udp_reuseport_workers = 4
                max_tcp_connections = 1
                max_concurrent_transfers = 1

                [health]
                max_connections = 7

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid multi-listener config");

    // (1 TCP connection + 1 transfer + 8 UDP worker sockets + 1 TCP
    // listener + 1 health listener + 7 accepted health connections + 1
    // transient post-accept health descriptor + 100
    // reserve) * 2.
    assert_eq!(required_file_descriptor_limit(&config), 240);
    validate_file_descriptor_limit_value(&config, 240).expect("exact requirement is accepted");
    assert!(matches!(
        validate_file_descriptor_limit_value(&config, 239),
        Err(RuntimeError::InsufficientFileDescriptorLimit {
            current: 239,
            required: 240
        })
    ));
}

#[test]
fn file_descriptor_limit_counts_af_xdp_queues_and_kernel_fallback_socket() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [limits]
                udp_backend = "af_xdp"
                udp_reuseport_workers = 4
                max_tcp_connections = 1
                max_concurrent_transfers = 1

                [xdp]
                interface = "lo"
                redirect_object = "target/borondns-xdp-redirect.bpf.o"

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid AF_XDP descriptor-shape config");

    // Four XSK queue descriptors plus one kernel UDP fallback socket.
    assert_eq!(required_file_descriptor_limit(&config), 214);
    assert!(matches!(
        validate_file_descriptor_limit_value(&config, 213),
        Err(RuntimeError::InsufficientFileDescriptorLimit {
            current: 213,
            required: 214
        })
    ));
}

#[test]
fn file_descriptor_limit_uses_explicit_af_xdp_queue_count() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["192.0.2.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [limits]
                udp_backend = "af_xdp"
                udp_reuseport_workers = 1
                max_tcp_connections = 1
                max_concurrent_transfers = 1

                [xdp]
                interface = "eth0"
                redirect_object = "target/borondns-xdp-redirect.bpf.o"
                queue_ids = [3, 17, 41]

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid sparse AF_XDP queue configuration");

    // One TCP connection + one transfer + three XSK/UMEM workers + one
    // shared kernel fallback UDP socket + 100 reserve, all doubled.
    assert_eq!(required_file_descriptor_limit(&config), 212);
    assert!(matches!(
        validate_file_descriptor_limit_value(&config, 211),
        Err(RuntimeError::InsufficientFileDescriptorLimit {
            current: 211,
            required: 212
        })
    ));
}

#[test]
#[cfg(target_pointer_width = "64")]
fn file_descriptor_limit_formula_saturates_extreme_limits() {
    let config = ServerConfig::from_toml_str(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [limits]
                max_tcp_connections = 18446744073709551615
                max_concurrent_transfers = 2305843009213693951

                [[zones]]
                name = "example.test."
                primaries = ["192.0.2.53:53"]
            "#,
    )
    .expect("valid config");

    assert_eq!(required_file_descriptor_limit(&config), u64::MAX);
}

#[test]
fn runtime_config_warnings_report_expiring_xot_trust_anchors() {
    let (trust_anchor, _key_path) =
        write_expiring_self_signed_xot_cert_files_for_name("primary.example.test");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
fn runtime_config_warnings_report_expiring_profile_backed_xot_trust_anchors() {
    let root = unique_test_path("borondns-xot-profile-expiry-warning", "dir");
    let (trust_anchor, key_path) =
        write_expiring_self_signed_xot_cert_files_for_name("primary.example.test");
    copy_secret_store_file(&root, &trust_anchor, "trust-anchor.pem");
    write_secret_store_manifest(
        &root,
        r#"
            [[xot_profiles]]
            name = "customer-xot"
            trust_anchors = ["trust-anchor.pem"]
        "#,
    );
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [secret_store]
                path = "{}"

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                xot_profile = "customer-xot"
            "#,
        root.display()
    ))
    .expect("valid profile-backed XoT config");

    let warnings = runtime_config_warnings_at(&config, 1_779_667_200)
        .expect("profile-backed XoT warning collection succeeds");

    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, "xot_trust_anchor_expiring_soon");
    assert!(warnings[0].message.contains("within 30 days"));
    assert!(
        warnings[0]
            .parameter
            .contains("zones[example.test.].transfer_primaries[192.0.2.53:853]")
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_file(trust_anchor);
    let _ = std::fs::remove_file(key_path);
}

#[cfg(unix)]
#[test]
fn profile_backed_expiry_warnings_use_captured_certificates_after_source_mutation() {
    for mutation in ["replacement", "removal", "malformed"] {
        let root = unique_test_path(&format!("borondns-xot-profile-warning-{mutation}"), "dir");
        let (trust_anchor, key_path) =
            write_expiring_self_signed_xot_cert_files_for_name("primary.example.test");
        let snapshot_anchor = copy_secret_store_file(&root, &trust_anchor, "trust-anchor.pem");
        write_secret_store_manifest(
            &root,
            r#"
                [[xot_profiles]]
                name = "customer-xot"
                trust_anchors = ["trust-anchor.pem"]
            "#,
        );
        let config = ServerConfig::from_toml_str(&format!(
            r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [secret_store]
                path = "{}"

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "192.0.2.53:853"
                transport = "xot"
                server_name = "primary.example.test"
                xot_profile = "customer-xot"
            "#,
            root.display()
        ))
        .expect("valid profile-backed XoT config");
        let secrets = SecretManager::from_config(&config).expect("capture trust anchor snapshot");
        let mut replacement_material = None;

        match mutation {
            "replacement" => {
                let (replacement, replacement_key) =
                    write_self_signed_xot_cert_files_for_name("primary.example.test");
                let staged = root.join("trust-anchor.next");
                std::fs::copy(&replacement, &staged).expect("stage replacement trust anchor");
                std::fs::rename(staged, &snapshot_anchor)
                    .expect("atomically replace captured trust-anchor source");
                replacement_material = Some((replacement, replacement_key));
            }
            "removal" => {
                std::fs::remove_file(&snapshot_anchor)
                    .expect("remove captured trust-anchor source");
            }
            "malformed" => {
                std::fs::write(&snapshot_anchor, b"not a certificate\n")
                    .expect("malform captured trust-anchor source");
            }
            _ => unreachable!(),
        }

        let warnings = runtime_config_warnings_with_secrets_at(&config, &secrets, 1_779_667_200)
            .unwrap_or_else(|error| {
                panic!("{mutation} source must not affect captured warning material: {error}")
            });
        assert_eq!(warnings.len(), 1, "mutation {mutation}");
        assert_eq!(warnings[0].code, "xot_trust_anchor_expiring_soon");

        if let Some((replacement, replacement_key)) = replacement_material {
            let _ = std::fs::remove_file(replacement);
            let _ = std::fs::remove_file(replacement_key);
        }
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(trust_anchor);
        let _ = std::fs::remove_file(key_path);
    }
}

#[test]
fn runtime_config_validation_rejects_missing_xot_trust_anchor_file() {
    let missing_trust_anchor = unique_test_path("missing-xot-ca", "pem");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&trust_anchor, std::fs::Permissions::from_mode(0o644))
            .expect("read-only malformed trust anchor mode");
    }
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

#[test]
fn runtime_rejects_invalid_xot_config_before_startup() {
    let missing_trust_anchor = unique_test_path("missing-runtime-xot-ca", "pem");
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:0"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let error =
        Runtime::new(config).expect_err("runtime must reject invalid XoT TLS files before startup");

    assert!(matches!(error, RuntimeError::InvalidRuntimeConfig(_)));
}

#[test]
fn runtime_revalidates_tcp_inflight_capacity_before_binding_or_spawning_tasks() {
    let mut config = ServerConfig::from_toml_str(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = []
            listen_tcp = ["127.0.0.1:0"]
            allow_non_rfc9210_single_transport = true

            [[zones]]
            name = "example.test."
            primaries = ["192.0.2.53:53"]
        "#,
    )
    .expect("baseline config validates");
    config.limits.max_tcp_inflight_queries_per_connection = usize::MAX;

    let error =
        Runtime::new(config).expect_err("runtime must reject unsafe TCP capacity before binding");

    let RuntimeError::InvalidRuntimeConfig(message) = error else {
        panic!("expected startup configuration error, got {error}");
    };
    assert!(message.contains("max_tcp_inflight_queries_per_connection"));
}

#[tokio::test]
async fn refresh_axfr_uses_xot_tls_transport() {
    let (primary, trust_anchor) = spawn_xot_axfr_primary_with_serial(1).await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await
    .expect("XoT AXFR should publish a snapshot");

    assert_eq!(metadata.serial, Some(1));
    assert!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("example.test.").unwrap())
            .expect("published XoT zone")
            .snapshot_for_transfer()
            .offline_oracle()
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
async fn profile_backed_xot_transfer_uses_snapshot_after_trust_path_replacement() {
    let (primary, trust_anchor) = spawn_xot_axfr_primary_with_serial(1).await;
    let secret_root = unique_test_path("borondns-xot-snapshot-transfer", "dir");
    std::fs::create_dir_all(&secret_root).expect("create secret-store root");
    std::fs::copy(&trust_anchor, secret_root.join("trust-anchor.pem"))
        .expect("copy trust anchor into immutable secret generation");
    write_secret_store_manifest(
        &secret_root,
        r#"
                [[xot_profiles]]
                name = "customer-xot"
                trust_anchors = ["trust-anchor.pem"]
            "#,
    );
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [secret_store]
                path = "{}"

                [[zones]]
                name = "example.test."

                [[zones.transfer_primaries]]
                addr = "{primary}"
                transport = "xot"
                server_name = "primary.example.test"
                xot_profile = "customer-xot"
            "#,
        secret_root.display()
    ))
    .expect("valid profile-backed XoT config");
    let secrets = SecretManager::from_config(&config).expect("load XoT material snapshot");

    let staged = unique_test_path("borondns-invalid-replacement-anchor", "pem");
    std::fs::write(&staged, b"not a certificate\n").expect("stage invalid anchor");
    std::fs::rename(&staged, secret_root.join("trust-anchor.pem"))
        .expect("atomically replace trust anchor path");

    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let plan = transfer_plan.get(&apex).expect("zone transfer plan");
    let zones = ZoneStore::new();
    zones.insert_loading(apex);
    let metrics = RuntimeMetrics::new();
    let ixfr_cooldowns = IxfrCooldownRegistry::new(std::time::Duration::from_secs(3600));

    let metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        None,
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets,
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await
    .expect("snapshot-owned trust anchor must survive source path replacement");

    assert_eq!(metadata.serial, Some(1));
    let _ = std::fs::remove_file(trust_anchor);
    let _ = std::fs::remove_dir_all(secret_root);
}

#[tokio::test]
async fn refresh_uses_axfr_during_ixfr_disabled_cooldown() {
    let (primary, qtypes) = spawn_ixfr_notimp_then_axfr_primary().await;
    let config = ServerConfig::from_toml_str(&format!(
        r#"
                [server]
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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

    let first_metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        Some(2),
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await
    .expect("first refresh succeeds via AXFR fallback");
    assert_eq!(first_metadata.serial, Some(2));

    let second_metadata = refresh_zone_metadata_from_primaries(
        &zones,
        &plan,
        Some(3),
        RefreshAttemptContext { current_attempt: None,
            ixfr_cooldowns: &ixfr_cooldowns,
            metrics: &metrics,
            transfer_plan: transfer_plan.clone(),
            secrets: SecretManager::from_config(&config)
                .expect("test configuration loads secret snapshot"),
            ixfr_timeout: std::time::Duration::from_secs(5),
            axfr_timeout: std::time::Duration::from_secs(5),
            tcp_connect_timeout: std::time::Duration::from_secs(5),
            reason: "test",
            zone_persistence: None,
        },
    )
    .await
    .expect("second refresh skips IXFR and succeeds via AXFR");
    assert_eq!(second_metadata.serial, Some(3));

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
        &zone_metadata_for(&snapshot),
        std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(604800))
            .unwrap(),
    );
    let config = ServerConfig::from_toml_str(
        r#"
            [server]
allow_non_rfc5936_cold_start = true
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = []
            allow_non_rfc9210_single_transport = true

            [[zones]]
            name = "example.test."
            primaries = ["192.0.2.1:53"]
        "#,
    )
    .unwrap();
    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let (tx, mut rx) = mpsc::channel(1);
    let worker = tokio::spawn(serve_scheduled_refreshes(
        zones.clone(),
        registry,
        transfer_plan,
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
        zones
            .exact_snapshot_for_transfer(&origin)
            .expect("expired zone")
            .metadata()
            .state,
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
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

                [[zones]]
                name = "example.test."
                primaries = ["{primary}"]
            "#
    ))
    .expect("valid config");

    let transfer_plan = TransferPlan::from_config(&config).expect("transfer plan");
    let runtime = Runtime::new(config).expect("valid runtime configuration");
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
        .exact_snapshot_for_transfer(&DomainName::from_absolute_str("example.test.").unwrap())
        .expect("published zone snapshot");
    assert_eq!(snapshot.metadata().state, ZoneState::Active);
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
allow_non_rfc5936_cold_start = true
                listen_udp = ["127.0.0.1:5300"]
                listen_tcp = []
                allow_non_rfc9210_single_transport = true

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
    let runtime = Runtime::new(config).expect("valid runtime configuration");
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
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("alpha.test.").unwrap())
            .expect("alpha zone")
            .metadata()
            .state,
        ZoneState::Active
    );
    assert_eq!(
        zones
            .exact_snapshot_for_transfer(&DomainName::from_absolute_str("beta.test.").unwrap())
            .expect("beta zone")
            .metadata()
            .state,
        ZoneState::Active
    );
}
#[test]
fn rfc5936_restart_restores_validated_last_good_zone_before_refresh() {
    let cache = std::env::temp_dir().join(format!(
        "borondns-rfc5936-runtime-{}-{}",
        std::process::id(),
        TEST_PATH_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let snapshot = ZoneSnapshot::active(
        origin.clone(),
        Some(42),
        vec![
            Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata_with_serial(42)],
            ),
            Rrset::new(
                origin.clone(),
                RecordType::Ns as u16,
                1,
                3600,
                vec![DomainName::from_absolute_str("ns.example.test.")
                    .unwrap()
                    .to_wire()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("ns.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                3600,
                vec![vec![192, 0, 2, 53]],
            ),
        ],
    );
    ZonePersistence::new(cache.clone(), 1024 * 1024)
        .persist(&snapshot)
        .unwrap();
    let config = ServerConfig::from_toml_str(&format!(
        r#"
            [server]
            listen_udp = ["127.0.0.1:0"]
            listen_tcp = ["127.0.0.1:0"]
            zone_cache_directory = {cache:?}

            [[zones]]
            name = "example.test."
            primaries = ["192.0.2.53:53"]
        "#,
        cache = cache.display().to_string()
    ))
    .unwrap();

    let runtime = Runtime::new(config.clone()).unwrap();
    let metadata = runtime.zones.exact_zone_metadata(&origin).unwrap();
    assert_eq!(metadata.state, ZoneState::Active);
    assert_eq!(metadata.serial, Some(42));

    let cache_file = std::fs::read_dir(&cache)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = std::fs::read(&cache_file).unwrap();
    let midpoint = bytes.len() / 2;
    bytes[midpoint] ^= 1;
    std::fs::write(cache_file, bytes).unwrap();
    let restarted = Runtime::new(config).unwrap();
    assert_eq!(
        restarted
            .zones
            .exact_zone_metadata(&origin)
            .unwrap()
            .state,
        ZoneState::Loading,
        "a corrupt persisted candidate must never be partially served"
    );
    std::fs::remove_dir_all(cache).unwrap();
}
