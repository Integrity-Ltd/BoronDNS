use std::{
    collections::HashMap,
    env, fs,
    hint::black_box,
    time::{Duration, Instant},
};

use oxidedns_core::{
    dns::{
        AnswerOptions, DatagramAction, DnsCookieContext, DomainName, ExtendedDnsErrorsMode,
        LookupResult, Opcode, Rcode, RecordType, ZoneImageProvider, answer_message,
        answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image,
        default_zone_image_provider,
    },
    zone::{
        OfflineZoneSnapshot, ResourceRecord, Rrset, ZoneMetadata, ZoneShapeHistogramBucket,
        ZoneSnapshot, ZoneState, ZoneStore,
    },
    zone_image::{
        ZoneImage, ZoneImageChildLookupProfile, ZoneImageLookupOutcome,
        ZoneImagePlanSectionSummary, ZoneImagePlanSummary,
    },
};
use sha1::{Digest, Sha1};

fn main() {
    let config = BenchConfig::from_env_and_args();
    let record_count = config.records;
    let iterations = config.iterations;
    let (snapshot, direct_qnames, mixed_queries) = build_snapshot(record_count);
    let (cname_free_snapshot, cname_free_qnames) = build_cname_free_snapshot(record_count);
    let hot_direct_qnames = hot_direct_qnames(&direct_qnames);
    let high_fanout_qnames = high_fanout_qnames(&direct_qnames);
    let (stress_snapshot, stress_queries) =
        build_delegation_dname_stress_snapshot(config.stress_candidates);

    let compile_started = Instant::now();
    let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
    let compile_duration = compile_started.elapsed();
    let cname_free_image =
        ZoneImage::compile(&cname_free_snapshot).expect("CNAME-free image compiles");
    let stress_compile_started = Instant::now();
    let stress_image = ZoneImage::compile(&stress_snapshot).expect("stress zone image compiles");
    let stress_compile_duration = stress_compile_started.elapsed();

    let mixed_validation_mismatches =
        count_mixed_lookup_mismatches(&snapshot, &image, &mixed_queries);
    let stress_validation_mismatches =
        count_mixed_lookup_mismatches(&stress_snapshot, &stress_image, &stress_queries);
    let current = time_current_lookup(&snapshot, &direct_qnames, iterations);
    let image_exact = time_zone_image_exact_lookup(&image, &direct_qnames, iterations);
    let current_hot = time_current_lookup(&snapshot, &hot_direct_qnames, iterations);
    let image_hot_exact = time_zone_image_exact_lookup(&image, &hot_direct_qnames, iterations);
    let current_high_fanout = time_current_lookup(&snapshot, &high_fanout_qnames, iterations);
    let image_high_fanout_exact =
        time_zone_image_exact_lookup(&image, &high_fanout_qnames, iterations);
    let image_absent_low_exact = time_zone_image_exact_lookup_for_type(
        &image,
        &direct_qnames,
        RecordType::Hinfo as u16,
        iterations,
    );
    let image_absent_high_exact = time_zone_image_exact_lookup_for_type(
        &image,
        &direct_qnames,
        BENCH_ABSENT_HIGH_TYPE,
        iterations,
    );
    let image_absent_present_low_any_exact = time_zone_image_exact_lookup_for_type_qclass(
        &image,
        &hot_direct_qnames,
        RecordType::Cname as u16,
        255,
        iterations,
    );
    let image_absent_high_any_exact = time_zone_image_exact_lookup_for_type_qclass(
        &image,
        &hot_direct_qnames,
        BENCH_ABSENT_HIGH_TYPE,
        255,
        iterations,
    );
    let image_absent_low_direct_preflight = time_zone_image_direct_preflight(
        &image,
        &direct_qnames,
        RecordType::Hinfo as u16,
        iterations,
    );
    let image_absent_high_direct_preflight = time_zone_image_direct_preflight(
        &image,
        &direct_qnames,
        BENCH_ABSENT_HIGH_TYPE,
        iterations,
    );
    let image_absent_present_low_direct_preflight = time_zone_image_direct_preflight(
        &image,
        &direct_qnames,
        RecordType::Cname as u16,
        iterations,
    );
    let absent_low_response_queries = rrtype_query_cases(&direct_qnames, RecordType::Hinfo as u16);
    let absent_high_response_queries = rrtype_query_cases(&direct_qnames, BENCH_ABSENT_HIGH_TYPE);
    let image_absent_low_response_plan =
        time_zone_image_response_plan(&image, &absent_low_response_queries, iterations);
    let image_absent_high_response_plan =
        time_zone_image_response_plan(&image, &absent_high_response_queries, iterations);
    let cname_free_absent_low_response_queries =
        rrtype_query_cases(&cname_free_qnames, RecordType::Hinfo as u16);
    let image_cname_free_absent_low_response_plan = time_zone_image_response_plan(
        &cname_free_image,
        &cname_free_absent_low_response_queries,
        iterations,
    );
    let child_lookup_profile = image
        .widest_child_lookup_profile()
        .expect("zone image has a widest child lookup profile");
    let child_lookup_queries = child_lookup_queries(&child_lookup_profile);
    let child_lookup_sorted = time_sorted_child_lookup(
        &child_lookup_profile.labels,
        &child_lookup_queries,
        iterations,
    );
    let child_lookup_hashmap = time_hashmap_child_lookup(
        &child_lookup_profile.labels,
        &child_lookup_queries,
        iterations,
    );
    let byte_bucket_child_index = ByteBucketChildIndex::new(&child_lookup_profile.labels);
    let byte_bucket_child_index_bytes = byte_bucket_child_index.index_bytes();
    let child_lookup_byte_bucket =
        time_byte_bucket_child_lookup(&byte_bucket_child_index, &child_lookup_queries, iterations);
    let length_bucket_child_index = LengthBucketChildIndex::new(&child_lookup_profile.labels);
    let length_bucket_child_index_bytes = length_bucket_child_index.index_bytes();
    let child_lookup_length_bucket = time_length_bucket_child_lookup(
        &length_bucket_child_index,
        &child_lookup_queries,
        iterations,
    );
    let last_byte_bucket_child_index = LastByteBucketChildIndex::new(&child_lookup_profile.labels);
    let last_byte_bucket_child_index_bytes = last_byte_bucket_child_index.index_bytes();
    let child_lookup_last_byte_bucket = time_last_byte_bucket_child_lookup(
        &last_byte_bucket_child_index,
        &child_lookup_queries,
        iterations,
    );
    let generated_child_hash = GeneratedChildHashIndex::new(&child_lookup_profile.labels);
    let generated_child_hash_slot_bytes = generated_child_hash.slot_bytes();
    let generated_child_hash_slots = generated_child_hash.slot_count();
    let child_lookup_generated_hash =
        time_generated_child_hash_lookup(&generated_child_hash, &child_lookup_queries, iterations);
    let compact_generated_child_hash =
        GeneratedChildHashIndex::new_compact(&child_lookup_profile.labels);
    let compact_generated_child_hash_slot_bytes = compact_generated_child_hash.slot_bytes();
    let compact_generated_child_hash_slots = compact_generated_child_hash.slot_count();
    let child_lookup_compact_generated_hash = time_generated_child_hash_lookup(
        &compact_generated_child_hash,
        &child_lookup_queries,
        iterations,
    );
    let small_child_lookup_labels = small_child_lookup_labels();
    let small_child_lookup_queries = child_lookup_queries_for_labels(&small_child_lookup_labels);
    let small_child_lookup_sorted = time_sorted_child_lookup(
        &small_child_lookup_labels,
        &small_child_lookup_queries,
        iterations,
    );
    let small_child_lookup_linear = time_linear_child_lookup(
        &small_child_lookup_labels,
        &small_child_lookup_queries,
        iterations,
    );
    let current_mixed = time_current_response_lookup(&snapshot, &mixed_queries, iterations);
    let image_mixed_plan = time_zone_image_response_plan(&image, &mixed_queries, iterations);
    let image_mixed_wire = time_zone_image_response_wire(&image, &mixed_queries, iterations);
    let current_stress =
        time_current_response_lookup(&stress_snapshot, &stress_queries, iterations);
    let image_stress_plan =
        time_zone_image_response_plan(&stress_image, &stress_queries, iterations);
    let image_stress_wire =
        time_zone_image_response_wire(&stress_image, &stress_queries, iterations);
    let (zone_directory_store, zone_directory_origins, zone_directory_qnames) =
        build_zone_directory_benchmark(config.zone_directory_zones);
    let zone_directory_snapshots = zone_directory_store.offline_snapshots();
    let offline_snapshot_iterations = iterations.min(512);
    let zone_directory_offline_snapshot_rebuild_sort =
        time_zone_directory_offline_snapshot_rebuild_sort(
            &zone_directory_snapshots,
            offline_snapshot_iterations,
        );
    let zone_directory_offline_snapshot_cached_sort =
        time_zone_directory_offline_snapshot_cached_sort(
            &zone_directory_store,
            offline_snapshot_iterations,
        );
    let zone_directory_linear = time_zone_directory_linear_lookup(
        &zone_directory_snapshots,
        &zone_directory_qnames,
        iterations,
    );
    let zone_directory_suffix = time_zone_directory_suffix_lookup(
        &zone_directory_store,
        &zone_directory_qnames,
        iterations,
    );
    let zone_directory_linear_active_count =
        time_zone_directory_linear_active_count(&zone_directory_snapshots, iterations);
    let zone_directory_cached_active_count =
        time_zone_directory_cached_active_count(&zone_directory_store, iterations);
    let zone_directory_full_metadata = time_zone_directory_full_metadata(
        &zone_directory_store,
        &zone_directory_origins,
        iterations,
    );
    let zone_directory_control_metadata = time_zone_directory_control_metadata(
        &zone_directory_store,
        &zone_directory_origins,
        iterations,
    );
    let (zone_directory_serial_gate_store, zone_directory_serial_gate_origins) =
        build_zone_directory_serial_gate_benchmark(config.zone_directory_zones);
    let zone_directory_serial_gated_transfer_snapshot =
        time_zone_directory_serial_gated_transfer_snapshot(
            &zone_directory_serial_gate_store,
            &zone_directory_serial_gate_origins,
            iterations,
        );
    let zone_metadata = zone_directory_store.zone_metadata();
    let zone_metadata_origin_key_rebuild =
        time_zone_metadata_origin_key_rebuild(&zone_metadata, iterations);
    let zone_metadata_cached_origin_key =
        time_zone_metadata_cached_origin_key(&zone_metadata, iterations);
    let zone_metadata_origin_name_rebuild =
        time_zone_metadata_origin_name_rebuild(&zone_metadata, iterations);
    let zone_metadata_cached_origin_name =
        time_zone_metadata_cached_origin_name(&zone_metadata, iterations);
    let (zone_expire_store, zone_expire_origins, _) =
        build_zone_directory_benchmark(config.zone_directory_zones);
    let zone_expire_snapshots = zone_expire_store.offline_snapshots();
    let zone_directory_snapshot_state_clone =
        time_zone_directory_snapshot_state_clone(&zone_expire_snapshots);
    let zone_directory_entry_state_expire =
        time_zone_directory_entry_state_expire(&zone_expire_store, &zone_expire_origins);
    let mixed_packets = mixed_query_packets(&mixed_queries);
    let hot_packets = direct_query_packets(&hot_direct_qnames);
    let trace_packets = load_trace_packets(&config.trace_path);
    let optioned_packets = optioned_packet_cases();
    let boundary_packets = boundary_packet_cases();
    let udp_ceiling_packets = udp_ceiling_packet_cases();
    let store = ZoneStore::new();
    store.insert_snapshot(snapshot.clone());
    let mixed_packet_validation_mismatches =
        count_mixed_packet_mismatches(&store, image.clone(), &mixed_packets);
    let hot_packet_validation_mismatches =
        count_mixed_packet_mismatches(&store, image.clone(), &hot_packets);
    let trace_packet_validation_mismatches =
        count_packet_case_mismatches(&store, image.clone(), &trace_packets);
    let optioned_packet_validation_mismatches =
        count_packet_case_mismatches(&store, image.clone(), &optioned_packets);
    let boundary_packet_validation_mismatches =
        count_packet_case_mismatches(&store, image.clone(), &boundary_packets);
    let udp_ceiling_packet_validation_mismatches =
        count_packet_case_mismatches(&store, image.clone(), &udp_ceiling_packets);
    let ede_fallback_packet_validation_mismatches =
        count_ede_not_ready_packet_mismatches(image.clone());
    let current_packet = time_current_packet_response(&store, &mixed_packets, iterations);
    let image_packet =
        time_zone_image_packet_response(&store, image.clone(), &mixed_packets, iterations);
    let current_hot_packet = time_current_packet_response(&store, &hot_packets, iterations);
    let image_hot_packet =
        time_zone_image_packet_response(&store, image.clone(), &hot_packets, iterations);
    let current_trace_packet =
        time_current_packet_case_response(&store, &trace_packets, iterations);
    let image_trace_packet =
        time_zone_image_packet_case_response(&store, image.clone(), &trace_packets, iterations);
    let current_optioned_packet =
        time_current_packet_case_response(&store, &optioned_packets, iterations);
    let image_optioned_packet =
        time_zone_image_packet_case_response(&store, image.clone(), &optioned_packets, iterations);
    let current_boundary_packet =
        time_current_packet_case_response(&store, &boundary_packets, iterations);
    let image_boundary_packet =
        time_zone_image_packet_case_response(&store, image.clone(), &boundary_packets, iterations);
    let current_udp_ceiling_packet =
        time_current_packet_case_response(&store, &udp_ceiling_packets, iterations);
    let image_udp_ceiling_packet = time_zone_image_packet_case_response(
        &store,
        image.clone(),
        &udp_ceiling_packets,
        iterations,
    );
    let notify_soa_validation_packets = notify_soa_validation_packets();
    let notify_soa_validation_exact =
        time_notify_soa_packet_response(&store, &notify_soa_validation_packets[0], iterations);
    let notify_soa_validation_mixed_case =
        time_notify_soa_packet_response(&store, &notify_soa_validation_packets[1], iterations);
    let chaos_classification_packets = chaos_classification_packets();
    let chaos_classification_exact =
        time_chaos_packet_response(&store, &chaos_classification_packets[0], iterations);
    let chaos_classification_mixed_case =
        time_chaos_packet_response(&store, &chaos_classification_packets[1], iterations);
    let stats = image.stats();
    let shape_histograms = snapshot.shape_histogram_summary();

    println!("metric\tvalue");
    println!("benchmark_schema_version\t1");
    println!("benchmark_kind\tin_process_zone_image_prototype");
    println!("benchmark_build_profile\t{}", config.build_profile);
    println!("benchmark_git_revision\t{}", config.git_revision);
    println!("benchmark_git_dirty\t{}", config.git_dirty);
    println!("benchmark_kernel\t{}", config.kernel);
    println!("benchmark_rustc\t{}", config.rustc);
    println!("benchmark_rust_target\t{}", config.rust_target);
    println!("benchmark_cpu_model\t{}", config.cpu_model);
    println!("benchmark_network_device\t{}", config.network_device);
    println!("benchmark_artifact\t{}", config.artifact);
    println!("benchmark_trace\t{}", config.trace_path);
    println!("query_mix_direct\tflat_positive_a");
    println!("query_mix_hot_direct\trepeated_host0_90_percent_spread_10_percent");
    println!("query_mix_high_fanout_exact\tfirst_child,middle_child,last_child,absent_child");
    println!("query_mix_trace\tweighted_reference_trace_tsv");
    println!(
        "query_mix_mixed\tpositive_a,cname,wildcard,referral_glue,nodata,nxdomain,dname,opaque_unknown"
    );
    println!("query_mix_optioned\tedns_nsid,dns_cookie,edns_padding");
    println!(
        "query_mix_boundary\tqtype_any_full,dnssec_positive_do,dnssec_nodata_do,response_build_truncation"
    );
    println!(
        "query_mix_udp_ceiling\tno_edns_512,edns_payload_512,edns_payload_1232,edns_payload_4096"
    );
    println!("query_mix_notify_soa_validation\texact_owner,mixed_case_owner");
    println!("query_mix_chaos_classification\texact_qname,mixed_case_qname");
    println!("query_mix_delegation_dname_stress\treferral_glue,dname_synthesis");
    println!("query_mix_zone_directory\tmany_zone_suffix_selection");
    println!("serving_gate\tzone_image_without_snapshot_rollback");
    println!("records\t{record_count}");
    println!("zone_directory_zones\t{}", config.zone_directory_zones);
    println!(
        "delegation_dname_stress_candidates\t{}",
        config.stress_candidates
    );
    println!("iterations\t{iterations}");
    println!("hot_direct_query_cases\t{}", hot_direct_qnames.len());
    println!("high_fanout_query_cases\t{}", high_fanout_qnames.len());
    println!("hot_packet_query_cases\t{}", hot_packets.len());
    println!("trace_packet_query_cases\t{}", trace_packets.len());
    println!("mixed_query_cases\t{}", mixed_queries.len());
    println!(
        "delegation_dname_stress_query_cases\t{}",
        stress_queries.len()
    );
    println!(
        "zone_directory_query_cases\t{}",
        zone_directory_qnames.len()
    );
    println!("mixed_validation_mismatches\t{mixed_validation_mismatches}");
    println!("delegation_dname_stress_validation_mismatches\t{stress_validation_mismatches}");
    println!("mixed_packet_validation_mismatches\t{mixed_packet_validation_mismatches}");
    println!("hot_packet_validation_mismatches\t{hot_packet_validation_mismatches}");
    println!("trace_packet_validation_mismatches\t{trace_packet_validation_mismatches}");
    println!("optioned_packet_cases\t{}", optioned_packets.len());
    println!("optioned_packet_validation_mismatches\t{optioned_packet_validation_mismatches}");
    println!("boundary_packet_cases\t{}", boundary_packets.len());
    println!("boundary_packet_validation_mismatches\t{boundary_packet_validation_mismatches}");
    println!("udp_ceiling_packet_cases\t{}", udp_ceiling_packets.len());
    println!(
        "udp_ceiling_packet_validation_mismatches\t{udp_ceiling_packet_validation_mismatches}"
    );
    println!(
        "notify_soa_validation_cases\t{}",
        notify_soa_validation_packets.len()
    );
    println!(
        "chaos_classification_cases\t{}",
        chaos_classification_packets.len()
    );
    println!("ede_fallback_packet_cases\t2");
    println!(
        "ede_fallback_packet_validation_mismatches\t{ede_fallback_packet_validation_mismatches}"
    );
    println!(
        "zone_image_compile_ms\t{:.3}",
        compile_duration.as_secs_f64() * 1000.0
    );
    println!(
        "zone_image_delegation_dname_stress_compile_ms\t{:.3}",
        stress_compile_duration.as_secs_f64() * 1000.0
    );
    println!(
        "current_lookup_ns_per_query\t{:.3}",
        ns_per_query(current.duration, iterations)
    );
    println!(
        "zone_image_exact_lookup_ns_per_query\t{:.3}",
        ns_per_query(image_exact.duration, iterations)
    );
    println!(
        "current_hot_lookup_ns_per_query\t{:.3}",
        ns_per_query(current_hot.duration, iterations)
    );
    println!(
        "zone_image_hot_exact_lookup_ns_per_query\t{:.3}",
        ns_per_query(image_hot_exact.duration, iterations)
    );
    println!(
        "current_high_fanout_lookup_ns_per_query\t{:.3}",
        ns_per_query(current_high_fanout.duration, iterations)
    );
    println!(
        "zone_image_high_fanout_exact_lookup_ns_per_query\t{:.3}",
        ns_per_query(image_high_fanout_exact.duration, iterations)
    );
    println!(
        "zone_image_absent_low_exact_lookup_ns_per_query\t{:.3}",
        ns_per_query(image_absent_low_exact.duration, iterations)
    );
    println!(
        "zone_image_absent_high_exact_lookup_ns_per_query\t{:.3}",
        ns_per_query(image_absent_high_exact.duration, iterations)
    );
    println!(
        "zone_image_absent_present_low_any_exact_lookup_ns_per_query\t{:.3}",
        ns_per_query(image_absent_present_low_any_exact.duration, iterations)
    );
    println!(
        "zone_image_absent_high_any_exact_lookup_ns_per_query\t{:.3}",
        ns_per_query(image_absent_high_any_exact.duration, iterations)
    );
    println!(
        "zone_image_absent_low_direct_preflight_ns_per_query\t{:.3}",
        ns_per_query(image_absent_low_direct_preflight.duration, iterations)
    );
    println!(
        "zone_image_absent_high_direct_preflight_ns_per_query\t{:.3}",
        ns_per_query(image_absent_high_direct_preflight.duration, iterations)
    );
    println!(
        "zone_image_absent_present_low_direct_preflight_ns_per_query\t{:.3}",
        ns_per_query(
            image_absent_present_low_direct_preflight.duration,
            iterations
        )
    );
    println!(
        "zone_image_absent_low_response_plan_ns_per_query\t{:.3}",
        ns_per_query(image_absent_low_response_plan.duration, iterations)
    );
    println!(
        "zone_image_absent_high_response_plan_ns_per_query\t{:.3}",
        ns_per_query(image_absent_high_response_plan.duration, iterations)
    );
    println!(
        "zone_image_cname_free_absent_low_response_plan_ns_per_query\t{:.3}",
        ns_per_query(
            image_cname_free_absent_low_response_plan.duration,
            iterations
        )
    );
    println!(
        "zone_image_indirection_free_absent_low_response_plan_ns_per_query\t{:.3}",
        ns_per_query(
            image_cname_free_absent_low_response_plan.duration,
            iterations
        )
    );
    println!(
        "zone_image_child_lookup_profile_fanout\t{}",
        child_lookup_profile.fanout
    );
    println!(
        "zone_image_child_lookup_query_cases\t{}",
        child_lookup_queries.len()
    );
    println!(
        "zone_image_child_lookup_sorted_ns_per_query\t{:.3}",
        ns_per_query(child_lookup_sorted.duration, iterations)
    );
    println!(
        "zone_image_child_lookup_hashmap_ns_per_query\t{:.3}",
        ns_per_query(child_lookup_hashmap.duration, iterations)
    );
    println!(
        "zone_image_child_lookup_byte_bucket_ns_per_query\t{:.3}",
        ns_per_query(child_lookup_byte_bucket.duration, iterations)
    );
    println!(
        "zone_image_child_lookup_length_bucket_ns_per_query\t{:.3}",
        ns_per_query(child_lookup_length_bucket.duration, iterations)
    );
    println!(
        "zone_image_child_lookup_last_byte_bucket_ns_per_query\t{:.3}",
        ns_per_query(child_lookup_last_byte_bucket.duration, iterations)
    );
    println!(
        "zone_image_child_lookup_generated_hash_ns_per_query\t{:.3}",
        ns_per_query(child_lookup_generated_hash.duration, iterations)
    );
    println!(
        "zone_image_child_lookup_compact_generated_hash_ns_per_query\t{:.3}",
        ns_per_query(child_lookup_compact_generated_hash.duration, iterations)
    );
    println!(
        "zone_image_child_lookup_generated_hash_slots\t{}",
        generated_child_hash_slots
    );
    println!(
        "zone_image_child_lookup_compact_generated_hash_slots\t{}",
        compact_generated_child_hash_slots
    );
    println!(
        "zone_image_child_lookup_generated_hash_slot_bytes\t{}",
        generated_child_hash_slot_bytes
    );
    println!(
        "zone_image_child_lookup_compact_generated_hash_slot_bytes\t{}",
        compact_generated_child_hash_slot_bytes
    );
    println!(
        "zone_image_child_lookup_byte_bucket_index_bytes\t{}",
        byte_bucket_child_index_bytes
    );
    println!(
        "zone_image_child_lookup_length_bucket_index_bytes\t{}",
        length_bucket_child_index_bytes
    );
    println!(
        "zone_image_child_lookup_last_byte_bucket_index_bytes\t{}",
        last_byte_bucket_child_index_bytes
    );
    println!(
        "zone_image_small_child_lookup_fanout\t{}",
        small_child_lookup_labels.len()
    );
    println!(
        "zone_image_small_child_lookup_query_cases\t{}",
        small_child_lookup_queries.len()
    );
    println!(
        "zone_image_small_child_lookup_sorted_ns_per_query\t{:.3}",
        ns_per_query(small_child_lookup_sorted.duration, iterations)
    );
    println!(
        "zone_image_small_child_lookup_linear_ns_per_query\t{:.3}",
        ns_per_query(small_child_lookup_linear.duration, iterations)
    );
    println!(
        "current_mixed_response_ns_per_query\t{:.3}",
        ns_per_query(current_mixed.duration, iterations)
    );
    println!(
        "current_delegation_dname_stress_response_ns_per_query\t{:.3}",
        ns_per_query(current_stress.duration, iterations)
    );
    println!(
        "zone_image_delegation_dname_stress_plan_ns_per_query\t{:.3}",
        ns_per_query(image_stress_plan.duration, iterations)
    );
    println!(
        "zone_image_delegation_dname_stress_wire_ns_per_query\t{:.3}",
        ns_per_query(image_stress_wire.duration, iterations)
    );
    println!(
        "zone_directory_linear_lookup_ns_per_query\t{:.3}",
        ns_per_query(zone_directory_linear.duration, iterations)
    );
    println!(
        "zone_directory_suffix_lookup_ns_per_query\t{:.3}",
        ns_per_query(zone_directory_suffix.duration, iterations)
    );
    println!(
        "zone_directory_linear_active_count_ns_per_query\t{:.3}",
        ns_per_query(zone_directory_linear_active_count.duration, iterations)
    );
    println!(
        "zone_directory_cached_active_count_ns_per_query\t{:.3}",
        ns_per_query(zone_directory_cached_active_count.duration, iterations)
    );
    println!(
        "zone_directory_full_metadata_ns_per_query\t{:.3}",
        ns_per_query(zone_directory_full_metadata.duration, iterations)
    );
    println!(
        "zone_directory_control_metadata_ns_per_query\t{:.3}",
        ns_per_query(zone_directory_control_metadata.duration, iterations)
    );
    println!(
        "zone_directory_serial_gated_transfer_snapshot_ns_per_query\t{:.3}",
        ns_per_query(
            zone_directory_serial_gated_transfer_snapshot.duration,
            iterations
        )
    );
    println!(
        "zone_directory_offline_snapshot_rebuild_sort_ns_per_query\t{:.3}",
        ns_per_query(
            zone_directory_offline_snapshot_rebuild_sort.duration,
            offline_snapshot_iterations
        )
    );
    println!(
        "zone_directory_offline_snapshot_cached_sort_ns_per_query\t{:.3}",
        ns_per_query(
            zone_directory_offline_snapshot_cached_sort.duration,
            offline_snapshot_iterations
        )
    );
    println!(
        "zone_metadata_origin_key_rebuild_ns_per_query\t{:.3}",
        ns_per_query(zone_metadata_origin_key_rebuild.duration, iterations)
    );
    println!(
        "zone_metadata_cached_origin_key_ns_per_query\t{:.3}",
        ns_per_query(zone_metadata_cached_origin_key.duration, iterations)
    );
    println!(
        "zone_metadata_origin_name_rebuild_ns_per_query\t{:.3}",
        ns_per_query(zone_metadata_origin_name_rebuild.duration, iterations)
    );
    println!(
        "zone_metadata_cached_origin_name_ns_per_query\t{:.3}",
        ns_per_query(zone_metadata_cached_origin_name.duration, iterations)
    );
    println!(
        "zone_directory_snapshot_state_clone_ns_per_query\t{:.3}",
        ns_per_query(
            zone_directory_snapshot_state_clone.duration,
            zone_expire_snapshots.len()
        )
    );
    println!(
        "zone_directory_entry_state_expire_ns_per_query\t{:.3}",
        ns_per_query(
            zone_directory_entry_state_expire.duration,
            zone_expire_origins.len()
        )
    );
    println!(
        "zone_image_mixed_plan_ns_per_query\t{:.3}",
        ns_per_query(image_mixed_plan.duration, iterations)
    );
    println!(
        "zone_image_mixed_wire_ns_per_query\t{:.3}",
        ns_per_query(image_mixed_wire.duration, iterations)
    );
    println!(
        "current_mixed_packet_ns_per_query\t{:.3}",
        ns_per_query(current_packet.duration, iterations)
    );
    println!(
        "zone_image_mixed_packet_ns_per_query\t{:.3}",
        ns_per_query(image_packet.duration, iterations)
    );
    println!(
        "current_hot_packet_ns_per_query\t{:.3}",
        ns_per_query(current_hot_packet.duration, iterations)
    );
    println!(
        "zone_image_hot_packet_ns_per_query\t{:.3}",
        ns_per_query(image_hot_packet.duration, iterations)
    );
    println!(
        "current_trace_packet_ns_per_query\t{:.3}",
        ns_per_query(current_trace_packet.duration, iterations)
    );
    println!(
        "zone_image_trace_packet_ns_per_query\t{:.3}",
        ns_per_query(image_trace_packet.duration, iterations)
    );
    println!(
        "current_optioned_packet_ns_per_query\t{:.3}",
        ns_per_query(current_optioned_packet.duration, iterations)
    );
    println!(
        "zone_image_optioned_packet_ns_per_query\t{:.3}",
        ns_per_query(image_optioned_packet.duration, iterations)
    );
    println!(
        "current_boundary_packet_ns_per_query\t{:.3}",
        ns_per_query(current_boundary_packet.duration, iterations)
    );
    println!(
        "zone_image_boundary_packet_ns_per_query\t{:.3}",
        ns_per_query(image_boundary_packet.duration, iterations)
    );
    println!(
        "current_udp_ceiling_packet_ns_per_query\t{:.3}",
        ns_per_query(current_udp_ceiling_packet.duration, iterations)
    );
    println!(
        "zone_image_udp_ceiling_packet_ns_per_query\t{:.3}",
        ns_per_query(image_udp_ceiling_packet.duration, iterations)
    );
    println!(
        "notify_soa_validation_exact_ns_per_query\t{:.3}",
        ns_per_query(notify_soa_validation_exact.duration, iterations)
    );
    println!(
        "notify_soa_validation_mixed_case_ns_per_query\t{:.3}",
        ns_per_query(notify_soa_validation_mixed_case.duration, iterations)
    );
    println!(
        "chaos_classification_exact_ns_per_query\t{:.3}",
        ns_per_query(chaos_classification_exact.duration, iterations)
    );
    println!(
        "chaos_classification_mixed_case_ns_per_query\t{:.3}",
        ns_per_query(chaos_classification_mixed_case.duration, iterations)
    );
    println!("current_answer_count\t{}", current.answer_count);
    println!(
        "zone_image_answer_rrset_count\t{}",
        image_exact.answer_count
    );
    println!("current_hot_answer_count\t{}", current_hot.answer_count);
    println!(
        "zone_image_hot_answer_rrset_count\t{}",
        image_hot_exact.answer_count
    );
    println!(
        "current_high_fanout_answer_count\t{}",
        current_high_fanout.answer_count
    );
    println!(
        "zone_image_high_fanout_answer_rrset_count\t{}",
        image_high_fanout_exact.answer_count
    );
    println!(
        "zone_image_absent_low_exact_answer_rrset_count\t{}",
        image_absent_low_exact.answer_count
    );
    println!(
        "zone_image_absent_high_exact_answer_rrset_count\t{}",
        image_absent_high_exact.answer_count
    );
    println!(
        "zone_image_absent_present_low_any_exact_answer_rrset_count\t{}",
        image_absent_present_low_any_exact.answer_count
    );
    println!(
        "zone_image_absent_high_any_exact_answer_rrset_count\t{}",
        image_absent_high_any_exact.answer_count
    );
    println!(
        "zone_image_absent_low_direct_preflight_answer_rrset_count\t{}",
        image_absent_low_direct_preflight.answer_count
    );
    println!(
        "zone_image_absent_high_direct_preflight_answer_rrset_count\t{}",
        image_absent_high_direct_preflight.answer_count
    );
    println!(
        "zone_image_absent_present_low_direct_preflight_answer_rrset_count\t{}",
        image_absent_present_low_direct_preflight.answer_count
    );
    println!(
        "zone_image_absent_low_response_plan_item_count\t{}",
        image_absent_low_response_plan.answer_count
    );
    println!(
        "zone_image_absent_high_response_plan_item_count\t{}",
        image_absent_high_response_plan.answer_count
    );
    println!(
        "zone_image_absent_low_response_plan_rcode_checksum\t{}",
        image_absent_low_response_plan.rcode_sum
    );
    println!(
        "zone_image_absent_high_response_plan_rcode_checksum\t{}",
        image_absent_high_response_plan.rcode_sum
    );
    println!(
        "zone_image_cname_free_absent_low_response_plan_item_count\t{}",
        image_cname_free_absent_low_response_plan.answer_count
    );
    println!(
        "zone_image_indirection_free_absent_low_response_plan_item_count\t{}",
        image_cname_free_absent_low_response_plan.answer_count
    );
    println!(
        "zone_image_cname_free_absent_low_response_plan_rcode_checksum\t{}",
        image_cname_free_absent_low_response_plan.rcode_sum
    );
    println!(
        "zone_image_indirection_free_absent_low_response_plan_rcode_checksum\t{}",
        image_cname_free_absent_low_response_plan.rcode_sum
    );
    println!(
        "zone_image_child_lookup_sorted_found_count\t{}",
        child_lookup_sorted.answer_count
    );
    println!(
        "zone_image_child_lookup_hashmap_found_count\t{}",
        child_lookup_hashmap.answer_count
    );
    println!(
        "zone_image_child_lookup_byte_bucket_found_count\t{}",
        child_lookup_byte_bucket.answer_count
    );
    println!(
        "zone_image_child_lookup_length_bucket_found_count\t{}",
        child_lookup_length_bucket.answer_count
    );
    println!(
        "zone_image_child_lookup_last_byte_bucket_found_count\t{}",
        child_lookup_last_byte_bucket.answer_count
    );
    println!(
        "zone_image_child_lookup_generated_hash_found_count\t{}",
        child_lookup_generated_hash.answer_count
    );
    println!(
        "zone_image_child_lookup_compact_generated_hash_found_count\t{}",
        child_lookup_compact_generated_hash.answer_count
    );
    println!(
        "zone_image_child_lookup_sorted_index_checksum\t{}",
        child_lookup_sorted.extra_sum
    );
    println!(
        "zone_image_child_lookup_hashmap_index_checksum\t{}",
        child_lookup_hashmap.extra_sum
    );
    println!(
        "zone_image_child_lookup_byte_bucket_index_checksum\t{}",
        child_lookup_byte_bucket.extra_sum
    );
    println!(
        "zone_image_child_lookup_length_bucket_index_checksum\t{}",
        child_lookup_length_bucket.extra_sum
    );
    println!(
        "zone_image_child_lookup_last_byte_bucket_index_checksum\t{}",
        child_lookup_last_byte_bucket.extra_sum
    );
    println!(
        "zone_image_child_lookup_generated_hash_index_checksum\t{}",
        child_lookup_generated_hash.extra_sum
    );
    println!(
        "zone_image_child_lookup_compact_generated_hash_index_checksum\t{}",
        child_lookup_compact_generated_hash.extra_sum
    );
    println!(
        "zone_image_small_child_lookup_sorted_found_count\t{}",
        small_child_lookup_sorted.answer_count
    );
    println!(
        "zone_image_small_child_lookup_linear_found_count\t{}",
        small_child_lookup_linear.answer_count
    );
    println!(
        "zone_image_small_child_lookup_sorted_index_checksum\t{}",
        small_child_lookup_sorted.extra_sum
    );
    println!(
        "zone_image_small_child_lookup_linear_index_checksum\t{}",
        small_child_lookup_linear.extra_sum
    );
    println!("current_mixed_record_count\t{}", current_mixed.answer_count);
    println!(
        "zone_image_mixed_plan_item_count\t{}",
        image_mixed_plan.answer_count
    );
    println!(
        "zone_image_mixed_wire_record_count\t{}",
        image_mixed_wire.answer_count
    );
    println!("current_mixed_packet_bytes\t{}", current_packet.extra_sum);
    println!("zone_image_mixed_packet_bytes\t{}", image_packet.extra_sum);
    println!("current_hot_packet_bytes\t{}", current_hot_packet.extra_sum);
    println!(
        "zone_image_hot_packet_bytes\t{}",
        image_hot_packet.extra_sum
    );
    println!(
        "current_trace_packet_bytes\t{}",
        current_trace_packet.extra_sum
    );
    println!(
        "zone_image_trace_packet_bytes\t{}",
        image_trace_packet.extra_sum
    );
    println!(
        "current_optioned_packet_bytes\t{}",
        current_optioned_packet.extra_sum
    );
    println!(
        "zone_image_optioned_packet_bytes\t{}",
        image_optioned_packet.extra_sum
    );
    println!(
        "current_boundary_packet_bytes\t{}",
        current_boundary_packet.extra_sum
    );
    println!(
        "zone_image_boundary_packet_bytes\t{}",
        image_boundary_packet.extra_sum
    );
    println!(
        "current_udp_ceiling_packet_bytes\t{}",
        current_udp_ceiling_packet.extra_sum
    );
    println!(
        "zone_image_udp_ceiling_packet_bytes\t{}",
        image_udp_ceiling_packet.extra_sum
    );
    println!(
        "notify_soa_validation_exact_noerror_count\t{}",
        notify_soa_validation_exact.answer_count
    );
    println!(
        "notify_soa_validation_mixed_case_noerror_count\t{}",
        notify_soa_validation_mixed_case.answer_count
    );
    println!(
        "notify_soa_validation_exact_rcode_checksum\t{}",
        notify_soa_validation_exact.rcode_sum
    );
    println!(
        "notify_soa_validation_mixed_case_rcode_checksum\t{}",
        notify_soa_validation_mixed_case.rcode_sum
    );
    println!(
        "notify_soa_validation_exact_bytes\t{}",
        notify_soa_validation_exact.extra_sum
    );
    println!(
        "notify_soa_validation_mixed_case_bytes\t{}",
        notify_soa_validation_mixed_case.extra_sum
    );
    println!(
        "chaos_classification_exact_noerror_count\t{}",
        chaos_classification_exact.answer_count
    );
    println!(
        "chaos_classification_mixed_case_noerror_count\t{}",
        chaos_classification_mixed_case.answer_count
    );
    println!(
        "chaos_classification_exact_rcode_checksum\t{}",
        chaos_classification_exact.rcode_sum
    );
    println!(
        "chaos_classification_mixed_case_rcode_checksum\t{}",
        chaos_classification_mixed_case.rcode_sum
    );
    println!(
        "chaos_classification_exact_bytes\t{}",
        chaos_classification_exact.extra_sum
    );
    println!(
        "chaos_classification_mixed_case_bytes\t{}",
        chaos_classification_mixed_case.extra_sum
    );
    println!(
        "zone_image_mixed_wire_bytes\t{}",
        image_mixed_wire.extra_sum
    );
    println!(
        "current_delegation_dname_stress_record_count\t{}",
        current_stress.answer_count
    );
    println!(
        "zone_image_delegation_dname_stress_plan_item_count\t{}",
        image_stress_plan.answer_count
    );
    println!(
        "zone_image_delegation_dname_stress_wire_record_count\t{}",
        image_stress_wire.answer_count
    );
    println!(
        "zone_directory_linear_found_count\t{}",
        zone_directory_linear.answer_count
    );
    println!(
        "zone_directory_suffix_found_count\t{}",
        zone_directory_suffix.answer_count
    );
    println!(
        "zone_directory_linear_label_checksum\t{}",
        zone_directory_linear.extra_sum
    );
    println!(
        "zone_directory_suffix_label_checksum\t{}",
        zone_directory_suffix.extra_sum
    );
    println!(
        "zone_directory_linear_active_count_checksum\t{}",
        zone_directory_linear_active_count.answer_count
    );
    println!(
        "zone_directory_cached_active_count_checksum\t{}",
        zone_directory_cached_active_count.answer_count
    );
    println!(
        "zone_directory_full_metadata_found_count\t{}",
        zone_directory_full_metadata.answer_count
    );
    println!(
        "zone_directory_control_metadata_found_count\t{}",
        zone_directory_control_metadata.answer_count
    );
    println!(
        "zone_directory_full_metadata_serial_checksum\t{}",
        zone_directory_full_metadata.extra_sum
    );
    println!(
        "zone_directory_control_metadata_serial_checksum\t{}",
        zone_directory_control_metadata.extra_sum
    );
    println!(
        "zone_directory_full_metadata_shape_count\t{}",
        zone_directory_full_metadata.rcode_sum
    );
    println!(
        "zone_directory_control_metadata_shape_count\t{}",
        zone_directory_control_metadata.rcode_sum
    );
    println!(
        "zone_directory_serial_gated_transfer_snapshot_found_count\t{}",
        zone_directory_serial_gated_transfer_snapshot.answer_count
    );
    println!(
        "zone_directory_serial_gated_transfer_snapshot_no_serial_skip_count\t{}",
        zone_directory_serial_gated_transfer_snapshot.rcode_sum
    );
    println!(
        "zone_directory_serial_gated_transfer_snapshot_serial_checksum\t{}",
        zone_directory_serial_gated_transfer_snapshot.extra_sum
    );
    println!(
        "zone_directory_offline_snapshot_rebuild_sort_count\t{}",
        zone_directory_offline_snapshot_rebuild_sort.answer_count
    );
    println!(
        "zone_directory_offline_snapshot_cached_sort_count\t{}",
        zone_directory_offline_snapshot_cached_sort.answer_count
    );
    println!(
        "zone_directory_offline_snapshot_rebuild_sort_checksum\t{}",
        zone_directory_offline_snapshot_rebuild_sort.rcode_sum
    );
    println!(
        "zone_directory_offline_snapshot_cached_sort_checksum\t{}",
        zone_directory_offline_snapshot_cached_sort.rcode_sum
    );
    println!(
        "zone_directory_snapshot_state_clone_count\t{}",
        zone_directory_snapshot_state_clone.answer_count
    );
    println!(
        "zone_directory_entry_state_expire_count\t{}",
        zone_directory_entry_state_expire.answer_count
    );
    println!(
        "zone_directory_snapshot_state_clone_serial_checksum\t{}",
        zone_directory_snapshot_state_clone.extra_sum
    );
    println!(
        "zone_directory_entry_state_expire_serial_checksum\t{}",
        zone_directory_entry_state_expire.extra_sum
    );
    println!(
        "zone_metadata_origin_key_rebuild_count\t{}",
        zone_metadata_origin_key_rebuild.answer_count
    );
    println!(
        "zone_metadata_cached_origin_key_count\t{}",
        zone_metadata_cached_origin_key.answer_count
    );
    println!(
        "zone_metadata_origin_key_rebuild_checksum\t{}",
        zone_metadata_origin_key_rebuild.rcode_sum
    );
    println!(
        "zone_metadata_cached_origin_key_checksum\t{}",
        zone_metadata_cached_origin_key.rcode_sum
    );
    println!(
        "zone_metadata_origin_name_rebuild_count\t{}",
        zone_metadata_origin_name_rebuild.answer_count
    );
    println!(
        "zone_metadata_cached_origin_name_count\t{}",
        zone_metadata_cached_origin_name.answer_count
    );
    println!(
        "zone_metadata_origin_name_rebuild_checksum\t{}",
        zone_metadata_origin_name_rebuild.rcode_sum
    );
    println!(
        "zone_metadata_cached_origin_name_checksum\t{}",
        zone_metadata_cached_origin_name.rcode_sum
    );
    println!("current_mixed_rcode_checksum\t{}", current_mixed.rcode_sum);
    println!(
        "zone_image_mixed_plan_rcode_checksum\t{}",
        image_mixed_plan.rcode_sum
    );
    println!(
        "zone_image_mixed_wire_rcode_checksum\t{}",
        image_mixed_wire.rcode_sum
    );
    println!("zone_image_nodes\t{}", stats.node_count);
    println!("zone_image_edges\t{}", stats.edge_count);
    println!("zone_image_child_hashes\t{}", stats.child_hash_count);
    println!(
        "zone_image_child_hash_slots\t{}",
        stats.child_hash_slot_count
    );
    println!(
        "zone_image_child_hash_slot_bytes\t{}",
        stats.child_hash_slot_bytes
    );
    println!("zone_image_max_child_fanout\t{}", stats.max_child_fanout);
    println!(
        "zone_image_max_rrsets_per_name\t{}",
        stats.max_rrsets_per_name
    );
    println!("zone_image_rrsets\t{}", stats.rrset_count);
    println!("zone_image_records\t{}", stats.record_count);
    println!("zone_image_hot_bytes\t{}", stats.hot_bytes);
    println!("zone_image_cold_bytes\t{}", stats.cold_bytes);
    println!("zone_image_bytes_per_record\t{}", stats.bytes_per_record);
    let stress_stats = stress_image.stats();
    println!(
        "zone_image_delegation_dname_stress_nodes\t{}",
        stress_stats.node_count
    );
    println!(
        "zone_image_delegation_dname_stress_edges\t{}",
        stress_stats.edge_count
    );
    println!(
        "zone_image_delegation_dname_stress_child_hashes\t{}",
        stress_stats.child_hash_count
    );
    println!(
        "zone_image_delegation_dname_stress_child_hash_slots\t{}",
        stress_stats.child_hash_slot_count
    );
    println!(
        "zone_image_delegation_dname_stress_child_hash_slot_bytes\t{}",
        stress_stats.child_hash_slot_bytes
    );
    println!(
        "zone_image_delegation_dname_stress_rrsets\t{}",
        stress_stats.rrset_count
    );
    println!(
        "zone_image_delegation_dname_stress_records\t{}",
        stress_stats.record_count
    );
    println!(
        "zone_image_delegation_dname_stress_hot_bytes\t{}",
        stress_stats.hot_bytes
    );
    println!(
        "zone_image_delegation_dname_stress_cold_bytes\t{}",
        stress_stats.cold_bytes
    );
    println!(
        "zone_image_delegation_dname_stress_bytes_per_record\t{}",
        stress_stats.bytes_per_record
    );
    emit_shape_histogram(
        "zone_shape_child_name_fanout_names",
        &shape_histograms.child_name_fanout_names,
    );
    emit_shape_histogram(
        "zone_shape_rrsets_per_owner_names",
        &shape_histograms.rrsets_per_owner_name,
    );
    emit_shape_histogram(
        "zone_shape_rdata_records_per_rrset",
        &shape_histograms.rdata_records_per_rrset,
    );
    emit_shape_histogram(
        "zone_shape_rdata_payload_bytes_per_rrset",
        &shape_histograms.rdata_payload_bytes_per_rrset,
    );
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_string(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

struct BenchConfig {
    records: usize,
    zone_directory_zones: usize,
    stress_candidates: usize,
    iterations: usize,
    build_profile: String,
    git_revision: String,
    git_dirty: String,
    kernel: String,
    rustc: String,
    rust_target: String,
    cpu_model: String,
    network_device: String,
    artifact: String,
    trace_path: String,
}

impl BenchConfig {
    fn from_env_and_args() -> Self {
        let mut config = Self {
            records: env_usize("OXIDEDNS_ZONE_IMAGE_BENCH_RECORDS", 10_000),
            zone_directory_zones: env_usize(
                "OXIDEDNS_ZONE_IMAGE_BENCH_ZONE_DIRECTORY_ZONES",
                1_000,
            ),
            stress_candidates: env_usize(
                "OXIDEDNS_ZONE_IMAGE_BENCH_STRESS_CANDIDATES",
                env_usize("OXIDEDNS_ZONE_IMAGE_BENCH_RECORDS", 10_000).min(2_000),
            ),
            iterations: env_usize("OXIDEDNS_ZONE_IMAGE_BENCH_ITERATIONS", 200_000),
            build_profile: env_string("OXIDEDNS_ZONE_IMAGE_BENCH_BUILD_PROFILE", "unknown"),
            git_revision: env_string("OXIDEDNS_ZONE_IMAGE_BENCH_GIT_REVISION", "unknown"),
            git_dirty: env_string("OXIDEDNS_ZONE_IMAGE_BENCH_GIT_DIRTY", "unknown"),
            kernel: env_string("OXIDEDNS_ZONE_IMAGE_BENCH_KERNEL", "unknown"),
            rustc: env_string("OXIDEDNS_ZONE_IMAGE_BENCH_RUSTC", "unknown"),
            rust_target: env_string("OXIDEDNS_ZONE_IMAGE_BENCH_RUST_TARGET", "unknown"),
            cpu_model: env_string("OXIDEDNS_ZONE_IMAGE_BENCH_CPU_MODEL", "unknown"),
            network_device: env_string("OXIDEDNS_ZONE_IMAGE_BENCH_NETWORK_DEVICE", "unknown"),
            artifact: env_string("OXIDEDNS_ZONE_IMAGE_BENCH_OUTPUT", "stdout"),
            trace_path: env_string(
                "OXIDEDNS_ZONE_IMAGE_BENCH_TRACE",
                "crates/oxidedns-core/examples/zone_image_reference_trace.tsv",
            ),
        };

        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--records" => config.records = parse_next_usize(&mut args, "--records"),
                "--zone-directory-zones" => {
                    config.zone_directory_zones =
                        parse_next_usize(&mut args, "--zone-directory-zones");
                }
                "--stress-candidates" => {
                    config.stress_candidates = parse_next_usize(&mut args, "--stress-candidates");
                }
                "--iterations" => {
                    config.iterations = parse_next_usize(&mut args, "--iterations");
                }
                "--build-profile" => config.build_profile = parse_next_string(&mut args, &arg),
                "--git-revision" => config.git_revision = parse_next_string(&mut args, &arg),
                "--git-dirty" => config.git_dirty = parse_next_string(&mut args, &arg),
                "--kernel" => config.kernel = parse_next_string(&mut args, &arg),
                "--rustc" => config.rustc = parse_next_string(&mut args, &arg),
                "--rust-target" => config.rust_target = parse_next_string(&mut args, &arg),
                "--cpu-model" => config.cpu_model = parse_next_string(&mut args, &arg),
                "--network-device" => config.network_device = parse_next_string(&mut args, &arg),
                "--artifact" => config.artifact = parse_next_string(&mut args, &arg),
                "--trace" => config.trace_path = parse_next_string(&mut args, &arg),
                _ => panic!("unsupported benchmark argument: {arg}"),
            }
        }

        config
    }
}

fn parse_next_string(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    args.next()
        .unwrap_or_else(|| panic!("missing value for {flag}"))
}

fn parse_next_usize(args: &mut impl Iterator<Item = String>, flag: &str) -> usize {
    parse_next_string(args, flag)
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or_else(|| panic!("{flag} requires a positive integer"))
}

fn build_snapshot(record_count: usize) -> (ZoneSnapshot, Vec<DomainName>, Vec<QueryCase>) {
    let origin = DomainName::from_absolute_str("bench.test.").unwrap();
    let mut rrsets = Vec::with_capacity(record_count + 15);
    let mut qnames = Vec::with_capacity(record_count);
    rrsets.push(Rrset::new(
        origin.clone(),
        RecordType::Soa as u16,
        1,
        300,
        vec![soa_rdata()],
    ));
    rrsets.push(Rrset::new(
        origin.clone(),
        RecordType::Ns as u16,
        1,
        300,
        vec![name_rdata("ns.bench.test.")],
    ));
    rrsets.push(Rrset::new(
        DomainName::from_absolute_str("ns.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
        300,
        vec![[192, 0, 2, 53].to_vec()],
    ));

    for index in 0..record_count {
        let owner = DomainName::from_absolute_str(&format!("host{index}.bench.test.")).unwrap();
        let rdata = vec![192, 0, ((index >> 8) & 0xff) as u8, (index & 0xff) as u8];
        rrsets.push(Rrset::new(
            owner.clone(),
            RecordType::A as u16,
            1,
            300,
            vec![rdata],
        ));
        qnames.push(owner);
    }

    rrsets.extend(mixed_rrsets());
    let mixed_queries = mixed_queries();

    (
        ZoneSnapshot::active(origin, Some(1), rrsets),
        qnames,
        mixed_queries,
    )
}

fn build_cname_free_snapshot(record_count: usize) -> (ZoneSnapshot, Vec<DomainName>) {
    let origin = DomainName::from_absolute_str("bench.test.").unwrap();
    let mut rrsets = Vec::with_capacity(record_count + 3);
    let mut qnames = Vec::with_capacity(record_count);
    rrsets.push(Rrset::new(
        origin.clone(),
        RecordType::Soa as u16,
        1,
        300,
        vec![soa_rdata()],
    ));
    rrsets.push(Rrset::new(
        origin.clone(),
        RecordType::Ns as u16,
        1,
        300,
        vec![name_rdata("ns.bench.test.")],
    ));
    rrsets.push(Rrset::new(
        DomainName::from_absolute_str("ns.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
        300,
        vec![[192, 0, 2, 53].to_vec()],
    ));

    for index in 0..record_count {
        let owner = DomainName::from_absolute_str(&format!("host{index}.bench.test.")).unwrap();
        let rdata = vec![192, 0, ((index >> 8) & 0xff) as u8, (index & 0xff) as u8];
        rrsets.push(Rrset::new(
            owner.clone(),
            RecordType::A as u16,
            1,
            300,
            vec![rdata],
        ));
        qnames.push(owner);
    }

    (ZoneSnapshot::active(origin, Some(1), rrsets), qnames)
}

fn build_delegation_dname_stress_snapshot(
    candidate_count: usize,
) -> (ZoneSnapshot, Vec<QueryCase>) {
    let origin = DomainName::from_absolute_str("bench.test.").unwrap();
    let mut rrsets = Vec::with_capacity(candidate_count.saturating_mul(4).saturating_add(3));
    rrsets.push(Rrset::new(
        origin.clone(),
        RecordType::Soa as u16,
        1,
        300,
        vec![soa_rdata()],
    ));
    rrsets.push(Rrset::new(
        origin.clone(),
        RecordType::Ns as u16,
        1,
        300,
        vec![name_rdata("ns.bench.test.")],
    ));
    rrsets.push(Rrset::new(
        DomainName::from_absolute_str("ns.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
        300,
        vec![[192, 0, 2, 53].to_vec()],
    ));

    for index in 0..candidate_count {
        let delegation_owner =
            DomainName::from_absolute_str(&format!("del{index}.bench.test.")).unwrap();
        let delegation_ns = format!("ns.del{index}.bench.test.");
        rrsets.push(Rrset::new(
            delegation_owner,
            RecordType::Ns as u16,
            1,
            300,
            vec![name_rdata(&delegation_ns)],
        ));
        rrsets.push(Rrset::new(
            DomainName::from_absolute_str(&delegation_ns).unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, ((index >> 8) & 0xff) as u8, (index & 0xff) as u8].to_vec()],
        ));

        let dname_owner =
            DomainName::from_absolute_str(&format!("dname{index}.bench.test.")).unwrap();
        let dname_target = format!("target{index}.bench.test.");
        rrsets.push(Rrset::new(
            dname_owner,
            RecordType::Dname as u16,
            1,
            300,
            vec![name_rdata(&dname_target)],
        ));
        rrsets.push(Rrset::new(
            DomainName::from_absolute_str(&format!("leaf.{dname_target}")).unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[198, 51, ((index >> 8) & 0xff) as u8, (index & 0xff) as u8].to_vec()],
        ));
    }

    let case_count = candidate_count.clamp(1, 100);
    let mut queries = Vec::with_capacity(case_count.saturating_mul(2));
    for offset in 0..case_count {
        let candidate_index = offset * candidate_count / case_count;
        queries.push(QueryCase {
            qname: DomainName::from_absolute_str(&format!("www.del{candidate_index}.bench.test."))
                .unwrap(),
            qtype: RecordType::A as u16,
            qclass: 1,
        });
        queries.push(QueryCase {
            qname: DomainName::from_absolute_str(&format!(
                "leaf.dname{candidate_index}.bench.test."
            ))
            .unwrap(),
            qtype: RecordType::A as u16,
            qclass: 1,
        });
    }

    (ZoneSnapshot::active(origin, Some(1), rrsets), queries)
}

fn build_zone_directory_benchmark(
    zone_count: usize,
) -> (ZoneStore, Vec<DomainName>, Vec<DomainName>) {
    let store = ZoneStore::new();
    let mut origins = Vec::with_capacity(zone_count);
    let mut qnames = Vec::with_capacity(zone_count.saturating_add(1));

    for index in 0..zone_count {
        let origin =
            DomainName::from_absolute_str(&format!("zone{index}.catalog-bench.test.")).unwrap();
        let serial = u32::try_from(index)
            .ok()
            .map(|value| value.saturating_add(1));
        store.insert_snapshot(ZoneSnapshot::active(origin.clone(), serial, Vec::new()));
        origins.push(origin);
        qnames.push(
            DomainName::from_absolute_str(&format!("www.zone{index}.catalog-bench.test.")).unwrap(),
        );
    }
    qnames.push(DomainName::from_absolute_str("outside.catalog-bench.test.").unwrap());

    (store, origins, qnames)
}

fn build_zone_directory_serial_gate_benchmark(zone_count: usize) -> (ZoneStore, Vec<DomainName>) {
    let store = ZoneStore::new();
    let mut origins = Vec::with_capacity(zone_count);

    for index in 0..zone_count {
        let origin =
            DomainName::from_absolute_str(&format!("ixfr{index}.catalog-bench.test.")).unwrap();
        let serial = (index % 2 == 0).then(|| {
            u32::try_from(index)
                .ok()
                .map(|value| value.saturating_add(1))
                .unwrap_or(u32::MAX)
        });
        store.insert_snapshot(ZoneSnapshot::active(origin.clone(), serial, Vec::new()));
        origins.push(origin);
    }

    (store, origins)
}

fn hot_direct_qnames(qnames: &[DomainName]) -> Vec<DomainName> {
    let mut hot = Vec::with_capacity(100);
    let hot_name = qnames
        .first()
        .expect("benchmark snapshot must include at least one direct query name");
    for _ in 0..90 {
        hot.push(hot_name.clone());
    }
    for offset in 0..10 {
        let spread_index = offset * qnames.len() / 10;
        hot.push(qnames[spread_index].clone());
    }
    hot
}

fn high_fanout_qnames(qnames: &[DomainName]) -> Vec<DomainName> {
    let first = qnames
        .first()
        .expect("benchmark snapshot must include direct query names")
        .clone();
    let middle = qnames[qnames.len() / 2].clone();
    let last = qnames
        .last()
        .expect("benchmark snapshot must include direct query names")
        .clone();
    vec![
        first,
        middle,
        last,
        DomainName::from_absolute_str("absent-high-fanout.bench.test.").unwrap(),
    ]
}

fn rrtype_query_cases(qnames: &[DomainName], qtype: u16) -> Vec<QueryCase> {
    qnames
        .iter()
        .cloned()
        .map(|qname| QueryCase {
            qname,
            qtype,
            qclass: 1,
        })
        .collect()
}

fn child_lookup_queries(profile: &ZoneImageChildLookupProfile) -> Vec<Vec<u8>> {
    child_lookup_queries_for_labels(&profile.labels)
}

fn child_lookup_queries_for_labels(labels: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let first = labels
        .first()
        .expect("widest child profile must include labels")
        .clone();
    let middle = labels[labels.len() / 2].clone();
    let last = labels
        .last()
        .expect("widest child profile must include labels")
        .clone();
    let mut absent = b"absent-high-fanout".to_vec();
    while labels
        .binary_search_by(|label| cmp_child_label(label, &absent))
        .is_ok()
    {
        absent.push(b'x');
    }

    vec![first, middle, last, absent]
}

fn small_child_lookup_labels() -> Vec<Vec<u8>> {
    ["alpha", "bravo", "charlie", "delta"]
        .into_iter()
        .map(|label| label.as_bytes().to_vec())
        .collect()
}

fn emit_shape_histogram(prefix: &str, buckets: &[ZoneShapeHistogramBucket]) {
    for bucket in buckets {
        println!("{prefix}_bucket_{}\t{}", bucket.bucket, bucket.count);
    }
}

fn time_current_lookup(
    snapshot: &ZoneSnapshot,
    qnames: &[DomainName],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut answer_count = 0usize;
    for index in 0..iterations {
        let qname = &qnames[index % qnames.len()];
        let lookup = snapshot
            .offline_oracle()
            .lookup(black_box(qname), RecordType::A as u16, 1);
        answer_count = answer_count.saturating_add(lookup.answers.len());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(answer_count),
        rcode_sum: 0,
        extra_sum: 0,
    }
}

fn time_zone_image_exact_lookup(
    image: &ZoneImage,
    qnames: &[DomainName],
    iterations: usize,
) -> TimedLookup {
    time_zone_image_exact_lookup_for_type(image, qnames, RecordType::A as u16, iterations)
}

fn time_zone_image_exact_lookup_for_type(
    image: &ZoneImage,
    qnames: &[DomainName],
    qtype: u16,
    iterations: usize,
) -> TimedLookup {
    time_zone_image_exact_lookup_for_type_qclass(image, qnames, qtype, 1, iterations)
}

fn time_zone_image_exact_lookup_for_type_qclass(
    image: &ZoneImage,
    qnames: &[DomainName],
    qtype: u16,
    qclass: u16,
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut answer_count = 0usize;
    for index in 0..iterations {
        let qname = &qnames[index % qnames.len()];
        if let ZoneImageLookupOutcome::Found(plan) =
            image.lookup_exact_plan(black_box(qname), black_box(qtype), black_box(qclass))
        {
            answer_count = answer_count.saturating_add(plan.answer_rrsets().len());
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(answer_count),
        rcode_sum: 0,
        extra_sum: 0,
    }
}

fn time_zone_image_direct_preflight(
    image: &ZoneImage,
    qnames: &[DomainName],
    qtype: u16,
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut answer_count = 0usize;
    for index in 0..iterations {
        let qname = &qnames[index % qnames.len()];
        if let Some(plan) = image.lookup_direct_answer_plan(black_box(qname), black_box(qtype), 1) {
            answer_count = answer_count.saturating_add(plan.answer_rrsets().len());
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(answer_count),
        rcode_sum: 0,
        extra_sum: 0,
    }
}

fn time_sorted_child_lookup(
    labels: &[Vec<u8>],
    queries: &[Vec<u8>],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut index_checksum = 0usize;
    for index in 0..iterations {
        let query = &queries[index % queries.len()];
        if let Some(label_index) = sorted_child_lookup(labels, black_box(query)) {
            found_count = found_count.saturating_add(1);
            index_checksum = index_checksum.saturating_add(label_index);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: 0,
        extra_sum: black_box(index_checksum),
    }
}

fn time_hashmap_child_lookup(
    labels: &[Vec<u8>],
    queries: &[Vec<u8>],
    iterations: usize,
) -> TimedLookup {
    let index = labels
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, label)| (label, index))
        .collect::<HashMap<_, _>>();
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut index_checksum = 0usize;
    for offset in 0..iterations {
        let query = &queries[offset % queries.len()];
        if let Some(label_index) = index.get(black_box(query.as_slice())) {
            found_count = found_count.saturating_add(1);
            index_checksum = index_checksum.saturating_add(*label_index);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: 0,
        extra_sum: black_box(index_checksum),
    }
}

fn time_linear_child_lookup(
    labels: &[Vec<u8>],
    queries: &[Vec<u8>],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut index_checksum = 0usize;
    for offset in 0..iterations {
        let query = &queries[offset % queries.len()];
        if let Some(label_index) = linear_child_lookup(labels, black_box(query)) {
            found_count = found_count.saturating_add(1);
            index_checksum = index_checksum.saturating_add(label_index);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: 0,
        extra_sum: black_box(index_checksum),
    }
}

fn time_byte_bucket_child_lookup(
    index: &ByteBucketChildIndex,
    queries: &[Vec<u8>],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut index_checksum = 0usize;
    for offset in 0..iterations {
        let query = &queries[offset % queries.len()];
        if let Some(label_index) = index.find(black_box(query)) {
            found_count = found_count.saturating_add(1);
            index_checksum = index_checksum.saturating_add(label_index);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: 0,
        extra_sum: black_box(index_checksum),
    }
}

fn time_length_bucket_child_lookup(
    index: &LengthBucketChildIndex,
    queries: &[Vec<u8>],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut index_checksum = 0usize;
    for offset in 0..iterations {
        let query = &queries[offset % queries.len()];
        if let Some(label_index) = index.find(black_box(query)) {
            found_count = found_count.saturating_add(1);
            index_checksum = index_checksum.saturating_add(label_index);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: 0,
        extra_sum: black_box(index_checksum),
    }
}

fn time_last_byte_bucket_child_lookup(
    index: &LastByteBucketChildIndex,
    queries: &[Vec<u8>],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut index_checksum = 0usize;
    for offset in 0..iterations {
        let query = &queries[offset % queries.len()];
        if let Some(label_index) = index.find(black_box(query)) {
            found_count = found_count.saturating_add(1);
            index_checksum = index_checksum.saturating_add(label_index);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: 0,
        extra_sum: black_box(index_checksum),
    }
}

fn time_generated_child_hash_lookup(
    index: &GeneratedChildHashIndex,
    queries: &[Vec<u8>],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut index_checksum = 0usize;
    for offset in 0..iterations {
        let query = &queries[offset % queries.len()];
        if let Some(label_index) = index.find(black_box(query)) {
            found_count = found_count.saturating_add(1);
            index_checksum = index_checksum.saturating_add(label_index);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: 0,
        extra_sum: black_box(index_checksum),
    }
}

fn sorted_child_lookup(labels: &[Vec<u8>], query: &[u8]) -> Option<usize> {
    let mut left = 0usize;
    let mut right = labels.len();
    while left < right {
        let mid = left + (right - left) / 2;
        match cmp_child_label(&labels[mid], query) {
            std::cmp::Ordering::Less => left = mid + 1,
            std::cmp::Ordering::Greater => right = mid,
            std::cmp::Ordering::Equal => return Some(mid),
        }
    }
    None
}

fn linear_child_lookup(labels: &[Vec<u8>], query: &[u8]) -> Option<usize> {
    labels
        .iter()
        .position(|label| label.eq_ignore_ascii_case(query))
}

fn time_current_response_lookup(
    snapshot: &ZoneSnapshot,
    queries: &[QueryCase],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut record_count = 0usize;
    let mut rcode_sum = 0u64;
    for index in 0..iterations {
        let query = &queries[index % queries.len()];
        let lookup =
            snapshot
                .offline_oracle()
                .lookup(black_box(&query.qname), query.qtype, query.qclass);
        record_count = record_count
            .saturating_add(lookup.answers.len())
            .saturating_add(lookup.authorities.len())
            .saturating_add(lookup.additionals.len());
        rcode_sum = rcode_sum.saturating_add(rcode_number(lookup.rcode));
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(record_count),
        rcode_sum: black_box(rcode_sum),
        extra_sum: 0,
    }
}

fn time_zone_directory_linear_lookup(
    snapshots: &[OfflineZoneSnapshot],
    qnames: &[DomainName],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut label_checksum = 0usize;
    for index in 0..iterations {
        let qname = &qnames[index % qnames.len()];
        let found = snapshots
            .iter()
            .map(|snapshot| snapshot.snapshot_for_offline_oracle())
            .filter(|zone| qname.is_equal_or_subdomain_of(&zone.origin))
            .max_by_key(|zone| zone.origin.label_count());
        if let Some(zone) = found {
            found_count = found_count.saturating_add(1);
            label_checksum = label_checksum.saturating_add(zone.origin.label_count());
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: 0,
        extra_sum: black_box(label_checksum),
    }
}

fn time_zone_directory_suffix_lookup(
    store: &ZoneStore,
    qnames: &[DomainName],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut label_checksum = 0usize;
    for index in 0..iterations {
        let qname = &qnames[index % qnames.len()];
        if let Some(published) =
            store.find_published_zone_with_ascii_lowercase_hint(black_box(qname), true)
        {
            found_count = found_count.saturating_add(1);
            label_checksum = label_checksum.saturating_add(published.origin_label_count());
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: 0,
        extra_sum: black_box(label_checksum),
    }
}

fn time_zone_directory_linear_active_count(
    snapshots: &[OfflineZoneSnapshot],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..iterations {
        let active_count = snapshots
            .iter()
            .filter(|snapshot| snapshot.state() == oxidedns_core::zone::ZoneState::Active)
            .count();
        checksum = checksum.saturating_add(active_count);
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(checksum),
        rcode_sum: 0,
        extra_sum: 0,
    }
}

fn time_zone_directory_cached_active_count(store: &ZoneStore, iterations: usize) -> TimedLookup {
    let started = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..iterations {
        checksum = checksum.saturating_add(store.active_count());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(checksum),
        rcode_sum: 0,
        extra_sum: 0,
    }
}

fn time_zone_directory_offline_snapshot_rebuild_sort(
    snapshots: &[OfflineZoneSnapshot],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut checksum = FNV_OFFSET_BASIS;
    let mut snapshot_count = 0usize;
    for _ in 0..iterations {
        let mut snapshots = snapshots
            .iter()
            .map(|snapshot| snapshot.snapshot_for_offline_oracle())
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|snapshot| snapshot.origin.canonical_key());
        snapshot_count = snapshot_count.saturating_add(snapshots.len());
        for snapshot in &snapshots {
            checksum = fnv1a_bytes(checksum, &snapshot.serial.unwrap_or_default().to_be_bytes());
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(snapshot_count),
        rcode_sum: black_box(checksum),
        extra_sum: 0,
    }
}

fn time_zone_directory_offline_snapshot_cached_sort(
    store: &ZoneStore,
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut checksum = FNV_OFFSET_BASIS;
    let mut snapshot_count = 0usize;
    for _ in 0..iterations {
        let snapshots = store.offline_snapshots();
        snapshot_count = snapshot_count.saturating_add(snapshots.len());
        for snapshot in &snapshots {
            checksum = fnv1a_bytes(
                checksum,
                &snapshot.serial().unwrap_or_default().to_be_bytes(),
            );
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(snapshot_count),
        rcode_sum: black_box(checksum),
        extra_sum: 0,
    }
}

fn time_zone_directory_full_metadata(
    store: &ZoneStore,
    origins: &[DomainName],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut shape_count = 0u64;
    let mut serial_checksum = 0usize;
    for index in 0..iterations {
        let origin = &origins[index % origins.len()];
        if let Some(metadata) = store.exact_zone_metadata(origin) {
            found_count = found_count.saturating_add(1);
            shape_count = shape_count.saturating_add(u64::from(metadata.shape.is_some()));
            serial_checksum =
                serial_checksum.saturating_add(metadata.serial.unwrap_or_default() as usize);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: black_box(shape_count),
        extra_sum: black_box(serial_checksum),
    }
}

fn time_zone_directory_control_metadata(
    store: &ZoneStore,
    origins: &[DomainName],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut shape_count = 0u64;
    let mut serial_checksum = 0usize;
    for index in 0..iterations {
        let origin = &origins[index % origins.len()];
        if let Some(metadata) = store.exact_zone_control_metadata(origin) {
            found_count = found_count.saturating_add(1);
            shape_count = shape_count.saturating_add(u64::from(metadata.shape.is_some()));
            serial_checksum =
                serial_checksum.saturating_add(metadata.serial.unwrap_or_default() as usize);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: black_box(shape_count),
        extra_sum: black_box(serial_checksum),
    }
}

fn time_zone_directory_serial_gated_transfer_snapshot(
    store: &ZoneStore,
    origins: &[DomainName],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut found_count = 0usize;
    let mut no_serial_skip_count = 0u64;
    let mut serial_checksum = 0usize;
    for index in 0..iterations {
        let origin = &origins[index % origins.len()];
        if let Some(current) = store.exact_snapshot_with_serial_for_transfer(origin) {
            found_count = found_count.saturating_add(1);
            serial_checksum = serial_checksum
                .saturating_add(current.metadata().serial.unwrap_or_default() as usize);
        } else if store
            .exact_zone_control_metadata(origin)
            .is_some_and(|metadata| metadata.serial.is_none())
        {
            no_serial_skip_count = no_serial_skip_count.saturating_add(1);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(found_count),
        rcode_sum: black_box(no_serial_skip_count),
        extra_sum: black_box(serial_checksum),
    }
}

fn time_zone_directory_snapshot_state_clone(snapshots: &[OfflineZoneSnapshot]) -> TimedLookup {
    let started = Instant::now();
    let mut expired_count = 0usize;
    let mut serial_checksum = 0usize;
    for snapshot in snapshots {
        let expired = black_box(
            snapshot
                .snapshot_for_offline_oracle()
                .with_state(ZoneState::Expired),
        );
        expired_count =
            expired_count.saturating_add(usize::from(expired.state == ZoneState::Expired));
        serial_checksum =
            serial_checksum.saturating_add(expired.serial.unwrap_or_default() as usize);
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(expired_count),
        rcode_sum: 0,
        extra_sum: black_box(serial_checksum),
    }
}

fn time_zone_directory_entry_state_expire(
    store: &ZoneStore,
    origins: &[DomainName],
) -> TimedLookup {
    let started = Instant::now();
    let mut expired_count = 0usize;
    let mut serial_checksum = 0usize;
    for origin in origins {
        if store.expire_zone(black_box(origin)) {
            expired_count = expired_count.saturating_add(1);
        }
        if let Some(metadata) = store.exact_zone_control_metadata(origin) {
            serial_checksum =
                serial_checksum.saturating_add(metadata.serial.unwrap_or_default() as usize);
        }
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(expired_count),
        rcode_sum: 0,
        extra_sum: black_box(serial_checksum),
    }
}

fn time_zone_metadata_origin_key_rebuild(
    metadata: &[ZoneMetadata],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut checksum = FNV_OFFSET_BASIS;
    for index in 0..iterations {
        let metadata = &metadata[index % metadata.len()];
        let key = metadata.origin.canonical_key();
        checksum = fnv1a_bytes(checksum, key.as_bytes());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: iterations,
        rcode_sum: black_box(checksum),
        extra_sum: 0,
    }
}

fn time_zone_metadata_cached_origin_key(
    metadata: &[ZoneMetadata],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut checksum = FNV_OFFSET_BASIS;
    for index in 0..iterations {
        let metadata = &metadata[index % metadata.len()];
        checksum = fnv1a_bytes(checksum, metadata.origin_key.as_bytes());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: iterations,
        rcode_sum: black_box(checksum),
        extra_sum: 0,
    }
}

fn time_zone_metadata_origin_name_rebuild(
    metadata: &[ZoneMetadata],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut checksum = FNV_OFFSET_BASIS;
    for index in 0..iterations {
        let metadata = &metadata[index % metadata.len()];
        let name = metadata.origin.to_string();
        checksum = fnv1a_bytes(checksum, name.as_bytes());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: iterations,
        rcode_sum: black_box(checksum),
        extra_sum: 0,
    }
}

fn time_zone_metadata_cached_origin_name(
    metadata: &[ZoneMetadata],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut checksum = FNV_OFFSET_BASIS;
    for index in 0..iterations {
        let metadata = &metadata[index % metadata.len()];
        checksum = fnv1a_bytes(checksum, metadata.origin_name.as_bytes());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: iterations,
        rcode_sum: black_box(checksum),
        extra_sum: 0,
    }
}

fn time_zone_image_response_plan(
    image: &ZoneImage,
    queries: &[QueryCase],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut item_count = 0usize;
    let mut rcode_sum = 0u64;
    for index in 0..iterations {
        let query = &queries[index % queries.len()];
        let plan = image.lookup_response_plan(
            black_box(&query.qname),
            query.qtype,
            query.qclass,
            8,
            oxidedns_core::dns::AnyResponseMode::Minimal,
        );
        item_count = item_count
            .saturating_add(plan.answer_rrsets().len())
            .saturating_add(plan.synthesized_answer_count())
            .saturating_add(plan.authority_rrsets().len())
            .saturating_add(plan.additional_rrsets().len());
        rcode_sum = rcode_sum.saturating_add(rcode_number(plan.rcode()));
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(item_count),
        rcode_sum: black_box(rcode_sum),
        extra_sum: 0,
    }
}

fn time_zone_image_response_wire(
    image: &ZoneImage,
    queries: &[QueryCase],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut record_count = 0usize;
    let mut rcode_sum = 0u64;
    let mut wire_bytes = 0usize;
    let mut wire = Vec::with_capacity(1024);
    for index in 0..iterations {
        let query = &queries[index % queries.len()];
        let plan = image.lookup_response_plan(
            black_box(&query.qname),
            query.qtype,
            query.qclass,
            8,
            oxidedns_core::dns::AnyResponseMode::Minimal,
        );
        wire.clear();
        record_count = record_count.saturating_add(image.append_plan_wire(&plan, &mut wire));
        wire_bytes = wire_bytes.saturating_add(wire.len());
        rcode_sum = rcode_sum.saturating_add(rcode_number(plan.rcode()));
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(record_count),
        rcode_sum: black_box(rcode_sum),
        extra_sum: black_box(wire_bytes),
    }
}

fn time_current_packet_response(
    store: &ZoneStore,
    packets: &[Vec<u8>],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut wire_bytes = 0usize;
    let mut rcode_sum = 0u64;
    for index in 0..iterations {
        let packet = &packets[index % packets.len()];
        let response = current_packet_response(store, black_box(packet));
        rcode_sum = rcode_sum.saturating_add(u64::from(response[3] & 0x0f));
        wire_bytes = wire_bytes.saturating_add(response.len());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: 0,
        rcode_sum: black_box(rcode_sum),
        extra_sum: black_box(wire_bytes),
    }
}

fn count_mixed_packet_mismatches(
    store: &ZoneStore,
    _image: ZoneImage,
    packets: &[Vec<u8>],
) -> usize {
    packets
        .iter()
        .filter(|packet| {
            let current = current_packet_response(store, packet);
            let zone_image =
                zone_image_packet_response(store, packet, &default_zone_image_provider);
            current != zone_image
        })
        .count()
}

fn count_packet_case_mismatches(
    store: &ZoneStore,
    _image: ZoneImage,
    packets: &[PacketCase],
) -> usize {
    packets
        .iter()
        .filter(|packet| {
            let current =
                current_packet_response_with_options(store, &packet.packet, packet.options);
            let zone_image = zone_image_packet_response_with_options(
                store,
                &packet.packet,
                packet.options,
                &default_zone_image_provider,
            );
            current != zone_image
        })
        .count()
}

fn count_ede_not_ready_packet_mismatches(_image: ZoneImage) -> usize {
    let store = ZoneStore::new();
    store.insert_loading(DomainName::from_absolute_str("bench.test.").unwrap());
    let mut packet = query_packet(
        &DomainName::from_absolute_str("host0.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 4096, 0, &[]);
    let options = AnswerOptions {
        extended_dns_errors: ExtendedDnsErrorsMode::Minimal,
        ..AnswerOptions::default()
    };
    let loading_mismatch = usize::from(
        current_packet_response_with_options(&store, &packet, options)
            != zone_image_packet_response_with_options(
                &store,
                &packet,
                options,
                &default_zone_image_provider,
            ),
    );

    loading_mismatch + count_ede_nsec3_truncation_packet_mismatch()
}

fn count_ede_nsec3_truncation_packet_mismatch() -> usize {
    let store = ZoneStore::new();
    let missing_nsec3 = nsec3_owner("missing.bench.test.", "bench.test.");
    let wildcard_nsec3 = nsec3_owner("*.bench.test.", "bench.test.");
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("bench.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("bench.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                missing_nsec3,
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata_with_iterations(1, 1)],
            ),
            Rrset::new(
                wildcard_nsec3,
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata_with_iterations(1, 1)],
            ),
        ],
    ));
    let mut packet = query_packet(
        &DomainName::from_absolute_str("missing.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 80, 0x8000, &[]);
    let options = AnswerOptions {
        nsec3_max_iterations: 0,
        extended_dns_errors: ExtendedDnsErrorsMode::Minimal,
        ..AnswerOptions::udp(80)
    };

    usize::from(
        current_packet_response_with_options(&store, &packet, options)
            != zone_image_packet_response_with_options(
                &store,
                &packet,
                options,
                &default_zone_image_provider,
            ),
    )
}

fn time_current_packet_case_response(
    store: &ZoneStore,
    packets: &[PacketCase],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut wire_bytes = 0usize;
    let mut rcode_sum = 0u64;
    for index in 0..iterations {
        let packet = &packets[index % packets.len()];
        let response =
            current_packet_response_with_options(store, black_box(&packet.packet), packet.options);
        rcode_sum = rcode_sum.saturating_add(u64::from(response[3] & 0x0f));
        wire_bytes = wire_bytes.saturating_add(response.len());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: 0,
        rcode_sum: black_box(rcode_sum),
        extra_sum: black_box(wire_bytes),
    }
}

fn time_zone_image_packet_case_response(
    store: &ZoneStore,
    _image: ZoneImage,
    packets: &[PacketCase],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut wire_bytes = 0usize;
    let mut rcode_sum = 0u64;
    for index in 0..iterations {
        let packet = &packets[index % packets.len()];
        let response = zone_image_packet_response_with_options(
            store,
            black_box(&packet.packet),
            packet.options,
            &default_zone_image_provider,
        );
        rcode_sum = rcode_sum.saturating_add(u64::from(response[3] & 0x0f));
        wire_bytes = wire_bytes.saturating_add(response.len());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: 0,
        rcode_sum: black_box(rcode_sum),
        extra_sum: black_box(wire_bytes),
    }
}

fn time_zone_image_packet_response(
    store: &ZoneStore,
    _image: ZoneImage,
    packets: &[Vec<u8>],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut wire_bytes = 0usize;
    let mut rcode_sum = 0u64;
    for index in 0..iterations {
        let packet = &packets[index % packets.len()];
        let response =
            zone_image_packet_response(store, black_box(packet), &default_zone_image_provider);
        rcode_sum = rcode_sum.saturating_add(u64::from(response[3] & 0x0f));
        wire_bytes = wire_bytes.saturating_add(response.len());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: 0,
        rcode_sum: black_box(rcode_sum),
        extra_sum: black_box(wire_bytes),
    }
}

fn time_notify_soa_packet_response(
    store: &ZoneStore,
    packet: &[u8],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut noerror_count = 0usize;
    let mut wire_bytes = 0usize;
    let mut rcode_sum = 0u64;
    for _ in 0..iterations {
        let response = current_packet_response(store, black_box(packet));
        let rcode = response[3] & 0x0f;
        noerror_count += usize::from(rcode == Rcode::NoError as u8);
        rcode_sum = rcode_sum.saturating_add(u64::from(rcode));
        wire_bytes = wire_bytes.saturating_add(response.len());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(noerror_count),
        rcode_sum: black_box(rcode_sum),
        extra_sum: black_box(wire_bytes),
    }
}

fn time_chaos_packet_response(store: &ZoneStore, packet: &[u8], iterations: usize) -> TimedLookup {
    let options = AnswerOptions {
        chaos: oxidedns_core::dns::ChaosOptions {
            version: "OxideDNS",
            hostname: "",
        },
        ..AnswerOptions::default()
    };
    let started = Instant::now();
    let mut noerror_count = 0usize;
    let mut wire_bytes = 0usize;
    let mut rcode_sum = 0u64;
    for _ in 0..iterations {
        let response = current_packet_response_with_options(store, black_box(packet), options);
        let rcode = response[3] & 0x0f;
        noerror_count += usize::from(rcode == Rcode::NoError as u8);
        rcode_sum = rcode_sum.saturating_add(u64::from(rcode));
        wire_bytes = wire_bytes.saturating_add(response.len());
    }
    TimedLookup {
        duration: started.elapsed(),
        answer_count: black_box(noerror_count),
        rcode_sum: black_box(rcode_sum),
        extra_sum: black_box(wire_bytes),
    }
}

fn current_packet_response(store: &ZoneStore, packet: &[u8]) -> Vec<u8> {
    current_packet_response_with_options(store, packet, AnswerOptions::default())
}

fn current_packet_response_with_options(
    store: &ZoneStore,
    packet: &[u8],
    options: AnswerOptions,
) -> Vec<u8> {
    match answer_message(packet, store, options) {
        DatagramAction::Respond(response) => response,
        DatagramAction::Discard => panic!("benchmark query was discarded"),
    }
}

fn zone_image_packet_response(
    store: &ZoneStore,
    packet: &[u8],
    provider: ZoneImageProvider<'_>,
) -> Vec<u8> {
    zone_image_packet_response_with_options(store, packet, AnswerOptions::default(), provider)
}

fn zone_image_packet_response_with_options(
    store: &ZoneStore,
    packet: &[u8],
    options: AnswerOptions,
    provider: ZoneImageProvider<'_>,
) -> Vec<u8> {
    match answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        packet,
        store,
        options,
        |_, _| true,
        |_, _, _| {},
        |_| {},
        provider,
    ) {
        DatagramAction::Respond(response) => response,
        DatagramAction::Discard => panic!("benchmark query was discarded"),
    }
}

fn count_mixed_lookup_mismatches(
    snapshot: &ZoneSnapshot,
    image: &ZoneImage,
    queries: &[QueryCase],
) -> usize {
    queries
        .iter()
        .filter(|query| {
            let snapshot_lookup =
                snapshot
                    .offline_oracle()
                    .lookup(&query.qname, query.qtype, query.qclass);
            let image_plan = image.lookup_response_plan(
                &query.qname,
                query.qtype,
                query.qclass,
                8,
                oxidedns_core::dns::AnyResponseMode::Minimal,
            );
            let image_summary = image
                .plan_summary(&image_plan)
                .expect("zone image plan summarizes");
            snapshot_lookup_summary(&snapshot_lookup) != image_summary
        })
        .count()
}

fn snapshot_lookup_summary(lookup: &LookupResult) -> ZoneImagePlanSummary {
    ZoneImagePlanSummary {
        rcode: lookup.rcode,
        authoritative: lookup.authoritative,
        answers: snapshot_records_summary(&lookup.answers),
        authorities: snapshot_records_summary(&lookup.authorities),
        additionals: snapshot_records_summary(&lookup.additionals),
        termination: lookup.termination,
        nsec3_iterations_exceeded: lookup.nsec3_iterations_exceeded,
    }
}

fn snapshot_records_summary(records: &[ResourceRecord]) -> ZoneImagePlanSectionSummary {
    let mut summary = SnapshotSectionSummary::default();
    for record in records {
        summary.observe(record);
    }
    summary.finish()
}

#[derive(Debug, Clone, Copy)]
struct SnapshotSectionSummary {
    count: usize,
    digest: u64,
}

impl Default for SnapshotSectionSummary {
    fn default() -> Self {
        Self {
            count: 0,
            digest: FNV_OFFSET_BASIS,
        }
    }
}

impl SnapshotSectionSummary {
    fn observe(&mut self, record: &ResourceRecord) {
        self.count += 1;
        self.digest = fnv1a_u64(
            self.digest,
            hash_record_identity(
                record.owner.canonical_key().as_bytes(),
                record.rr_type,
                record.class,
                record.ttl,
                &record.rdata,
            ),
        );
    }

    fn finish(self) -> ZoneImagePlanSectionSummary {
        ZoneImagePlanSectionSummary {
            count: self.count,
            digest: self.digest,
        }
    }
}

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn hash_record_identity(owner_key: &[u8], rr_type: u16, class: u16, ttl: u32, rdata: &[u8]) -> u64 {
    let mut digest = FNV_OFFSET_BASIS;
    digest = fnv1a_bytes(digest, owner_key);
    digest = fnv1a_bytes(digest, &rr_type.to_be_bytes());
    digest = fnv1a_bytes(digest, &class.to_be_bytes());
    digest = fnv1a_bytes(digest, &ttl.to_be_bytes());
    digest = fnv1a_bytes(digest, &(rdata.len() as u64).to_be_bytes());
    fnv1a_bytes(digest, rdata)
}

fn fnv1a_u64(digest: u64, value: u64) -> u64 {
    fnv1a_bytes(digest, &value.to_be_bytes())
}

fn fnv1a_bytes(mut digest: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(FNV_PRIME);
    }
    digest
}

struct ByteBucketChildIndex {
    labels: Vec<Vec<u8>>,
    ranges: [(u32, u32); 256],
}

impl ByteBucketChildIndex {
    fn new(labels: &[Vec<u8>]) -> Self {
        let mut ranges = [(0u32, 0u32); 256];
        let mut start = 0usize;
        while start < labels.len() {
            let bucket = child_label_bucket(&labels[start]);
            let mut end = start + 1;
            while end < labels.len() && child_label_bucket(&labels[end]) == bucket {
                end += 1;
            }
            ranges[bucket] = (
                u32::try_from(start).expect("benchmark label start fits in u32"),
                u32::try_from(end).expect("benchmark label end fits in u32"),
            );
            start = end;
        }

        Self {
            labels: labels.to_vec(),
            ranges,
        }
    }

    fn find(&self, label: &[u8]) -> Option<usize> {
        let (start, end) = self.ranges[child_label_bucket(label)];
        if start == end {
            return None;
        }
        let base = start as usize;
        self.labels[base..end as usize]
            .binary_search_by(|candidate| cmp_child_label(candidate, label))
            .ok()
            .map(|offset| base + offset)
    }

    fn index_bytes(&self) -> usize {
        self.ranges.len() * std::mem::size_of::<(u32, u32)>()
    }
}

struct LengthBucketChildIndex {
    labels: Vec<Vec<u8>>,
    original_indexes: Vec<u32>,
    ranges: [(u32, u32); 64],
}

impl LengthBucketChildIndex {
    fn new(labels: &[Vec<u8>]) -> Self {
        let mut indexed_labels = labels
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, label)| {
                (
                    u32::try_from(index).expect("benchmark label index fits in u32"),
                    label,
                )
            })
            .collect::<Vec<_>>();
        indexed_labels.sort_by(|(_, left), (_, right)| {
            left.len()
                .cmp(&right.len())
                .then_with(|| cmp_child_label(left, right))
        });

        let mut ranges = [(0u32, 0u32); 64];
        let mut labels = Vec::with_capacity(indexed_labels.len());
        let mut original_indexes = Vec::with_capacity(indexed_labels.len());
        let mut start = 0usize;
        while start < indexed_labels.len() {
            let length = child_label_length_bucket(&indexed_labels[start].1);
            let mut end = start + 1;
            while end < indexed_labels.len()
                && child_label_length_bucket(&indexed_labels[end].1) == length
            {
                end += 1;
            }
            ranges[length] = (
                u32::try_from(start).expect("benchmark label range start fits in u32"),
                u32::try_from(end).expect("benchmark label range end fits in u32"),
            );
            for (original_index, label) in &indexed_labels[start..end] {
                original_indexes.push(*original_index);
                labels.push(label.clone());
            }
            start = end;
        }

        Self {
            labels,
            original_indexes,
            ranges,
        }
    }

    fn find(&self, label: &[u8]) -> Option<usize> {
        let (start, end) = self.ranges[child_label_length_bucket(label)];
        if start == end {
            return None;
        }
        let base = start as usize;
        self.labels[base..end as usize]
            .binary_search_by(|candidate| cmp_child_label(candidate, label))
            .ok()
            .map(|offset| self.original_indexes[base + offset] as usize)
    }

    fn index_bytes(&self) -> usize {
        self.ranges.len() * std::mem::size_of::<(u32, u32)>()
            + self.original_indexes.len() * std::mem::size_of::<u32>()
    }
}

struct LastByteBucketChildIndex {
    labels: Vec<Vec<u8>>,
    original_indexes: Vec<u32>,
    ranges: [(u32, u32); 256],
}

impl LastByteBucketChildIndex {
    fn new(labels: &[Vec<u8>]) -> Self {
        let mut indexed_labels = labels
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, label)| {
                (
                    u32::try_from(index).expect("benchmark label index fits in u32"),
                    label,
                )
            })
            .collect::<Vec<_>>();
        indexed_labels.sort_by(|(_, left), (_, right)| {
            child_label_last_byte_bucket(left)
                .cmp(&child_label_last_byte_bucket(right))
                .then_with(|| cmp_child_label(left, right))
        });

        let mut ranges = [(0u32, 0u32); 256];
        let mut labels = Vec::with_capacity(indexed_labels.len());
        let mut original_indexes = Vec::with_capacity(indexed_labels.len());
        let mut start = 0usize;
        while start < indexed_labels.len() {
            let bucket = child_label_last_byte_bucket(&indexed_labels[start].1);
            let mut end = start + 1;
            while end < indexed_labels.len()
                && child_label_last_byte_bucket(&indexed_labels[end].1) == bucket
            {
                end += 1;
            }
            ranges[bucket] = (
                u32::try_from(start).expect("benchmark label range start fits in u32"),
                u32::try_from(end).expect("benchmark label range end fits in u32"),
            );
            for (original_index, label) in &indexed_labels[start..end] {
                original_indexes.push(*original_index);
                labels.push(label.clone());
            }
            start = end;
        }

        Self {
            labels,
            original_indexes,
            ranges,
        }
    }

    fn find(&self, label: &[u8]) -> Option<usize> {
        let (start, end) = self.ranges[child_label_last_byte_bucket(label)];
        if start == end {
            return None;
        }
        let base = start as usize;
        self.labels[base..end as usize]
            .binary_search_by(|candidate| cmp_child_label(candidate, label))
            .ok()
            .map(|offset| self.original_indexes[base + offset] as usize)
    }

    fn index_bytes(&self) -> usize {
        self.ranges.len() * std::mem::size_of::<(u32, u32)>()
            + self.original_indexes.len() * std::mem::size_of::<u32>()
    }
}

struct GeneratedChildHashIndex {
    labels: Vec<Vec<u8>>,
    slots: Vec<u32>,
}

impl GeneratedChildHashIndex {
    fn new(labels: &[Vec<u8>]) -> Self {
        let slot_count = labels.len().saturating_mul(2).next_power_of_two().max(1);
        Self::with_slot_count(labels, slot_count)
    }

    fn new_compact(labels: &[Vec<u8>]) -> Self {
        let slot_count = labels.len().next_power_of_two().max(1);
        Self::with_slot_count(labels, slot_count)
    }

    fn with_slot_count(labels: &[Vec<u8>], slot_count: usize) -> Self {
        let mut index = Self {
            labels: labels.to_vec(),
            slots: vec![u32::MAX; slot_count],
        };

        for label_index in 0..index.labels.len() {
            let mut slot = child_label_hash(&index.labels[label_index]) & (slot_count - 1);
            loop {
                if index.slots[slot] == u32::MAX {
                    index.slots[slot] =
                        u32::try_from(label_index).expect("benchmark label index fits in u32");
                    break;
                }
                slot = (slot + 1) & (slot_count - 1);
            }
        }

        index
    }

    fn find(&self, label: &[u8]) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }

        let mask = self.slots.len() - 1;
        let mut slot = child_label_hash(label) & mask;
        for _ in 0..self.slots.len() {
            let label_index = self.slots[slot];
            if label_index == u32::MAX {
                return None;
            }
            let label_index = label_index as usize;
            if self.labels[label_index].eq_ignore_ascii_case(label) {
                return Some(label_index);
            }
            slot = (slot + 1) & mask;
        }

        None
    }

    fn slot_count(&self) -> usize {
        self.slots.len()
    }

    fn slot_bytes(&self) -> usize {
        self.slots.len() * std::mem::size_of::<u32>()
    }
}

fn child_label_hash(label: &[u8]) -> usize {
    let mut digest = FNV_OFFSET_BASIS;
    for byte in label {
        digest ^= u64::from(byte.to_ascii_lowercase());
        digest = digest.wrapping_mul(FNV_PRIME);
    }
    digest as usize
}

fn child_label_bucket(label: &[u8]) -> usize {
    label
        .first()
        .map(|byte| byte.to_ascii_lowercase() as usize)
        .unwrap_or(0)
}

fn child_label_length_bucket(label: &[u8]) -> usize {
    label.len().min(63)
}

fn child_label_last_byte_bucket(label: &[u8]) -> usize {
    label
        .last()
        .map(|byte| byte.to_ascii_lowercase() as usize)
        .unwrap_or(0)
}

fn cmp_child_label(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    for (left, right) in left.iter().zip(right) {
        match left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase()) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    left.len().cmp(&right.len())
}

struct TimedLookup {
    duration: Duration,
    answer_count: usize,
    rcode_sum: u64,
    extra_sum: usize,
}

#[derive(Debug, Clone)]
struct QueryCase {
    qname: DomainName,
    qtype: u16,
    qclass: u16,
}

struct PacketCase {
    packet: Vec<u8>,
    options: AnswerOptions<'static>,
}

static DNS_COOKIE_SECRET: [u8; 16] = [
    0xe5, 0xe9, 0x73, 0xe5, 0xa6, 0xb2, 0xa4, 0x3f, 0x48, 0xe7, 0xdc, 0x84, 0x9e, 0x37, 0xbf, 0xcf,
];
const EDNS_NSID_OPTION: u16 = 3;
const EDNS_COOKIE_OPTION: u16 = 10;
const EDNS_PADDING_OPTION: u16 = 12;
const BENCH_UNKNOWN_TYPE: u16 = 65_280;
const BENCH_ABSENT_HIGH_TYPE: u16 = 65_281;

fn ns_per_query(duration: Duration, iterations: usize) -> f64 {
    duration.as_secs_f64() * 1_000_000_000.0 / iterations as f64
}

fn mixed_rrsets() -> Vec<Rrset> {
    vec![
        Rrset::new(
            DomainName::from_absolute_str("host0.bench.test.").unwrap(),
            RecordType::Nsec as u16,
            1,
            300,
            vec![nsec_rdata("host1.bench.test.")],
        ),
        Rrset::new(
            DomainName::from_absolute_str("host0.bench.test.").unwrap(),
            RecordType::Rrsig as u16,
            1,
            300,
            vec![rrsig_rdata(RecordType::A), rrsig_rdata(RecordType::Nsec)],
        ),
        Rrset::new(
            DomainName::from_absolute_str("target.bench.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 60].to_vec()],
        ),
        Rrset::new(
            DomainName::from_absolute_str("alias.bench.test.").unwrap(),
            RecordType::Cname as u16,
            1,
            300,
            vec![name_rdata("target.bench.test.")],
        ),
        Rrset::new(
            DomainName::from_absolute_str("*.wild.bench.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 61].to_vec()],
        ),
        Rrset::new(
            DomainName::from_absolute_str("child.bench.test.").unwrap(),
            RecordType::Ns as u16,
            1,
            300,
            vec![name_rdata("ns.child.bench.test.")],
        ),
        Rrset::new(
            DomainName::from_absolute_str("ns.child.bench.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 62].to_vec()],
        ),
        Rrset::new(
            DomainName::from_absolute_str("text.bench.test.").unwrap(),
            RecordType::Txt as u16,
            1,
            300,
            vec![txt_rdata("present")],
        ),
        Rrset::new(
            DomainName::from_absolute_str("dname.bench.test.").unwrap(),
            RecordType::Dname as u16,
            1,
            300,
            vec![name_rdata("target.bench.test.")],
        ),
        Rrset::new(
            DomainName::from_absolute_str("host.target.bench.test.").unwrap(),
            RecordType::A as u16,
            1,
            300,
            vec![[192, 0, 2, 63].to_vec()],
        ),
        Rrset::new(
            DomainName::from_absolute_str("big.bench.test.").unwrap(),
            RecordType::Txt as u16,
            1,
            300,
            (0..20).map(|_| vec![60; 50]).collect(),
        ),
        Rrset::new(
            DomainName::from_absolute_str("opaque.bench.test.").unwrap(),
            BENCH_UNKNOWN_TYPE,
            1,
            300,
            vec![Vec::new(), vec![0xc0, 0x0c, 0, 255]],
        ),
    ]
}

fn mixed_queries() -> Vec<QueryCase> {
    [
        ("host0.bench.test.", RecordType::A as u16),
        ("alias.bench.test.", RecordType::A as u16),
        ("alpha.wild.bench.test.", RecordType::A as u16),
        ("www.child.bench.test.", RecordType::A as u16),
        ("text.bench.test.", RecordType::A as u16),
        ("absent.bench.test.", RecordType::A as u16),
        ("host.dname.bench.test.", RecordType::A as u16),
        ("opaque.bench.test.", BENCH_UNKNOWN_TYPE),
    ]
    .into_iter()
    .map(|(qname, qtype)| QueryCase {
        qname: DomainName::from_absolute_str(qname).unwrap(),
        qtype,
        qclass: 1,
    })
    .collect()
}

fn mixed_query_packets(queries: &[QueryCase]) -> Vec<Vec<u8>> {
    queries
        .iter()
        .map(|query| query_packet(&query.qname, query.qtype, query.qclass))
        .collect()
}

fn direct_query_packets(qnames: &[DomainName]) -> Vec<Vec<u8>> {
    qnames
        .iter()
        .map(|qname| query_packet(qname, RecordType::A as u16, 1))
        .collect()
}

fn load_trace_packets(path: &str) -> Vec<PacketCase> {
    let trace = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("failed to read benchmark trace {path}: {error}");
    });
    let packets: Vec<PacketCase> = trace
        .lines()
        .enumerate()
        .filter_map(|(line_index, line)| parse_trace_line(path, line_index + 1, line))
        .collect();
    assert!(
        !packets.is_empty(),
        "benchmark trace {path} has no query cases"
    );
    packets
}

fn parse_trace_line(path: &str, line_number: usize, line: &str) -> Option<PacketCase> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = line.split('\t').collect();
    assert!(
        fields.len() >= 4,
        "{path}:{line_number}: expected qname, qtype, qclass, and edns fields"
    );
    let qname = DomainName::from_absolute_str(fields[0]).unwrap_or_else(|error| {
        panic!(
            "{path}:{line_number}: invalid qname {:?}: {error}",
            fields[0]
        );
    });
    let mut packet = query_packet(
        &qname,
        parse_trace_qtype(path, line_number, fields[1]),
        parse_trace_qclass(path, line_number, fields[2]),
    );
    match fields[3] {
        "none" => {}
        "edns" => append_opt(&mut packet, 4096, 0, &[]),
        "do" => append_opt(&mut packet, 4096, 0x8000, &[]),
        value => panic!("{path}:{line_number}: unsupported edns value {value:?}"),
    }
    Some(PacketCase {
        packet,
        options: AnswerOptions::default(),
    })
}

fn parse_trace_qtype(path: &str, line_number: usize, value: &str) -> u16 {
    match value {
        "A" => RecordType::A as u16,
        "AAAA" => RecordType::Aaaa as u16,
        "TXT" => RecordType::Txt as u16,
        "NS" => RecordType::Ns as u16,
        "SOA" => RecordType::Soa as u16,
        "MX" => RecordType::Mx as u16,
        "CNAME" => RecordType::Cname as u16,
        "DNAME" => RecordType::Dname as u16,
        value => value
            .parse::<u16>()
            .unwrap_or_else(|_| panic!("{path}:{line_number}: unsupported qtype {value:?}")),
    }
}

fn parse_trace_qclass(path: &str, line_number: usize, value: &str) -> u16 {
    match value {
        "IN" => 1,
        "ANY" => 255,
        value => value
            .parse::<u16>()
            .unwrap_or_else(|_| panic!("{path}:{line_number}: unsupported qclass {value:?}")),
    }
}

fn optioned_packet_cases() -> Vec<PacketCase> {
    let mut nsid_packet = query_packet(
        &DomainName::from_absolute_str("host0.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
    );
    append_opt(
        &mut nsid_packet,
        4096,
        0,
        &edns_option(EDNS_NSID_OPTION, &[]),
    );

    let mut cookie_packet = query_packet(
        &DomainName::from_absolute_str("host0.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
    );
    append_opt(
        &mut cookie_packet,
        4096,
        0,
        &edns_option(
            EDNS_COOKIE_OPTION,
            &[0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57],
        ),
    );

    let mut padding_packet = query_packet(
        &DomainName::from_absolute_str("host0.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
    );
    append_opt(
        &mut padding_packet,
        4096,
        0,
        &edns_option(EDNS_PADDING_OPTION, &[0, 0, 0, 0]),
    );

    vec![
        PacketCase {
            packet: nsid_packet,
            options: AnswerOptions {
                nsid: b"bench-node",
                ..AnswerOptions::default()
            },
        },
        PacketCase {
            packet: cookie_packet,
            options: AnswerOptions {
                dns_cookie: Some(DnsCookieContext::new(
                    "198.51.100.100".parse().unwrap(),
                    &DNS_COOKIE_SECRET,
                    1_559_731_985,
                )),
                ..AnswerOptions::default()
            },
        },
        PacketCase {
            packet: padding_packet,
            options: AnswerOptions {
                edns_padding_block_size: 32,
                ..AnswerOptions::default()
            },
        },
    ]
}

fn boundary_packet_cases() -> Vec<PacketCase> {
    let mut dnssec_positive_do = query_packet(
        &DomainName::from_absolute_str("host0.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
    );
    append_opt(&mut dnssec_positive_do, 4096, 0x8000, &[]);

    let mut dnssec_nodata_do = query_packet(
        &DomainName::from_absolute_str("host0.bench.test.").unwrap(),
        RecordType::Aaaa as u16,
        1,
    );
    append_opt(&mut dnssec_nodata_do, 4096, 0x8000, &[]);

    vec![
        PacketCase {
            packet: dnssec_positive_do,
            options: AnswerOptions::default(),
        },
        PacketCase {
            packet: dnssec_nodata_do,
            options: AnswerOptions::default(),
        },
        PacketCase {
            packet: query_packet(
                &DomainName::from_absolute_str("alias.bench.test.").unwrap(),
                255,
                1,
            ),
            options: AnswerOptions {
                any_response: oxidedns_core::dns::AnyResponseMode::Full,
                ..AnswerOptions::default()
            },
        },
        PacketCase {
            packet: query_packet(
                &DomainName::from_absolute_str("big.bench.test.").unwrap(),
                RecordType::Txt as u16,
                1,
            ),
            options: AnswerOptions::udp(128),
        },
    ]
}

fn udp_ceiling_packet_cases() -> Vec<PacketCase> {
    let mut small_edns_512 = query_packet(
        &DomainName::from_absolute_str("host0.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
    );
    append_opt(&mut small_edns_512, 512, 0, &[]);

    let mut big_edns_1232 = query_packet(
        &DomainName::from_absolute_str("big.bench.test.").unwrap(),
        RecordType::Txt as u16,
        1,
    );
    append_opt(&mut big_edns_1232, 4096, 0, &[]);

    let mut big_edns_4096 = query_packet(
        &DomainName::from_absolute_str("big.bench.test.").unwrap(),
        RecordType::Txt as u16,
        1,
    );
    append_opt(&mut big_edns_4096, 4096, 0, &[]);

    vec![
        PacketCase {
            packet: query_packet(
                &DomainName::from_absolute_str("host0.bench.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            options: AnswerOptions::udp(512),
        },
        PacketCase {
            packet: small_edns_512,
            options: AnswerOptions::udp(1232),
        },
        PacketCase {
            packet: query_packet(
                &DomainName::from_absolute_str("big.bench.test.").unwrap(),
                RecordType::Txt as u16,
                1,
            ),
            options: AnswerOptions::udp(1232),
        },
        PacketCase {
            packet: big_edns_1232,
            options: AnswerOptions::udp(1232),
        },
        PacketCase {
            packet: big_edns_4096,
            options: AnswerOptions::udp(4096),
        },
    ]
}

fn query_packet(qname: &DomainName, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x1234u16.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&qname.to_wire());
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());
    packet
}

fn notify_soa_validation_packets() -> [Vec<u8>; 2] {
    [
        notify_packet_with_soa_answer("bench.test."),
        notify_packet_with_soa_answer("BENCH.TEST."),
    ]
}

fn notify_packet_with_soa_answer(answer_owner: &str) -> Vec<u8> {
    let qname = DomainName::from_absolute_str("bench.test.").unwrap();
    let mut packet = query_packet(&qname, RecordType::Soa as u16, 1);
    packet[2..4].copy_from_slice(&((Opcode::Notify as u16) << 11).to_be_bytes());
    packet[6..8].copy_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(
        &DomainName::from_absolute_str(answer_owner)
            .unwrap()
            .to_wire(),
    );
    packet.extend_from_slice(&(RecordType::Soa as u16).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&300u32.to_be_bytes());
    let rdata = soa_rdata();
    packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    packet.extend_from_slice(&rdata);
    packet
}

fn chaos_classification_packets() -> [Vec<u8>; 2] {
    [
        query_packet(
            &DomainName::from_absolute_str("version.bind.").unwrap(),
            RecordType::Txt as u16,
            3,
        ),
        query_packet(
            &DomainName::from_absolute_str("VeRsIoN.BiNd.").unwrap(),
            RecordType::Txt as u16,
            3,
        ),
    ]
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

fn name_rdata(name: &str) -> Vec<u8> {
    DomainName::from_absolute_str(name).unwrap().to_wire()
}

fn txt_rdata(text: &str) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(text.len() + 1);
    rdata.push(text.len() as u8);
    rdata.extend_from_slice(text.as_bytes());
    rdata
}

fn rcode_number(rcode: Rcode) -> u64 {
    rcode as u64
}

fn soa_rdata() -> Vec<u8> {
    b"\x02ns\x05bench\x04test\x00\x0ahostmaster\x05bench\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()
}

fn rrsig_rdata(type_covered: RecordType) -> Vec<u8> {
    let mut rdata = (type_covered as u16).to_be_bytes().to_vec();
    rdata.extend_from_slice(&[8, 2]);
    rdata.extend_from_slice(&300u32.to_be_bytes());
    rdata.extend_from_slice(&1_700_086_400u32.to_be_bytes());
    rdata.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    rdata.extend_from_slice(&1u16.to_be_bytes());
    rdata.extend(name_rdata("bench.test."));
    rdata.extend_from_slice(b"signature");
    rdata
}

fn nsec_rdata(next_owner: &str) -> Vec<u8> {
    let mut rdata = name_rdata(next_owner);
    rdata.extend_from_slice(&[0, 1, 0x40]);
    rdata
}

fn nsec3_rdata_with_iterations(hash_algorithm: u8, iterations: u16) -> Vec<u8> {
    const TEST_NEXT_HASH: [u8; 20] = [
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
        0xef, 0xde, 0xad, 0xbe, 0xef,
    ];
    let mut rdata = vec![hash_algorithm, 0];
    rdata.extend_from_slice(&iterations.to_be_bytes());
    rdata.push(0);
    rdata.push(TEST_NEXT_HASH.len() as u8);
    rdata.extend_from_slice(&TEST_NEXT_HASH);
    rdata.extend_from_slice(&[0, 1, 0x40]);
    rdata
}

fn nsec3_owner(name: &str, origin: &str) -> DomainName {
    DomainName::from_absolute_str(&format!("{}.{}", nsec3_hash_label(name), origin)).unwrap()
}

fn nsec3_hash_label(name: &str) -> String {
    let canonical = DomainName::from_absolute_str(name).unwrap().canonical_key();
    let wire = DomainName::from_absolute_str(&canonical).unwrap().to_wire();
    let mut digest = Sha1::new();
    digest.update(wire);
    let first = digest.finalize();
    let mut digest = Sha1::new();
    digest.update(first);
    let hash = digest.finalize();
    base32hex_lower(&hash)
}

fn base32hex_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 0x1f) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}
