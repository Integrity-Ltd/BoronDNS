use std::{
    env, fs,
    hint::black_box,
    sync::Arc,
    time::{Duration, Instant},
};

use oxidedns_core::{
    dns::{
        AnswerOptions, DatagramAction, DnsCookieContext, DomainName, ExtendedDnsErrorsMode, Rcode,
        RecordType, answer_message,
        answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image,
    },
    zone::{Rrset, ZoneSnapshot, ZoneStore},
    zone_image::{ZoneImage, ZoneImageLookupOutcome},
};

fn main() {
    let config = BenchConfig::from_env_and_args();
    let record_count = config.records;
    let iterations = config.iterations;
    let (snapshot, direct_qnames, mixed_queries) = build_snapshot(record_count);
    let hot_direct_qnames = hot_direct_qnames(&direct_qnames);
    let (stress_snapshot, stress_queries) =
        build_delegation_dname_stress_snapshot(config.stress_candidates);

    let compile_started = Instant::now();
    let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
    let compile_duration = compile_started.elapsed();
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
    let current_mixed = time_current_response_lookup(&snapshot, &mixed_queries, iterations);
    let image_mixed_plan = time_zone_image_response_plan(&image, &mixed_queries, iterations);
    let image_mixed_wire = time_zone_image_response_wire(&image, &mixed_queries, iterations);
    let image_mixed = time_zone_image_response_lookup(&image, &mixed_queries, iterations);
    let current_stress =
        time_current_response_lookup(&stress_snapshot, &stress_queries, iterations);
    let image_stress_plan =
        time_zone_image_response_plan(&stress_image, &stress_queries, iterations);
    let image_stress_wire =
        time_zone_image_response_wire(&stress_image, &stress_queries, iterations);
    let image_stress = time_zone_image_response_lookup(&stress_image, &stress_queries, iterations);
    let mixed_packets = mixed_query_packets(&mixed_queries);
    let hot_packets = direct_query_packets(&hot_direct_qnames);
    let trace_packets = load_trace_packets(&config.trace_path);
    let optioned_packets = optioned_packet_cases();
    let fallback_packets = fallback_packet_cases();
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
    let fallback_packet_validation_mismatches =
        count_packet_case_mismatches(&store, image.clone(), &fallback_packets);
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
    let stats = image.stats();

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
    println!("query_mix_trace\tweighted_reference_trace_tsv");
    println!(
        "query_mix_mixed\tpositive_a,cname,wildcard,referral_glue,nodata,nxdomain,dname,opaque_unknown"
    );
    println!("query_mix_optioned\tedns_nsid,dns_cookie,edns_padding");
    println!("query_mix_fallback\tdo_dnssec,full_any,udp_truncation,ede_not_ready");
    println!(
        "query_mix_udp_ceiling\tno_edns_512,edns_payload_512,edns_payload_1232,edns_payload_4096"
    );
    println!("query_mix_delegation_dname_stress\treferral_glue,dname_synthesis");
    println!("serving_gate\tnon_dnssec_minimal_any_only_with_snapshot_fallback");
    println!("records\t{record_count}");
    println!(
        "delegation_dname_stress_candidates\t{}",
        config.stress_candidates
    );
    println!("iterations\t{iterations}");
    println!("hot_direct_query_cases\t{}", hot_direct_qnames.len());
    println!("hot_packet_query_cases\t{}", hot_packets.len());
    println!("trace_packet_query_cases\t{}", trace_packets.len());
    println!("mixed_query_cases\t{}", mixed_queries.len());
    println!(
        "delegation_dname_stress_query_cases\t{}",
        stress_queries.len()
    );
    println!("mixed_validation_mismatches\t{mixed_validation_mismatches}");
    println!("delegation_dname_stress_validation_mismatches\t{stress_validation_mismatches}");
    println!("mixed_packet_validation_mismatches\t{mixed_packet_validation_mismatches}");
    println!("hot_packet_validation_mismatches\t{hot_packet_validation_mismatches}");
    println!("trace_packet_validation_mismatches\t{trace_packet_validation_mismatches}");
    println!("optioned_packet_cases\t{}", optioned_packets.len());
    println!("optioned_packet_validation_mismatches\t{optioned_packet_validation_mismatches}");
    println!("fallback_packet_cases\t{}", fallback_packets.len());
    println!("fallback_packet_validation_mismatches\t{fallback_packet_validation_mismatches}");
    println!("udp_ceiling_packet_cases\t{}", udp_ceiling_packets.len());
    println!(
        "udp_ceiling_packet_validation_mismatches\t{udp_ceiling_packet_validation_mismatches}"
    );
    println!("ede_fallback_packet_cases\t1");
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
        "current_mixed_response_ns_per_query\t{:.3}",
        ns_per_query(current_mixed.duration, iterations)
    );
    println!(
        "zone_image_mixed_response_ns_per_query\t{:.3}",
        ns_per_query(image_mixed.duration, iterations)
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
        "zone_image_delegation_dname_stress_response_ns_per_query\t{:.3}",
        ns_per_query(image_stress.duration, iterations)
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
        "zone_image_mixed_wire_bytes\t{}",
        image_mixed_wire.extra_sum
    );
    println!(
        "zone_image_mixed_record_count\t{}",
        image_mixed.answer_count
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
        "zone_image_delegation_dname_stress_record_count\t{}",
        image_stress.answer_count
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
    println!("zone_image_mixed_rcode_checksum\t{}", image_mixed.rcode_sum);
    println!("zone_image_nodes\t{}", stats.node_count);
    println!("zone_image_edges\t{}", stats.edge_count);
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

fn time_current_lookup(
    snapshot: &ZoneSnapshot,
    qnames: &[DomainName],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut answer_count = 0usize;
    for index in 0..iterations {
        let qname = &qnames[index % qnames.len()];
        let lookup = snapshot.lookup(black_box(qname), RecordType::A as u16, 1);
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
    let started = Instant::now();
    let mut answer_count = 0usize;
    for index in 0..iterations {
        let qname = &qnames[index % qnames.len()];
        if let ZoneImageLookupOutcome::Found(plan) =
            image.lookup_exact_plan(black_box(qname), RecordType::A as u16, 1)
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
        let lookup = snapshot.lookup(black_box(&query.qname), query.qtype, query.qclass);
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

fn time_zone_image_response_lookup(
    image: &ZoneImage,
    queries: &[QueryCase],
    iterations: usize,
) -> TimedLookup {
    let started = Instant::now();
    let mut record_count = 0usize;
    let mut rcode_sum = 0u64;
    for index in 0..iterations {
        let query = &queries[index % queries.len()];
        let lookup = image
            .lookup_response(black_box(&query.qname), query.qtype, query.qclass)
            .expect("zone image lookup succeeds");
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
        let plan = image
            .lookup_response_plan(black_box(&query.qname), query.qtype, query.qclass, 8)
            .expect("zone image plan lookup succeeds");
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
        let plan = image
            .lookup_response_plan(black_box(&query.qname), query.qtype, query.qclass, 8)
            .expect("zone image plan lookup succeeds");
        wire.clear();
        record_count = record_count.saturating_add(
            image
                .append_plan_wire(&plan, &mut wire)
                .expect("zone image plan wire appends"),
        );
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
    image: ZoneImage,
    packets: &[Vec<u8>],
) -> usize {
    let image = Arc::new(image);
    let provider = |_: &Arc<ZoneSnapshot>| Some(image.clone());
    packets
        .iter()
        .filter(|packet| {
            let current = current_packet_response(store, packet);
            let zone_image = zone_image_packet_response(store, packet, &provider);
            current != zone_image
        })
        .count()
}

fn count_packet_case_mismatches(
    store: &ZoneStore,
    image: ZoneImage,
    packets: &[PacketCase],
) -> usize {
    let image = Arc::new(image);
    let provider = |_: &Arc<ZoneSnapshot>| Some(image.clone());
    packets
        .iter()
        .filter(|packet| {
            let current =
                current_packet_response_with_options(store, &packet.packet, packet.options);
            let zone_image = zone_image_packet_response_with_options(
                store,
                &packet.packet,
                packet.options,
                &provider,
            );
            current != zone_image
        })
        .count()
}

fn count_ede_not_ready_packet_mismatches(image: ZoneImage) -> usize {
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
    let image = Arc::new(image);
    let provider = |_: &Arc<ZoneSnapshot>| Some(image.clone());
    usize::from(
        current_packet_response_with_options(&store, &packet, options)
            != zone_image_packet_response_with_options(&store, &packet, options, &provider),
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
    image: ZoneImage,
    packets: &[PacketCase],
    iterations: usize,
) -> TimedLookup {
    let image = Arc::new(image);
    let provider = |_: &Arc<ZoneSnapshot>| Some(image.clone());
    let started = Instant::now();
    let mut wire_bytes = 0usize;
    let mut rcode_sum = 0u64;
    for index in 0..iterations {
        let packet = &packets[index % packets.len()];
        let response = zone_image_packet_response_with_options(
            store,
            black_box(&packet.packet),
            packet.options,
            &provider,
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
    image: ZoneImage,
    packets: &[Vec<u8>],
    iterations: usize,
) -> TimedLookup {
    let image = Arc::new(image);
    let provider = |_: &Arc<ZoneSnapshot>| Some(image.clone());
    let started = Instant::now();
    let mut wire_bytes = 0usize;
    let mut rcode_sum = 0u64;
    for index in 0..iterations {
        let packet = &packets[index % packets.len()];
        let response = zone_image_packet_response(store, black_box(packet), &provider);
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
    provider: &impl Fn(&Arc<ZoneSnapshot>) -> Option<Arc<ZoneImage>>,
) -> Vec<u8> {
    zone_image_packet_response_with_options(store, packet, AnswerOptions::default(), provider)
}

fn zone_image_packet_response_with_options(
    store: &ZoneStore,
    packet: &[u8],
    options: AnswerOptions,
    provider: &impl Fn(&Arc<ZoneSnapshot>) -> Option<Arc<ZoneImage>>,
) -> Vec<u8> {
    match answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        packet,
        store,
        options,
        |_, _| true,
        |_, _, _| {},
        |_| {},
        Some(provider),
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
            let snapshot_lookup = snapshot.lookup(&query.qname, query.qtype, query.qclass);
            let image_lookup = image
                .lookup_response(&query.qname, query.qtype, query.qclass)
                .expect("zone image lookup succeeds");
            snapshot_lookup != image_lookup
        })
        .count()
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

fn ns_per_query(duration: Duration, iterations: usize) -> f64 {
    duration.as_secs_f64() * 1_000_000_000.0 / iterations as f64
}

fn mixed_rrsets() -> Vec<Rrset> {
    vec![
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

fn fallback_packet_cases() -> Vec<PacketCase> {
    let mut dnssec_do = query_packet(
        &DomainName::from_absolute_str("host0.bench.test.").unwrap(),
        RecordType::A as u16,
        1,
    );
    append_opt(&mut dnssec_do, 4096, 0x8000, &[]);

    vec![
        PacketCase {
            packet: dnssec_do,
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
