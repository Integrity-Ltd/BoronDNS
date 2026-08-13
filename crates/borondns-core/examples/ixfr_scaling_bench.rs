use std::{
    env, fs,
    hint::black_box,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use arc_swap as _;
use base64 as _;
use borondns_core::{
    axfr::{IxfrResponse, parse_ixfr_response},
    dns::{DomainName, RecordType},
    zone::{
        ResourceRecord, Rrset, ZonePublicationPolicy, ZonePublicationStrategy, ZoneSnapshot,
        ZoneStore,
    },
    zone_image::ZoneImageLookupOutcome,
};
use hmac as _;
use libc as _;
use serde as _;
use sha1 as _;
use sha2 as _;
use siphasher as _;
use smallvec as _;
use subtle as _;
use thiserror as _;
use toml as _;
use tracing as _;
use url as _;
use zeroize as _;

const QID: u16 = 0x4958;
const QCLASS: u16 = 1;
const TTL: u32 = 300;
const MAX_DNS_MESSAGE_BYTES: usize = u16::MAX as usize;

struct Config {
    records: usize,
    delta: usize,
    delta_mode: DeltaMode,
    query_threads: usize,
    sample_seconds: u64,
    query_engine: QueryEngine,
    publication_strategy: ZonePublicationStrategy,
    publication_threshold: usize,
    artifact: Option<PathBuf>,
}

#[derive(Clone, Copy)]
enum QueryEngine {
    Image,
    Snapshot,
    Overlay,
}

#[derive(Clone, Copy)]
enum DeltaMode {
    Add,
    Replace,
    Mixed,
}

impl DeltaMode {
    fn label(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Replace => "replace",
            Self::Mixed => "mixed",
        }
    }

    fn replacement_count(self, delta: usize) -> usize {
        match self {
            Self::Add => 0,
            Self::Replace => delta,
            Self::Mixed => delta / 2,
        }
    }
}

impl QueryEngine {
    fn label(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Snapshot => "snapshot",
            Self::Overlay => "overlay",
        }
    }
}

#[derive(Clone, Copy, Default)]
struct MemorySample {
    rss_kib: u64,
    hwm_kib: u64,
}

fn main() {
    let config = parse_args();
    let started_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_secs();
    let apex = DomainName::from_absolute_str("ixfr-scale.test.").expect("valid benchmark apex");
    let lookup_name = generated_owner(b'n', config.records - 1, &apex);

    let build_started = Instant::now();
    let base_snapshot = Arc::new(build_base_snapshot(config.records, &apex));
    let base_build = build_started.elapsed();
    let base_shape = base_snapshot.shape_summary();
    assert_eq!(base_shape.rdata_count, config.records + 2);
    assert_eq!(base_snapshot.serial, Some(1));
    let after_base = memory_sample();

    let store = Arc::new(ZoneStore::with_publication_policy(ZonePublicationPolicy {
        strategy: config.publication_strategy,
        sharded_rrset_threshold: config.publication_threshold,
        ..ZonePublicationPolicy::default()
    }));
    let initial_publish_started = Instant::now();
    let initial_metadata = store
        .insert_snapshot_arc_for_transfer(base_snapshot.clone())
        .expect("base snapshot publishes");
    let initial_publish = initial_publish_started.elapsed();
    assert_eq!(initial_metadata.serial, Some(1));
    let after_initial_publish = memory_sample();

    let query_counter = Arc::new(AtomicU64::new(0));
    let query_stop = Arc::new(AtomicBool::new(false));
    let query_workers = start_query_workers(
        config.query_threads,
        store.clone(),
        base_snapshot.clone(),
        lookup_name,
        config.query_engine,
        query_counter.clone(),
        query_stop.clone(),
    );
    let baseline_qps = sample_qps(&query_counter, Duration::from_secs(config.sample_seconds));

    let wire_started = Instant::now();
    let messages = build_ixfr_messages(&apex, config.records, config.delta, config.delta_mode);
    let wire_build = wire_started.elapsed();
    let wire_bytes = messages.iter().map(Vec::len).sum::<usize>();
    let after_wire = memory_sample();

    let process_counter_before = query_counter.load(Ordering::Relaxed);
    let process_started = Instant::now();
    let response = parse_ixfr_response(QID, &apex, QCLASS, &base_snapshot, &messages)
        .expect("generated IXFR parses and applies");
    let ixfr_process = process_started.elapsed();
    let process_counter_after = query_counter.load(Ordering::Relaxed);
    let ixfr_qps = qps_for_count(
        process_counter_after.saturating_sub(process_counter_before),
        ixfr_process,
    );
    let IxfrResponse::Updated(updated_snapshot) = response else {
        panic!("generated IXFR unexpectedly reported the zone current");
    };
    let updated_snapshot: Arc<ZoneSnapshot> = Arc::from(updated_snapshot);
    assert_eq!(updated_snapshot.serial, Some(2));
    let updated_rdata_records = updated_snapshot.rdata_record_count();
    let added_records = config
        .delta
        .saturating_sub(config.delta_mode.replacement_count(config.delta));
    assert_eq!(updated_rdata_records, config.records + added_records + 2);
    let after_ixfr = memory_sample();

    let publish_counter_before = query_counter.load(Ordering::Relaxed);
    let publish_started = Instant::now();
    let updated_metadata = store
        .insert_snapshot_arc_for_transfer(updated_snapshot)
        .expect("updated IXFR snapshot publishes");
    let publication = publish_started.elapsed();
    let publish_counter_after = query_counter.load(Ordering::Relaxed);
    let publication_qps = qps_for_count(
        publish_counter_after.saturating_sub(publish_counter_before),
        publication,
    );
    assert_eq!(updated_metadata.serial, Some(2));
    let after_publication = memory_sample();

    let post_qps = sample_qps(&query_counter, Duration::from_secs(config.sample_seconds));
    query_stop.store(true, Ordering::Release);
    for worker in query_workers {
        worker.join().expect("query worker did not panic");
    }

    let header = "schema\tstarted_unix_seconds\tbase_data_records\tdelta_changed_rrsets\tdelta_mode\tquery_threads\tquery_engine\tpublication_strategy\tpublication_threshold\tbase_build_seconds\tinitial_publish_seconds\tixfr_wire_build_seconds\tixfr_wire_messages\tixfr_wire_bytes\tixfr_process_seconds\tpublication_seconds\tbaseline_qps\tixfr_qps\tpublication_qps\tpost_qps\tafter_base_rss_kib\tafter_initial_publish_rss_kib\tafter_wire_rss_kib\tafter_ixfr_rss_kib\tafter_publication_rss_kib\tpeak_hwm_kib\tupdated_rdata_records\tupdated_serial\tstatus";
    let peak_hwm_kib = [
        after_base.hwm_kib,
        after_initial_publish.hwm_kib,
        after_wire.hwm_kib,
        after_ixfr.hwm_kib,
        after_publication.hwm_kib,
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    let row = format!(
        "5\t{started_unix_seconds}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.9}\t{:.9}\t{:.9}\t{}\t{}\t{:.9}\t{:.9}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\tok",
        config.records,
        config.delta,
        config.delta_mode.label(),
        config.query_threads,
        config.query_engine.label(),
        match config.publication_strategy {
            ZonePublicationStrategy::Compact => "compact",
            ZonePublicationStrategy::Sharded => "sharded",
            ZonePublicationStrategy::Auto => "auto",
        },
        config.publication_threshold,
        base_build.as_secs_f64(),
        initial_publish.as_secs_f64(),
        wire_build.as_secs_f64(),
        messages.len(),
        wire_bytes,
        ixfr_process.as_secs_f64(),
        publication.as_secs_f64(),
        baseline_qps,
        ixfr_qps,
        publication_qps,
        post_qps,
        after_base.rss_kib,
        after_initial_publish.rss_kib,
        after_wire.rss_kib,
        after_ixfr.rss_kib,
        after_publication.rss_kib,
        peak_hwm_kib,
        updated_rdata_records,
        updated_metadata.serial.expect("updated serial exists"),
    );
    let output = format!("{header}\n{row}\n");
    if let Some(artifact) = config.artifact {
        if let Some(parent) = artifact.parent() {
            fs::create_dir_all(parent).expect("artifact parent can be created");
        }
        fs::write(artifact, &output).expect("benchmark artifact can be written");
    }
    print!("{output}");
}

fn parse_args() -> Config {
    let mut records = None;
    let mut delta = None;
    let mut delta_mode = DeltaMode::Add;
    let mut query_threads = 0usize;
    let mut sample_seconds = 2u64;
    let mut query_engine = QueryEngine::Image;
    let mut publication_strategy = ZonePublicationStrategy::Compact;
    let mut publication_threshold = 1_000_000usize;
    let mut artifact = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = match arg.as_str() {
            "--records"
            | "--delta"
            | "--delta-mode"
            | "--query-threads"
            | "--sample-seconds"
            | "--query-engine"
            | "--publication-strategy"
            | "--publication-threshold"
            | "--artifact" => args
                .next()
                .unwrap_or_else(|| panic!("missing value for {arg}")),
            "--help" | "-h" => {
                println!(
                    "usage: ixfr_scaling_bench --records N --delta N [--delta-mode add|replace|mixed] [--query-threads N] [--query-engine image|snapshot|overlay] [--publication-strategy compact|sharded|auto] [--publication-threshold N] [--sample-seconds N] [--artifact PATH]"
                );
                std::process::exit(0);
            }
            _ => panic!("unknown argument {arg}"),
        };
        match arg.as_str() {
            "--records" => records = Some(parse_usize(&arg, &value)),
            "--delta" => delta = Some(parse_usize(&arg, &value)),
            "--delta-mode" => {
                delta_mode = match value.as_str() {
                    "add" => DeltaMode::Add,
                    "replace" => DeltaMode::Replace,
                    "mixed" => DeltaMode::Mixed,
                    _ => panic!("{arg} must be add, replace, or mixed"),
                };
            }
            "--query-threads" => query_threads = parse_usize(&arg, &value),
            "--sample-seconds" => {
                sample_seconds = value
                    .parse::<u64>()
                    .unwrap_or_else(|_| panic!("{arg} must be an integer"));
                assert!(sample_seconds > 0, "{arg} must be positive");
            }
            "--query-engine" => {
                query_engine = match value.as_str() {
                    "image" => QueryEngine::Image,
                    "snapshot" => QueryEngine::Snapshot,
                    "overlay" => QueryEngine::Overlay,
                    _ => panic!("{arg} must be image, snapshot, or overlay"),
                };
            }
            "--publication-strategy" => {
                publication_strategy = match value.as_str() {
                    "compact" => ZonePublicationStrategy::Compact,
                    "sharded" => ZonePublicationStrategy::Sharded,
                    "auto" => ZonePublicationStrategy::Auto,
                    _ => panic!("{arg} must be compact, sharded, or auto"),
                };
            }
            "--publication-threshold" => {
                publication_threshold = parse_usize(&arg, &value);
                assert!(publication_threshold > 0, "{arg} must be positive");
            }
            "--artifact" => artifact = Some(PathBuf::from(value)),
            _ => unreachable!(),
        }
    }
    let records = records.expect("--records is required");
    assert!(records > 0, "--records must be positive");
    Config {
        records,
        delta: delta.expect("--delta is required"),
        delta_mode,
        query_threads,
        sample_seconds,
        query_engine,
        publication_strategy,
        publication_threshold,
        artifact,
    }
}

fn parse_usize(arg: &str, value: &str) -> usize {
    value
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("{arg} must be a non-negative integer"))
}

fn build_base_snapshot(records: usize, apex: &DomainName) -> ZoneSnapshot {
    let mut rrsets = Vec::with_capacity(records.saturating_add(2));
    rrsets.push(Rrset::new(
        apex.clone(),
        RecordType::Soa as u16,
        QCLASS,
        TTL,
        vec![soa_rdata(apex, 1)],
    ));
    rrsets.push(Rrset::new(
        apex.clone(),
        RecordType::Ns as u16,
        QCLASS,
        TTL,
        vec![name_under_apex_wire(b"ns", apex)],
    ));
    for index in 0..records {
        rrsets.push(Rrset::new(
            generated_owner(b'n', index, apex),
            RecordType::A as u16,
            QCLASS,
            TTL,
            vec![generated_ipv4(index)],
        ));
    }
    ZoneSnapshot::active(apex.clone(), Some(1), rrsets)
}

fn generated_owner(prefix: u8, index: usize, apex: &DomainName) -> DomainName {
    let name = format!("{}{index:016x}.{}", char::from(prefix), apex);
    DomainName::from_absolute_str(&name).expect("generated owner is valid")
}

fn name_under_apex_wire(label: &[u8], apex: &DomainName) -> Vec<u8> {
    assert!(label.len() <= 63);
    let apex_wire = apex.to_wire();
    let mut wire = Vec::with_capacity(label.len() + 1 + apex_wire.len());
    wire.push(label.len() as u8);
    wire.extend_from_slice(label);
    wire.extend_from_slice(&apex_wire);
    wire
}

fn generated_ipv4(index: usize) -> Vec<u8> {
    let value = (index as u32).wrapping_mul(2_654_435_761);
    value.to_be_bytes().to_vec()
}

fn soa_record(apex: &DomainName, serial: u32) -> ResourceRecord {
    ResourceRecord {
        owner: apex.clone(),
        rr_type: RecordType::Soa as u16,
        class: QCLASS,
        ttl: TTL,
        rdata: soa_rdata(apex, serial),
    }
}

fn soa_rdata(apex: &DomainName, serial: u32) -> Vec<u8> {
    let mut rdata = name_under_apex_wire(b"ns", apex);
    rdata.extend_from_slice(&name_under_apex_wire(b"hostmaster", apex));
    for value in [serial, 3600, 600, 86_400, 300] {
        rdata.extend_from_slice(&value.to_be_bytes());
    }
    rdata
}

fn build_ixfr_messages(
    apex: &DomainName,
    records: usize,
    delta: usize,
    mode: DeltaMode,
) -> Vec<Vec<u8>> {
    let replacements = mode.replacement_count(delta);
    assert!(
        replacements <= records,
        "replacement delta exceeds base zone"
    );
    let old_soa = soa_record(apex, 1);
    let new_soa = soa_record(apex, 2);
    let mut writer = IxfrMessageWriter::new(apex);
    writer.push(&new_soa);
    writer.push(&old_soa);
    for index in 0..replacements {
        writer.push(&ResourceRecord {
            owner: generated_owner(b'n', index, apex),
            rr_type: RecordType::A as u16,
            class: QCLASS,
            ttl: TTL,
            rdata: generated_ipv4(index),
        });
    }
    writer.push(&new_soa);
    for index in 0..replacements {
        writer.push(&ResourceRecord {
            owner: generated_owner(b'n', index, apex),
            rr_type: RecordType::A as u16,
            class: QCLASS,
            ttl: TTL,
            rdata: generated_ipv4(index ^ usize::MAX),
        });
    }
    for index in replacements..delta {
        writer.push(&ResourceRecord {
            owner: generated_owner(b'd', index - replacements, apex),
            rr_type: RecordType::A as u16,
            class: QCLASS,
            ttl: TTL,
            rdata: generated_ipv4(index ^ usize::MAX),
        });
    }
    writer.push(&new_soa);
    writer.finish()
}

struct IxfrMessageWriter {
    apex: DomainName,
    messages: Vec<Vec<u8>>,
    current: Vec<u8>,
    answer_count: u16,
    first: bool,
}

impl IxfrMessageWriter {
    fn new(apex: &DomainName) -> Self {
        Self {
            apex: apex.clone(),
            messages: Vec::new(),
            current: Vec::new(),
            answer_count: 0,
            first: true,
        }
    }

    fn start_message(&mut self) {
        self.current.clear();
        self.current.extend_from_slice(&QID.to_be_bytes());
        self.current.extend_from_slice(&0x8400u16.to_be_bytes());
        self.current
            .extend_from_slice(&(u16::from(self.first)).to_be_bytes());
        self.current.extend_from_slice(&0u16.to_be_bytes());
        self.current.extend_from_slice(&0u16.to_be_bytes());
        self.current.extend_from_slice(&0u16.to_be_bytes());
        if self.first {
            self.current.extend_from_slice(&self.apex.to_wire());
            self.current
                .extend_from_slice(&(RecordType::Ixfr as u16).to_be_bytes());
            self.current.extend_from_slice(&QCLASS.to_be_bytes());
        }
        self.answer_count = 0;
    }

    fn push(&mut self, record: &ResourceRecord) {
        if self.current.is_empty() {
            self.start_message();
        }
        let encoded = encode_record(record);
        if self.answer_count == u16::MAX
            || self.current.len().saturating_add(encoded.len()) > MAX_DNS_MESSAGE_BYTES
        {
            self.flush();
            self.start_message();
        }
        assert!(self.current.len() + encoded.len() <= MAX_DNS_MESSAGE_BYTES);
        self.current.extend_from_slice(&encoded);
        self.answer_count += 1;
    }

    fn flush(&mut self) {
        if self.answer_count == 0 {
            return;
        }
        self.current[6..8].copy_from_slice(&self.answer_count.to_be_bytes());
        self.messages.push(std::mem::take(&mut self.current));
        self.first = false;
        self.answer_count = 0;
    }

    fn finish(mut self) -> Vec<Vec<u8>> {
        self.flush();
        self.messages
    }
}

fn encode_record(record: &ResourceRecord) -> Vec<u8> {
    let owner = record.owner.to_wire();
    let rdlength = u16::try_from(record.rdata.len()).expect("benchmark RDATA fits DNS RDLENGTH");
    let mut wire = Vec::with_capacity(owner.len() + 10 + record.rdata.len());
    wire.extend_from_slice(&owner);
    wire.extend_from_slice(&record.rr_type.to_be_bytes());
    wire.extend_from_slice(&record.class.to_be_bytes());
    wire.extend_from_slice(&record.ttl.to_be_bytes());
    wire.extend_from_slice(&rdlength.to_be_bytes());
    wire.extend_from_slice(&record.rdata);
    wire
}

fn start_query_workers(
    count: usize,
    store: Arc<ZoneStore>,
    snapshot: Arc<ZoneSnapshot>,
    qname: DomainName,
    query_engine: QueryEngine,
    counter: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> Vec<thread::JoinHandle<()>> {
    (0..count)
        .map(|_| {
            let store = store.clone();
            let snapshot = snapshot.clone();
            let qname = qname.clone();
            let counter = counter.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut local = 0u64;
                while !stop.load(Ordering::Acquire) {
                    match query_engine {
                        QueryEngine::Image => {
                            let zone = store
                                .find_published_zone(&qname)
                                .expect("query name stays published");
                            let outcome = zone.active_zone_image_ref().lookup_exact_plan(
                                &qname,
                                RecordType::A as u16,
                                QCLASS,
                            );
                            assert!(matches!(outcome, ZoneImageLookupOutcome::Found(_)));
                            black_box(outcome);
                        }
                        QueryEngine::Snapshot => {
                            let lookup = snapshot.offline_oracle().lookup(
                                &qname,
                                RecordType::A as u16,
                                QCLASS,
                            );
                            assert_eq!(lookup.answers.len(), 1);
                            black_box(lookup);
                        }
                        QueryEngine::Overlay => {
                            let zone = store
                                .find_published_zone(&qname)
                                .expect("query name stays published");
                            if zone.has_incremental_overlay() {
                                assert!(zone.overlay_allows_compact_direct_shape(
                                    &qname,
                                    RecordType::A as u16,
                                    QCLASS,
                                ));
                            }
                            let outcome = zone.active_zone_image_ref().lookup_exact_plan(
                                &qname,
                                RecordType::A as u16,
                                QCLASS,
                            );
                            if let ZoneImageLookupOutcome::Found(plan) = &outcome
                                && zone.has_incremental_overlay()
                            {
                                assert!(zone.overlay_allows_compact_plan(plan));
                            }
                            assert!(matches!(outcome, ZoneImageLookupOutcome::Found(_)));
                            black_box(outcome);
                        }
                    }
                    local = local.wrapping_add(1);
                    if local & 0x3ff == 0 {
                        counter.fetch_add(0x400, Ordering::Relaxed);
                        local = 0;
                    }
                }
                counter.fetch_add(local, Ordering::Relaxed);
            })
        })
        .collect()
}

fn sample_qps(counter: &AtomicU64, duration: Duration) -> f64 {
    if duration.is_zero() {
        return 0.0;
    }
    let before = counter.load(Ordering::Relaxed);
    let started = Instant::now();
    thread::sleep(duration);
    let elapsed = started.elapsed();
    let after = counter.load(Ordering::Relaxed);
    qps_for_count(after.saturating_sub(before), elapsed)
}

fn qps_for_count(count: u64, elapsed: Duration) -> f64 {
    if elapsed.is_zero() {
        0.0
    } else {
        count as f64 / elapsed.as_secs_f64()
    }
}

fn memory_sample() -> MemorySample {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    MemorySample {
        rss_kib: status_value_kib(&status, "VmRSS:"),
        hwm_kib: status_value_kib(&status, "VmHWM:"),
    }
}

fn status_value_kib(status: &str, key: &str) -> u64 {
    status
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix(key)?.split_whitespace().next()?;
            value.parse::<u64>().ok()
        })
        .unwrap_or(0)
}
