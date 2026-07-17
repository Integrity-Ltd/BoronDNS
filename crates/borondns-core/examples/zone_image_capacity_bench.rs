use std::{env, hint::black_box, time::Instant};

use borondns_core::{
    dns::{DomainName, RecordType},
    zone::{Rrset, ZoneSnapshot},
    zone_image::ZoneImage,
};

const DEFAULT_NAMES: usize = 50_000;
const DEFAULT_LOOKUPS: usize = 1_000_000;
const SAMPLE_NAMES: usize = 1_024;

fn main() {
    let config = Config::from_args();

    let build_started = Instant::now();
    let (snapshot, query_names) =
        build_flat_snapshot(config.names, config.signed, config.records_per_rrset);
    let build_seconds = build_started.elapsed().as_secs_f64();

    let compile_started = Instant::now();
    let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
    let compile_seconds = compile_started.elapsed().as_secs_f64();

    let lookup_started = Instant::now();
    let mut found = 0usize;
    for index in 0..config.lookups {
        let qname = &query_names[index % query_names.len()];
        if matches!(
            black_box(&image).lookup_exact_plan(
                black_box(qname),
                black_box(RecordType::A as u16),
                black_box(1),
            ),
            borondns_core::zone_image::ZoneImageLookupOutcome::Found(_)
        ) {
            found += 1;
        }
    }
    let lookup_seconds = lookup_started.elapsed().as_secs_f64();
    let stats = image.stats();

    println!("metric\tvalue");
    println!("names\t{}", config.names);
    println!("signed\t{}", config.signed);
    println!("records_per_rrset\t{}", config.records_per_rrset);
    println!("snapshot_build_seconds\t{build_seconds:.9}");
    println!("compile_seconds\t{compile_seconds:.9}");
    println!("lookup_iterations\t{}", config.lookups);
    println!("lookup_seconds\t{lookup_seconds:.9}");
    println!(
        "lookup_nanoseconds_each\t{:.3}",
        lookup_seconds * 1_000_000_000.0 / config.lookups as f64
    );
    println!("lookup_found\t{found}");
    println!("records\t{}", stats.record_count);
    println!("rrsets\t{}", stats.rrset_count);
    println!("nodes\t{}", stats.node_count);
    println!("edges\t{}", stats.edge_count);
    println!("child_hash_slots\t{}", stats.child_hash_slot_count);
    println!("child_hash_slot_bytes\t{}", stats.child_hash_slot_bytes);
    println!("rdata_bytes\t{}", stats.rdata_bytes);
    println!("wire_bytes\t{}", stats.wire_bytes);
    println!("hot_bytes\t{}", stats.hot_bytes);
    println!("cold_bytes\t{}", stats.cold_bytes);
    println!("bytes_per_record\t{}", stats.bytes_per_record);
}

struct Config {
    names: usize,
    lookups: usize,
    signed: bool,
    records_per_rrset: usize,
}

impl Config {
    fn from_args() -> Self {
        let mut config = Self {
            names: DEFAULT_NAMES,
            lookups: DEFAULT_LOOKUPS,
            signed: false,
            records_per_rrset: 1,
        };
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--names" => config.names = parse_usize(args.next(), "--names"),
                "--lookups" => config.lookups = parse_usize(args.next(), "--lookups"),
                "--records-per-rrset" => {
                    config.records_per_rrset = parse_usize(args.next(), "--records-per-rrset")
                }
                "--signed" => config.signed = true,
                _ => panic!("unknown argument: {arg}"),
            }
        }
        assert!(config.names > 0, "--names must be greater than zero");
        assert!(config.lookups > 0, "--lookups must be greater than zero");
        assert!(
            config.records_per_rrset > 0,
            "--records-per-rrset must be greater than zero"
        );
        config
    }
}

fn parse_usize(value: Option<String>, flag: &str) -> usize {
    value
        .unwrap_or_else(|| panic!("{flag} requires a value"))
        .parse()
        .unwrap_or_else(|_| panic!("{flag} requires a non-negative integer"))
}

fn build_flat_snapshot(
    names: usize,
    signed: bool,
    records_per_rrset: usize,
) -> (ZoneSnapshot, Vec<DomainName>) {
    let origin = DomainName::from_absolute_str("capacity-bench.test.").unwrap();
    let rrsets_per_name = if signed { 2 } else { 1 };
    let mut rrsets = Vec::with_capacity(names.saturating_mul(rrsets_per_name));
    let sample_count = names.min(SAMPLE_NAMES);
    let mut query_names = Vec::with_capacity(sample_count);

    for index in 0..names {
        let owner =
            DomainName::from_absolute_str(&format!("n{index:016x}.capacity-bench.test.")).unwrap();
        let address_records = (0..records_per_rrset)
            .map(|record| {
                vec![
                    192,
                    (record & 0xff) as u8,
                    ((index >> 8) & 0xff) as u8,
                    (index & 0xff) as u8,
                ]
            })
            .collect();
        rrsets.push(Rrset::new(
            owner.clone(),
            RecordType::A as u16,
            1,
            300,
            address_records,
        ));
        if signed {
            let signature_records = (0..records_per_rrset)
                .map(|record| {
                    let mut rdata = rrsig_rdata(RecordType::A as u16);
                    rdata.push((record & 0xff) as u8);
                    rdata
                })
                .collect();
            rrsets.push(Rrset::new(
                owner.clone(),
                RecordType::Rrsig as u16,
                1,
                300,
                signature_records,
            ));
        }
        if query_names.len() < sample_count {
            query_names.push(owner);
        }
    }

    (ZoneSnapshot::active(origin, Some(1), rrsets), query_names)
}

fn rrsig_rdata(covered_type: u16) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(20);
    rdata.extend_from_slice(&covered_type.to_be_bytes());
    rdata.extend_from_slice(&[8, 2]);
    rdata.extend_from_slice(&300u32.to_be_bytes());
    rdata.extend_from_slice(&u32::MAX.to_be_bytes());
    rdata.extend_from_slice(&0u32.to_be_bytes());
    rdata.extend_from_slice(&1u16.to_be_bytes());
    rdata.extend_from_slice(&[0]);
    rdata.push(0xaa);
    rdata
}
