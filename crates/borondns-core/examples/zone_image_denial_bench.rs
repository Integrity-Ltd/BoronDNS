use std::{env, hint::black_box, time::Instant};

use borondns_core::{
    dns::{AnyResponseMode, DomainName, RecordType},
    zone::{Rrset, ZoneSnapshot},
    zone_image::ZoneImage,
};
use sha1::{Digest, Sha1};

fn main() {
    let records = positive_arg("--records", 10_000);
    let iterations = positive_arg("--iterations", 10_000);
    let query_cases = positive_arg("--query-cases", 257);

    println!("metric\tvalue");
    println!("benchmark_kind\tzone_image_denial_lookup");
    println!("records\t{records}");
    println!("iterations\t{iterations}");
    println!("query_cases\t{query_cases}");

    let (nsec_snapshot, nsec_queries) = build_nsec_snapshot(records, query_cases);
    let started = Instant::now();
    let nsec_image = ZoneImage::compile(&nsec_snapshot).expect("NSEC image compiles");
    let nsec_stats = nsec_image.stats();
    println!(
        "nsec_compile_ms\t{:.3}",
        started.elapsed().as_secs_f64() * 1_000.0
    );
    println!("nsec_range_groups\t{}", nsec_stats.nsec_range_group_count);
    println!(
        "nsec_indexed_range_groups\t{}",
        nsec_stats.nsec_indexed_range_group_count
    );
    let (elapsed, proof_count) = time_denial_lookup(&nsec_image, &nsec_queries, iterations);
    println!(
        "nsec_denial_ns_per_query\t{:.3}",
        elapsed.as_secs_f64() * 1_000_000_000.0 / iterations as f64
    );
    println!("nsec_proof_rrset_count\t{}", black_box(proof_count));

    let (nsec3_snapshot, nsec3_queries) = build_nsec3_snapshot(records, query_cases);
    let started = Instant::now();
    let nsec3_image = ZoneImage::compile(&nsec3_snapshot).expect("NSEC3 image compiles");
    let nsec3_stats = nsec3_image.stats();
    println!(
        "nsec3_compile_ms\t{:.3}",
        started.elapsed().as_secs_f64() * 1_000.0
    );
    println!(
        "nsec3_range_groups\t{}",
        nsec3_stats.nsec3_range_group_count
    );
    println!(
        "nsec3_indexed_range_groups\t{}",
        nsec3_stats.nsec3_indexed_range_group_count
    );
    let (elapsed, proof_count) = time_denial_lookup(&nsec3_image, &nsec3_queries, iterations);
    println!(
        "nsec3_denial_ns_per_query\t{:.3}",
        elapsed.as_secs_f64() * 1_000_000_000.0 / iterations as f64
    );
    println!("nsec3_proof_rrset_count\t{}", black_box(proof_count));
}

fn positive_arg(flag: &str, default: usize) -> usize {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == flag {
            return args
                .next()
                .and_then(|value| value.parse().ok())
                .filter(|value| *value > 0)
                .unwrap_or_else(|| panic!("{flag} requires a positive integer"));
        }
    }
    default
}

fn build_nsec_snapshot(records: usize, query_cases: usize) -> (ZoneSnapshot, Vec<DomainName>) {
    let origin = DomainName::from_absolute_str("nsec-bench.test.").unwrap();
    let owners = (0..records)
        .map(|index| {
            DomainName::from_absolute_str(&format!("n{index:016x}.nsec-bench.test.")).unwrap()
        })
        .collect::<Vec<_>>();
    let mut rrsets = Vec::with_capacity(records + 1);
    rrsets.push(soa_rrset(&origin));
    for (index, owner) in owners.iter().enumerate() {
        let next = &owners[(index + 1) % owners.len()];
        rrsets.push(Rrset::new(
            owner.clone(),
            RecordType::Nsec as u16,
            1,
            300,
            vec![nsec_rdata(next)],
        ));
    }
    let queries = (0..query_cases)
        .map(|index| {
            let slot = index.saturating_mul(records) / query_cases;
            DomainName::from_absolute_str(&format!("n{slot:016x}-missing.nsec-bench.test."))
                .unwrap()
        })
        .collect();
    (ZoneSnapshot::active(origin, Some(1), rrsets), queries)
}

fn build_nsec3_snapshot(records: usize, query_cases: usize) -> (ZoneSnapshot, Vec<DomainName>) {
    let origin = DomainName::from_absolute_str("nsec3-bench.test.").unwrap();
    let mut hashes = (0..records)
        .map(|index| Sha1::digest(format!("owner-{index:016x}").as_bytes()).into())
        .collect::<Vec<[u8; 20]>>();
    hashes.sort_unstable();
    hashes.dedup();
    assert_eq!(
        hashes.len(),
        records,
        "synthetic owner hashes must be unique"
    );

    let mut rrsets = Vec::with_capacity(records + 1);
    rrsets.push(soa_rrset(&origin));
    for (index, owner_hash) in hashes.iter().enumerate() {
        let owner = DomainName::from_absolute_str(&format!(
            "{}.nsec3-bench.test.",
            base32hex_no_padding(owner_hash)
        ))
        .unwrap();
        let next_hash = &hashes[(index + 1) % hashes.len()];
        rrsets.push(Rrset::new(
            owner,
            RecordType::Nsec3 as u16,
            1,
            300,
            vec![nsec3_rdata(next_hash)],
        ));
    }
    let queries = (0..query_cases)
        .map(|index| {
            DomainName::from_absolute_str(&format!("missing-{index:016x}.nsec3-bench.test."))
                .unwrap()
        })
        .collect();
    (ZoneSnapshot::active(origin, Some(1), rrsets), queries)
}

fn time_denial_lookup(
    image: &ZoneImage,
    queries: &[DomainName],
    iterations: usize,
) -> (std::time::Duration, usize) {
    let started = Instant::now();
    let mut proof_count = 0usize;
    for index in 0..iterations {
        let qname = black_box(&queries[index % queries.len()]);
        let plan =
            image.lookup_response_plan(qname, RecordType::A as u16, 1, 8, AnyResponseMode::Minimal);
        let plan = image.augment_lookup_plan_with_dnssec(plan, qname, 1, 2_500);
        proof_count = proof_count.saturating_add(plan.authority_rrsets().len());
    }
    (started.elapsed(), proof_count)
}

fn soa_rrset(origin: &DomainName) -> Rrset {
    let mut rdata = DomainName::from_absolute_str("ns.nsec-bench.test.")
        .unwrap()
        .to_wire();
    rdata.extend(
        DomainName::from_absolute_str("hostmaster.nsec-bench.test.")
            .unwrap()
            .to_wire(),
    );
    for value in [1u32, 3_600, 600, 86_400, 300] {
        rdata.extend_from_slice(&value.to_be_bytes());
    }
    Rrset::new(origin.clone(), RecordType::Soa as u16, 1, 300, vec![rdata])
}

fn nsec_rdata(next: &DomainName) -> Vec<u8> {
    let mut rdata = next.to_wire();
    rdata.extend_from_slice(&[0, 1, 0x40]);
    rdata
}

fn nsec3_rdata(next_hash: &[u8; 20]) -> Vec<u8> {
    let mut rdata = vec![1, 0, 0, 0, 0, 20];
    rdata.extend_from_slice(next_hash);
    rdata.extend_from_slice(&[0, 1, 0x40]);
    rdata
}

fn base32hex_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
            buffer &= (1u32 << bits) - 1;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}
