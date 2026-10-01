use boron_gen::{ContentProfile, Scenario, ScenarioConfig, ZoneKind};
use borondns_core::dns::RecordType;
use std::collections::BTreeSet;

#[test]
fn portfolio_names_records_and_nested_selection_are_deterministic() {
    let profile: ContentProfile = "portfolio".parse().expect("portfolio profile");
    let config = ScenarioConfig {
        profile,
        zones: 1000,
        names_per_zone: 3,
        records_per_name: 4,
        structural_rrsigs: false,
        ixfr_delta_rrsets: 0,
        ..ScenarioConfig::default()
    };
    let a = Scenario::new(config.clone()).unwrap();
    let b = Scenario::new(config).unwrap();
    let mut origins = BTreeSet::new();
    let mut owner_lengths = BTreeSet::new();
    for index in 0..1000 {
        let origin = a.zone_origin(index).unwrap();
        assert_eq!(origin, b.zone_origin(index).unwrap());
        assert!(origins.insert(origin.canonical_key()));
        assert_eq!(a.locate_zone(&origin), Some(ZoneKind::Member(index)));
        if index % 100 == 99 {
            assert_eq!(
                origin.canonical_key(),
                format!("c.{}", a.zone_origin(index - 1).unwrap().canonical_key())
            );
        }
        let records = a
            .records(ZoneKind::Member(index))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(records.len(), 24); //23 snapshot records plus closing SOA
        assert_eq!(a.manifest().member_snapshot_records_each, 23);
        assert_eq!(records.first(), records.last());
        assert_eq!(
            records
                .iter()
                .filter(|r| r.rr_type == RecordType::Ns as u16)
                .count(),
            2
        );
        let hosts = records
            .iter()
            .filter(|r| {
                r.rr_type == RecordType::A as u16 && !r.owner.canonical_key().starts_with("ns")
            })
            .map(|r| r.owner.canonical_key())
            .collect::<BTreeSet<_>>();
        assert_eq!(hosts.len(), 3);
        for host in hosts {
            owner_lengths.insert(host.len());
            assert_eq!(records.iter().filter(|r| r.rr_type == RecordType::A as u16 && r.owner.canonical_key() == host).map(|r| r.rdata.clone()).collect::<BTreeSet<_>>().len(), 4, "four distinct A values survive ingestion deduplication");
            assert_eq!(records.iter().filter(|r| r.rr_type == RecordType::A as u16 && r.owner.canonical_key() == host).count(), 4);
        }
    }
    assert_eq!(
        owner_lengths.len(),
        1,
        "nested and flat queries have equal wire length"
    );
    assert!(a.zone_origin(1000).is_err());
}

#[test]
fn portfolio_large_indices_roundtrip_without_aliases() {
    let config = ScenarioConfig {
        profile: ContentProfile::Portfolio,
        zones: 1_000_000,
        names_per_zone: 3,
        records_per_name: 4,
        structural_rrsigs: false,
        ..ScenarioConfig::default()
    };
    for seed in [0, 1, u64::MAX, config.seed] {
        let scenario = Scenario::new(ScenarioConfig {
            seed,
            ..config.clone()
        })
        .unwrap();
        for index in [0, 98, 99, 100, 100_000, 999_998, 999_999] {
            let name = scenario.zone_origin(index).unwrap();
            assert_eq!(scenario.locate_zone(&name), Some(ZoneKind::Member(index)));
        }
        let fake = borondns_core::dns::DomainName::from_absolute_str(&format!(
            "c.{}",
            scenario.zone_origin(0).unwrap().canonical_key()
        ))
        .unwrap();
        assert_eq!(scenario.locate_zone(&fake), None);
    }
}

#[test]
fn portfolio_rejects_incompatible_shape() {
    let profile: ContentProfile = "portfolio".parse().unwrap();
    let valid = ScenarioConfig {
        profile,
        zones: 1000,
        names_per_zone: 3,
        records_per_name: 4,
        structural_rrsigs: false,
        ..ScenarioConfig::default()
    };
    for config in [
        ScenarioConfig {
            names_per_zone: 4,
            ..valid.clone()
        },
        ScenarioConfig {
            records_per_name: 5,
            ..valid.clone()
        },
        ScenarioConfig {
            structural_rrsigs: true,
            ..valid.clone()
        },
        ScenarioConfig {
            zones: u64::MAX,
            ..valid
        },
    ] {
        assert!(Scenario::new(config).is_err());
    }
}

fn churn_config(delta: u64) -> ScenarioConfig {
    ScenarioConfig {
        profile: ContentProfile::Portfolio,
        zones: 1000,
        names_per_zone: 3,
        records_per_name: 4,
        structural_rrsigs: false,
        ixfr_delta_rrsets: delta,
        ..ScenarioConfig::default()
    }
}

#[test]
fn portfolio_churn_ixfr_matches_axfr_and_preserves_query_corpus() {
    use boron_gen::GeneratedRecord;
    let scenario = Scenario::new(churn_config(3)).expect("portfolio supports bounded churn");
    let unchanged = Scenario::new(churn_config(0)).unwrap();
    assert_eq!(scenario.manifest().member_snapshot_records_each, 26);
    for index in [0, 98, 99, 999] {
        let zone = ZoneKind::Member(index);
        for (from, to) in [(1u32, 2u32), (10, 13), (u32::MAX - 1, 1)] {
            let snapshot = |serial| {
                let mut records = scenario
                    .records_at_serial(zone, serial)
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert_eq!(records.len(), 27);
                assert_eq!(records.first(), records.last());
                records.pop();
                records
            };
            let mut current = snapshot(from);
            let target = snapshot(to);
            let deltas = scenario
                .ixfr_records(zone, from, to)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(deltas.first(), target.first());
            assert_eq!(deltas.last(), target.first());
            let generations = to.wrapping_sub(from) as usize;
            assert_eq!(deltas.len(), 2 + generations * 8);
            let (generations, remainder) = deltas[1..deltas.len() - 1].as_chunks::<8>();
            assert!(remainder.is_empty());
            for generation in generations {
                assert_eq!(&current[0], &generation[0]);
                for deleted in &generation[1..4] {
                    let position = current
                        .iter()
                        .position(|r| r == deleted)
                        .expect("IXFR may only delete a present record");
                    current.remove(position);
                }
                current[0] = generation[4].clone();
                for added in &generation[5..8] {
                    assert!(!current.contains(added));
                    current.push(added.clone());
                }
            }
            let key = |r: &GeneratedRecord| {
                (
                    r.owner.canonical_key(),
                    r.rr_type,
                    r.class,
                    r.ttl,
                    r.rdata.clone(),
                )
            };
            assert_eq!(
                current.iter().map(key).collect::<BTreeSet<_>>(),
                target.iter().map(key).collect()
            );
            let stable = scenario
                .records_at_serial(zone, to)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .into_iter()
                .filter(|r| !r.owner.canonical_key().starts_with("ix"))
                .collect::<Vec<_>>();
            let reference = unchanged
                .records_at_serial(zone, to)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(
                stable, reference,
                "benchmark host records must stay byte-identical"
            );
            let unchanged_ixfr = scenario
                .ixfr_records(zone, to, to)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(unchanged_ixfr, vec![target[0].clone()]);
        }
    }
    assert_eq!(scenario.ixfr_delta_rrsets(ZoneKind::Catalog), 0);
    assert_eq!(
        scenario.records(ZoneKind::Catalog).unwrap().count(),
        unchanged.records(ZoneKind::Catalog).unwrap().count()
    );
}

#[test]
fn portfolio_churn_counts_reject_overflow_without_generating_records() {
    assert!(matches!(
        Scenario::new(churn_config(u64::MAX)),
        Err(boron_gen::ScenarioError::RecordCountOverflow)
    ));
}

#[test]
fn portfolio_churn_names_are_checked_before_generation() {
    let mut config = churn_config(1);
    config.origin = format!(
        "{}.{}.{}.{}.",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(28)
    );
    assert!(matches!(
        Scenario::new(config),
        Err(boron_gen::ScenarioError::GeneratedNameTooLong)
    ));

    let config = ScenarioConfig {
        origin: format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(27)
        ),
        ..churn_config(1)
    };
    let scenario = Scenario::new(config).expect("255-byte churn owner fits");
    let records = scenario
        .records(ZoneKind::Member(99))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let churn = records
        .iter()
        .find(|r| r.owner.canonical_key().starts_with("ix"))
        .unwrap();
    assert_eq!(churn.owner.to_wire().len(), 255);
}
