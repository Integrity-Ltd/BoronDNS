fn overlay_rrset(owner: &str, kind: u16, rdata: Vec<u8>) -> Rrset {
    Rrset::new(DomainName::from_absolute_str(owner).unwrap(), kind, 1, 300, vec![rdata])
}

// Touch each RRset and advance the actual SOA, not just snapshot metadata.
// This exercises a dirty publication, unlike inserting a fresh sharded image.
fn dirty_and_compact_stores(mut rrsets: Vec<Rrset>) -> (ZoneStore, ZoneStore) {
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    rrsets.push(overlay_rrset("example.test.", 6, soa_rdata()));
    let base = ZoneSnapshot::active(origin, Some(1), rrsets.clone());
    let changes = rrsets.into_iter().map(|mut rrset| {
        if rrset.rr_type == 6 {
            let mut data = soa_rdata();
            let (_, first) = DomainName::parse(&data, 0).unwrap();
            let (_, second) = DomainName::parse(&data, first).unwrap();
            data[first + second..first + second + 4].copy_from_slice(&2u32.to_be_bytes());
            rrset = overlay_rrset("example.test.", 6, data);
        }
        (rrset.owner.canonical_key(), rrset.rr_type, rrset.class, Some(rrset))
    }).collect();
    let updated = base.with_cow_rrset_replacements(2, changes);
    let overlay = ZoneStore::with_publication_policy(crate::zone::ZonePublicationPolicy {
        strategy: crate::zone::ZonePublicationStrategy::Sharded,
        sharded_rrset_threshold: 1,
        ..crate::zone::ZonePublicationPolicy::default()
    });
    overlay.insert_snapshot(base);
    overlay.insert_snapshot(updated.clone());
    let compact = ZoneStore::new();
    compact.insert_snapshot(updated);
    (overlay, compact)
}

fn observed_overlay_response(packet: &[u8], store: &ZoneStore) -> Vec<u8> {
    let snapshot_used = Cell::new(false);
    let action = answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        packet, store, AnswerOptions::default(), |_, _| true, |_, _, _| true,
        |metrics| {
            if !metrics.zone_image_used && metrics.zone_image_failure_reason.is_none() {
                snapshot_used.set(true);
            }
        }, &default_zone_image_provider,
    );
    assert!(snapshot_used.get(), "fixture did not execute snapshot fallback");
    match action {
        DatagramAction::Respond(packet) => packet,
        DatagramAction::Discard => panic!("expected a response"),
    }
}

fn overlay_fixture_response(rrsets: Vec<Rrset>, name: &str, kind: u16) -> Vec<u8> {
    let (overlay, compact) = dirty_and_compact_stores(rrsets);
    let packet = query(&cname_rdata(name), kind, 1);
    let response = observed_overlay_response(&packet, &overlay);
    assert_semantic_response_eq(&response, &store_response(&packet, &compact));
    response
}

#[test]
fn dirty_overlay_dname_occludes_exact_descendants_and_alias_targets() {
    let records = vec![
        overlay_rrset("d.example.test.", 39, cname_rdata("target.example.test.")),
        overlay_rrset("www.d.example.test.", 1, vec![192, 0, 2, 1]),
        overlay_rrset("www.target.example.test.", 1, vec![192, 0, 2, 80]),
        overlay_rrset("alias.example.test.", 5, cname_rdata("www.d.example.test.")),
    ];
    for name in ["www.d.example.test.", "alias.example.test."] {
        let response = overlay_fixture_response(records.clone(), name, 1);
        let parsed = semantic_response(&response).unwrap();
        assert_eq!(parsed.flags & 0x860f, 0x8400);
        let answers = &parsed.sections[0];
        assert!(answers.iter().any(|rr| rr.rr_type == 39 && rr.owner == cname_rdata("d.example.test.") && rr.rdata == cname_rdata("target.example.test.")));
        assert!(answers.iter().any(|rr| rr.rr_type == 5 && rr.owner == cname_rdata("www.d.example.test.") && rr.rdata == cname_rdata("www.target.example.test.")));
        assert_eq!(answers.iter().filter(|rr| rr.rr_type == 1).map(|rr| rr.rdata.clone()).collect::<Vec<_>>(), vec![vec![192, 0, 2, 80]]);
    }
    for kind in [5, 255] {
        let response = overlay_fixture_response(records.clone(), "www.d.example.test.", kind);
        assert!(response_answer_types(&response).contains(&39));
        assert!(!response_answer_rdatas(&response, 1).contains(&vec![192, 0, 2, 1]));
    }
    // The DNAME owner itself is not redirected.
    let response = overlay_fixture_response(records, "d.example.test.", 39);
    assert_eq!(response_answer_types(&response), vec![39]);
}

#[test]
fn dirty_overlay_repeated_dname_keeps_chain_and_budget() {
    let records = vec![
        overlay_rrset("d.example.test.", 39, cname_rdata("example.test.")),
        overlay_rrset("x.example.test.", 1, vec![192, 0, 2, 80]),
    ];
    let response = overlay_fixture_response(records, "x.d.d.example.test.", 1);
    assert_eq!(response[3] & 0x0f, 0);
    assert_eq!(response_answer_types(&response), vec![39, 5, 5, 1]);
    let parsed = semantic_response(&response).unwrap();
    let aliases = parsed.sections[0].iter().filter(|rr| rr.rr_type == 5).map(|rr| (rr.owner.clone(), rr.rdata.clone())).collect::<Vec<_>>();
    assert!(aliases.contains(&(cname_rdata("x.d.d.example.test."), cname_rdata("x.d.example.test."))));
    assert!(aliases.contains(&(cname_rdata("x.d.example.test."), cname_rdata("x.example.test."))));
}

#[test]
fn dirty_alias_to_delegation_preserves_referral_and_hosted_child_continuation() {
    let (dirty, compact) = dirty_and_compact_stores(vec![
        overlay_rrset("alias.example.test.", 5, cname_rdata("www.child.example.test.")),
        overlay_rrset("child.example.test.", 2, cname_rdata("ns.child.example.test.")),
        overlay_rrset("ns.child.example.test.", 1, vec![192, 0, 2, 53]),
    ]);
    let packet = query(&cname_rdata("alias.example.test."), 1, 1);
    for hosted in [false, true] {
        if hosted {
            for store in [&dirty, &compact] {
                store.insert_snapshot(ZoneSnapshot::active(DomainName::from_absolute_str("child.example.test.").unwrap(), Some(1), vec![
                    overlay_rrset("child.example.test.", 6, soa_rdata()),
                    overlay_rrset("www.child.example.test.", 1, vec![192, 0, 2, 80]),
                ]));
            }
        }
        let response = store_response(&packet, &dirty);
        assert_semantic_response_eq(&response, &store_response(&packet, &compact));
        assert_eq!(response[2] & 4, 4);
        if hosted {
            assert_eq!(response_answer_rdatas(&response, 1), vec![vec![192, 0, 2, 80]]);
        } else {
            let parsed = semantic_response(&response).unwrap();
            assert!(parsed.sections[1].iter().any(|rr| rr.rr_type == 2));
            assert!(parsed.sections[2].iter().any(|rr| rr.rr_type == 1 && rr.rdata == vec![192, 0, 2, 53]));
        }
    }
}

#[test]
fn outer_dname_occludes_nested_dname_in_compact_and_dirty_images() {
    let records = vec![
        overlay_rrset("d.example.test.", 39, cname_rdata("target.example.test.")),
        overlay_rrset("nested.d.example.test.", 39, cname_rdata("wrong.example.test.")),
        overlay_rrset("x.nested.target.example.test.", 1, vec![192, 0, 2, 80]),
        overlay_rrset("x.wrong.example.test.", 1, vec![192, 0, 2, 1]),
    ];
    let (overlay, compact) = dirty_and_compact_stores(records);
    let packet = query(&cname_rdata("x.nested.d.example.test."), 1, 1);
    for store in [&compact, &overlay] {
        let response = store_response(&packet, store);
        assert_eq!(response_answer_rdatas(&response, 1), vec![vec![192, 0, 2, 80]]);
        assert_eq!(response_answer_rdatas(&response, 39), vec![cname_rdata("target.example.test.")]);
    }
}

#[test]
fn alias_continuation_preserves_configured_any_mode() {
    let (overlay, compact) = dirty_and_compact_stores(vec![
        overlay_rrset("d.example.test.", 39, cname_rdata("target.example.test.")),
        overlay_rrset("w.example.test.", 39, cname_rdata("wild.example.test.")),
        overlay_rrset("x.target.example.test.", 1, vec![192, 0, 2, 80]),
        overlay_rrset("x.target.example.test.", 28, vec![0; 16]),
        overlay_rrset("*.wild.example.test.", 1, vec![192, 0, 2, 80]),
        overlay_rrset("*.wild.example.test.", 28, vec![0; 16]),
        overlay_rrset("alias.example.test.", 5, cname_rdata("x.wild.example.test.")),
    ]);
    for name in ["x.d.example.test.", "x.w.example.test.", "alias.example.test."] {
        let packet = query(&cname_rdata(name), 255, 1);
        for mode in [AnyResponseMode::Minimal, AnyResponseMode::Full] {
            let options = AnswerOptions { any_response: mode, ..AnswerOptions::default() };
            let response = store_response_with_options(&packet, &overlay, options);
            assert_semantic_response_eq(&response, &store_response_with_options(&packet, &compact, options));
            // ANY stops at either an ordinary or synthesized CNAME, in both
            // modes. It must not return records belonging to the target.
            assert_eq!(response_answer_rdatas(&response, 5).len(), 1);
            assert!(response_answer_rdatas(&response, 1).is_empty());
            assert!(response_answer_rdatas(&response, 28).is_empty());
            assert!(response_authority_types(&response).is_empty());
        }
    }
}

#[test]
fn dirty_overlay_alias_continuation_restarts_wildcard_lookup() {
    let response = overlay_fixture_response(vec![
        overlay_rrset("alias.example.test.", 5, cname_rdata("missing.wild.example.test.")),
        overlay_rrset("*.wild.example.test.", 1, vec![192, 0, 2, 80]),
    ], "alias.example.test.", 1);
    assert_eq!(response[3] & 0x0f, 0);
    assert_eq!(response_answer_types(&response), vec![5, 1]);
    assert_eq!(response_answer_rdatas(&response, 1), vec![vec![192, 0, 2, 80]]);
}

#[test]
fn dirty_overlay_wildcard_cname_loop_retains_two_expansions_once() {
    let response = overlay_fixture_response(vec![
        overlay_rrset("*.wild.example.test.", 5, cname_rdata("missing.wild.example.test.")),
    ], "other.wild.example.test.", 1);
    assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
    assert_eq!(response_answer_types(&response), vec![5, 5]);
    let parsed = semantic_response(&response).unwrap();
    assert_eq!(parsed.sections[0].iter().map(|rr| rr.owner.clone()).collect::<Vec<_>>(), vec![cname_rdata("other.wild.example.test."), cname_rdata("missing.wild.example.test.")].into_iter().collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>());
}

#[test]
fn dirty_overlay_delegation_still_precedes_parent_dname() {
    let response = overlay_fixture_response(vec![
        overlay_rrset("child.example.test.", 2, cname_rdata("ns.child.example.test.")),
        overlay_rrset("d.child.example.test.", 39, cname_rdata("example.test.")),
    ], "x.d.child.example.test.", 1);
    assert_eq!(response[2] & 4, 0);
    assert!(response_answer_types(&response).is_empty());
    assert_eq!(response_authority_types(&response), vec![2]);
}

fn overlay_signed_wildcard_records() -> Vec<Rrset> {
    let mut records = vec![
        overlay_rrset("example.test.", 51, nsec3param_rdata(1)),
        overlay_rrset("example.test.", 46, rrsig_rdata(RecordType::Soa)),
        overlay_rrset("*.a.example.test.", 5, cname_rdata("deep.missing.b.example.test.")),
        overlay_rrset("*.a.example.test.", 46, rrsig_rdata(RecordType::Cname)),
        overlay_rrset("*.b.example.test.", 1, vec![192, 0, 2, 80]),
        overlay_rrset("*.b.example.test.", 46, rrsig_rdata(RecordType::A)),
        overlay_rrset("alias.example.test.", 5, cname_rdata("deep.missing.b.example.test.")),
        overlay_rrset("alias.example.test.", 46, rrsig_rdata(RecordType::Cname)),
    ];
    let mut names = vec!["example.test.".to_owned(), "a.example.test.".to_owned(), "b.example.test.".to_owned(), "*.a.example.test.".to_owned(), "*.b.example.test.".to_owned(), "alias.example.test.".to_owned()];
    for index in 0..32 {
        let name = format!("anchor-{index}.example.test.");
        records.push(overlay_rrset(&name, 16, b"\x01x".to_vec()));
        names.push(name);
    }
    records.extend(nsec3_ring_rrsets(&names, "example.test."));
    records
}

fn assert_wildcard_proof_roles(response: &[u8], records: &[Rrset], next_closers: &[&str]) {
    let parsed = semantic_response(response).unwrap();
    assert_eq!(parsed.flags & 0x860f, 0x8400);
    let ring_names = records.iter().filter(|rr| rr.rr_type == 50).map(|rr| rr.owner.clone()).collect::<Vec<_>>();
    let mut hashes = ring_names.iter().map(|name| name.canonical_key()).collect::<Vec<_>>();
    hashes.sort();
    let expected = next_closers.iter().map(|name| {
        let hash = nsec3_owner(name, "example.test.").canonical_key();
        let cover = hashes.iter().rev().find(|owner| **owner < hash).unwrap_or(hashes.last().unwrap());
        cname_rdata(cover)
    }).collect::<std::collections::BTreeSet<_>>();
    let actual = parsed.sections[1].iter().filter(|rr| rr.rr_type == 50).map(|rr| rr.owner.clone()).collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected, "next-closer proof roles, not QNAME or original alias");
    for owner in &actual {
        assert!(parsed.sections[1].iter().any(|rr| rr.rr_type == 46 && &rr.owner == owner && rr.rdata == rrsig_rdata(RecordType::Nsec3)));
    }
    let address = parsed.sections[0].iter().find(|rr| rr.rr_type == 1).unwrap();
    assert_eq!(address.rdata, vec![192, 0, 2, 80]);
    assert!(parsed.sections[0].iter().any(|rr| rr.rr_type == 46 && rr.owner == address.owner && rr.rdata == rrsig_rdata(RecordType::A)), "wildcard source signature must have the expanded owner");
}

#[test]
fn dirty_overlay_direct_wildcard_preserves_next_closer_proof_and_signature() {
    let records = overlay_signed_wildcard_records();
    let (overlay, compact) = dirty_and_compact_stores(records.clone());
    for name in ["missing.b.example.test.", "deep.missing.b.example.test."] {
        let mut packet = query(&cname_rdata(name), 1, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);
        let response = observed_overlay_response(&packet, &overlay);
        assert_wildcard_proof_roles(&response, &records, &["missing.b.example.test."]);
        assert_semantic_response_eq(&response, &store_response(&packet, &compact));
    }
}

#[test]
fn dirty_overlay_alias_wildcard_uses_target_proof_context() {
    let records = overlay_signed_wildcard_records();
    let (overlay, compact) = dirty_and_compact_stores(records.clone());
    let mut packet = query(&cname_rdata("alias.example.test."), 1, 1);
    append_opt(&mut packet, 4096, 0x8000, &[]);
    let response = observed_overlay_response(&packet, &overlay);
    assert_wildcard_proof_roles(&response, &records, &["missing.b.example.test."]);
    assert_semantic_response_eq(&response, &store_response(&packet, &compact));
}

#[test]
fn compact_and_overlay_prove_every_wildcard_in_an_alias_chain() {
    let records = overlay_signed_wildcard_records();
    let (overlay, compact) = dirty_and_compact_stores(records.clone());
    let mut packet = query(&cname_rdata("deep.missing.a.example.test."), 1, 1);
    append_opt(&mut packet, 4096, 0x8000, &[]);
    let compact_response = store_response(&packet, &compact);
    assert_wildcard_proof_roles(&compact_response, &records, &["missing.a.example.test.", "missing.b.example.test."]);
    let response = observed_overlay_response(&packet, &overlay);
    assert_wildcard_proof_roles(&response, &records, &["missing.a.example.test.", "missing.b.example.test."]);
    assert_semantic_response_eq(&response, &compact_response);
}

#[test]
fn dirty_overlay_optout_ds_uses_closest_provable_and_next_closer() {
    let mut names = vec!["example.test.".to_owned()];
    let mut records = vec![
        overlay_rrset("example.test.", 51, nsec3param_rdata(1)),
        overlay_rrset("child.branch.example.test.", 2, cname_rdata("ns.example.test.")),
    ];
    for index in 0..32 {
        let name = format!("anchor-{index}.example.test.");
        records.push(overlay_rrset(&name, 16, b"\x01x".to_vec()));
        names.push(name);
    }
    records.extend(nsec3_optout_ring_rrsets(&names, "example.test.", "branch.example.test."));
    let (overlay, compact) = dirty_and_compact_stores(records);
    for (name, kind) in [("child.branch.example.test.", 43), ("branch.example.test.", 1)] {
    let mut packet = query(&cname_rdata(name), kind, 1);
    append_opt(&mut packet, 4096, 0x8000, &[]);
    let response = observed_overlay_response(&packet, &overlay);
    let expected = [nsec3_owner("example.test.", "example.test."), nsec3_covering_owner("branch.example.test.", &names, "example.test.")];
    let owners = response_authority_owners(&response, 50);
    for owner in expected { assert!(owners.contains(&owner), "missing Opt-Out proof role {owner}"); }
    assert_semantic_response_eq(&response, &store_response(&packet, &compact));
    }
}

#[test]
fn dirty_overlay_signatures_use_the_covered_rrset_ttl() {
    let mut records = overlay_signed_wildcard_records();
    for rrset in &mut records {
        if rrset.rr_type == 46 { rrset.ttl = 0; }
    }
    let (overlay, compact) = dirty_and_compact_stores(records);
    for name in ["deep.missing.b.example.test.", "alias.example.test."] {
        let mut packet = query(&cname_rdata(name), 1, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);
        let response = observed_overlay_response(&packet, &overlay);
        let parsed = semantic_response(&response).unwrap();
        let signatures = parsed.sections.iter().flatten().filter(|rr| rr.rr_type == 46).collect::<Vec<_>>();
        assert!(!signatures.is_empty());
        assert!(signatures.iter().all(|rr| rr.ttl == 300), "signature TTL must match its covered RRset");
        assert_semantic_response_eq(&response, &store_response(&packet, &compact));
    }
}

#[test]
fn dirty_overlay_negative_alias_and_wildcard_nodata_keep_terminal_context() {
    let mut records = overlay_signed_wildcard_records();
    records.push(overlay_rrset("negative.example.test.", 5, cname_rdata("missing.anchor-0.example.test.")));
    records.push(overlay_rrset("negative.example.test.", 46, rrsig_rdata(RecordType::Cname)));
    // The additional alias must be represented in the denial ring as well.
    records.retain(|rr| rr.rr_type != 50 && !(rr.rr_type == 46 && rr.owner.labels()[0].len() == 32));
    let mut names = records.iter().filter(|rr| rr.rr_type != 46).map(|rr| rr.owner.canonical_key()).collect::<Vec<_>>();
    names.extend(["a.example.test.".to_owned(), "b.example.test.".to_owned()]);
    records.extend(nsec3_ring_rrsets(&names, "example.test."));
    let (overlay, compact) = dirty_and_compact_stores(records);
    for (name, kind, rcode) in [("negative.example.test.", 1, 3), ("alias.example.test.", 28, 0)] {
        let mut packet = query(&cname_rdata(name), kind, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);
        let response = observed_overlay_response(&packet, &overlay);
        assert_eq!(response[3] & 0x0f, rcode);
        assert!(response_answer_types(&response).contains(&5));
        assert!(!response_authority_owners(&response, 50).is_empty());
        assert_semantic_response_eq(&response, &store_response(&packet, &compact));
    }
}

#[test]
fn cross_zone_signed_overlay_keeps_remaining_budget_and_continuation_after_signatures() {
    let (store, _) = dirty_and_compact_stores(vec![
        overlay_rrset("middle.example.test.", 5, cname_rdata("step.example.test.")),
        overlay_rrset("middle.example.test.", 46, rrsig_rdata(RecordType::Cname)),
        overlay_rrset("step.example.test.", 5, cname_rdata("target.other.test.")),
        overlay_rrset("step.example.test.", 46, rrsig_rdata(RecordType::Cname)),
    ]);
    store.insert_snapshot(ZoneSnapshot::active(DomainName::from_absolute_str("start.test.").unwrap(), Some(1), vec![
        overlay_rrset("start.test.", 6, soa_rdata()),
        overlay_rrset("alias.start.test.", 5, cname_rdata("middle.example.test.")),
    ]));
    store.insert_snapshot(ZoneSnapshot::active(DomainName::from_absolute_str("other.test.").unwrap(), Some(1), vec![
        overlay_rrset("other.test.", 6, soa_rdata()),
        overlay_rrset("target.other.test.", 1, vec![192, 0, 2, 99]),
    ]));
    let mut packet = query(&cname_rdata("alias.start.test."), 1, 1);
    append_opt(&mut packet, 4096, 0x8000, &[]);
    // The public metrics observer reports the final stage only. Prove the
    // intermediate publication is dirty; cross-zone dispatch always uses its
    // snapshot in that case, while the final other.test stage is compact.
    assert!(store.find_published_zone(&DomainName::from_absolute_str("middle.example.test.").unwrap()).unwrap().has_incremental_overlay());
    let response = store_response(&packet, &store);
    assert_eq!(response_answer_rdatas(&response, 1), vec![vec![192, 0, 2, 99]]);
    let response = store_response_with_options(&packet, &store, AnswerOptions { max_cname_chain: 2, ..AnswerOptions::default() });
    assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
    assert!(response_answer_rdatas(&response, 1).is_empty());
}
