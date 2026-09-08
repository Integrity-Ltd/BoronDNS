fn cross_zone_target(store: &ZoneStore, target: &str, kind: u16, data: Vec<u8>) {
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("other.test.").unwrap(),
        Some(1),
        vec![overlay_rrset("other.test.", 6, soa_rdata()), overlay_rrset(target, kind, data)],
    ));
}

#[test]
fn cross_zone_dirty_initial_alias_follows_target_and_preserves_budget() {
    let (dirty, compact) = dirty_and_compact_stores(vec![
        overlay_rrset("alias.example.test.", 5, cname_rdata("step.example.test.")),
        overlay_rrset("step.example.test.", 5, cname_rdata("target.other.test.")),
    ]);
    for store in [&dirty, &compact] {
        cross_zone_target(store, "target.other.test.", 1, vec![192, 0, 2, 77]);
    }
    let packet = query(&cname_rdata("alias.example.test."), 1, 1);
    let response = store_response(&packet, &dirty);
    assert_eq!(response_answer_rdatas(&response, 1), vec![vec![192, 0, 2, 77]]);
    assert_semantic_response_eq(&response, &store_response(&packet, &compact));
    let options = AnswerOptions { max_cname_chain: 1, ..AnswerOptions::default() };
    let response = store_response_with_options(&packet, &dirty, options);
    assert_eq!(response[3] & 15, Rcode::ServFail as u8);
    assert!(response_answer_rdatas(&response, 1).is_empty());
    cross_zone_target(&dirty, "target.other.test.", 5, cname_rdata("next.other.test."));
    let response = store_response_with_options(&packet, &dirty, AnswerOptions { max_cname_chain: 2, ..AnswerOptions::default() });
    assert_eq!(response[3] & 15, Rcode::ServFail as u8, "cross-zone transition must not reset the two consumed steps");
}

#[test]
fn cross_zone_wildcard_alias_keeps_initial_denial_proof() {
    let mut records = overlay_signed_wildcard_records();
    for rrset in &mut records {
        if rrset.owner.canonical_key() == "*.a.example.test." && rrset.rr_type == 5 {
            *rrset = overlay_rrset("*.a.example.test.", 5, cname_rdata("target.other.test."));
        }
    }
    let (dirty, compact) = dirty_and_compact_stores(records);
    let mut packet = query(&cname_rdata("missing.a.example.test."), 1, 1);
    append_opt(&mut packet, 4096, 0x8000, &[]);
    for store in [&compact, &dirty] {
        let partial = store_response(&packet, store);
        let proofs = response_authority_owners(&partial, 50);
        let expected = semantic_response(&partial).unwrap();
        assert!(!proofs.is_empty(), "fixture must carry a wildcard denial proof");
        cross_zone_target(store, "target.other.test.", 1, vec![192, 0, 2, 77]);
        let response = store_response(&packet, store);
        assert_eq!(response_authority_owners(&response, 50), proofs, "cross-zone continuation dropped the wildcard proof");
        assert_eq!(semantic_response(&response).unwrap().sections[1], expected.sections[1], "proof signatures and TTLs must survive composition too");
        assert_eq!(response_answer_rdatas(&response, 1), vec![vec![192, 0, 2, 77]]);
        assert!(response_answer_types(&response).contains(&46));
    }
}

#[test]
fn cross_zone_dirty_initial_loop_terminates() {
    let (dirty, compact) = dirty_and_compact_stores(vec![overlay_rrset("alias.example.test.", 5, cname_rdata("target.other.test."))]);
    for store in [&dirty, &compact] {
        cross_zone_target(store, "target.other.test.", 5, cname_rdata("alias.example.test."));
        let packet = query(&cname_rdata("alias.example.test."), 1, 1);
        let response = store_response(&packet, store);
        assert_eq!(response[3] & 15, Rcode::ServFail as u8);
        assert!(response_answer_rdatas(&response, 1).is_empty());
    }
}

#[test]
fn cross_zone_intermediate_wildcard_alias_keeps_denial_proof() {
    let mut records = overlay_signed_wildcard_records();
    for rrset in &mut records {
        if rrset.owner.canonical_key() == "*.a.example.test." && rrset.rr_type == 5 {
            *rrset = overlay_rrset("*.a.example.test.", 5, cname_rdata("target.other.test."));
        }
    }
    let (dirty, compact) = dirty_and_compact_stores(records);
    let mut intermediate = query(&cname_rdata("missing.a.example.test."), 1, 1);
    append_opt(&mut intermediate, 4096, 0x8000, &[]);
    let mut packet = query(&cname_rdata("alias.start.test."), 1, 1);
    append_opt(&mut packet, 4096, 0x8000, &[]);
    for store in [&compact, &dirty] {
        let proofs = response_authority_owners(&store_response(&intermediate, store), 50);
        assert!(!proofs.is_empty());
        store.insert_snapshot(ZoneSnapshot::active(DomainName::from_absolute_str("start.test.").unwrap(), Some(1), vec![
            overlay_rrset("start.test.", 6, soa_rdata()),
            overlay_rrset("alias.start.test.", 5, cname_rdata("missing.a.example.test.")),
        ]));
        cross_zone_target(store, "target.other.test.", 1, vec![192, 0, 2, 77]);
        let response = store_response(&packet, store);
        assert_eq!(response_authority_owners(&response, 50), proofs, "intermediate wildcard proof was lost");
        assert_eq!(response_answer_rdatas(&response, 1), vec![vec![192, 0, 2, 77]]);
        assert_eq!(response_answer_types(&response).iter().filter(|&&kind| kind == 5).count(), 2);
    }
}

fn cross_zone_dname_fixture() -> (ZoneStore, ZoneStore) {
    dirty_and_compact_stores(vec![
        overlay_rrset("d.example.test.", 39, cname_rdata("other.test.")),
        overlay_rrset("alias.example.test.", 5, cname_rdata("target.d.example.test.")),
    ])
}

#[test]
fn cross_zone_dname_direct_continues_to_served_target() {
    let (dirty, compact) = cross_zone_dname_fixture();
    let packet = query(&cname_rdata("target.d.example.test."), 1, 1);
    for store in [&compact, &dirty] {
        cross_zone_target(store, "target.other.test.", 1, vec![192, 0, 2, 77]);
        let response = store_response_with_options(&packet, store, AnswerOptions { max_cname_chain: 1, ..AnswerOptions::default() });
        assert_eq!(response[3] & 15, 0);
        assert_eq!(response_answer_rdatas(&response, 1), vec![vec![192, 0, 2, 77]]);
        assert_eq!(response_answer_types(&response), vec![39, 5, 1]);
    }
    assert_semantic_response_eq(&store_response(&packet, &dirty), &store_response(&packet, &compact));
}

#[test]
fn cross_zone_dname_after_cname_continues_with_remaining_budget() {
    let (dirty, compact) = cross_zone_dname_fixture();
    let packet = query(&cname_rdata("alias.example.test."), 1, 1);
    for store in [&compact, &dirty] {
        cross_zone_target(store, "target.other.test.", 1, vec![192, 0, 2, 77]);
        let response = store_response_with_options(&packet, store, AnswerOptions { max_cname_chain: 2, ..AnswerOptions::default() });
        assert_eq!(response[3] & 15, 0);
        assert_eq!(response_answer_rdatas(&response, 1), vec![vec![192, 0, 2, 77]]);
        assert_eq!(response_answer_types(&response), vec![5, 39, 5, 1]);
        let response = store_response_with_options(&packet, store, AnswerOptions { max_cname_chain: 1, ..AnswerOptions::default() });
        assert_eq!(response[3] & 15, Rcode::ServFail as u8);
        assert!(response_answer_rdatas(&response, 1).is_empty());
    }
}

#[test]
fn cross_zone_dname_external_partial_chain_and_target_alias_budget() {
    let (dirty, compact) = cross_zone_dname_fixture();
    for (name, limit, expected_types) in [
        ("target.d.example.test.", 1, vec![39, 5]),
        ("alias.example.test.", 2, vec![5, 39, 5]),
    ] {
        let packet = query(&cname_rdata(name), 1, 1);
        let options = AnswerOptions { max_cname_chain: limit, ..AnswerOptions::default() };
        for store in [&compact, &dirty] {
            let partial = store_response_with_options(&packet, store, options);
            assert_eq!(partial[3] & 15, 0);
            assert_eq!(response_answer_types(&partial), expected_types);
        }
    }
    for store in [&compact, &dirty] {
        cross_zone_target(store, "target.other.test.", 5, cname_rdata("next.other.test."));
        for (name, limit) in [("target.d.example.test.", 1), ("alias.example.test.", 2)] {
            let packet = query(&cname_rdata(name), 1, 1);
            let response = store_response_with_options(&packet, store, AnswerOptions { max_cname_chain: limit, ..AnswerOptions::default() });
            assert_eq!(response[3] & 15, Rcode::ServFail as u8, "DNAME must consume one shared alias step");
        }
    }
}

#[test]
fn cross_zone_dname_does_not_spend_an_exhausted_budget_in_target_zone() {
    let (dirty, compact) = dirty_and_compact_stores(vec![
        overlay_rrset("alias.example.test.", 5, cname_rdata("target.d.other.test.")),
    ]);
    let packet = query(&cname_rdata("alias.example.test."), 1, 1);
    for store in [&compact, &dirty] {
        cross_zone_target(store, "d.other.test.", 39, cname_rdata("outside.test."));
        let response = store_response_with_options(&packet, store, AnswerOptions { max_cname_chain: 1, ..AnswerOptions::default() });
        assert_eq!(response[3] & 15, Rcode::ServFail as u8, "zero remaining steps cannot synthesize another DNAME alias");
        assert_eq!(response_answer_types(&response), vec![5]);
        let response = store_response_with_options(&packet, store, AnswerOptions { max_cname_chain: 2, ..AnswerOptions::default() });
        assert_eq!(response[3] & 15, 0);
        assert_eq!(response_answer_types(&response), vec![5, 39, 5]);
    }
}

#[test]
fn cross_zone_wildcard_cname_does_not_spend_an_exhausted_budget_in_target_zone() {
    let (dirty, compact) = dirty_and_compact_stores(vec![
        overlay_rrset("alias.example.test.", 5, cname_rdata("missing.other.test.")),
    ]);
    let packet = query(&cname_rdata("alias.example.test."), 1, 1);
    for store in [&compact, &dirty] {
        store.insert_snapshot(ZoneSnapshot::active(DomainName::from_absolute_str("other.test.").unwrap(), Some(1), vec![
            overlay_rrset("other.test.", 6, soa_rdata()),
            overlay_rrset("*.other.test.", 5, cname_rdata("target.other.test.")),
            overlay_rrset("target.other.test.", 1, vec![192, 0, 2, 77]),
        ]));
        let response = store_response_with_options(&packet, store, AnswerOptions { max_cname_chain: 1, ..AnswerOptions::default() });
        assert_eq!(response[3] & 15, Rcode::ServFail as u8, "zero remaining steps cannot expand another wildcard alias");
        assert_eq!(response_answer_types(&response), vec![5]);
        let response = store_response_with_options(&packet, store, AnswerOptions { max_cname_chain: 2, ..AnswerOptions::default() });
        assert_eq!(response[3] & 15, 0);
        assert_eq!(response_answer_types(&response), vec![5, 5, 1]);
        assert_eq!(response_answer_rdatas(&response, 1), vec![vec![192, 0, 2, 77]]);
    }
}
