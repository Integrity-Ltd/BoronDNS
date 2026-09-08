// Structural proof-selection regressions. Synthetic RRSIGs check selection,
// not cryptographic validity; live signer/validator coverage is separate.
fn denial_fixture(exact_child: bool, optout: bool) -> Vec<Rrset> {
    let mut records = vec![
        overlay_rrset("example.test.", 51, nsec3param_rdata(1)),
        overlay_rrset("example.test.", 46, rrsig_rdata(RecordType::Soa)),
        overlay_rrset("child.example.test.", 2, cname_rdata("ns.example.test.")),
        overlay_rrset("present.example.test.", 1, vec![192, 0, 2, 10]),
    ];
    let mut names = vec!["example.test.", "present.example.test."];
    if exact_child {
        names.push("child.example.test.");
    }
    let ring = if optout {
        nsec3_optout_ring_rrsets(&names, "example.test.", "child.example.test.")
    } else {
        nsec3_ring_rrsets(&names, "example.test.")
    };
    records.extend(ring);
    // An exact insecure delegation has NS, but neither SOA nor DS.
    let child_hash = nsec3_owner("child.example.test.", "example.test.");
    for rrset in &mut records {
        if rrset.rr_type == 50 && rrset.owner == child_hash {
            let mut data = rrset.rdatas()[0].clone();
            data.truncate(26);
            data.extend_from_slice(&[0, 1, 0x20]);
            *rrset = Rrset::new(rrset.owner.clone(), 50, 1, 300, vec![data]);
        }
    }
    records
}

fn denial_packet(name: &str, kind: u16, dnssec: bool) -> Vec<u8> {
    let mut packet = query(&cname_rdata(name), kind, 1);
    append_opt(&mut packet, 4096, if dnssec { 0x8000 } else { 0 }, &[]);
    packet
}

fn assert_denial_servfail(response: &[u8]) {
    assert_eq!(response[3] & 15, Rcode::ServFail as u8);
    assert_eq!(
        response[2] & 2,
        0,
        "proof unavailable before encoding, not UDP truncation"
    );
}

#[test]
fn denial_completeness_rejects_ordinary_nodata_without_exact_nsec3() {
    let mut records = denial_fixture(false, false);
    records.push(overlay_rrset(
        "omitted.example.test.",
        1,
        vec![192, 0, 2, 11],
    ));
    // The ring itself is complete; only this required owner is absent.
    let (overlay, compact) = dirty_and_compact_stores(records);
    let packet = denial_packet("omitted.example.test.", 28, true);
    assert_denial_servfail(&store_response(&packet, &compact));
    assert_denial_servfail(&observed_overlay_response(&packet, &overlay));
    assert_eq!(
        store_response(&denial_packet("omitted.example.test.", 28, false), &overlay)[3] & 15,
        0
    );
}

#[test]
fn denial_completeness_rejects_non_optout_cover_for_omitted_delegation() {
    let (overlay, compact) = dirty_and_compact_stores(denial_fixture(false, false));
    for (name, kind) in [("child.example.test.", 43), ("host.child.example.test.", 1)] {
        let packet = denial_packet(name, kind, true);
        assert_denial_servfail(&store_response(&packet, &compact));
        assert_denial_servfail(&observed_overlay_response(&packet, &overlay));
        assert_eq!(
            store_response(&denial_packet(name, kind, false), &overlay)[3] & 15,
            0
        );
    }
}

#[test]
fn denial_completeness_rejects_referral_nsec3_bitmap_claiming_ds() {
    let mut records = denial_fixture(true, false);
    let child_hash = nsec3_owner("child.example.test.", "example.test.");
    for rrset in &mut records {
        if rrset.rr_type == 50 && rrset.owner == child_hash {
            let mut data = rrset.rdatas()[0].clone();
            data.truncate(26);
            data.extend_from_slice(&[0, 6, 0x20, 0, 0, 0, 0, 0x10]);
            *rrset = Rrset::new(rrset.owner.clone(), 50, 1, 300, vec![data]);
        }
    }
    let (overlay, compact) = dirty_and_compact_stores(records);
    let packet = denial_packet("host.child.example.test.", 1, true);
    assert_denial_servfail(&store_response(&packet, &compact));
    assert_denial_servfail(&observed_overlay_response(&packet, &overlay));
}

#[test]
fn denial_completeness_rejects_wildcard_nodata_without_exact_wildcard_proof() {
    let mut records = denial_fixture(false, false);
    records.push(overlay_rrset("*.example.test.", 1, vec![192, 0, 2, 22]));
    records.push(overlay_rrset(
        "*.example.test.",
        46,
        rrsig_rdata(RecordType::A),
    ));
    let (overlay, compact) = dirty_and_compact_stores(records);
    let packet = denial_packet("missing.example.test.", 28, true);
    assert_denial_servfail(&store_response(&packet, &compact));
    assert_denial_servfail(&observed_overlay_response(&packet, &overlay));
}

#[test]
fn denial_completeness_rejects_nxdomain_without_provable_encloser() {
    let mut records = denial_fixture(false, false);
    records
        .retain(|rr| rr.rr_type != 50 && !(rr.rr_type == 46 && rr.owner.labels()[0].len() == 32));
    // Structurally complete hash ring but no apex or other ancestor match.
    records.extend(nsec3_ring_rrsets(
        &["present.example.test."],
        "example.test.",
    ));
    let (overlay, compact) = dirty_and_compact_stores(records);
    let packet = denial_packet("missing.example.test.", 1, true);
    assert_denial_servfail(&store_response(&packet, &compact));
    assert_denial_servfail(&observed_overlay_response(&packet, &overlay));
}

#[test]
fn denial_completeness_preserves_exact_and_optout_insecure_delegations() {
    for (exact, optout) in [(true, false), (false, true)] {
        let (overlay, compact) = dirty_and_compact_stores(denial_fixture(exact, optout));
        for (name, kind) in [("child.example.test.", 43), ("host.child.example.test.", 1)] {
            let packet = denial_packet(name, kind, true);
            let response = observed_overlay_response(&packet, &overlay);
            assert_eq!(response[3] & 15, 0);
            let proof_owners = response_authority_owners(&response, 50);
            assert!(!proof_owners.is_empty());
            if exact {
                assert_eq!(
                    proof_owners,
                    vec![nsec3_owner("child.example.test.", "example.test.")]
                );
            }
            let signatures = response_authority_owners(&response, 46);
            assert!(proof_owners.iter().all(|owner| signatures.contains(owner)));
            assert_semantic_response_eq(&response, &store_response(&packet, &compact));
        }
    }
}

#[test]
fn denial_completeness_preserves_unsigned_and_positive_answers() {
    let unsigned = vec![overlay_rrset(
        "present.example.test.",
        1,
        vec![192, 0, 2, 10],
    )];
    let (overlay, compact) = dirty_and_compact_stores(unsigned);
    for (name, kind, rcode) in [
        ("present.example.test.", 1, 0),
        ("present.example.test.", 28, 0),
        ("missing.example.test.", 1, 3),
    ] {
        let packet = denial_packet(name, kind, true);
        let response = observed_overlay_response(&packet, &overlay);
        assert_eq!(response[3] & 15, rcode);
        assert_semantic_response_eq(&response, &store_response(&packet, &compact));
    }
    // A malformed/missing denial proof does not affect an ordinary positive.
    let (overlay, _) = dirty_and_compact_stores(denial_fixture(false, false));
    let packet = denial_packet("present.example.test.", 1, true);
    let response = observed_overlay_response(&packet, &overlay);
    assert_eq!(response[3] & 15, 0);
    assert_eq!(
        response_answer_rdatas(&response, 1),
        vec![vec![192, 0, 2, 10]]
    );
}

#[test]
fn denial_completeness_preserves_udp_truncation_of_available_proof() {
    let mut records = denial_fixture(true, false);
    let child_hash = nsec3_owner("child.example.test.", "example.test.");
    for rrset in &mut records {
        if rrset.rr_type == 46 && rrset.owner == child_hash {
            let mut data = rrsig_rdata(RecordType::Nsec3);
            data.extend_from_slice(&[0x5a; 800]);
            *rrset = Rrset::new(rrset.owner.clone(), 46, 1, 300, vec![data]);
        }
    }
    let (overlay, compact) = dirty_and_compact_stores(records);
    let mut packet = query(&cname_rdata("child.example.test."), 43, 1);
    append_opt(&mut packet, 512, 0x8000, &[]);
    for response in [
        observed_overlay_response(&packet, &overlay),
        store_response(&packet, &compact),
    ] {
        assert_eq!(response[3] & 15, 0);
        assert_ne!(response[2] & 2, 0);
        assert!(response.len() <= 512);
    }
}

#[test]
fn denial_completeness_preserves_nsec_and_unsigned_referral_glue() {
    let records = vec![
        overlay_rrset("example.test.", 47, nsec_rdata("present.example.test.")),
        overlay_rrset("example.test.", 46, rrsig_rdata(RecordType::Nsec)),
        overlay_rrset("present.example.test.", 1, vec![192, 0, 2, 10]),
        overlay_rrset("present.example.test.", 47, nsec_rdata("example.test.")),
        overlay_rrset("present.example.test.", 46, rrsig_rdata(RecordType::Nsec)),
    ];
    let (overlay, compact) = dirty_and_compact_stores(records);
    for (name, kind, rcode) in [
        ("present.example.test.", 28, 0),
        ("missing.example.test.", 1, 3),
    ] {
        let packet = denial_packet(name, kind, true);
        let response = observed_overlay_response(&packet, &overlay);
        assert_eq!(response[3] & 15, rcode);
        assert!(!response_authority_owners(&response, 47).is_empty());
        assert_semantic_response_eq(&response, &store_response(&packet, &compact));
    }
    let (overlay, compact) = dirty_and_compact_stores(vec![
        overlay_rrset(
            "child.example.test.",
            2,
            cname_rdata("ns.child.example.test."),
        ),
        overlay_rrset("ns.child.example.test.", 1, vec![192, 0, 2, 53]),
    ]);
    let packet = denial_packet("host.child.example.test.", 1, true);
    let response = observed_overlay_response(&packet, &overlay);
    assert_eq!(response[3] & 15, 0);
    let parsed = semantic_response(&response).unwrap();
    assert!(
        parsed.sections[2]
            .iter()
            .any(|rr| rr.rr_type == 1 && rr.rdata == vec![192, 0, 2, 53])
    );
    assert_semantic_response_eq(&response, &store_response(&packet, &compact));
}
