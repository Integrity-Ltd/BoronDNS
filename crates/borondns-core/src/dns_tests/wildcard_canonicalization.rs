// Selection fixtures only: the RRSIG bytes below are intentionally synthetic.
// They test proof/answer provenance, not cryptographic DNSSEC validation.
fn mixed_case_wildcard_store() -> ZoneStore {
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let wildcard = DomainName::from_absolute_str("*.example.test.").unwrap();
    let mut rrsets = vec![
        Rrset::new(origin.clone(), 6, 1, 3600, vec![soa_rdata()]),
        Rrset::new(origin.clone(), 51, 1, 300, vec![nsec3param_rdata(1)]),
        Rrset::new(wildcard.clone(), 1, 1, 300, vec![vec![192, 0, 2, 20]]),
        Rrset::new(wildcard, 46, 1, 300, vec![rrsig_rdata(RecordType::A)]),
    ];
    let mut names = vec!["example.test.".to_owned(), "*.example.test.".to_owned()];
    // A reasonably populated ring separates the correct canonical hash from
    // the incorrect mixed-case hash. Pin the independently expected cover below.
    for index in 0..32 {
        let name = format!("anchor-{index}.example.test.");
        rrsets.push(Rrset::new(
            DomainName::from_absolute_str(&name).unwrap(),
            16,
            1,
            300,
            vec![b"\x01x".to_vec()],
        ));
        names.push(name);
    }
    for (alias, target) in [
        ("alias-lower.example.test.", "deep.missing.example.test."),
        ("alias-mixed.example.test.", "deep.MiSsInG.ExAmPlE.TeSt."),
    ] {
        rrsets.push(Rrset::new(
            DomainName::from_absolute_str(alias).unwrap(),
            5,
            1,
            300,
            vec![cname_rdata(target)],
        ));
        names.push(alias.to_owned());
    }
    rrsets.extend(nsec3_ring_rrsets(&names, "example.test."));
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(origin, Some(1), rrsets));
    store
}

fn assert_mixed_case_wildcard_response(
    store: &ZoneStore,
    qname: &str,
    expanded: &str,
    dnssec: bool,
) -> Vec<u8> {
    let mut packet = query(&cname_rdata(qname), 1, 1);
    append_opt(&mut packet, 4096, if dnssec { 0x8000 } else { 0 }, &[]);
    let response = store_response(&packet, store);
    let parsed = semantic_response(&response).unwrap();
    assert_eq!(
        parsed.flags & 0x860f,
        0x8400,
        "NOERROR, AA, not truncated: {qname}"
    );
    let answers = &parsed.sections[0];
    let a = answers
        .iter()
        .find(|record| record.rr_type == 1)
        .expect("wildcard A answer");
    assert_eq!(a.owner, cname_rdata(expanded).to_ascii_lowercase());
    assert_eq!(
        (a.class, a.ttl, a.rdata.as_slice()),
        (1, 300, [192, 0, 2, 20].as_slice())
    );
    if dnssec {
        let signature = answers
            .iter()
            .find(|record| record.rr_type == 46)
            .expect("wildcard signature");
        assert_eq!(signature.owner, a.owner);
        assert_eq!(signature.rdata, rrsig_rdata(RecordType::A));
        let proofs = parsed.sections[1]
            .iter()
            .filter(|record| record.rr_type == 50)
            .collect::<Vec<_>>();
        assert_eq!(proofs.len(), 1);
        assert_eq!(
            proofs[0].owner,
            cname_rdata("qiph87k0827s46kntjrata8caehd7k15.example.test.")
        );
        assert_eq!((proofs[0].class, proofs[0].ttl), (1, 300));
        assert!(parsed.sections[1].iter().any(|record| record.rr_type == 46
            && record.owner == proofs[0].owner
            && record.rdata == rrsig_rdata(RecordType::Nsec3)));
    } else {
        assert!(!answers.iter().any(|record| record.rr_type == 46));
        assert!(parsed.sections[1].is_empty());
    }
    // The question's presentation spelling must survive canonical proof hashing.
    assert_eq!(
        DomainName::parse(&response, DNS_HEADER_LEN)
            .unwrap()
            .0
            .to_wire(),
        cname_rdata(qname)
    );
    response
}

#[test]
fn compact_nsec3_wildcard_proofs_are_case_independent() {
    let store = mixed_case_wildcard_store();
    for dnssec in [false, true] {
        let lower = assert_mixed_case_wildcard_response(
            &store,
            "deep.missing.example.test.",
            "deep.missing.example.test.",
            dnssec,
        );
        for qname in ["deep.MiSsInG.ExAmPlE.TeSt.", "DEEP.MISSING.EXAMPLE.TEST."] {
            let mixed = assert_mixed_case_wildcard_response(&store, qname, qname, dnssec);
            assert_semantic_response_eq(&lower, &mixed);
        }
    }
}

#[test]
fn compact_nsec3_wildcard_alias_target_case_is_independent_of_question_hint() {
    let store = mixed_case_wildcard_store();
    for dnssec in [false, true] {
        for (qname, target) in [
            ("alias-lower.example.test.", "deep.missing.example.test."),
            ("ALIAS-LOWER.EXAMPLE.TEST.", "deep.missing.example.test."),
            ("alias-mixed.example.test.", "deep.MiSsInG.ExAmPlE.TeSt."),
            ("ALIAS-MIXED.EXAMPLE.TEST.", "deep.MiSsInG.ExAmPlE.TeSt."),
        ] {
            let response = assert_mixed_case_wildcard_response(&store, qname, target, dnssec);
            let parsed = semantic_response(&response).unwrap();
            let alias = parsed.sections[0]
                .iter()
                .find(|record| record.rr_type == 5)
                .unwrap();
            assert_eq!(alias.rdata, cname_rdata(target).to_ascii_lowercase());
            assert_eq!(
                response_answer_types(&response)
                    .iter()
                    .filter(|&&kind| kind == 5)
                    .count(),
                1
            );
        }
    }
}
