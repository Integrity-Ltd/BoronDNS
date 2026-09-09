// Independent expected answers, not just agreement between the two layouts.
fn dname_terminal_response(
    packet: &[u8],
    store: &ZoneStore,
    options: AnswerOptions<'_>,
    dirty: bool,
) -> Vec<u8> {
    let saw_expected_path = Cell::new(false);
    let action = answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        packet, store, options, |_, _| true, |_, _, _| true,
        |metrics| {
            if metrics.zone_image_failure_reason.is_none() && metrics.zone_image_used != dirty {
                saw_expected_path.set(true);
            }
        }, &default_zone_image_provider,
    );
    assert!(saw_expected_path.get(), "wrong lookup path (dirty={dirty})");
    match action {
        DatagramAction::Respond(wire) => wire,
        DatagramAction::Discard => panic!("expected response"),
    }
}

fn terminal_dname_records() -> Vec<Rrset> {
    vec![
        overlay_rrset("d.example.test.", 39, cname_rdata("target.example.test.")),
        overlay_rrset("out.example.test.", 39, cname_rdata("other.test.")),
        overlay_rrset("www.target.example.test.", 1, vec![192, 0, 2, 80]),
        overlay_rrset("cn.target.example.test.", 5, cname_rdata("final.example.test.")),
        overlay_rrset("final.example.test.", 1, vec![192, 0, 2, 81]),
        overlay_rrset("loop.example.test.", 39, cname_rdata("sub.loop.example.test.")),
    ]
}

fn assert_terminal_dname(wire: &[u8], name: &str, target: &str) {
    let p = semantic_response(wire).unwrap();
    assert_eq!(p.flags & 0x860f, 0x8400, "must be positive and authoritative for {name}");
    let data = p.sections[0].iter().filter(|r| r.rr_type != 46).collect::<Vec<_>>();
    assert_eq!(data.len(), 2, "DNAME and synthesized CNAME only for {name}");
    assert!(data.iter().any(|r| r.rr_type == 39));
    assert!(data.iter().any(|r| r.rr_type == 5 && r.owner == cname_rdata(name)
        && r.rdata == cname_rdata(target) && r.ttl == 300 && r.class == 1));
    assert!(p.sections[1].is_empty(), "positive synthesized CNAME must not acquire denial records for {name}");
    assert!(!p.sections[0].iter().any(|r| r.rr_type == 46 && r.rdata.starts_with(&5u16.to_be_bytes())),
        "synthesized CNAME is not independently signed");
}

#[test]
fn dname_terminal_cname_and_any_do_not_chase_synthesized_target() {
    let (dirty, compact) = dirty_and_compact_stores(terminal_dname_records());
    for hosted in [false, true] {
        if hosted {
            for store in [&dirty, &compact] {
                cross_zone_target(store, "www.other.test.", 1, vec![192, 0, 2, 82]);
            }
        }
        for (name, target) in [
            ("www.d.example.test.", "www.target.example.test."),
            ("cn.d.example.test.", "cn.target.example.test."),
            ("absent.d.example.test.", "absent.target.example.test."),
            ("www.out.example.test.", "www.other.test."),
            ("www.loop.example.test.", "www.sub.loop.example.test."),
        ] {
            for kind in [5, 255] {
                for mode in [AnyResponseMode::Minimal, AnyResponseMode::Full] {
                    let options = AnswerOptions { any_response: mode, ..AnswerOptions::default() };
                    let packet = query(&cname_rdata(name), kind, 1);
                    for (store, is_dirty) in [(&compact, false), (&dirty, true)] {
                        assert_terminal_dname(&dname_terminal_response(&packet, store, options, is_dirty), name, target);
                    }
                }
            }
        }
    }
}

#[test]
fn dname_terminal_dnssec_keeps_dname_signature_without_terminal_denial() {
    let mut records = terminal_dname_records();
    records.extend([
        overlay_rrset("example.test.", 51, nsec3param_rdata(1)),
        overlay_rrset("example.test.", 46, rrsig_rdata(RecordType::Soa)),
        overlay_rrset("d.example.test.", 46, rrsig_rdata(RecordType::Dname)),
    ]);
    records.extend(nsec3_ring_rrsets(&["example.test.", "d.example.test.", "target.example.test.", "www.target.example.test."], "example.test."));
    let (dirty, compact) = dirty_and_compact_stores(records);
    for (name, target) in [("www.d.example.test.", "www.target.example.test."), ("absent.d.example.test.", "absent.target.example.test.")] {
        for kind in [5, 255] {
            let mut packet = query(&cname_rdata(name), kind, 1);
            append_opt(&mut packet, 4096, 0x8000, &[]);
            for (store, is_dirty) in [(&compact, false), (&dirty, true)] {
                let wire = dname_terminal_response(&packet, store, AnswerOptions::default(), is_dirty);
                assert_terminal_dname(&wire, name, target);
                let p = semantic_response(&wire).unwrap();
                assert!(p.sections[0].iter().any(|r| r.rr_type == 46 && r.owner == cname_rdata("d.example.test.")
                    && r.rdata.starts_with(&39u16.to_be_bytes())), "available DNAME signature must survive");
            }
        }
    }
}

#[test]
fn dname_terminal_outer_dname_occludes_delegation_for_every_qtype() {
    let (dirty, compact) = dirty_and_compact_stores(vec![
        overlay_rrset("d.example.test.", 39, cname_rdata("elsewhere.invalid.")),
        overlay_rrset("cut.d.example.test.", 2, cname_rdata("ns.invalid.")),
        overlay_rrset("cut.d.example.test.", 43, vec![0, 1, 8, 2, 0, 0]),
        overlay_rrset("entry.example.test.", 5, cname_rdata("x.cut.d.example.test.")),
        overlay_rrset("first.example.test.", 39, cname_rdata("cut.d.example.test.")),
    ]);
    for name in ["x.cut.d.example.test.", "cut.d.example.test.", "entry.example.test.", "x.first.example.test."] {
        for kind in [1, 2, 5, 39, 43, 255] {
            let packet = query(&cname_rdata(name), kind, 1);
            for (store, is_dirty) in [(&compact, false), (&dirty, true)] {
                let wire = dname_terminal_response(&packet, store, AnswerOptions::default(), is_dirty);
                let p = semantic_response(&wire).unwrap();
                assert_eq!(p.flags & 0x860f, 0x8400, "{name} type={kind}");
                assert!(p.sections[1].is_empty(), "hidden delegation exposed for {name} type={kind}");
                assert!(!p.sections[0].iter().any(|r| r.rr_type == 2 || r.rr_type == 43));
                // CNAME/ANY terminate before reaching another alias target.
                let terminal = (kind == 5 || kind == 255) && (name == "entry.example.test." || name == "x.first.example.test.");
                if !terminal {
                    assert!(p.sections[0].iter().any(|r| r.rr_type == 39 && r.owner == cname_rdata("d.example.test.")));
                }
            }
        }
    }
}

#[test]
fn dname_terminal_does_not_override_an_earlier_delegation() {
    let (dirty, compact) = dirty_and_compact_stores(vec![
        overlay_rrset("cut.example.test.", 2, cname_rdata("ns.invalid.")),
        overlay_rrset("d.cut.example.test.", 39, cname_rdata("elsewhere.invalid.")),
    ]);
    for kind in [1, 2, 5, 39, 43, 255] {
        let packet = query(&cname_rdata("x.d.cut.example.test."), kind, 1);
        for (store, is_dirty) in [(&compact, false), (&dirty, true)] {
            let wire = dname_terminal_response(&packet, store, AnswerOptions::default(), is_dirty);
            let p = semantic_response(&wire).unwrap();
            assert_eq!(p.flags & 0x860f, 0x8000);
            assert!(p.sections[0].is_empty());
            assert_eq!(p.sections[1].len(), 1);
            assert_eq!(p.sections[1][0].rr_type, 2);
            assert_eq!(p.sections[1][0].owner, cname_rdata("cut.example.test."));
        }
    }
}

#[test]
fn dname_terminal_preserves_chain_budget_for_queries_that_chase() {
    let (dirty, compact) = dirty_and_compact_stores(terminal_dname_records());
    for (store, is_dirty) in [(&compact, false), (&dirty, true)] {
        let packet = query(&cname_rdata("www.loop.example.test."), 1, 1);
        let options = AnswerOptions { max_cname_chain: 4, ..AnswerOptions::default() };
        let p = semantic_response(&dname_terminal_response(&packet, store, options, is_dirty)).unwrap();
        assert_eq!(p.flags & 0x860f, 0x8402);
        assert!(p.sections[1].is_empty());
        assert_eq!(p.sections[0].iter().filter(|r| r.rr_type == 5).count(), 4);
        for kind in [1, 5, 255] {
            let packet = query(&cname_rdata("www.d.example.test."), kind, 1);
            let options = AnswerOptions { max_cname_chain: 0, ..AnswerOptions::default() };
            let p = semantic_response(&dname_terminal_response(&packet, store, options, is_dirty)).unwrap();
            assert_eq!(p.flags & 0x860f, 0x8402, "zero budget must still prevent synthesis");
            assert!(p.sections[0].is_empty());
        }
    }
}
