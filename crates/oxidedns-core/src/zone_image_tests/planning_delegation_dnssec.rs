    #[test]
    fn plan_wire_upper_bound_matches_uncompressed_plan_wire() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        for (qname, rr_type) in [
            ("host.wild.example.test.", RecordType::A as u16),
            ("www.subtree.example.test.", RecordType::A as u16),
            ("missing.example.test.", RecordType::A as u16),
        ] {
            let qname = DomainName::from_absolute_str(qname).unwrap();
            let plan = image.lookup_response_plan(
                &qname,
                rr_type,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Minimal,
            );
            let mut wire = Vec::new();
            image.append_plan_wire(&plan, &mut wire);
            let (answer_count, authority_count, additional_count) = plan.section_record_counts();
            let (
                accounted_answer_count,
                accounted_authority_count,
                accounted_additional_count,
                accounted_wire_upper_bound,
            ) = image.plan_accounting_direct(&plan);
            let response_shape = plan
                .response_shape()
                .expect("test plan section counts fit DNS header fields");

            assert_eq!(
                image.plan_wire_upper_bound(&plan),
                wire.len(),
                "wire upper bound mismatch for {qname}"
            );
            assert_eq!(
                plan.response_body_wire_upper_bound(),
                image.plan_wire_upper_bound(&plan),
                "carried response wire bound mismatch for {qname}"
            );
            assert_eq!(
                accounted_wire_upper_bound,
                wire.len(),
                "combined wire upper bound mismatch for {qname}"
            );
            assert_eq!(
                (
                    accounted_answer_count,
                    accounted_authority_count,
                    accounted_additional_count
                ),
                (answer_count, authority_count, additional_count),
                "combined section counts mismatch for {qname}"
            );
            assert_eq!(
                plan.total_record_count(),
                answer_count
                    .saturating_add(authority_count)
                    .saturating_add(additional_count),
                "derived total record count mismatch for {qname}"
            );
            assert_eq!(
                (
                    response_shape.response_flag_bits,
                    usize::from(response_shape.answer_count),
                    usize::from(response_shape.authority_count),
                    usize::from(response_shape.additional_count),
                    response_shape.body_wire_upper_bound,
                ),
                (
                    plan.rcode().response_flag_bits(plan.authoritative()),
                    answer_count,
                    authority_count,
                    additional_count,
                    image.plan_wire_upper_bound(&plan),
                ),
                "response shape accounting mismatch for {qname}"
            );
            assert_eq!(
                response_shape.section_count_header_bytes,
                test_section_count_header_bytes(
                    response_shape.answer_count,
                    response_shape.authority_count,
                    response_shape.additional_count,
                ),
                "response shape count bytes mismatch for {qname}"
            );
            assert_eq!(
                response_shape.section_count_header_bytes_with_extra_additional(1),
                response_shape
                    .additional_count
                    .checked_add(1)
                    .map(|additional_count| {
                        test_section_count_header_bytes(
                            response_shape.answer_count,
                            response_shape.authority_count,
                            additional_count,
                        )
                    }),
                "response shape EDNS count bytes mismatch for {qname}"
            );
        }
    }

    fn test_section_count_header_bytes(
        answer_count: u16,
        authority_count: u16,
        additional_count: u16,
    ) -> [u8; 6] {
        let answer_count = answer_count.to_be_bytes();
        let authority_count = authority_count.to_be_bytes();
        let additional_count = additional_count.to_be_bytes();
        [
            answer_count[0],
            answer_count[1],
            authority_count[0],
            authority_count[1],
            additional_count[0],
            additional_count[1],
        ]
    }

    #[test]
    fn direct_answer_plan_preserves_delegation_dname_and_additional_semantics() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let direct = DomainName::from_absolute_str("www.example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let delegated_glue = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let under_dname = DomainName::from_absolute_str("www.subtree.example.test.").unwrap();
        let delegated_child = DomainName::from_absolute_str("child.example.test.").unwrap();

        let direct_plan = image
            .lookup_direct_answer_plan(&direct, RecordType::A as u16, 1)
            .expect("direct A plan is present");
        assert!(direct_plan.direct_answer_candidate());
        let semantic_direct_plan = image.lookup_response_plan(
            &direct,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(semantic_direct_plan.direct_answer_candidate());
        let direct_a = direct_plan.answer_rrsets()[0];
        let direct_rrset = image
            .direct_rrset_wire(direct_a)
            .expect("direct A RRset wire exists");
        assert_eq!(
            direct_rrset.section_count_header_bytes(false),
            test_section_count_header_bytes(direct_rrset.record_count(), 0, 0),
            "direct RRset should carry no-EDNS section-count bytes"
        );
        assert_eq!(
            direct_rrset.section_count_header_bytes(true),
            test_section_count_header_bytes(direct_rrset.record_count(), 0, 1),
            "direct RRset should carry EDNS-adjusted section-count bytes"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&delegated_glue, RecordType::A as u16, 1)
                .is_none(),
            "direct shortcut must not serve glue below a delegation as authoritative data"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&under_dname, RecordType::A as u16, 1)
                .is_none(),
            "direct shortcut must not bypass ancestor DNAME synthesis"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&delegated_child, RecordType::Ns as u16, 1)
                .is_none(),
            "direct shortcut must not bypass referral handling at the cut"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&direct, RecordType::Srv as u16, 1)
                .is_none(),
            "direct shortcut must not skip additional-address processing"
        );
        let cname = image
            .find_rrset(&alias, RecordType::Cname as u16, 1)
            .expect("CNAME RRset exists");
        assert!(
            image.direct_rrset_wire(cname).is_none(),
            "eligible-only direct RRset view must reject compressible RDATA types"
        );
    }

    #[test]
    fn direct_answer_preflight_uses_compiled_low_rrtype_bitmap() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("www.example.test.").unwrap();
        let private_type = 65_280u16;
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(53),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    owner.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
                Rrset::new(owner.clone(), private_type, 1, 300, vec![vec![1, 2, 3, 4]]),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        assert!(image.low_rrtype_may_exist(RecordType::A as u16));
        assert!(
            !image.low_rrtype_may_exist(RecordType::Txt as u16),
            "low RR type absent from the compiled image should skip direct preflight"
        );
        assert!(
            image.low_rrtype_may_exist(private_type),
            "private/high RR types keep the conservative direct-preflight path"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&owner, RecordType::Txt as u16, 1)
                .is_none(),
            "direct preflight must reject RR types known absent from the image"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&owner, private_type, 1)
                .is_some(),
            "high RR types are not ruled out by the low-type bitmap"
        );
    }

    #[test]
    fn node_local_low_rrtype_bitmap_skips_absent_present_types() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("www.example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let target = DomainName::from_absolute_str("target.example.test.").unwrap();
        let private_type = 65_280u16;
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(55),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    owner.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 55]],
                ),
                Rrset::new(
                    owner.clone(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![0; 16]],
                ),
                Rrset::new(
                    alias.clone(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![target.to_wire()],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        assert!(
            image.low_rrtype_may_exist(RecordType::Cname as u16),
            "the image-wide bitmap remains conservative when CNAME exists elsewhere"
        );
        assert_eq!(
            image.node_low_rrtype_may_exist(&owner, RecordType::Cname as u16),
            Some(false),
            "the owner-local bitmap should reject an absent low RR type before scanning RRsets"
        );
        assert_eq!(
            image.node_low_rrtype_may_exist(&alias, RecordType::Cname as u16),
            Some(true)
        );
        assert_eq!(
            image.node_low_rrtype_may_exist(&owner, private_type),
            Some(true),
            "high/private RR types keep the conservative per-node lookup path"
        );
        assert!(
            image
                .lookup_direct_answer_plan(&owner, RecordType::Cname as u16, 1)
                .is_none()
        );
        assert!(
            image
                .lookup_direct_answer_plan(&alias, RecordType::Cname as u16, 1)
                .is_some()
        );
        assert_eq!(
            image.lookup_exact_plan(&owner, RecordType::Cname as u16, 255),
            ZoneImageLookupOutcome::NoData,
            "QCLASS=ANY exact lookup should use the same owner-local absent-type gate"
        );
    }

    #[test]
    fn semantic_planning_skips_absent_low_rrtype_exact_probe_but_keeps_cname_fallback() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let absent_low_type = RecordType::Hinfo as u16;

        assert!(!image.low_rrtype_may_exist(absent_low_type));
        let plan = image.lookup_response_plan(
            &alias,
            absent_low_type,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan_answer_types(&image, &plan), [RecordType::Cname as u16]);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(&alias, absent_low_type, 1))
        );
    }

    #[test]
    fn semantic_planning_skips_indirection_probes_when_image_has_no_cname_or_dname_rrsets() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(54),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    owner.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 54]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        assert!(!image.low_rrtype_may_exist(RecordType::Cname as u16));
        assert!(!image.low_rrtype_may_exist(RecordType::Dname as u16));
        let plan = image.lookup_response_plan(
            &owner,
            RecordType::Txt as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan_answer_types(&image, &plan), []);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&owner, RecordType::Txt as u16, 1)
            )
        );
    }

    #[test]
    fn wildcard_planning_skips_absent_low_rrtype_and_absent_cname_probe() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let wildcard = DomainName::from_absolute_str("*.wild.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(55),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    wildcard,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 55]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        assert!(!image.low_rrtype_may_exist(RecordType::Txt as u16));
        assert!(!image.low_rrtype_may_exist(RecordType::Cname as u16));
        let plan = image.lookup_response_plan(
            &qname,
            RecordType::Txt as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan_answer_types(&image, &plan), []);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&qname, RecordType::Txt as u16, 1)
            )
        );
    }

    #[test]
    fn node_policy_hints_precompute_in_delegation_and_dname_covers() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let child_host = DomainName::from_absolute_str("www.child.example.test.").unwrap();
        let dname = DomainName::from_absolute_str("dname.example.test.").unwrap();
        let dname_host = DomainName::from_absolute_str("host.dname.example.test.").unwrap();
        let chaos = DomainName::from_absolute_str("chaos.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(52),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    child_host.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1]],
                ),
                Rrset::new(
                    dname.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("target.example.test.")],
                ),
                Rrset::new(
                    dname_host.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 2]],
                ),
                Rrset::new(
                    chaos.clone(),
                    RecordType::Ns as u16,
                    3,
                    300,
                    vec![name_rdata("ns.chaos.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let child_node = image.find_node(&child).expect("child node exists");
        let child_host_node = image
            .find_node(&child_host)
            .expect("child host node exists");
        let dname_node = image.find_node(&dname).expect("DNAME node exists");
        let dname_host_node = image
            .find_node(&dname_host)
            .expect("DNAME child node exists");
        let chaos_node = image.find_node(&chaos).expect("CHAOS node exists");

        let child_ns = image
            .find_rrset_at_node(child_node, RecordType::Ns as u16, 1)
            .expect("IN delegation exists");
        let dname_rrset = image
            .find_rrset_at_node(dname_node, RecordType::Dname as u16, 1)
            .expect("IN DNAME exists");
        let chaos_ns = image
            .find_rrset_at_node(chaos_node, RecordType::Ns as u16, 3)
            .expect("CHAOS delegation exists");

        assert_eq!(image.delegation_for_node(child_node, 1), Some(child_ns));
        assert_eq!(
            image.delegation_for_node(child_host_node, 1),
            Some(child_ns)
        );
        assert_eq!(image.delegation_for_node(chaos_node, 1), None);
        assert_eq!(image.delegation_for_node(chaos_node, 3), Some(chaos_ns));
        assert!(
            !image.any_class_delegation_policy_is_in_only,
            "non-IN delegation keeps QCLASS=ANY on conservative scan"
        );
        assert_eq!(image.delegation_for_node(chaos_node, 255), Some(chaos_ns));

        assert_eq!(image.dname_for_node(None, dname_node, 1), Some(dname_rrset));
        assert_eq!(image.dname_for_node(Some(dname_node), dname_node, 1), None);
        assert_eq!(
            image.dname_for_node(Some(dname_host_node), dname_host_node, 1),
            Some(dname_rrset)
        );
        assert!(image.covering_dname_blocks_direct_answer(dname_host_node, 1));

        let in_only_snapshot = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(53),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    dname.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("target.example.test.")],
                ),
                Rrset::new(
                    child_host.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 3]],
                ),
                Rrset::new(
                    dname_host.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 4]],
                ),
            ],
        );
        let in_only = ZoneImage::compile(&in_only_snapshot).expect("IN-only image compiles");
        let in_only_child_node = in_only
            .find_node(&child)
            .expect("IN-only child node exists");
        let in_only_child_host_node = in_only
            .find_node(&child_host)
            .expect("IN-only child host node exists");
        let in_only_dname_host_node = in_only
            .find_node(&dname_host)
            .expect("IN-only DNAME child node exists");
        let in_only_child_ns = in_only
            .find_rrset(&child, RecordType::Ns as u16, 1)
            .expect("IN-only child NS exists");
        let in_only_dname_rrset = in_only
            .find_rrset(&dname, RecordType::Dname as u16, 1)
            .expect("IN-only DNAME exists");
        assert!(in_only.any_class_delegation_policy_is_in_only);
        assert!(in_only.any_class_dname_policy_is_in_only);
        assert_eq!(
            in_only.delegation_for_node(in_only_child_host_node, 255),
            Some(in_only_child_ns)
        );
        assert!(
            !in_only.covering_delegation_blocks_direct_answer(
                in_only_child_node,
                RecordType::Ds as u16,
                255
            ),
            "DS at a delegation owner should use compiled policy ownership without blocking"
        );
        assert!(
            in_only.covering_delegation_blocks_direct_answer(
                in_only_child_host_node,
                RecordType::Ds as u16,
                255
            ),
            "DS below a delegation should still be blocked by the covering delegation"
        );
        assert_eq!(
            in_only.dname_for_node(Some(in_only_dname_host_node), in_only_dname_host_node, 255),
            Some(in_only_dname_rrset)
        );
        assert!(in_only.covering_dname_blocks_direct_answer(in_only_dname_host_node, 255));
    }

    #[test]
    fn ds_at_delegation_owner_uses_compiled_node_ownership() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let child_ns = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let mixed_case_child = DomainName::from_absolute_str("CHILD.Example.TEST.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(51),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    child.clone(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![12, 34, 8, 2, 0xaa, 0xbb, 0xcc, 0xdd]],
                ),
                Rrset::new(
                    child_ns,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let child_node = image.find_node(&child).expect("child node exists");
        let child_ns = image
            .find_rrset_at_node(child_node, RecordType::Ns as u16, 1)
            .expect("IN delegation exists");
        assert_eq!(
            image.rrsets[child_ns.0 as usize].owner_label_count as usize,
            child.label_count()
        );

        let plan = image.lookup_response_plan(
            &mixed_case_child,
            RecordType::Ds as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(
            plan_answer_types(&image, &plan),
            vec![RecordType::Ds as u16]
        );
        assert!(plan.authority_rrsets().is_empty());
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(
                &mixed_case_child,
                RecordType::Ds as u16,
                1
            ))
        );
        let any_plan = image.lookup_response_plan(
            &mixed_case_child,
            RecordType::Ds as u16,
            255,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &any_plan),
            vec![RecordType::Ds as u16]
        );
        assert!(any_plan.authority_rrsets().is_empty());

        let below_child = DomainName::from_absolute_str("below.child.example.test.").unwrap();
        let referral_plan = image.lookup_response_plan(
            &below_child,
            RecordType::Ds as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(referral_plan.answer_rrsets().is_empty());
        assert_eq!(referral_plan.authority_rrsets(), &[child_ns]);
        let any_referral_plan = image.lookup_response_plan(
            &below_child,
            RecordType::Ds as u16,
            255,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(any_referral_plan.answer_rrsets().is_empty());
        assert_eq!(any_referral_plan.authority_rrsets(), &[child_ns]);
    }

    #[test]
    fn referral_dnssec_uses_precomputed_delegation_proof_relations() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let secure_child = DomainName::from_absolute_str("secure.example.test.").unwrap();
        let mixed_secure_child = DomainName::from_absolute_str("SECURE.Example.TEST.").unwrap();
        let unsigned_child = DomainName::from_absolute_str("unsigned.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(53),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    secure_child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.secure.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.secure.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
                Rrset::new(
                    mixed_secure_child,
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![12, 34, 8, 2, 0xaa, 0xbb, 0xcc, 0xdd]],
                ),
                Rrset::new(
                    unsigned_child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.unsigned.example.test.")],
                ),
                Rrset::new(
                    unsigned_child.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![name_rdata("z.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let secure_ns = image
            .find_rrset(&secure_child, RecordType::Ns as u16, 1)
            .expect("secure child NS exists");
        let secure_ds = image
            .find_rrset(&secure_child, RecordType::Ds as u16, 1)
            .expect("secure child DS exists");
        let unsigned_ns = image
            .find_rrset(&unsigned_child, RecordType::Ns as u16, 1)
            .expect("unsigned child NS exists");
        let unsigned_nsec = image
            .find_rrset(&unsigned_child, RecordType::Nsec as u16, 1)
            .expect("unsigned child NSEC exists");

        let secure_relation = image
            .precomputed_referral_dnssec_rrset(secure_ns)
            .expect("secure child has precomputed DS proof relation");
        let secure_span = image
            .rrset_relation_span(image.rrsets[secure_ns.0 as usize].relation_span)
            .expect("secure child NS has a relation span");
        assert_eq!(secure_relation.kind, ImageRrsetRelationKind::DelegationDs);
        assert_eq!(secure_relation.rrset_id, secure_ds);
        assert_eq!(secure_span.single_name_target_offset, NO_RELATION_OFFSET);
        assert_eq!(secure_span.rrsig_offset, NO_RELATION_OFFSET);
        assert_ne!(secure_span.referral_glue_offset, NO_RELATION_OFFSET);
        assert_ne!(secure_span.delegation_dnssec_offset, NO_RELATION_OFFSET);
        assert_ne!(secure_span.additional_address_offset, NO_RELATION_OFFSET);
        assert_eq!(
            image
                .rrset_relations_of_kind(secure_ns, ImageRrsetRelationKind::ReferralGlue)
                .len(),
            1
        );
        assert_eq!(
            image
                .rrset_relations_of_kind(secure_ns, ImageRrsetRelationKind::DelegationDs)
                .len(),
            1
        );

        let unsigned_relation = image
            .precomputed_referral_dnssec_rrset(unsigned_ns)
            .expect("unsigned child has precomputed NSEC proof relation");
        assert_eq!(
            unsigned_relation.kind,
            ImageRrsetRelationKind::DelegationNsec
        );
        assert_eq!(unsigned_relation.rrset_id, unsigned_nsec);

        let qname = DomainName::from_absolute_str("www.secure.example.test.").unwrap();
        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.referral_ns_rrset(), Some(secure_ns));
        let augmented = image.augment_lookup_plan_with_dnssec(plan, &qname, 1, 100);

        assert!(augmented.authority_rrsets().contains(&secure_ds));
    }

    #[test]
    fn referral_dnssec_relation_owner_key_is_built_from_wire() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let secure_child = DomainName::from_absolute_str("secure.example.test.").unwrap();
        let mixed_secure_child = DomainName::from_absolute_str("SECURE.Example.TEST.").unwrap();
        let mut compressed = mixed_secure_child.to_wire();
        compressed[0] = 0xc0;
        let mut trailing = mixed_secure_child.to_wire();
        trailing.push(0);
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(153),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    mixed_secure_child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.secure.example.test.")],
                ),
                Rrset::new(
                    secure_child.clone(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![12, 34, 8, 2, 0xaa, 0xbb, 0xcc, 0xdd]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let secure_ns = image
            .find_rrset(&secure_child, RecordType::Ns as u16, 1)
            .expect("secure child NS exists");

        assert_eq!(
            canonical_key_from_uncompressed_wire(mixed_secure_child.to_wire().as_slice())
                .as_deref(),
            Some("secure.example.test.")
        );
        assert_eq!(canonical_key_from_uncompressed_wire(&compressed), None);
        assert_eq!(canonical_key_from_uncompressed_wire(&trailing), None);
        assert_eq!(
            image
                .precomputed_referral_dnssec_rrset(secure_ns)
                .expect("mixed-case NS owner finds DS by direct wire key")
                .kind,
            ImageRrsetRelationKind::DelegationDs
        );
    }

    #[test]
    fn referral_dnssec_requires_plan_referral_handle() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(63),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    child.clone(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![1, 2, 3, 4]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let child_ns = image
            .find_rrset(&child, RecordType::Ns as u16, 1)
            .expect("child NS exists");
        let child_ds = image
            .find_rrset(&child, RecordType::Ds as u16, 1)
            .expect("child DS exists");
        let mut legacy_shape = ZoneImageLookupPlan::positive();
        legacy_shape.clear_flag(PLAN_FLAG_AUTHORITATIVE);
        image.push_authority_rrset_to_plan(&mut legacy_shape, child_ns);
        assert_eq!(legacy_shape.referral_ns_rrset(), None);

        let augmented = image.augment_lookup_plan_with_dnssec(
            legacy_shape,
            &DomainName::from_absolute_str("www.child.example.test.").unwrap(),
            1,
            100,
        );

        assert!(!augmented.authority_rrsets().contains(&child_ds));
    }

    #[test]
    fn referral_dnssec_nsec3_fallback_hashes_stored_owner_wire() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.child.example.test.").unwrap();
        let params = Nsec3Params {
            hash_algorithm: 1,
            iterations: 0,
            salt: &[],
        };
        let child_hash = nsec3_hash_domain(&child, params).expect("hash computes");
        let nsec3_owner =
            DomainName::from_absolute_str(&format!("{child_hash}.example.test.")).unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(64),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    nsec3_owner.clone(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_next_hash(1, 0, &[], &[0x80; 20])],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let child_ns = image
            .find_rrset(&child, RecordType::Ns as u16, 1)
            .expect("child NS exists");
        let child_nsec3 = image
            .find_rrset(&nsec3_owner, RecordType::Nsec3 as u16, 1)
            .expect("child NSEC3 exists");
        assert!(
            image.precomputed_referral_dnssec_rrset(child_ns).is_none(),
            "fallback path should be exercised when no DS/NSEC relation exists"
        );

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.referral_ns_rrset(), Some(child_ns));
        let augmented = image.augment_lookup_plan_with_dnssec(plan, &qname, 1, 100);

        assert!(augmented.authority_rrsets().contains(&child_nsec3));
    }

    #[test]
    fn dnssec_denial_helpers_skip_empty_range_families() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("missing.example.test.").unwrap();
        let nsec_only = ZoneImage::compile(&ZoneSnapshot::active(
            origin.clone(),
            Some(69),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    origin.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
            ],
        ))
        .expect("NSEC-only zone image compiles");
        let nsec = nsec_only
            .find_rrset(&origin, RecordType::Nsec as u16, 1)
            .expect("NSEC proof rrset exists");
        let mut plan = ZoneImageLookupPlan::nxdomain();
        let mut state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: u16::try_from(plan.authority_rrsets.len())
                .unwrap_or(u16::MAX),
            seen_selected_records: SmallVec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations: 100,
        };
        nsec_only.push_nsec3_for_name(&qname, 1, false, &mut plan, &mut state);
        assert!(plan.authority_rrsets.is_empty());
        assert!(state.appended_authority_rrsets.is_empty());
        assert!(!state.dnssec_augmented);
        let nxdomain_plan = nsec_only.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        let augmented = nsec_only.augment_lookup_plan_with_dnssec(nxdomain_plan, &qname, 1, 100);
        assert!(
            augmented.authority_rrsets().contains(&nsec),
            "NSEC-only NXDOMAIN should skip NSEC3 helper entry and keep NSEC proof selection"
        );

        let params = Nsec3Params {
            hash_algorithm: 1,
            iterations: 0,
            salt: &[],
        };
        let qname_hash = nsec3_hash_domain(&qname, params).expect("hash computes");
        let nsec3_owner =
            DomainName::from_absolute_str(&format!("{qname_hash}.example.test.")).unwrap();
        let nsec3_only = ZoneImage::compile(&ZoneSnapshot::active(
            origin.clone(),
            Some(70),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 70]],
                ),
                Rrset::new(
                    nsec3_owner.clone(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_next_hash(1, 0, &[], &[0x80; 20])],
                ),
            ],
        ))
        .expect("NSEC3-only zone image compiles");
        let mut plan = ZoneImageLookupPlan::nxdomain();
        let mut state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: u16::try_from(plan.authority_rrsets.len())
                .unwrap_or(u16::MAX),
            seen_selected_records: SmallVec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations: 100,
        };
        nsec3_only.push_nsec_covering_name(&qname, 1, &mut plan, &mut state);
        assert!(plan.authority_rrsets.is_empty());
        assert!(state.appended_authority_rrsets.is_empty());
        assert!(!state.dnssec_augmented);

        let nsec3 = nsec3_only
            .find_rrset(&nsec3_owner, RecordType::Nsec3 as u16, 1)
            .expect("NSEC3 proof rrset exists");
        let nodata_plan = nsec3_only.lookup_response_plan(
            &qname,
            RecordType::Aaaa as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(nodata_plan.answer_rrsets().is_empty());
        let augmented = nsec3_only.augment_lookup_plan_with_dnssec(nodata_plan, &qname, 1, 100);
        assert!(
            augmented.authority_rrsets().contains(&nsec3),
            "NSEC3-only exact NODATA should skip exact NSEC probing and use the NSEC3 family"
        );
    }

