    #[test]
    fn compact_rdata_range_keeps_image_record_and_rrset_metadata_bounded() {
        assert_eq!(mem::size_of::<RdataRange>(), mem::size_of::<BlobRange>());
        assert_eq!(mem::size_of::<ImageRecord>(), mem::size_of::<BlobRange>());
        assert_eq!(mem::size_of::<ImageRrsetRelation>(), 16);
        assert_eq!(mem::size_of::<ImageRrset>(), 72);
        assert_eq!(mem::size_of::<NameNode>(), 36);
        assert_eq!(mem::align_of::<NameNode>(), 4);
        assert_eq!(mem::size_of::<ImageChildHash>(), 12);
        assert_eq!(mem::size_of::<PackedRdataEncoding>(), 2);
        assert_eq!(mem::size_of::<ZoneImageSelectedRecord>(), 32);
        assert_eq!(mem::size_of::<ZoneImageWireRecord<'static>>(), 48);
    }

    #[test]
    fn global_offsets_and_ordinals_represent_values_above_u32() {
        let above_u32 = u64::from(u32::MAX) + 1;
        let range = BlobRange {
            offset: above_u32,
            len: above_u32,
        };
        let rdata = RdataRange {
            offset: above_u32,
            len: 1,
            rdata_encoding: PackedRdataEncoding::copy(),
        };
        let rrset = ImageRrset {
            owner_wire: range,
            fixed_fields: [0; 8],
            negative_ttl_bytes: [0; 4],
            first_record: above_u32,
            record_count: 0,
            ownerless_wire_len: ownerless_wire_len(0, 0, above_u32),
            owner_label_count: 0,
            relation_span: u32::MAX,
            direct_answer_body_len: 0,
            wire: range,
        };
        let relation = ImageRrsetRelation::new(
            ImageRrsetRelationKind::Rrsig,
            ZoneImageRrsetId(0),
            above_u32,
            0,
            0,
            false,
        );
        let span = ImageRrsetRelationSpan::new(above_u32, 0, &[])
            .expect("u64 relation ordinal is representable");

        assert_eq!(range.offset, above_u32);
        assert_eq!(range.len, above_u32);
        assert_eq!(blob_len(range), above_u32 as usize);
        assert_eq!(
            rrset_ownerless_wire_len(rrset),
            u32::MAX as usize,
            "compiled capacity hints saturate without narrowing global arena ranges"
        );
        assert_eq!(rdata.offset, above_u32);
        assert_eq!(rrset.first_record, above_u32);
        assert_eq!(relation.record_index, above_u32);
        assert_eq!(span.first_relation, above_u32);
    }

    #[test]
    fn direct_answer_template_falls_back_above_dns_section_count_capacity() {
        let rdatas = vec![&[][..]; usize::from(u16::MAX) + 1];
        let mut wire = Vec::new();

        let result = push_direct_answer_body(&mut wire, true, [0; 8], &rdatas)
            .expect("oversized direct answer falls back to records");

        assert_eq!(result, DIRECT_ANSWER_BODY_RECORDS_FALLBACK);
        assert!(wire.is_empty());
    }

    #[test]
    fn dnssec_proof_servfail_transition_mutates_the_existing_plan() {
        let mut plan = ZoneImageLookupPlan::positive();
        plan.answer_rrsets.push(ZoneImageRrsetId(1));
        plan.answer_record_count = 1;
        plan.answer_wire_upper_bound = 41;
        plan.body_wire_upper_bound = 97;
        plan.authority_rrsets.push(ZoneImageRrsetId(2));
        plan.authority_record_count = 2;
        plan.additional_rrsets.push(ZoneImageRrsetId(3));
        plan.additional_record_count = 3;
        plan.termination = Some(LookupTermination::CnameLoop);

        plan.set_dnssec_proof_servfail();

        assert_eq!(plan.rcode, Rcode::ServFail);
        assert!(plan.authoritative());
        assert_eq!(plan.answer_rrsets.as_slice(), [ZoneImageRrsetId(1)]);
        assert_eq!(plan.answer_record_count, 1);
        assert!(plan.authority_rrsets.is_empty());
        assert_eq!(plan.authority_record_count, 0);
        assert!(plan.additional_rrsets.is_empty());
        assert_eq!(plan.additional_record_count, 0);
        assert_eq!(plan.body_wire_upper_bound, plan.answer_wire_upper_bound);
        assert_eq!(plan.termination, None);
    }

    #[test]
    fn compact_u32_indexes_reserve_the_none_sentinel() {
        let largest_valid = usize::try_from(u32::MAX - 1).expect("supported pointer width");
        let sentinel = usize::try_from(u32::MAX).expect("supported pointer width");

        assert_eq!(
            checked_u32_index(largest_valid, "test indexes"),
            Ok(u32::MAX - 1)
        );
        assert_eq!(
            checked_u32_index(sentinel, "test indexes"),
            Err(ZoneImageBuildError::TooManyItems {
                kind: "test indexes"
            })
        );
        assert_eq!(
            checked_compact_array_end(largest_valid - 9, 10, "test slots"),
            Ok(sentinel)
        );
        assert_eq!(
            checked_compact_array_end(largest_valid - 9, 11, "test slots"),
            Err(ZoneImageBuildError::TooManyItems { kind: "test slots" })
        );
    }

    #[test]
    fn child_hash_slots_widen_only_above_the_u16_edge_offset_space() {
        let fanout = usize::from(u16::MAX) + 1;
        let mut labels = Vec::with_capacity(fanout * mem::size_of::<u32>());
        let mut edges = Vec::with_capacity(fanout);
        for index in 0..fanout {
            let offset = labels.len() as u64;
            labels.extend_from_slice(&(index as u32).to_be_bytes());
            edges.push(NameEdge {
                label: BlobRange { offset, len: 4 },
                child: index as u32,
            });
        }
        let mut nodes = [NameNode {
            first_edge: 0,
            edge_count: fanout as u32,
            low_rrtype_bitmap: NO_NODE_LOW_RRTYPE_BITMAP,
            first_rrset: u32::MAX,
            rrset_count: 0,
            parent: 0,
            depth: 0,
            nearest_in_delegation: u32::MAX,
            nearest_in_dname: u32::MAX,
            child_hash: u32::MAX,
        }];

        let BuiltChildHashes {
            hashes,
            slots_u16: narrow_slots,
            slots_u32: wide_slots,
        } = build_child_hashes(&mut nodes, &edges, &labels).expect("wide child hash builds");

        assert!(narrow_slots.is_empty());
        assert_eq!(wide_slots.len(), fanout * 2);
        assert_eq!(hashes.len(), 1);
        assert!(hashes[0].wide_slots);
        assert_eq!(nodes[0].child_hash, 0);
    }

    #[test]
    fn plan_answer_indexes_stay_compact() {
        assert_eq!(mem::size_of::<PlanAnswer>(), 40);
        assert_eq!(mem::align_of::<PlanAnswer>(), 8);
        assert_eq!(
            mem::size_of::<IndirectionTargetWire<'static>>(),
            mem::size_of::<Option<&'static [u8]>>()
        );
        let plan = ZoneImageLookupPlan::positive();
        assert_eq!(
            mem::size_of_val(&plan.authority_soa_index),
            mem::size_of::<u16>()
        );
        assert_eq!(plan.authority_soa_index, NO_AUTHORITY_SOA_INDEX);
        let response_shape = plan
            .response_shape()
            .expect("empty positive plan section counts fit DNS header fields");
        assert_eq!(
            mem::size_of_val(&response_shape.answer_count),
            mem::size_of::<u16>()
        );
        assert_eq!(
            mem::size_of_val(&response_shape.authority_count),
            mem::size_of::<u16>()
        );
        assert_eq!(
            mem::size_of_val(&response_shape.additional_count),
            mem::size_of::<u16>()
        );
        let dnssec_state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: 0,
            seen_selected_records: SmallVec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations: 0,
        };
        assert_eq!(
            mem::size_of_val(&dnssec_state.original_authority_rrset_count),
            mem::size_of::<u16>()
        );
    }

    #[test]
    fn soa_rdata_encoding_carries_both_prevalidated_name_spans() {
        let rdata = soa_rdata();
        let encoding = zone_image_rdata_encoding(RecordType::Soa as u16, &rdata);

        assert_eq!(encoding.soa_lengths(), Some((17, 25)));
        assert!(PackedRdataEncoding::copy().soa_lengths().is_none());
        assert!(PackedRdataEncoding::single_name().soa_lengths().is_none());
        assert!(PackedRdataEncoding::mx().soa_lengths().is_none());
    }

    #[test]
    fn soa_minimum_reads_prevalidated_wire_names_without_domain_parse() {
        let rdata = soa_rdata();

        assert_eq!(soa_minimum(&rdata), Some(300));

        let mut compressed_mname = rdata.clone();
        compressed_mname[0] = 0xc0;
        assert_eq!(soa_minimum(&compressed_mname), None);

        let mut trailing = rdata.clone();
        trailing.push(0);
        assert_eq!(soa_minimum(&trailing), None);
    }

    #[test]
    fn plan_summary_owner_key_is_built_directly_from_wire() {
        let owner = DomainName::from_absolute_str("MiXeD.Example.TEST.").unwrap();
        let owner_wire = owner.to_wire();
        let mut compressed = owner_wire.clone();
        compressed[0] = 0xc0;
        let mut trailing = owner_wire.clone();
        trailing.push(0);

        assert_eq!(
            canonical_owner_key_from_wire(&owner_wire).as_deref(),
            Ok("mixed.example.test.")
        );
        assert_eq!(
            canonical_owner_key_from_wire(&compressed),
            Err(ZoneImageBuildError::InvalidCompiledOwner)
        );
        assert_eq!(
            canonical_owner_key_from_wire(&trailing),
            Err(ZoneImageBuildError::InvalidCompiledOwner)
        );
    }

    #[test]
    fn additional_relation_targets_borrow_validated_wire_names() {
        let target_wire = name_rdata("Mail.Example.TEST.");
        let mut compressed = target_wire.clone();
        compressed[0] = 0xc0;
        let mut trailing = target_wire.clone();
        trailing.push(0);

        let mx = mx_rdata("Mail.Example.TEST.");
        let srv = srv_rdata("Mail.Example.TEST.");
        let mut svcb = svc_param_rdata("Mail.Example.TEST.");
        svcb.extend_from_slice(&[0, 1, 0, 0]);
        let svcb_target_len = wire_name_len_at(&svcb, 2).expect("valid SVCB target length");

        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Ns as u16, &target_wire),
            Some(target_wire.as_slice())
        );
        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Mx as u16, &mx),
            Some(&mx[2..])
        );
        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Srv as u16, &srv),
            Some(&srv[6..])
        );
        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Svcb as u16, &svcb),
            Some(&svcb[2..2 + svcb_target_len])
        );
        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Ns as u16, &compressed),
            None
        );
        assert_eq!(
            additional_address_target_wire_rdata(RecordType::Ns as u16, &trailing),
            None
        );
    }

    #[test]
    fn compile_rejects_rdata_that_cannot_fit_wire_rdlength() {
        let snapshot = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("oversized.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                vec![vec![0; usize::from(u16::MAX) + 1]],
            )],
        );

        assert_eq!(
            ZoneImage::compile(&snapshot),
            Err(ZoneImageBuildError::RdataTooLarge)
        );
    }

    #[test]
    fn exact_lookup_matches_snapshot_for_direct_positive_answer() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();

        let ZoneImageLookupOutcome::Found(plan) =
            image.lookup_exact_plan(&qname, RecordType::A as u16, 1)
        else {
            panic!("expected exact A lookup to find an answer");
        };

        let snapshot_lookup = snapshot
            .offline_oracle()
            .lookup(&qname, RecordType::A as u16, 1);
        assert_eq!(snapshot_lookup.rcode, Rcode::NoError);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes").answers,
            records_summary(&snapshot_lookup.answers)
        );
        assert_eq!(plan.answer_rrsets().len(), 1);
        assert!(
            !image
                .rrset_wire(plan.answer_rrsets()[0])
                .unwrap()
                .is_empty()
        );

        let mixed_case_qname = DomainName::from_absolute_str("WWW.Example.TEST.").unwrap();
        assert!(matches!(
            image.lookup_exact_plan(&mixed_case_qname, RecordType::A as u16, 1),
            ZoneImageLookupOutcome::Found(_)
        ));

        let mut wire = Vec::new();
        let record_count = image.append_plan_wire(&plan, &mut wire);
        assert_eq!(record_count, snapshot_lookup.answers.len());
        assert_eq!(wire, image.rrset_wire(plan.answer_rrsets()[0]).unwrap());
    }

    #[test]
    fn exact_lookup_supports_any_class_for_direct_answers() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();

        let ZoneImageLookupOutcome::Found(plan) =
            image.lookup_exact_plan(&qname, RecordType::A as u16, 255)
        else {
            panic!("expected ANY-class direct A lookup to find an answer");
        };

        assert_eq!(image.plan_summary(&plan).unwrap().answers.count, 2);
    }

    #[test]
    fn exact_lookup_concrete_class_uses_single_compiled_rrset_match() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("multi.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(46),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![0; 16]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    3,
                    300,
                    vec![vec![198, 51, 100, 10]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let ZoneImageLookupOutcome::Found(in_plan) =
            image.lookup_exact_plan(&qname, RecordType::A as u16, 1)
        else {
            panic!("expected concrete IN A lookup to find an answer");
        };
        assert_eq!(
            plan_answer_classes_types(&image, &in_plan),
            vec![(1, RecordType::A as u16)]
        );

        let ZoneImageLookupOutcome::Found(any_class_plan) =
            image.lookup_exact_plan(&qname, RecordType::A as u16, 255)
        else {
            panic!("expected ANY-class A lookup to find answers");
        };
        assert_eq!(
            plan_answer_classes_types(&image, &any_class_plan),
            vec![(1, RecordType::A as u16), (3, RecordType::A as u16)]
        );
    }

    #[test]
    fn single_rrset_owner_lookup_uses_direct_match_semantics() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let node = image.find_node(&qname).expect("single-RRset owner node");
        assert_eq!(image.nodes[node as usize].rrset_count, 1);

        assert!(matches!(
            image.lookup_exact_plan(&qname, RecordType::A as u16, 1),
            ZoneImageLookupOutcome::Found(_)
        ));
        assert!(matches!(
            image.lookup_exact_plan(&qname, RecordType::A as u16, 255),
            ZoneImageLookupOutcome::Found(_)
        ));
        assert_eq!(
            image.lookup_exact_plan(&qname, RecordType::Aaaa as u16, 1),
            ZoneImageLookupOutcome::NoData
        );

        let semantic = ZoneImage::compile(&semantic_snapshot()).expect("semantic image compiles");
        let empty_owner = DomainName::from_absolute_str("ent.example.test.").unwrap();
        let empty_node = semantic
            .find_node(&empty_owner)
            .expect("empty non-terminal node exists");
        assert_eq!(semantic.nodes[empty_node as usize].rrset_count, 0);
        assert_eq!(
            semantic.lookup_exact_plan(&empty_owner, RecordType::A as u16, 1),
            ZoneImageLookupOutcome::NoData
        );
    }

    #[test]
    fn exact_lookup_skips_absent_low_rrtype_after_node_classification() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let existing = DomainName::from_absolute_str("www.example.test.").unwrap();
        let missing = DomainName::from_absolute_str("missing.example.test.").unwrap();
        let outside = DomainName::from_absolute_str("www.example.invalid.").unwrap();

        assert!(!image.low_rrtype_may_exist(RecordType::Txt as u16));
        assert_eq!(
            image.lookup_exact_plan(&existing, RecordType::Txt as u16, 1),
            ZoneImageLookupOutcome::NoData
        );
        assert_eq!(
            image.lookup_exact_plan(&existing, RecordType::Txt as u16, 255),
            ZoneImageLookupOutcome::NoData
        );
        assert_eq!(
            image.lookup_exact_plan(&missing, RecordType::Txt as u16, 1),
            ZoneImageLookupOutcome::NameError
        );
        assert_eq!(
            image.lookup_exact_plan(&outside, RecordType::Txt as u16, 1),
            ZoneImageLookupOutcome::OutOfZone
        );
    }

    #[test]
    fn leaf_child_lookup_returns_missing_with_current_closest_node() {
        let image = ZoneImage::compile(&sample_snapshot()).expect("zone image compiles");
        let leaf = DomainName::from_absolute_str("www.example.test.").unwrap();
        let missing_below_leaf = DomainName::from_absolute_str("missing.www.example.test.")
            .expect("absolute name parses");
        let leaf_node = image.find_node(&leaf).expect("leaf node exists");

        assert_eq!(image.nodes[leaf_node as usize].edge_count, 0);
        assert_eq!(image.find_child(leaf_node, b"missing"), None);
        assert_eq!(
            image.query_node_handles(&missing_below_leaf, true),
            (None, Some(leaf_node))
        );
    }

    #[test]
    fn authority_soa_ttl_override_uses_plan_index_without_scan() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(44),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    www.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let answer_plan = image.lookup_response_plan(
            &www,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        let a_rrset = answer_plan.answer_rrsets()[0];
        let soa_rrset = image.soa_rrset(1).expect("SOA exists");

        let mut plan = ZoneImageLookupPlan::positive();
        image.push_authority_rrset_to_plan(&mut plan, a_rrset);
        image.push_authority_rrset_to_plan(&mut plan, soa_rrset);

        assert_eq!(plan.authority_soa_index(), Some(1));
        assert!(plan.authority_has_soa());
        assert!(!plan.authority_first_rrset_is_soa());

        let mut actual = Vec::new();
        assert_eq!(image.append_plan_wire(&plan, &mut actual), 2);

        let mut expected = Vec::new();
        image.append_rrset_wire(a_rrset, &mut expected);
        image.append_rrset_wire_with_fixed_fields(
            soa_rrset,
            image.negative_authority_soa_fixed_fields(soa_rrset),
            &mut expected,
        );
        assert_eq!(actual, expected);

        let mut unmodified = Vec::new();
        image.append_rrset_wire(a_rrset, &mut unmodified);
        image.append_rrset_wire(soa_rrset, &mut unmodified);
        assert_ne!(
            actual, unmodified,
            "authority SOA TTL should use the negative TTL override"
        );
    }

    #[test]
    fn authority_removability_uses_plan_soa_position() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(44),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    www.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let answer_plan = image.lookup_response_plan(
            &www,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        let a_rrset = answer_plan.answer_rrsets()[0];
        let soa_rrset = image.soa_rrset(1).expect("SOA exists");

        let mut plan = ZoneImageLookupPlan::positive();
        image.push_authority_rrset_to_plan(&mut plan, a_rrset);
        image.push_authority_rrset_to_plan(&mut plan, soa_rrset);
        assert_eq!(plan.authority_soa_index(), Some(1));

        let mut authority_removability = Vec::new();
        image.visit_plan_record_sections_with_authority_removability(
            &plan,
            |_| {},
            |record, removable| {
                authority_removability.push((
                    u16::from_be_bytes([record.fixed_fields[0], record.fixed_fields[1]]),
                    removable,
                ));
            },
            |_| {},
        );

        assert_eq!(
            authority_removability,
            vec![
                (RecordType::A as u16, true),
                (RecordType::Soa as u16, false)
            ]
        );
    }

    #[test]
    fn exact_lookup_matches_snapshot_for_direct_rrtype_corpus() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(7),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 300, vec![soa_rdata()]),
                Rrset::new(
                    www.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 1]],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![b"\x05hello".to_vec()],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::Svcb as u16,
                    1,
                    300,
                    vec![svc_param_rdata("svc.example.test.")],
                ),
                Rrset::new(
                    www.clone(),
                    RecordType::Https as u16,
                    1,
                    300,
                    vec![svc_param_rdata(".")],
                ),
                Rrset::new(www.clone(), 65_280, 1, 300, vec![b"unknown".to_vec()]),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        for rr_type in [
            RecordType::A as u16,
            RecordType::Aaaa as u16,
            RecordType::Mx as u16,
            RecordType::Txt as u16,
            RecordType::Svcb as u16,
            RecordType::Https as u16,
            65_280,
        ] {
            assert_exact_matches_snapshot(&snapshot, &image, &www, rr_type, 1);
        }
    }

    #[test]
    fn exact_lookup_reports_nodata_nameerror_and_out_of_zone() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let existing = DomainName::from_absolute_str("www.example.test.").unwrap();
        let missing = DomainName::from_absolute_str("missing.example.test.").unwrap();
        let outside = DomainName::from_absolute_str("www.example.invalid.").unwrap();

        assert_eq!(
            image.lookup_exact_plan(&existing, RecordType::Aaaa as u16, 1),
            ZoneImageLookupOutcome::NoData
        );
        assert_eq!(
            image.lookup_exact_plan(&missing, RecordType::A as u16, 1),
            ZoneImageLookupOutcome::NameError
        );
        assert_eq!(
            image.lookup_exact_plan(&outside, RecordType::A as u16, 1),
            ZoneImageLookupOutcome::OutOfZone
        );
    }

    #[test]
    fn semantic_lookup_matches_snapshot_for_name_semantics() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        for (qname, rr_type) in [
            ("alias.example.test.", RecordType::A as u16),
            ("host.wild.example.test.", RecordType::A as u16),
            ("ent.example.test.", RecordType::A as u16),
            ("www.child.example.test.", RecordType::A as u16),
            ("www.subtree.example.test.", RecordType::A as u16),
            ("missing.example.test.", RecordType::A as u16),
        ] {
            let qname = DomainName::from_absolute_str(qname).unwrap();
            let image_plan = image.lookup_response_plan(
                &qname,
                rr_type,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Minimal,
            );
            let snapshot_lookup = snapshot.offline_oracle().lookup(&qname, rr_type, 1);
            assert_eq!(
                image.plan_summary(&image_plan).expect("plan summarizes"),
                lookup_summary(&snapshot_lookup),
                "lookup mismatch for {qname}"
            );
        }
    }

    #[test]
    fn qtype_any_plan_serves_exact_and_wildcard_rrsets() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let exact = DomainName::from_absolute_str("multi.example.test.").unwrap();
        let mx_only = DomainName::from_absolute_str("mx-only.example.test.").unwrap();
        let nsec_only = DomainName::from_absolute_str("nsec-only.example.test.").unwrap();
        let wildcard = DomainName::from_absolute_str("*.wild.example.test.").unwrap();
        let wildcard_qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();
        let mail = DomainName::from_absolute_str("mail.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(45),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    exact.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    exact.clone(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![vec![7, b'p', b'r', b'e', b's', b'e', b'n', b't']],
                ),
                Rrset::new(
                    exact.clone(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
                Rrset::new(
                    exact.clone(),
                    RecordType::A as u16,
                    3,
                    300,
                    vec![vec![198, 51, 100, 10]],
                ),
                Rrset::new(
                    exact,
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![vec![0, 1, 2, 3]],
                ),
                Rrset::new(
                    mx_only.clone(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
                Rrset::new(
                    nsec_only.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("next.example.test.")],
                ),
                Rrset::new(
                    wildcard.clone(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
                Rrset::new(
                    wildcard.clone(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![vec![8, b'w', b'i', b'l', b'd', b'c', b'a', b'r', b'd']],
                ),
                Rrset::new(
                    wildcard,
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![vec![0, 1, 2, 3]],
                ),
                Rrset::new(
                    mail.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 25]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let exact_minimal = image.lookup_response_plan(
            &DomainName::from_absolute_str("multi.example.test.").unwrap(),
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &exact_minimal),
            vec![RecordType::A as u16]
        );

        let mx_only_minimal = image.lookup_response_plan(
            &mx_only,
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &mx_only_minimal),
            vec![RecordType::Mx as u16]
        );
        assert_eq!(mx_only_minimal.additional_rrsets().len(), 1);
        let mx_only_full = image.lookup_response_plan(
            &mx_only,
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Full,
        );
        assert_eq!(
            plan_answer_types(&image, &mx_only_full),
            vec![RecordType::Mx as u16]
        );
        assert_eq!(mx_only_full.additional_rrsets().len(), 1);
        let nsec_only_minimal = image.lookup_response_plan(
            &nsec_only,
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(nsec_only_minimal.answer_rrsets().is_empty());
        assert!(nsec_only_minimal.authority_has_soa());

        let exact_full = image.lookup_response_plan(
            &DomainName::from_absolute_str("multi.example.test.").unwrap(),
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Full,
        );
        assert_eq!(
            plan_answer_types(&image, &exact_full),
            vec![
                RecordType::A as u16,
                RecordType::Mx as u16,
                RecordType::Txt as u16
            ]
        );
        assert_eq!(exact_full.additional_rrsets().len(), 1);

        let exact_full_any_class = image.lookup_response_plan(
            &DomainName::from_absolute_str("multi.example.test.").unwrap(),
            255,
            255,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Full,
        );
        assert_eq!(
            plan_answer_classes_types(&image, &exact_full_any_class),
            vec![
                (1, RecordType::A as u16),
                (1, RecordType::Mx as u16),
                (1, RecordType::Txt as u16),
                (3, RecordType::A as u16),
            ]
        );

        let exact_full_chaos_class = image.lookup_response_plan(
            &DomainName::from_absolute_str("multi.example.test.").unwrap(),
            255,
            3,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Full,
        );
        assert_eq!(
            plan_answer_classes_types(&image, &exact_full_chaos_class),
            vec![(3, RecordType::A as u16)]
        );
        assert!(matches!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("multi.example.test.").unwrap(),
                RecordType::A as u16,
                3
            ),
            ZoneImageLookupOutcome::Found(_)
        ));
        let exact_minimal_chaos_class = image.lookup_response_plan(
            &DomainName::from_absolute_str("multi.example.test.").unwrap(),
            255,
            3,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_classes_types(&image, &exact_minimal_chaos_class),
            vec![(3, RecordType::A as u16)]
        );

        let wildcard_full = image.lookup_response_plan(
            &wildcard_qname,
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Full,
        );
        assert_eq!(
            plan_answer_types(&image, &wildcard_full),
            vec![RecordType::Mx as u16, RecordType::Txt as u16]
        );
        assert_eq!(wildcard_full.additional_rrsets().len(), 1);
        assert_eq!(wildcard_full.owner_overrides.len(), 1);
        assert!(!wildcard_full.owner_overrides.spilled());
        assert!(!wildcard_full.owner_overrides[0].spilled());
        assert!(wildcard_full.answer_items.iter().all(|item| {
            matches!(
                item,
                PlanAnswer::RrsetWithOwner {
                    owner_index,
                    ..
                } if wildcard_full.owner_overrides[usize::from(*owner_index)].as_slice()
                    == wildcard_qname.to_wire().as_slice()
            )
        }));

        let wildcard_minimal = image.lookup_response_plan(
            &wildcard_qname,
            255,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &wildcard_minimal),
            vec![RecordType::Mx as u16]
        );
        assert_eq!(wildcard_minimal.additional_rrsets().len(), 1);
        assert_eq!(wildcard_minimal.owner_overrides.len(), 1);
    }
    #[test]
    fn uncompressed_wire_canonical_key_preserves_label_boundaries() {
        let embedded_dot = b"\x03a.b\x07example\x04test\x00";
        let split_labels = b"\x01a\x01b\x07example\x04test\x00";

        assert_ne!(
            canonical_key_from_uncompressed_wire(embedded_dot),
            canonical_key_from_uncompressed_wire(split_labels)
        );
        assert_eq!(
            canonical_key_from_uncompressed_wire(b"\x03WWW\x07Example\x04TEST\x00"),
            canonical_key_from_uncompressed_wire(b"\x03www\x07example\x04test\x00")
        );
    }
