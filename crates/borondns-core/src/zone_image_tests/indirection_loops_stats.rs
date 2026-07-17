    #[test]
    fn dname_target_resolution_preserves_existing_target_nodata() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let subtree = DomainName::from_absolute_str("subtree.example.test.").unwrap();
        let dname_query = DomainName::from_absolute_str("leaf.subtree.example.test.").unwrap();
        let generated_target =
            DomainName::from_absolute_str("leaf.target-tree.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(62),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    subtree.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("target-tree.example.test.")],
                ),
                Rrset::new(
                    generated_target,
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        assert!(
            !image.low_rrtype_may_exist(RecordType::A as u16),
            "the DNAME target-resolution exact probe can be skipped for absent low RR types"
        );
        assert!(
            !image.low_rrtype_may_exist(RecordType::Cname as u16),
            "the DNAME target-resolution CNAME fallback can be skipped when the image has no CNAME RRsets"
        );

        let plan = image.lookup_response_plan(
            &dname_query,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.rcode(), Rcode::NoError);
        assert_eq!(plan.dynamic_answers.len(), 1);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(
                &dname_query,
                RecordType::A as u16,
                1
            ))
        );
    }

    #[test]
    fn dname_out_of_zone_literal_target_can_synthesize_in_zone_target() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let subtree = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let dname_query = DomainName::from_absolute_str("example.alias.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(63),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    subtree.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let dname_rrset = image
            .find_rrset(&subtree, RecordType::Dname as u16, 1)
            .expect("DNAME rrset exists");
        assert_eq!(
            image
                .single_name_rrset_target(dname_rrset)
                .expect("DNAME target precomputes")
                .node_hint,
            ImageTargetNode::OutOfZoneParentSuffix
        );

        let plan = image.lookup_response_plan(
            &dname_query,
            RecordType::Soa as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan.rcode(), Rcode::NoError);
        assert_eq!(plan.dynamic_answers.len(), 1);
        assert_eq!(
            plan.dynamic_answers[0].rdata.as_slice(),
            origin.to_wire().as_slice()
        );
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(
                &dname_query,
                RecordType::Soa as u16,
                1
            ))
        );
    }

    #[test]
    fn unrelated_out_of_zone_dname_target_stays_out_of_zone_without_synthesized_lookup() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let subtree = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let dname_query = DomainName::from_absolute_str("leaf.alias.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(64),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    subtree.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("invalid.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let dname_rrset = image
            .find_rrset(&subtree, RecordType::Dname as u16, 1)
            .expect("DNAME rrset exists");
        let target = image
            .single_name_rrset_target(dname_rrset)
            .expect("DNAME target precomputes");

        assert_eq!(target.node_hint, ImageTargetNode::OutOfZone);
        let plan = image.lookup_response_plan(
            &dname_query,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.rcode(), Rcode::NoError);
        assert_eq!(plan.dynamic_answers.len(), 1);
        assert_eq!(
            plan.dynamic_answers[0].rdata.as_slice(),
            DomainName::from_absolute_str("leaf.invalid.")
                .unwrap()
                .to_wire()
                .as_slice()
        );
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(
                &dname_query,
                RecordType::A as u16,
                1
            ))
        );
    }

    #[test]
    fn cname_loop_tracking_borrows_original_query_name() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(55),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    alias,
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("ALIAS.Example.TEST.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let mixed_case_alias = DomainName::from_absolute_str("Alias.example.test.").unwrap();

        let plan = image.lookup_response_plan(
            &mixed_case_alias,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan.termination(), Some(LookupTermination::CnameLoop));
        assert_eq!(
            plan.section_record_counts().0,
            1,
            "partial CNAME chain is preserved on loop"
        );
        assert_eq!(
            plan.response_body_wire_upper_bound(),
            image.plan_wire_upper_bound(&plan),
            "SERVFAIL conversion preserves the carried answer body bound"
        );
        assert_eq!(
            plan.total_record_count(),
            plan.section_record_counts().0,
            "SERVFAIL conversion derives total count from the remaining partial-answer count"
        );
    }

    #[test]
    fn cname_loop_tracking_detects_existing_target_node_cycle() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let first = DomainName::from_absolute_str("first.example.test.").unwrap();
        let second = DomainName::from_absolute_str("second.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(63),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    first.clone(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("second.example.test.")],
                ),
                Rrset::new(
                    second,
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("first.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let plan = image.lookup_response_plan(
            &first,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan.termination(), Some(LookupTermination::CnameLoop));
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&first, RecordType::A as u16, 1)
            )
        );
    }

    #[test]
    fn dnssec_rrsig_augmentation_uses_precomputed_record_spans() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(47),
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
                    RecordType::Dnskey as u16,
                    1,
                    300,
                    vec![vec![1, 1, 3, 8, 0xaa]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![
                        rrsig_rdata(RecordType::A),
                        rrsig_rdata(RecordType::Dnskey),
                        rrsig_rdata(RecordType::Rrsig),
                        rrsig_rdata(RecordType::Nsec),
                    ],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let a_rrset = image
            .find_rrset(&qname, RecordType::A as u16, 1)
            .expect("A rrset exists");
        let precomputed = image.precomputed_rrsig_records(a_rrset).collect::<Vec<_>>();
        let rrsig_rrset = image
            .find_rrset(&qname, RecordType::Rrsig as u16, 1)
            .expect("RRSIG rrset exists");
        let dnskey_rrset = image
            .find_rrset(&qname, RecordType::Dnskey as u16, 1)
            .expect("DNSKEY rrset exists");

        assert_eq!(precomputed.len(), 1);
        assert!(image.has_precomputed_rrsig_relations(a_rrset.0 as usize));
        assert!(!image.has_precomputed_rrsig_relations(rrsig_rrset.0 as usize));
        assert_eq!(
            image.precomputed_rrsig_records(dnskey_rrset).count(),
            1,
            "covered RRsets sorted after RRSIG must resolve through the completed index"
        );
        assert!(
            image
                .precomputed_rrsig_records(rrsig_rrset)
                .next()
                .is_none(),
            "compile-time relation builder should not emit selected RRSIG relations for an RRSIG RRset"
        );
        assert_eq!(
            rrsig_type_covered_rdata(
                image.blob(
                    &image.rdata,
                    image.records[precomputed[0].record_index as usize]
                        .rdata
                        .blob_range(),
                ),
            ),
            Some(RecordType::A as u16)
        );
        let rrsig_record = image.records[precomputed[0].record_index as usize];
        let expected_wire_len = image
            .blob(
                &image.names,
                image.rrsets[precomputed[0].rrset_id.0 as usize].owner_wire,
            )
            .len()
            .saturating_add(10)
            .saturating_add(rrsig_record.rdata.len());
        assert_eq!(precomputed[0].rdata_len as usize, rrsig_record.rdata.len());
        assert_eq!(
            precomputed[0].owner_wire_len as usize,
            image
                .blob(
                    &image.names,
                    image.rrsets[precomputed[0].rrset_id.0 as usize].owner_wire
                )
                .len()
        );
        assert_eq!(
            image.selected_record_from_relation(precomputed[0]).wire_len as usize,
            expected_wire_len
        );
        assert_eq!(
            image
                .selected_record_from_relation(precomputed[0])
                .fixed_fields,
            image.rrsets[precomputed[0].rrset_id.0 as usize].fixed_fields,
            "selected DNSSEC handles should carry immutable fixed fields"
        );
        assert_eq!(
            image.selected_record_from_relation(precomputed[0]).rdata,
            rrsig_record.rdata,
            "selected DNSSEC handles should carry the immutable RDATA range"
        );

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        let augmented = image.augment_lookup_plan_with_dnssec(plan, &qname, 1, 100);

        assert_eq!(augmented.synthesized_answer_count(), 0);
        assert_eq!(augmented.dynamic_answers.len(), 0);
        let [.., PlanAnswer::SelectedRecord(selected)] = augmented.answer_items.as_slice() else {
            panic!("expected selected RRSIG answer record");
        };
        let signature = image.selected_wire_record(*selected);
        assert_eq!(selected.fixed_fields, signature.fixed_fields);
        assert_eq!(selected.rdata.rdlength_bytes(), signature.rdlength_bytes);
        assert_eq!(selected.rdata.rdata_encoding, signature.rdata_encoding);
        assert_eq!(
            u16::from_be_bytes([signature.fixed_fields[0], signature.fixed_fields[1]]),
            RecordType::Rrsig as u16
        );
        assert_eq!(
            selected.wire_len as usize,
            signature
                .owner_wire
                .len()
                .saturating_add(10)
                .saturating_add(signature.rdata.len())
        );
        assert_eq!(
            image.selected_record_wire_len(*selected),
            selected.wire_len as usize
        );
        assert_eq!(
            rrsig_type_covered_rdata(signature.rdata),
            Some(RecordType::A as u16)
        );

        let rrsig_plan = image.lookup_response_plan(
            &qname,
            RecordType::Rrsig as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        let rrsig_augmented = image.augment_lookup_plan_with_dnssec(rrsig_plan, &qname, 1, 100);
        assert!(
            !rrsig_augmented
                .answer_items
                .iter()
                .any(|item| matches!(item, PlanAnswer::SelectedRecord(_))),
            "RRSIG query augmentation should rely on the empty compiled relation slice, not a runtime RRset-type guard"
        );
    }

    #[test]
    fn dnssec_rrsig_augmentation_deduplicates_selected_record_handles() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(48),
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
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10,
                    ]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::A), rrsig_rdata(RecordType::Aaaa)],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let a_rrset = image
            .find_rrset(&qname, RecordType::A as u16, 1)
            .expect("A rrset exists");
        let aaaa_rrset = image
            .find_rrset(&qname, RecordType::Aaaa as u16, 1)
            .expect("AAAA rrset exists");
        let mut plan = ZoneImageLookupPlan::positive();
        plan.push_answer_rrset(a_rrset, image.rrset_plan_metrics(a_rrset));
        plan.push_authority_rrset(a_rrset, image.rrset_plan_metrics(a_rrset));

        let augmented = image.augment_lookup_plan_with_dnssec(plan, &qname, 1, 100);

        assert_eq!(selected_answer_count(&augmented.answer_items), 1);
        assert_eq!(augmented.dynamic_answers.len(), 0);
        assert_eq!(augmented.selected_authorities.len(), 0);
        assert_eq!(augmented.selected_additionals.len(), 0);

        let mut section_plan = ZoneImageLookupPlan::positive();
        section_plan.push_authority_rrset(a_rrset, image.rrset_plan_metrics(a_rrset));
        section_plan.push_additional_rrset(aaaa_rrset, image.rrset_plan_metrics(aaaa_rrset));
        let section_augmented = image.augment_lookup_plan_with_dnssec(section_plan, &qname, 1, 100);

        assert_eq!(selected_answer_count(&section_augmented.answer_items), 0);
        assert_eq!(section_augmented.dynamic_answers.len(), 0);
        assert_eq!(section_augmented.selected_authorities.len(), 1);
        assert_eq!(section_augmented.selected_additionals.len(), 1);
        let authority_signature =
            image.selected_wire_record(section_augmented.selected_authorities[0]);
        let additional_signature =
            image.selected_wire_record(section_augmented.selected_additionals[0]);
        assert_eq!(
            rrsig_type_covered_rdata(authority_signature.rdata),
            Some(RecordType::A as u16)
        );
        assert_eq!(
            rrsig_type_covered_rdata(additional_signature.rdata),
            Some(RecordType::Aaaa as u16)
        );
    }

    #[test]
    fn compile_reports_shape_statistics() {
        let snapshot = sample_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let stats = image.stats();

        assert_eq!(stats.rrset_count, 3);
        assert_eq!(stats.record_count, 4);
        assert_eq!(stats.name_count, 3);
        assert!(stats.node_count >= stats.name_count);
        assert!(stats.edge_count >= 2);
        assert_eq!(
            stats.child_hash_slot_bytes,
            stats.child_hash_slot_count * mem::size_of::<u16>()
        );
        assert!(stats.max_child_fanout >= 1);
        assert!(stats.max_rrsets_per_name >= 1);
        assert!(stats.max_depth >= 1);
        assert!(stats.rdata_bytes > 0);
        assert!(stats.wire_bytes > stats.rdata_bytes);
        assert!(stats.hot_bytes > 0);
        assert!(stats.cold_bytes > 0);
        assert!(stats.bytes_per_record > 0);
        let apex_soa = image
            .find_rrset_at_node(0, RecordType::Soa as u16, 1)
            .expect("sample apex SOA is indexed");
        assert_eq!(image.apex_in_soa_rrset, Some(apex_soa));
        assert_eq!(image.soa_rrset(1), Some(apex_soa));
        assert_eq!(image.soa_rrset(255), Some(apex_soa));
    }
