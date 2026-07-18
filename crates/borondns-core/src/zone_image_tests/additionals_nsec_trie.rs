    #[test]
    fn answer_additionals_use_precomputed_rrset_spans() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let mail = DomainName::from_absolute_str("mail.example.test.").unwrap();
        let service = DomainName::from_absolute_str("service.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(46),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    qname.clone(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![
                        mx_rdata("mail.example.test."),
                        mx_rdata("mail.example.test."),
                    ],
                ),
                Rrset::new(
                    mail.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 25]],
                ),
                Rrset::new(
                    service.clone(),
                    RecordType::Srv as u16,
                    1,
                    300,
                    vec![srv_rdata("missing-target.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let mx = image
            .find_rrset(&qname, RecordType::Mx as u16, 1)
            .expect("MX rrset exists");
        let precomputed = image.precomputed_additional_rrsets(mx).collect::<Vec<_>>();
        let span = image
            .rrset_relation_span(image.rrsets[mx.0 as usize].relation_span)
            .expect("MX has a relation span");

        assert_eq!(precomputed.len(), 1);
        assert_eq!(span.single_name_target_offset, NO_RELATION_OFFSET);
        assert_eq!(span.rrsig_offset, NO_RELATION_OFFSET);
        assert_eq!(span.referral_glue_offset, NO_RELATION_OFFSET);
        assert_eq!(span.delegation_dnssec_offset, NO_RELATION_OFFSET);
        assert_ne!(span.additional_address_offset, NO_RELATION_OFFSET);
        assert!(image.has_precomputed_additional_address_relations(mx.0 as usize));
        assert_eq!(
            image.rrsets[precomputed[0].0 as usize].rr_type(),
            RecordType::A as u16
        );
        assert!(!image.has_precomputed_additional_address_relations(precomputed[0].0 as usize));

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::Mx as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.additional_rrsets(), precomputed.as_slice());
        assert!(!plan.direct_answer_candidate());

        let address_plan = image.lookup_response_plan(
            &mail,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(address_plan.additional_rrsets().is_empty());
        assert!(address_plan.direct_answer_candidate());

        let srv = image
            .find_rrset(&service, RecordType::Srv as u16, 1)
            .expect("SRV rrset exists");
        assert!(!image.has_precomputed_additional_address_relations(srv.0 as usize));
        let plan_without_additionals = image.lookup_response_plan(
            &service,
            RecordType::Srv as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(plan_without_additionals.additional_rrsets().is_empty());
        assert_eq!(
            image
                .plan_summary(&plan_without_additionals)
                .expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&service, RecordType::Srv as u16, 1)
            )
        );
    }

    #[test]
    fn referral_glue_uses_precomputed_delegation_filtered_spans() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let child_ns = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let sibling_ns = DomainName::from_absolute_str("ns.sibling.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.child.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(49),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![
                        name_rdata("ns.child.example.test."),
                        name_rdata("ns.child.example.test."),
                        name_rdata("ns.sibling.example.test."),
                    ],
                ),
                Rrset::new(
                    child_ns,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
                Rrset::new(
                    sibling_ns,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 54]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let ns_rrset = image
            .find_rrset(&child, RecordType::Ns as u16, 1)
            .expect("delegation NS rrset exists");
        let glue = image
            .precomputed_referral_glue_rrsets(ns_rrset)
            .collect::<Vec<_>>();

        assert_eq!(glue.len(), 1);
        assert_eq!(
            image.rrset_owner_wire(glue[0]).expect("glue owner wire"),
            name_rdata("ns.child.example.test.").as_slice()
        );

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(plan.authority_rrsets(), &[ns_rrset]);
        assert_eq!(plan.additional_rrsets(), glue.as_slice());
    }

    #[test]
    fn referral_glue_delegation_owner_filter_uses_stored_wire() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("CHILD.Example.TEST.").unwrap();
        let child_ns = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let sibling_ns = DomainName::from_absolute_str("ns.sibling.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(149),
            vec![
                Rrset::new(
                    origin.clone(),
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
                    vec![
                        name_rdata("NS.Child.Example.TEST."),
                        name_rdata("ns.sibling.example.test."),
                    ],
                ),
                Rrset::new(
                    child_ns.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 53]],
                ),
                Rrset::new(
                    sibling_ns,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 54]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let ns_rrset = image
            .find_rrset(&child, RecordType::Ns as u16, 1)
            .expect("delegation NS rrset exists");
        let owner_wire = image
            .rrset_owner_wire(ns_rrset)
            .expect("delegation owner wire");
        let mut trailing = owner_wire.to_vec();
        trailing.push(0);
        let glue = image
            .precomputed_referral_glue_rrsets(ns_rrset)
            .collect::<Vec<_>>();
        let child_ns_wire = child_ns.to_wire();
        let sibling_ns_wire = DomainName::from_absolute_str("ns.sibling.example.test.")
            .unwrap()
            .to_wire();

        assert!(wire_name_is_equal_or_subdomain_of_wire(
            &child_ns_wire,
            owner_wire,
            child.label_count(),
        ));
        assert!(!wire_name_is_equal_or_subdomain_of_wire(
            &sibling_ns_wire,
            owner_wire,
            child.label_count(),
        ));
        assert!(!wire_name_is_equal_or_subdomain_of_wire(
            &child_ns_wire,
            &trailing,
            child.label_count(),
        ));
        assert_eq!(glue.len(), 1);
        assert_eq!(
            image.rrset_owner_wire(glue[0]).expect("glue owner wire"),
            child_ns.to_wire().as_slice()
        );
    }

    #[test]
    fn nsec_covering_lookup_uses_precomputed_range_keys() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("a.example.test.").unwrap();
        let covered = DomainName::from_absolute_str("M.Example.TEST.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(52),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    owner.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![name_rdata("z.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let nsec = image
            .find_rrset(&owner, RecordType::Nsec as u16, 1)
            .expect("NSEC rrset exists");

        assert_eq!(image.nsec_ranges.len(), 1);
        assert_eq!(image.stats().nsec_range_group_count, 1);
        assert_eq!(image.stats().nsec_indexed_range_group_count, 0);
        assert_eq!(image.nsec_ranges[0].rrset_id, nsec);
        assert_eq!(image.nsec_rrset_covering_name(&covered, 1), Some(nsec));
    }

    #[test]
    fn nsec_canonical_ring_uses_indexed_predecessor_lookup() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owners = ["a.example.test.", "m.example.test.", "z.example.test."]
            .map(|name| DomainName::from_absolute_str(name).unwrap());
        let mut rrsets = vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            600,
            vec![soa_rdata()],
        )];
        for index in 0..owners.len() {
            rrsets.push(Rrset::new(
                owners[index].clone(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata(&owners[(index + 1) % owners.len()].to_string())],
            ));
        }
        let image = ZoneImage::compile(&ZoneSnapshot::active(origin, Some(53), rrsets))
            .expect("zone image compiles");
        let a_nsec = image
            .find_rrset(&owners[0], RecordType::Nsec as u16, 1)
            .expect("a NSEC exists");
        let m_nsec = image
            .find_rrset(&owners[1], RecordType::Nsec as u16, 1)
            .expect("m NSEC exists");
        let z_nsec = image
            .find_rrset(&owners[2], RecordType::Nsec as u16, 1)
            .expect("z NSEC exists");

        assert_eq!(image.stats().nsec_range_group_count, 1);
        assert_eq!(image.stats().nsec_indexed_range_group_count, 1);
        assert_eq!(
            image.nsec_rrset_covering_name(
                &DomainName::from_absolute_str("b.example.test.").unwrap(),
                1,
            ),
            Some(a_nsec)
        );
        assert_eq!(
            image.nsec_rrset_covering_name(
                &DomainName::from_absolute_str("y.example.test.").unwrap(),
                1,
            ),
            Some(m_nsec)
        );
        assert_eq!(
            image.nsec_rrset_covering_name(
                &DomainName::from_absolute_str("0.example.test.").unwrap(),
                1,
            ),
            Some(z_nsec)
        );
        assert_eq!(
            image.nsec_rrset_covering_name(&owners[1], 1),
            None,
            "an NSEC owner is not covered by the preceding interval"
        );
    }

    #[test]
    fn nsec_canonical_order_keys_are_built_directly_from_wire_names() {
        let owner_wire = DomainName::from_absolute_str("A.Example.TEST.")
            .unwrap()
            .to_wire();
        let mut names = owner_wire.clone();
        let owner_key = push_canonical_order_name_arena_key(
            &mut names,
            BlobRange {
                offset: 0,
                len: owner_wire.len() as u32,
            },
            "names",
        )
        .expect("owner wire key builds")
        .expect("owner wire is valid");
        assert_eq!(
            blob_from_arena(&names, owner_key),
            b"\x04test\x07example\x01a\x00"
        );

        let mut rdata = nsec_rdata("Z.Example.TEST.");
        let mut arena = Vec::new();
        let next_key = push_canonical_order_wire_key(&mut arena, &rdata, false, "names")
            .expect("next-owner wire key builds")
            .expect("next owner is valid");
        assert_eq!(
            blob_from_arena(&arena, next_key),
            b"\x04test\x07example\x01z\x00"
        );
        assert!(
            push_canonical_order_wire_key(&mut arena, &rdata, true, "names")
                .expect("trailing NSEC bitmap is handled")
                .is_none(),
            "full-name mode rejects trailing NSEC bitmap bytes"
        );

        rdata[0] = 0xc0;
        assert!(
            push_canonical_order_wire_key(&mut arena, &rdata, false, "names")
                .expect("compressed NSEC next-owner wire is rejected without build error")
                .is_none()
        );
    }

    #[test]
    fn dnssec_authority_augmentation_seeds_existing_rrset_dedupe() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("a.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
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
                    owner.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![name_rdata("z.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let soa = image
            .find_rrset(&origin, RecordType::Soa as u16, 1)
            .expect("SOA exists");
        let nsec = image
            .find_rrset(&owner, RecordType::Nsec as u16, 1)
            .expect("NSEC exists");
        let mut plan = ZoneImageLookupPlan::nodata();
        plan.push_authority_rrset(soa, image.rrset_plan_metrics(soa));
        plan.push_authority_rrset(nsec, image.rrset_plan_metrics(nsec));

        let augmented = image.augment_lookup_plan_with_dnssec(plan, &owner, 1, 100);

        assert_eq!(
            augmented
                .authority_rrsets()
                .iter()
                .filter(|rrset| **rrset == nsec)
                .count(),
            1,
            "DNSSEC authority dedupe is seeded from existing authority rrsets"
        );
    }

    #[test]
    fn nsec3_hash_cache_reuses_hash_for_matching_parameters() {
        let name = DomainName::from_absolute_str("WWW.Example.TEST.").unwrap();
        let canonical = name.to_canonical_wire();
        let params = Nsec3Params {
            hash_algorithm: 1,
            iterations: 2,
            salt: &[0xaa, 0xbb],
        };
        let mut cache = SmallVec::<[(Nsec3Params<'_>, Option<[u8; 20]>); 1]>::new();

        let canonical_hash = nsec3_hash_canonical_wire(&canonical, params)
            .and_then(|hash| base32hex_no_padding_decode_lower(hash.as_bytes()))
            .expect("NSEC3 hash computes");
        let first_index = nsec3_hash_domain_cache_index(&name, params, &mut cache);
        let first = cache[first_index].1.expect("NSEC3 hash computes");
        let second_index = nsec3_hash_domain_cache_index(&name, params, &mut cache);
        let second = cache[second_index].1.expect("cached NSEC3 hash computes");

        assert_eq!(first.as_slice(), canonical_hash.as_slice());
        assert_eq!(first, second);
        assert_eq!(first_index, second_index);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn nsec3_owner_hash_bytes_decodes_owner_label_without_allocating() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let hash = [0x25; 20];
        let hash_label = base32hex_no_padding_lower(&hash);
        let owner = DomainName::from_absolute_str(&format!("{hash_label}.example.test.")).unwrap();

        assert_eq!(nsec3_owner_hash_bytes(&owner, &origin), Some(hash));
    }

    #[test]
    fn nsec3_owner_hash_bytes_matches_origin_suffix_case_insensitively() {
        let origin = DomainName::from_absolute_str("Example.TEST.").unwrap();
        let hash = [0xa5; 20];
        let hash_label = base32hex_no_padding_lower(&hash);
        let owner = DomainName::from_absolute_str(&format!("{hash_label}.example.test.")).unwrap();

        assert_eq!(nsec3_owner_hash_bytes(&owner, &origin), Some(hash));
    }

    #[test]
    fn nsec3_owner_hash_bytes_rejects_extra_owner_prefix_labels() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let hash = [0x5a; 20];
        let hash_label = base32hex_no_padding_lower(&hash);
        let owner =
            DomainName::from_absolute_str(&format!("extra.{hash_label}.example.test.")).unwrap();

        assert_eq!(nsec3_owner_hash_bytes(&owner, &origin), None);
    }

    #[test]
    fn nsec3_owner_wire_hash_bytes_rejects_malformed_or_compressed_owner_wire() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let hash = [0x3c; 20];
        let hash_label = base32hex_no_padding_lower(&hash);
        let owner = DomainName::from_absolute_str(&format!("{hash_label}.example.test.")).unwrap();
        let mut trailing = owner.to_wire();
        trailing.push(0);
        let mut compressed_suffix = Vec::with_capacity(hash_label.len() + 3);
        compressed_suffix.push(hash_label.len() as u8);
        compressed_suffix.extend_from_slice(hash_label.as_bytes());
        compressed_suffix.extend_from_slice(&[0xc0, 0x0c]);

        assert_eq!(nsec3_owner_wire_hash_bytes(&trailing, &origin), None);
        assert_eq!(
            nsec3_owner_wire_hash_bytes(&compressed_suffix, &origin),
            None
        );
    }

    #[test]
    fn nsec3_lookup_uses_precomputed_range_metadata() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("missing.example.test.").unwrap();
        let other_qname = DomainName::from_absolute_str("other.example.test.").unwrap();
        let params = Nsec3Params {
            hash_algorithm: 1,
            iterations: 0,
            salt: &[],
        };
        let owner_hash = nsec3_hash_domain(&qname, params).expect("hash computes");
        let other_owner_hash = nsec3_hash_domain(&other_qname, params).expect("hash computes");
        let owner = DomainName::from_absolute_str(&format!("{owner_hash}.example.test.")).unwrap();
        let other_owner =
            DomainName::from_absolute_str(&format!("{other_owner_hash}.example.test.")).unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(53),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    owner.clone(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_next_hash(1, 0, &[], &[0x80; 20])],
                ),
                Rrset::new(
                    other_owner.clone(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_next_hash(1, 0, &[], &[0x80; 20])],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let nsec3 = image
            .find_rrset(&owner, RecordType::Nsec3 as u16, 1)
            .expect("NSEC3 rrset exists");
        let mut iterations_exceeded = false;

        assert_eq!(image.nsec3_ranges.len(), 2);
        assert_eq!(image.nsec3_param_sets.len(), 1);
        assert_eq!(image.stats().nsec3_range_group_count, 1);
        assert_eq!(image.stats().nsec3_indexed_range_group_count, 0);
        assert!(
            image.nsec3_ranges.iter().all(|range| range.param_set == 0),
            "NSEC3 ranges with shared algorithm/iterations/salt should share one parameter set"
        );
        let range = image
            .nsec3_ranges
            .iter()
            .find(|range| range.rrset_id == nsec3)
            .expect("compiled NSEC3 range for queried owner exists");
        assert_eq!(
            range.owner_hash,
            base32hex_sha1_no_padding_decode_lower(owner_hash.as_bytes())
                .expect("owner hash decodes")
        );
        assert_eq!(
            image.nsec3_rrset_for_name(&qname, 1, &mut iterations_exceeded, 100, false),
            Some(nsec3)
        );
        assert_eq!(
            image.nsec3_rrset_for_name(&qname, 1, &mut iterations_exceeded, 100, true),
            Some(nsec3),
            "lowercase-hinted NSEC3 hashing must match the conservative path"
        );
        assert_eq!(
            image.nsec3_rrset_for_label_view(
                NameLabelView {
                    prefix: None,
                    labels: qname.labels(),
                    ascii_lowercase: false,
                },
                1,
                &mut iterations_exceeded,
                100,
            ),
            Some(nsec3)
        );
        assert_eq!(
            image.nsec3_rrset_for_label_view(
                NameLabelView {
                    prefix: None,
                    labels: qname.labels(),
                    ascii_lowercase: true,
                },
                1,
                &mut iterations_exceeded,
                100,
            ),
            Some(nsec3)
        );
        assert_eq!(
            image.nsec3_rrset_for_wire_name(&qname.to_wire(), 1, &mut iterations_exceeded, 100),
            Some(nsec3)
        );
        assert!(!iterations_exceeded);
    }

    #[test]
    fn nsec3_hash_ring_uses_indexed_exact_predecessor_and_wrap_lookup() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let hashes = [[0x10; 20], [0x80; 20], [0xf0; 20]];
        let owners = hashes.map(|hash| {
            DomainName::from_absolute_str(&format!(
                "{}.example.test.",
                base32hex_no_padding_lower(&hash)
            ))
            .unwrap()
        });
        let mut rrsets = vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            600,
            vec![soa_rdata()],
        )];
        for index in 0..hashes.len() {
            rrsets.push(Rrset::new(
                owners[index].clone(),
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata_with_next_hash(
                    1,
                    0,
                    &[],
                    &hashes[(index + 1) % hashes.len()],
                )],
            ));
        }
        let image = ZoneImage::compile(&ZoneSnapshot::active(origin, Some(54), rrsets))
            .expect("zone image compiles");
        let ids = owners.map(|owner| {
            image
                .find_rrset(&owner, RecordType::Nsec3 as u16, 1)
                .expect("NSEC3 rrset exists")
        });
        let group = &image.nsec3_range_groups[0];

        assert_eq!(image.stats().nsec3_range_group_count, 1);
        assert_eq!(image.stats().nsec3_indexed_range_group_count, 1);
        assert_eq!(
            image.nsec3_range_match(group, &hashes[1]),
            Some((ids[1], true))
        );
        assert_eq!(
            image.nsec3_range_match(group, &[0x90; 20]),
            Some((ids[1], false))
        );
        assert_eq!(
            image.nsec3_range_match(group, &[0x05; 20]),
            Some((ids[2], false))
        );
    }

    #[test]
    fn widest_child_lookup_profile_exports_sorted_max_fanout_labels() {
        let image = ZoneImage::compile(&sample_snapshot()).expect("zone image compiles");
        let profile = image
            .widest_child_lookup_profile()
            .expect("profile exists for non-empty image");

        assert!(profile.fanout >= 2);
        assert_eq!(profile.fanout, profile.labels.len());
        assert!(
            profile
                .labels
                .windows(2)
                .all(|labels| labels[0] < labels[1])
        );
    }

    #[test]
    fn closest_encloser_proof_name_uses_compiled_trie_depth() {
        let image = ZoneImage::compile(&semantic_snapshot()).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("absent.ent.example.test.").unwrap();
        let (_, closest_node) = image.query_node_handles(&qname, true);

        assert_eq!(
            image.closest_encloser_proof_name(&qname),
            Some(DomainName::from_absolute_str("ent.example.test.").unwrap())
        );
        assert_eq!(
            image.closest_encloser_proof_name_from_node(&qname, closest_node),
            Some(DomainName::from_absolute_str("ent.example.test.").unwrap())
        );
        assert_eq!(
            image
                .closest_encloser_labels_from_node(&qname, closest_node)
                .expect("closest labels"),
            DomainName::from_absolute_str("ent.example.test.")
                .unwrap()
                .labels()
        );
        assert_eq!(
            image.closest_encloser_proof_name(
                &DomainName::from_absolute_str("absent.wild.example.test.").unwrap()
            ),
            Some(DomainName::from_absolute_str("wild.example.test.").unwrap())
        );
        assert_eq!(
            image.closest_encloser_proof_name(
                &DomainName::from_absolute_str("absent.example.test.").unwrap()
            ),
            Some(DomainName::from_absolute_str("example.test.").unwrap())
        );
    }

    #[test]
    fn query_node_handles_return_exact_and_closest_in_one_walk() {
        let image = ZoneImage::compile(&semantic_snapshot()).expect("zone image compiles");
        let exact = image
            .find_node(&DomainName::from_absolute_str("ent.example.test.").unwrap())
            .expect("exact node exists");
        let root = image
            .find_node(&DomainName::from_absolute_str("example.test.").unwrap())
            .expect("root node exists");

        assert_eq!(
            image.query_node_handles(
                &DomainName::from_absolute_str("ent.example.test.").unwrap(),
                true,
            ),
            (Some(exact), Some(exact))
        );
        assert_eq!(
            image.query_node_handles(
                &DomainName::from_absolute_str("absent.ent.example.test.").unwrap(),
                true,
            ),
            (None, Some(exact))
        );
        assert_eq!(
            image.query_node_handles(
                &DomainName::from_absolute_str("outside.example.invalid.").unwrap(),
                true,
            ),
            (None, None)
        );
        assert_eq!(
            image.query_node_handles(
                &DomainName::from_absolute_str("example.test.").unwrap(),
                true,
            ),
            (Some(root), Some(root))
        );
    }

    #[test]
    fn query_node_handles_lowercase_hint_matches_canonical_path() {
        let image = ZoneImage::compile(&semantic_snapshot()).expect("zone image compiles");
        let lowercase = DomainName::from_absolute_str("ent.example.test.").unwrap();
        let mixed_case = DomainName::from_absolute_str("ENT.Example.Test.").unwrap();

        assert_eq!(
            image.query_node_handles(&lowercase, true),
            image.query_node_handles(&mixed_case, false)
        );
        assert_eq!(
            image.lookup_response_plan_with_ascii_lowercase_hint(
                &lowercase,
                RecordType::A as u16,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Minimal,
                true,
            ),
            image.lookup_response_plan(
                &mixed_case,
                RecordType::A as u16,
                1,
                DEFAULT_MAX_CNAME_CHAIN,
                AnyResponseMode::Minimal,
            )
        );
        assert_eq!(
            image.lookup_direct_answer_plan_with_ascii_lowercase_hint(
                &lowercase,
                RecordType::A as u16,
                1,
                true,
            ),
            image.lookup_direct_answer_plan(&mixed_case, RecordType::A as u16, 1)
        );
    }

    #[test]
    fn single_child_lookup_uses_case_insensitive_direct_edge_check() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let single = DomainName::from_absolute_str("only.example.test.").unwrap();
        let image = ZoneImage::compile(&ZoneSnapshot::active(
            origin,
            Some(55),
            vec![Rrset::new(
                single,
                RecordType::A as u16,
                1,
                300,
                vec![vec![192, 0, 2, 55]],
            )],
        ))
        .expect("single-child image compiles");

        assert!(matches!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("ONLY.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            ZoneImageLookupOutcome::Found(_)
        ));
        assert_eq!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("other.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            ZoneImageLookupOutcome::NameError
        );
    }

    #[test]
    fn small_child_lookup_uses_case_insensitive_linear_scan() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let image = ZoneImage::compile(&ZoneSnapshot::active(
            origin,
            Some(56),
            ["alpha", "bravo", "charlie", "delta"]
                .into_iter()
                .map(|label| {
                    Rrset::new(
                        DomainName::from_absolute_str(&format!("{label}.example.test.")).unwrap(),
                        RecordType::A as u16,
                        1,
                        300,
                        vec![vec![192, 0, 2, 56]],
                    )
                })
                .collect(),
        ))
        .expect("small-child image compiles");

        assert!(matches!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("CHARLIE.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            ZoneImageLookupOutcome::Found(_)
        ));
        assert_eq!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("echo.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            ZoneImageLookupOutcome::NameError
        );
    }

    #[test]
    fn high_fanout_child_hash_index_preserves_exact_lookup() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let mut rrsets = vec![Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            600,
            vec![soa_rdata()],
        )];
        for index in 0..CHILD_HASH_FANOUT_THRESHOLD {
            rrsets.push(Rrset::new(
                DomainName::from_absolute_str(&format!("host{index}.example.test.")).unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![vec![192, 0, 2, 1]],
            ));
        }
        let image =
            ZoneImage::compile(&ZoneSnapshot::active(origin, Some(54), rrsets)).expect("compiles");

        assert_eq!(image.child_hashes.len(), 1);
        assert_eq!(image.nodes[0].child_hash, 0);
        assert!(image.child_hash_slots_u16.len() >= CHILD_HASH_FANOUT_THRESHOLD);
        assert!(image.child_hash_slots_u32.is_empty());
        for qname in [
            "host0.example.test.",
            "HOST0.example.test.",
            "host512.example.test.",
            "host1023.example.test.",
        ] {
            assert!(matches!(
                image.lookup_exact_plan(
                    &DomainName::from_absolute_str(qname).unwrap(),
                    RecordType::A as u16,
                    1,
                ),
                ZoneImageLookupOutcome::Found(_)
            ));
        }
        assert_eq!(
            image.lookup_exact_plan(
                &DomainName::from_absolute_str("absent.example.test.").unwrap(),
                RecordType::A as u16,
                1,
            ),
            ZoneImageLookupOutcome::NameError
        );
    }

    #[test]
    fn single_name_target_precompute_uses_whole_uncompressed_wire_names() {
        let target = DomainName::from_absolute_str("Target.Example.TEST.").unwrap();
        let target_wire = target.to_wire();
        assert_eq!(single_name_rdata_bytes(&target_wire), Some(target));

        let mut trailing = target_wire.clone();
        trailing.push(0);
        assert_eq!(single_name_rdata_bytes(&trailing), None);
        assert_eq!(single_name_rdata_bytes(&[0xc0, 0x00]), None);
    }

    #[test]
    fn cname_and_dname_targets_use_precomputed_single_name_table() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let target = DomainName::from_absolute_str("target.example.test.").unwrap();
        let subtree = DomainName::from_absolute_str("subtree.example.test.").unwrap();
        let dname_target = DomainName::from_absolute_str("target-tree.example.test.").unwrap();
        let dname_query = DomainName::from_absolute_str("leaf.subtree.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(50),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    alias.clone(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("target.example.test.")],
                ),
                Rrset::new(
                    alias.clone(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Cname)],
                ),
                Rrset::new(
                    target.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    subtree.clone(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("target-tree.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("leaf.target-tree.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 20]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let cname_rrset = image
            .find_rrset(&alias, RecordType::Cname as u16, 1)
            .expect("CNAME rrset exists");
        let dname_rrset = image
            .find_rrset(&subtree, RecordType::Dname as u16, 1)
            .expect("DNAME rrset exists");
        assert_eq!(
            image.rrsets[dname_rrset.0 as usize].owner_label_count as usize,
            subtree.labels().len()
        );

        let cname_target = image
            .single_name_rrset_target(cname_rrset)
            .expect("CNAME target is precomputed");
        let cname_span = image
            .rrset_relation_span(image.rrsets[cname_rrset.0 as usize].relation_span)
            .expect("CNAME has a relation span");
        let target_wire = target.to_wire();
        assert_eq!(cname_target.name, target);
        assert_eq!(image.single_name_target_wire(cname_target), target_wire);
        assert_eq!(image.rdata_blob(cname_target.rdata), target_wire.as_slice());
        assert_eq!(cname_span.single_name_target_offset, 0);
        assert_ne!(cname_span.rrsig_offset, NO_RELATION_OFFSET);
        assert_eq!(cname_span.referral_glue_offset, NO_RELATION_OFFSET);
        assert_eq!(cname_span.delegation_dnssec_offset, NO_RELATION_OFFSET);
        assert_eq!(cname_span.additional_address_offset, NO_RELATION_OFFSET);
        assert_eq!(
            image
                .rrset_relations_of_kind(cname_rrset, ImageRrsetRelationKind::SingleNameTarget)
                .len(),
            1
        );
        assert_eq!(
            image
                .rrset_relations_of_kind(cname_rrset, ImageRrsetRelationKind::Rrsig)
                .len(),
            1
        );
        assert_eq!(
            cname_target.node_hint,
            ImageTargetNode::InZoneNode(image.find_node(&target).expect("target node exists"))
        );

        let dname_target_ref = image
            .single_name_rrset_target(dname_rrset)
            .expect("DNAME target is precomputed");
        assert_eq!(dname_target_ref.name, dname_target);
        assert_eq!(
            dname_target_ref.node_hint,
            ImageTargetNode::InZoneNode(
                image
                    .find_node(&dname_target)
                    .expect("DNAME replacement target node exists")
            )
        );
        assert_eq!(
            dname_query.with_replaced_wire_suffix(
                image
                    .rrset_owner_wire(dname_rrset)
                    .expect("DNAME owner wire"),
                &dname_target_ref.name,
            ),
            Some(DomainName::from_absolute_str("leaf.target-tree.example.test.").unwrap())
        );

        let cname_plan = image.lookup_response_plan(
            &alias,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            image.plan_summary(&cname_plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&alias, RecordType::A as u16, 1)
            )
        );

        let dname_plan = image.lookup_response_plan(
            &dname_query,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(dname_plan.dynamic_answers.len(), 1);
        let synthesized = &dname_plan.dynamic_answers[0];
        assert_eq!(
            synthesized.fixed_fields,
            synthesized_cname_fixed_fields_from_rrset(image.rrsets[dname_rrset.0 as usize])
        );
        assert_eq!(
            synthesized.rdata_encoding,
            PackedRdataEncoding::single_name(),
            "DNAME synthesized CNAME RDATA should carry the checked single-name encoding"
        );
        assert!(
            !synthesized.owner_wire.spilled(),
            "common DNAME synthesized owner wire should stay inline"
        );
        assert!(
            !synthesized.rdata.spilled(),
            "common DNAME synthesized target wire should stay inline"
        );
        assert_eq!(
            synthesized.rdata.as_slice(),
            DomainName::from_absolute_str("leaf.target-tree.example.test.")
                .unwrap()
                .to_wire()
                .as_slice()
        );
        assert_eq!(
            image.plan_summary(&dname_plan).expect("plan summarizes"),
            lookup_summary(&snapshot.offline_oracle().lookup(
                &dname_query,
                RecordType::A as u16,
                1
            ))
        );
    }
