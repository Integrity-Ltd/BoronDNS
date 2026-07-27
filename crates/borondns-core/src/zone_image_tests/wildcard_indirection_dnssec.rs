    #[test]
    fn wildcard_owner_override_plan_emits_wire_and_additionals_from_handles() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let wildcard = DomainName::from_absolute_str("*.wild.example.test.").unwrap();
        let mail = DomainName::from_absolute_str("mail.example.test.").unwrap();
        let qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(44),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    wildcard,
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata("mail.example.test.")],
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

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::Mx as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert_eq!(plan.synthesized_answer_count(), 0);
        assert!(matches!(
            plan.answer_items.as_slice(),
            [PlanAnswer::RrsetWithOwner { .. }]
        ));
        assert_eq!(plan.owner_overrides.len(), 1);
        assert!(!plan.owner_overrides.spilled());
        assert!(!plan.owner_overrides[0].spilled());
        assert_eq!(plan.additional_rrsets().len(), 1);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&qname, RecordType::Mx as u16, 1)
            )
        );

        let mut visited = Vec::new();
        image.visit_plan_records(&plan, |record| {
            visited.push(record.owner_wire.to_vec());
        });
        assert_eq!(visited.first(), Some(&qname.to_wire()));
        assert!(
            visited.contains(
                &DomainName::from_absolute_str("mail.example.test.")
                    .unwrap()
                    .to_wire()
            )
        );
    }

    #[test]
    fn wildcard_non_target_rrsets_skip_additional_planning() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert!(matches!(
            plan.answer_items.as_slice(),
            [PlanAnswer::RrsetWithOwner { .. }]
        ));
        assert_eq!(plan.additional_rrsets(), &[]);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&qname, RecordType::A as u16, 1)
            )
        );
    }

    #[test]
    fn wildcard_direct_copy_owner_override_uses_compiled_body_length_for_accounting() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();

        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        let [
            PlanAnswer::RrsetWithOwner {
                rrset_id,
                owner_index,
            },
        ] = plan.answer_items.as_slice()
        else {
            panic!("expected one wildcard owner-override answer");
        };
        let rrset = image.rrsets[rrset_id.0 as usize];
        assert_ne!(
            rrset.direct_answer_body_len, 0,
            "wildcard A answer should have a compiled direct-copy body template"
        );
        let record_count = rrset.record_count as usize;
        assert_eq!(
            rrset.ownerless_wire_len as usize,
            record_count * (8 + 2 + 4),
            "compiled ownerless wire length should carry TYPE/CLASS/TTL, RDLENGTH, and A RDATA bytes"
        );
        let compiled_non_owner_wire_len = direct_answer_non_owner_wire_len(&rrset);
        let expected_answer_wire_len = plan.owner_overrides[usize::from(*owner_index)]
            .len()
            .saturating_mul(record_count)
            .saturating_add(compiled_non_owner_wire_len);

        assert_eq!(
            plan.answer_wire_upper_bound(),
            expected_answer_wire_len,
            "wildcard direct-copy owner override accounting should reuse the compiled non-owner body length"
        );
    }

    #[test]
    fn indirection_additionals_are_gated_by_target_rrset_type() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let canonical = DomainName::from_absolute_str("canonical.example.test.").unwrap();
        let service_target = DomainName::from_absolute_str("target.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(64),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    alias.clone(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("canonical.example.test.")],
                ),
                Rrset::new(
                    canonical.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    canonical,
                    RecordType::Srv as u16,
                    1,
                    300,
                    vec![srv_rdata("target.example.test.")],
                ),
                Rrset::new(
                    service_target,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 11]],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let address_plan = image.lookup_response_plan(
            &alias,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &address_plan),
            [RecordType::Cname as u16, RecordType::A as u16]
        );
        assert_eq!(address_plan.additional_rrsets(), &[]);
        assert_eq!(
            image.plan_summary(&address_plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&alias, RecordType::A as u16, 1)
            )
        );

        let service_plan = image.lookup_response_plan(
            &alias,
            RecordType::Srv as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan_answer_types(&image, &service_plan),
            [RecordType::Cname as u16, RecordType::Srv as u16]
        );
        assert_eq!(service_plan.additional_rrsets().len(), 1);
        assert_eq!(
            image.plan_summary(&service_plan).expect("plan summarizes"),
            lookup_summary(
                &snapshot
                    .offline_oracle()
                    .lookup(&alias, RecordType::Srv as u16, 1)
            )
        );
    }

    #[test]
    fn dnssec_denial_candidate_reuses_answer_presence_classification() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");

        let exact_qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let exact_plan = image.lookup_response_plan(
            &exact_qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(exact_plan.answer_items.is_empty());
        assert!(exact_plan.answer_has_records());
        let exact_denial_candidate =
            plan_is_nodata_candidate(&exact_plan, exact_plan.answer_has_records())
                || plan_is_nxdomain_candidate(&exact_plan, exact_plan.answer_has_records());
        assert!(!exact_denial_candidate);
        assert!(!plan_is_wildcard_synthesis_candidate(
            &exact_plan,
            exact_plan.answer_has_records()
        ));

        let wildcard_qname = DomainName::from_absolute_str("host.wild.example.test.").unwrap();
        let wildcard_plan = image.lookup_response_plan(
            &wildcard_qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(!wildcard_plan.answer_items.is_empty());
        assert!(wildcard_plan.answer_has_records());
        let wildcard_denial_candidate =
            plan_is_nodata_candidate(&wildcard_plan, wildcard_plan.answer_has_records())
                || plan_is_nxdomain_candidate(&wildcard_plan, wildcard_plan.answer_has_records());
        assert!(!wildcard_denial_candidate);
        assert!(plan_is_wildcard_synthesis_candidate(
            &wildcard_plan,
            wildcard_plan.answer_has_records()
        ));

        let dname_qname = DomainName::from_absolute_str("leaf.subtree.example.test.").unwrap();
        let dname_plan = image.lookup_response_plan(
            &dname_qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(
            !dname_plan.dynamic_answers.is_empty(),
            "DNAME positive plan should keep a synthesized CNAME answer"
        );
        assert!(dname_plan.answer_has_records());
        let dname_denial_candidate =
            plan_is_nodata_candidate(&dname_plan, dname_plan.answer_has_records())
                || plan_is_nxdomain_candidate(&dname_plan, dname_plan.answer_has_records());
        assert!(!dname_denial_candidate);
        assert!(!plan_is_wildcard_synthesis_candidate(
            &dname_plan,
            dname_plan.answer_has_records()
        ));

        let nxdomain_qname = DomainName::from_absolute_str("missing.example.test.").unwrap();
        let nxdomain_plan = image.lookup_response_plan(
            &nxdomain_qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(!nxdomain_plan.answer_has_records());
        assert!(nxdomain_plan.authority_has_soa());
        assert!(nxdomain_plan.authority_first_rrset_is_soa());
        let nxdomain_denial_candidate =
            plan_is_nodata_candidate(&nxdomain_plan, nxdomain_plan.answer_has_records())
                || plan_is_nxdomain_candidate(&nxdomain_plan, nxdomain_plan.answer_has_records());
        assert!(nxdomain_denial_candidate);
        let servfail_plan = nxdomain_plan
            .clone()
            .into_servfail(LookupTermination::CnameLoop);
        assert!(!servfail_plan.authority_has_soa());
        assert!(!servfail_plan.authority_first_rrset_is_soa());
    }

    #[test]
    fn dnssec_nodata_augmentation_uses_plan_nodata_precondition() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            origin.clone(),
            Some(69),
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
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let nsec = image
            .find_rrset(&qname, RecordType::Nsec as u16, 1)
            .expect("NSEC rrset exists");
        let plan = image.lookup_response_plan(
            &qname,
            RecordType::Aaaa as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert!(!plan.answer_has_records());
        assert!(plan.authority_has_soa());

        let hinted_augmented = image.augment_lookup_plan_with_dnssec_ascii_lowercase_hint(
            plan.clone(),
            &qname,
            1,
            100,
            true,
        );
        let augmented = image.augment_lookup_plan_with_dnssec(plan, &qname, 1, 100);

        assert_eq!(
            hinted_augmented, augmented,
            "lowercase-hinted DNSSEC denial augmentation must match the conservative path"
        );

        assert!(
            augmented.authority_rrsets.contains(&nsec),
            "NODATA DNSSEC augmentation should trust the no-answer plan bit and append the exact-name NSEC proof"
        );
        assert!(augmented.dnssec_augmented());
    }

    #[test]
    fn dnssec_augmentation_skips_unsigned_images() {
        let snapshot = semantic_snapshot();
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );

        assert!(!image.dnssec_augmentation_possible);
        assert!(!image.dnssec_denial_augmentation_possible);
        assert!(!image.dnssec_referral_augmentation_possible);
        assert!(!image.dnssec_rrsig_augmentation_possible);
        assert_eq!(
            image.augment_lookup_plan_with_dnssec(plan.clone(), &qname, 1, 100),
            plan
        );

        let signed = ZoneImage::compile(&ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(65),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::A)],
                ),
            ],
        ))
        .expect("signed zone image compiles");
        assert!(signed.dnssec_augmentation_possible);
        assert!(!signed.dnssec_denial_augmentation_possible);
        assert!(!signed.dnssec_referral_augmentation_possible);
        assert!(signed.dnssec_rrsig_augmentation_possible);

        let denial_only = ZoneImage::compile(&ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(66),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
            ],
        ))
        .expect("denial-only zone image compiles");
        assert!(denial_only.dnssec_augmentation_possible);
        assert!(denial_only.dnssec_denial_augmentation_possible);
        assert!(!denial_only.dnssec_referral_augmentation_possible);
        assert!(!denial_only.dnssec_rrsig_augmentation_possible);

        let proof_family_only = ZoneImage::compile(&ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(67),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
            ],
        ))
        .expect("proof-family-only zone image compiles");
        let positive_plan = proof_family_only.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert!(positive_plan.answer_has_records());
        assert_eq!(
            proof_family_only.augment_lookup_plan_with_dnssec(
                positive_plan.clone(),
                &qname,
                1,
                100,
            ),
            positive_plan,
            "proof-family-only images should skip DNSSEC state for positive non-wildcard plans"
        );
    }

    #[test]
    fn dnssec_dedupe_state_seeding_follows_capability_gates() {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let signed = ZoneImage::compile(&ZoneSnapshot::active(
            origin.clone(),
            Some(67),
            vec![
                Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    qname.clone(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::A)],
                ),
            ],
        ))
        .expect("rrsig-only zone image compiles");
        let soa = signed
            .find_rrset(&origin, RecordType::Soa as u16, 1)
            .expect("SOA rrset exists");
        let mut plan = signed.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        plan.push_authority_rrset(soa, signed.rrset_plan_metrics(soa));
        let mut state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: u16::try_from(plan.authority_rrsets.len())
                .unwrap_or(u16::MAX),
            seen_selected_records: SmallVec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations: 100,
        };
        signed.add_rrsig_augmentations(&mut plan, &mut state);
        assert!(state.appended_authority_rrsets.is_empty());
        assert_eq!(state.seen_selected_records.len(), 1);

        let denial_only = ZoneImage::compile(&ZoneSnapshot::active(
            origin.clone(),
            Some(68),
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
        .expect("denial-only zone image compiles");
        let soa = denial_only
            .find_rrset(&origin, RecordType::Soa as u16, 1)
            .expect("SOA rrset exists");
        let nsec = denial_only
            .find_rrset(&origin, RecordType::Nsec as u16, 1)
            .expect("NSEC rrset exists");
        let mut plan = ZoneImageLookupPlan::positive();
        plan.push_authority_rrset(soa, denial_only.rrset_plan_metrics(soa));
        let mut state = ZoneImageDnssecState {
            appended_authority_rrsets: SmallVec::new(),
            original_authority_rrset_count: u16::try_from(plan.authority_rrsets.len())
                .unwrap_or(u16::MAX),
            seen_selected_records: SmallVec::new(),
            dnssec_augmented: false,
            nsec3_iterations_exceeded: false,
            nsec3_max_iterations: 100,
        };
        denial_only.push_authority_rrset(&mut plan, soa, &mut state);
        assert!(state.appended_authority_rrsets.is_empty());
        assert_eq!(plan.authority_rrsets.as_slice(), [soa]);
        assert!(!state.dnssec_augmented);
        denial_only.push_authority_rrset(&mut plan, nsec, &mut state);
        assert_eq!(state.appended_authority_rrsets.as_slice(), [nsec]);
        assert_eq!(plan.authority_rrsets.as_slice(), [soa, nsec]);
        assert!(state.dnssec_augmented);
        denial_only.push_authority_rrset(&mut plan, nsec, &mut state);
        assert_eq!(state.appended_authority_rrsets.as_slice(), [nsec]);
        assert_eq!(plan.authority_rrsets.as_slice(), [soa, nsec]);
        assert!(
            denial_only
                .initial_dnssec_seen_selected_records(&plan)
                .is_empty()
        );
    }
