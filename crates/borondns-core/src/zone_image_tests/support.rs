    fn sample_snapshot() -> ZoneSnapshot {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let mx = DomainName::from_absolute_str("mail.example.test.").unwrap();
        ZoneSnapshot::active(
            origin.clone(),
            Some(42),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 300, vec![soa_rdata()]),
                Rrset::new(
                    www,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10], vec![192, 0, 2, 11]],
                ),
                Rrset::new(mx, RecordType::A as u16, 1, 300, vec![vec![192, 0, 2, 20]]),
            ],
        )
    }

    fn semantic_snapshot() -> ZoneSnapshot {
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let www = DomainName::from_absolute_str("www.example.test.").unwrap();
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let wildcard = DomainName::from_absolute_str("*.wild.example.test.").unwrap();
        let leaf = DomainName::from_absolute_str("leaf.ent.example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let child_ns = DomainName::from_absolute_str("ns.child.example.test.").unwrap();
        let subtree = DomainName::from_absolute_str("subtree.example.test.").unwrap();
        let target = DomainName::from_absolute_str("www.target.example.test.").unwrap();
        ZoneSnapshot::active(
            origin.clone(),
            Some(43),
            vec![
                Rrset::new(origin, RecordType::Soa as u16, 1, 600, vec![soa_rdata()]),
                Rrset::new(
                    www.clone(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 10]],
                ),
                Rrset::new(
                    alias,
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![name_rdata("www.example.test.")],
                ),
                Rrset::new(
                    wildcard,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 55]],
                ),
                Rrset::new(
                    leaf,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 56]],
                ),
                Rrset::new(
                    child,
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![name_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    child_ns,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 57]],
                ),
                Rrset::new(
                    subtree,
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![name_rdata("target.example.test.")],
                ),
                Rrset::new(
                    target,
                    RecordType::A as u16,
                    1,
                    300,
                    vec![vec![192, 0, 2, 58]],
                ),
                Rrset::new(
                    www,
                    RecordType::Srv as u16,
                    1,
                    300,
                    vec![srv_rdata("target.example.test.")],
                ),
            ],
        )
    }

    fn assert_exact_matches_snapshot(
        snapshot: &ZoneSnapshot,
        image: &ZoneImage,
        qname: &DomainName,
        rr_type: u16,
        qclass: u16,
    ) {
        let ZoneImageLookupOutcome::Found(plan) = image.lookup_exact_plan(qname, rr_type, qclass)
        else {
            panic!("expected exact lookup to find rrtype {rr_type}");
        };
        let snapshot_lookup = snapshot.offline_oracle().lookup(qname, rr_type, qclass);
        assert_eq!(
            image.plan_summary(&plan).expect("plan summarizes").answers,
            records_summary(&snapshot_lookup.answers)
        );
    }

    fn lookup_summary(lookup: &crate::dns::LookupResult) -> ZoneImagePlanSummary {
        ZoneImagePlanSummary {
            rcode: lookup.rcode,
            authoritative: lookup.authoritative,
            answers: records_summary(&lookup.answers),
            authorities: records_summary(&lookup.authorities),
            additionals: records_summary(&lookup.additionals),
            termination: lookup.termination,
            nsec3_iterations_exceeded: lookup.nsec3_iterations_exceeded,
        }
    }

    fn records_summary(records: &[ResourceRecord]) -> ZoneImagePlanSectionSummary {
        let mut summary = ZoneImagePlanSectionAccumulator::default();
        for record in records {
            summary.digest = fnv1a_u64(
                summary.digest,
                hash_record_identity(
                    record.owner.canonical_key().as_bytes(),
                    zone_image_record_fixed_fields(record.rr_type, record.class, record.ttl),
                    &record.rdata,
                ),
            );
            summary.count += 1;
        }
        summary.finish()
    }

    fn plan_answer_types(image: &ZoneImage, plan: &ZoneImageLookupPlan) -> Vec<u16> {
        if plan.answer_items.is_empty() {
            return plan
                .answer_rrsets()
                .iter()
                .map(|rrset_id| image.rrsets[rrset_id.0 as usize].rr_type())
                .collect();
        }
        plan.answer_items
            .iter()
            .map(|item| {
                let rrset_id = match item {
                    PlanAnswer::Rrset(rrset_id) | PlanAnswer::RrsetWithOwner { rrset_id, .. } => {
                        rrset_id
                    }
                    PlanAnswer::DynamicRecord(_)
                    | PlanAnswer::SelectedRecord(_)
                    | PlanAnswer::SelectedRecordWithOwner { .. } => {
                        panic!("expected rrset answer")
                    }
                };
                image.rrsets[rrset_id.0 as usize].rr_type()
            })
            .collect()
    }

    fn plan_answer_classes_types(image: &ZoneImage, plan: &ZoneImageLookupPlan) -> Vec<(u16, u16)> {
        if plan.answer_items.is_empty() {
            return plan
                .answer_rrsets()
                .iter()
                .map(|rrset_id| {
                    let rrset = image.rrsets[rrset_id.0 as usize];
                    (rrset.class(), rrset.rr_type())
                })
                .collect();
        }
        plan.answer_items
            .iter()
            .map(|item| {
                let rrset_id = match item {
                    PlanAnswer::Rrset(rrset_id) | PlanAnswer::RrsetWithOwner { rrset_id, .. } => {
                        rrset_id
                    }
                    PlanAnswer::DynamicRecord(_)
                    | PlanAnswer::SelectedRecord(_)
                    | PlanAnswer::SelectedRecordWithOwner { .. } => {
                        panic!("expected rrset answer")
                    }
                };
                let rrset = image.rrsets[rrset_id.0 as usize];
                (rrset.class(), rrset.rr_type())
            })
            .collect()
    }

    fn name_rdata(name: &str) -> Vec<u8> {
        DomainName::from_absolute_str(name).unwrap().to_wire()
    }

    fn selected_answer_count(items: &[PlanAnswer]) -> usize {
        items
            .iter()
            .filter(|item| matches!(item, PlanAnswer::SelectedRecord(_)))
            .count()
    }

    fn mx_rdata(exchange: &str) -> Vec<u8> {
        let mut rdata = 10u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(&DomainName::from_absolute_str(exchange).unwrap().to_wire());
        rdata
    }

    fn svc_param_rdata(target: &str) -> Vec<u8> {
        let mut rdata = 1u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(&DomainName::from_absolute_str(target).unwrap().to_wire());
        rdata
    }

    fn srv_rdata(target: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&0u16.to_be_bytes());
        rdata.extend_from_slice(&0u16.to_be_bytes());
        rdata.extend_from_slice(&443u16.to_be_bytes());
        rdata.extend_from_slice(&DomainName::from_absolute_str(target).unwrap().to_wire());
        rdata
    }

    fn rrsig_rdata(type_covered: RecordType) -> Vec<u8> {
        let mut rdata = (type_covered as u16).to_be_bytes().to_vec();
        rdata.extend_from_slice(&[1, 5, 0, 3]);
        rdata.extend_from_slice(&300u32.to_be_bytes());
        rdata.extend_from_slice(&0u32.to_be_bytes());
        rdata.extend_from_slice(&0u32.to_be_bytes());
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(
            &DomainName::from_absolute_str("example.test.")
                .unwrap()
                .to_wire(),
        );
        rdata.extend_from_slice(b"signature");
        rdata
    }

    fn nsec3_rdata_with_next_hash(
        hash_algorithm: u8,
        iterations: u16,
        salt: &[u8],
        next_hash: &[u8],
    ) -> Vec<u8> {
        let mut rdata = vec![hash_algorithm, 0];
        rdata.extend_from_slice(&iterations.to_be_bytes());
        rdata.push(salt.len() as u8);
        rdata.extend_from_slice(salt);
        rdata.push(next_hash.len() as u8);
        rdata.extend_from_slice(next_hash);
        rdata.extend_from_slice(&[0, 1, 0x40]);
        rdata
    }

    fn nsec_rdata(next_owner: &str) -> Vec<u8> {
        let mut rdata = DomainName::from_absolute_str(next_owner).unwrap().to_wire();
        rdata.extend_from_slice(&[0, 1, 0x40]);
        rdata
    }

    fn soa_rdata() -> Vec<u8> {
        b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()
    }
