#[test]
fn qtype_any_defaults_to_minimal_real_rrset_response() {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Mx as u16,
                1,
                300,
                vec![mx_rdata(10, "mail.example.test.")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            ),
        ],
    ));

    let packet = query(b"\x03www\x07example\x04test\x00", 255, 1);
    let response = store_response(&packet, &store);

    assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
    assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
    assert!(!response_answer_types(&response).contains(&13));
}

#[test]
fn qtype_any_full_mode_returns_all_owner_rrsets() {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Mx as u16,
                1,
                300,
                vec![mx_rdata(10, "mail.example.test.")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            ),
        ],
    ));

    let packet = query(b"\x03www\x07example\x04test\x00", 255, 1);
    let response = store_response_with_options(
        &packet,
        &store,
        AnswerOptions {
            transport: Transport::Udp,
            max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
            max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
            nsec3_max_iterations: 100,
            tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Full,
            nsid: &[],
            chaos: ChaosOptions::default(),
            dns_cookie: None,
        },
    );

    assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
    assert_eq!(
        response_answer_types(&response),
        vec![RecordType::A as u16, RecordType::Mx as u16]
    );
}

#[test]
fn qtype_any_full_mode_omits_dnssec_proofs_and_signatures_without_do() {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::A)],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("www.example.test.")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata(1)],
            ),
        ],
    ));

    let packet = query(b"\x03www\x07example\x04test\x00", 255, 1);
    let response = store_response_with_options(
        &packet,
        &store,
        AnswerOptions {
            transport: Transport::Udp,
            max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
            max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
            nsec3_max_iterations: 100,
            tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Full,
            nsid: &[],
            chaos: ChaosOptions::default(),
            dns_cookie: None,
        },
    );

    assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
    assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
}

#[test]
fn answers_nodata_with_soa_for_existing_name() {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        ));

    let packet = query(
        b"\x03www\x07example\x04test\x00",
        RecordType::Aaaa as u16,
        1,
    );
    let response = store_response(&packet, &store);
    assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
    assert_eq!(
        response_authority_ttls(&response, RecordType::Soa as u16),
        vec![300]
    );
}

#[test]
fn do_nodata_for_existing_name_includes_nsec_and_covering_rrsig() {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("www.example.test.")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
        ],
    ));
    let mut packet = query(
        b"\x03www\x07example\x04test\x00",
        RecordType::Aaaa as u16,
        1,
    );
    append_opt(&mut packet, 4096, 0x8000, &[]);

    let response = store_response(&packet, &store);

    assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert_eq!(
        response_authority_types(&response),
        vec![
            RecordType::Soa as u16,
            RecordType::Nsec as u16,
            RecordType::Rrsig as u16,
        ]
    );
    assert_eq!(response_opt_ttl(&response), Some(0x8000));
}

#[test]
fn do_nodata_rejects_covering_nsec3_when_an_exact_match_is_required() {
    let covering_owner =
        DomainName::from_absolute_str("00000000000000000000000000000000.example.test.").unwrap();
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Nsec3Param as u16,
                1,
                300,
                vec![nsec3param_rdata(1)],
            ),
            Rrset::new(
                DomainName::from_absolute_str("target.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                vec![b"\x07present".to_vec()],
            ),
            Rrset::new(
                covering_owner.clone(),
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata_with_next_hash([0xff; 20])],
            ),
            Rrset::new(
                covering_owner,
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec3)],
            ),
        ],
    ));
    let mut packet = query(
        b"\x06target\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 4096, 0x8000, &[]);

    let response = store_response(&packet, &store);

    assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
}

#[test]
fn non_do_nodata_omits_nsec_dnssec_augmentation() {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("zzz.example.test.")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
        ],
    ));
    let packet = query(
        b"\x03www\x07example\x04test\x00",
        RecordType::Aaaa as u16,
        1,
    );

    let response = store_response(&packet, &store);

    assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
    assert_eq!(
        response_authority_types(&response),
        vec![RecordType::Soa as u16]
    );
}

#[test]
fn answers_nxdomain_with_soa_for_missing_name() {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()],
            )],
        ));

    let packet = query(
        b"\x07missing\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );
    let response = store_response(&packet, &store);
    assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
    assert_eq!(
        response_authority_ttls(&response, RecordType::Soa as u16),
        vec![300]
    );
}

#[test]
fn do_nxdomain_includes_nsec_denial_proofs_and_covering_rrsigs() {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("a.example.test.")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("a.example.test.").unwrap(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("example.test.")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
            Rrset::new(
                DomainName::from_absolute_str("a.example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
        ],
    ));
    let mut packet = query(
        b"\x07missing\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 4096, 0x8000, &[]);

    let response = store_response(&packet, &store);

    assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert_eq!(
        response_authority_types(&response),
        vec![
            RecordType::Soa as u16,
            RecordType::Nsec as u16,
            RecordType::Nsec as u16,
            RecordType::Rrsig as u16,
            RecordType::Rrsig as u16,
        ]
    );
    assert_eq!(response_opt_ttl(&response), Some(0x8000));
}

#[test]
fn incremental_overlay_nsec_nxdomain_matches_fresh_compact_image() {
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let old_ring_owner = DomainName::from_absolute_str("a.example.test.").unwrap();
    let new_ring_owner = DomainName::from_absolute_str("m.example.test.").unwrap();
    let base = ZoneSnapshot::active(
        origin.clone(),
        Some(1),
        vec![
            Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                origin.clone(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("a.example.test.")],
            ),
            Rrset::new(
                old_ring_owner.clone(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("example.test.")],
            ),
            Rrset::new(
                origin.clone(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
            Rrset::new(
                old_ring_owner.clone(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
        ],
    );
    let mut soa2 = soa_rdata();
    let (_, mname_len) = DomainName::parse(&soa2, 0).unwrap();
    let (_, rname_len) = DomainName::parse(&soa2, mname_len).unwrap();
    let serial_offset = mname_len + rname_len;
    soa2[serial_offset..serial_offset + 4].copy_from_slice(&2u32.to_be_bytes());
    let updated = base.with_cow_rrset_replacements(
        2,
        vec![
            (
                origin.canonical_key(),
                RecordType::Soa as u16,
                1,
                Some(Rrset::new(
                    origin.clone(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa2],
                )),
            ),
            (
                origin.canonical_key(),
                RecordType::Nsec as u16,
                1,
                Some(Rrset::new(
                    origin,
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("m.example.test.")],
                )),
            ),
            (
                old_ring_owner.canonical_key(),
                RecordType::Nsec as u16,
                1,
                None,
            ),
            (
                old_ring_owner.canonical_key(),
                RecordType::Rrsig as u16,
                1,
                None,
            ),
            (
                new_ring_owner.canonical_key(),
                RecordType::Nsec as u16,
                1,
                Some(Rrset::new(
                    new_ring_owner.clone(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("example.test.")],
                )),
            ),
            (
                new_ring_owner.canonical_key(),
                RecordType::Rrsig as u16,
                1,
                Some(Rrset::new(
                    new_ring_owner,
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
                )),
            ),
        ],
    );
    let overlay_store = ZoneStore::with_publication_policy(crate::zone::ZonePublicationPolicy {
        strategy: crate::zone::ZonePublicationStrategy::Sharded,
        sharded_rrset_threshold: 1,
        ..crate::zone::ZonePublicationPolicy::default()
    });
    overlay_store.insert_snapshot(base);
    overlay_store.insert_snapshot(updated.clone());
    let compact_store = ZoneStore::new();
    compact_store.insert_snapshot(updated);
    for qname in [
        b"\x01b\x07example\x04test\x00".as_slice(),
        b"\x07missing\x07example\x04test\x00".as_slice(),
        b"\x01z\x07example\x04test\x00".as_slice(),
    ] {
        let mut packet = query(qname, RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);
        assert_semantic_response_eq(
            &store_response(&packet, &overlay_store),
            &store_response(&packet, &compact_store),
        );
    }
}

#[test]
fn do_nxdomain_includes_nsec3_denial_proofs_and_covering_rrsigs() {
    let mut rrsets = vec![
        Rrset::new(
            DomainName::from_absolute_str("example.test.").unwrap(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        ),
        Rrset::new(
            DomainName::from_absolute_str("example.test.").unwrap(),
            RecordType::Nsec3Param as u16,
            1,
            300,
            vec![nsec3param_rdata(1)],
        ),
        Rrset::new(
            DomainName::from_absolute_str("anchor.example.test.").unwrap(),
            RecordType::Txt as u16,
            1,
            300,
            vec![b"\x06anchor".to_vec()],
        ),
    ];
    rrsets.extend(nsec3_ring_rrsets(
        &["example.test.", "anchor.example.test."],
        "example.test.",
    ));
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        rrsets,
    ));
    let mut packet = query(
        b"\x07missing\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 4096, 0x8000, &[]);

    let response = store_response(&packet, &store);

    assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert_eq!(
        response_authority_types(&response),
        vec![
            RecordType::Soa as u16,
            RecordType::Nsec3 as u16,
            RecordType::Rrsig as u16
        ]
    );
    assert_eq!(response_opt_ttl(&response), Some(0x8000));
}

#[test]
fn incremental_overlay_nsec3_nxdomain_matches_fresh_compact_image() {
    let origin = DomainName::from_absolute_str("example.test.").unwrap();
    let old_anchor = "anchor.example.test.";
    let new_anchor = "other.example.test.";
    let mut rrsets = vec![
        Rrset::new(
            origin.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        ),
        Rrset::new(
            origin.clone(),
            RecordType::Nsec3Param as u16,
            1,
            300,
            vec![nsec3param_rdata(1)],
        ),
        Rrset::new(
            DomainName::from_absolute_str("anchor.example.test.").unwrap(),
            RecordType::Txt as u16,
            1,
            300,
            vec![b"\x06anchor".to_vec()],
        ),
    ];
    rrsets.extend(nsec3_ring_rrsets(
        &["example.test.", "anchor.example.test."],
        "example.test.",
    ));
    let base = ZoneSnapshot::active(origin.clone(), Some(1), rrsets);
    let mut soa2 = soa_rdata();
    let (_, mname_len) = DomainName::parse(&soa2, 0).unwrap();
    let (_, rname_len) = DomainName::parse(&soa2, mname_len).unwrap();
    let serial_offset = mname_len + rname_len;
    soa2[serial_offset..serial_offset + 4].copy_from_slice(&2u32.to_be_bytes());
    let mut replacements = vec![
        (
            origin.canonical_key(),
            RecordType::Soa as u16,
            1,
            Some(Rrset::new(
                origin.clone(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa2],
            )),
        ),
        (old_anchor.to_owned(), RecordType::Txt as u16, 1, None),
        (
            nsec3_owner(old_anchor, "example.test.").canonical_key(),
            RecordType::Nsec3 as u16,
            1,
            None,
        ),
        (
            nsec3_owner(old_anchor, "example.test.").canonical_key(),
            RecordType::Rrsig as u16,
            1,
            None,
        ),
        (
            new_anchor.to_owned(),
            RecordType::Txt as u16,
            1,
            Some(Rrset::new(
                DomainName::from_absolute_str(new_anchor).unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                vec![b"\x05other".to_vec()],
            )),
        ),
    ];
    replacements.extend(
        nsec3_ring_rrsets(&["example.test.", new_anchor], "example.test.")
            .into_iter()
            .map(|rrset| {
                (
                    rrset.owner.canonical_key(),
                    rrset.rr_type,
                    rrset.class,
                    Some(rrset),
                )
            }),
    );
    let updated = base.with_cow_rrset_replacements(2, replacements);
    let overlay_store = ZoneStore::with_publication_policy(crate::zone::ZonePublicationPolicy {
        strategy: crate::zone::ZonePublicationStrategy::Sharded,
        sharded_rrset_threshold: 1,
        ..crate::zone::ZonePublicationPolicy::default()
    });
    overlay_store.insert_snapshot(base);
    overlay_store.insert_snapshot(updated.clone());
    let compact_store = ZoneStore::new();
    compact_store.insert_snapshot(updated);
    for qname in [
        b"\x01a\x07example\x04test\x00".as_slice(),
        b"\x07missing\x07example\x04test\x00".as_slice(),
        b"\x01z\x07example\x04test\x00".as_slice(),
    ] {
        let mut packet = query(qname, RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);
        assert_semantic_response_eq(
            &store_response(&packet, &overlay_store),
            &store_response(&packet, &compact_store),
        );
    }
}

#[test]
fn nsec3_only_hashed_owner_is_answered_as_nxdomain() {
    let hashed_owner = nsec3_owner("example.test.", "example.test.");
    let mut rrsets = vec![
        Rrset::new(
            DomainName::from_absolute_str("example.test.").unwrap(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        ),
        Rrset::new(
            DomainName::from_absolute_str("example.test.").unwrap(),
            RecordType::Nsec3Param as u16,
            1,
            300,
            vec![nsec3param_rdata(1)],
        ),
        Rrset::new(
            DomainName::from_absolute_str("anchor.example.test.").unwrap(),
            RecordType::Txt as u16,
            1,
            300,
            vec![b"\x06anchor".to_vec()],
        ),
    ];
    rrsets.extend(nsec3_ring_rrsets(
        &["example.test.", "anchor.example.test."],
        "example.test.",
    ));
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        rrsets,
    ));
    let mut packet = query(&hashed_owner.to_wire(), RecordType::A as u16, 1);
    append_opt(&mut packet, 4096, 0x8000, &[]);

    let response = store_response(&packet, &store);

    assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert!(response_authority_types(&response).contains(&(RecordType::Nsec3 as u16)));
}

#[test]
fn nsec3_hashed_owner_with_other_data_remains_an_existing_name() {
    let hashed_owner = nsec3_owner("example.test.", "example.test.");
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                hashed_owner.clone(),
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata_with_next_hash(nsec3_hash_bytes(
                    "example.test.",
                ))],
            ),
            Rrset::new(
                hashed_owner.clone(),
                RecordType::Txt as u16,
                1,
                300,
                vec![b"\x04real".to_vec()],
            ),
        ],
    ));

    let response = store_response(
        &query(&hashed_owner.to_wire(), RecordType::A as u16, 1),
        &store,
    );

    assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
    assert!(response_answer_types(&response).is_empty());
}

#[test]
fn nsec3_hashed_owner_with_an_ordinary_descendant_is_an_empty_nonterminal() {
    let hashed_owner = nsec3_owner("example.test.", "example.test.");
    let mut child_wire = b"\x05child".to_vec();
    child_wire.extend_from_slice(&hashed_owner.to_wire());
    let (child, consumed) = DomainName::parse(&child_wire, 0).unwrap();
    assert_eq!(consumed, child_wire.len());
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                hashed_owner.clone(),
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata_with_next_hash(nsec3_hash_bytes(
                    "example.test.",
                ))],
            ),
            Rrset::new(
                child,
                RecordType::A as u16,
                1,
                300,
                vec![vec![192, 0, 2, 1]],
            ),
        ],
    ));

    let response = store_response(
        &query(&hashed_owner.to_wire(), RecordType::A as u16, 1),
        &store,
    );

    assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
    assert!(response_answer_types(&response).is_empty());
}

#[test]
fn incomplete_nsec_chain_fails_closed_for_dnssec_denial() {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("a.example.test.").unwrap(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("missing-link.example.test.")],
            ),
        ],
    ));
    let mut packet = query(
        b"\x07missing\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 4096, 0x8000, &[]);

    let response = store_response(&packet, &store);

    assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
    assert!(response_authority_types(&response).is_empty());
}

fn transition_denial_response(include_nsec3param: bool) -> Vec<u8> {
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let anchor = DomainName::from_absolute_str("anchor.example.test.").unwrap();
    let mut rrsets = vec![
        Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        ),
        Rrset::new(
            apex.clone(),
            RecordType::Nsec as u16,
            1,
            300,
            vec![nsec_rdata("anchor.example.test.")],
        ),
        Rrset::new(
            apex.clone(),
            RecordType::Rrsig as u16,
            1,
            300,
            vec![rrsig_rdata(RecordType::Nsec)],
        ),
        Rrset::new(
            anchor.clone(),
            RecordType::Txt as u16,
            1,
            300,
            vec![b"\x06anchor".to_vec()],
        ),
        Rrset::new(
            anchor.clone(),
            RecordType::Nsec as u16,
            1,
            300,
            vec![nsec_rdata("example.test.")],
        ),
        Rrset::new(
            anchor,
            RecordType::Rrsig as u16,
            1,
            300,
            vec![rrsig_rdata(RecordType::Nsec)],
        ),
    ];
    if include_nsec3param {
        rrsets.push(Rrset::new(
            apex.clone(),
            RecordType::Nsec3Param as u16,
            1,
            300,
            vec![nsec3param_rdata(1)],
        ));
    }
    rrsets.extend(nsec3_ring_rrsets(
        &["example.test.", "anchor.example.test."],
        "example.test.",
    ));
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(apex, Some(1), rrsets));
    let mut packet = query(
        b"\x07missing\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 4096, 0x8000, &[]);
    store_response(&packet, &store)
}

#[test]
fn nsec3_records_without_nsec3param_do_not_replace_nsec_denial() {
    let response = transition_denial_response(false);

    assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
    let authority_types = response_authority_types(&response);
    assert!(authority_types.contains(&(RecordType::Nsec as u16)));
    assert!(!authority_types.contains(&(RecordType::Nsec3 as u16)));
}

#[test]
fn nsec3param_switches_transitioning_zone_to_nsec3_denial() {
    let response = transition_denial_response(true);

    assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
    let authority_types = response_authority_types(&response);
    assert!(authority_types.contains(&(RecordType::Nsec3 as u16)));
    assert!(!authority_types.contains(&(RecordType::Nsec as u16)));
}

#[test]
fn do_nxdomain_rejects_nsec3_without_an_exact_closest_encloser_proof() {
    let covering_owner =
        DomainName::from_absolute_str("00000000000000000000000000000000.example.test.").unwrap();
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Nsec3Param as u16,
                1,
                300,
                vec![nsec3param_rdata(1)],
            ),
            Rrset::new(
                covering_owner.clone(),
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata_with_next_hash([0xff; 20])],
            ),
            Rrset::new(
                covering_owner,
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec3)],
            ),
        ],
    ));
    let mut packet = query(
        b"\x04deep\x07missing\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 4096, 0x8000, &[]);

    let response = store_response(&packet, &store);

    assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
}

fn nsec3_iteration_cap_snapshot() -> ZoneSnapshot {
    let apex = DomainName::from_absolute_str("example.test.").unwrap();
    let mut rrsets = vec![
        Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            1,
            3600,
            vec![soa_rdata()],
        ),
        Rrset::new(
            apex.clone(),
            RecordType::Nsec3Param as u16,
            1,
            300,
            vec![nsec3param_rdata(1)],
        ),
        Rrset::new(
            DomainName::from_absolute_str("anchor.example.test.").unwrap(),
            RecordType::Txt as u16,
            1,
            300,
            vec![b"\x06anchor".to_vec()],
        ),
    ];
    rrsets.extend(nsec3_ring_rrsets(
        &["example.test.", "anchor.example.test."],
        "example.test.",
    ));
    ZoneSnapshot::active(apex, Some(1), rrsets)
}

fn nsec3_iterations_over_cap_response(
    extended_dns_errors: ExtendedDnsErrorsMode,
) -> (Vec<u8>, bool) {
    let store = ZoneStore::new();
    store.insert_snapshot(nsec3_iteration_cap_snapshot());
    let mut packet = query(
        b"\x07missing\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 4096, 0x8000, &[]);

    let nsec3_iterations_exceeded = std::cell::Cell::new(false);
    let action = answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        &packet,
        &store,
        AnswerOptions {
            nsec3_max_iterations: 0,
            extended_dns_errors,
            ..AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD)
        },
        |_, _| true,
        |_, _, _| {},
        |lookup| nsec3_iterations_exceeded.set(lookup.nsec3_iterations_exceeded),
        &default_zone_image_provider,
    );
    let response = match action {
        DatagramAction::Discard => panic!("expected response"),
        DatagramAction::Respond(response) => response,
    };
    (response, nsec3_iterations_exceeded.get())
}

#[test]
fn nsec3_iterations_over_cap_fails_closed_and_emits_ede_when_enabled() {
    let (response, nsec3_iterations_exceeded) =
        nsec3_iterations_over_cap_response(ExtendedDnsErrorsMode::Minimal);

    assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
    assert!(nsec3_iterations_exceeded);
    assert!(response_authority_types(&response).is_empty());
    assert_eq!(response_opt_ttl(&response), Some(0x8000));
    assert_eq!(
        response_ede_info_codes(&response),
        vec![EDE_UNSUPPORTED_NSEC3_ITERATIONS]
    );
}

#[test]
fn zone_image_serving_handles_dnssec_nsec3_ede_cap() {
    let store = ZoneStore::new();
    store.insert_snapshot(nsec3_iteration_cap_snapshot());
    let mut packet = query(
        b"\x07missing\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 4096, 0x8000, &[]);
    let options = AnswerOptions {
        nsec3_max_iterations: 0,
        extended_dns_errors: ExtendedDnsErrorsMode::Minimal,
        ..AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD)
    };
    let nsec3_iterations_exceeded = std::cell::Cell::new(false);

    let action = answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        &packet,
        &store,
        options,
        |_, _| true,
        |_, _, _| {},
        |lookup| nsec3_iterations_exceeded.set(lookup.nsec3_iterations_exceeded),
        &default_zone_image_provider,
    );
    let zone_image_response = match action {
        DatagramAction::Discard => panic!("expected response"),
        DatagramAction::Respond(response) => response,
    };
    let snapshot_response = store_response_with_options(&packet, &store, options);

    assert!(nsec3_iterations_exceeded.get());
    assert_eq!(zone_image_response, snapshot_response);
    assert_eq!(zone_image_response[3] & 0x0f, Rcode::ServFail as u8);
    assert!(response_authority_types(&zone_image_response).is_empty());
    assert_eq!(response_opt_ttl(&zone_image_response), Some(0x8000));
    assert_eq!(
        response_ede_info_codes(&zone_image_response),
        vec![EDE_UNSUPPORTED_NSEC3_ITERATIONS]
    );
}

#[test]
fn zone_image_nsec3_cap_servfail_fits_small_udp_ceiling_with_ede() {
    let store = ZoneStore::new();
    store.insert_snapshot(nsec3_iteration_cap_snapshot());
    let mut packet = query(
        b"\x07missing\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );
    append_opt(&mut packet, 80, 0x8000, &[]);
    let options = AnswerOptions {
        nsec3_max_iterations: 0,
        extended_dns_errors: ExtendedDnsErrorsMode::Minimal,
        ..AnswerOptions::udp(80)
    };

    let zone_image_response = store_response_with_zone_image_provider(
        &packet,
        &store,
        options,
        &default_zone_image_provider,
    );
    let snapshot_response = store_response_with_options(&packet, &store, options);

    assert_eq!(zone_image_response, snapshot_response);
    assert_eq!(zone_image_response[3] & 0x0f, Rcode::ServFail as u8);
    assert_eq!(
        zone_image_response[2] & 0x02,
        0,
        "compact SERVFAIL should fit without truncation"
    );
    assert_eq!(
        response_ede_info_codes(&zone_image_response),
        vec![EDE_UNSUPPORTED_NSEC3_ITERATIONS]
    );
    assert!(
        zone_image_response.len() <= 80,
        "stripped truncated response must fit the advertised UDP ceiling"
    );
}

#[test]
fn nsec3_iterations_over_cap_remains_observable_when_ede_is_off() {
    let (response, nsec3_iterations_exceeded) =
        nsec3_iterations_over_cap_response(ExtendedDnsErrorsMode::Off);

    assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
    assert!(nsec3_iterations_exceeded);
    assert!(response_authority_types(&response).is_empty());
    assert_eq!(response_opt_ttl(&response), Some(0x8000));
    assert!(response_ede_info_codes(&response).is_empty());
}

#[test]
fn non_do_nxdomain_omits_nsec_dnssec_augmentation() {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("a.example.test.").unwrap(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("z.example.test.")],
            ),
            Rrset::new(
                DomainName::from_absolute_str("a.example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec)],
            ),
        ],
    ));
    let packet = query(
        b"\x07missing\x07example\x04test\x00",
        RecordType::A as u16,
        1,
    );

    let response = store_response(&packet, &store);

    assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
    assert_eq!(
        response_authority_types(&response),
        vec![RecordType::Soa as u16]
    );
}
