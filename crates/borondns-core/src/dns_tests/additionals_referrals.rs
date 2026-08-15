    #[test]
    fn mx_answer_includes_in_zone_exchange_addresses_as_additionals() {
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
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata(10, "mail.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("mail.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 25].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("mail.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x25,
                    ]],
                ),
            ],
        ));

        let packet = query(b"\x07example\x04test\x00", RecordType::Mx as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Mx as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn optional_additional_rrset_overflow_is_omitted_without_tc() {
        let store = ZoneStore::new();
        let addresses = (0..64)
            .map(|last| vec![192, 0, 2, last])
            .collect::<Vec<_>>();
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
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata(10, "mail.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("mail.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    addresses,
                ),
            ],
        ));

        let response = store_response(
            &query(b"\x07example\x04test\x00", RecordType::Mx as u16, 1),
            &store,
        );
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response_answer_types(&response), vec![RecordType::Mx as u16]);
        assert!(response_additional_types(&response).is_empty());
        assert_eq!(flags & 0x0200, 0, "optional Additional omission must not set TC");
        assert!(response.len() <= 512);
    }

    #[test]
    fn mx_answer_omits_out_of_zone_exchange_additionals() {
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
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata(10, "mail.other.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("mail.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 25].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x07example\x04test\x00", RecordType::Mx as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Mx as u16]
        );
        assert!(response_additional_types(&response).is_empty());
    }

    #[test]
    fn mx_answer_omits_occluded_address_data_below_delegation() {
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
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata(10, "mail.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("mail.child.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 25].to_vec()],
                ),
            ],
        ));

        let response = store_response(
            &query(b"\x07example\x04test\x00", RecordType::Mx as u16, 1),
            &store,
        );

        assert_eq!(response_answer_types(&response), vec![RecordType::Mx as u16]);
        assert!(response_additional_types(&response).is_empty());
    }

    #[test]
    fn srv_answer_includes_in_zone_target_addresses_as_additionals() {
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
                    DomainName::from_absolute_str("_xmpp._tcp.example.test.").unwrap(),
                    RecordType::Srv as u16,
                    1,
                    300,
                    vec![srv_rdata(10, 20, 5222, "chat.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("chat.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 26].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("chat.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x26,
                    ]],
                ),
            ],
        ));

        let packet = query(
            b"\x05_xmpp\x04_tcp\x07example\x04test\x00",
            RecordType::Srv as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Srv as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn ns_answer_includes_in_zone_target_addresses_as_additionals() {
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
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns1.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns1.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 53].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns1.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
                    ]],
                ),
            ],
        ));

        let packet = query(b"\x07example\x04test\x00", RecordType::Ns as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Ns as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn naptr_answer_includes_in_zone_replacement_addresses_as_additionals() {
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
                    DomainName::from_absolute_str("sip.example.test.").unwrap(),
                    RecordType::Naptr as u16,
                    1,
                    300,
                    vec![naptr_rdata("_sip._udp.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("_sip._udp.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 27].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("_sip._udp.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x27,
                    ]],
                ),
            ],
        ));

        let packet = query(
            b"\x03sip\x07example\x04test\x00",
            RecordType::Naptr as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Naptr as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn svcb_answer_includes_service_mode_target_addresses_as_additionals() {
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
                    DomainName::from_absolute_str("_dns.example.test.").unwrap(),
                    RecordType::Svcb as u16,
                    1,
                    300,
                    vec![svcb_rdata(
                        1,
                        "svc.example.test.",
                        &[0, 1, 0, 3, 2, b'h', b'2'],
                    )],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("svc.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 28].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("svc.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x28,
                    ]],
                ),
            ],
        ));

        let packet = query(
            b"\x04_dns\x07example\x04test\x00",
            RecordType::Svcb as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Svcb as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn svcb_and_https_answers_include_target_service_rrset_and_dnssec_records() {
        for rr_type in [RecordType::Svcb, RecordType::Https] {
            let owner = DomainName::from_absolute_str("service.example.test.").unwrap();
            let target = DomainName::from_absolute_str("target.example.test.").unwrap();
            let store = ZoneStore::new();
            store.insert_snapshot(ZoneSnapshot::active(
                DomainName::from_absolute_str("example.test.").unwrap(),
                Some(1),
                vec![
                    Rrset::new(
                        owner.clone(),
                        rr_type as u16,
                        1,
                        300,
                        vec![svcb_rdata(0, "target.example.test.", &[])],
                    ),
                    Rrset::new(
                        target.clone(),
                        rr_type as u16,
                        1,
                        300,
                        vec![svcb_rdata(1, ".", &[])],
                    ),
                    Rrset::new(
                        target.clone(),
                        RecordType::A as u16,
                        1,
                        300,
                        vec![[192, 0, 2, 32].to_vec()],
                    ),
                    Rrset::new(
                        target.clone(),
                        RecordType::Rrsig as u16,
                        1,
                        300,
                        vec![rrsig_rdata(rr_type), rrsig_rdata(RecordType::A)],
                    ),
                ],
            ));
            let mut packet = query(
                b"\x07service\x07example\x04test\x00",
                rr_type as u16,
                1,
            );
            append_opt(&mut packet, 4096, 0x8000, &[]);

            let response = store_response(&packet, &store);
            let additional_types = response_additional_types(&response);

            assert!(additional_types.contains(&(rr_type as u16)));
            assert!(additional_types.contains(&(RecordType::A as u16)));
            assert_eq!(
                response_additional_owners(&response, rr_type as u16),
                vec![target.clone()]
            );
            assert_eq!(
                response_additional_owners(&response, RecordType::Rrsig as u16),
                vec![target.clone(), target.clone()]
            );
        }
    }

    #[test]
    fn svcb_and_https_service_mode_root_target_use_exact_effective_owner_for_additionals() {
        for rr_type in [RecordType::Svcb, RecordType::Https] {
            let store = ZoneStore::new();
            let owner = DomainName::from_absolute_str("svc.example.test.").unwrap();
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
                        owner.clone(),
                        rr_type as u16,
                        1,
                        300,
                        vec![svcb_rdata(1, ".", &[])],
                    ),
                    Rrset::new(
                        owner.clone(),
                        RecordType::A as u16,
                        1,
                        300,
                        vec![[192, 0, 2, 30].to_vec()],
                    ),
                    Rrset::new(
                        owner.clone(),
                        RecordType::Aaaa as u16,
                        1,
                        300,
                        vec![vec![0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30]],
                    ),
                ],
            ));

            let response = store_response(
                &query(b"\x03svc\x07example\x04test\x00", rr_type as u16, 1),
                &store,
            );

            assert_eq!(
                response_additional_types(&response),
                vec![RecordType::A as u16, RecordType::Aaaa as u16]
            );
            assert_eq!(
                response_additional_owners(&response, RecordType::A as u16),
                vec![owner.clone()]
            );
        }
    }

    #[test]
    fn svcb_and_https_service_mode_root_target_use_wildcard_effective_owner_for_additionals() {
        for rr_type in [RecordType::Svcb, RecordType::Https] {
            let store = ZoneStore::new();
            let wildcard = DomainName::from_absolute_str("*.example.test.").unwrap();
            let effective_owner = DomainName::from_absolute_str("foo.example.test.").unwrap();
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
                        wildcard.clone(),
                        rr_type as u16,
                        1,
                        300,
                        vec![svcb_rdata(1, ".", &[])],
                    ),
                    Rrset::new(
                        wildcard.clone(),
                        RecordType::A as u16,
                        1,
                        300,
                        vec![[192, 0, 2, 31].to_vec()],
                    ),
                    Rrset::new(
                        wildcard,
                        RecordType::Aaaa as u16,
                        1,
                        300,
                        vec![vec![0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31]],
                    ),
                ],
            ));

            let response = store_response(
                &query(b"\x03foo\x07example\x04test\x00", rr_type as u16, 1),
                &store,
            );

            assert_eq!(
                response_additional_types(&response),
                vec![RecordType::A as u16, RecordType::Aaaa as u16]
            );
            assert_eq!(
                response_additional_owners(&response, RecordType::A as u16),
                vec![effective_owner]
            );
        }
    }

    #[test]
    fn https_answer_includes_alias_mode_target_addresses_as_additionals() {
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
                    RecordType::Https as u16,
                    1,
                    300,
                    vec![svcb_rdata(0, "alias.example.test.", &[])],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 29].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x29,
                    ]],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Https as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Https as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn ds_query_at_delegation_owner_is_authoritative_positive() {
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
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![0, 12, 8, 2, 1, 2, 3, 4]],
                ),
            ],
        ));

        let packet = query(
            b"\x05child\x07example\x04test\x00",
            RecordType::Ds as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0x0400);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Ds as u16]
        );
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
    }

    #[test]
    fn ds_query_at_unsigned_delegation_owner_is_authoritative_nodata() {
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
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
            ],
        ));

        let packet = query(
            b"\x05child\x07example\x04test\x00",
            RecordType::Ds as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0x0400);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Soa as u16]
        );
    }

    #[test]
    fn ds_query_below_delegation_gets_referral() {
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
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::Ds as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
    }

    #[test]
    fn root_referral_includes_available_sibling_glue() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str(".").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("com.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    172800,
                    vec![cname_rdata("a.gtld-servers.net.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.gtld-servers.net.").unwrap(),
                    RecordType::A as u16,
                    1,
                    172800,
                    vec![[192, 5, 6, 30].to_vec()],
                ),
            ],
        ));

        let response = store_response(
            &query(b"\x03www\x03com\x00", RecordType::A as u16, 1),
            &store,
        );

        assert_eq!(response_authority_types(&response), vec![RecordType::Ns as u16]);
        assert_eq!(response_additional_types(&response), vec![RecordType::A as u16]);
        assert_eq!(
            response_additional_owners(&response, RecordType::A as u16),
            vec![DomainName::from_absolute_str("a.gtld-servers.net.").unwrap()]
        );
    }

    #[test]
    fn oversized_referral_sets_tc_when_required_in_domain_glue_is_omitted() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.child.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    (1..=100)
                        .map(|last| vec![192, 0, 2, last])
                        .collect(),
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response_with_options(&packet, &store, AnswerOptions::udp(512));
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response_authority_types(&response), vec![RecordType::Ns as u16]);
        assert!(response_additional_types(&response).is_empty());
        assert_ne!(
            flags & 0x0200,
            0,
            "RFC 9471 requires TC when available in-domain referral glue cannot fit"
        );
    }

    #[test]
    fn do_referral_includes_ds_and_covering_rrsigs() {
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
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![0, 12, 8, 2, 1, 2, 3, 4]],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Ns), rrsig_rdata(RecordType::Ds)],
                ),
            ],
        ));
        let mut packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![
                RecordType::Ns as u16,
                RecordType::Ds as u16,
                RecordType::Rrsig as u16,
                RecordType::Rrsig as u16,
            ]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn do_referral_for_unsigned_child_includes_nsec_and_covering_rrsigs() {
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
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Ns), rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let mut packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![
                RecordType::Ns as u16,
                RecordType::Nsec as u16,
                RecordType::Rrsig as u16,
                RecordType::Rrsig as u16,
            ]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn non_do_referral_omits_ds_dnssec_augmentation() {
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
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![0, 12, 8, 2, 1, 2, 3, 4]],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Ns), rrsig_rdata(RecordType::Ds)],
                ),
            ],
        ));
        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
    }

    #[test]
    fn non_do_referral_omits_nsec_dnssec_augmentation() {
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
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("next.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Ns), rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
    }
