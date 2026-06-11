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
                    vec![nsec_rdata("zzz.example.test.")],
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
                    vec![nsec_rdata("z.example.test.")],
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
    fn do_nxdomain_includes_nsec3_denial_proofs_and_covering_rrsigs() {
        let missing_nsec3 = nsec3_owner("missing.example.test.", "example.test.");
        let wildcard_nsec3 = nsec3_owner("*.example.test.", "example.test.");
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
                    missing_nsec3.clone(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata(1)],
                ),
                Rrset::new(
                    wildcard_nsec3.clone(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata(1)],
                ),
                Rrset::new(
                    missing_nsec3,
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec3)],
                ),
                Rrset::new(
                    wildcard_nsec3,
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec3)],
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
                RecordType::Nsec3 as u16,
                RecordType::Nsec3 as u16,
                RecordType::Rrsig as u16,
                RecordType::Rrsig as u16,
            ]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    fn nsec3_iterations_over_cap_response(
        extended_dns_errors: ExtendedDnsErrorsMode,
    ) -> (Vec<u8>, bool) {
        let missing_nsec3 = nsec3_owner("missing.example.test.", "example.test.");
        let wildcard_nsec3 = nsec3_owner("*.example.test.", "example.test.");
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
                    missing_nsec3,
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_iterations(1, 1)],
                ),
                Rrset::new(
                    wildcard_nsec3,
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_iterations(1, 1)],
                ),
            ],
        ));
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
    fn nsec3_iterations_over_cap_omits_proofs_and_emits_ede_when_enabled() {
        let (response, nsec3_iterations_exceeded) =
            nsec3_iterations_over_cap_response(ExtendedDnsErrorsMode::Minimal);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert!(nsec3_iterations_exceeded);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Soa as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
        assert_eq!(
            response_ede_info_codes(&response),
            vec![EDE_UNSUPPORTED_NSEC3_ITERATIONS]
        );
    }

    #[test]
    fn zone_image_serving_handles_dnssec_nsec3_ede_cap() {
        let missing_nsec3 = nsec3_owner("missing.example.test.", "example.test.");
        let wildcard_nsec3 = nsec3_owner("*.example.test.", "example.test.");
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
                    missing_nsec3,
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_iterations(1, 1)],
                ),
                Rrset::new(
                    wildcard_nsec3,
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_iterations(1, 1)],
                ),
            ],
        ));
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
        assert_eq!(zone_image_response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(
            response_authority_types(&zone_image_response),
            vec![RecordType::Soa as u16]
        );
        assert_eq!(response_opt_ttl(&zone_image_response), Some(0x8000));
        assert_eq!(
            response_ede_info_codes(&zone_image_response),
            vec![EDE_UNSUPPORTED_NSEC3_ITERATIONS]
        );
    }

    #[test]
    fn zone_image_truncation_reuses_ede_stripped_edns_sizing() {
        let missing_nsec3 = nsec3_owner("missing.example.test.", "example.test.");
        let wildcard_nsec3 = nsec3_owner("*.example.test.", "example.test.");
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
                    missing_nsec3,
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_iterations(1, 1)],
                ),
                Rrset::new(
                    wildcard_nsec3,
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata_with_iterations(1, 1)],
                ),
            ],
        ));
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
        assert!(zone_image_response[2] & 0x02 != 0, "TC bit must be set");
        assert_eq!(
            response_ede_info_codes(&zone_image_response),
            Vec::<u16>::new(),
            "EDE must remain stripped after truncation retry removes records"
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

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert!(nsec3_iterations_exceeded);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Soa as u16]
        );
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

