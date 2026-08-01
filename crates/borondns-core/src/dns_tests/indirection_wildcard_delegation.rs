    #[test]
    fn follows_cname_to_target_rrset() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.example.test.")],
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

        let packet = query(b"\x05alias\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16, RecordType::A as u16]
        );
    }

    #[test]
    fn cname_continuation_applies_covering_dname() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.d.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("d.example.test.").unwrap(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.target.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 80].to_vec()],
                ),
            ],
        ));

        let response = store_response(
            &query(
                b"\x05alias\x07example\x04test\x00",
                RecordType::A as u16,
                1,
            ),
            &store,
        );

        assert_eq!(
            response_answer_types(&response),
            vec![
                RecordType::Cname as u16,
                RecordType::Dname as u16,
                RecordType::Cname as u16,
                RecordType::A as u16,
            ]
        );
    }

    #[test]
    fn cname_continuation_applies_wildcard_synthesis() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 81].to_vec()],
                ),
            ],
        ));

        let response = store_response(
            &query(
                b"\x05alias\x07example\x04test\x00",
                RecordType::A as u16,
                1,
            ),
            &store,
        );
        let answers = response_answers(&response);

        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16, RecordType::A as u16]
        );
        assert_eq!(answers[1].0.to_string(), "target.example.test.");
    }

    #[test]
    fn concurrent_snapshot_replacement_answers_from_one_zone_version() {
        let store = ZoneStore::new();
        let old_snapshot = alias_snapshot(1, "old-target.example.test.", [192, 0, 2, 10]);
        let new_snapshot = alias_snapshot(2, "new-target.example.test.", [198, 51, 100, 20]);
        store.insert_snapshot(old_snapshot.clone());

        let packet = query(b"\x05alias\x07example\x04test\x00", RecordType::A as u16, 1);
        let reader_count = 4;
        let start = std::sync::Arc::new(std::sync::Barrier::new(reader_count + 1));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut readers = Vec::new();

        for _ in 0..reader_count {
            let reader_store = store.clone();
            let reader_packet = packet.clone();
            let reader_start = std::sync::Arc::clone(&start);
            let reader_stop = std::sync::Arc::clone(&stop);

            readers.push(std::thread::spawn(move || {
                reader_start.wait();
                let mut observations = 0usize;
                while !reader_stop.load(std::sync::atomic::Ordering::Acquire) || observations == 0 {
                    let response = store_response(&reader_packet, &reader_store);
                    assert_atomic_alias_response(&response);
                    observations += 1;
                }
                observations
            }));
        }

        start.wait();
        for iteration in 0..5_000 {
            if iteration % 2 == 0 {
                store.insert_snapshot(new_snapshot.clone());
            } else {
                store.insert_snapshot(old_snapshot.clone());
            }
            if iteration % 128 == 0 {
                std::thread::yield_now();
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Release);

        let observations = readers
            .into_iter()
            .map(|reader| reader.join().expect("reader thread panicked"))
            .sum::<usize>();
        assert!(observations >= reader_count);
    }

    #[test]
    fn direct_cname_query_returns_only_cname_rrset() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.example.test.")],
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
            b"\x05alias\x07example\x04test\x00",
            RecordType::Cname as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
    }

    #[test]
    fn cname_negative_terminal_keeps_chain_and_soa() {
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
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("missing.example.test.")],
                ),
            ],
        ));

        let packet = query(b"\x05alias\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
    }

    #[test]
    fn do_cname_terminal_nodata_proves_the_terminal_name() {
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
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("target.example.test.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![b"\x07present".to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("target.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("target.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("target.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let mut packet = query(
            b"\x05alias\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_answer_types(&response), vec![RecordType::Cname as u16]);
        assert_eq!(
            response_authority_types(&response),
            vec![
                RecordType::Soa as u16,
                RecordType::Nsec as u16,
                RecordType::Rrsig as u16,
            ]
        );
    }

    #[test]
    fn do_cname_terminal_nxdomain_proves_the_terminal_name_and_wildcard_absence() {
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
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("missing.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("a.example.test.")],
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
            b"\x05alias\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(response_answer_types(&response), vec![RecordType::Cname as u16]);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Soa as u16, RecordType::Nsec as u16, RecordType::Rrsig as u16]
        );
    }

    #[test]
    fn cname_loop_returns_authoritative_servfail_with_partial_chain() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("b.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("b.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("a.example.test.")],
                ),
            ],
        ));

        let packet = query(b"\x01a\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
        assert_ne!(response[2] & 0x04, 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16, RecordType::Cname as u16]
        );
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let zone = store
            .exact_snapshot_for_transfer(&origin)
            .expect("zone snapshot");
        let lookup = zone.snapshot_for_transfer().offline_oracle().lookup(
            &DomainName::from_absolute_str("a.example.test.").unwrap(),
            RecordType::A as u16,
            1,
        );
        assert_eq!(lookup.rcode, Rcode::ServFail);
        assert!(lookup.authoritative);
        assert!(lookup.authorities.is_empty());
        assert_eq!(lookup.termination, Some(LookupTermination::CnameLoop));
    }

    #[test]
    fn configured_cname_chain_limit_returns_authoritative_servfail() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("b.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("b.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("c.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("c.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 31].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x01a\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response_with_options(
            &packet,
            &store,
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: 1,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: &[],
                chaos: ChaosOptions::default(),
                dns_cookie: None,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
        assert_ne!(response[2] & 0x04, 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        let zone = store
            .exact_snapshot_for_transfer(&origin)
            .expect("zone snapshot");
        let lookup = zone
            .snapshot_for_transfer()
            .offline_oracle()
            .lookup_with_options(
                &DomainName::from_absolute_str("a.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                1,
                AnyResponseMode::Minimal,
            );
        assert_eq!(lookup.rcode, Rcode::ServFail);
        assert!(lookup.authoritative);
        assert!(lookup.authorities.is_empty());
        assert_eq!(lookup.termination, Some(LookupTermination::CnameChainLimit));
    }

    #[test]
    fn dname_synthesizes_cname_and_resolves_target_rrset() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.target.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 40].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05alias\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let answers = response_answers(&response);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![
                RecordType::Dname as u16,
                RecordType::Cname as u16,
                RecordType::A as u16
            ]
        );
        assert_eq!(answers[1].0.to_string(), "www.alias.example.test.");
    }

    #[test]
    fn exact_data_below_dname_is_occluded_by_the_dname() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.alias.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 99].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.target.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 40].to_vec()],
                ),
            ],
        ));

        let response = store_response(
            &query(
                b"\x03www\x05alias\x07example\x04test\x00",
                RecordType::A as u16,
                1,
            ),
            &store,
        );

        assert_eq!(
            response_answer_types(&response),
            vec![
                RecordType::Dname as u16,
                RecordType::Cname as u16,
                RecordType::A as u16,
            ]
        );
        assert_eq!(
            response_answer_rdatas(&response, RecordType::A as u16),
            vec![[192, 0, 2, 40].to_vec()],
        );
    }

    #[test]
    fn dname_chain_leaving_zone_returns_constructed_answer_only() {
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
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.other.test.")],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05alias\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Dname as u16, RecordType::Cname as u16]
        );
    }

    #[test]
    fn dname_synthesis_overflow_returns_yxdomain_without_cname() {
        let long_label = "a".repeat(63);
        let qname =
            DomainName::from_absolute_str(&format!("{long_label}.d.example.test.")).unwrap();
        let target = format!("{0}.{0}.{0}.target.test.", long_label);
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
                    DomainName::from_absolute_str("d.example.test.").unwrap(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![cname_rdata(&target)],
                ),
            ],
        ));

        let packet = query(&qname.to_wire(), RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::YxDomain as u8);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Dname as u16]
        );
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Soa as u16]
        );
    }

    #[test]
    fn multiple_dname_records_return_servfail() {
        let qname = DomainName::from_absolute_str("www.alias.example.test.").unwrap();
        let zone = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("alias.example.test.").unwrap(),
                RecordType::Dname as u16,
                1,
                300,
                vec![
                    cname_rdata("target.example.test."),
                    cname_rdata("other.example.test."),
                ],
            )],
        );
        let lookup = zone
            .offline_oracle()
            .lookup(&qname, RecordType::A as u16, 1);

        assert_eq!(lookup.rcode, Rcode::ServFail);
        assert_eq!(lookup.answers.len(), 2);
        assert_eq!(lookup.termination, Some(LookupTermination::MalformedDname));
    }

    #[test]
    fn dname_negative_terminal_keeps_chain_and_soa() {
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
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.example.test.")],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05alias\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Dname as u16, RecordType::Cname as u16]
        );
    }

    #[test]
    fn direct_dname_query_returns_only_dname_rrset() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("alias.example.test.").unwrap(),
                RecordType::Dname as u16,
                1,
                300,
                vec![cname_rdata("target.example.test.")],
            )],
        ));

        let packet = query(
            b"\x05alias\x07example\x04test\x00",
            RecordType::Dname as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Dname as u16]
        );
    }

    #[test]
    fn wildcard_synthesizes_answer_owner() {
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
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 20].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);
        let answers = response_answers(&response);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0.to_string(), "foo.example.test.");
        assert_eq!(answers[0].1, RecordType::A as u16);
    }

    #[test]
    fn do_wildcard_answer_includes_nsec_proof_for_exact_name_absence() {
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
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 20].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::A)],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("a.example.test.")],
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
        let mut packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::A as u16, RecordType::Rrsig as u16]
        );
        assert!(
            response_answers(&response)
                .iter()
                .all(|(owner, _)| owner.to_string() == "foo.example.test."),
            "the wildcard data and its RRSIG must both use the expanded owner"
        );
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Nsec as u16, RecordType::Rrsig as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn do_nsec3_wildcard_answer_proves_the_next_closer_name() {
        let mut ring_names = vec!["example.test.".to_owned(), "*.example.test.".to_owned()];
        for index in 0..1_000 {
            ring_names.push(format!("anchor-{index}.example.test."));
            if nsec3_covering_owner("missing.example.test.", &ring_names, "example.test.")
                != nsec3_covering_owner(
                    "deep.missing.example.test.",
                    &ring_names,
                    "example.test.",
                )
            {
                break;
            }
        }
        let expected_cover =
            nsec3_covering_owner("missing.example.test.", &ring_names, "example.test.");
        let wrong_qname_cover = nsec3_covering_owner(
            "deep.missing.example.test.",
            &ring_names,
            "example.test.",
        );
        assert_ne!(expected_cover, wrong_qname_cover, "fixture must distinguish the RFC next-closer proof from a broad QNAME proof");

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
                DomainName::from_absolute_str("*.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 20].to_vec()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("*.example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::A)],
            ),
        ];
        for name in &ring_names[2..] {
            rrsets.push(Rrset::new(
                DomainName::from_absolute_str(name).unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                vec![b"\x06anchor".to_vec()],
            ));
        }
        rrsets.extend(nsec3_ring_rrsets(&ring_names, "example.test."));
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            rrsets,
        ));
        let mut packet = query(
            b"\x04deep\x07missing\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::A as u16, RecordType::Rrsig as u16]
        );
        assert_eq!(
            response_authority_owners(&response, RecordType::Nsec3 as u16),
            vec![expected_cover]
        );
    }

    #[test]
    fn non_do_wildcard_answer_omits_nsec_dnssec_augmentation() {
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
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 20].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("*.example.test.")],
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
        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_authority_types(&response), Vec::<u16>::new());
    }

    #[test]
    fn wildcard_cname_chases_to_target_rrset() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 30].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);
        let answers = response_answers(&response);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16, RecordType::A as u16]
        );
        assert_eq!(answers[0].0.to_string(), "foo.example.test.");
    }

    #[test]
    fn wildcard_cname_negative_terminal_keeps_chain_and_soa() {
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
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("missing.block.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.block.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 31].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
    }

    #[test]
    fn wildcard_cname_reapplication_honors_chain_limit() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("*.example.test.").unwrap(),
                RecordType::Cname as u16,
                1,
                300,
                vec![cname_rdata("missing.example.test.")],
            )],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
        assert!(u16::from_be_bytes([response[6], response[7]]) > 0);
    }

    #[test]
    fn wildcard_cname_leaving_zone_returns_constructed_answer_only() {
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
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.other.test.")],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
    }

    #[test]
    fn wildcard_name_without_qtype_gets_nodata() {
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
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![vec![0, 10, 0]],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
    }

    #[test]
    fn empty_non_terminal_wildcard_source_gets_nodata() {
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
                    DomainName::from_absolute_str("child.*.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 22].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
    }

    #[test]
    fn do_wildcard_nodata_proves_qname_absence_and_wildcard_type_absence() {
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
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![b"\x08wildcard".to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("a.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("*.example.test.")],
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
        let mut packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert!(response_answer_types(&response).is_empty());
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
    }

    #[test]
    fn do_wildcard_nodata_rejects_covering_nsec3_for_the_required_wildcard_match() {
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
                DomainName::from_absolute_str("*.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                vec![b"\x08wildcard".to_vec()],
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
        let mut packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
    }

    #[test]
    fn do_wildcard_nodata_includes_exact_nsec3_for_closest_encloser_and_wildcard() {
        let ring_names = [
            "example.test.",
            "*.example.test.",
            "anchor.example.test.",
        ];
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
                DomainName::from_absolute_str("*.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                vec![b"\x08wildcard".to_vec()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("anchor.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                vec![b"\x06anchor".to_vec()],
            ),
        ];
        rrsets.extend(nsec3_ring_rrsets(&ring_names, "example.test."));
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            rrsets,
        ));
        let mut packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);
        let nsec3_owners = response_authority_owners(&response, RecordType::Nsec3 as u16);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert!(
            nsec3_owners.contains(&nsec3_owner("example.test.", "example.test.")),
            "closest encloser requires an exact NSEC3 match"
        );
        assert!(
            nsec3_owners.contains(&nsec3_owner("*.example.test.", "example.test.")),
            "wildcard NODATA requires an exact NSEC3 match for the wildcard owner"
        );
    }

    #[test]
    fn empty_non_terminal_blocks_higher_wildcard() {
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
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 20].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.foo.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 21].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
    }

    #[test]
    fn delegated_child_query_gets_referral_with_glue() {
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
                    DomainName::from_absolute_str("ns.child.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 53].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.child.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
                    ]],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
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
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn nsec3_optout_unsigned_referral_includes_closest_encloser_proof() {
        let mut ring_names = vec!["example.test.".to_owned()];
        for index in 0..1_000 {
            ring_names.push(format!("anchor-{index}.example.test."));
            if nsec3_covering_owner(
                "child.example.test.",
                &ring_names,
                "example.test.",
            ) != nsec3_owner("example.test.", "example.test.")
            {
                break;
            }
        }
        let expected_closest = nsec3_owner("example.test.", "example.test.");
        let expected_cover = nsec3_covering_owner(
            "child.example.test.",
            &ring_names,
            "example.test.",
        );
        assert_ne!(expected_closest, expected_cover);

        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
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
                child,
                RecordType::Ns as u16,
                1,
                300,
                vec![cname_rdata("ns.child.example.test.")],
            ),
        ];
        for name in &ring_names[1..] {
            rrsets.push(Rrset::new(
                DomainName::from_absolute_str(name).unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                vec![b"\x06anchor".to_vec()],
            ));
        }
        rrsets.extend(nsec3_optout_ring_rrsets(
            &ring_names,
            "example.test.",
            "child.example.test.",
        ));
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(apex, Some(1), rrsets));
        let mut packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);
        let owners = response_authority_owners(&response, RecordType::Nsec3 as u16);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x0400, 0);
        assert!(owners.contains(&expected_closest));
        assert!(owners.contains(&expected_cover));
    }

    #[test]
    fn nsec3_unsigned_referral_rejects_cover_without_optout_flag() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
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
                child,
                RecordType::Ns as u16,
                1,
                300,
                vec![cname_rdata("ns.child.example.test.")],
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
        store.insert_snapshot(ZoneSnapshot::active(apex, Some(1), rrsets));
        let mut packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
        assert!(response_authority_types(&response).is_empty());
    }

    #[test]
    fn ds_at_a_locally_served_child_apex_is_answered_from_the_parent_zone() {
        let store = ZoneStore::new();
        let child = DomainName::from_absolute_str("child.example.test.").unwrap();
        let mut ds = vec![0x12, 0x34, 8, 2];
        ds.extend_from_slice(&[0x5a; 32]);

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
                    child.clone(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    child.clone(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![ds],
                ),
            ],
        ));
        store.insert_snapshot(ZoneSnapshot::active(
            child,
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("child.example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            )],
        ));

        let packet = query(
            b"\x05child\x07example\x04test\x00",
            RecordType::Ds as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_answer_types(&response), vec![RecordType::Ds as u16]);
        assert_ne!(u16::from_be_bytes([response[2], response[3]]) & 0x0400, 0);
    }

    #[test]
    fn delegated_child_referral_includes_available_parent_side_ns_address() {
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
                    vec![cname_rdata("ns.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 53].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
        assert_eq!(response_additional_types(&response), vec![RecordType::A as u16]);
    }

    #[test]
    fn glue_below_delegation_is_not_served_as_authoritative_answer() {
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
                    DomainName::from_absolute_str("ns.child.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 53].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x02ns\x05child\x07example\x04test\x00",
            RecordType::A as u16,
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
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16]
        );
    }

    #[test]
    fn cname_chain_into_delegation_includes_referral() {
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
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.child.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 99].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x05alias\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_ne!(flags & 0x0400, 0);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
        assert!(response_additional_types(&response).is_empty());
    }

    #[test]
    fn cname_chain_resumes_in_a_separately_served_child_zone() {
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
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.child.example.test.")],
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
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("child.example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.child.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 100].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x05alias\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_ne!(flags & 0x0400, 0);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16, RecordType::A as u16]
        );
        assert!(response_authority_types(&response).is_empty());
    }

    #[test]
    fn cross_zone_cname_to_referral_keeps_authoritative_answer_bit() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.grand.child.example.test.")],
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
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("child.example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("grand.child.example.test.").unwrap(),
                RecordType::Ns as u16,
                1,
                300,
                vec![cname_rdata("ns.grand.child.example.test.")],
            )],
        ));

        let response = store_response(
            &query(
                b"\x05alias\x07example\x04test\x00",
                RecordType::A as u16,
                1,
            ),
            &store,
        );
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_ne!(flags & 0x0400, 0);
        assert_eq!(response_answer_types(&response), vec![RecordType::Cname as u16]);
        assert_eq!(response_authority_types(&response), vec![RecordType::Ns as u16]);
    }

    #[test]
    fn occluded_non_glue_below_delegation_is_not_served() {
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
                    DomainName::from_absolute_str("www.child.example.test.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![b"\x07occlude".to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.child.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 99].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::Txt as u16,
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
        assert!(response_additional_types(&response).is_empty());
    }
