    #[test]
    fn answers_positive_rrset_from_active_zone() {
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

        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);
        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
    }

    #[test]
    fn zone_image_serving_matches_snapshot_positive_response() {
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
            ],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let snapshot_response = store_response(&packet, &store);
        let zone_image_response = store_response_with_zone_image(&packet, &store);

        assert_semantic_response_eq(&snapshot_response, &zone_image_response);
        let answer_offset = first_answer_offset(&zone_image_response);
        assert_eq!(zone_image_response[answer_offset] & 0xc0, 0xc0);
    }

    #[test]
    fn zone_image_direct_answer_fast_path_handles_edns_positive_rrset() {
        let snapshot = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec(), [192, 0, 2, 11].to_vec()],
            )],
        );
        let image = ZoneImage::compile(&snapshot).unwrap();
        let store = ZoneStore::new();
        store.insert_snapshot(snapshot);
        let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &edns_option(EDNS_NSID_OPTION, &[]));
        let options = AnswerOptions {
            nsid: b"dns-bud-1",
            ..AnswerOptions::default()
        };

        let direct = direct_zone_image_response_for_packet(&packet, &image, options)
            .expect("direct fast path should accept direct A+EDNS response");
        let snapshot_response = store_response_with_options(&packet, &store, options);

        assert_eq!(direct, snapshot_response);
        assert_eq!(u16::from_be_bytes([direct[6], direct[7]]), 2);
        assert_eq!(u16::from_be_bytes([direct[10], direct[11]]), 1);
        assert_eq!(direct[first_answer_offset(&direct)..][0] & 0xc0, 0xc0);
        assert_eq!(
            response_opt_option(&direct, EDNS_NSID_OPTION),
            Some(b"dns-bud-1".to_vec())
        );
        assert_eq!(
            direct.capacity(),
            direct.len(),
            "direct EDNS response should reserve from exact OPT option shape, not fixed slack"
        );
    }

    #[test]
    fn zone_image_publishes_rrset_beyond_u16_and_separates_udp_from_tcp_limits() {
        let qname = DomainName::from_absolute_str("wide.example.test.").unwrap();
        let rdatas = (0..=u32::from(u16::MAX))
            .map(|value| value.to_be_bytes().to_vec())
            .collect();
        let snapshot = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                qname.clone(),
                RecordType::A as u16,
                1,
                300,
                rdatas,
            )],
        );
        let image = ZoneImage::compile(&snapshot).expect("wide RRset publishes");
        let plan = image.lookup_response_plan(
            &qname,
            RecordType::A as u16,
            1,
            DEFAULT_MAX_CNAME_CHAIN,
            AnyResponseMode::Minimal,
        );
        assert_eq!(
            plan.section_record_counts(),
            (usize::from(u16::MAX) + 1, 0, 0)
        );
        assert!(
            image.direct_rrset_wire(plan.answer_rrsets()[0]).is_none(),
            "direct response metadata cannot encode a u16-overflowing ANCOUNT"
        );

        let packet = query(
            b"\x04wide\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let header = Header::parse(&packet).unwrap();
        let question = Question::parse(&packet).unwrap();
        let metadata = RequestMetadata::parse(&header, &packet, &question).unwrap();
        let udp_options = AnswerOptions::udp(1232);
        let udp_sizing = zone_image_response_sizing(
            &question,
            metadata.udp_ceiling(udp_options),
            &metadata,
            udp_options,
        );
        let udp_response = build_zone_image_response(
            &header,
            &question,
            &image,
            &plan,
            metadata,
            udp_options,
            true,
            udp_sizing,
        )
        .expect("UDP can report truncation");
        let udp_flags = u16::from_be_bytes([udp_response[2], udp_response[3]]);
        assert_ne!(udp_flags & 0x0200, 0, "TC must report the oversized RRset");
        assert_eq!(u16::from_be_bytes([udp_response[6], udp_response[7]]), 0);

        let tcp_options = AnswerOptions::tcp();
        let tcp_sizing = zone_image_response_sizing(
            &question,
            metadata.udp_ceiling(tcp_options),
            &metadata,
            tcp_options,
        );
        assert!(
            build_zone_image_response(
                &header,
                &question,
                &image,
                &plan,
                metadata,
                tcp_options,
                true,
                tcp_sizing,
            )
            .is_none(),
            "classic DNS-over-TCP cannot encode more than u16 section records"
        );
    }

    #[test]
    fn zone_image_reuses_rejected_direct_plan_for_generic_response() {
        let alias = DomainName::from_absolute_str("alias.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                alias.clone(),
                RecordType::Cname as u16,
                1,
                300,
                vec![cname_rdata("target.example.test.")],
            )],
        );
        let image = ZoneImage::compile(&snapshot).unwrap();
        let direct_plan = image
            .lookup_direct_answer_plan(&alias, RecordType::Cname as u16, 1)
            .expect("CNAME has a valid exact direct semantic plan");
        assert!(direct_plan.direct_answer_candidate());
        let store = ZoneStore::new();
        store.insert_snapshot(snapshot);
        let packet = query(
            b"\x05alias\x07example\x04test\x00",
            RecordType::Cname as u16,
            1,
        );
        let header = Header::parse(&packet).unwrap();
        let question = Question::parse(&packet).unwrap();
        let metadata = RequestMetadata::parse(&header, &packet, &question).unwrap();
        let options = AnswerOptions::default();
        let udp_ceiling = metadata.udp_ceiling(options);
        let response_sizing =
            zone_image_response_sizing(&question, udp_ceiling, &metadata, options);

        assert!(
            build_direct_zone_image_answer_response(
                &header,
                &question,
                &image,
                &direct_plan,
                metadata,
                options,
                response_sizing,
            )
            .is_none(),
            "compressible CNAME RDATA should fall back to the generic composer"
        );
        let expected = build_zone_image_response(
            &header,
            &question,
            &image,
            &direct_plan,
            metadata,
            options,
            false,
            response_sizing,
        )
        .expect("generic response builds from rejected direct semantic plan");

        let observed = std::cell::Cell::new(None);
        let response = match answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
            &packet,
            &store,
            options,
            |_, _| true,
            |_, _, _| {},
            |lookup| observed.set(Some(lookup)),
            &default_zone_image_provider,
        ) {
            DatagramAction::Discard => panic!("expected response"),
            DatagramAction::Respond(response) => response,
        };

        assert_eq!(response, expected);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
        let metrics = observed.get().expect("lookup metrics observed");
        assert!(metrics.zone_image_used);
        assert!(
            !metrics.zone_image_direct_answer,
            "generic composer handled the rejected direct plan"
        );
    }

    #[test]
    fn direct_answer_body_uses_compiled_record_metadata() {
        let qname = DomainName::from_absolute_str("www.example.test.").unwrap();
        let snapshot = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                qname.clone(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec(), [192, 0, 2, 11].to_vec()],
            )],
        );
        let image = ZoneImage::compile(&snapshot).unwrap();
        let plan = image
            .lookup_direct_answer_plan(&qname, RecordType::A as u16, 1)
            .expect("direct A plan exists");
        let rrset = image
            .direct_rrset_wire(plan.answer_rrsets()[0])
            .expect("direct RRset wire exists");

        assert_eq!(rrset.record_count(), 2);
        assert_eq!(rrset.body_wire_len, 32);

        let mut direct_answer_wire = Vec::new();
        image.append_eligible_direct_answer_wire(&rrset, &mut direct_answer_wire);
        assert_eq!(direct_answer_wire.len(), 32);
        assert_eq!(&direct_answer_wire[..2], &0xc00cu16.to_be_bytes());
        assert_eq!(&direct_answer_wire[16..18], &0xc00cu16.to_be_bytes());
    }

    #[test]
    fn zone_image_wire_record_uncompressed_len_uses_carried_rdlength() {
        let owner = b"\x03www\x07example\x04test\x00";
        let rdata = b"\xc0\x00\x02\x01";
        let a = ZoneImageWireRecord {
            owner_wire: owner,
            fixed_fields: zone_image_record_fixed_fields(RecordType::A as u16, 1, 300),
            rdlength_bytes: 4u16.to_be_bytes(),
            rdata_encoding: PackedRdataEncoding::copy(),
            rdata,
        };

        assert_eq!(
            zone_image_wire_record_uncompressed_len(a),
            owner.len() + 10 + rdata.len()
        );
        let carried_len = ZoneImageWireRecord {
            rdlength_bytes: 1u16.to_be_bytes(),
            ..a
        };
        assert_eq!(
            zone_image_wire_record_uncompressed_len(carried_len),
            owner.len() + 10 + 1,
            "truncation accounting should read the carried prevalidated rdlength"
        );
    }

    #[test]
    fn zone_image_direct_answer_fast_path_handles_case_insensitive_owner() {
        let snapshot = ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            )],
        );
        let image = ZoneImage::compile(&snapshot).unwrap();
        let store = ZoneStore::new();
        store.insert_snapshot(snapshot);
        let packet = query(b"\x03WWW\x07Example\x04TEST\x00", RecordType::A as u16, 1);

        let direct =
            direct_zone_image_response_for_packet(&packet, &image, AnswerOptions::default())
                .expect("direct fast path should accept case-insensitive owner match");
        let snapshot_response = store_response(&packet, &store);

        assert_eq!(direct, snapshot_response);
        assert_eq!(direct[first_answer_offset(&direct)..][0] & 0xc0, 0xc0);
    }

    #[test]
    fn zone_image_direct_answer_fast_path_handles_opaque_unknown_rrsets() {
        const UNKNOWN_TYPE: u16 = 65_280;
        let pointer_like_rdata = vec![0xc0, 0x0c, 0, 255];
        let snapshot = ZoneSnapshot::active(
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
                    DomainName::from_absolute_str("opaque.example.test.").unwrap(),
                    UNKNOWN_TYPE,
                    1,
                    300,
                    vec![Vec::new(), pointer_like_rdata.clone()],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).unwrap();
        let store = ZoneStore::new();
        store.insert_snapshot(snapshot);
        let packet = query(b"\x06opaque\x07example\x04test\x00", UNKNOWN_TYPE, 1);

        let direct =
            direct_zone_image_response_for_packet(&packet, &image, AnswerOptions::default())
                .expect("direct fast path should accept opaque unknown RRsets");
        let snapshot_response = store_response(&packet, &store);

        assert_eq!(direct, snapshot_response);
        assert_eq!(
            response_answer_types(&direct),
            vec![UNKNOWN_TYPE, UNKNOWN_TYPE]
        );
        assert_eq!(
            response_answer_rdatas(&direct, UNKNOWN_TYPE),
            vec![Vec::new(), pointer_like_rdata]
        );
    }

    #[test]
    fn zone_image_direct_answer_fast_path_rejects_unsupported_shapes() {
        let snapshot = ZoneSnapshot::active(
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
                    vec![cname_rdata("ns.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 53].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("mx.example.test.").unwrap(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata(10, "mail.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.wild.example.test.").unwrap(),
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
        );
        let image = ZoneImage::compile(&snapshot).unwrap();
        let cname = query(
            b"\x05alias\x07example\x04test\x00",
            RecordType::Cname as u16,
            1,
        );
        let ns_with_additional = query(b"\x07example\x04test\x00", RecordType::Ns as u16, 1);
        let missing = query(
            b"\x07missing\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let tiny_udp = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let mut do_bit = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut do_bit, 4096, 0x8000, &[]);
        let soa_with_compressible_rdata =
            query(b"\x07example\x04test\x00", RecordType::Soa as u16, 1);
        let mx_with_compressible_rdata =
            query(b"\x02mx\x07example\x04test\x00", RecordType::Mx as u16, 1);
        let wildcard_cname_to_final_a = query(
            b"\x04host\x04wild\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );

        for (packet, options) in [
            (&cname, AnswerOptions::default()),
            (&ns_with_additional, AnswerOptions::default()),
            (&missing, AnswerOptions::default()),
            (&tiny_udp, AnswerOptions::udp(32)),
            (&do_bit, AnswerOptions::default()),
            (&soa_with_compressible_rdata, AnswerOptions::default()),
            (&mx_with_compressible_rdata, AnswerOptions::default()),
            (&wildcard_cname_to_final_a, AnswerOptions::default()),
        ] {
            assert!(
                direct_zone_image_response_for_packet(packet, &image, options).is_none(),
                "direct fast path accepted unsupported packet {packet:?}"
            );
        }
    }

    #[test]
    fn zone_image_serving_matches_snapshot_negative_response() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            )],
        ));

        let packet = query(
            b"\x07missing\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let snapshot_response = store_response(&packet, &store);
        let zone_image_response = store_response_with_zone_image(&packet, &store);

        assert_semantic_response_eq(&snapshot_response, &zone_image_response);
        assert_eq!(zone_image_response[3] & 0x0f, Rcode::NxDomain as u8);
    }

    #[test]
    fn zone_image_serving_compresses_known_name_rdata() {
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
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x05alias\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response_with_zone_image(&packet, &store);
        let cname_rdatas = response_answer_rdatas(&response, RecordType::Cname as u16);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(cname_rdatas.len(), 1);
        assert_ne!(cname_rdatas[0], cname_rdata("target.example.test."));
        assert_eq!(
            response_answer_single_name_rdatas(&response, RecordType::Cname as u16),
            vec![cname_rdata("target.example.test.")]
        );
    }

    #[test]
    fn zone_image_serving_matches_snapshot_for_malformed_known_name_rdata() {
        let cases = [
            (
                "bad_ns_target",
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Ns as u16,
                vec![0xc0, 0x0c],
                query(b"\x07example\x04test\x00", RecordType::Ns as u16, 1),
            ),
            (
                "bad_cname_target",
                DomainName::from_absolute_str("alias.example.test.").unwrap(),
                RecordType::Cname as u16,
                vec![0xc0, 0x0c],
                query(
                    b"\x05alias\x07example\x04test\x00",
                    RecordType::Cname as u16,
                    1,
                ),
            ),
            (
                "bad_mx_exchange",
                DomainName::from_absolute_str("mx.example.test.").unwrap(),
                RecordType::Mx as u16,
                vec![0, 10, 0xc0, 0x0c],
                query(b"\x02mx\x07example\x04test\x00", RecordType::Mx as u16, 1),
            ),
        ];

        for (case, owner, rr_type, rdata, packet) in cases {
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
                    Rrset::new(owner, rr_type, 1, 300, vec![rdata]),
                ],
            ));

            let snapshot_response = store_response(&packet, &store);
            let zone_image_response = store_response_with_zone_image(&packet, &store);
            assert_eq!(
                zone_image_response, snapshot_response,
                "packet mismatch for {case}"
            );
        }
    }

    #[test]
    fn zone_image_serving_matches_snapshot_mixed_packet_corpus() {
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
                    vec![cname_rdata("ns.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 53].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
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
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 14].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.wild.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 11].to_vec()],
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
                    vec![[192, 0, 2, 12].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("text.example.test.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![character_string(b"present")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("dname.example.test.").unwrap(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("host.target.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 13].to_vec()],
                ),
            ],
        ));

        for (qname, qtype) in [
            (
                b"\x03www\x07example\x04test\x00".as_slice(),
                RecordType::A as u16,
            ),
            (
                b"\x05alias\x07example\x04test\x00".as_slice(),
                RecordType::A as u16,
            ),
            (
                b"\x05alpha\x04wild\x07example\x04test\x00".as_slice(),
                RecordType::A as u16,
            ),
            (
                b"\x03www\x05child\x07example\x04test\x00".as_slice(),
                RecordType::A as u16,
            ),
            (
                b"\x04text\x07example\x04test\x00".as_slice(),
                RecordType::A as u16,
            ),
            (
                b"\x06absent\x07example\x04test\x00".as_slice(),
                RecordType::A as u16,
            ),
            (
                b"\x04host\x05dname\x07example\x04test\x00".as_slice(),
                RecordType::A as u16,
            ),
        ] {
            let packet = query(qname, qtype, 1);
            let snapshot_response = store_response(&packet, &store);
            let zone_image_response = store_response_with_zone_image(&packet, &store);

            assert_semantic_response_eq(&snapshot_response, &zone_image_response);
            assert_eq!(
                snapshot_response.len(),
                zone_image_response.len(),
                "response length mismatch for {:?}",
                qname
            );
        }
    }

    #[test]
    fn zone_image_generic_response_capacity_uses_plan_wire_bound_before_udp_ceiling() {
        let snapshot = ZoneSnapshot::active(
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
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        );
        let image = ZoneImage::compile(&snapshot).expect("zone image compiles");
        let mut packet = query(b"\x05alias\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[]);
        let header = Header::parse(&packet).expect("header parses");
        let question = Question::parse(&packet).expect("question parses");
        let metadata =
            RequestMetadata::parse(&header, &packet, &question).expect("metadata parses");
        let options = AnswerOptions::default();
        let udp_ceiling = metadata.udp_ceiling(options);
        let response_sizing =
            zone_image_response_sizing(&question, udp_ceiling, &metadata, options);
        let plan = image.lookup_response_plan(
            &question.qname,
            question.qtype,
            question.qclass,
            8,
            options.any_response,
        );
        let response = build_zone_image_response(
            &header,
            &question,
            &image,
            &plan,
            metadata,
            options,
            false,
            response_sizing,
        )
        .expect("zone image response builds");
        let lookup =
            snapshot
                .offline_oracle()
                .lookup(&question.qname, question.qtype, question.qclass);
        let snapshot_response = build_response_inner(
            &header,
            lookup.rcode,
            lookup.authoritative,
            false,
            Some(&question),
            &lookup.answers,
            &lookup.authorities,
            &lookup.additionals,
            &metadata,
            options,
        );

        assert_eq!(response, snapshot_response);
        assert_eq!(
            response.capacity(),
            DNS_HEADER_LEN
                .saturating_add(question.wire_len())
                .saturating_add(plan.response_body_wire_upper_bound())
                .saturating_add(response_sizing.edns.capacity_hint),
            "ordinary unpadded generic UDP response should size from the carried plan wire bound"
        );
        assert!(
            response.capacity() < 4096,
            "ordinary unpadded generic UDP response should not reserve the whole EDNS ceiling"
        );
    }

    #[test]
    fn zone_image_serving_handles_dnssec_do_queries() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
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
            ],
        ));
        let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);
        let observed = std::cell::Cell::new(None);

        let snapshot_response =
            store_response_with_options(&packet, &store, AnswerOptions::default());
        let zone_image_response =
            match answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
                &packet,
                &store,
                AnswerOptions::default(),
                |_, _| true,
                |_, _, _| {},
                |metrics| observed.set(Some(metrics)),
                &default_zone_image_provider,
            ) {
                DatagramAction::Discard => panic!("expected response"),
                DatagramAction::Respond(response) => response,
            };

        assert_eq!(zone_image_response, snapshot_response);
        assert_eq!(
            observed
                .get()
                .map(|metrics| metrics.zone_image_direct_answer),
            Some(false),
            "DO-bit responses should go directly to the generic DNSSEC composer"
        );
        assert_eq!(
            response_answer_types(&zone_image_response),
            vec![RecordType::A as u16, RecordType::Rrsig as u16]
        );
        assert_eq!(response_opt_ttl(&zone_image_response), Some(0x8000));
    }

    #[test]
    fn zone_image_serving_matches_dnssec_proof_selection_corpus() {
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
                    DomainName::from_absolute_str("example.test.").unwrap(),
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
                    vec![nsec_rdata("z.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
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
                    vec![rrsig_rdata(RecordType::A), rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));

        let mut positive = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut positive, 4096, 0x8000, &[]);
        let mut nodata = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Aaaa as u16,
            1,
        );
        append_opt(&mut nodata, 4096, 0x8000, &[]);
        let mut nxdomain = query(
            b"\x07missing\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut nxdomain, 4096, 0x8000, &[]);

        for packet in [&positive, &nodata, &nxdomain] {
            let snapshot_response =
                store_response_with_options(packet, &store, AnswerOptions::default());
            let zone_image_response = store_response_with_zone_image_provider(
                packet,
                &store,
                AnswerOptions::default(),
                &default_zone_image_provider,
            );

            assert_eq!(zone_image_response, snapshot_response);
            assert_eq!(response_opt_ttl(&zone_image_response), Some(0x8000));
        }

        assert_eq!(
            response_answer_types(&store_response_with_options(
                &positive,
                &store,
                AnswerOptions::default(),
            )),
            vec![RecordType::A as u16, RecordType::Rrsig as u16]
        );
        assert_eq!(
            response_authority_types(&store_response_with_options(
                &nodata,
                &store,
                AnswerOptions::default(),
            )),
            vec![
                RecordType::Soa as u16,
                RecordType::Nsec as u16,
                RecordType::Rrsig as u16,
            ]
        );
        assert_eq!(
            response_authority_types(&store_response_with_options(
                &nxdomain,
                &store,
                AnswerOptions::default(),
            )),
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
    fn zone_image_serving_matches_signed_packet_edge_corpus() {
        let cases = [
            (
                "wildcard_nsec_proof",
                ZoneSnapshot::active(
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
                ),
                query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1),
            ),
            (
                "signed_referral_with_ds",
                ZoneSnapshot::active(
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
                ),
                query(
                    b"\x03www\x05child\x07example\x04test\x00",
                    RecordType::A as u16,
                    1,
                ),
            ),
            (
                "unsigned_referral_nsec_proof",
                ZoneSnapshot::active(
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
                ),
                query(
                    b"\x03www\x05child\x07example\x04test\x00",
                    RecordType::A as u16,
                    1,
                ),
            ),
        ];

        for (case, snapshot, mut packet) in cases {
            append_opt(&mut packet, 4096, 0x8000, &[]);
            let store = ZoneStore::new();
            store.insert_snapshot(snapshot);

            let snapshot_response =
                store_response_with_options(&packet, &store, AnswerOptions::default());
            let zone_image_response = store_response_with_zone_image_provider(
                &packet,
                &store,
                AnswerOptions::default(),
                &default_zone_image_provider,
            );

            assert_eq!(
                zone_image_response, snapshot_response,
                "packet mismatch for {case}"
            );
            assert_eq!(response_opt_ttl(&zone_image_response), Some(0x8000));
        }
    }

    #[test]
    fn zone_image_serving_uses_provider_for_full_any_query() {
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
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![character_string(b"present")],
                ),
            ],
        ));
        let packet = query(b"\x05alias\x07example\x04test\x00", DNS_CLASS_ANY, 1);
        let options = AnswerOptions {
            any_response: AnyResponseMode::Full,
            ..AnswerOptions::default()
        };
        let observed = std::cell::Cell::new(None);

        let snapshot_response = store_response_with_options(&packet, &store, options);
        let zone_image_response =
            match answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
                &packet,
                &store,
                options,
                |_, _| true,
                |_, _, _| {},
                |metrics| observed.set(Some(metrics)),
                &default_zone_image_provider,
            ) {
                DatagramAction::Discard => panic!("expected response"),
                DatagramAction::Respond(response) => response,
            };

        assert_eq!(zone_image_response, snapshot_response);
        assert_eq!(
            observed
                .get()
                .and_then(|metrics| metrics.zone_image_failure_reason),
            None
        );
        assert_eq!(
            observed.get().map(|metrics| metrics.zone_image_used),
            Some(true)
        );
        assert_eq!(
            response_answer_types(&zone_image_response),
            vec![RecordType::Cname as u16, RecordType::Txt as u16]
        );
    }

    #[test]
    fn zone_image_serving_uses_provider_for_non_any_query_in_full_any_mode() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![vec![192, 0, 2, 1]],
            )],
        ));
        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let options = AnswerOptions {
            any_response: AnyResponseMode::Full,
            ..AnswerOptions::default()
        };
        let observed = std::cell::Cell::new(None);

        let snapshot_response = store_response_with_options(&packet, &store, options);
        let zone_image_response =
            match answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
                &packet,
                &store,
                options,
                |_, _| true,
                |_, _, _| {},
                |metrics| observed.set(Some(metrics)),
                &default_zone_image_provider,
            ) {
                DatagramAction::Discard => panic!("expected response"),
                DatagramAction::Respond(response) => response,
            };

        assert_eq!(zone_image_response, snapshot_response);
        assert_eq!(
            observed
                .get()
                .map(|metrics| (metrics.zone_image_used, metrics.zone_image_failure_reason)),
            Some((true, None))
        );
    }

    #[test]
    fn zone_image_serving_truncates_without_snapshot_fallback_when_udp_ceiling_requires_it() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                (0..20).map(|_| vec![60; 50]).collect(),
            )],
        ));
        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::Txt as u16, 1);
        let options = AnswerOptions::udp(128);
        let observed = std::cell::Cell::new(None);

        let snapshot_response = store_response_with_options(&packet, &store, options);
        let zone_image_response =
            match answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
                &packet,
                &store,
                options,
                |_, _| true,
                |_, _, _| {},
                |metrics| observed.set(Some(metrics)),
                &default_zone_image_provider,
            ) {
                DatagramAction::Discard => panic!("expected response"),
                DatagramAction::Respond(response) => response,
            };
        let flags = u16::from_be_bytes([zone_image_response[2], zone_image_response[3]]);

        assert_eq!(zone_image_response, snapshot_response);
        assert_eq!(
            observed
                .get()
                .map(|metrics| (metrics.zone_image_used, metrics.zone_image_failure_reason)),
            Some((true, None))
        );
        assert!(zone_image_response.len() <= 128);
        assert_eq!(flags & 0x0200, 0x0200);
    }

    #[test]
    fn zone_image_serving_matches_snapshot_with_edns_options() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::A as u16,
                1,
                300,
                vec![[192, 0, 2, 10].to_vec()],
            )],
        ));

        let mut nsid_packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(
            &mut nsid_packet,
            4096,
            0,
            &edns_option(EDNS_NSID_OPTION, &[]),
        );
        let nsid_options = AnswerOptions {
            nsid: b"dns-bud-1",
            ..AnswerOptions::default()
        };
        assert_eq!(
            store_response_with_zone_image_provider(
                &nsid_packet,
                &store,
                nsid_options,
                &default_zone_image_provider,
            ),
            store_response_with_options(&nsid_packet, &store, nsid_options)
        );

        let secret = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        let client_cookie = hex_to_vec("2464c4abcf10c957");
        let mut cookie_packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(
            &mut cookie_packet,
            4096,
            0,
            &edns_option(EDNS_COOKIE_OPTION, &client_cookie),
        );
        let cookie_options = AnswerOptions {
            dns_cookie: Some(context),
            ..AnswerOptions::default()
        };
        let cookie_response = store_response_with_zone_image_provider(
            &cookie_packet,
            &store,
            cookie_options,
            &default_zone_image_provider,
        );
        assert_eq!(
            cookie_response,
            store_response_with_options(&cookie_packet, &store, cookie_options)
        );
        assert_eq!(
            response_opt_option(&cookie_response, EDNS_COOKIE_OPTION),
            Some(hex_to_vec(
                "2464c4abcf10c957010000005cf79f111f8130c3eee29480"
            ))
        );

        let mut padding_packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(
            &mut padding_packet,
            4096,
            0,
            &edns_option(EDNS_PADDING_OPTION, &[0, 0, 0, 0]),
        );
        let padding_options = AnswerOptions {
            edns_padding_block_size: 32,
            ..AnswerOptions::default()
        };
        let padding_response = store_response_with_zone_image_provider(
            &padding_packet,
            &store,
            padding_options,
            &default_zone_image_provider,
        );
        assert_eq!(
            padding_response,
            store_response_with_options(&padding_packet, &store, padding_options)
        );
        assert_eq!(padding_response.len() % 32, 0);
    }

    #[test]
    fn zone_image_serving_preserves_ede_not_ready_without_image_attempt() {
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());
        let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[]);
        let options = AnswerOptions {
            extended_dns_errors: ExtendedDnsErrorsMode::Minimal,
            ..AnswerOptions::default()
        };
        let snapshot_response = store_response_with_options(&packet, &store, options);
        let zone_image_response = store_response_with_zone_image_provider(
            &packet,
            &store,
            options,
            &default_zone_image_provider,
        );

        assert_eq!(zone_image_response, snapshot_response);
        assert_eq!(zone_image_response[3] & 0x0f, Rcode::ServFail as u8);
        assert_eq!(
            response_ede_info_codes(&zone_image_response),
            vec![EDE_NOT_READY]
        );
    }

    #[test]
    fn zone_image_failure_response_uses_zone_image_prefix_path() {
        let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[]);
        let header = Header::parse(&packet).expect("header parses");
        let question = Question::parse(&packet).expect("question parses");
        let metadata = RequestMetadata::parse(&header, &packet, &question)
            .expect("metadata parses")
            .with_extended_dns_error(ExtendedDnsError::NotReady);
        let options = AnswerOptions {
            extended_dns_errors: ExtendedDnsErrorsMode::Minimal,
            ..AnswerOptions::default()
        };

        let response = build_zone_image_failure_response(&header, &question, metadata, options);
        let expected = build_response(
            &header,
            Rcode::ServFail,
            true,
            Some(&question),
            &[],
            &[],
            &[],
            metadata,
            options,
        );

        assert_eq!(response, expected);
        assert_eq!(response_ede_info_codes(&response), vec![EDE_NOT_READY]);
    }

    #[test]
    fn empty_response_uses_zone_image_prefix_and_edns_path() {
        let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &edns_option(EDNS_NSID_OPTION, &[]));
        let header = Header::parse(&packet).expect("header parses");
        let question = Question::parse(&packet).expect("question parses");
        let metadata =
            RequestMetadata::parse(&header, &packet, &question).expect("metadata parses");
        let options = AnswerOptions {
            nsid: b"dns-bud-1",
            ..AnswerOptions::default()
        };

        let response = build_response(
            &header,
            Rcode::Refused,
            false,
            Some(&question),
            &[],
            &[],
            &[],
            metadata,
            options,
        );

        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 1);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(
            response_opt_option(&response, EDNS_NSID_OPTION),
            Some(b"dns-bud-1".to_vec())
        );
    }

    #[test]
    fn zone_image_serving_matches_snapshot_across_udp_ceiling_cases() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("big.example.test.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    (0..20).map(|_| vec![60; 50]).collect(),
                ),
            ],
        ));

        let mut small_edns_512 = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut small_edns_512, 512, 0, &[]);
        let mut big_edns_1232 = query(b"\x03big\x07example\x04test\x00", RecordType::Txt as u16, 1);
        append_opt(&mut big_edns_1232, 4096, 0, &[]);
        let mut big_edns_4096 = query(b"\x03big\x07example\x04test\x00", RecordType::Txt as u16, 1);
        append_opt(&mut big_edns_4096, 4096, 0, &[]);

        for (packet, options, expect_truncated) in [
            (
                query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1),
                AnswerOptions::udp(512),
                false,
            ),
            (small_edns_512, AnswerOptions::udp(1232), false),
            (
                query(b"\x03big\x07example\x04test\x00", RecordType::Txt as u16, 1),
                AnswerOptions::udp(1232),
                true,
            ),
            (big_edns_1232, AnswerOptions::udp(1232), true),
            (big_edns_4096, AnswerOptions::udp(4096), false),
        ] {
            let snapshot_response = store_response_with_options(&packet, &store, options);
            let zone_image_response = store_response_with_zone_image_provider(
                &packet,
                &store,
                options,
                &default_zone_image_provider,
            );
            let flags = u16::from_be_bytes([zone_image_response[2], zone_image_response[3]]);

            assert_eq!(zone_image_response, snapshot_response);
            assert_eq!(flags & 0x0200 != 0, expect_truncated);
            if options.transport == Transport::Udp {
                assert!(zone_image_response.len() <= options.max_udp_payload as usize);
            }
        }
    }

    #[test]
    fn direct_soa_answer_keeps_rrset_ttl() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![soa_rdata()],
            )],
        ));

        let packet = query(b"\x07example\x04test\x00", RecordType::Soa as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(
            response_answer_ttls(&response, RecordType::Soa as u16),
            vec![3600]
        );
    }

    #[test]
    fn qclass_any_matches_in_zone_data() {
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
            ],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 255);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
    }

    #[test]
    fn unknown_type_query_preserves_zero_and_pointer_like_rdata() {
        const UNKNOWN_TYPE: u16 = 65_280;
        let pointer_like_rdata = vec![0xc0, 0x0c, 0, 255];
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
                    DomainName::from_absolute_str("opaque.example.test.").unwrap(),
                    UNKNOWN_TYPE,
                    1,
                    300,
                    vec![Vec::new(), pointer_like_rdata.clone()],
                ),
            ],
        ));

        let packet = query(b"\x06opaque\x07example\x04test\x00", UNKNOWN_TYPE, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![UNKNOWN_TYPE, UNKNOWN_TYPE]
        );
        assert_eq!(
            response_answer_rdatas(&response, UNKNOWN_TYPE),
            vec![Vec::new(), pointer_like_rdata]
        );
    }

    #[test]
    fn response_owner_names_are_compressed_against_question() {
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
            ],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);
        let answer_offset = first_answer_offset(&response);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(&response[answer_offset..answer_offset + 2], &[0xc0, 0x0c]);
        assert_eq!(
            response_answers(&response)[0].0.to_string(),
            "www.example.test."
        );
    }

    #[test]
    fn compressed_qname_is_reencoded_before_response_compression() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("www.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("www.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        ));
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(b"\x03www\xc0\x04");
        packet.extend_from_slice(&(RecordType::A as u16).to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        let parsed_question = Question::parse(&packet).unwrap();
        assert_eq!(parsed_question.qname.to_string(), "www.");
        assert_eq!(parsed_question.wire_len(), 10);
        assert_eq!(parsed_question.qname_wire_len(), 6);
        assert!(parsed_question.qname_ascii_lowercase());
        assert_eq!(parsed_question.qtype, RecordType::A as u16);
        assert_eq!(
            parsed_question.qtype_qclass_wire,
            [0, RecordType::A as u8, 0, 1,],
            "question stores parsed QTYPE/QCLASS wire bytes for response echo"
        );
        assert_eq!(
            parsed_question.qname.canonical_key(),
            DomainName::from_absolute_str("www.")
                .unwrap()
                .canonical_key()
        );
        assert!(
            parsed_question
                .qname
                .is_equal_or_subdomain_of(&DomainName::from_absolute_str("www.").unwrap())
        );
        assert!(store.find_published_zone(&parsed_question.qname).is_some());

        let mut mixed_case_packet = packet.clone();
        mixed_case_packet[13..16].copy_from_slice(b"WWW");
        let mixed_case_question = Question::parse(&mixed_case_packet).unwrap();
        assert_eq!(mixed_case_question.qname.to_string(), "WWW.");
        assert!(!mixed_case_question.qname_ascii_lowercase());

        let response = store_response(&packet, &store);
        let answer_offset = first_answer_offset(&response);
        let (question_name, consumed) = DomainName::parse(&response, DNS_HEADER_LEN).unwrap();

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(question_name.to_string(), "www.");
        assert_eq!(
            &response[DNS_HEADER_LEN..DNS_HEADER_LEN + consumed],
            b"\x03www\x00"
        );
        assert_eq!(&response[answer_offset..answer_offset + 2], &[0xc0, 0x0c]);
    }

    #[test]
    fn permitted_name_rdata_is_compressed_but_unknown_rdata_stays_opaque() {
        const UNKNOWN_TYPE: u16 = 65_280;
        let pointer_like_rdata = vec![0xc0, 0x0c, 0, 255];
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
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    UNKNOWN_TYPE,
                    1,
                    300,
                    vec![pointer_like_rdata.clone()],
                ),
            ],
        ));

        let packet = query(b"\x05alias\x07example\x04test\x00", DNS_CLASS_ANY, 1);
        let response = store_response_with_options(
            &packet,
            &store,
            AnswerOptions {
                any_response: AnyResponseMode::Full,
                ..AnswerOptions::default()
            },
        );
        let cname_rdatas = response_answer_rdatas(&response, RecordType::Cname as u16);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(cname_rdatas.len(), 1);
        assert_ne!(cname_rdatas[0], cname_rdata("target.example.test."));
        assert_eq!(&cname_rdatas[0], b"\x06target\xc0\x12");
        assert_eq!(
            response_answer_single_name_rdatas(&response, RecordType::Cname as u16),
            vec![cname_rdata("target.example.test.")]
        );
        assert_eq!(
            response_answer_rdatas(&response, UNKNOWN_TYPE),
            vec![pointer_like_rdata]
        );
    }
