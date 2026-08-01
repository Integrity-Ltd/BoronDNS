    #[test]
    fn discards_short_header() {
        assert_eq!(
            answer_datagram(&[0; 11], &ZoneStore::new()),
            DatagramAction::Discard
        );
    }

    #[test]
    fn discards_response_on_query_socket() {
        let mut packet = query(&example_name(), 1, 1);
        packet[2] = 0x80;
        assert_eq!(
            answer_datagram(&packet, &ZoneStore::new()),
            DatagramAction::Discard
        );
    }

    #[test]
    fn unsupported_opcode_gets_notimp() {
        let mut packet = query(&example_name(), 1, 1);
        packet[2] = 0x28;
        let response = store_response(&packet, &ZoneStore::new());
        assert_eq!(response[3] & 0x0f, Rcode::NotImp as u8);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn dns_update_opcode_gets_notimp_without_zone_mutation() {
        let mut packet = query(&example_name(), RecordType::Soa as u16, 1);
        packet[2..4].copy_from_slice(&(5u16 << 11).to_be_bytes());

        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(7),
            Vec::new(),
        ));

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NotImp as u8);
        let origin = DomainName::from_absolute_str("example.test.").unwrap();
        assert_eq!(
            store
                .exact_snapshot_for_transfer(&origin)
                .expect("zone exists")
                .metadata()
                .serial,
            Some(7)
        );
    }

    #[test]
    fn invalid_qdcount_gets_formerr_without_question() {
        let mut packet = query(&example_name(), 1, 1);
        packet[5] = 2;
        let response = store_response(&packet, &ZoneStore::new());
        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 0);
    }

    #[test]
    fn standard_query_rejects_nonempty_answer_section() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_answer(
            &mut packet,
            "example.test.",
            RecordType::A as u16,
            1,
            vec![192, 0, 2, 1],
        );

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }

    #[test]
    fn standard_query_rejects_nonempty_authority_section() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_answer(
            &mut packet,
            "example.test.",
            RecordType::Ns as u16,
            1,
            cname_rdata("ns.example.test."),
        );
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet[8..10].copy_from_slice(&1u16.to_be_bytes());

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }

    #[test]
    fn notify_soa_for_configured_zone_gets_notify_response() {
        let packet = notify(&example_name(), RecordType::Soa as u16, 1);
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x7800, (Opcode::Notify as u16) << 11);
        assert_eq!(flags & 0x0400, 0x0400);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn notify_with_nonzero_reserved_request_flags_is_ignored() {
        for invalid_bits in [0x0200u16, 0x0100, 0x0080, 0x0040, 0x0020, 0x0010, 0x0001] {
            let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
            let flags = u16::from_be_bytes([packet[2], packet[3]]) | invalid_bits;
            packet[2..4].copy_from_slice(&flags.to_be_bytes());
            let store = ZoneStore::new();
            store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());
            let accepted = std::cell::Cell::new(false);

            let action = answer_message_with_notify_hooks(
                &packet,
                &store,
                AnswerOptions::default(),
                |_, _| true,
                |_, _, _| accepted.set(true),
            );

            assert_eq!(action, DatagramAction::Discard, "invalid bits {invalid_bits:#06x}");
            assert!(!accepted.get(), "invalid NOTIFY must not enqueue refresh");
        }
    }

    #[test]
    fn notify_embedded_soa_matching_question_is_accepted() {
        let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
        append_answer(
            &mut packet,
            "example.test.",
            RecordType::Soa as u16,
            1,
            soa_rdata(),
        );
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn notify_embedded_soa_owner_matches_case_insensitively() {
        let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
        append_answer(
            &mut packet,
            "EXAMPLE.TEST.",
            RecordType::Soa as u16,
            1,
            soa_rdata(),
        );
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn notify_embedded_soa_accepts_compressed_rdata_names() {
        let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
        let mut rdata = b"\x02ns\xc0\x0c\x0ahostmaster\xc0\x0c".to_vec();
        rdata.extend_from_slice(&1u32.to_be_bytes());
        rdata.extend_from_slice(&60u32.to_be_bytes());
        rdata.extend_from_slice(&30u32.to_be_bytes());
        rdata.extend_from_slice(&300u32.to_be_bytes());
        rdata.extend_from_slice(&300u32.to_be_bytes());
        append_answer(
            &mut packet,
            "example.test.",
            RecordType::Soa as u16,
            1,
            rdata,
        );
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());
        let observed = std::cell::Cell::new(None);

        let response = match answer_message_with_notify_hooks(
            &packet,
            &store,
            AnswerOptions::default(),
            |_, _| true,
            |_, _, serial| observed.set(serial),
        ) {
            DatagramAction::Respond(response) => response,
            DatagramAction::Discard => panic!("expected NOTIFY response"),
        };

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(observed.get(), Some(1));
    }

    #[test]
    fn notify_embedded_soa_owner_mismatch_gets_formerr() {
        let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
        append_answer(
            &mut packet,
            "other.example.test.",
            RecordType::Soa as u16,
            1,
            soa_rdata(),
        );
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }

    #[test]
    fn notify_embedded_soa_class_mismatch_gets_formerr() {
        let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
        append_answer(
            &mut packet,
            "example.test.",
            RecordType::Soa as u16,
            3,
            soa_rdata(),
        );
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }

    #[test]
    fn notify_non_soa_question_gets_formerr() {
        let packet = notify(&example_name(), RecordType::A as u16, 1);
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn notify_unknown_zone_gets_refused() {
        let packet = notify(&example_name(), RecordType::Soa as u16, 1);
        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn notify_unauthorized_source_is_discarded() {
        let packet = notify(&example_name(), RecordType::Soa as u16, 1);
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let action = answer_message_with_notify_authority(
            &packet,
            &store,
            AnswerOptions::default(),
            |_, _| false,
        );

        assert_eq!(action, DatagramAction::Discard);
    }

    #[test]
    fn notify_acceptance_hook_receives_embedded_soa_serial() {
        let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
        append_answer(
            &mut packet,
            "example.test.",
            RecordType::Soa as u16,
            1,
            soa_rdata(),
        );
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());
        let observed = std::cell::Cell::new(None);

        let response = match answer_message_with_notify_hooks(
            &packet,
            &store,
            AnswerOptions::default(),
            |_, _| true,
            |_, _, serial| observed.set(serial),
        ) {
            DatagramAction::Respond(response) => response,
            DatagramAction::Discard => panic!("expected NOTIFY response"),
        };

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(observed.get(), Some(1));
    }

    #[test]
    fn malformed_qname_gets_formerr() {
        let packet = query(b"\xc0\x0c", 1, 1);
        let response = store_response(&packet, &ZoneStore::new());
        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }

    #[test]
    fn answer_datagram_does_not_panic_for_malformed_corpus() {
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());
        let mut corpus = Vec::new();

        for len in 0..=32 {
            let mut packet = Vec::with_capacity(len);
            for index in 0..len {
                packet.push(((index * 37 + len * 11) & 0xff) as u8);
            }
            corpus.push(packet);
        }

        corpus.extend([
            query(b"\xc0\x0c", 1, 1),
            query(b"\xc0\xff", 1, 1),
            query(b"\x3ftruncated-label", 1, 1),
            query(b"\x04loop\xc0\x0c", 1, 1),
            query(b"\xff", 1, 1),
        ]);

        let mut qdcount_overflow = query(&example_name(), 1, 1);
        qdcount_overflow[4..6].copy_from_slice(&2u16.to_be_bytes());
        corpus.push(qdcount_overflow);

        let mut truncated_extra_section = query(&example_name(), 1, 1);
        truncated_extra_section[10..12].copy_from_slice(&1u16.to_be_bytes());
        truncated_extra_section.push(0);
        corpus.push(truncated_extra_section);

        let mut malformed_opt = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut malformed_opt, 4096, 0, &[0, 1, 0]);
        corpus.push(malformed_opt);

        let mut response_packet = query(&example_name(), 1, 1);
        response_packet[2] = 0x80;
        corpus.push(response_packet);

        let mut unsupported_opcode = query(&example_name(), 1, 1);
        unsupported_opcode[2] = 0x78;
        corpus.push(unsupported_opcode);

        for packet in corpus {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = answer_datagram(&packet, &store);
            }));
            assert!(result.is_ok(), "answer_datagram panicked for {packet:02x?}");
        }
    }

    #[test]
    fn unsupported_qclass_gets_refused_with_question() {
        let packet = query(&example_name(), 1, 3);
        let response = store_response(&packet, &ZoneStore::new());
        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn chaos_version_txt_defaults_to_refused() {
        let packet = query(
            &DomainName::from_absolute_str("version.bind.")
                .unwrap()
                .to_wire(),
            RecordType::Txt as u16,
            DNS_CLASS_CH,
        );

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn chaos_version_txt_returns_configured_value() {
        let packet = query(
            &DomainName::from_absolute_str("version.server.")
                .unwrap()
                .to_wire(),
            RecordType::Txt as u16,
            DNS_CLASS_CH,
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                chaos: ChaosOptions {
                    version: "BoronDNS anycast",
                    hostname: "",
                },
                ..AnswerOptions::default()
            },
        );
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0x0400);
        assert_eq!(
            response_answer_classes(&response, RecordType::Txt as u16),
            vec![DNS_CLASS_CH]
        );
        assert_eq!(
            response_answer_ttls(&response, RecordType::Txt as u16),
            vec![0]
        );
        assert_eq!(
            response_answer_rdatas(&response, RecordType::Txt as u16),
            vec![b"\x10BoronDNS anycast".to_vec()]
        );
    }

    #[test]
    fn chaos_txt_response_uses_direct_question_owner_pointer() {
        let mut packet = query(
            &DomainName::from_absolute_str("version.bind.")
                .unwrap()
                .to_wire(),
            RecordType::Txt as u16,
            DNS_CLASS_CH,
        );
        append_opt(&mut packet, 4096, 0, &edns_option(EDNS_NSID_OPTION, &[]));

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                chaos: ChaosOptions {
                    version: "BoronDNS",
                    hostname: "",
                },
                nsid: b"dns-bud-1",
                ..AnswerOptions::default()
            },
        );
        let answer_offset = first_answer_offset(&response);

        assert_eq!(&response[answer_offset..answer_offset + 2], b"\xc0\x0c");
        assert_eq!(
            response_answer_rdatas(&response, RecordType::Txt as u16),
            vec![b"\x08BoronDNS".to_vec()]
        );
        assert_eq!(
            response_opt_option(&response, EDNS_NSID_OPTION),
            Some(b"dns-bud-1".to_vec())
        );
    }

    #[test]
    fn chaos_version_name_matches_case_insensitively_without_canonical_key() {
        let packet = query(
            &DomainName::from_absolute_str("VeRsIoN.BiNd.")
                .unwrap()
                .to_wire(),
            RecordType::Txt as u16,
            DNS_CLASS_CH,
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                chaos: ChaosOptions {
                    version: "BoronDNS",
                    hostname: "",
                },
                ..AnswerOptions::default()
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_rdatas(&response, RecordType::Txt as u16),
            vec![b"\x08BoronDNS".to_vec()]
        );
    }

    #[test]
    fn chaos_hostname_txt_uses_config_then_printable_nsid_fallback() {
        for (chaos, nsid, expected) in [
            (
                ChaosOptions {
                    version: "",
                    hostname: "bud-dns-1",
                },
                b"ignored".as_slice(),
                b"\x09bud-dns-1".to_vec(),
            ),
            (
                ChaosOptions {
                    version: "",
                    hostname: "",
                },
                b"nsid-bud-2".as_slice(),
                b"\x0ansid-bud-2".to_vec(),
            ),
        ] {
            let packet = query(
                &DomainName::from_absolute_str("id.server.")
                    .unwrap()
                    .to_wire(),
                RecordType::Txt as u16,
                DNS_CLASS_CH,
            );
            let response = store_response_with_options(
                &packet,
                &ZoneStore::new(),
                AnswerOptions {
                    chaos,
                    nsid,
                    ..AnswerOptions::default()
                },
            );

            assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
            assert_eq!(
                response_answer_rdatas(&response, RecordType::Txt as u16),
                vec![expected]
            );
        }
    }

    #[test]
    fn chaos_hostname_txt_refuses_nonprintable_nsid() {
        let packet = query(
            &DomainName::from_absolute_str("hostname.bind.")
                .unwrap()
                .to_wire(),
            RecordType::Txt as u16,
            DNS_CLASS_CH,
        );
        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                nsid: b"bud\x00node",
                ..AnswerOptions::default()
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn chaos_unsupported_names_and_non_txt_types_are_refused() {
        for (name, qtype) in [
            ("authors.bind.", RecordType::Txt as u16),
            ("site.example.", RecordType::Txt as u16),
            ("version.bind.", RecordType::A as u16),
            ("version.bind.", RecordType::Axfr as u16),
            ("version.bind.", 255),
        ] {
            let packet = query(
                &DomainName::from_absolute_str(name).unwrap().to_wire(),
                qtype,
                DNS_CLASS_CH,
            );
            let response = store_response_with_options(
                &packet,
                &ZoneStore::new(),
                AnswerOptions {
                    chaos: ChaosOptions {
                        version: "BoronDNS",
                        hostname: "node",
                    },
                    ..AnswerOptions::default()
                },
            );

            assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
            assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
            assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
        }
    }

    #[test]
    fn in_class_version_name_uses_normal_zone_lookup() {
        let packet = query(
            &DomainName::from_absolute_str("version.bind.")
                .unwrap()
                .to_wire(),
            RecordType::Txt as u16,
            DNS_CLASS_IN,
        );
        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                chaos: ChaosOptions {
                    version: "BoronDNS",
                    hostname: "node",
                },
                ..AnswerOptions::default()
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn chaos_query_observation_classifies_supported_cases() {
        let packet = query(
            &DomainName::from_absolute_str("version.bind.")
                .unwrap()
                .to_wire(),
            RecordType::Txt as u16,
            DNS_CLASS_CH,
        );

        let observation = chaos_query_observation(
            &packet,
            &[],
            ChaosOptions {
                version: "BoronDNS",
                hostname: "",
            },
        )
        .expect("CHAOS observation");

        assert_eq!(observation.qname, "version.bind.");
        assert_eq!(observation.qtype, RecordType::Txt as u16);
        assert_eq!(observation.outcome, ChaosQueryOutcome::Answered);
    }

    #[test]
    fn outside_served_zones_gets_refused() {
        let packet = query(&example_name(), 1, 1);
        let zones = [DomainName::from_absolute_str("other.test.").unwrap()];
        let response = response(&packet, &zones);
        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
    }

    #[test]
    fn configured_but_unloaded_zone_gets_servfail() {
        let packet = query(&example_name(), 1, 1);
        let zones = [DomainName::from_absolute_str("test.").unwrap()];
        let response = response(&packet, &zones);
        assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn preserves_rd_and_clears_ra_z_ad_cd_bits() {
        let mut packet = query(&example_name(), 1, 1);
        packet[2..4].copy_from_slice(&0x01f0u16.to_be_bytes());
        let response = store_response(&packet, &ZoneStore::new());
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x8000, 0x8000);
        assert_eq!(flags & 0x0100, 0x0100);
        assert_eq!(flags & 0x0080, 0);
        assert_eq!(flags & 0x0070, 0);
        assert_eq!(flags & 0x0020, 0);
        assert_eq!(flags & 0x0010, 0);
    }

    #[test]
    fn parses_compressed_qname() {
        let mut packet = query(&example_name(), 1, 1);
        packet.extend_from_slice(&0x9999u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        let compressed_offset = packet.len();
        packet.extend_from_slice(b"\xc0\x0c");
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        let (name, consumed) = DomainName::parse(&packet, compressed_offset).unwrap();
        assert_eq!(name.to_string(), "Example.test.");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn skip_compressed_name_matches_parser_consumed_length() {
        let mut packet = query(&example_name(), 1, 1);
        packet.extend_from_slice(&0x9999u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        let compressed_offset = packet.len();
        packet.extend_from_slice(b"\xc0\x0c");

        let (_, parsed_consumed) = DomainName::parse(&packet, compressed_offset).unwrap();

        assert_eq!(parsed_consumed, 2);
        assert_eq!(
            skip_compressed_name(&packet, compressed_offset).unwrap(),
            parsed_consumed
        );
    }

    #[test]
    fn parses_nested_compression_without_consumed_underflow() {
        let packet = b"\x07example\x04test\x00\x02ns\xc0\x00\x04mail\xc0\x0e";

        let (name, consumed) = DomainName::parse(packet, 19).unwrap();

        assert_eq!(name.to_string(), "mail.ns.example.test.");
        assert_eq!(consumed, 7);
    }

    #[test]
    fn skip_compressed_name_validates_without_materializing_labels() {
        let packet = b"\x07example\x04test\x00\x02ns\xc0\x00\x04mail\xc0\x0e";

        assert_eq!(skip_compressed_name(packet, 19).unwrap(), 7);
    }

    #[test]
    fn skip_compressed_name_rejects_pointer_loop() {
        let packet = b"\xc0\x00";

        assert_eq!(
            skip_compressed_name(packet, 0).expect_err("pointer loop must fail"),
            DnsParseError::FormErr
        );
    }

    #[test]
    fn domain_name_parse_rejects_forward_compression_pointer() {
        let packet = b"\xc0\x02\x00";

        assert_eq!(
            DomainName::parse(packet, 0).expect_err("RFC 1035 pointers refer to prior names"),
            DnsParseError::FormErr
        );
    }

    #[test]
    fn compressed_name_scanner_rejects_forward_pointer() {
        let packet = b"\xc0\x02\x00";

        assert_eq!(
            skip_compressed_name(packet, 0)
                .expect_err("RFC 9267 requires position-aware pointer validation"),
            DnsParseError::FormErr
        );
    }

    #[test]
    fn parse_rejects_excessive_compression_pointer_chain() {
        let (packet, offset) = compressed_pointer_chain(MAX_COMPRESSED_NAME_POINTERS + 1);

        assert_eq!(
            DomainName::parse(&packet, offset).expect_err("long pointer chain must fail"),
            DnsParseError::FormErr
        );
    }

    #[test]
    fn skip_compressed_name_rejects_excessive_pointer_chain() {
        let (packet, offset) = compressed_pointer_chain(MAX_COMPRESSED_NAME_POINTERS + 1);

        assert_eq!(
            skip_compressed_name(&packet, offset).expect_err("long pointer chain must fail"),
            DnsParseError::FormErr
        );
    }

    fn compressed_pointer_chain(pointer_count: usize) -> (Vec<u8>, usize) {
        let mut packet = Vec::with_capacity(pointer_count * 2 + 1);
        packet.push(0);
        let mut target = 0u16;
        for _ in 0..pointer_count {
            let pointer_offset = packet.len();
            packet.push(0xc0 | ((target >> 8) as u8 & 0x3f));
            packet.push(target as u8);
            target = pointer_offset as u16;
        }
        (packet, usize::from(target))
    }

    #[test]
    fn parse_record_view_matches_compressed_owner_in_one_scan() {
        let mut packet = b"\x07example\x04test\x00".to_vec();
        let record_offset = packet.len();
        packet.extend_from_slice(b"\x03WWW\xc0\x00");
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 0, 2, 1]);
        let expected = DomainName::from_absolute_str("www.example.test.").unwrap();

        let ((record, matches), consumed) =
            parse_record_view_with_owner_match(&packet, record_offset, &expected).unwrap();

        assert!(matches);
        assert_eq!(record.rr_type, 1);
        assert_eq!(record.rdata, [192, 0, 2, 1]);
        assert_eq!(consumed, 6 + 10 + 4);
    }

    #[test]
    fn parse_record_view_rejects_compressed_owner_mismatch() {
        let mut packet = b"\x07example\x04test\x00".to_vec();
        let record_offset = packet.len();
        packet.extend_from_slice(b"\x03api\xc0\x00");
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 0, 2, 1]);
        let expected = DomainName::from_absolute_str("www.example.test.").unwrap();

        let ((record, matches), consumed) =
            parse_record_view_with_owner_match(&packet, record_offset, &expected).unwrap();

        assert!(!matches);
        assert_eq!(record.rr_type, 1);
        assert_eq!(consumed, 6 + 10 + 4);
    }

    #[test]
    fn parse_record_header_skips_compressed_owner() {
        let mut packet = query(&example_name(), 1, 1);
        let record_offset = packet.len();
        packet.extend_from_slice(b"\xc0\x0c");
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 0, 2, 1]);

        let (rr_type, consumed) = parse_record_header(&packet, record_offset).unwrap();

        assert_eq!(rr_type, 1);
        assert_eq!(consumed, 2 + 10 + 4);
    }

    #[test]
    fn parse_record_view_detects_compressed_root_owner_without_materializing() {
        let mut packet = query(&example_name(), 1, 1);
        let root_offset = packet.len();
        packet.push(0);
        let record_offset = packet.len();
        packet.push(0xc0);
        packet.push(root_offset as u8);
        packet.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
        packet.extend_from_slice(&1232u16.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());

        let (record, consumed) = parse_record_view(&packet, record_offset).unwrap();

        assert!(record.owner_is_root);
        assert_eq!(record.rr_type, RecordType::Opt as u16);
        assert_eq!(record.class, 1232);
        assert_eq!(consumed, 2 + 10);
    }

    #[test]
    fn parse_with_ascii_lowercase_tracks_nested_compressed_name() {
        let lowercase = b"\x07example\x04test\x00\x02ns\xc0\x00\x04mail\xc0\x0e";
        let (name, consumed, ascii_lowercase) =
            DomainName::parse_with_ascii_lowercase(lowercase, 19).unwrap();
        assert_eq!(name.to_string(), "mail.ns.example.test.");
        assert_eq!(consumed, 7);
        assert!(ascii_lowercase);

        let mixed_case = b"\x07Example\x04test\x00\x02ns\xc0\x00\x04mail\xc0\x0e";
        let (name, consumed, ascii_lowercase) =
            DomainName::parse_with_ascii_lowercase(mixed_case, 19).unwrap();
        assert_eq!(name.to_string(), "mail.ns.Example.test.");
        assert_eq!(consumed, 7);
        assert!(!ascii_lowercase);
    }
