    #[test]
    fn edns_query_gets_opt_response() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD),
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        let opt_offset = response.len() - 11;
        assert_eq!(response[opt_offset], 0);
        assert_eq!(
            u16::from_be_bytes([response[opt_offset + 1], response[opt_offset + 2]]),
            RecordType::Opt as u16
        );
        assert_eq!(
            u16::from_be_bytes([response[opt_offset + 3], response[opt_offset + 4]]),
            DEFAULT_MAX_UDP_PAYLOAD
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn tcp_edns_keepalive_request_gets_timeout_response() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &[0, EDNS_TCP_KEEPALIVE_OPTION as u8, 0, 0],
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Tcp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: 5,
                edns_padding_block_size: 0,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: &[],
                chaos: ChaosOptions::default(),
                dns_cookie: None,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(
            response_opt_rdata(&response),
            Some(vec![0, EDNS_TCP_KEEPALIVE_OPTION as u8, 0, 2, 0, 50])
        );
    }

    #[test]
    fn tcp_edns_keepalive_request_with_timeout_gets_formerr_and_opt() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &[0, EDNS_TCP_KEEPALIVE_OPTION as u8, 0, 2, 0, 50],
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions::tcp(),
        );

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn udp_edns_keepalive_request_is_ignored() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &[0, EDNS_TCP_KEEPALIVE_OPTION as u8, 0, 0],
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD),
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn edns_nsid_request_returns_configured_identifier() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[0, EDNS_NSID_OPTION as u8, 0, 0]);

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: b"dns-bud-1",
                chaos: ChaosOptions::default(),
                dns_cookie: None,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(
            response_opt_rdata(&response),
            Some(b"\x00\x03\x00\tdns-bud-1".to_vec())
        );
    }

    #[test]
    fn edns_nsid_request_is_ignored_without_configured_identifier() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[0, EDNS_NSID_OPTION as u8, 0, 0]);

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD),
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn edns_nsid_nonzero_query_data_is_treated_as_request() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &[0, EDNS_NSID_OPTION as u8, 0, 3, b'b', b'a', b'd'],
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: b"dns-bud-1",
                chaos: ChaosOptions::default(),
                dns_cookie: None,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(
            response_opt_rdata(&response),
            Some(b"\x00\x03\x00\tdns-bud-1".to_vec())
        );
    }

    #[test]
    fn edns_cookie_absent_does_not_emit_cookie_option() {
        let secret = [7; 16];
        let context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[]);

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: &[],
                chaos: ChaosOptions::default(),
                dns_cookie: Some(context),
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
        assert_eq!(
            dns_cookie_request_status(&packet, Some(context)),
            Some(DnsCookieRequestStatus::NoCookie)
        );
    }

    #[test]
    fn edns_client_cookie_only_returns_rfc9018_server_cookie() {
        let secret = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let client_cookie = hex_to_vec("2464c4abcf10c957");
        let context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &edns_option(EDNS_COOKIE_OPTION, &client_cookie),
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: &[],
                chaos: ChaosOptions::default(),
                dns_cookie: Some(context),
            },
        );

        assert_eq!(
            response_opt_option(&response, EDNS_COOKIE_OPTION),
            Some(hex_to_vec(
                "2464c4abcf10c957010000005cf79f111f8130c3eee29480"
            ))
        );
        assert_eq!(
            dns_cookie_request_status(&packet, Some(context)),
            Some(DnsCookieRequestStatus::ClientCookieOnly)
        );
    }

    #[test]
    fn malformed_duplicate_cookie_after_valid_cookie_is_ignored() {
        let secret = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let client_cookie = hex_to_vec("2464c4abcf10c957");
        let context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        let mut options = edns_option(EDNS_COOKIE_OPTION, &client_cookie);
        options.extend_from_slice(&edns_option(EDNS_COOKIE_OPTION, &[0]));
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &options);

        assert_eq!(
            dns_cookie_request_status(&packet, Some(context)),
            Some(DnsCookieRequestStatus::ClientCookieOnly),
            "RFC 7873 section 5.2 requires every COOKIE after the first to be ignored"
        );
    }

    #[test]
    fn empty_question_client_cookie_query_returns_noerror_cookie() {
        let secret = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        let mut packet = vec![
            0x12, 0x34, 0, 0, // ID and QUERY flags
            0, 0, // QDCOUNT
            0, 0, // ANCOUNT
            0, 0, // NSCOUNT
            0, 0, // ARCOUNT, incremented by append_opt
        ];
        append_opt(
            &mut packet,
            1232,
            0,
            &edns_option(EDNS_COOKIE_OPTION, &hex_to_vec("2464c4abcf10c957")),
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                dns_cookie: Some(context),
                ..AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD)
            },
        );

        assert_eq!(full_response_rcode(&response), Rcode::NoError as u16);
        assert_eq!(
            (
                u16::from_be_bytes([response[4], response[5]]),
                u16::from_be_bytes([response[6], response[7]]),
                u16::from_be_bytes([response[8], response[9]]),
                u16::from_be_bytes([response[10], response[11]]),
            ),
            (0, 0, 0, 1)
        );
        assert_eq!(
            response_opt_option(&response, EDNS_COOKIE_OPTION),
            Some(hex_to_vec(
                "2464c4abcf10c957010000005cf79f111f8130c3eee29480"
            ))
        );
        assert_eq!(
            dns_cookie_request_status(&packet, Some(context)),
            Some(DnsCookieRequestStatus::ClientCookieOnly)
        );
    }

    #[test]
    fn empty_question_cookie_query_uses_rfc7873_rcodes() {
        let secret = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let mut context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        context.policy = DnsCookiePolicy::Strict;

        for (cookie_hex, expected_rcode) in [
            (
                "2464c4abcf10c957010000005cf79f111f8130c3eee29480",
                Rcode::NoError as u16,
            ),
            (
                "2464c4abcf10c957010000005cf79f111f8130c3eee29481",
                Rcode::BadCookie as u16,
            ),
        ] {
            let mut packet = vec![
                0x12, 0x34, 0, 0, // ID and QUERY flags
                0, 0, // QDCOUNT
                0, 0, // ANCOUNT
                0, 0, // NSCOUNT
                0, 0, // ARCOUNT, incremented by append_opt
            ];
            append_opt(
                &mut packet,
                1232,
                0,
                &edns_option(EDNS_COOKIE_OPTION, &hex_to_vec(cookie_hex)),
            );

            let response = store_response_with_options(
                &packet,
                &ZoneStore::new(),
                AnswerOptions {
                    dns_cookie: Some(context),
                    ..AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD)
                },
            );

            assert_eq!(full_response_rcode(&response), expected_rcode);
            assert_eq!(u16::from_be_bytes([response[4], response[5]]), 0);
            assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
            assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
            assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
            assert!(response_opt_option(&response, EDNS_COOKIE_OPTION).is_some());
        }
    }

    #[test]
    fn edns_cookie_server_cookie_validates_for_same_client_ip() {
        let secret = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &edns_option(
                EDNS_COOKIE_OPTION,
                &hex_to_vec("2464c4abcf10c957010000005cf79f111f8130c3eee29480"),
            ),
        );

        assert!(request_has_valid_dns_server_cookie(&packet, context));
        assert_eq!(
            dns_cookie_request_status(&packet, Some(context)),
            Some(DnsCookieRequestStatus::ValidServerCookie)
        );
    }

    #[test]
    fn edns_cookie_previous_server_secret_validates_during_rollover() {
        let current = hex_to_array_16("00112233445566778899aabbccddeeff");
        let previous = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let mut context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &current, 1_559_731_985);
        context.previous_server_secret = Some(&previous);
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &edns_option(
                EDNS_COOKIE_OPTION,
                &hex_to_vec("2464c4abcf10c957010000005cf79f111f8130c3eee29480"),
            ),
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: &[],
                chaos: ChaosOptions::default(),
                dns_cookie: Some(context),
            },
        );

        assert_eq!(
            dns_cookie_request_status(&packet, Some(context)),
            Some(DnsCookieRequestStatus::ValidServerCookie)
        );
        assert_ne!(
            response_opt_option(&response, EDNS_COOKIE_OPTION),
            Some(hex_to_vec(
                "2464c4abcf10c957010000005cf79f111f8130c3eee29480"
            ))
        );
    }

    #[test]
    fn edns_cookie_validation_rejects_tamper_changed_source_and_bad_time() {
        let secret = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        let mut cookie = hex_to_vec("2464c4abcf10c957010000005cf79f111f8130c3eee29480");
        append_opt(
            &mut packet,
            4096,
            0,
            &edns_option(EDNS_COOKIE_OPTION, &cookie),
        );
        let valid_context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        let changed_source =
            DnsCookieContext::new("198.51.100.101".parse().unwrap(), &secret, 1_559_731_985);
        let expired =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_735_586);
        let future =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_684);

        assert!(request_has_valid_dns_server_cookie(&packet, valid_context));
        assert!(!request_has_valid_dns_server_cookie(
            &packet,
            changed_source
        ));
        assert!(!request_has_valid_dns_server_cookie(&packet, expired));
        assert!(!request_has_valid_dns_server_cookie(&packet, future));

        cookie[23] ^= 0x01;
        let mut tampered = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut tampered,
            4096,
            0,
            &edns_option(EDNS_COOKIE_OPTION, &cookie),
        );
        assert!(!request_has_valid_dns_server_cookie(
            &tampered,
            valid_context
        ));
        assert_eq!(
            dns_cookie_request_status(&tampered, Some(valid_context)),
            Some(DnsCookieRequestStatus::InvalidServerCookie)
        );
    }

    #[test]
    fn edns_cookie_tampered_server_cookie_is_leniently_refreshed() {
        let secret = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        let mut cookie = hex_to_vec("2464c4abcf10c957010000005cf79f111f8130c3eee29480");
        cookie[23] ^= 0x01;
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &edns_option(EDNS_COOKIE_OPTION, &cookie),
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: &[],
                chaos: ChaosOptions::default(),
                dns_cookie: Some(context),
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(
            response_opt_option(&response, EDNS_COOKIE_OPTION),
            Some(hex_to_vec(
                "2464c4abcf10c957010000005cf79f111f8130c3eee29480"
            ))
        );
    }

    #[test]
    fn strict_dns_cookie_policy_returns_badcookie_for_client_cookie_only() {
        let secret = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let mut context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        context.policy = DnsCookiePolicy::Strict;
        let client_cookie = hex_to_vec("2464c4abcf10c957");
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &edns_option(EDNS_COOKIE_OPTION, &client_cookie),
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: &[],
                chaos: ChaosOptions::default(),
                dns_cookie: Some(context),
            },
        );

        assert_eq!(full_response_rcode(&response), Rcode::BadCookie as u16);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_opt_option(&response, EDNS_COOKIE_OPTION),
            Some(hex_to_vec(
                "2464c4abcf10c957010000005cf79f111f8130c3eee29480"
            ))
        );
    }

    #[test]
    fn strict_dns_cookie_policy_allows_valid_server_cookie() {
        let secret = hex_to_array_16("e5e973e5a6b2a43f48e7dc849e37bfcf");
        let mut context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        context.policy = DnsCookiePolicy::Strict;
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &edns_option(
                EDNS_COOKIE_OPTION,
                &hex_to_vec("2464c4abcf10c957010000005cf79f111f8130c3eee29480"),
            ),
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: &[],
                chaos: ChaosOptions::default(),
                dns_cookie: Some(context),
            },
        );

        assert_eq!(full_response_rcode(&response), Rcode::Refused as u16);
        assert_eq!(
            response_opt_option(&response, EDNS_COOKIE_OPTION),
            Some(hex_to_vec(
                "2464c4abcf10c957010000005cf79f111f8130c3eee29480"
            ))
        );
    }

    #[test]
    fn disabled_dns_cookie_policy_omits_cookie_response() {
        let client_cookie = hex_to_vec("2464c4abcf10c957");
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &edns_option(EDNS_COOKIE_OPTION, &client_cookie),
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD),
        );

        assert_eq!(full_response_rcode(&response), Rcode::Refused as u16);
        assert_eq!(response_opt_option(&response, EDNS_COOKIE_OPTION), None);
    }

    #[test]
    fn malformed_cookie_lengths_get_formerr() {
        for cookie_len in [7usize, 9, 15, 41] {
            let mut packet = query(&example_name(), RecordType::A as u16, 1);
            append_opt(
                &mut packet,
                4096,
                0,
                &edns_option(EDNS_COOKIE_OPTION, &vec![0u8; cookie_len]),
            );

            let response = store_response_with_options(
                &packet,
                &ZoneStore::new(),
                AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD),
            );

            assert_eq!(
                response[3] & 0x0f,
                Rcode::FormErr as u8,
                "cookie length {cookie_len} should be FORMERR"
            );
            assert_eq!(
                u16::from_be_bytes([response[10], response[11]]),
                1,
                "COOKIE format errors must retain a response OPT"
            );
        }
    }

    #[test]
    fn response_opt_copies_query_do_bit_without_dnssec_augmentation() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn do_query_includes_covering_rrsig_and_sets_response_do_bit() {
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

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::A as u16, RecordType::Rrsig as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn non_do_query_omits_dnssec_augmentation() {
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
        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
    }

    #[test]
    fn explicit_rrsig_query_without_do_returns_rrsig_without_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::A)],
            )],
        ));
        let mut packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Rrsig as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Rrsig as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0));
    }

    #[test]
    fn explicit_rrsig_query_with_do_does_not_mark_answer_as_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::A)],
            )],
        ));
        let mut packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Rrsig as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Rrsig as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn explicit_nsec_query_without_do_returns_nsec_without_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("zzz.example.test.")],
            )],
        ));
        let mut packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Nsec as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Nsec as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0));
    }

    #[test]
    fn explicit_nsec3_query_for_nsec3_only_owner_returns_nxdomain() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("hash.example.test.").unwrap(),
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata(253)],
            )],
        ));
        let mut packet = query(
            b"\x04hash\x07example\x04test\x00",
            RecordType::Nsec3 as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert!(response_answer_types(&response).is_empty());
        assert_eq!(response_opt_ttl(&response), Some(0));
    }

    #[test]
    fn direct_dnskey_and_nsec3param_queries_preserve_unknown_algorithms() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Dnskey as u16,
                    1,
                    300,
                    vec![dnskey_rdata(253)],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Nsec3Param as u16,
                    1,
                    300,
                    vec![nsec3param_rdata(254)],
                ),
            ],
        ));

        let dnskey_response = store_response(
            &query(b"\x07example\x04test\x00", RecordType::Dnskey as u16, 1),
            &store,
        );
        let nsec3param_response = store_response(
            &query(b"\x07example\x04test\x00", RecordType::Nsec3Param as u16, 1),
            &store,
        );

        assert_eq!(dnskey_response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&dnskey_response),
            vec![RecordType::Dnskey as u16]
        );
        assert_eq!(nsec3param_response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&nsec3param_response),
            vec![RecordType::Nsec3Param as u16]
        );
    }

    #[test]
    fn edns_padding_default_off_omits_padding_response_option() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &[0, EDNS_PADDING_OPTION as u8, 0, 4, 0, 0, 0, 0],
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD),
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn ede_not_ready_is_opt_in_for_loading_zones() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[]);
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let default_response = store_response(&packet, &store);
        let ede_response = store_response_with_options(
            &packet,
            &store,
            AnswerOptions {
                extended_dns_errors: ExtendedDnsErrorsMode::Minimal,
                ..AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD)
            },
        );

        assert_eq!(default_response[3] & 0x0f, Rcode::ServFail as u8);
        assert_eq!(
            response_ede_info_codes(&default_response),
            Vec::<u16>::new()
        );
        assert_eq!(ede_response[3] & 0x0f, Rcode::ServFail as u8);
        assert_eq!(response_ede_info_codes(&ede_response), vec![EDE_NOT_READY]);
    }

    #[test]
    fn configured_plaintext_udp_edns_padding_is_not_emitted() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[0, EDNS_PADDING_OPTION as u8, 0, 0]);

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 32,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: &[],
                chaos: ChaosOptions::default(),
                dns_cookie: None,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn configured_encrypted_edns_padding_aligns_response_to_block_size() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[0, EDNS_PADDING_OPTION as u8, 0, 0]);

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Tls,
                edns_padding_block_size: 32,
                ..AnswerOptions::tcp()
            },
        );

        let rdata = response_opt_rdata(&response).expect("OPT rdata");
        let padding_len = u16::from_be_bytes([rdata[2], rdata[3]]) as usize;
        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response.len() % 32, 0);
        assert_eq!(
            u16::from_be_bytes([rdata[0], rdata[1]]),
            EDNS_PADDING_OPTION
        );
        assert_eq!(rdata.len(), 4 + padding_len);
        assert!(rdata[4..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn configured_udp_edns_padding_is_omitted_when_it_would_exceed_ceiling() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 512, 0, &[0, EDNS_PADDING_OPTION as u8, 0, 0]);

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: 512,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                nsec3_max_iterations: 100,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 600,
                extended_dns_errors: ExtendedDnsErrorsMode::Off,
                any_response: AnyResponseMode::Minimal,
                nsid: &[],
                chaos: ChaosOptions::default(),
                dns_cookie: None,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert!(response.len() < 512);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn malformed_edns_options_get_formerr() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[0, 1, 0]);

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn multiple_opt_records_get_formerr() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[]);
        append_opt(&mut packet, 4096, 0, &[]);

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn unsupported_version_before_second_opt_gets_formerr() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 1 << 16, &[]);
        append_opt(&mut packet, 4096, 0, &[]);

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
    }

    #[test]
    fn duplicate_padding_options_get_formerr_and_opt() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &[
                0,
                EDNS_PADDING_OPTION as u8,
                0,
                0,
                0,
                EDNS_PADDING_OPTION as u8,
                0,
                0,
            ],
        );

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn unsupported_edns_version_gets_badvers_opt_response() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, (1 << 16) | 0x8000, &[]);

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        assert_eq!(response_opt_ttl(&response), Some((1 << 24) | 0x8000));
    }

    #[test]
    fn invalid_pseudo_rr_qtypes_are_rejected() {
        for qtype in [
            0,
            RecordType::Opt as u16,
            RecordType::Tsig as u16,
            RecordType::Tkey as u16,
            u16::MAX,
        ] {
            let packet = query(&example_name(), qtype, 1);
            let response = store_response(&packet, &ZoneStore::new());
            assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        }
    }

    #[test]
    fn inbound_transfer_queries_are_refused() {
        for qtype in [RecordType::Ixfr as u16, RecordType::Axfr as u16] {
            let packet = query(&example_name(), qtype, 1);
            let response = store_response(&packet, &ZoneStore::new());
            assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        }
    }

    #[test]
    fn non_edns_udp_response_over_512_octets_is_truncated_without_opt() {
        let store = ZoneStore::new();
        let rdatas = (0..20).map(|_| vec![60; 50]).collect::<Vec<_>>();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                rdatas,
            )],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::Txt as u16, 1);
        let response = store_response_with_options(&packet, &store, AnswerOptions::udp(1232));
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert!(response.len() <= 512);
        assert_eq!(flags & 0x0200, 0x0200);
        assert_eq!(response_additional_types(&response), Vec::<u16>::new());
    }

    #[test]
    fn truncated_do_response_copies_query_do_when_rrsig_is_removed() {
        let store = ZoneStore::new();
        let mut large_rrsig = rrsig_rdata(RecordType::A);
        large_rrsig.extend(vec![0; 400]);
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
                    vec![large_rrsig],
                ),
            ],
        ));
        let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response_with_options(&packet, &store, AnswerOptions::udp(128));
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert!(response.len() <= 128);
        assert_eq!(flags & 0x0200, 0x0200);
        assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn tcp_response_is_not_udp_truncated() {
        let store = ZoneStore::new();
        let rdatas = (0..20).map(|_| vec![60; 50]).collect::<Vec<_>>();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                rdatas,
            )],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::Txt as u16, 1);
        let response = store_response_with_options(&packet, &store, AnswerOptions::tcp());
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert!(response.len() > 512);
        assert_eq!(flags & 0x0200, 0);
    }
