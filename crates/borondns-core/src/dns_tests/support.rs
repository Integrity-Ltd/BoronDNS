    fn query(qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(qname);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&qclass.to_be_bytes());
        packet
    }

    fn notify(qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut packet = query(qname, qtype, qclass);
        packet[2..4].copy_from_slice(&((Opcode::Notify as u16) << 11).to_be_bytes());
        packet
    }

    fn append_opt(packet: &mut Vec<u8>, payload_size: u16, ttl: u32, rdata: &[u8]) {
        packet[11] = packet[11].checked_add(1).unwrap();
        packet.push(0);
        packet.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
        packet.extend_from_slice(&payload_size.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(rdata);
    }

    fn edns_option(code: u16, data: &[u8]) -> Vec<u8> {
        let mut option = Vec::new();
        option.extend_from_slice(&code.to_be_bytes());
        option.extend_from_slice(&(data.len() as u16).to_be_bytes());
        option.extend_from_slice(data);
        option
    }

    fn append_answer(packet: &mut Vec<u8>, owner: &str, rr_type: u16, class: u16, rdata: Vec<u8>) {
        let answer_count = u16::from_be_bytes([packet[6], packet[7]]) + 1;
        packet[6..8].copy_from_slice(&answer_count.to_be_bytes());
        packet.extend_from_slice(&DomainName::from_absolute_str(owner).unwrap().to_wire());
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&class.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);
    }

    fn example_name() -> Vec<u8> {
        b"\x07Example\x04test\x00".to_vec()
    }

    fn response(packet: &[u8], zones: &[DomainName]) -> Vec<u8> {
        let store = ZoneStore::new();
        for zone in zones {
            store.insert_loading(zone.clone());
        }

        match answer_datagram(packet, &store) {
            DatagramAction::Discard => panic!("expected response"),
            DatagramAction::Respond(response) => response,
        }
    }

    fn store_response(packet: &[u8], store: &ZoneStore) -> Vec<u8> {
        match answer_datagram(packet, store) {
            DatagramAction::Discard => panic!("expected response"),
            DatagramAction::Respond(response) => response,
        }
    }

    fn store_response_with_options(
        packet: &[u8],
        store: &ZoneStore,
        options: AnswerOptions,
    ) -> Vec<u8> {
        match answer_message(packet, store, options) {
            DatagramAction::Discard => panic!("expected response"),
            DatagramAction::Respond(response) => response,
        }
    }

    fn store_response_with_zone_image(packet: &[u8], store: &ZoneStore) -> Vec<u8> {
        store_response_with_zone_image_provider(
            packet,
            store,
            AnswerOptions::default(),
            &default_zone_image_provider,
        )
    }

    fn store_response_with_zone_image_provider(
        packet: &[u8],
        store: &ZoneStore,
        options: AnswerOptions,
        provider: ZoneImageProvider<'_>,
    ) -> Vec<u8> {
        match answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
            packet,
            store,
            options,
            |_, _| true,
            |_, _, _| true,
            |_| {},
            provider,
        ) {
            DatagramAction::Discard => panic!("expected response"),
            DatagramAction::Respond(response) => response,
        }
    }

    fn direct_zone_image_response_for_packet(
        packet: &[u8],
        image: &ZoneImage,
        options: AnswerOptions,
    ) -> Option<Vec<u8>> {
        let header = Header::parse(packet).ok()?;
        let question = Question::parse(packet).ok()?;
        let metadata = RequestMetadata::parse(&header, packet, &question).ok()?;
        if metadata.dnssec_requested() {
            return None;
        }
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
        build_direct_zone_image_answer_response(
            &header,
            &question,
            image,
            &plan,
            metadata,
            options,
            response_sizing,
        )
    }

    #[test]
    fn truncation_retry_counts_patch_preencoded_section_count_bytes() {
        let response_shape = ZoneImagePlanResponseShape {
            response_flag_bits: 0,
            answer_count: 2,
            authority_count: 1,
            additional_count: 1,
            section_count_header_bytes: zone_image_section_count_header_bytes(2, 1, 1),
            body_wire_upper_bound: 0,
        };
        let mut counts = ZoneImageRetrySectionCounts::from_response_shape(response_shape);

        assert_eq!(
            counts.section_count_header_bytes_with_extra_additional(1),
            Some(zone_image_section_count_header_bytes(2, 1, 2))
        );

        counts.decrement_answer();
        assert_eq!(
            counts.section_count_header_bytes_with_extra_additional(1),
            Some(zone_image_section_count_header_bytes(1, 1, 2))
        );

        counts.decrement_authority();
        assert_eq!(
            counts.section_count_header_bytes_with_extra_additional(1),
            Some(zone_image_section_count_header_bytes(1, 0, 2))
        );

        counts.decrement_additional();
        assert_eq!(
            counts.section_count_header_bytes_with_extra_additional(1),
            Some(zone_image_section_count_header_bytes(1, 0, 1))
        );
    }

    fn response_answer_types(response: &[u8]) -> Vec<u16> {
        response_answers(response)
            .into_iter()
            .map(|(_, rr_type)| rr_type)
            .collect()
    }

    fn response_answer_rdatas(response: &[u8], expected_type: u16) -> Vec<Vec<u8>> {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        let mut rdatas = Vec::new();
        for _ in 0..header.ancount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed;
            let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let rdlength =
                u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
            offset += 10;
            if rr_type == expected_type {
                rdatas.push(response[offset..offset + rdlength].to_vec());
            }
            offset += rdlength;
        }
        rdatas
    }

    fn response_answer_single_name_rdatas(response: &[u8], expected_type: u16) -> Vec<Vec<u8>> {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        let mut rdatas = Vec::new();
        for _ in 0..header.ancount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed;
            let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let rdlength =
                u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
            let rdata_offset = offset + 10;
            if rr_type == expected_type {
                let (name, consumed) = DomainName::parse(response, rdata_offset).unwrap();
                assert_eq!(consumed, rdlength);
                rdatas.push(name.to_wire());
            }
            offset = rdata_offset + rdlength;
        }
        rdatas
    }

    fn first_answer_offset(response: &[u8]) -> usize {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }
        offset
    }

    fn response_answers(response: &[u8]) -> Vec<(DomainName, u16)> {
        response_sections(response).0
    }

    fn response_authority_types(response: &[u8]) -> Vec<u16> {
        response_sections(response)
            .1
            .into_iter()
            .map(|(_, rr_type)| rr_type)
            .collect()
    }

    fn response_authority_owners(response: &[u8], expected_type: u16) -> Vec<DomainName> {
        response_sections(response)
            .1
            .into_iter()
            .filter_map(|(owner, rr_type)| (rr_type == expected_type).then_some(owner))
            .collect()
    }

    fn response_answer_ttls(response: &[u8], expected_type: u16) -> Vec<u32> {
        response_section_ttls(response, expected_type, Section::Answer)
    }

    fn response_answer_classes(response: &[u8], expected_type: u16) -> Vec<u16> {
        response_section_classes(response, expected_type, Section::Answer)
    }

    fn response_authority_ttls(response: &[u8], expected_type: u16) -> Vec<u32> {
        response_section_ttls(response, expected_type, Section::Authority)
    }

    fn response_additional_types(response: &[u8]) -> Vec<u16> {
        response_sections(response)
            .2
            .into_iter()
            .map(|(_, rr_type)| rr_type)
            .collect()
    }

    fn response_additional_owners(response: &[u8], expected_type: u16) -> Vec<DomainName> {
        response_sections(response)
            .2
            .into_iter()
            .filter_map(|(owner, rr_type)| (rr_type == expected_type).then_some(owner))
            .collect()
    }

    type ParsedSection = Vec<(DomainName, u16)>;

    #[derive(Debug, Clone, Copy)]
    enum Section {
        Answer,
        Authority,
    }

    fn response_section_ttls(response: &[u8], expected_type: u16, section: Section) -> Vec<u32> {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        if matches!(section, Section::Authority) {
            skip_response_records(response, &mut offset, header.ancount);
        }

        let count = match section {
            Section::Answer => header.ancount,
            Section::Authority => header.nscount,
        };
        parse_response_record_ttls(response, &mut offset, count, expected_type)
    }

    fn response_section_classes(response: &[u8], expected_type: u16, section: Section) -> Vec<u16> {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        if matches!(section, Section::Authority) {
            skip_response_records(response, &mut offset, header.ancount);
        }

        let count = match section {
            Section::Answer => header.ancount,
            Section::Authority => header.nscount,
        };
        parse_response_record_classes(response, &mut offset, count, expected_type)
    }

    fn response_sections(response: &[u8]) -> (ParsedSection, ParsedSection, ParsedSection) {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        let answers = parse_response_records(response, &mut offset, header.ancount);
        let authorities = parse_response_records(response, &mut offset, header.nscount);
        let additionals = parse_response_records(response, &mut offset, header.arcount);
        (answers, authorities, additionals)
    }

    fn assert_semantic_response_eq(left: &[u8], right: &[u8]) {
        let left_header = Header::parse(left).unwrap();
        let right_header = Header::parse(right).unwrap();
        assert_eq!(left_header.flags & 0x800f, right_header.flags & 0x800f);
        assert_eq!(left_header.qdcount, right_header.qdcount);
        assert_eq!(left_header.ancount, right_header.ancount);
        assert_eq!(left_header.nscount, right_header.nscount);
        assert_eq!(left_header.arcount, right_header.arcount);
        assert_eq!(response_sections(left), response_sections(right));
    }

    fn parse_response_records(response: &[u8], offset: &mut usize, count: u16) -> ParsedSection {
        let mut records = Vec::new();
        for _ in 0..count {
            let (owner, consumed) = DomainName::parse(response, *offset).unwrap();
            *offset += consumed;
            let rr_type = u16::from_be_bytes([response[*offset], response[*offset + 1]]);
            let rdlength =
                u16::from_be_bytes([response[*offset + 8], response[*offset + 9]]) as usize;
            records.push((owner, rr_type));
            *offset += 10 + rdlength;
        }
        records
    }

    fn parse_response_record_ttls(
        response: &[u8],
        offset: &mut usize,
        count: u16,
        expected_type: u16,
    ) -> Vec<u32> {
        let mut ttls = Vec::new();
        for _ in 0..count {
            let (_, consumed) = DomainName::parse(response, *offset).unwrap();
            *offset += consumed;
            let rr_type = u16::from_be_bytes([response[*offset], response[*offset + 1]]);
            let ttl = u32::from_be_bytes([
                response[*offset + 4],
                response[*offset + 5],
                response[*offset + 6],
                response[*offset + 7],
            ]);
            let rdlength =
                u16::from_be_bytes([response[*offset + 8], response[*offset + 9]]) as usize;
            if rr_type == expected_type {
                ttls.push(ttl);
            }
            *offset += 10 + rdlength;
        }
        ttls
    }

    fn parse_response_record_classes(
        response: &[u8],
        offset: &mut usize,
        count: u16,
        expected_type: u16,
    ) -> Vec<u16> {
        let mut classes = Vec::new();
        for _ in 0..count {
            let (_, consumed) = DomainName::parse(response, *offset).unwrap();
            *offset += consumed;
            let rr_type = u16::from_be_bytes([response[*offset], response[*offset + 1]]);
            let class = u16::from_be_bytes([response[*offset + 2], response[*offset + 3]]);
            let rdlength =
                u16::from_be_bytes([response[*offset + 8], response[*offset + 9]]) as usize;
            if rr_type == expected_type {
                classes.push(class);
            }
            *offset += 10 + rdlength;
        }
        classes
    }

    fn response_opt_rdata(response: &[u8]) -> Option<Vec<u8>> {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        skip_response_records(response, &mut offset, header.ancount);
        skip_response_records(response, &mut offset, header.nscount);

        for _ in 0..header.arcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed;
            let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let rdlength =
                u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
            offset += 10;
            let rdata = response[offset..offset + rdlength].to_vec();
            offset += rdlength;
            if rr_type == RecordType::Opt as u16 {
                return Some(rdata);
            }
        }

        None
    }

    fn response_opt_option(response: &[u8], code: u16) -> Option<Vec<u8>> {
        let rdata = response_opt_rdata(response)?;
        let mut offset = 0usize;
        while offset < rdata.len() {
            let option_code = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
            let option_len = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
            offset += 4;
            if option_code == code {
                return Some(rdata[offset..offset + option_len].to_vec());
            }
            offset += option_len;
        }
        None
    }

    fn response_ede_info_codes(response: &[u8]) -> Vec<u16> {
        let Some(rdata) = response_opt_rdata(response) else {
            return Vec::new();
        };
        let mut codes = Vec::new();
        let mut offset = 0usize;
        while offset + 4 <= rdata.len() {
            let option_code = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
            let option_len = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
            offset += 4;
            assert!(offset + option_len <= rdata.len());
            if option_code == EDNS_EXTENDED_DNS_ERROR_OPTION {
                assert!(option_len >= 2);
                codes.push(u16::from_be_bytes([rdata[offset], rdata[offset + 1]]));
                assert_eq!(option_len, 2);
            }
            offset += option_len;
        }
        codes
    }

    fn hex_to_vec(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
            .collect()
    }

    fn hex_to_array_16(hex: &str) -> [u8; 16] {
        hex_to_vec(hex).try_into().expect("16-octet hex value")
    }

    fn response_opt_ttl(response: &[u8]) -> Option<u32> {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        skip_response_records(response, &mut offset, header.ancount);
        skip_response_records(response, &mut offset, header.nscount);

        for _ in 0..header.arcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed;
            let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let ttl = u32::from_be_bytes([
                response[offset + 4],
                response[offset + 5],
                response[offset + 6],
                response[offset + 7],
            ]);
            let rdlength =
                u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
            offset += 10 + rdlength;
            if rr_type == RecordType::Opt as u16 {
                return Some(ttl);
            }
        }

        None
    }

    fn full_response_rcode(response: &[u8]) -> u16 {
        let base = u16::from(response[3] & 0x0f);
        let extended = response_opt_ttl(response).map_or(0, |ttl| ((ttl >> 24) as u16) << 4);
        base | extended
    }

    fn skip_response_records(response: &[u8], offset: &mut usize, count: u16) {
        for _ in 0..count {
            let (_, consumed) = DomainName::parse(response, *offset).unwrap();
            *offset += consumed;
            let rdlength =
                u16::from_be_bytes([response[*offset + 8], response[*offset + 9]]) as usize;
            *offset += 10 + rdlength;
        }
    }

    fn cname_rdata(target: &str) -> Vec<u8> {
        DomainName::from_absolute_str(target).unwrap().to_wire()
    }

    fn alias_snapshot(serial: u32, target: &str, address: [u8; 4]) -> ZoneSnapshot {
        ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(serial),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata(target)],
                ),
                Rrset::new(
                    DomainName::from_absolute_str(target).unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![address.to_vec()],
                ),
            ],
        )
    }

    fn assert_atomic_alias_response(response: &[u8]) {
        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(response),
            vec![RecordType::Cname as u16, RecordType::A as u16]
        );

        let cnames = response_answer_single_name_rdatas(response, RecordType::Cname as u16);
        let addrs = response_answer_rdatas(response, RecordType::A as u16);
        let old_cnames = vec![cname_rdata("old-target.example.test.")];
        let old_addrs = vec![[192, 0, 2, 10].to_vec()];
        let new_cnames = vec![cname_rdata("new-target.example.test.")];
        let new_addrs = vec![[198, 51, 100, 20].to_vec()];

        let old_version = cnames == old_cnames && addrs == old_addrs;
        let new_version = cnames == new_cnames && addrs == new_addrs;
        assert!(
            old_version || new_version,
            "response mixed zone versions: cnames={cnames:?} addrs={addrs:?}"
        );
    }

    fn mx_rdata(preference: u16, exchange: &str) -> Vec<u8> {
        let mut rdata = preference.to_be_bytes().to_vec();
        rdata.extend(cname_rdata(exchange));
        rdata
    }

    fn srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        rdata.extend_from_slice(&weight.to_be_bytes());
        rdata.extend_from_slice(&port.to_be_bytes());
        rdata.extend(cname_rdata(target));
        rdata
    }

    fn character_string(value: &[u8]) -> Vec<u8> {
        let mut wire = vec![value.len() as u8];
        wire.extend_from_slice(value);
        wire
    }

    fn naptr_rdata(replacement: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&10u16.to_be_bytes());
        rdata.extend_from_slice(&20u16.to_be_bytes());
        rdata.extend(character_string(b"s"));
        rdata.extend(character_string(b"SIP+D2U"));
        rdata.extend(character_string(b""));
        rdata.extend(cname_rdata(replacement));
        rdata
    }

    fn svcb_rdata(priority: u16, target: &str, params: &[u8]) -> Vec<u8> {
        let mut rdata = priority.to_be_bytes().to_vec();
        rdata.extend(cname_rdata(target));
        rdata.extend_from_slice(params);
        rdata
    }

    fn soa_rdata() -> Vec<u8> {
        b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()
    }

    fn rrsig_rdata(type_covered: RecordType) -> Vec<u8> {
        let mut rdata = (type_covered as u16).to_be_bytes().to_vec();
        rdata.extend_from_slice(&[8, 2]);
        rdata.extend_from_slice(&300u32.to_be_bytes());
        rdata.extend_from_slice(&1_700_086_400u32.to_be_bytes());
        rdata.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend(cname_rdata("example.test."));
        rdata.extend_from_slice(b"signature");
        rdata
    }

    fn nsec_rdata(next_owner: &str) -> Vec<u8> {
        let mut rdata = cname_rdata(next_owner);
        rdata.extend_from_slice(&[0, 1, 0x40]);
        rdata
    }

    fn dnskey_rdata(algorithm: u8) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&256u16.to_be_bytes());
        rdata.push(3);
        rdata.push(algorithm);
        rdata.extend_from_slice(b"public-key");
        rdata
    }

    fn nsec3_rdata(hash_algorithm: u8) -> Vec<u8> {
        nsec3_rdata_with_iterations(hash_algorithm, 1)
    }

    fn nsec3_rdata_with_iterations(hash_algorithm: u8, iterations: u16) -> Vec<u8> {
        const TEST_NEXT_HASH: [u8; 20] = [
            0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
            0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        ];
        let mut rdata = vec![hash_algorithm, 0];
        rdata.extend_from_slice(&iterations.to_be_bytes());
        rdata.push(0);
        rdata.push(TEST_NEXT_HASH.len() as u8);
        rdata.extend_from_slice(&TEST_NEXT_HASH);
        rdata.extend_from_slice(&[0, 1, 0x40]);
        rdata
    }

    fn nsec3_rdata_with_next_hash(next_hash: [u8; 20]) -> Vec<u8> {
        nsec3_rdata_with_next_hash_and_flags(next_hash, 0)
    }

    fn nsec3_rdata_with_next_hash_and_flags(next_hash: [u8; 20], flags: u8) -> Vec<u8> {
        let mut rdata = vec![1, flags];
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(0);
        rdata.push(next_hash.len() as u8);
        rdata.extend_from_slice(&next_hash);
        rdata.extend_from_slice(&[0, 1, 0x40]);
        rdata
    }

    fn nsec3_owner(name: &str, origin: &str) -> DomainName {
        DomainName::from_absolute_str(&format!("{}.{}", nsec3_hash_label(name), origin)).unwrap()
    }

    fn nsec3_hash_label(name: &str) -> String {
        base32hex_lower(&nsec3_hash_bytes(name))
    }

    fn nsec3_hash_bytes(name: &str) -> [u8; 20] {
        let canonical = DomainName::from_absolute_str(name).unwrap().canonical_key();
        let wire = DomainName::from_absolute_str(&canonical).unwrap().to_wire();
        let mut digest = Sha1::new();
        digest.update(wire);
        let first = digest.finalize();
        let mut digest = Sha1::new();
        digest.update(first);
        let hash = digest.finalize();
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash);
        bytes
    }

    fn nsec3_ring_rrsets<S: AsRef<str>>(names: &[S], origin: &str) -> Vec<Rrset> {
        let mut hashes = names
            .iter()
            .map(|name| nsec3_hash_bytes(name.as_ref()))
            .collect::<Vec<_>>();
        hashes.sort_unstable();
        hashes.dedup();
        assert!(!hashes.is_empty());

        let mut rrsets = Vec::with_capacity(hashes.len() * 2);
        for (index, hash) in hashes.iter().enumerate() {
            let next_hash = hashes[(index + 1) % hashes.len()];
            let owner = DomainName::from_absolute_str(&format!(
                "{}.{}",
                base32hex_lower(hash),
                origin
            ))
            .unwrap();
            rrsets.push(Rrset::new(
                owner.clone(),
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata_with_next_hash(next_hash)],
            ));
            rrsets.push(Rrset::new(
                owner,
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec3)],
            ));
        }
        rrsets
    }

    fn nsec3_optout_ring_rrsets<S: AsRef<str>>(
        names: &[S],
        origin: &str,
        omitted_name: &str,
    ) -> Vec<Rrset> {
        let omitted_hash = nsec3_hash_bytes(omitted_name);
        let mut hashes = names
            .iter()
            .map(|name| nsec3_hash_bytes(name.as_ref()))
            .collect::<Vec<_>>();
        hashes.sort_unstable();
        hashes.dedup();
        assert!(!hashes.is_empty());

        let mut rrsets = Vec::with_capacity(hashes.len() * 2);
        for (index, hash) in hashes.iter().enumerate() {
            let next_hash = hashes[(index + 1) % hashes.len()];
            let owner = DomainName::from_absolute_str(&format!(
                "{}.{}",
                base32hex_lower(hash),
                origin
            ))
            .unwrap();
            let covers_omitted = if *hash < next_hash {
                *hash < omitted_hash && omitted_hash < next_hash
            } else if *hash > next_hash {
                *hash < omitted_hash || omitted_hash < next_hash
            } else {
                omitted_hash != *hash
            };
            let flags = u8::from(covers_omitted);
            rrsets.push(Rrset::new(
                owner.clone(),
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata_with_next_hash_and_flags(next_hash, flags)],
            ));
            rrsets.push(Rrset::new(
                owner,
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::Nsec3)],
            ));
        }
        rrsets
    }

    fn nsec3_covering_owner<S: AsRef<str>>(
        name: &str,
        ring_names: &[S],
        origin: &str,
    ) -> DomainName {
        let target = nsec3_hash_bytes(name);
        let mut hashes = ring_names
            .iter()
            .map(|name| nsec3_hash_bytes(name.as_ref()))
            .collect::<Vec<_>>();
        hashes.sort_unstable();
        hashes.dedup();
        let insertion = hashes.partition_point(|hash| *hash < target);
        let predecessor = if insertion == 0 {
            hashes.last().unwrap()
        } else {
            &hashes[insertion - 1]
        };
        DomainName::from_absolute_str(&format!(
            "{}.{}",
            base32hex_lower(predecessor),
            origin
        ))
        .unwrap()
    }

    fn base32hex_lower(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
        let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
        let mut buffer = 0u16;
        let mut bits = 0u8;
        for byte in bytes {
            buffer = (buffer << 8) | u16::from(*byte);
            bits += 8;
            while bits >= 5 {
                out.push(ALPHABET[((buffer >> (bits - 5)) & 0x1f) as usize] as char);
                bits -= 5;
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
        }
        out
    }

    fn nsec3param_rdata(hash_algorithm: u8) -> Vec<u8> {
        let mut rdata = vec![hash_algorithm, 0];
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(0);
        rdata
    }
