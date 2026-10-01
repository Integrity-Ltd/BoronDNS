fn batch_test_store() -> ZoneStore {
    let store = ZoneStore::new();
    store.insert_snapshot(ZoneSnapshot::active(
        DomainName::from_absolute_str("example.test.").unwrap(),
        Some(1),
        vec![
            Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                6,
                1,
                300,
                vec![soa_rdata()],
            ),
            Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                1,
                1,
                300,
                vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]],
            ),
        ],
    ));
    store
}

#[cfg(feature = "experimental-query-preparation")]
#[test]
fn query_preparation_all_hits_skip_fallback_work() {
    let store = ZoneStore::new();
    let mut packets = Vec::new();
    for i in 0..8 {
        let origin = DomainName::from_absolute_str(&format!("z{i}.test.")).unwrap();
        let owner = DomainName::from_absolute_str(&format!("www.z{i}.test.")).unwrap();
        store.insert_snapshot(ZoneSnapshot::active(
            origin,
            Some(1),
            vec![Rrset::new(
                owner.clone(),
                1,
                1,
                60,
                vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]],
            )],
        ));
        packets.push(query(&owner.to_wire(), 1, 1));
    }
    let requests: Vec<_> = packets.iter().map(|p| ParsedDnsRequest::new(p)).collect();
    let expected: Vec<_> = packets.iter().map(|p| store_response(p, &store)).collect();
    batch_serving::FALLBACK_PREPARATIONS.with(|count| count.set(0));
    with_prepared_dns_batch(&requests, &store, |batch| {
        assert!(batch.iter().all(|q| q.lookup.unwrap().fused.is_some()));
        for (q, expected) in batch.iter().zip(&expected) {
            assert_eq!(batch_test_answer(q, &store), *expected);
        }
    });
    batch_serving::FALLBACK_PREPARATIONS.with(|count| {
        assert_eq!(
            count.get(),
            0,
            "all-hit batches must skip fallback preparation"
        );
    });
}

#[cfg(feature = "experimental-query-preparation")]
#[test]
fn query_preparation_unsigned_proof_requires_complete_same_packet_validation() {
    let plain = query(b"\x03www\x07example\x04test\x00", 1, 1);
    let mut opt = plain.clone();
    append_opt(&mut opt, 1232, 0, &edns_option(10, &[1; 8]));
    for packet in [&plain, &opt] {
        let request = ParsedDnsRequest::new(packet);
        assert!(!request.validated_unsigned_query_for(packet));
        assert!(request.udp_payload_ceiling(1232).is_some());
        assert!(request.validated_unsigned_query_for(packet));
        assert!(!request.validated_unsigned_query_for(&packet.to_vec()));
        assert!(!request.validated_unsigned_query_for(&packet[..packet.len() - 1]));
        assert!(crate::tsig::message_tsig_key(packet).unwrap().is_none());
        for end in 0..packet.len() {
            let truncated = &packet[..end];
            let request = ParsedDnsRequest::new(truncated);
            let _ = request.udp_payload_ceiling(1232);
            assert!(!request.validated_unsigned_query_for(truncated));
        }
        let mut trailing = packet.to_vec();
        trailing.push(0);
        let request = ParsedDnsRequest::new(&trailing);
        let _ = request.udp_payload_ceiling(1232);
        assert!(!request.validated_unsigned_query_for(&trailing));
    }
    let key = crate::tsig::TsigKey::from_base64("key.test.", "hmac-sha256", "c2VjcmV0").unwrap();
    for packet in [&plain, &opt] {
        let signed = key.sign_request(packet, 1000, 300).unwrap().message;
        let request = ParsedDnsRequest::new(&signed);
        let _ = request.udp_payload_ceiling(1232);
        assert!(!request.validated_unsigned_query_for(&signed));
    }
    // Mutate every byte, including header counts, label encodings, record type,
    // OPT lengths and option bytes. Any positive proof must agree with the
    // independent TSIG envelope parser; errors must never certify absence.
    for seed in [&plain, &opt] {
        for offset in 0..seed.len() {
            for replacement in [0, 1, 41, 63, 192, 250, 255] {
                let mut packet = seed.clone();
                packet[offset] = replacement;
                let request = ParsedDnsRequest::new(&packet);
                let _ = request.udp_payload_ceiling(1232);
                if request.validated_unsigned_query_for(&packet) {
                    assert!(crate::tsig::message_tsig_key(&packet).unwrap().is_none());
                }
            }
        }
    }
}

#[cfg(feature = "experimental-fused-serving")]
#[test]
fn fused_serving_batch_matches_reference_and_freezes_before_child_publication() {
    let store = ZoneStore::new();
    let mut packets = Vec::new();
    for i in 0..8 {
        let origin = DomainName::from_absolute_str(&format!("z{i}.test.")).unwrap();
        let owner = DomainName::from_absolute_str(&format!("www.z{i}.test.")).unwrap();
        store.insert_snapshot(ZoneSnapshot::active(
            origin,
            Some(1),
            vec![Rrset::new(
                owner.clone(),
                1,
                1,
                60,
                vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]],
            )],
        ));
        packets.push(query(&owner.to_wire(), 1, 1));
    }
    let requests: Vec<_> = packets.iter().map(|p| ParsedDnsRequest::new(p)).collect();
    let expected: Vec<_> = packets.iter().map(|p| store_response(p, &store)).collect();
    with_prepared_dns_batch(&requests, &store, |batch| {
        store.insert_loading(DomainName::from_absolute_str("www.z0.test.").unwrap());
        for (prepared, expected) in batch.iter().zip(&expected) {
            assert_eq!(batch_test_answer(prepared, &store), *expected);
        }
    });
    with_prepared_dns_batch(&requests, &store, |batch| {
        assert_eq!(
            batch_test_answer(&batch[0], &store),
            store_response(&packets[0], &store)
        );
        assert_eq!(
            batch_test_answer(&batch[0], &store)[3] & 15,
            Rcode::ServFail as u8
        );
    });
}

#[test]
fn staged_batch_keeps_descriptors_bound_to_many_queries_and_zone_images() {
    let store = ZoneStore::new();
    let mut packets = Vec::new();
    for zone in 0..8u8 {
        let origin = DomainName::from_absolute_str(&format!("z{zone}.test.")).unwrap();
        let mut rrsets = vec![Rrset::new(origin.clone(), 6, 1, 300, vec![soa_rdata()])];
        for owner in 0..64u8 {
            let name =
                DomainName::from_absolute_str(&format!("name{owner}.z{zone}.test.")).unwrap();
            rrsets.push(Rrset::new(
                name.clone(),
                1,
                1,
                300,
                vec![vec![192, 0, zone, owner], vec![198, 51, zone, owner]],
            ));
            packets.push(query(&name.to_wire(), 1, 1));
        }
        store.insert_snapshot(ZoneSnapshot::active(origin, Some(1), rrsets));
    }
    // Interleave images and bucket positions; identical relative keys in two
    // different zones must never exchange templates or answer bytes.
    for owner in 0..64usize {
        let wires: Vec<_> = (0..8).map(|zone| &packets[zone * 64 + owner]).collect();
        let requests: Vec<_> = wires.iter().map(|p| ParsedDnsRequest::new(p)).collect();
        with_prepared_dns_batch(&requests, &store, |batch| {
            for (prepared, packet) in batch.iter().zip(&wires) {
                assert_eq!(
                    batch_test_answer(prepared, &store),
                    response_from_action(answer_datagram(packet, &store))
                );
            }
        });
    }
}

#[test]
#[cfg(feature = "experimental-fused-serving")]
fn fused_serving_inline_and_large_bodies_match_full_reference_wire() {
    let store = ZoneStore::new();
    let mut packets = Vec::new();
    for i in 0..8 {
        let origin = DomainName::from_absolute_str(&format!("z{i}.test.")).unwrap();
        let owner = DomainName::from_absolute_str(&format!("www.z{i}.test.")).unwrap();
        let count = [2u8, 8, 9, 40][i % 4];
        store.insert_snapshot(ZoneSnapshot::active(
            origin,
            Some(1),
            vec![Rrset::new(
                owner.clone(),
                1,
                1,
                60,
                (0..count).map(|j| vec![192, 0, i as u8, j]).collect(),
            )],
        ));
        packets.push(query(&owner.to_wire(), 1, 1));
    }
    let requests: Vec<_> = packets.iter().map(|p| ParsedDnsRequest::new(p)).collect();
    with_prepared_dns_batch(&requests, &store, |batch| {
        for (prepared, packet) in batch.iter().zip(&packets) {
            assert_eq!(
                batch_test_answer(prepared, &store),
                response_from_action(answer_datagram(packet, &store))
            );
        }
    });
}

fn batch_test_answer(query: &PreparedDnsBatchQuery<'_, '_>, store: &ZoneStore) -> Vec<u8> {
    match query.answer_with_default_hooks(
        store,
        AnswerOptions::default(),
        |_, _| false,
        |_, _, _| false,
        |_| {},
    ) {
        DatagramAction::Respond(response) => response,
        DatagramAction::Discard => panic!("query unexpectedly discarded"),
    }
}

#[cfg(feature = "experimental-fused-serving")]
#[test]
fn fused_serving_proof_respects_custom_provider_and_frozen_sizing_fallback() {
    let store = ZoneStore::new();
    for i in 0..8 {
        let origin = DomainName::from_absolute_str(&format!("z{i}.test.")).unwrap();
        let owner = DomainName::from_absolute_str(&format!("www.z{i}.test.")).unwrap();
        store.insert_snapshot(ZoneSnapshot::active(
            origin,
            Some(1),
            vec![Rrset::new(
                owner,
                1,
                1,
                60,
                (0..8).map(|j| vec![192, 0, 2, j]).collect(),
            )],
        ));
    }
    let packet = query(b"\x03www\x02z0\x04test\x00", 1, 1);
    let requests = [ParsedDnsRequest::new(&packet)];
    let options = AnswerOptions::udp(80);
    let expected_small = requests[0].answer_with_hooks(
        &store,
        options,
        |_, _| false,
        |_, _, _| false,
        |_| {},
        &default_zone_image_provider,
    );
    let expected_full = store_response(&packet, &store);
    with_prepared_dns_batch(&requests, &store, |batch| {
        assert!(batch[0].lookup.as_ref().unwrap().fused.is_some());
        assert!(batch[0].lookup.as_ref().unwrap().zone.is_none());
        // Both custom-provider and sizing fallback must consult the pinned
        // directory, not this newer child authority.
        store.insert_loading(DomainName::from_absolute_str("www.z0.test.").unwrap());
        let calls = std::cell::Cell::new(0);
        let custom = batch[0].answer_with_hooks(
            &store,
            AnswerOptions::default(),
            |_, _| false,
            |_, _, _| false,
            |_| {},
            &|zone| {
                calls.set(calls.get() + 1);
                default_zone_image_provider(zone)
            },
        );
        assert_eq!(response_from_action(custom), expected_full);
        assert!(calls.get() > 0);
        static ALTERNATE: std::sync::OnceLock<ZoneImage> = std::sync::OnceLock::new();
        let alternate = ALTERNATE.get_or_init(|| {
            ZoneImage::compile(&ZoneSnapshot::active(
                DomainName::from_absolute_str("z0.test.").unwrap(),
                Some(1),
                vec![Rrset::new(
                    DomainName::from_absolute_str("www.z0.test.").unwrap(),
                    1,
                    1,
                    60,
                    vec![vec![203, 0, 113, 7], vec![203, 0, 113, 8]],
                )],
            ))
            .unwrap()
        });
        let custom = batch[0].answer_with_hooks(
            &store,
            AnswerOptions::default(),
            |_, _| false,
            |_, _, _| false,
            |_| {},
            &|_| alternate,
        );
        assert_eq!(
            response_answer_rdatas(&response_from_action(custom), 1),
            vec![vec![203, 0, 113, 7], vec![203, 0, 113, 8]]
        );
        assert_eq!(
            batch[0].answer_with_default_hooks(
                &store,
                options,
                |_, _| false,
                |_, _, _| false,
                |_| {}
            ),
            expected_small
        );
        assert_eq!(batch_test_answer(&batch[0], &store), expected_full);
    });
    assert_eq!(
        store_response(&packet, &store)[3] & 15,
        Rcode::ServFail as u8
    );
}

#[cfg(feature = "experimental-fused-serving")]
#[test]
fn fused_serving_proof_preserves_cookie_edns_and_transport_policy() {
    let store = ZoneStore::new();
    for i in 0..8 {
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str(&format!("z{i}.test.")).unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str(&format!("www.z{i}.test.")).unwrap(),
                1,
                1,
                60,
                vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]],
            )],
        ));
    }
    let secret = [0x31; 16];
    let context = DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
    let options = [
        AnswerOptions::default(),
        AnswerOptions::udp(60),
        AnswerOptions {
            dns_cookie: Some(context),
            nsid: b"proof",
            ..AnswerOptions::default()
        },
        AnswerOptions {
            transport: Transport::Tls,
            edns_padding_block_size: 128,
            ..AnswerOptions::tcp()
        },
    ];
    let mut packets = vec![query(b"\x03www\x02z0\x04test\x00", 1, 1)];
    for (ttl, data) in [
        (0, vec![]),
        (0x8000, vec![]),
        (0x10000, vec![]),
        (0, edns_option(EDNS_COOKIE_OPTION, &[0x42; 8])),
        (0, edns_option(EDNS_COOKIE_OPTION, &[0x42; 24])),
        (0, edns_option(EDNS_PADDING_OPTION, &[0; 4])),
        (0, edns_option(EDNS_NSID_OPTION, &[])),
    ] {
        let mut packet = packets[0].clone();
        append_opt(&mut packet, 1232, ttl, &data);
        packets.push(packet);
    }
    let requests: Vec<_> = packets.iter().map(|p| ParsedDnsRequest::new(p)).collect();
    with_prepared_dns_batch(&requests, &store, |batch| {
        assert!(batch[0].lookup.as_ref().unwrap().fused.is_some());
        for options in options {
            for (i, prepared) in batch.iter().enumerate() {
                let actual = prepared.answer_with_default_hooks(
                    &store,
                    options,
                    |_, _| false,
                    |_, _, _| false,
                    |_| {},
                );
                let expected = requests[i].answer_with_hooks(
                    &store,
                    options,
                    |_, _| false,
                    |_, _, _| false,
                    |_| {},
                    &default_zone_image_provider,
                );
                assert_eq!(actual, expected, "packet{i}, options{options:?}");
            }
        }
    });
}

#[test]
fn staged_batch_keeps_selected_publication_and_next_batch_sees_expiration() {
    let store = batch_test_store();
    let packet = query(b"\x03www\x07example\x04test\x00", 1, 1);
    let requests = [
        ParsedDnsRequest::new(&packet),
        ParsedDnsRequest::new(&packet),
    ];
    let expected = store_response(&packet, &store);
    with_prepared_dns_batch(&requests, &store, |batch| {
        assert!(store.expire_zone(&DomainName::from_absolute_str("example.test.").unwrap()));
        for prepared in batch {
            assert_eq!(batch_test_answer(prepared, &store), expected);
        }
    });
    with_prepared_dns_batch(&requests, &store, |batch| {
        assert_eq!(
            batch_test_answer(&batch[0], &store)[3] & 15,
            Rcode::ServFail as u8
        );
    });
}

#[test]
fn staged_batch_binds_packet_identity_and_matches_reference_mixed_queries() {
    let store = batch_test_store();
    let packets = [
        query(b"\x03www\x07example\x04test\x00", 1, 1),
        query(b"\x03WWW\x07example\x04test\x00", 28, 1),
        query(b"\x07missing\x07example\x04test\x00", 1, 1),
        query(b"\x03www\x07example\x04test\x00", 255, 1),
        query(b"\x03www\x07example\x04test\x00", 1, 255),
        query(b"\x07outside\x04test\x00", 1, 1),
    ];
    let requests: Vec<_> = packets.iter().map(|p| ParsedDnsRequest::new(p)).collect();
    with_prepared_dns_batch(&requests, &store, |batch| {
        for (i, prepared) in batch.iter().enumerate() {
            assert!(prepared.matches_packet(&packets[i]));
            assert!(!prepared.matches_packet(&packets[(i + 1) % packets.len()]));
            assert_eq!(
                batch_test_answer(prepared, &store),
                response_from_action(answer_datagram(&packets[i], &store))
            );
        }
    });
}

#[test]
fn staged_batch_rejects_a_different_store_and_recycles_all_eight_live_names() {
    QUERY_LABEL_CACHE.with(|cache| *cache.borrow_mut() = Default::default());
    let store = batch_test_store();
    let empty = ZoneStore::new();
    let packet = query(b"\x03www\x07example\x04test\x00", 1, 1);
    let pointers = {
        let requests: [_; DNS_SERVING_BATCH_SIZE] =
            std::array::from_fn(|_| ParsedDnsRequest::new(&packet));
        with_prepared_dns_batch(&requests, &store, |batch| {
            assert_eq!(
                batch_test_answer(&batch[0], &empty)[3] & 15,
                Rcode::Refused as u8
            );
            requests
                .iter()
                .map(|r| r.question().unwrap().qname.labels()[0].as_ptr())
                .collect::<HashSet<_>>()
        })
    };
    assert_eq!(pointers.len(), DNS_SERVING_BATCH_SIZE);
    let requests: [_; DNS_SERVING_BATCH_SIZE] =
        std::array::from_fn(|_| ParsedDnsRequest::new(&packet));
    let reused: HashSet<_> = requests
        .iter()
        .map(|r| r.question().unwrap().qname.labels()[0].as_ptr())
        .collect();
    assert_eq!(pointers, reused);
}
