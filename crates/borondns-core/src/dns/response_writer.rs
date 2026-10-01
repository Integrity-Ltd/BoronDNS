use super::*;

/// Result of answering into a caller-owned, bounded DNS payload buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum BufferedDatagramAction {
    /// The caller buffer is unchanged; use the ordinary owned response/action.
    Owned(DatagramAction),
    /// Exactly this many bytes were initialized in the caller buffer.
    #[cfg(feature = "experimental-response-writer")]
    Written(usize),
}

impl From<DatagramAction> for BufferedDatagramAction {
    fn from(action: DatagramAction) -> Self {
        Self::Owned(action)
    }
}

impl BufferedDatagramAction {
    pub(super) fn into_owned(self) -> DatagramAction {
        match self {
            Self::Owned(action) => action,
            #[cfg(feature = "experimental-response-writer")]
            Self::Written(_) => unreachable!("owned API never supplies a destination"),
        }
    }
}

// A small common serializer surface, statically dispatched for both Vec and a
// pre-sized slice. The wire construction and EDNS policy are shared, not copied
// into an alternative resolver. Only the slice path needs a sizing preflight.
pub(super) trait DnsWireWrite {
    fn len(&self) -> usize;
    fn extend_from_slice(&mut self, bytes: &[u8]);
    fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }
    fn resize(&mut self, len: usize, byte: u8);
}

impl DnsWireWrite for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Vec::extend_from_slice(self, bytes);
    }
    fn resize(&mut self, len: usize, byte: u8) {
        Vec::resize(self, len, byte);
    }
}

#[cfg(feature = "experimental-response-writer")]
struct SliceWriter<'a> {
    destination: &'a mut [u8],
    len: usize,
}

#[cfg(feature = "experimental-response-writer")]
impl DnsWireWrite for SliceWriter<'_> {
    fn len(&self) -> usize {
        self.len
    }
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        self.destination[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }
    fn resize(&mut self, len: usize, byte: u8) {
        assert!(len >= self.len, "DNS serializer only appends padding");
        self.destination[self.len..len].fill(byte);
        self.len = len;
    }
}

#[cfg(feature = "experimental-response-writer")]
pub(super) fn write_compact_answer_into(
    header: &Header,
    question: &Question,
    answer: ZoneImageTemplateAnswer<'_>,
    metadata: RequestMetadata,
    options: AnswerOptions,
    sizing: ZoneImageResponseSizing,
    destination: &mut [u8],
) -> Option<usize> {
    let before_opt = sizing
        .minimum_capacity
        .checked_add(answer.body_wire_len())?;
    let required = if let Some(edns) = metadata.edns {
        let shape = edns_response_options_shape_from_base(
            edns,
            options,
            sizing.edns.base_shape?,
            before_opt,
            sizing.udp_ceiling,
        );
        before_opt.checked_add(11)?.checked_add(shape.rdata_len)?
    } else {
        before_opt
    };
    // No destination byte changes on a failed fit, including the DNS ceiling.
    // This is deliberately not a short write followed by an owned fallback.
    if required > destination.len()
        || (options.transport == Transport::Udp && required > sizing.udp_ceiling)
    {
        return None;
    }
    let mut writer = SliceWriter {
        destination: &mut destination[..required],
        len: 0,
    };
    append_compact_zone_image_answer(
        header,
        question,
        answer,
        metadata,
        options,
        sizing,
        &mut writer,
    );
    assert_eq!(
        writer.len, required,
        "bounded response sizing matches serialization"
    );
    Some(required)
}

#[cfg(all(test, feature = "experimental-response-writer"))]
mod tests {
    use super::super::*;

    fn store() -> ZoneStore {
        let store = ZoneStore::new();
        for i in 0..8 {
            store.insert_snapshot(crate::zone::ZoneSnapshot::active(
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
        store
    }

    fn query() -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(b"\x03WwW\x02z0\x04test\x00\x00\x01\x00\x01");
        packet
    }

    #[test]
    fn response_writer_writes_exact_reference_bytes_without_touching_tail() {
        let store = store();
        let packet = query();
        let requests = [ParsedDnsRequest::new(&packet)];
        with_prepared_dns_batch(&requests, &store, |batch| {
            let DatagramAction::Respond(expected) = batch[0].answer_with_default_hooks(
                &store,
                AnswerOptions::default(),
                |_, _| false,
                |_, _, _| false,
                |_| {},
            ) else {
                panic!("expected answer")
            };
            let mut destination = [0xa5; 512];
            let actual = batch[0].answer_with_default_hooks_into(
                &store,
                AnswerOptions::default(),
                |_, _| false,
                |_, _, _| false,
                |_| {},
                &mut destination,
            );
            assert_eq!(actual, BufferedDatagramAction::Written(expected.len()));
            assert_eq!(&destination[..expected.len()], expected);
            assert!(destination[expected.len()..].iter().all(|b| *b == 0xa5));
        });
    }

    #[test]
    fn response_writer_short_destination_falls_back_unchanged() {
        let store = store();
        let packet = query();
        let requests = [ParsedDnsRequest::new(&packet)];
        with_prepared_dns_batch(&requests, &store, |batch| {
            let expected = batch[0].answer_with_default_hooks(
                &store,
                AnswerOptions::default(),
                |_, _| false,
                |_, _, _| false,
                |_| {},
            );
            for len in 0..32 {
                let mut destination = vec![0xa5; len];
                let actual = batch[0].answer_with_default_hooks_into(
                    &store,
                    AnswerOptions::default(),
                    |_, _| false,
                    |_, _, _| false,
                    |_| {},
                    &mut destination,
                );
                assert_eq!(actual, BufferedDatagramAction::Owned(expected.clone()));
                assert_eq!(destination, vec![0xa5; len]);
            }
        });
    }

    fn with_opt(mut packet: Vec<u8>, ttl: u32, code: Option<u16>, data: &[u8]) -> Vec<u8> {
        packet[10..12].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 41, 4, 208]);
        packet.extend_from_slice(&ttl.to_be_bytes());
        let len = code.map_or(0, |_| 4 + data.len());
        packet.extend_from_slice(&(len as u16).to_be_bytes());
        if let Some(code) = code {
            packet.extend_from_slice(&code.to_be_bytes());
            packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
            packet.extend_from_slice(data);
        }
        packet
    }

    #[test]
    fn response_writer_matches_reference_policy_edns_and_all_fit_boundaries() {
        let store = store();
        let secret = [0x31; 16];
        let context =
            DnsCookieContext::new("198.51.100.100".parse().unwrap(), &secret, 1_559_731_985);
        let options = [
            AnswerOptions::default(),
            AnswerOptions::udp(60),
            AnswerOptions {
                dns_cookie: Some(context),
                nsid: b"writer-test",
                ..AnswerOptions::default()
            },
            AnswerOptions {
                transport: Transport::Tls,
                edns_padding_block_size: 128,
                ..AnswerOptions::tcp()
            },
        ];
        let mut packets = vec![query()];
        for (ttl, code, data) in [
            (0, None, vec![]),
            (0x8000, None, vec![]),
            (0x10000, None, vec![]),
            (0, Some(EDNS_COOKIE_OPTION), vec![0x42; 8]),
            (0, Some(EDNS_COOKIE_OPTION), vec![0x42; 24]),
            (0, Some(EDNS_NSID_OPTION), vec![]),
            (0, Some(EDNS_PADDING_OPTION), vec![0; 4]),
            (0, Some(EDNS_TCP_KEEPALIVE_OPTION), vec![]),
            (0, Some(EDNS_TCP_KEEPALIVE_OPTION), vec![0]),
        ] {
            packets.push(with_opt(query(), ttl, code, &data));
        }
        let mut response_packet = query();
        response_packet[2] |= 0x80;
        packets.push(response_packet);
        packets.push(vec![0; 3]);
        let mut any = query();
        let len = any.len();
        any[len - 4..len - 2].copy_from_slice(&255u16.to_be_bytes());
        packets.push(any);
        for packets in packets.chunks(DNS_SERVING_BATCH_SIZE) {
            let requests: Vec<_> = packets.iter().map(|p| ParsedDnsRequest::new(p)).collect();
            with_prepared_dns_batch(&requests, &store, |batch| {
                for options in options {
                    for (request, prepared) in requests.iter().zip(batch) {
                        let expected = request.answer_with_hooks(
                            &store,
                            options,
                            |_, _| false,
                            |_, _, _| false,
                            |_| {},
                            &default_zone_image_provider,
                        );
                        let len = match &expected {
                            DatagramAction::Respond(bytes) => bytes.len(),
                            DatagramAction::Discard => 0,
                        };
                        for capacity in [0, len.saturating_sub(1), len, len + 1, 1024] {
                            let mut destination = vec![0xa5; capacity];
                            let actual = prepared.answer_with_default_hooks_into(
                                &store,
                                options,
                                |_, _| false,
                                |_, _, _| false,
                                |_| {},
                                &mut destination,
                            );
                            match actual {
                                BufferedDatagramAction::Owned(action) => {
                                    assert_eq!(action, expected);
                                    assert!(destination.iter().all(|b| *b == 0xa5));
                                }
                                BufferedDatagramAction::Written(written) => {
                                    assert_eq!(written, len);
                                    assert_eq!(
                                        DatagramAction::Respond(destination[..written].to_vec()),
                                        expected
                                    );
                                    assert!(destination[written..].iter().all(|b| *b == 0xa5));
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    #[test]
    fn response_writer_keeps_frozen_fallback_and_rejects_another_store() {
        let store = store();
        let packet = query();
        let requests = [ParsedDnsRequest::new(&packet)];
        let options = AnswerOptions::udp(40);
        let expected = requests[0].answer_with_hooks(
            &store,
            options,
            |_, _| false,
            |_, _, _| false,
            |_| {},
            &default_zone_image_provider,
        );
        with_prepared_dns_batch(&requests, &store, |batch| {
            assert!(batch[0].lookup.as_ref().unwrap().fused.is_some());
            store.insert_loading(DomainName::from_absolute_str("www.z0.test.").unwrap());
            let observations = Cell::new(0);
            let mut destination = [0xa5; 512];
            let actual = batch[0].answer_with_default_hooks_into(
                &store,
                options,
                |_, _| false,
                |_, _, _| false,
                |_| observations.set(observations.get() + 1),
                &mut destination,
            );
            assert_eq!(actual, BufferedDatagramAction::Owned(expected));
            assert_eq!(observations.get(), 1);
            assert_eq!(destination, [0xa5; 512]);
            let other = ZoneStore::new();
            let expected = batch[0].answer_with_default_hooks(
                &other,
                AnswerOptions::default(),
                |_, _| false,
                |_, _, _| false,
                |_| {},
            );
            assert_eq!(
                batch[0].answer_with_default_hooks_into(
                    &other,
                    AnswerOptions::default(),
                    |_, _| false,
                    |_, _, _| false,
                    |_| {},
                    &mut destination,
                ),
                BufferedDatagramAction::Owned(expected)
            );
            assert_eq!(destination, [0xa5; 512]);
        });
    }
}
