#[test]
fn response_writer_frame_payload_matches_owned_ipv4_and_ipv6() {
    use crate::udp::UdpReplyBuffers;
    for ipv6 in [false, true] {
        let mut storage = [0xa5u8; 2048];
        let mut reference_storage = [0xa5u8; 2048];
        let mut packet = xdp::Packet::testing_new(&mut storage);
        let mut reference = xdp::Packet::testing_new(&mut reference_storage);
        let query = if ipv6 {
            ipv6_udp_frame(&[1; 4])
        } else {
            ipv4_udp_frame(&[1; 4])
        };
        let len = if ipv6 {
            ipv6_udp_frame_len(4)
        } else {
            ipv4_udp_frame_len(4)
        };
        packet.insert(0, &query[..len]).unwrap();
        reference.insert(0, &query[..len]).unwrap();
        let frame = parse_udp_ip_frame(&packet).unwrap();
        let mut frames = vec![Some(ReceivedFrame {
            packet,
            frame: frame.clone(),
            prepared_len: None,
            reply_epoch: 7,
        })];
        let body = [9u8; 64];
        let token = {
            let mut buffers = response_writer::ReplyFrames {
                frames: &mut frames,
            };
            buffers.buffer(0).expect("mutable bounded payload")[..body.len()]
                .copy_from_slice(&body);
            buffers.seal(0, body.len(), None).unwrap()
        };
        let prepared = frames[0].as_mut().unwrap();
        let actual_len = response_writer::finish(prepared, 0, token).unwrap();
        let expected_len = write_udp_ip_response(&mut reference, frame, &body).unwrap();
        assert_eq!(actual_len, expected_len);
        assert_eq!(&prepared.packet[..], &reference[..]);
        parse_udp_ip_frame(&prepared.packet).expect("valid response checksums");
        assert!(
            response_writer::finish(prepared, 0, token).is_err(),
            "token is consumed once"
        );
    }
}

#[test]
fn response_writer_rejects_invalidated_or_previous_batch_descriptor() {
    use crate::udp::UdpReplyBuffers;
    let mut storage = [0u8; 2048];
    let mut packet = xdp::Packet::testing_new(&mut storage);
    let query = ipv4_udp_frame(&[1; 4]);
    packet.insert(0, &query[..ipv4_udp_frame_len(4)]).unwrap();
    let frame = parse_udp_ip_frame(&packet).unwrap();
    let mut frames = vec![Some(ReceivedFrame {
        packet,
        frame,
        prepared_len: None,
        reply_epoch: 7,
    })];
    let token = {
        let mut buffers = response_writer::ReplyFrames {
            frames: &mut frames,
        };
        buffers.buffer(0).unwrap()[..32].fill(1);
        assert!(buffers.seal(0, usize::MAX, None).is_none());
        let token = buffers.seal(0, 32, None).unwrap();
        buffers.buffer(0).unwrap(); // a new lease invalidates the old completion
        token
    };
    assert!(response_writer::finish(frames[0].as_mut().unwrap(), 0, token).is_err());
    let token = response_writer::ReplyFrames {
        frames: &mut frames,
    }
    .seal(0, 32, None)
    .unwrap();
    let frame = frames[0].as_mut().unwrap();
    frame.reply_epoch += 1;
    assert!(response_writer::finish(frame, 0, token).is_err());
}

#[test]
fn response_writer_abandoned_buffer_keeps_owned_fallback_frame_exact() {
    use crate::udp::UdpReplyBuffers;
    for ipv6 in [false, true] {
        let mut storage = [0xa5; 2048];
        let mut reference_storage = [0xa5; 2048];
        let mut packet = xdp::Packet::testing_new(&mut storage);
        let mut reference = xdp::Packet::testing_new(&mut reference_storage);
        let query = if ipv6 {
            ipv6_udp_frame(&[1; 64])
        } else {
            ipv4_udp_frame(&[1; 64])
        };
        let len = if ipv6 {
            ipv6_udp_frame_len(64)
        } else {
            ipv4_udp_frame_len(64)
        };
        packet.insert(0, &query[..len]).unwrap();
        reference.insert(0, &query[..len]).unwrap();
        let frame = parse_udp_ip_frame(&packet).unwrap();
        let mut frames = [Some(ReceivedFrame {
            packet,
            frame: frame.clone(),
            prepared_len: None,
            reply_epoch: 8,
        })];
        {
            let mut buffers = response_writer::ReplyFrames {
                frames: &mut frames,
            };
            assert!(buffers.buffer(1).is_none());
            // The transport grows the frame to expose capacity even when the
            // core decides to return an owned fallback, or RRL requests Slip.
            buffers.buffer(0).unwrap()[..128].fill(0x77);
        }
        let body = [9u8; 12];
        let actual = frames[0].as_mut().unwrap();
        write_udp_ip_response(&mut actual.packet, actual.frame.clone(), &body).unwrap();
        write_udp_ip_response(&mut reference, frame, &body).unwrap();
        assert_eq!(&actual.packet[..], &reference[..]);
        parse_udp_ip_frame(&actual.packet).expect("fallback has valid lengths and checksums");
        assert_eq!(actual.prepared_len, None);
    }
}
