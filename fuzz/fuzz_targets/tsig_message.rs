#![no_main]

use std::sync::OnceLock;

use borondns_core::{
    dns::RecordType,
    tsig::{
        DEFAULT_TSIG_FUDGE_SECS, TSIG_ERROR_BADKEY, TsigAlgorithm, TsigError,
        TsigErrorResponseFields, TsigKey, append_unsigned_tsig_error, extract_tsig_mac,
        message_has_tsig, sign_request, sign_response, sign_tcp_response_continuation,
        sign_tsig_error_response, verify_request, verify_response, verify_tcp_response_stream,
        verify_tcp_response_stream_owned, verify_tcp_response_stream_owned_at_times,
    },
};
use libfuzzer_sys::fuzz_target;

const NOW_UNIX: u64 = 1_700_000_000;
const QID: u16 = 0x1234;
const QCLASS_IN: u16 = 1;

fuzz_target!(|data: &[u8]| {
    let key = tsig_key();
    let bounded = &data[..data.len().min(4096)];
    let request_mac = &bounded[..bounded.len().min(64)];

    if let Ok(text) = std::str::from_utf8(&bounded[..bounded.len().min(128)]) {
        let _ = TsigAlgorithm::parse(text);
        let _ = TsigKey::from_base64("transfer-key.alpha.test.", text, "c2VjcmV0");
    }

    let _ = message_has_tsig(bounded);
    let _ = extract_tsig_mac(bounded);
    let _ = verify_request(bounded, key, NOW_UNIX);
    let _ = verify_response(bounded, key, request_mac, NOW_UNIX);

    let messages = split_messages(bounded);
    let borrowed = verify_tcp_response_stream(&messages, key, request_mac, NOW_UNIX);
    let owned = verify_tcp_response_stream_owned(messages.clone(), key, request_mac, NOW_UNIX);
    assert_eq!(borrowed, owned);
    let received_at = messages
        .clone()
        .into_iter()
        .enumerate()
        .map(|(index, message)| {
            let offset = u64::from(byte(data, index));
            (message, NOW_UNIX.saturating_add(offset))
        })
        .collect();
    let _ = verify_tcp_response_stream_owned_at_times(received_at, key, request_mac);

    exercise_shaped_tsig_messages(data, key);
});

fn tsig_key() -> &'static TsigKey {
    static KEY: OnceLock<TsigKey> = OnceLock::new();
    KEY.get_or_init(|| {
        TsigKey::from_base64("transfer-key.alpha.test.", "hmac-sha256", "c2VjcmV0")
            .expect("static TSIG key is valid")
    })
}

fn exercise_shaped_tsig_messages(data: &[u8], key: &TsigKey) {
    let query = dns_message(QID, false, RecordType::Soa as u16);
    let response = dns_message(QID, true, RecordType::Soa as u16);
    let time_signed = NOW_UNIX + (byte(data, 0) & 0x03) as u64;
    let fudge = DEFAULT_TSIG_FUDGE_SECS + (byte(data, 1) & 0x03) as u16;

    let Ok(signed_request) = sign_request(&query, key, time_signed, fudge) else {
        return;
    };
    let _ = verify_request(&signed_request.message, key, NOW_UNIX);
    let _ = message_has_tsig(&signed_request.message);
    let _ = extract_tsig_mac(&signed_request.message);

    let mut mutated_request = signed_request.message.clone();
    mutate_one_byte(&mut mutated_request, data);
    let _ = verify_request(&mutated_request, key, NOW_UNIX);
    let _ = message_has_tsig(&mutated_request);
    let _ = extract_tsig_mac(&mutated_request);

    if let Ok(signed_response) = sign_response(
        &response,
        key,
        &signed_request.mac,
        time_signed,
        DEFAULT_TSIG_FUDGE_SECS,
    ) {
        let _ = verify_response(&signed_response.message, key, &signed_request.mac, NOW_UNIX);

        let continuation = sign_tcp_response_continuation(
            &response,
            key,
            &signed_response.mac,
            time_signed,
            DEFAULT_TSIG_FUDGE_SECS,
        );
        if let Ok(terminal) = continuation {
            let stream = vec![
                signed_response.message.clone(),
                response.clone(),
                terminal.message.clone(),
            ];
            let borrowed = verify_tcp_response_stream(&stream, key, &signed_request.mac, NOW_UNIX);
            let owned = verify_tcp_response_stream_owned(
                stream.clone(),
                key,
                &signed_request.mac,
                NOW_UNIX,
            );
            assert_eq!(borrowed, owned);

            let received_at = stream
                .clone()
                .into_iter()
                .enumerate()
                .map(|(index, message)| (message, NOW_UNIX + index as u64))
                .collect();
            let timed =
                verify_tcp_response_stream_owned_at_times(received_at, key, &signed_request.mac);
            assert_eq!(owned, timed);

            let mut trailing_terminal = terminal.message;
            trailing_terminal.push(byte(data, 2));
            let trailing_stream = vec![
                signed_response.message.clone(),
                response.clone(),
                trailing_terminal,
            ];
            assert!(
                verify_tcp_response_stream_owned_at_times(
                    trailing_stream
                        .into_iter()
                        .map(|message| (message, NOW_UNIX))
                        .collect(),
                    key,
                    &signed_request.mac,
                )
                .is_err()
            );

            let expired_at = time_signed
                .saturating_add(u64::from(DEFAULT_TSIG_FUDGE_SECS))
                .saturating_add(1);
            assert_eq!(
                verify_tcp_response_stream_owned_at_times(
                    vec![(signed_response.message.clone(), expired_at)],
                    key,
                    &signed_request.mac,
                ),
                Err(TsigError::TimeOutsideFudge)
            );

            if let Ok(backwards) = sign_tcp_response_continuation(
                &response,
                key,
                &signed_response.mac,
                time_signed.saturating_sub(1),
                DEFAULT_TSIG_FUDGE_SECS,
            ) {
                assert_eq!(
                    verify_tcp_response_stream_owned_at_times(
                        vec![
                            (signed_response.message, NOW_UNIX),
                            (backwards.message, NOW_UNIX),
                        ],
                        key,
                        &signed_request.mac,
                    ),
                    Err(TsigError::NonMonotonicTimeSigned)
                );
            }
        }
    }

    let other_data = &data[..data.len().min(48)];
    if let Ok(unsigned_error) = append_unsigned_tsig_error(
        &response,
        key,
        time_signed,
        DEFAULT_TSIG_FUDGE_SECS,
        QID,
        TSIG_ERROR_BADKEY,
        other_data,
    ) {
        let _ = message_has_tsig(&unsigned_error);
        let _ = extract_tsig_mac(&unsigned_error);
        let _ = verify_response(&unsigned_error, key, &signed_request.mac, NOW_UNIX);
    }

    let fields = TsigErrorResponseFields {
        request_mac: &signed_request.mac,
        time_signed,
        fudge: DEFAULT_TSIG_FUDGE_SECS,
        original_id: QID,
        error: TSIG_ERROR_BADKEY,
        other_data,
    };
    if let Ok(signed_error) = sign_tsig_error_response(&response, key, fields) {
        let _ = verify_response(&signed_error.message, key, &signed_request.mac, NOW_UNIX);
    }
}

fn split_messages(data: &[u8]) -> Vec<Vec<u8>> {
    let mut offset = 0;
    let mut messages = Vec::new();

    while offset + 2 <= data.len() && messages.len() < 16 {
        let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let end = offset.saturating_add(len).min(data.len());
        messages.push(data[offset..end].to_vec());
        offset = end;
    }

    if messages.is_empty() && !data.is_empty() {
        messages.push(data.to_vec());
    }

    messages
}

fn dns_message(id: u16, response: bool, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    let flags = if response { 0x8400u16 } else { 0x0100u16 };
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&name_wire("alpha.test."));
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
    packet
}

fn name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn mutate_one_byte(message: &mut [u8], data: &[u8]) {
    if message.is_empty() || data.len() < 3 {
        return;
    }
    let index = get_u16(data, 1) as usize % message.len();
    message[index] ^= data[data.len() - 1];
}

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(0)
}

fn get_u16(data: &[u8], index: usize) -> u16 {
    let high = byte(data, index);
    let low = byte(data, index + 1);
    u16::from_be_bytes([high, low])
}
