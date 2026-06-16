#![no_main]

use std::{hint::black_box, sync::OnceLock};

use libfuzzer_sys::fuzz_target;
use oxidedns_core::{
    dns::{
        AnswerOptions, DEFAULT_MAX_UDP_PAYLOAD, DatagramAction, DomainName, Header, Opcode,
        RecordType, Transport, answer_message_with_notify_hooks,
    },
    zone::{Rrset, ZoneSnapshot, ZoneStore},
};

const QID: u16 = 0x5151;
const QCLASS_IN: u16 = 1;

fuzz_target!(|data: &[u8]| {
    let zones = zones();
    let options = answer_options(data);

    let authorized = |qname: &DomainName, qclass: u16| {
        black_box((qname, qclass));
        byte(data, 0) & 0x40 == 0
    };
    let accepted = |qname: &DomainName, qclass: u16, serial: Option<u32>| {
        black_box((qname, qclass, serial));
    };

    let _ = answer_message_with_notify_hooks(data, zones, options, authorized, accepted);

    let packet = shaped_notify_packet(data);
    if let Ok(header) = Header::parse(&packet) {
        black_box(header.opcode());
    }
    let action = answer_message_with_notify_hooks(
        &packet,
        zones,
        options,
        |qname, qclass| {
            black_box((qname, qclass));
            byte(data, 1) & 0x80 == 0
        },
        |qname, qclass, serial| {
            black_box((qname, qclass, serial));
        },
    );
    if let DatagramAction::Respond(response) = action {
        black_box(response.len());
    }
});

fn zones() -> &'static ZoneStore {
    static ZONES: OnceLock<ZoneStore> = OnceLock::new();
    ZONES.get_or_init(|| {
        let apex = DomainName::from_absolute_str("alpha.test.").expect("static apex is valid");
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            apex.clone(),
            Some(1),
            vec![
                Rrset::new(
                    apex.clone(),
                    RecordType::Soa as u16,
                    QCLASS_IN,
                    3600,
                    vec![soa_rdata(1)],
                ),
                Rrset::new(
                    apex.clone(),
                    RecordType::Ns as u16,
                    QCLASS_IN,
                    3600,
                    vec![name_wire("ns1.alpha.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns1.alpha.test.")
                        .expect("static NS name is valid"),
                    RecordType::A as u16,
                    QCLASS_IN,
                    3600,
                    vec![vec![192, 0, 2, 53]],
                ),
            ],
        ));
        store
    })
}

fn answer_options(data: &[u8]) -> AnswerOptions<'_> {
    let transport = if byte(data, 2) & 1 == 0 {
        Transport::Udp
    } else {
        Transport::Tcp
    };
    let padding_block = match byte(data, 3) & 0x03 {
        0 => 0,
        1 => 8,
        2 => 32,
        _ => 128,
    };

    let mut options =
        AnswerOptions::udp(512 + (get_u16(data, 4) % (DEFAULT_MAX_UDP_PAYLOAD - 511)));
    options.transport = transport;
    options.edns_padding_block_size = padding_block;
    options
}

fn shaped_notify_packet(data: &[u8]) -> Vec<u8> {
    let include_answer = byte(data, 6) & 1 != 0;
    let opt_count = (byte(data, 7) % 3) as u16;
    let qtype = if byte(data, 8) & 0x80 == 0 {
        RecordType::Soa as u16
    } else {
        get_u16(data, 9)
    };
    let qclass = if byte(data, 11) & 0x80 == 0 {
        QCLASS_IN
    } else {
        get_u16(data, 12)
    };

    let mut packet = Vec::new();
    packet.extend_from_slice(&QID.to_be_bytes());
    let flags = (Opcode::Notify as u16) << 11;
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&(include_answer as u16).to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&opt_count.to_be_bytes());
    packet.extend_from_slice(&name_wire("alpha.test."));
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());

    let mut offset = 14usize.min(data.len());
    if include_answer {
        let len = (byte(data, 14) as usize).min(96);
        let rdata = take(data, &mut offset, len);
        append_record(
            &mut packet,
            "alpha.test.",
            RecordType::Soa as u16,
            qclass,
            3600,
            rdata,
        );
    }

    for index in 0..opt_count {
        let len = (byte(data, 15 + index as usize) as usize).min(96);
        let rdata = take(data, &mut offset, len);
        append_opt(&mut packet, data, index, rdata);
    }

    packet
}

fn append_record(
    packet: &mut Vec<u8>,
    owner: &str,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: &[u8],
) {
    packet.extend_from_slice(&name_wire(owner));
    packet.extend_from_slice(&rr_type.to_be_bytes());
    packet.extend_from_slice(&class.to_be_bytes());
    packet.extend_from_slice(&ttl.to_be_bytes());
    packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    packet.extend_from_slice(rdata);
}

fn append_opt(packet: &mut Vec<u8>, data: &[u8], index: u16, rdata: &[u8]) {
    packet.push(0);
    packet.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
    let payload = 512 + (get_u16(data, 18 + index as usize) % 1232);
    packet.extend_from_slice(&payload.to_be_bytes());
    let version = if byte(data, 22 + index as usize) & 0x20 == 0 {
        0u8
    } else {
        byte(data, 23 + index as usize)
    };
    let flags = if byte(data, 24 + index as usize) & 0x80 == 0 {
        0x8000u16
    } else {
        0
    };
    let ttl = ((version as u32) << 16) | flags as u32;
    packet.extend_from_slice(&ttl.to_be_bytes());
    packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    packet.extend_from_slice(rdata);
}

fn take<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> &'a [u8] {
    let start = (*offset).min(data.len());
    let end = start.saturating_add(len).min(data.len());
    *offset = end;
    &data[start..end]
}

fn soa_rdata(serial: u32) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&name_wire("ns1.alpha.test."));
    rdata.extend_from_slice(&name_wire("hostmaster.alpha.test."));
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&3600u32.to_be_bytes());
    rdata.extend_from_slice(&600u32.to_be_bytes());
    rdata.extend_from_slice(&86400u32.to_be_bytes());
    rdata.extend_from_slice(&300u32.to_be_bytes());
    rdata
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

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(0)
}

fn get_u16(data: &[u8], index: usize) -> u16 {
    u16::from_be_bytes([byte(data, index), byte(data, index + 1)])
}
