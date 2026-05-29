#![no_main]

use std::{
    hint::black_box,
    sync::{Arc, OnceLock},
};

use libfuzzer_sys::fuzz_target;
use oxidedns_core::{
    dns::{
        answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image, AnswerOptions,
        DatagramAction, DomainName, Header, RecordType, Transport, DEFAULT_MAX_UDP_PAYLOAD,
    },
    zone::{PublishedZone, Rrset, ZoneSnapshot, ZoneStore},
    zone_image::ZoneImage,
};

const QID: u16 = 0x5a11;
const QCLASS_IN: u16 = 1;

fuzz_target!(|data: &[u8]| {
    let image = zone_image();
    let provider = |_zone: &PublishedZone| Arc::clone(image);

    exercise_packet(data, data, &provider);

    let packet = shaped_query_packet(data);
    if let Ok(header) = Header::parse(&packet) {
        black_box(header.qdcount);
    }
    exercise_packet(&packet, data, &provider);
});

fn exercise_packet(
    packet: &[u8],
    data: &[u8],
    provider: &dyn Fn(&PublishedZone) -> Arc<ZoneImage>,
) {
    let action = answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        packet,
        zones(),
        answer_options(data),
        |qname, qclass| {
            black_box((qname, qclass));
            true
        },
        |qname, qclass, serial| {
            black_box((qname, qclass, serial));
        },
        |metrics| {
            black_box(metrics);
        },
        provider,
    );

    if let DatagramAction::Respond(response) = action {
        black_box(response.len());
    }
}

fn zones() -> &'static ZoneStore {
    static ZONES: OnceLock<ZoneStore> = OnceLock::new();
    ZONES.get_or_init(|| {
        let apex = DomainName::from_absolute_str("zoneimage.test.").expect("static apex is valid");
        let store = ZoneStore::new();
        store.insert_snapshot(zone_snapshot(apex));
        store
    })
}

fn zone_image() -> &'static Arc<ZoneImage> {
    static IMAGE: OnceLock<Arc<ZoneImage>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        let apex = DomainName::from_absolute_str("zoneimage.test.").expect("static apex is valid");
        Arc::new(ZoneImage::compile(&zone_snapshot(apex)).expect("static zone image compiles"))
    })
}

fn zone_snapshot(apex: DomainName) -> ZoneSnapshot {
    ZoneSnapshot::active(
        apex.clone(),
        Some(1),
        vec![
            rrset(&apex, RecordType::Soa, vec![soa_rdata(1)]),
            rrset(
                &apex,
                RecordType::Ns,
                vec![name_wire("ns1.zoneimage.test.")],
            ),
            rrset(
                &name("ns1.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 53]],
            ),
            rrset(
                &name("www.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 80]],
            ),
            rrset(
                &name("www.zoneimage.test."),
                RecordType::Aaaa,
                vec![vec![
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80,
                ]],
            ),
            rrset(
                &name("alias.zoneimage.test."),
                RecordType::Cname,
                vec![name_wire("www.zoneimage.test.")],
            ),
            rrset(
                &name("mail.zoneimage.test."),
                RecordType::Mx,
                vec![mx_rdata(10, "mx1.zoneimage.test.")],
            ),
            rrset(
                &name("mx1.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 25]],
            ),
            rrset(
                &name("txt.zoneimage.test."),
                RecordType::Txt,
                vec![txt_rdata(b"zone-image composer fuzz")],
            ),
            rrset(
                &name("badns.zoneimage.test."),
                RecordType::Ns,
                vec![vec![0xc0, 0x0c]],
            ),
            rrset(
                &name("badcname.zoneimage.test."),
                RecordType::Cname,
                vec![vec![0xc0, 0x0c]],
            ),
            rrset(
                &name("badmx.zoneimage.test."),
                RecordType::Mx,
                vec![vec![0, 10, 0xc0, 0x0c]],
            ),
            Rrset::new(
                name("opaque.zoneimage.test."),
                65_280,
                QCLASS_IN,
                300,
                vec![vec![0xc0, 0x0c, 0x03, b'w', b'w']],
            ),
        ],
    )
}

fn rrset(owner: &DomainName, rr_type: RecordType, rdatas: Vec<Vec<u8>>) -> Rrset {
    Rrset::new(owner.clone(), rr_type as u16, QCLASS_IN, 300, rdatas)
}

fn answer_options(data: &[u8]) -> AnswerOptions<'_> {
    let transport = if byte(data, 0) & 1 == 0 {
        Transport::Udp
    } else {
        Transport::Tcp
    };
    let padding_block = match byte(data, 1) & 0x03 {
        0 => 0,
        1 => 8,
        2 => 32,
        _ => 128,
    };

    let mut options = AnswerOptions::udp(512 + (get_u16(data, 2) % (DEFAULT_MAX_UDP_PAYLOAD - 511)));
    options.transport = transport;
    options.edns_padding_block_size = padding_block;
    options
}

fn shaped_query_packet(data: &[u8]) -> Vec<u8> {
    let names = [
        "zoneimage.test.",
        "www.zoneimage.test.",
        "alias.zoneimage.test.",
        "mail.zoneimage.test.",
        "txt.zoneimage.test.",
        "badns.zoneimage.test.",
        "badcname.zoneimage.test.",
        "badmx.zoneimage.test.",
        "opaque.zoneimage.test.",
        "*.zoneimage.test.",
    ];
    let qtypes = [
        RecordType::A as u16,
        RecordType::Aaaa as u16,
        RecordType::Ns as u16,
        RecordType::Cname as u16,
        RecordType::Mx as u16,
        RecordType::Txt as u16,
        65_280,
        get_u16(data, 6),
    ];

    let qname = names[(byte(data, 4) as usize) % names.len()];
    let qtype = qtypes[(byte(data, 5) as usize) % qtypes.len()];
    let qclass = if byte(data, 8) & 0x80 == 0 {
        QCLASS_IN
    } else {
        get_u16(data, 9)
    };

    let mut packet = Vec::new();
    packet.extend_from_slice(&(QID ^ get_u16(data, 11)).to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    let include_opt = byte(data, 13) & 1 != 0;
    packet.extend_from_slice(&(include_opt as u16).to_be_bytes());
    packet.extend_from_slice(&name_wire(qname));
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());

    if include_opt {
        append_opt(&mut packet, data);
    }

    packet
}

fn append_opt(packet: &mut Vec<u8>, data: &[u8]) {
    packet.push(0);
    packet.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
    let payload = 512 + (get_u16(data, 14) % 1232);
    packet.extend_from_slice(&payload.to_be_bytes());
    let ttl = if byte(data, 16) & 0x80 == 0 {
        0x8000u32
    } else {
        ((byte(data, 17) as u32) << 16) | get_u16(data, 18) as u32
    };
    packet.extend_from_slice(&ttl.to_be_bytes());

    let option_len = byte(data, 20).min(32) as usize;
    let mut rdata = Vec::new();
    if option_len > 0 {
        rdata.extend_from_slice(&get_u16(data, 21).to_be_bytes());
        rdata.extend_from_slice(&(option_len as u16).to_be_bytes());
        for index in 0..option_len {
            rdata.push(byte(data, 23 + index));
        }
    }
    packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    packet.extend_from_slice(&rdata);
}

fn soa_rdata(serial: u32) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&name_wire("ns1.zoneimage.test."));
    rdata.extend_from_slice(&name_wire("hostmaster.zoneimage.test."));
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&3600u32.to_be_bytes());
    rdata.extend_from_slice(&600u32.to_be_bytes());
    rdata.extend_from_slice(&86400u32.to_be_bytes());
    rdata.extend_from_slice(&300u32.to_be_bytes());
    rdata
}

fn mx_rdata(preference: u16, exchange: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&preference.to_be_bytes());
    rdata.extend_from_slice(&name_wire(exchange));
    rdata
}

fn txt_rdata(text: &[u8]) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.push(text.len().min(255) as u8);
    rdata.extend_from_slice(&text[..text.len().min(255)]);
    rdata
}

fn name(value: &str) -> DomainName {
    DomainName::from_absolute_str(value).expect("static name is valid")
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
