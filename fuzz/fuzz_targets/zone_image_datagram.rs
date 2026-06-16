#![no_main]

use std::{hint::black_box, sync::OnceLock};

use libfuzzer_sys::fuzz_target;
use oxidedns_core::{
    dns::{
        AnswerOptions, DEFAULT_MAX_UDP_PAYLOAD, DatagramAction, DomainName, Header, RecordType,
        Transport, ZoneImageProvider,
        answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image,
        default_zone_image_provider,
    },
    zone::{Rrset, ZoneSnapshot, ZoneStore},
};

const QID: u16 = 0x5a11;
const QCLASS_IN: u16 = 1;

fuzz_target!(|data: &[u8]| {
    exercise_packet(data, data, &default_zone_image_provider);

    let packet = shaped_query_packet(data);
    if let Ok(header) = Header::parse(&packet) {
        black_box(header.qdcount);
    }
    exercise_packet(&packet, data, &default_zone_image_provider);
});

fn exercise_packet(packet: &[u8], data: &[u8], provider: ZoneImageProvider<'_>) {
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
                &name("*.wild.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 90]],
            ),
            rrset(
                &name("tree.zoneimage.test."),
                RecordType::Dname,
                vec![name_wire("target.zoneimage.test.")],
            ),
            rrset(
                &name("leaf.target.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 91]],
            ),
            rrset(
                &name("child.zoneimage.test."),
                RecordType::Ns,
                vec![name_wire("ns.child.zoneimage.test.")],
            ),
            rrset(
                &name("ns.child.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 92]],
            ),
            rrset(
                &name("_sip._udp.zoneimage.test."),
                RecordType::Srv,
                vec![srv_rdata(10, 20, 5060, "sip.zoneimage.test.")],
            ),
            rrset(
                &name("sip.zoneimage.test."),
                RecordType::A,
                vec![vec![192, 0, 2, 93]],
            ),
            rrset(
                &name("www.zoneimage.test."),
                RecordType::Rrsig,
                vec![rrsig_rdata(RecordType::A)],
            ),
            rrset(
                &apex,
                RecordType::Nsec,
                vec![nsec_rdata("www.zoneimage.test.")],
            ),
            rrset(
                &apex,
                RecordType::Rrsig,
                vec![rrsig_rdata(RecordType::Nsec)],
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

    let mut options =
        AnswerOptions::udp(512 + (get_u16(data, 2) % (DEFAULT_MAX_UDP_PAYLOAD - 511)));
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
        "host.wild.zoneimage.test.",
        "leaf.tree.zoneimage.test.",
        "child.zoneimage.test.",
        "www.child.zoneimage.test.",
        "_sip._udp.zoneimage.test.",
        "absent.zoneimage.test.",
        "*.zoneimage.test.",
    ];
    let qtypes = [
        RecordType::A as u16,
        RecordType::Aaaa as u16,
        RecordType::Ns as u16,
        RecordType::Cname as u16,
        RecordType::Dname as u16,
        RecordType::Soa as u16,
        RecordType::Mx as u16,
        RecordType::Srv as u16,
        RecordType::Txt as u16,
        RecordType::Ds as u16,
        RecordType::Nsec as u16,
        255,
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

fn srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&priority.to_be_bytes());
    rdata.extend_from_slice(&weight.to_be_bytes());
    rdata.extend_from_slice(&port.to_be_bytes());
    rdata.extend_from_slice(&name_wire(target));
    rdata
}

fn txt_rdata(text: &[u8]) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.push(text.len().min(255) as u8);
    rdata.extend_from_slice(&text[..text.len().min(255)]);
    rdata
}

fn rrsig_rdata(type_covered: RecordType) -> Vec<u8> {
    let mut rdata = (type_covered as u16).to_be_bytes().to_vec();
    rdata.extend_from_slice(&[8, 2]);
    rdata.extend_from_slice(&300u32.to_be_bytes());
    rdata.extend_from_slice(&1_700_086_400u32.to_be_bytes());
    rdata.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    rdata.extend_from_slice(&1u16.to_be_bytes());
    rdata.extend_from_slice(&name_wire("zoneimage.test."));
    rdata.extend_from_slice(b"signature");
    rdata
}

fn nsec_rdata(next_owner: &str) -> Vec<u8> {
    let mut rdata = name_wire(next_owner);
    rdata.extend_from_slice(&[0, 1, 0x40]);
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
