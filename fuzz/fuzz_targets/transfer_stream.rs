#![no_main]

use libfuzzer_sys::fuzz_target;
use borondns_core::{
    axfr::{parse_axfr_response, parse_ixfr_response},
    dns::{DomainName, RecordType},
    zone::{Rrset, ZoneSnapshot},
};

const QID: u16 = 0x1234;
const QCLASS_IN: u16 = 1;

fuzz_target!(|data: &[u8]| {
    let apex = DomainName::from_absolute_str("alpha.test.").expect("static apex is valid");
    let current_zone = current_zone(&apex);
    let messages = split_tcp_messages(data);

    let _ = parse_axfr_response(QID, &apex, QCLASS_IN, &messages);
    let _ = parse_ixfr_response(QID, &apex, QCLASS_IN, &current_zone, &messages);
});

fn split_tcp_messages(data: &[u8]) -> Vec<Vec<u8>> {
    let mut offset = 0;
    let mut messages = Vec::new();

    while offset + 2 <= data.len() && messages.len() < 32 {
        let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + len > data.len() {
            messages.push(data[offset..].to_vec());
            return messages;
        }
        messages.push(data[offset..offset + len].to_vec());
        offset += len;
    }

    if messages.is_empty() && !data.is_empty() {
        messages.push(data.to_vec());
    }

    messages
}

fn current_zone(apex: &DomainName) -> ZoneSnapshot {
    ZoneSnapshot::active(
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
        ],
    )
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
