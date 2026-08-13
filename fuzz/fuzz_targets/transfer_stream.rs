#![no_main]

use borondns_core::{
    axfr::{IxfrResponse, parse_axfr_response, parse_ixfr_response},
    dns::{DomainName, RecordType},
    zone::{ResourceRecord, Rrset, ZoneSnapshot},
    zone_image::ZoneImage,
};
use libfuzzer_sys::fuzz_target;

const QID: u16 = 0x1234;
const QCLASS_IN: u16 = 1;
const DIFFERENTIAL_OWNER_COUNT: usize = 32;
const MAX_DIFFERENTIAL_GENERATIONS: usize = 64;

fuzz_target!(|data: &[u8]| {
    let apex = DomainName::from_absolute_str("alpha.test.").expect("static apex is valid");
    let current_zone = current_zone(&apex);
    let messages = split_tcp_messages(data);

    let _ = parse_axfr_response(QID, &apex, QCLASS_IN, &messages);
    let _ = parse_ixfr_response(QID, &apex, QCLASS_IN, &current_zone, &messages);

    exercise_valid_ixfr_generations(data);
});

fn exercise_valid_ixfr_generations(data: &[u8]) {
    let apex = DomainName::from_absolute_str("delta.test.").expect("static apex is valid");
    let owners = (0..DIFFERENTIAL_OWNER_COUNT)
        .map(|index| {
            DomainName::from_absolute_str(&format!("n{index}.delta.test."))
                .expect("generated owner is valid")
        })
        .collect::<Vec<_>>();
    let mut values = (0..DIFFERENTIAL_OWNER_COUNT)
        .map(|index| (index % 2 == 0).then_some([192, 0, 2, index as u8]))
        .collect::<Vec<_>>();
    let mut serial = 1u32;
    let mut snapshot = fresh_snapshot(&apex, &owners, &values, serial);

    for operation in data.chunks(3).take(MAX_DIFFERENTIAL_GENERATIONS) {
        let owner_index =
            usize::from(operation.first().copied().unwrap_or(0)) % DIFFERENTIAL_OWNER_COUNT;
        let old_value = values[owner_index];
        let opcode = operation.get(1).copied().unwrap_or(0) % 3;
        let payload = operation.get(2).copied().unwrap_or(0);
        let new_value = match opcode {
            0 => None,
            _ => Some([198, 51, opcode, payload]),
        };
        if old_value == new_value {
            continue;
        }

        let old_soa = record(
            apex.clone(),
            RecordType::Soa as u16,
            soa_rdata_for(&apex, serial),
        );
        serial = serial.wrapping_add(1);
        let new_soa = record(
            apex.clone(),
            RecordType::Soa as u16,
            soa_rdata_for(&apex, serial),
        );
        let owner = owners[owner_index].clone();
        let mut answers = vec![new_soa.clone(), old_soa];
        if let Some(value) = old_value {
            answers.push(record(owner.clone(), RecordType::A as u16, value.to_vec()));
        }
        answers.push(new_soa.clone());
        if let Some(value) = new_value {
            answers.push(record(owner, RecordType::A as u16, value.to_vec()));
        }
        answers.push(new_soa.clone());

        let response = parse_ixfr_response(
            QID,
            &apex,
            QCLASS_IN,
            &snapshot,
            &[ixfr_message(&apex, answers)],
        )
        .expect("constructed IXFR generation must be valid");
        let IxfrResponse::Updated(updated) = response else {
            panic!("constructed IXFR generation must advance the zone");
        };
        values[owner_index] = new_value;
        let fresh = fresh_snapshot(&apex, &owners, &values, serial);
        assert_eq!(
            *updated, fresh,
            "incremental snapshot diverged from rebuild"
        );
        assert_eq!(
            ZoneImage::compile(&updated).expect("incremental image compiles"),
            ZoneImage::compile(&fresh).expect("fresh image compiles"),
            "incremental image diverged from rebuild",
        );
        snapshot = *updated;
    }
}

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

fn fresh_snapshot(
    apex: &DomainName,
    owners: &[DomainName],
    values: &[Option<[u8; 4]>],
    serial: u32,
) -> ZoneSnapshot {
    let mut rrsets = vec![
        Rrset::new(
            apex.clone(),
            RecordType::Soa as u16,
            QCLASS_IN,
            3600,
            vec![soa_rdata_for(apex, serial)],
        ),
        Rrset::new(
            apex.clone(),
            RecordType::Ns as u16,
            QCLASS_IN,
            3600,
            vec![name_wire("ns.delta.test.")],
        ),
    ];
    rrsets.extend(owners.iter().zip(values).filter_map(|(owner, value)| {
        value.map(|value| {
            Rrset::new(
                owner.clone(),
                RecordType::A as u16,
                QCLASS_IN,
                300,
                vec![value.to_vec()],
            )
        })
    }));
    ZoneSnapshot::active(apex.clone(), Some(serial), rrsets)
}

fn record(owner: DomainName, rr_type: u16, rdata: Vec<u8>) -> ResourceRecord {
    ResourceRecord {
        owner,
        rr_type,
        class: QCLASS_IN,
        ttl: if rr_type == RecordType::Soa as u16 {
            3600
        } else {
            300
        },
        rdata,
    }
}

fn ixfr_message(apex: &DomainName, answers: Vec<ResourceRecord>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&QID.to_be_bytes());
    out.extend_from_slice(&0x8000u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&apex.to_wire());
    out.extend_from_slice(&(RecordType::Ixfr as u16).to_be_bytes());
    out.extend_from_slice(&QCLASS_IN.to_be_bytes());
    for answer in answers {
        out.extend_from_slice(&answer.owner.to_wire());
        out.extend_from_slice(&answer.rr_type.to_be_bytes());
        out.extend_from_slice(&answer.class.to_be_bytes());
        out.extend_from_slice(&answer.ttl.to_be_bytes());
        out.extend_from_slice(&(answer.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&answer.rdata);
    }
    out
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

fn soa_rdata_for(apex: &DomainName, serial: u32) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&name_wire("ns.delta.test."));
    let mut hostmaster = vec![10];
    hostmaster.extend_from_slice(b"hostmaster");
    hostmaster.extend_from_slice(&apex.to_wire());
    rdata.extend_from_slice(&hostmaster);
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
