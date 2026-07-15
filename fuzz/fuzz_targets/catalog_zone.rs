#![no_main]

use std::hint::black_box;

use borondns_core::{
    catalog::parse_catalog_members,
    dns::{DomainName, RecordType},
    zone::{Rrset, ZoneSnapshot},
};
use libfuzzer_sys::fuzz_target;

const QCLASS_IN: u16 = 1;

fuzz_target!(|data: &[u8]| {
    let catalog_origin =
        DomainName::from_absolute_str("catalog-fuzz.test.").expect("static catalog origin");
    let snapshot = catalog_snapshot(catalog_origin, data);
    let result = parse_catalog_members(snapshot.catalog_zone_view());

    if let Ok(members) = result {
        black_box(members.len());
        for member in members.iter().take(8) {
            black_box((&member.member_node, &member.zone, &member.transfer));
        }
    }
});

fn catalog_snapshot(catalog_origin: DomainName, data: &[u8]) -> ZoneSnapshot {
    let mut rrsets = Vec::new();
    let version_rdata = match byte(data, 0) & 0x07 {
        0 => txt_rdata("2"),
        1 => txt_rdata("1"),
        2 => txt_rdata("2;ignored=true"),
        3 => Vec::new(),
        4 => vec![2, b'2', 1, b'x'],
        _ => take_vec(data, 1, (byte(data, 2) as usize).min(48)),
    };
    rrsets.push(Rrset::new(
        name(&format!("version.{catalog_origin}")),
        RecordType::Txt as u16,
        QCLASS_IN,
        0,
        vec![version_rdata],
    ));

    let member_count = 1 + (byte(data, 3) % 6) as usize;
    let mut offset = 4usize;
    for index in 0..member_count {
        let member_node = name(&format!("m{index}.zones.{catalog_origin}"));
        let member_zone = member_zone_wire(index, data, &mut offset);
        let ptr_rdatas = if byte(data, offset) & 0x10 != 0 {
            vec![
                member_zone.clone(),
                name_wire(&format!("duplicate{index}.example.")),
            ]
        } else if byte(data, offset) & 0x20 != 0 {
            Vec::new()
        } else {
            vec![member_zone]
        };
        rrsets.push(Rrset::new(
            member_node.clone(),
            RecordType::Ptr as u16,
            QCLASS_IN,
            0,
            ptr_rdatas,
        ));

        if byte(data, offset + 1) & 1 != 0 {
            rrsets.push(Rrset::new(
                name(&format!("primaries.ext.{member_node}")),
                RecordType::A as u16,
                QCLASS_IN,
                0,
                vec![ipv4_rdata(data, offset + 2)],
            ));
        }
        if byte(data, offset + 3) & 1 != 0 {
            rrsets.push(Rrset::new(
                name(&format!("primaries.ext.{member_node}")),
                RecordType::Aaaa as u16,
                QCLASS_IN,
                0,
                vec![ipv6_rdata(data, offset + 4)],
            ));
        }
        if byte(data, offset + 5) & 1 != 0 {
            rrsets.push(Rrset::new(
                name(&format!("primaries.ext.{member_node}")),
                RecordType::Txt as u16,
                QCLASS_IN,
                0,
                vec![txt_rdata(tsig_name(data, offset + 6))],
            ));
        }
        if byte(data, offset + 7) & 1 != 0 {
            let first = xfr_text(data, offset + 8);
            let mut policies = vec![txt_rdata(first)];
            if byte(data, offset + 7) & 2 != 0 {
                let second = if byte(data, offset + 7) & 4 != 0 {
                    first
                } else {
                    xfr_text(data, offset + 9)
                };
                policies.push(txt_rdata(second));
            }
            rrsets.push(Rrset::new(
                name(&format!("_udns-xfr.{member_node}")),
                RecordType::Txt as u16,
                QCLASS_IN,
                0,
                policies,
            ));
        }
        if byte(data, offset + 9) & 1 != 0 {
            rrsets.push(Rrset::new(
                name(&format!("_udns-notify.{member_node}")),
                RecordType::Txt as u16,
                QCLASS_IN,
                0,
                vec![txt_rdata(notify_text(data, offset + 10))],
            ));
        }
        if byte(data, offset + 11) & 1 != 0 {
            rrsets.push(Rrset::new(
                name(&format!("noise.ext.{member_node}")),
                get_u16(data, offset + 12),
                QCLASS_IN,
                0,
                vec![take_vec(
                    data,
                    offset + 14,
                    (byte(data, offset + 15) as usize).min(64),
                )],
            ));
        }
        offset = offset.saturating_add(16);
    }

    if byte(data, 1) & 0x80 != 0 {
        rrsets.push(Rrset::new(
            name(&format!("dup.zones.{catalog_origin}")),
            RecordType::Ptr as u16,
            QCLASS_IN,
            0,
            vec![name_wire("member0.example.")],
        ));
    }

    ZoneSnapshot::active(catalog_origin, Some(get_u32(data, 20)), rrsets)
}

fn member_zone_wire(index: usize, data: &[u8], offset: &mut usize) -> Vec<u8> {
    match byte(data, *offset) & 0x07 {
        0 => name_wire(&format!("member{index}.example.")),
        1 => name_wire("member0.example."),
        2 => vec![0xc0, 0x0c],
        3 => take_vec(
            data,
            offset.saturating_add(1),
            (byte(data, offset.saturating_add(2)) as usize).min(64),
        ),
        _ => {
            let label = byte(data, offset.saturating_add(3)) % 26 + b'a';
            name_wire(&format!("m{index}-{}.example.", label as char))
        }
    }
}

fn xfr_text(data: &[u8], offset: usize) -> &'static str {
    match byte(data, offset) % 12 {
        0 => "transport=tcp;port=53",
        1 => "transport=xot;port=853;server_name=primary.example",
        2 => "transport=udp;port=53",
        3 => "port=0",
        4 => "server_name=bad name",
        5 => "mode=ignored;transport=tcp;port=5300",
        6 => "unknown=value;transport=xot",
        7 => "transport=xot;transport=tcp",
        8 => "port=853;port=853",
        9 => "transport=xot;server_name=-primary.example",
        10 => "transport=xot;server_name=primary.example.",
        _ => "",
    }
}

fn notify_text(data: &[u8], offset: usize) -> &'static str {
    match byte(data, offset) % 6 {
        0 => "source=192.0.2.1",
        1 => "sources=192.0.2.1, 2001:db8::1",
        2 => "source=not-an-ip",
        3 => "sources=, 127.0.0.1, ::1",
        4 => "unknown=value",
        _ => "",
    }
}

fn tsig_name(data: &[u8], offset: usize) -> &'static str {
    match byte(data, offset) % 5 {
        0 => "transfer-key.example.",
        1 => "TRANSFER-Key.Example.",
        2 => "not-absolute",
        3 => "",
        _ => "other-key.example.",
    }
}

fn ipv4_rdata(data: &[u8], offset: usize) -> Vec<u8> {
    if byte(data, offset) & 0x40 != 0 {
        take_vec(data, offset, (byte(data, offset + 1) as usize).min(8))
    } else {
        vec![
            byte(data, offset),
            byte(data, offset + 1),
            byte(data, offset + 2),
            byte(data, offset + 3),
        ]
    }
}

fn ipv6_rdata(data: &[u8], offset: usize) -> Vec<u8> {
    if byte(data, offset) & 0x40 != 0 {
        take_vec(data, offset, (byte(data, offset + 1) as usize).min(24))
    } else {
        (0..16).map(|index| byte(data, offset + index)).collect()
    }
}

fn take_vec(data: &[u8], offset: usize, len: usize) -> Vec<u8> {
    let start = offset.min(data.len());
    let end = start.saturating_add(len).min(data.len());
    data[start..end].to_vec()
}

fn txt_rdata(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let len = bytes.len().min(255);
    let mut out = Vec::with_capacity(len + 1);
    out.push(len as u8);
    out.extend_from_slice(&bytes[..len]);
    out
}

fn name(value: &str) -> DomainName {
    DomainName::from_absolute_str(value).expect("generated owner name is valid")
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

fn get_u32(data: &[u8], index: usize) -> u32 {
    u32::from_be_bytes([
        byte(data, index),
        byte(data, index + 1),
        byte(data, index + 2),
        byte(data, index + 3),
    ])
}
