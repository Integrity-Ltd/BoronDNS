// Test-only wire oracle. Keep this separate from production RDATA identity and
// lookup code so a serving bug cannot redefine the expected response semantics.
// Ignore transaction IDs and legal RR ordering, but not duplicate multiplicity.
// Alias dependency order and presentation-case preservation need explicit tests.
#[derive(Debug, PartialEq, Eq)]
struct SemanticResponse {
    flags: u16,
    questions: Vec<(Vec<u8>, u16, u16)>,
    sections: [Vec<SemanticRecord>; 3],
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SemanticRecord {
    owner: Vec<u8>,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

// RDLENGTH bounds consumption at the name's location, not pointer destinations.
struct SemanticCursor<'a> {
    packet: &'a [u8],
    offset: usize,
    end: usize,
}

impl<'a> SemanticCursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        let end = self.offset.checked_add(len).ok_or("length overflow")?;
        if end > self.end {
            return Err("truncated field");
        }
        let bytes = self
            .packet
            .get(self.offset..end)
            .ok_or("truncated packet")?;
        self.offset = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn name(&mut self) -> Result<Vec<u8>, &'static str> {
        let (name, consumed) =
            DomainName::parse(self.packet, self.offset).map_err(|_| "invalid domain name")?;
        self.take(consumed)?;
        Ok(name.to_ascii_lowercased().to_wire())
    }

    fn rest(&mut self) -> Result<&'a [u8], &'static str> {
        self.take(self.end - self.offset)
    }
}

fn semantic_response(packet: &[u8]) -> Result<SemanticResponse, &'static str> {
    let header = Header::parse(packet).map_err(|_| "invalid header")?;
    let mut cursor = SemanticCursor {
        packet,
        offset: DNS_HEADER_LEN,
        end: packet.len(),
    };
    let mut questions = Vec::new();
    for _ in 0..header.qdcount {
        questions.push((cursor.name()?, cursor.u16()?, cursor.u16()?));
    }
    let mut sections = [Vec::new(), Vec::new(), Vec::new()];
    for (section, count) in
        sections
            .iter_mut()
            .zip([header.ancount, header.nscount, header.arcount])
    {
        for _ in 0..count {
            let owner = cursor.name()?;
            let rr_type = cursor.u16()?;
            let class = cursor.u16()?;
            // For OPT this includes extended RCODE, version and all EDNS flags.
            let ttl = u32::from_be_bytes(cursor.take(4)?.try_into().unwrap());
            let len = usize::from(cursor.u16()?);
            let start = cursor.offset;
            cursor.take(len)?;
            let rdata = semantic_rdata(
                rr_type,
                SemanticCursor {
                    packet,
                    offset: start,
                    end: cursor.offset,
                },
            )?;
            section.push(SemanticRecord {
                owner,
                rr_type,
                class,
                ttl,
                rdata,
            });
        }
        section.sort();
    }
    if cursor.offset != packet.len() {
        return Err("trailing message bytes");
    }
    Ok(SemanticResponse {
        flags: header.flags,
        questions,
        sections,
    })
}

fn semantic_rdata(rr_type: u16, mut cursor: SemanticCursor<'_>) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    match rr_type {
        1 => out.extend(cursor.take(4)?),
        28 => out.extend(cursor.take(16)?),
        // NS, obsolete mail names, CNAME, PTR, DNAME.
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 39 => out.extend(cursor.name()?),
        14 | 17 | 58 => {
            out.extend(cursor.name()?);
            out.extend(cursor.name()?);
        }
        6 => {
            out.extend(cursor.name()?);
            out.extend(cursor.name()?);
            out.extend(cursor.take(20)?);
        }
        15 | 18 | 21 | 36 | 107 => {
            out.extend(cursor.take(2)?);
            out.extend(cursor.name()?);
        }
        26 => {
            out.extend(cursor.take(2)?);
            out.extend(cursor.name()?);
            out.extend(cursor.name()?);
        }
        // Signature bytes and type bitmaps are opaque: never case-fold them.
        24 | 46 => {
            out.extend(cursor.take(18)?);
            out.extend(cursor.name()?);
            out.extend(cursor.rest()?);
        }
        30 | 47 => {
            out.extend(cursor.name()?);
            out.extend(cursor.rest()?);
        }
        33 => {
            out.extend(cursor.take(6)?);
            out.extend(cursor.name()?);
        }
        35 => {
            out.extend(cursor.take(4)?);
            for _ in 0..3 {
                let len = cursor.take(1)?[0];
                out.push(len);
                out.extend(cursor.take(usize::from(len))?);
            }
            out.extend(cursor.name()?);
        }
        64 | 65 => {
            out.extend(cursor.take(2)?);
            out.extend(cursor.name()?);
            out.extend(cursor.rest()?);
        }
        16 => {
            while cursor.offset < cursor.end {
                let len = cursor.take(1)?[0];
                out.push(len);
                out.extend(cursor.take(usize::from(len))?);
            }
        }
        41 => {
            while cursor.offset < cursor.end {
                out.extend(cursor.take(2)?);
                let len = cursor.u16()?;
                out.extend(len.to_be_bytes());
                out.extend(cursor.take(usize::from(len))?);
            }
        }
        // Includes NSEC3, DNSKEY, DS and unknown RFC 3597 data. Their bytes
        // are significant in full, regardless of ASCII case or pointer values.
        _ => out.extend(cursor.rest()?),
    }
    if cursor.offset != cursor.end {
        return Err("trailing RDATA bytes");
    }
    Ok(out)
}

// Tests for the test oracle itself. Mutation cases must be rejected even when
// the two messages have the same section counts, owner names and record types.
fn semantic_fixture(rr_type: u16, rdata: Vec<u8>) -> Vec<u8> {
    let mut packet = query(&cname_rdata("example.test."), RecordType::A as u16, 1);
    packet[2..4].copy_from_slice(&0x8500u16.to_be_bytes());
    append_answer(&mut packet, "example.test.", rr_type, 1, rdata);
    packet
}

fn assert_semantic_difference(left: &[u8], right: &[u8], field: &str) {
    assert!(
        std::panic::catch_unwind(|| assert_semantic_response_eq(left, right)).is_err(),
        "semantic comparison ignored {field}"
    );
}

#[test]
fn semantic_comparator_rejects_header_question_and_record_mutations() {
    let baseline = semantic_fixture(RecordType::A as u16, vec![192, 0, 2, 1]);
    let name_len = cname_rdata("example.test.").len();
    let record_fields = DNS_HEADER_LEN + name_len + 4 + name_len;
    let mut missed = Vec::new();
    for (field, offset, mask) in [
        ("QR", 2, 0x80),
        ("OPCODE", 2, 0x08),
        ("AA", 2, 0x04),
        ("TC", 2, 0x02),
        ("RD", 2, 0x01),
        ("RA", 3, 0x80),
        ("AD", 3, 0x20),
        ("CD", 3, 0x10),
        ("RCODE", 3, 1),
        ("QNAME", 13, 1),
        ("QTYPE", DNS_HEADER_LEN + name_len + 1, 1),
        ("QCLASS", DNS_HEADER_LEN + name_len + 3, 1),
        ("CLASS", record_fields + 3, 1),
        ("TTL", record_fields + 7, 1),
        ("RDATA", record_fields + 13, 1),
    ] {
        let mut changed = baseline.clone();
        changed[offset] ^= mask;
        if std::panic::catch_unwind(|| assert_semantic_response_eq(&baseline, &changed)).is_ok() {
            missed.push(field);
        }
    }
    assert!(missed.is_empty(), "comparator ignored: {missed:?}");
}

#[test]
fn semantic_comparator_rejects_material_rdata_and_edns_changes() {
    for (rr_type, rdata) in [
        (RecordType::A as u16, vec![192, 0, 2, 1]),
        (RecordType::Aaaa as u16, vec![0; 16]),
        (RecordType::Cname as u16, cname_rdata("target.test.")),
        (RecordType::Dname as u16, cname_rdata("target.test.")),
        (RecordType::Soa as u16, soa_rdata()),
        (RecordType::Rrsig as u16, rrsig_rdata(RecordType::A)),
        (RecordType::Nsec as u16, nsec_rdata("next.test.")),
        (RecordType::Nsec3 as u16, nsec3_rdata(1)),
        (RecordType::Txt as u16, b"\x04DATA".to_vec()),
        (65280, b"OPAQUE".to_vec()),
    ] {
        let baseline = semantic_fixture(rr_type, rdata);
        let mut changed = baseline.clone();
        // Change a label byte for name-only RDATA, an opaque/timer byte otherwise.
        let index = if [5, 39].contains(&rr_type) {
            changed.len() - 3
        } else {
            changed.len() - 1
        };
        changed[index] ^= 1;
        assert_semantic_difference(&baseline, &changed, &format!("RDATA type {rr_type}"));
    }
    let mut baseline = semantic_fixture(1, vec![192, 0, 2, 1]);
    let opt_start = baseline.len();
    append_opt(&mut baseline, 1232, 0x8000, &edns_option(65001, b"DATA"));
    for (field, offset, mask) in [
        ("EDNS payload", opt_start + 4, 1),
        ("extended RCODE", opt_start + 5, 1),
        ("EDNS version", opt_start + 6, 1),
        ("DO", opt_start + 7, 0x80),
        ("EDNS option code", opt_start + 12, 1),
        ("EDNS option data", baseline.len() - 1, 0x20),
    ] {
        let mut changed = baseline.clone();
        changed[offset] ^= mask;
        assert_semantic_difference(&baseline, &changed, field);
    }
}

#[test]
fn semantic_comparator_accepts_compression_name_case_and_rr_order() {
    let mut plain = semantic_fixture(5, cname_rdata("example.test."));
    append_answer(&mut plain, "example.test.", 1, 1, vec![192, 0, 2, 1]);
    let mut compressed = query(&cname_rdata("EXAMPLE.TEST."), 1, 1);
    compressed[2..4].copy_from_slice(&0x8500u16.to_be_bytes());
    append_answer(&mut compressed, "EXAMPLE.TEST.", 1, 1, vec![192, 0, 2, 1]);
    append_answer(&mut compressed, "EXAMPLE.TEST.", 5, 1, vec![0xc0, 0x0c]);
    assert_semantic_response_eq(&plain, &compressed);
}

#[test]
fn semantic_comparator_preserves_multiplicity_and_section_membership() {
    let mut left = semantic_fixture(1, vec![192, 0, 2, 1]);
    append_answer(&mut left, "example.test.", 1, 1, vec![192, 0, 2, 1]);
    let mut right = semantic_fixture(1, vec![192, 0, 2, 1]);
    append_answer(&mut right, "example.test.", 1, 1, vec![192, 0, 2, 2]);
    assert_semantic_difference(&left, &right, "duplicate replaced by distinct record");
    right = left.clone();
    right[6..8].copy_from_slice(&1u16.to_be_bytes());
    right[8..10].copy_from_slice(&1u16.to_be_bytes());
    assert_semantic_difference(&left, &right, "section membership");
}

#[test]
fn semantic_comparator_normalizes_only_name_fields_in_rdata() {
    let lower = cname_rdata("example.test.");
    let upper = cname_rdata("EXAMPLE.TEST.");
    for (rr_type, prefix, suffix) in [
        (2, vec![], vec![]),
        (5, vec![], vec![]),
        (12, vec![], vec![]),
        (39, vec![], vec![]),
        (15, vec![0, 10], vec![]),
        (33, vec![0, 1, 0, 2, 0, 53], vec![]),
        (
            46,
            rrsig_rdata(RecordType::A)[..18].to_vec(),
            b"SIGNATURE".to_vec(),
        ),
        (47, vec![], vec![0, 1, 0x40]),
        (64, vec![0, 1], vec![0, 3, 0, 2, 0, 53]),
    ] {
        let left = semantic_fixture(rr_type, [prefix.as_slice(), &lower, &suffix].concat());
        let right = semantic_fixture(rr_type, [prefix.as_slice(), &upper, &suffix].concat());
        assert_semantic_response_eq(&left, &right);
        if !suffix.is_empty() {
            let mut changed = right;
            *changed.last_mut().unwrap() ^= 0x20;
            assert_semantic_difference(&left, &changed, "opaque RDATA suffix case");
        }
    }
    let mut left_soa = [lower.as_slice(), lower.as_slice()].concat();
    left_soa.extend([0; 20]);
    let mut right_soa = [upper.as_slice(), upper.as_slice()].concat();
    right_soa.extend([0; 20]);
    assert_semantic_response_eq(
        &semantic_fixture(6, left_soa),
        &semantic_fixture(6, right_soa),
    );
    for rr_type in [16, 65280] {
        assert_semantic_difference(
            &semantic_fixture(rr_type, b"\x04DATA".to_vec()),
            &semantic_fixture(rr_type, b"\x04data".to_vec()),
            "opaque RDATA ASCII case",
        );
    }
}

#[test]
fn semantic_comparator_rejects_malformed_even_when_identical() {
    let baseline = semantic_fixture(5, cname_rdata("target.test."));
    let mut trailing = baseline.clone();
    trailing.push(0);
    let mut truncated = baseline.clone();
    truncated.pop();
    let mut looped = semantic_fixture(5, vec![0xc0, 0x0c]);
    looped[12..14].copy_from_slice(&[0xc0, 0x0c]);
    let bad_edns = {
        let mut packet = baseline;
        append_opt(&mut packet, 1232, 0, &[0, 1, 0, 10, 0]);
        packet
    };
    for packet in [trailing, truncated, looped, bad_edns] {
        assert_semantic_difference(&packet, &packet, "malformed message");
    }
}
