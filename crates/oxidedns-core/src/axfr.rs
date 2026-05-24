use thiserror::Error;

use crate::{
    dns::{DNS_HEADER_LEN, DnsParseError, DomainName, Header, RecordType},
    zone::{ResourceRecord, Rrset, ZoneSnapshot},
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AxfrError {
    #[error("AXFR response stream is empty")]
    EmptyResponse,

    #[error("AXFR response message is malformed")]
    MalformedMessage,

    #[error("AXFR response QID does not match query QID")]
    MismatchedQid,

    #[error("AXFR response opcode is not QUERY")]
    MismatchedOpcode,

    #[error("AXFR response returned error RCODE {0}")]
    ErrorRcode(u8),

    #[error("AXFR response did not start with SOA at the zone apex")]
    MissingInitialSoa,

    #[error("AXFR response ended before the terminating SOA")]
    MissingTerminatingSoa,

    #[error("AXFR terminating SOA does not match initial SOA")]
    MismatchedTerminatingSoa,

    #[error("AXFR response contained an unexpected middle SOA")]
    MiddleSoa,

    #[error("AXFR response contained records after the terminating SOA")]
    TrailingRecords,

    #[error("AXFR response contained a record with an unexpected class")]
    ClassMismatch,

    #[error("AXFR response contained an out-of-zone owner name")]
    OutOfZoneOwner,

    #[error("AXFR response contained a reserved RR type")]
    ReservedType,

    #[error("AXFR response contained invalid RDATA for a known RR type")]
    InvalidRdata,

    #[error("AXFR response did not contain an apex NS RRset")]
    MissingApexNs,

    #[error("AXFR response contained a CNAME owner with non-DNSSEC data")]
    CnameCoexistsWithOtherData,

    #[error("AXFR response contained a DNAME owner with CNAME data")]
    DnameCoexistsWithCname,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SoaQueryError {
    #[error("SOA response message is malformed")]
    MalformedMessage,

    #[error("SOA response was not marked as a response")]
    NotResponse,

    #[error("SOA response QID does not match query QID")]
    MismatchedQid,

    #[error("SOA response opcode is not QUERY")]
    MismatchedOpcode,

    #[error("SOA response returned error RCODE {0}")]
    ErrorRcode(u8),

    #[error("SOA response question does not match the SOA poll query")]
    MismatchedQuestion,

    #[error("SOA response did not contain an SOA answer at the zone apex")]
    MissingSoa,

    #[error("SOA response contained an answer with an unexpected class")]
    ClassMismatch,

    #[error("SOA response contained an out-of-zone answer owner name")]
    OutOfZoneOwner,

    #[error("SOA response contained a reserved RR type")]
    ReservedType,

    #[error("SOA response contained invalid RDATA for a known RR type")]
    InvalidRdata,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IxfrError {
    #[error("IXFR query requires the currently held apex SOA")]
    InvalidCurrentSoa,

    #[error("IXFR response stream is empty")]
    EmptyResponse,

    #[error("IXFR response message is malformed")]
    MalformedMessage,

    #[error("IXFR response QID does not match query QID")]
    MismatchedQid,

    #[error("IXFR response opcode is not QUERY")]
    MismatchedOpcode,

    #[error("IXFR response returned error RCODE {0}")]
    ErrorRcode(u8),

    #[error("IXFR response did not start with SOA at the zone apex")]
    MissingInitialSoa,

    #[error("IXFR response ended before a complete mode could be determined")]
    IncompleteResponse,

    #[error("IXFR response difference sequence does not chain SOA serials correctly")]
    BrokenSoaChain,

    #[error("IXFR response tried to delete a record that is not present")]
    DeleteAbsentRecord,

    #[error("IXFR response tried to add a record that is already present")]
    AddExistingRecord,

    #[error("IXFR mode 2 AXFR fallback response validation failed: {0}")]
    Axfr(#[from] AxfrError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IxfrResponse {
    Updated(ZoneSnapshot),
    Current,
}

pub fn build_axfr_query(qid: u16, zone_apex: &DomainName, qclass: u16) -> Vec<u8> {
    build_query(qid, zone_apex, RecordType::Axfr as u16, qclass)
}

pub fn build_soa_query(qid: u16, zone_apex: &DomainName, qclass: u16) -> Vec<u8> {
    build_query(qid, zone_apex, RecordType::Soa as u16, qclass)
}

pub fn build_ixfr_query(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    current_soa: &ResourceRecord,
) -> Result<Vec<u8>, IxfrError> {
    validate_current_soa(current_soa, zone_apex, qclass)?;

    let mut message = Vec::new();
    message.extend_from_slice(&qid.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&zone_apex.to_wire());
    message.extend_from_slice(&(RecordType::Ixfr as u16).to_be_bytes());
    message.extend_from_slice(&qclass.to_be_bytes());
    append_record(&mut message, current_soa);
    Ok(message)
}

fn build_query(qid: u16, zone_apex: &DomainName, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&qid.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&zone_apex.to_wire());
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&qclass.to_be_bytes());
    message
}

fn append_record(message: &mut Vec<u8>, record: &ResourceRecord) {
    message.extend_from_slice(&record.owner.to_wire());
    message.extend_from_slice(&record.rr_type.to_be_bytes());
    message.extend_from_slice(&record.class.to_be_bytes());
    message.extend_from_slice(&record.ttl.to_be_bytes());
    message.extend_from_slice(&(record.rdata.len() as u16).to_be_bytes());
    message.extend_from_slice(&record.rdata);
}

pub fn frame_tcp_message(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&(message.len() as u16).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

pub fn parse_axfr_response(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    messages: &[Vec<u8>],
) -> Result<ZoneSnapshot, AxfrError> {
    if messages.is_empty() {
        return Err(AxfrError::EmptyResponse);
    }

    let mut initial_soa = None;
    let mut zone_serial = None;
    let mut zone_records = Vec::new();
    let mut complete = false;

    for message in messages {
        let header = Header::parse(message).map_err(|_| AxfrError::MalformedMessage)?;
        if header.id != qid {
            return Err(AxfrError::MismatchedQid);
        }
        if header.opcode_value() != 0 {
            return Err(AxfrError::MismatchedOpcode);
        }
        let rcode = (header.flags & 0x000f) as u8;
        if rcode != 0 {
            return Err(AxfrError::ErrorRcode(rcode));
        }

        let mut offset = skip_questions(message, header.qdcount)?;
        for _ in 0..header.ancount {
            if complete {
                return Err(AxfrError::TrailingRecords);
            }
            let (record, consumed) = parse_record(message, offset)?;
            offset += consumed;

            validate_record_scope(&record, zone_apex, qclass)?;

            if record.rr_type == RecordType::Soa as u16 {
                match &initial_soa {
                    None => {
                        if record.owner != *zone_apex {
                            return Err(AxfrError::MissingInitialSoa);
                        }
                        zone_serial = Some(soa_serial(&record.rdata)?);
                        initial_soa = Some(record.clone());
                        zone_records.push(record);
                    }
                    Some(initial) if record == *initial => {
                        complete = true;
                    }
                    Some(_) => return Err(AxfrError::MismatchedTerminatingSoa),
                }
            } else {
                if initial_soa.is_none() {
                    return Err(AxfrError::MissingInitialSoa);
                }
                zone_records.push(record);
            }
        }
    }

    if initial_soa.is_none() {
        return Err(AxfrError::MissingInitialSoa);
    }
    if !complete {
        return Err(AxfrError::MissingTerminatingSoa);
    }
    validate_zone_record_set(zone_apex, &zone_records)?;

    Ok(ZoneSnapshot::active(
        zone_apex.clone(),
        zone_serial,
        rrsets_from_records(zone_records),
    ))
}

pub fn parse_soa_response(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    message: &[u8],
) -> Result<u32, SoaQueryError> {
    let header = Header::parse(message).map_err(|_| SoaQueryError::MalformedMessage)?;
    if header.id != qid {
        return Err(SoaQueryError::MismatchedQid);
    }
    if !header.is_response() {
        return Err(SoaQueryError::NotResponse);
    }
    if header.opcode_value() != 0 {
        return Err(SoaQueryError::MismatchedOpcode);
    }
    let rcode = (header.flags & 0x000f) as u8;
    if rcode != 0 {
        return Err(SoaQueryError::ErrorRcode(rcode));
    }

    let mut offset = validate_soa_response_question(message, header.qdcount, zone_apex, qclass)?;
    for _ in 0..header.ancount {
        let (record, consumed) =
            parse_record(message, offset).map_err(|_| SoaQueryError::MalformedMessage)?;
        offset += consumed;

        validate_soa_answer_scope(&record, zone_apex, qclass)?;
        if record.owner == *zone_apex && record.rr_type == RecordType::Soa as u16 {
            return soa_serial(&record.rdata).map_err(|_| SoaQueryError::MalformedMessage);
        }
    }

    Err(SoaQueryError::MissingSoa)
}

pub fn parse_ixfr_response(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    current_zone: &ZoneSnapshot,
    messages: &[Vec<u8>],
) -> Result<IxfrResponse, IxfrError> {
    let current_soa = current_zone
        .soa_record(qclass)
        .ok_or(IxfrError::InvalidCurrentSoa)?;
    validate_current_soa(&current_soa, zone_apex, qclass)?;
    if messages.is_empty() {
        return Err(IxfrError::EmptyResponse);
    }

    let mut answers = Vec::new();
    for message in messages {
        let header = Header::parse(message).map_err(|_| IxfrError::MalformedMessage)?;
        if header.id != qid {
            return Err(IxfrError::MismatchedQid);
        }
        if header.opcode_value() != 0 {
            return Err(IxfrError::MismatchedOpcode);
        }
        let rcode = (header.flags & 0x000f) as u8;
        if rcode != 0 {
            return Err(IxfrError::ErrorRcode(rcode));
        }

        let mut offset =
            skip_questions(message, header.qdcount).map_err(|_| IxfrError::MalformedMessage)?;
        for _ in 0..header.ancount {
            let (record, consumed) =
                parse_record(message, offset).map_err(|_| IxfrError::MalformedMessage)?;
            offset += consumed;
            validate_record_scope(&record, zone_apex, qclass).map_err(ixfr_scope_error)?;
            answers.push(record);
        }
    }

    let Some(first) = answers.first() else {
        return Err(IxfrError::MissingInitialSoa);
    };
    if first.owner != *zone_apex || first.rr_type != RecordType::Soa as u16 {
        return Err(IxfrError::MissingInitialSoa);
    }

    if answers.len() == 1 {
        let response_serial = soa_serial(&first.rdata).map_err(|_| IxfrError::MalformedMessage)?;
        let current_serial =
            soa_serial(&current_soa.rdata).map_err(|_| IxfrError::InvalidCurrentSoa)?;
        if response_serial == current_serial {
            return Ok(IxfrResponse::Current);
        }
        return Err(IxfrError::IncompleteResponse);
    }

    if answers[1].rr_type == RecordType::Soa as u16 {
        return apply_ixfr_incremental(zone_apex, qclass, current_zone, &answers);
    }

    parse_axfr_response(qid, zone_apex, qclass, messages)
        .map(IxfrResponse::Updated)
        .map_err(IxfrError::Axfr)
}

fn apply_ixfr_incremental(
    zone_apex: &DomainName,
    qclass: u16,
    current_zone: &ZoneSnapshot,
    answers: &[ResourceRecord],
) -> Result<IxfrResponse, IxfrError> {
    let outer_soa = answers.first().ok_or(IxfrError::MissingInitialSoa)?;
    let final_serial = soa_serial(&outer_soa.rdata).map_err(|_| IxfrError::MalformedMessage)?;
    let current_soa = current_zone
        .soa_record(qclass)
        .ok_or(IxfrError::InvalidCurrentSoa)?;
    let mut expected_old_soa = current_soa;
    let mut records = current_zone.records();
    let mut index = 1usize;

    while index < answers.len() {
        let old_soa = &answers[index];
        if old_soa.rr_type != RecordType::Soa as u16 || old_soa != &expected_old_soa {
            return Err(IxfrError::BrokenSoaChain);
        }
        remove_record(&mut records, old_soa)?;
        index += 1;

        while index < answers.len() && answers[index].rr_type != RecordType::Soa as u16 {
            remove_record(&mut records, &answers[index])?;
            index += 1;
        }

        let Some(new_soa) = answers.get(index) else {
            return Err(IxfrError::IncompleteResponse);
        };
        if new_soa.rr_type != RecordType::Soa as u16 || new_soa.owner != *zone_apex {
            return Err(IxfrError::BrokenSoaChain);
        }
        add_record(&mut records, new_soa.clone())?;
        expected_old_soa = new_soa.clone();
        index += 1;

        while index < answers.len() && answers[index].rr_type != RecordType::Soa as u16 {
            add_record(&mut records, answers[index].clone())?;
            index += 1;
        }
    }

    let final_applied_serial =
        soa_serial(&expected_old_soa.rdata).map_err(|_| IxfrError::MalformedMessage)?;
    if expected_old_soa != *outer_soa || final_applied_serial != final_serial {
        return Err(IxfrError::BrokenSoaChain);
    }
    validate_zone_record_set(zone_apex, &records).map_err(IxfrError::Axfr)?;

    Ok(IxfrResponse::Updated(ZoneSnapshot::active(
        zone_apex.clone(),
        Some(final_serial),
        rrsets_from_records(records),
    )))
}

fn remove_record(
    records: &mut Vec<ResourceRecord>,
    target: &ResourceRecord,
) -> Result<(), IxfrError> {
    let Some(index) = records.iter().position(|record| record == target) else {
        return Err(IxfrError::DeleteAbsentRecord);
    };
    records.remove(index);
    Ok(())
}

fn add_record(records: &mut Vec<ResourceRecord>, record: ResourceRecord) -> Result<(), IxfrError> {
    if records.contains(&record) {
        return Err(IxfrError::AddExistingRecord);
    }
    records.push(record);
    Ok(())
}

fn ixfr_scope_error(error: AxfrError) -> IxfrError {
    match error {
        AxfrError::MalformedMessage => IxfrError::MalformedMessage,
        AxfrError::ErrorRcode(rcode) => IxfrError::ErrorRcode(rcode),
        AxfrError::MissingInitialSoa => IxfrError::MissingInitialSoa,
        other => IxfrError::Axfr(other),
    }
}

fn validate_current_soa(
    record: &ResourceRecord,
    zone_apex: &DomainName,
    qclass: u16,
) -> Result<(), IxfrError> {
    if record.owner != *zone_apex
        || record.rr_type != RecordType::Soa as u16
        || record.class != qclass
    {
        return Err(IxfrError::InvalidCurrentSoa);
    }
    soa_serial(&record.rdata).map_err(|_| IxfrError::InvalidCurrentSoa)?;
    Ok(())
}

fn validate_soa_response_question(
    message: &[u8],
    qdcount: u16,
    zone_apex: &DomainName,
    qclass: u16,
) -> Result<usize, SoaQueryError> {
    if qdcount != 1 {
        return Err(SoaQueryError::MismatchedQuestion);
    }

    let (qname, consumed) =
        DomainName::parse(message, DNS_HEADER_LEN).map_err(|_| SoaQueryError::MalformedMessage)?;
    let offset = DNS_HEADER_LEN + consumed;
    if offset + 4 > message.len() {
        return Err(SoaQueryError::MalformedMessage);
    }

    let qtype = u16::from_be_bytes([message[offset], message[offset + 1]]);
    let response_qclass = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
    if qname != *zone_apex || qtype != RecordType::Soa as u16 || response_qclass != qclass {
        return Err(SoaQueryError::MismatchedQuestion);
    }

    Ok(offset + 4)
}

fn soa_serial(rdata: &[u8]) -> Result<u32, AxfrError> {
    let (_, consumed_mname) = DomainName::parse(rdata, 0)?;
    let rname_offset = consumed_mname;
    let (_, consumed_rname) = DomainName::parse(rdata, rname_offset)?;
    let serial_offset = rname_offset + consumed_rname;
    if serial_offset + 20 != rdata.len() {
        return Err(AxfrError::MalformedMessage);
    }

    Ok(u32::from_be_bytes([
        rdata[serial_offset],
        rdata[serial_offset + 1],
        rdata[serial_offset + 2],
        rdata[serial_offset + 3],
    ]))
}

fn skip_questions(message: &[u8], qdcount: u16) -> Result<usize, AxfrError> {
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..qdcount {
        let (_, consumed) =
            DomainName::parse(message, offset).map_err(|_| AxfrError::MalformedMessage)?;
        offset += consumed;
        if offset + 4 > message.len() {
            return Err(AxfrError::MalformedMessage);
        }
        offset += 4;
    }
    Ok(offset)
}

fn parse_record(message: &[u8], offset: usize) -> Result<(ResourceRecord, usize), DnsParseError> {
    let start = offset;
    let (owner, consumed) = DomainName::parse(message, offset)?;
    let mut offset = offset + consumed;
    if offset + 10 > message.len() {
        return Err(DnsParseError::FormErr);
    }

    let rr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
    let class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
    let ttl = u32::from_be_bytes([
        message[offset + 4],
        message[offset + 5],
        message[offset + 6],
        message[offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
    offset += 10;
    if offset + rdlength > message.len() {
        return Err(DnsParseError::FormErr);
    }

    let rdata = message[offset..offset + rdlength].to_vec();
    offset += rdlength;

    Ok((
        ResourceRecord {
            owner,
            rr_type,
            class,
            ttl,
            rdata,
        },
        offset - start,
    ))
}

fn validate_record_scope(
    record: &ResourceRecord,
    zone_apex: &DomainName,
    qclass: u16,
) -> Result<(), AxfrError> {
    if record.class != qclass {
        return Err(AxfrError::ClassMismatch);
    }
    if record.rr_type == 0 || record.rr_type == u16::MAX {
        return Err(AxfrError::ReservedType);
    }
    validate_known_rdata(record)?;
    if !record.owner.is_equal_or_subdomain_of(zone_apex) {
        return Err(AxfrError::OutOfZoneOwner);
    }
    Ok(())
}

fn validate_soa_answer_scope(
    record: &ResourceRecord,
    zone_apex: &DomainName,
    qclass: u16,
) -> Result<(), SoaQueryError> {
    if record.class != qclass {
        return Err(SoaQueryError::ClassMismatch);
    }
    if record.rr_type == 0 || record.rr_type == u16::MAX {
        return Err(SoaQueryError::ReservedType);
    }
    validate_known_rdata(record).map_err(|_| SoaQueryError::InvalidRdata)?;
    if !record.owner.is_equal_or_subdomain_of(zone_apex) {
        return Err(SoaQueryError::OutOfZoneOwner);
    }
    Ok(())
}

fn validate_known_rdata(record: &ResourceRecord) -> Result<(), AxfrError> {
    match record.rr_type {
        rr_type if rr_type == RecordType::A as u16 => validate_fixed_rdata(record, 4),
        rr_type if rr_type == RecordType::Aaaa as u16 => validate_fixed_rdata(record, 16),
        rr_type if rr_type == RecordType::Dname as u16 => {
            validate_uncompressed_domain_name_rdata(&record.rdata)
        }
        _ => Ok(()),
    }
}

fn validate_fixed_rdata(record: &ResourceRecord, expected_len: usize) -> Result<(), AxfrError> {
    if record.rdata.len() == expected_len {
        Ok(())
    } else {
        Err(AxfrError::InvalidRdata)
    }
}

fn validate_uncompressed_domain_name_rdata(rdata: &[u8]) -> Result<(), AxfrError> {
    let mut pos = 0usize;
    let mut total_len = 1usize;

    loop {
        let Some(&len) = rdata.get(pos) else {
            return Err(AxfrError::InvalidRdata);
        };
        if len & 0xc0 != 0 {
            return Err(AxfrError::InvalidRdata);
        }
        pos += 1;

        if len == 0 {
            return if pos == rdata.len() {
                Ok(())
            } else {
                Err(AxfrError::InvalidRdata)
            };
        }

        let label_len = len as usize;
        if label_len > 63 || pos + label_len > rdata.len() {
            return Err(AxfrError::InvalidRdata);
        }

        total_len += 1 + label_len;
        if total_len > 255 {
            return Err(AxfrError::InvalidRdata);
        }

        pos += label_len;
    }
}

fn validate_zone_record_set(
    zone_apex: &DomainName,
    records: &[ResourceRecord],
) -> Result<(), AxfrError> {
    validate_apex_ns(zone_apex, records)?;
    validate_cname_and_dname_coexistence(records)?;
    Ok(())
}

fn validate_apex_ns(zone_apex: &DomainName, records: &[ResourceRecord]) -> Result<(), AxfrError> {
    if records
        .iter()
        .any(|record| record.owner == *zone_apex && record.rr_type == RecordType::Ns as u16)
    {
        Ok(())
    } else {
        Err(AxfrError::MissingApexNs)
    }
}

fn validate_cname_and_dname_coexistence(records: &[ResourceRecord]) -> Result<(), AxfrError> {
    for record in records {
        if record.rr_type == RecordType::Dname as u16
            && records.iter().any(|other| {
                other.owner == record.owner && other.rr_type == RecordType::Cname as u16
            })
        {
            return Err(AxfrError::DnameCoexistsWithCname);
        }
    }

    for record in records {
        if record.rr_type == RecordType::Cname as u16
            && records.iter().any(|other| {
                other.owner == record.owner
                    && other.rr_type != RecordType::Cname as u16
                    && !is_dnssec_cname_exception_type(other.rr_type)
            })
        {
            return Err(AxfrError::CnameCoexistsWithOtherData);
        }
    }

    Ok(())
}

fn is_dnssec_cname_exception_type(rr_type: u16) -> bool {
    rr_type == RecordType::Rrsig as u16
        || rr_type == RecordType::Nsec as u16
        || rr_type == RecordType::Nsec3 as u16
}

fn rrsets_from_records(records: Vec<ResourceRecord>) -> Vec<Rrset> {
    let mut rrsets = Vec::<RrsetAccumulator>::new();

    for record in records {
        if let Some(existing) = rrsets.iter_mut().find(|rrset| {
            rrset.owner == record.owner
                && rrset.rr_type == record.rr_type
                && rrset.class == record.class
        }) {
            existing.ttl = existing.ttl.min(record.ttl);
            existing.rdatas.push(record.rdata);
        } else {
            rrsets.push(RrsetAccumulator {
                owner: record.owner,
                rr_type: record.rr_type,
                class: record.class,
                ttl: record.ttl,
                rdatas: vec![record.rdata],
            });
        }
    }

    rrsets
        .into_iter()
        .map(|rrset| {
            Rrset::new(
                rrset.owner,
                rrset.rr_type,
                rrset.class,
                rrset.ttl,
                rrset.rdatas,
            )
        })
        .collect()
}

struct RrsetAccumulator {
    owner: DomainName,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdatas: Vec<Vec<u8>>,
}

impl From<DnsParseError> for AxfrError {
    fn from(_: DnsParseError) -> Self {
        Self::MalformedMessage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dns::RecordType,
        zone::{SoaTimers, ZoneSnapshot, ZoneState},
    };

    fn soa_rdata() -> Vec<u8> {
        soa_rdata_with_serial(1)
    }

    fn soa_rdata_with_serial(serial: u32) -> Vec<u8> {
        let mut rdata = b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec();
        let (_, consumed_mname) = DomainName::parse(&rdata, 0).unwrap();
        let (_, consumed_rname) = DomainName::parse(&rdata, consumed_mname).unwrap();
        let serial_offset = consumed_mname + consumed_rname;
        rdata[serial_offset..serial_offset + 4].copy_from_slice(&serial.to_be_bytes());
        rdata
    }

    fn message(qid: u16, answers: Vec<ResourceRecord>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&qid.to_be_bytes());
        out.extend_from_slice(&0x8000u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
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

    fn soa_message(qid: u16, answers: Vec<ResourceRecord>) -> Vec<u8> {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&qid.to_be_bytes());
        out.extend_from_slice(&0x8000u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&apex.to_wire());
        out.extend_from_slice(&(RecordType::Soa as u16).to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
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

    fn record(owner: &str, rr_type: u16, rdata: Vec<u8>) -> ResourceRecord {
        ResourceRecord {
            owner: DomainName::from_absolute_str(owner).unwrap(),
            rr_type,
            class: 1,
            ttl: 300,
            rdata,
        }
    }

    fn apex_ns() -> ResourceRecord {
        record(
            "example.test.",
            RecordType::Ns as u16,
            name_rdata("ns.example.test."),
        )
    }

    fn name_rdata(name: &str) -> Vec<u8> {
        DomainName::from_absolute_str(name).unwrap().to_wire()
    }

    fn current_zone(records: Vec<ResourceRecord>) -> ZoneSnapshot {
        ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            rrsets_from_records(records),
        )
    }

    #[test]
    fn builds_axfr_query_wire_message() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let query = build_axfr_query(0x1234, &apex, 1);
        assert_eq!(&query[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(&query[2..4], &0u16.to_be_bytes());
        assert_eq!(&query[4..6], &1u16.to_be_bytes());
        assert_eq!(&query[12..26], b"\x07example\x04test\x00");
        assert_eq!(&query[26..28], &(RecordType::Axfr as u16).to_be_bytes());
        assert_eq!(&query[28..30], &1u16.to_be_bytes());
    }

    #[test]
    fn builds_soa_query_wire_message() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let query = build_soa_query(0x1234, &apex, 1);
        assert_eq!(&query[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(&query[2..4], &0u16.to_be_bytes());
        assert_eq!(&query[4..6], &1u16.to_be_bytes());
        assert_eq!(&query[12..26], b"\x07example\x04test\x00");
        assert_eq!(&query[26..28], &(RecordType::Soa as u16).to_be_bytes());
        assert_eq!(&query[28..30], &1u16.to_be_bytes());
    }

    #[test]
    fn builds_ixfr_query_with_current_soa_in_authority() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let query = build_ixfr_query(0x1234, &apex, 1, &soa).expect("IXFR query");

        assert_eq!(&query[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(&query[2..4], &0u16.to_be_bytes());
        assert_eq!(&query[4..6], &1u16.to_be_bytes());
        assert_eq!(&query[8..10], &1u16.to_be_bytes());
        assert_eq!(&query[12..26], b"\x07example\x04test\x00");
        assert_eq!(&query[26..28], &(RecordType::Ixfr as u16).to_be_bytes());
        assert_eq!(&query[28..30], &1u16.to_be_bytes());
        assert_eq!(&query[30..44], b"\x07example\x04test\x00");
        assert_eq!(&query[44..46], &(RecordType::Soa as u16).to_be_bytes());
    }

    #[test]
    fn rejects_ixfr_query_without_current_apex_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let error = build_ixfr_query(0x1234, &apex, 1, &a).expect_err("invalid current SOA");

        assert_eq!(error, IxfrError::InvalidCurrentSoa);
    }

    #[test]
    fn frames_tcp_message_with_length_prefix() {
        let framed = frame_tcp_message(&[1, 2, 3]);
        assert_eq!(framed, vec![0, 3, 1, 2, 3]);
    }

    #[test]
    fn parses_valid_axfr_response_into_active_zone() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let ns = apex_ns();
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(0x1234, vec![soa.clone(), ns, a, soa])],
        )
        .expect("valid AXFR");

        assert_eq!(snapshot.state, crate::zone::ZoneState::Active);
        assert_eq!(snapshot.origin, apex);
        assert_eq!(snapshot.serial, Some(1));
        assert_eq!(
            snapshot.soa_timers,
            Some(SoaTimers {
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 300,
            })
        );
        assert!(
            snapshot
                .lookup(
                    &DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1
                )
                .answers
                .len()
                == 1
        );
    }

    #[test]
    fn parses_valid_soa_response_serial() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let serial =
            parse_soa_response(0x1234, &apex, 1, &soa_message(0x1234, vec![soa])).expect("SOA");

        assert_eq!(serial, 1);
    }

    #[test]
    fn parses_ixfr_mode2_axfr_fallback_into_active_zone() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa]);
        let new_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let ns = apex_ns();
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let response = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(0x1234, vec![new_soa.clone(), ns, a, new_soa])],
        )
        .expect("mode 2 fallback");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert_eq!(snapshot.state, ZoneState::Active);
        assert_eq!(snapshot.serial, Some(1));
    }

    #[test]
    fn parses_ixfr_mode3_current_response() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa.clone()]);
        let response = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(0x1234, vec![current_soa.clone()])],
        )
        .expect("mode 3 current");

        assert_eq!(response, IxfrResponse::Current);
    }

    #[test]
    fn rejects_ixfr_response_with_mismatched_qid() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa.clone()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(0x9999, vec![current_soa])],
        )
        .expect_err("mismatched IXFR qid");

        assert_eq!(error, IxfrError::MismatchedQid);
    }

    #[test]
    fn rejects_ixfr_response_with_mismatched_opcode() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa.clone()]);
        let mut response = message(0x1234, vec![current_soa]);
        response[2] = 0x88;

        let error = parse_ixfr_response(0x1234, &apex, 1, &current_zone, &[response])
            .expect_err("mismatched IXFR opcode");

        assert_eq!(error, IxfrError::MismatchedOpcode);
    }

    #[test]
    fn rejects_ixfr_response_with_error_rcode() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa.clone()]);
        let mut response = message(0x1234, vec![current_soa]);
        response[3] = 4;

        let error = parse_ixfr_response(0x1234, &apex, 1, &current_zone, &[response])
            .expect_err("IXFR error RCODE");

        assert_eq!(error, IxfrError::ErrorRcode(4));
    }

    #[test]
    fn rejects_ixfr_response_without_initial_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa]);
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );

        let error =
            parse_ixfr_response(0x1234, &apex, 1, &current_zone, &[message(0x1234, vec![a])])
                .expect_err("missing IXFR initial SOA");

        assert_eq!(error, IxfrError::MissingInitialSoa);
    }

    #[test]
    fn rejects_ixfr_single_newer_soa_as_incomplete() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa]);
        let newer_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );

        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(0x1234, vec![newer_soa])],
        )
        .expect_err("incomplete newer IXFR response");

        assert_eq!(error, IxfrError::IncompleteResponse);
    }

    #[test]
    fn parses_ixfr_mode1_incremental_diff_into_active_zone() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let old_a = record(
            "old.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let new_a = record(
            "new.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 2],
        );
        let current_zone = current_zone(vec![current_soa.clone(), apex_ns(), old_a.clone()]);
        let response = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![
                    new_soa.clone(),
                    current_soa,
                    old_a,
                    new_soa.clone(),
                    new_a.clone(),
                ],
            )],
        )
        .expect("mode 1 diff");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert_eq!(snapshot.serial, Some(2));
        assert!(
            snapshot
                .lookup(
                    &DomainName::from_absolute_str("old.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers
                .is_empty()
        );
        assert_eq!(
            snapshot
                .lookup(
                    &DomainName::from_absolute_str("new.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers,
            vec![new_a]
        );
    }

    #[test]
    fn rejects_ixfr_mode1_final_zone_without_apex_ns() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let old_a = record(
            "old.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let new_a = record(
            "new.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 2],
        );
        let current_zone = current_zone(vec![current_soa.clone(), old_a.clone()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![new_soa.clone(), current_soa, old_a, new_soa, new_a],
            )],
        )
        .expect_err("IXFR final zone missing apex NS");

        assert_eq!(error, IxfrError::Axfr(AxfrError::MissingApexNs));
    }

    #[test]
    fn rejects_ixfr_mode1_final_zone_with_cname_and_other_data() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let cname = record(
            "alias.example.test.",
            RecordType::Cname as u16,
            name_rdata("target.example.test."),
        );
        let a = record(
            "alias.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let current_zone = current_zone(vec![current_soa.clone(), apex_ns()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![new_soa.clone(), current_soa, new_soa, cname, a],
            )],
        )
        .expect_err("IXFR final zone with CNAME and other data");

        assert_eq!(
            error,
            IxfrError::Axfr(AxfrError::CnameCoexistsWithOtherData)
        );
    }

    #[test]
    fn rejects_ixfr_record_with_invalid_fixed_size_rdata() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let bad_a = record("www.example.test.", RecordType::A as u16, vec![192, 0, 2]);
        let current_zone = current_zone(vec![current_soa.clone(), apex_ns()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![new_soa.clone(), current_soa, bad_a, new_soa],
            )],
        )
        .expect_err("IXFR invalid A RDATA");

        assert_eq!(error, IxfrError::Axfr(AxfrError::InvalidRdata));
    }

    #[test]
    fn rejects_ixfr_dname_with_invalid_target_rdata() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let bad_dname = record(
            "redirect.example.test.",
            RecordType::Dname as u16,
            vec![0xc0, 0],
        );
        let current_zone = current_zone(vec![current_soa.clone(), apex_ns()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![new_soa.clone(), current_soa, bad_dname, new_soa],
            )],
        )
        .expect_err("IXFR invalid DNAME target RDATA");

        assert_eq!(error, IxfrError::Axfr(AxfrError::InvalidRdata));
    }

    #[test]
    fn rejects_ixfr_starting_old_soa_mismatch() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let wrong_old_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(9),
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let current_zone = current_zone(vec![current_soa]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![new_soa.clone(), wrong_old_soa, new_soa],
            )],
        )
        .expect_err("starting old SOA mismatch");

        assert_eq!(error, IxfrError::BrokenSoaChain);
    }

    #[test]
    fn rejects_ixfr_final_soa_chain_mismatch() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let intermediate_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let final_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(3),
        );
        let current_zone = current_zone(vec![current_soa.clone()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![final_soa, current_soa, intermediate_soa],
            )],
        )
        .expect_err("final SOA chain mismatch");

        assert_eq!(error, IxfrError::BrokenSoaChain);
    }

    #[test]
    fn rejects_ixfr_deleting_absent_record() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let absent_a = record(
            "absent.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let current_zone = current_zone(vec![current_soa.clone()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![new_soa.clone(), current_soa, absent_a, new_soa],
            )],
        )
        .expect_err("absent delete");

        assert_eq!(error, IxfrError::DeleteAbsentRecord);
    }

    #[test]
    fn rejects_ixfr_adding_existing_record() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let existing_a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let current_zone = current_zone(vec![current_soa.clone(), existing_a.clone()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![new_soa.clone(), current_soa, new_soa, existing_a],
            )],
        )
        .expect_err("existing add");

        assert_eq!(error, IxfrError::AddExistingRecord);
    }

    #[test]
    fn rejects_ixfr_record_with_mismatched_class() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let mut wrong_class = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        wrong_class.class = 3;
        let current_zone = current_zone(vec![current_soa.clone()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![new_soa.clone(), current_soa, wrong_class, new_soa],
            )],
        )
        .expect_err("IXFR class mismatch");

        assert_eq!(error, IxfrError::Axfr(AxfrError::ClassMismatch));
    }

    #[test]
    fn rejects_ixfr_out_of_zone_record() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let out = record("outside.test.", RecordType::A as u16, vec![192, 0, 2, 10]);
        let current_zone = current_zone(vec![current_soa.clone()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![new_soa.clone(), current_soa, out, new_soa],
            )],
        )
        .expect_err("IXFR out-of-zone record");

        assert_eq!(error, IxfrError::Axfr(AxfrError::OutOfZoneOwner));
    }

    #[test]
    fn rejects_ixfr_reserved_record_type() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let reserved = record("www.example.test.", 0, vec![192, 0, 2, 10]);
        let current_zone = current_zone(vec![current_soa.clone()]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(
                0x1234,
                vec![new_soa.clone(), current_soa, reserved, new_soa],
            )],
        )
        .expect_err("IXFR reserved type");

        assert_eq!(error, IxfrError::Axfr(AxfrError::ReservedType));
    }

    #[test]
    fn rejects_soa_response_with_mismatched_qid() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let error = parse_soa_response(0x1234, &apex, 1, &soa_message(0x9999, vec![soa]))
            .expect_err("mismatched qid");

        assert_eq!(error, SoaQueryError::MismatchedQid);
    }

    #[test]
    fn rejects_soa_response_without_apex_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let error = parse_soa_response(0x1234, &apex, 1, &soa_message(0x1234, vec![a]))
            .expect_err("missing SOA");

        assert_eq!(error, SoaQueryError::MissingSoa);
    }

    #[test]
    fn rejects_mismatched_qid() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let error =
            parse_axfr_response(0x1234, &apex, 1, &[message(0x9999, vec![soa.clone(), soa])])
                .expect_err("mismatched qid");
        assert_eq!(error, AxfrError::MismatchedQid);
    }

    #[test]
    fn rejects_axfr_without_apex_ns() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(0x1234, vec![soa.clone(), a, soa])],
        )
        .expect_err("missing apex NS");

        assert_eq!(error, AxfrError::MissingApexNs);
    }

    #[test]
    fn rejects_ixfr_mode2_fallback_without_apex_ns() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa]);
        let new_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[message(0x1234, vec![new_soa.clone(), a, new_soa])],
        )
        .expect_err("mode 2 fallback missing apex NS");

        assert_eq!(error, IxfrError::Axfr(AxfrError::MissingApexNs));
    }

    #[test]
    fn rejects_axfr_cname_with_non_dnssec_data() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let cname = record(
            "alias.example.test.",
            RecordType::Cname as u16,
            name_rdata("target.example.test."),
        );
        let a = record(
            "alias.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(0x1234, vec![soa.clone(), apex_ns(), cname, a, soa])],
        )
        .expect_err("CNAME with non-DNSSEC data");

        assert_eq!(error, AxfrError::CnameCoexistsWithOtherData);
    }

    #[test]
    fn accepts_axfr_cname_with_dnssec_records() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let cname = record(
            "alias.example.test.",
            RecordType::Cname as u16,
            name_rdata("target.example.test."),
        );
        let rrsig = record("alias.example.test.", RecordType::Rrsig as u16, vec![0]);
        let nsec = record("alias.example.test.", RecordType::Nsec as u16, vec![0]);
        let nsec3 = record("alias.example.test.", RecordType::Nsec3 as u16, vec![0]);
        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(
                0x1234,
                vec![soa.clone(), apex_ns(), cname, rrsig, nsec, nsec3, soa],
            )],
        )
        .expect("CNAME with DNSSEC exception data");

        assert_eq!(snapshot.serial, Some(1));
    }

    #[test]
    fn rejects_axfr_dname_with_cname_data() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let dname = record(
            "redirect.example.test.",
            RecordType::Dname as u16,
            name_rdata("target.example.test."),
        );
        let cname = record(
            "redirect.example.test.",
            RecordType::Cname as u16,
            name_rdata("target.example.test."),
        );
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(
                0x1234,
                vec![soa.clone(), apex_ns(), dname, cname, soa],
            )],
        )
        .expect_err("DNAME with CNAME data");

        assert_eq!(error, AxfrError::DnameCoexistsWithCname);
    }

    #[test]
    fn rejects_axfr_a_record_with_invalid_rdata_length() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let bad_a = record("www.example.test.", RecordType::A as u16, vec![192, 0, 2]);
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(0x1234, vec![soa.clone(), apex_ns(), bad_a, soa])],
        )
        .expect_err("invalid A RDATA length");

        assert_eq!(error, AxfrError::InvalidRdata);
    }

    #[test]
    fn rejects_axfr_aaaa_record_with_invalid_rdata_length() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let bad_aaaa = record("www.example.test.", RecordType::Aaaa as u16, vec![0; 15]);
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(0x1234, vec![soa.clone(), apex_ns(), bad_aaaa, soa])],
        )
        .expect_err("invalid AAAA RDATA length");

        assert_eq!(error, AxfrError::InvalidRdata);
    }

    #[test]
    fn rejects_axfr_dname_with_trailing_rdata() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut target = name_rdata("target.example.test.");
        target.push(0);
        let dname = record("redirect.example.test.", RecordType::Dname as u16, target);
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(0x1234, vec![soa.clone(), apex_ns(), dname, soa])],
        )
        .expect_err("DNAME with trailing RDATA");

        assert_eq!(error, AxfrError::InvalidRdata);
    }

    #[test]
    fn rejects_axfr_dname_with_compressed_target_rdata() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let dname = record(
            "redirect.example.test.",
            RecordType::Dname as u16,
            vec![0xc0, 0],
        );
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(0x1234, vec![soa.clone(), apex_ns(), dname, soa])],
        )
        .expect_err("DNAME with compressed target RDATA");

        assert_eq!(error, AxfrError::InvalidRdata);
    }

    #[test]
    fn rejects_soa_response_with_invalid_fixed_size_rdata() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let bad_a = record("www.example.test.", RecordType::A as u16, vec![192, 0, 2]);
        let error = parse_soa_response(0x1234, &apex, 1, &soa_message(0x1234, vec![bad_a]))
            .expect_err("invalid A RDATA in SOA response");

        assert_eq!(error, SoaQueryError::InvalidRdata);
    }

    #[test]
    fn rejects_missing_initial_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let error = parse_axfr_response(0x1234, &apex, 1, &[message(0x1234, vec![a])])
            .expect_err("bad AXFR");
        assert_eq!(error, AxfrError::MissingInitialSoa);
    }

    #[test]
    fn rejects_mismatched_terminating_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut other_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        other_soa.ttl = 301;
        let error = parse_axfr_response(0x1234, &apex, 1, &[message(0x1234, vec![soa, other_soa])])
            .expect_err("bad terminating SOA");
        assert_eq!(error, AxfrError::MismatchedTerminatingSoa);
    }

    #[test]
    fn rejects_records_after_terminating_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(0x1234, vec![soa.clone(), soa, a])],
        )
        .expect_err("trailing AXFR data");
        assert_eq!(error, AxfrError::TrailingRecords);
    }

    #[test]
    fn rejects_out_of_zone_record() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let out = record("outside.test.", RecordType::A as u16, vec![192, 0, 2, 10]);
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[message(0x1234, vec![soa.clone(), out, soa])],
        )
        .expect_err("out-of-zone record");
        assert_eq!(error, AxfrError::OutOfZoneOwner);
    }
}
