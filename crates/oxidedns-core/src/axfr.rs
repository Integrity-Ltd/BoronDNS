use std::collections::{HashMap, HashSet};

use thiserror::Error;
use tracing::warn;

use crate::{
    dns::{DNS_HEADER_LEN, DnsParseError, DomainName, Header, RecordType},
    zone::{ResourceRecord, Rrset, SoaRecordView, ZoneSnapshot},
};

// ODS-NFR-MAINT-004 principal functional requirement references for zone
// transfer parsing, outbound response validation, unknown RR handling, and
// transferred RR catalogue validation:
// - ODS-FR-SPOOF-001 ODS-FR-SPOOF-002 ODS-FR-SPOOF-003
// - ODS-FR-SPOOF-004 ODS-FR-SPOOF-005 ODS-FR-SPOOF-006
// - ODS-FR-SPOOF-007
// - ODS-FR-AXFR-001 ODS-FR-AXFR-002 ODS-FR-AXFR-003 ODS-FR-AXFR-004
// - ODS-FR-AXFR-005 ODS-FR-AXFR-006 ODS-FR-AXFR-007 ODS-FR-AXFR-008
// - ODS-FR-AXFR-009 ODS-FR-AXFR-010 ODS-FR-AXFR-011 ODS-FR-AXFR-012
// - ODS-FR-AXFR-013 ODS-FR-AXFR-014 ODS-FR-AXFR-015 ODS-FR-AXFR-016
// - ODS-FR-AXFR-017 ODS-FR-AXFR-018 ODS-FR-AXFR-019 ODS-FR-AXFR-020
// - ODS-FR-AXFR-021 ODS-FR-AXFR-022 ODS-FR-AXFR-023 ODS-FR-AXFR-024
// - ODS-FR-AXFR-025 ODS-FR-AXFR-026
// - ODS-FR-IXFR-001 ODS-FR-IXFR-002 ODS-FR-IXFR-003 ODS-FR-IXFR-004
// - ODS-FR-IXFR-005 ODS-FR-IXFR-006 ODS-FR-IXFR-007 ODS-FR-IXFR-008
// - ODS-FR-IXFR-009 ODS-FR-IXFR-010 ODS-FR-IXFR-011 ODS-FR-IXFR-012
// - ODS-FR-IXFR-013 ODS-FR-IXFR-014 ODS-FR-IXFR-015 ODS-FR-IXFR-016
// - ODS-FR-IXFR-017 ODS-FR-IXFR-018 ODS-FR-IXFR-019
// - ODS-FR-URR-001 ODS-FR-URR-002 ODS-FR-URR-003 ODS-FR-URR-004
// - ODS-FR-URR-005 ODS-FR-URR-006 ODS-FR-URR-007 ODS-FR-URR-008
// - ODS-FR-URR-009
// - ODS-FR-RR-001 ODS-FR-RR-002 ODS-FR-RR-003 ODS-FR-RR-004
// - ODS-FR-RR-005 ODS-FR-RR-006 ODS-FR-RR-007
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AxfrError {
    #[error("AXFR response stream is empty")]
    EmptyResponse,

    #[error("AXFR response message is malformed")]
    MalformedMessage,

    #[error("AXFR response QID does not match query QID")]
    MismatchedQid,

    #[error("AXFR response was not marked as a response")]
    NotResponse,

    #[error("AXFR response opcode is not QUERY")]
    MismatchedOpcode,

    #[error("AXFR response returned error RCODE {0}")]
    ErrorRcode(u8),

    #[error("AXFR response question does not match the AXFR query")]
    MismatchedQuestion,

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

    #[error("AXFR response contained a pseudo or transfer meta RR type as zone content")]
    ProhibitedType,

    #[error("AXFR response contained invalid RDATA for a known RR type")]
    InvalidRdata,

    #[error("AXFR response final zone did not contain exactly one apex SOA")]
    InvalidZoneSoa,

    #[error("AXFR response did not contain an apex NS RRset")]
    MissingApexNs,

    #[error("AXFR response contained a CNAME owner with non-DNSSEC data")]
    CnameCoexistsWithOtherData,

    #[error("AXFR response contained a DNAME owner with CNAME data")]
    DnameCoexistsWithCname,

    #[error("AXFR response contained a DNAME RRset with multiple records")]
    MultipleDnameRecords,
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

    #[error("SOA response was truncated")]
    Truncated,

    #[error("SOA response did not contain an SOA answer at the zone apex")]
    MissingSoa,

    #[error("SOA response contained an answer with an unexpected class")]
    ClassMismatch,

    #[error("SOA response contained an out-of-zone answer owner name")]
    OutOfZoneOwner,

    #[error("SOA response contained a reserved RR type")]
    ReservedType,

    #[error("SOA response contained a pseudo or transfer meta RR type as zone content")]
    ProhibitedType,

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

    #[error("IXFR response was not marked as a response")]
    NotResponse,

    #[error("IXFR response opcode is not QUERY")]
    MismatchedOpcode,

    #[error("IXFR response returned error RCODE {0}")]
    ErrorRcode(u8),

    #[error("IXFR response question does not match the IXFR query")]
    MismatchedQuestion,

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
    Updated(Box<ZoneSnapshot>),
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
    Ok(build_ixfr_query_message(
        qid,
        zone_apex,
        qclass,
        &current_soa.owner,
        current_soa.ttl,
        &current_soa.rdata,
    ))
}

pub fn build_ixfr_query_from_soa_view(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    current_soa: SoaRecordView<'_>,
) -> Result<Vec<u8>, IxfrError> {
    validate_current_soa_view(current_soa, zone_apex, qclass)?;
    Ok(build_ixfr_query_message(
        qid,
        zone_apex,
        qclass,
        current_soa.owner,
        current_soa.ttl,
        current_soa.rdata,
    ))
}

fn build_ixfr_query_message(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    current_soa_owner: &DomainName,
    current_soa_ttl: u32,
    current_soa_rdata: &[u8],
) -> Vec<u8> {
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
    append_record_parts(
        &mut message,
        current_soa_owner,
        RecordType::Soa as u16,
        qclass,
        current_soa_ttl,
        current_soa_rdata,
    );
    message
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

fn append_record_parts(
    message: &mut Vec<u8>,
    owner: &DomainName,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: &[u8],
) {
    message.extend_from_slice(&owner.to_wire());
    message.extend_from_slice(&rr_type.to_be_bytes());
    message.extend_from_slice(&class.to_be_bytes());
    message.extend_from_slice(&ttl.to_be_bytes());
    message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    message.extend_from_slice(rdata);
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
    parse_axfr_response_with_question(qid, zone_apex, qclass, RecordType::Axfr as u16, messages)
}

pub fn axfr_response_message_apex_soa_count(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    message: &[u8],
    require_question: bool,
) -> Result<usize, AxfrError> {
    let header = Header::parse(message).map_err(|_| AxfrError::MalformedMessage)?;
    if header.id != qid {
        return Err(AxfrError::MismatchedQid);
    }
    if !header.is_response() {
        return Err(AxfrError::NotResponse);
    }
    if header.opcode_value() != 0 {
        return Err(AxfrError::MismatchedOpcode);
    }
    let rcode = (header.flags & 0x000f) as u8;
    if rcode != 0 {
        return Err(AxfrError::ErrorRcode(rcode));
    }

    let mut offset = validate_axfr_response_question(
        message,
        header.qdcount,
        zone_apex,
        RecordType::Axfr as u16,
        qclass,
        require_question,
    )?;
    let mut apex_soa_count = 0usize;
    for _ in 0..header.ancount {
        let (record, consumed) = parse_record(message, offset)?;
        offset += consumed;
        if record.rr_type == RecordType::Soa as u16
            && record.class == qclass
            && record.owner.canonical_key() == zone_apex.canonical_key()
        {
            apex_soa_count += 1;
        }
    }
    Ok(apex_soa_count)
}

fn parse_axfr_response_with_question(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    qtype: u16,
    messages: &[Vec<u8>],
) -> Result<ZoneSnapshot, AxfrError> {
    if messages.is_empty() {
        return Err(AxfrError::EmptyResponse);
    }

    let mut initial_soa = None;
    let mut zone_serial = None;
    let mut zone_records = Vec::new();
    let mut complete = false;
    let mut saw_response_question = false;

    for message in messages {
        let header = Header::parse(message).map_err(|_| AxfrError::MalformedMessage)?;
        if header.id != qid {
            return Err(AxfrError::MismatchedQid);
        }
        if !header.is_response() {
            return Err(AxfrError::NotResponse);
        }
        if header.opcode_value() != 0 {
            return Err(AxfrError::MismatchedOpcode);
        }
        let rcode = (header.flags & 0x000f) as u8;
        if rcode != 0 {
            return Err(AxfrError::ErrorRcode(rcode));
        }

        let mut offset = validate_axfr_response_question(
            message,
            header.qdcount,
            zone_apex,
            qtype,
            qclass,
            !saw_response_question,
        )?;
        if header.qdcount == 1 {
            saw_response_question = true;
        }
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
                        if record.owner.canonical_key() != zone_apex.canonical_key() {
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
    if header.flags & 0x0200 != 0 {
        return Err(SoaQueryError::Truncated);
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
        if record.owner.canonical_key() == zone_apex.canonical_key()
            && record.rr_type == RecordType::Soa as u16
        {
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
        .transfer_soa_record(qclass)
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
        if !header.is_response() {
            return Err(IxfrError::NotResponse);
        }
        if header.opcode_value() != 0 {
            return Err(IxfrError::MismatchedOpcode);
        }
        let rcode = (header.flags & 0x000f) as u8;
        if rcode != 0 {
            return Err(IxfrError::ErrorRcode(rcode));
        }

        let mut offset = validate_ixfr_response_question(
            message,
            header.qdcount,
            zone_apex,
            RecordType::Ixfr as u16,
            qclass,
        )?;
        for _ in 0..header.ancount {
            let (mut record, consumed) =
                parse_record(message, offset).map_err(|_| IxfrError::MalformedMessage)?;
            offset += consumed;
            validate_record_scope(&record, zone_apex, qclass).map_err(ixfr_scope_error)?;
            canonicalize_record_owner(&mut record).map_err(|_| IxfrError::MalformedMessage)?;
            answers.push(record);
        }
    }

    let Some(first) = answers.first() else {
        return Err(IxfrError::MissingInitialSoa);
    };
    if first.owner.canonical_key() != zone_apex.canonical_key()
        || first.rr_type != RecordType::Soa as u16
    {
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

    parse_axfr_response_with_question(qid, zone_apex, qclass, RecordType::Ixfr as u16, messages)
        .map(Box::new)
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
        .transfer_soa_record(qclass)
        .ok_or(IxfrError::InvalidCurrentSoa)?;
    let mut expected_old_soa = current_soa;
    let mut records = current_zone.transfer_records();
    let mut index = 1usize;

    while index < answers.len() {
        let old_soa = &answers[index];
        if old_soa == outer_soa && expected_old_soa == *outer_soa {
            index += 1;
            break;
        }
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
        if new_soa.rr_type != RecordType::Soa as u16
            || new_soa.owner.canonical_key() != zone_apex.canonical_key()
        {
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
    if index != answers.len() {
        return Err(IxfrError::BrokenSoaChain);
    }

    let final_applied_serial =
        soa_serial(&expected_old_soa.rdata).map_err(|_| IxfrError::MalformedMessage)?;
    if expected_old_soa != *outer_soa || final_applied_serial != final_serial {
        return Err(IxfrError::BrokenSoaChain);
    }
    validate_zone_record_set(zone_apex, &records).map_err(IxfrError::Axfr)?;

    Ok(IxfrResponse::Updated(Box::new(ZoneSnapshot::active(
        zone_apex.clone(),
        Some(final_serial),
        rrsets_from_records(records),
    ))))
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

fn canonicalize_record_owner(record: &mut ResourceRecord) -> Result<(), DnsParseError> {
    record.owner = DomainName::from_absolute_str(&record.owner.canonical_key())?;
    Ok(())
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

fn validate_current_soa_view(
    record: SoaRecordView<'_>,
    zone_apex: &DomainName,
    qclass: u16,
) -> Result<(), IxfrError> {
    if record.owner != zone_apex || record.class != qclass {
        return Err(IxfrError::InvalidCurrentSoa);
    }
    soa_serial(record.rdata).map_err(|_| IxfrError::InvalidCurrentSoa)?;
    Ok(())
}

fn validate_soa_response_question(
    message: &[u8],
    qdcount: u16,
    zone_apex: &DomainName,
    qclass: u16,
) -> Result<usize, SoaQueryError> {
    validate_response_question(message, qdcount, zone_apex, RecordType::Soa as u16, qclass).map_err(
        |error| match error {
            ResponseQuestionError::MalformedMessage => SoaQueryError::MalformedMessage,
            ResponseQuestionError::MismatchedQuestion => SoaQueryError::MismatchedQuestion,
        },
    )
}

fn validate_axfr_response_question(
    message: &[u8],
    qdcount: u16,
    zone_apex: &DomainName,
    qtype: u16,
    qclass: u16,
    require_question: bool,
) -> Result<usize, AxfrError> {
    if qdcount == 0 && !require_question {
        return Ok(DNS_HEADER_LEN);
    }
    validate_response_question(message, qdcount, zone_apex, qtype, qclass).map_err(|error| {
        match error {
            ResponseQuestionError::MalformedMessage => AxfrError::MalformedMessage,
            ResponseQuestionError::MismatchedQuestion => AxfrError::MismatchedQuestion,
        }
    })
}

fn validate_ixfr_response_question(
    message: &[u8],
    qdcount: u16,
    zone_apex: &DomainName,
    qtype: u16,
    qclass: u16,
) -> Result<usize, IxfrError> {
    validate_response_question(message, qdcount, zone_apex, qtype, qclass).map_err(|error| {
        match error {
            ResponseQuestionError::MalformedMessage => IxfrError::MalformedMessage,
            ResponseQuestionError::MismatchedQuestion => IxfrError::MismatchedQuestion,
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseQuestionError {
    MalformedMessage,
    MismatchedQuestion,
}

fn validate_response_question(
    message: &[u8],
    qdcount: u16,
    zone_apex: &DomainName,
    qtype: u16,
    qclass: u16,
) -> Result<usize, ResponseQuestionError> {
    if qdcount != 1 {
        return Err(ResponseQuestionError::MismatchedQuestion);
    }

    let (qname, consumed) = DomainName::parse(message, DNS_HEADER_LEN)
        .map_err(|_| ResponseQuestionError::MalformedMessage)?;
    let offset = DNS_HEADER_LEN + consumed;
    if offset + 4 > message.len() {
        return Err(ResponseQuestionError::MalformedMessage);
    }

    let response_qtype = u16::from_be_bytes([message[offset], message[offset + 1]]);
    let response_qclass = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
    if qname.canonical_key() != zone_apex.canonical_key()
        || response_qtype != qtype
        || response_qclass != qclass
    {
        return Err(ResponseQuestionError::MismatchedQuestion);
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

    let rdata_offset = offset;
    let rdata = normalize_transfer_rdata(message, rr_type, rdata_offset, rdlength)?;
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

fn normalize_transfer_rdata(
    message: &[u8],
    rr_type: u16,
    rdata_offset: usize,
    rdlength: usize,
) -> Result<Vec<u8>, DnsParseError> {
    let rdata_end = rdata_offset
        .checked_add(rdlength)
        .ok_or(DnsParseError::FormErr)?;
    let raw_rdata = message
        .get(rdata_offset..rdata_end)
        .ok_or(DnsParseError::FormErr)?;

    match rr_type {
        rr_type
            if rr_type == RecordType::Ns as u16
                || rr_type == RecordType::Cname as u16
                || rr_type == RecordType::Ptr as u16 =>
        {
            let (name, consumed) = parse_rdata_name(message, rdata_offset, rdata_end)?;
            if rdata_offset + consumed == rdata_end {
                Ok(name.to_wire())
            } else {
                Err(DnsParseError::FormErr)
            }
        }
        rr_type if rr_type == RecordType::Soa as u16 => {
            normalize_soa_rdata(message, rdata_offset, rdata_end)
        }
        rr_type if rr_type == RecordType::Mx as u16 => {
            normalize_mx_rdata(message, rdata_offset, rdata_end)
        }
        _ => Ok(raw_rdata.to_vec()),
    }
}

fn normalize_soa_rdata(
    message: &[u8],
    rdata_offset: usize,
    rdata_end: usize,
) -> Result<Vec<u8>, DnsParseError> {
    let (mname, consumed_mname) = parse_rdata_name(message, rdata_offset, rdata_end)?;
    let rname_offset = rdata_offset + consumed_mname;
    let (rname, consumed_rname) = parse_rdata_name(message, rname_offset, rdata_end)?;
    let timers_offset = rname_offset + consumed_rname;
    if timers_offset + 20 != rdata_end {
        return Err(DnsParseError::FormErr);
    }

    let mut normalized = mname.to_wire();
    normalized.extend(rname.to_wire());
    normalized.extend_from_slice(&message[timers_offset..rdata_end]);
    Ok(normalized)
}

fn normalize_mx_rdata(
    message: &[u8],
    rdata_offset: usize,
    rdata_end: usize,
) -> Result<Vec<u8>, DnsParseError> {
    let exchange_offset = rdata_offset.checked_add(2).ok_or(DnsParseError::FormErr)?;
    if exchange_offset > rdata_end {
        return Err(DnsParseError::FormErr);
    }

    let (exchange, consumed) = parse_rdata_name(message, exchange_offset, rdata_end)?;
    if exchange_offset + consumed != rdata_end {
        return Err(DnsParseError::FormErr);
    }

    let mut normalized = message[rdata_offset..exchange_offset].to_vec();
    normalized.extend(exchange.to_wire());
    Ok(normalized)
}

fn parse_rdata_name(
    message: &[u8],
    offset: usize,
    rdata_end: usize,
) -> Result<(DomainName, usize), DnsParseError> {
    if offset >= rdata_end {
        return Err(DnsParseError::FormErr);
    }
    let (name, consumed) = DomainName::parse(message, offset)?;
    if offset + consumed > rdata_end {
        return Err(DnsParseError::FormErr);
    }
    Ok((name, consumed))
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
    if is_prohibited_transfer_content_type(record.rr_type) {
        return Err(AxfrError::ProhibitedType);
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
    if is_prohibited_transfer_content_type(record.rr_type) {
        return Err(SoaQueryError::ProhibitedType);
    }
    validate_known_rdata(record).map_err(|_| SoaQueryError::InvalidRdata)?;
    if !record.owner.is_equal_or_subdomain_of(zone_apex) {
        return Err(SoaQueryError::OutOfZoneOwner);
    }
    Ok(())
}

fn is_prohibited_transfer_content_type(rr_type: u16) -> bool {
    rr_type == RecordType::Opt as u16
        || rr_type == RecordType::Tkey as u16
        || rr_type == RecordType::Tsig as u16
        || rr_type == RecordType::Ixfr as u16
        || rr_type == RecordType::Axfr as u16
        || rr_type == 253
        || rr_type == 254
        || rr_type == 255
}

fn validate_known_rdata(record: &ResourceRecord) -> Result<(), AxfrError> {
    match record.rr_type {
        rr_type if rr_type == RecordType::A as u16 => validate_fixed_rdata(record, 4),
        rr_type if rr_type == RecordType::Aaaa as u16 => validate_fixed_rdata(record, 16),
        rr_type if rr_type == RecordType::Ds as u16 => validate_min_rdata(&record.rdata, 4),
        rr_type if rr_type == RecordType::Hinfo as u16 => {
            validate_character_strings(&record.rdata, Some(2))
        }
        rr_type if rr_type == RecordType::Txt as u16 => {
            validate_character_strings(&record.rdata, None)
        }
        rr_type if rr_type == RecordType::Srv as u16 => {
            validate_uncompressed_domain_name_at_end(&record.rdata, 6)
        }
        rr_type if rr_type == RecordType::Naptr as u16 => validate_naptr_rdata(&record.rdata),
        rr_type if rr_type == RecordType::Dname as u16 => {
            validate_uncompressed_domain_name_rdata(&record.rdata)
        }
        rr_type if rr_type == RecordType::Rrsig as u16 => {
            validate_uncompressed_domain_name_with_trailing(&record.rdata, 18).map(|_| ())
        }
        rr_type if rr_type == RecordType::Dnskey as u16 => validate_dnskey_rdata(&record.rdata),
        rr_type if rr_type == RecordType::Nsec as u16 => validate_nsec_rdata(&record.rdata),
        rr_type if rr_type == RecordType::Nsec3 as u16 => validate_nsec3_rdata(&record.rdata),
        rr_type if rr_type == RecordType::Nsec3Param as u16 => {
            validate_nsec3param_rdata(&record.rdata)
        }
        rr_type if rr_type == RecordType::Tlsa as u16 => validate_min_rdata(&record.rdata, 3),
        rr_type if rr_type == RecordType::Svcb as u16 || rr_type == RecordType::Https as u16 => {
            validate_svcb_like_rdata(&record.rdata)
        }
        rr_type if rr_type == RecordType::Uri as u16 => validate_uri_rdata(&record.rdata),
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

fn validate_min_rdata(rdata: &[u8], min_len: usize) -> Result<(), AxfrError> {
    if rdata.len() >= min_len {
        Ok(())
    } else {
        Err(AxfrError::InvalidRdata)
    }
}

fn validate_character_strings(
    rdata: &[u8],
    expected_count: Option<usize>,
) -> Result<(), AxfrError> {
    validate_character_strings_from(rdata, 0, expected_count)
}

fn validate_character_strings_from(
    rdata: &[u8],
    mut offset: usize,
    expected_count: Option<usize>,
) -> Result<(), AxfrError> {
    if offset >= rdata.len() {
        return Err(AxfrError::InvalidRdata);
    }

    let mut count = 0usize;
    while offset < rdata.len() {
        offset = skip_character_string(rdata, offset)?;
        count += 1;
    }

    if expected_count.is_none_or(|expected| count == expected) {
        Ok(())
    } else {
        Err(AxfrError::InvalidRdata)
    }
}

fn validate_uncompressed_domain_name_rdata(rdata: &[u8]) -> Result<(), AxfrError> {
    let consumed = validate_uncompressed_domain_name_at(rdata, 0)?;
    if consumed == rdata.len() {
        Ok(())
    } else {
        Err(AxfrError::InvalidRdata)
    }
}

fn validate_uncompressed_domain_name_at_end(rdata: &[u8], offset: usize) -> Result<(), AxfrError> {
    let consumed = validate_uncompressed_domain_name_at(rdata, offset)?;
    if offset + consumed == rdata.len() {
        Ok(())
    } else {
        Err(AxfrError::InvalidRdata)
    }
}

fn validate_uncompressed_domain_name_with_trailing(
    rdata: &[u8],
    offset: usize,
) -> Result<usize, AxfrError> {
    validate_uncompressed_domain_name_at(rdata, offset)
}

fn validate_uncompressed_domain_name_at(rdata: &[u8], offset: usize) -> Result<usize, AxfrError> {
    let mut pos = offset;
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
            return Ok(pos - offset);
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

fn validate_naptr_rdata(rdata: &[u8]) -> Result<(), AxfrError> {
    if rdata.len() < 8 {
        return Err(AxfrError::InvalidRdata);
    }

    let mut offset = 4;
    for _ in 0..3 {
        offset = skip_character_string(rdata, offset)?;
    }
    validate_uncompressed_domain_name_at_end(rdata, offset)
}

fn validate_dnskey_rdata(rdata: &[u8]) -> Result<(), AxfrError> {
    validate_min_rdata(rdata, 4)?;
    if rdata[2] == 3 {
        Ok(())
    } else {
        Err(AxfrError::InvalidRdata)
    }
}

fn validate_nsec_rdata(rdata: &[u8]) -> Result<(), AxfrError> {
    let next_name_len = validate_uncompressed_domain_name_with_trailing(rdata, 0)?;
    validate_type_bit_maps(&rdata[next_name_len..], false)
}

fn validate_nsec3_rdata(rdata: &[u8]) -> Result<(), AxfrError> {
    if rdata.len() < 6 {
        return Err(AxfrError::InvalidRdata);
    }

    let salt_len = rdata[4] as usize;
    let hash_len_offset = 5 + salt_len;
    let Some(&hash_len) = rdata.get(hash_len_offset) else {
        return Err(AxfrError::InvalidRdata);
    };
    if hash_len == 0 {
        return Err(AxfrError::InvalidRdata);
    }

    let bit_maps_offset = hash_len_offset + 1 + hash_len as usize;
    if bit_maps_offset > rdata.len() {
        return Err(AxfrError::InvalidRdata);
    }

    validate_type_bit_maps(&rdata[bit_maps_offset..], true)
}

fn validate_nsec3param_rdata(rdata: &[u8]) -> Result<(), AxfrError> {
    if rdata.len() < 5 {
        return Err(AxfrError::InvalidRdata);
    }

    let salt_len = rdata[4] as usize;
    if 5 + salt_len == rdata.len() {
        Ok(())
    } else {
        Err(AxfrError::InvalidRdata)
    }
}

fn validate_type_bit_maps(bit_maps: &[u8], allow_empty: bool) -> Result<(), AxfrError> {
    if bit_maps.is_empty() {
        if allow_empty {
            return Ok(());
        }
        return Err(AxfrError::InvalidRdata);
    }

    let mut offset = 0usize;
    let mut last_window = None;
    while offset < bit_maps.len() {
        if offset + 2 > bit_maps.len() {
            return Err(AxfrError::InvalidRdata);
        }

        let window = bit_maps[offset];
        let bitmap_len = bit_maps[offset + 1] as usize;
        offset += 2;

        if bitmap_len == 0 || bitmap_len > 32 || offset + bitmap_len > bit_maps.len() {
            return Err(AxfrError::InvalidRdata);
        }
        if last_window.is_some_and(|last| window <= last) {
            return Err(AxfrError::InvalidRdata);
        }
        if bit_maps[offset + bitmap_len - 1] == 0 {
            return Err(AxfrError::InvalidRdata);
        }

        last_window = Some(window);
        offset += bitmap_len;
    }

    Ok(())
}

fn validate_uri_rdata(rdata: &[u8]) -> Result<(), AxfrError> {
    if rdata.len() < 5 {
        return Err(AxfrError::InvalidRdata);
    }
    Ok(())
}

fn validate_svcb_like_rdata(rdata: &[u8]) -> Result<(), AxfrError> {
    if rdata.len() < 3 {
        return Err(AxfrError::InvalidRdata);
    }

    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    let target_len = validate_uncompressed_domain_name_with_trailing(rdata, 2)?;
    let mut offset = 2 + target_len;
    if priority == 0 && offset != rdata.len() {
        return Err(AxfrError::InvalidRdata);
    }

    let mut last_key = None;
    while offset < rdata.len() {
        if offset + 4 > rdata.len() {
            return Err(AxfrError::InvalidRdata);
        }
        let key = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
        let len = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
        offset += 4;
        if offset + len > rdata.len() {
            return Err(AxfrError::InvalidRdata);
        }
        if last_key.is_some_and(|last| key <= last) {
            return Err(AxfrError::InvalidRdata);
        }
        last_key = Some(key);
        offset += len;
    }

    Ok(())
}

fn skip_character_string(rdata: &[u8], offset: usize) -> Result<usize, AxfrError> {
    let Some(&len) = rdata.get(offset) else {
        return Err(AxfrError::InvalidRdata);
    };
    let next = offset
        .checked_add(1)
        .and_then(|next| next.checked_add(len as usize))
        .ok_or(AxfrError::InvalidRdata)?;
    if next <= rdata.len() {
        Ok(next)
    } else {
        Err(AxfrError::InvalidRdata)
    }
}

fn validate_zone_record_set(
    zone_apex: &DomainName,
    records: &[ResourceRecord],
) -> Result<(), AxfrError> {
    validate_exact_apex_soa(zone_apex, records)?;
    validate_apex_ns(zone_apex, records)?;
    validate_cname_and_dname_coexistence(records)?;
    Ok(())
}

fn validate_exact_apex_soa(
    zone_apex: &DomainName,
    records: &[ResourceRecord],
) -> Result<(), AxfrError> {
    let soa_records = records
        .iter()
        .filter(|record| record.rr_type == RecordType::Soa as u16)
        .collect::<Vec<_>>();
    if soa_records.len() == 1 && soa_records[0].owner.canonical_key() == zone_apex.canonical_key() {
        Ok(())
    } else {
        Err(AxfrError::InvalidZoneSoa)
    }
}

fn validate_apex_ns(zone_apex: &DomainName, records: &[ResourceRecord]) -> Result<(), AxfrError> {
    if records.iter().any(|record| {
        record.owner.canonical_key() == zone_apex.canonical_key()
            && record.rr_type == RecordType::Ns as u16
    }) {
        Ok(())
    } else {
        Err(AxfrError::MissingApexNs)
    }
}

fn validate_cname_and_dname_coexistence(records: &[ResourceRecord]) -> Result<(), AxfrError> {
    let mut dname_rrsets = HashSet::<(String, u16)>::new();
    for record in records {
        if record.rr_type != RecordType::Dname as u16 {
            continue;
        }

        let record_key = record.owner.canonical_key();
        let dname_key = (record_key.clone(), record.class);
        if !dname_rrsets.insert(dname_key) {
            return Err(AxfrError::MultipleDnameRecords);
        }

        if records.iter().any(|other| {
            other.owner.canonical_key() == record_key && other.rr_type == RecordType::Cname as u16
        }) {
            return Err(AxfrError::DnameCoexistsWithCname);
        }
    }

    for record in records {
        let record_key = record.owner.canonical_key();
        if record.rr_type == RecordType::Cname as u16
            && records.iter().any(|other| {
                other.owner.canonical_key() == record_key
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
    let mut rrset_indexes = HashMap::<(String, u16, u16), usize>::new();
    let mut rrsets = Vec::<RrsetAccumulator>::new();

    for record in records {
        let key = (record.owner.canonical_key(), record.rr_type, record.class);
        if let Some(&index) = rrset_indexes.get(&key) {
            let existing = &mut rrsets[index];
            if existing.ttl != record.ttl {
                warn!(
                    owner = %record.owner,
                    rr_type = record.rr_type,
                    class = record.class,
                    existing_ttl = existing.ttl,
                    incoming_ttl = record.ttl,
                    adopted_ttl = existing.ttl.min(record.ttl),
                    "zone transfer delivered non-uniform RRset TTLs; adopting lowest TTL"
                );
            }
            existing.ttl = existing.ttl.min(record.ttl);
            existing.rdatas.push(record.rdata);
        } else {
            rrset_indexes.insert(key, rrsets.len());
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
    use crate::zone_image::ZoneImage;
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

    fn axfr_message(qid: u16, answers: Vec<ResourceRecord>) -> Vec<u8> {
        transfer_response_message(qid, "example.test.", RecordType::Axfr as u16, 1, answers)
    }

    fn ixfr_message(qid: u16, answers: Vec<ResourceRecord>) -> Vec<u8> {
        transfer_response_message(qid, "example.test.", RecordType::Ixfr as u16, 1, answers)
    }

    fn transfer_response_message(
        qid: u16,
        question_name: &str,
        qtype: u16,
        qclass: u16,
        answers: Vec<ResourceRecord>,
    ) -> Vec<u8> {
        let qname = DomainName::from_absolute_str(question_name).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&qid.to_be_bytes());
        out.extend_from_slice(&0x8000u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&qname.to_wire());
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&qclass.to_be_bytes());
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

    fn transfer_response_message_without_question(
        qid: u16,
        answers: Vec<ResourceRecord>,
    ) -> Vec<u8> {
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
        transfer_response_message(qid, "example.test.", RecordType::Soa as u16, 1, answers)
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

    fn compressed_apex_name_rdata() -> Vec<u8> {
        vec![0xc0, 0x0c]
    }

    fn compressed_apex_suffix_name_rdata(label: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label.as_bytes());
        rdata.extend(compressed_apex_name_rdata());
        rdata
    }

    fn compressed_soa_rdata() -> Vec<u8> {
        let base = soa_rdata();
        let (_, consumed_mname) = DomainName::parse(&base, 0).unwrap();
        let (_, consumed_rname) = DomainName::parse(&base, consumed_mname).unwrap();
        let timers_offset = consumed_mname + consumed_rname;

        let mut rdata = compressed_apex_name_rdata();
        rdata.extend(compressed_apex_name_rdata());
        rdata.extend_from_slice(&base[timers_offset..]);
        rdata
    }

    fn mx_rdata(preference: u16, exchange: Vec<u8>) -> Vec<u8> {
        let mut rdata = preference.to_be_bytes().to_vec();
        rdata.extend(exchange);
        rdata
    }

    fn srv_rdata(target: Vec<u8>) -> Vec<u8> {
        let mut rdata = vec![0, 10, 0, 20, 1, 187];
        rdata.extend(target);
        rdata
    }

    fn naptr_rdata(replacement: Vec<u8>) -> Vec<u8> {
        let mut rdata = vec![0, 10, 0, 20, 0, 0, 0];
        rdata.extend(replacement);
        rdata
    }

    fn ds_rdata(algorithm: u8) -> Vec<u8> {
        let mut rdata = vec![0x12, 0x34, algorithm, 2];
        rdata.extend([0xaa; 32]);
        rdata
    }

    fn rrsig_rdata(signer: Vec<u8>) -> Vec<u8> {
        rrsig_rdata_with_algorithm(RecordType::A, 8, signer)
    }

    fn rrsig_rdata_with_algorithm(
        type_covered: RecordType,
        algorithm: u8,
        signer: Vec<u8>,
    ) -> Vec<u8> {
        let mut rdata = vec![0; 18];
        rdata[0..2].copy_from_slice(&(type_covered as u16).to_be_bytes());
        rdata[2] = algorithm;
        rdata.extend(signer);
        rdata
    }

    fn dnskey_rdata(algorithm: u8) -> Vec<u8> {
        vec![1, 0, 3, algorithm, 0xde, 0xad, 0xbe, 0xef]
    }

    fn nsec_rdata(next_name: Vec<u8>) -> Vec<u8> {
        nsec_rdata_with_bit_maps(next_name, &[0, 1, 1])
    }

    fn nsec_rdata_with_bit_maps(next_name: Vec<u8>, bit_maps: &[u8]) -> Vec<u8> {
        let mut rdata = next_name;
        rdata.extend(bit_maps);
        rdata
    }

    fn nsec3_rdata(bit_maps: &[u8]) -> Vec<u8> {
        let mut rdata = vec![1, 0, 0, 0, 0, 1, 0];
        rdata.extend(bit_maps);
        rdata
    }

    fn svcb_rdata(priority: u16, target: Vec<u8>, params: &[u8]) -> Vec<u8> {
        let mut rdata = priority.to_be_bytes().to_vec();
        rdata.extend(target);
        rdata.extend(params);
        rdata
    }

    fn first_rdata(snapshot: &ZoneSnapshot, owner: &str, rr_type: u16) -> Vec<u8> {
        let owner = DomainName::from_absolute_str(owner).unwrap();
        snapshot
            .transfer_records()
            .into_iter()
            .find(|record| record.owner == owner && record.rr_type == rr_type)
            .expect("record present")
            .rdata
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
    fn builds_ixfr_query_from_borrowed_soa_view() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let snapshot = current_zone(vec![soa.clone()]);
        let soa_view = snapshot.soa_record_view(1).expect("SOA view");

        let borrowed_query =
            build_ixfr_query_from_soa_view(0x1234, &apex, 1, soa_view).expect("IXFR query");
        let owned_query = build_ixfr_query(0x1234, &apex, 1, &soa).expect("IXFR query");

        assert_eq!(borrowed_query, owned_query);
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
            &[axfr_message(0x1234, vec![soa.clone(), ns, a, soa])],
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
                .offline_oracle()
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
    fn parses_multi_message_axfr_with_empty_later_question_sections() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let ns = apex_ns();
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let first = axfr_message(0x1234, vec![soa.clone(), ns]);
        let second = transfer_response_message_without_question(0x1234, vec![a, soa]);
        let snapshot = parse_axfr_response(0x1234, &apex, 1, &[first, second])
            .expect("multi-message AXFR with omitted later questions");

        assert_eq!(snapshot.state, crate::zone::ZoneState::Active);
        assert_eq!(snapshot.serial, Some(1));
        assert!(
            snapshot
                .offline_oracle()
                .lookup(
                    &DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers
                .len()
                == 1
        );
    }

    #[test]
    fn counts_streamed_axfr_apex_soa_case_insensitively() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let mixed_case_soa = record("EXAMPLE.TEST.", RecordType::Soa as u16, soa_rdata());
        let message = axfr_message(0x1234, vec![mixed_case_soa]);

        assert_eq!(
            axfr_response_message_apex_soa_count(0x1234, &apex, 1, &message, true)
                .expect("SOA count"),
            1
        );
    }

    #[test]
    fn rejects_axfr_without_initial_response_question() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let ns = apex_ns();
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[transfer_response_message_without_question(
                0x1234,
                vec![soa.clone(), ns, soa],
            )],
        )
        .expect_err("missing initial AXFR question");

        assert_eq!(error, AxfrError::MismatchedQuestion);
    }

    #[test]
    fn parses_axfr_and_normalizes_compressed_permitted_rdata_names() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let compressed_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            compressed_soa_rdata(),
        );
        let compressed_ns = record(
            "example.test.",
            RecordType::Ns as u16,
            compressed_apex_suffix_name_rdata("ns"),
        );
        let compressed_mx = record(
            "example.test.",
            RecordType::Mx as u16,
            mx_rdata(10, compressed_apex_suffix_name_rdata("mx")),
        );
        let compressed_cname = record(
            "alias.example.test.",
            RecordType::Cname as u16,
            compressed_apex_suffix_name_rdata("target"),
        );
        let opaque_unknown = record("opaque.example.test.", 65000, vec![0xc0, 0x0c]);
        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![
                    compressed_soa.clone(),
                    compressed_ns,
                    compressed_mx,
                    compressed_cname,
                    opaque_unknown,
                    compressed_soa,
                ],
            )],
        )
        .expect("AXFR with permitted compressed RDATA names");

        let mut expected_soa = name_rdata("example.test.");
        expected_soa.extend(name_rdata("example.test."));
        let base_soa = soa_rdata();
        let (_, consumed_mname) = DomainName::parse(&base_soa, 0).unwrap();
        let (_, consumed_rname) = DomainName::parse(&base_soa, consumed_mname).unwrap();
        expected_soa.extend_from_slice(&base_soa[consumed_mname + consumed_rname..]);
        assert_eq!(
            first_rdata(&snapshot, "example.test.", RecordType::Soa as u16),
            expected_soa
        );
        assert_eq!(
            first_rdata(&snapshot, "example.test.", RecordType::Ns as u16),
            name_rdata("ns.example.test.")
        );
        assert_eq!(
            first_rdata(&snapshot, "example.test.", RecordType::Mx as u16),
            mx_rdata(10, name_rdata("mx.example.test."))
        );
        assert_eq!(
            first_rdata(&snapshot, "alias.example.test.", RecordType::Cname as u16),
            name_rdata("target.example.test.")
        );
        assert_eq!(
            first_rdata(&snapshot, "opaque.example.test.", 65000),
            vec![0xc0, 0x0c]
        );
    }

    #[test]
    fn parses_axfr_unknown_types_as_opaque_rdata() {
        const UNKNOWN_TYPE: u16 = 65_280;
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let zero_rdata = record("opaque.example.test.", UNKNOWN_TYPE, Vec::new());
        let pointer_like_rdata = record(
            "opaque.example.test.",
            UNKNOWN_TYPE,
            vec![0xc0, 0x0c, 0, 255],
        );
        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), zero_rdata, pointer_like_rdata, soa],
            )],
        )
        .expect("AXFR with opaque unknown RDATA");

        let lookup = snapshot.offline_oracle().lookup(
            &DomainName::from_absolute_str("opaque.example.test.").unwrap(),
            UNKNOWN_TYPE,
            1,
        );
        let rdatas = lookup
            .answers
            .into_iter()
            .map(|record| record.rdata)
            .collect::<Vec<_>>();

        assert_eq!(rdatas, vec![Vec::new(), vec![0xc0, 0x0c, 0, 255]]);
    }

    #[test]
    fn accepts_axfr_dnssec_algorithm_numbers_opaquely() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let ds = record("child.example.test.", RecordType::Ds as u16, ds_rdata(253));
        let dnskey = record(
            "example.test.",
            RecordType::Dnskey as u16,
            dnskey_rdata(254),
        );
        let rrsig = record(
            "example.test.",
            RecordType::Rrsig as u16,
            rrsig_rdata_with_algorithm(RecordType::Dnskey, 255, name_rdata("example.test.")),
        );

        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![
                    soa.clone(),
                    apex_ns(),
                    ds.clone(),
                    dnskey.clone(),
                    rrsig.clone(),
                    soa,
                ],
            )],
        )
        .expect("AXFR should preserve DNSSEC algorithm fields opaquely");

        assert_eq!(
            first_rdata(&snapshot, "child.example.test.", RecordType::Ds as u16),
            ds.rdata
        );
        assert_eq!(
            first_rdata(&snapshot, "example.test.", RecordType::Dnskey as u16),
            dnskey.rdata
        );
        assert_eq!(
            first_rdata(&snapshot, "example.test.", RecordType::Rrsig as u16),
            rrsig.rdata
        );
    }

    #[test]
    fn parses_axfr_rrset_with_mismatched_ttls_using_lowest_ttl() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let first_a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let mut second_a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 11],
        );
        second_a.ttl = 120;
        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), first_a, second_a, soa],
            )],
        )
        .expect("AXFR with non-uniform RRset TTLs");

        let lookup = snapshot.offline_oracle().lookup(
            &DomainName::from_absolute_str("www.example.test.").unwrap(),
            RecordType::A as u16,
            1,
        );
        assert_eq!(lookup.answers.len(), 2);
        assert!(
            lookup.answers.iter().all(|record| record.ttl == 120),
            "all RRset members should use the adopted lowest TTL"
        );
    }

    #[test]
    fn rejects_axfr_message_not_marked_as_response() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut response = axfr_message(0x1234, vec![soa.clone(), apex_ns(), soa]);
        response[2] &= !0x80;

        let error = parse_axfr_response(0x1234, &apex, 1, &[response])
            .expect_err("AXFR envelope without QR response bit");

        assert_eq!(error, AxfrError::NotResponse);
    }

    #[test]
    fn rejects_axfr_response_with_mismatched_opcode() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut response = axfr_message(0x1234, vec![soa.clone(), apex_ns(), soa]);
        response[2] = 0x88;

        let error =
            parse_axfr_response(0x1234, &apex, 1, &[response]).expect_err("mismatched AXFR opcode");

        assert_eq!(error, AxfrError::MismatchedOpcode);
    }

    #[test]
    fn rejects_axfr_response_with_error_rcode() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut response = axfr_message(0x1234, vec![soa.clone(), apex_ns(), soa]);
        response[3] = 5;

        let error =
            parse_axfr_response(0x1234, &apex, 1, &[response]).expect_err("AXFR error RCODE");

        assert_eq!(error, AxfrError::ErrorRcode(5));
    }

    #[test]
    fn rejects_axfr_record_with_mismatched_class() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut wrong_class = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        wrong_class.class = 3;

        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), wrong_class, soa],
            )],
        )
        .expect_err("AXFR class mismatch");

        assert_eq!(error, AxfrError::ClassMismatch);
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
            &[ixfr_message(0x1234, vec![new_soa.clone(), ns, a, new_soa])],
        )
        .expect("mode 2 fallback");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert_eq!(snapshot.state, ZoneState::Active);
        assert_eq!(snapshot.serial, Some(1));
    }

    #[test]
    fn parses_ixfr_mode2_axfr_fallback_with_mixed_case_apex_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa]);
        let new_soa = record("EXAMPLE.TEST.", RecordType::Soa as u16, soa_rdata());
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
            &[ixfr_message(0x1234, vec![new_soa.clone(), ns, a, new_soa])],
        )
        .expect("mode 2 fallback with mixed-case apex SOA");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert_eq!(snapshot.state, ZoneState::Active);
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
            &[ixfr_message(0x1234, vec![current_soa.clone()])],
        )
        .expect("mode 3 current");

        assert_eq!(response, IxfrResponse::Current);
    }

    #[test]
    fn parses_ixfr_mode3_current_response_with_mixed_case_apex_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa]);
        let mixed_case_soa = record("EXAMPLE.TEST.", RecordType::Soa as u16, soa_rdata());
        let response = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[ixfr_message(0x1234, vec![mixed_case_soa])],
        )
        .expect("mode 3 current with mixed-case apex SOA");

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
            &[ixfr_message(0x9999, vec![current_soa])],
        )
        .expect_err("mismatched IXFR qid");

        assert_eq!(error, IxfrError::MismatchedQid);
    }

    #[test]
    fn rejects_ixfr_response_with_mismatched_question() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa.clone()]);
        let response = transfer_response_message(
            0x1234,
            "other.test.",
            RecordType::Ixfr as u16,
            1,
            vec![current_soa],
        );
        let error = parse_ixfr_response(0x1234, &apex, 1, &current_zone, &[response])
            .expect_err("mismatched IXFR question");

        assert_eq!(error, IxfrError::MismatchedQuestion);
    }

    #[test]
    fn rejects_ixfr_message_not_marked_as_response() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa.clone()]);
        let mut response = ixfr_message(0x1234, vec![current_soa]);
        response[2] &= !0x80;

        let error = parse_ixfr_response(0x1234, &apex, 1, &current_zone, &[response])
            .expect_err("IXFR envelope without QR response bit");

        assert_eq!(error, IxfrError::NotResponse);
    }

    #[test]
    fn rejects_ixfr_response_with_mismatched_opcode() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa.clone()]);
        let mut response = ixfr_message(0x1234, vec![current_soa]);
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
        let mut response = ixfr_message(0x1234, vec![current_soa]);
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

        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[ixfr_message(0x1234, vec![a])],
        )
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
            &[ixfr_message(0x1234, vec![newer_soa])],
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
            &[ixfr_message(
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
                .offline_oracle()
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
                .offline_oracle()
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
    fn parses_ixfr_mode1_incremental_diff_with_mixed_case_owners() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let old_a = record(
            "old.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let new_soa = record(
            "EXAMPLE.TEST.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let old_soa = record("EXAMPLE.TEST.", RecordType::Soa as u16, soa_rdata());
        let old_a_mixed = record(
            "OLD.EXAMPLE.TEST.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let new_a = record(
            "new.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 2],
        );
        let new_a_mixed = record(
            "NEW.EXAMPLE.TEST.",
            RecordType::A as u16,
            vec![192, 0, 2, 2],
        );
        let current_zone = current_zone(vec![current_soa, apex_ns(), old_a]);
        let response = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[ixfr_message(
                0x1234,
                vec![
                    new_soa.clone(),
                    old_soa,
                    old_a_mixed,
                    new_soa.clone(),
                    new_a_mixed,
                ],
            )],
        )
        .expect("mode 1 diff with mixed-case owners");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert!(
            snapshot
                .offline_oracle()
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
                .offline_oracle()
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
    fn parses_ixfr_mode1_incremental_diff_with_final_soa_terminator() {
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
            &[ixfr_message(
                0x1234,
                vec![
                    new_soa.clone(),
                    current_soa,
                    old_a,
                    new_soa.clone(),
                    new_a.clone(),
                    new_soa.clone(),
                ],
            )],
        )
        .expect("mode 1 diff with final SOA terminator");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert_eq!(snapshot.serial, Some(2));
        assert_eq!(
            snapshot
                .offline_oracle()
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
            &[ixfr_message(
                0x1234,
                vec![new_soa.clone(), current_soa, old_a, new_soa, new_a],
            )],
        )
        .expect_err("IXFR final zone missing apex NS");

        assert_eq!(error, IxfrError::Axfr(AxfrError::MissingApexNs));
    }

    #[test]
    fn rejects_ixfr_mode1_final_zone_with_non_apex_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let non_apex_soa = record("child.example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa.clone(), apex_ns(), non_apex_soa]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[ixfr_message(
                0x1234,
                vec![new_soa.clone(), current_soa, new_soa],
            )],
        )
        .expect_err("IXFR final zone with non-apex SOA");

        assert_eq!(error, IxfrError::Axfr(AxfrError::InvalidZoneSoa));
    }

    #[test]
    fn rejects_ixfr_mode1_final_zone_with_multiple_apex_soas() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let extra_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(99),
        );
        let current_zone = current_zone(vec![current_soa.clone(), apex_ns(), extra_soa]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[ixfr_message(
                0x1234,
                vec![new_soa.clone(), current_soa, new_soa],
            )],
        )
        .expect_err("IXFR final zone with multiple apex SOAs");

        assert_eq!(error, IxfrError::Axfr(AxfrError::InvalidZoneSoa));
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
            &[ixfr_message(
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
            &[ixfr_message(
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
            &[ixfr_message(
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
            &[ixfr_message(
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
            &[ixfr_message(
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
            &[ixfr_message(
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
            &[ixfr_message(
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
            &[ixfr_message(
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
            &[ixfr_message(
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
            &[ixfr_message(
                0x1234,
                vec![new_soa.clone(), current_soa, reserved, new_soa],
            )],
        )
        .expect_err("IXFR reserved type");

        assert_eq!(error, IxfrError::Axfr(AxfrError::ReservedType));
    }

    #[test]
    fn rejects_ixfr_pseudo_and_transfer_meta_record_types() {
        for rr_type in [
            RecordType::Opt as u16,
            RecordType::Tkey as u16,
            RecordType::Tsig as u16,
            RecordType::Ixfr as u16,
            RecordType::Axfr as u16,
            253,
            254,
            255,
        ] {
            let apex = DomainName::from_absolute_str("example.test.").unwrap();
            let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
            let new_soa = record(
                "example.test.",
                RecordType::Soa as u16,
                soa_rdata_with_serial(2),
            );
            let prohibited = record("www.example.test.", rr_type, vec![0]);
            let current_zone = current_zone(vec![current_soa.clone()]);
            let error = parse_ixfr_response(
                0x1234,
                &apex,
                1,
                &current_zone,
                &[ixfr_message(
                    0x1234,
                    vec![new_soa.clone(), current_soa, prohibited, new_soa],
                )],
            )
            .expect_err("IXFR prohibited type");

            assert_eq!(
                error,
                IxfrError::Axfr(AxfrError::ProhibitedType),
                "RR type {rr_type}"
            );
        }
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
    fn accepts_soa_response_question_qname_case_insensitively() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let response = transfer_response_message(
            0x1234,
            "EXAMPLE.TEST.",
            RecordType::Soa as u16,
            1,
            vec![soa],
        );
        let serial = parse_soa_response(0x1234, &apex, 1, &response)
            .expect("SOA response question comparison is case-insensitive");

        assert_eq!(serial, 1);
    }

    #[test]
    fn accepts_soa_response_answer_owner_case_insensitively() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("EXAMPLE.TEST.", RecordType::Soa as u16, soa_rdata());
        let serial = parse_soa_response(0x1234, &apex, 1, &soa_message(0x1234, vec![soa]))
            .expect("SOA answer owner comparison is case-insensitive");

        assert_eq!(serial, 1);
    }

    #[test]
    fn rejects_truncated_soa_response() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut response = soa_message(0x1234, vec![soa]);
        response[2] |= 0x02;
        let error =
            parse_soa_response(0x1234, &apex, 1, &response).expect_err("truncated SOA response");

        assert_eq!(error, SoaQueryError::Truncated);
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
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(0x9999, vec![soa.clone(), soa])],
        )
        .expect_err("mismatched qid");
        assert_eq!(error, AxfrError::MismatchedQid);
    }

    #[test]
    fn rejects_axfr_response_with_mismatched_question() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let response = transfer_response_message(
            0x1234,
            "other.test.",
            RecordType::Axfr as u16,
            1,
            vec![soa.clone(), soa],
        );
        let error = parse_axfr_response(0x1234, &apex, 1, &[response])
            .expect_err("mismatched AXFR question");

        assert_eq!(error, AxfrError::MismatchedQuestion);
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
            &[axfr_message(0x1234, vec![soa.clone(), a, soa])],
        )
        .expect_err("missing apex NS");

        assert_eq!(error, AxfrError::MissingApexNs);
    }

    #[test]
    fn accepts_axfr_apex_soa_and_ns_owners_case_insensitively() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("EXAMPLE.TEST.", RecordType::Soa as u16, soa_rdata());
        let ns = record(
            "Example.Test.",
            RecordType::Ns as u16,
            name_rdata("ns.example.test."),
        );
        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(0x1234, vec![soa.clone(), ns, soa])],
        )
        .expect("mixed-case apex SOA and NS owners");

        assert_eq!(snapshot.serial, Some(1));
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
            &[ixfr_message(0x1234, vec![new_soa.clone(), a, new_soa])],
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
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), cname, a, soa],
            )],
        )
        .expect_err("CNAME with non-DNSSEC data");

        assert_eq!(error, AxfrError::CnameCoexistsWithOtherData);
    }

    #[test]
    fn rejects_axfr_cname_with_mixed_case_non_dnssec_data() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let cname = record(
            "ALIAS.example.test.",
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
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), cname, a, soa],
            )],
        )
        .expect_err("mixed-case CNAME with non-DNSSEC data");

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
        let rrsig = record(
            "alias.example.test.",
            RecordType::Rrsig as u16,
            rrsig_rdata(name_rdata("example.test.")),
        );
        let nsec = record(
            "alias.example.test.",
            RecordType::Nsec as u16,
            nsec_rdata(name_rdata("next.example.test.")),
        );
        let nsec3 = record(
            "alias.example.test.",
            RecordType::Nsec3 as u16,
            nsec3_rdata(&[0, 1, 1]),
        );
        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
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
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), dname, cname, soa],
            )],
        )
        .expect_err("DNAME with CNAME data");

        assert_eq!(error, AxfrError::DnameCoexistsWithCname);
    }

    #[test]
    fn rejects_axfr_dname_with_mixed_case_cname_data() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let dname = record(
            "Redirect.example.test.",
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
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), dname, cname, soa],
            )],
        )
        .expect_err("mixed-case DNAME with CNAME data");

        assert_eq!(error, AxfrError::DnameCoexistsWithCname);
    }

    #[test]
    fn rejects_axfr_multiple_dname_records_for_owner() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let first = record(
            "redirect.example.test.",
            RecordType::Dname as u16,
            name_rdata("target.example.test."),
        );
        let second = record(
            "redirect.example.test.",
            RecordType::Dname as u16,
            name_rdata("other.example.test."),
        );
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), first, second, soa],
            )],
        )
        .expect_err("multiple DNAME records");

        assert_eq!(error, AxfrError::MultipleDnameRecords);
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
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), bad_a, soa],
            )],
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
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), bad_aaaa, soa],
            )],
        )
        .expect_err("invalid AAAA RDATA length");

        assert_eq!(error, AxfrError::InvalidRdata);
    }

    #[test]
    fn rejects_axfr_txt_with_invalid_character_string_rdata() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let cases = [
            (Vec::new(), "empty TXT RDATA"),
            (vec![3, b'f', b'o'], "truncated TXT character-string"),
        ];

        for (rdata, context) in cases {
            let bad_txt = record("txt.example.test.", RecordType::Txt as u16, rdata);
            let error = parse_axfr_response(
                0x1234,
                &apex,
                1,
                &[axfr_message(
                    0x1234,
                    vec![soa.clone(), apex_ns(), bad_txt, soa.clone()],
                )],
            )
            .expect_err(context);

            assert_eq!(error, AxfrError::InvalidRdata, "{context}");
        }
    }

    #[test]
    fn rejects_axfr_hinfo_with_wrong_character_string_count() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let cases = [
            (vec![3, b'c', b'p', b'u'], "single HINFO string"),
            (vec![0, 0, 0], "three HINFO strings"),
        ];

        for (rdata, context) in cases {
            let bad_hinfo = record("host.example.test.", RecordType::Hinfo as u16, rdata);
            let error = parse_axfr_response(
                0x1234,
                &apex,
                1,
                &[axfr_message(
                    0x1234,
                    vec![soa.clone(), apex_ns(), bad_hinfo, soa.clone()],
                )],
            )
            .expect_err(context);

            assert_eq!(error, AxfrError::InvalidRdata, "{context}");
        }
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
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), dname, soa],
            )],
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
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), dname, soa],
            )],
        )
        .expect_err("DNAME with compressed target RDATA");

        assert_eq!(error, AxfrError::InvalidRdata);
    }

    #[test]
    fn rejects_axfr_post_rfc3597_compressed_name_rdata() {
        let compressed_name = vec![0xc0, 0];
        let cases = [
            (
                RecordType::Srv as u16,
                srv_rdata(compressed_name.clone()),
                "SRV compressed target",
            ),
            (
                RecordType::Naptr as u16,
                naptr_rdata(compressed_name.clone()),
                "NAPTR compressed replacement",
            ),
            (
                RecordType::Rrsig as u16,
                rrsig_rdata(compressed_name.clone()),
                "RRSIG compressed signer",
            ),
            (
                RecordType::Nsec as u16,
                nsec_rdata(compressed_name.clone()),
                "NSEC compressed next domain",
            ),
            (
                RecordType::Svcb as u16,
                svcb_rdata(1, compressed_name.clone(), &[]),
                "SVCB compressed target",
            ),
            (
                RecordType::Https as u16,
                svcb_rdata(1, compressed_name, &[]),
                "HTTPS compressed target",
            ),
        ];

        for (rr_type, rdata, context) in cases {
            let apex = DomainName::from_absolute_str("example.test.").unwrap();
            let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
            let invalid = record("www.example.test.", rr_type, rdata);
            let error = parse_axfr_response(
                0x1234,
                &apex,
                1,
                &[axfr_message(
                    0x1234,
                    vec![soa.clone(), apex_ns(), invalid, soa],
                )],
            )
            .expect_err(context);

            assert_eq!(error, AxfrError::InvalidRdata, "{context}");
        }
    }

    #[test]
    fn rejects_axfr_nsec_with_malformed_type_bit_maps() {
        let cases = [
            (
                nsec_rdata_with_bit_maps(name_rdata("next.example.test."), &[]),
                "missing NSEC bitmap",
            ),
            (
                nsec_rdata_with_bit_maps(name_rdata("next.example.test."), &[0]),
                "truncated NSEC window header",
            ),
            (
                nsec_rdata_with_bit_maps(name_rdata("next.example.test."), &[0, 0]),
                "zero-length NSEC bitmap",
            ),
            (
                nsec_rdata_with_bit_maps(name_rdata("next.example.test."), &[0, 33, 1]),
                "overlong NSEC bitmap",
            ),
            (
                nsec_rdata_with_bit_maps(name_rdata("next.example.test."), &[0, 2, 0x80, 0]),
                "NSEC bitmap with trailing zero octet",
            ),
            (
                nsec_rdata_with_bit_maps(name_rdata("next.example.test."), &[1, 1, 1, 0, 1, 1]),
                "out-of-order NSEC bitmap windows",
            ),
        ];

        for (rdata, context) in cases {
            let apex = DomainName::from_absolute_str("example.test.").unwrap();
            let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
            let invalid = record("www.example.test.", RecordType::Nsec as u16, rdata);
            let error = parse_axfr_response(
                0x1234,
                &apex,
                1,
                &[axfr_message(
                    0x1234,
                    vec![soa.clone(), apex_ns(), invalid, soa],
                )],
            )
            .expect_err(context);

            assert_eq!(error, AxfrError::InvalidRdata, "{context}");
        }
    }

    #[test]
    fn rejects_axfr_nsec3_with_malformed_hash_or_type_bit_maps() {
        let cases = [
            (vec![1, 0, 0, 0, 0], "missing NSEC3 hash length"),
            (vec![1, 0, 0, 0, 0, 0], "zero NSEC3 hash length"),
            (vec![1, 0, 0, 0, 0, 2, 0], "truncated NSEC3 next hash"),
            (nsec3_rdata(&[0, 0]), "zero-length NSEC3 bitmap"),
            (nsec3_rdata(&[0, 33, 1]), "overlong NSEC3 bitmap"),
            (
                nsec3_rdata(&[0, 2, 0x80, 0]),
                "NSEC3 bitmap with trailing zero octet",
            ),
            (
                nsec3_rdata(&[1, 1, 1, 0, 1, 1]),
                "out-of-order NSEC3 bitmap windows",
            ),
        ];

        for (rdata, context) in cases {
            let apex = DomainName::from_absolute_str("example.test.").unwrap();
            let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
            let invalid = record("hash.example.test.", RecordType::Nsec3 as u16, rdata);
            let error = parse_axfr_response(
                0x1234,
                &apex,
                1,
                &[axfr_message(
                    0x1234,
                    vec![soa.clone(), apex_ns(), invalid, soa],
                )],
            )
            .expect_err(context);

            assert_eq!(error, AxfrError::InvalidRdata, "{context}");
        }
    }

    #[test]
    fn accepts_axfr_nsec3_with_empty_type_bit_maps() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let nsec3 = record(
            "hash.example.test.",
            RecordType::Nsec3 as u16,
            nsec3_rdata(&[]),
        );

        parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), nsec3, soa],
            )],
        )
        .expect("NSEC3 for an empty non-terminal may have an empty type bitmap");
    }

    #[test]
    fn rejects_axfr_simple_known_types_with_invalid_rdata() {
        let cases = [
            (
                RecordType::Ds as u16,
                vec![0, 1, 8],
                "DS missing digest type",
            ),
            (
                RecordType::Dnskey as u16,
                vec![1, 0, 3],
                "DNSKEY missing algorithm",
            ),
            (
                RecordType::Dnskey as u16,
                vec![1, 0, 2, 8],
                "DNSKEY protocol is not 3",
            ),
            (
                RecordType::Nsec3Param as u16,
                vec![1, 0, 0, 0],
                "NSEC3PARAM missing salt length",
            ),
            (
                RecordType::Nsec3Param as u16,
                vec![1, 0, 0, 0, 2, 0],
                "NSEC3PARAM truncated salt",
            ),
            (
                RecordType::Tlsa as u16,
                vec![3, 1],
                "TLSA missing matching type",
            ),
            (
                RecordType::Uri as u16,
                vec![0, 10, 0, 20],
                "URI missing target",
            ),
        ];

        for (rr_type, rdata, context) in cases {
            let apex = DomainName::from_absolute_str("example.test.").unwrap();
            let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
            let invalid = record("www.example.test.", rr_type, rdata);
            let error = parse_axfr_response(
                0x1234,
                &apex,
                1,
                &[axfr_message(
                    0x1234,
                    vec![soa.clone(), apex_ns(), invalid, soa],
                )],
            )
            .expect_err(context);

            assert_eq!(error, AxfrError::InvalidRdata, "{context}");
        }
    }

    #[test]
    fn accepts_axfr_uri_with_raw_target_octets() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let uri = record(
            "uri.example.test.",
            RecordType::Uri as u16,
            vec![
                0, 10, 0, 20, b'h', b't', b't', b'p', b's', b':', b'/', b'/', b'e', b'x',
            ],
        );

        parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(0x1234, vec![soa.clone(), apex_ns(), uri, soa])],
        )
        .expect("URI target is raw RFC 7553 octets, not DNS character-string RDATA");
    }

    #[test]
    fn rejects_axfr_malformed_svcb_params() {
        let cases = [
            (
                svcb_rdata(1, name_rdata("svc.example.test."), &[0, 1, 0, 4, 1]),
                "truncated SVCB param",
            ),
            (
                svcb_rdata(0, name_rdata("alias.example.test."), &[0, 1, 0, 0]),
                "AliasMode SVCB with params",
            ),
            (
                svcb_rdata(
                    1,
                    name_rdata("svc.example.test."),
                    &[0, 2, 0, 0, 0, 1, 0, 0],
                ),
                "out-of-order SVCB params",
            ),
        ];

        for (rdata, context) in cases {
            let apex = DomainName::from_absolute_str("example.test.").unwrap();
            let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
            let invalid = record("svc.example.test.", RecordType::Svcb as u16, rdata);
            let error = parse_axfr_response(
                0x1234,
                &apex,
                1,
                &[axfr_message(
                    0x1234,
                    vec![soa.clone(), apex_ns(), invalid, soa],
                )],
            )
            .expect_err(context);

            assert_eq!(error, AxfrError::InvalidRdata, "{context}");
        }
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
    fn rejects_soa_response_with_pseudo_or_transfer_meta_answer_type() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let prohibited = record("www.example.test.", RecordType::Tsig as u16, vec![0]);
        let error = parse_soa_response(0x1234, &apex, 1, &soa_message(0x1234, vec![prohibited]))
            .expect_err("prohibited SOA answer type");

        assert_eq!(error, SoaQueryError::ProhibitedType);
    }

    #[test]
    fn rejects_axfr_pseudo_and_transfer_meta_record_types() {
        for rr_type in [
            RecordType::Opt as u16,
            RecordType::Tkey as u16,
            RecordType::Tsig as u16,
            RecordType::Ixfr as u16,
            RecordType::Axfr as u16,
            253,
            254,
            255,
        ] {
            let apex = DomainName::from_absolute_str("example.test.").unwrap();
            let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
            let prohibited = record("www.example.test.", rr_type, vec![0]);
            let error = parse_axfr_response(
                0x1234,
                &apex,
                1,
                &[axfr_message(
                    0x1234,
                    vec![soa.clone(), apex_ns(), prohibited, soa],
                )],
            )
            .expect_err("AXFR prohibited type");

            assert_eq!(error, AxfrError::ProhibitedType, "RR type {rr_type}");
        }
    }

    #[test]
    fn rejects_missing_initial_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let error = parse_axfr_response(0x1234, &apex, 1, &[axfr_message(0x1234, vec![a])])
            .expect_err("bad AXFR");
        assert_eq!(error, AxfrError::MissingInitialSoa);
    }

    #[test]
    fn rejects_mismatched_terminating_soa() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut other_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        other_soa.ttl = 301;
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(0x1234, vec![soa, other_soa])],
        )
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
            &[axfr_message(0x1234, vec![soa.clone(), soa, a])],
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
            &[axfr_message(0x1234, vec![soa.clone(), out, soa])],
        )
        .expect_err("out-of-zone record");
        assert_eq!(error, AxfrError::OutOfZoneOwner);
    }

    #[test]
    fn accepted_axfr_snapshot_compiles_for_publication() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );

        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(0x1234, vec![soa.clone(), apex_ns(), a, soa])],
        )
        .expect("accepted AXFR parses");

        ZoneImage::compile(&snapshot).expect("accepted AXFR snapshot compiles for publication");
    }
}
