use std::{
    collections::{BTreeSet, HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
};

use thiserror::Error;
use tracing::warn;

use crate::{
    dns::{DNS_HEADER_LEN, DnsParseError, DomainName, Header, RecordType},
    zone::{ResourceRecord, Rrset, SoaRecordView, ZoneSnapshot},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferExtendedDnsError {
    pub info_code: u16,
    pub extra_text: String,
}

// BDS-NFR-MAINT-004 principal functional requirement references for zone
// transfer parsing, outbound response validation, unknown RR handling, and
// transferred RR catalogue validation:
// - BDS-FR-SPOOF-001 BDS-FR-SPOOF-002 BDS-FR-SPOOF-003
// - BDS-FR-SPOOF-004 BDS-FR-SPOOF-005 BDS-FR-SPOOF-006
// - BDS-FR-SPOOF-007
// - BDS-FR-AXFR-001 BDS-FR-AXFR-002 BDS-FR-AXFR-003 BDS-FR-AXFR-004
// - BDS-FR-AXFR-005 BDS-FR-AXFR-006 BDS-FR-AXFR-007 BDS-FR-AXFR-008
// - BDS-FR-AXFR-009 BDS-FR-AXFR-010 BDS-FR-AXFR-011 BDS-FR-AXFR-012
// - BDS-FR-AXFR-013 BDS-FR-AXFR-014 BDS-FR-AXFR-015 BDS-FR-AXFR-016
// - BDS-FR-AXFR-017 BDS-FR-AXFR-018 BDS-FR-AXFR-019 BDS-FR-AXFR-020
// - BDS-FR-AXFR-021 BDS-FR-AXFR-022 BDS-FR-AXFR-023 BDS-FR-AXFR-024
// - BDS-FR-AXFR-025 BDS-FR-AXFR-026
// - BDS-FR-IXFR-001 BDS-FR-IXFR-002 BDS-FR-IXFR-003 BDS-FR-IXFR-004
// - BDS-FR-IXFR-005 BDS-FR-IXFR-006 BDS-FR-IXFR-007 BDS-FR-IXFR-008
// - BDS-FR-IXFR-009 BDS-FR-IXFR-010 BDS-FR-IXFR-011 BDS-FR-IXFR-012
// - BDS-FR-IXFR-013 BDS-FR-IXFR-014 BDS-FR-IXFR-015 BDS-FR-IXFR-016
// - BDS-FR-IXFR-017 BDS-FR-IXFR-018 BDS-FR-IXFR-019
// - BDS-FR-URR-001 BDS-FR-URR-002 BDS-FR-URR-003 BDS-FR-URR-004
// - BDS-FR-URR-005 BDS-FR-URR-006 BDS-FR-URR-007 BDS-FR-URR-008
// - BDS-FR-URR-009
// - BDS-FR-RR-001 BDS-FR-RR-002 BDS-FR-RR-003 BDS-FR-RR-004
// - BDS-FR-RR-005 BDS-FR-RR-006 BDS-FR-RR-007
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TcpFrameError {
    #[error("DNS message length {length} exceeds the 65,535-byte TCP frame limit")]
    MessageTooLong { length: usize },
}

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

    #[error("AXFR response returned error RCODE {rcode} with EDE {ede:?}")]
    ErrorRcodeWithEde {
        rcode: u8,
        ede: TransferExtendedDnsError,
    },

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

    #[error("AXFR response contained a CNAME RRset with multiple distinct records")]
    MultipleCnameRecords,

    #[error("AXFR response contained a DNAME owner with CNAME data")]
    DnameCoexistsWithCname,

    #[error("AXFR response contained a DNAME RRset with multiple records")]
    MultipleDnameRecords,

    #[error("AXFR response contained DNAME and NS at the same non-apex owner")]
    DnameCoexistsWithNs,
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

    #[error("SOA response returned error RCODE {rcode} with EDE {ede:?}")]
    ErrorRcodeWithEde {
        rcode: u8,
        ede: TransferExtendedDnsError,
    },

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

    #[error("IXFR response returned error RCODE {rcode} with EDE {ede:?}")]
    ErrorRcodeWithEde {
        rcode: u8,
        ede: TransferExtendedDnsError,
    },

    #[error("IXFR response question does not match the IXFR query")]
    MismatchedQuestion,

    #[error("IXFR response did not start with SOA at the zone apex")]
    MissingInitialSoa,

    #[error("IXFR response ended before a complete mode could be determined")]
    IncompleteResponse,

    #[error("IXFR response difference sequence does not chain SOA serials correctly")]
    BrokenSoaChain,

    #[error("IXFR response serial does not advance under RFC 1982 arithmetic")]
    SerialNotForward,

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IxfrDelta {
    old_serial: u32,
    new_serial: u32,
    sequences: Vec<IxfrDeltaSequence>,
    affected_rrsets: Vec<(String, u16, u16)>,
}

impl IxfrDelta {
    pub fn old_serial(&self) -> u32 {
        self.old_serial
    }

    pub fn new_serial(&self) -> u32 {
        self.new_serial
    }

    pub fn sequences(&self) -> &[IxfrDeltaSequence] {
        &self.sequences
    }

    pub fn affected_rrsets(&self) -> &[(String, u16, u16)] {
        &self.affected_rrsets
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IxfrDeltaSequence {
    old_soa: ResourceRecord,
    deletes: Vec<ResourceRecord>,
    new_soa: ResourceRecord,
    adds: Vec<ResourceRecord>,
}

impl IxfrDeltaSequence {
    pub fn old_soa(&self) -> &ResourceRecord {
        &self.old_soa
    }

    pub fn deletes(&self) -> &[ResourceRecord] {
        &self.deletes
    }

    pub fn new_soa(&self) -> &ResourceRecord {
        &self.new_soa
    }

    pub fn adds(&self) -> &[ResourceRecord] {
        &self.adds
    }
}

pub fn build_axfr_query(qid: u16, zone_apex: &DomainName, qclass: u16) -> Vec<u8> {
    build_query(qid, zone_apex, RecordType::Axfr as u16, qclass)
}

pub fn build_soa_query(qid: u16, zone_apex: &DomainName, qclass: u16) -> Vec<u8> {
    build_query(qid, zone_apex, RecordType::Soa as u16, qclass)
}

/// Adds the EDNS(0) OPT required for DNS-over-TLS transfer requests by RFC 9103.
/// Call this before appending TSIG so TSIG remains the final Additional record.
pub fn append_xot_opt(message: &mut Vec<u8>) {
    debug_assert!(message.len() >= DNS_HEADER_LEN);
    let arcount = u16::from_be_bytes([message[10], message[11]]);
    message[10..12].copy_from_slice(&arcount.saturating_add(1).to_be_bytes());
    message.push(0);
    message.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
    message.extend_from_slice(&1232u16.to_be_bytes());
    message.extend_from_slice(&0u32.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
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

pub fn frame_tcp_message(message: &[u8]) -> Result<Vec<u8>, TcpFrameError> {
    let length = u16::try_from(message.len()).map_err(|_| TcpFrameError::MessageTooLong {
        length: message.len(),
    })?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(message);
    Ok(framed)
}

pub fn parse_axfr_response(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    messages: &[Vec<u8>],
) -> Result<ZoneSnapshot, AxfrError> {
    parse_axfr_response_with_question(qid, zone_apex, qclass, RecordType::Axfr as u16, messages)
}

/// Revalidate records decoded from a durable last-good zone image before
/// allowing them back into the authoritative store after restart.
pub fn validated_persisted_zone_snapshot(
    zone_apex: &DomainName,
    qclass: u16,
    serial: Option<u32>,
    mut records: Vec<ResourceRecord>,
) -> Result<ZoneSnapshot, AxfrError> {
    for record in &mut records {
        validate_record_scope(record, zone_apex, qclass)?;
        normalize_record_owner(record);
    }
    validate_zone_record_set(zone_apex, &records)?;
    let soa_serial = records
        .iter()
        .find(|record| {
            record.rr_type == RecordType::Soa as u16
                && record.owner.canonical_key() == zone_apex.canonical_key()
        })
        .ok_or(AxfrError::InvalidZoneSoa)
        .and_then(|record| soa_serial(&record.rdata))?;
    if serial != Some(soa_serial) {
        return Err(AxfrError::InvalidZoneSoa);
    }
    Ok(ZoneSnapshot::active(
        zone_apex.to_ascii_lowercased(),
        Some(soa_serial),
        rrsets_from_records(records),
    ))
}

pub fn axfr_response_message_apex_soa_count(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    message: &[u8],
    require_question: bool,
) -> Result<usize, AxfrError> {
    axfr_response_message_probe(qid, zone_apex, qclass, message, require_question)
        .map(|probe| probe.apex_soa_count)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxfrMessageProbe {
    pub apex_soa_count: usize,
    pub saw_response_question: bool,
}

pub fn axfr_response_message_probe(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    message: &[u8],
    require_question: bool,
) -> Result<AxfrMessageProbe, AxfrError> {
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
        return Err(axfr_rcode_error(rcode, message, &header));
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
    Ok(AxfrMessageProbe {
        apex_soa_count,
        saw_response_question: header.qdcount == 1,
    })
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
            return Err(axfr_rcode_error(rcode, message, &header));
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
                    Some(initial) if resource_records_semantically_equal(&record, initial) => {
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
        ensure_no_authority_and_only_opt_additional(
            message,
            offset,
            header.nscount,
            header.arcount,
        )?;
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
        return Err(soa_rcode_error(rcode, message, &header));
    }

    let mut offset = validate_soa_response_question(message, header.qdcount, zone_apex, qclass)?;
    let mut serial = None;
    for _ in 0..header.ancount {
        let (record, consumed) =
            parse_record(message, offset).map_err(|_| SoaQueryError::MalformedMessage)?;
        offset += consumed;

        validate_soa_answer_scope(&record, zone_apex, qclass)?;
        if record.owner.canonical_key() == zone_apex.canonical_key()
            && record.rr_type == RecordType::Soa as u16
        {
            serial = Some(soa_serial(&record.rdata).map_err(|_| SoaQueryError::MalformedMessage)?);
        }
    }
    skip_authority_additional_and_ensure_end(message, offset, header.nscount, header.arcount)
        .map_err(|_| SoaQueryError::MalformedMessage)?;

    serial.ok_or(SoaQueryError::MissingSoa)
}

pub fn parse_ixfr_response(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    current_zone: &ZoneSnapshot,
    messages: &[Vec<u8>],
) -> Result<IxfrResponse, IxfrError> {
    let mut current_soa = current_zone
        .transfer_soa_record(qclass)
        .ok_or(IxfrError::InvalidCurrentSoa)?;
    normalize_record_owner(&mut current_soa);
    validate_current_soa(&current_soa, zone_apex, qclass)?;
    if messages.is_empty() {
        return Err(IxfrError::EmptyResponse);
    }

    let mut answers = Vec::new();
    let mut saw_response_question = false;
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
            return Err(ixfr_rcode_error(rcode, message, &header));
        }

        let mut offset = validate_ixfr_response_question(
            message,
            header.qdcount,
            zone_apex,
            RecordType::Ixfr as u16,
            qclass,
            !saw_response_question,
        )?;
        if header.qdcount == 1 {
            saw_response_question = true;
        }
        for _ in 0..header.ancount {
            let (mut record, consumed) =
                parse_record(message, offset).map_err(|_| IxfrError::MalformedMessage)?;
            offset += consumed;
            validate_record_scope(&record, zone_apex, qclass).map_err(ixfr_scope_error)?;
            normalize_record_owner(&mut record);
            answers.push(record);
        }
        ensure_no_authority_and_only_opt_additional(
            message,
            offset,
            header.nscount,
            header.arcount,
        )
        .map_err(|_| IxfrError::MalformedMessage)?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IxfrMessageProbe {
    pub answers: Vec<IxfrProbeAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IxfrProbeAnswer {
    pub apex_soa_serial: Option<u32>,
    pub apex_soa_rdata: Option<Vec<u8>>,
}

pub fn ixfr_response_message_probe(
    qid: u16,
    zone_apex: &DomainName,
    qclass: u16,
    message: &[u8],
) -> Result<IxfrMessageProbe, IxfrError> {
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
        return Err(ixfr_rcode_error(rcode, message, &header));
    }

    let mut offset = validate_ixfr_response_question(
        message,
        header.qdcount,
        zone_apex,
        RecordType::Ixfr as u16,
        qclass,
        false,
    )?;
    let mut answers = Vec::with_capacity(header.ancount as usize);
    let apex_key = zone_apex.canonical_key();
    for _ in 0..header.ancount {
        let (record, consumed) =
            parse_record(message, offset).map_err(|_| IxfrError::MalformedMessage)?;
        offset += consumed;
        validate_record_scope(&record, zone_apex, qclass).map_err(ixfr_scope_error)?;
        let is_apex_soa =
            record.rr_type == RecordType::Soa as u16 && record.owner.canonical_key() == apex_key;
        let (apex_soa_serial, apex_soa_rdata) = if is_apex_soa {
            (
                Some(soa_serial(&record.rdata).map_err(|_| IxfrError::MalformedMessage)?),
                Some(record.rdata.clone()),
            )
        } else {
            (None, None)
        };
        answers.push(IxfrProbeAnswer {
            apex_soa_serial,
            apex_soa_rdata,
        });
    }

    Ok(IxfrMessageProbe { answers })
}

fn apply_ixfr_incremental(
    zone_apex: &DomainName,
    qclass: u16,
    current_zone: &ZoneSnapshot,
    answers: &[ResourceRecord],
) -> Result<IxfrResponse, IxfrError> {
    let mut current_soa = current_zone
        .transfer_soa_record(qclass)
        .ok_or(IxfrError::InvalidCurrentSoa)?;
    normalize_record_owner(&mut current_soa);
    let (delta, terminal_soa_seen) =
        parse_ixfr_incremental_delta_parts(zone_apex, qclass, &current_soa, answers)?;
    let mut working_rrsets = HashMap::<(String, u16, u16), Vec<ResourceRecord>>::new();

    for sequence in delta.sequences() {
        remove_delta_record(current_zone, &mut working_rrsets, sequence.old_soa())?;
        for record in sequence.deletes() {
            remove_delta_record(current_zone, &mut working_rrsets, record)?;
        }
        add_delta_record(current_zone, &mut working_rrsets, sequence.new_soa())?;
        for record in sequence.adds() {
            add_delta_record(current_zone, &mut working_rrsets, record)?;
        }
    }
    if !terminal_soa_seen {
        return Err(IxfrError::IncompleteResponse);
    }
    let replacements = working_rrsets
        .into_iter()
        .map(|((owner_key, rr_type, class), records)| {
            let mut rrsets = rrsets_from_records(records);
            debug_assert!(rrsets.len() <= 1);
            (owner_key, rr_type, class, rrsets.pop())
        })
        .collect();
    let updated = current_zone.with_cow_rrset_replacements(delta.new_serial(), replacements);
    validate_incremental_zone(zone_apex, qclass, &updated, &delta)?;

    Ok(IxfrResponse::Updated(Box::new(updated)))
}

fn remove_delta_record(
    current_zone: &ZoneSnapshot,
    working_rrsets: &mut HashMap<(String, u16, u16), Vec<ResourceRecord>>,
    record: &ResourceRecord,
) -> Result<(), IxfrError> {
    let key = rrset_identity(record);
    let records = working_rrsets
        .entry(key.clone())
        .or_insert_with(|| current_zone.transfer_rrset_records_by_key(&key.0, key.1, key.2));
    let Some(index) = records
        .iter()
        .position(|existing| resource_records_semantically_equal(existing, record))
    else {
        return Err(IxfrError::DeleteAbsentRecord);
    };
    records.swap_remove(index);
    Ok(())
}

fn add_delta_record(
    current_zone: &ZoneSnapshot,
    working_rrsets: &mut HashMap<(String, u16, u16), Vec<ResourceRecord>>,
    record: &ResourceRecord,
) -> Result<(), IxfrError> {
    let key = rrset_identity(record);
    let records = working_rrsets
        .entry(key.clone())
        .or_insert_with(|| current_zone.transfer_rrset_records_by_key(&key.0, key.1, key.2));
    if records
        .iter()
        .any(|existing| resource_records_semantically_equal(existing, record))
    {
        return Err(IxfrError::AddExistingRecord);
    }
    records.push(record.clone());
    Ok(())
}

fn validate_incremental_zone(
    zone_apex: &DomainName,
    qclass: u16,
    updated: &ZoneSnapshot,
    delta: &IxfrDelta,
) -> Result<(), IxfrError> {
    let apex_key = zone_apex.canonical_key();
    let soa = updated.transfer_rrset_records_by_key(&apex_key, RecordType::Soa as u16, qclass);
    if soa.len() != 1 || updated.soa_record_count() != 1 {
        return Err(IxfrError::Axfr(AxfrError::InvalidZoneSoa));
    }
    if updated
        .transfer_rrset_records_by_key(&apex_key, RecordType::Ns as u16, qclass)
        .is_empty()
    {
        return Err(IxfrError::Axfr(AxfrError::MissingApexNs));
    }

    let affected_owners = delta
        .affected_rrsets()
        .iter()
        .map(|(owner, _, _)| owner.as_str())
        .collect::<BTreeSet<_>>();
    let affected_records = affected_owners
        .into_iter()
        .flat_map(|owner| updated.transfer_records_at_name_key(owner))
        .collect::<Vec<_>>();
    validate_cname_and_dname_coexistence(zone_apex, &affected_records).map_err(IxfrError::Axfr)
}

#[cfg(test)]
fn parse_ixfr_incremental_delta(
    zone_apex: &DomainName,
    qclass: u16,
    current_soa: &ResourceRecord,
    answers: &[ResourceRecord],
) -> Result<IxfrDelta, IxfrError> {
    let (delta, terminal_soa_seen) =
        parse_ixfr_incremental_delta_parts(zone_apex, qclass, current_soa, answers)?;
    if !terminal_soa_seen {
        return Err(IxfrError::IncompleteResponse);
    }
    Ok(delta)
}

fn parse_ixfr_incremental_delta_parts(
    zone_apex: &DomainName,
    qclass: u16,
    current_soa: &ResourceRecord,
    answers: &[ResourceRecord],
) -> Result<(IxfrDelta, bool), IxfrError> {
    validate_current_soa(current_soa, zone_apex, qclass)?;
    let outer_soa = answers.first().ok_or(IxfrError::MissingInitialSoa)?;
    validate_current_soa(outer_soa, zone_apex, qclass).map_err(|_| IxfrError::MissingInitialSoa)?;
    let old_serial = soa_serial(&current_soa.rdata).map_err(|_| IxfrError::InvalidCurrentSoa)?;
    let new_serial = soa_serial(&outer_soa.rdata).map_err(|_| IxfrError::MalformedMessage)?;
    let serial_distance = new_serial.wrapping_sub(old_serial);
    if serial_distance == 0 || serial_distance >= (1u32 << 31) {
        return Err(IxfrError::SerialNotForward);
    }
    let mut expected_old_soa = current_soa.clone();
    let mut sequences = Vec::new();
    let mut affected_rrsets = BTreeSet::new();
    let mut index = 1usize;
    let mut terminal_soa_seen = false;

    while index < answers.len() {
        let old_soa = &answers[index];
        if resource_records_semantically_equal(old_soa, outer_soa)
            && resource_records_semantically_equal(&expected_old_soa, outer_soa)
        {
            index += 1;
            terminal_soa_seen = true;
            break;
        }
        if old_soa.rr_type != RecordType::Soa as u16
            || !resource_records_semantically_equal(old_soa, &expected_old_soa)
        {
            return Err(IxfrError::BrokenSoaChain);
        }
        affected_rrsets.insert(rrset_identity(old_soa));
        index += 1;

        let delete_start = index;
        while index < answers.len() && answers[index].rr_type != RecordType::Soa as u16 {
            affected_rrsets.insert(rrset_identity(&answers[index]));
            index += 1;
        }
        let deletes = answers[delete_start..index].to_vec();

        let Some(new_soa) = answers.get(index) else {
            return Err(IxfrError::IncompleteResponse);
        };
        if new_soa.rr_type != RecordType::Soa as u16
            || new_soa.owner.canonical_key() != zone_apex.canonical_key()
            || new_soa.class != qclass
        {
            return Err(IxfrError::BrokenSoaChain);
        }
        soa_serial(&new_soa.rdata).map_err(|_| IxfrError::MalformedMessage)?;
        affected_rrsets.insert(rrset_identity(new_soa));
        expected_old_soa = new_soa.clone();
        index += 1;

        let add_start = index;
        while index < answers.len() && answers[index].rr_type != RecordType::Soa as u16 {
            affected_rrsets.insert(rrset_identity(&answers[index]));
            index += 1;
        }
        let adds = answers[add_start..index].to_vec();
        sequences.push(IxfrDeltaSequence {
            old_soa: old_soa.clone(),
            deletes,
            new_soa: new_soa.clone(),
            adds,
        });
    }
    if index != answers.len() {
        return Err(IxfrError::BrokenSoaChain);
    }

    if terminal_soa_seen {
        let final_applied_serial =
            soa_serial(&expected_old_soa.rdata).map_err(|_| IxfrError::MalformedMessage)?;
        if !resource_records_semantically_equal(&expected_old_soa, outer_soa)
            || final_applied_serial != new_serial
        {
            return Err(IxfrError::BrokenSoaChain);
        }
    }

    Ok((
        IxfrDelta {
            old_serial,
            new_serial,
            sequences,
            affected_rrsets: affected_rrsets.into_iter().collect(),
        },
        terminal_soa_seen,
    ))
}

fn rrset_identity(record: &ResourceRecord) -> (String, u16, u16) {
    (record.owner.canonical_key(), record.rr_type, record.class)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RecordKey {
    owner: DomainName,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

impl RecordKey {
    fn from_record(record: &ResourceRecord) -> Self {
        Self {
            owner: record.owner.to_ascii_lowercased(),
            rr_type: record.rr_type,
            class: record.class,
            ttl: record.ttl,
            rdata: canonical_rdata_identity(record.rr_type, &record.rdata),
        }
    }
}

fn resource_records_semantically_equal(left: &ResourceRecord, right: &ResourceRecord) -> bool {
    RecordKey::from_record(left) == RecordKey::from_record(right)
}

fn canonical_rdata_identity(rr_type: u16, rdata: &[u8]) -> Vec<u8> {
    canonical_domain_name_rdata_identity(rr_type, rdata).unwrap_or_else(|| rdata.to_vec())
}

fn canonical_domain_name_rdata_identity(rr_type: u16, rdata: &[u8]) -> Option<Vec<u8>> {
    let mut canonical = Vec::with_capacity(rdata.len());
    match rr_type {
        // Single domain-name RDATA fields.
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 39 => {
            let end = append_canonical_rdata_name(rdata, 0, &mut canonical)?;
            (end == rdata.len()).then_some(canonical)
        }
        // MINFO, RP, and TALINK carry two domain names.
        14 | 17 | 58 => {
            let second = append_canonical_rdata_name(rdata, 0, &mut canonical)?;
            let end = append_canonical_rdata_name(rdata, second, &mut canonical)?;
            (end == rdata.len()).then_some(canonical)
        }
        // SOA carries MNAME and RNAME followed by five u32 fields.
        6 => {
            let rname = append_canonical_rdata_name(rdata, 0, &mut canonical)?;
            let timers = append_canonical_rdata_name(rdata, rname, &mut canonical)?;
            (timers.checked_add(20)? == rdata.len()).then(|| {
                canonical.extend_from_slice(&rdata[timers..]);
                canonical
            })
        }
        // Preference/subtype followed by one domain name.
        15 | 18 | 21 | 36 | 107 => {
            canonical.extend_from_slice(rdata.get(..2)?);
            let end = append_canonical_rdata_name(rdata, 2, &mut canonical)?;
            (end == rdata.len()).then_some(canonical)
        }
        // PX carries a preference and two domain names.
        26 => {
            canonical.extend_from_slice(rdata.get(..2)?);
            let second = append_canonical_rdata_name(rdata, 2, &mut canonical)?;
            let end = append_canonical_rdata_name(rdata, second, &mut canonical)?;
            (end == rdata.len()).then_some(canonical)
        }
        // SIG/RRSIG signer name followed by no additional fields.
        24 | 46 => {
            canonical.extend_from_slice(rdata.get(..18)?);
            let end = append_canonical_rdata_name(rdata, 18, &mut canonical)?;
            (end == rdata.len()).then_some(canonical)
        }
        // NXT/NSEC next-domain name followed by a type bitmap.
        30 | 47 => {
            let bitmap = append_canonical_rdata_name(rdata, 0, &mut canonical)?;
            canonical.extend_from_slice(&rdata[bitmap..]);
            Some(canonical)
        }
        // SRV fixed fields followed by Target.
        33 => {
            canonical.extend_from_slice(rdata.get(..6)?);
            let end = append_canonical_rdata_name(rdata, 6, &mut canonical)?;
            (end == rdata.len()).then_some(canonical)
        }
        // NAPTR fixed fields and three character-strings precede Replacement.
        35 => {
            let mut replacement = 4usize;
            for _ in 0..3 {
                let len = usize::from(*rdata.get(replacement)?);
                replacement = replacement.checked_add(1 + len)?;
                if replacement > rdata.len() {
                    return None;
                }
            }
            canonical.extend_from_slice(rdata.get(..replacement)?);
            let end = append_canonical_rdata_name(rdata, replacement, &mut canonical)?;
            (end == rdata.len()).then_some(canonical)
        }
        // SVCB/HTTPS priority + TargetName + byte-exact SvcParams.
        64 | 65 => {
            canonical.extend_from_slice(rdata.get(..2)?);
            let params = append_canonical_rdata_name(rdata, 2, &mut canonical)?;
            canonical.extend_from_slice(&rdata[params..]);
            Some(canonical)
        }
        _ => None,
    }
}

fn append_canonical_rdata_name(rdata: &[u8], offset: usize, output: &mut Vec<u8>) -> Option<usize> {
    let (name, consumed) = DomainName::parse(rdata, offset).ok()?;
    output.extend(name.to_ascii_lowercased().to_wire());
    offset.checked_add(consumed)
}

fn canonical_rdata_hash(rr_type: u16, rdata: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    canonical_rdata_identity(rr_type, rdata).hash(&mut hasher);
    hasher.finish()
}

fn ixfr_scope_error(error: AxfrError) -> IxfrError {
    match error {
        AxfrError::MalformedMessage => IxfrError::MalformedMessage,
        AxfrError::ErrorRcode(rcode) => IxfrError::ErrorRcode(rcode),
        AxfrError::ErrorRcodeWithEde { rcode, ede } => IxfrError::ErrorRcodeWithEde { rcode, ede },
        AxfrError::MissingInitialSoa => IxfrError::MissingInitialSoa,
        other => IxfrError::Axfr(other),
    }
}

fn normalize_record_owner(record: &mut ResourceRecord) {
    record.owner = record.owner.to_ascii_lowercased();
}

fn validate_current_soa(
    record: &ResourceRecord,
    zone_apex: &DomainName,
    qclass: u16,
) -> Result<(), IxfrError> {
    let zone_apex = zone_apex.to_ascii_lowercased();
    if record.owner.to_ascii_lowercased() != zone_apex
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
    if record.owner.to_ascii_lowercased() != zone_apex.to_ascii_lowercased()
        || record.class != qclass
    {
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
    require_question: bool,
) -> Result<usize, IxfrError> {
    if qdcount == 0 && !require_question {
        return Ok(DNS_HEADER_LEN);
    }
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
    let wire_ttl = u32::from_be_bytes([
        message[offset + 4],
        message[offset + 5],
        message[offset + 6],
        message[offset + 7],
    ]);
    let ttl = if wire_ttl & 0x8000_0000 != 0 {
        0
    } else {
        wire_ttl
    };
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

fn ensure_no_authority_and_only_opt_additional(
    message: &[u8],
    mut offset: usize,
    nscount: u16,
    arcount: u16,
) -> Result<(), DnsParseError> {
    if nscount != 0 || arcount > 1 {
        return Err(DnsParseError::FormErr);
    }
    if arcount == 1 {
        let (owner, consumed) = DomainName::parse(message, offset)?;
        offset += consumed;
        if owner.label_count() != 0 || offset + 10 > message.len() {
            return Err(DnsParseError::FormErr);
        }
        let rr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let rdlength = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
        offset += 10;
        let rdata_end = offset
            .checked_add(rdlength)
            .filter(|end| *end <= message.len())
            .ok_or(DnsParseError::FormErr)?;
        if rr_type != RecordType::Opt as u16 {
            return Err(DnsParseError::FormErr);
        }
        let mut option_offset = offset;
        while option_offset < rdata_end {
            if option_offset + 4 > rdata_end {
                return Err(DnsParseError::FormErr);
            }
            let option_len =
                u16::from_be_bytes([message[option_offset + 2], message[option_offset + 3]])
                    as usize;
            option_offset = option_offset
                .checked_add(4 + option_len)
                .filter(|end| *end <= rdata_end)
                .ok_or(DnsParseError::FormErr)?;
        }
        offset = rdata_end;
    }
    (offset == message.len())
        .then_some(())
        .ok_or(DnsParseError::FormErr)
}

fn transfer_extended_dns_error(
    message: &[u8],
    header: &Header,
) -> Option<TransferExtendedDnsError> {
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..header.qdcount {
        let (_, consumed) = DomainName::parse(message, offset).ok()?;
        offset = offset.checked_add(consumed + 4)?;
        if offset > message.len() {
            return None;
        }
    }
    for _ in 0..usize::from(header.ancount) + usize::from(header.nscount) {
        offset = skip_raw_dns_record(message, offset)?;
    }
    for _ in 0..header.arcount {
        let (owner, consumed) = DomainName::parse(message, offset).ok()?;
        offset = offset.checked_add(consumed)?;
        let fixed = message.get(offset..offset + 10)?;
        let rr_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdlength = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        offset = offset.checked_add(10)?;
        let rdata = message.get(offset..offset.checked_add(rdlength)?)?;
        offset += rdlength;
        if owner.label_count() != 0 || rr_type != RecordType::Opt as u16 {
            continue;
        }
        let mut option_offset = 0usize;
        while option_offset < rdata.len() {
            let option_header = rdata.get(option_offset..option_offset + 4)?;
            let option_code = u16::from_be_bytes([option_header[0], option_header[1]]);
            let option_len = u16::from_be_bytes([option_header[2], option_header[3]]) as usize;
            option_offset += 4;
            let option = rdata.get(option_offset..option_offset.checked_add(option_len)?)?;
            option_offset += option_len;
            if option_code == 15 && option.len() >= 2 {
                return Some(TransferExtendedDnsError {
                    info_code: u16::from_be_bytes([option[0], option[1]]),
                    extra_text: std::str::from_utf8(&option[2..]).ok()?.to_owned(),
                });
            }
        }
    }
    None
}

fn skip_raw_dns_record(message: &[u8], offset: usize) -> Option<usize> {
    let (_, consumed) = DomainName::parse(message, offset).ok()?;
    let fixed_offset = offset.checked_add(consumed)?;
    let fixed = message.get(fixed_offset..fixed_offset + 10)?;
    let rdlength = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
    fixed_offset
        .checked_add(10 + rdlength)
        .filter(|end| *end <= message.len())
}

fn axfr_rcode_error(rcode: u8, message: &[u8], header: &Header) -> AxfrError {
    transfer_extended_dns_error(message, header).map_or(AxfrError::ErrorRcode(rcode), |ede| {
        AxfrError::ErrorRcodeWithEde { rcode, ede }
    })
}

fn ixfr_rcode_error(rcode: u8, message: &[u8], header: &Header) -> IxfrError {
    transfer_extended_dns_error(message, header).map_or(IxfrError::ErrorRcode(rcode), |ede| {
        IxfrError::ErrorRcodeWithEde { rcode, ede }
    })
}

fn soa_rcode_error(rcode: u8, message: &[u8], header: &Header) -> SoaQueryError {
    transfer_extended_dns_error(message, header).map_or(SoaQueryError::ErrorRcode(rcode), |ede| {
        SoaQueryError::ErrorRcodeWithEde { rcode, ede }
    })
}

fn skip_authority_additional_and_ensure_end(
    message: &[u8],
    mut offset: usize,
    nscount: u16,
    arcount: u16,
) -> Result<(), DnsParseError> {
    for _ in 0..usize::from(nscount) + usize::from(arcount) {
        let (_, consumed) = parse_record(message, offset)?;
        offset += consumed;
    }
    if offset != message.len() {
        return Err(DnsParseError::FormErr);
    }
    Ok(())
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
                || rr_type == 3 // MD
                || rr_type == 4 // MF
                || rr_type == RecordType::Cname as u16
                || rr_type == 7 // MB
                || rr_type == 8 // MG
                || rr_type == 9 // MR
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
        14 => normalize_two_name_rdata(message, rdata_offset, rdata_end), // MINFO
        _ => Ok(raw_rdata.to_vec()),
    }
}

fn normalize_two_name_rdata(
    message: &[u8],
    rdata_offset: usize,
    rdata_end: usize,
) -> Result<Vec<u8>, DnsParseError> {
    let (first, consumed_first) = parse_rdata_name(message, rdata_offset, rdata_end)?;
    let second_offset = rdata_offset + consumed_first;
    let (second, consumed_second) = parse_rdata_name(message, second_offset, rdata_end)?;
    if second_offset + consumed_second != rdata_end {
        return Err(DnsParseError::FormErr);
    }
    let mut normalized = first.to_wire();
    normalized.extend(second.to_wire());
    Ok(normalized)
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
    if priority == 0 {
        return Ok(());
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
    validate_cname_and_dname_coexistence(zone_apex, records)?;
    Ok(())
}

fn validate_exact_apex_soa(
    zone_apex: &DomainName,
    records: &[ResourceRecord],
) -> Result<(), AxfrError> {
    let zone_apex = zone_apex.to_ascii_lowercased();
    let soa_records = records
        .iter()
        .filter(|record| record.rr_type == RecordType::Soa as u16)
        .collect::<Vec<_>>();
    if soa_records.len() == 1 && soa_records[0].owner.to_ascii_lowercased() == zone_apex {
        Ok(())
    } else {
        Err(AxfrError::InvalidZoneSoa)
    }
}

fn validate_apex_ns(zone_apex: &DomainName, records: &[ResourceRecord]) -> Result<(), AxfrError> {
    let zone_apex = zone_apex.to_ascii_lowercased();
    if records.iter().any(|record| {
        record.owner.to_ascii_lowercased() == zone_apex && record.rr_type == RecordType::Ns as u16
    }) {
        Ok(())
    } else {
        Err(AxfrError::MissingApexNs)
    }
}

fn validate_cname_and_dname_coexistence(
    zone_apex: &DomainName,
    records: &[ResourceRecord],
) -> Result<(), AxfrError> {
    #[derive(Default)]
    struct OwnerRecordKinds {
        has_cname: bool,
        has_dname: bool,
        has_ns: bool,
        has_cname_incompatible_data: bool,
        cname_target: Option<String>,
        dname_target: Option<String>,
    }

    let mut owner_kinds = HashMap::<DomainName, OwnerRecordKinds>::new();
    for record in records {
        let owner_key = record.owner.to_ascii_lowercased();
        let kinds = owner_kinds.entry(owner_key.clone()).or_default();

        if record.rr_type == RecordType::Dname as u16 {
            let target = DomainName::from_uncompressed_wire(&record.rdata)
                .map_err(|_| AxfrError::InvalidRdata)?
                .canonical_key();
            if kinds
                .dname_target
                .as_ref()
                .is_some_and(|existing| existing != &target)
            {
                return Err(AxfrError::MultipleDnameRecords);
            }
            kinds.dname_target = Some(target);
            kinds.has_dname = true;
        } else if record.rr_type == RecordType::Cname as u16 {
            let target = DomainName::from_uncompressed_wire(&record.rdata)
                .map_err(|_| AxfrError::InvalidRdata)?
                .canonical_key();
            if kinds
                .cname_target
                .as_ref()
                .is_some_and(|existing| existing != &target)
            {
                return Err(AxfrError::MultipleCnameRecords);
            }
            kinds.cname_target = Some(target);
            kinds.has_cname = true;
        } else if record.rr_type == RecordType::Ns as u16 {
            kinds.has_ns = true;
            kinds.has_cname_incompatible_data = true;
        } else if !is_dnssec_cname_exception_type(record.rr_type) {
            kinds.has_cname_incompatible_data = true;
        }
    }

    for kinds in owner_kinds.values() {
        if kinds.has_dname && kinds.has_cname {
            return Err(AxfrError::DnameCoexistsWithCname);
        }
    }

    let zone_apex = zone_apex.to_ascii_lowercased();
    for (owner, kinds) in &owner_kinds {
        if kinds.has_dname && kinds.has_ns && owner != &zone_apex {
            return Err(AxfrError::DnameCoexistsWithNs);
        }
    }

    for kinds in owner_kinds.values() {
        if kinds.has_cname && kinds.has_cname_incompatible_data {
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
    let mut rrset_indexes = HashMap::<(DomainName, u16, u16), usize>::new();
    let mut rrsets = Vec::<RrsetAccumulator>::new();

    for mut record in records {
        normalize_record_owner(&mut record);
        let key = (record.owner.clone(), record.rr_type, record.class);
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
            let rdata_hash = canonical_rdata_hash(record.rr_type, &record.rdata);
            let duplicate = existing
                .seen_rdata_hashes
                .get(&rdata_hash)
                .is_some_and(|indexes| {
                    indexes.iter().any(|index| {
                        canonical_rdata_identity(record.rr_type, &existing.rdatas[*index])
                            == canonical_rdata_identity(record.rr_type, &record.rdata)
                    })
                });
            if !duplicate {
                let rdata_index = existing.rdatas.len();
                existing.rdatas.push(record.rdata);
                existing
                    .seen_rdata_hashes
                    .entry(rdata_hash)
                    .or_default()
                    .push(rdata_index);
            }
        } else {
            rrset_indexes.insert(key, rrsets.len());
            let rdata_hash = canonical_rdata_hash(record.rr_type, &record.rdata);
            rrsets.push(RrsetAccumulator {
                owner: record.owner,
                rr_type: record.rr_type,
                class: record.class,
                ttl: record.ttl,
                rdatas: vec![record.rdata],
                seen_rdata_hashes: HashMap::from([(rdata_hash, vec![0])]),
            });
        }
    }

    rrsets
        .into_iter()
        .map(|accumulator| {
            Rrset::new(
                accumulator.owner,
                accumulator.rr_type,
                accumulator.class,
                accumulator.ttl,
                accumulator.rdatas,
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
    seen_rdata_hashes: HashMap<u64, Vec<usize>>,
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
            append_wire_record(&mut out, &answer);
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
            append_wire_record(&mut out, &answer);
        }
        out
    }

    fn soa_message(qid: u16, answers: Vec<ResourceRecord>) -> Vec<u8> {
        transfer_response_message(qid, "example.test.", RecordType::Soa as u16, 1, answers)
    }

    fn append_wire_record(out: &mut Vec<u8>, record: &ResourceRecord) {
        out.extend_from_slice(&record.owner.to_wire());
        out.extend_from_slice(&record.rr_type.to_be_bytes());
        out.extend_from_slice(&record.class.to_be_bytes());
        out.extend_from_slice(&record.ttl.to_be_bytes());
        out.extend_from_slice(&(record.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&record.rdata);
    }

    fn append_authority_record(message: &mut Vec<u8>, record: &ResourceRecord) {
        message[8..10].copy_from_slice(&1u16.to_be_bytes());
        append_wire_record(message, record);
    }

    fn append_additional_record(message: &mut Vec<u8>, record: &ResourceRecord) {
        message[10..12].copy_from_slice(&1u16.to_be_bytes());
        append_wire_record(message, record);
    }

    fn append_padding_opt(message: &mut Vec<u8>, padding_len: usize) {
        let mut padding = vec![0, 12, 0, padding_len as u8];
        padding.resize(4 + padding_len, 0);
        append_additional_record(
            message,
            &ResourceRecord {
                owner: DomainName::root(),
                rr_type: RecordType::Opt as u16,
                class: 1232,
                ttl: 0,
                rdata: padding,
            },
        );
    }

    fn append_ede_opt(message: &mut Vec<u8>, info_code: u16, text: &str) {
        let mut ede = Vec::with_capacity(6 + text.len());
        ede.extend_from_slice(&15u16.to_be_bytes());
        ede.extend_from_slice(&(2u16 + text.len() as u16).to_be_bytes());
        ede.extend_from_slice(&info_code.to_be_bytes());
        ede.extend_from_slice(text.as_bytes());
        append_additional_record(
            message,
            &ResourceRecord {
                owner: DomainName::root(),
                rr_type: RecordType::Opt as u16,
                class: 1232,
                ttl: 0,
                rdata: ede,
            },
        );
    }

    fn record(owner: &str, rr_type: u16, rdata: Vec<u8>) -> ResourceRecord {
        record_with_owner(
            DomainName::from_absolute_str(owner).unwrap(),
            rr_type,
            rdata,
        )
    }

    fn record_with_owner(owner: DomainName, rr_type: u16, rdata: Vec<u8>) -> ResourceRecord {
        ResourceRecord {
            owner,
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

    fn embedded_dot_owner(first_label: &[u8]) -> DomainName {
        let mut wire = Vec::new();
        wire.push(first_label.len() as u8);
        wire.extend_from_slice(first_label);
        wire.extend_from_slice(b"\x07example\x04test\x00");
        let (owner, consumed) = DomainName::parse(&wire, 0).unwrap();
        assert_eq!(consumed, wire.len());
        owner
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
    fn xot_query_opt_is_added_before_tsig_position() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let mut query = build_axfr_query(0x1234, &apex, 1);
        append_xot_opt(&mut query);

        let header = Header::parse(&query).unwrap();
        assert_eq!(header.arcount, 1);
        let mut offset = DNS_HEADER_LEN + apex.to_wire().len() + 4;
        let (opt, consumed) = parse_record(&query, offset).unwrap();
        offset += consumed;
        assert_eq!(opt.owner, DomainName::root());
        assert_eq!(opt.rr_type, RecordType::Opt as u16);
        assert_eq!(opt.class, 1232);
        assert_eq!(offset, query.len());
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
    fn builds_ixfr_query_from_borrowed_soa_view_with_mixed_case_configured_apex() {
        let apex = DomainName::from_absolute_str("EXAMPLE.TEST.").unwrap();
        let soa = record("EXAMPLE.TEST.", RecordType::Soa as u16, soa_rdata());
        let snapshot = ZoneSnapshot::active(apex.clone(), Some(1), rrsets_from_records(vec![soa]));
        let soa_view = snapshot.soa_record_view(1).expect("SOA view");

        build_ixfr_query_from_soa_view(0x1234, &apex, 1, soa_view)
            .expect("IXFR query for mixed-case configured apex");
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
        let framed = frame_tcp_message(&[1, 2, 3]).expect("short message fits TCP frame");
        assert_eq!(framed, vec![0, 3, 1, 2, 3]);
    }

    #[test]
    fn rejects_oversized_tcp_message_frame() {
        let message = vec![0; usize::from(u16::MAX) + 1];
        assert_eq!(
            frame_tcp_message(&message),
            Err(TcpFrameError::MessageTooLong {
                length: message.len()
            })
        );
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

        assert_eq!(snapshot.state(), crate::zone::ZoneState::Active);
        assert_eq!(snapshot.origin(), &apex);
        assert_eq!(snapshot.serial(), Some(1));
        assert_eq!(
            snapshot.soa_timers(),
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
    fn accepts_rfc9103_padded_axfr_messages_including_empty_continuation() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut first = axfr_message(0x1234, vec![soa.clone(), apex_ns()]);
        append_padding_opt(&mut first, 16);
        let mut empty = transfer_response_message_without_question(0x1234, vec![]);
        append_padding_opt(&mut empty, 32);
        let mut last = transfer_response_message_without_question(0x1234, vec![soa]);
        append_padding_opt(&mut last, 8);

        parse_axfr_response(0x1234, &apex, 1, &[first, empty, last])
            .expect("RFC 9103 AXoT permits padded messages with no answer RRs");
    }

    #[test]
    fn rejects_axfr_response_with_authority_or_trailing_bytes() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let ns = apex_ns();
        let mut response = axfr_message(0x1234, vec![soa.clone(), ns.clone(), soa]);
        append_authority_record(&mut response, &ns);

        let error = parse_axfr_response(0x1234, &apex, 1, &[response])
            .expect_err("AXFR authority section must be rejected");
        assert_eq!(error, AxfrError::MalformedMessage);

        let mut response = axfr_message(
            0x1234,
            vec![
                record("example.test.", RecordType::Soa as u16, soa_rdata()),
                apex_ns(),
                record("example.test.", RecordType::Soa as u16, soa_rdata()),
            ],
        );
        response.push(0);
        let error = parse_axfr_response(0x1234, &apex, 1, &[response])
            .expect_err("AXFR trailing bytes must be rejected");
        assert_eq!(error, AxfrError::MalformedMessage);
    }

    #[test]
    fn parses_axfr_lowercases_owner_without_splitting_embedded_dot_label() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mixed_embedded_dot_owner = embedded_dot_owner(b"A.B");
        let lower_embedded_dot_owner = embedded_dot_owner(b"a.b");
        let split_owner = DomainName::from_absolute_str("a.b.example.test.").unwrap();
        let dotted_a = record_with_owner(
            mixed_embedded_dot_owner,
            RecordType::A as u16,
            vec![192, 0, 2, 11],
        );
        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), dotted_a, soa],
            )],
        )
        .expect("AXFR with embedded-dot owner label");

        let owners = snapshot
            .transfer_records()
            .into_iter()
            .map(|record| record.owner)
            .collect::<Vec<_>>();
        assert!(owners.contains(&lower_embedded_dot_owner));
        assert!(!owners.contains(&split_owner));
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

        assert_eq!(snapshot.state(), crate::zone::ZoneState::Active);
        assert_eq!(snapshot.serial(), Some(1));
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
    fn axfr_stream_probe_accepts_question_only_first_message() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let first = axfr_message(0x1234, Vec::new());
        let first_probe = axfr_response_message_probe(0x1234, &apex, 1, &first, true)
            .expect("question-only AXFR message");
        assert!(first_probe.saw_response_question);
        assert_eq!(first_probe.apex_soa_count, 0);

        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let second = transfer_response_message_without_question(0x1234, vec![soa]);
        let second_probe = axfr_response_message_probe(0x1234, &apex, 1, &second, false)
            .expect("later AXFR message without repeated question");
        assert!(!second_probe.saw_response_question);
        assert_eq!(second_probe.apex_soa_count, 1);
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
    fn parses_axfr_and_normalizes_compressed_legacy_mail_rdata_names() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut records = vec![soa.clone(), apex_ns()];
        for (rr_type, label) in [(3, "md"), (4, "mf"), (7, "mb"), (8, "mg"), (9, "mr")] {
            records.push(record(
                &format!("type{rr_type}.example.test."),
                rr_type,
                compressed_apex_suffix_name_rdata(label),
            ));
        }
        let mut minfo = compressed_apex_suffix_name_rdata("responsible");
        minfo.extend(compressed_apex_suffix_name_rdata("errors"));
        records.push(record("minfo.example.test.", 14, minfo));
        records.push(soa);

        let snapshot = parse_axfr_response(0x1234, &apex, 1, &[axfr_message(0x1234, records)])
            .expect("AXFR with compressed legacy mail RDATA names");

        for (rr_type, label) in [(3, "md"), (4, "mf"), (7, "mb"), (8, "mg"), (9, "mr")] {
            assert_eq!(
                first_rdata(&snapshot, &format!("type{rr_type}.example.test."), rr_type),
                name_rdata(&format!("{label}.example.test."))
            );
        }
        let mut expected_minfo = name_rdata("responsible.example.test.");
        expected_minfo.extend(name_rdata("errors.example.test."));
        assert_eq!(
            first_rdata(&snapshot, "minfo.example.test.", 14),
            expected_minfo
        );
    }

    #[test]
    fn axfr_ignores_duplicate_resource_records() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let address = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), address.clone(), address, soa],
            )],
        )
        .expect("AXFR clients ignore duplicate RRs per RFC 5936");

        assert_eq!(
            snapshot
                .offline_oracle()
                .lookup(
                    &DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers
                .len(),
            1
        );
    }

    #[test]
    fn axfr_treats_ttl_with_high_bit_set_as_zero() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut address = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 10],
        );
        address.ttl = 0x8000_002a;
        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), address, soa],
            )],
        )
        .expect("high-bit transfer TTL is accepted as zero per RFC 2181");

        assert_eq!(
            snapshot
                .offline_oracle()
                .lookup(
                    &DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers[0]
                .ttl,
            0
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
    fn preserves_rrsig_ttl_by_type_covered_at_one_owner() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let owner = "www.example.test.";
        let mut a = record(owner, RecordType::A as u16, vec![192, 0, 2, 1]);
        a.ttl = 300;
        let mut aaaa = record(
            owner,
            RecordType::Aaaa as u16,
            vec![0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        aaaa.ttl = 600;
        let mut a_sig = record(
            owner,
            RecordType::Rrsig as u16,
            rrsig_rdata_with_algorithm(RecordType::A, 8, name_rdata("example.test.")),
        );
        a_sig.ttl = 300;
        let mut aaaa_sig = record(
            owner,
            RecordType::Rrsig as u16,
            rrsig_rdata_with_algorithm(RecordType::Aaaa, 8, name_rdata("example.test.")),
        );
        aaaa_sig.ttl = 600;

        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), a, aaaa, a_sig, aaaa_sig, soa],
            )],
        )
        .expect("RRSIG TTLs may differ by Type Covered");

        let mut observed = snapshot
            .transfer_records()
            .into_iter()
            .filter(|record| record.rr_type == RecordType::Rrsig as u16)
            .map(|record| {
                (
                    u16::from_be_bytes([record.rdata[0], record.rdata[1]]),
                    record.ttl,
                )
            })
            .collect::<Vec<_>>();
        observed.sort_unstable();
        assert_eq!(
            observed,
            vec![(RecordType::A as u16, 300), (RecordType::Aaaa as u16, 600),]
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
    fn axfr_error_preserves_rfc9103_extended_dns_error() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let mut response = axfr_message(0x1234, vec![]);
        response[3] = 2;
        append_ede_opt(&mut response, 22, "No Reachable Authority");

        assert_eq!(
            parse_axfr_response(0x1234, &apex, 1, &[response]),
            Err(AxfrError::ErrorRcodeWithEde {
                rcode: 2,
                ede: TransferExtendedDnsError {
                    info_code: 22,
                    extra_text: "No Reachable Authority".to_owned(),
                },
            })
        );
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
    fn soa_error_preserves_rfc9103_extended_dns_error() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let mut response = soa_message(0x1234, vec![]);
        response[3] = 2;
        append_ede_opt(&mut response, 23, "Network Error");

        assert_eq!(
            parse_soa_response(0x1234, &apex, 1, &response),
            Err(SoaQueryError::ErrorRcodeWithEde {
                rcode: 2,
                ede: TransferExtendedDnsError {
                    info_code: 23,
                    extra_text: "Network Error".to_owned(),
                },
            })
        );
    }

    #[test]
    fn accepts_soa_response_with_authority_and_additional_records() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut response = soa_message(0x1234, vec![soa]);
        append_authority_record(&mut response, &apex_ns());
        append_additional_record(&mut response, &apex_ns());

        let serial = parse_soa_response(0x1234, &apex, 1, &response).expect("SOA extra sections");

        assert_eq!(serial, 1);
    }

    #[test]
    fn rejects_soa_response_with_trailing_bytes() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let mut response = soa_message(
            0x1234,
            vec![record("example.test.", RecordType::Soa as u16, soa_rdata())],
        );
        response.push(0);
        let error = parse_soa_response(0x1234, &apex, 1, &response)
            .expect_err("SOA response trailing bytes must be rejected");
        assert_eq!(error, SoaQueryError::MalformedMessage);
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
        assert_eq!(snapshot.state(), ZoneState::Active);
        assert_eq!(snapshot.serial(), Some(1));
    }

    #[test]
    fn accepts_rfc9103_padding_on_ixfr_response_messages() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let old_a = record(
            "old.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let current_zone = current_zone(vec![current_soa.clone(), apex_ns(), old_a.clone()]);
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
        let mut response = ixfr_message(
            0x1234,
            vec![
                new_soa.clone(),
                current_soa,
                old_a,
                new_soa.clone(),
                new_a,
                new_soa,
            ],
        );
        append_padding_opt(&mut response, 16);

        parse_ixfr_response(0x1234, &apex, 1, &current_zone, &[response])
            .expect("RFC 9103 IXoT permits EDNS Padding");
    }

    #[test]
    fn parses_multi_message_ixfr_axfr_fallback_with_omitted_later_question() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa]);
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let first = ixfr_message(0x1234, vec![new_soa.clone(), apex_ns()]);
        let second = transfer_response_message_without_question(
            0x1234,
            vec![
                record(
                    "www.example.test.",
                    RecordType::A as u16,
                    vec![192, 0, 2, 10],
                ),
                new_soa,
            ],
        );

        let response = parse_ixfr_response(0x1234, &apex, 1, &current_zone, &[first, second])
            .expect("IXFR AXFR fallback permits QDCOUNT=0 after the first message");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected AXFR fallback update");
        };
        assert_eq!(snapshot.serial(), Some(2));
    }

    #[test]
    fn rejects_ixfr_response_with_authority_or_trailing_bytes() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let current_zone = current_zone(vec![current_soa.clone()]);
        let mut response = ixfr_message(0x1234, vec![new_soa.clone(), current_soa, new_soa]);
        append_authority_record(&mut response, &apex_ns());

        let error = parse_ixfr_response(0x1234, &apex, 1, &current_zone, &[response])
            .expect_err("IXFR authority section must be rejected");
        assert_eq!(error, IxfrError::MalformedMessage);

        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let mut response = ixfr_message(0x1234, vec![new_soa.clone(), current_soa, new_soa]);
        response.push(0);
        let error = parse_ixfr_response(0x1234, &apex, 1, &current_zone, &[response])
            .expect_err("IXFR trailing bytes must be rejected");
        assert_eq!(error, IxfrError::MalformedMessage);
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
        assert_eq!(snapshot.state(), ZoneState::Active);
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
    fn parses_ixfr_mode3_current_response_with_mixed_case_configured_apex() {
        let apex = DomainName::from_absolute_str("EXAMPLE.TEST.").unwrap();
        let current_soa = record("EXAMPLE.TEST.", RecordType::Soa as u16, soa_rdata());
        let current_zone = ZoneSnapshot::active(
            apex.clone(),
            Some(1),
            rrsets_from_records(vec![current_soa]),
        );
        let lower_response_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let response = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[ixfr_message(0x1234, vec![lower_response_soa])],
        )
        .expect("mode 3 current with mixed-case configured apex");

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
    fn ixfr_error_preserves_rfc9103_extended_dns_error() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa, apex_ns()]);
        let mut response = ixfr_message(0x1234, vec![]);
        response[3] = 2;
        append_ede_opt(&mut response, 24, "Invalid Data");

        assert_eq!(
            parse_ixfr_response(0x1234, &apex, 1, &current_zone, &[response]),
            Err(IxfrError::ErrorRcodeWithEde {
                rcode: 2,
                ede: TransferExtendedDnsError {
                    info_code: 24,
                    extra_text: "Invalid Data".to_owned(),
                },
            })
        );
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
                    new_soa,
                ],
            )],
        )
        .expect("mode 1 diff");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert_eq!(snapshot.serial(), Some(2));
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
    fn ixfr_incremental_wire_is_retained_as_rrset_granular_delta() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let old_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let removed = record(
            "changed.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let added = record(
            "changed.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 2],
        );
        let answers = vec![
            new_soa.clone(),
            old_soa.clone(),
            removed.clone(),
            new_soa.clone(),
            added.clone(),
            new_soa,
        ];

        let delta = parse_ixfr_incremental_delta(&apex, 1, &old_soa, &answers)
            .expect("valid RFC 1995 delta");

        assert_eq!(delta.old_serial(), 1);
        assert_eq!(delta.new_serial(), 2);
        assert_eq!(delta.sequences().len(), 1);
        assert_eq!(delta.sequences()[0].deletes(), &[removed]);
        assert_eq!(delta.sequences()[0].adds(), &[added]);
        assert_eq!(
            delta.affected_rrsets(),
            [
                ("changed.example.test.".to_owned(), RecordType::A as u16, 1),
                ("example.test.".to_owned(), RecordType::Soa as u16, 1),
            ]
        );
    }

    #[test]
    fn ixfr_rejects_serial_that_is_not_forward_under_rfc1982() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let old_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(10),
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(9),
        );

        let error = parse_ixfr_incremental_delta(
            &apex,
            1,
            &old_soa,
            &[new_soa.clone(), old_soa.clone(), new_soa.clone(), new_soa],
        )
        .unwrap_err();

        assert_eq!(error, IxfrError::SerialNotForward);
    }

    #[test]
    fn ixfr_accepts_rfc1982_serial_wraparound() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let old_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(u32::MAX),
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(0),
        );

        let delta = parse_ixfr_incremental_delta(
            &apex,
            1,
            &old_soa,
            &[new_soa.clone(), old_soa.clone(), new_soa.clone(), new_soa],
        )
        .unwrap();

        assert_eq!(delta.new_serial(), 0);
    }

    #[test]
    fn repeated_ixfr_generations_match_fresh_snapshot_and_image_compilation() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let owner = DomainName::from_absolute_str("churn.example.test.").unwrap();
        let mut soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut value = record_with_owner(owner.clone(), RecordType::A as u16, vec![192, 0, 2, 0]);
        let mut snapshot = ZoneSnapshot::active(
            apex.clone(),
            Some(1),
            rrsets_from_records(vec![soa.clone(), apex_ns(), value.clone()]),
        );

        for new_serial in 2..=101 {
            let new_soa = record(
                "example.test.",
                RecordType::Soa as u16,
                soa_rdata_with_serial(new_serial),
            );
            let new_value = record_with_owner(
                owner.clone(),
                RecordType::A as u16,
                vec![192, 0, 2, (new_serial - 1) as u8],
            );
            let response = parse_ixfr_response(
                new_serial as u16,
                &apex,
                1,
                &snapshot,
                &[ixfr_message(
                    new_serial as u16,
                    vec![
                        new_soa.clone(),
                        soa,
                        value,
                        new_soa.clone(),
                        new_value.clone(),
                        new_soa.clone(),
                    ],
                )],
            )
            .expect("churn IXFR remains valid");
            let IxfrResponse::Updated(updated) = response else {
                panic!("churn IXFR must advance the zone");
            };
            snapshot = *updated;

            let fresh = ZoneSnapshot::active(
                apex.clone(),
                Some(new_serial),
                rrsets_from_records(vec![new_soa.clone(), apex_ns(), new_value.clone()]),
            );
            assert_eq!(snapshot, fresh, "snapshot diverged at serial {new_serial}");
            assert_eq!(
                ZoneImage::compile(&snapshot).unwrap(),
                ZoneImage::compile(&fresh).unwrap(),
                "query image diverged at serial {new_serial}"
            );
            soa = new_soa;
            value = new_value;
        }
    }

    #[test]
    fn ixfr_owner_creation_and_removal_matches_fresh_empty_non_terminal_semantics() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let wildcard = record("*.example.test.", RecordType::A as u16, vec![192, 0, 2, 1]);
        let leaf = record(
            "leaf.branch.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 2],
        );
        let queried = DomainName::from_absolute_str("missing.branch.example.test.").unwrap();
        let soa1 = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let soa2 = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let soa3 = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(3),
        );
        let initial = ZoneSnapshot::active(
            apex.clone(),
            Some(1),
            rrsets_from_records(vec![soa1.clone(), apex_ns(), wildcard.clone()]),
        );

        let added = parse_ixfr_response(
            0x2002,
            &apex,
            1,
            &initial,
            &[ixfr_message(
                0x2002,
                vec![soa2.clone(), soa1, soa2.clone(), leaf.clone(), soa2.clone()],
            )],
        )
        .expect("IXFR may create a new owner below a new empty non-terminal");
        let IxfrResponse::Updated(added) = added else {
            panic!("owner-creation IXFR must advance the zone");
        };
        let fresh_added = ZoneSnapshot::active(
            apex.clone(),
            Some(2),
            rrsets_from_records(vec![
                soa2.clone(),
                apex_ns(),
                wildcard.clone(),
                leaf.clone(),
            ]),
        );
        assert_eq!(*added, fresh_added);
        assert_eq!(
            added
                .offline_oracle()
                .lookup(&queried, RecordType::A as u16, 1),
            fresh_added
                .offline_oracle()
                .lookup(&queried, RecordType::A as u16, 1),
            "the new empty non-terminal must suppress the apex wildcard"
        );

        let removed = parse_ixfr_response(
            0x2003,
            &apex,
            1,
            &added,
            &[ixfr_message(
                0x2003,
                vec![soa3.clone(), soa2, leaf, soa3.clone(), soa3.clone()],
            )],
        )
        .expect("IXFR may remove the last owner below an empty non-terminal");
        let IxfrResponse::Updated(removed) = removed else {
            panic!("owner-removal IXFR must advance the zone");
        };
        let fresh_removed = ZoneSnapshot::active(
            apex,
            Some(3),
            rrsets_from_records(vec![soa3, apex_ns(), wildcard]),
        );
        assert_eq!(*removed, fresh_removed);
        assert_eq!(
            removed
                .offline_oracle()
                .lookup(&queried, RecordType::A as u16, 1),
            fresh_removed
                .offline_oracle()
                .lookup(&queried, RecordType::A as u16, 1),
            "removing the last descendant must restore apex-wildcard synthesis"
        );
    }

    #[test]
    fn small_ixfr_reuses_untouched_large_snapshot_shards() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let old_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut records = Vec::with_capacity(70_002);
        records.push(old_soa.clone());
        records.push(apex_ns());
        for index in 0..70_000u32 {
            records.push(record(
                &format!("n{index}.example.test."),
                RecordType::A as u16,
                index.to_be_bytes().to_vec(),
            ));
        }
        let old_value = record(
            "n4242.example.test.",
            RecordType::A as u16,
            4_242u32.to_be_bytes().to_vec(),
        );
        let new_value = record(
            "n4242.example.test.",
            RecordType::A as u16,
            70_001u32.to_be_bytes().to_vec(),
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let current = ZoneSnapshot::active(apex.clone(), Some(1), rrsets_from_records(records));
        assert!(current.rrset_storage_shard_count() > 1);

        let response = parse_ixfr_response(
            0x4242,
            &apex,
            1,
            &current,
            &[ixfr_message(
                0x4242,
                vec![
                    new_soa.clone(),
                    old_soa,
                    old_value,
                    new_soa.clone(),
                    new_value,
                    new_soa,
                ],
            )],
        )
        .expect("small update to large snapshot");
        let IxfrResponse::Updated(updated) = response else {
            panic!("expected updated snapshot");
        };
        assert_eq!(
            updated.rrset_storage_shard_count(),
            current.rrset_storage_shard_count()
        );
        assert!(
            updated.shared_rrset_storage_shards(&current)
                >= current.rrset_storage_shard_count().saturating_sub(2),
            "only the SOA and changed-owner shards may be copied"
        );
    }

    #[test]
    fn rejects_ixfr_mode1_incremental_diff_without_terminal_soa() {
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
        .expect_err("RFC 1995 requires a closing copy of the current SOA");

        assert_eq!(error, IxfrError::IncompleteResponse);
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
                    new_soa,
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
    fn parses_ixfr_mode1_delete_against_mixed_case_current_zone_owner() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("EXAMPLE.TEST.", RecordType::Soa as u16, soa_rdata());
        let old_a_mixed_current = record(
            "WWW.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let old_a_lower_ixfr = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let old_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa, apex_ns(), old_a_mixed_current]);
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
                    old_a_lower_ixfr,
                    new_soa.clone(),
                    new_soa,
                ],
            )],
        )
        .expect("mode 1 delete against mixed-case current owner");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert!(
            snapshot
                .offline_oracle()
                .lookup(
                    &DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                )
                .answers
                .is_empty()
        );
    }

    #[test]
    fn parses_ixfr_delete_with_case_variant_domain_name_rdata() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_cname = record(
            "alias.example.test.",
            RecordType::Cname as u16,
            name_rdata("Target.Example.Test."),
        );
        let delete_cname = record(
            "alias.example.test.",
            RecordType::Cname as u16,
            name_rdata("target.example.test."),
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let current_zone = current_zone(vec![current_soa.clone(), apex_ns(), current_cname]);

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
                    delete_cname,
                    new_soa.clone(),
                    new_soa,
                ],
            )],
        )
        .expect("domain names in RDATA compare case-insensitively");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        assert!(
            snapshot
                .offline_oracle()
                .lookup(
                    &DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                )
                .answers
                .is_empty()
        );
    }

    #[test]
    fn parses_ixfr_soa_chain_with_case_variant_mname_and_rname() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let mut case_variant_soa_rdata = name_rdata("NS.EXAMPLE.TEST.");
        case_variant_soa_rdata.extend(name_rdata("HOSTMASTER.EXAMPLE.TEST."));
        case_variant_soa_rdata.extend_from_slice(
            &soa_rdata()[name_rdata("ns.example.test.").len()
                + name_rdata("hostmaster.example.test.").len()..],
        );
        let old_soa_case_variant = record(
            "example.test.",
            RecordType::Soa as u16,
            case_variant_soa_rdata,
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let current_zone = current_zone(vec![current_soa, apex_ns()]);

        let response = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[ixfr_message(
                0x1234,
                vec![
                    new_soa.clone(),
                    old_soa_case_variant,
                    new_soa.clone(),
                    new_soa,
                ],
            )],
        )
        .expect("SOA chain identity compares MNAME and RNAME case-insensitively");

        assert!(matches!(response, IxfrResponse::Updated(_)));
    }

    #[test]
    fn parses_ixfr_mode1_embedded_dot_owner_without_restructuring_labels() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let lower_embedded_dot_owner = embedded_dot_owner(b"a.b");
        let split_owner = DomainName::from_absolute_str("a.b.example.test.").unwrap();
        let old_embedded_dot_a = record_with_owner(
            embedded_dot_owner(b"A.B"),
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let old_embedded_dot_a_ixfr = record_with_owner(
            lower_embedded_dot_owner.clone(),
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let old_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let current_zone = current_zone(vec![current_soa, apex_ns(), old_embedded_dot_a]);
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
                    old_embedded_dot_a_ixfr,
                    new_soa.clone(),
                    new_soa,
                ],
            )],
        )
        .expect("mode 1 delete of owner with embedded dot label");

        let IxfrResponse::Updated(snapshot) = response else {
            panic!("expected updated zone");
        };
        let owners = snapshot
            .transfer_records()
            .into_iter()
            .map(|record| record.owner)
            .collect::<Vec<_>>();
        assert!(!owners.contains(&lower_embedded_dot_owner));
        assert!(!owners.contains(&split_owner));
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
        assert_eq!(snapshot.serial(), Some(2));
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
                vec![
                    new_soa.clone(),
                    current_soa,
                    old_a,
                    new_soa.clone(),
                    new_a,
                    new_soa,
                ],
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
                vec![new_soa.clone(), current_soa, new_soa.clone(), new_soa],
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
                vec![new_soa.clone(), current_soa, new_soa.clone(), new_soa],
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
                vec![
                    new_soa.clone(),
                    current_soa,
                    new_soa.clone(),
                    cname,
                    a,
                    new_soa,
                ],
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
                vec![final_soa.clone(), current_soa, intermediate_soa, final_soa],
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
    fn rejects_ixfr_delete_when_only_ttl_differs() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let current_soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let existing_a = record(
            "www.example.test.",
            RecordType::A as u16,
            vec![192, 0, 2, 1],
        );
        let mut wrong_ttl_a = existing_a.clone();
        wrong_ttl_a.ttl += 1;
        let new_soa = record(
            "example.test.",
            RecordType::Soa as u16,
            soa_rdata_with_serial(2),
        );
        let current_zone = current_zone(vec![current_soa.clone(), existing_a]);
        let error = parse_ixfr_response(
            0x1234,
            &apex,
            1,
            &current_zone,
            &[ixfr_message(
                0x1234,
                vec![new_soa.clone(), current_soa, wrong_ttl_a, new_soa],
            )],
        )
        .expect_err("TTL is part of exact IXFR record identity");

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

        assert_eq!(snapshot.serial(), Some(1));
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

        assert_eq!(snapshot.serial(), Some(1));
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
    fn rejects_axfr_multiple_cname_records_for_owner() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let first = record(
            "alias.example.test.",
            RecordType::Cname as u16,
            name_rdata("target.example.test."),
        );
        let second = record(
            "ALIAS.example.test.",
            RecordType::Cname as u16,
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
        .expect_err("multiple CNAME records");

        assert_eq!(error, AxfrError::MultipleCnameRecords);
    }

    #[test]
    fn rejects_axfr_non_apex_dname_with_ns() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let dname = record(
            "redirect.example.test.",
            RecordType::Dname as u16,
            name_rdata("target.example.test."),
        );
        let ns = record(
            "REDIRECT.example.test.",
            RecordType::Ns as u16,
            name_rdata("ns.redirect.example.test."),
        );
        let error = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), dname, ns, soa],
            )],
        )
        .expect_err("non-apex DNAME with NS");

        assert_eq!(error, AxfrError::DnameCoexistsWithNs);
    }

    #[test]
    fn accepts_axfr_dname_owners_that_collide_as_canonical_strings() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let embedded_dot = record_with_owner(
            embedded_dot_owner(b"a.b"),
            RecordType::Dname as u16,
            name_rdata("embedded-target.example.test."),
        );
        let split_labels = record(
            "a.b.example.test.",
            RecordType::Dname as u16,
            name_rdata("split-target.example.test."),
        );

        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), embedded_dot, split_labels, soa],
            )],
        )
        .expect("structurally distinct DNAME owners must not be merged");

        assert_eq!(snapshot.serial(), Some(1));
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
    fn accepts_and_preserves_alias_mode_svcb_and_https_params() {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let soa = record("example.test.", RecordType::Soa as u16, soa_rdata());
        let params = [0, 1, 0, 3, 2, b'h', b'2'];
        let svcb = record(
            "svc.example.test.",
            RecordType::Svcb as u16,
            svcb_rdata(0, name_rdata("alias.example.test."), &params),
        );
        let https = record(
            "www.example.test.",
            RecordType::Https as u16,
            svcb_rdata(0, name_rdata("alias.example.test."), &params),
        );

        let snapshot = parse_axfr_response(
            0x1234,
            &apex,
            1,
            &[axfr_message(
                0x1234,
                vec![soa.clone(), apex_ns(), svcb.clone(), https.clone(), soa],
            )],
        )
        .expect("AliasMode parameters are ignored by recipients, not rejected");

        let records = snapshot.transfer_records();
        assert!(records.contains(&svcb));
        assert!(records.contains(&https));
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
