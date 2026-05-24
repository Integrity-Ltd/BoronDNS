use std::fmt;

use thiserror::Error;

use crate::zone::{ResourceRecord, Rrset, ZoneState, ZoneStore};

pub const DNS_HEADER_LEN: usize = 12;
pub const DEFAULT_MAX_UDP_PAYLOAD: u16 = 1232;
pub const DEFAULT_MAX_CNAME_CHAIN: usize = 8;
pub const DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS: u64 = 30;
const DNS_CLASS_IN: u16 = 1;
const DNS_CLASS_ANY: u16 = 255;
const EDNS_TCP_KEEPALIVE_OPTION: u16 = 11;
const EDNS_PADDING_OPTION: u16 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Query = 0,
    Notify = 4,
}

impl Opcode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Query),
            4 => Some(Self::Notify),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Hinfo = 13,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Naptr = 35,
    Dname = 39,
    Ds = 43,
    Rrsig = 46,
    Nsec = 47,
    Dnskey = 48,
    Nsec3 = 50,
    Nsec3Param = 51,
    Tlsa = 52,
    Svcb = 64,
    Https = 65,
    Uri = 256,
    Tkey = 249,
    Tsig = 250,
    Ixfr = 251,
    Axfr = 252,
    Opt = 41,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
    NotAuth = 9,
}

impl Rcode {
    fn bits(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsParseError {
    #[error("DNS message is shorter than the 12-octet header")]
    ShortHeader,

    #[error("DNS message is malformed")]
    FormErr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn parse(packet: &[u8]) -> Result<Self, DnsParseError> {
        if packet.len() < DNS_HEADER_LEN {
            return Err(DnsParseError::ShortHeader);
        }

        Ok(Self {
            id: u16::from_be_bytes([packet[0], packet[1]]),
            flags: u16::from_be_bytes([packet[2], packet[3]]),
            qdcount: u16::from_be_bytes([packet[4], packet[5]]),
            ancount: u16::from_be_bytes([packet[6], packet[7]]),
            nscount: u16::from_be_bytes([packet[8], packet[9]]),
            arcount: u16::from_be_bytes([packet[10], packet[11]]),
        })
    }

    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn opcode_value(&self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }

    pub fn opcode(&self) -> Option<Opcode> {
        Opcode::from_u8(self.opcode_value())
    }

    fn response_flags(&self, rcode: Rcode, authoritative: bool, truncated: bool) -> u16 {
        let opcode = self.flags & 0x7800;
        let rd = self.flags & 0x0100;
        let aa = if authoritative { 0x0400 } else { 0 };
        let tc = if truncated { 0x0200 } else { 0 };
        0x8000 | opcode | aa | tc | rd | rcode.bits()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainName {
    labels: Vec<Vec<u8>>,
}

impl DomainName {
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    pub fn from_absolute_str(name: &str) -> Result<Self, DnsParseError> {
        if name == "." {
            return Ok(Self::root());
        }

        let Some(stripped) = name.strip_suffix('.') else {
            return Err(DnsParseError::FormErr);
        };

        let mut labels = Vec::new();
        let mut total_len = 1usize;
        for label in stripped.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(DnsParseError::FormErr);
            }

            total_len += 1 + label.len();
            if total_len > 255 {
                return Err(DnsParseError::FormErr);
            }

            labels.push(label.as_bytes().to_vec());
        }

        Ok(Self { labels })
    }

    pub fn parse(packet: &[u8], offset: usize) -> Result<(Self, usize), DnsParseError> {
        let mut labels = Vec::new();
        let mut pos = offset;
        let mut consumed = None;
        let mut visited_pointers = Vec::new();
        let mut total_len = 1usize;

        loop {
            let Some(&len) = packet.get(pos) else {
                return Err(DnsParseError::FormErr);
            };

            match len & 0xc0 {
                0xc0 => {
                    let Some(&next) = packet.get(pos + 1) else {
                        return Err(DnsParseError::FormErr);
                    };
                    let pointer = (((len & 0x3f) as usize) << 8) | next as usize;
                    if pointer >= packet.len() || visited_pointers.contains(&pointer) {
                        return Err(DnsParseError::FormErr);
                    }
                    visited_pointers.push(pointer);
                    consumed.get_or_insert(pos + 2 - offset);
                    pos = pointer;
                }
                0x00 => {
                    pos += 1;
                    if len == 0 {
                        let consumed = consumed.unwrap_or_else(|| pos - offset);
                        return Ok((Self { labels }, consumed));
                    }

                    let label_len = len as usize;
                    if label_len > 63 || pos + label_len > packet.len() {
                        return Err(DnsParseError::FormErr);
                    }

                    total_len += 1 + label_len;
                    if total_len > 255 {
                        return Err(DnsParseError::FormErr);
                    }

                    labels.push(packet[pos..pos + label_len].to_vec());
                    pos += label_len;
                }
                _ => return Err(DnsParseError::FormErr),
            }
        }
    }

    pub fn is_equal_or_subdomain_of(&self, zone: &DomainName) -> bool {
        if zone.labels.len() > self.labels.len() {
            return false;
        }

        let offset = self.labels.len() - zone.labels.len();
        self.labels[offset..]
            .iter()
            .zip(&zone.labels)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    pub fn parent(&self) -> Option<Self> {
        if self.labels.is_empty() {
            return None;
        }

        Some(Self {
            labels: self.labels[1..].to_vec(),
        })
    }

    pub fn wildcard_child(&self) -> Self {
        let mut labels = Vec::with_capacity(self.labels.len() + 1);
        labels.push(b"*".to_vec());
        labels.extend_from_slice(&self.labels);
        Self { labels }
    }

    pub fn with_replaced_suffix(
        &self,
        suffix: &DomainName,
        replacement: &DomainName,
    ) -> Option<Self> {
        if !self.is_equal_or_subdomain_of(suffix) {
            return None;
        }

        let prefix_len = self.labels.len().checked_sub(suffix.labels.len())?;
        let mut labels = Vec::with_capacity(prefix_len + replacement.labels.len());
        labels.extend_from_slice(&self.labels[..prefix_len]);
        labels.extend_from_slice(&replacement.labels);

        let wire_len = labels.iter().map(|label| 1 + label.len()).sum::<usize>() + 1;
        if wire_len > 255 {
            return None;
        }

        Some(Self { labels })
    }

    pub fn canonical_key(&self) -> String {
        if self.labels.is_empty() {
            return ".".to_owned();
        }

        let mut key = String::new();
        for label in &self.labels {
            for byte in label {
                key.push(byte.to_ascii_lowercase() as char);
            }
            key.push('.');
        }
        key
    }

    pub(crate) fn canonical_order_key(&self) -> Vec<Vec<u8>> {
        self.labels
            .iter()
            .rev()
            .map(|label| label.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>())
            .collect()
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut wire = Vec::new();
        for label in &self.labels {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label);
        }
        wire.push(0);
        wire
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_str(".");
        }

        for label in &self.labels {
            write!(f, "{}.", String::from_utf8_lossy(label))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: DomainName,
    pub qtype: u16,
    pub qclass: u16,
    wire: Vec<u8>,
}

impl Question {
    pub fn parse(packet: &[u8]) -> Result<Self, DnsParseError> {
        let (qname, qname_len) = DomainName::parse(packet, DNS_HEADER_LEN)?;
        let qtype_offset = DNS_HEADER_LEN + qname_len;
        if qtype_offset + 4 > packet.len() {
            return Err(DnsParseError::FormErr);
        }

        Ok(Self {
            qname,
            qtype: u16::from_be_bytes([packet[qtype_offset], packet[qtype_offset + 1]]),
            qclass: u16::from_be_bytes([packet[qtype_offset + 2], packet[qtype_offset + 3]]),
            wire: packet[DNS_HEADER_LEN..qtype_offset + 4].to_vec(),
        })
    }

    fn wire(&self) -> &[u8] {
        &self.wire
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramAction {
    Discard,
    Respond(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnyResponseMode {
    #[default]
    Minimal,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnswerOptions {
    pub transport: Transport,
    pub max_udp_payload: u16,
    pub max_cname_chain: usize,
    pub tcp_keepalive_timeout_secs: u64,
    pub edns_padding_block_size: u16,
    pub any_response: AnyResponseMode,
}

impl AnswerOptions {
    pub fn udp(max_udp_payload: u16) -> Self {
        Self {
            transport: Transport::Udp,
            max_udp_payload,
            max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
            tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
            edns_padding_block_size: 0,
            any_response: AnyResponseMode::Minimal,
        }
    }

    pub fn tcp() -> Self {
        Self {
            transport: Transport::Tcp,
            max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
            max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
            tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
            edns_padding_block_size: 0,
            any_response: AnyResponseMode::Minimal,
        }
    }
}

impl Default for AnswerOptions {
    fn default() -> Self {
        Self::udp(DEFAULT_MAX_UDP_PAYLOAD)
    }
}

pub fn answer_datagram(packet: &[u8], zone_store: &ZoneStore) -> DatagramAction {
    answer_message(packet, zone_store, AnswerOptions::default())
}

pub fn answer_message(
    packet: &[u8],
    zone_store: &ZoneStore,
    options: AnswerOptions,
) -> DatagramAction {
    answer_message_with_notify_authority(packet, zone_store, options, |_, _| true)
}

pub fn answer_message_with_notify_authority(
    packet: &[u8],
    zone_store: &ZoneStore,
    options: AnswerOptions,
    notify_authorized: impl Fn(&DomainName, u16) -> bool,
) -> DatagramAction {
    answer_message_with_notify_hooks(packet, zone_store, options, notify_authorized, |_, _, _| {})
}

pub fn answer_message_with_notify_hooks(
    packet: &[u8],
    zone_store: &ZoneStore,
    options: AnswerOptions,
    notify_authorized: impl Fn(&DomainName, u16) -> bool,
    notify_accepted: impl Fn(&DomainName, u16, Option<u32>),
) -> DatagramAction {
    answer_message_with_notify_hooks_and_query_observer(
        packet,
        zone_store,
        options,
        notify_authorized,
        notify_accepted,
        |_| {},
    )
}

pub fn answer_message_with_notify_hooks_and_query_observer(
    packet: &[u8],
    zone_store: &ZoneStore,
    options: AnswerOptions,
    notify_authorized: impl Fn(&DomainName, u16) -> bool,
    notify_accepted: impl Fn(&DomainName, u16, Option<u32>),
    query_answered: impl Fn(&LookupResult),
) -> DatagramAction {
    let header = match Header::parse(packet) {
        Ok(header) => header,
        Err(DnsParseError::ShortHeader) => return DatagramAction::Discard,
        Err(DnsParseError::FormErr) => return DatagramAction::Discard,
    };

    if header.is_response() {
        return DatagramAction::Discard;
    }

    match header.opcode() {
        Some(Opcode::Query) => {}
        Some(Opcode::Notify) => {
            return answer_notify_message(
                &header,
                packet,
                zone_store,
                options,
                &notify_authorized,
                &notify_accepted,
            );
        }
        None => {
            let question = parse_echoable_question(&header, packet);
            return DatagramAction::Respond(build_response(
                &header,
                Rcode::NotImp,
                false,
                question.as_ref(),
                &[],
                &[],
                &[],
                RequestMetadata::empty(),
                options,
            ));
        }
    }

    answer_query_message(&header, packet, zone_store, options, &query_answered)
}

fn answer_query_message(
    header: &Header,
    packet: &[u8],
    zone_store: &ZoneStore,
    options: AnswerOptions,
    query_answered: &impl Fn(&LookupResult),
) -> DatagramAction {
    if header.qdcount != 1 {
        return DatagramAction::Respond(build_response(
            header,
            Rcode::FormErr,
            false,
            None,
            &[],
            &[],
            &[],
            RequestMetadata::empty(),
            options,
        ));
    }

    let question = match Question::parse(packet) {
        Ok(question) => question,
        Err(DnsParseError::ShortHeader) => return DatagramAction::Discard,
        Err(DnsParseError::FormErr) => {
            return DatagramAction::Respond(build_response(
                header,
                Rcode::FormErr,
                false,
                None,
                &[],
                &[],
                &[],
                RequestMetadata::empty(),
                options,
            ));
        }
    };

    let metadata = match RequestMetadata::parse(header, packet, &question) {
        Ok(metadata) => metadata,
        Err(EdnsError::FormErr) => {
            return DatagramAction::Respond(build_response(
                header,
                Rcode::FormErr,
                false,
                Some(&question),
                &[],
                &[],
                &[],
                RequestMetadata::empty(),
                options,
            ));
        }
        Err(EdnsError::BadVers(metadata)) => {
            return DatagramAction::Respond(build_response(
                header,
                Rcode::NoError,
                false,
                Some(&question),
                &[],
                &[],
                &[],
                metadata.with_extended_rcode(16),
                options,
            ));
        }
    };

    if let Some(response_code) = rejected_qtype(question.qtype) {
        return DatagramAction::Respond(build_response(
            header,
            response_code,
            false,
            Some(&question),
            &[],
            &[],
            &[],
            metadata,
            options,
        ));
    }

    if question.qclass != DNS_CLASS_IN && question.qclass != DNS_CLASS_ANY {
        return DatagramAction::Respond(build_response(
            header,
            Rcode::Refused,
            false,
            Some(&question),
            &[],
            &[],
            &[],
            metadata,
            options,
        ));
    }

    let Some(zone) = zone_store.find_zone(&question.qname) else {
        return DatagramAction::Respond(build_response(
            header,
            Rcode::Refused,
            false,
            Some(&question),
            &[],
            &[],
            &[],
            metadata,
            options,
        ));
    };

    if zone.state != ZoneState::Active {
        return DatagramAction::Respond(build_response(
            header,
            Rcode::ServFail,
            false,
            Some(&question),
            &[],
            &[],
            &[],
            metadata,
            options,
        ));
    }

    let lookup = zone.lookup_with_options(
        &question.qname,
        question.qtype,
        question.qclass,
        options.max_cname_chain,
        options.any_response,
    );
    let (lookup, dnssec_augmented) = if metadata.dnssec_requested() {
        zone.augment_lookup_result_with_dnssec(
            lookup,
            &question.qname,
            question.qtype,
            question.qclass,
        )
    } else {
        (lookup, false)
    };
    query_answered(&lookup);
    DatagramAction::Respond(build_response(
        header,
        lookup.rcode,
        lookup.authoritative,
        Some(&question),
        &lookup.answers,
        &lookup.authorities,
        &lookup.additionals,
        metadata.with_dnssec_augmented(dnssec_augmented),
        options,
    ))
}

fn answer_notify_message(
    header: &Header,
    packet: &[u8],
    zone_store: &ZoneStore,
    options: AnswerOptions,
    notify_authorized: &impl Fn(&DomainName, u16) -> bool,
    notify_accepted: &impl Fn(&DomainName, u16, Option<u32>),
) -> DatagramAction {
    if header.qdcount != 1 {
        return DatagramAction::Respond(build_response(
            header,
            Rcode::FormErr,
            false,
            None,
            &[],
            &[],
            &[],
            RequestMetadata::empty(),
            options,
        ));
    }

    let question = match Question::parse(packet) {
        Ok(question) => question,
        Err(DnsParseError::ShortHeader) => return DatagramAction::Discard,
        Err(DnsParseError::FormErr) => {
            return DatagramAction::Respond(build_response(
                header,
                Rcode::FormErr,
                false,
                None,
                &[],
                &[],
                &[],
                RequestMetadata::empty(),
                options,
            ));
        }
    };

    let metadata = match RequestMetadata::parse(header, packet, &question) {
        Ok(metadata) => metadata,
        Err(EdnsError::FormErr) => {
            return DatagramAction::Respond(build_response(
                header,
                Rcode::FormErr,
                false,
                Some(&question),
                &[],
                &[],
                &[],
                RequestMetadata::empty(),
                options,
            ));
        }
        Err(EdnsError::BadVers(metadata)) => {
            return DatagramAction::Respond(build_response(
                header,
                Rcode::NoError,
                false,
                Some(&question),
                &[],
                &[],
                &[],
                metadata.with_extended_rcode(16),
                options,
            ));
        }
    };

    if question.qtype != RecordType::Soa as u16 {
        return DatagramAction::Respond(build_response(
            header,
            Rcode::FormErr,
            false,
            Some(&question),
            &[],
            &[],
            &[],
            metadata,
            options,
        ));
    }

    let notify_soa_serial = match validate_notify_answer_soa(header, packet, &question) {
        Ok(serial) => serial,
        Err(_) => {
            return DatagramAction::Respond(build_response(
                header,
                Rcode::FormErr,
                false,
                Some(&question),
                &[],
                &[],
                &[],
                metadata,
                options,
            ));
        }
    };

    if question.qclass != DNS_CLASS_IN || zone_store.find_exact_zone(&question.qname).is_none() {
        return DatagramAction::Respond(build_response(
            header,
            Rcode::Refused,
            false,
            Some(&question),
            &[],
            &[],
            &[],
            metadata,
            options,
        ));
    }

    if !notify_authorized(&question.qname, question.qclass) {
        return DatagramAction::Discard;
    }

    notify_accepted(&question.qname, question.qclass, notify_soa_serial);

    DatagramAction::Respond(build_response(
        header,
        Rcode::NoError,
        true,
        Some(&question),
        &[],
        &[],
        &[],
        metadata,
        options,
    ))
}

fn validate_notify_answer_soa(
    header: &Header,
    packet: &[u8],
    question: &Question,
) -> Result<Option<u32>, EdnsError> {
    let mut offset = DNS_HEADER_LEN + question.wire().len();
    let mut serial = None;
    for _ in 0..header.ancount {
        let (record, consumed) = parse_additional_record(packet, offset)?;
        offset += consumed;
        if record.rr_type == RecordType::Soa as u16 {
            if record.owner.canonical_key() != question.qname.canonical_key()
                || record.class != question.qclass
            {
                return Err(EdnsError::FormErr);
            }
            serial = Some(soa_serial(&record.rdata)?);
        }
    }
    Ok(serial)
}

fn soa_serial(rdata: &[u8]) -> Result<u32, EdnsError> {
    let (_, consumed_mname) = DomainName::parse(rdata, 0).map_err(|_| EdnsError::FormErr)?;
    let offset = consumed_mname;
    let (_, consumed_rname) = DomainName::parse(rdata, offset).map_err(|_| EdnsError::FormErr)?;
    let offset = offset + consumed_rname;
    if offset + 20 != rdata.len() {
        return Err(EdnsError::FormErr);
    }
    Ok(u32::from_be_bytes([
        rdata[offset],
        rdata[offset + 1],
        rdata[offset + 2],
        rdata[offset + 3],
    ]))
}

fn parse_echoable_question(header: &Header, packet: &[u8]) -> Option<Question> {
    if header.qdcount == 1 {
        Question::parse(packet).ok()
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn build_response(
    header: &Header,
    rcode: Rcode,
    authoritative: bool,
    question: Option<&Question>,
    answers: &[ResourceRecord],
    authorities: &[ResourceRecord],
    additionals: &[ResourceRecord],
    metadata: RequestMetadata,
    options: AnswerOptions,
) -> Vec<u8> {
    let mut response = build_response_inner(
        header,
        rcode,
        authoritative,
        false,
        question,
        answers,
        authorities,
        additionals,
        &metadata,
        options,
    );
    if options.transport == Transport::Udp && response.len() > metadata.udp_ceiling(options) {
        response = build_truncated_response(
            header,
            rcode,
            authoritative,
            question,
            answers,
            authorities,
            additionals,
            &metadata,
            options,
        );
    }
    response
}

#[allow(clippy::too_many_arguments)]
fn build_response_inner(
    header: &Header,
    rcode: Rcode,
    authoritative: bool,
    truncated: bool,
    question: Option<&Question>,
    answers: &[ResourceRecord],
    authorities: &[ResourceRecord],
    additionals: &[ResourceRecord],
    metadata: &RequestMetadata,
    options: AnswerOptions,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(DNS_HEADER_LEN + question.map_or(0, |q| q.wire().len()));
    response.extend_from_slice(&header.id.to_be_bytes());
    response.extend_from_slice(
        &header
            .response_flags(rcode, authoritative, truncated)
            .to_be_bytes(),
    );
    response.extend_from_slice(&(u16::from(question.is_some())).to_be_bytes());
    response.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    response.extend_from_slice(&(authorities.len() as u16).to_be_bytes());
    response.extend_from_slice(
        &((additionals.len() + usize::from(metadata.edns.is_some())) as u16).to_be_bytes(),
    );

    if let Some(question) = question {
        response.extend_from_slice(question.wire());
    }

    for record in answers.iter().chain(authorities).chain(additionals) {
        encode_record(record, &mut response);
    }

    if let Some(edns) = metadata.edns {
        encode_opt_record(
            edns,
            metadata.extended_rcode,
            metadata.dnssec_augmented,
            options,
            metadata.udp_ceiling(options),
            &mut response,
        );
    }

    response
}

#[allow(clippy::too_many_arguments)]
fn build_truncated_response(
    header: &Header,
    rcode: Rcode,
    authoritative: bool,
    question: Option<&Question>,
    answers: &[ResourceRecord],
    authorities: &[ResourceRecord],
    additionals: &[ResourceRecord],
    metadata: &RequestMetadata,
    options: AnswerOptions,
) -> Vec<u8> {
    let ceiling = metadata.udp_ceiling(options);
    let mut kept_answers = answers.to_vec();
    let mut kept_authorities = authorities.to_vec();
    let mut kept_additionals = additionals.to_vec();

    loop {
        let metadata = metadata.with_dnssec_augmented(truncated_dnssec_augmented(
            metadata,
            &kept_answers,
            &kept_authorities,
            &kept_additionals,
        ));
        let response = build_response_inner(
            header,
            rcode,
            authoritative,
            true,
            question,
            &kept_answers,
            &kept_authorities,
            &kept_additionals,
            &metadata,
            options,
        );
        if response.len() <= ceiling {
            return response;
        }

        let removed_record = if kept_additionals.pop().is_some() {
            true
        } else if let Some(index) = kept_authorities
            .iter()
            .rposition(|record| record.rr_type != RecordType::Soa as u16)
        {
            kept_authorities.remove(index);
            true
        } else {
            kept_answers.pop().is_some() || kept_authorities.pop().is_some()
        };

        if !removed_record {
            return response;
        }
    }
}

fn truncated_dnssec_augmented(
    metadata: &RequestMetadata,
    answers: &[ResourceRecord],
    authorities: &[ResourceRecord],
    additionals: &[ResourceRecord],
) -> bool {
    metadata.dnssec_augmented
        && answers
            .iter()
            .chain(authorities)
            .chain(additionals)
            .any(|record| {
                matches!(
                    record.rr_type,
                    rr_type if rr_type == RecordType::Ds as u16
                        || rr_type == RecordType::Rrsig as u16
                        || rr_type == RecordType::Nsec as u16
                        || rr_type == RecordType::Nsec3 as u16
                )
            })
}

fn encode_record(record: &ResourceRecord, response: &mut Vec<u8>) {
    response.extend_from_slice(&record.owner.to_wire());
    response.extend_from_slice(&record.rr_type.to_be_bytes());
    response.extend_from_slice(&record.class.to_be_bytes());
    response.extend_from_slice(&record.ttl.to_be_bytes());
    response.extend_from_slice(&(record.rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&record.rdata);
}

fn encode_opt_record(
    edns: EdnsMetadata,
    extended_rcode: u16,
    dnssec_augmented: bool,
    options: AnswerOptions,
    udp_ceiling: usize,
    response: &mut Vec<u8>,
) {
    let rdata = encode_edns_response_options(edns, options, response.len(), udp_ceiling);

    response.push(0);
    response.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
    response.extend_from_slice(&options.max_udp_payload.to_be_bytes());
    let ext_rcode = ((extended_rcode >> 4) as u32) << 24;
    let ttl = ext_rcode | u32::from(dnssec_augmented) << 15;
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);
}

fn encode_edns_response_options(
    edns: EdnsMetadata,
    options: AnswerOptions,
    response_len_before_opt: usize,
    udp_ceiling: usize,
) -> Vec<u8> {
    let mut rdata = Vec::new();

    if options.transport == Transport::Tcp && edns.tcp_keepalive_requested {
        let timeout_units = options
            .tcp_keepalive_timeout_secs
            .saturating_mul(10)
            .min(u64::from(u16::MAX)) as u16;

        rdata.extend_from_slice(&EDNS_TCP_KEEPALIVE_OPTION.to_be_bytes());
        rdata.extend_from_slice(&2u16.to_be_bytes());
        rdata.extend_from_slice(&timeout_units.to_be_bytes());
    }

    if edns.padding_requested && options.edns_padding_block_size > 0 {
        append_edns_padding_if_it_fits(&mut rdata, options, response_len_before_opt, udp_ceiling);
    }

    rdata
}

fn append_edns_padding_if_it_fits(
    rdata: &mut Vec<u8>,
    options: AnswerOptions,
    response_len_before_opt: usize,
    udp_ceiling: usize,
) {
    let block_size = options.edns_padding_block_size as usize;
    let total_before_padding_data = response_len_before_opt + 11 + rdata.len() + 4;
    let padding_len = (block_size - (total_before_padding_data % block_size)) % block_size;
    let padded_response_len = total_before_padding_data + padding_len;

    if options.transport == Transport::Udp && padded_response_len > udp_ceiling {
        return;
    }

    rdata.extend_from_slice(&EDNS_PADDING_OPTION.to_be_bytes());
    rdata.extend_from_slice(&(padding_len as u16).to_be_bytes());
    rdata.resize(rdata.len() + padding_len, 0);
}

fn rejected_qtype(qtype: u16) -> Option<Rcode> {
    match qtype {
        0 | 41 | 249 | 250 | 65_535 => Some(Rcode::FormErr),
        251 | 252 => Some(Rcode::Refused),
        253 | 254 => Some(Rcode::NotImp),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequestMetadata {
    edns: Option<EdnsMetadata>,
    extended_rcode: u16,
    dnssec_augmented: bool,
}

impl RequestMetadata {
    fn empty() -> Self {
        Self {
            edns: None,
            extended_rcode: 0,
            dnssec_augmented: false,
        }
    }

    fn parse(header: &Header, packet: &[u8], question: &Question) -> Result<Self, EdnsError> {
        let mut offset = DNS_HEADER_LEN + question.wire().len();
        for _ in 0..header.ancount {
            let (rr_type, consumed) = parse_record_header(packet, offset)?;
            if rr_type == RecordType::Opt as u16 {
                return Err(EdnsError::FormErr);
            }
            offset += consumed;
        }
        for _ in 0..header.nscount {
            let (rr_type, consumed) = parse_record_header(packet, offset)?;
            if rr_type == RecordType::Opt as u16 {
                return Err(EdnsError::FormErr);
            }
            offset += consumed;
        }

        let mut edns = None;
        for _ in 0..header.arcount {
            let (record, consumed) = parse_additional_record(packet, offset)?;
            offset += consumed;
            if record.rr_type == RecordType::Opt as u16 {
                if edns.is_some() || record.owner != DomainName::root() {
                    return Err(EdnsError::FormErr);
                }

                let parsed_options = parse_edns_options(&record.rdata)?;
                let metadata = EdnsMetadata {
                    payload_size: record.class.max(512),
                    version: ((record.ttl >> 16) & 0xff) as u8,
                    do_bit: record.ttl & 0x8000 != 0,
                    tcp_keepalive_requested: parsed_options.tcp_keepalive_requested,
                    padding_requested: parsed_options.padding_requested,
                };
                if metadata.version > 0 {
                    return Err(EdnsError::BadVers(Self {
                        edns: Some(metadata),
                        extended_rcode: 0,
                        dnssec_augmented: false,
                    }));
                }
                edns = Some(metadata);
            }
        }

        if offset != packet.len() {
            return Err(EdnsError::FormErr);
        }

        Ok(Self {
            edns,
            extended_rcode: 0,
            dnssec_augmented: false,
        })
    }

    fn with_extended_rcode(mut self, extended_rcode: u16) -> Self {
        self.extended_rcode = extended_rcode;
        self
    }

    fn with_dnssec_augmented(mut self, dnssec_augmented: bool) -> Self {
        self.dnssec_augmented = dnssec_augmented;
        self
    }

    fn dnssec_requested(&self) -> bool {
        self.edns.is_some_and(|edns| edns.do_bit)
    }

    fn udp_ceiling(&self, options: AnswerOptions) -> usize {
        let client_payload = self.edns.map_or(512, |edns| edns.payload_size) as usize;
        client_payload.min(options.max_udp_payload as usize)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EdnsMetadata {
    payload_size: u16,
    version: u8,
    do_bit: bool,
    tcp_keepalive_requested: bool,
    padding_requested: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct EdnsOptions {
    tcp_keepalive_requested: bool,
    padding_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRecord {
    owner: DomainName,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdnsError {
    FormErr,
    BadVers(RequestMetadata),
}

fn parse_record_header(packet: &[u8], offset: usize) -> Result<(u16, usize), EdnsError> {
    let start = offset;
    let (_, consumed) = DomainName::parse(packet, offset).map_err(|_| EdnsError::FormErr)?;
    let offset = offset + consumed;
    if offset + 10 > packet.len() {
        return Err(EdnsError::FormErr);
    }
    let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
    let end = offset + 10 + rdlength;
    if end > packet.len() {
        return Err(EdnsError::FormErr);
    }
    Ok((rr_type, end - start))
}

fn parse_additional_record(
    packet: &[u8],
    offset: usize,
) -> Result<(ParsedRecord, usize), EdnsError> {
    let start = offset;
    let (owner, consumed) = DomainName::parse(packet, offset).map_err(|_| EdnsError::FormErr)?;
    let mut offset = offset + consumed;
    if offset + 10 > packet.len() {
        return Err(EdnsError::FormErr);
    }
    let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let ttl = u32::from_be_bytes([
        packet[offset + 4],
        packet[offset + 5],
        packet[offset + 6],
        packet[offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
    offset += 10;
    if offset + rdlength > packet.len() {
        return Err(EdnsError::FormErr);
    }
    let rdata = packet[offset..offset + rdlength].to_vec();
    offset += rdlength;

    Ok((
        ParsedRecord {
            owner,
            rr_type,
            class,
            ttl,
            rdata,
        },
        offset - start,
    ))
}

fn parse_edns_options(rdata: &[u8]) -> Result<EdnsOptions, EdnsError> {
    let mut options = EdnsOptions::default();
    let mut offset = 0usize;
    while offset < rdata.len() {
        if offset + 4 > rdata.len() {
            return Err(EdnsError::FormErr);
        }
        let option_code = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
        let option_len = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
        offset += 4;
        if offset + option_len > rdata.len() {
            return Err(EdnsError::FormErr);
        }
        if option_code == EDNS_TCP_KEEPALIVE_OPTION {
            options.tcp_keepalive_requested = true;
        } else if option_code == EDNS_PADDING_OPTION {
            options.padding_requested = true;
        }
        offset += option_len;
    }
    Ok(options)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupResult {
    pub rcode: Rcode,
    pub authoritative: bool,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
    pub termination: Option<LookupTermination>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupTermination {
    CnameChainLimit,
    CnameLoop,
}

impl LookupResult {
    pub fn positive(rrset: &Rrset) -> Self {
        Self::positive_records(rrset.records())
    }

    pub fn positive_records(answers: Vec<ResourceRecord>) -> Self {
        Self::positive_with_additionals(answers, Vec::new())
    }

    pub fn positive_records_with_termination(
        answers: Vec<ResourceRecord>,
        termination: LookupTermination,
    ) -> Self {
        Self {
            termination: Some(termination),
            ..Self::positive_records(answers)
        }
    }

    pub fn positive_with_additionals(
        answers: Vec<ResourceRecord>,
        additionals: Vec<ResourceRecord>,
    ) -> Self {
        Self {
            rcode: Rcode::NoError,
            authoritative: true,
            answers,
            authorities: Vec::new(),
            additionals,
            termination: None,
        }
    }

    pub fn referral(authorities: Vec<ResourceRecord>, additionals: Vec<ResourceRecord>) -> Self {
        Self {
            rcode: Rcode::NoError,
            authoritative: false,
            answers: Vec::new(),
            authorities,
            additionals,
            termination: None,
        }
    }

    pub fn nodata(soa: Option<&Rrset>) -> Self {
        Self {
            rcode: Rcode::NoError,
            authoritative: true,
            answers: Vec::new(),
            authorities: soa.map_or_else(Vec::new, Rrset::records),
            additionals: Vec::new(),
            termination: None,
        }
    }

    pub fn nodata_with_answers(answers: Vec<ResourceRecord>, soa: Option<&Rrset>) -> Self {
        Self {
            rcode: Rcode::NoError,
            authoritative: true,
            answers,
            authorities: soa.map_or_else(Vec::new, Rrset::records),
            additionals: Vec::new(),
            termination: None,
        }
    }

    pub fn nxdomain(soa: Option<&Rrset>) -> Self {
        Self::nxdomain_with_answers(Vec::new(), soa)
    }

    pub fn nxdomain_with_answers(answers: Vec<ResourceRecord>, soa: Option<&Rrset>) -> Self {
        Self {
            rcode: Rcode::NxDomain,
            authoritative: true,
            answers,
            authorities: soa.map_or_else(Vec::new, Rrset::records),
            additionals: Vec::new(),
            termination: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::{ZoneSnapshot, ZoneStore};

    fn query(qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(qname);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&qclass.to_be_bytes());
        packet
    }

    fn notify(qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut packet = query(qname, qtype, qclass);
        packet[2..4].copy_from_slice(&((Opcode::Notify as u16) << 11).to_be_bytes());
        packet
    }

    fn append_opt(packet: &mut Vec<u8>, payload_size: u16, ttl: u32, rdata: &[u8]) {
        packet[11] = packet[11].checked_add(1).unwrap();
        packet.push(0);
        packet.extend_from_slice(&(RecordType::Opt as u16).to_be_bytes());
        packet.extend_from_slice(&payload_size.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(rdata);
    }

    fn append_answer(packet: &mut Vec<u8>, owner: &str, rr_type: u16, class: u16, rdata: Vec<u8>) {
        let answer_count = u16::from_be_bytes([packet[6], packet[7]]) + 1;
        packet[6..8].copy_from_slice(&answer_count.to_be_bytes());
        packet.extend_from_slice(&DomainName::from_absolute_str(owner).unwrap().to_wire());
        packet.extend_from_slice(&rr_type.to_be_bytes());
        packet.extend_from_slice(&class.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);
    }

    fn example_name() -> Vec<u8> {
        b"\x07Example\x04test\x00".to_vec()
    }

    fn response(packet: &[u8], zones: &[DomainName]) -> Vec<u8> {
        let store = ZoneStore::new();
        for zone in zones {
            store.insert_loading(zone.clone());
        }

        match answer_datagram(packet, &store) {
            DatagramAction::Discard => panic!("expected response"),
            DatagramAction::Respond(response) => response,
        }
    }

    fn store_response(packet: &[u8], store: &ZoneStore) -> Vec<u8> {
        match answer_datagram(packet, store) {
            DatagramAction::Discard => panic!("expected response"),
            DatagramAction::Respond(response) => response,
        }
    }

    fn store_response_with_options(
        packet: &[u8],
        store: &ZoneStore,
        options: AnswerOptions,
    ) -> Vec<u8> {
        match answer_message(packet, store, options) {
            DatagramAction::Discard => panic!("expected response"),
            DatagramAction::Respond(response) => response,
        }
    }

    fn response_answer_types(response: &[u8]) -> Vec<u16> {
        response_answers(response)
            .into_iter()
            .map(|(_, rr_type)| rr_type)
            .collect()
    }

    fn response_answer_rdatas(response: &[u8], expected_type: u16) -> Vec<Vec<u8>> {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        let mut rdatas = Vec::new();
        for _ in 0..header.ancount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed;
            let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let rdlength =
                u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
            offset += 10;
            if rr_type == expected_type {
                rdatas.push(response[offset..offset + rdlength].to_vec());
            }
            offset += rdlength;
        }
        rdatas
    }

    fn response_answers(response: &[u8]) -> Vec<(DomainName, u16)> {
        response_sections(response).0
    }

    fn response_authority_types(response: &[u8]) -> Vec<u16> {
        response_sections(response)
            .1
            .into_iter()
            .map(|(_, rr_type)| rr_type)
            .collect()
    }

    fn response_additional_types(response: &[u8]) -> Vec<u16> {
        response_sections(response)
            .2
            .into_iter()
            .map(|(_, rr_type)| rr_type)
            .collect()
    }

    type ParsedSection = Vec<(DomainName, u16)>;

    fn response_sections(response: &[u8]) -> (ParsedSection, ParsedSection, ParsedSection) {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        let answers = parse_response_records(response, &mut offset, header.ancount);
        let authorities = parse_response_records(response, &mut offset, header.nscount);
        let additionals = parse_response_records(response, &mut offset, header.arcount);
        (answers, authorities, additionals)
    }

    fn parse_response_records(response: &[u8], offset: &mut usize, count: u16) -> ParsedSection {
        let mut records = Vec::new();
        for _ in 0..count {
            let (owner, consumed) = DomainName::parse(response, *offset).unwrap();
            *offset += consumed;
            let rr_type = u16::from_be_bytes([response[*offset], response[*offset + 1]]);
            let rdlength =
                u16::from_be_bytes([response[*offset + 8], response[*offset + 9]]) as usize;
            records.push((owner, rr_type));
            *offset += 10 + rdlength;
        }
        records
    }

    fn response_opt_rdata(response: &[u8]) -> Option<Vec<u8>> {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        skip_response_records(response, &mut offset, header.ancount);
        skip_response_records(response, &mut offset, header.nscount);

        for _ in 0..header.arcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed;
            let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let rdlength =
                u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
            offset += 10;
            let rdata = response[offset..offset + rdlength].to_vec();
            offset += rdlength;
            if rr_type == RecordType::Opt as u16 {
                return Some(rdata);
            }
        }

        None
    }

    fn response_opt_ttl(response: &[u8]) -> Option<u32> {
        let header = Header::parse(response).unwrap();
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..header.qdcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed + 4;
        }

        skip_response_records(response, &mut offset, header.ancount);
        skip_response_records(response, &mut offset, header.nscount);

        for _ in 0..header.arcount {
            let (_, consumed) = DomainName::parse(response, offset).unwrap();
            offset += consumed;
            let rr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let ttl = u32::from_be_bytes([
                response[offset + 4],
                response[offset + 5],
                response[offset + 6],
                response[offset + 7],
            ]);
            let rdlength =
                u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
            offset += 10 + rdlength;
            if rr_type == RecordType::Opt as u16 {
                return Some(ttl);
            }
        }

        None
    }

    fn skip_response_records(response: &[u8], offset: &mut usize, count: u16) {
        for _ in 0..count {
            let (_, consumed) = DomainName::parse(response, *offset).unwrap();
            *offset += consumed;
            let rdlength =
                u16::from_be_bytes([response[*offset + 8], response[*offset + 9]]) as usize;
            *offset += 10 + rdlength;
        }
    }

    fn cname_rdata(target: &str) -> Vec<u8> {
        DomainName::from_absolute_str(target).unwrap().to_wire()
    }

    fn mx_rdata(preference: u16, exchange: &str) -> Vec<u8> {
        let mut rdata = preference.to_be_bytes().to_vec();
        rdata.extend(cname_rdata(exchange));
        rdata
    }

    fn srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        rdata.extend_from_slice(&weight.to_be_bytes());
        rdata.extend_from_slice(&port.to_be_bytes());
        rdata.extend(cname_rdata(target));
        rdata
    }

    fn character_string(value: &[u8]) -> Vec<u8> {
        let mut wire = vec![value.len() as u8];
        wire.extend_from_slice(value);
        wire
    }

    fn naptr_rdata(replacement: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&10u16.to_be_bytes());
        rdata.extend_from_slice(&20u16.to_be_bytes());
        rdata.extend(character_string(b"s"));
        rdata.extend(character_string(b"SIP+D2U"));
        rdata.extend(character_string(b""));
        rdata.extend(cname_rdata(replacement));
        rdata
    }

    fn svcb_rdata(priority: u16, target: &str, params: &[u8]) -> Vec<u8> {
        let mut rdata = priority.to_be_bytes().to_vec();
        rdata.extend(cname_rdata(target));
        rdata.extend_from_slice(params);
        rdata
    }

    fn soa_rdata() -> Vec<u8> {
        b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()
    }

    fn rrsig_rdata(type_covered: RecordType) -> Vec<u8> {
        let mut rdata = (type_covered as u16).to_be_bytes().to_vec();
        rdata.extend_from_slice(&[8, 2]);
        rdata.extend_from_slice(&300u32.to_be_bytes());
        rdata.extend_from_slice(&1_700_086_400u32.to_be_bytes());
        rdata.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend(cname_rdata("example.test."));
        rdata.extend_from_slice(b"signature");
        rdata
    }

    fn nsec_rdata(next_owner: &str) -> Vec<u8> {
        let mut rdata = cname_rdata(next_owner);
        rdata.extend_from_slice(&[0, 1, 0x40]);
        rdata
    }

    fn dnskey_rdata(algorithm: u8) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&256u16.to_be_bytes());
        rdata.push(3);
        rdata.push(algorithm);
        rdata.extend_from_slice(b"public-key");
        rdata
    }

    fn nsec3_rdata(hash_algorithm: u8) -> Vec<u8> {
        let mut rdata = vec![hash_algorithm, 0];
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(0);
        rdata.push(4);
        rdata.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        rdata.extend_from_slice(&[0, 1, 0x40]);
        rdata
    }

    fn nsec3param_rdata(hash_algorithm: u8) -> Vec<u8> {
        let mut rdata = vec![hash_algorithm, 0];
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(0);
        rdata
    }

    #[test]
    fn discards_short_header() {
        assert_eq!(
            answer_datagram(&[0; 11], &ZoneStore::new()),
            DatagramAction::Discard
        );
    }

    #[test]
    fn discards_response_on_query_socket() {
        let mut packet = query(&example_name(), 1, 1);
        packet[2] = 0x80;
        assert_eq!(
            answer_datagram(&packet, &ZoneStore::new()),
            DatagramAction::Discard
        );
    }

    #[test]
    fn unsupported_opcode_gets_notimp() {
        let mut packet = query(&example_name(), 1, 1);
        packet[2] = 0x28;
        let response = store_response(&packet, &ZoneStore::new());
        assert_eq!(response[3] & 0x0f, Rcode::NotImp as u8);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn invalid_qdcount_gets_formerr_without_question() {
        let mut packet = query(&example_name(), 1, 1);
        packet[5] = 2;
        let response = store_response(&packet, &ZoneStore::new());
        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 0);
    }

    #[test]
    fn notify_soa_for_configured_zone_gets_notify_response() {
        let packet = notify(&example_name(), RecordType::Soa as u16, 1);
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x7800, (Opcode::Notify as u16) << 11);
        assert_eq!(flags & 0x0400, 0x0400);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn notify_embedded_soa_matching_question_is_accepted() {
        let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
        append_answer(
            &mut packet,
            "example.test.",
            RecordType::Soa as u16,
            1,
            soa_rdata(),
        );
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn notify_embedded_soa_owner_mismatch_gets_formerr() {
        let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
        append_answer(
            &mut packet,
            "other.example.test.",
            RecordType::Soa as u16,
            1,
            soa_rdata(),
        );
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }

    #[test]
    fn notify_embedded_soa_class_mismatch_gets_formerr() {
        let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
        append_answer(
            &mut packet,
            "example.test.",
            RecordType::Soa as u16,
            3,
            soa_rdata(),
        );
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }

    #[test]
    fn notify_non_soa_question_gets_formerr() {
        let packet = notify(&example_name(), RecordType::A as u16, 1);
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn notify_unknown_zone_gets_refused() {
        let packet = notify(&example_name(), RecordType::Soa as u16, 1);
        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn notify_unauthorized_source_is_discarded() {
        let packet = notify(&example_name(), RecordType::Soa as u16, 1);
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());

        let action = answer_message_with_notify_authority(
            &packet,
            &store,
            AnswerOptions::default(),
            |_, _| false,
        );

        assert_eq!(action, DatagramAction::Discard);
    }

    #[test]
    fn notify_acceptance_hook_receives_embedded_soa_serial() {
        let mut packet = notify(&example_name(), RecordType::Soa as u16, 1);
        append_answer(
            &mut packet,
            "example.test.",
            RecordType::Soa as u16,
            1,
            soa_rdata(),
        );
        let store = ZoneStore::new();
        store.insert_loading(DomainName::from_absolute_str("example.test.").unwrap());
        let observed = std::cell::Cell::new(None);

        let response = match answer_message_with_notify_hooks(
            &packet,
            &store,
            AnswerOptions::default(),
            |_, _| true,
            |_, _, serial| observed.set(serial),
        ) {
            DatagramAction::Respond(response) => response,
            DatagramAction::Discard => panic!("expected NOTIFY response"),
        };

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(observed.get(), Some(1));
    }

    #[test]
    fn malformed_qname_gets_formerr() {
        let packet = query(b"\xc0\x0c", 1, 1);
        let response = store_response(&packet, &ZoneStore::new());
        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }

    #[test]
    fn unsupported_qclass_gets_refused_with_question() {
        let packet = query(&example_name(), 1, 3);
        let response = store_response(&packet, &ZoneStore::new());
        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn outside_served_zones_gets_refused() {
        let packet = query(&example_name(), 1, 1);
        let zones = [DomainName::from_absolute_str("other.test.").unwrap()];
        let response = response(&packet, &zones);
        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
    }

    #[test]
    fn configured_but_unloaded_zone_gets_servfail() {
        let packet = query(&example_name(), 1, 1);
        let zones = [DomainName::from_absolute_str("test.").unwrap()];
        let response = response(&packet, &zones);
        assert_eq!(response[3] & 0x0f, Rcode::ServFail as u8);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[test]
    fn preserves_rd_and_clears_ra_z_ad_cd_bits() {
        let mut packet = query(&example_name(), 1, 1);
        packet[2..4].copy_from_slice(&0x01f0u16.to_be_bytes());
        let response = store_response(&packet, &ZoneStore::new());
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x8000, 0x8000);
        assert_eq!(flags & 0x0100, 0x0100);
        assert_eq!(flags & 0x0080, 0);
        assert_eq!(flags & 0x0070, 0);
        assert_eq!(flags & 0x0020, 0);
        assert_eq!(flags & 0x0010, 0);
    }

    #[test]
    fn parses_compressed_qname() {
        let mut packet = query(&example_name(), 1, 1);
        packet.extend_from_slice(&0x9999u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        let compressed_offset = packet.len();
        packet.extend_from_slice(b"\xc0\x0c");
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());

        let (name, consumed) = DomainName::parse(&packet, compressed_offset).unwrap();
        assert_eq!(name.to_string(), "Example.test.");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn answers_positive_rrset_from_active_zone() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);
        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
    }

    #[test]
    fn qclass_any_matches_in_zone_data() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 255);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
    }

    #[test]
    fn unknown_type_query_preserves_zero_and_pointer_like_rdata() {
        const UNKNOWN_TYPE: u16 = 65_280;
        let pointer_like_rdata = vec![0xc0, 0x0c, 0, 255];
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("opaque.example.test.").unwrap(),
                    UNKNOWN_TYPE,
                    1,
                    300,
                    vec![Vec::new(), pointer_like_rdata.clone()],
                ),
            ],
        ));

        let packet = query(b"\x06opaque\x07example\x04test\x00", UNKNOWN_TYPE, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![UNKNOWN_TYPE, UNKNOWN_TYPE]
        );
        assert_eq!(
            response_answer_rdatas(&response, UNKNOWN_TYPE),
            vec![Vec::new(), pointer_like_rdata]
        );
    }

    #[test]
    fn qtype_any_defaults_to_minimal_real_rrset_response() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata(10, "mail.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", 255, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
        assert!(!response_answer_types(&response).contains(&13));
    }

    #[test]
    fn qtype_any_full_mode_returns_all_owner_rrsets() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata(10, "mail.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", 255, 1);
        let response = store_response_with_options(
            &packet,
            &store,
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                any_response: AnyResponseMode::Full,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::A as u16, RecordType::Mx as u16]
        );
    }

    #[test]
    fn qtype_any_full_mode_omits_dnssec_proofs_and_signatures_without_do() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::A)],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Nsec3 as u16,
                    1,
                    300,
                    vec![nsec3_rdata(1)],
                ),
            ],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", 255, 1);
        let response = store_response_with_options(
            &packet,
            &store,
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                any_response: AnyResponseMode::Full,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
    }

    #[test]
    fn answers_nodata_with_soa_for_existing_name() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Aaaa as u16,
            1,
        );
        let response = store_response(&packet, &store);
        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
    }

    #[test]
    fn do_nodata_for_existing_name_includes_nsec_and_covering_rrsig() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let mut packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Aaaa as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![
                RecordType::Soa as u16,
                RecordType::Nsec as u16,
                RecordType::Rrsig as u16,
            ]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn non_do_nodata_omits_nsec_dnssec_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("zzz.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Aaaa as u16,
            1,
        );

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Soa as u16]
        );
    }

    #[test]
    fn answers_nxdomain_with_soa_for_missing_name() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("example.test.").unwrap(),
                RecordType::Soa as u16,
                1,
                3600,
                vec![b"\x02ns\x07example\x04test\x00\x0ahostmaster\x07example\x04test\x00\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58\x00\x09\x3a\x80\x00\x00\x01\x2c".to_vec()],
            )],
        ));

        let packet = query(
            b"\x07missing\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);
        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
    }

    #[test]
    fn do_nxdomain_includes_nsec_denial_proofs_and_covering_rrsigs() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("a.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("z.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let mut packet = query(
            b"\x07missing\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![
                RecordType::Soa as u16,
                RecordType::Nsec as u16,
                RecordType::Nsec as u16,
                RecordType::Rrsig as u16,
                RecordType::Rrsig as u16,
            ]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn non_do_nxdomain_omits_nsec_dnssec_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("z.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let packet = query(
            b"\x07missing\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Soa as u16]
        );
    }

    #[test]
    fn follows_cname_to_target_rrset() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x05alias\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16, RecordType::A as u16]
        );
    }

    #[test]
    fn direct_cname_query_returns_only_cname_rrset() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x05alias\x07example\x04test\x00",
            RecordType::Cname as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
    }

    #[test]
    fn cname_negative_terminal_keeps_chain_and_soa() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("missing.example.test.")],
                ),
            ],
        ));

        let packet = query(b"\x05alias\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
    }

    #[test]
    fn cname_loop_stops_with_constructed_chain() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("b.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("b.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("a.example.test.")],
                ),
            ],
        ));

        let packet = query(b"\x01a\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16, RecordType::Cname as u16]
        );
        let zone = store.get("example.test.").expect("zone snapshot");
        let lookup = zone.lookup(
            &DomainName::from_absolute_str("a.example.test.").unwrap(),
            RecordType::A as u16,
            1,
        );
        assert_eq!(lookup.termination, Some(LookupTermination::CnameLoop));
    }

    #[test]
    fn configured_cname_chain_limit_stops_constructed_response() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("b.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("b.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("c.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("c.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 31].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x01a\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response_with_options(
            &packet,
            &store,
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: 1,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 0,
                any_response: AnyResponseMode::Minimal,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
        let zone = store.get("example.test.").expect("zone snapshot");
        let lookup = zone.lookup_with_options(
            &DomainName::from_absolute_str("a.example.test.").unwrap(),
            RecordType::A as u16,
            1,
            1,
            AnyResponseMode::Minimal,
        );
        assert_eq!(lookup.termination, Some(LookupTermination::CnameChainLimit));
    }

    #[test]
    fn dname_synthesizes_cname_and_resolves_target_rrset() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.target.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 40].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05alias\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let answers = response_answers(&response);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![
                RecordType::Dname as u16,
                RecordType::Cname as u16,
                RecordType::A as u16
            ]
        );
        assert_eq!(answers[1].0.to_string(), "www.alias.example.test.");
    }

    #[test]
    fn dname_chain_leaving_zone_returns_constructed_answer_only() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.other.test.")],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05alias\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Dname as u16, RecordType::Cname as u16]
        );
    }

    #[test]
    fn dname_negative_terminal_keeps_chain_and_soa() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Dname as u16,
                    1,
                    300,
                    vec![cname_rdata("target.example.test.")],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05alias\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Dname as u16, RecordType::Cname as u16]
        );
    }

    #[test]
    fn direct_dname_query_returns_only_dname_rrset() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("alias.example.test.").unwrap(),
                RecordType::Dname as u16,
                1,
                300,
                vec![cname_rdata("target.example.test.")],
            )],
        ));

        let packet = query(
            b"\x05alias\x07example\x04test\x00",
            RecordType::Dname as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Dname as u16]
        );
    }

    #[test]
    fn wildcard_synthesizes_answer_owner() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 20].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);
        let answers = response_answers(&response);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].0.to_string(), "foo.example.test.");
        assert_eq!(answers[0].1, RecordType::A as u16);
    }

    #[test]
    fn do_wildcard_answer_includes_nsec_proof_for_exact_name_absence() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 20].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("z.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let mut packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Nsec as u16, RecordType::Rrsig as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn non_do_wildcard_answer_omits_nsec_dnssec_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 20].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("z.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("a.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_authority_types(&response), Vec::<u16>::new());
    }

    #[test]
    fn wildcard_cname_chases_to_target_rrset() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 30].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);
        let answers = response_answers(&response);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16, RecordType::A as u16]
        );
        assert_eq!(answers[0].0.to_string(), "foo.example.test.");
    }

    #[test]
    fn wildcard_cname_negative_terminal_keeps_chain_and_soa() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("missing.example.test.")],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NxDomain as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
    }

    #[test]
    fn wildcard_cname_leaving_zone_returns_constructed_answer_only() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Cname as u16,
                    1,
                    300,
                    vec![cname_rdata("www.other.test.")],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Cname as u16]
        );
    }

    #[test]
    fn wildcard_name_without_qtype_gets_nodata() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![vec![0, 10, 0]],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
    }

    #[test]
    fn empty_non_terminal_blocks_higher_wildcard() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 20].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.foo.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 21].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x03foo\x07example\x04test\x00", RecordType::A as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 1);
    }

    #[test]
    fn delegated_child_query_gets_referral_with_glue() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.child.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 53].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.child.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
                    ]],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn glue_below_delegation_is_not_served_as_authoritative_answer() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns.child.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 53].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x02ns\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16]
        );
    }

    #[test]
    fn occluded_non_glue_below_delegation_is_not_served() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.child.example.test.").unwrap(),
                    RecordType::Txt as u16,
                    1,
                    300,
                    vec![b"\x07occlude".to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("*.child.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 99].to_vec()],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::Txt as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
        assert!(response_additional_types(&response).is_empty());
    }

    #[test]
    fn mx_answer_includes_in_zone_exchange_addresses_as_additionals() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata(10, "mail.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("mail.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 25].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("mail.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x25,
                    ]],
                ),
            ],
        ));

        let packet = query(b"\x07example\x04test\x00", RecordType::Mx as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Mx as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn mx_answer_omits_out_of_zone_exchange_additionals() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Mx as u16,
                    1,
                    300,
                    vec![mx_rdata(10, "mail.other.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("mail.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 25].to_vec()],
                ),
            ],
        ));

        let packet = query(b"\x07example\x04test\x00", RecordType::Mx as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Mx as u16]
        );
        assert!(response_additional_types(&response).is_empty());
    }

    #[test]
    fn srv_answer_includes_in_zone_target_addresses_as_additionals() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("_xmpp._tcp.example.test.").unwrap(),
                    RecordType::Srv as u16,
                    1,
                    300,
                    vec![srv_rdata(10, 20, 5222, "chat.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("chat.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 26].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("chat.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x26,
                    ]],
                ),
            ],
        ));

        let packet = query(
            b"\x05_xmpp\x04_tcp\x07example\x04test\x00",
            RecordType::Srv as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Srv as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn ns_answer_includes_in_zone_target_addresses_as_additionals() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns1.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns1.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 53].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("ns1.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
                    ]],
                ),
            ],
        ));

        let packet = query(b"\x07example\x04test\x00", RecordType::Ns as u16, 1);
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Ns as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn naptr_answer_includes_in_zone_replacement_addresses_as_additionals() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("sip.example.test.").unwrap(),
                    RecordType::Naptr as u16,
                    1,
                    300,
                    vec![naptr_rdata("_sip._udp.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("_sip._udp.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 27].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("_sip._udp.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x27,
                    ]],
                ),
            ],
        ));

        let packet = query(
            b"\x03sip\x07example\x04test\x00",
            RecordType::Naptr as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Naptr as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn svcb_answer_includes_service_mode_target_addresses_as_additionals() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("_dns.example.test.").unwrap(),
                    RecordType::Svcb as u16,
                    1,
                    300,
                    vec![svcb_rdata(
                        1,
                        "svc.example.test.",
                        &[0, 1, 0, 3, 2, b'h', b'2'],
                    )],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("svc.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 28].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("svc.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x28,
                    ]],
                ),
            ],
        ));

        let packet = query(
            b"\x04_dns\x07example\x04test\x00",
            RecordType::Svcb as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Svcb as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn https_answer_includes_alias_mode_target_addresses_as_additionals() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Https as u16,
                    1,
                    300,
                    vec![svcb_rdata(0, "alias.example.test.", &[])],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 29].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("alias.example.test.").unwrap(),
                    RecordType::Aaaa as u16,
                    1,
                    300,
                    vec![vec![
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x29,
                    ]],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Https as u16,
            1,
        );
        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Https as u16]
        );
        assert_eq!(
            response_additional_types(&response),
            vec![RecordType::A as u16, RecordType::Aaaa as u16]
        );
    }

    #[test]
    fn ds_query_at_delegation_owner_is_authoritative_positive() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![0, 12, 8, 2, 1, 2, 3, 4]],
                ),
            ],
        ));

        let packet = query(
            b"\x05child\x07example\x04test\x00",
            RecordType::Ds as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0x0400);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Ds as u16]
        );
        assert_eq!(u16::from_be_bytes([response[8], response[9]]), 0);
    }

    #[test]
    fn ds_query_at_unsigned_delegation_owner_is_authoritative_nodata() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
            ],
        ));

        let packet = query(
            b"\x05child\x07example\x04test\x00",
            RecordType::Ds as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0x0400);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Soa as u16]
        );
    }

    #[test]
    fn ds_query_below_delegation_gets_referral() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
            ],
        ));

        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::Ds as u16,
            1,
        );
        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
    }

    #[test]
    fn do_referral_includes_ds_and_covering_rrsigs() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![0, 12, 8, 2, 1, 2, 3, 4]],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Ns), rrsig_rdata(RecordType::Ds)],
                ),
            ],
        ));
        let mut packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![
                RecordType::Ns as u16,
                RecordType::Ds as u16,
                RecordType::Rrsig as u16,
                RecordType::Rrsig as u16,
            ]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn do_referral_for_unsigned_child_includes_nsec_and_covering_rrsigs() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("next.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Ns), rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let mut packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(flags & 0x0400, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            response_authority_types(&response),
            vec![
                RecordType::Ns as u16,
                RecordType::Nsec as u16,
                RecordType::Rrsig as u16,
                RecordType::Rrsig as u16,
            ]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn non_do_referral_omits_ds_dnssec_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ds as u16,
                    1,
                    300,
                    vec![vec![0, 12, 8, 2, 1, 2, 3, 4]],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Ns), rrsig_rdata(RecordType::Ds)],
                ),
            ],
        ));
        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
    }

    #[test]
    fn non_do_referral_omits_nsec_dnssec_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Soa as u16,
                    1,
                    3600,
                    vec![soa_rdata()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Ns as u16,
                    1,
                    300,
                    vec![cname_rdata("ns.child.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Nsec as u16,
                    1,
                    300,
                    vec![nsec_rdata("next.example.test.")],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("child.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::Ns), rrsig_rdata(RecordType::Nsec)],
                ),
            ],
        ));
        let packet = query(
            b"\x03www\x05child\x07example\x04test\x00",
            RecordType::A as u16,
            1,
        );

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_authority_types(&response),
            vec![RecordType::Ns as u16]
        );
    }

    #[test]
    fn edns_query_gets_opt_response() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD),
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        let opt_offset = response.len() - 11;
        assert_eq!(response[opt_offset], 0);
        assert_eq!(
            u16::from_be_bytes([response[opt_offset + 1], response[opt_offset + 2]]),
            RecordType::Opt as u16
        );
        assert_eq!(
            u16::from_be_bytes([response[opt_offset + 3], response[opt_offset + 4]]),
            DEFAULT_MAX_UDP_PAYLOAD
        );
        assert_eq!(response_opt_ttl(&response), Some(0));
    }

    #[test]
    fn tcp_edns_keepalive_request_gets_timeout_response() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &[0, EDNS_TCP_KEEPALIVE_OPTION as u8, 0, 0],
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Tcp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                tcp_keepalive_timeout_secs: 5,
                edns_padding_block_size: 0,
                any_response: AnyResponseMode::Minimal,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(
            response_opt_rdata(&response),
            Some(vec![0, EDNS_TCP_KEEPALIVE_OPTION as u8, 0, 2, 0, 50])
        );
    }

    #[test]
    fn udp_edns_keepalive_request_is_ignored() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &[0, EDNS_TCP_KEEPALIVE_OPTION as u8, 0, 0],
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD),
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn response_opt_clears_do_bit_without_dnssec_augmentation() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response_opt_ttl(&response), Some(0));
    }

    #[test]
    fn do_query_includes_covering_rrsig_and_sets_response_do_bit() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::A)],
                ),
            ],
        ));
        let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::A as u16, RecordType::Rrsig as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0x8000));
    }

    #[test]
    fn non_do_query_omits_dnssec_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![rrsig_rdata(RecordType::A)],
                ),
            ],
        ));
        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
    }

    #[test]
    fn explicit_rrsig_query_without_do_returns_rrsig_without_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::A)],
            )],
        ));
        let mut packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Rrsig as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Rrsig as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0));
    }

    #[test]
    fn explicit_rrsig_query_with_do_does_not_mark_answer_as_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Rrsig as u16,
                1,
                300,
                vec![rrsig_rdata(RecordType::A)],
            )],
        ));
        let mut packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Rrsig as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Rrsig as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0));
    }

    #[test]
    fn explicit_nsec_query_without_do_returns_nsec_without_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Nsec as u16,
                1,
                300,
                vec![nsec_rdata("zzz.example.test.")],
            )],
        ));
        let mut packet = query(
            b"\x03www\x07example\x04test\x00",
            RecordType::Nsec as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Nsec as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0));
    }

    #[test]
    fn explicit_nsec3_query_without_do_returns_nsec3_without_augmentation() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("hash.example.test.").unwrap(),
                RecordType::Nsec3 as u16,
                1,
                300,
                vec![nsec3_rdata(253)],
            )],
        ));
        let mut packet = query(
            b"\x04hash\x07example\x04test\x00",
            RecordType::Nsec3 as u16,
            1,
        );
        append_opt(&mut packet, 4096, 0, &[]);

        let response = store_response(&packet, &store);

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&response),
            vec![RecordType::Nsec3 as u16]
        );
        assert_eq!(response_opt_ttl(&response), Some(0));
    }

    #[test]
    fn direct_dnskey_and_nsec3param_queries_preserve_unknown_algorithms() {
        let store = ZoneStore::new();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Dnskey as u16,
                    1,
                    300,
                    vec![dnskey_rdata(253)],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("example.test.").unwrap(),
                    RecordType::Nsec3Param as u16,
                    1,
                    300,
                    vec![nsec3param_rdata(254)],
                ),
            ],
        ));

        let dnskey_response = store_response(
            &query(b"\x07example\x04test\x00", RecordType::Dnskey as u16, 1),
            &store,
        );
        let nsec3param_response = store_response(
            &query(b"\x07example\x04test\x00", RecordType::Nsec3Param as u16, 1),
            &store,
        );

        assert_eq!(dnskey_response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&dnskey_response),
            vec![RecordType::Dnskey as u16]
        );
        assert_eq!(nsec3param_response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(
            response_answer_types(&nsec3param_response),
            vec![RecordType::Nsec3Param as u16]
        );
    }

    #[test]
    fn edns_padding_default_off_omits_padding_response_option() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(
            &mut packet,
            4096,
            0,
            &[0, EDNS_PADDING_OPTION as u8, 0, 4, 0, 0, 0, 0],
        );

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions::udp(DEFAULT_MAX_UDP_PAYLOAD),
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn configured_edns_padding_aligns_response_to_block_size() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[0, EDNS_PADDING_OPTION as u8, 0, 0]);

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 32,
                any_response: AnyResponseMode::Minimal,
            },
        );

        let rdata = response_opt_rdata(&response).expect("OPT rdata");
        let padding_len = u16::from_be_bytes([rdata[2], rdata[3]]) as usize;
        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert_eq!(response.len() % 32, 0);
        assert_eq!(
            u16::from_be_bytes([rdata[0], rdata[1]]),
            EDNS_PADDING_OPTION
        );
        assert_eq!(rdata.len(), 4 + padding_len);
        assert!(rdata[4..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn configured_udp_edns_padding_is_omitted_when_it_would_exceed_ceiling() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 512, 0, &[0, EDNS_PADDING_OPTION as u8, 0, 0]);

        let response = store_response_with_options(
            &packet,
            &ZoneStore::new(),
            AnswerOptions {
                transport: Transport::Udp,
                max_udp_payload: 512,
                max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
                tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
                edns_padding_block_size: 600,
                any_response: AnyResponseMode::Minimal,
            },
        );

        assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        assert!(response.len() < 512);
        assert_eq!(response_opt_rdata(&response), Some(Vec::new()));
    }

    #[test]
    fn malformed_edns_options_get_formerr() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[0, 1, 0]);

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 0);
    }

    #[test]
    fn multiple_opt_records_get_formerr() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0, &[]);
        append_opt(&mut packet, 4096, 0, &[]);

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
    }

    #[test]
    fn unsupported_edns_version_gets_badvers_opt_response() {
        let mut packet = query(&example_name(), RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, (1 << 16) | 0x8000, &[]);

        let response = store_response(&packet, &ZoneStore::new());

        assert_eq!(response[3] & 0x0f, Rcode::NoError as u8);
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        assert_eq!(response_opt_ttl(&response), Some(1 << 24));
    }

    #[test]
    fn invalid_pseudo_rr_qtypes_are_rejected() {
        for qtype in [
            0,
            RecordType::Opt as u16,
            RecordType::Tsig as u16,
            RecordType::Tkey as u16,
            u16::MAX,
        ] {
            let packet = query(&example_name(), qtype, 1);
            let response = store_response(&packet, &ZoneStore::new());
            assert_eq!(response[3] & 0x0f, Rcode::FormErr as u8);
        }
    }

    #[test]
    fn inbound_transfer_queries_are_refused() {
        for qtype in [RecordType::Ixfr as u16, RecordType::Axfr as u16] {
            let packet = query(&example_name(), qtype, 1);
            let response = store_response(&packet, &ZoneStore::new());
            assert_eq!(response[3] & 0x0f, Rcode::Refused as u8);
        }
    }

    #[test]
    fn udp_response_over_ceiling_is_truncated() {
        let store = ZoneStore::new();
        let rdatas = (0..20).map(|_| vec![60; 50]).collect::<Vec<_>>();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                rdatas,
            )],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::Txt as u16, 1);
        let response = store_response_with_options(&packet, &store, AnswerOptions::udp(512));
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert!(response.len() <= 512);
        assert_eq!(flags & 0x0200, 0x0200);
    }

    #[test]
    fn truncated_do_response_clears_do_when_rrsig_is_removed() {
        let store = ZoneStore::new();
        let mut large_rrsig = rrsig_rdata(RecordType::A);
        large_rrsig.extend(vec![0; 400]);
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::A as u16,
                    1,
                    300,
                    vec![[192, 0, 2, 10].to_vec()],
                ),
                Rrset::new(
                    DomainName::from_absolute_str("www.example.test.").unwrap(),
                    RecordType::Rrsig as u16,
                    1,
                    300,
                    vec![large_rrsig],
                ),
            ],
        ));
        let mut packet = query(b"\x03www\x07example\x04test\x00", RecordType::A as u16, 1);
        append_opt(&mut packet, 4096, 0x8000, &[]);

        let response = store_response_with_options(&packet, &store, AnswerOptions::udp(128));
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert!(response.len() <= 128);
        assert_eq!(flags & 0x0200, 0x0200);
        assert_eq!(response_answer_types(&response), vec![RecordType::A as u16]);
        assert_eq!(response_opt_ttl(&response), Some(0));
    }

    #[test]
    fn tcp_response_is_not_udp_truncated() {
        let store = ZoneStore::new();
        let rdatas = (0..20).map(|_| vec![60; 50]).collect::<Vec<_>>();
        store.insert_snapshot(ZoneSnapshot::active(
            DomainName::from_absolute_str("example.test.").unwrap(),
            Some(1),
            vec![Rrset::new(
                DomainName::from_absolute_str("www.example.test.").unwrap(),
                RecordType::Txt as u16,
                1,
                300,
                rdatas,
            )],
        ));

        let packet = query(b"\x03www\x07example\x04test\x00", RecordType::Txt as u16, 1);
        let response = store_response_with_options(&packet, &store, AnswerOptions::tcp());
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert!(response.len() > 512);
        assert_eq!(flags & 0x0200, 0);
    }
}
