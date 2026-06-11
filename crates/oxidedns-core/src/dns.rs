use std::{collections::HashMap, fmt, hash::Hasher, net::IpAddr};

use siphasher::sip::SipHasher24;
use smallvec::SmallVec;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::{
    zone::{PublishedZoneView, ResourceRecord, Rrset, ZoneState, ZoneStore},
    zone_image::{
        PackedRdataEncoding, ZoneImage, ZoneImageLookupPlan, ZoneImagePlanResponseShape,
        ZoneImageWireRecord,
    },
};

#[cfg(test)]
use crate::zone_image::zone_image_record_fixed_fields;

pub(crate) type InlineNameWire = SmallVec<[u8; 64]>;

const MAX_COMPRESSED_NAME_POINTERS: usize = 128;

// ODS-NFR-MAINT-004 principal functional requirement references for DNS
// message parsing, authoritative response construction, EDNS, DNSSEC serving,
// and DNS Cookies:
// - ODS-FR-CORE-001 ODS-FR-CORE-002 ODS-FR-CORE-003 ODS-FR-CORE-004
// - ODS-FR-CORE-005 ODS-FR-CORE-006 ODS-FR-CORE-007 ODS-FR-CORE-008
// - ODS-FR-CORE-009 ODS-FR-CORE-010 ODS-FR-CORE-011 ODS-FR-CORE-012
// - ODS-FR-CORE-013 ODS-FR-CORE-014 ODS-FR-CORE-015 ODS-FR-CORE-016
// - ODS-FR-CORE-017 ODS-FR-CORE-018 ODS-FR-CORE-019 ODS-FR-CORE-020
// - ODS-FR-CORE-021 ODS-FR-CORE-022 ODS-FR-CORE-023 ODS-FR-CORE-024
// - ODS-FR-CORE-025 ODS-FR-CORE-026 ODS-FR-CORE-027 ODS-FR-CORE-028
// - ODS-FR-CORE-029
// - ODS-FR-QRY-001 ODS-FR-QRY-002 ODS-FR-QRY-003 ODS-FR-QRY-004
// - ODS-FR-QRY-005 ODS-FR-QRY-006 ODS-FR-QRY-007 ODS-FR-QRY-008
// - ODS-FR-QRY-009 ODS-FR-QRY-010 ODS-FR-QRY-011 ODS-FR-QRY-012
// - ODS-FR-QRY-013 ODS-FR-QRY-014 ODS-FR-QRY-015 ODS-FR-QRY-016
// - ODS-FR-QRY-017 ODS-FR-QRY-018 ODS-FR-QRY-019 ODS-FR-QRY-020
// - ODS-FR-QRY-021 ODS-FR-QRY-022 ODS-FR-QRY-023 ODS-FR-QRY-024
// - ODS-FR-QRY-025
// - ODS-FR-NRESP-001 ODS-FR-NRESP-002 ODS-FR-NRESP-003
// - ODS-FR-NRESP-004 ODS-FR-NRESP-005 ODS-FR-NRESP-006
// - ODS-FR-EDNS-001 ODS-FR-EDNS-002 ODS-FR-EDNS-003 ODS-FR-EDNS-004
// - ODS-FR-EDNS-005 ODS-FR-EDNS-006 ODS-FR-EDNS-007 ODS-FR-EDNS-008
// - ODS-FR-EDNS-009 ODS-FR-EDNS-010 ODS-FR-EDNS-011 ODS-FR-EDNS-012
// - ODS-FR-EDNS-013 ODS-FR-EDNS-014 ODS-FR-EDNS-015 ODS-FR-EDNS-016
// - ODS-FR-EDNS-017 ODS-FR-EDNS-018
// - ODS-FR-DNSSEC-001 ODS-FR-DNSSEC-002 ODS-FR-DNSSEC-003
// - ODS-FR-DNSSEC-004 ODS-FR-DNSSEC-005 ODS-FR-DNSSEC-006
// - ODS-FR-DNSSEC-007 ODS-FR-DNSSEC-008 ODS-FR-DNSSEC-009
// - ODS-FR-DNSSEC-010 ODS-FR-DNSSEC-011 ODS-FR-DNSSEC-012
// - ODS-FR-DNSSEC-013 ODS-FR-DNSSEC-014
// - ODS-FR-COOKIE-001 ODS-FR-COOKIE-002 ODS-FR-COOKIE-003
// - ODS-FR-COOKIE-004 ODS-FR-COOKIE-005 ODS-FR-COOKIE-006
// - ODS-FR-COOKIE-007 ODS-FR-COOKIE-008 ODS-FR-COOKIE-009
// - ODS-FR-COOKIE-010 ODS-FR-COOKIE-011
// - ODS-FR-CHAS-001 ODS-FR-CHAS-002 ODS-FR-CHAS-003
// - ODS-FR-CHAS-004 ODS-FR-CHAS-005 ODS-FR-CHAS-006
pub const DNS_HEADER_LEN: usize = 12;
pub const DEFAULT_MAX_UDP_PAYLOAD: u16 = 1232;
pub const DEFAULT_MAX_CNAME_CHAIN: usize = 8;
pub const DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS: u64 = 30;
const DNS_CLASS_IN: u16 = 1;
const DNS_CLASS_CH: u16 = 3;
const DNS_CLASS_ANY: u16 = 255;
const EDNS_NSID_OPTION: u16 = 3;
const EDNS_COOKIE_OPTION: u16 = 10;
const EDNS_TCP_KEEPALIVE_OPTION: u16 = 11;
const EDNS_PADDING_OPTION: u16 = 12;
const EDNS_EXTENDED_DNS_ERROR_OPTION: u16 = 15;
const EDE_NOT_READY: u16 = 14;
const EDE_UNSUPPORTED_NSEC3_ITERATIONS: u16 = 27;
const DNS_COOKIE_CLIENT_LEN: usize = 8;
const DNS_COOKIE_SERVER_V1_LEN: usize = 16;
const DNS_COOKIE_VERSION_1: u8 = 1;
const OPT_OWNER_AND_TYPE_WIRE: [u8; 3] = [0, 0, RecordType::Opt as u8];
const EDNS_TCP_KEEPALIVE_RESPONSE_OPTION_PREFIX: [u8; 4] =
    [0, EDNS_TCP_KEEPALIVE_OPTION as u8, 0, 2];
const EDNS_COOKIE_RESPONSE_OPTION_PREFIX: [u8; 4] = [
    0,
    EDNS_COOKIE_OPTION as u8,
    0,
    (DNS_COOKIE_CLIENT_LEN + DNS_COOKIE_SERVER_V1_LEN) as u8,
];
const EDNS_EXTENDED_DNS_ERROR_RESPONSE_OPTION_PREFIX: [u8; 4] =
    [0, EDNS_EXTENDED_DNS_ERROR_OPTION as u8, 0, 2];
const DNS_COOKIE_DEFAULT_PAST_WINDOW_SECS: u32 = 3600;
const DNS_COOKIE_DEFAULT_FUTURE_WINDOW_SECS: u32 = 300;

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
    YxDomain = 6,
    NotAuth = 9,
    BadCookie = 23,
}

impl Rcode {
    pub(crate) fn bits(self) -> u16 {
        (self as u16) & 0x000f
    }

    pub(crate) fn response_flag_bits(self, authoritative: bool) -> u16 {
        let aa = if authoritative { 0x0400 } else { 0 };
        aa | self.bits()
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
        self.response_flags_from_plan_bits(rcode.response_flag_bits(authoritative), truncated)
    }

    fn response_flags_from_plan_bits(&self, plan_response_flag_bits: u16, truncated: bool) -> u16 {
        let opcode = self.flags & 0x7800;
        let rd = self.flags & 0x0100;
        let tc = if truncated { 0x0200 } else { 0 };
        0x8000 | opcode | tc | rd | plan_response_flag_bits
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
        let (name, consumed, _) = Self::parse_with_ascii_lowercase(packet, offset)?;
        Ok((name, consumed))
    }

    pub(crate) fn parse_with_ascii_lowercase(
        packet: &[u8],
        offset: usize,
    ) -> Result<(Self, usize, bool), DnsParseError> {
        let mut labels = Vec::new();
        let mut pos = offset;
        let mut consumed = None;
        let mut visited_pointers = SmallVec::<[usize; 4]>::new();
        let mut total_len = 1usize;
        let mut ascii_lowercase = true;

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
                    if visited_pointers.len() >= MAX_COMPRESSED_NAME_POINTERS {
                        return Err(DnsParseError::FormErr);
                    }
                    visited_pointers.push(pointer);
                    consumed.get_or_insert_with(|| pos + 2 - offset);
                    pos = pointer;
                }
                0x00 => {
                    pos += 1;
                    if len == 0 {
                        let consumed = consumed.unwrap_or_else(|| pos - offset);
                        return Ok((Self { labels }, consumed, ascii_lowercase));
                    }

                    let label_len = len as usize;
                    if label_len > 63 || pos + label_len > packet.len() {
                        return Err(DnsParseError::FormErr);
                    }

                    total_len += 1 + label_len;
                    if total_len > 255 {
                        return Err(DnsParseError::FormErr);
                    }

                    ascii_lowercase &= packet[pos..pos + label_len]
                        .iter()
                        .all(|byte| byte.to_ascii_lowercase() == *byte);
                    labels.push(packet[pos..pos + label_len].to_vec());
                    pos += label_len;
                }
                _ => return Err(DnsParseError::FormErr),
            }
        }
    }

    pub(crate) fn from_uncompressed_wire(wire: &[u8]) -> Result<Self, DnsParseError> {
        let mut labels = Vec::new();
        let mut pos = 0usize;
        let mut total_len = 1usize;

        loop {
            let Some(&len) = wire.get(pos) else {
                return Err(DnsParseError::FormErr);
            };
            pos += 1;

            if len == 0 {
                return (pos == wire.len())
                    .then_some(Self { labels })
                    .ok_or(DnsParseError::FormErr);
            }

            if len & 0xc0 != 0 {
                return Err(DnsParseError::FormErr);
            }

            let label_len = len as usize;
            if label_len > 63 || pos + label_len > wire.len() {
                return Err(DnsParseError::FormErr);
            }

            total_len += 1 + label_len;
            if total_len > 255 {
                return Err(DnsParseError::FormErr);
            }

            labels.push(wire[pos..pos + label_len].to_vec());
            pos += label_len;
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

    pub(crate) fn matches_ascii_labels_ignore_case(&self, labels: &[&[u8]]) -> bool {
        self.labels.len() == labels.len()
            && self
                .labels
                .iter()
                .zip(labels)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    pub(crate) fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    #[cfg(test)]
    pub(crate) fn suffix_from_label_index(&self, start: usize) -> Option<Self> {
        if start > self.labels.len() {
            return None;
        }

        Some(Self {
            labels: self.labels[start..].to_vec(),
        })
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

    #[cfg(test)]
    pub(crate) fn with_replaced_wire_suffix(
        &self,
        suffix_wire: &[u8],
        replacement: &DomainName,
    ) -> Option<Self> {
        self.with_replaced_wire_suffix_and_wire(suffix_wire, replacement)
            .map(|(name, _)| name)
    }

    #[cfg(test)]
    pub(crate) fn with_replaced_wire_suffix_and_wire(
        &self,
        suffix_wire: &[u8],
        replacement: &DomainName,
    ) -> Option<(Self, Vec<u8>)> {
        let replacement_wire = replacement.to_wire();
        self.with_replaced_wire_suffix_and_stored_wire(suffix_wire, replacement, &replacement_wire)
    }

    #[cfg(test)]
    pub(crate) fn with_replaced_wire_suffix_and_stored_wire(
        &self,
        suffix_wire: &[u8],
        replacement: &DomainName,
        replacement_wire: &[u8],
    ) -> Option<(Self, Vec<u8>)> {
        self.with_replaced_wire_suffix_and_stored_wire_parts(
            suffix_wire,
            replacement,
            replacement_wire,
        )
        .map(|(name, wire, _)| (name, wire.to_vec()))
    }

    #[cfg(test)]
    pub(crate) fn with_replaced_wire_suffix_and_stored_wire_parts(
        &self,
        suffix_wire: &[u8],
        replacement: &DomainName,
        replacement_wire: &[u8],
    ) -> Option<(Self, InlineNameWire, usize)> {
        let suffix_label_count = wire_label_count(suffix_wire)?;
        self.with_replaced_wire_suffix_and_stored_wire_parts_counted(
            suffix_wire,
            suffix_label_count,
            replacement,
            replacement_wire,
        )
    }

    pub(crate) fn with_replaced_wire_suffix_and_stored_wire_parts_counted(
        &self,
        suffix_wire: &[u8],
        suffix_label_count: usize,
        replacement: &DomainName,
        replacement_wire: &[u8],
    ) -> Option<(Self, InlineNameWire, usize)> {
        let (wire, prefix_len) = self.with_replaced_wire_suffix_wire_counted(
            suffix_wire,
            suffix_label_count,
            replacement_wire,
        )?;

        let mut labels = Vec::with_capacity(prefix_len + replacement.labels.len());
        labels.extend_from_slice(&self.labels[..prefix_len]);
        labels.extend_from_slice(&replacement.labels);

        Some((Self { labels }, wire, prefix_len))
    }

    pub(crate) fn with_replaced_wire_suffix_wire_counted(
        &self,
        suffix_wire: &[u8],
        suffix_label_count: usize,
        replacement_wire: &[u8],
    ) -> Option<(InlineNameWire, usize)> {
        if suffix_label_count > self.labels.len() {
            return None;
        }

        let prefix_len = self.labels.len() - suffix_label_count;
        if !wire_labels_match_name_suffix(suffix_wire, &self.labels[prefix_len..])? {
            return None;
        }

        let mut wire = InlineNameWire::new();
        for label in &self.labels[..prefix_len] {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label);
        }
        wire.extend_from_slice(replacement_wire);

        if wire.len() > 255 {
            return None;
        }

        Some((wire, prefix_len))
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

    pub fn to_wire(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(self.wire_len());
        self.append_wire_to(&mut wire);
        wire
    }

    pub(crate) fn wire_len(&self) -> usize {
        self.labels
            .iter()
            .map(|label| 1 + label.len())
            .sum::<usize>()
            + 1
    }

    pub(crate) fn append_wire_to(&self, wire: &mut Vec<u8>) {
        for label in &self.labels {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label);
        }
        wire.push(0);
    }

    #[cfg(test)]
    pub(crate) fn to_canonical_wire(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(self.wire_len());
        for label in &self.labels {
            wire.push(label.len() as u8);
            wire.extend(label.iter().map(u8::to_ascii_lowercase));
        }
        wire.push(0);
        wire
    }
}

fn skip_compressed_name(packet: &[u8], offset: usize) -> Result<usize, DnsParseError> {
    scan_compressed_name(packet, offset, None).map(|scan| scan.consumed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompressedNameScan {
    consumed: usize,
    label_count: usize,
    matches_expected: bool,
}

fn scan_compressed_name(
    packet: &[u8],
    offset: usize,
    expected: Option<&DomainName>,
) -> Result<CompressedNameScan, DnsParseError> {
    let mut pos = offset;
    let mut consumed = None;
    let mut visited_pointers = SmallVec::<[usize; 4]>::new();
    let mut total_len = 1usize;
    let mut label_count = 0usize;
    let mut matches_expected = true;

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
                if visited_pointers.len() >= MAX_COMPRESSED_NAME_POINTERS {
                    return Err(DnsParseError::FormErr);
                }
                visited_pointers.push(pointer);
                consumed.get_or_insert_with(|| pos + 2 - offset);
                pos = pointer;
            }
            0x00 => {
                pos += 1;
                if len == 0 {
                    if let Some(expected) = expected {
                        matches_expected &= label_count == expected.labels.len();
                    }
                    return Ok(CompressedNameScan {
                        consumed: consumed.unwrap_or_else(|| pos - offset),
                        label_count,
                        matches_expected,
                    });
                }

                let label_len = len as usize;
                if label_len > 63 || pos + label_len > packet.len() {
                    return Err(DnsParseError::FormErr);
                }

                total_len += 1 + label_len;
                if total_len > 255 {
                    return Err(DnsParseError::FormErr);
                }

                if let Some(expected) = expected {
                    matches_expected &= expected.labels.get(label_count).is_some_and(|label| {
                        label.eq_ignore_ascii_case(&packet[pos..pos + label_len])
                    });
                }
                label_count += 1;
                pos += label_len;
            }
            _ => return Err(DnsParseError::FormErr),
        }
    }
}

#[cfg(test)]
fn wire_label_count(mut wire: &[u8]) -> Option<usize> {
    let mut count = 0usize;
    let mut total_len = 1usize;
    loop {
        let (&len, rest) = wire.split_first()?;
        if len == 0 {
            return rest.is_empty().then_some(count);
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let label_len = len as usize;
        if label_len > 63 || rest.len() < label_len {
            return None;
        }
        total_len += 1 + label_len;
        if total_len > 255 {
            return None;
        }
        let (_, next) = rest.split_at(label_len);
        count += 1;
        wire = next;
    }
}

fn wire_labels_match_name_suffix(mut wire: &[u8], labels: &[Vec<u8>]) -> Option<bool> {
    let mut total_len = 1usize;
    for label in labels {
        let (&len, rest) = wire.split_first()?;
        if len & 0xc0 != 0 || len as usize != label.len() {
            return Some(false);
        }
        let label_len = len as usize;
        if label_len > 63 || rest.len() < label_len {
            return None;
        }
        total_len += 1 + label_len;
        if total_len > 255 {
            return None;
        }
        let (wire_label, next) = rest.split_at(label_len);
        if !label.eq_ignore_ascii_case(wire_label) {
            return Some(false);
        }
        wire = next;
    }
    Some(wire == [0])
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
    qname_wire_len: usize,
    qtype_qclass_wire: [u8; 4],
    qname_ascii_lowercase: bool,
}

impl Question {
    pub fn parse(packet: &[u8]) -> Result<Self, DnsParseError> {
        let (qname, qname_len, qname_ascii_lowercase) =
            DomainName::parse_with_ascii_lowercase(packet, DNS_HEADER_LEN)?;
        let qtype_offset = DNS_HEADER_LEN + qname_len;
        if qtype_offset + 4 > packet.len() {
            return Err(DnsParseError::FormErr);
        }

        Ok(Self {
            qname,
            qtype: u16::from_be_bytes([packet[qtype_offset], packet[qtype_offset + 1]]),
            qclass: u16::from_be_bytes([packet[qtype_offset + 2], packet[qtype_offset + 3]]),
            qname_wire_len: qname_len,
            qtype_qclass_wire: packet[qtype_offset..qtype_offset + 4]
                .try_into()
                .expect("question qtype/qclass slice length is checked above"),
            qname_ascii_lowercase,
        })
    }

    fn wire_len(&self) -> usize {
        self.qname_wire_len + self.qtype_qclass_wire.len()
    }

    fn qname_wire_len(&self) -> usize {
        self.qname_wire_len
    }

    /// Return whether packet parsing proved every QNAME label byte was already
    /// lowercase ASCII.
    pub fn qname_ascii_lowercase(&self) -> bool {
        self.qname_ascii_lowercase
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramAction {
    Discard,
    Respond(Vec<u8>),
}

pub type ZoneImageProvider<'a> =
    &'a dyn for<'published> Fn(&'published dyn PublishedZoneView) -> &'published ZoneImage;

/// Borrow the active immutable query image from a published zone.
pub fn default_zone_image_provider(published: &dyn PublishedZoneView) -> &ZoneImage {
    published.active_zone_image_ref()
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
pub struct AnswerOptions<'a> {
    pub transport: Transport,
    pub max_udp_payload: u16,
    pub max_cname_chain: usize,
    pub nsec3_max_iterations: u16,
    pub tcp_keepalive_timeout_secs: u64,
    pub edns_padding_block_size: u16,
    pub extended_dns_errors: ExtendedDnsErrorsMode,
    pub any_response: AnyResponseMode,
    pub nsid: &'a [u8],
    pub chaos: ChaosOptions<'a>,
    pub dns_cookie: Option<DnsCookieContext<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChaosOptions<'a> {
    pub version: &'a str,
    pub hostname: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaosQueryOutcome {
    Answered,
    MissingValue,
    UnrecognizedName,
    NonTxt,
}

impl ChaosQueryOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::MissingValue => "missing_value",
            Self::UnrecognizedName => "unrecognized_name",
            Self::NonTxt => "non_txt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaosQueryObservation {
    pub qname: String,
    pub qtype: u16,
    pub outcome: ChaosQueryOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExtendedDnsErrorsMode {
    #[default]
    Off,
    Minimal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsCookieContext<'a> {
    pub client_ip: IpAddr,
    pub server_secret: &'a [u8; 16],
    pub previous_server_secret: Option<&'a [u8; 16]>,
    pub now_unix_secs: u32,
    pub past_window_secs: u32,
    pub future_window_secs: u32,
    pub policy: DnsCookiePolicy,
}

impl<'a> DnsCookieContext<'a> {
    pub fn new(client_ip: IpAddr, server_secret: &'a [u8; 16], now_unix_secs: u32) -> Self {
        Self {
            client_ip,
            server_secret,
            previous_server_secret: None,
            now_unix_secs,
            past_window_secs: DNS_COOKIE_DEFAULT_PAST_WINDOW_SECS,
            future_window_secs: DNS_COOKIE_DEFAULT_FUTURE_WINDOW_SECS,
            policy: DnsCookiePolicy::Lenient,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCookiePolicy {
    Lenient,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCookieRequestStatus {
    NoCookie,
    ClientCookieOnly,
    ValidServerCookie,
    InvalidServerCookie,
}

impl AnswerOptions<'_> {
    pub fn udp(max_udp_payload: u16) -> Self {
        Self {
            transport: Transport::Udp,
            max_udp_payload,
            max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
            nsec3_max_iterations: 100,
            tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Minimal,
            nsid: &[],
            chaos: ChaosOptions::default(),
            dns_cookie: None,
        }
    }

    pub fn tcp() -> Self {
        Self {
            transport: Transport::Tcp,
            max_udp_payload: DEFAULT_MAX_UDP_PAYLOAD,
            max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
            nsec3_max_iterations: 100,
            tcp_keepalive_timeout_secs: DEFAULT_TCP_KEEPALIVE_TIMEOUT_SECS,
            edns_padding_block_size: 0,
            extended_dns_errors: ExtendedDnsErrorsMode::Off,
            any_response: AnyResponseMode::Minimal,
            nsid: &[],
            chaos: ChaosOptions::default(),
            dns_cookie: None,
        }
    }
}

impl Default for AnswerOptions<'_> {
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
    answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
        packet,
        zone_store,
        options,
        notify_authorized,
        notify_accepted,
        |_| {},
        &default_zone_image_provider as ZoneImageProvider<'_>,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn answer_message_with_notify_hooks_lookup_metrics_observer_and_zone_image(
    packet: &[u8],
    zone_store: &ZoneStore,
    options: AnswerOptions,
    notify_authorized: impl Fn(&DomainName, u16) -> bool,
    notify_accepted: impl Fn(&DomainName, u16, Option<u32>),
    lookup_observed: impl Fn(LookupMetrics),
    zone_image_provider: ZoneImageProvider<'_>,
) -> DatagramAction {
    let observer = LookupMetricsObserver {
        callback: lookup_observed,
    };
    answer_message_with_notify_hooks_observer_and_zone_image(
        packet,
        zone_store,
        options,
        notify_authorized,
        notify_accepted,
        &observer,
        zone_image_provider,
    )
}

#[allow(clippy::too_many_arguments)]
fn answer_message_with_notify_hooks_observer_and_zone_image(
    packet: &[u8],
    zone_store: &ZoneStore,
    options: AnswerOptions,
    notify_authorized: impl Fn(&DomainName, u16) -> bool,
    notify_accepted: impl Fn(&DomainName, u16, Option<u32>),
    query_observer: &impl AnswerQueryObserver,
    zone_image_provider: ZoneImageProvider<'_>,
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

    answer_query_message(
        &header,
        packet,
        zone_store,
        options,
        query_observer,
        zone_image_provider,
    )
}

trait AnswerQueryObserver {
    fn observe_zone_image_plan(&self, plan: &ZoneImageLookupPlan, direct_answer: bool);
    fn observe_zone_image_failure(&self, reason: ZoneImageServeFailureReason);
}

struct LookupMetricsObserver<F> {
    callback: F,
}

impl<F> AnswerQueryObserver for LookupMetricsObserver<F>
where
    F: Fn(LookupMetrics),
{
    fn observe_zone_image_plan(&self, plan: &ZoneImageLookupPlan, direct_answer: bool) {
        (self.callback)(LookupMetrics::from_zone_image_plan(plan, direct_answer));
    }

    fn observe_zone_image_failure(&self, reason: ZoneImageServeFailureReason) {
        (self.callback)(LookupMetrics::from_zone_image_failure(reason));
    }
}

fn answer_query_message(
    header: &Header,
    packet: &[u8],
    zone_store: &ZoneStore,
    options: AnswerOptions,
    query_observer: &impl AnswerQueryObserver,
    zone_image_provider: ZoneImageProvider<'_>,
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

    if dns_cookie_requires_badcookie(metadata, options) {
        return DatagramAction::Respond(build_response(
            header,
            Rcode::BadCookie,
            false,
            Some(&question),
            &[],
            &[],
            &[],
            metadata.with_extended_rcode(Rcode::BadCookie as u16),
            options,
        ));
    }

    if question.qclass == DNS_CLASS_CH {
        return answer_chaos_query(header, &question, metadata, options);
    }

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

    let Some(action) = zone_store.with_published_zone_with_ascii_lowercase_hint(
        &question.qname,
        question.qname_ascii_lowercase(),
        |published_zone| {
            if published_zone.state() != ZoneState::Active {
                return DatagramAction::Respond(build_response(
                    header,
                    Rcode::ServFail,
                    false,
                    Some(&question),
                    &[],
                    &[],
                    &[],
                    metadata.with_extended_dns_error(ExtendedDnsError::NotReady),
                    options,
                ));
            }
            match try_answer_with_zone_image(
                header,
                &question,
                metadata,
                options,
                query_observer,
                zone_image_provider,
                &published_zone,
            ) {
                ZoneImageAnswerAttempt::Respond(response) => DatagramAction::Respond(response),
                ZoneImageAnswerAttempt::Failure(reason) => {
                    query_observer.observe_zone_image_failure(reason);
                    DatagramAction::Respond(build_zone_image_failure_response(
                        header, &question, metadata, options,
                    ))
                }
            }
        },
    ) else {
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
    action
}

enum ZoneImageAnswerAttempt {
    Respond(Vec<u8>),
    Failure(ZoneImageServeFailureReason),
}

fn try_answer_with_zone_image(
    header: &Header,
    question: &Question,
    metadata: RequestMetadata,
    options: AnswerOptions,
    query_observer: &impl AnswerQueryObserver,
    zone_image_provider: ZoneImageProvider<'_>,
    published_zone: &dyn PublishedZoneView,
) -> ZoneImageAnswerAttempt {
    let image = zone_image_provider(published_zone);
    let dnssec_requested = metadata.dnssec_requested();
    let udp_ceiling = metadata.udp_ceiling(options);
    let direct_response_sizing = (!dnssec_requested)
        .then(|| zone_image_response_sizing(question, udp_ceiling, &metadata, options));
    let mut direct_plan_rejected = false;
    let mut rejected_direct_plan = None;
    if !dnssec_requested
        && let Some(plan) = image.lookup_direct_answer_plan_with_ascii_lowercase_hint(
            &question.qname,
            question.qtype,
            question.qclass,
            question.qname_ascii_lowercase(),
        )
    {
        if let Some(response) = build_direct_zone_image_answer_response(
            header,
            question,
            image,
            &plan,
            metadata,
            options,
            direct_response_sizing.expect("direct preflight is gated to non-DNSSEC requests"),
        ) {
            query_observer.observe_zone_image_plan(&plan, true);
            return ZoneImageAnswerAttempt::Respond(response);
        }
        direct_plan_rejected = true;
        rejected_direct_plan = Some(plan);
    }

    let plan = rejected_direct_plan.unwrap_or_else(|| {
        image.lookup_response_plan_with_ascii_lowercase_hint(
            &question.qname,
            question.qtype,
            question.qclass,
            options.max_cname_chain,
            options.any_response,
            question.qname_ascii_lowercase(),
        )
    });
    let plan = if dnssec_requested {
        image.augment_lookup_plan_with_dnssec_ascii_lowercase_hint(
            plan,
            &question.qname,
            question.qclass,
            options.nsec3_max_iterations,
            question.qname_ascii_lowercase(),
        )
    } else {
        plan
    };
    let mut metadata = metadata;
    let response_sizing = if plan.nsec3_iterations_exceeded() {
        metadata = metadata.with_extended_dns_error(ExtendedDnsError::UnsupportedNsec3Iterations);
        zone_image_response_sizing(question, udp_ceiling, &metadata, options)
    } else {
        direct_response_sizing.unwrap_or_else(|| {
            zone_image_response_sizing(question, udp_ceiling, &metadata, options)
        })
    };
    let allow_direct_answer_retry = !direct_plan_rejected && !dnssec_requested;

    let Some(response) = build_zone_image_response(
        header,
        question,
        image,
        &plan,
        metadata,
        options,
        allow_direct_answer_retry,
        response_sizing,
    ) else {
        return ZoneImageAnswerAttempt::Failure(ZoneImageServeFailureReason::ResponseBuildFailed);
    };
    query_observer.observe_zone_image_plan(&plan, false);
    ZoneImageAnswerAttempt::Respond(response)
}

pub fn chaos_query_observation(
    packet: &[u8],
    nsid: &[u8],
    chaos: ChaosOptions<'_>,
) -> Option<ChaosQueryObservation> {
    let header = Header::parse(packet).ok()?;
    if header.is_response() || header.opcode() != Some(Opcode::Query) || header.qdcount != 1 {
        return None;
    }
    let question = Question::parse(packet).ok()?;
    if question.qclass != DNS_CLASS_CH {
        return None;
    }
    Some(ChaosQueryObservation {
        qname: question.qname.to_string(),
        qtype: question.qtype,
        outcome: classify_chaos_query(&question, nsid, chaos).outcome,
    })
}

fn answer_chaos_query(
    header: &Header,
    question: &Question,
    metadata: RequestMetadata,
    options: AnswerOptions,
) -> DatagramAction {
    let classification = classify_chaos_query(question, options.nsid, options.chaos);
    let Some(value) = classification.value else {
        return DatagramAction::Respond(build_response(
            header,
            Rcode::Refused,
            false,
            Some(question),
            &[],
            &[],
            &[],
            metadata,
            options,
        ));
    };

    DatagramAction::Respond(build_chaos_txt_response(
        header, question, value, metadata, options,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChaosClassification<'a> {
    outcome: ChaosQueryOutcome,
    value: Option<&'a [u8]>,
}

fn classify_chaos_query<'a>(
    question: &Question,
    nsid: &'a [u8],
    chaos: ChaosOptions<'a>,
) -> ChaosClassification<'a> {
    if question.qtype != RecordType::Txt as u16 {
        return ChaosClassification {
            outcome: ChaosQueryOutcome::NonTxt,
            value: None,
        };
    }

    if is_chaos_version_name(&question.qname) {
        configured_chaos_value(chaos.version.as_bytes())
    } else if is_chaos_hostname_name(&question.qname) {
        configured_chaos_value(chaos.hostname.as_bytes())
            .or_else(|| printable_nsid_chaos_value(nsid))
    } else {
        ChaosClassification {
            outcome: ChaosQueryOutcome::UnrecognizedName,
            value: None,
        }
    }
}

fn is_chaos_version_name(name: &DomainName) -> bool {
    name.matches_ascii_labels_ignore_case(&[b"version".as_slice(), b"bind".as_slice()])
        || name.matches_ascii_labels_ignore_case(&[b"version".as_slice(), b"server".as_slice()])
}

fn is_chaos_hostname_name(name: &DomainName) -> bool {
    name.matches_ascii_labels_ignore_case(&[b"hostname".as_slice(), b"bind".as_slice()])
        || name.matches_ascii_labels_ignore_case(&[b"id".as_slice(), b"server".as_slice()])
}

impl<'a> ChaosClassification<'a> {
    fn or_else(self, fallback: impl FnOnce() -> Self) -> Self {
        if self.value.is_some() {
            self
        } else {
            fallback()
        }
    }
}

fn configured_chaos_value(value: &[u8]) -> ChaosClassification<'_> {
    if value.is_empty() {
        ChaosClassification {
            outcome: ChaosQueryOutcome::MissingValue,
            value: None,
        }
    } else {
        ChaosClassification {
            outcome: ChaosQueryOutcome::Answered,
            value: Some(value),
        }
    }
}

fn printable_nsid_chaos_value(nsid: &[u8]) -> ChaosClassification<'_> {
    if !nsid.is_empty() && nsid.len() <= 255 && nsid.iter().all(|byte| (0x20..=0x7e).contains(byte))
    {
        ChaosClassification {
            outcome: ChaosQueryOutcome::Answered,
            value: Some(nsid),
        }
    } else {
        ChaosClassification {
            outcome: ChaosQueryOutcome::MissingValue,
            value: None,
        }
    }
}

fn build_chaos_txt_response(
    header: &Header,
    question: &Question,
    value: &[u8],
    metadata: RequestMetadata,
    options: AnswerOptions,
) -> Vec<u8> {
    let udp_ceiling = metadata.udp_ceiling(options);
    let response_sizing = zone_image_response_sizing(question, udp_ceiling, &metadata, options);
    let answer_wire_len = 2usize
        .saturating_add(10)
        .saturating_add(1)
        .saturating_add(value.len());
    let response_capacity =
        zone_image_response_capacity_hint(response_sizing, answer_wire_len, false);
    let mut response = zone_image_response_prefix(
        header,
        Rcode::NoError.response_flag_bits(true),
        false,
        zone_image_section_count_header_bytes(1, 0, response_sizing.edns.additional_count),
        response_capacity,
    );
    encode_question(question, &mut response);
    encode_chaos_txt_answer(value, &mut response);
    append_zone_image_response_edns(
        &mut response,
        &metadata,
        options,
        response_sizing.udp_ceiling,
        response_sizing.edns,
    );

    if options.transport == Transport::Udp && response.len() > udp_ceiling {
        return build_empty_response(
            header,
            Rcode::NoError,
            true,
            Some(question),
            metadata,
            options,
        );
    }

    response
}

fn encode_chaos_txt_answer(value: &[u8], response: &mut Vec<u8>) {
    response.extend_from_slice(&0xc00cu16.to_be_bytes());
    response.extend_from_slice(&(RecordType::Txt as u16).to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_CH.to_be_bytes());
    response.extend_from_slice(&0u32.to_be_bytes());
    response.extend_from_slice(&(value.len().saturating_add(1) as u16).to_be_bytes());
    response.push(value.len() as u8);
    response.extend_from_slice(value);
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

    if question.qclass != DNS_CLASS_IN
        || !zone_store.contains_exact_zone_for_control(&question.qname)
    {
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
    let mut offset = DNS_HEADER_LEN + question.wire_len();
    let mut serial = None;
    for _ in 0..header.ancount {
        let ((record, owner_matches_question), consumed) =
            parse_record_view_with_owner_match(packet, offset, &question.qname)?;
        offset += consumed;
        if record.rr_type == RecordType::Soa as u16 {
            if !owner_matches_question || record.class != question.qclass {
                return Err(EdnsError::FormErr);
            }
            serial = Some(soa_serial(packet, record.rdata_offset, record.rdata.len())?);
        }
    }
    Ok(serial)
}

fn soa_serial(packet: &[u8], rdata_offset: usize, rdata_len: usize) -> Result<u32, EdnsError> {
    let rdata_end = rdata_offset
        .checked_add(rdata_len)
        .ok_or(EdnsError::FormErr)?;
    let consumed_mname =
        skip_compressed_name(packet, rdata_offset).map_err(|_| EdnsError::FormErr)?;
    let rname_offset = rdata_offset + consumed_mname;
    let consumed_rname =
        skip_compressed_name(packet, rname_offset).map_err(|_| EdnsError::FormErr)?;
    let serial_offset = rname_offset + consumed_rname;
    if serial_offset + 20 != rdata_end {
        return Err(EdnsError::FormErr);
    }
    Ok(u32::from_be_bytes([
        packet[serial_offset],
        packet[serial_offset + 1],
        packet[serial_offset + 2],
        packet[serial_offset + 3],
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
    if answers.is_empty() && authorities.is_empty() && additionals.is_empty() {
        return build_empty_response(header, rcode, authoritative, question, metadata, options);
    }

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

fn build_empty_response(
    header: &Header,
    rcode: Rcode,
    authoritative: bool,
    question: Option<&Question>,
    metadata: RequestMetadata,
    options: AnswerOptions,
) -> Vec<u8> {
    let udp_ceiling = metadata.udp_ceiling(options);
    let edns_sizing = zone_image_edns_sizing(&metadata, options);
    let mut response = build_empty_response_inner(
        header,
        rcode,
        authoritative,
        false,
        question,
        &metadata,
        options,
        udp_ceiling,
        edns_sizing,
    );
    if options.transport == Transport::Udp && response.len() > udp_ceiling {
        response = build_empty_response_inner(
            header,
            rcode,
            authoritative,
            true,
            question,
            &metadata,
            options,
            udp_ceiling,
            edns_sizing,
        );
    }
    response
}

#[allow(clippy::too_many_arguments)]
fn build_empty_response_inner(
    header: &Header,
    rcode: Rcode,
    authoritative: bool,
    truncated: bool,
    question: Option<&Question>,
    metadata: &RequestMetadata,
    options: AnswerOptions,
    udp_ceiling: usize,
    edns_sizing: ZoneImageEdnsSizing,
) -> Vec<u8> {
    let response_capacity =
        empty_response_capacity_hint(question, truncated, udp_ceiling, edns_sizing);
    let mut response = Vec::with_capacity(response_capacity);
    response.extend_from_slice(&header.id.to_be_bytes());
    response.extend_from_slice(
        &header
            .response_flags(rcode, authoritative, truncated)
            .to_be_bytes(),
    );
    response.extend_from_slice(&(u16::from(question.is_some())).to_be_bytes());
    response.extend_from_slice(&zone_image_section_count_header_bytes(
        0,
        0,
        edns_sizing.additional_count,
    ));

    if let Some(question) = question {
        encode_question(question, &mut response);
    }

    append_zone_image_response_edns(&mut response, metadata, options, udp_ceiling, edns_sizing);
    response
}

fn empty_response_capacity_hint(
    question: Option<&Question>,
    truncated: bool,
    udp_ceiling: usize,
    edns_sizing: ZoneImageEdnsSizing,
) -> usize {
    let minimum_capacity = DNS_HEADER_LEN + question.map_or(0, Question::wire_len);
    if truncated || edns_sizing.reserve_full_udp_capacity {
        return udp_ceiling.max(minimum_capacity);
    }
    minimum_capacity.saturating_add(edns_sizing.capacity_hint)
}

fn build_zone_image_failure_response(
    header: &Header,
    question: &Question,
    metadata: RequestMetadata,
    options: AnswerOptions,
) -> Vec<u8> {
    let udp_ceiling = metadata.udp_ceiling(options);
    let response_sizing = zone_image_response_sizing(question, udp_ceiling, &metadata, options);
    let response_capacity = zone_image_response_capacity_hint(response_sizing, 0, false);
    let mut response = zone_image_response_prefix(
        header,
        Rcode::ServFail.response_flag_bits(true),
        false,
        zone_image_section_count_header_bytes(0, 0, response_sizing.edns.additional_count),
        response_capacity,
    );
    encode_question(question, &mut response);
    append_zone_image_response_edns(
        &mut response,
        &metadata,
        options,
        response_sizing.udp_ceiling,
        response_sizing.edns,
    );
    response
}

#[allow(clippy::too_many_arguments)]
fn build_zone_image_response(
    header: &Header,
    question: &Question,
    image: &ZoneImage,
    plan: &ZoneImageLookupPlan,
    metadata: RequestMetadata,
    options: AnswerOptions,
    allow_direct_answer: bool,
    response_sizing: ZoneImageResponseSizing,
) -> Option<Vec<u8>> {
    if allow_direct_answer
        && let Some(response) = build_direct_zone_image_answer_response(
            header,
            question,
            image,
            plan,
            metadata,
            options,
            response_sizing,
        )
    {
        return Some(response);
    }

    let response_shape = plan.response_shape()?;
    let response = build_zone_image_response_from_plan_records(
        header,
        question,
        image,
        plan,
        response_shape,
        &metadata,
        options,
        false,
        response_sizing,
    )?;

    if options.transport == Transport::Udp && response.len() > response_sizing.udp_ceiling {
        return build_truncated_zone_image_response(
            header,
            question,
            image,
            plan,
            response_shape,
            metadata,
            options,
            response_sizing,
        );
    }
    Some(response)
}

#[allow(clippy::too_many_arguments)]
fn build_truncated_zone_image_response(
    header: &Header,
    question: &Question,
    image: &ZoneImage,
    plan: &ZoneImageLookupPlan,
    response_shape: ZoneImagePlanResponseShape,
    metadata: RequestMetadata,
    options: AnswerOptions,
    mut response_sizing: ZoneImageResponseSizing,
) -> Option<Vec<u8>> {
    let mut metadata = metadata;
    if metadata.extended_dns_error.is_some() {
        metadata = metadata.without_extended_dns_error();
        let stripped_edns_sizing = zone_image_edns_sizing(&metadata, options);
        let stripped_response_sizing = response_sizing.with_edns_sizing(stripped_edns_sizing);
        let response = build_zone_image_response_from_plan_records(
            header,
            question,
            image,
            plan,
            response_shape,
            &metadata,
            options,
            true,
            stripped_response_sizing,
        )?;
        if response.len() <= response_sizing.udp_ceiling {
            return Some(response);
        }
        response_sizing = stripped_response_sizing;
    }

    let mut kept_answers: SmallVec<[ZoneImageWireRecord<'_>; 4]> =
        SmallVec::with_capacity(usize::from(response_shape.answer_count));
    let mut kept_authorities: SmallVec<[ZoneImageWireRecord<'_>; 4]> =
        SmallVec::with_capacity(usize::from(response_shape.authority_count));
    let mut kept_additionals: SmallVec<[ZoneImageWireRecord<'_>; 8]> =
        SmallVec::with_capacity(usize::from(response_shape.additional_count));
    let mut section_counts = ZoneImageRetrySectionCounts::from_response_shape(response_shape);
    let mut body_wire_upper_bound = response_shape.body_wire_upper_bound;
    let mut removable_authority_indices = SmallVec::<[u16; 4]>::new();
    image.visit_plan_record_sections_with_authority_removability(
        plan,
        |record| {
            kept_answers.push(record);
        },
        |record, removable_authority| {
            if removable_authority {
                debug_assert!(
                    kept_authorities.len() <= u16::MAX as usize,
                    "truncation authority index is bounded by DNS section count"
                );
                removable_authority_indices.push(kept_authorities.len() as u16);
            }
            kept_authorities.push(record);
        },
        |record| {
            kept_additionals.push(record);
        },
    );

    loop {
        let response = build_zone_image_response_from_wire_records(
            header,
            question,
            response_shape.response_flag_bits,
            true,
            section_counts,
            &kept_answers,
            &kept_authorities,
            &kept_additionals,
            body_wire_upper_bound,
            &metadata,
            options,
            response_sizing,
        )?;
        if response.len() <= response_sizing.udp_ceiling {
            return Some(response);
        }

        let removed_record = if let Some(record) = kept_additionals.pop() {
            section_counts.decrement_additional();
            Some(record)
        } else if let Some(index) = removable_authority_indices.pop() {
            let index = usize::from(index);
            let removed = if index + 1 == kept_authorities.len() {
                kept_authorities.pop()
            } else {
                Some(kept_authorities.remove(index))
            };
            if removed.is_some() {
                section_counts.decrement_authority();
            }
            removed
        } else if let Some(record) = kept_answers.pop() {
            section_counts.decrement_answer();
            Some(record)
        } else {
            let removed = kept_authorities.pop();
            if removed.is_some() {
                section_counts.decrement_authority();
            }
            removed
        };

        let Some(record) = removed_record else {
            return Some(response);
        };
        body_wire_upper_bound =
            body_wire_upper_bound.saturating_sub(zone_image_wire_record_uncompressed_len(record));
    }
}

#[allow(clippy::too_many_arguments)]
fn build_zone_image_response_from_plan_records(
    header: &Header,
    question: &Question,
    image: &ZoneImage,
    plan: &ZoneImageLookupPlan,
    response_shape: ZoneImagePlanResponseShape,
    metadata: &RequestMetadata,
    options: AnswerOptions,
    truncated: bool,
    response_sizing: ZoneImageResponseSizing,
) -> Option<Vec<u8>> {
    let section_count_header_bytes = response_shape
        .section_count_header_bytes_with_extra_additional(response_sizing.edns.additional_count)?;
    let response_capacity = zone_image_response_capacity_hint(
        response_sizing,
        response_shape.body_wire_upper_bound,
        truncated,
    );
    let mut response = zone_image_response_prefix(
        header,
        response_shape.response_flag_bits,
        truncated,
        section_count_header_bytes,
        response_capacity,
    );
    let mut compressor = WireNameCompressor::default();
    encode_question(question, &mut response);
    compressor.register_name_labels_at_offset(
        question.qname.labels(),
        question.qname_wire_len(),
        question.qname_ascii_lowercase(),
        DNS_HEADER_LEN,
    );

    image.visit_plan_records(plan, |record| {
        encode_zone_image_wire_record(record, &mut response, &mut compressor);
    });

    append_zone_image_response_edns(
        &mut response,
        metadata,
        options,
        response_sizing.udp_ceiling,
        response_sizing.edns,
    );
    Some(response)
}

#[allow(clippy::too_many_arguments)]
fn zone_image_response_prefix(
    header: &Header,
    response_flag_bits: u16,
    truncated: bool,
    section_count_header_bytes: [u8; 6],
    response_capacity: usize,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(response_capacity);
    response.extend_from_slice(&header.id.to_be_bytes());
    response.extend_from_slice(
        &header
            .response_flags_from_plan_bits(response_flag_bits, truncated)
            .to_be_bytes(),
    );
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&section_count_header_bytes);
    response
}

fn zone_image_section_count_header_bytes(
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
) -> [u8; 6] {
    let answer_count = answer_count.to_be_bytes();
    let authority_count = authority_count.to_be_bytes();
    let additional_count = additional_count.to_be_bytes();
    [
        answer_count[0],
        answer_count[1],
        authority_count[0],
        authority_count[1],
        additional_count[0],
        additional_count[1],
    ]
}

fn zone_image_response_capacity_hint(
    sizing: ZoneImageResponseSizing,
    body_wire_upper_bound: usize,
    truncated: bool,
) -> usize {
    if truncated || sizing.edns.reserve_full_udp_capacity {
        return sizing.udp_ceiling.max(sizing.minimum_capacity);
    }

    sizing
        .minimum_capacity
        .saturating_add(body_wire_upper_bound)
        .saturating_add(sizing.edns.capacity_hint)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ZoneImageEdnsSizing {
    additional_count: u16,
    capacity_hint: usize,
    reserve_full_udp_capacity: bool,
    base_shape: Option<EdnsResponseBaseShape>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ZoneImageResponseSizing {
    udp_ceiling: usize,
    minimum_capacity: usize,
    edns: ZoneImageEdnsSizing,
}

impl ZoneImageResponseSizing {
    fn with_edns_sizing(self, edns: ZoneImageEdnsSizing) -> Self {
        Self { edns, ..self }
    }
}

fn zone_image_response_sizing(
    question: &Question,
    udp_ceiling: usize,
    metadata: &RequestMetadata,
    options: AnswerOptions,
) -> ZoneImageResponseSizing {
    ZoneImageResponseSizing {
        udp_ceiling,
        minimum_capacity: DNS_HEADER_LEN + question.wire_len(),
        edns: zone_image_edns_sizing(metadata, options),
    }
}

fn zone_image_edns_sizing(
    metadata: &RequestMetadata,
    options: AnswerOptions,
) -> ZoneImageEdnsSizing {
    let Some(edns) = metadata.edns else {
        return ZoneImageEdnsSizing::default();
    };

    let base_shape = edns_response_base_shape(edns, options, metadata.extended_dns_error);

    ZoneImageEdnsSizing {
        additional_count: 1,
        capacity_hint: 11usize.saturating_add(base_shape.rdata_len),
        reserve_full_udp_capacity: options.transport == Transport::Udp
            && edns.padding_requested
            && options.edns_padding_block_size > 0,
        base_shape: Some(base_shape),
    }
}

fn append_zone_image_response_edns(
    response: &mut Vec<u8>,
    metadata: &RequestMetadata,
    options: AnswerOptions,
    udp_ceiling: usize,
    edns_sizing: ZoneImageEdnsSizing,
) {
    debug_assert_eq!(metadata.edns.is_some(), edns_sizing.additional_count != 0);
    if let Some(edns) = metadata.edns {
        let base_shape = edns_sizing
            .base_shape
            .expect("ZoneImage EDNS sizing must carry OPT base shape when EDNS is present");
        debug_assert_eq!(
            edns_sizing.capacity_hint,
            11usize.saturating_add(base_shape.rdata_len)
        );
        encode_opt_record_with_base_shape(
            edns,
            metadata.extended_rcode,
            metadata.extended_dns_error,
            options,
            udp_ceiling,
            base_shape,
            response,
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ZoneImageRetrySectionCounts {
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
    section_count_header_bytes: [u8; 6],
}

impl ZoneImageRetrySectionCounts {
    fn from_response_shape(response_shape: ZoneImagePlanResponseShape) -> Self {
        Self {
            answer_count: response_shape.answer_count,
            authority_count: response_shape.authority_count,
            additional_count: response_shape.additional_count,
            section_count_header_bytes: response_shape.section_count_header_bytes,
        }
    }

    fn section_count_header_bytes_with_extra_additional(
        self,
        extra_additional_count: u16,
    ) -> Option<[u8; 6]> {
        let mut bytes = self.section_count_header_bytes;
        if extra_additional_count != 0 {
            let additional_count = self.additional_count.checked_add(extra_additional_count)?;
            bytes[4..6].copy_from_slice(&additional_count.to_be_bytes());
        }
        Some(bytes)
    }

    fn decrement_answer(&mut self) {
        decrement_dns_section_count(
            &mut self.answer_count,
            &mut self.section_count_header_bytes[0..2],
        );
    }

    fn decrement_authority(&mut self) {
        decrement_dns_section_count(
            &mut self.authority_count,
            &mut self.section_count_header_bytes[2..4],
        );
    }

    fn decrement_additional(&mut self) {
        decrement_dns_section_count(
            &mut self.additional_count,
            &mut self.section_count_header_bytes[4..6],
        );
    }
}

fn decrement_dns_section_count(count: &mut u16, count_bytes: &mut [u8]) {
    *count = count.saturating_sub(1);
    count_bytes.copy_from_slice(&count.to_be_bytes());
}

#[allow(clippy::too_many_arguments)]
fn build_zone_image_response_from_wire_records(
    header: &Header,
    question: &Question,
    response_flag_bits: u16,
    truncated: bool,
    section_counts: ZoneImageRetrySectionCounts,
    answers: &[ZoneImageWireRecord<'_>],
    authorities: &[ZoneImageWireRecord<'_>],
    additionals: &[ZoneImageWireRecord<'_>],
    body_wire_upper_bound: usize,
    metadata: &RequestMetadata,
    options: AnswerOptions,
    response_sizing: ZoneImageResponseSizing,
) -> Option<Vec<u8>> {
    debug_assert_eq!(usize::from(section_counts.answer_count), answers.len());
    debug_assert_eq!(
        usize::from(section_counts.authority_count),
        authorities.len()
    );
    debug_assert_eq!(
        usize::from(section_counts.additional_count),
        additionals.len()
    );
    let section_count_header_bytes = section_counts
        .section_count_header_bytes_with_extra_additional(response_sizing.edns.additional_count)?;
    let response_capacity =
        zone_image_response_capacity_hint(response_sizing, body_wire_upper_bound, truncated);
    let mut response = zone_image_response_prefix(
        header,
        response_flag_bits,
        truncated,
        section_count_header_bytes,
        response_capacity,
    );
    let mut compressor = WireNameCompressor::default();
    encode_question(question, &mut response);
    compressor.register_name_labels_at_offset(
        question.qname.labels(),
        question.qname_wire_len(),
        question.qname_ascii_lowercase(),
        DNS_HEADER_LEN,
    );

    encode_zone_image_wire_record_section(answers, &mut response, &mut compressor);
    encode_zone_image_wire_record_section(authorities, &mut response, &mut compressor);
    encode_zone_image_wire_record_section(additionals, &mut response, &mut compressor);

    append_zone_image_response_edns(
        &mut response,
        metadata,
        options,
        response_sizing.udp_ceiling,
        response_sizing.edns,
    );
    Some(response)
}

fn encode_zone_image_wire_record_section(
    records: &[ZoneImageWireRecord<'_>],
    response: &mut Vec<u8>,
    compressor: &mut WireNameCompressor,
) {
    for record in records {
        encode_zone_image_wire_record(*record, response, compressor);
    }
}

fn zone_image_wire_record_uncompressed_len(record: ZoneImageWireRecord<'_>) -> usize {
    record
        .owner_wire
        .len()
        .saturating_add(10)
        .saturating_add(usize::from(u16::from_be_bytes(record.rdlength_bytes)))
}

fn build_direct_zone_image_answer_response(
    header: &Header,
    question: &Question,
    image: &ZoneImage,
    plan: &ZoneImageLookupPlan,
    metadata: RequestMetadata,
    options: AnswerOptions,
    response_sizing: ZoneImageResponseSizing,
) -> Option<Vec<u8>> {
    debug_assert!(
        !metadata.dnssec_requested(),
        "direct ZoneImage answer builder is only called for non-DNSSEC requests"
    );
    if !plan.direct_answer_candidate() {
        return None;
    }

    debug_assert_eq!(plan.rcode(), Rcode::NoError);
    debug_assert!(plan.authoritative());
    debug_assert!(plan.authority_rrsets().is_empty());
    debug_assert!(plan.additional_rrsets().is_empty());
    debug_assert!(!plan.has_custom_answer_items());
    let [rrset_id] = plan.answer_rrsets() else {
        return None;
    };
    let rrset = image.direct_rrset_wire(*rrset_id)?;
    let response_capacity =
        zone_image_response_capacity_hint(response_sizing, rrset.body_wire_len, false);
    let mut response = zone_image_response_prefix(
        header,
        Rcode::NoError.response_flag_bits(true),
        false,
        rrset.section_count_header_bytes(response_sizing.edns.additional_count != 0),
        response_capacity,
    );
    encode_question(question, &mut response);

    image.append_eligible_direct_answer_wire(&rrset, &mut response);
    append_zone_image_response_edns(
        &mut response,
        &metadata,
        options,
        response_sizing.udp_ceiling,
        response_sizing.edns,
    );

    if options.transport == Transport::Udp && response.len() > response_sizing.udp_ceiling {
        return None;
    }
    Some(response)
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
    let mut response = Vec::with_capacity(DNS_HEADER_LEN + question.map_or(0, Question::wire_len));
    let mut compressor = NameCompressor::default();
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
        encode_question(question, &mut response);
        compressor.register_name_at_offset(&question.qname, DNS_HEADER_LEN);
    }

    for record in answers.iter().chain(authorities).chain(additionals) {
        encode_record(record, &mut response, &mut compressor);
    }

    if let Some(edns) = metadata.edns {
        encode_opt_record(
            edns,
            metadata.extended_rcode,
            metadata.extended_dns_error,
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
    let mut metadata = *metadata;
    if metadata.extended_dns_error.is_some() {
        metadata = metadata.without_extended_dns_error();
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
    }

    loop {
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

#[derive(Debug, Default)]
struct NameCompressor {
    suffix_offsets: HashMap<Vec<Vec<u8>>, u16>,
}

impl NameCompressor {
    fn register_name_at_offset(&mut self, name: &DomainName, start_offset: usize) {
        let mut offset = start_offset;
        for index in 0..name.labels.len() {
            if offset <= 0x3fff {
                self.suffix_offsets
                    .entry(name_suffix_key(&name.labels[index..]))
                    .or_insert(offset as u16);
            }
            offset += 1 + name.labels[index].len();
        }
    }

    fn write_name(&mut self, name: &DomainName, response: &mut Vec<u8>) {
        let pointer_suffix = (0..name.labels.len()).find_map(|index| {
            let suffix = &name.labels[index..];
            if name_wire_len(suffix) <= 2 {
                return None;
            }
            self.suffix_offsets
                .get(&name_suffix_key(suffix))
                .copied()
                .map(|offset| (index, offset))
        });

        let pointer_index = pointer_suffix.map(|(index, _)| index);
        for index in 0..pointer_index.unwrap_or(name.labels.len()) {
            if response.len() <= 0x3fff {
                self.suffix_offsets
                    .entry(name_suffix_key(&name.labels[index..]))
                    .or_insert(response.len() as u16);
            }
            let label = &name.labels[index];
            response.push(label.len() as u8);
            response.extend_from_slice(label);
        }

        if let Some((_, offset)) = pointer_suffix {
            response.extend_from_slice(&(0xc000 | offset).to_be_bytes());
        } else {
            response.push(0);
        }
    }
}

#[derive(Debug, Default)]
struct WireNameCompressor {
    suffix_offsets: SmallVec<[WireSuffixOffset; 8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WireSuffixOffset {
    key: SmallVec<[u8; 64]>,
    offset: u16,
}

impl WireNameCompressor {
    #[cfg(test)]
    fn register_wire_name_at_offset(&mut self, wire_name: &[u8], start_offset: usize) {
        let Some(label_offsets) = wire_label_offsets(wire_name) else {
            return;
        };
        for label_offset in label_offsets {
            let offset = start_offset + label_offset;
            if offset <= 0x3fff && wire_name.len().saturating_sub(label_offset) > 2 {
                self.register_wire_suffix_offset(&wire_name[label_offset..], offset as u16);
            }
        }
    }

    fn register_name_labels_at_offset(
        &mut self,
        labels: &[Vec<u8>],
        name_wire_len: usize,
        labels_are_ascii_lowercase: bool,
        start_offset: usize,
    ) {
        debug_assert!(
            self.suffix_offsets.is_empty(),
            "question labels seed a fresh response compressor"
        );
        let mut offset = start_offset;
        let mut suffix_wire_len = name_wire_len;
        for index in 0..labels.len() {
            if offset <= 0x3fff && suffix_wire_len > 2 {
                self.push_label_suffix_offset(
                    &labels[index..],
                    suffix_wire_len,
                    labels_are_ascii_lowercase,
                    offset as u16,
                );
            }
            let label_wire_len = 1 + labels[index].len();
            offset += label_wire_len;
            suffix_wire_len = suffix_wire_len.saturating_sub(label_wire_len);
        }
    }

    fn write_wire_name(&mut self, wire_name: &[u8], response: &mut Vec<u8>) {
        if wire_name.len() > 2
            && let Some(offset) = self.wire_suffix_offset(wire_name)
        {
            response.extend_from_slice(&(0xc000 | offset).to_be_bytes());
            return;
        }

        let Some((write_end, pointer_suffix)) = self.wire_name_write_plan(wire_name, false) else {
            response.extend_from_slice(wire_name);
            return;
        };
        let response_start = response.len();
        self.register_pre_pointer_wire_suffixes(wire_name, write_end, response_start);
        response.extend_from_slice(&wire_name[..write_end]);
        if let Some((_, offset)) = pointer_suffix {
            response.extend_from_slice(&(0xc000 | offset).to_be_bytes());
        } else {
            response.push(0);
        }
    }

    fn wire_name_write_plan(
        &self,
        wire_name: &[u8],
        check_full_suffix: bool,
    ) -> Option<(usize, Option<(usize, u16)>)> {
        let mut pointer_suffix = None;
        let mut cursor = 0usize;
        loop {
            let len = *wire_name.get(cursor)? as usize;
            if len & 0xc0 != 0 || len > 63 {
                return None;
            }
            if len == 0 {
                if cursor + 1 != wire_name.len() {
                    return None;
                }
                let write_end = pointer_suffix.map_or(cursor, |(label_offset, _)| label_offset);
                return Some((write_end, pointer_suffix));
            }
            if (cursor != 0 || check_full_suffix)
                && pointer_suffix.is_none()
                && wire_name.len().saturating_sub(cursor) > 2
                && let Some(offset) = self.wire_suffix_offset(&wire_name[cursor..])
            {
                pointer_suffix = Some((cursor, offset));
            }
            cursor = cursor.checked_add(1)?.checked_add(len)?;
            if cursor >= wire_name.len() {
                return None;
            }
        }
    }

    fn register_pre_pointer_wire_suffixes(
        &mut self,
        wire_name: &[u8],
        write_end: usize,
        response_start: usize,
    ) {
        let mut cursor = 0usize;
        while cursor < write_end {
            let response_offset = response_start + cursor;
            if response_offset <= 0x3fff && wire_name.len().saturating_sub(cursor) > 2 {
                self.push_wire_suffix_offset(&wire_name[cursor..], response_offset as u16);
            }
            cursor += 1 + wire_name[cursor] as usize;
        }
    }

    fn wire_suffix_offset(&self, wire_suffix: &[u8]) -> Option<u16> {
        for entry in &self.suffix_offsets {
            if wire_suffix_matches_key(wire_suffix, &entry.key) {
                return Some(entry.offset);
            }
        }
        None
    }

    #[cfg(test)]
    fn register_wire_suffix_offset(&mut self, wire_suffix: &[u8], offset: u16) {
        if self.wire_suffix_offset(wire_suffix).is_some() {
            return;
        }
        self.push_wire_suffix_offset(wire_suffix, offset);
    }

    fn push_wire_suffix_offset(&mut self, wire_suffix: &[u8], offset: u16) {
        self.suffix_offsets.push(WireSuffixOffset {
            key: wire_suffix_small_key(wire_suffix),
            offset,
        });
    }

    fn push_label_suffix_offset(
        &mut self,
        labels: &[Vec<u8>],
        wire_len: usize,
        labels_are_ascii_lowercase: bool,
        offset: u16,
    ) {
        self.suffix_offsets.push(WireSuffixOffset {
            key: label_suffix_small_key(labels, wire_len, labels_are_ascii_lowercase),
            offset,
        });
    }
}

#[cfg(test)]
type WireLabelOffsets = SmallVec<[usize; 8]>;

#[cfg(test)]
fn wire_label_offsets(wire_name: &[u8]) -> Option<WireLabelOffsets> {
    let mut offsets = SmallVec::new();
    let mut cursor = 0usize;
    loop {
        let len = *wire_name.get(cursor)? as usize;
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        if len == 0 {
            return (cursor + 1 == wire_name.len()).then_some(offsets);
        }
        offsets.push(cursor);
        cursor = cursor.checked_add(1)?.checked_add(len)?;
        if cursor >= wire_name.len() {
            return None;
        }
    }
}

pub(crate) fn wire_name_len_at(bytes: &[u8], offset: usize) -> Option<usize> {
    let mut cursor = offset;
    loop {
        let len = *bytes.get(cursor)? as usize;
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        cursor += 1;
        if len == 0 {
            return Some(cursor - offset);
        }
        cursor = cursor.checked_add(len)?;
        if cursor > bytes.len() {
            return None;
        }
    }
}

#[cfg(test)]
fn wire_suffix_key(wire_suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(wire_suffix.len());
    let mut cursor = 0usize;
    while cursor < wire_suffix.len() {
        let len = wire_suffix[cursor] as usize;
        key.push(wire_suffix[cursor]);
        cursor += 1;
        if len == 0 {
            break;
        }
        key.extend(
            wire_suffix[cursor..cursor + len]
                .iter()
                .map(u8::to_ascii_lowercase),
        );
        cursor += len;
    }
    key
}

fn wire_suffix_small_key(wire_suffix: &[u8]) -> SmallVec<[u8; 64]> {
    let mut key = SmallVec::with_capacity(wire_suffix.len());
    let mut cursor = 0usize;
    while cursor < wire_suffix.len() {
        let len = wire_suffix[cursor] as usize;
        key.push(wire_suffix[cursor]);
        cursor += 1;
        if len == 0 {
            break;
        }
        let label = &wire_suffix[cursor..cursor + len];
        if label.iter().any(u8::is_ascii_uppercase) {
            key.extend(label.iter().map(u8::to_ascii_lowercase));
        } else {
            key.extend_from_slice(label);
        }
        cursor += len;
    }
    key
}

fn label_suffix_small_key(
    labels: &[Vec<u8>],
    wire_len: usize,
    labels_are_ascii_lowercase: bool,
) -> SmallVec<[u8; 64]> {
    let mut key = SmallVec::with_capacity(wire_len);
    if labels_are_ascii_lowercase {
        for label in labels {
            key.push(label.len() as u8);
            key.extend_from_slice(label);
        }
    } else {
        for label in labels {
            key.push(label.len() as u8);
            key.extend(label.iter().map(u8::to_ascii_lowercase));
        }
    }
    key.push(0);
    key
}

fn wire_suffix_matches_key(wire_suffix: &[u8], key: &[u8]) -> bool {
    if wire_suffix == key {
        return true;
    }

    let mut suffix_cursor = 0usize;
    let mut key_cursor = 0usize;
    loop {
        let Some(&suffix_len) = wire_suffix.get(suffix_cursor) else {
            return false;
        };
        let Some(&key_len) = key.get(key_cursor) else {
            return false;
        };
        if suffix_len != key_len {
            return false;
        }
        suffix_cursor += 1;
        key_cursor += 1;
        let label_len = suffix_len as usize;
        if label_len == 0 {
            return suffix_cursor == wire_suffix.len() && key_cursor == key.len();
        }
        let Some(suffix_label) = wire_suffix.get(suffix_cursor..suffix_cursor + label_len) else {
            return false;
        };
        let Some(key_label) = key.get(key_cursor..key_cursor + label_len) else {
            return false;
        };
        if !wire_label_matches_key(suffix_label, key_label) {
            return false;
        }
        suffix_cursor += label_len;
        key_cursor += label_len;
    }
}

fn wire_label_matches_key(label: &[u8], canonical_key_label: &[u8]) -> bool {
    label == canonical_key_label || label.eq_ignore_ascii_case(canonical_key_label)
}

#[cfg(test)]
fn canonical_wire_suffix_key(wire_suffix: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if wire_suffix_is_ascii_lowercase(wire_suffix) {
        std::borrow::Cow::Borrowed(wire_suffix)
    } else {
        std::borrow::Cow::Owned(wire_suffix_key(wire_suffix))
    }
}

#[cfg(test)]
fn wire_suffix_is_ascii_lowercase(wire_suffix: &[u8]) -> bool {
    let mut cursor = 0usize;
    while cursor < wire_suffix.len() {
        let len = wire_suffix[cursor] as usize;
        cursor += 1;
        if len == 0 {
            return true;
        }
        if wire_suffix[cursor..cursor + len]
            .iter()
            .any(u8::is_ascii_uppercase)
        {
            return false;
        }
        cursor += len;
    }
    true
}

fn encode_question(question: &Question, response: &mut Vec<u8>) {
    encode_name_labels(question.qname.labels(), response);
    response.extend_from_slice(&question.qtype_qclass_wire);
}

fn encode_name_labels(labels: &[Vec<u8>], response: &mut Vec<u8>) {
    for label in labels {
        response.push(label.len() as u8);
        response.extend_from_slice(label);
    }
    response.push(0);
}

fn name_suffix_key(labels: &[Vec<u8>]) -> Vec<Vec<u8>> {
    labels
        .iter()
        .map(|label| label.iter().map(u8::to_ascii_lowercase).collect())
        .collect()
}

fn name_wire_len(labels: &[Vec<u8>]) -> usize {
    labels.iter().map(|label| 1 + label.len()).sum::<usize>() + 1
}

fn encode_record(record: &ResourceRecord, response: &mut Vec<u8>, compressor: &mut NameCompressor) {
    compressor.write_name(&record.owner, response);
    response.extend_from_slice(&record.rr_type.to_be_bytes());
    response.extend_from_slice(&record.class.to_be_bytes());
    response.extend_from_slice(&record.ttl.to_be_bytes());
    let rdlength_offset = response.len();
    response.extend_from_slice(&0u16.to_be_bytes());
    let rdata_offset = response.len();
    encode_record_rdata(record, response, compressor);
    let rdlength = response.len() - rdata_offset;
    response[rdlength_offset..rdlength_offset + 2]
        .copy_from_slice(&(rdlength as u16).to_be_bytes());
}

fn encode_zone_image_wire_record(
    record: ZoneImageWireRecord<'_>,
    response: &mut Vec<u8>,
    compressor: &mut WireNameCompressor,
) {
    compressor.write_wire_name(record.owner_wire, response);
    response.extend_from_slice(&record.fixed_fields);
    if record.rdata_encoding.is_copy() {
        debug_assert_eq!(
            usize::from(u16::from_be_bytes(record.rdlength_bytes)),
            record.rdata.len()
        );
        response.extend_from_slice(&record.rdlength_bytes);
        response.extend_from_slice(record.rdata);
        return;
    }

    let rdlength_offset = response.len();
    response.extend_from_slice(&0u16.to_be_bytes());
    let rdata_offset = response.len();
    encode_zone_image_wire_record_rdata(record.rdata_encoding, record.rdata, response, compressor);
    let rdlength = response.len() - rdata_offset;
    response[rdlength_offset..rdlength_offset + 2]
        .copy_from_slice(&(rdlength as u16).to_be_bytes());
}

fn encode_zone_image_wire_record_rdata(
    rdata_encoding: PackedRdataEncoding,
    rdata: &[u8],
    response: &mut Vec<u8>,
    compressor: &mut WireNameCompressor,
) {
    if rdata_encoding.is_copy() {
        response.extend_from_slice(rdata);
    } else if rdata_encoding.is_single_name() {
        compressor.write_wire_name(rdata, response);
    } else if let Some((mname_len, rname_len)) = rdata_encoding.soa_lengths() {
        let mname_len = usize::from(mname_len);
        let rname_len = usize::from(rname_len);
        debug_assert!(rname_len > 0);
        debug_assert_eq!(mname_len + rname_len + 20, rdata.len());
        compressor.write_wire_name(&rdata[..mname_len], response);
        compressor.write_wire_name(&rdata[mname_len..mname_len + rname_len], response);
        response.extend_from_slice(&rdata[mname_len + rname_len..]);
    } else if rdata_encoding.is_mx() {
        response.extend_from_slice(&rdata[..2]);
        compressor.write_wire_name(&rdata[2..], response);
    }
}

fn encode_record_rdata(
    record: &ResourceRecord,
    response: &mut Vec<u8>,
    compressor: &mut NameCompressor,
) {
    encode_record_rdata_parts(record.rr_type, &record.rdata, response, compressor);
}

fn encode_record_rdata_parts(
    rr_type: u16,
    rdata: &[u8],
    response: &mut Vec<u8>,
    compressor: &mut NameCompressor,
) {
    match rr_type {
        rr_type
            if rr_type == RecordType::Ns as u16
                || rr_type == RecordType::Cname as u16
                || rr_type == RecordType::Ptr as u16 =>
        {
            encode_single_name_rdata(rdata, response, compressor)
        }
        rr_type if rr_type == RecordType::Soa as u16 => {
            encode_soa_rdata(rdata, response, compressor)
        }
        rr_type if rr_type == RecordType::Mx as u16 => encode_mx_rdata(rdata, response, compressor),
        _ => response.extend_from_slice(rdata),
    }
}

fn encode_single_name_rdata(rdata: &[u8], response: &mut Vec<u8>, compressor: &mut NameCompressor) {
    let Ok((name, consumed)) = DomainName::parse(rdata, 0) else {
        response.extend_from_slice(rdata);
        return;
    };
    if consumed == rdata.len() {
        compressor.write_name(&name, response);
    } else {
        response.extend_from_slice(rdata);
    }
}

fn encode_soa_rdata(rdata: &[u8], response: &mut Vec<u8>, compressor: &mut NameCompressor) {
    let Ok((mname, consumed_mname)) = DomainName::parse(rdata, 0) else {
        response.extend_from_slice(rdata);
        return;
    };
    let rname_offset = consumed_mname;
    let Ok((rname, consumed_rname)) = DomainName::parse(rdata, rname_offset) else {
        response.extend_from_slice(rdata);
        return;
    };
    let timers_offset = rname_offset + consumed_rname;
    if timers_offset + 20 != rdata.len() {
        response.extend_from_slice(rdata);
        return;
    }
    compressor.write_name(&mname, response);
    compressor.write_name(&rname, response);
    response.extend_from_slice(&rdata[timers_offset..]);
}

fn encode_mx_rdata(rdata: &[u8], response: &mut Vec<u8>, compressor: &mut NameCompressor) {
    if rdata.len() < 3 {
        response.extend_from_slice(rdata);
        return;
    }
    let Ok((exchange, consumed)) = DomainName::parse(rdata, 2) else {
        response.extend_from_slice(rdata);
        return;
    };
    if 2 + consumed == rdata.len() {
        response.extend_from_slice(&rdata[..2]);
        compressor.write_name(&exchange, response);
    } else {
        response.extend_from_slice(rdata);
    }
}

fn encode_opt_record(
    edns: EdnsMetadata,
    extended_rcode: u16,
    extended_dns_error: Option<ExtendedDnsError>,
    options: AnswerOptions,
    udp_ceiling: usize,
    response: &mut Vec<u8>,
) {
    let base_shape = edns_response_base_shape(edns, options, extended_dns_error);
    encode_opt_record_with_base_shape(
        edns,
        extended_rcode,
        extended_dns_error,
        options,
        udp_ceiling,
        base_shape,
        response,
    );
}

fn encode_opt_record_with_base_shape(
    edns: EdnsMetadata,
    extended_rcode: u16,
    extended_dns_error: Option<ExtendedDnsError>,
    options: AnswerOptions,
    udp_ceiling: usize,
    base_shape: EdnsResponseBaseShape,
    response: &mut Vec<u8>,
) {
    debug_assert_eq!(
        base_shape.extended_dns_error,
        if options.extended_dns_errors == ExtendedDnsErrorsMode::Minimal {
            extended_dns_error
        } else {
            None
        }
    );
    let shape = edns_response_options_shape_from_base(
        edns,
        options,
        base_shape,
        response.len(),
        udp_ceiling,
    );
    response.extend_from_slice(&OPT_OWNER_AND_TYPE_WIRE);
    response.extend_from_slice(&options.max_udp_payload.to_be_bytes());
    let ext_rcode = ((extended_rcode >> 4) as u32) << 24;
    let ttl = ext_rcode | u32::from(edns.do_bit) << 15;
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&(shape.rdata_len as u16).to_be_bytes());
    let rdata_start = response.len();
    append_edns_response_options(edns, options, shape, response);
    debug_assert_eq!(response.len() - rdata_start, shape.rdata_len);
}

fn edns_response_base_shape(
    edns: EdnsMetadata,
    options: AnswerOptions,
    extended_dns_error: Option<ExtendedDnsError>,
) -> EdnsResponseBaseShape {
    let tcp_keepalive_response =
        options.transport == Transport::Tcp && edns.tcp_keepalive_requested;
    let nsid_len = if edns.nsid_requested && !options.nsid.is_empty() {
        options.nsid.len()
    } else {
        0
    };
    let cookie_response = edns.cookie.is_some() && options.dns_cookie.is_some();
    let extended_dns_error = if options.extended_dns_errors == ExtendedDnsErrorsMode::Minimal {
        extended_dns_error
    } else {
        None
    };

    let mut rdata_len = 0usize;
    if tcp_keepalive_response {
        rdata_len = rdata_len.saturating_add(6);
    }
    if nsid_len > 0 {
        rdata_len = rdata_len.saturating_add(4).saturating_add(nsid_len);
    }
    if cookie_response {
        rdata_len = rdata_len
            .saturating_add(4)
            .saturating_add(DNS_COOKIE_CLIENT_LEN)
            .saturating_add(DNS_COOKIE_SERVER_V1_LEN);
    }
    if extended_dns_error.is_some() {
        rdata_len = rdata_len.saturating_add(6);
    }

    EdnsResponseBaseShape {
        tcp_keepalive_response,
        nsid_len,
        cookie_response,
        extended_dns_error,
        rdata_len,
    }
}

fn edns_response_options_shape_from_base(
    edns: EdnsMetadata,
    options: AnswerOptions,
    base_shape: EdnsResponseBaseShape,
    response_len_before_opt: usize,
    udp_ceiling: usize,
) -> EdnsResponseOptionsShape {
    let mut rdata_len = base_shape.rdata_len;
    let padding_len = if edns.padding_requested && options.edns_padding_block_size > 0 {
        let block_size = options.edns_padding_block_size as usize;
        let total_before_padding_data = response_len_before_opt + 11 + rdata_len + 4;
        let padding_len = (block_size - (total_before_padding_data % block_size)) % block_size;
        let padded_response_len = total_before_padding_data + padding_len;

        if options.transport == Transport::Udp && padded_response_len > udp_ceiling {
            None
        } else {
            rdata_len = rdata_len.saturating_add(4).saturating_add(padding_len);
            Some(padding_len)
        }
    } else {
        None
    };

    EdnsResponseOptionsShape {
        tcp_keepalive_response: base_shape.tcp_keepalive_response,
        nsid_len: base_shape.nsid_len,
        cookie_response: base_shape.cookie_response,
        extended_dns_error: base_shape.extended_dns_error,
        padding_len,
        rdata_len,
    }
}

fn append_edns_response_options(
    edns: EdnsMetadata,
    options: AnswerOptions,
    shape: EdnsResponseOptionsShape,
    response: &mut Vec<u8>,
) {
    if shape.tcp_keepalive_response {
        let timeout_units = options
            .tcp_keepalive_timeout_secs
            .saturating_mul(10)
            .min(u64::from(u16::MAX)) as u16;

        response.extend_from_slice(&EDNS_TCP_KEEPALIVE_RESPONSE_OPTION_PREFIX);
        response.extend_from_slice(&timeout_units.to_be_bytes());
    }

    if shape.nsid_len > 0 {
        response.extend_from_slice(&EDNS_NSID_OPTION.to_be_bytes());
        response.extend_from_slice(&(shape.nsid_len as u16).to_be_bytes());
        response.extend_from_slice(options.nsid);
    }

    if shape.cookie_response {
        let cookie = edns
            .cookie
            .expect("EDNS response shape requires request cookie");
        let context = options
            .dns_cookie
            .expect("EDNS response shape requires DNS Cookie context");
        let server_cookie = compute_dns_server_cookie(cookie.client, context);
        response.extend_from_slice(&EDNS_COOKIE_RESPONSE_OPTION_PREFIX);
        response.extend_from_slice(&cookie.client);
        response.extend_from_slice(&server_cookie);
    }

    if let Some(error) = shape.extended_dns_error {
        response.extend_from_slice(&EDNS_EXTENDED_DNS_ERROR_RESPONSE_OPTION_PREFIX);
        response.extend_from_slice(&error.info_code().to_be_bytes());
    }

    if let Some(padding_len) = shape.padding_len {
        append_edns_padding(response, padding_len);
    }
}

fn append_edns_padding(response: &mut Vec<u8>, padding_len: usize) {
    response.extend_from_slice(&EDNS_PADDING_OPTION.to_be_bytes());
    response.extend_from_slice(&(padding_len as u16).to_be_bytes());
    response.resize(response.len() + padding_len, 0);
}

pub fn request_has_valid_dns_server_cookie(packet: &[u8], context: DnsCookieContext) -> bool {
    matches!(
        dns_cookie_request_status(packet, Some(context)),
        Some(DnsCookieRequestStatus::ValidServerCookie)
    )
}

pub fn dns_cookie_request_status(
    packet: &[u8],
    context: Option<DnsCookieContext>,
) -> Option<DnsCookieRequestStatus> {
    let Ok(header) = Header::parse(packet) else {
        return None;
    };
    if header.is_response() || header.opcode() != Some(Opcode::Query) || header.qdcount != 1 {
        return None;
    }
    let Ok(question) = Question::parse(packet) else {
        return None;
    };
    let Ok(metadata) = RequestMetadata::parse(&header, packet, &question) else {
        return None;
    };
    let Some(cookie) = metadata.edns.and_then(|edns| edns.cookie) else {
        return Some(DnsCookieRequestStatus::NoCookie);
    };
    if cookie.server.is_none() {
        return Some(DnsCookieRequestStatus::ClientCookieOnly);
    }
    let Some(context) = context else {
        return Some(DnsCookieRequestStatus::InvalidServerCookie);
    };
    if dns_server_cookie_is_valid(cookie, context) {
        Some(DnsCookieRequestStatus::ValidServerCookie)
    } else {
        Some(DnsCookieRequestStatus::InvalidServerCookie)
    }
}

fn dns_server_cookie_is_valid(cookie: EdnsCookie, context: DnsCookieContext) -> bool {
    let Some(server_cookie) = cookie.server else {
        return false;
    };
    if server_cookie.len as usize != DNS_COOKIE_SERVER_V1_LEN
        || server_cookie.bytes[0] != DNS_COOKIE_VERSION_1
    {
        return false;
    }

    let timestamp = u32::from_be_bytes([
        server_cookie.bytes[4],
        server_cookie.bytes[5],
        server_cookie.bytes[6],
        server_cookie.bytes[7],
    ]);
    if !dns_cookie_timestamp_is_valid(timestamp, context) {
        return false;
    }

    dns_cookie_hash_matches_secret(cookie, &server_cookie.bytes, context.server_secret, context)
        || context.previous_server_secret.is_some_and(|secret| {
            dns_cookie_hash_matches_secret(cookie, &server_cookie.bytes, secret, context)
        })
}

fn dns_cookie_hash_matches_secret(
    cookie: EdnsCookie,
    server_cookie_bytes: &[u8; 32],
    secret: &[u8; 16],
    context: DnsCookieContext,
) -> bool {
    let expected = compute_dns_server_cookie_with_fields(
        cookie.client,
        &server_cookie_bytes[..8],
        context.client_ip,
        secret,
    );
    expected
        .ct_eq(&server_cookie_bytes[8..DNS_COOKIE_SERVER_V1_LEN])
        .into()
}

fn dns_cookie_requires_badcookie(metadata: RequestMetadata, options: AnswerOptions) -> bool {
    let Some(context) = options.dns_cookie else {
        return false;
    };
    if context.policy != DnsCookiePolicy::Strict {
        return false;
    }
    let Some(cookie) = metadata.edns.and_then(|edns| edns.cookie) else {
        return false;
    };
    !dns_server_cookie_is_valid(cookie, context)
}

fn compute_dns_server_cookie(
    cookie: [u8; DNS_COOKIE_CLIENT_LEN],
    context: DnsCookieContext,
) -> [u8; DNS_COOKIE_SERVER_V1_LEN] {
    let mut prefix = [0u8; 8];
    prefix[0] = DNS_COOKIE_VERSION_1;
    prefix[4..8].copy_from_slice(&context.now_unix_secs.to_be_bytes());
    let hash = compute_dns_server_cookie_with_fields(
        cookie,
        &prefix,
        context.client_ip,
        context.server_secret,
    );

    let mut server_cookie = [0u8; DNS_COOKIE_SERVER_V1_LEN];
    server_cookie[..8].copy_from_slice(&prefix);
    server_cookie[8..].copy_from_slice(&hash);
    server_cookie
}

fn compute_dns_server_cookie_with_fields(
    client_cookie: [u8; DNS_COOKIE_CLIENT_LEN],
    server_cookie_prefix: &[u8],
    client_ip: IpAddr,
    secret: &[u8; 16],
) -> [u8; 8] {
    let k0 = u64::from_le_bytes(secret[..8].try_into().expect("secret key half"));
    let k1 = u64::from_le_bytes(secret[8..].try_into().expect("secret key half"));
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(&client_cookie);
    hasher.write(server_cookie_prefix);
    match client_ip {
        IpAddr::V4(addr) => hasher.write(&addr.octets()),
        IpAddr::V6(addr) => hasher.write(&addr.octets()),
    }
    hasher.finish().to_le_bytes()
}

fn dns_cookie_timestamp_is_valid(timestamp: u32, context: DnsCookieContext) -> bool {
    context.now_unix_secs.wrapping_sub(timestamp) <= context.past_window_secs
        || timestamp.wrapping_sub(context.now_unix_secs) <= context.future_window_secs
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
    extended_dns_error: Option<ExtendedDnsError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedDnsError {
    NotReady,
    UnsupportedNsec3Iterations,
}

impl ExtendedDnsError {
    fn info_code(self) -> u16 {
        match self {
            Self::NotReady => EDE_NOT_READY,
            Self::UnsupportedNsec3Iterations => EDE_UNSUPPORTED_NSEC3_ITERATIONS,
        }
    }
}

impl RequestMetadata {
    fn empty() -> Self {
        Self {
            edns: None,
            extended_rcode: 0,
            extended_dns_error: None,
        }
    }

    fn parse(header: &Header, packet: &[u8], question: &Question) -> Result<Self, EdnsError> {
        let mut offset = DNS_HEADER_LEN + question.wire_len();
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
            let (record, consumed) = parse_record_view(packet, offset)?;
            offset += consumed;
            if record.rr_type == RecordType::Opt as u16 {
                if edns.is_some() || !record.owner_is_root {
                    return Err(EdnsError::FormErr);
                }

                let parsed_options = parse_edns_options(record.rdata)?;
                let metadata = EdnsMetadata {
                    payload_size: record.class.max(512),
                    version: ((record.ttl >> 16) & 0xff) as u8,
                    do_bit: record.ttl & 0x8000 != 0,
                    tcp_keepalive_requested: parsed_options.tcp_keepalive_requested,
                    nsid_requested: parsed_options.nsid_requested,
                    cookie: parsed_options.cookie,
                    padding_requested: parsed_options.padding_requested,
                };
                if metadata.version > 0 {
                    return Err(EdnsError::BadVers(Self {
                        edns: Some(metadata),
                        extended_rcode: 0,
                        extended_dns_error: None,
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
            extended_dns_error: None,
        })
    }

    fn with_extended_rcode(mut self, extended_rcode: u16) -> Self {
        self.extended_rcode = extended_rcode;
        self
    }

    fn with_extended_dns_error(mut self, error: ExtendedDnsError) -> Self {
        self.extended_dns_error = Some(error);
        self
    }

    fn without_extended_dns_error(mut self) -> Self {
        self.extended_dns_error = None;
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
    nsid_requested: bool,
    cookie: Option<EdnsCookie>,
    padding_requested: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EdnsResponseBaseShape {
    tcp_keepalive_response: bool,
    nsid_len: usize,
    cookie_response: bool,
    extended_dns_error: Option<ExtendedDnsError>,
    rdata_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EdnsResponseOptionsShape {
    tcp_keepalive_response: bool,
    nsid_len: usize,
    cookie_response: bool,
    extended_dns_error: Option<ExtendedDnsError>,
    padding_len: Option<usize>,
    rdata_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct EdnsOptions {
    tcp_keepalive_requested: bool,
    nsid_requested: bool,
    cookie: Option<EdnsCookie>,
    padding_requested: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EdnsCookie {
    client: [u8; DNS_COOKIE_CLIENT_LEN],
    server: Option<EdnsServerCookie>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EdnsServerCookie {
    len: u8,
    bytes: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedRecordView<'a> {
    owner_is_root: bool,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata_offset: usize,
    rdata: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdnsError {
    FormErr,
    BadVers(RequestMetadata),
}

fn parse_record_header(packet: &[u8], offset: usize) -> Result<(u16, usize), EdnsError> {
    let start = offset;
    let consumed = skip_compressed_name(packet, offset).map_err(|_| EdnsError::FormErr)?;
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

fn parse_record_view(
    packet: &[u8],
    offset: usize,
) -> Result<(ParsedRecordView<'_>, usize), EdnsError> {
    parse_record_view_inner(packet, offset, None).map(|(record, _, consumed)| (record, consumed))
}

fn parse_record_view_with_owner_match<'packet>(
    packet: &'packet [u8],
    offset: usize,
    expected_owner: &DomainName,
) -> Result<((ParsedRecordView<'packet>, bool), usize), EdnsError> {
    parse_record_view_inner(packet, offset, Some(expected_owner)).map(
        |(record, owner_matches_expected, consumed)| ((record, owner_matches_expected), consumed),
    )
}

fn parse_record_view_inner<'packet>(
    packet: &'packet [u8],
    offset: usize,
    expected_owner: Option<&DomainName>,
) -> Result<(ParsedRecordView<'packet>, bool, usize), EdnsError> {
    let start = offset;
    let owner_scan =
        scan_compressed_name(packet, offset, expected_owner).map_err(|_| EdnsError::FormErr)?;
    let consumed = owner_scan.consumed;
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
    let rdata_offset = offset;
    if offset + rdlength > packet.len() {
        return Err(EdnsError::FormErr);
    }
    let rdata = &packet[offset..offset + rdlength];
    offset += rdlength;

    Ok((
        ParsedRecordView {
            owner_is_root: owner_scan.label_count == 0,
            rr_type,
            class,
            ttl,
            rdata_offset,
            rdata,
        },
        owner_scan.matches_expected,
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
        match option_code {
            EDNS_NSID_OPTION => options.nsid_requested = true,
            EDNS_COOKIE_OPTION => {
                let cookie = parse_edns_cookie_option(&rdata[offset..offset + option_len])?;
                if options.cookie.is_none() {
                    options.cookie = Some(cookie);
                }
            }
            EDNS_TCP_KEEPALIVE_OPTION => options.tcp_keepalive_requested = true,
            EDNS_PADDING_OPTION => options.padding_requested = true,
            _ => {}
        }
        offset += option_len;
    }
    Ok(options)
}

fn parse_edns_cookie_option(rdata: &[u8]) -> Result<EdnsCookie, EdnsError> {
    if rdata.len() != DNS_COOKIE_CLIENT_LEN
        && !(DNS_COOKIE_CLIENT_LEN + 8..=DNS_COOKIE_CLIENT_LEN + 32).contains(&rdata.len())
    {
        return Err(EdnsError::FormErr);
    }

    let mut client = [0u8; DNS_COOKIE_CLIENT_LEN];
    client.copy_from_slice(&rdata[..DNS_COOKIE_CLIENT_LEN]);
    let server = if rdata.len() > DNS_COOKIE_CLIENT_LEN {
        let server_data = &rdata[DNS_COOKIE_CLIENT_LEN..];
        let mut bytes = [0u8; 32];
        bytes[..server_data.len()].copy_from_slice(server_data);
        Some(EdnsServerCookie {
            len: server_data.len() as u8,
            bytes,
        })
    } else {
        None
    };

    Ok(EdnsCookie { client, server })
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupResult {
    pub rcode: Rcode,
    pub authoritative: bool,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
    pub termination: Option<LookupTermination>,
    pub nsec3_iterations_exceeded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupTermination {
    CnameChainLimit,
    CnameLoop,
    MalformedDname,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupMetrics {
    pub termination: Option<LookupTermination>,
    pub nsec3_iterations_exceeded: bool,
    pub zone_image_used: bool,
    pub zone_image_direct_answer: bool,
    pub zone_image_failure_reason: Option<ZoneImageServeFailureReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneImageServeFailureReason {
    ResponseBuildFailed,
}

impl ZoneImageServeFailureReason {
    pub const COUNT: usize = 1;
    pub const ALL: [Self; 1] = [Self::ResponseBuildFailed];

    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::ResponseBuildFailed => "response_build_failed",
        }
    }

    pub const fn metric_index(self) -> usize {
        match self {
            Self::ResponseBuildFailed => 0,
        }
    }
}

impl From<&ZoneImageLookupPlan> for LookupMetrics {
    fn from(plan: &ZoneImageLookupPlan) -> Self {
        Self::from_zone_image_plan(plan, false)
    }
}

impl LookupMetrics {
    fn from_zone_image_plan(plan: &ZoneImageLookupPlan, direct_answer: bool) -> Self {
        Self {
            termination: plan.termination(),
            nsec3_iterations_exceeded: plan.nsec3_iterations_exceeded(),
            zone_image_used: true,
            zone_image_direct_answer: direct_answer,
            zone_image_failure_reason: None,
        }
    }

    fn from_zone_image_failure(reason: ZoneImageServeFailureReason) -> Self {
        Self {
            termination: None,
            nsec3_iterations_exceeded: false,
            zone_image_used: false,
            zone_image_direct_answer: false,
            zone_image_failure_reason: Some(reason),
        }
    }
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

    pub fn servfail_records_with_termination(
        answers: Vec<ResourceRecord>,
        termination: LookupTermination,
    ) -> Self {
        Self {
            rcode: Rcode::ServFail,
            authoritative: true,
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
            termination: Some(termination),
            nsec3_iterations_exceeded: false,
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
            nsec3_iterations_exceeded: false,
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
            nsec3_iterations_exceeded: false,
        }
    }

    pub fn nodata(soa: Option<&Rrset>) -> Self {
        Self {
            rcode: Rcode::NoError,
            authoritative: true,
            answers: Vec::new(),
            authorities: negative_soa_records(soa),
            additionals: Vec::new(),
            termination: None,
            nsec3_iterations_exceeded: false,
        }
    }

    pub fn nodata_with_answers(answers: Vec<ResourceRecord>, soa: Option<&Rrset>) -> Self {
        Self {
            rcode: Rcode::NoError,
            authoritative: true,
            answers,
            authorities: negative_soa_records(soa),
            additionals: Vec::new(),
            termination: None,
            nsec3_iterations_exceeded: false,
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
            authorities: negative_soa_records(soa),
            additionals: Vec::new(),
            termination: None,
            nsec3_iterations_exceeded: false,
        }
    }

    pub fn yxdomain_with_answers(answers: Vec<ResourceRecord>, soa: Option<&Rrset>) -> Self {
        Self {
            rcode: Rcode::YxDomain,
            authoritative: true,
            answers,
            authorities: negative_soa_records(soa),
            additionals: Vec::new(),
            termination: None,
            nsec3_iterations_exceeded: false,
        }
    }
}

fn negative_soa_records(soa: Option<&Rrset>) -> Vec<ResourceRecord> {
    soa.map_or_else(Vec::new, |rrset| {
        rrset
            .records()
            .into_iter()
            .map(|mut record| {
                if record.rr_type == RecordType::Soa as u16
                    && let Some(minimum) = soa_minimum(&record.rdata)
                {
                    record.ttl = record.ttl.min(minimum);
                }
                record
            })
            .collect()
    })
}

fn soa_minimum(rdata: &[u8]) -> Option<u32> {
    let (_, consumed_mname) = DomainName::parse(rdata, 0).ok()?;
    let rname_offset = consumed_mname;
    let (_, consumed_rname) = DomainName::parse(rdata, rname_offset).ok()?;
    let minimum_offset = rname_offset + consumed_rname + 16;
    let minimum = rdata.get(minimum_offset..minimum_offset + 4)?;
    Some(u32::from_be_bytes([
        minimum[0], minimum[1], minimum[2], minimum[3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::{ZoneSnapshot, ZoneStore};
    use sha1::{Digest, Sha1};

    include!("dns_tests/support.rs");
    include!("dns_tests/message_parse_notify.rs");
    include!("dns_tests/zone_image_serving.rs");
    include!("dns_tests/wire_names.rs");
    include!("dns_tests/any_negative_dnssec.rs");
    include!("dns_tests/indirection_wildcard_delegation.rs");
    include!("dns_tests/additionals_referrals.rs");
    include!("dns_tests/edns_dnssec_cookie.rs");
}
