use borondns_core::{
    dns::{DNS_HEADER_LEN, DomainName, Header, Question, Rcode, RecordType},
    zone::ResourceRecord,
};
use thiserror::Error;

use crate::scenario::{GeneratedRecord, IxfrRecordIter, ScenarioError, ZoneRecordIter};

const RESPONSE_FLAGS_AUTHORITATIVE: u16 = 0x8400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQuery {
    pub id: u16,
    pub qname: DomainName,
    pub qtype: u16,
    pub qclass: u16,
    pub ixfr_serial: Option<u32>,
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("malformed DNS query")]
    MalformedQuery,
    #[error("DNS query is not a standard single-question request")]
    UnsupportedQuery,
    #[error("configured DNS message target {0} is outside 512..=64000")]
    InvalidMessageBytes(usize),
    #[error(
        "generated record of {record_bytes} bytes cannot fit in a {message_bytes}-byte DNS message"
    )]
    RecordTooLarge {
        record_bytes: usize,
        message_bytes: usize,
    },
    #[error("unable to allocate bounded {bytes}-byte DNS output buffer")]
    Allocation { bytes: usize },
    #[error(transparent)]
    Scenario(#[from] ScenarioError),
}

pub fn parse_query(message: &[u8]) -> Result<ParsedQuery, WireError> {
    let header = Header::parse(message).map_err(|_| WireError::MalformedQuery)?;
    if header.is_response()
        || header.opcode_value() != 0
        || header.qdcount != 1
        || message.len() < DNS_HEADER_LEN
    {
        return Err(WireError::UnsupportedQuery);
    }
    let question = Question::parse(message).map_err(|_| WireError::MalformedQuery)?;
    let ixfr_serial = if question.qtype == RecordType::Ixfr as u16 {
        Some(parse_ixfr_authority_serial(message, &header, &question)?)
    } else {
        None
    };
    Ok(ParsedQuery {
        id: header.id,
        qname: question.qname,
        qtype: question.qtype,
        qclass: question.qclass,
        ixfr_serial,
    })
}

fn parse_ixfr_authority_serial(
    message: &[u8],
    header: &Header,
    question: &Question,
) -> Result<u32, WireError> {
    if header.ancount != 0 || header.nscount != 1 {
        return Err(WireError::UnsupportedQuery);
    }
    let (_, qname_len) =
        DomainName::parse(message, DNS_HEADER_LEN).map_err(|_| WireError::MalformedQuery)?;
    let mut offset = DNS_HEADER_LEN
        .checked_add(qname_len)
        .and_then(|value| value.checked_add(4))
        .ok_or(WireError::MalformedQuery)?;
    let (owner, owner_len) =
        DomainName::parse(message, offset).map_err(|_| WireError::MalformedQuery)?;
    offset = offset
        .checked_add(owner_len)
        .ok_or(WireError::MalformedQuery)?;
    let fixed = message
        .get(offset..offset + 10)
        .ok_or(WireError::MalformedQuery)?;
    let rr_type = u16::from_be_bytes([fixed[0], fixed[1]]);
    let class = u16::from_be_bytes([fixed[2], fixed[3]]);
    let rdlength = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
    if owner != question.qname || rr_type != RecordType::Soa as u16 || class != question.qclass {
        return Err(WireError::UnsupportedQuery);
    }
    let rdata_start = offset + 10;
    let rdata_end = rdata_start
        .checked_add(rdlength)
        .filter(|end| *end <= message.len())
        .ok_or(WireError::MalformedQuery)?;
    let (_, mname_len) =
        DomainName::parse(message, rdata_start).map_err(|_| WireError::MalformedQuery)?;
    let rname_start = rdata_start
        .checked_add(mname_len)
        .ok_or(WireError::MalformedQuery)?;
    let (_, rname_len) =
        DomainName::parse(message, rname_start).map_err(|_| WireError::MalformedQuery)?;
    let serial_start = rname_start
        .checked_add(rname_len)
        .ok_or(WireError::MalformedQuery)?;
    if serial_start.checked_add(20) != Some(rdata_end) {
        return Err(WireError::MalformedQuery);
    }
    let serial = message
        .get(serial_start..serial_start + 4)
        .ok_or(WireError::MalformedQuery)?;
    Ok(u32::from_be_bytes([
        serial[0], serial[1], serial[2], serial[3],
    ]))
}

pub fn single_answer_response(
    query: &ParsedQuery,
    answer: Option<&GeneratedRecord>,
    rcode: Rcode,
) -> Result<Vec<u8>, WireError> {
    let mut message = response_prefix(query, true, usize::from(answer.is_some()))?;
    if let Some(answer) = answer {
        append_record(&mut message, answer)?;
    }
    let flags = RESPONSE_FLAGS_AUTHORITATIVE | (rcode as u16 & 0x000f);
    message[2..4].copy_from_slice(&flags.to_be_bytes());
    Ok(message)
}

pub type AxfrMessageStream<'a> = GeneratedMessageStream<ZoneRecordIter<'a>>;
pub type IxfrMessageStream<'a> = GeneratedMessageStream<IxfrRecordIter<'a>>;

pub struct GeneratedMessageStream<I> {
    query: ParsedQuery,
    records: I,
    max_message_bytes: usize,
    pending: Option<GeneratedRecord>,
    message_index: u64,
    finished: bool,
}

impl<I> GeneratedMessageStream<I>
where
    I: Iterator<Item = Result<GeneratedRecord, ScenarioError>>,
{
    pub fn new(
        query: ParsedQuery,
        records: I,
        max_message_bytes: usize,
    ) -> Result<Self, WireError> {
        if !(512..=64_000).contains(&max_message_bytes) {
            return Err(WireError::InvalidMessageBytes(max_message_bytes));
        }
        Ok(Self {
            query,
            records,
            max_message_bytes,
            pending: None,
            message_index: 0,
            finished: false,
        })
    }

    pub fn next_message(&mut self) -> Option<Result<Vec<u8>, WireError>> {
        if self.finished {
            return None;
        }

        let include_question = self.message_index == 0;
        let mut message = match response_prefix(&self.query, include_question, 0) {
            Ok(message) => message,
            Err(error) => return Some(Err(error)),
        };
        if message
            .try_reserve(self.max_message_bytes.saturating_sub(message.len()))
            .is_err()
        {
            return Some(Err(WireError::Allocation {
                bytes: self.max_message_bytes,
            }));
        }

        let mut answers = 0u16;
        loop {
            let next_record = if let Some(record) = self.pending.take() {
                Some(Ok(record))
            } else {
                self.records.next()
            };
            let Some(next_record) = next_record else {
                self.finished = true;
                break;
            };
            let record = match next_record {
                Ok(record) => record,
                Err(error) => return Some(Err(error.into())),
            };
            let record_len = record.wire_len();
            if message.len().saturating_add(record_len) > self.max_message_bytes
                || answers == u16::MAX
            {
                if answers == 0 {
                    return Some(Err(WireError::RecordTooLarge {
                        record_bytes: record_len,
                        message_bytes: self.max_message_bytes,
                    }));
                }
                self.pending = Some(record);
                break;
            }
            if let Err(error) = append_record(&mut message, &record) {
                return Some(Err(error));
            }
            answers += 1;
        }

        if answers == 0 {
            self.finished = true;
            return None;
        }
        message[6..8].copy_from_slice(&answers.to_be_bytes());
        self.message_index += 1;
        Some(Ok(message))
    }
}

fn response_prefix(
    query: &ParsedQuery,
    include_question: bool,
    answers: usize,
) -> Result<Vec<u8>, WireError> {
    let qname_wire = query.qname.to_wire();
    let capacity = DNS_HEADER_LEN
        .saturating_add(if include_question {
            qname_wire.len() + 4
        } else {
            0
        })
        .saturating_add(answers.saturating_mul(32));
    let mut message = Vec::new();
    message
        .try_reserve_exact(capacity)
        .map_err(|_| WireError::Allocation { bytes: capacity })?;
    message.extend_from_slice(&query.id.to_be_bytes());
    message.extend_from_slice(&RESPONSE_FLAGS_AUTHORITATIVE.to_be_bytes());
    message.extend_from_slice(&u16::from(include_question).to_be_bytes());
    message.extend_from_slice(&(answers as u16).to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    if include_question {
        message.extend_from_slice(&qname_wire);
        message.extend_from_slice(&query.qtype.to_be_bytes());
        message.extend_from_slice(&query.qclass.to_be_bytes());
    }
    Ok(message)
}

fn append_record(message: &mut Vec<u8>, record: &GeneratedRecord) -> Result<(), WireError> {
    let record_len = record.wire_len();
    message
        .try_reserve(record_len)
        .map_err(|_| WireError::Allocation { bytes: record_len })?;
    message.extend_from_slice(&record.owner.to_wire());
    message.extend_from_slice(&record.rr_type.to_be_bytes());
    message.extend_from_slice(&record.class.to_be_bytes());
    message.extend_from_slice(&record.ttl.to_be_bytes());
    let rdlength = u16::try_from(record.rdata.len()).map_err(|_| ScenarioError::RdataTooLong)?;
    message.extend_from_slice(&rdlength.to_be_bytes());
    message.extend_from_slice(&record.rdata);
    Ok(())
}

impl From<&GeneratedRecord> for ResourceRecord {
    fn from(record: &GeneratedRecord) -> Self {
        Self {
            owner: record.owner.clone(),
            rr_type: record.rr_type,
            class: record.class,
            ttl: record.ttl,
            rdata: record.rdata.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use borondns_core::{
        axfr::{
            IxfrResponse, build_axfr_query, build_ixfr_query_from_soa_view, parse_axfr_response,
            parse_ixfr_response,
        },
        dns::Header,
    };

    use super::*;
    use crate::scenario::{ContentProfile, Scenario, ScenarioConfig, ZoneKind};

    #[test]
    fn bounded_axfr_messages_parse_through_the_production_parser() {
        let scenario = Scenario::new(ScenarioConfig {
            profile: ContentProfile::RegistryNsec3,
            names_per_zone: 41,
            nsec3_records_per_zone: 37,
            ..ScenarioConfig::default()
        })
        .unwrap();
        let origin = scenario.zone_origin(0).unwrap();
        let query_wire = build_axfr_query(0x4242, &origin, 1);
        let query = parse_query(&query_wire).unwrap();
        let records = scenario.records(ZoneKind::Member(0)).unwrap();
        let mut stream = AxfrMessageStream::new(query, records, 1_200).unwrap();
        let messages = std::iter::from_fn(|| stream.next_message())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(messages.len() > 1);
        assert!(messages.iter().all(|message| message.len() <= 1_200));
        assert_eq!(Header::parse(&messages[0]).unwrap().qdcount, 1);
        assert!(
            messages[1..]
                .iter()
                .all(|message| Header::parse(message).unwrap().qdcount == 0)
        );

        let snapshot = parse_axfr_response(0x4242, &origin, 1, &messages).unwrap();
        assert_eq!(snapshot.serial(), Some(1));
    }

    #[test]
    fn record_larger_than_the_message_target_fails_without_unbounded_growth() {
        let scenario = Scenario::new(ScenarioConfig {
            profile: ContentProfile::Mixed,
            names_per_zone: 1,
            txt_rdata_bytes: 2_000,
            structural_rrsigs: false,
            ..ScenarioConfig::default()
        })
        .unwrap();
        let origin = scenario.zone_origin(0).unwrap();
        let query = parse_query(&build_axfr_query(1, &origin, 1)).unwrap();
        let mut stream =
            AxfrMessageStream::new(query, scenario.records(ZoneKind::Member(0)).unwrap(), 512)
                .unwrap();
        let error = std::iter::from_fn(|| stream.next_message())
            .find_map(Result::err)
            .expect("oversized TXT record");
        assert!(matches!(error, WireError::RecordTooLarge { .. }));
    }

    #[test]
    fn on_the_fly_multi_generation_ixfr_round_trips_through_production_parser() {
        let scenario = Scenario::new(ScenarioConfig {
            profile: ContentProfile::Mixed,
            names_per_zone: 17,
            records_per_name: 2,
            structural_rrsigs: false,
            serial: 3,
            ixfr_delta_rrsets: 5,
            ..ScenarioConfig::default()
        })
        .unwrap();
        let origin = scenario.zone_origin(0).unwrap();
        let axfr_query = parse_query(&build_axfr_query(0x6161, &origin, 1)).unwrap();
        let mut axfr = AxfrMessageStream::new(
            axfr_query,
            scenario.records_at_serial(ZoneKind::Member(0), 1).unwrap(),
            1_200,
        )
        .unwrap();
        let axfr_messages = std::iter::from_fn(|| axfr.next_message())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let base = parse_axfr_response(0x6161, &origin, 1, &axfr_messages).unwrap();
        assert_eq!(base.serial(), Some(1));

        let ixfr_query_wire =
            build_ixfr_query_from_soa_view(0x6262, &origin, 1, base.soa_record_view(1).unwrap())
                .unwrap();
        let ixfr_query = parse_query(&ixfr_query_wire).unwrap();
        assert_eq!(ixfr_query.ixfr_serial, Some(1));
        let mut ixfr = IxfrMessageStream::new(
            ixfr_query,
            scenario.ixfr_records(ZoneKind::Member(0), 1, 3).unwrap(),
            900,
        )
        .unwrap();
        let ixfr_messages = std::iter::from_fn(|| ixfr.next_message())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let response = parse_ixfr_response(0x6262, &origin, 1, &base, &ixfr_messages).unwrap();
        let IxfrResponse::Updated(updated) = response else {
            panic!("expected generated IXFR update")
        };
        assert_eq!(updated.serial(), Some(3));
        assert_eq!(updated.rdata_record_count(), base.rdata_record_count());
    }
}
