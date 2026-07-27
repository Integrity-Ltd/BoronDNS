use borondns_core::{
    dns::{DNS_HEADER_LEN, DomainName, Header, Question, Rcode},
    zone::ResourceRecord,
};
use thiserror::Error;

use crate::scenario::{GeneratedRecord, ScenarioError, ZoneRecordIter};

const RESPONSE_FLAGS_AUTHORITATIVE: u16 = 0x8400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQuery {
    pub id: u16,
    pub qname: DomainName,
    pub qtype: u16,
    pub qclass: u16,
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
    Ok(ParsedQuery {
        id: header.id,
        qname: question.qname,
        qtype: question.qtype,
        qclass: question.qclass,
    })
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

pub struct AxfrMessageStream<'a> {
    query: ParsedQuery,
    records: ZoneRecordIter<'a>,
    max_message_bytes: usize,
    pending: Option<GeneratedRecord>,
    message_index: u64,
    finished: bool,
}

impl<'a> AxfrMessageStream<'a> {
    pub fn new(
        query: ParsedQuery,
        records: ZoneRecordIter<'a>,
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
        axfr::{build_axfr_query, parse_axfr_response},
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
        assert_eq!(snapshot.serial, Some(1));
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
}
