use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::dns::DomainName;

pub const DEFAULT_TSIG_FUDGE_SECS: u16 = 300;
const DNS_HEADER_ARCOUNT_OFFSET: usize = 10;
const DNS_HEADER_ID_OFFSET: usize = 0;
const DNS_HEADER_LEN: usize = 12;
const DNS_CLASS_ANY: u16 = 255;
const TSIG_RR_TYPE: u16 = 250;
const TSIG_TTL: u32 = 0;
const TSIG_ERROR_NOERROR: u16 = 0;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TsigError {
    #[error("TSIG key name must be an absolute DNS name")]
    InvalidKeyName,

    #[error("unsupported TSIG algorithm {0}")]
    UnsupportedAlgorithm(String),

    #[error("TSIG shared secret is not valid base64")]
    InvalidSecret,

    #[error("TSIG shared secret is not usable as an HMAC key")]
    InvalidHmacKey,

    #[error("DNS message is too short to sign with TSIG")]
    MalformedMessage,

    #[error("DNS message additional record count cannot be incremented")]
    AdditionalRecordCountOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigAlgorithm {
    HmacSha256,
}

impl TsigAlgorithm {
    pub fn parse(name: &str) -> Result<Self, TsigError> {
        match canonical_algorithm_name(name).as_str() {
            "hmac-sha256" => Ok(Self::HmacSha256),
            other => Err(TsigError::UnsupportedAlgorithm(other.to_owned())),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha256",
        }
    }

    pub fn mac_len(self) -> usize {
        match self {
            Self::HmacSha256 => 32,
        }
    }
}

pub struct TsigKey {
    pub name: DomainName,
    pub algorithm: TsigAlgorithm,
    secret: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub mac: Vec<u8>,
}

struct TsigRecordFields<'a> {
    time_signed: u64,
    fudge: u16,
    mac: &'a [u8],
    original_id: u16,
    error: u16,
    other_data: &'a [u8],
}

impl fmt::Debug for TsigKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl TsigKey {
    pub fn from_base64(
        name: &str,
        algorithm: &str,
        secret_base64: &str,
    ) -> Result<Self, TsigError> {
        let name = DomainName::from_absolute_str(name).map_err(|_| TsigError::InvalidKeyName)?;
        let algorithm = TsigAlgorithm::parse(algorithm)?;
        let secret = STANDARD
            .decode(secret_base64)
            .map_err(|_| TsigError::InvalidSecret)?;

        Ok(Self {
            name,
            algorithm,
            secret: Zeroizing::new(secret),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TsigError> {
        self.algorithm.sign(&self.secret, message)
    }

    pub fn verify(&self, message: &[u8], mac: &[u8]) -> Result<bool, TsigError> {
        let expected = self.sign(message)?;
        Ok(expected.ct_eq(mac).into())
    }

    pub fn sign_request(
        &self,
        message: &[u8],
        time_signed: u64,
        fudge: u16,
    ) -> Result<SignedMessage, TsigError> {
        sign_request(message, self, time_signed, fudge)
    }
}

pub fn sign_request(
    message: &[u8],
    key: &TsigKey,
    time_signed: u64,
    fudge: u16,
) -> Result<SignedMessage, TsigError> {
    if message.len() < DNS_HEADER_LEN {
        return Err(TsigError::MalformedMessage);
    }

    let original_id = u16::from_be_bytes([
        message[DNS_HEADER_ID_OFFSET],
        message[DNS_HEADER_ID_OFFSET + 1],
    ]);
    let arcount = u16::from_be_bytes([
        message[DNS_HEADER_ARCOUNT_OFFSET],
        message[DNS_HEADER_ARCOUNT_OFFSET + 1],
    ]);
    let signed_arcount = arcount
        .checked_add(1)
        .ok_or(TsigError::AdditionalRecordCountOverflow)?;

    let variables = tsig_variables(key, time_signed, fudge, TSIG_ERROR_NOERROR, &[]);
    let mut mac_input = Vec::with_capacity(message.len() + variables.len());
    mac_input.extend_from_slice(message);
    mac_input.extend_from_slice(&variables);
    let mac = key.sign(&mac_input)?;

    let mut signed_message = Vec::with_capacity(message.len() + tsig_rr_len(key, mac.len()));
    signed_message.extend_from_slice(message);
    signed_message[DNS_HEADER_ARCOUNT_OFFSET..DNS_HEADER_ARCOUNT_OFFSET + 2]
        .copy_from_slice(&signed_arcount.to_be_bytes());
    append_tsig_rr(
        &mut signed_message,
        key,
        TsigRecordFields {
            time_signed,
            fudge,
            mac: &mac,
            original_id,
            error: TSIG_ERROR_NOERROR,
            other_data: &[],
        },
    );

    Ok(SignedMessage {
        message: signed_message,
        mac,
    })
}

impl TsigAlgorithm {
    fn sign(self, secret: &[u8], message: &[u8]) -> Result<Vec<u8>, TsigError> {
        match self {
            Self::HmacSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                    .map_err(|_| TsigError::InvalidHmacKey)?;
                mac.update(message);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }
}

fn canonical_algorithm_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn tsig_variables(
    key: &TsigKey,
    time_signed: u64,
    fudge: u16,
    error: u16,
    other_data: &[u8],
) -> Vec<u8> {
    let mut variables = Vec::new();
    variables.extend_from_slice(&canonical_name_wire(&key.name));
    variables.extend_from_slice(&DNS_CLASS_ANY.to_be_bytes());
    variables.extend_from_slice(&TSIG_TTL.to_be_bytes());
    variables.extend_from_slice(&algorithm_name_wire(key.algorithm));
    append_u48(&mut variables, time_signed);
    variables.extend_from_slice(&fudge.to_be_bytes());
    variables.extend_from_slice(&error.to_be_bytes());
    variables.extend_from_slice(&(other_data.len() as u16).to_be_bytes());
    variables.extend_from_slice(other_data);
    variables
}

fn append_tsig_rr(message: &mut Vec<u8>, key: &TsigKey, fields: TsigRecordFields<'_>) {
    message.extend_from_slice(&canonical_name_wire(&key.name));
    message.extend_from_slice(&TSIG_RR_TYPE.to_be_bytes());
    message.extend_from_slice(&DNS_CLASS_ANY.to_be_bytes());
    message.extend_from_slice(&TSIG_TTL.to_be_bytes());

    let mut rdata = Vec::new();
    rdata.extend_from_slice(&algorithm_name_wire(key.algorithm));
    append_u48(&mut rdata, fields.time_signed);
    rdata.extend_from_slice(&fields.fudge.to_be_bytes());
    rdata.extend_from_slice(&(fields.mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(fields.mac);
    rdata.extend_from_slice(&fields.original_id.to_be_bytes());
    rdata.extend_from_slice(&fields.error.to_be_bytes());
    rdata.extend_from_slice(&(fields.other_data.len() as u16).to_be_bytes());
    rdata.extend_from_slice(fields.other_data);

    message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    message.extend_from_slice(&rdata);
}

fn tsig_rr_len(key: &TsigKey, mac_len: usize) -> usize {
    canonical_name_wire(&key.name).len()
        + 10
        + algorithm_name_wire(key.algorithm).len()
        + 6
        + 2
        + 2
        + mac_len
        + 2
        + 2
        + 2
}

fn algorithm_name_wire(algorithm: TsigAlgorithm) -> Vec<u8> {
    let name = format!("{}.", algorithm.name());
    DomainName::from_absolute_str(&name)
        .expect("TSIG algorithm names are absolute DNS names")
        .to_wire()
}

fn canonical_name_wire(name: &DomainName) -> Vec<u8> {
    DomainName::from_absolute_str(&name.canonical_key())
        .expect("canonical DNS keys are absolute DNS names")
        .to_wire()
}

fn append_u48(out: &mut Vec<u8>, value: u64) {
    let value = value & 0x0000_ffff_ffff_ffff;
    out.extend_from_slice(&((value >> 32) as u16).to_be_bytes());
    out.extend_from_slice(&(value as u32).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hmac_sha256_algorithm_name_case_insensitively() {
        assert_eq!(
            TsigAlgorithm::parse("HMAC-SHA256.").unwrap(),
            TsigAlgorithm::HmacSha256
        );
    }

    #[test]
    fn rejects_hmac_md5_algorithm() {
        let error =
            TsigAlgorithm::parse("hmac-md5.sig-alg.reg.int.").expect_err("MD5 is prohibited");

        assert_eq!(
            error,
            TsigError::UnsupportedAlgorithm("hmac-md5.sig-alg.reg.int".to_owned())
        );
    }

    #[test]
    fn signs_hmac_sha256_rfc4231_case_1() {
        let secret = STANDARD.encode([0x0b; 20]);
        let key = TsigKey::from_base64("transfer.example.", "hmac-sha256", &secret).unwrap();
        let mac = key.sign(b"Hi There").unwrap();

        assert_eq!(
            hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7"
                .replace(char::is_whitespace, "")
        );
        assert!(key.verify(b"Hi There", &mac).unwrap());
        assert!(!key.verify(b"Hi there", &mac).unwrap());
    }

    #[test]
    fn rejects_invalid_secret_base64() {
        let error = TsigKey::from_base64("transfer.example.", "hmac-sha256", "not base64")
            .expect_err("invalid base64");

        assert_eq!(error, TsigError::InvalidSecret);
    }

    #[test]
    fn rejects_relative_key_name() {
        let secret = STANDARD.encode(b"secret");
        let error =
            TsigKey::from_base64("transfer", "hmac-sha256", &secret).expect_err("relative name");

        assert_eq!(error, TsigError::InvalidKeyName);
    }

    #[test]
    fn signs_request_and_appends_tsig_as_last_additional_record() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("Transfer-Key.Example.", "hmac-sha256.", &secret).unwrap();
        let query = sample_soa_query();

        let signed = key
            .sign_request(&query, 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed query");

        assert_eq!(
            u16::from_be_bytes([signed.message[10], signed.message[11]]),
            1
        );
        assert_eq!(signed.mac.len(), key.algorithm.mac_len());
        assert_eq!(&signed.message[..query.len()], {
            let mut expected = query.clone();
            expected[10..12].copy_from_slice(&1u16.to_be_bytes());
            expected
        });

        let mut offset = query.len();
        assert_eq!(
            DomainName::parse(&signed.message, offset).unwrap().0,
            DomainName::from_absolute_str("transfer-key.example.").unwrap()
        );
        offset += DomainName::parse(&signed.message, offset).unwrap().1;
        assert_eq!(
            u16::from_be_bytes([signed.message[offset], signed.message[offset + 1]]),
            250
        );
        assert_eq!(
            u16::from_be_bytes([signed.message[offset + 2], signed.message[offset + 3]]),
            255
        );
        assert_eq!(
            u32::from_be_bytes([
                signed.message[offset + 4],
                signed.message[offset + 5],
                signed.message[offset + 6],
                signed.message[offset + 7],
            ]),
            0
        );
        let rdlen =
            u16::from_be_bytes([signed.message[offset + 8], signed.message[offset + 9]]) as usize;
        offset += 10;
        let rdata_end = offset + rdlen;

        let (algorithm, algorithm_len) = DomainName::parse(&signed.message, offset).unwrap();
        assert_eq!(
            algorithm,
            DomainName::from_absolute_str("hmac-sha256.").unwrap()
        );
        offset += algorithm_len;
        assert_eq!(
            &signed.message[offset..offset + 6],
            &[0, 0, 0x65, 0x53, 0xf1, 0x00]
        );
        offset += 6;
        assert_eq!(
            u16::from_be_bytes([signed.message[offset], signed.message[offset + 1]]),
            DEFAULT_TSIG_FUDGE_SECS
        );
        offset += 2;
        let mac_len =
            u16::from_be_bytes([signed.message[offset], signed.message[offset + 1]]) as usize;
        offset += 2;
        assert_eq!(mac_len, signed.mac.len());
        assert_eq!(&signed.message[offset..offset + mac_len], signed.mac);
        offset += mac_len;
        assert_eq!(
            u16::from_be_bytes([signed.message[offset], signed.message[offset + 1]]),
            0x1234
        );
        offset += 2;
        assert_eq!(
            u16::from_be_bytes([signed.message[offset], signed.message[offset + 1]]),
            0
        );
        offset += 2;
        assert_eq!(
            u16::from_be_bytes([signed.message[offset], signed.message[offset + 1]]),
            0
        );
        offset += 2;
        assert_eq!(offset, rdata_end);
        assert_eq!(offset, signed.message.len());
    }

    #[test]
    fn rejects_signing_short_message() {
        let secret = STANDARD.encode(b"secret");
        let key = TsigKey::from_base64("transfer.example.", "hmac-sha256", &secret).unwrap();

        let error = key
            .sign_request(b"short", 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .expect_err("short message");

        assert_eq!(error, TsigError::MalformedMessage);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn sample_soa_query() -> Vec<u8> {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&apex.to_wire());
        query.extend_from_slice(&6u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }
}
