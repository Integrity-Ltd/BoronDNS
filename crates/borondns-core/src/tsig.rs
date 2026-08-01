use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::dns::DomainName;

// BDS-NFR-MAINT-004 principal functional requirement references for TSIG
// key, MAC, TCP stream, and error-response handling:
// - BDS-FR-TSIG-001 BDS-FR-TSIG-002 BDS-FR-TSIG-003
// - BDS-FR-TSIG-004 BDS-FR-TSIG-005 BDS-FR-TSIG-006
// - BDS-FR-TSIG-007 BDS-FR-TSIG-008 BDS-FR-TSIG-009
// - BDS-FR-TSIG-010 BDS-FR-TSIG-011 BDS-FR-TSIG-012
// - BDS-FR-TSIG-013 BDS-FR-TSIG-014 BDS-FR-TSIG-015
// - BDS-FR-TSIG-016 BDS-FR-TSIG-017
pub const DEFAULT_TSIG_FUDGE_SECS: u16 = 300;
const DNS_HEADER_ARCOUNT_OFFSET: usize = 10;
const DNS_HEADER_ID_OFFSET: usize = 0;
const DNS_HEADER_LEN: usize = 12;
const DNS_CLASS_ANY: u16 = 255;
const TSIG_RR_TYPE: u16 = 250;
const TSIG_TTL: u32 = 0;
const TSIG_ERROR_NOERROR: u16 = 0;
pub const TSIG_ERROR_BADSIG: u16 = 16;
pub const TSIG_ERROR_BADKEY: u16 = 17;
pub const TSIG_ERROR_BADTIME: u16 = 18;
pub const TSIG_ERROR_BADALG: u16 = 21;
pub const TSIG_ERROR_BADTRUNC: u16 = 22;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TsigError {
    #[error("TSIG key name must be an absolute DNS name")]
    InvalidKeyName,

    #[error("unsupported TSIG algorithm {0}")]
    UnsupportedAlgorithm(String),

    #[error("TSIG shared secret is not valid base64")]
    InvalidSecret,

    #[error("TSIG shared secret must not be empty")]
    EmptySecret,

    #[error("TSIG shared secret is not usable as an HMAC key")]
    InvalidHmacKey,

    #[error("DNS message is too short to sign with TSIG")]
    MalformedMessage,

    #[error("DNS message additional record count cannot be incremented")]
    AdditionalRecordCountOverflow,

    #[error("DNS message is missing the expected TSIG record")]
    MissingTsig,

    #[error("DNS TCP response stream did not end with a TSIG record")]
    MissingTerminalTsig,

    #[error("DNS TCP response stream exceeded 99 unsigned messages between TSIG records")]
    TooManyUnsignedMessages,

    #[error("DNS TCP response stream TSIG times moved backwards")]
    NonMonotonicTimeSigned,

    #[error("DNS message TSIG record is not the final additional record")]
    MisplacedTsig,

    #[error("DNS message TSIG record is malformed")]
    MalformedTsig,

    #[error("DNS message TSIG key does not match the expected key")]
    KeyMismatch,

    #[error("DNS message TSIG algorithm does not match the expected key")]
    AlgorithmMismatch,

    #[error("DNS message TSIG MAC verification failed")]
    InvalidMac,

    #[error("DNS message TSIG MAC length is outside the accepted truncation range")]
    BadTrunc,

    #[error("DNS message TSIG time is outside the accepted fudge window")]
    TimeOutsideFudge,

    #[error("DNS message TSIG returned error code {0}")]
    ResponseError(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithm {
    pub fn parse(name: &str) -> Result<Self, TsigError> {
        match canonical_algorithm_name(name).as_str() {
            "hmac-sha1" => Ok(Self::HmacSha1),
            "hmac-sha256" => Ok(Self::HmacSha256),
            "hmac-sha384" => Ok(Self::HmacSha384),
            "hmac-sha512" => Ok(Self::HmacSha512),
            other => Err(TsigError::UnsupportedAlgorithm(other.to_owned())),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::HmacSha1 => "hmac-sha1",
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
        }
    }

    pub fn mac_len(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
        }
    }

    pub fn min_mac_len(self) -> usize {
        self.mac_len() / 2
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMessage {
    pub message: Vec<u8>,
    pub mac: Vec<u8>,
    pub time_signed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigMessageKey {
    pub name: DomainName,
    pub algorithm_name: DomainName,
    pub algorithm: Option<TsigAlgorithm>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigRequestData {
    pub key: TsigMessageKey,
    pub mac: Vec<u8>,
    pub time_signed: u64,
    pub fudge: u16,
    pub original_id: u16,
}

struct TsigRecordFields<'a> {
    time_signed: u64,
    fudge: u16,
    mac: &'a [u8],
    original_id: u16,
    error: u16,
    other_data: &'a [u8],
}

pub struct TsigErrorResponseFields<'a> {
    pub request_mac: &'a [u8],
    pub time_signed: u64,
    pub fudge: u16,
    pub original_id: u16,
    pub error: u16,
    pub other_data: &'a [u8],
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
        if secret.is_empty() {
            return Err(TsigError::EmptySecret);
        }

        Ok(Self {
            name,
            algorithm,
            secret: Zeroizing::new(secret),
        })
    }

    pub fn for_unsigned_error(name: DomainName, algorithm: TsigAlgorithm) -> Self {
        Self {
            name,
            algorithm,
            secret: Zeroizing::new(Vec::new()),
        }
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

    pub fn sign_response(
        &self,
        message: &[u8],
        request_mac: &[u8],
        time_signed: u64,
        fudge: u16,
    ) -> Result<SignedMessage, TsigError> {
        sign_response(message, self, request_mac, time_signed, fudge)
    }

    pub fn verify_response(
        &self,
        message: &[u8],
        request_mac: &[u8],
        now_unix: u64,
    ) -> Result<VerifiedMessage, TsigError> {
        verify_response(message, self, request_mac, now_unix)
    }

    pub fn verify_request(
        &self,
        message: &[u8],
        now_unix: u64,
    ) -> Result<VerifiedMessage, TsigError> {
        verify_request(message, self, now_unix)
    }

    pub fn verify_tcp_response_stream(
        &self,
        messages: &[Vec<u8>],
        request_mac: &[u8],
        now_unix: u64,
    ) -> Result<Vec<Vec<u8>>, TsigError> {
        verify_tcp_response_stream(messages, self, request_mac, now_unix)
    }

    pub fn verify_tcp_response_stream_owned(
        &self,
        messages: Vec<Vec<u8>>,
        request_mac: &[u8],
        now_unix: u64,
    ) -> Result<Vec<Vec<u8>>, TsigError> {
        verify_tcp_response_stream_owned(messages, self, request_mac, now_unix)
    }

    pub fn verify_tcp_response_stream_owned_at_times(
        &self,
        messages: Vec<(Vec<u8>, u64)>,
        request_mac: &[u8],
    ) -> Result<Vec<Vec<u8>>, TsigError> {
        verify_tcp_response_stream_owned_at_times(messages, self, request_mac)
    }

    pub fn sign_tcp_response_continuation(
        &self,
        message: &[u8],
        prior_mac: &[u8],
        time_signed: u64,
        fudge: u16,
    ) -> Result<SignedMessage, TsigError> {
        sign_tcp_response_continuation(message, self, prior_mac, time_signed, fudge)
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

pub fn sign_response(
    message: &[u8],
    key: &TsigKey,
    request_mac: &[u8],
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
    let mut mac_input = response_mac_input(request_mac, message, &variables);
    let mac = key.sign(&mac_input)?;
    mac_input.zeroize();

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

pub fn sign_tcp_response_continuation(
    message: &[u8],
    key: &TsigKey,
    prior_mac: &[u8],
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

    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&(prior_mac.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(prior_mac);
    mac_input.extend_from_slice(message);
    append_u48(&mut mac_input, time_signed);
    mac_input.extend_from_slice(&fudge.to_be_bytes());
    let mac = key.sign(&mac_input)?;
    mac_input.zeroize();

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

pub fn append_unsigned_tsig_error(
    message: &[u8],
    key: &TsigKey,
    time_signed: u64,
    fudge: u16,
    original_id: u16,
    error: u16,
    other_data: &[u8],
) -> Result<Vec<u8>, TsigError> {
    if message.len() < DNS_HEADER_LEN {
        return Err(TsigError::MalformedMessage);
    }

    let arcount = u16::from_be_bytes([
        message[DNS_HEADER_ARCOUNT_OFFSET],
        message[DNS_HEADER_ARCOUNT_OFFSET + 1],
    ]);
    let signed_arcount = arcount
        .checked_add(1)
        .ok_or(TsigError::AdditionalRecordCountOverflow)?;

    let mut signed_message = Vec::with_capacity(message.len() + tsig_rr_len(key, 0));
    signed_message.extend_from_slice(message);
    signed_message[DNS_HEADER_ARCOUNT_OFFSET..DNS_HEADER_ARCOUNT_OFFSET + 2]
        .copy_from_slice(&signed_arcount.to_be_bytes());
    append_tsig_rr(
        &mut signed_message,
        key,
        TsigRecordFields {
            time_signed,
            fudge,
            mac: &[],
            original_id,
            error,
            other_data,
        },
    );

    Ok(signed_message)
}

pub fn append_unsigned_tsig_error_for_message_key(
    message: &[u8],
    key: &TsigMessageKey,
    time_signed: u64,
    fudge: u16,
    original_id: u16,
    error: u16,
    other_data: &[u8],
) -> Result<Vec<u8>, TsigError> {
    if message.len() < DNS_HEADER_LEN {
        return Err(TsigError::MalformedMessage);
    }

    let arcount = u16::from_be_bytes([
        message[DNS_HEADER_ARCOUNT_OFFSET],
        message[DNS_HEADER_ARCOUNT_OFFSET + 1],
    ]);
    let signed_arcount = arcount
        .checked_add(1)
        .ok_or(TsigError::AdditionalRecordCountOverflow)?;

    let mut signed_message = Vec::with_capacity(
        message.len() + tsig_rr_len_for_names(&key.name, &key.algorithm_name, 0),
    );
    signed_message.extend_from_slice(message);
    signed_message[DNS_HEADER_ARCOUNT_OFFSET..DNS_HEADER_ARCOUNT_OFFSET + 2]
        .copy_from_slice(&signed_arcount.to_be_bytes());
    append_tsig_rr_for_names(
        &mut signed_message,
        &key.name,
        &key.algorithm_name,
        TsigRecordFields {
            time_signed,
            fudge,
            mac: &[],
            original_id,
            error,
            other_data,
        },
    );

    Ok(signed_message)
}

pub fn sign_tsig_error_response(
    message: &[u8],
    key: &TsigKey,
    fields: TsigErrorResponseFields<'_>,
) -> Result<SignedMessage, TsigError> {
    if message.len() < DNS_HEADER_LEN {
        return Err(TsigError::MalformedMessage);
    }

    let arcount = u16::from_be_bytes([
        message[DNS_HEADER_ARCOUNT_OFFSET],
        message[DNS_HEADER_ARCOUNT_OFFSET + 1],
    ]);
    let signed_arcount = arcount
        .checked_add(1)
        .ok_or(TsigError::AdditionalRecordCountOverflow)?;

    let variables = tsig_variables(
        key,
        fields.time_signed,
        fields.fudge,
        fields.error,
        fields.other_data,
    );
    let mut mac_input = response_mac_input(fields.request_mac, message, &variables);
    let mac = key.sign(&mac_input)?;
    mac_input.zeroize();

    let mut signed_message = Vec::with_capacity(message.len() + tsig_rr_len(key, mac.len()));
    signed_message.extend_from_slice(message);
    signed_message[DNS_HEADER_ARCOUNT_OFFSET..DNS_HEADER_ARCOUNT_OFFSET + 2]
        .copy_from_slice(&signed_arcount.to_be_bytes());
    append_tsig_rr(
        &mut signed_message,
        key,
        TsigRecordFields {
            time_signed: fields.time_signed,
            fudge: fields.fudge,
            mac: &mac,
            original_id: fields.original_id,
            error: fields.error,
            other_data: fields.other_data,
        },
    );

    Ok(SignedMessage {
        message: signed_message,
        mac,
    })
}

pub fn extract_tsig_mac(message: &[u8]) -> Result<Vec<u8>, TsigError> {
    let (_, tsig) = remove_tsig(message)?;
    Ok(tsig.mac)
}

pub fn verify_response(
    message: &[u8],
    key: &TsigKey,
    request_mac: &[u8],
    now_unix: u64,
) -> Result<VerifiedMessage, TsigError> {
    let (unsigned_message, tsig) = remove_tsig(message)?;
    validate_tsig_identity(key, &tsig)?;
    if is_unsigned_tsig_error(&tsig) {
        return Err(TsigError::ResponseError(tsig.error));
    }
    validate_protocol_mac_length(key.algorithm, &tsig.mac)?;
    let variables = tsig_variables(
        key,
        tsig.time_signed,
        tsig.fudge,
        tsig.error,
        &tsig.other_data,
    );
    let mut mac_input = response_mac_input(request_mac, &unsigned_message, &variables);
    let mac_verification = verify_tsig_mac(key, &mac_input, &tsig.mac);
    mac_input.zeroize();
    mac_verification?;
    if tsig.error != TSIG_ERROR_NOERROR {
        return Err(TsigError::ResponseError(tsig.error));
    }
    validate_tsig_time(tsig.time_signed, tsig.fudge, now_unix)?;

    Ok(VerifiedMessage {
        message: unsigned_message,
        mac: tsig.mac,
        time_signed: tsig.time_signed,
    })
}

fn verify_response_owned(
    message: Vec<u8>,
    key: &TsigKey,
    request_mac: &[u8],
    now_unix: u64,
) -> Result<VerifiedMessage, TsigError> {
    let (unsigned_message, tsig) = remove_tsig_owned(message)?;
    validate_tsig_identity(key, &tsig)?;
    if is_unsigned_tsig_error(&tsig) {
        return Err(TsigError::ResponseError(tsig.error));
    }
    validate_protocol_mac_length(key.algorithm, &tsig.mac)?;
    let variables = tsig_variables(
        key,
        tsig.time_signed,
        tsig.fudge,
        tsig.error,
        &tsig.other_data,
    );
    let mut mac_input = response_mac_input(request_mac, &unsigned_message, &variables);
    let mac_verification = verify_tsig_mac(key, &mac_input, &tsig.mac);
    mac_input.zeroize();
    mac_verification?;
    validate_authenticated_response_error(&tsig)?;
    validate_tsig_time(tsig.time_signed, tsig.fudge, now_unix)?;

    Ok(VerifiedMessage {
        message: unsigned_message,
        mac: tsig.mac,
        time_signed: tsig.time_signed,
    })
}

pub fn verify_request(
    message: &[u8],
    key: &TsigKey,
    now_unix: u64,
) -> Result<VerifiedMessage, TsigError> {
    let (unsigned_message, tsig) = remove_tsig(message)?;
    validate_tsig_identity(key, &tsig)?;
    validate_request_tsig_structure(&tsig)?;
    let variables = tsig_variables(
        key,
        tsig.time_signed,
        tsig.fudge,
        tsig.error,
        &tsig.other_data,
    );
    let mut mac_input = Vec::with_capacity(unsigned_message.len() + variables.len());
    mac_input.extend_from_slice(&unsigned_message);
    mac_input.extend_from_slice(&variables);
    let mac_verification = verify_tsig_mac(key, &mac_input, &tsig.mac);
    mac_input.zeroize();
    mac_verification?;
    validate_tsig_time(tsig.time_signed, tsig.fudge, now_unix)?;

    Ok(VerifiedMessage {
        message: unsigned_message,
        mac: tsig.mac,
        time_signed: tsig.time_signed,
    })
}

pub fn verify_tcp_response_stream(
    messages: &[Vec<u8>],
    key: &TsigKey,
    request_mac: &[u8],
    now_unix: u64,
) -> Result<Vec<Vec<u8>>, TsigError> {
    let Some(first_message) = messages.first() else {
        return Err(TsigError::MissingTsig);
    };

    let first = verify_response(first_message, key, request_mac, now_unix)?;
    let mut unsigned_messages = Vec::with_capacity(messages.len());
    let mut last_time_signed = first.time_signed;
    unsigned_messages.push(first.message);
    let mut prior_mac = first.mac;
    let mut pending_unsigned = Vec::new();
    let mut last_message_had_tsig = true;

    for message in &messages[1..] {
        match remove_tsig(message) {
            Ok((unsigned_message, tsig)) => {
                validate_tsig_identity(key, &tsig)?;
                validate_protocol_mac_length(key.algorithm, &tsig.mac)?;
                pending_unsigned.push(unsigned_message.clone());
                verify_tcp_tsig_mac(key, &prior_mac, &pending_unsigned, &tsig)?;
                if tsig.time_signed < last_time_signed {
                    return Err(TsigError::NonMonotonicTimeSigned);
                }
                validate_authenticated_response_error(&tsig)?;
                validate_tsig_time(tsig.time_signed, tsig.fudge, now_unix)?;
                unsigned_messages.push(unsigned_message);
                last_time_signed = tsig.time_signed;
                prior_mac = tsig.mac;
                pending_unsigned.clear();
                last_message_had_tsig = true;
            }
            Err(TsigError::MissingTsig) => {
                if pending_unsigned.len() >= 99 {
                    return Err(TsigError::TooManyUnsignedMessages);
                }
                pending_unsigned.push(message.clone());
                unsigned_messages.push(message.clone());
                last_message_had_tsig = false;
            }
            Err(error) => return Err(error),
        }
    }

    if !last_message_had_tsig {
        return Err(TsigError::MissingTerminalTsig);
    }

    Ok(unsigned_messages)
}

pub fn verify_tcp_response_stream_owned(
    messages: Vec<Vec<u8>>,
    key: &TsigKey,
    request_mac: &[u8],
    now_unix: u64,
) -> Result<Vec<Vec<u8>>, TsigError> {
    verify_tcp_response_stream_owned_at_times(
        messages
            .into_iter()
            .map(|message| (message, now_unix))
            .collect(),
        key,
        request_mac,
    )
}

pub fn verify_tcp_response_stream_owned_at_times(
    messages: Vec<(Vec<u8>, u64)>,
    key: &TsigKey,
    request_mac: &[u8],
) -> Result<Vec<Vec<u8>>, TsigError> {
    let mut messages = messages.into_iter();
    let (first_message, first_received_at) = messages.next().ok_or(TsigError::MissingTsig)?;
    let first = verify_response_owned(first_message, key, request_mac, first_received_at)?;
    let mut unsigned_messages = Vec::with_capacity(messages.size_hint().0.saturating_add(1));
    let mut last_time_signed = first.time_signed;
    unsigned_messages.push(first.message);
    let mut prior_mac = first.mac;
    let mut pending_start = unsigned_messages.len();
    let mut last_message_had_tsig = true;

    for (message, received_at) in messages {
        if final_tsig_record_view(&message)?.is_some() {
            let (unsigned_message, tsig) = remove_tsig_owned(message)?;
            validate_tsig_identity(key, &tsig)?;
            validate_protocol_mac_length(key.algorithm, &tsig.mac)?;
            verify_tcp_tsig_mac_with_current(
                key,
                &prior_mac,
                &unsigned_messages[pending_start..],
                &unsigned_message,
                &tsig,
            )?;
            if tsig.time_signed < last_time_signed {
                return Err(TsigError::NonMonotonicTimeSigned);
            }
            validate_authenticated_response_error(&tsig)?;
            validate_tsig_time(tsig.time_signed, tsig.fudge, received_at)?;
            unsigned_messages.push(unsigned_message);
            last_time_signed = tsig.time_signed;
            prior_mac = tsig.mac;
            pending_start = unsigned_messages.len();
            last_message_had_tsig = true;
        } else {
            if unsigned_messages.len().saturating_sub(pending_start) >= 99 {
                return Err(TsigError::TooManyUnsignedMessages);
            }
            unsigned_messages.push(message);
            last_message_had_tsig = false;
        }
    }

    if !last_message_had_tsig {
        return Err(TsigError::MissingTerminalTsig);
    }

    Ok(unsigned_messages)
}

pub fn message_has_tsig(message: &[u8]) -> Result<bool, TsigError> {
    match remove_tsig(message) {
        Ok(_) => Ok(true),
        Err(TsigError::MissingTsig) => Ok(false),
        Err(error) => Err(error),
    }
}

pub fn message_tsig_key_name(message: &[u8]) -> Result<Option<DomainName>, TsigError> {
    Ok(message_tsig_key(message)?.map(|key| key.name))
}

pub fn message_tsig_owner_name(message: &[u8]) -> Result<Option<DomainName>, TsigError> {
    match final_tsig_record_view(message)? {
        Some(record) => Ok(Some(record.owner)),
        None => Ok(None),
    }
}

pub fn message_tsig_key(message: &[u8]) -> Result<Option<TsigMessageKey>, TsigError> {
    match remove_tsig(message) {
        Ok((_, tsig)) => {
            validate_request_tsig_structure(&tsig)?;
            Ok(Some(tsig.message_key()))
        }
        Err(TsigError::MissingTsig) => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn message_tsig_request_data(message: &[u8]) -> Result<Option<TsigRequestData>, TsigError> {
    match remove_tsig(message) {
        Ok((_, tsig)) => Ok(Some(TsigRequestData {
            key: tsig.message_key(),
            mac: tsig.mac,
            time_signed: tsig.time_signed,
            fudge: tsig.fudge,
            original_id: tsig.original_id,
        })),
        Err(TsigError::MissingTsig) => Ok(None),
        Err(error) => Err(error),
    }
}

impl TsigAlgorithm {
    fn sign(self, secret: &[u8], message: &[u8]) -> Result<Vec<u8>, TsigError> {
        match self {
            Self::HmacSha1 => {
                let mut mac =
                    Hmac::<Sha1>::new_from_slice(secret).map_err(|_| TsigError::InvalidHmacKey)?;
                mac.update(message);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            Self::HmacSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                    .map_err(|_| TsigError::InvalidHmacKey)?;
                mac.update(message);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            Self::HmacSha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(secret)
                    .map_err(|_| TsigError::InvalidHmacKey)?;
                mac.update(message);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            Self::HmacSha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(secret)
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
    let algorithm_name = DomainName::from_absolute_str(&format!("{}.", key.algorithm.name()))
        .expect("TSIG algorithm names are absolute DNS names");
    append_tsig_rr_for_names(message, &key.name, &algorithm_name, fields);
}

fn append_tsig_rr_for_names(
    message: &mut Vec<u8>,
    key_name: &DomainName,
    algorithm_name: &DomainName,
    fields: TsigRecordFields<'_>,
) {
    message.extend_from_slice(&canonical_name_wire(key_name));
    message.extend_from_slice(&TSIG_RR_TYPE.to_be_bytes());
    message.extend_from_slice(&DNS_CLASS_ANY.to_be_bytes());
    message.extend_from_slice(&TSIG_TTL.to_be_bytes());

    let mut rdata = Vec::new();
    rdata.extend_from_slice(&canonical_name_wire(algorithm_name));
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

#[derive(Debug)]
struct ParsedTsig {
    owner: DomainName,
    algorithm_name: DomainName,
    algorithm: Option<TsigAlgorithm>,
    time_signed: u64,
    fudge: u16,
    mac: Vec<u8>,
    original_id: u16,
    error: u16,
    other_data: Vec<u8>,
}

impl ParsedTsig {
    fn message_key(&self) -> TsigMessageKey {
        TsigMessageKey {
            name: self.owner.clone(),
            algorithm_name: self.algorithm_name.clone(),
            algorithm: self.algorithm,
        }
    }
}

struct RecordView<'a> {
    owner: DomainName,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: &'a [u8],
    start: usize,
    end: usize,
}

fn remove_tsig(message: &[u8]) -> Result<(Vec<u8>, ParsedTsig), TsigError> {
    if message.len() < DNS_HEADER_LEN {
        return Err(TsigError::MalformedMessage);
    }
    let arcount = u16::from_be_bytes([message[10], message[11]]);
    let tsig_view = final_tsig_record_view(message)?.ok_or(TsigError::MissingTsig)?;
    let tsig = parse_tsig_record(&tsig_view)?;
    let mut unsigned = Vec::with_capacity(message.len() - (tsig_view.end - tsig_view.start));
    unsigned.extend_from_slice(&message[..tsig_view.start]);
    unsigned.extend_from_slice(&message[tsig_view.end..]);
    unsigned[DNS_HEADER_ID_OFFSET..DNS_HEADER_ID_OFFSET + 2]
        .copy_from_slice(&tsig.original_id.to_be_bytes());
    unsigned[DNS_HEADER_ARCOUNT_OFFSET..DNS_HEADER_ARCOUNT_OFFSET + 2]
        .copy_from_slice(&(arcount - 1).to_be_bytes());

    Ok((unsigned, tsig))
}

fn remove_tsig_owned(mut message: Vec<u8>) -> Result<(Vec<u8>, ParsedTsig), TsigError> {
    if message.len() < DNS_HEADER_LEN {
        return Err(TsigError::MalformedMessage);
    }
    let arcount = u16::from_be_bytes([message[10], message[11]]);
    let (tsig_start, tsig) = {
        let tsig_view = final_tsig_record_view(&message)?.ok_or(TsigError::MissingTsig)?;
        (tsig_view.start, parse_tsig_record(&tsig_view)?)
    };
    message.truncate(tsig_start);
    message[DNS_HEADER_ID_OFFSET..DNS_HEADER_ID_OFFSET + 2]
        .copy_from_slice(&tsig.original_id.to_be_bytes());
    message[DNS_HEADER_ARCOUNT_OFFSET..DNS_HEADER_ARCOUNT_OFFSET + 2]
        .copy_from_slice(&(arcount - 1).to_be_bytes());
    Ok((message, tsig))
}

fn final_tsig_record_view(message: &[u8]) -> Result<Option<RecordView<'_>>, TsigError> {
    if message.len() < DNS_HEADER_LEN {
        return Err(TsigError::MalformedMessage);
    }

    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    let ancount = u16::from_be_bytes([message[6], message[7]]);
    let nscount = u16::from_be_bytes([message[8], message[9]]);
    let arcount = u16::from_be_bytes([message[10], message[11]]);

    let mut offset = skip_questions(message, qdcount)?;
    for _ in 0..ancount {
        let record = parse_record_view(message, offset)?;
        if record.rr_type == TSIG_RR_TYPE {
            return Err(TsigError::MisplacedTsig);
        }
        offset = record.end;
    }
    for _ in 0..nscount {
        let record = parse_record_view(message, offset)?;
        if record.rr_type == TSIG_RR_TYPE {
            return Err(TsigError::MisplacedTsig);
        }
        offset = record.end;
    }

    let mut tsig_view = None;
    for index in 0..arcount {
        let record = parse_record_view(message, offset)?;
        offset = record.end;
        if record.rr_type == TSIG_RR_TYPE {
            if index + 1 != arcount {
                return Err(TsigError::MisplacedTsig);
            }
            tsig_view = Some(record);
        }
    }
    if offset != message.len() {
        return Err(TsigError::MalformedMessage);
    }

    Ok(tsig_view)
}

fn parse_tsig_record(record: &RecordView<'_>) -> Result<ParsedTsig, TsigError> {
    if record.class != DNS_CLASS_ANY || record.ttl != TSIG_TTL {
        return Err(TsigError::MalformedTsig);
    }

    let rdata = record.rdata;
    let (algorithm_name, consumed) =
        DomainName::parse(rdata, 0).map_err(|_| TsigError::MalformedTsig)?;
    let algorithm = TsigAlgorithm::parse(&algorithm_name.canonical_key()).ok();
    let mut offset = consumed;
    if offset + 6 + 2 + 2 > rdata.len() {
        return Err(TsigError::MalformedTsig);
    }

    let time_signed = u48_from_wire(&rdata[offset..offset + 6]);
    offset += 6;
    let fudge = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
    offset += 2;
    let mac_len = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]) as usize;
    offset += 2;
    if offset + mac_len + 2 + 2 + 2 > rdata.len() {
        return Err(TsigError::MalformedTsig);
    }

    let mac = rdata[offset..offset + mac_len].to_vec();
    offset += mac_len;
    let original_id = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
    offset += 2;
    let error = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
    offset += 2;
    let other_len = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]) as usize;
    offset += 2;
    if offset + other_len != rdata.len() {
        return Err(TsigError::MalformedTsig);
    }
    let other_data = rdata[offset..offset + other_len].to_vec();

    Ok(ParsedTsig {
        owner: record.owner.clone(),
        algorithm_name,
        algorithm,
        time_signed,
        fudge,
        mac,
        original_id,
        error,
        other_data,
    })
}

fn validate_tsig_identity(key: &TsigKey, tsig: &ParsedTsig) -> Result<(), TsigError> {
    if tsig.owner.canonical_key() != key.name.canonical_key() {
        return Err(TsigError::KeyMismatch);
    }
    if tsig.algorithm != Some(key.algorithm) {
        return Err(TsigError::AlgorithmMismatch);
    }
    Ok(())
}

fn validate_request_tsig_structure(tsig: &ParsedTsig) -> Result<(), TsigError> {
    if tsig.error != TSIG_ERROR_NOERROR {
        return Err(TsigError::MalformedTsig);
    }
    if let Some(algorithm) = tsig.algorithm {
        validate_protocol_mac_length(algorithm, &tsig.mac)?;
    }
    Ok(())
}

fn validate_protocol_mac_length(
    algorithm: TsigAlgorithm,
    received_mac: &[u8],
) -> Result<(), TsigError> {
    if received_mac.len() < algorithm.min_mac_len() || received_mac.len() > algorithm.mac_len() {
        return Err(TsigError::MalformedTsig);
    }
    Ok(())
}

fn is_unsigned_tsig_error(tsig: &ParsedTsig) -> bool {
    tsig.mac.is_empty()
        && matches!(tsig.error, TSIG_ERROR_BADKEY | TSIG_ERROR_BADSIG)
        && tsig.other_data.is_empty()
}

fn validate_authenticated_response_error(tsig: &ParsedTsig) -> Result<(), TsigError> {
    if tsig.error != TSIG_ERROR_NOERROR {
        return Err(TsigError::ResponseError(tsig.error));
    }
    Ok(())
}

fn validate_tsig_time(time_signed: u64, fudge: u16, now_unix: u64) -> Result<(), TsigError> {
    if now_unix.saturating_add(fudge as u64) < time_signed
        || time_signed.saturating_add(fudge as u64) < now_unix
    {
        return Err(TsigError::TimeOutsideFudge);
    }
    Ok(())
}

fn verify_tcp_tsig_mac(
    key: &TsigKey,
    prior_mac: &[u8],
    messages_since_tsig: &[Vec<u8>],
    tsig: &ParsedTsig,
) -> Result<(), TsigError> {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&(prior_mac.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(prior_mac);
    for message in messages_since_tsig {
        mac_input.extend_from_slice(message);
    }
    append_u48(&mut mac_input, tsig.time_signed);
    mac_input.extend_from_slice(&tsig.fudge.to_be_bytes());

    let mac_verification = verify_tsig_mac(key, &mac_input, &tsig.mac);
    mac_input.zeroize();
    mac_verification
}

fn verify_tcp_tsig_mac_with_current(
    key: &TsigKey,
    prior_mac: &[u8],
    messages_since_tsig: &[Vec<u8>],
    current_message: &[u8],
    tsig: &ParsedTsig,
) -> Result<(), TsigError> {
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&(prior_mac.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(prior_mac);
    for message in messages_since_tsig {
        mac_input.extend_from_slice(message);
    }
    mac_input.extend_from_slice(current_message);
    append_u48(&mut mac_input, tsig.time_signed);
    mac_input.extend_from_slice(&tsig.fudge.to_be_bytes());

    let mac_verification = verify_tsig_mac(key, &mac_input, &tsig.mac);
    mac_input.zeroize();
    mac_verification
}

fn verify_tsig_mac(key: &TsigKey, mac_input: &[u8], received_mac: &[u8]) -> Result<(), TsigError> {
    let expected_mac = key.sign(mac_input)?;
    if !bool::from(expected_mac[..received_mac.len()].ct_eq(received_mac)) {
        return Err(TsigError::InvalidMac);
    }
    Ok(())
}

fn response_mac_input(request_mac: &[u8], message: &[u8], variables: &[u8]) -> Vec<u8> {
    let mut mac_input = Vec::with_capacity(2 + request_mac.len() + message.len() + variables.len());
    mac_input.extend_from_slice(&(request_mac.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(request_mac);
    mac_input.extend_from_slice(message);
    mac_input.extend_from_slice(variables);
    mac_input
}

fn skip_questions(message: &[u8], qdcount: u16) -> Result<usize, TsigError> {
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..qdcount {
        let (_, consumed) =
            DomainName::parse(message, offset).map_err(|_| TsigError::MalformedMessage)?;
        offset += consumed;
        if offset + 4 > message.len() {
            return Err(TsigError::MalformedMessage);
        }
        offset += 4;
    }
    Ok(offset)
}

fn parse_record_view(message: &[u8], offset: usize) -> Result<RecordView<'_>, TsigError> {
    let start = offset;
    let (owner, consumed) =
        DomainName::parse(message, offset).map_err(|_| TsigError::MalformedMessage)?;
    let mut offset = offset + consumed;
    if offset + 10 > message.len() {
        return Err(TsigError::MalformedMessage);
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
        return Err(TsigError::MalformedMessage);
    }
    let rdata = &message[offset..offset + rdlength];
    offset += rdlength;

    Ok(RecordView {
        owner,
        rr_type,
        class,
        ttl,
        rdata,
        start,
        end: offset,
    })
}

fn tsig_rr_len(key: &TsigKey, mac_len: usize) -> usize {
    let algorithm_name = DomainName::from_absolute_str(&format!("{}.", key.algorithm.name()))
        .expect("TSIG algorithm names are absolute DNS names");
    tsig_rr_len_for_names(&key.name, &algorithm_name, mac_len)
}

fn tsig_rr_len_for_names(
    key_name: &DomainName,
    algorithm_name: &DomainName,
    mac_len: usize,
) -> usize {
    canonical_name_wire(key_name).len()
        + 10
        + canonical_name_wire(algorithm_name).len()
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
    name.to_ascii_lowercased().to_wire()
}

fn append_u48(out: &mut Vec<u8>, value: u64) {
    let value = value & 0x0000_ffff_ffff_ffff;
    out.extend_from_slice(&((value >> 32) as u16).to_be_bytes());
    out.extend_from_slice(&(value as u32).to_be_bytes());
}

fn u48_from_wire(bytes: &[u8]) -> u64 {
    ((u16::from_be_bytes([bytes[0], bytes[1]]) as u64) << 32)
        | u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as u64
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
    fn parses_hmac_sha1_algorithm_name_case_insensitively() {
        assert_eq!(
            TsigAlgorithm::parse("HMAC-SHA1.").unwrap(),
            TsigAlgorithm::HmacSha1
        );
        assert_eq!(TsigAlgorithm::HmacSha1.name(), "hmac-sha1");
        assert_eq!(TsigAlgorithm::HmacSha1.mac_len(), 20);
    }

    #[test]
    fn parses_hmac_sha384_and_sha512_algorithm_names_case_insensitively() {
        assert_eq!(
            TsigAlgorithm::parse("HMAC-SHA384.").unwrap(),
            TsigAlgorithm::HmacSha384
        );
        assert_eq!(
            TsigAlgorithm::parse("HMAC-SHA512.").unwrap(),
            TsigAlgorithm::HmacSha512
        );
        assert_eq!(TsigAlgorithm::HmacSha384.name(), "hmac-sha384");
        assert_eq!(TsigAlgorithm::HmacSha384.mac_len(), 48);
        assert_eq!(TsigAlgorithm::HmacSha512.name(), "hmac-sha512");
        assert_eq!(TsigAlgorithm::HmacSha512.mac_len(), 64);
    }

    #[test]
    fn canonical_name_wire_preserves_non_ascii_label_octets() {
        let (name, consumed) = DomainName::parse(b"\x02A\xc3\x00", 0).unwrap();

        assert_eq!(consumed, 4);
        assert_eq!(canonical_name_wire(&name), b"\x02a\xc3\x00");
    }

    #[test]
    fn algorithm_minimum_tsig_mac_lengths_are_half_digest_lengths() {
        assert_eq!(TsigAlgorithm::HmacSha1.min_mac_len(), 10);
        assert_eq!(TsigAlgorithm::HmacSha256.min_mac_len(), 16);
        assert_eq!(TsigAlgorithm::HmacSha384.min_mac_len(), 24);
        assert_eq!(TsigAlgorithm::HmacSha512.min_mac_len(), 32);
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
    fn signs_hmac_sha1_rfc2202_case_1() {
        let secret = STANDARD.encode([0x0b; 20]);
        let key = TsigKey::from_base64("transfer.example.", "hmac-sha1", &secret).unwrap();
        let mac = key.sign(b"Hi There").unwrap();

        assert_eq!(hex(&mac), "b617318655057264e28bc0b6fb378c8ef146be00");
        assert!(key.verify(b"Hi There", &mac).unwrap());
        assert!(!key.verify(b"Hi there", &mac).unwrap());
    }

    #[test]
    fn signs_hmac_sha384_rfc4231_case_1() {
        let secret = STANDARD.encode([0x0b; 20]);
        let key = TsigKey::from_base64("transfer.example.", "hmac-sha384", &secret).unwrap();
        let mac = key.sign(b"Hi There").unwrap();

        assert_eq!(
            hex(&mac),
            "afd03944d84895626b0825f4ab46907f\
             15f9dadbe4101ec682aa034c7cebc59c\
             faea9ea9076ede7f4af152e8b2fa9cb6"
                .replace(char::is_whitespace, "")
        );
        assert!(key.verify(b"Hi There", &mac).unwrap());
        assert!(!key.verify(b"Hi there", &mac).unwrap());
    }

    #[test]
    fn signs_hmac_sha512_rfc4231_case_1() {
        let secret = STANDARD.encode([0x0b; 20]);
        let key = TsigKey::from_base64("transfer.example.", "hmac-sha512", &secret).unwrap();
        let mac = key.sign(b"Hi There").unwrap();

        assert_eq!(
            hex(&mac),
            "87aa7cdea5ef619d4ff0b4241a1d6cb0\
             2379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4\
             be9d914eeb61f1702e696c203a126854"
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
    fn rejects_empty_decoded_secret() {
        let error = TsigKey::from_base64("transfer.example.", "hmac-sha256", "")
            .expect_err("empty decoded TSIG secret");

        assert_eq!(error, TsigError::EmptySecret);
    }

    #[test]
    fn accepts_padded_and_rejects_unpadded_secret_base64() {
        TsigKey::from_base64("transfer.example.", "hmac-sha256", "YQ==")
            .expect("canonical padded Base64");
        let error = TsigKey::from_base64("transfer.example.", "hmac-sha256", "YQ")
            .expect_err("unpadded Base64");
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
    fn verifies_request_and_returns_unsigned_message() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let query = sample_soa_query();
        let signed = key
            .sign_request(&query, 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed request");

        let verified = key
            .verify_request(&signed.message, 1_700_000_000)
            .expect("verified request");

        assert_eq!(verified.message, query);
        assert_eq!(verified.mac, signed.mac);
    }

    #[test]
    fn verifies_request_with_authenticated_opaque_other_data() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let query = sample_soa_query();
        let time_signed = 1_700_000_000;
        let fudge = DEFAULT_TSIG_FUDGE_SECS;
        let other_data = b"opaque-request-data";
        let variables = tsig_variables(&key, time_signed, fudge, TSIG_ERROR_NOERROR, other_data);
        let mut mac_input = query.clone();
        mac_input.extend_from_slice(&variables);
        let mac = key.sign(&mac_input).unwrap();
        let mut signed = query.clone();
        signed[10..12].copy_from_slice(&1u16.to_be_bytes());
        append_tsig_rr(
            &mut signed,
            &key,
            TsigRecordFields {
                time_signed,
                fudge,
                mac: &mac,
                original_id: 0x1234,
                error: TSIG_ERROR_NOERROR,
                other_data,
            },
        );

        let verified = key
            .verify_request(&signed, time_signed)
            .expect("request Other Data is opaque but authenticated");

        assert_eq!(verified.message, query);
        assert_eq!(verified.mac, mac);
    }

    #[test]
    fn verifies_request_with_minimum_truncated_tsig_mac() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let query = sample_soa_query();
        let signed = key
            .sign_request(&query, 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed request");
        let truncated_mac = &signed.mac[..key.algorithm.min_mac_len()];
        let truncated_message = replace_tsig_mac(&signed.message, &key, truncated_mac);

        let verified = key
            .verify_request(&truncated_message, 1_700_000_000)
            .expect("verified request with truncated TSIG MAC");

        assert_eq!(verified.message, query);
        assert_eq!(verified.mac, truncated_mac);
    }

    #[test]
    fn verifies_response_with_minimum_truncated_tsig_mac() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let response = sample_soa_response();
        let signed_response = key
            .sign_response(
                &response,
                &request.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .expect("signed response");
        let truncated_mac = &signed_response.mac[..key.algorithm.min_mac_len()];
        let truncated_message = replace_tsig_mac(&signed_response.message, &key, truncated_mac);

        let verified = key
            .verify_response(&truncated_message, &request.mac, 1_700_000_001)
            .expect("verified response with truncated TSIG MAC");

        assert_eq!(verified.message, response);
        assert_eq!(verified.mac, truncated_mac);
    }

    #[test]
    fn rejects_request_with_invalid_mac() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let mut signed = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed request");
        let unsigned_len = sample_soa_query().len();
        signed.message[unsigned_len - 1] ^= 0x01;

        let error = key
            .verify_request(&signed.message, 1_700_000_000)
            .expect_err("tampered request");

        assert_eq!(error, TsigError::InvalidMac);
    }

    #[test]
    fn rejects_request_invalid_mac_before_time_window() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let mut signed = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed request");
        let unsigned_len = sample_soa_query().len();
        signed.message[unsigned_len - 1] ^= 0x01;

        let error = key
            .verify_request(&signed.message, 1_700_001_000)
            .expect_err("tampered and expired request");

        assert_eq!(error, TsigError::InvalidMac);
    }

    #[test]
    fn rejects_request_with_structurally_invalid_short_tsig_mac() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let signed = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed request");
        let too_short_mac = &signed.mac[..key.algorithm.min_mac_len() - 1];
        let too_short_message = replace_tsig_mac(&signed.message, &key, too_short_mac);

        let error = key
            .verify_request(&too_short_message, 1_700_000_000)
            .expect_err("too-short TSIG MAC");

        assert_eq!(error, TsigError::MalformedTsig);
    }

    #[test]
    fn rejects_request_with_overlong_tsig_mac() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let signed = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed request");
        let mut overlong_mac = signed.mac.clone();
        overlong_mac.push(0);
        let overlong_message = replace_tsig_mac(&signed.message, &key, &overlong_mac);

        let error = key
            .verify_request(&overlong_message, 1_700_000_000)
            .expect_err("overlong TSIG MAC");

        assert_eq!(error, TsigError::MalformedTsig);
    }

    #[test]
    fn rejects_nonzero_request_tsig_error_as_malformed() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let signed = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .expect("signed request");
        let malformed = replace_tsig_error(&signed.message, &key, TSIG_ERROR_BADTIME);

        let error = key
            .verify_request(&malformed, 1_700_000_000)
            .expect_err("a request TSIG Error field must be zero");

        assert_eq!(error, TsigError::MalformedTsig);
    }

    #[test]
    fn verifies_response_and_returns_unsigned_message() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let response = sample_soa_response();
        let signed_response = key
            .sign_response(
                &response,
                &request.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .expect("signed response");

        let verified = key
            .verify_response(&signed_response.message, &request.mac, 1_700_000_001)
            .expect("verified response");

        assert_eq!(verified.message, response);
        assert_eq!(verified.mac, signed_response.mac);
    }

    #[test]
    fn verifies_tcp_response_stream_with_unsigned_intermediary_message() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let first_message = sample_response_with_id_and_serial(0x1234, 1);
        let unsigned_middle = sample_response_with_id_and_serial(0x1234, 2);
        let final_message = sample_response_with_id_and_serial(0x1234, 3);
        let first = key
            .sign_response(
                &first_message,
                &request.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();

        let mut continuation_input = Vec::new();
        continuation_input.extend_from_slice(&(first.mac.len() as u16).to_be_bytes());
        continuation_input.extend_from_slice(&first.mac);
        continuation_input.extend_from_slice(&unsigned_middle);
        continuation_input.extend_from_slice(&final_message);
        append_u48(&mut continuation_input, 1_700_000_002);
        continuation_input.extend_from_slice(&DEFAULT_TSIG_FUDGE_SECS.to_be_bytes());
        let expected_final_mac = key.sign(&continuation_input).unwrap();

        let final_signed = signed_tcp_response_for_messages(
            &key,
            &first.mac,
            &[unsigned_middle.clone(), final_message.clone()],
            1_700_000_002,
            DEFAULT_TSIG_FUDGE_SECS,
        )
        .unwrap();
        assert_eq!(final_signed.mac, expected_final_mac);

        let stream = vec![first.message, unsigned_middle.clone(), final_signed.message];
        let verified = key
            .verify_tcp_response_stream(&stream, &request.mac, 1_700_000_002)
            .expect("verified TCP response stream");
        let verified_owned = key
            .verify_tcp_response_stream_owned(stream, &request.mac, 1_700_000_002)
            .expect("verified owned TCP response stream");

        assert_eq!(
            verified,
            vec![first_message, unsigned_middle, final_message]
        );
        assert_eq!(verified_owned, verified);
    }

    #[test]
    fn verifies_long_tcp_response_stream_against_each_message_receipt_time() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let first_time = 1_700_000_000;
        let fudge = 5;
        let final_time = first_time + u64::from(fudge) + 1;
        let request = key
            .sign_request(&sample_soa_query(), first_time, fudge)
            .unwrap();
        let first_message = sample_response_with_id_and_serial(0x1234, 1);
        let unsigned_middle = sample_response_with_id_and_serial(0x1234, 2);
        let final_message = sample_response_with_id_and_serial(0x1234, 3);
        let first = key
            .sign_response(&first_message, &request.mac, first_time, fudge)
            .unwrap();
        let final_signed = signed_tcp_response_for_messages(
            &key,
            &first.mac,
            &[unsigned_middle.clone(), final_message.clone()],
            final_time,
            fudge,
        )
        .unwrap();
        let stream = vec![first.message, unsigned_middle.clone(), final_signed.message];

        assert_eq!(
            key.verify_tcp_response_stream_owned(stream.clone(), &request.mac, final_time)
                .expect_err("completion-time validation makes the first response appear stale"),
            TsigError::TimeOutsideFudge
        );

        let verified = key
            .verify_tcp_response_stream_owned_at_times(
                vec![
                    (stream[0].clone(), first_time),
                    (stream[1].clone(), first_time + 1),
                    (stream[2].clone(), final_time),
                ],
                &request.mac,
            )
            .expect("each signed response is fresh when it is received");
        assert_eq!(
            verified,
            vec![first_message, unsigned_middle, final_message]
        );
    }

    #[test]
    fn accepts_tcp_response_stream_with_ninety_nine_unsigned_message_gap() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let first_message = sample_response_with_id_and_serial(0x1234, 1);
        let first = key
            .sign_response(
                &first_message,
                &request.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        let unsigned_messages = (2..=100)
            .map(|serial| sample_response_with_id_and_serial(0x1234, serial))
            .collect::<Vec<_>>();
        let final_message = sample_response_with_id_and_serial(0x1234, 101);
        let mut signed_window = unsigned_messages.clone();
        signed_window.push(final_message.clone());
        let final_signed = signed_tcp_response_for_messages(
            &key,
            &first.mac,
            &signed_window,
            1_700_000_002,
            DEFAULT_TSIG_FUDGE_SECS,
        )
        .unwrap();

        let mut stream = Vec::new();
        stream.push(first.message);
        stream.extend(unsigned_messages.clone());
        stream.push(final_signed.message);
        let verified = key
            .verify_tcp_response_stream(&stream, &request.mac, 1_700_000_002)
            .expect("99 unsigned messages between TSIG records are allowed");

        let mut expected = Vec::new();
        expected.push(first_message);
        expected.extend(unsigned_messages);
        expected.push(final_message);
        assert_eq!(verified, expected);
    }

    #[test]
    fn rejects_tcp_response_stream_with_one_hundred_unsigned_message_gap() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let first = key
            .sign_response(
                &sample_response_with_id_and_serial(0x1234, 1),
                &request.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        let unsigned_messages = (2..=101)
            .map(|serial| sample_response_with_id_and_serial(0x1234, serial))
            .collect::<Vec<_>>();
        let final_message = sample_response_with_id_and_serial(0x1234, 102);
        let mut signed_window = unsigned_messages.clone();
        signed_window.push(final_message);
        let final_signed = signed_tcp_response_for_messages(
            &key,
            &first.mac,
            &signed_window,
            1_700_000_002,
            DEFAULT_TSIG_FUDGE_SECS,
        )
        .unwrap();

        let mut stream = Vec::new();
        stream.push(first.message);
        stream.extend(unsigned_messages);
        stream.push(final_signed.message);
        let error = key
            .verify_tcp_response_stream(&stream, &request.mac, 1_700_000_002)
            .expect_err("100 unsigned messages between TSIG records must fail");

        assert_eq!(error, TsigError::TooManyUnsignedMessages);
    }

    #[test]
    fn rejects_tcp_response_stream_without_terminal_tsig() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let first = key
            .sign_response(
                &sample_response_with_id_and_serial(0x1234, 1),
                &request.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        let final_unsigned = sample_response_with_id_and_serial(0x1234, 2);

        let error = key
            .verify_tcp_response_stream(
                &[first.message, final_unsigned],
                &request.mac,
                1_700_000_002,
            )
            .expect_err("missing terminal TSIG");

        assert_eq!(error, TsigError::MissingTerminalTsig);
    }

    #[test]
    fn rejects_tsig_in_answer_even_with_valid_final_tsig() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let source = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let source_tsig = final_tsig_record_view(&source.message)
            .unwrap()
            .expect("source TSIG");
        let mut malformed = sample_soa_query();
        malformed[6..8].copy_from_slice(&1u16.to_be_bytes());
        malformed.extend_from_slice(&source.message[source_tsig.start..source_tsig.end]);
        let signed = key
            .sign_request(&malformed, 1_700_000_001, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();

        let error = key
            .verify_request(&signed.message, 1_700_000_001)
            .expect_err("TSIG outside Additional must be rejected");

        assert_eq!(error, TsigError::MisplacedTsig);
    }

    #[test]
    fn rejects_tsig_in_authority_without_final_tsig_as_misplaced() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let source = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let source_tsig = final_tsig_record_view(&source.message)
            .unwrap()
            .expect("source TSIG");
        let mut malformed = sample_soa_query();
        malformed[8..10].copy_from_slice(&1u16.to_be_bytes());
        malformed.extend_from_slice(&source.message[source_tsig.start..source_tsig.end]);

        let error = key
            .verify_request(&malformed, 1_700_000_000)
            .expect_err("authority TSIG must be classified as misplaced");

        assert_eq!(error, TsigError::MisplacedTsig);
    }

    #[test]
    fn rejects_tcp_response_stream_when_tsig_time_moves_backwards() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let first = key
            .sign_response(
                &sample_response_with_id_and_serial(0x1234, 1),
                &request.mac,
                1_700_000_002,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        let final_signed = key
            .sign_tcp_response_continuation(
                &sample_response_with_id_and_serial(0x1234, 2),
                &first.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();

        let error = key
            .verify_tcp_response_stream(
                &[first.message, final_signed.message],
                &request.mac,
                1_700_000_002,
            )
            .expect_err("backwards TSIG time");

        assert_eq!(error, TsigError::NonMonotonicTimeSigned);
    }

    #[test]
    fn rejects_tcp_continuation_invalid_mac_before_monotonic_time_check() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let first = key
            .sign_response(
                &sample_response_with_id_and_serial(0x1234, 1),
                &request.mac,
                1_700_000_002,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        let final_message = sample_response_with_id_and_serial(0x1234, 2);
        let mut final_signed = key
            .sign_tcp_response_continuation(
                &final_message,
                &first.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        final_signed.message[final_message.len() - 1] ^= 0x01;
        let messages = vec![first.message, final_signed.message];

        let borrowed_error = key
            .verify_tcp_response_stream(&messages, &request.mac, 1_700_000_002)
            .expect_err("unauthenticated backwards time must not be trusted");
        let owned_error = key
            .verify_tcp_response_stream_owned(messages, &request.mac, 1_700_000_002)
            .expect_err("owned verifier must authenticate before checking time order");

        assert_eq!(borrowed_error, TsigError::InvalidMac);
        assert_eq!(owned_error, TsigError::InvalidMac);
    }

    #[test]
    fn rejects_tcp_continuation_invalid_mac_before_time_window() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let first = key
            .sign_response(
                &sample_response_with_id_and_serial(0x1234, 1),
                &request.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        let final_message = sample_response_with_id_and_serial(0x1234, 2);
        let mut final_signed = key
            .sign_tcp_response_continuation(
                &final_message,
                &first.mac,
                1_700_001_000,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .unwrap();
        final_signed.message[final_message.len() - 1] ^= 0x01;

        let error = key
            .verify_tcp_response_stream(
                &[first.message, final_signed.message],
                &request.mac,
                1_700_000_002,
            )
            .expect_err("tampered and expired TCP continuation");

        assert_eq!(error, TsigError::InvalidMac);
    }

    #[test]
    fn rejects_response_with_invalid_mac() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let mut signed_response = key
            .sign_response(
                &sample_soa_response(),
                &request.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .expect("signed response");
        let unsigned_len = sample_soa_response().len();
        signed_response.message[unsigned_len - 1] ^= 0x01;

        let error = key
            .verify_response(&signed_response.message, &request.mac, 1_700_000_001)
            .expect_err("tampered response");

        assert_eq!(error, TsigError::InvalidMac);
    }

    #[test]
    fn rejects_response_invalid_mac_before_time_window() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let mut signed_response = key
            .sign_response(
                &sample_soa_response(),
                &request.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .expect("signed response");
        let unsigned_len = sample_soa_response().len();
        signed_response.message[unsigned_len - 1] ^= 0x01;

        let error = key
            .verify_response(&signed_response.message, &request.mac, 1_700_001_000)
            .expect_err("tampered and expired response");

        assert_eq!(error, TsigError::InvalidMac);
    }

    #[test]
    fn authenticates_signed_tsig_error_before_returning_response_error() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let server_time = 1_700_001_000u64;
        let other_data = server_time.to_be_bytes()[2..].to_vec();
        let mut signed_error = sign_tsig_error_response(
            &sample_soa_response(),
            &key,
            TsigErrorResponseFields {
                request_mac: &request.mac,
                time_signed: 1_700_000_000,
                fudge: DEFAULT_TSIG_FUDGE_SECS,
                original_id: 0x1234,
                error: TSIG_ERROR_BADTIME,
                other_data: &other_data,
            },
        )
        .expect("signed BADTIME response");
        let unsigned_len = sample_soa_response().len();
        signed_error.message[unsigned_len - 1] ^= 0x01;

        let error = key
            .verify_response(&signed_error.message, &request.mac, server_time)
            .expect_err("tampered signed error response");

        assert_eq!(error, TsigError::InvalidMac);
    }

    #[test]
    fn returns_authenticated_badtime_without_applying_normal_response_time_check() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let server_time = 1_700_001_000u64;
        let other_data = server_time.to_be_bytes()[2..].to_vec();
        let signed_error = sign_tsig_error_response(
            &sample_soa_response(),
            &key,
            TsigErrorResponseFields {
                request_mac: &request.mac,
                time_signed: 1,
                fudge: DEFAULT_TSIG_FUDGE_SECS,
                original_id: 0x1234,
                error: TSIG_ERROR_BADTIME,
                other_data: &other_data,
            },
        )
        .expect("signed BADTIME response");

        let error = key
            .verify_response(&signed_error.message, &request.mac, server_time)
            .expect_err("authenticated BADTIME response");

        assert_eq!(error, TsigError::ResponseError(TSIG_ERROR_BADTIME));
    }

    #[test]
    fn rejects_response_outside_tsig_fudge_window() {
        let secret = STANDARD.encode(b"topsecret");
        let key = TsigKey::from_base64("transfer-key.example.", "hmac-sha256.", &secret).unwrap();
        let request = key
            .sign_request(&sample_soa_query(), 1_700_000_000, DEFAULT_TSIG_FUDGE_SECS)
            .unwrap();
        let signed_response = key
            .sign_response(
                &sample_soa_response(),
                &request.mac,
                1_700_000_001,
                DEFAULT_TSIG_FUDGE_SECS,
            )
            .expect("signed response");

        let error = key
            .verify_response(&signed_response.message, &request.mac, 1_700_001_000)
            .expect_err("expired response");

        assert_eq!(error, TsigError::TimeOutsideFudge);
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

    fn sample_soa_response() -> Vec<u8> {
        sample_response_with_id_and_serial(0x1234, 1)
    }

    fn sample_response_with_id_and_serial(qid: u16, serial: u32) -> Vec<u8> {
        let apex = DomainName::from_absolute_str("example.test.").unwrap();
        let mut rdata = Vec::new();
        rdata.extend_from_slice(
            &DomainName::from_absolute_str("ns1.example.test.")
                .unwrap()
                .to_wire(),
        );
        rdata.extend_from_slice(
            &DomainName::from_absolute_str("hostmaster.example.test.")
                .unwrap()
                .to_wire(),
        );
        rdata.extend_from_slice(&serial.to_be_bytes());
        rdata.extend_from_slice(&3600u32.to_be_bytes());
        rdata.extend_from_slice(&600u32.to_be_bytes());
        rdata.extend_from_slice(&604800u32.to_be_bytes());
        rdata.extend_from_slice(&300u32.to_be_bytes());

        let mut response = Vec::new();
        response.extend_from_slice(&qid.to_be_bytes());
        response.extend_from_slice(&0x8000u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&apex.to_wire());
        response.extend_from_slice(&6u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&apex.to_wire());
        response.extend_from_slice(&6u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&3600u32.to_be_bytes());
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);
        response
    }

    fn replace_tsig_mac(message: &[u8], key: &TsigKey, replacement_mac: &[u8]) -> Vec<u8> {
        let (mut unsigned, tsig) = remove_tsig(message).expect("message has TSIG");
        let arcount = u16::from_be_bytes([unsigned[10], unsigned[11]]);
        unsigned[10..12].copy_from_slice(&(arcount + 1).to_be_bytes());
        append_tsig_rr(
            &mut unsigned,
            key,
            TsigRecordFields {
                time_signed: tsig.time_signed,
                fudge: tsig.fudge,
                mac: replacement_mac,
                original_id: tsig.original_id,
                error: tsig.error,
                other_data: &tsig.other_data,
            },
        );
        unsigned
    }

    fn replace_tsig_error(message: &[u8], key: &TsigKey, replacement_error: u16) -> Vec<u8> {
        let (mut unsigned, tsig) = remove_tsig(message).expect("message has TSIG");
        let arcount = u16::from_be_bytes([unsigned[10], unsigned[11]]);
        unsigned[10..12].copy_from_slice(&(arcount + 1).to_be_bytes());
        append_tsig_rr(
            &mut unsigned,
            key,
            TsigRecordFields {
                time_signed: tsig.time_signed,
                fudge: tsig.fudge,
                mac: &tsig.mac,
                original_id: tsig.original_id,
                error: replacement_error,
                other_data: &tsig.other_data,
            },
        );
        unsigned
    }

    fn signed_tcp_response_for_messages(
        key: &TsigKey,
        prior_mac: &[u8],
        messages_since_tsig: &[Vec<u8>],
        time_signed: u64,
        fudge: u16,
    ) -> Result<SignedMessage, TsigError> {
        let Some(final_message) = messages_since_tsig.last() else {
            return Err(TsigError::MalformedMessage);
        };
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&(prior_mac.len() as u16).to_be_bytes());
        mac_input.extend_from_slice(prior_mac);
        for message in messages_since_tsig {
            mac_input.extend_from_slice(message);
        }
        append_u48(&mut mac_input, time_signed);
        mac_input.extend_from_slice(&fudge.to_be_bytes());
        let mac = key.sign(&mac_input)?;

        let original_id = u16::from_be_bytes([final_message[0], final_message[1]]);
        let arcount = u16::from_be_bytes([final_message[10], final_message[11]]);
        let mut signed_message = final_message.clone();
        signed_message[10..12].copy_from_slice(&(arcount + 1).to_be_bytes());
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
}
