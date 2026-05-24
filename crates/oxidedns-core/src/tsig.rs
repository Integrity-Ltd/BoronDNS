use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::dns::DomainName;

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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
