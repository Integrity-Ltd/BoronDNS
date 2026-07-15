use std::net::SocketAddr;

use borondns_core::{
    axfr::{self, AxfrError},
    tsig::TsigError,
};
use thiserror::Error;

use crate::privilege;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("failed to bind UDP listener {addr}: {source}")]
    BindUdp {
        addr: std::net::SocketAddr,
        source: std::io::Error,
    },

    #[error("failed to bind TCP listener {addr}: {source}")]
    BindTcp {
        addr: std::net::SocketAddr,
        source: std::io::Error,
    },

    #[error("failed to bind health listener {addr}: {source}")]
    BindHealth {
        addr: std::net::SocketAddr,
        source: std::io::Error,
    },

    #[error("UDP listener failed: {0}")]
    Udp(std::io::Error),

    #[error("UDP backend {backend} is not available: {reason}")]
    UdpBackendUnavailable {
        backend: &'static str,
        reason: &'static str,
    },

    #[error("TCP listener failed: {0}")]
    Tcp(std::io::Error),

    #[error("health listener failed: {0}")]
    Health(std::io::Error),

    #[error("shutdown signal failed: {0}")]
    ShutdownSignal(std::io::Error),

    #[error("{task_set} task panicked or was cancelled unexpectedly: {message}")]
    RuntimeTask {
        task_set: &'static str,
        message: String,
    },

    #[error("invalid runtime configuration: {0}")]
    InvalidRuntimeConfig(String),

    #[error("failed to generate DNS Cookie server secret: {0}")]
    DnsCookieSecret(getrandom::Error),

    #[error("failed to randomize primary rotation: {0}")]
    PrimaryRotationRandom(getrandom::Error),

    #[error(
        "file-descriptor rlimit is insufficient for configured connection limits: current {current}, required {required}; increase the supervisor or container nofile limit, for example docker run --ulimit nofile=65536:65536"
    )]
    InsufficientFileDescriptorLimit { current: u64, required: u64 },

    #[error("failed to inspect file-descriptor rlimit: {0}")]
    FileDescriptorLimit(std::io::Error),

    #[error("failed to apply process hardening: {0}")]
    ProcessHardening(std::io::Error),

    #[error("{0}")]
    PrivilegeDrop(String),
}

impl From<privilege::PrivilegeError> for RuntimeError {
    fn from(error: privilege::PrivilegeError) -> Self {
        Self::PrivilegeDrop(error.to_string())
    }
}

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("failed to bind outbound UDP socket for primary {addr}: {source}")]
    BindUdp {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("failed to connect to TCP primary {addr}: {source}")]
    ConnectTcp {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("failed to bind outbound TCP socket {source_addr} for primary {addr}: {source}")]
    BindTcp {
        addr: SocketAddr,
        source_addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("DNS transfer I/O with primary {addr} failed: {source}")]
    Io {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("AXFR session timed out after {timeout_secs} seconds")]
    Timeout { timeout_secs: u64 },

    #[error("AXFR response validation failed: {0}")]
    Axfr(#[from] AxfrError),

    #[error("IXFR response validation failed: {0}")]
    Ixfr(#[from] axfr::IxfrError),

    #[error("SOA poll response validation failed: {0}")]
    Soa(#[from] axfr::SoaQueryError),

    #[error("failed to generate random DNS query ID: {0}")]
    RandomQueryId(getrandom::Error),

    #[error("failed to sign transfer query with TSIG: {0}")]
    Tsig(#[from] TsigError),

    #[error("configured TSIG key {key_name} is not loaded in the current secret snapshot")]
    MissingTsigKey { key_name: String },

    #[error("XoT TLS configuration for primary {addr} is invalid: {message}")]
    XotConfig { addr: SocketAddr, message: String },

    #[error("failed to read XoT TLS file {path}: {source}")]
    ReadTlsFile {
        path: String,
        source: std::io::Error,
    },

    #[error("failed XoT TLS handshake with primary {addr}: {source}")]
    TlsHandshake {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("XoT primary {addr} did not negotiate ALPN dot")]
    XotAlpn { addr: SocketAddr },

    #[error(
        "{protocol} session from primary {addr} exceeded configured ingestion size cap at {received_bytes} octets (limit {limit_bytes})"
    )]
    IngestSizeLimit {
        protocol: &'static str,
        addr: SocketAddr,
        received_bytes: u64,
        limit_bytes: u64,
    },

    #[error(
        "{protocol} session from primary {addr} could not reserve {requested_bytes} octets from the global transfer ingestion budget ({in_flight_bytes} octets already in flight, limit {limit_bytes})"
    )]
    IngestGlobalSizeLimit {
        protocol: &'static str,
        addr: SocketAddr,
        requested_bytes: u64,
        in_flight_bytes: u64,
        limit_bytes: u64,
    },

    #[error(
        "{protocol} session from primary {addr} exceeded configured ingestion message cap at {received_messages} messages (limit {limit_messages})"
    )]
    IngestMessageLimit {
        protocol: &'static str,
        addr: SocketAddr,
        received_messages: u64,
        limit_messages: u64,
    },
}
