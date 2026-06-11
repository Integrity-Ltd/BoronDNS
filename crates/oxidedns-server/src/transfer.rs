use std::{
    future::Future,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use oxidedns_core::{
    axfr::{self, AxfrError, IxfrResponse},
    config::{TransferPrimaryConfig, TransferTransportConfig},
    dns::DomainName,
    tsig::{DEFAULT_TSIG_FUDGE_SECS, TsigError, TsigKey},
    zone::ZoneSnapshot,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket},
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
        version,
    },
};
use tracing::{info, warn};

use crate::TransferError;

pub async fn transfer_axfr_from_primary(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    timeout_duration: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    transfer_axfr_from_primary_with_tsig(
        primary,
        zone_apex,
        qclass,
        qid,
        TransferSession::default_unsigned(),
        timeout_duration,
    )
    .await
}

async fn transfer_axfr_from_primary_with_tsig(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    session: TransferSession<'_>,
    timeout_duration: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    let target = TransferPrimaryConfig::tcp(primary);
    transfer_axfr_from_target_with_tsig(&target, zone_apex, qclass, qid, session, timeout_duration)
        .await
}

pub(crate) async fn transfer_axfr_from_target_with_tsig(
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    session: TransferSession<'_>,
    timeout_duration: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    transfer_axfr_from_target_with_tsig_and_source(
        primary,
        zone_apex,
        qclass,
        qid,
        session,
        None,
        timeout_duration,
        timeout_duration,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn transfer_axfr_from_target_with_tsig_and_source(
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    session: TransferSession<'_>,
    transfer_source: Option<SocketAddr>,
    timeout_duration: Duration,
    connect_timeout: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    let session = session.with_transfer_source(transfer_source);
    tokio::time::timeout(timeout_duration, async {
        transfer_axfr_from_primary_inner(primary, zone_apex, qclass, qid, session, connect_timeout)
            .await
    })
    .await
    .map_err(|_| TransferError::Timeout {
        timeout_secs: timeout_duration.as_secs(),
    })?
}

pub async fn poll_soa_from_primary(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    timeout_duration: Duration,
) -> Result<u32, TransferError> {
    poll_soa_from_primary_with_tsig(
        primary,
        zone_apex,
        qclass,
        qid,
        TransferTsig::unsigned(),
        timeout_duration,
    )
    .await
}

pub(crate) async fn poll_soa_from_primary_with_tsig(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    tsig: TransferTsig<'_>,
    timeout_duration: Duration,
) -> Result<u32, TransferError> {
    poll_soa_from_primary_with_tsig_and_source(
        primary,
        zone_apex,
        qclass,
        qid,
        tsig,
        None,
        timeout_duration,
    )
    .await
}

pub(crate) async fn poll_soa_from_primary_with_tsig_and_source(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    tsig: TransferTsig<'_>,
    transfer_source: Option<SocketAddr>,
    timeout_duration: Duration,
) -> Result<u32, TransferError> {
    tokio::time::timeout(timeout_duration, async {
        poll_soa_from_primary_inner(primary, zone_apex, qclass, qid, tsig, transfer_source).await
    })
    .await
    .map_err(|_| TransferError::Timeout {
        timeout_secs: timeout_duration.as_secs(),
    })?
}

async fn poll_soa_from_primary_inner(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    tsig: TransferTsig<'_>,
    transfer_source: Option<SocketAddr>,
) -> Result<u32, TransferError> {
    let socket = UdpSocket::bind(outbound_udp_bind_addr(primary, transfer_source))
        .await
        .map_err(|source| TransferError::BindUdp {
            addr: primary,
            source,
        })?;
    socket
        .connect(primary)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary,
            source,
        })?;

    let query = maybe_sign_transfer_query(axfr::build_soa_query(qid, zone_apex, qclass), tsig)?;
    socket
        .send(&query.message)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary,
            source,
        })?;

    let mut buffer = vec![0u8; 512];
    let len = socket
        .recv(&mut buffer)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary,
            source,
        })?;

    let response =
        maybe_verify_transfer_response(&buffer[..len], tsig.key, query.request_mac.as_deref())?;
    match axfr::parse_soa_response(qid, zone_apex, qclass, &response) {
        Ok(serial) => Ok(serial),
        Err(error) => {
            warn!(
                zone = %zone_apex,
                %primary,
                qid,
                %error,
                "SOA poll response rejected"
            );
            Err(TransferError::Soa(error))
        }
    }
}

enum TransferStream {
    Tcp(TcpStream),
    Xot(XotTransferStream),
}

struct XotTransferStream {
    stream: Box<TlsStream<TcpStream>>,
    session: XotSessionLog,
}

struct XotSessionLog {
    addr: SocketAddr,
    sni: String,
    started_at: Instant,
    bytes_in: u64,
    bytes_out: u64,
}

impl TransferStream {
    async fn write_all(&mut self, buffer: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(buffer).await,
            Self::Xot(stream) => stream.write_all(buffer).await,
        }
    }

    async fn read_exact(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read_exact(buffer).await,
            Self::Xot(stream) => stream.read_exact(buffer).await,
        }
    }
}

impl XotTransferStream {
    fn new(stream: TlsStream<TcpStream>, addr: SocketAddr, sni: String) -> Self {
        Self {
            stream: Box::new(stream),
            session: XotSessionLog {
                addr,
                sni,
                started_at: Instant::now(),
                bytes_in: 0,
                bytes_out: 0,
            },
        }
    }

    async fn write_all(&mut self, buffer: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(buffer).await?;
        self.session.bytes_out = self.session.bytes_out.saturating_add(buffer.len() as u64);
        Ok(())
    }

    async fn read_exact(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.stream.read_exact(buffer).await?;
        self.session.bytes_in = self.session.bytes_in.saturating_add(read as u64);
        Ok(read)
    }
}

impl Drop for XotSessionLog {
    fn drop(&mut self) {
        let duration_ms = duration_millis_u64(self.started_at.elapsed());
        let bytes = self.bytes_in.saturating_add(self.bytes_out);
        info!(
            category = "xot",
            event = "xot_tls_session_closed",
            primary = %self.addr,
            peer_ip = %self.addr.ip(),
            sni = %self.sni,
            duration_ms,
            bytes,
            bytes_in = self.bytes_in,
            bytes_out = self.bytes_out,
            "XoT TLS session closed"
        );
    }
}

async fn connect_tcp_stream(
    primary: SocketAddr,
    transfer_source: Option<SocketAddr>,
    connect_timeout: Duration,
) -> Result<TcpStream, TransferError> {
    let socket = match primary {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|source| TransferError::ConnectTcp {
        addr: primary,
        source,
    })?;

    if let Some(source_addr) =
        transfer_source.filter(|source| source.is_ipv4() == primary.is_ipv4())
    {
        socket
            .bind(source_addr)
            .map_err(|source| TransferError::BindTcp {
                addr: primary,
                source_addr,
                source,
            })?;
    }

    tcp_connect_with_timeout(primary, connect_timeout, socket.connect(primary)).await
}

pub(crate) async fn tcp_connect_with_timeout<T, F>(
    primary: SocketAddr,
    connect_timeout: Duration,
    connect: F,
) -> Result<T, TransferError>
where
    F: Future<Output = std::io::Result<T>>,
{
    tokio::time::timeout(connect_timeout, connect)
        .await
        .map_err(|_| TransferError::Timeout {
            timeout_secs: connect_timeout.as_secs(),
        })?
        .map_err(|source| TransferError::ConnectTcp {
            addr: primary,
            source,
        })
}

async fn connect_transfer_stream(
    primary: &TransferPrimaryConfig,
    transfer_source: Option<SocketAddr>,
    connect_timeout: Duration,
) -> Result<TransferStream, TransferError> {
    match primary.transport {
        TransferTransportConfig::Tcp => {
            let tcp = connect_tcp_stream(primary.addr, transfer_source, connect_timeout).await?;
            Ok(TransferStream::Tcp(tcp))
        }
        TransferTransportConfig::Xot => {
            connect_xot_stream(primary, transfer_source, connect_timeout).await
        }
    }
}

async fn connect_xot_stream(
    primary: &TransferPrimaryConfig,
    transfer_source: Option<SocketAddr>,
    connect_timeout: Duration,
) -> Result<TransferStream, TransferError> {
    let sni = primary
        .server_name
        .as_deref()
        .ok_or_else(|| TransferError::XotConfig {
            addr: primary.addr,
            message: "missing server_name".to_owned(),
        })?
        .to_owned();
    let server_name =
        ServerName::try_from(sni.clone()).map_err(|error| TransferError::XotConfig {
            addr: primary.addr,
            message: format!("invalid server_name {sni:?}: {error}"),
        })?;

    let mut client_config = build_xot_client_config(primary)?;
    client_config.alpn_protocols = vec![b"dot".to_vec()];
    let tcp = connect_tcp_stream(primary.addr, transfer_source, connect_timeout).await?;
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = match connector.connect(server_name, tcp).await {
        Ok(stream) => stream,
        Err(source) => {
            warn!(
                category = "xot",
                event = "xot_tls_handshake_failed",
                primary = %primary.addr,
                peer_ip = %primary.addr.ip(),
                sni = %sni,
                error = %source,
                "XoT TLS handshake failed"
            );
            return Err(TransferError::TlsHandshake {
                addr: primary.addr,
                source,
            });
        }
    };
    if stream.get_ref().1.alpn_protocol() != Some(b"dot".as_slice()) {
        warn!(
            category = "xot",
            event = "xot_alpn_negotiation_failed",
            primary = %primary.addr,
            peer_ip = %primary.addr.ip(),
            sni = %sni,
            error = "missing negotiated dot ALPN",
            "XoT ALPN negotiation failed"
        );
        return Err(TransferError::XotAlpn { addr: primary.addr });
    }
    let tls_version = stream
        .get_ref()
        .1
        .protocol_version()
        .map(|version| format!("{version:?}"))
        .unwrap_or_else(|| "unknown".to_owned());
    let cipher_suite = stream
        .get_ref()
        .1
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_else(|| "unknown".to_owned());
    info!(
        category = "xot",
        event = "xot_tls_session_established",
        primary = %primary.addr,
        peer_ip = %primary.addr.ip(),
        sni = %sni,
        tls_version = %tls_version,
        cipher_suite = %cipher_suite,
        "XoT TLS session established"
    );
    Ok(TransferStream::Xot(XotTransferStream::new(
        stream,
        primary.addr,
        sni,
    )))
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub(crate) fn build_xot_client_config(
    primary: &TransferPrimaryConfig,
) -> Result<ClientConfig, TransferError> {
    let mut roots = RootCertStore::empty();
    for trust_anchor in &primary.trust_anchors {
        let certs = load_pem_certs_for_primary(primary.addr, trust_anchor)?;
        if certs.is_empty() {
            return Err(TransferError::XotConfig {
                addr: primary.addr,
                message: format!("trust anchor file {trust_anchor:?} did not contain certificates"),
            });
        }
        for cert in certs {
            roots.add(cert).map_err(|error| TransferError::XotConfig {
                addr: primary.addr,
                message: format!("failed to add trust anchor {trust_anchor:?}: {error}"),
            })?;
        }
    }
    if roots.is_empty() {
        return Err(TransferError::XotConfig {
            addr: primary.addr,
            message: "at least one trust anchor is required".to_owned(),
        });
    }

    let builder = ClientConfig::builder_with_protocol_versions(&[&version::TLS13])
        .with_root_certificates(roots);
    match (
        &primary.client_cert,
        &primary.client_key,
        &primary.client_key_pem,
    ) {
        (Some(cert_path), Some(key_path), None) => {
            validate_private_key_file_mode(primary.addr, key_path)?;
            let certs = load_pem_certs(cert_path)?;
            let key = load_pem_private_key_from_file(primary.addr, key_path)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|error| TransferError::XotConfig {
                    addr: primary.addr,
                    message: format!("invalid XoT client certificate/key pair: {error}"),
                })
        }
        (Some(cert_path), None, Some(key_pem)) => {
            let certs = load_pem_certs(cert_path)?;
            let key = load_pem_private_key_from_inline(primary.addr, key_pem)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|error| TransferError::XotConfig {
                    addr: primary.addr,
                    message: format!("invalid XoT client certificate/key pair: {error}"),
                })
        }
        (None, None, None) => Ok(builder.with_no_client_auth()),
        _ => Err(TransferError::XotConfig {
            addr: primary.addr,
            message: "client_cert and exactly one of client_key or client_key_pem must be configured together".to_owned(),
        }),
    }
}

pub(crate) fn load_pem_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TransferError> {
    let pem = std::fs::read(path).map_err(|source| TransferError::ReadTlsFile {
        path: path.to_owned(),
        source,
    })?;
    CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TransferError::XotConfig {
            addr: "0.0.0.0:0"
                .parse()
                .expect("hard-coded placeholder socket address is valid"),
            message: format!("failed to parse certificate PEM file {path:?}: {error}"),
        })
}

pub(crate) fn load_pem_private_key_from_file(
    addr: SocketAddr,
    path: &str,
) -> Result<PrivateKeyDer<'static>, TransferError> {
    let pem = std::fs::read(path).map_err(|source| TransferError::ReadTlsFile {
        path: path.to_owned(),
        source,
    })?;
    PrivateKeyDer::from_pem_slice(&pem).map_err(|error| TransferError::XotConfig {
        addr,
        message: format!("failed to parse private key PEM file {path:?}: {error}"),
    })
}

fn load_pem_private_key_from_inline(
    addr: SocketAddr,
    key_pem: &str,
) -> Result<PrivateKeyDer<'static>, TransferError> {
    PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|error| TransferError::XotConfig {
        addr,
        message: format!("failed to parse inline private key PEM: {error}"),
    })
}

pub(crate) fn load_pem_certs_for_primary(
    addr: SocketAddr,
    path: &str,
) -> Result<Vec<CertificateDer<'static>>, TransferError> {
    let certs = load_pem_certs(path).map_err(|error| match error {
        TransferError::XotConfig { message, .. } => TransferError::XotConfig { addr, message },
        other => other,
    })?;
    if certs.is_empty() {
        return Err(TransferError::XotConfig {
            addr,
            message: format!("certificate file {path:?} did not contain certificates"),
        });
    }
    Ok(certs)
}

#[cfg(unix)]
fn validate_private_key_file_mode(addr: SocketAddr, path: &str) -> Result<(), TransferError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path).map_err(|source| TransferError::ReadTlsFile {
        path: path.to_owned(),
        source,
    })?;
    if metadata.permissions().mode() & 0o007 != 0 {
        return Err(TransferError::XotConfig {
            addr,
            message: format!("private key file {path:?} must not be readable by other users"),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_file_mode(_addr: SocketAddr, _path: &str) -> Result<(), TransferError> {
    Ok(())
}

pub async fn transfer_ixfr_from_primary(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    current_zone: &ZoneSnapshot,
    timeout_duration: Duration,
) -> Result<IxfrResponse, TransferError> {
    transfer_ixfr_from_primary_with_tsig(
        primary,
        zone_apex,
        qclass,
        qid,
        current_zone,
        TransferSession::default_unsigned(),
        timeout_duration,
    )
    .await
}

async fn transfer_ixfr_from_primary_with_tsig(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    current_zone: &ZoneSnapshot,
    session: TransferSession<'_>,
    timeout_duration: Duration,
) -> Result<IxfrResponse, TransferError> {
    let target = TransferPrimaryConfig::tcp(primary);
    transfer_ixfr_from_target_with_tsig(
        &target,
        zone_apex,
        qclass,
        qid,
        current_zone,
        session,
        timeout_duration,
        timeout_duration,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn transfer_ixfr_from_target_with_tsig(
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    current_zone: &ZoneSnapshot,
    session: TransferSession<'_>,
    timeout_duration: Duration,
    connect_timeout: Duration,
) -> Result<IxfrResponse, TransferError> {
    tokio::time::timeout(timeout_duration, async {
        transfer_ixfr_from_primary_inner(
            primary,
            zone_apex,
            qclass,
            qid,
            current_zone,
            session,
            connect_timeout,
        )
        .await
    })
    .await
    .map_err(|_| TransferError::Timeout {
        timeout_secs: timeout_duration.as_secs(),
    })?
}

async fn transfer_ixfr_from_primary_inner(
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    current_zone: &ZoneSnapshot,
    session: TransferSession<'_>,
    connect_timeout: Duration,
) -> Result<IxfrResponse, TransferError> {
    let mut stream =
        connect_transfer_stream(primary, session.transfer_source, connect_timeout).await?;

    let current_soa = current_zone
        .soa_record_view(qclass)
        .ok_or(axfr::IxfrError::InvalidCurrentSoa)?;
    let query = maybe_sign_transfer_query(
        axfr::build_ixfr_query_from_soa_view(qid, zone_apex, qclass, current_soa)?,
        session.tsig,
    )?;
    let framed_query = axfr::frame_tcp_message(&query.message);
    stream
        .write_all(&framed_query)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary.addr,
            source,
        })?;

    let mut messages = Vec::new();
    let mut ingest = TransferIngestTracker::new("IXFR", primary.addr, session.max_ingest_bytes);
    loop {
        let mut length_prefix = [0u8; 2];
        match stream.read_exact(&mut length_prefix).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                let verified_messages = maybe_verify_tcp_transfer_messages(
                    &messages,
                    session.tsig.key,
                    query.request_mac.as_deref(),
                )?;
                return axfr::parse_ixfr_response(
                    qid,
                    zone_apex,
                    qclass,
                    current_zone,
                    &verified_messages,
                )
                .map_err(TransferError::Ixfr);
            }
            Err(source) => {
                return Err(TransferError::Io {
                    addr: primary.addr,
                    source,
                });
            }
        }

        let message_len = u16::from_be_bytes(length_prefix) as usize;
        ingest.record_message(message_len)?;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message).await.map_err(|source| {
            if source.kind() == std::io::ErrorKind::UnexpectedEof {
                TransferError::Ixfr(axfr::IxfrError::IncompleteResponse)
            } else {
                TransferError::Io {
                    addr: primary.addr,
                    source,
                }
            }
        })?;
        messages.push(message);

        match axfr::parse_ixfr_response(qid, zone_apex, qclass, current_zone, &messages) {
            Ok(_) => {
                match maybe_verify_tcp_transfer_messages(
                    &messages,
                    session.tsig.key,
                    query.request_mac.as_deref(),
                ) {
                    Ok(verified_messages) => {
                        return axfr::parse_ixfr_response(
                            qid,
                            zone_apex,
                            qclass,
                            current_zone,
                            &verified_messages,
                        )
                        .map_err(TransferError::Ixfr);
                    }
                    Err(TransferError::Tsig(TsigError::MissingTerminalTsig)) => {}
                    Err(error) => return Err(error),
                }
            }
            Err(axfr::IxfrError::IncompleteResponse)
            | Err(axfr::IxfrError::Axfr(AxfrError::MissingTerminatingSoa)) => {}
            Err(error) => return Err(TransferError::Ixfr(error)),
        }
    }
}

fn outbound_udp_bind_addr(primary: SocketAddr, transfer_source: Option<SocketAddr>) -> SocketAddr {
    transfer_source
        .filter(|source| source.is_ipv4() == primary.is_ipv4())
        .unwrap_or_else(|| match primary {
            SocketAddr::V4(_) => "0.0.0.0:0"
                .parse()
                .expect("hard-coded IPv4 wildcard socket address is valid"),
            SocketAddr::V6(_) => "[::]:0"
                .parse()
                .expect("hard-coded IPv6 wildcard socket address is valid"),
        })
}

struct TransferQuery {
    message: Vec<u8>,
    request_mac: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
pub(crate) struct TransferTsig<'a> {
    key: Option<&'a TsigKey>,
    fudge_seconds: u16,
}

impl<'a> TransferTsig<'a> {
    pub(crate) fn new(key: Option<&'a TsigKey>, fudge_seconds: u16) -> Self {
        Self { key, fudge_seconds }
    }

    pub(crate) fn unsigned() -> Self {
        Self::new(None, DEFAULT_TSIG_FUDGE_SECS)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TransferSession<'a> {
    tsig: TransferTsig<'a>,
    max_ingest_bytes: u64,
    transfer_source: Option<SocketAddr>,
}

impl<'a> TransferSession<'a> {
    pub(crate) fn new(tsig: TransferTsig<'a>, max_ingest_bytes: u64) -> Self {
        Self {
            tsig,
            max_ingest_bytes,
            transfer_source: None,
        }
    }

    pub(crate) fn default_unsigned() -> Self {
        Self::new(TransferTsig::unsigned(), default_transfer_ingest_bytes())
    }

    pub(crate) fn with_transfer_source(mut self, transfer_source: Option<SocketAddr>) -> Self {
        self.transfer_source = transfer_source;
        self
    }
}

fn default_transfer_ingest_bytes() -> u64 {
    4 * 1024 * 1024 * 1024
}

struct TransferIngestTracker {
    protocol: &'static str,
    addr: SocketAddr,
    limit_bytes: u64,
    received_bytes: u64,
}

impl TransferIngestTracker {
    fn new(protocol: &'static str, addr: SocketAddr, limit_bytes: u64) -> Self {
        Self {
            protocol,
            addr,
            limit_bytes,
            received_bytes: 0,
        }
    }

    fn record_message(&mut self, message_len: usize) -> Result<(), TransferError> {
        let next = self.received_bytes.saturating_add(message_len as u64);
        if next > self.limit_bytes {
            return Err(TransferError::IngestSizeLimit {
                protocol: self.protocol,
                addr: self.addr,
                received_bytes: next,
                limit_bytes: self.limit_bytes,
            });
        }
        self.received_bytes = next;
        Ok(())
    }
}

fn maybe_sign_transfer_query(
    query: Vec<u8>,
    tsig: TransferTsig<'_>,
) -> Result<TransferQuery, TransferError> {
    let Some(tsig_key) = tsig.key else {
        return Ok(TransferQuery {
            message: query,
            request_mac: None,
        });
    };

    let signed = tsig_key.sign_request(&query, tsig_time_signed(), tsig.fudge_seconds)?;
    Ok(TransferQuery {
        message: signed.message,
        request_mac: Some(signed.mac),
    })
}

fn maybe_verify_transfer_response(
    message: &[u8],
    tsig_key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
) -> Result<Vec<u8>, TransferError> {
    let (Some(tsig_key), Some(request_mac)) = (tsig_key, request_mac) else {
        return Ok(message.to_vec());
    };

    let verified = tsig_key.verify_response(message, request_mac, tsig_time_signed())?;
    Ok(verified.message)
}

fn maybe_verify_tcp_transfer_messages(
    messages: &[Vec<u8>],
    tsig_key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>, TransferError> {
    let (Some(tsig_key), Some(request_mac)) = (tsig_key, request_mac) else {
        return Ok(messages.to_vec());
    };

    tsig_key
        .verify_tcp_response_stream(messages, request_mac, tsig_time_signed())
        .map_err(TransferError::Tsig)
}

pub(crate) fn tsig_time_signed() -> u64 {
    unix_timestamp_seconds()
}

pub(crate) fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn transfer_axfr_from_primary_inner(
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    session: TransferSession<'_>,
    connect_timeout: Duration,
) -> Result<ZoneSnapshot, TransferError> {
    let mut stream =
        connect_transfer_stream(primary, session.transfer_source, connect_timeout).await?;

    let query =
        maybe_sign_transfer_query(axfr::build_axfr_query(qid, zone_apex, qclass), session.tsig)?;
    let framed_query = axfr::frame_tcp_message(&query.message);
    stream
        .write_all(&framed_query)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary.addr,
            source,
        })?;

    let mut messages = Vec::new();
    let mut saw_initial_soa = false;
    let mut ingest = TransferIngestTracker::new("AXFR", primary.addr, session.max_ingest_bytes);
    loop {
        let mut length_prefix = [0u8; 2];
        match stream.read_exact(&mut length_prefix).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                let verified_messages = maybe_verify_tcp_transfer_messages(
                    &messages,
                    session.tsig.key,
                    query.request_mac.as_deref(),
                )?;
                return axfr::parse_axfr_response(qid, zone_apex, qclass, &verified_messages)
                    .map_err(TransferError::Axfr);
            }
            Err(source) => {
                return Err(TransferError::Io {
                    addr: primary.addr,
                    source,
                });
            }
        }

        let message_len = u16::from_be_bytes(length_prefix) as usize;
        ingest.record_message(message_len)?;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message).await.map_err(|source| {
            if source.kind() == std::io::ErrorKind::UnexpectedEof {
                TransferError::Axfr(AxfrError::MissingTerminatingSoa)
            } else {
                TransferError::Io {
                    addr: primary.addr,
                    source,
                }
            }
        })?;
        let apex_soa_count = axfr::axfr_response_message_apex_soa_count(
            qid,
            zone_apex,
            qclass,
            &message,
            !saw_initial_soa,
        )
        .map_err(TransferError::Axfr)?;
        if apex_soa_count > 0 {
            let complete = saw_initial_soa || apex_soa_count >= 2;
            saw_initial_soa = true;
            if complete {
                messages.push(message);
                match maybe_verify_tcp_transfer_messages(
                    &messages,
                    session.tsig.key,
                    query.request_mac.as_deref(),
                ) {
                    Ok(verified_messages) => {
                        return axfr::parse_axfr_response(
                            qid,
                            zone_apex,
                            qclass,
                            &verified_messages,
                        )
                        .map_err(TransferError::Axfr);
                    }
                    Err(TransferError::Tsig(TsigError::MissingTerminalTsig)) => {}
                    Err(error) => return Err(error),
                }
                continue;
            }
        }
        messages.push(message);
    }
}

pub(crate) fn transfer_query_id() -> Result<u16, TransferError> {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).map_err(TransferError::RandomQueryId)?;
    Ok(query_id_from_random_bytes(bytes))
}

pub(crate) fn query_id_from_random_bytes(bytes: [u8; 2]) -> u16 {
    u16::from_be_bytes(bytes)
}
