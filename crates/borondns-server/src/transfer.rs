use std::{
    fs::File,
    future::Future,
    io::Read,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use borondns_core::{
    axfr::{self, AxfrError, IxfrResponse},
    config::{
        MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE, MAX_XOT_TRUST_ANCHORS_PER_PROFILE,
        TransferPrimaryConfig, TransferTransportConfig, open_readonly_no_follow,
    },
    dns::{DomainName, Header},
    tsig::{DEFAULT_TSIG_FUDGE_SECS, TsigKey, message_has_tsig},
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
use zeroize::Zeroizing;

use crate::TransferError;

pub(crate) use borondns_core::config::MAX_DIRECT_XOT_TLS_MATERIAL_BYTES;

pub(crate) const DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT: u64 = 4096;
const MAX_TCP_DNS_MESSAGE_BYTES: u64 = u16::MAX as u64;
pub(crate) type XotClientConfig = Arc<ClientConfig>;

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
        poll_soa_from_primary_inner(
            primary,
            zone_apex,
            qclass,
            qid,
            tsig,
            transfer_source,
            timeout_duration,
        )
        .await
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
    connect_timeout: Duration,
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

    let mut buffer = vec![0u8; 4096];
    loop {
        let len = socket
            .recv(&mut buffer)
            .await
            .map_err(|source| TransferError::Io {
                addr: primary,
                source,
            })?;

        match udp_response_tc_status(&buffer[..len], qid) {
            UdpTcStatus::ValidTruncatedResponse => {
                let tcp_primary = TransferPrimaryConfig::tcp(primary);
                return poll_soa_from_primary_tcp_inner(
                    &tcp_primary,
                    zone_apex,
                    qclass,
                    qid,
                    tsig,
                    transfer_source,
                    connect_timeout,
                )
                .await;
            }
            UdpTcStatus::InvalidTruncatedResponse => continue,
            UdpTcStatus::NotTruncated => {}
        }

        let response =
            maybe_verify_transfer_response(&buffer[..len], tsig.key, query.request_mac.as_deref())?;
        return parse_soa_poll_response(primary, zone_apex, qclass, qid, &response);
    }
}

async fn poll_soa_from_primary_tcp_inner(
    primary: &TransferPrimaryConfig,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    tsig: TransferTsig<'_>,
    transfer_source: Option<SocketAddr>,
    connect_timeout: Duration,
) -> Result<u32, TransferError> {
    let mut stream =
        connect_transfer_stream(primary, transfer_source, connect_timeout, None).await?;
    let query = maybe_sign_transfer_query(axfr::build_soa_query(qid, zone_apex, qclass), tsig)?;
    let framed_query = axfr::frame_tcp_message(&query.message);
    stream
        .write_all(&framed_query)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary.addr,
            source,
        })?;

    let mut length_prefix = [0u8; 2];
    stream
        .read_exact(&mut length_prefix)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary.addr,
            source,
        })?;
    let message_len = u16::from_be_bytes(length_prefix) as usize;
    let mut message = vec![0u8; message_len];
    stream
        .read_exact(&mut message)
        .await
        .map_err(|source| TransferError::Io {
            addr: primary.addr,
            source,
        })?;

    let response =
        maybe_verify_transfer_response(&message, tsig.key, query.request_mac.as_deref())?;
    parse_soa_poll_response(primary.addr, zone_apex, qclass, qid, &response)
}

fn parse_soa_poll_response(
    primary: SocketAddr,
    zone_apex: &DomainName,
    qclass: u16,
    qid: u16,
    response: &[u8],
) -> Result<u32, TransferError> {
    match axfr::parse_soa_response(qid, zone_apex, qclass, response) {
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
    xot_client_config: Option<&XotClientConfig>,
) -> Result<TransferStream, TransferError> {
    match primary.transport {
        TransferTransportConfig::Tcp => {
            let tcp = connect_tcp_stream(primary.addr, transfer_source, connect_timeout).await?;
            Ok(TransferStream::Tcp(tcp))
        }
        TransferTransportConfig::Xot => {
            connect_xot_stream(primary, transfer_source, connect_timeout, xot_client_config).await
        }
    }
}

async fn connect_xot_stream(
    primary: &TransferPrimaryConfig,
    transfer_source: Option<SocketAddr>,
    connect_timeout: Duration,
    snapshot_client_config: Option<&XotClientConfig>,
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

    let mut client_config = match snapshot_client_config {
        Some(config) => ClientConfig::clone(config.as_ref()),
        None => build_xot_client_config(primary)?,
    };
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
    if primary.trust_anchors.len() > MAX_XOT_TRUST_ANCHORS_PER_PROFILE {
        return Err(TransferError::XotConfig {
            addr: primary.addr,
            message: format!(
                "XoT profile must not configure more than {MAX_XOT_TRUST_ANCHORS_PER_PROFILE} trust anchors"
            ),
        });
    }
    if let Some(key) = primary.client_key_pem.as_ref() {
        validate_direct_xot_inline_private_key_size(primary.addr, key.expose_secret().as_bytes())?;
    }
    let mut material_budget = XotMaterialBudget::for_profile();
    let trust_anchor_pems = primary
        .trust_anchors
        .iter()
        .map(|path| read_tls_material_file_with_budget(primary.addr, path, &mut material_budget))
        .collect::<Result<Vec<_>, _>>()?;
    let client_cert_pem = primary
        .client_cert
        .as_deref()
        .map(|path| read_tls_material_file_with_budget(primary.addr, path, &mut material_budget))
        .transpose()?;
    let client_key_pem = match (&primary.client_key, &primary.client_key_pem) {
        (Some(path), None) => Some(read_private_key_file_with_budget(
            primary.addr,
            path,
            &mut material_budget,
        )?),
        (None, Some(key)) => {
            material_budget.charge(
                primary.addr,
                "inline private key",
                "client_key_pem",
                key.expose_secret().len(),
            )?;
            Some(Zeroizing::new(key.expose_secret().as_bytes().to_vec()))
        }
        (None, None) => None,
        (Some(_), Some(_)) => {
            return Err(TransferError::XotConfig {
                addr: primary.addr,
                message: "client_key and client_key_pem are mutually exclusive".to_owned(),
            });
        }
    };
    let inline_private_key = primary.client_key_pem.is_some();
    build_xot_client_config_from_pem(
        primary.addr,
        &trust_anchor_pems,
        client_cert_pem.as_deref(),
        client_key_pem.as_ref().map(|pem| pem.as_slice()),
    )
    .map_err(|error| match error {
        TransferError::XotConfig { addr, message }
            if inline_private_key && message.contains("client private key PEM") =>
        {
            TransferError::XotConfig {
                addr,
                message: message.replace("client private key PEM", "inline private key PEM"),
            }
        }
        other => other,
    })
}

pub(crate) fn validate_direct_xot_inline_private_key_size(
    addr: SocketAddr,
    key_pem: &[u8],
) -> Result<(), TransferError> {
    if key_pem.len() > MAX_DIRECT_XOT_TLS_MATERIAL_BYTES {
        return Err(direct_xot_material_size_error(
            addr,
            "inline client_key_pem",
            "inline private key",
        ));
    }
    Ok(())
}

pub(crate) fn build_xot_client_config_from_pem(
    addr: SocketAddr,
    trust_anchor_pems: &[Vec<u8>],
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<ClientConfig, TransferError> {
    let mut roots = RootCertStore::empty();
    for pem in trust_anchor_pems {
        let certs = parse_pem_certs(addr, pem, "trust anchor")?;
        if certs.is_empty() {
            return Err(TransferError::XotConfig {
                addr,
                message: "trust anchor did not contain certificates".to_owned(),
            });
        }
        for cert in certs {
            roots.add(cert).map_err(|error| TransferError::XotConfig {
                addr,
                message: format!("failed to add trust anchor: {error}"),
            })?;
        }
    }
    if roots.is_empty() {
        return Err(TransferError::XotConfig {
            addr,
            message: "at least one trust anchor is required".to_owned(),
        });
    }

    let builder = ClientConfig::builder_with_protocol_versions(&[&version::TLS13])
        .with_root_certificates(roots);
    match (client_cert_pem, client_key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            let certs = parse_pem_certs(addr, cert_pem, "client certificate")?;
            let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|error| {
                TransferError::XotConfig {
                    addr,
                    message: format!("failed to parse client private key PEM: {error}"),
                }
            })?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|error| TransferError::XotConfig {
                    addr,
                    message: format!("invalid XoT client certificate/key pair: {error}"),
                })
        }
        (None, None) => Ok(builder.with_no_client_auth()),
        _ => Err(TransferError::XotConfig {
            addr,
            message: "client certificate and private key must be configured together".to_owned(),
        }),
    }
}

pub(crate) fn parse_pem_certs(
    addr: SocketAddr,
    pem: &[u8],
    label: &str,
) -> Result<Vec<CertificateDer<'static>>, TransferError> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TransferError::XotConfig {
            addr,
            message: format!("failed to parse {label} PEM: {error}"),
        })
}

fn read_tls_material_file(path: &str) -> Result<Vec<u8>, TransferError> {
    read_tls_material_file_with_hook(path, || {})
}

fn read_tls_material_file_with_hook(
    path: &str,
    after_open: impl FnOnce(),
) -> Result<Vec<u8>, TransferError> {
    let mut file = open_tls_material_file(path)?;
    after_open();
    let mut pem = Vec::new();
    let mut budget = XotMaterialBudget::for_profile();
    read_bounded_direct_xot_material(
        &mut file,
        path,
        direct_xot_placeholder_addr(),
        "TLS material file",
        &mut pem,
        &mut budget,
    )?;
    Ok(pem)
}

fn read_tls_material_file_with_budget(
    addr: SocketAddr,
    path: &str,
    budget: &mut XotMaterialBudget,
) -> Result<Vec<u8>, TransferError> {
    let mut file = open_tls_material_file(path)?;
    let mut pem = Vec::new();
    read_bounded_direct_xot_material(&mut file, path, addr, "TLS material file", &mut pem, budget)?;
    Ok(pem)
}

#[cfg(test)]
fn read_private_key_file(
    addr: SocketAddr,
    path: &str,
) -> Result<Zeroizing<Vec<u8>>, TransferError> {
    read_private_key_file_with_hook(addr, path, || {})
}

fn read_private_key_file_with_budget(
    addr: SocketAddr,
    path: &str,
    budget: &mut XotMaterialBudget,
) -> Result<Zeroizing<Vec<u8>>, TransferError> {
    let mut file = open_private_key_file(addr, path)?;
    let mut pem = Zeroizing::new(Vec::new());
    read_bounded_direct_xot_material(&mut file, path, addr, "private key file", &mut pem, budget)?;
    Ok(pem)
}

#[cfg(test)]
fn read_private_key_file_with_hook(
    addr: SocketAddr,
    path: &str,
    after_open: impl FnOnce(),
) -> Result<Zeroizing<Vec<u8>>, TransferError> {
    let mut file = open_private_key_file(addr, path)?;
    after_open();
    let mut pem = Zeroizing::new(Vec::new());
    let mut budget = XotMaterialBudget::for_profile();
    read_bounded_direct_xot_material(
        &mut file,
        path,
        addr,
        "private key file",
        &mut pem,
        &mut budget,
    )?;
    Ok(pem)
}

#[derive(Debug)]
struct XotMaterialBudget {
    limit: usize,
    consumed: usize,
}

impl XotMaterialBudget {
    fn for_profile() -> Self {
        Self {
            limit: MAX_XOT_TLS_MATERIAL_BYTES_PER_PROFILE,
            consumed: 0,
        }
    }

    fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.consumed)
    }

    fn charge(
        &mut self,
        addr: SocketAddr,
        label: &str,
        path: &str,
        bytes: usize,
    ) -> Result<(), TransferError> {
        let total = self.consumed.saturating_add(bytes);
        if total > self.limit {
            return Err(TransferError::XotConfig {
                addr,
                message: format!(
                    "{label} {path:?} would raise aggregate XoT TLS material to {total} bytes, exceeding {limit} byte per-profile limit",
                    limit = self.limit
                ),
            });
        }
        self.consumed = total;
        Ok(())
    }
}

fn read_bounded_direct_xot_material(
    file: &mut File,
    path: &str,
    addr: SocketAddr,
    label: &str,
    output: &mut Vec<u8>,
    budget: &mut XotMaterialBudget,
) -> Result<(), TransferError> {
    let metadata_len = usize::try_from(
        file.metadata()
            .map_err(|source| TransferError::ReadTlsFile {
                path: path.to_owned(),
                source,
            })?
            .len(),
    )
    .unwrap_or(usize::MAX);
    budget.charge(addr, label, path, metadata_len)?;
    // Undo the metadata reservation until the same-handle bounded read confirms
    // the actual byte count. This rejects known-over-budget files before their
    // allocation while still detecting concurrent growth.
    budget.consumed = budget.consumed.saturating_sub(metadata_len);
    let read_limit = MAX_DIRECT_XOT_TLS_MATERIAL_BYTES.min(budget.remaining());
    file.by_ref()
        .take(read_limit.saturating_add(1) as u64)
        .read_to_end(output)
        .map_err(|source| TransferError::ReadTlsFile {
            path: path.to_owned(),
            source,
        })?;
    if output.len() > MAX_DIRECT_XOT_TLS_MATERIAL_BYTES {
        return Err(direct_xot_material_size_error(addr, path, label));
    }
    budget.charge(addr, label, path, output.len())?;
    Ok(())
}

fn direct_xot_material_size_error(addr: SocketAddr, path: &str, label: &str) -> TransferError {
    TransferError::XotConfig {
        addr,
        message: format!(
            "{label} {path:?} exceeds {MAX_DIRECT_XOT_TLS_MATERIAL_BYTES} byte direct XoT material limit"
        ),
    }
}

fn direct_xot_placeholder_addr() -> SocketAddr {
    "0.0.0.0:0"
        .parse()
        .expect("hard-coded placeholder socket address is valid")
}

pub(crate) fn load_pem_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TransferError> {
    let pem = read_tls_material_file(path)?;
    parse_pem_certs(
        "0.0.0.0:0"
            .parse()
            .expect("hard-coded placeholder socket address is valid"),
        &pem,
        &format!("certificate file {path:?}"),
    )
}

fn open_tls_material_file(path: &str) -> Result<File, TransferError> {
    let file = open_readonly_no_follow(path).map_err(|source| TransferError::ReadTlsFile {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| TransferError::ReadTlsFile {
            path: path.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(TransferError::XotConfig {
            addr: direct_xot_placeholder_addr(),
            message: format!("TLS material file {path:?} must be a regular file"),
        });
    }
    validate_direct_xot_material_size(
        &metadata,
        direct_xot_placeholder_addr(),
        path,
        "TLS material file",
    )?;
    #[cfg(unix)]
    validate_tls_material_integrity(&metadata, path)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_tls_material_integrity(
    metadata: &std::fs::Metadata,
    path: &str,
) -> Result<(), TransferError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(TransferError::XotConfig {
            addr: direct_xot_placeholder_addr(),
            message: format!("TLS material file {path:?} must not be group- or world-writable"),
        });
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn load_pem_private_key_from_file(
    addr: SocketAddr,
    path: &str,
) -> Result<PrivateKeyDer<'static>, TransferError> {
    let pem = read_private_key_file(addr, path)?;
    PrivateKeyDer::from_pem_slice(&pem).map_err(|error| TransferError::XotConfig {
        addr,
        message: format!("failed to parse private key PEM file {path:?}: {error}"),
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

fn open_private_key_file(addr: SocketAddr, path: &str) -> Result<File, TransferError> {
    let file = open_readonly_no_follow(path).map_err(|source| TransferError::ReadTlsFile {
        path: path.to_owned(),
        source,
    })?;
    validate_private_key_file(&file, addr, path)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_private_key_file(
    file: &File,
    addr: SocketAddr,
    path: &str,
) -> Result<(), TransferError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = file
        .metadata()
        .map_err(|source| TransferError::ReadTlsFile {
            path: path.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(TransferError::XotConfig {
            addr,
            message: format!("private key file {path:?} must be a regular file"),
        });
    }
    validate_direct_xot_material_size(&metadata, addr, path, "private key file")?;
    let mode = metadata.permissions().mode();
    if mode & 0o004 != 0 {
        return Err(TransferError::XotConfig {
            addr,
            message: format!("private key file {path:?} must not be world-readable"),
        });
    }
    if mode & 0o022 != 0 {
        return Err(TransferError::XotConfig {
            addr,
            message: format!("private key file {path:?} must not be group- or world-writable"),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_file(
    file: &File,
    addr: SocketAddr,
    path: &str,
) -> Result<(), TransferError> {
    let metadata = file
        .metadata()
        .map_err(|source| TransferError::ReadTlsFile {
            path: path.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(TransferError::XotConfig {
            addr,
            message: format!("private key file {path:?} must be a regular file"),
        });
    }
    validate_direct_xot_material_size(&metadata, addr, path, "private key file")?;
    Ok(())
}

fn validate_direct_xot_material_size(
    metadata: &std::fs::Metadata,
    addr: SocketAddr,
    path: &str,
    label: &str,
) -> Result<(), TransferError> {
    if metadata.len() > MAX_DIRECT_XOT_TLS_MATERIAL_BYTES as u64 {
        return Err(direct_xot_material_size_error(addr, path, label));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn direct_xot_tls_material_len_after_open_for_test(
    path: &str,
    after_open: impl FnOnce(),
) -> Result<usize, TransferError> {
    read_tls_material_file_with_hook(path, after_open).map(|material| material.len())
}

#[cfg(test)]
pub(crate) fn direct_xot_private_key_len_after_open_for_test(
    addr: SocketAddr,
    path: &str,
    after_open: impl FnOnce(),
) -> Result<usize, TransferError> {
    read_private_key_file_with_hook(addr, path, after_open).map(|material| material.len())
}

#[cfg(test)]
pub(crate) fn direct_xot_aggregate_material_len_for_test(
    addr: SocketAddr,
    paths: &[&str],
) -> Result<usize, TransferError> {
    let mut budget = XotMaterialBudget::for_profile();
    for path in paths {
        let _material = read_tls_material_file_with_budget(addr, path, &mut budget)?;
    }
    Ok(budget.consumed)
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
    let mut stream = connect_transfer_stream(
        primary,
        session.transfer_source,
        connect_timeout,
        session.xot_client_config,
    )
    .await?;

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

    let mut ingest = TransferIngestTracker::new("IXFR", primary.addr, session.max_ingest_bytes)
        .with_ingest_budget(session.ingest_budget);
    // Declare retained messages after the tracker so Rust drops the message
    // buffers before releasing their aggregate-budget reservations.
    let mut messages = Vec::new();
    let mut completion_probe = IxfrCompletionProbe::new(current_zone.serial);
    loop {
        let mut length_prefix = [0u8; 2];
        match stream.read_exact(&mut length_prefix).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                let verified_messages = maybe_verify_tcp_transfer_messages(
                    messages,
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
        let received_at_unix = tsig_time_signed();
        let message_probe = axfr::ixfr_response_message_probe(qid, zone_apex, qclass, &message)
            .map_err(TransferError::Ixfr)?;
        let complete = completion_probe
            .observe(message_probe)
            .map_err(TransferError::Ixfr)?;
        messages.push(ReceivedTransferMessage {
            wire: message,
            received_at_unix,
        });

        if complete && transfer_terminal_tsig_ready(&messages, session.tsig.key)? {
            match maybe_verify_tcp_transfer_messages(
                std::mem::take(&mut messages),
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
                Err(error) => return Err(error),
            }
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

struct ReceivedTransferMessage {
    wire: Vec<u8>,
    received_at_unix: u64,
}

struct IxfrCompletionProbe {
    current_serial: Option<u32>,
    answer_count: usize,
    first_soa_rdata: Option<Vec<u8>>,
    complete: bool,
}

impl IxfrCompletionProbe {
    fn new(current_serial: Option<u32>) -> Self {
        Self {
            current_serial,
            answer_count: 0,
            first_soa_rdata: None,
            complete: false,
        }
    }

    fn observe(&mut self, probe: axfr::IxfrMessageProbe) -> Result<bool, axfr::IxfrError> {
        let mut complete = false;
        for answer in probe.answers {
            self.answer_count += 1;
            if self.answer_count == 1 {
                let Some(serial) = answer.apex_soa_serial else {
                    return Err(axfr::IxfrError::MissingInitialSoa);
                };
                self.first_soa_rdata = answer.apex_soa_rdata;
                complete = self.current_serial == Some(serial);
                continue;
            }

            if answer.apex_soa_rdata.is_some()
                && answer.apex_soa_rdata == self.first_soa_rdata
                && self.answer_count > 2
            {
                complete = true;
            }
        }
        self.complete |= complete;
        Ok(self.complete)
    }
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
    ingest_budget: Option<&'a TransferIngestBudget>,
    transfer_source: Option<SocketAddr>,
    xot_client_config: Option<&'a XotClientConfig>,
}

impl<'a> TransferSession<'a> {
    pub(crate) fn new(tsig: TransferTsig<'a>, max_ingest_bytes: u64) -> Self {
        Self {
            tsig,
            max_ingest_bytes,
            ingest_budget: None,
            transfer_source: None,
            xot_client_config: None,
        }
    }

    pub(crate) fn default_unsigned() -> Self {
        Self::new(TransferTsig::unsigned(), default_transfer_ingest_bytes())
    }

    pub(crate) fn with_transfer_source(mut self, transfer_source: Option<SocketAddr>) -> Self {
        self.transfer_source = transfer_source;
        self
    }

    pub(crate) fn with_ingest_budget(mut self, ingest_budget: &'a TransferIngestBudget) -> Self {
        self.ingest_budget = Some(ingest_budget);
        self
    }

    pub(crate) fn with_xot_client_config(
        mut self,
        xot_client_config: Option<&'a XotClientConfig>,
    ) -> Self {
        self.xot_client_config = xot_client_config;
        self
    }
}

fn default_transfer_ingest_bytes() -> u64 {
    4 * 1024 * 1024 * 1024
}

#[derive(Debug, Clone)]
pub(crate) struct TransferIngestBudget {
    inner: Arc<TransferIngestBudgetInner>,
}

#[derive(Debug)]
struct TransferIngestBudgetInner {
    limit_bytes: u64,
    in_flight_bytes: AtomicU64,
}

impl TransferIngestBudget {
    pub(crate) fn new(limit_bytes: u64) -> Self {
        Self {
            inner: Arc::new(TransferIngestBudgetInner {
                limit_bytes,
                in_flight_bytes: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn for_concurrent_sessions(
        per_session_limit_bytes: u64,
        max_concurrent_sessions: usize,
    ) -> Self {
        let max_concurrent_sessions = u64::try_from(max_concurrent_sessions).unwrap_or(u64::MAX);
        Self::new(per_session_limit_bytes.saturating_mul(max_concurrent_sessions))
    }

    fn try_reserve(
        &self,
        protocol: &'static str,
        addr: SocketAddr,
        message_bytes: u64,
    ) -> Result<TransferIngestReservation, TransferError> {
        let mut in_flight = self.inner.in_flight_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = in_flight.checked_add(message_bytes) else {
                return Err(TransferError::IngestGlobalSizeLimit {
                    protocol,
                    addr,
                    requested_bytes: message_bytes,
                    in_flight_bytes: in_flight,
                    limit_bytes: self.inner.limit_bytes,
                });
            };
            if next > self.inner.limit_bytes {
                return Err(TransferError::IngestGlobalSizeLimit {
                    protocol,
                    addr,
                    requested_bytes: message_bytes,
                    in_flight_bytes: in_flight,
                    limit_bytes: self.inner.limit_bytes,
                });
            }
            match self.inner.in_flight_bytes.compare_exchange_weak(
                in_flight,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(TransferIngestReservation {
                        inner: self.inner.clone(),
                        reserved_bytes: message_bytes,
                    });
                }
                Err(observed) => in_flight = observed,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn in_flight_bytes(&self) -> u64 {
        self.inner.in_flight_bytes.load(Ordering::Acquire)
    }
}

struct TransferIngestReservation {
    inner: Arc<TransferIngestBudgetInner>,
    reserved_bytes: u64,
}

impl Drop for TransferIngestReservation {
    fn drop(&mut self) {
        self.inner
            .in_flight_bytes
            .fetch_sub(self.reserved_bytes, Ordering::AcqRel);
    }
}

pub(crate) struct TransferIngestTracker<'a> {
    protocol: &'static str,
    addr: SocketAddr,
    limit_bytes: u64,
    limit_message_bytes: u64,
    received_bytes: u64,
    limit_messages: u64,
    received_messages: u64,
    ingest_budget: Option<&'a TransferIngestBudget>,
    reservations: Vec<TransferIngestReservation>,
}

impl<'a> TransferIngestTracker<'a> {
    pub(crate) fn new(protocol: &'static str, addr: SocketAddr, limit_bytes: u64) -> Self {
        Self {
            protocol,
            addr,
            limit_bytes,
            limit_message_bytes: limit_bytes.min(MAX_TCP_DNS_MESSAGE_BYTES),
            received_bytes: 0,
            limit_messages: DEFAULT_TRANSFER_INGEST_MESSAGE_LIMIT,
            received_messages: 0,
            ingest_budget: None,
            reservations: Vec::new(),
        }
    }

    pub(crate) fn with_ingest_budget(
        mut self,
        ingest_budget: Option<&'a TransferIngestBudget>,
    ) -> Self {
        self.ingest_budget = ingest_budget;
        self
    }

    pub(crate) fn record_message(&mut self, message_len: usize) -> Result<(), TransferError> {
        let next_messages = self.received_messages.saturating_add(1);
        if next_messages > self.limit_messages {
            return Err(TransferError::IngestMessageLimit {
                protocol: self.protocol,
                addr: self.addr,
                received_messages: next_messages,
                limit_messages: self.limit_messages,
            });
        }
        let message_len = message_len as u64;
        let next = self.received_bytes.saturating_add(message_len);
        if message_len > self.limit_message_bytes || next > self.limit_bytes {
            return Err(TransferError::IngestSizeLimit {
                protocol: self.protocol,
                addr: self.addr,
                received_bytes: next,
                limit_bytes: self.limit_bytes,
            });
        }
        if let Some(ingest_budget) = self.ingest_budget {
            self.reservations.push(ingest_budget.try_reserve(
                self.protocol,
                self.addr,
                message_len,
            )?);
        }
        self.received_messages = next_messages;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpTcStatus {
    NotTruncated,
    InvalidTruncatedResponse,
    ValidTruncatedResponse,
}

fn udp_response_tc_status(message: &[u8], qid: u16) -> UdpTcStatus {
    let Ok(header) = Header::parse(message) else {
        return UdpTcStatus::NotTruncated;
    };
    if header.flags & 0x0200 == 0 {
        return UdpTcStatus::NotTruncated;
    }
    if header.id == qid && header.is_response() && header.opcode_value() == 0 {
        UdpTcStatus::ValidTruncatedResponse
    } else {
        UdpTcStatus::InvalidTruncatedResponse
    }
}

fn maybe_verify_tcp_transfer_messages(
    messages: Vec<ReceivedTransferMessage>,
    tsig_key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>, TransferError> {
    let (Some(tsig_key), Some(request_mac)) = (tsig_key, request_mac) else {
        return Ok(messages.into_iter().map(|message| message.wire).collect());
    };

    tsig_key
        .verify_tcp_response_stream_owned_at_times(
            messages
                .into_iter()
                .map(|message| (message.wire, message.received_at_unix))
                .collect(),
            request_mac,
        )
        .map_err(TransferError::Tsig)
}

fn transfer_terminal_tsig_ready(
    messages: &[ReceivedTransferMessage],
    tsig_key: Option<&TsigKey>,
) -> Result<bool, TransferError> {
    if tsig_key.is_none() {
        return Ok(true);
    }
    let Some(last) = messages.last() else {
        return Ok(false);
    };
    message_has_tsig(&last.wire).map_err(TransferError::Tsig)
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
    let mut stream = connect_transfer_stream(
        primary,
        session.transfer_source,
        connect_timeout,
        session.xot_client_config,
    )
    .await?;

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

    let mut ingest = TransferIngestTracker::new("AXFR", primary.addr, session.max_ingest_bytes)
        .with_ingest_budget(session.ingest_budget);
    // Keep the reservation owner alive until after all retained wire messages
    // have been freed on success, error, timeout, or cancellation.
    let mut messages = Vec::new();
    let mut saw_initial_soa = false;
    let mut complete = false;
    let mut saw_response_question = false;
    loop {
        let mut length_prefix = [0u8; 2];
        match stream.read_exact(&mut length_prefix).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                let verified_messages = maybe_verify_tcp_transfer_messages(
                    messages,
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
        let received_at_unix = tsig_time_signed();
        let probe = axfr::axfr_response_message_probe(
            qid,
            zone_apex,
            qclass,
            &message,
            !saw_response_question,
        )
        .map_err(TransferError::Axfr)?;
        saw_response_question |= probe.saw_response_question;
        if probe.apex_soa_count > 0 {
            complete |= saw_initial_soa || probe.apex_soa_count >= 2;
            saw_initial_soa = true;
        }
        messages.push(ReceivedTransferMessage {
            wire: message,
            received_at_unix,
        });
        if complete {
            if !transfer_terminal_tsig_ready(&messages, session.tsig.key)? {
                continue;
            }
            match maybe_verify_tcp_transfer_messages(
                std::mem::take(&mut messages),
                session.tsig.key,
                query.request_mac.as_deref(),
            ) {
                Ok(verified_messages) => {
                    return axfr::parse_axfr_response(qid, zone_apex, qclass, &verified_messages)
                        .map_err(TransferError::Axfr);
                }
                Err(error) => return Err(error),
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ixfr_probe_with_apex_soa(serial: u32, rdata: Vec<u8>) -> axfr::IxfrMessageProbe {
        axfr::IxfrMessageProbe {
            answers: vec![axfr::IxfrProbeAnswer {
                apex_soa_serial: Some(serial),
                apex_soa_rdata: Some(rdata),
            }],
        }
    }

    #[test]
    fn ixfr_completion_probe_stays_complete_for_terminal_tsig_message() {
        let mut probe = IxfrCompletionProbe::new(Some(7));
        assert!(
            probe
                .observe(ixfr_probe_with_apex_soa(7, b"current-soa".to_vec()))
                .expect("current IXFR response completes")
        );

        assert!(
            probe
                .observe(axfr::IxfrMessageProbe {
                    answers: Vec::new(),
                })
                .expect("terminal TSIG-only message keeps completion state")
        );
    }

    #[test]
    fn unsigned_transfer_verification_reuses_retained_message_allocations() {
        let messages = vec![
            ReceivedTransferMessage {
                wire: vec![0x11; 32],
                received_at_unix: 1,
            },
            ReceivedTransferMessage {
                wire: vec![0x22; 48],
                received_at_unix: 2,
            },
        ];
        let pointers = messages
            .iter()
            .map(|message| message.wire.as_ptr())
            .collect::<Vec<_>>();

        let verified = maybe_verify_tcp_transfer_messages(messages, None, None)
            .expect("unsigned messages require no transformation");

        assert_eq!(verified[0].as_ptr(), pointers[0]);
        assert_eq!(verified[1].as_ptr(), pointers[1]);
    }
}
