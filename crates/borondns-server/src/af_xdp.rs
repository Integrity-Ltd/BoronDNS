#![allow(dead_code)]
#![allow(unsafe_code)]

use std::{
    collections::VecDeque,
    error::Error,
    ffi::CString,
    fmt,
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Range,
    os::fd::{AsRawFd, RawFd},
    path::Path,
    sync::Arc,
    time::Duration,
};

use aya::{
    Ebpf, Pod,
    maps::{Array, XskMap},
    programs::{Xdp, XdpFlags},
};
use borondns_core::config::{XdpConfig, XdpMode, XdpZeroCopyMode};
use tokio::{
    io::{Interest, unix::AsyncFd},
    net::UdpSocket,
};
use xdp::{
    slab::{HeapSlab, Slab},
    socket::XdpSocketBuilder,
};

use super::{
    AfXdpPacketIoStats, PacketIo, PacketIoSendError, RuntimeMetrics, UDP_PACKET_BUFFER_LEN,
    UdpInbound, UdpOutbound, UdpPacketTarget, record_query_send_metric,
    udp::ensure_udp_admission_open,
};

const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const RESPONSE_IP_HOP_LIMIT: u8 = 64;
const IP_PROTOCOL_UDP: u8 = 17;
const RING_KICK_RETRY_DELAY: Duration = Duration::from_millis(1);
// Keep one AF_XDP queue responsive when a driver keeps rejecting a wake. Ring
// ownership remains pending across this bounded service attempt, so a later
// receive/send pass can retry without recycling kernel-owned descriptors.
const RING_KICK_MAX_RECOVERY_ATTEMPTS: u64 = 64;
const BENCHMARK_FIXED_DNS_RESPONSE_TEMPLATE: [u8; 65] = [
    0x00, 0x00, // ID, patched from the query.
    0x84, 0x00, // QR + AA, NOERROR.
    0x00, 0x01, // QDCOUNT.
    0x00, 0x01, // ANCOUNT.
    0x00, 0x00, // NSCOUNT.
    0x00, 0x01, // ARCOUNT.
    0x0a, b'h', b'o', b's', b't', b'0', b'0', b'0', b'0', b'0', b'0', 0x04, b'p', b'e', b'r', b'f',
    0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01, // host000000.perf.test. A IN.
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 0, 0, 0x00,
    0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UdpIpv4Frame {
    ipv4_header_offset: usize,
    ipv4_header_len: usize,
    udp_header_offset: usize,
    payload: Range<usize>,
}

impl UdpIpv4Frame {
    pub(crate) fn payload(&self) -> Range<usize> {
        self.payload.clone()
    }

    pub(crate) fn source_addr(&self, frame: &[u8]) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(ipv4_addr_at(frame, self.ipv4_header_offset + 12)),
            u16::from_be_bytes([
                frame[self.udp_header_offset],
                frame[self.udp_header_offset + 1],
            ]),
        )
    }

    pub(crate) fn destination_addr(&self, frame: &[u8]) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(ipv4_addr_at(frame, self.ipv4_header_offset + 16)),
            u16::from_be_bytes([
                frame[self.udp_header_offset + 2],
                frame[self.udp_header_offset + 3],
            ]),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UdpIpv6Frame {
    ipv6_header_offset: usize,
    udp_header_offset: usize,
    payload: Range<usize>,
}

impl UdpIpv6Frame {
    pub(crate) fn payload(&self) -> Range<usize> {
        self.payload.clone()
    }

    pub(crate) fn source_addr(&self, frame: &[u8]) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(ipv6_addr_at(frame, self.ipv6_header_offset + 8)),
            u16::from_be_bytes([
                frame[self.udp_header_offset],
                frame[self.udp_header_offset + 1],
            ]),
        )
    }

    pub(crate) fn destination_addr(&self, frame: &[u8]) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(ipv6_addr_at(frame, self.ipv6_header_offset + 24)),
            u16::from_be_bytes([
                frame[self.udp_header_offset + 2],
                frame[self.udp_header_offset + 3],
            ]),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UdpIpFrame {
    Ipv4(UdpIpv4Frame),
    Ipv6(UdpIpv6Frame),
}

impl UdpIpFrame {
    pub(crate) fn payload(&self) -> Range<usize> {
        match self {
            Self::Ipv4(frame) => frame.payload(),
            Self::Ipv6(frame) => frame.payload(),
        }
    }

    pub(crate) fn source_addr(&self, packet: &[u8]) -> SocketAddr {
        match self {
            Self::Ipv4(frame) => frame.source_addr(packet),
            Self::Ipv6(frame) => frame.source_addr(packet),
        }
    }

    pub(crate) fn destination_addr(&self, packet: &[u8]) -> SocketAddr {
        match self {
            Self::Ipv4(frame) => frame.destination_addr(packet),
            Self::Ipv6(frame) => frame.destination_addr(packet),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AfXdpFrameError {
    ShortEthernet,
    UnsupportedEtherType(u16),
    ShortIpv4,
    InvalidIpv4Header,
    InvalidIpv4Checksum,
    InvalidSourceAddress,
    NotUdp,
    FragmentedIpv4,
    InvalidIpv4TotalLength,
    ShortUdp,
    InvalidUdpLength,
    InvalidUdpChecksum,
    ShortIpv6,
    UnsupportedIpv6NextHeader(u8),
    InvalidIpv6PayloadLength,
    MissingIpv6UdpChecksum,
    ResponseTooLarge,
    PacketResize,
}

impl fmt::Display for AfXdpFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortEthernet => formatter.write_str("short Ethernet frame"),
            Self::UnsupportedEtherType(ethertype) => {
                write!(formatter, "unsupported Ethernet type 0x{ethertype:04x}")
            }
            Self::ShortIpv4 => formatter.write_str("short IPv4 packet"),
            Self::InvalidIpv4Header => formatter.write_str("invalid IPv4 header"),
            Self::InvalidIpv4Checksum => formatter.write_str("invalid IPv4 header checksum"),
            Self::InvalidSourceAddress => formatter.write_str("invalid IP source address"),
            Self::NotUdp => formatter.write_str("IPv4 packet is not UDP"),
            Self::FragmentedIpv4 => formatter.write_str("fragmented IPv4 UDP packet"),
            Self::InvalidIpv4TotalLength => formatter.write_str("invalid IPv4 total length"),
            Self::ShortUdp => formatter.write_str("short UDP datagram"),
            Self::InvalidUdpLength => formatter.write_str("invalid UDP length"),
            Self::InvalidUdpChecksum => formatter.write_str("invalid UDP checksum"),
            Self::ShortIpv6 => formatter.write_str("short IPv6 packet"),
            Self::UnsupportedIpv6NextHeader(next_header) => {
                write!(formatter, "unsupported IPv6 next header {next_header}")
            }
            Self::InvalidIpv6PayloadLength => formatter.write_str("invalid IPv6 payload length"),
            Self::MissingIpv6UdpChecksum => {
                formatter.write_str("IPv6 UDP datagram has a zero checksum")
            }
            Self::ResponseTooLarge => formatter.write_str("AF_XDP response does not fit frame"),
            Self::PacketResize => formatter.write_str("failed to resize AF_XDP packet"),
        }
    }
}

impl Error for AfXdpFrameError {}

pub(crate) fn target_for_frame(frame_index: usize) -> UdpPacketTarget {
    UdpPacketTarget::AfXdp { frame_index }
}

pub(crate) struct PreparedXdpConfig {
    interface: String,
    queue_id: u32,
    batch_size: usize,
    umem: xdp::umem::UmemCfg,
    rings: xdp::RingConfig,
}

pub(crate) fn prepare_xdp_config(
    config: &XdpConfig,
) -> Result<PreparedXdpConfig, xdp::error::Error> {
    let umem = xdp::umem::UmemCfgBuilder {
        frame_count: config.umem_frame_count,
        tx_checksum: false,
        tx_timestamp: false,
        ..Default::default()
    }
    .build()?;
    let rings = xdp::RingConfigBuilder {
        rx_count: config.rx_ring_size,
        tx_count: config.tx_ring_size,
        fill_count: config.fill_ring_size,
        completion_count: config.completion_ring_size,
    }
    .build()?;
    Ok(PreparedXdpConfig {
        interface: config.interface.clone().unwrap_or_default(),
        queue_id: config.queue_id,
        batch_size: config
            .batch_size
            .min(config.rx_ring_size as usize)
            .min(config.tx_ring_size as usize)
            .max(1),
        umem,
        rings,
    })
}

pub(crate) struct AfXdpPacketIo {
    _udp_socket: Arc<UdpSocket>,
    socket: AsyncFd<xdp::socket::XdpSocket>,
    _redirect: Option<Arc<XdpRedirectGuard>>,
    rx_ring: xdp::RxRing,
    tx_ring: xdp::WakableTxRing,
    fill_ring: xdp::WakableFillRing,
    completion_ring: xdp::CompletionRing,
    umem: xdp::Umem,
    local_addr: SocketAddr,
    batch_size: usize,
    rx_drain_passes: usize,
    fill_ring_size: usize,
    completion_ring_size: usize,
    inbound: Vec<UdpInbound>,
    active_inbound: usize,
    frames: Vec<Option<ReceivedFrame>>,
    recv_slab: HeapSlab,
    tx_slab: HeapSlab,
    tx_kick_pending: bool,
    fill_kick_pending: bool,
    pending_stats: AfXdpPacketIoStats,
}

struct ReceivedFrame {
    packet: xdp::Packet,
    frame: UdpIpFrame,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReceiveSlabDrain {
    consumed: usize,
    retained: usize,
    batch_full: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceivePassAction {
    Continue,
    ReturnBatch,
    Yield,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RingKickKind {
    Tx,
    Fill,
}

fn is_transient_ring_kick_error(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock)
        || matches!(error.raw_os_error(), Some(libc::ENOBUFS | libc::ENOMEM))
}

fn is_lossy_tx_kick_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EBUSY)
}

fn mark_ring_kick_pending(pending: &mut bool, admitted: usize) {
    if admitted > 0 {
        *pending = true;
    }
}

fn kick_af_xdp_ring(socket_fd: RawFd, kind: RingKickKind) -> io::Result<()> {
    // AF_XDP defines zero-length sendto/recvfrom calls as TX/FILL wakeups.
    // SAFETY: `socket_fd` is the live AF_XDP socket owned by the adapter; both
    // operations use a zero length and null data/address pointers, so the
    // kernel cannot dereference userspace packet memory through this call.
    let result = unsafe {
        match kind {
            RingKickKind::Tx => libc::sendto(
                socket_fd,
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            ),
            RingKickKind::Fill => libc::recvfrom(
                socket_fd,
                std::ptr::null_mut(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ),
        }
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Completes a ring wake that may have failed after ownership was transferred
/// to the kernel ring. A transient error leaves `pending` set, and the next
/// attempt happens after either readiness or a short timeout, so an isolated
/// batch does not depend on later traffic to make progress.
#[derive(Debug, Default)]
struct RingKickReport {
    attempts: u64,
    successes: u64,
    transient_failures: u64,
    delivery_failures: u64,
    delivery_error: Option<io::Error>,
}

#[derive(Debug)]
struct RingKickServiceError {
    error: io::Error,
    report: RingKickReport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RingKickObservation {
    Success,
    TransientFailure,
    DeliveryFailure,
    PermanentFailure,
}

impl RingKickObservation {
    fn requires_completion_drain(self) -> bool {
        matches!(self, Self::TransientFailure | Self::DeliveryFailure)
    }
}

fn record_tx_kick_observation(stats: &mut AfXdpPacketIoStats, observation: RingKickObservation) {
    stats.tx_wakeups = stats.tx_wakeups.saturating_add(1);
    match observation {
        RingKickObservation::Success => {
            stats.tx_kick_successes = stats.tx_kick_successes.saturating_add(1);
        }
        RingKickObservation::TransientFailure => {
            stats.tx_kick_transient_failures = stats.tx_kick_transient_failures.saturating_add(1);
        }
        RingKickObservation::DeliveryFailure => {
            stats.tx_delivery_failures = stats.tx_delivery_failures.saturating_add(1);
        }
        RingKickObservation::PermanentFailure => {}
    }
}

/// Commits one aggregate UDP send batch when this AF_XDP send future ends.
///
/// AF_XDP can admit descriptors before a kick reports a delivery failure or
/// before the outer shutdown deadline cancels the future. Recording from Drop
/// keeps the generic transport counters aligned with TX-ring admission on
/// success, error, and cancellation while counting the logical batch once.
struct UdpSendAdmissionBatch<'a> {
    metrics: &'a RuntimeMetrics,
    worker_id: usize,
    admitted: usize,
}

impl<'a> UdpSendAdmissionBatch<'a> {
    fn new(metrics: &'a RuntimeMetrics, worker_id: usize) -> Self {
        Self {
            metrics,
            worker_id,
            admitted: 0,
        }
    }

    fn record(&mut self, admitted: usize) {
        self.admitted = self.admitted.saturating_add(admitted);
    }

    fn total(&self) -> usize {
        self.admitted
    }
}

impl Drop for UdpSendAdmissionBatch<'_> {
    fn drop(&mut self) {
        self.metrics.record_udp_send_batch(self.admitted);
        self.metrics
            .record_af_xdp_worker_send_batch(self.worker_id, self.admitted);
    }
}

fn flush_af_xdp_packet_io_stats(pending_stats: &mut AfXdpPacketIoStats, metrics: &RuntimeMetrics) {
    metrics.record_af_xdp_packet_io_stats(std::mem::take(pending_stats));
}

struct RingKickServicePolicy {
    interest: Option<Interest>,
    max_recovery_attempts: u64,
}

async fn service_pending_ring_kick<T, K, C, L, O>(
    socket: &AsyncFd<T>,
    pending: &mut bool,
    policy: RingKickServicePolicy,
    mut kick: K,
    mut cancelled: C,
    is_lossy: L,
    mut observe: O,
) -> Result<RingKickReport, RingKickServiceError>
where
    T: AsRawFd,
    K: FnMut() -> io::Result<()>,
    C: FnMut() -> bool,
    L: Fn(&io::Error) -> bool,
    O: FnMut(RingKickObservation),
{
    let mut report = RingKickReport::default();
    let mut last_transient_error = None;
    let max_recovery_attempts = policy.max_recovery_attempts.max(1);
    let mut readiness: Option<tokio::io::unix::AsyncFdReadyGuard<'_, T>> = None;
    while *pending {
        if cancelled() {
            return Err(RingKickServiceError {
                error: io::Error::from(ErrorKind::Interrupted),
                report,
            });
        }
        report.attempts = report.attempts.saturating_add(1);
        match kick() {
            Ok(()) => {
                report.successes = report.successes.saturating_add(1);
                observe(RingKickObservation::Success);
                *pending = false;
                return Ok(report);
            }
            Err(error) if is_transient_ring_kick_error(&error) => {
                report.transient_failures = report.transient_failures.saturating_add(1);
                last_transient_error = Some(error);
                if let Some(mut readiness) = readiness.take() {
                    // The syscall made the actual not-ready observation after
                    // this edge; discard the cached edge before waiting again.
                    readiness.clear_ready();
                }
                observe(RingKickObservation::TransientFailure);
            }
            Err(error) if is_lossy(&error) => {
                report.delivery_failures = report.delivery_failures.saturating_add(1);
                if report.delivery_error.is_none() {
                    report.delivery_error = Some(error);
                }
                observe(RingKickObservation::DeliveryFailure);
            }
            Err(error) => {
                observe(RingKickObservation::PermanentFailure);
                return Err(RingKickServiceError { error, report });
            }
        }

        if report.attempts >= max_recovery_attempts {
            // A delivery failure is more specific than a later transient
            // retry failure: it means a descriptor admitted to TX may already
            // have been consumed without delivery. Preserve `pending` so the
            // owning adapter retries the ring later and never recycles those
            // descriptors before completion ownership returns from the kernel.
            let error = report.delivery_error.take().unwrap_or_else(|| {
                last_transient_error
                    .take()
                    .expect("bounded ring-kick recovery follows a recoverable error")
            });
            return Err(RingKickServiceError { error, report });
        }

        tokio::task::yield_now().await;
        if cancelled() {
            return Err(RingKickServiceError {
                error: io::Error::from(ErrorKind::Interrupted),
                report,
            });
        }
        readiness = if let Some(interest) = policy.interest {
            match tokio::time::timeout(
                RING_KICK_RETRY_DELAY,
                wait_for_fd_readiness(socket, interest),
            )
            .await
            {
                Ok(Ok(readiness)) => Some(readiness),
                Ok(Err(error)) => return Err(RingKickServiceError { error, report }),
                Err(_) => None,
            }
        } else {
            // FILL wake retries must not consume or clear READABLE readiness:
            // that edge belongs to the RX-ring dequeue rather than recvfrom's
            // zero-length wake operation.
            tokio::time::sleep(RING_KICK_RETRY_DELAY).await;
            None
        };
    }
    Ok(report)
}

fn receive_pass_action(
    active_inbound: usize,
    receive_passes: usize,
    receive_pass_limit: usize,
) -> ReceivePassAction {
    if receive_passes < receive_pass_limit {
        ReceivePassAction::Continue
    } else if active_inbound > 0 {
        ReceivePassAction::ReturnBatch
    } else {
        ReceivePassAction::Yield
    }
}

fn drain_receive_slab<S, F>(slab: &mut S, received: usize, mut consume: F) -> ReceiveSlabDrain
where
    S: Slab,
    F: FnMut(xdp::Packet) -> bool,
{
    assert!(
        received <= slab.len(),
        "RX ring reported more packets than it placed in the receive slab"
    );
    let mut consumed = 0usize;
    let mut batch_full = false;
    while consumed < received {
        let packet = slab
            .pop_back()
            .expect("validated receive-slab packet count");
        consumed += 1;
        if consume(packet) {
            batch_full = true;
            break;
        }
    }
    ReceiveSlabDrain {
        consumed,
        retained: received - consumed,
        batch_full,
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RedirectConfig {
    udp_dest_port_be: u16,
    address_family: u8,
    wildcard_address: u8,
    destination_addr: [u8; 16],
}

impl RedirectConfig {
    fn for_listener(local_addr: SocketAddr) -> Self {
        let (address_family, wildcard_address, destination_addr) = match local_addr.ip() {
            IpAddr::V4(address) => {
                let mut destination_addr = [0; 16];
                destination_addr[..4].copy_from_slice(&address.octets());
                (4, u8::from(address.is_unspecified()), destination_addr)
            }
            IpAddr::V6(address) => (6, u8::from(address.is_unspecified()), address.octets()),
        };
        Self {
            udp_dest_port_be: local_addr.port().to_be(),
            address_family,
            wildcard_address,
            destination_addr,
        }
    }
}

// SAFETY: RedirectConfig is repr(C), Copy, contains only integer/byte fields,
// and has no references or invalid bit patterns.
unsafe impl Pod for RedirectConfig {}

struct XdpRedirectGuard {
    _bpf: Ebpf,
}

impl XdpRedirectGuard {
    fn attach(
        object: &Path,
        interface: &str,
        mode: XdpMode,
        local_addr: SocketAddr,
        xsk_entries: &[(u32, RawFd)],
    ) -> io::Result<Self> {
        let mut bpf = Ebpf::load_file(object).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "failed to load BoronDNS XDP redirect object {}: {error}",
                    object.display()
                ),
            )
        })?;
        {
            let map = bpf.map_mut("REDIRECT_CONFIG").ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "REDIRECT_CONFIG map missing from BoronDNS XDP redirect object",
                )
            })?;
            let mut config = Array::<_, RedirectConfig>::try_from(map).map_err(aya_error)?;
            config
                .set(0, RedirectConfig::for_listener(local_addr), 0)
                .map_err(aya_error)?;
        }
        {
            let map = bpf.map_mut("BORONDNS_XSKS").ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "BORONDNS_XSKS map missing from BoronDNS XDP redirect object",
                )
            })?;
            let mut xsk_map = XskMap::try_from(map).map_err(aya_error)?;
            for (queue_id, socket_fd) in xsk_entries {
                xsk_map.set(*queue_id, *socket_fd, 0).map_err(aya_error)?;
            }
        }
        {
            let program: &mut Xdp = bpf
                .program_mut("borondns_xdp_redirect")
                .ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "borondns_xdp_redirect program missing from BoronDNS XDP redirect object",
                    )
                })?
                .try_into()
                .map_err(aya_error)?;
            program.load().map_err(aya_error)?;
            program
                .attach(interface, xdp_flags(mode))
                .map_err(aya_error)?;
        }

        Ok(Self { _bpf: bpf })
    }
}

// SAFETY: the adapter owns the AF_XDP socket, rings, UMEM, slabs, and all
// outstanding packets as one unit. Packets are never shared concurrently; moving
// the adapter between Tokio worker threads moves the owning UMEM and packet
// handles together.
unsafe impl Send for AfXdpPacketIo {}

fn drain_completions_into(
    completion_ring: &mut xdp::CompletionRing,
    umem: &mut xdp::Umem,
    completion_ring_size: usize,
    stats: &mut AfXdpPacketIoStats,
) {
    let completed = completion_ring.dequeue(umem, completion_ring_size);
    stats.completion_dequeues = stats.completion_dequeues.saturating_add(1);
    stats.completed_packets = stats.completed_packets.saturating_add(completed as u64);
}

fn apply_tx_kick_result(result: Result<RingKickReport, RingKickServiceError>) -> io::Result<()> {
    let (mut report, service_error) = match result {
        Ok(report) => (report, None),
        Err(failure) => (failure.report, Some(failure.error)),
    };
    if let Some(error) = service_error.or_else(|| report.delivery_error.take()) {
        Err(error)
    } else {
        Ok(())
    }
}

impl AfXdpPacketIo {
    /// Returns the kernel UDP socket that receives every packet the XDP
    /// redirect deliberately passes to the ordinary network stack.
    ///
    /// The AF_XDP owner must service exactly one clone of this socket alongside
    /// the XSK queues. Redirected packets bypass the kernel socket, so the two
    /// receive paths cannot produce duplicate responses.
    pub(crate) fn kernel_fallback_socket(&self) -> Arc<UdpSocket> {
        self._udp_socket.clone()
    }

    pub(crate) fn bind(udp_socket: UdpSocket, config: &XdpConfig) -> io::Result<Self> {
        Self::bind_queues(udp_socket, config, 1)?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other("AF_XDP bind produced no packet adapters"))
    }

    pub(crate) fn bind_queues(
        udp_socket: UdpSocket,
        config: &XdpConfig,
        queue_count: usize,
    ) -> io::Result<Vec<Self>> {
        let local_addr = udp_socket.local_addr()?;
        validate_af_xdp_listener(local_addr)?;
        if config.tx_wakeup_interval != 1 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "xdp.tx_wakeup_interval must be 1; the current AF_XDP ring API does not expose the kernel needs-wakeup flag",
            ));
        }
        let prepared = prepare_xdp_config(config).map_err(xdp_config_error)?;
        if (config.completion_ring_size as usize) < prepared.batch_size {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "xdp.completion_ring_size must be at least the effective AF_XDP batch size {}",
                    prepared.batch_size
                ),
            ));
        }
        if prepared.interface.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "xdp.interface must be set for AF_XDP",
            ));
        }
        let redirect_object = config.redirect_object.as_deref().ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "xdp.redirect_object must be set for AF_XDP",
            )
        })?;
        let ifname = CString::new(prepared.interface.as_str()).map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "xdp.interface contains NUL byte")
        })?;
        let nic = xdp::nic::NicIndex::lookup_by_name(&ifname)?
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "xdp.interface was not found"))?;
        let caps = nic.query_capabilities()?;
        if config.zero_copy == XdpZeroCopyMode::Require && !caps.zero_copy.is_available() {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "xdp.zero_copy = \"require\" but interface does not report zero-copy support",
            ));
        }
        let queue_ids = config
            .effective_queue_ids(queue_count)
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error.to_string()))?;
        for queue_id in &queue_ids {
            if *queue_id >= caps.queue_count {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "AF_XDP queue id {} is outside interface queue count {}",
                        queue_id, caps.queue_count
                    ),
                ));
            }
        }

        let udp_socket = Arc::new(udp_socket);
        let mut adapters = Vec::with_capacity(queue_ids.len());
        let mut xsk_entries = Vec::with_capacity(queue_ids.len());
        for queue_id in queue_ids {
            let (adapter, socket_fd) =
                Self::bind_queue(udp_socket.clone(), local_addr, config, nic, queue_id)?;
            adapters.push(adapter);
            xsk_entries.push((queue_id, socket_fd));
        }
        let redirect = Arc::new(XdpRedirectGuard::attach(
            redirect_object,
            &prepared.interface,
            config.mode,
            local_addr,
            &xsk_entries,
        )?);
        for adapter in &mut adapters {
            adapter._redirect = Some(redirect.clone());
        }
        Ok(adapters)
    }

    fn bind_queue(
        udp_socket: Arc<UdpSocket>,
        local_addr: SocketAddr,
        config: &XdpConfig,
        nic: xdp::nic::NicIndex,
        queue_id: u32,
    ) -> io::Result<(Self, RawFd)> {
        let mut prepared = prepare_xdp_config(config).map_err(xdp_config_error)?;
        prepared.queue_id = queue_id;
        let mut umem = xdp::Umem::map(prepared.umem)?;
        let mut builder = XdpSocketBuilder::new().map_err(xdp_socket_error)?;
        let (mut rings, mut bind_flags) = builder
            .build_wakable_rings(&umem, prepared.rings)
            .map_err(xdp_socket_error)?;
        match config.zero_copy {
            XdpZeroCopyMode::Auto => {}
            XdpZeroCopyMode::Require => bind_flags.force_zerocopy(),
            XdpZeroCopyMode::Disable => bind_flags.force_copy(),
        }
        let socket = builder
            .bind(nic, prepared.queue_id, bind_flags)
            .map_err(xdp_socket_error)?;
        let socket_fd = socket.raw_fd();
        let socket = AsyncFd::new(socket)?;
        let rx_ring = rings
            .rx_ring
            .take()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "AF_XDP RX ring missing"))?;
        let tx_ring = rings
            .tx_ring
            .take()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "AF_XDP TX ring missing"))?;

        let fill_ring_size = config.fill_ring_size as usize;
        // SAFETY: all fill-ring frame addresses are allocated from `umem`, and
        // the UMEM, rings, and socket are stored in one adapter so UMEM outlives
        // the AF_XDP rings that reference it.
        let initially_filled = unsafe {
            rings
                .fill_ring
                .enqueue(&mut umem, fill_ring_size, false)
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("failed to populate AF_XDP fill ring: {error}"),
                    )
                })?
        };
        let mut fill_kick_pending = false;
        mark_ring_kick_pending(&mut fill_kick_pending, initially_filled);
        if fill_kick_pending {
            match kick_af_xdp_ring(socket_fd, RingKickKind::Fill) {
                Ok(()) => fill_kick_pending = false,
                Err(error) if is_transient_ring_kick_error(&error) => {
                    // Preserve the admitted addresses and let the first async
                    // receive pass retry this wake with cancellation support.
                }
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("failed to wake populated AF_XDP fill ring: {error}"),
                    ));
                }
            }
        }

        Ok((
            Self {
                _udp_socket: udp_socket,
                socket,
                _redirect: None,
                rx_ring,
                tx_ring,
                fill_ring: rings.fill_ring,
                completion_ring: rings.completion_ring,
                umem,
                local_addr,
                batch_size: prepared.batch_size,
                rx_drain_passes: config.rx_drain_passes,
                fill_ring_size,
                completion_ring_size: config.completion_ring_size as usize,
                inbound: (0..prepared.batch_size)
                    .map(|_| UdpInbound::new())
                    .collect(),
                active_inbound: 0,
                frames: Vec::with_capacity(prepared.batch_size),
                recv_slab: HeapSlab::with_capacity(prepared.batch_size),
                tx_slab: HeapSlab::with_capacity(prepared.batch_size),
                tx_kick_pending: false,
                fill_kick_pending,
                pending_stats: AfXdpPacketIoStats::default(),
            },
            socket_fd,
        ))
    }

    fn drain_completions(&mut self) {
        drain_completions_into(
            &mut self.completion_ring,
            &mut self.umem,
            self.completion_ring_size,
            &mut self.pending_stats,
        );
    }

    fn release_unsent_frames(&mut self) {
        for frame in self.frames.drain(..).flatten() {
            self.umem.free_packet(frame.packet);
        }
    }

    async fn service_tx_kick(
        &mut self,
        admission_open: Option<&std::sync::atomic::AtomicBool>,
        metrics: Option<&RuntimeMetrics>,
    ) -> io::Result<()> {
        if self.tx_kick_pending {
            // An older kick can be pending precisely because the completion
            // ring was full. Return any completed frames before the first
            // retry so CQ pressure cannot make recovery self-deadlock.
            self.drain_completions();
            if let Some(metrics) = metrics {
                self.flush_pending_stats(metrics);
            }
        }
        let socket_fd = self.socket.get_ref().as_raw_fd();
        let result = service_pending_ring_kick(
            &self.socket,
            &mut self.tx_kick_pending,
            // AF_XDP poll itself can drive TX and discards xmit's errno. Use
            // timed backoff here so every pending-ring progress/error result
            // comes from an explicit kick and remains exactly observable.
            RingKickServicePolicy {
                interest: None,
                max_recovery_attempts: RING_KICK_MAX_RECOVERY_ATTEMPTS,
            },
            || kick_af_xdp_ring(socket_fd, RingKickKind::Tx),
            || admission_open.is_some_and(|open| !open.load(std::sync::atomic::Ordering::Acquire)),
            is_lossy_tx_kick_error,
            |observation| {
                // Commit the syscall observation before the next await. The
                // outer UDP shutdown deadline may drop this future while it is
                // backing off, so deferred report accounting is not durable.
                if let Some(metrics) = metrics {
                    metrics.record_af_xdp_tx_kick_observation(
                        matches!(observation, RingKickObservation::Success),
                        matches!(observation, RingKickObservation::TransientFailure),
                        matches!(observation, RingKickObservation::DeliveryFailure),
                    );
                } else {
                    record_tx_kick_observation(&mut self.pending_stats, observation);
                }
                if observation.requires_completion_drain() {
                    drain_completions_into(
                        &mut self.completion_ring,
                        &mut self.umem,
                        self.completion_ring_size,
                        &mut self.pending_stats,
                    );
                    if let Some(metrics) = metrics {
                        flush_af_xdp_packet_io_stats(&mut self.pending_stats, metrics);
                    }
                }
            },
        )
        .await;
        apply_tx_kick_result(result)
    }

    async fn service_fill_kick(
        &mut self,
        admission_open: Option<&std::sync::atomic::AtomicBool>,
    ) -> io::Result<()> {
        let socket_fd = self.socket.get_ref().as_raw_fd();
        service_pending_ring_kick(
            &self.socket,
            &mut self.fill_kick_pending,
            RingKickServicePolicy {
                interest: None,
                max_recovery_attempts: RING_KICK_MAX_RECOVERY_ATTEMPTS,
            },
            || kick_af_xdp_ring(socket_fd, RingKickKind::Fill),
            || admission_open.is_some_and(|open| !open.load(std::sync::atomic::Ordering::Acquire)),
            |_| false,
            |_| {},
        )
        .await
        .map(|_| ())
        .map_err(|failure| failure.error)
    }

    async fn replenish_fill_ring(
        &mut self,
        admission_open: Option<&std::sync::atomic::AtomicBool>,
    ) -> io::Result<()> {
        // Finish an earlier wake before admitting more addresses. In
        // particular, a previous wake error may have occurred after the ring
        // consumed every currently free UMEM frame, leaving a later enqueue
        // with no new address on which to piggyback another wake.
        self.service_fill_kick(admission_open).await?;
        // SAFETY: the fill ring and UMEM are owned by this adapter. Packets
        // returned to UMEM are not accessed again before being re-enqueued.
        let queued = unsafe {
            self.fill_ring
                .enqueue(&mut self.umem, self.fill_ring_size, false)
        }?;
        mark_ring_kick_pending(&mut self.fill_kick_pending, queued);
        self.service_fill_kick(admission_open).await
    }

    fn drain_tx_slab_to_umem(&mut self) {
        while let Some(packet) = self.tx_slab.pop_back() {
            self.umem.free_packet(packet);
        }
    }

    fn consume_received_packets(&mut self, received: usize) -> ReceiveSlabDrain {
        debug_assert!(self.active_inbound < self.batch_size);
        let local_addr = self.local_addr;
        let batch_size = self.batch_size;
        let active_inbound = &mut self.active_inbound;
        let inbound = &mut self.inbound;
        let frames = &mut self.frames;
        let recv_slab = &mut self.recv_slab;
        let umem = &mut self.umem;
        let pending_stats = &mut self.pending_stats;

        drain_receive_slab(recv_slab, received, |packet| {
            let frame = match parse_udp_ip_frame(&packet) {
                Ok(frame) => frame,
                Err(_) => {
                    pending_stats.rx_parse_errors += 1;
                    umem.free_packet(packet);
                    return false;
                }
            };
            if !destination_matches_listener(local_addr, frame.destination_addr(&packet)) {
                umem.free_packet(packet);
                return false;
            }
            let payload = frame.payload();
            if payload.len() > UDP_PACKET_BUFFER_LEN {
                umem.free_packet(packet);
                return false;
            }
            if *active_inbound == inbound.len() {
                inbound.push(UdpInbound::new());
            }

            let frame_index = frames.len();
            let peer = frame.source_addr(&packet);
            let admitted = &mut inbound[*active_inbound];
            let payload_len = payload.len();
            admitted.buffer[..payload_len].copy_from_slice(&packet[payload]);
            admitted.len = payload_len;
            admitted.peer = peer;
            admitted.target = target_for_frame(frame_index);
            frames.push(Some(ReceivedFrame { packet, frame }));
            *active_inbound += 1;
            *active_inbound == batch_size
        })
    }

    fn recycle_received_packets(&mut self, received: usize) {
        let umem = &mut self.umem;
        let drained = drain_receive_slab(&mut self.recv_slab, received, |packet| {
            umem.free_packet(packet);
            false
        });
        debug_assert_eq!(drained.consumed, received);
        debug_assert_eq!(drained.retained, 0);
        debug_assert!(!drained.batch_full);
    }

    fn flush_pending_stats(&mut self, metrics: &RuntimeMetrics) {
        flush_af_xdp_packet_io_stats(&mut self.pending_stats, metrics);
    }
}

/// Waits for one readiness edge. `AsyncFd::ready` is cancel safe, so aborting
/// an idle AF_XDP worker does not leave a blocking poll on a Tokio executor
/// thread. Callers clear the guard only after their ring operation observes an
/// empty ring.
async fn wait_for_fd_readiness<T>(
    fd: &AsyncFd<T>,
    interest: Interest,
) -> io::Result<tokio::io::unix::AsyncFdReadyGuard<'_, T>>
where
    T: AsRawFd,
{
    fd.ready(interest).await
}

impl PacketIo for AfXdpPacketIo {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn is_af_xdp(&self) -> bool {
        true
    }

    async fn service_pending_send(
        &mut self,
        admission_open: &std::sync::atomic::AtomicBool,
        metrics: &RuntimeMetrics,
    ) -> io::Result<()> {
        self.service_tx_kick(Some(admission_open), Some(metrics))
            .await
    }

    async fn recv_batch(
        &mut self,
        admission_open: &std::sync::atomic::AtomicBool,
    ) -> io::Result<&[UdpInbound]> {
        self.release_unsent_frames();
        self.drain_completions();
        self.replenish_fill_ring(Some(admission_open)).await?;
        self.active_inbound = 0;
        self.frames.clear();
        let mut receive_passes = 0usize;

        loop {
            if !admission_open.load(std::sync::atomic::Ordering::Acquire) {
                let pending = self.recv_slab.len();
                self.recycle_received_packets(pending);
                if self.active_inbound > 0 {
                    return Ok(&self.inbound[..self.active_inbound]);
                }
                return Err(io::Error::from(ErrorKind::Interrupted));
            }

            // A full batch can leave the tail of its final RX dequeue in the
            // slab. Consume that explicitly retained tail before waiting for
            // readiness or dequeuing any newer frames.
            let pending = self.recv_slab.len();
            if pending > 0 {
                let drained = self.consume_received_packets(pending);
                debug_assert_eq!(drained.consumed + drained.retained, pending);
                if drained.batch_full {
                    self.replenish_fill_ring(Some(admission_open)).await?;
                    return Ok(&self.inbound[..self.active_inbound]);
                }
                debug_assert_eq!(drained.retained, 0);
                // Publish this older partial batch now. Dequeuing into the
                // newly empty slab in the same call could fill the batch and
                // replace the just-consumed tail with another retained tail
                // forever under sustained load.
                if self.active_inbound > 0 {
                    return Ok(&self.inbound[..self.active_inbound]);
                }
                self.replenish_fill_ring(Some(admission_open)).await?;
                continue;
            }

            // SAFETY: packets returned by the RX ring are either admitted into
            // `self.frames`, returned to this adapter's UMEM, or explicitly
            // retained in `self.recv_slab`. Retained packets are consumed at
            // the top of the next loop/call before any readiness wait or RX
            // dequeue, and no packet outlives the owning UMEM.
            let received = if self.active_inbound == 0 {
                let mut readiness = wait_for_fd_readiness(&self.socket, Interest::READABLE).await?;
                let received = unsafe { self.rx_ring.recv(&self.umem, &mut self.recv_slab) };
                if received == 0 {
                    // A zero-sized dequeue is the AF_XDP ring equivalent of
                    // `WouldBlock`; only then may Tokio's cached edge be
                    // cleared.
                    readiness.clear_ready();
                }
                received
            } else {
                // After the first ready packet, drain the userspace ring
                // without awaiting another edge. This keeps batching bounded
                // by `rx_drain_passes` and avoids delaying a partial batch.
                // SAFETY: the RX ring, receive slab, and UMEM are owned by this
                // adapter, and every dequeued packet is admitted, recycled, or
                // retained in the slab before the owning UMEM can be dropped.
                let received = unsafe { self.rx_ring.recv(&self.umem, &mut self.recv_slab) };
                if received == 0 {
                    // The empty dequeue is the actual not-ready observation.
                    // Clear any cached edge without waiting for a new packet.
                    let _ = self.socket.try_io(Interest::READABLE, |_| {
                        Err::<(), _>(io::Error::from(ErrorKind::WouldBlock))
                    });
                }
                received
            };
            // The readiness edge (or optimistic ring-drain pass) can race the
            // admission boundary. Frames from this dequeue are not published
            // until a post-dequeue acquire observes the boundary still open.
            // If it closed, discard only this pass and preserve any batch that
            // was admitted by an earlier pass.
            if ensure_udp_admission_open(admission_open).is_err() {
                self.recycle_received_packets(received);
                if self.active_inbound > 0 {
                    return Ok(&self.inbound[..self.active_inbound]);
                }
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            self.pending_stats.rx_recv_calls += 1;
            if received == 0 {
                self.pending_stats.rx_empty_recv_calls += 1;
            } else {
                self.pending_stats.rx_received_packets += received as u64;
            }
            if received == 0 && self.active_inbound > 0 {
                return Ok(&self.inbound[..self.active_inbound]);
            }
            if received > 0 {
                receive_passes = receive_passes.wrapping_add(1);
            }
            let drained = self.consume_received_packets(received);
            debug_assert_eq!(drained.consumed + drained.retained, received);
            if drained.batch_full {
                self.replenish_fill_ring(Some(admission_open)).await?;
                return Ok(&self.inbound[..self.active_inbound]);
            }
            debug_assert_eq!(drained.retained, 0);
            match receive_pass_action(self.active_inbound, receive_passes, self.rx_drain_passes) {
                ReceivePassAction::Continue => {}
                ReceivePassAction::ReturnBatch => {
                    return Ok(&self.inbound[..self.active_inbound]);
                }
                ReceivePassAction::Yield => {
                    self.replenish_fill_ring(Some(admission_open)).await?;
                    tokio::task::yield_now().await;
                    receive_passes = 0;
                    continue;
                }
            }
            self.replenish_fill_ring(Some(admission_open)).await?;
        }
    }

    async fn send_batch(
        &mut self,
        outbound: &[UdpOutbound],
        metrics: &RuntimeMetrics,
        worker_id: usize,
    ) -> Result<usize, PacketIoSendError> {
        let mut admitted_batch = UdpSendAdmissionBatch::new(metrics, worker_id);
        let mut pending_send_metrics = VecDeque::with_capacity(outbound.len());
        // RX and prior completion observations must be durable before the
        // first cancellable TX-kick wait in this logical send scope.
        self.flush_pending_stats(metrics);
        if let Err(error) = self.service_tx_kick(None, Some(metrics)).await {
            self.flush_pending_stats(metrics);
            return Err(PacketIoSendError::new(error, admitted_batch.total()));
        }
        for (packet_index, packet) in outbound.iter().enumerate() {
            let UdpPacketTarget::AfXdp { frame_index } = packet.target else {
                return Err(PacketIoSendError::new(
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        "AF_XDP backend cannot send standard UDP socket target",
                    ),
                    admitted_batch.total(),
                ));
            };
            let Some(slot) = self.frames.get_mut(frame_index) else {
                return Err(PacketIoSendError::new(
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        "AF_XDP response referenced an unknown frame",
                    ),
                    admitted_batch.total(),
                ));
            };
            let Some(mut frame) = slot.take() else {
                continue;
            };
            let send_started = packet
                .query_metrics
                .as_ref()
                .and_then(|_| metrics.start_pipeline_timer());
            let write_result = if packet.benchmark_fixed_response {
                write_benchmark_fixed_dns_response(&mut frame.packet, frame.frame)
            } else {
                write_udp_ip_response(&mut frame.packet, frame.frame, &packet.response)
            };
            if let Err(error) = write_result {
                self.umem.free_packet(frame.packet);
                self.drain_tx_slab_to_umem();
                self.release_unsent_frames();
                return Err(PacketIoSendError::new(
                    io::Error::new(ErrorKind::InvalidData, error.to_string()),
                    admitted_batch.total(),
                ));
            }
            if let Some(overflow) = self.tx_slab.push_front(frame.packet) {
                self.umem.free_packet(overflow);
                self.drain_tx_slab_to_umem();
                self.release_unsent_frames();
                return Err(PacketIoSendError::new(
                    io::Error::new(ErrorKind::OutOfMemory, "AF_XDP TX slab reached capacity"),
                    admitted_batch.total(),
                ));
            }
            pending_send_metrics.push_back((packet_index, send_started));
        }

        self.release_unsent_frames();
        while !self.tx_slab.is_empty() {
            // SAFETY: all packets in `tx_slab` came from this adapter's UMEM,
            // and the UMEM outlives the socket and TX ring.
            let pending_before = self.tx_slab.len();
            let send_result = unsafe { self.tx_ring.send(&mut self.tx_slab, false) };
            let admitted = pending_before - self.tx_slab.len();
            admitted_batch.record(admitted);
            record_admitted_send_metrics(&mut pending_send_metrics, outbound, admitted, metrics);
            match send_result {
                Ok(queued) if queued > 0 => {
                    debug_assert_eq!(queued, admitted);
                    self.pending_stats.tx_send_calls += 1;
                    self.pending_stats.tx_queued_packets += queued as u64;
                    mark_ring_kick_pending(&mut self.tx_kick_pending, admitted);
                    // The outer UDP shutdown deadline may drop the kick future.
                    // Commit ring admission before crossing that await while
                    // retaining descriptor ownership in `tx_kick_pending`.
                    self.flush_pending_stats(metrics);
                    if let Err(error) = self.service_tx_kick(None, Some(metrics)).await {
                        self.flush_pending_stats(metrics);
                        self.drain_tx_slab_to_umem();
                        return Err(PacketIoSendError::new(error, admitted_batch.total()));
                    }
                    self.drain_completions();
                }
                Ok(_) => {
                    self.pending_stats.tx_send_calls += 1;
                    self.pending_stats.tx_empty_send_calls += 1;
                    self.drain_completions();
                    loop {
                        self.pending_stats.tx_poll_write_calls += 1;
                        self.flush_pending_stats(metrics);
                        let mut readiness =
                            match wait_for_fd_readiness(&self.socket, Interest::WRITABLE).await {
                                Ok(readiness) => readiness,
                                Err(error) => {
                                    self.flush_pending_stats(metrics);
                                    self.drain_tx_slab_to_umem();
                                    return Err(PacketIoSendError::new(
                                        error,
                                        admitted_batch.total(),
                                    ));
                                }
                            };
                        self.pending_stats.tx_poll_write_ready += 1;
                        // SAFETY: all packets in `tx_slab` came from this
                        // adapter's UMEM, which outlives the TX ring.
                        let pending_before = self.tx_slab.len();
                        let send_result = unsafe { self.tx_ring.send(&mut self.tx_slab, false) };
                        let admitted = pending_before - self.tx_slab.len();
                        admitted_batch.record(admitted);
                        record_admitted_send_metrics(
                            &mut pending_send_metrics,
                            outbound,
                            admitted,
                            metrics,
                        );
                        match send_result {
                            Ok(0) => {
                                debug_assert_eq!(admitted, 0);
                                self.pending_stats.tx_send_calls += 1;
                                self.pending_stats.tx_empty_send_calls += 1;
                                // The empty enqueue is the actual not-ready
                                // observation. Clear the cached edge and await
                                // another without blocking this executor.
                                readiness.clear_ready();
                                self.flush_pending_stats(metrics);
                            }
                            Ok(queued) => {
                                debug_assert_eq!(queued, admitted);
                                self.pending_stats.tx_send_calls += 1;
                                self.pending_stats.tx_queued_packets += queued as u64;
                                mark_ring_kick_pending(&mut self.tx_kick_pending, admitted);
                                debug_assert!(queued > 0);
                                drop(readiness);
                                self.flush_pending_stats(metrics);
                                if let Err(error) = self.service_tx_kick(None, Some(metrics)).await
                                {
                                    self.flush_pending_stats(metrics);
                                    self.drain_tx_slab_to_umem();
                                    return Err(PacketIoSendError::new(
                                        error,
                                        admitted_batch.total(),
                                    ));
                                }
                                self.drain_completions();
                                break;
                            }
                            Err(error) => {
                                self.pending_stats.tx_send_calls += 1;
                                self.pending_stats.tx_queued_packets += admitted as u64;
                                if admitted == 0 {
                                    self.pending_stats.tx_empty_send_calls += 1;
                                }
                                if admitted > 0 {
                                    mark_ring_kick_pending(&mut self.tx_kick_pending, admitted);
                                }
                                self.flush_pending_stats(metrics);
                                self.drain_tx_slab_to_umem();
                                return Err(PacketIoSendError::new(error, admitted_batch.total()));
                            }
                        }
                    }
                }
                Err(error) => {
                    self.pending_stats.tx_send_calls += 1;
                    self.pending_stats.tx_queued_packets += admitted as u64;
                    if admitted == 0 {
                        self.pending_stats.tx_empty_send_calls += 1;
                    }
                    if admitted > 0 {
                        mark_ring_kick_pending(&mut self.tx_kick_pending, admitted);
                    }
                    self.flush_pending_stats(metrics);
                    self.drain_tx_slab_to_umem();
                    return Err(PacketIoSendError::new(error, admitted_batch.total()));
                }
            }
        }
        self.drain_completions();
        self.flush_pending_stats(metrics);
        if let Err(error) = self.replenish_fill_ring(None).await {
            self.flush_pending_stats(metrics);
            return Err(PacketIoSendError::new(error, admitted_batch.total()));
        }
        self.flush_pending_stats(metrics);
        Ok(admitted_batch.total())
    }
}

fn record_admitted_send_metrics(
    pending: &mut VecDeque<(usize, Option<std::time::Instant>)>,
    outbound: &[UdpOutbound],
    admitted: usize,
    metrics: &RuntimeMetrics,
) {
    for _ in 0..admitted {
        let (packet_index, started) = pending
            .pop_front()
            .expect("TX ring cannot admit more packets than were staged");
        let packet = &outbound[packet_index];
        if let (Some(query_metrics), Some(started)) = (&packet.query_metrics, started) {
            record_query_send_metric(query_metrics, &packet.response, metrics, started.elapsed());
        }
    }
}

fn validate_af_xdp_listener(local_addr: SocketAddr) -> io::Result<()> {
    if local_addr.ip().is_unspecified() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "AF_XDP listener {local_addr} must use a concrete local IP address; wildcard listeners can intercept non-local ingress traffic before kernel routing"
            ),
        ));
    }
    Ok(())
}

fn xdp_config_error(error: xdp::error::Error) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, error.to_string())
}

fn xdp_socket_error(error: xdp::socket::SocketError) -> io::Error {
    io::Error::other(error.to_string())
}

fn aya_error(error: impl fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn xdp_flags(mode: XdpMode) -> XdpFlags {
    match mode {
        XdpMode::Skb => XdpFlags::SKB_MODE,
        XdpMode::Drv => XdpFlags::DRV_MODE,
        XdpMode::Hw => XdpFlags::HW_MODE,
    }
}

fn destination_matches_listener(listener: SocketAddr, destination: SocketAddr) -> bool {
    if listener.port() != destination.port() {
        return false;
    }
    // AF_XDP wildcard binds are deliberately family-specific. Do not infer
    // dual-stack behavior from an IPv6 wildcard socket at this lab boundary.
    match (listener.ip(), destination.ip()) {
        (IpAddr::V4(listener), IpAddr::V4(destination)) => {
            listener.is_unspecified() || listener == destination
        }
        (IpAddr::V6(listener), IpAddr::V6(destination)) => {
            listener.is_unspecified() || listener == destination
        }
        _ => false,
    }
}

pub(crate) fn parse_udp_ipv4_frame(frame: &[u8]) -> Result<UdpIpv4Frame, AfXdpFrameError> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(AfXdpFrameError::ShortEthernet);
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_IPV4 {
        return Err(AfXdpFrameError::UnsupportedEtherType(ethertype));
    }

    let ipv4_header_offset = ETHERNET_HEADER_LEN;
    if frame.len() < ipv4_header_offset + IPV4_MIN_HEADER_LEN {
        return Err(AfXdpFrameError::ShortIpv4);
    }
    let version_ihl = frame[ipv4_header_offset];
    let version = version_ihl >> 4;
    let ihl = usize::from(version_ihl & 0x0f) * 4;
    if version != 4 || ihl < IPV4_MIN_HEADER_LEN {
        return Err(AfXdpFrameError::InvalidIpv4Header);
    }
    if frame.len() < ipv4_header_offset + ihl {
        return Err(AfXdpFrameError::ShortIpv4);
    }
    if ipv4_checksum(&frame[ipv4_header_offset..ipv4_header_offset + ihl]) != 0 {
        return Err(AfXdpFrameError::InvalidIpv4Checksum);
    }
    if frame[ipv4_header_offset + 9] != IP_PROTOCOL_UDP {
        return Err(AfXdpFrameError::NotUdp);
    }
    let source = ipv4_addr_at(frame, ipv4_header_offset + 12);
    if invalid_ipv4_source(source) {
        return Err(AfXdpFrameError::InvalidSourceAddress);
    }

    let fragment =
        u16::from_be_bytes([frame[ipv4_header_offset + 6], frame[ipv4_header_offset + 7]]);
    if fragment & 0x3fff != 0 {
        return Err(AfXdpFrameError::FragmentedIpv4);
    }

    let total_len = usize::from(u16::from_be_bytes([
        frame[ipv4_header_offset + 2],
        frame[ipv4_header_offset + 3],
    ]));
    if total_len < ihl + UDP_HEADER_LEN || frame.len() < ipv4_header_offset + total_len {
        return Err(AfXdpFrameError::InvalidIpv4TotalLength);
    }

    let udp_header_offset = ipv4_header_offset + ihl;
    if frame.len() < udp_header_offset + UDP_HEADER_LEN {
        return Err(AfXdpFrameError::ShortUdp);
    }
    let udp_len = usize::from(u16::from_be_bytes([
        frame[udp_header_offset + 4],
        frame[udp_header_offset + 5],
    ]));
    if udp_len < UDP_HEADER_LEN || udp_len > total_len - ihl {
        return Err(AfXdpFrameError::InvalidUdpLength);
    }
    let payload_start = udp_header_offset + UDP_HEADER_LEN;
    let payload_end = payload_start + udp_len - UDP_HEADER_LEN;
    let udp_checksum =
        u16::from_be_bytes([frame[udp_header_offset + 6], frame[udp_header_offset + 7]]);
    if udp_checksum != 0
        && udp_ipv4_checksum(frame, ipv4_header_offset, udp_header_offset, udp_len) != 0xffff
    {
        return Err(AfXdpFrameError::InvalidUdpChecksum);
    }

    Ok(UdpIpv4Frame {
        ipv4_header_offset,
        ipv4_header_len: ihl,
        udp_header_offset,
        payload: payload_start..payload_end,
    })
}

pub(crate) fn parse_udp_ipv6_frame(frame: &[u8]) -> Result<UdpIpv6Frame, AfXdpFrameError> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(AfXdpFrameError::ShortEthernet);
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_IPV6 {
        return Err(AfXdpFrameError::UnsupportedEtherType(ethertype));
    }

    let ipv6_header_offset = ETHERNET_HEADER_LEN;
    if frame.len() < ipv6_header_offset + IPV6_HEADER_LEN {
        return Err(AfXdpFrameError::ShortIpv6);
    }
    let version = frame[ipv6_header_offset] >> 4;
    if version != 6 {
        return Err(AfXdpFrameError::ShortIpv6);
    }
    let source = ipv6_addr_at(frame, ipv6_header_offset + 8);
    if source.is_unspecified() || source.is_multicast() || source.is_loopback() {
        return Err(AfXdpFrameError::InvalidSourceAddress);
    }
    let payload_len = usize::from(u16::from_be_bytes([
        frame[ipv6_header_offset + 4],
        frame[ipv6_header_offset + 5],
    ]));
    let next_header = frame[ipv6_header_offset + 6];
    if next_header != IP_PROTOCOL_UDP {
        return Err(AfXdpFrameError::UnsupportedIpv6NextHeader(next_header));
    }
    if payload_len < UDP_HEADER_LEN
        || frame.len() < ipv6_header_offset + IPV6_HEADER_LEN + payload_len
    {
        return Err(AfXdpFrameError::InvalidIpv6PayloadLength);
    }

    let udp_header_offset = ipv6_header_offset + IPV6_HEADER_LEN;
    let udp_len = usize::from(u16::from_be_bytes([
        frame[udp_header_offset + 4],
        frame[udp_header_offset + 5],
    ]));
    if udp_len < UDP_HEADER_LEN || udp_len != payload_len {
        return Err(AfXdpFrameError::InvalidUdpLength);
    }
    let payload_start = udp_header_offset + UDP_HEADER_LEN;
    let payload_end = payload_start + udp_len - UDP_HEADER_LEN;
    let udp_checksum =
        u16::from_be_bytes([frame[udp_header_offset + 6], frame[udp_header_offset + 7]]);
    if udp_checksum == 0 {
        return Err(AfXdpFrameError::MissingIpv6UdpChecksum);
    }
    if udp_ipv6_checksum(frame, udp_header_offset, udp_len) != 0xffff {
        return Err(AfXdpFrameError::InvalidUdpChecksum);
    }

    Ok(UdpIpv6Frame {
        ipv6_header_offset,
        udp_header_offset,
        payload: payload_start..payload_end,
    })
}

pub(crate) fn parse_udp_ip_frame(frame: &[u8]) -> Result<UdpIpFrame, AfXdpFrameError> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(AfXdpFrameError::ShortEthernet);
    }

    match u16::from_be_bytes([frame[12], frame[13]]) {
        ETHERTYPE_IPV4 => parse_udp_ipv4_frame(frame).map(UdpIpFrame::Ipv4),
        ETHERTYPE_IPV6 => parse_udp_ipv6_frame(frame).map(UdpIpFrame::Ipv6),
        ethertype => Err(AfXdpFrameError::UnsupportedEtherType(ethertype)),
    }
}

pub(crate) fn rewrite_udp_ipv4_response_headers(
    frame: &mut [u8],
    packet: UdpIpv4Frame,
    response_len: usize,
) -> Result<usize, AfXdpFrameError> {
    if response_len > usize::from(u16::MAX) - packet.ipv4_header_len - UDP_HEADER_LEN {
        return Err(AfXdpFrameError::ResponseTooLarge);
    }
    let packet_len = packet.ipv4_header_len + UDP_HEADER_LEN + response_len;
    let frame_len = ETHERNET_HEADER_LEN + packet_len;
    if frame.len() < frame_len || packet.payload.start + response_len > frame.len() {
        return Err(AfXdpFrameError::ResponseTooLarge);
    }

    for index in 0..6 {
        frame.swap(index, index + 6);
    }
    for index in 0..4 {
        frame.swap(
            packet.ipv4_header_offset + 12 + index,
            packet.ipv4_header_offset + 16 + index,
        );
    }
    for index in 0..2 {
        frame.swap(
            packet.udp_header_offset + index,
            packet.udp_header_offset + 2 + index,
        );
    }

    // Do not reflect request-owned IPv4 state into the response. Keep the
    // parsed header width so the UDP payload remains in place, but make any
    // request options an EOL followed by zero padding. Mark the response atomic
    // with DF so RFC 6864 permits an identification value of zero.
    frame[packet.ipv4_header_offset] =
        0x40 | u8::try_from(packet.ipv4_header_len / 4).expect("validated IPv4 IHL");
    frame[packet.ipv4_header_offset + 1] = 0;
    frame[packet.ipv4_header_offset + 4..packet.ipv4_header_offset + 8]
        .copy_from_slice(&[0, 0, 0x40, 0]);
    frame[packet.ipv4_header_offset + 8] = RESPONSE_IP_HOP_LIMIT;
    frame[packet.ipv4_header_offset + 9] = IP_PROTOCOL_UDP;
    frame[packet.ipv4_header_offset + IPV4_MIN_HEADER_LEN
        ..packet.ipv4_header_offset + packet.ipv4_header_len]
        .fill(0);

    let total_len = u16::try_from(packet_len)
        .map_err(|_| AfXdpFrameError::ResponseTooLarge)?
        .to_be_bytes();
    frame[packet.ipv4_header_offset + 2..packet.ipv4_header_offset + 4].copy_from_slice(&total_len);
    let udp_len = u16::try_from(UDP_HEADER_LEN + response_len)
        .map_err(|_| AfXdpFrameError::ResponseTooLarge)?
        .to_be_bytes();
    frame[packet.udp_header_offset + 4..packet.udp_header_offset + 6].copy_from_slice(&udp_len);
    frame[packet.udp_header_offset + 6..packet.udp_header_offset + 8].copy_from_slice(&[0, 0]);
    let udp_checksum = nonzero_udp_checksum(udp_ipv4_checksum(
        frame,
        packet.ipv4_header_offset,
        packet.udp_header_offset,
        UDP_HEADER_LEN + response_len,
    ));
    frame[packet.udp_header_offset + 6..packet.udp_header_offset + 8]
        .copy_from_slice(&udp_checksum.to_be_bytes());

    frame[packet.ipv4_header_offset + 10..packet.ipv4_header_offset + 12].copy_from_slice(&[0, 0]);
    let checksum = ipv4_checksum(
        &frame[packet.ipv4_header_offset..packet.ipv4_header_offset + packet.ipv4_header_len],
    );
    frame[packet.ipv4_header_offset + 10..packet.ipv4_header_offset + 12]
        .copy_from_slice(&checksum.to_be_bytes());

    Ok(frame_len)
}

pub(crate) fn rewrite_udp_ipv6_response_headers(
    frame: &mut [u8],
    packet: UdpIpv6Frame,
    response_len: usize,
) -> Result<usize, AfXdpFrameError> {
    if response_len > usize::from(u16::MAX) - UDP_HEADER_LEN {
        return Err(AfXdpFrameError::ResponseTooLarge);
    }
    let udp_len = UDP_HEADER_LEN + response_len;
    let frame_len = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + udp_len;
    if frame.len() < frame_len || packet.payload.start + response_len > frame.len() {
        return Err(AfXdpFrameError::ResponseTooLarge);
    }

    for index in 0..6 {
        frame.swap(index, index + 6);
    }
    for index in 0..16 {
        frame.swap(
            packet.ipv6_header_offset + 8 + index,
            packet.ipv6_header_offset + 24 + index,
        );
    }
    for index in 0..2 {
        frame.swap(
            packet.udp_header_offset + index,
            packet.udp_header_offset + 2 + index,
        );
    }

    // Traffic class, flow label, and hop limit belong to this server's
    // response rather than to the received query.
    frame[packet.ipv6_header_offset..packet.ipv6_header_offset + 4]
        .copy_from_slice(&[0x60, 0, 0, 0]);
    frame[packet.ipv6_header_offset + 6] = IP_PROTOCOL_UDP;
    frame[packet.ipv6_header_offset + 7] = RESPONSE_IP_HOP_LIMIT;

    let payload_len = u16::try_from(udp_len)
        .map_err(|_| AfXdpFrameError::ResponseTooLarge)?
        .to_be_bytes();
    frame[packet.ipv6_header_offset + 4..packet.ipv6_header_offset + 6]
        .copy_from_slice(&payload_len);
    frame[packet.udp_header_offset + 4..packet.udp_header_offset + 6].copy_from_slice(&payload_len);
    frame[packet.udp_header_offset + 6..packet.udp_header_offset + 8].copy_from_slice(&[0, 0]);
    let checksum =
        nonzero_udp_checksum(udp_ipv6_checksum(frame, packet.udp_header_offset, udp_len));
    frame[packet.udp_header_offset + 6..packet.udp_header_offset + 8]
        .copy_from_slice(&checksum.to_be_bytes());

    Ok(frame_len)
}

fn nonzero_udp_checksum(checksum: u16) -> u16 {
    if checksum == 0 { u16::MAX } else { checksum }
}

fn invalid_ipv4_source(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_unspecified() || address.is_multicast() || address.is_loopback() || octets[0] >= 240
}

pub(crate) fn write_udp_ipv4_response(
    packet: &mut xdp::Packet,
    frame: UdpIpv4Frame,
    response: &[u8],
) -> Result<usize, AfXdpFrameError> {
    if response.len() > usize::from(u16::MAX) - frame.ipv4_header_len - UDP_HEADER_LEN {
        return Err(AfXdpFrameError::ResponseTooLarge);
    }
    let frame_len = ETHERNET_HEADER_LEN + frame.ipv4_header_len + UDP_HEADER_LEN + response.len();
    if frame_len > packet.capacity() {
        return Err(AfXdpFrameError::ResponseTooLarge);
    }
    let current_len = packet.len();
    let resize = i32::try_from(frame_len)
        .and_then(|new_len| i32::try_from(current_len).map(|old_len| new_len - old_len))
        .map_err(|_| AfXdpFrameError::PacketResize)?;
    if resize != 0 {
        packet
            .adjust_tail(resize)
            .map_err(|_| AfXdpFrameError::PacketResize)?;
    }
    packet[frame.payload.start..frame.payload.start + response.len()].copy_from_slice(response);
    rewrite_udp_ipv4_response_headers(packet, frame, response.len())
}

pub(crate) fn write_udp_ipv6_response(
    packet: &mut xdp::Packet,
    frame: UdpIpv6Frame,
    response: &[u8],
) -> Result<usize, AfXdpFrameError> {
    if response.len() > usize::from(u16::MAX) - UDP_HEADER_LEN {
        return Err(AfXdpFrameError::ResponseTooLarge);
    }
    let frame_len = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + response.len();
    if frame_len > packet.capacity() {
        return Err(AfXdpFrameError::ResponseTooLarge);
    }
    let current_len = packet.len();
    let resize = i32::try_from(frame_len)
        .and_then(|new_len| i32::try_from(current_len).map(|old_len| new_len - old_len))
        .map_err(|_| AfXdpFrameError::PacketResize)?;
    if resize != 0 {
        packet
            .adjust_tail(resize)
            .map_err(|_| AfXdpFrameError::PacketResize)?;
    }
    packet[frame.payload.start..frame.payload.start + response.len()].copy_from_slice(response);
    rewrite_udp_ipv6_response_headers(packet, frame, response.len())
}

pub(crate) fn write_udp_ip_response(
    packet: &mut xdp::Packet,
    frame: UdpIpFrame,
    response: &[u8],
) -> Result<usize, AfXdpFrameError> {
    match frame {
        UdpIpFrame::Ipv4(frame) => write_udp_ipv4_response(packet, frame, response),
        UdpIpFrame::Ipv6(frame) => write_udp_ipv6_response(packet, frame, response),
    }
}

pub(crate) fn write_benchmark_fixed_dns_response(
    packet: &mut xdp::Packet,
    frame: UdpIpFrame,
) -> Result<usize, AfXdpFrameError> {
    match frame {
        UdpIpFrame::Ipv4(frame) => {
            let response = benchmark_fixed_dns_response(packet, frame.payload.clone())?;
            write_udp_ipv4_response(packet, frame, &response)
        }
        UdpIpFrame::Ipv6(frame) => {
            let response = benchmark_fixed_dns_response(packet, frame.payload.clone())?;
            write_udp_ipv6_response(packet, frame, &response)
        }
    }
}

fn benchmark_fixed_dns_response(
    packet: &[u8],
    payload: Range<usize>,
) -> Result<[u8; BENCHMARK_FIXED_DNS_RESPONSE_TEMPLATE.len()], AfXdpFrameError> {
    let query_id = packet
        .get(payload.start..payload.start + 2)
        .ok_or(AfXdpFrameError::InvalidUdpLength)?;
    let mut response = BENCHMARK_FIXED_DNS_RESPONSE_TEMPLATE;
    response[..2].copy_from_slice(query_id);
    Ok(response)
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = header.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ones_complement_add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(last) << 8;
    }
    sum
}

fn ones_complement_finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_ipv6_checksum(frame: &[u8], udp_header_offset: usize, udp_len: usize) -> u16 {
    let ipv6_header_offset = ETHERNET_HEADER_LEN;
    let mut sum = 0u32;
    sum = ones_complement_add_bytes(sum, &frame[ipv6_header_offset + 8..ipv6_header_offset + 24]);
    sum = ones_complement_add_bytes(
        sum,
        &frame[ipv6_header_offset + 24..ipv6_header_offset + 40],
    );
    sum = ones_complement_add_bytes(sum, &(udp_len as u32).to_be_bytes());
    sum += u32::from(IP_PROTOCOL_UDP);
    sum = ones_complement_add_bytes(sum, &frame[udp_header_offset..udp_header_offset + udp_len]);
    match ones_complement_finish(sum) {
        0 => 0xffff,
        checksum => checksum,
    }
}

fn udp_ipv4_checksum(
    frame: &[u8],
    ipv4_header_offset: usize,
    udp_header_offset: usize,
    udp_len: usize,
) -> u16 {
    let mut sum = 0u32;
    sum = ones_complement_add_bytes(
        sum,
        &frame[ipv4_header_offset + 12..ipv4_header_offset + 16],
    );
    sum = ones_complement_add_bytes(
        sum,
        &frame[ipv4_header_offset + 16..ipv4_header_offset + 20],
    );
    sum += u32::from(IP_PROTOCOL_UDP);
    sum += udp_len as u32;
    sum = ones_complement_add_bytes(sum, &frame[udp_header_offset..udp_header_offset + udp_len]);
    match ones_complement_finish(sum) {
        0 => 0xffff,
        checksum => checksum,
    }
}

fn ipv4_addr_at(frame: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        frame[offset],
        frame[offset + 1],
        frame[offset + 2],
        frame[offset + 3],
    )
}

fn ipv6_addr_at(frame: &[u8], offset: usize) -> Ipv6Addr {
    Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[offset..offset + 16])
            .expect("IPv6 address range was validated during packet parsing"),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        future::Future,
        io::{Read, Write},
        os::unix::net::UnixStream,
        task::{Context, Poll, Waker},
    };

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn async_fd_readiness_wait_can_be_cancelled_and_resumed() {
        let (mut writer, reader) = UnixStream::pair().expect("Unix stream pair");
        writer
            .set_nonblocking(true)
            .expect("nonblocking stream writer");
        reader
            .set_nonblocking(true)
            .expect("nonblocking stream reader");
        let reader = AsyncFd::new(reader).expect("Tokio AsyncFd reader");

        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            wait_for_fd_readiness(&reader, Interest::READABLE),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "idle readiness wait must be cancellable"
        );

        writer.write_all(&[0x53]).expect("signal readable stream");
        let mut readiness = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_for_fd_readiness(&reader, Interest::READABLE),
        )
        .await
        .expect("resumed readiness wait timed out")
        .expect("resumed readiness wait failed");
        let mut byte = [0u8; 1];
        let read = readiness
            .try_io(|fd| {
                let mut stream = fd.get_ref();
                stream.read(&mut byte)
            })
            .expect("readiness edge was a false positive")
            .expect("stream read failed");
        assert_eq!(read, 1);
        assert_eq!(byte, [0x53]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_fd_empty_observation_clears_and_rearms_readiness() {
        let (mut writer, reader) = UnixStream::pair().expect("Unix stream pair");
        writer
            .set_nonblocking(true)
            .expect("nonblocking stream writer");
        reader
            .set_nonblocking(true)
            .expect("nonblocking stream reader");
        let reader = AsyncFd::new(reader).expect("Tokio AsyncFd reader");

        writer.write_all(&[1]).expect("first readiness byte");
        let mut readiness = wait_for_fd_readiness(&reader, Interest::READABLE)
            .await
            .expect("first readiness edge");
        let mut byte = [0u8; 1];
        readiness
            .try_io(|fd| {
                let mut stream = fd.get_ref();
                stream.read_exact(&mut byte)
            })
            .expect("first edge was a false positive")
            .expect("first stream read failed");
        assert_eq!(byte, [1]);
        assert!(
            readiness
                .try_io(|fd| {
                    let mut stream = fd.get_ref();
                    stream.read(&mut byte)
                })
                .is_err(),
            "empty nonblocking read should clear the cached edge"
        );
        drop(readiness);

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                wait_for_fd_readiness(&reader, Interest::READABLE),
            )
            .await
            .is_err(),
            "cleared readiness must wait for a new edge"
        );
        writer.write_all(&[2]).expect("second readiness byte");
        let _readiness = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_for_fd_readiness(&reader, Interest::READABLE),
        )
        .await
        .expect("rearmed readiness wait timed out")
        .expect("rearmed readiness wait failed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tx_kick_retries_transient_error_without_new_admission() {
        let (_peer, socket) = UnixStream::pair().expect("Unix stream pair");
        socket.set_nonblocking(true).expect("nonblocking socket");
        let socket = AsyncFd::new(socket).expect("Tokio AsyncFd socket");
        let admitted = 7usize;
        let mut pending = false;
        mark_ring_kick_pending(&mut pending, admitted);
        let mut kick_calls = 0usize;

        let report = service_pending_ring_kick(
            &socket,
            &mut pending,
            RingKickServicePolicy {
                interest: None,
                max_recovery_attempts: RING_KICK_MAX_RECOVERY_ATTEMPTS,
            },
            || {
                kick_calls += 1;
                if kick_calls == 1 {
                    Err(io::Error::from(ErrorKind::WouldBlock))
                } else {
                    Ok(())
                }
            },
            || false,
            |_| false,
            |_| {},
        )
        .await
        .expect("second TX kick succeeds");

        assert_eq!(report.attempts, 2);
        assert_eq!(report.successes, 1);
        assert_eq!(report.transient_failures, 1);
        assert_eq!(report.delivery_failures, 0);
        assert_eq!(kick_calls, 2);
        assert_eq!(admitted, 7, "ring-owned packet accounting is unchanged");
        assert!(!pending);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fill_kick_retries_transient_error_without_new_admission() {
        let (_peer, socket) = UnixStream::pair().expect("Unix stream pair");
        socket.set_nonblocking(true).expect("nonblocking socket");
        let socket = AsyncFd::new(socket).expect("Tokio AsyncFd socket");
        let admitted = 11usize;
        let mut pending = false;
        mark_ring_kick_pending(&mut pending, admitted);
        let mut kick_calls = 0usize;

        let report = service_pending_ring_kick(
            &socket,
            &mut pending,
            RingKickServicePolicy {
                interest: None,
                max_recovery_attempts: RING_KICK_MAX_RECOVERY_ATTEMPTS,
            },
            || {
                kick_calls += 1;
                if kick_calls == 1 {
                    Err(io::Error::from_raw_os_error(libc::ENOBUFS))
                } else {
                    Ok(())
                }
            },
            || false,
            |_| false,
            |_| {},
        )
        .await
        .expect("second FILL kick succeeds without readable traffic");

        assert_eq!(report.attempts, 2);
        assert_eq!(report.successes, 1);
        assert_eq!(report.transient_failures, 1);
        assert_eq!(report.delivery_failures, 0);
        assert_eq!(kick_calls, 2);
        assert_eq!(admitted, 11, "ring-owned frame accounting is unchanged");
        assert!(!pending);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_kick_retry_preserves_pending_ring_ownership() {
        let (_peer, socket) = UnixStream::pair().expect("Unix stream pair");
        socket.set_nonblocking(true).expect("nonblocking socket");
        let socket = AsyncFd::new(socket).expect("Tokio AsyncFd socket");
        let admitted = 5usize;
        let mut pending = false;
        mark_ring_kick_pending(&mut pending, admitted);
        let mut kick_calls = 0usize;
        let mut cancellation_checks = 0usize;

        let error = service_pending_ring_kick(
            &socket,
            &mut pending,
            RingKickServicePolicy {
                interest: None,
                max_recovery_attempts: RING_KICK_MAX_RECOVERY_ATTEMPTS,
            },
            || {
                kick_calls += 1;
                Err(io::Error::from(ErrorKind::WouldBlock))
            },
            || {
                cancellation_checks += 1;
                cancellation_checks >= 2
            },
            |_| false,
            |_| {},
        )
        .await
        .expect_err("shutdown cancels a transient kick retry");

        assert_eq!(error.error.kind(), ErrorKind::Interrupted);
        assert_eq!(error.report.attempts, 1);
        assert_eq!(error.report.transient_failures, 1);
        assert_eq!(kick_calls, 1);
        assert_eq!(admitted, 5, "ring-owned packets must not be freed");
        assert!(pending, "the owning adapter retains the unfinished wake");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_pending_kick_future_preserves_observed_attempt_and_ring_ownership() {
        let (_peer, socket) = UnixStream::pair().expect("Unix stream pair");
        socket.set_nonblocking(true).expect("nonblocking socket");
        let socket = AsyncFd::new(socket).expect("Tokio AsyncFd socket");
        let mut pending = true;
        let mut stats = AfXdpPacketIoStats::default();
        let mut future = Box::pin(service_pending_ring_kick(
            &socket,
            &mut pending,
            RingKickServicePolicy {
                interest: None,
                max_recovery_attempts: RING_KICK_MAX_RECOVERY_ATTEMPTS,
            },
            || Err(io::Error::from(ErrorKind::WouldBlock)),
            || false,
            |_| false,
            |observation| record_tx_kick_observation(&mut stats, observation),
        ));
        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        drop(future);

        assert!(pending, "dropping the retry future retains ring ownership");
        assert_eq!(stats.tx_wakeups, 1);
        assert_eq!(stats.tx_kick_successes, 0);
        assert_eq!(stats.tx_kick_transient_failures, 1);
        assert_eq!(stats.tx_delivery_failures, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tx_kick_retry_drains_completion_capacity_before_retry() {
        let (_peer, socket) = UnixStream::pair().expect("Unix stream pair");
        socket.set_nonblocking(true).expect("nonblocking socket");
        let socket = AsyncFd::new(socket).expect("Tokio AsyncFd socket");
        let mut pending = true;
        let completion_used = Cell::new(1usize);
        let completion_drains = Cell::new(0usize);

        let report = service_pending_ring_kick(
            &socket,
            &mut pending,
            RingKickServicePolicy {
                interest: None,
                max_recovery_attempts: RING_KICK_MAX_RECOVERY_ATTEMPTS,
            },
            || {
                if completion_used.get() == 0 {
                    Ok(())
                } else {
                    Err(io::Error::from(ErrorKind::WouldBlock))
                }
            },
            || false,
            |_| false,
            |observation| {
                if observation.requires_completion_drain() {
                    completion_used.set(0);
                    completion_drains.set(completion_drains.get() + 1);
                }
            },
        )
        .await
        .expect("completion drain lets the next TX kick progress");

        assert_eq!(completion_drains.get(), 1);
        assert_eq!(report.attempts, 2);
        assert_eq!(report.transient_failures, 1);
        assert!(!pending);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tx_ebusy_drains_ownership_but_surfaces_delivery_failure_and_exact_metrics() {
        let (_peer, socket) = UnixStream::pair().expect("Unix stream pair");
        socket.set_nonblocking(true).expect("nonblocking socket");
        let socket = AsyncFd::new(socket).expect("Tokio AsyncFd socket");
        let mut pending = true;
        let kick_calls = Cell::new(0usize);
        let completion_drains = Cell::new(0usize);
        let mut stats = AfXdpPacketIoStats::default();

        let report = service_pending_ring_kick(
            &socket,
            &mut pending,
            RingKickServicePolicy {
                interest: None,
                max_recovery_attempts: RING_KICK_MAX_RECOVERY_ATTEMPTS,
            },
            || {
                kick_calls.set(kick_calls.get() + 1);
                if kick_calls.get() == 1 {
                    Err(io::Error::from_raw_os_error(libc::EBUSY))
                } else {
                    Ok(())
                }
            },
            || false,
            is_lossy_tx_kick_error,
            |observation| {
                record_tx_kick_observation(&mut stats, observation);
                if observation.requires_completion_drain() {
                    completion_drains.set(completion_drains.get() + 1);
                }
            },
        )
        .await
        .expect("lossy progress still drains the pending TX ring");
        let error = apply_tx_kick_result(Ok(report))
            .expect_err("consumed EBUSY descriptor remains a delivery failure");

        assert_eq!(error.raw_os_error(), Some(libc::EBUSY));
        assert_eq!(kick_calls.get(), 2);
        assert_eq!(completion_drains.get(), 1);
        assert!(
            !pending,
            "remaining ring ownership was drained exactly once"
        );
        assert_eq!(stats.tx_wakeups, 2);
        assert_eq!(stats.tx_kick_successes, 1);
        assert_eq!(stats.tx_kick_transient_failures, 0);
        assert_eq!(stats.tx_delivery_failures, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn persistent_tx_ebusy_exhausts_retry_budget_without_releasing_ring_ownership() {
        let (_peer, socket) = UnixStream::pair().expect("Unix stream pair");
        socket.set_nonblocking(true).expect("nonblocking socket");
        let socket = AsyncFd::new(socket).expect("Tokio AsyncFd socket");
        let mut pending = true;
        let kick_calls = Cell::new(0usize);
        let completion_drains = Cell::new(0usize);
        let mut stats = AfXdpPacketIoStats::default();

        let failure = service_pending_ring_kick(
            &socket,
            &mut pending,
            RingKickServicePolicy {
                interest: None,
                max_recovery_attempts: 3,
            },
            || {
                kick_calls.set(kick_calls.get() + 1);
                Err(io::Error::from_raw_os_error(libc::EBUSY))
            },
            || false,
            is_lossy_tx_kick_error,
            |observation| {
                record_tx_kick_observation(&mut stats, observation);
                if observation.requires_completion_drain() {
                    completion_drains.set(completion_drains.get() + 1);
                }
            },
        )
        .await
        .expect_err("persistent EBUSY must exhaust the bounded recovery attempt");

        assert_eq!(failure.error.raw_os_error(), Some(libc::EBUSY));
        assert_eq!(failure.report.attempts, 3);
        assert_eq!(failure.report.successes, 0);
        assert_eq!(failure.report.transient_failures, 0);
        assert_eq!(failure.report.delivery_failures, 3);
        assert_eq!(kick_calls.get(), 3);
        assert_eq!(completion_drains.get(), 3);
        assert!(pending, "the adapter must retain unfinished TX ownership");
        assert_eq!(stats.tx_wakeups, 3);
        assert_eq!(stats.tx_kick_successes, 0);
        assert_eq!(stats.tx_kick_transient_failures, 0);
        assert_eq!(stats.tx_delivery_failures, 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn persistent_transient_tx_kick_exhausts_retry_budget_without_releasing_ownership() {
        let (_peer, socket) = UnixStream::pair().expect("Unix stream pair");
        socket.set_nonblocking(true).expect("nonblocking socket");
        let socket = AsyncFd::new(socket).expect("Tokio AsyncFd socket");
        let mut pending = true;
        let kick_calls = Cell::new(0usize);
        let mut stats = AfXdpPacketIoStats::default();

        let failure = service_pending_ring_kick(
            &socket,
            &mut pending,
            RingKickServicePolicy {
                interest: None,
                max_recovery_attempts: 3,
            },
            || {
                kick_calls.set(kick_calls.get() + 1);
                Err(io::Error::from(ErrorKind::WouldBlock))
            },
            || false,
            is_lossy_tx_kick_error,
            |observation| record_tx_kick_observation(&mut stats, observation),
        )
        .await
        .expect_err("persistent transient error must exhaust the bounded recovery attempt");

        assert_eq!(failure.error.kind(), ErrorKind::WouldBlock);
        assert_eq!(failure.report.attempts, 3);
        assert_eq!(failure.report.successes, 0);
        assert_eq!(failure.report.transient_failures, 3);
        assert_eq!(failure.report.delivery_failures, 0);
        assert_eq!(kick_calls.get(), 3);
        assert!(pending, "the adapter must retain unfinished TX ownership");
        assert_eq!(stats.tx_wakeups, 3);
        assert_eq!(stats.tx_kick_successes, 0);
        assert_eq!(stats.tx_kick_transient_failures, 3);
        assert_eq!(stats.tx_delivery_failures, 0);
    }

    #[test]
    fn af_xdp_admissions_commit_one_generic_udp_batch_when_send_scope_ends() {
        let metrics = RuntimeMetrics::new();
        {
            let mut admitted_batch = UdpSendAdmissionBatch::new(&metrics, 3);
            admitted_batch.record(2);
            admitted_batch.record(3);
            assert_eq!(admitted_batch.total(), 5);
            assert_eq!(metrics.snapshot().udp_send_batches, 0);
        }

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.udp_send_batches, 1);
        assert_eq!(snapshot.udp_sent_datagrams, 5);
        assert_eq!(
            metrics.af_xdp_durable_send_stats_for_test(3),
            (0, 0, 0, 0, 1, 5)
        );
    }

    #[test]
    fn dropping_send_scope_after_admission_keeps_all_telemetry_durable() {
        let metrics = RuntimeMetrics::new();
        let mut future = Box::pin(async {
            let mut admitted_batch = UdpSendAdmissionBatch::new(&metrics, 7);
            let mut pending_stats = AfXdpPacketIoStats {
                tx_send_calls: 1,
                tx_queued_packets: 4,
                completion_dequeues: 1,
                completed_packets: 3,
                ..AfXdpPacketIoStats::default()
            };
            admitted_batch.record(4);
            // Production send paths flush this batch immediately before each
            // cancellable kick/readiness/FILL await.
            flush_af_xdp_packet_io_stats(&mut pending_stats, &metrics);
            std::future::pending::<()>().await;
        });
        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        drop(future);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.udp_send_batches, 1);
        assert_eq!(snapshot.udp_sent_datagrams, 4);
        assert_eq!(
            metrics.af_xdp_durable_send_stats_for_test(7),
            (1, 4, 1, 3, 1, 4)
        );
    }

    fn push_test_packet(slab: &mut HeapSlab, buffer: &mut [u8; 2 * 1024], id: u8) {
        let mut packet = xdp::Packet::testing_new(buffer);
        packet.insert(0, &[id]).expect("test packet payload");
        assert!(slab.push_front(packet).is_none());
    }

    #[test]
    fn full_second_receive_pass_retains_exact_tail_for_next_batch() {
        const BATCH_SIZE: usize = 8;
        let mut buffers = [[0u8; 2 * 1024]; BATCH_SIZE * 2 - 1];
        let mut slab = HeapSlab::with_capacity(BATCH_SIZE);
        let mut seen = Vec::new();
        let mut active = 0usize;

        for (id, buffer) in buffers[..BATCH_SIZE - 1].iter_mut().enumerate() {
            push_test_packet(&mut slab, buffer, id as u8);
        }
        let first = drain_receive_slab(&mut slab, BATCH_SIZE - 1, |packet| {
            seen.push(packet[0]);
            active += 1;
            active == BATCH_SIZE
        });
        assert_eq!(
            first,
            ReceiveSlabDrain {
                consumed: BATCH_SIZE - 1,
                retained: 0,
                batch_full: false,
            }
        );
        assert!(slab.is_empty());

        for (id, buffer) in buffers[BATCH_SIZE - 1..].iter_mut().enumerate() {
            push_test_packet(&mut slab, buffer, (BATCH_SIZE - 1 + id) as u8);
        }
        let second = drain_receive_slab(&mut slab, BATCH_SIZE, |packet| {
            seen.push(packet[0]);
            active += 1;
            active == BATCH_SIZE
        });
        assert_eq!(
            second,
            ReceiveSlabDrain {
                consumed: 1,
                retained: BATCH_SIZE - 1,
                batch_full: true,
            }
        );
        assert_eq!(slab.len(), BATCH_SIZE - 1);

        // `recv_batch` resets its published batch, then consumes this retained
        // tail before it can await readiness or dequeue any newer RX frames.
        active = 0;
        let pending = slab.len();
        let third = drain_receive_slab(&mut slab, pending, |packet| {
            seen.push(packet[0]);
            active += 1;
            active == BATCH_SIZE
        });
        assert_eq!(
            third,
            ReceiveSlabDrain {
                consumed: BATCH_SIZE - 1,
                retained: 0,
                batch_full: false,
            }
        );
        assert!(slab.is_empty());
        assert_eq!(active, BATCH_SIZE - 1);
        assert_eq!(seen, (0..(BATCH_SIZE * 2 - 1) as u8).collect::<Vec<_>>());
    }

    #[test]
    fn receive_slab_drain_accounts_for_zero_rejected_and_exact_full_edges() {
        const BATCH_SIZE: usize = 4;
        let mut buffers = [[0u8; 2 * 1024]; BATCH_SIZE];
        let mut slab = HeapSlab::with_capacity(BATCH_SIZE);

        assert_eq!(
            drain_receive_slab(&mut slab, 0, |_| unreachable!()),
            ReceiveSlabDrain {
                consumed: 0,
                retained: 0,
                batch_full: false,
            }
        );

        for (id, buffer) in buffers.iter_mut().enumerate() {
            push_test_packet(&mut slab, buffer, id as u8);
        }
        let mut rejected = 0usize;
        let all_rejected = drain_receive_slab(&mut slab, BATCH_SIZE, |_| {
            rejected += 1;
            false
        });
        assert_eq!(rejected, BATCH_SIZE);
        assert_eq!(
            all_rejected,
            ReceiveSlabDrain {
                consumed: BATCH_SIZE,
                retained: 0,
                batch_full: false,
            }
        );
        assert!(slab.is_empty());

        for (id, buffer) in buffers.iter_mut().enumerate() {
            push_test_packet(&mut slab, buffer, id as u8);
        }
        let mut admitted = 0usize;
        let exact_full = drain_receive_slab(&mut slab, BATCH_SIZE, |_| {
            admitted += 1;
            admitted == BATCH_SIZE
        });
        assert_eq!(
            exact_full,
            ReceiveSlabDrain {
                consumed: BATCH_SIZE,
                retained: 0,
                batch_full: true,
            }
        );
        assert!(slab.is_empty());
    }

    fn ipv4_udp_frame(payload: &[u8]) -> Vec<u8> {
        let total_len = IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        let udp_len = UDP_HEADER_LEN + payload.len();
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
        frame[6..12].copy_from_slice(&[0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip = ETHERNET_HEADER_LEN;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
        frame[ip + 8] = 64;
        frame[ip + 9] = IP_PROTOCOL_UDP;
        frame[ip + 12..ip + 16].copy_from_slice(&[192, 0, 2, 1]);
        frame[ip + 16..ip + 20].copy_from_slice(&[198, 51, 100, 53]);
        let checksum = ipv4_checksum(&frame[ip..ip + IPV4_MIN_HEADER_LEN]);
        frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
        let udp = ip + IPV4_MIN_HEADER_LEN;
        frame[udp..udp + 2].copy_from_slice(&12345u16.to_be_bytes());
        frame[udp + 2..udp + 4].copy_from_slice(&53u16.to_be_bytes());
        frame[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[udp + UDP_HEADER_LEN..udp + UDP_HEADER_LEN + payload.len()].copy_from_slice(payload);
        let checksum = udp_ipv4_checksum(&frame, ip, udp, udp_len);
        frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    fn refresh_ipv4_header_checksum(frame: &mut [u8]) {
        let ip = ETHERNET_HEADER_LEN;
        frame[ip + 10..ip + 12].copy_from_slice(&[0, 0]);
        let checksum = ipv4_checksum(&frame[ip..ip + IPV4_MIN_HEADER_LEN]);
        frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    }

    fn ipv4_udp_frame_len(payload_len: usize) -> usize {
        ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload_len
    }

    fn ipv6_udp_frame(payload: &[u8]) -> Vec<u8> {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let mut frame = vec![0u8; 256];
        frame[0..6].copy_from_slice(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
        frame[6..12].copy_from_slice(&[0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let ip = ETHERNET_HEADER_LEN;
        frame[ip] = 0x60;
        frame[ip + 4..ip + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[ip + 6] = IP_PROTOCOL_UDP;
        frame[ip + 7] = 64;
        frame[ip + 8..ip + 24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        frame[ip + 24..ip + 40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
        ]);
        let udp = ip + IPV6_HEADER_LEN;
        frame[udp..udp + 2].copy_from_slice(&12345u16.to_be_bytes());
        frame[udp + 2..udp + 4].copy_from_slice(&53u16.to_be_bytes());
        frame[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[udp + UDP_HEADER_LEN..udp + UDP_HEADER_LEN + payload.len()].copy_from_slice(payload);
        let checksum = udp_ipv6_checksum(&frame, udp, udp_len);
        frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    fn ipv6_udp_frame_len(payload_len: usize) -> usize {
        ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + payload_len
    }

    #[test]
    fn parses_udp_ipv4_dns_payload_range() {
        let frame = ipv4_udp_frame(&[1, 2, 3, 4]);
        let packet = parse_udp_ipv4_frame(&frame).expect("IPv4 UDP frame");

        assert_eq!(&frame[packet.payload()], &[1, 2, 3, 4]);
        assert_eq!(
            packet.source_addr(&frame),
            SocketAddr::from(([192, 0, 2, 1], 12345))
        );
        assert_eq!(
            packet.destination_addr(&frame),
            SocketAddr::from(([198, 51, 100, 53], 53))
        );
    }

    #[test]
    fn parses_udp_ipv6_dns_payload_range() {
        let frame = ipv6_udp_frame(&[1, 2, 3, 4]);
        let packet = parse_udp_ipv6_frame(&frame).expect("IPv6 UDP frame");

        assert_eq!(&frame[packet.payload()], &[1, 2, 3, 4]);
        assert_eq!(
            packet.source_addr(&frame),
            SocketAddr::new("2001:db8::1".parse().expect("IPv6 source"), 12345)
        );
        assert_eq!(
            packet.destination_addr(&frame),
            SocketAddr::new("2001:db8::53".parse().expect("IPv6 destination"), 53)
        );
        assert!(matches!(
            parse_udp_ip_frame(&frame),
            Ok(UdpIpFrame::Ipv6(_))
        ));
    }

    #[test]
    fn builds_af_xdp_packet_target_for_owned_frame() {
        assert_eq!(
            target_for_frame(7),
            UdpPacketTarget::AfXdp { frame_index: 7 }
        );
    }

    #[test]
    fn redirect_config_preserves_listener_family_address_and_wildcard_semantics() {
        assert_eq!(std::mem::size_of::<RedirectConfig>(), 20);
        let ipv4 = RedirectConfig::for_listener(SocketAddr::from(([198, 51, 100, 53], 5353)));
        assert_eq!(ipv4.udp_dest_port_be, 5353u16.to_be());
        assert_eq!(ipv4.address_family, 4);
        assert_eq!(ipv4.wildcard_address, 0);
        assert_eq!(&ipv4.destination_addr[..4], &[198, 51, 100, 53]);

        let ipv6 = RedirectConfig::for_listener(SocketAddr::new(
            "2001:db8::53".parse().expect("IPv6 listener"),
            53,
        ));
        assert_eq!(ipv6.address_family, 6);
        assert_eq!(ipv6.wildcard_address, 0);
        assert_eq!(
            ipv6.destination_addr,
            "2001:db8::53".parse::<Ipv6Addr>().unwrap().octets()
        );

        let wildcard_v4 = RedirectConfig::for_listener(SocketAddr::from(([0, 0, 0, 0], 53)));
        let wildcard_v6 =
            RedirectConfig::for_listener(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 53));
        assert_eq!(
            (wildcard_v4.address_family, wildcard_v4.wildcard_address),
            (4, 1)
        );
        assert_eq!(
            (wildcard_v6.address_family, wildcard_v6.wildcard_address),
            (6, 1)
        );
    }

    #[test]
    fn listener_destination_filter_rejects_multihomed_and_cross_family_traffic() {
        let listener_v4 = SocketAddr::from(([198, 51, 100, 53], 53));
        assert!(destination_matches_listener(listener_v4, listener_v4));
        assert!(!destination_matches_listener(
            listener_v4,
            SocketAddr::from(([198, 51, 100, 54], 53))
        ));
        assert!(!destination_matches_listener(
            listener_v4,
            SocketAddr::from(([198, 51, 100, 53], 5353))
        ));
        assert!(!destination_matches_listener(
            listener_v4,
            SocketAddr::new("2001:db8::53".parse().unwrap(), 53)
        ));

        let listener_v6 = SocketAddr::new("2001:db8::53".parse().unwrap(), 53);
        assert!(destination_matches_listener(listener_v6, listener_v6));
        assert!(!destination_matches_listener(
            listener_v6,
            SocketAddr::new("2001:db8::54".parse().unwrap(), 53)
        ));
    }

    #[test]
    fn wildcard_listener_matches_only_its_own_family_and_port() {
        assert!(destination_matches_listener(
            SocketAddr::from(([0, 0, 0, 0], 53)),
            SocketAddr::from(([203, 0, 113, 53], 53))
        ));
        assert!(!destination_matches_listener(
            SocketAddr::from(([0, 0, 0, 0], 53)),
            SocketAddr::new("2001:db8::53".parse().unwrap(), 53)
        ));
        assert!(destination_matches_listener(
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 53),
            SocketAddr::new("2001:db8::53".parse().unwrap(), 53)
        ));
    }

    #[test]
    fn af_xdp_preflight_rejects_wildcard_listeners() {
        for listener in ["0.0.0.0:53", "[::]:53"] {
            let error = validate_af_xdp_listener(listener.parse().unwrap())
                .expect_err("wildcard AF_XDP listener rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
        validate_af_xdp_listener("192.0.2.1:53".parse().unwrap())
            .expect("concrete IPv4 listener accepted");
        validate_af_xdp_listener("[2001:db8::1]:53".parse().unwrap())
            .expect("concrete IPv6 listener accepted");
    }

    #[test]
    fn receive_pass_budget_yields_reject_only_work_and_returns_admitted_work() {
        assert_eq!(receive_pass_action(0, 0, 1), ReceivePassAction::Continue);
        assert_eq!(receive_pass_action(0, 1, 1), ReceivePassAction::Yield);
        assert_eq!(receive_pass_action(0, 8, 4), ReceivePassAction::Yield);
        assert_eq!(receive_pass_action(1, 1, 1), ReceivePassAction::ReturnBatch);
        assert_eq!(receive_pass_action(4, 3, 4), ReceivePassAction::Continue);
    }

    #[test]
    fn prepares_xdp_umem_and_ring_config() {
        let config = XdpConfig {
            interface: Some("eth0".to_owned()),
            queue_id: 3,
            batch_size: 4096,
            ..XdpConfig::default()
        };

        let prepared = prepare_xdp_config(&config).expect("prepared AF_XDP config");
        let PreparedXdpConfig {
            interface,
            queue_id,
            batch_size,
            umem: _,
            rings: _,
        } = prepared;

        assert_eq!(interface, "eth0");
        assert_eq!(queue_id, 3);
        assert_eq!(batch_size, 1024);
    }

    #[test]
    fn expands_contiguous_xdp_queue_ids_from_worker_count() {
        let config = XdpConfig {
            queue_id: 3,
            ..XdpConfig::default()
        };

        assert_eq!(
            config.effective_queue_ids(4).expect("queue ids"),
            vec![3, 4, 5, 6]
        );
    }

    #[test]
    fn uses_explicit_xdp_queue_ids() {
        let config = XdpConfig {
            queue_ids: vec![3, 17, 41],
            ..XdpConfig::default()
        };

        assert_eq!(
            config.effective_queue_ids(63).expect("queue ids"),
            vec![3, 17, 41]
        );
    }

    #[test]
    fn rejects_fragmented_ipv4_udp_frame() {
        let mut frame = ipv4_udp_frame(&[1, 2, 3, 4]);
        frame[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8]
            .copy_from_slice(&0x2000u16.to_be_bytes());
        refresh_ipv4_header_checksum(&mut frame);

        assert_eq!(
            parse_udp_ipv4_frame(&frame),
            Err(AfXdpFrameError::FragmentedIpv4)
        );
    }

    #[test]
    fn rejects_invalid_ipv4_header_checksum() {
        let mut frame = ipv4_udp_frame(&[1, 2, 3, 4]);
        frame[ETHERNET_HEADER_LEN + 8] ^= 1;

        assert_eq!(
            parse_udp_ipv4_frame(&frame),
            Err(AfXdpFrameError::InvalidIpv4Checksum)
        );
    }

    #[test]
    fn validates_nonzero_ipv4_udp_checksum_but_accepts_legal_zero_checksum() {
        let mut frame = ipv4_udp_frame(&[1, 2, 3, 4]);
        let udp = ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        assert_ne!(u16::from_be_bytes([frame[udp + 6], frame[udp + 7]]), 0);
        frame[udp + UDP_HEADER_LEN] ^= 1;
        assert_eq!(
            parse_udp_ipv4_frame(&frame),
            Err(AfXdpFrameError::InvalidUdpChecksum)
        );

        frame[udp + 6..udp + 8].copy_from_slice(&[0, 0]);
        assert!(parse_udp_ipv4_frame(&frame).is_ok());
    }

    #[test]
    fn rejects_zero_and_invalid_ipv6_udp_checksums() {
        let mut missing = ipv6_udp_frame(&[1, 2, 3, 4]);
        let udp = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN;
        missing[udp + 6..udp + 8].copy_from_slice(&[0, 0]);
        assert_eq!(
            parse_udp_ipv6_frame(&missing),
            Err(AfXdpFrameError::MissingIpv6UdpChecksum)
        );

        let mut invalid = ipv6_udp_frame(&[1, 2, 3, 4]);
        invalid[udp + UDP_HEADER_LEN] ^= 1;
        assert_eq!(
            parse_udp_ipv6_frame(&invalid),
            Err(AfXdpFrameError::InvalidUdpChecksum)
        );
    }

    #[test]
    fn rejects_ipv6_extension_header_for_now() {
        let mut frame = ipv6_udp_frame(&[1, 2, 3, 4]);
        frame[ETHERNET_HEADER_LEN + 6] = 0;

        assert_eq!(
            parse_udp_ipv6_frame(&frame),
            Err(AfXdpFrameError::UnsupportedIpv6NextHeader(0))
        );
    }

    #[test]
    fn rewrites_udp_ipv4_response_headers() {
        let mut frame = ipv4_udp_frame(&[1, 2, 3, 4]);
        let packet = parse_udp_ipv4_frame(&frame).expect("IPv4 UDP frame");
        frame[packet.payload.start..packet.payload.start + 6].copy_from_slice(&[9, 8, 7, 6, 5, 4]);

        let frame_len =
            rewrite_udp_ipv4_response_headers(&mut frame, packet, 6).expect("rewritten response");

        assert_eq!(
            frame_len,
            ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + 6
        );
        assert_eq!(&frame[0..6], &[0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
        assert_eq!(&frame[6..12], &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
        let ip = ETHERNET_HEADER_LEN;
        assert_eq!(&frame[ip + 12..ip + 16], &[198, 51, 100, 53]);
        assert_eq!(&frame[ip + 16..ip + 20], &[192, 0, 2, 1]);
        assert_eq!(u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]), 34);
        assert_eq!(frame[ip + 1], 0);
        assert_eq!(&frame[ip + 4..ip + 8], &[0, 0, 0x40, 0]);
        assert_eq!(frame[ip + 8], RESPONSE_IP_HOP_LIMIT);
        assert_eq!(ipv4_checksum(&frame[ip..ip + IPV4_MIN_HEADER_LEN]), 0);
        let udp = ip + IPV4_MIN_HEADER_LEN;
        assert_eq!(u16::from_be_bytes([frame[udp], frame[udp + 1]]), 53);
        assert_eq!(u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]), 12345);
        assert_eq!(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]), 14);
        assert_ne!(u16::from_be_bytes([frame[udp + 6], frame[udp + 7]]), 0);
        assert_eq!(udp_ipv4_checksum(&frame, ip, udp, 14), 0xffff);
    }

    #[test]
    fn ipv4_response_does_not_inherit_request_id_flags_ttl_or_options() {
        let mut frame = ipv4_udp_frame(&[1, 2, 3, 4]);
        let ip = ETHERNET_HEADER_LEN;
        let old_udp = ip + IPV4_MIN_HEADER_LEN;
        let new_udp = old_udp + 4;
        frame.copy_within(old_udp..old_udp + UDP_HEADER_LEN + 4, new_udp);
        frame[ip] = 0x46;
        frame[ip + 1] = 0xff;
        frame[ip + 2..ip + 4].copy_from_slice(&36u16.to_be_bytes());
        frame[ip + 4..ip + 6].copy_from_slice(&0x1234u16.to_be_bytes());
        frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip + 8] = 1;
        frame[ip + IPV4_MIN_HEADER_LEN..new_udp].copy_from_slice(&[1, 1, 1, 0]);
        frame[ip + 10..ip + 12].copy_from_slice(&[0, 0]);
        let header_checksum = ipv4_checksum(&frame[ip..new_udp]);
        frame[ip + 10..ip + 12].copy_from_slice(&header_checksum.to_be_bytes());
        frame[new_udp + 6..new_udp + 8].copy_from_slice(&[0, 0]);
        let udp_checksum = udp_ipv4_checksum(&frame, ip, new_udp, UDP_HEADER_LEN + 4);
        frame[new_udp + 6..new_udp + 8].copy_from_slice(&udp_checksum.to_be_bytes());
        let packet = parse_udp_ipv4_frame(&frame).expect("IPv4 query with options");

        let frame_len =
            rewrite_udp_ipv4_response_headers(&mut frame, packet, 4).expect("rewritten response");

        assert_eq!(frame_len, ETHERNET_HEADER_LEN + 24 + UDP_HEADER_LEN + 4);
        assert_eq!(frame[ip], 0x46);
        assert_eq!(frame[ip + 1], 0);
        assert_eq!(&frame[ip + 4..ip + 8], &[0, 0, 0x40, 0]);
        assert_eq!(frame[ip + 8], RESPONSE_IP_HOP_LIMIT);
        assert_eq!(&frame[ip + IPV4_MIN_HEADER_LEN..new_udp], &[0, 0, 0, 0]);
        assert_eq!(ipv4_checksum(&frame[ip..new_udp]), 0);
        parse_udp_ipv4_frame(&frame[..frame_len]).expect("normalized IPv4 response");
    }

    #[test]
    fn rejects_rfc1122_invalid_ipv4_source_addresses() {
        for source in [
            [0, 0, 0, 0],
            [127, 0, 0, 1],
            [224, 0, 0, 1],
            [240, 0, 0, 1],
            [255, 255, 255, 255],
        ] {
            let mut frame = ipv4_udp_frame(&[1, 2, 3, 4]);
            let ip = ETHERNET_HEADER_LEN;
            frame[ip + 12..ip + 16].copy_from_slice(&source);
            refresh_ipv4_header_checksum(&mut frame);
            assert_eq!(
                parse_udp_ipv4_frame(&frame),
                Err(AfXdpFrameError::InvalidSourceAddress),
                "source {source:?} must be discarded"
            );
        }
    }

    #[test]
    fn rejects_rfc1122_invalid_ipv6_source_addresses() {
        for source in [Ipv6Addr::UNSPECIFIED, "ff02::1".parse().unwrap()] {
            let mut frame = ipv6_udp_frame(&[1, 2, 3, 4]);
            let ip = ETHERNET_HEADER_LEN;
            frame[ip + 8..ip + 24].copy_from_slice(&source.octets());
            let udp = ip + IPV6_HEADER_LEN;
            frame[udp + 6..udp + 8].copy_from_slice(&[0, 0]);
            let checksum = nonzero_udp_checksum(udp_ipv6_checksum(&frame, udp, UDP_HEADER_LEN + 4));
            frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
            assert_eq!(
                parse_udp_ipv6_frame(&frame),
                Err(AfXdpFrameError::InvalidSourceAddress)
            );
        }
    }

    #[test]
    fn rewrites_udp_ipv6_response_headers_and_checksum() {
        let mut frame = ipv6_udp_frame(&[1, 2, 3, 4]);
        let ip = ETHERNET_HEADER_LEN;
        frame[ip..ip + 4].copy_from_slice(&[0x6f, 0xff, 0xff, 0xff]);
        frame[ip + 7] = 1;
        let packet = parse_udp_ipv6_frame(&frame).expect("IPv6 UDP frame");
        frame[packet.payload.start..packet.payload.start + 6].copy_from_slice(&[9, 8, 7, 6, 5, 4]);

        let frame_len =
            rewrite_udp_ipv6_response_headers(&mut frame, packet, 6).expect("rewritten response");

        assert_eq!(frame_len, ipv6_udp_frame_len(6));
        assert_eq!(&frame[0..6], &[0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
        assert_eq!(&frame[6..12], &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
        assert_eq!(&frame[ip..ip + 4], &[0x60, 0, 0, 0]);
        assert_eq!(frame[ip + 7], RESPONSE_IP_HOP_LIMIT);
        assert_eq!(
            &frame[ip + 8..ip + 24],
            &[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
            ]
        );
        assert_eq!(
            &frame[ip + 24..ip + 40],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,]
        );
        assert_eq!(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]), 14);
        let udp = ip + IPV6_HEADER_LEN;
        assert_eq!(u16::from_be_bytes([frame[udp], frame[udp + 1]]), 53);
        assert_eq!(u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]), 12345);
        assert_eq!(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]), 14);
        assert_ne!(u16::from_be_bytes([frame[udp + 6], frame[udp + 7]]), 0);
        assert_eq!(udp_ipv6_checksum(&frame, udp, 14), 0xffff);
    }

    #[test]
    fn ipv6_generated_zero_udp_checksum_is_encoded_as_ones_complement_zero() {
        assert_eq!(nonzero_udp_checksum(0), u16::MAX);
        assert_eq!(nonzero_udp_checksum(0x1234), 0x1234);
    }

    #[test]
    fn accepted_ipv4_destination_becomes_response_source() {
        let listener = SocketAddr::from(([198, 51, 100, 53], 53));
        let mut frame = ipv4_udp_frame(&[1, 2, 3, 4]);
        let query = parse_udp_ipv4_frame(&frame).expect("IPv4 UDP frame");
        assert!(destination_matches_listener(
            listener,
            query.destination_addr(&frame)
        ));

        let frame_len =
            rewrite_udp_ipv4_response_headers(&mut frame, query, 4).expect("rewritten response");
        let response =
            parse_udp_ipv4_frame(&frame[..frame_len]).expect("valid IPv4 UDP response frame");
        assert_eq!(response.source_addr(&frame), listener);
    }

    #[test]
    fn accepted_ipv6_destination_becomes_response_source() {
        let listener = SocketAddr::new("2001:db8::53".parse().expect("IPv6 listener"), 53);
        let mut frame = ipv6_udp_frame(&[1, 2, 3, 4]);
        let query = parse_udp_ipv6_frame(&frame).expect("IPv6 UDP frame");
        assert!(destination_matches_listener(
            listener,
            query.destination_addr(&frame)
        ));

        let frame_len =
            rewrite_udp_ipv6_response_headers(&mut frame, query, 4).expect("rewritten response");
        let response =
            parse_udp_ipv6_frame(&frame[..frame_len]).expect("valid IPv6 UDP response frame");
        assert_eq!(response.source_addr(&frame), listener);
    }

    #[test]
    fn writes_larger_udp_ipv4_response_into_xdp_packet() {
        let mut storage = [0u8; 2 * 1024];
        let mut packet = xdp::Packet::testing_new(&mut storage);
        let frame = ipv4_udp_frame(&[1, 2, 3, 4]);
        packet
            .insert(0, &frame[..ipv4_udp_frame_len(4)])
            .expect("insert query frame");
        let parsed = parse_udp_ipv4_frame(&packet).expect("IPv4 UDP frame");
        let response = [9u8; 32];

        let frame_len =
            write_udp_ipv4_response(&mut packet, parsed, &response).expect("write response");

        assert_eq!(frame_len, ipv4_udp_frame_len(response.len()));
        assert_eq!(packet.len(), frame_len);
        assert_eq!(
            &packet[ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN..],
            response
        );
        assert_eq!(
            ipv4_checksum(&packet[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + 20]),
            0
        );
    }

    #[test]
    fn writes_smaller_udp_ipv4_response_into_xdp_packet() {
        let mut storage = [0u8; 2 * 1024];
        let mut packet = xdp::Packet::testing_new(&mut storage);
        let frame = ipv4_udp_frame(&[1; 64]);
        packet
            .insert(0, &frame[..ipv4_udp_frame_len(64)])
            .expect("insert query frame");
        let parsed = parse_udp_ipv4_frame(&packet).expect("IPv4 UDP frame");
        let response = [7u8; 12];

        let frame_len =
            write_udp_ipv4_response(&mut packet, parsed, &response).expect("write response");

        assert_eq!(frame_len, ipv4_udp_frame_len(response.len()));
        assert_eq!(packet.len(), frame_len);
        assert_eq!(
            &packet[ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN..],
            response
        );
    }

    #[test]
    fn writes_udp_ipv6_response_into_xdp_packet() {
        let mut storage = [0u8; 2 * 1024];
        let mut packet = xdp::Packet::testing_new(&mut storage);
        let frame = ipv6_udp_frame(&[1; 64]);
        packet
            .insert(0, &frame[..ipv6_udp_frame_len(64)])
            .expect("insert query frame");
        let parsed = parse_udp_ipv6_frame(&packet).expect("IPv6 UDP frame");
        let response = [7u8; 12];

        let frame_len =
            write_udp_ipv6_response(&mut packet, parsed, &response).expect("write response");

        assert_eq!(frame_len, ipv6_udp_frame_len(response.len()));
        assert_eq!(packet.len(), frame_len);
        assert_eq!(
            &packet[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN..],
            response
        );
        assert_eq!(
            udp_ipv6_checksum(
                &packet,
                ETHERNET_HEADER_LEN + IPV6_HEADER_LEN,
                UDP_HEADER_LEN + response.len()
            ),
            0xffff
        );
    }

    #[test]
    fn writes_benchmark_fixed_ipv4_response_into_xdp_packet() {
        let mut storage = [0u8; 2 * 1024];
        let mut packet = xdp::Packet::testing_new(&mut storage);
        let frame = ipv4_udp_frame(&[0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        packet
            .insert(0, &frame[..ipv4_udp_frame_len(12)])
            .expect("insert query frame");
        let parsed = parse_udp_ip_frame(&packet).expect("UDP/IP frame");

        let frame_len =
            write_benchmark_fixed_dns_response(&mut packet, parsed).expect("write response");

        assert_eq!(
            frame_len,
            ipv4_udp_frame_len(BENCHMARK_FIXED_DNS_RESPONSE_TEMPLATE.len())
        );
        assert_eq!(packet.len(), frame_len);
        let payload = &packet[ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN..];
        assert_eq!(&payload[..2], &[0x12, 0x34]);
        assert_eq!(&payload[2..8], &[0x84, 0x00, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(
            ipv4_checksum(&packet[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + 20]),
            0
        );
    }

    #[test]
    fn writes_benchmark_fixed_ipv6_response_into_xdp_packet() {
        let mut storage = [0u8; 2 * 1024];
        let mut packet = xdp::Packet::testing_new(&mut storage);
        let frame = ipv6_udp_frame(&[0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        packet
            .insert(0, &frame[..ipv6_udp_frame_len(12)])
            .expect("insert query frame");
        let parsed = parse_udp_ip_frame(&packet).expect("UDP/IP frame");

        let frame_len =
            write_benchmark_fixed_dns_response(&mut packet, parsed).expect("write response");

        assert_eq!(
            frame_len,
            ipv6_udp_frame_len(BENCHMARK_FIXED_DNS_RESPONSE_TEMPLATE.len())
        );
        assert_eq!(packet.len(), frame_len);
        let payload = &packet[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN..];
        assert_eq!(&payload[..2], &[0xab, 0xcd]);
        assert_eq!(&payload[2..8], &[0x84, 0x00, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(
            udp_ipv6_checksum(
                &packet,
                ETHERNET_HEADER_LEN + IPV6_HEADER_LEN,
                UDP_HEADER_LEN + BENCHMARK_FIXED_DNS_RESPONSE_TEMPLATE.len()
            ),
            0xffff
        );
    }
}
