#![allow(dead_code)]
#![allow(unsafe_code)]

use std::{
    collections::VecDeque,
    error::Error,
    ffi::CString,
    fmt,
    fs::File,
    io::{self, ErrorKind, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Range,
    os::{
        fd::{AsRawFd, RawFd},
        unix::fs::MetadataExt,
    },
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
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
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
const MAX_XDP_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
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

pub(crate) fn prepare_xdp_config(config: &XdpConfig) -> io::Result<PreparedXdpConfig> {
    let umem = xdp::umem::UmemCfgBuilder {
        frame_size: configured_umem_frame_size(config.umem_frame_size)?,
        frame_count: config.umem_frame_count,
        tx_checksum: false,
        tx_timestamp: false,
        ..Default::default()
    }
    .build()
    .map_err(xdp_config_error)?;
    let rings = xdp::RingConfigBuilder {
        rx_count: config.rx_ring_size,
        tx_count: config.tx_ring_size,
        fill_count: config.fill_ring_size,
        completion_count: config.completion_ring_size,
    }
    .build()
    .map_err(xdp_config_error)?;
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

fn configured_umem_frame_size(bytes: u32) -> io::Result<xdp::umem::FrameSize> {
    match bytes {
        2048 => Ok(xdp::umem::FrameSize::TwoK),
        4096 => Ok(xdp::umem::FrameSize::FourK),
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "xdp.umem_frame_size must be 2048 or 4096",
        )),
    }
}

pub(crate) struct AfXdpPacketIo {
    _udp_socket: Arc<UdpSocket>,
    socket: AsyncFd<xdp::socket::XdpSocket>,
    _redirect: Option<Arc<XdpRedirectGuard>>,
    rx_ring: xdp::RxRing,
    tx_ring: xdp::WakableTxRing,
    #[cfg(feature = "experimental-xdp-conditional-wakeup")]
    tx_wakeup_flags: RingWakeupFlags,
    #[cfg(feature = "experimental-xdp-conditional-wakeup")]
    fill_wakeup_flags: RingWakeupFlags,
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
    #[cfg(feature = "experimental-response-writer")]
    reply_epoch: u64,
    frames: Vec<Option<ReceivedFrame>>,
    recv_slab: ReceiveSlab,
    tx_slab: HeapSlab,
    tx_kick_pending: bool,
    fill_kick_pending: bool,
    pending_stats: AfXdpPacketIoStats,
    #[cfg(feature = "experimental-xdp-time-turn")]
    receive_time_turn: ReceiveTimeTurn,
}

struct ReceivedFrame {
    packet: xdp::Packet,
    frame: UdpIpFrame,
    #[cfg(feature = "experimental-response-writer")]
    prepared_len: Option<usize>,
    #[cfg(feature = "experimental-response-writer")]
    reply_epoch: u64,
}

#[cfg(feature = "experimental-xdp-group-loop")]
pub(crate) mod group;

#[cfg(feature = "experimental-xdp-group-loop")]
fn group_ring_io<T: AsRawFd>(
    socket: &AsyncFd<T>,
    interest: Interest,
    mut operation: impl FnMut() -> io::Result<usize>,
) -> io::Result<usize> {
    let count = operation()?;
    if count > 0 {
        return Ok(count);
    }
    // The first empty observation predates this readiness token. Recheck the
    // ring while holding it: a packet/slot may have arrived in between. Only
    // that second empty observation can justify clearing the current edge.
    let mut operation_error = None;
    let result = socket.try_io(interest, |_| {
        // AsyncFd normalizes WouldBlock and can discard its raw errno. Keep
        // the actual ring error separately, including partial-admission errors.
        let count = operation().map_err(|error| {
            let kind = error.kind();
            operation_error = Some(error);
            io::Error::from(kind)
        })?;
        if count == 0 {
            Err(io::Error::from(ErrorKind::WouldBlock))
        } else {
            Ok(count)
        }
    });
    if let Some(error) = operation_error {
        return Err(error);
    }
    match result {
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(0),
        // Preserve real operation errors, including WouldBlock following
        // partial TX admission; the owner still accounts for those frames.
        result => result,
    }
}

#[cfg(feature = "experimental-xdp-group-loop")]
fn group_receive_once(io: &mut AfXdpPacketIo) -> io::Result<usize> {
    // SAFETY: the queue owner keeps UMEM and RX slab alive together. It drains
    // any retained slab tail before calling this, and consumes/recycles every
    // dequeued frame before reuse. No frame reference crosses a group turn.
    group_ring_io(&io.socket, Interest::READABLE, || {
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-016
        let received = unsafe { io.rx_ring.recv(&io.umem, &mut io.recv_slab) };
        io.pending_stats.rx_recv_calls += 1;
        io.pending_stats.rx_received_packets += received as u64;
        if received == 0 {
            io.pending_stats.rx_empty_recv_calls += 1;
        }
        Ok(received)
    })
}

#[cfg(feature = "experimental-xdp-group-loop")]
fn group_publish_once(io: &mut AfXdpPacketIo) -> (usize, io::Result<usize>) {
    let pending = io.tx_slab.len();
    // SAFETY: the slab contains only frames belonging to this queue's UMEM;
    // TX consumes ownership from the slab, and completion alone returns it.
    // The owner never recycles the consumed prefix, including on syscall error.
    let result = group_ring_io(&io.socket, Interest::WRITABLE, || {
        let before = io.tx_slab.len();
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-017
        let result = unsafe { io.tx_ring.send(&mut io.tx_slab, false) };
        let admitted = before - io.tx_slab.len();
        io.pending_stats.tx_send_calls += 1;
        io.pending_stats.tx_queued_packets += admitted as u64;
        if admitted == 0 {
            io.pending_stats.tx_empty_send_calls += 1;
        }
        result
    });
    (pending - io.tx_slab.len(), result)
}

#[cfg(feature = "experimental-xdp-group-loop")]
fn group_fill_once(io: &mut AfXdpPacketIo) -> io::Result<usize> {
    // SAFETY: enqueue allocates only free frames from this adapter's UMEM.
    // Neither retained RX frames nor staged/admitted TX frames are free. The
    // adapter owns the FILL ring and UMEM for the entire publication operation.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-018
    enqueue_fill_frames(io.fill_ring_size, |requested| unsafe {
        io.fill_ring.enqueue(&mut io.umem, requested, false)
    })
}

#[cfg(feature = "experimental-response-writer")]
mod response_writer;
#[cfg(feature = "experimental-response-writer")]
pub(crate) use response_writer::PreparedReply;

/// Experimental soft queue-service deadline. This is checked between complete
/// batches, never while changing descriptor ownership. Sampling once per eight
/// batches amortizes the clock read; it is not a hard per-packet time limit.
#[cfg(feature = "experimental-xdp-time-turn")]
struct ReceiveTimeTurn {
    started: std::time::Instant,
    batches: u8,
}

#[cfg(feature = "experimental-xdp-time-turn")]
impl ReceiveTimeTurn {
    const LIMIT: Duration = Duration::from_millis(1);
    const CLOCK_INTERVAL: u8 = 8;

    fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            batches: 0,
        }
    }

    fn due(&mut self, now: impl FnOnce() -> std::time::Instant) -> bool {
        self.batches += 1;
        if self.batches < Self::CLOCK_INTERVAL {
            return false;
        }
        self.batches = 0;
        now().saturating_duration_since(self.started) >= Self::LIMIT
    }

    async fn checkpoint(&mut self) {
        if self.due(std::time::Instant::now) {
            tokio::task::yield_now().await;
            // Do not charge another queue's run time to this queue's new turn.
            self.started = std::time::Instant::now();
        }
    }
}

/// RX owns each packet before it enters this slab. Start bringing its first
/// two cache lines into the CPU while the ring continues collecting the batch.
/// These are only hints; parsing and all ownership rules remain unchanged.
struct ReceiveSlab(HeapSlab);

impl ReceiveSlab {
    fn with_capacity(capacity: usize) -> Self {
        Self(HeapSlab::with_capacity(capacity))
    }
}

impl Slab for ReceiveSlab {
    fn available(&self) -> usize {
        self.0.available()
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn push_front(&mut self, packet: xdp::Packet) -> Option<xdp::Packet> {
        if self.available() == 0 {
            return Some(packet);
        }
        prefetch_packet_head(&packet);
        self.0.push_front(packet)
    }
    fn pop_back(&mut self) -> Option<xdp::Packet> {
        self.0.pop_back()
    }
}

#[inline]
#[cfg(target_arch = "aarch64")]
fn prefetch_packet_head(packet: &[u8]) {
    for offset in [0, 64] {
        let Some(byte) = packet.get(offset) else {
            break;
        };
        // SAFETY: the address points inside a currently owned, live packet
        // slice. The instruction only issues a read-prefetch hint; it neither
        // changes the bytes nor transfers or extends descriptor ownership.
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-010
        unsafe {
            std::arch::asm!("prfm pldl1keep, [{address}]", address = in(reg) byte as *const u8, options(nostack, readonly, preserves_flags));
        }
    }
}

// Keep unmeasured targets unchanged; the GX10 evidence covers AArch64 only.
#[inline]
#[cfg(not(target_arch = "aarch64"))]
fn prefetch_packet_head(_packet: &[u8]) {}

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

#[cfg(feature = "experimental-xdp-conditional-wakeup")]
fn mark_conditional_tx_kick(
    pending: &mut bool,
    admitted: usize,
    needs_wakeup: impl FnOnce() -> bool,
) {
    // A prior unsuccessful syscall must still go through explicit recovery,
    // even if the kernel subsequently clears the flag. Only fresh successful
    // publications may rely on the needs-wakeup handshake.
    if !*pending && admitted > 0 {
        *pending = needs_wakeup();
    }
}

#[cfg(feature = "experimental-xdp-conditional-wakeup")]
fn mark_conditional_fill_kick(
    pending: &mut bool,
    _admitted: usize,
    needs_wakeup: impl FnOnce() -> bool,
) {
    // Unlike TX, RX can run out of hardware buffers and set the flag even
    // when this attempt publishes no new FILL entries. Recheck every time;
    // preserve an earlier failed wake independently of the current flag.
    if !*pending {
        *pending = needs_wakeup();
    }
}

/// Read-only second mapping of a producer ring header, using Linux's public ABI.
/// xdp 0.7.3 owns descriptor publication but does not expose this flag. This
/// view never reads/writes descriptors or producer/consumer indices.
#[cfg(feature = "experimental-xdp-conditional-wakeup")]
struct RingWakeupFlags {
    mapping: *mut libc::c_void,
    length: usize,
    flag_offset: usize,
}

#[cfg(feature = "experimental-xdp-conditional-wakeup")]
fn tx_wakeup_mapping_length(flag_offset: u64, offsets_length: usize) -> io::Result<usize> {
    // Refuse the legacy ABI without flags and impossible/misaligned headers.
    // A bounded header view suffices; do not map the descriptor array again.
    if offsets_length != std::mem::size_of::<libc::xdp_mmap_offsets>()
        || flag_offset > 4092
        || !flag_offset.is_multiple_of(std::mem::align_of::<u32>() as u64)
    {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "unsupported AF_XDP TX flag layout",
        ));
    }
    Ok(flag_offset as usize + std::mem::size_of::<u32>())
}

#[cfg(feature = "experimental-xdp-conditional-wakeup")]
impl RingWakeupFlags {
    fn map(socket_fd: RawFd, kind: RingKickKind) -> io::Result<Self> {
        let empty = libc::xdp_ring_offset {
            producer: 0,
            consumer: 0,
            desc: 0,
            flags: 0,
        };
        let mut offsets = libc::xdp_mmap_offsets {
            rx: empty,
            tx: empty,
            fr: empty,
            cr: empty,
        };
        let mut offsets_length = std::mem::size_of_val(&offsets) as libc::socklen_t;
        // SAFETY: the output and length point to live, correctly sized ABI
        // objects. The syscall validates the descriptor and never retains them.
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-012
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::SOL_XDP,
                libc::XDP_MMAP_OFFSETS,
                (&mut offsets as *mut libc::xdp_mmap_offsets).cast(),
                &mut offsets_length,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let (flag_offset, page_offset) = match kind {
            RingKickKind::Tx => (offsets.tx.flags, libc::XDP_PGOFF_TX_RING),
            RingKickKind::Fill => (
                offsets.fr.flags,
                libc::off_t::try_from(libc::XDP_UMEM_PGOFF_FILL_RING).map_err(|_| {
                    io::Error::new(
                        ErrorKind::Unsupported,
                        "AF_XDP FILL mapping offset does not fit off_t",
                    )
                })?,
            ),
        };
        let length = tx_wakeup_mapping_length(flag_offset, offsets_length as usize)?;
        // SAFETY: the socket's producer ring is initialized. Linux permits a
        // second shared header mapping; length is bounded and nonzero. No fixed
        // address is requested and this mapping cannot mutate the ring.
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-013
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_SHARED,
                socket_fd,
                page_offset,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            mapping,
            length,
            flag_offset: flag_offset as usize,
        })
    }

    fn needs_wakeup(&self) -> bool {
        use std::sync::atomic::{Ordering, fence};
        // Descriptor publication precedes the flag observation, including on
        // weakly ordered CPUs. The driver sets the flag then rechecks ring work;
        // a cleared flag therefore delegates progress to the active driver.
        fence(Ordering::SeqCst);
        // SAFETY: map() validated alignment and bounds of the kernel's u32
        // flag; mmap is page-aligned and remains live until Drop. The kernel
        // owns updates outside Rust's memory model. Like the kernel ABI's
        // READ_ONCE helper, read one aligned u32 without creating a reference.
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-014
        let flags = unsafe {
            std::ptr::read_volatile(
                self.mapping
                    .cast::<u8>()
                    .add(self.flag_offset)
                    .cast::<u32>(),
            )
        };
        fence(Ordering::Acquire);
        flags & libc::XDP_RING_NEED_WAKEUP != 0
    }
}

#[cfg(feature = "experimental-xdp-conditional-wakeup")]
impl Drop for RingWakeupFlags {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the successful mmap view and its
        // original length; no flag reference escapes needs_wakeup(). Unmapping
        // this view does not alter the xdp crate's separately owned mappings.
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-015
        unsafe {
            libc::munmap(self.mapping, self.length);
        }
    }
}

fn enqueue_fill_frames(
    mut requested: usize,
    mut enqueue: impl FnMut(usize) -> io::Result<usize>,
) -> io::Result<usize> {
    // xdp 0.7.3 reserves min(requested, free UMEM frames) all-or-nothing.
    // A driver may retain a short FILL tail while waiting for a full RX
    // allocation batch. Waiting for space for the entire ring would then
    // deadlock even though both free slots and reusable frames exist.
    // Retry smaller reservations, bounded to log2(requested) + 1 calls.
    // A failed reservation transfers no ownership; stop on the first success.
    while requested > 0 {
        let queued = enqueue(requested)?;
        if queued > 0 {
            return Ok(queued);
        }
        requested /= 2;
    }
    Ok(0)
}

fn kick_af_xdp_ring(socket_fd: RawFd, kind: RingKickKind) -> io::Result<()> {
    // AF_XDP defines zero-length sendto/recvfrom calls as TX/FILL wakeups.
    // SAFETY: `socket_fd` is the live AF_XDP socket owned by the adapter; both
    // operations use a zero length and null data/address pointers, so the
    // kernel cannot dereference userspace packet memory through this call.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-001
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

#[cfg(feature = "experimental-xdp-busy-poll")]
fn xdp_busy_poll_socket_options() -> [(libc::c_int, libc::c_int); 3] {
    [
        (libc::SO_PREFER_BUSY_POLL, 1),
        (libc::SO_BUSY_POLL, 20),
        (libc::SO_BUSY_POLL_BUDGET, 64),
    ]
}

#[cfg(feature = "experimental-xdp-busy-poll")]
fn set_xdp_socket_int_option(
    socket_fd: RawFd,
    option: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `socket_fd` is a live AF_XDP socket; SOL_SOCKET options consume
    // one initialized c_int synchronously and retain no userspace pointer.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-019
    let result = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        Err(io::Error::new(
            error.kind(),
            format!(
                "failed to configure experimental AF_XDP busy-poll socket option {option}: {error}"
            ),
        ))
    }
}

#[cfg(feature = "experimental-xdp-busy-poll")]
fn configure_xdp_busy_poll(socket_fd: RawFd) -> io::Result<()> {
    for (option, value) in xdp_busy_poll_socket_options() {
        set_xdp_socket_int_option(socket_fd, option, value)?;
    }
    Ok(())
}

#[cfg(all(test, feature = "experimental-xdp-busy-poll"))]
#[test]
fn experimental_busy_poll_socket_options_match_irq_mitigation_contract() {
    assert_eq!(
        xdp_busy_poll_socket_options(),
        [
            (libc::SO_PREFER_BUSY_POLL, 1),
            (libc::SO_BUSY_POLL, 20),
            (libc::SO_BUSY_POLL_BUDGET, 64),
        ]
    );
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
// SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-002
unsafe impl Pod for RedirectConfig {}

struct XdpRedirectGuard {
    _bpf: Ebpf,
}

fn load_redirect_object(bytes: &[u8], local_addr: SocketAddr) -> Result<Ebpf, aya::EbpfError> {
    #[cfg(feature = "experimental-static-redirect")]
    {
        let config = RedirectConfig::for_listener(local_addr);
        // Old objects lack this global and keep using REDIRECT_CONFIG below.
        // Aya initializes and freezes read-only globals before program load.
        aya::EbpfLoader::new()
            .set_global("STATIC_REDIRECT_CONFIG", &config, false)
            .load(bytes)
    }
    #[cfg(not(feature = "experimental-static-redirect"))]
    {
        let _ = local_addr;
        Ebpf::load(bytes)
    }
}

impl XdpRedirectGuard {
    fn attach(
        object: &Path,
        interface: &str,
        mode: XdpMode,
        local_addr: SocketAddr,
        xsk_entries: &[(u32, RawFd)],
    ) -> io::Result<Self> {
        let object_bytes = read_trusted_xdp_object(object)?;
        let mut bpf = load_redirect_object(&object_bytes, local_addr).map_err(|error| {
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

fn read_trusted_xdp_object(path: &Path) -> io::Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "the AF_XDP redirect object path must be absolute",
        ));
    }
    let fd = openat2(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| {
        io::Error::new(
            ErrorKind::PermissionDenied,
            format!("failed to open AF_XDP redirect object without following links: {error}"),
        )
    })?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "the AF_XDP redirect object must be a regular file",
        ));
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != 0 && metadata.uid() != effective_uid {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "the AF_XDP redirect object must be owned by root or the BoronDNS process user",
        ));
    }
    if metadata.mode() & 0o022 != 0 || metadata.nlink() != 1 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "the AF_XDP redirect object must not be group/world writable or hard-linked",
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_XDP_OBJECT_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("the AF_XDP redirect object must be 1..={MAX_XDP_OBJECT_BYTES} bytes"),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&file)
        .take(MAX_XDP_OBJECT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let final_metadata = file.metadata()?;
    if bytes.len() as u64 != metadata.len()
        || metadata.dev() != final_metadata.dev()
        || metadata.ino() != final_metadata.ino()
        || metadata.len() != final_metadata.len()
        || metadata.mtime() != final_metadata.mtime()
        || metadata.mtime_nsec() != final_metadata.mtime_nsec()
        || metadata.ctime() != final_metadata.ctime()
        || metadata.ctime_nsec() != final_metadata.ctime_nsec()
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "the AF_XDP redirect object changed while it was being read",
        ));
    }
    Ok(bytes)
}

// SAFETY: the adapter owns the AF_XDP socket, rings, UMEM, slabs, and all
// outstanding packets as one unit. Packets are never shared concurrently; moving
// the adapter between Tokio worker threads moves the owning UMEM and packet
// handles together.
// SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-003
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
        let prepared = prepare_xdp_config(config)?;
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
        let mut prepared = prepare_xdp_config(config)?;
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
        #[cfg(feature = "experimental-xdp-busy-poll")]
        configure_xdp_busy_poll(socket_fd)?;
        #[cfg(feature = "experimental-xdp-conditional-wakeup")]
        let tx_wakeup_flags = RingWakeupFlags::map(socket_fd, RingKickKind::Tx)?;
        #[cfg(feature = "experimental-xdp-conditional-wakeup")]
        let fill_wakeup_flags = RingWakeupFlags::map(socket_fd, RingKickKind::Fill)?;
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
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-004
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
        #[cfg(not(feature = "experimental-xdp-conditional-wakeup"))]
        mark_ring_kick_pending(&mut fill_kick_pending, initially_filled);
        #[cfg(feature = "experimental-xdp-conditional-wakeup")]
        mark_conditional_fill_kick(&mut fill_kick_pending, initially_filled, || {
            fill_wakeup_flags.needs_wakeup()
        });
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
                #[cfg(feature = "experimental-xdp-conditional-wakeup")]
                tx_wakeup_flags,
                #[cfg(feature = "experimental-xdp-conditional-wakeup")]
                fill_wakeup_flags,
                fill_ring: rings.fill_ring,
                completion_ring: rings.completion_ring,
                umem,
                local_addr,
                batch_size: prepared.batch_size,
                rx_drain_passes: config.rx_drain_passes,
                fill_ring_size,
                completion_ring_size: config.completion_ring_size as usize,
                inbound: (0..prepared.batch_size)
                    .map(|_| UdpInbound::new_af_xdp())
                    .collect(),
                active_inbound: 0,
                #[cfg(feature = "experimental-response-writer")]
                reply_epoch: 0,
                frames: Vec::with_capacity(prepared.batch_size),
                recv_slab: ReceiveSlab::with_capacity(prepared.batch_size),
                tx_slab: HeapSlab::with_capacity(prepared.batch_size),
                tx_kick_pending: false,
                fill_kick_pending,
                pending_stats: AfXdpPacketIoStats::default(),
                #[cfg(feature = "experimental-xdp-time-turn")]
                receive_time_turn: ReceiveTimeTurn::new(),
            },
            socket_fd,
        ))
    }

    /// Move registration to the runtime that will own this queue task. Moving
    /// only the future would leave readiness attached to the old reactor.
    pub(crate) fn reregister_runtime(mut self) -> io::Result<Self> {
        // Keep the rest of the adapter intact, including its normal field-drop
        // order on error. No packet/ring/UMEM ownership is split or duplicated.
        self.socket = crate::xdp_runtime::reregister(self.socket)?;
        Ok(self)
    }

    fn drain_completions(&mut self) {
        drain_completions_into(
            &mut self.completion_ring,
            &mut self.umem,
            self.completion_ring_size,
            &mut self.pending_stats,
        );
    }

    fn mark_successful_tx_publication(&mut self, admitted: usize) {
        #[cfg(feature = "experimental-xdp-conditional-wakeup")]
        mark_conditional_tx_kick(&mut self.tx_kick_pending, admitted, || {
            self.tx_wakeup_flags.needs_wakeup()
        });
        #[cfg(not(feature = "experimental-xdp-conditional-wakeup"))]
        mark_ring_kick_pending(&mut self.tx_kick_pending, admitted);
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
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-005
        let queued = enqueue_fill_frames(self.fill_ring_size, |requested| unsafe {
            self.fill_ring.enqueue(&mut self.umem, requested, false)
        })?;
        #[cfg(not(feature = "experimental-xdp-conditional-wakeup"))]
        mark_ring_kick_pending(&mut self.fill_kick_pending, queued);
        #[cfg(feature = "experimental-xdp-conditional-wakeup")]
        mark_conditional_fill_kick(&mut self.fill_kick_pending, queued, || {
            self.fill_wakeup_flags.needs_wakeup()
        });
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

        #[cfg(feature = "experimental-response-writer")]
        let reply_epoch = self.reply_epoch;

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
                inbound.push(UdpInbound::new_af_xdp());
            }

            let frame_index = frames.len();
            let peer = frame.source_addr(&packet);
            let admitted = &mut inbound[*active_inbound];
            admitted.copy_af_xdp_payload(&packet[payload]);
            admitted.peer = peer;
            admitted.target = target_for_frame(frame_index);
            frames.push(Some(ReceivedFrame {
                packet,
                frame,
                #[cfg(feature = "experimental-response-writer")]
                prepared_len: None,
                #[cfg(feature = "experimental-response-writer")]
                reply_epoch,
            }));
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
    #[cfg(feature = "experimental-response-writer")]
    fn supports_reply_buffers(&self) -> bool {
        true
    }

    #[cfg(feature = "experimental-response-writer")]
    fn with_reply_buffers<T>(
        &mut self,
        visit: impl FnOnce(&[UdpInbound], &mut dyn crate::udp::UdpReplyBuffers) -> T,
    ) -> io::Result<T> {
        // Disjoint adapter fields are borrowed only for this synchronous call.
        // No frame reference survives into the asynchronous send operation.
        Ok(visit(
            &self.inbound[..self.active_inbound],
            &mut response_writer::ReplyFrames {
                frames: &mut self.frames,
            },
        ))
    }

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
        #[cfg(feature = "experimental-xdp-time-turn")]
        self.receive_time_turn.checkpoint().await;
        self.release_unsent_frames();
        self.drain_completions();
        self.replenish_fill_ring(Some(admission_open)).await?;
        self.active_inbound = 0;
        #[cfg(feature = "experimental-response-writer")]
        {
            self.reply_epoch = self
                .reply_epoch
                .checked_add(1)
                .expect("AF_XDP reply epoch exhausted");
        }
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
                // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-006
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
                // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-007
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
        let umem = &mut self.umem;
        if let Err(error) = prepare_tx_frames(
            &mut self.frames,
            &mut self.tx_slab,
            &mut pending_send_metrics,
            outbound,
            metrics,
            |packet| umem.free_packet(packet),
        ) {
            return Err(PacketIoSendError::new(error, admitted_batch.total()));
        }
        while !self.tx_slab.is_empty() {
            // SAFETY: all packets in `tx_slab` came from this adapter's UMEM,
            // and the UMEM outlives the socket and TX ring.
            let pending_before = self.tx_slab.len();
            // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-008
            let send_result = unsafe { self.tx_ring.send(&mut self.tx_slab, false) };
            let admitted = pending_before - self.tx_slab.len();
            admitted_batch.record(admitted);
            record_admitted_send_metrics(&mut pending_send_metrics, outbound, admitted, metrics);
            match send_result {
                Ok(queued) if queued > 0 => {
                    debug_assert_eq!(queued, admitted);
                    self.pending_stats.tx_send_calls += 1;
                    self.pending_stats.tx_queued_packets += queued as u64;
                    self.mark_successful_tx_publication(admitted);
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
                        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-009
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
                                debug_assert!(queued > 0);
                                drop(readiness);
                                self.mark_successful_tx_publication(admitted);
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
            match &packet.response {
                crate::udp::UdpResponse::Owned(bytes) => {
                    record_query_send_metric(query_metrics, bytes, metrics, started.elapsed())
                }
                #[cfg(feature = "experimental-response-writer")]
                crate::udp::UdpResponse::Prepared(reply) => {
                    if let Some(category) = reply.send_category {
                        metrics.record_query_pipeline_latency(
                            crate::QueryPipelineStage::Send,
                            category,
                            started.elapsed(),
                        );
                    }
                }
            }
        }
    }
}

/// Prepare a complete local batch without publishing any TX descriptors. This
/// boundary is shared with the queue-group owner so a blocked send can retain
/// staged frames and metric indices across scheduling turns.
fn prepare_tx_frames(
    frames: &mut Vec<Option<ReceivedFrame>>,
    slab: &mut HeapSlab,
    pending: &mut VecDeque<(usize, Option<std::time::Instant>)>,
    outbound: &[UdpOutbound],
    metrics: &RuntimeMetrics,
    mut recycle: impl FnMut(xdp::Packet),
) -> io::Result<()> {
    if !slab.is_empty() || !pending.is_empty() {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "previous TX batch is still staged",
        ));
    }
    let result = (|| {
        for (index, response) in outbound.iter().enumerate() {
            let UdpPacketTarget::AfXdp { frame_index } = response.target else {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "AF_XDP backend cannot send standard UDP socket target",
                ));
            };
            let slot = frames.get_mut(frame_index).ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    "AF_XDP response referenced an unknown frame",
                )
            })?;
            let Some(mut frame) = slot.take() else {
                continue;
            };
            let started = response
                .query_metrics
                .as_ref()
                .and_then(|_| metrics.start_pipeline_timer());
            let written = if response.benchmark_fixed_response {
                write_benchmark_fixed_dns_response(&mut frame.packet, frame.frame)
            } else {
                match &response.response {
                    crate::udp::UdpResponse::Owned(bytes) => {
                        write_udp_ip_response(&mut frame.packet, frame.frame, bytes)
                    }
                    #[cfg(feature = "experimental-response-writer")]
                    crate::udp::UdpResponse::Prepared(reply) => {
                        response_writer::finish(&mut frame, frame_index, *reply)
                    }
                }
            };
            if let Err(error) = written {
                recycle(frame.packet);
                return Err(io::Error::new(ErrorKind::InvalidData, error.to_string()));
            }
            if let Some(overflow) = slab.push_front(frame.packet) {
                recycle(overflow);
                return Err(io::Error::new(
                    ErrorKind::OutOfMemory,
                    "AF_XDP TX slab reached capacity",
                ));
            }
            pending.push_back((index, started));
        }
        Ok(())
    })();
    if result.is_err() {
        while let Some(packet) = slab.pop_back() {
            recycle(packet);
        }
        pending.clear();
    }
    for frame in frames.drain(..).flatten() {
        recycle(frame.packet);
    }
    result
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

#[inline]
fn swap_adjacent_header_fields<const WIDTH: usize>(frame: &mut [u8], offset: usize) {
    // A single bounded region lets the compiler swap fixed-width fields in
    // words instead of independently checking every byte in each address.
    let (left, right) = frame[offset..offset + WIDTH * 2].split_at_mut(WIDTH);
    left.swap_with_slice(right);
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

    swap_adjacent_header_fields::<6>(frame, 0);
    swap_adjacent_header_fields::<4>(frame, packet.ipv4_header_offset + 12);
    swap_adjacent_header_fields::<2>(frame, packet.udp_header_offset);

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

    swap_adjacent_header_fields::<6>(frame, 0);
    swap_adjacent_header_fields::<16>(frame, packet.ipv6_header_offset + 8);
    swap_adjacent_header_fields::<2>(frame, packet.udp_header_offset);

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
    let (chunks, remainder) = header.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ones_complement_add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_endian = "little"
    ))]
    let bytes = {
        let (wide, tail) = bytes.as_chunks::<16>();
        // SAFETY: this branch is compiled only with little-endian AArch64 NEON.
        // Each unaligned load is bounded by an exact 16-byte chunk. No store,
        // pointer escape or access beyond the supplied slice is performed.
        // At most 65535 UDP bytes plus the separately added pseudo-header are
        // summed by callers, so neither the u32 lanes nor their total overflow.
        // SAFETY-ID: UNSAFE-BORONDNS-SERVER-AF-XDP-011
        unsafe {
            use std::arch::aarch64::*;
            let mut lanes = vdupq_n_u32(0);
            for chunk in wide {
                let octets = vld1q_u8(chunk.as_ptr());
                let words = vreinterpretq_u16_u8(vrev16q_u8(octets));
                lanes = vaddq_u32(lanes, vpaddlq_u16(words));
            }
            sum += vaddvq_u32(lanes);
        }
        tail
    };
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = remainder.first() {
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
mod redirect_tests;

#[cfg(test)]
mod tests {
    #[cfg(feature = "experimental-xdp-conditional-wakeup")]
    #[test]
    fn conditional_fill_wakeup_rechecks_idle_even_without_new_buffers() {
        let mut pending = false;
        super::mark_conditional_fill_kick(&mut pending, 64, || false);
        assert!(
            !pending,
            "active receive driver needs no redundant FILL kick"
        );
        super::mark_conditional_fill_kick(&mut pending, 0, || true);
        assert!(
            pending,
            "idle receive driver can need a wake with buffers already published"
        );
        super::mark_conditional_fill_kick(&mut pending, 0, || {
            panic!("failed wake must remain pending")
        });
        assert!(pending);
    }

    #[cfg(feature = "experimental-xdp-conditional-wakeup")]
    #[test]
    fn conditional_tx_wakeup_mapping_rejects_old_and_invalid_layouts() {
        let size = std::mem::size_of::<libc::xdp_mmap_offsets>();
        assert_eq!(super::tx_wakeup_mapping_length(196, size).unwrap(), 200);
        for (offset, length) in [(196, size - 32), (3, size), (4096, size), (u64::MAX, size)] {
            assert!(super::tx_wakeup_mapping_length(offset, length).is_err());
        }
        assert!(super::RingWakeupFlags::map(-1, super::RingKickKind::Tx).is_err());
        assert!(super::RingWakeupFlags::map(-1, super::RingKickKind::Fill).is_err());
    }

    #[cfg(feature = "experimental-xdp-conditional-wakeup")]
    #[test]
    fn conditional_tx_wakeup_skips_only_fresh_active_kernel_work() {
        let mut pending = false;
        super::mark_conditional_tx_kick(&mut pending, 64, || false);
        assert!(!pending, "active kernel needs no redundant TX kick");
        super::mark_conditional_tx_kick(&mut pending, 1, || true);
        assert!(pending, "an isolated packet must wake an idle driver");
    }

    #[cfg(feature = "experimental-xdp-conditional-wakeup")]
    #[test]
    fn conditional_tx_wakeup_preserves_failed_wake_and_zero_admission() {
        let mut pending = true;
        super::mark_conditional_tx_kick(&mut pending, 64, || {
            panic!("an outstanding failed wake must not trust a cleared flag")
        });
        assert!(pending);
        super::mark_conditional_tx_kick(&mut pending, 0, || panic!("no new work"));
        assert!(pending);
        pending = false;
        super::mark_conditional_tx_kick(&mut pending, 0, || panic!("no new work"));
        assert!(!pending);
    }

    #[cfg(feature = "experimental-xdp-conditional-wakeup")]
    #[test]
    fn conditional_tx_wakeup_observes_each_new_publication() {
        let mut pending = false;
        let mut calls = 0;
        for needs_wakeup in [false, true, false, true] {
            super::mark_conditional_tx_kick(&mut pending, 1, || {
                calls += 1;
                needs_wakeup
            });
            assert_eq!(pending, needs_wakeup);
            pending = false; // Successful service; next batch is a new publication.
        }
        assert_eq!(calls, 4);
    }

    #[cfg(feature = "experimental-response-writer")]
    include!("af_xdp/response_writer_tests.rs");

    fn staged_response(index: usize, size: usize) -> UdpOutbound {
        UdpOutbound {
            response: crate::udp::UdpResponse::Owned(vec![0x53; size]),
            target: target_for_frame(index),
            query_metrics: None,
            benchmark_fixed_response: false,
        }
    }

    #[test]
    fn group_staging_failure_returns_every_local_frame_once() {
        for failure in 0..4 {
            let mut buffers = [[0u8; 2048]; 3];
            let mut expected = Vec::new();
            let mut frames = buffers
                .iter_mut()
                .map(|buffer| {
                    let mut packet = xdp::Packet::testing_new(buffer);
                    packet
                        .insert(0, &ipv4_udp_frame(&[1; 4])[..ipv4_udp_frame_len(4)])
                        .unwrap();
                    expected.push(packet.as_ptr() as usize);
                    let frame = parse_udp_ip_frame(&packet).unwrap();
                    Some(ReceivedFrame {
                        packet,
                        frame,
                        #[cfg(feature = "experimental-response-writer")]
                        prepared_len: None,
                        #[cfg(feature = "experimental-response-writer")]
                        reply_epoch: 1,
                    })
                })
                .collect::<Vec<_>>();
            let mut outbound = vec![staged_response(0, 12), staged_response(1, 12)];
            match failure {
                0 => outbound[1].target = UdpPacketTarget::Socket("192.0.2.1:53".parse().unwrap()),
                1 => outbound[1].target = target_for_frame(9),
                2 => outbound[1] = staged_response(1, 3000),
                _ => {}
            }
            let mut slab = HeapSlab::with_capacity(if failure == 3 { 1 } else { 3 });
            let mut pending = VecDeque::with_capacity(3);
            let mut reclaimed = Vec::new();
            assert!(
                prepare_tx_frames(
                    &mut frames,
                    &mut slab,
                    &mut pending,
                    &outbound,
                    &RuntimeMetrics::new(),
                    |packet| reclaimed.push(packet.as_ptr() as usize)
                )
                .is_err()
            );
            assert!(
                slab.is_empty(),
                "failed staging must reclaim earlier staged frames"
            );
            assert!(
                pending.is_empty(),
                "failed staging cannot retain stale metric indices"
            );
            assert!(frames.is_empty());
            expected.sort_unstable();
            reclaimed.sort_unstable();
            assert_eq!(
                reclaimed, expected,
                "failure={failure}: exactly one owner per frame"
            );
        }
    }

    #[test]
    fn group_staging_preserves_fifo_indices_and_pending_batch() {
        let mut buffers = [[0u8; 2048]; 3];
        let mut frames = buffers
            .iter_mut()
            .map(|buffer| {
                let mut packet = xdp::Packet::testing_new(buffer);
                packet
                    .insert(0, &ipv4_udp_frame(&[1; 4])[..ipv4_udp_frame_len(4)])
                    .unwrap();
                let frame = parse_udp_ip_frame(&packet).unwrap();
                Some(ReceivedFrame {
                    packet,
                    frame,
                    #[cfg(feature = "experimental-response-writer")]
                    prepared_len: None,
                    #[cfg(feature = "experimental-response-writer")]
                    reply_epoch: 1,
                })
            })
            .collect::<Vec<_>>();
        let outbound = [
            staged_response(2, 12),
            staged_response(0, 16),
            staged_response(2, 20),
        ];
        let mut slab = HeapSlab::with_capacity(3);
        let mut pending = VecDeque::with_capacity(3);
        let mut recycled = 0;
        prepare_tx_frames(
            &mut frames,
            &mut slab,
            &mut pending,
            &outbound,
            &RuntimeMetrics::new(),
            |_| recycled += 1,
        )
        .unwrap();
        assert_eq!(recycled, 1, "unanswered frame returns to UMEM");
        assert_eq!(pending.iter().map(|p| p.0).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(
            slab.len(),
            2,
            "duplicate target cannot enqueue the same frame twice"
        );
        assert_eq!(
            prepare_tx_frames(
                &mut frames,
                &mut slab,
                &mut pending,
                &[],
                &RuntimeMetrics::new(),
                |_| panic!("must not touch previous batch")
            )
            .unwrap_err()
            .kind(),
            ErrorKind::AlreadyExists
        );
        for length in [12, 16] {
            let packet = slab.pop_back().unwrap();
            let frame = parse_udp_ip_frame(&packet).unwrap();
            assert_eq!(frame.payload().len(), length);
        }
        assert!(slab.is_empty());
    }
    use std::{
        cell::Cell,
        fs,
        future::Future,
        io::{Read, Write},
        os::unix::fs::{PermissionsExt, symlink},
        os::unix::net::UnixStream,
        task::{Context, Poll, Waker},
    };

    use super::*;

    #[cfg(feature = "experimental-xdp-time-turn")]
    #[test]
    fn receive_time_turn_uses_elapsed_time_not_a_fixed_batch_budget() {
        let start = std::time::Instant::now();
        let mut turn = ReceiveTimeTurn {
            started: start,
            batches: 0,
        };
        for _ in 0..100 {
            for _ in 1..ReceiveTimeTurn::CLOCK_INTERVAL {
                assert!(!turn.due(|| panic!("clock sampled too often")));
            }
            assert!(!turn.due(|| start + Duration::from_micros(999)));
        }
        for _ in 1..ReceiveTimeTurn::CLOCK_INTERVAL {
            assert!(!turn.due(|| panic!("clock sampled too often")));
        }
        assert!(turn.due(|| start + ReceiveTimeTurn::LIMIT));
    }

    #[cfg(feature = "experimental-xdp-time-turn")]
    #[test]
    fn receive_time_turn_expired_checkpoint_yields_and_restarts_after_resume() {
        let old_start = std::time::Instant::now() - Duration::from_secs(1);
        let mut turn = ReceiveTimeTurn {
            started: old_start,
            batches: ReceiveTimeTurn::CLOCK_INTERVAL - 1,
        };
        let mut context = Context::from_waker(Waker::noop());
        {
            let mut checkpoint = std::pin::pin!(turn.checkpoint());
            assert!(checkpoint.as_mut().poll(&mut context).is_pending());
            assert!(checkpoint.as_mut().poll(&mut context).is_ready());
        }
        assert!(turn.started > old_start);
        assert_eq!(turn.batches, 0);
        let mut checkpoint = std::pin::pin!(turn.checkpoint());
        assert!(checkpoint.as_mut().poll(&mut context).is_ready());
    }

    #[test]
    fn af_xdp_payload_buffers_grow_within_bound_and_do_not_expose_stale_tails() {
        let mut first = UdpInbound::new_af_xdp();
        let mut second = UdpInbound::new_af_xdp();
        assert!(first.buffer.is_empty());
        assert_eq!(UdpInbound::new().buffer.len(), UDP_PACKET_BUFFER_LEN);
        for len in [
            0, 1, 127, 128, 129, 255, 256, 511, 512, 1023, 1024, 1025, 2047, 2048, 4095, 4096, 13,
            0,
        ] {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_add(len as u8))
                .collect();
            first.copy_af_xdp_payload(&data);
            second.copy_af_xdp_payload(&[0xa5; 17]);
            assert_eq!(first.payload(), data);
            assert_eq!(second.payload(), [0xa5; 17]);
            assert!(first.buffer.len() <= UDP_PACKET_BUFFER_LEN);
            assert!(first.buffer.capacity() <= UDP_PACKET_BUFFER_LEN);
            assert!(second.buffer.capacity() <= 128);
        }
        let allocation = first.buffer.as_ptr();
        first.copy_af_xdp_payload(&[0x5a; 31]);
        assert_eq!(first.buffer.as_ptr(), allocation);
        assert_eq!(first.payload(), [0x5a; 31]);
    }

    #[test]
    #[should_panic]
    fn af_xdp_payload_storage_rejects_oversized_input_before_growing() {
        let mut inbound = UdpInbound::new_af_xdp();
        inbound.copy_af_xdp_payload(&vec![0; UDP_PACKET_BUFFER_LEN + 1]);
    }

    #[test]
    fn fixed_width_header_swaps_match_bytewise_oracle_without_touching_neighbors() {
        fn check<const WIDTH: usize>() {
            for offset in 0..32 {
                let mut actual: Vec<u8> = (0..offset + WIDTH * 2 + 33)
                    .map(|index| (index as u8).wrapping_mul(73).wrapping_add(11))
                    .collect();
                let original = actual.clone();
                let mut expected = actual.clone();
                for index in 0..WIDTH {
                    expected.swap(offset + index, offset + WIDTH + index);
                }
                swap_adjacent_header_fields::<WIDTH>(&mut actual, offset);
                assert_eq!(actual, expected, "width={WIDTH}, offset={offset}");
                swap_adjacent_header_fields::<WIDTH>(&mut actual, offset);
                assert_eq!(actual, original);
            }
        }
        check::<2>();
        check::<4>();
        check::<6>();
        check::<16>();
    }

    #[test]
    fn checksum_wide_chunks_match_scalar_for_offsets_tails_and_max_udp_lengths() {
        for pattern in [0u8, 0xff, 0xa5, 0x37] {
            let bytes: Vec<u8> = (0..65568)
                .map(|i| {
                    if pattern == 0x37 {
                        (i as u8).wrapping_mul(73).wrapping_add((i >> 8) as u8)
                    } else {
                        pattern
                    }
                })
                .collect();
            for offset in 0..16 {
                for len in (0..=257).chain([511, 512, 1232, 4096, 65507, 65527, 65535]) {
                    let data = &bytes[offset..offset + len];
                    let mut expected = 123456u32;
                    for pair in data.chunks(2) {
                        expected += u32::from(pair[0]) << 8;
                        if pair.len() == 2 {
                            expected += u32::from(pair[1]);
                        }
                    }
                    assert_eq!(
                        ones_complement_add_bytes(123456, data),
                        expected,
                        "pattern={pattern}, offset={offset}, len={len}"
                    );
                }
            }
        }
    }

    #[test]
    fn receive_prefetch_slab_preserves_bytes_order_capacity_and_empty_packets() {
        let mut buffers = [[0u8; 2048]; 7];
        let lengths = [0, 1, 63, 64, 65, 128, 257];
        let mut slab = ReceiveSlab::with_capacity(4);
        for (index, (buffer, length)) in buffers.iter_mut().zip(lengths).enumerate() {
            let mut packet = xdp::Packet::testing_new(buffer);
            packet.insert(0, &vec![index as u8; length]).unwrap();
            if index < 4 {
                assert!(slab.push_front(packet).is_none());
            } else {
                let packet = slab
                    .push_front(packet)
                    .expect("a full slab returns ownership");
                assert_eq!(&*packet, vec![index as u8; length]);
                prefetch_packet_head(&packet);
            }
        }
        assert_eq!(slab.len(), 4);
        assert_eq!(slab.available(), 0);
        for (index, length) in lengths[..4].iter().enumerate() {
            let packet = slab.pop_back().unwrap();
            assert_eq!(&*packet, vec![index as u8; *length]);
        }
        assert!(slab.is_empty());
        assert!(slab.pop_back().is_none());
        assert_eq!(slab.available(), 4);
    }

    #[test]
    fn fill_refill_progresses_with_partial_capacity_and_available_frames() {
        // xdp 0.7.3 FillRing::enqueue limits the request by free UMEM
        // frames, but XskProducer::reserve is all-or-nothing. mlx5 can
        // stop its RX queue with a nonempty FILL tail smaller than the
        // driver's allocation batch. Requiring a wholly empty ring then
        // prevents the producer from ever replenishing it.
        for capacity in [1, 63, 64, 4095, 8191, 8192] {
            for available in [1, 63, 64, 511, 8192, 16384] {
                let mut calls = 0;
                let mut transferred = 0;
                let queued = enqueue_fill_frames(8192, |requested| {
                    calls += 1;
                    let actual = requested.min(available);
                    if actual <= capacity {
                        transferred += actual;
                        Ok(actual)
                    } else {
                        Ok(0)
                    }
                })
                .expect("refill succeeds");
                assert!(
                    queued > 0,
                    "free slots={capacity}, available frames={available}"
                );
                assert!(queued <= capacity.min(available));
                assert_eq!(
                    queued, transferred,
                    "successful ownership transfer is counted once"
                );
                assert!(calls <= 14, "bounded logarithmic reservation attempts");
            }
        }
    }

    #[test]
    fn fill_refill_empty_resources_are_bounded_and_errors_are_preserved() {
        let mut calls = 0;
        assert_eq!(
            enqueue_fill_frames(8192, |_| {
                calls += 1;
                Ok(0)
            })
            .unwrap(),
            0
        );
        assert!(calls <= 14);
        let mut calls = 0;
        let error = enqueue_fill_frames(8192, |_| {
            calls += 1;
            Err(io::Error::from_raw_os_error(libc::EIO))
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn fill_refill_fast_path_and_zero_request_do_not_retry() {
        let mut calls = 0;
        assert_eq!(
            enqueue_fill_frames(8192, |requested| {
                calls += 1;
                Ok(requested)
            })
            .unwrap(),
            8192
        );
        assert_eq!(calls, 1);
        assert_eq!(
            enqueue_fill_frames(0, |_| panic!("no reservation for zero frames")).unwrap(),
            0
        );
    }

    #[test]
    fn xdp_object_reader_binds_trusted_regular_file_descriptor() {
        let directory = std::env::temp_dir().join(format!(
            "borondns-xdp-object-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir(&directory).expect("create fixture directory");
        let object = directory.join("redirect.bpf.o");
        fs::write(&object, b"trusted-object").expect("write fixture object");
        fs::set_permissions(&object, fs::Permissions::from_mode(0o600))
            .expect("secure fixture permissions");

        assert_eq!(
            read_trusted_xdp_object(&object).expect("trusted object"),
            b"trusted-object"
        );
        assert!(read_trusted_xdp_object(Path::new("relative.bpf.o")).is_err());

        let link = directory.join("redirect-link.bpf.o");
        symlink(&object, &link).expect("create symlink fixture");
        assert!(read_trusted_xdp_object(&link).is_err());

        fs::set_permissions(&object, fs::Permissions::from_mode(0o622))
            .expect("make fixture writable");
        assert!(read_trusted_xdp_object(&object).is_err());

        fs::remove_dir_all(directory).expect("remove fixture directory");
    }

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

    fn push_test_packet(slab: &mut impl Slab, buffer: &mut [u8; 2 * 1024], id: u8) {
        let mut packet = xdp::Packet::testing_new(buffer);
        packet.insert(0, &[id]).expect("test packet payload");
        assert!(slab.push_front(packet).is_none());
    }

    #[test]
    fn full_second_receive_pass_retains_exact_tail_for_next_batch() {
        const BATCH_SIZE: usize = 8;
        let mut buffers = [[0u8; 2 * 1024]; BATCH_SIZE * 2 - 1];
        let mut slab = ReceiveSlab::with_capacity(BATCH_SIZE);
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
        let mut slab = ReceiveSlab::with_capacity(BATCH_SIZE);

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
    fn redirect_loader_rejects_invalid_object_for_both_listener_families() {
        for address in ["192.0.2.53:53", "[2001:db8::53]:53"] {
            assert!(load_redirect_object(b"not an ELF object", address.parse().unwrap()).is_err());
        }
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
    fn selects_validated_umem_frame_size_without_silent_fallback() {
        assert_eq!(XdpConfig::default().umem_frame_size, 4096);
        for size in [2048, 4096] {
            assert_eq!(
                u32::try_from(configured_umem_frame_size(size).unwrap()).unwrap(),
                size
            );
            prepare_xdp_config(&XdpConfig {
                umem_frame_size: size,
                ..XdpConfig::default()
            })
            .expect("supported frame size");
        }
        for size in [0, 1024, 3072, 8192, u32::MAX] {
            let config = XdpConfig {
                umem_frame_size: size,
                ..XdpConfig::default()
            };
            assert_eq!(
                prepare_xdp_config(&config).err().unwrap().kind(),
                ErrorKind::InvalidInput
            );
        }
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
