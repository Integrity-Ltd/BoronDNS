#![allow(dead_code)]
#![allow(unsafe_code)]

use std::{
    error::Error,
    ffi::CString,
    fmt,
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Range,
    os::fd::RawFd,
    path::Path,
    sync::Arc,
    time::Duration,
};

use aya::{
    Ebpf, Pod,
    maps::{Array, XskMap},
    programs::{Xdp, XdpFlags},
};
use oxidedns_core::config::{XdpConfig, XdpMode, XdpZeroCopyMode};
use tokio::net::UdpSocket;
use xdp::{
    slab::{HeapSlab, Slab},
    socket::{PollTimeout, XdpSocketBuilder},
};

use super::{
    PacketIo, RuntimeMetrics, UDP_PACKET_BUFFER_LEN, UdpInbound, UdpOutbound, UdpPacketTarget,
    record_query_send_metric,
};

const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const IP_PROTOCOL_UDP: u8 = 17;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AfXdpFrameError {
    ShortEthernet,
    UnsupportedEtherType(u16),
    ShortIpv4,
    InvalidIpv4Header,
    NotUdp,
    FragmentedIpv4,
    InvalidIpv4TotalLength,
    ShortUdp,
    InvalidUdpLength,
    ShortIpv6,
    UnsupportedIpv6NextHeader(u8),
    InvalidIpv6PayloadLength,
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
            Self::NotUdp => formatter.write_str("IPv4 packet is not UDP"),
            Self::FragmentedIpv4 => formatter.write_str("fragmented IPv4 UDP packet"),
            Self::InvalidIpv4TotalLength => formatter.write_str("invalid IPv4 total length"),
            Self::ShortUdp => formatter.write_str("short UDP datagram"),
            Self::InvalidUdpLength => formatter.write_str("invalid UDP length"),
            Self::ShortIpv6 => formatter.write_str("short IPv6 packet"),
            Self::UnsupportedIpv6NextHeader(next_header) => {
                write!(formatter, "unsupported IPv6 next header {next_header}")
            }
            Self::InvalidIpv6PayloadLength => formatter.write_str("invalid IPv6 payload length"),
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
    socket: xdp::socket::XdpSocket,
    _redirect: Option<Arc<XdpRedirectGuard>>,
    rx_ring: xdp::RxRing,
    tx_ring: xdp::WakableTxRing,
    fill_ring: xdp::WakableFillRing,
    completion_ring: xdp::CompletionRing,
    umem: xdp::Umem,
    local_addr: SocketAddr,
    batch_size: usize,
    tx_wakeup_interval: usize,
    tx_send_passes: usize,
    fill_ring_size: usize,
    completion_ring_size: usize,
    inbound: Vec<UdpInbound>,
    active_inbound: usize,
    frames: Vec<Option<ReceivedFrame>>,
    recv_slab: HeapSlab,
    tx_slab: HeapSlab,
}

struct ReceivedFrame {
    packet: xdp::Packet,
    frame: UdpIpFrame,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RedirectConfig {
    udp_dest_port_be: u16,
}

// SAFETY: RedirectConfig is repr(C), Copy, contains only an integer field, and
// has no references or invalid bit patterns.
unsafe impl Pod for RedirectConfig {}

struct XdpRedirectGuard {
    _bpf: Ebpf,
}

impl XdpRedirectGuard {
    fn attach(
        object: &Path,
        interface: &str,
        mode: XdpMode,
        udp_dest_port: u16,
        xsk_entries: &[(u32, RawFd)],
    ) -> io::Result<Self> {
        let mut bpf = Ebpf::load_file(object).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "failed to load OxideDNS XDP redirect object {}: {error}",
                    object.display()
                ),
            )
        })?;
        {
            let map = bpf.map_mut("REDIRECT_CONFIG").ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "REDIRECT_CONFIG map missing from OxideDNS XDP redirect object",
                )
            })?;
            let mut config = Array::<_, RedirectConfig>::try_from(map).map_err(aya_error)?;
            config
                .set(
                    0,
                    RedirectConfig {
                        udp_dest_port_be: udp_dest_port.to_be(),
                    },
                    0,
                )
                .map_err(aya_error)?;
        }
        {
            let map = bpf.map_mut("OXIDEDNS_XSKS").ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "OXIDEDNS_XSKS map missing from OxideDNS XDP redirect object",
                )
            })?;
            let mut xsk_map = XskMap::try_from(map).map_err(aya_error)?;
            for (queue_id, socket_fd) in xsk_entries {
                xsk_map.set(*queue_id, *socket_fd, 0).map_err(aya_error)?;
            }
        }
        {
            let program: &mut Xdp = bpf
                .program_mut("oxidedns_xdp_redirect")
                .ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "oxidedns_xdp_redirect program missing from OxideDNS XDP redirect object",
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

impl AfXdpPacketIo {
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
        let prepared = prepare_xdp_config(config).map_err(xdp_config_error)?;
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
        if prepared.queue_id >= caps.queue_count {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "xdp.queue_id {} is outside interface queue count {}",
                    prepared.queue_id, caps.queue_count
                ),
            ));
        }
        if config.zero_copy == XdpZeroCopyMode::Require && !caps.zero_copy.is_available() {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "xdp.zero_copy = \"require\" but interface does not report zero-copy support",
            ));
        }
        let queue_count = queue_count.max(1);
        let queue_count_u32 = u32::try_from(queue_count).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "AF_XDP worker count is too large for queue indexing",
            )
        })?;
        let last_queue_id = prepared
            .queue_id
            .checked_add(queue_count_u32.saturating_sub(1))
            .ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidInput, "AF_XDP queue range overflows u32")
            })?;
        if last_queue_id >= caps.queue_count {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "AF_XDP queue range {}..={} is outside interface queue count {}",
                    prepared.queue_id, last_queue_id, caps.queue_count
                ),
            ));
        }

        let udp_socket = Arc::new(udp_socket);
        let mut adapters = Vec::with_capacity(queue_count);
        let mut xsk_entries = Vec::with_capacity(queue_count);
        for offset in 0..queue_count_u32 {
            let queue_id = prepared.queue_id + offset;
            let (adapter, socket_fd) =
                Self::bind_queue(udp_socket.clone(), local_addr, config, nic, queue_id)?;
            adapters.push(adapter);
            xsk_entries.push((queue_id, socket_fd));
        }
        let redirect = Arc::new(XdpRedirectGuard::attach(
            redirect_object,
            &prepared.interface,
            config.mode,
            local_addr.port(),
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
        unsafe {
            rings
                .fill_ring
                .enqueue(&mut umem, fill_ring_size, true)
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("failed to populate AF_XDP fill ring: {error}"),
                    )
                })?;
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
                tx_wakeup_interval: config.tx_wakeup_interval,
                tx_send_passes: 0,
                fill_ring_size,
                completion_ring_size: config.completion_ring_size as usize,
                inbound: (0..prepared.batch_size)
                    .map(|_| UdpInbound::new())
                    .collect(),
                active_inbound: 0,
                frames: Vec::with_capacity(prepared.batch_size),
                recv_slab: HeapSlab::with_capacity(prepared.batch_size),
                tx_slab: HeapSlab::with_capacity(prepared.batch_size),
            },
            socket_fd,
        ))
    }

    fn drain_completions(&mut self) {
        self.completion_ring
            .dequeue(&mut self.umem, self.completion_ring_size);
    }

    fn release_unsent_frames(&mut self) {
        for frame in self.frames.drain(..).flatten() {
            self.umem.free_packet(frame.packet);
        }
    }

    fn replenish_fill_ring(&mut self) -> io::Result<()> {
        // SAFETY: the fill ring and UMEM are owned by this adapter. Packets
        // returned to UMEM are not accessed again before being re-enqueued.
        unsafe {
            self.fill_ring
                .enqueue(&mut self.umem, self.fill_ring_size, true)
                .map(|_| ())
        }
    }

    fn drain_tx_slab_to_umem(&mut self) {
        while let Some(packet) = self.tx_slab.pop_back() {
            self.umem.free_packet(packet);
        }
    }

    fn push_inbound(&mut self, packet: xdp::Packet, frame: UdpIpFrame) -> bool {
        let payload = frame.payload();
        if payload.len() > UDP_PACKET_BUFFER_LEN {
            self.umem.free_packet(packet);
            return false;
        }
        if self.active_inbound == self.inbound.len() {
            self.inbound.push(UdpInbound::new());
        }

        let frame_index = self.frames.len();
        let peer = frame.source_addr(&packet);
        let inbound = &mut self.inbound[self.active_inbound];
        let payload_len = payload.len();
        inbound.buffer[..payload_len].copy_from_slice(&packet[payload]);
        inbound.len = payload_len;
        inbound.peer = peer;
        inbound.target = target_for_frame(frame_index);
        self.frames.push(Some(ReceivedFrame { packet, frame }));
        self.active_inbound += 1;
        true
    }
}

impl PacketIo for AfXdpPacketIo {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    async fn recv_batch(&mut self) -> io::Result<&[UdpInbound]> {
        self.release_unsent_frames();
        self.drain_completions();
        self.replenish_fill_ring()?;
        self.active_inbound = 0;
        self.frames.clear();

        loop {
            while !self
                .socket
                .poll_read(PollTimeout::new(Some(Duration::from_millis(10))))?
            {
                tokio::task::yield_now().await;
            }
            // SAFETY: packets returned by the RX ring are kept in `self.frames`
            // only until `send_batch` or the next `recv_batch`, both of which
            // either transmit them or return them to the same UMEM.
            let received = unsafe { self.rx_ring.recv(&self.umem, &mut self.recv_slab) };
            for _ in 0..received {
                let Some(packet) = self.recv_slab.pop_back() else {
                    break;
                };
                match parse_udp_ip_frame(&packet) {
                    Ok(frame) => {
                        self.push_inbound(packet, frame);
                        if self.active_inbound == self.batch_size {
                            return Ok(&self.inbound[..self.active_inbound]);
                        }
                    }
                    Err(_) => self.umem.free_packet(packet),
                }
            }
            if self.active_inbound > 0 {
                return Ok(&self.inbound[..self.active_inbound]);
            }
            self.replenish_fill_ring()?;
        }
    }

    async fn send_batch(
        &mut self,
        outbound: &[UdpOutbound],
        metrics: &RuntimeMetrics,
    ) -> io::Result<()> {
        let mut sent = 0usize;
        for packet in outbound {
            let UdpPacketTarget::AfXdp { frame_index } = packet.target else {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "AF_XDP backend cannot send standard UDP socket target",
                ));
            };
            let Some(slot) = self.frames.get_mut(frame_index) else {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "AF_XDP response referenced an unknown frame",
                ));
            };
            let Some(mut frame) = slot.take() else {
                continue;
            };
            let send_started = packet
                .query_metrics
                .as_ref()
                .and_then(|_| metrics.start_pipeline_timer());
            let write_result =
                write_udp_ip_response(&mut frame.packet, frame.frame, &packet.response);
            if let Err(error) = write_result {
                self.umem.free_packet(frame.packet);
                return Err(io::Error::new(ErrorKind::InvalidData, error.to_string()));
            }
            if let Some(overflow) = self.tx_slab.push_front(frame.packet) {
                self.umem.free_packet(overflow);
                return Err(io::Error::new(
                    ErrorKind::OutOfMemory,
                    "AF_XDP TX slab reached capacity",
                ));
            }
            sent += 1;
            if let (Some(query_metrics), Some(started)) = (&packet.query_metrics, send_started) {
                record_query_send_metric(
                    query_metrics,
                    &packet.response,
                    metrics,
                    started.elapsed(),
                );
            }
        }

        self.release_unsent_frames();
        while !self.tx_slab.is_empty() {
            self.socket
                .poll_write(PollTimeout::new(Some(Duration::from_millis(10))))?;
            // SAFETY: all packets in `tx_slab` came from this adapter's UMEM,
            // and the UMEM outlives the socket and TX ring.
            let wakeup = should_wakeup_tx(self.tx_wakeup_interval, self.tx_send_passes);
            self.tx_send_passes = self.tx_send_passes.wrapping_add(1);
            match unsafe { self.tx_ring.send(&mut self.tx_slab, wakeup) } {
                Ok(queued) if queued > 0 => {}
                Ok(_) => tokio::task::yield_now().await,
                Err(error) => {
                    self.drain_tx_slab_to_umem();
                    return Err(error);
                }
            }
            self.drain_completions();
        }
        self.drain_completions();
        self.replenish_fill_ring()?;

        if sent > 0 {
            metrics.record_udp_send_batch(sent);
        }
        Ok(())
    }
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

fn should_wakeup_tx(interval: usize, send_passes: usize) -> bool {
    interval != 0 && send_passes % interval == 0
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
    if frame[ipv4_header_offset + 9] != IP_PROTOCOL_UDP {
        return Err(AfXdpFrameError::NotUdp);
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

    let total_len = u16::try_from(packet_len)
        .map_err(|_| AfXdpFrameError::ResponseTooLarge)?
        .to_be_bytes();
    frame[packet.ipv4_header_offset + 2..packet.ipv4_header_offset + 4].copy_from_slice(&total_len);
    let udp_len = u16::try_from(UDP_HEADER_LEN + response_len)
        .map_err(|_| AfXdpFrameError::ResponseTooLarge)?
        .to_be_bytes();
    frame[packet.udp_header_offset + 4..packet.udp_header_offset + 6].copy_from_slice(&udp_len);
    frame[packet.udp_header_offset + 6..packet.udp_header_offset + 8].copy_from_slice(&[0, 0]);

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

    let payload_len = u16::try_from(udp_len)
        .map_err(|_| AfXdpFrameError::ResponseTooLarge)?
        .to_be_bytes();
    frame[packet.ipv6_header_offset + 4..packet.ipv6_header_offset + 6]
        .copy_from_slice(&payload_len);
    frame[packet.udp_header_offset + 4..packet.udp_header_offset + 6].copy_from_slice(&payload_len);
    frame[packet.udp_header_offset + 6..packet.udp_header_offset + 8].copy_from_slice(&[0, 0]);
    let checksum = udp_ipv6_checksum(frame, packet.udp_header_offset, udp_len);
    frame[packet.udp_header_offset + 6..packet.udp_header_offset + 8]
        .copy_from_slice(&checksum.to_be_bytes());

    Ok(frame_len)
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
    use super::*;

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
        frame
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
    fn tx_wakeup_interval_wakes_first_and_then_every_n_passes() {
        assert!(should_wakeup_tx(1, 0));
        assert!(should_wakeup_tx(1, 7));
        assert!(should_wakeup_tx(4, 0));
        assert!(!should_wakeup_tx(4, 1));
        assert!(!should_wakeup_tx(4, 3));
        assert!(should_wakeup_tx(4, 4));
        assert!(!should_wakeup_tx(0, 0));
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
    fn rejects_fragmented_ipv4_udp_frame() {
        let mut frame = ipv4_udp_frame(&[1, 2, 3, 4]);
        frame[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8]
            .copy_from_slice(&0x2000u16.to_be_bytes());

        assert_eq!(
            parse_udp_ipv4_frame(&frame),
            Err(AfXdpFrameError::FragmentedIpv4)
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
        assert_eq!(ipv4_checksum(&frame[ip..ip + IPV4_MIN_HEADER_LEN]), 0);
        let udp = ip + IPV4_MIN_HEADER_LEN;
        assert_eq!(u16::from_be_bytes([frame[udp], frame[udp + 1]]), 53);
        assert_eq!(u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]), 12345);
        assert_eq!(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]), 14);
        assert_eq!(u16::from_be_bytes([frame[udp + 6], frame[udp + 7]]), 0);
    }

    #[test]
    fn rewrites_udp_ipv6_response_headers_and_checksum() {
        let mut frame = ipv6_udp_frame(&[1, 2, 3, 4]);
        let packet = parse_udp_ipv6_frame(&frame).expect("IPv6 UDP frame");
        frame[packet.payload.start..packet.payload.start + 6].copy_from_slice(&[9, 8, 7, 6, 5, 4]);

        let frame_len =
            rewrite_udp_ipv6_response_headers(&mut frame, packet, 6).expect("rewritten response");

        assert_eq!(frame_len, ipv6_udp_frame_len(6));
        assert_eq!(&frame[0..6], &[0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
        assert_eq!(&frame[6..12], &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
        let ip = ETHERNET_HEADER_LEN;
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
}
