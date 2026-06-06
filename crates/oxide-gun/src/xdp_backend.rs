#![allow(unsafe_code)]

use std::ffi::CString;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf, Pod,
    maps::{Array, PerCpuArray, XskMap},
    programs::{Xdp, XdpFlags},
};
use serde::Serialize;
use time::OffsetDateTime;
use xdp::Packet;
use xdp::slab::Slab;
use xdp::socket::{BindFlags, PollTimeout, XdpSocketBuilder};

use super::{
    DEFAULT_TARGET, DropImplementation, FileConfig, LogFormat, MacAddr, PortSelect, QueryPool,
    QueryTemplate, RecvMode, ResponseClass, SourceEndpoint, SourceSelector, Stats, XdpMode,
    XdpReplyTracking, XdpZeroCopyMode, build_dns_query, classify_response, drop_implementation,
    parse_ipv4_cidr, query_pool, response_id, serde_plain_drop_implementation,
};

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;

#[derive(Debug, Serialize)]
struct XdpOutputRecord<'a> {
    record_type: &'a str,
    timestamp: String,
    summary: bool,
    backend: &'a str,
    xdp_mode: XdpMode,
    zerocopy: XdpZeroCopyMode,
    interface: &'a str,
    tx_queue: u32,
    rx_queue: u32,
    queue_count: u32,
    recv_mode: RecvMode,
    xdp_reply_tracking: XdpReplyTracking,
    xdp_rx_drain_passes: usize,
    xdp_tx_wakeup_interval: usize,
    drop_implementation: DropImplementation,
    target: SocketAddr,
    source_ip: IpAddr,
    source_port: u16,
    qname: &'a str,
    qtype: &'a str,
    query_pool_size: usize,
    query_select: super::QuerySelect,
    source_strategy: &'a str,
    source_port_strategy: &'a str,
    requested_qps: Option<u64>,
    tx_packets_total: u64,
    tx_bytes_total: u64,
    rx_packets_total: u64,
    rx_bytes_total: u64,
    rx_dns_responses_total: u64,
    rx_dns_unmatched_total: u64,
    rx_truncated_total: u64,
    positive_total: u64,
    nxdomain_total: u64,
    nodata_total: u64,
    servfail_total: u64,
    refused_total: u64,
    other_rcode_total: u64,
    queries_unanswered_total: u64,
    rx_kernel_dropped_total: u64,
    errors_total: u64,
    duration_seconds: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    send_duration_seconds: Option<f64>,
    tx_qps: f64,
    rx_qps: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue_stats: Option<&'a [XdpQueueOutputRecord]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_p50_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_p99_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_p999_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct XdpQueueOutputRecord {
    tx_queue: u32,
    rx_queue: u32,
    source_port: u16,
    requested_qps: Option<u64>,
    tx_packets_total: u64,
    rx_packets_total: u64,
    rx_dns_responses_total: u64,
    rx_dns_responses_minus_tx_packets: i64,
    rx_kernel_dropped_total: u64,
    errors_total: u64,
    send_duration_seconds: f64,
    tx_qps: f64,
    rx_qps: f64,
}

#[derive(Debug)]
struct XdpRunOutcome {
    stats: Stats,
    send_duration: Duration,
    tx_queue: u32,
    rx_queue: u32,
    source_port: u16,
    requested_qps: Option<u64>,
}

struct BoundXdpWorker {
    socket: xdp::socket::XdpSocket,
    socket_fd: RawFd,
    umem: xdp::Umem,
    tx_ring: xdp::WakableTxRing,
    rx_ring: Option<xdp::RxRing>,
    fill_ring: xdp::WakableFillRing,
    completion_ring: xdp::CompletionRing,
    batch_size: usize,
}

#[derive(Debug, Clone)]
struct XdpPacketTemplate {
    frame: Vec<u8>,
    udp_start: usize,
    udp_checksum: u16,
    map_zero_udp_checksum: bool,
}

#[derive(Debug)]
struct XdpPacketTemplates {
    first_port: u16,
    port_count: usize,
    query_count: usize,
    templates: Vec<XdpPacketTemplate>,
}

struct PacketSlab {
    packets: Vec<Packet>,
    capacity: usize,
}

impl PacketSlab {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            packets: Vec::with_capacity(capacity),
            capacity,
        }
    }
}

impl Slab for PacketSlab {
    fn available(&self) -> usize {
        self.capacity.saturating_sub(self.packets.len())
    }

    fn len(&self) -> usize {
        self.packets.len()
    }

    fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    fn push_front(&mut self, packet: Packet) -> Option<Packet> {
        if self.packets.len() < self.capacity {
            self.packets.push(packet);
            None
        } else {
            Some(packet)
        }
    }

    fn pop_back(&mut self) -> Option<Packet> {
        self.packets.pop()
    }
}

// SAFETY: the worker owns the AF_XDP socket, rings, UMEM, slabs, and packets as
// one unit. Packets are never shared concurrently; moving the worker to a
// thread transfers ownership of the UMEM and all ring handles together.
unsafe impl Send for BoundXdpWorker {}

#[derive(Debug)]
struct SharedInflight {
    first_port: u16,
    port_count: usize,
    origin: Instant,
    sent_micros: Vec<AtomicU64>,
    outstanding: AtomicU64,
}

impl SharedInflight {
    fn new(first_port: u16, last_port: u16, origin: Instant) -> Self {
        let port_count = usize::from(last_port - first_port) + 1;
        let entry_count = port_count * (usize::from(u16::MAX) + 1);
        let sent_micros = (0..entry_count).map(|_| AtomicU64::new(0)).collect();
        Self {
            first_port,
            port_count,
            origin,
            sent_micros,
            outstanding: AtomicU64::new(0),
        }
    }

    fn insert(&self, port: u16, id: u16, sent_at: Instant) {
        if let Some(index) = self.index(port, id) {
            let micros = sent_at
                .duration_since(self.origin)
                .as_micros()
                .min(u128::from(u64::MAX - 1)) as u64
                + 1;
            let previous = self.sent_micros[index].swap(micros, Ordering::Relaxed);
            if previous == 0 {
                self.outstanding.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn take(&self, port: u16, id: u16, now: Instant) -> Option<Duration> {
        let index = self.index(port, id)?;
        let micros = self.sent_micros[index].swap(0, Ordering::Relaxed);
        if micros == 0 {
            return None;
        }
        self.outstanding.fetch_sub(1, Ordering::Relaxed);
        let sent_at = self.origin + Duration::from_micros(micros - 1);
        Some(now.saturating_duration_since(sent_at))
    }

    fn is_empty(&self) -> bool {
        self.outstanding.load(Ordering::Relaxed) == 0
    }

    fn index(&self, port: u16, id: u16) -> Option<usize> {
        let port_offset = port.checked_sub(self.first_port)?;
        let port_offset = usize::from(port_offset);
        (port_offset < self.port_count).then_some((port_offset << 16) | usize::from(id))
    }
}

#[derive(Debug)]
enum InflightTracker {
    Local(Vec<Option<Instant>>),
    Shared(Arc<SharedInflight>),
}

impl InflightTracker {
    fn record(&mut self, port: u16, id: u16, sent_at: Instant) {
        match self {
            Self::Local(inflight) => {
                inflight[id as usize] = Some(sent_at);
            }
            Self::Shared(inflight) => inflight.insert(port, id, sent_at),
        }
    }

    fn take(&mut self, port: u16, id: u16, now: Instant) -> Option<Duration> {
        match self {
            Self::Local(inflight) => {
                let _ = port;
                inflight[id as usize]
                    .take()
                    .map(|sent_at| now.saturating_duration_since(sent_at))
            }
            Self::Shared(inflight) => inflight.take(port, id, now),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Local(inflight) => inflight.iter().all(Option::is_none),
            Self::Shared(inflight) => inflight.is_empty(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct DropConfig {
    port_start_be: u16,
    port_end_be: u16,
    target_ipv4_be: u32,
    source_ipv4_be: u32,
    source_mask_be: u32,
}

// SAFETY: DropConfig is repr(C), Copy, contains only integer fields, and has no
// padding-sensitive references or invalid bit patterns.
unsafe impl Pod for DropConfig {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct ReplyRedirectConfig {
    udp_source_port_be: u16,
    udp_dest_port_start_be: u16,
    udp_dest_port_end_be: u16,
}

// SAFETY: ReplyRedirectConfig is repr(C), Copy, contains only integer fields,
// and has no references or invalid bit patterns.
unsafe impl Pod for ReplyRedirectConfig {}

struct KernelDropGuard {
    bpf: Ebpf,
}

impl KernelDropGuard {
    fn attach(
        path: &Path,
        interface: &str,
        mode: XdpMode,
        drop_scope: DropScope,
        port_start: u16,
        port_end: u16,
    ) -> Result<Self> {
        let mut bpf = Ebpf::load_file(path)
            .with_context(|| format!("failed to load XDP drop object {}", path.display()))?;
        {
            let mut config = Array::<_, DropConfig>::try_from(
                bpf.map_mut("DROP_CONFIG")
                    .ok_or_else(|| anyhow!("DROP_CONFIG map missing from XDP drop object"))?,
            )
            .context("failed to open DROP_CONFIG map")?;
            config
                .set(
                    0,
                    DropConfig {
                        port_start_be: port_start.to_be(),
                        port_end_be: port_end.to_be(),
                        target_ipv4_be: ipv4_to_bpf_word(drop_scope.target),
                        source_ipv4_be: ipv4_to_bpf_word(drop_scope.source_network),
                        source_mask_be: ipv4_mask_to_bpf_word(drop_scope.source_mask),
                    },
                    0,
                )
                .context("failed to configure XDP drop selector")?;
        }

        let program: &mut Xdp = bpf
            .program_mut("oxide_gun_drop")
            .ok_or_else(|| anyhow!("oxide_gun_drop program missing from XDP drop object"))?
            .try_into()
            .context("oxide_gun_drop is not an XDP program")?;
        program.load().context("failed to load XDP drop program")?;
        program
            .attach(interface, xdp_flags(mode))
            .with_context(|| format!("failed to attach XDP drop program to {interface}"))?;

        Ok(Self { bpf })
    }

    fn dropped_packets(&self) -> Result<u64> {
        let dropped = PerCpuArray::<_, u64>::try_from(
            self.bpf
                .map("DROPPED_PACKETS")
                .ok_or_else(|| anyhow!("DROPPED_PACKETS map missing from XDP drop object"))?,
        )
        .context("failed to open DROPPED_PACKETS map")?;
        let values = dropped
            .get(&0, 0)
            .context("failed to read XDP drop counter")?;
        Ok(values.iter().copied().sum())
    }
}

struct ReplyRedirectGuard {
    _bpf: Ebpf,
}

impl ReplyRedirectGuard {
    fn attach(
        object: &Path,
        interface: &str,
        mode: XdpMode,
        udp_source_port: u16,
        udp_dest_port_start: u16,
        udp_dest_port_end: u16,
        xsk_entries: &[(u32, RawFd)],
    ) -> Result<Self> {
        let mut bpf = Ebpf::load_file(object).with_context(|| {
            format!(
                "failed to load XDP reply redirect object {}",
                object.display()
            )
        })?;
        {
            let map = bpf.map_mut("REPLY_REDIRECT_CONFIG").ok_or_else(|| {
                anyhow!("REPLY_REDIRECT_CONFIG map missing from XDP reply redirect object")
            })?;
            let mut config = Array::<_, ReplyRedirectConfig>::try_from(map)
                .context("failed to open REPLY_REDIRECT_CONFIG map")?;
            config
                .set(
                    0,
                    ReplyRedirectConfig {
                        udp_source_port_be: udp_source_port.to_be(),
                        udp_dest_port_start_be: udp_dest_port_start.to_be(),
                        udp_dest_port_end_be: udp_dest_port_end.to_be(),
                    },
                    0,
                )
                .context("failed to configure XDP reply redirect selector")?;
        }
        {
            let map = bpf.map_mut("OXIDE_GUN_XSKS").ok_or_else(|| {
                anyhow!("OXIDE_GUN_XSKS map missing from XDP reply redirect object")
            })?;
            let mut xsk_map = XskMap::try_from(map).context("failed to open OXIDE_GUN_XSKS map")?;
            for (queue_id, socket_fd) in xsk_entries {
                xsk_map
                    .set(*queue_id, *socket_fd, 0)
                    .with_context(|| format!("failed to register XSK fd for queue {queue_id}"))?;
            }
        }
        {
            let program: &mut Xdp = bpf
                .program_mut("oxide_gun_reply_redirect")
                .ok_or_else(|| {
                    anyhow!(
                        "oxide_gun_reply_redirect program missing from XDP reply redirect object"
                    )
                })?
                .try_into()
                .context("oxide_gun_reply_redirect is not an XDP program")?;
            program
                .load()
                .context("failed to load XDP reply redirect program")?;
            program
                .attach(interface, xdp_flags(mode))
                .with_context(|| {
                    format!("failed to attach XDP reply redirect program to {interface}")
                })?;
        }

        Ok(Self { _bpf: bpf })
    }
}

pub(super) fn run(config: &FileConfig) -> Result<()> {
    if config.interface.queue_count > 1 {
        return run_multi_queue(config);
    }
    let _ = run_single(config.clone(), None, true)?;
    Ok(())
}

fn run_multi_queue(config: &FileConfig) -> Result<()> {
    let target = config.target.address.unwrap_or(DEFAULT_TARGET);
    let interface = config
        .interface
        .nic
        .as_deref()
        .ok_or_else(|| anyhow!("backend xdp requires interface.nic"))?;
    let queue_count = active_queue_count(config);
    let auto_source_port_range = config.source.port_range.is_none();
    let mut aggregate_config = config.clone();
    aggregate_config.interface.queue_count = queue_count;
    if auto_source_port_range && queue_count > 1 {
        let last_port = aggregate_config.source.port + (queue_count - 1) as u16;
        aggregate_config.source.port_range =
            Some(format!("{}-{last_port}", aggregate_config.source.port));
        aggregate_config.source.port_select = PortSelect::Sequential;
    }
    let query_pool = query_pool(&aggregate_config)?;
    let source_selector = SourceSelector::new(&aggregate_config.source, aggregate_config.run.seed)?;
    let mut workers = Vec::with_capacity(queue_count as usize);
    let mut xsk_entries = Vec::with_capacity(queue_count as usize);

    for worker_index in 0..queue_count {
        let worker_config = worker_config(
            &aggregate_config,
            worker_index,
            queue_count,
            auto_source_port_range,
        )?;
        let worker = bind_xdp_worker(&worker_config)?;
        xsk_entries.push((worker_config.interface.rx_queue, worker.socket_fd));
        workers.push((worker_config, worker));
    }

    let _reply_redirect =
        attach_reply_redirect(&aggregate_config, interface, target, &xsk_entries)?;
    let start = Instant::now();
    let shared_inflight = if config.recv.mode == RecvMode::Process {
        let (first_port, last_port) = source_port_bounds(&aggregate_config)?;
        Some(Arc::new(SharedInflight::new(first_port, last_port, start)))
    } else {
        None
    };
    let mut handles = Vec::with_capacity(queue_count as usize);

    for (worker_config, worker) in workers {
        let inflight = shared_inflight
            .as_ref()
            .map(|shared| InflightTracker::Shared(Arc::clone(shared)));
        handles.push(thread::spawn(move || {
            run_bound_worker(worker_config, worker, inflight, false)
        }));
    }

    let mut aggregate = Stats::default();
    let mut send_duration = Duration::ZERO;
    let mut queue_stats = Vec::with_capacity(queue_count as usize);
    for handle in handles {
        let outcome = handle
            .join()
            .map_err(|_| anyhow!("XDP queue worker panicked"))??;
        send_duration = send_duration.max(outcome.send_duration);
        queue_stats.push(XdpQueueOutputRecord::from_outcome(&outcome));
        merge_stats(&mut aggregate, outcome.stats);
    }
    aggregate.queries_unanswered = aggregate
        .tx_packets
        .saturating_sub(aggregate.rx_dns_responses);

    emit_xdp_record(
        &aggregate_config,
        interface,
        target,
        query_pool.first(),
        &query_pool,
        &source_selector,
        &aggregate,
        start,
        Some(send_duration),
        Some(&queue_stats),
        true,
    )
}

fn active_queue_count(config: &FileConfig) -> u32 {
    let mut queue_count = config.interface.queue_count;
    if config.run.max_packets != 0 {
        queue_count = queue_count.min(config.run.max_packets.min(u64::from(u32::MAX)) as u32);
    }
    if let Some(target_qps) = config.rate.target_qps
        && target_qps > 0
    {
        queue_count = queue_count.min(target_qps.min(u64::from(u32::MAX)) as u32);
    }
    queue_count.max(1)
}

fn worker_config(
    config: &FileConfig,
    worker_index: u32,
    queue_count: u32,
    auto_source_port_range: bool,
) -> Result<FileConfig> {
    let mut worker = config.clone();
    worker.interface.tx_queue = config.interface.tx_queue + worker_index;
    worker.interface.rx_queue = config.interface.rx_queue + worker_index;
    worker.interface.queue_count = 1;
    worker.log.flush_interval_ms = 0;
    worker.run.seed = config.run.seed.wrapping_add(u64::from(worker_index));
    if let Some(target_qps) = config.rate.target_qps {
        if target_qps > 0 {
            let base = target_qps / u64::from(queue_count);
            let remainder = target_qps % u64::from(queue_count);
            worker.rate.target_qps = Some(base + u64::from(worker_index < remainder as u32));
        }
    }
    if config.run.max_packets != 0 {
        let base = config.run.max_packets / u64::from(queue_count);
        let remainder = config.run.max_packets % u64::from(queue_count);
        worker.run.max_packets = base + u64::from(worker_index < remainder as u32);
    }
    if auto_source_port_range {
        worker.source.port = config
            .source
            .port
            .checked_add(worker_index as u16)
            .ok_or_else(|| anyhow!("source.port plus queue worker index overflows u16"))?;
        worker.source.port_range = None;
    }
    Ok(worker)
}

fn merge_stats(total: &mut Stats, stats: Stats) {
    total.tx_packets += stats.tx_packets;
    total.tx_bytes += stats.tx_bytes;
    total.rx_packets += stats.rx_packets;
    total.rx_bytes += stats.rx_bytes;
    total.rx_dns_responses += stats.rx_dns_responses;
    total.rx_dns_unmatched += stats.rx_dns_unmatched;
    total.rx_truncated += stats.rx_truncated;
    total.positive += stats.positive;
    total.nxdomain += stats.nxdomain;
    total.nodata += stats.nodata;
    total.servfail += stats.servfail;
    total.refused += stats.refused;
    total.other_rcode += stats.other_rcode;
    total.queries_unanswered += stats.queries_unanswered;
    total.rx_kernel_dropped += stats.rx_kernel_dropped;
    total.errors += stats.errors;
    for (dst, src) in total.latency.counts.iter_mut().zip(stats.latency.counts) {
        *dst += src;
    }
}

fn signed_delta(lhs: u64, rhs: u64) -> i64 {
    let delta = i128::from(lhs) - i128::from(rhs);
    delta.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

impl XdpQueueOutputRecord {
    fn from_outcome(outcome: &XdpRunOutcome) -> Self {
        let send_elapsed = outcome.send_duration.as_secs_f64().max(0.000_001);
        Self {
            tx_queue: outcome.tx_queue,
            rx_queue: outcome.rx_queue,
            source_port: outcome.source_port,
            requested_qps: outcome.requested_qps,
            tx_packets_total: outcome.stats.tx_packets,
            rx_packets_total: outcome.stats.rx_packets,
            rx_dns_responses_total: outcome.stats.rx_dns_responses,
            rx_dns_responses_minus_tx_packets: signed_delta(
                outcome.stats.rx_dns_responses,
                outcome.stats.tx_packets,
            ),
            rx_kernel_dropped_total: outcome.stats.rx_kernel_dropped,
            errors_total: outcome.stats.errors,
            send_duration_seconds: send_elapsed,
            tx_qps: outcome.stats.tx_packets as f64 / send_elapsed,
            rx_qps: outcome.stats.rx_packets as f64 / send_elapsed,
        }
    }
}

fn run_single(
    config: FileConfig,
    shared_inflight: Option<InflightTracker>,
    emit_records: bool,
) -> Result<XdpRunOutcome> {
    let target = config.target.address.unwrap_or(DEFAULT_TARGET);
    let interface = config
        .interface
        .nic
        .as_deref()
        .ok_or_else(|| anyhow!("backend xdp requires interface.nic"))?;
    let worker = bind_xdp_worker(&config)?;
    let xsk_entries = [(config.interface.rx_queue, worker.socket_fd)];
    let _reply_redirect = attach_reply_redirect(&config, interface, target, &xsk_entries)?;
    run_bound_worker(config, worker, shared_inflight, emit_records)
}

fn bind_xdp_worker(config: &FileConfig) -> Result<BoundXdpWorker> {
    let interface = config
        .interface
        .nic
        .as_deref()
        .ok_or_else(|| anyhow!("backend xdp requires interface.nic"))?;
    let ifname = CString::new(interface).context("interface name contains NUL byte")?;
    let nic = xdp::nic::NicIndex::lookup_by_name(&ifname)?
        .ok_or_else(|| anyhow!("network interface {interface:?} does not exist"))?;
    let caps = nic
        .query_capabilities()
        .with_context(|| format!("failed to query XDP capabilities for {interface}"))?;
    let umem_cfg = xdp::umem::UmemCfgBuilder {
        frame_count: config.xdp.umem_frame_count,
        tx_checksum: false,
        tx_timestamp: false,
        ..Default::default()
    }
    .build()
    .context("failed to build AF_XDP UMEM configuration")?;
    let mut umem = xdp::Umem::map(umem_cfg).context("failed to map AF_XDP UMEM")?;
    let ring_cfg = xdp::RingConfigBuilder {
        rx_count: if config.recv.mode == RecvMode::Process {
            config.xdp.rx_ring_size
        } else {
            0
        },
        tx_count: config.xdp.tx_ring_size,
        fill_count: config.xdp.fill_ring_size,
        completion_count: config.xdp.completion_ring_size,
    }
    .build()
    .context("failed to build AF_XDP ring configuration")?;
    let mut builder = XdpSocketBuilder::new().context("failed to create AF_XDP socket")?;
    let (mut rings, mut bind_flags) = builder
        .build_wakable_rings(&umem, ring_cfg)
        .context("failed to create AF_XDP rings")?;
    apply_bind_policy(
        &mut bind_flags,
        config.xdp.zerocopy,
        caps.zero_copy.is_available(),
    );
    let socket = builder
        .bind(nic, config.interface.tx_queue, bind_flags)
        .with_context(|| {
            format!(
                "failed to bind AF_XDP socket to {interface} queue {}",
                config.interface.tx_queue
            )
        })?;
    let socket_fd = socket.raw_fd();

    if config.recv.mode == RecvMode::Process {
        // SAFETY: all RX frame addresses come from `umem`, and both the UMEM
        // mapping and AF_XDP socket outlive the fill/RX rings in this worker.
        unsafe {
            rings
                .fill_ring
                .enqueue(&mut umem, config.xdp.fill_ring_size as usize, true)
                .context("failed to populate AF_XDP fill ring")?;
        }
    }

    let tx_ring = rings
        .tx_ring
        .take()
        .ok_or_else(|| anyhow!("AF_XDP TX ring was not configured"))?;
    let rx_ring = rings.rx_ring.take();
    let batch_size = config
        .xdp
        .batch_size
        .min(config.xdp.tx_ring_size as usize)
        .max(1);

    Ok(BoundXdpWorker {
        socket,
        socket_fd,
        umem,
        tx_ring,
        rx_ring,
        fill_ring: rings.fill_ring,
        completion_ring: rings.completion_ring,
        batch_size,
    })
}

fn attach_reply_redirect(
    config: &FileConfig,
    interface: &str,
    target: SocketAddr,
    xsk_entries: &[(u32, RawFd)],
) -> Result<Option<ReplyRedirectGuard>> {
    if config.recv.mode != RecvMode::Process {
        return Ok(None);
    }
    let Some(object) = config.xdp.redirect_object.as_deref() else {
        return Ok(None);
    };
    let (port_start, port_end) = source_port_bounds(config)?;
    ReplyRedirectGuard::attach(
        object,
        interface,
        config.xdp.mode,
        target.port(),
        port_start,
        port_end,
        xsk_entries,
    )
    .map(Some)
}

fn run_bound_worker(
    config: FileConfig,
    mut worker: BoundXdpWorker,
    shared_inflight: Option<InflightTracker>,
    emit_records: bool,
) -> Result<XdpRunOutcome> {
    let target = config.target.address.unwrap_or(DEFAULT_TARGET);
    let interface = config
        .interface
        .nic
        .as_deref()
        .ok_or_else(|| anyhow!("backend xdp requires interface.nic"))?;
    let source_mac = config
        .source
        .mac
        .ok_or_else(|| anyhow!("backend xdp requires source.mac"))?;
    let target_mac = config
        .target
        .mac
        .ok_or_else(|| anyhow!("backend xdp requires target.mac"))?;
    let query_pool = query_pool(&config)?;
    let encoded_queries = encoded_query_pool(&query_pool)?;
    let packet_templates =
        XdpPacketTemplates::new(&config, target_mac, source_mac, target, &encoded_queries)?;
    let mut source_selector = SourceSelector::new(&config.source, config.run.seed)?;
    let kernel_drop = if config.recv.mode == RecvMode::Drop {
        match config.xdp.drop_object.as_deref() {
            Some(path) => {
                let (port_start, port_end) = source_port_bounds(&config)?;
                let drop_scope = drop_scope(&config, target)?;
                Some(KernelDropGuard::attach(
                    path,
                    interface,
                    config.xdp.mode,
                    drop_scope,
                    port_start,
                    port_end,
                )?)
            }
            None => None,
        }
    } else {
        None
    };

    let mut stats = Stats::default();
    let batch_size = worker.batch_size;
    let rx_drain_passes = config.xdp.rx_drain_passes;
    let tx_wakeup_interval = config.xdp.tx_wakeup_interval;
    let mut tx_send_passes = 0_usize;
    let mut send_slab = PacketSlab::with_capacity(batch_size);
    let mut send_lengths = Vec::with_capacity(batch_size);
    let process_responses = config.recv.mode == RecvMode::Process;
    let track_latency = process_responses && config.xdp.reply_tracking == XdpReplyTracking::Latency;
    let mut recv_slab = PacketSlab::with_capacity(if process_responses { batch_size } else { 0 });
    let start = Instant::now();
    let deadline = config
        .run
        .duration_seconds
        .map(|seconds| start + Duration::from_secs_f64(seconds));
    let mut last_flush = start;
    let per_packet_delay = config
        .rate
        .target_qps
        .and_then(|qps| (qps > 0).then(|| Duration::from_secs_f64(1.0 / qps as f64)));
    let max_packets = if config.run.max_packets == 0 {
        u64::MAX
    } else {
        config.run.max_packets
    };
    let mut query_id = config.run.seed as u16;
    let mut query_rng = super::XorShift64::new(config.run.seed);
    let uses_shared_inflight = shared_inflight.is_some();
    let mut inflight = track_latency.then(|| {
        shared_inflight.unwrap_or_else(|| InflightTracker::Local(vec![None; u16::MAX as usize + 1]))
    });

    while stats.tx_packets < max_packets {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }

        while send_slab.available() > 0 && stats.tx_packets + (send_slab.len() as u64) < max_packets
        {
            query_id = query_id.wrapping_add(1);
            let query_index = stats.tx_packets + send_slab.len() as u64;
            let source = source_selector.next();
            let selected_query_index = query_pool.select_index(&mut query_rng, query_index);
            let query = &encoded_queries[selected_query_index];
            // SAFETY: returned packet stays within this function, is either handed
            // to the TX ring while `umem` and `socket` remain alive, or immediately
            // freed back to the same UMEM on error.
            let Some(mut packet) = (unsafe { worker.umem.alloc() }) else {
                worker.completion_ring.dequeue(&mut worker.umem, batch_size);
                break;
            };
            let frame_len = match packet_templates
                .as_ref()
                .and_then(|templates| templates.get(source.port, selected_query_index))
            {
                Some(template) => template.write_packet(&mut packet, query_id),
                None => write_ethernet_udp_dns_packet_with_query_id(
                    &mut packet,
                    target_mac,
                    source_mac,
                    source.ip,
                    target.ip(),
                    source.port,
                    target.port(),
                    query,
                    query_id,
                ),
            };
            let frame_len = match frame_len {
                Ok(frame_len) => frame_len,
                Err(error) => {
                    worker.umem.free_packet(packet);
                    return Err(error).context("failed to write AF_XDP packet frame");
                }
            };
            if packet.len() != frame_len {
                worker.umem.free_packet(packet);
                bail!("internal AF_XDP packet length mismatch");
            }
            if send_slab.push_front(packet).is_some() {
                bail!("internal AF_XDP send slab overflow");
            }
            if let Some(inflight) = inflight.as_mut() {
                inflight.record(source.port, query_id, Instant::now());
            }
            send_lengths.push(frame_len as u64);
        }

        if send_slab.is_empty() {
            worker.completion_ring.dequeue(&mut worker.umem, batch_size);
            continue;
        }

        // SAFETY: every packet in `send_slab` was allocated from `umem`, and
        // `umem` outlives the socket and TX ring for the entire send loop.
        let queued_before = send_slab.len();
        let wakeup = should_wakeup_tx(tx_wakeup_interval, tx_send_passes);
        tx_send_passes = tx_send_passes.wrapping_add(1);
        let sent = match unsafe { worker.tx_ring.send(&mut send_slab, wakeup) } {
            Ok(sent) => sent,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let queued = queued_before.saturating_sub(send_slab.len());
                account_sent_packets(queued, &mut send_lengths, &mut stats);
                worker.completion_ring.dequeue(&mut worker.umem, batch_size);
                pace_after_sent(
                    per_packet_delay,
                    queued,
                    &worker.socket,
                    worker.rx_ring.as_mut(),
                    &mut worker.fill_ring,
                    &mut worker.umem,
                    &mut recv_slab,
                    inflight.as_mut(),
                    &mut stats,
                    process_responses,
                )?;
                continue;
            }
            Err(error) => return Err(error).context("failed to enqueue AF_XDP packet"),
        };
        if sent == 0 {
            worker.completion_ring.dequeue(&mut worker.umem, batch_size);
            if !worker
                .socket
                .poll_write(PollTimeout::new(Some(Duration::from_millis(1))))
                .context("failed to poll AF_XDP TX ring")?
            {
                thread::yield_now();
            }
            continue;
        } else {
            account_sent_packets(sent, &mut send_lengths, &mut stats);
        }
        worker.completion_ring.dequeue(&mut worker.umem, batch_size);

        if process_responses {
            for _ in 0..rx_drain_passes {
                let received = receive_available_xdp(
                    &worker.socket,
                    worker.rx_ring.as_mut(),
                    &mut worker.fill_ring,
                    &mut worker.umem,
                    &mut recv_slab,
                    inflight.as_mut(),
                    &mut stats,
                )?;
                if received == 0 {
                    break;
                }
            }
        }

        if emit_records
            && config.log.flush_interval_ms > 0
            && last_flush.elapsed() >= Duration::from_millis(config.log.flush_interval_ms)
        {
            refresh_kernel_drop_count(&mut stats, kernel_drop.as_ref())?;
            emit_xdp_record(
                &config,
                interface,
                target,
                query_pool.first(),
                &query_pool,
                &source_selector,
                &stats,
                start,
                None,
                None,
                false,
            )?;
            last_flush = Instant::now();
        }

        pace_after_sent(
            per_packet_delay,
            sent,
            &worker.socket,
            worker.rx_ring.as_mut(),
            &mut worker.fill_ring,
            &mut worker.umem,
            &mut recv_slab,
            inflight.as_mut(),
            &mut stats,
            process_responses,
        )?;
    }

    let send_duration = start.elapsed();

    if process_responses {
        drain_xdp_replies(
            &worker.socket,
            worker.rx_ring.as_mut(),
            &mut worker.fill_ring,
            &mut worker.umem,
            &mut recv_slab,
            inflight.as_mut(),
            &mut stats,
            Duration::from_millis(config.recv.response_timeout_ms),
        )?;
        if !uses_shared_inflight {
            stats.queries_unanswered = stats.tx_packets.saturating_sub(stats.rx_dns_responses);
        }
    }
    refresh_kernel_drop_count(&mut stats, kernel_drop.as_ref())?;
    if emit_records {
        emit_xdp_record(
            &config,
            interface,
            target,
            query_pool.first(),
            &query_pool,
            &source_selector,
            &stats,
            start,
            Some(send_duration),
            None,
            true,
        )?;
    }
    Ok(XdpRunOutcome {
        stats,
        send_duration,
        tx_queue: config.interface.tx_queue,
        rx_queue: config.interface.rx_queue,
        source_port: config.source.port,
        requested_qps: config.rate.target_qps,
    })
}

#[allow(clippy::too_many_arguments)]
fn drain_xdp_replies(
    socket: &xdp::socket::XdpSocket,
    rx_ring: Option<&mut xdp::RxRing>,
    fill_ring: &mut xdp::WakableFillRing,
    umem: &mut xdp::Umem,
    recv_slab: &mut PacketSlab,
    mut inflight: Option<&mut InflightTracker>,
    stats: &mut Stats,
    timeout: Duration,
) -> Result<()> {
    let Some(rx_ring) = rx_ring else {
        return Ok(());
    };
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if inflight.as_ref().is_some_and(|tracker| tracker.is_empty()) {
            break;
        }
        let before = stats.rx_packets;
        let received = receive_available_xdp(
            socket,
            Some(&mut *rx_ring),
            fill_ring,
            umem,
            recv_slab,
            inflight.as_mut().map(|tracker| &mut **tracker),
            stats,
        )?;
        if received == 0 || stats.rx_packets == before {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}

fn source_port_bounds(config: &FileConfig) -> Result<(u16, u16)> {
    let Some(range) = &config.source.port_range else {
        return Ok((config.source.port, config.source.port));
    };
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| anyhow!("source port range must be min-max: {range}"))?;
    let start = start
        .parse::<u16>()
        .with_context(|| format!("invalid source port range start {range}"))?;
    let end = end
        .parse::<u16>()
        .with_context(|| format!("invalid source port range end {range}"))?;
    Ok((start, end))
}

fn encoded_query_pool(query_pool: &QueryPool) -> Result<Vec<Vec<u8>>> {
    query_pool
        .templates
        .iter()
        .map(|query| build_dns_query(query, 0))
        .collect()
}

const MAX_PREBUILT_XDP_PACKET_TEMPLATES: usize = 65_536;

impl XdpPacketTemplates {
    fn new(
        config: &FileConfig,
        target_mac: MacAddr,
        source_mac: MacAddr,
        target: SocketAddr,
        encoded_queries: &[Vec<u8>],
    ) -> Result<Option<Self>> {
        let Some(source_ip) = static_source_ip(config) else {
            return Ok(None);
        };
        let (first_port, last_port) = source_port_bounds(config)?;
        let port_count = usize::from(last_port - first_port) + 1;
        let query_count = encoded_queries.len();
        let template_count = port_count
            .checked_mul(query_count)
            .ok_or_else(|| anyhow!("XDP packet template count overflows usize"))?;
        if template_count > MAX_PREBUILT_XDP_PACKET_TEMPLATES {
            return Ok(None);
        }

        let mut templates = Vec::with_capacity(template_count);
        for port_offset in 0..port_count {
            let source_port = first_port + port_offset as u16;
            let source = SourceEndpoint {
                ip: source_ip,
                port: source_port,
            };
            for query in encoded_queries {
                templates.push(XdpPacketTemplate::new(
                    target_mac, source_mac, source, target, query,
                )?);
            }
        }

        Ok(Some(Self {
            first_port,
            port_count,
            query_count,
            templates,
        }))
    }

    fn get(&self, source_port: u16, query_index: usize) -> Option<&XdpPacketTemplate> {
        let port_offset = source_port.checked_sub(self.first_port)?;
        let port_offset = usize::from(port_offset);
        if port_offset >= self.port_count || query_index >= self.query_count {
            return None;
        }
        self.templates
            .get(port_offset * self.query_count + query_index)
    }
}

impl XdpPacketTemplate {
    fn new(
        target_mac: MacAddr,
        source_mac: MacAddr,
        source: SourceEndpoint,
        target: SocketAddr,
        dns_payload_template: &[u8],
    ) -> Result<Self> {
        let frame_len =
            ethernet_udp_dns_frame_len(source.ip, target.ip(), dns_payload_template.len())
                .map_err(|_| anyhow!("packet frame length is invalid"))?;
        let mut frame = vec![0_u8; frame_len];
        write_ethernet_udp_dns_slice_with_query_id(
            &mut frame,
            target_mac,
            source_mac,
            source.ip,
            target.ip(),
            source.port,
            target.port(),
            dns_payload_template,
            None,
        )
        .map_err(|_| anyhow!("failed to build XDP packet template"))?;
        let (udp_start, map_zero_udp_checksum) = match (source.ip, target.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => (ETHERNET_HEADER_LEN + IPV4_HEADER_LEN, true),
            (IpAddr::V6(_), IpAddr::V6(_)) => (ETHERNET_HEADER_LEN + IPV6_HEADER_LEN, false),
            _ => bail!("source and target IP families do not match"),
        };
        let udp_checksum = u16::from_be_bytes([frame[udp_start + 6], frame[udp_start + 7]]);
        Ok(Self {
            frame,
            udp_start,
            udp_checksum,
            map_zero_udp_checksum,
        })
    }

    fn write_packet(
        &self,
        packet: &mut xdp::Packet,
        query_id: u16,
    ) -> Result<usize, xdp::packet::PacketError> {
        packet.clear();
        packet.adjust_tail(self.frame.len() as i32)?;
        packet.copy_from_slice(&self.frame);
        let query_id_offset = self.udp_start + UDP_HEADER_LEN;
        packet[query_id_offset..query_id_offset + 2].copy_from_slice(&query_id.to_be_bytes());
        let checksum = replace_checksum_word(self.udp_checksum, 0, query_id);
        let checksum = if self.map_zero_udp_checksum && checksum == 0 {
            0xffff
        } else {
            checksum
        };
        packet[self.udp_start + 6..self.udp_start + 8].copy_from_slice(&checksum.to_be_bytes());
        Ok(self.frame.len())
    }
}

fn static_source_ip(config: &FileConfig) -> Option<IpAddr> {
    (config.source.cidr.is_none()
        && config.source.list.is_empty()
        && config.source.range_start.is_none()
        && config.source.range_count.is_none())
    .then_some(config.source.ip)
}

#[cfg(test)]
fn write_query_id_into_dns_payload(packet: &mut Vec<u8>, template: &[u8], id: u16) {
    packet.clear();
    packet.extend_from_slice(template);
    packet[..2].copy_from_slice(&id.to_be_bytes());
}

fn account_sent_packets(sent: usize, send_lengths: &mut Vec<u64>, stats: &mut Stats) {
    stats.tx_packets += sent as u64;
    for _ in 0..sent {
        if let Some(len) = send_lengths.pop() {
            stats.tx_bytes += len;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn pace_after_sent(
    per_packet_delay: Option<Duration>,
    sent: usize,
    socket: &xdp::socket::XdpSocket,
    rx_ring: Option<&mut xdp::RxRing>,
    fill_ring: &mut xdp::WakableFillRing,
    umem: &mut xdp::Umem,
    recv_slab: &mut PacketSlab,
    mut inflight: Option<&mut InflightTracker>,
    stats: &mut Stats,
    process_responses: bool,
) -> Result<()> {
    if sent == 0 {
        return Ok(());
    }
    let Some(delay) = per_packet_delay else {
        return Ok(());
    };
    let wait = delay.mul_f64(sent as f64);
    if !process_responses {
        std::thread::sleep(wait);
        return Ok(());
    }
    let Some(rx_ring) = rx_ring else {
        std::thread::sleep(wait);
        return Ok(());
    };

    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        let received = receive_available_xdp(
            socket,
            Some(&mut *rx_ring),
            fill_ring,
            umem,
            recv_slab,
            inflight.as_mut().map(|tracker| &mut **tracker),
            stats,
        )?;
        if received == 0 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            std::thread::sleep((deadline - now).min(Duration::from_micros(250)));
        }
    }
    Ok(())
}

fn should_wakeup_tx(interval: usize, send_passes: usize) -> bool {
    interval != 0 && send_passes % interval == 0
}

#[derive(Debug, Clone, Copy)]
struct DropScope {
    target: Ipv4Addr,
    source_network: Ipv4Addr,
    source_mask: u32,
}

fn drop_scope(config: &FileConfig, target: SocketAddr) -> Result<DropScope> {
    let IpAddr::V4(target) = target.ip() else {
        bail!("--xdp-drop-object currently supports IPv4 targets only");
    };
    let (source_network, source_mask) = if let Some(cidr) = &config.source.cidr {
        let (network, host_mask, _) = parse_ipv4_cidr(cidr)?;
        (Ipv4Addr::from(network), !host_mask)
    } else if config.source.list.is_empty() && config.source.range_start.is_none() {
        let IpAddr::V4(source) = config.source.ip else {
            bail!("--xdp-drop-object currently supports IPv4 sources only");
        };
        (source, u32::MAX)
    } else {
        (Ipv4Addr::UNSPECIFIED, 0)
    };

    Ok(DropScope {
        target,
        source_network,
        source_mask,
    })
}

fn ipv4_to_bpf_word(addr: Ipv4Addr) -> u32 {
    u32::from_be_bytes(addr.octets()).to_be()
}

fn ipv4_mask_to_bpf_word(mask: u32) -> u32 {
    mask.to_be()
}

fn refresh_kernel_drop_count(
    stats: &mut Stats,
    kernel_drop: Option<&KernelDropGuard>,
) -> Result<()> {
    if let Some(kernel_drop) = kernel_drop {
        stats.rx_kernel_dropped = kernel_drop.dropped_packets()?;
    }
    Ok(())
}

fn apply_bind_policy(flags: &mut BindFlags, mode: XdpZeroCopyMode, zerocopy_available: bool) {
    match mode {
        XdpZeroCopyMode::Auto => {
            if !zerocopy_available {
                flags.force_copy();
            }
        }
        XdpZeroCopyMode::Force => flags.force_zerocopy(),
        XdpZeroCopyMode::Copy => flags.force_copy(),
    }
}

fn xdp_flags(mode: XdpMode) -> XdpFlags {
    match mode {
        XdpMode::Drv => XdpFlags::DRV_MODE,
        XdpMode::Skb => XdpFlags::SKB_MODE,
        XdpMode::Hw => XdpFlags::HW_MODE,
    }
}

fn receive_available_xdp(
    socket: &xdp::socket::XdpSocket,
    rx_ring: Option<&mut xdp::RxRing>,
    fill_ring: &mut xdp::WakableFillRing,
    umem: &mut xdp::Umem,
    recv_slab: &mut PacketSlab,
    mut inflight: Option<&mut InflightTracker>,
    stats: &mut Stats,
) -> Result<usize> {
    let Some(rx_ring) = rx_ring else {
        return Ok(0);
    };
    if !socket
        .poll_read(PollTimeout::new(Some(Duration::from_millis(0))))
        .context("failed to poll AF_XDP RX ring")?
    {
        return Ok(0);
    }
    // SAFETY: received packet views are consumed and returned to the same UMEM
    // before this function returns; `umem` outlives the RX ring and socket.
    let received = unsafe { rx_ring.recv(umem, recv_slab) };
    for _ in 0..received {
        let Some(packet) = recv_slab.pop_back() else {
            break;
        };
        stats.rx_packets += 1;
        stats.rx_bytes += packet.len() as u64;
        if let Some(received) = dns_payload_from_ethernet_frame(&packet) {
            let Some(id) = response_id(received.payload) else {
                stats.rx_dns_unmatched += 1;
                umem.free_packet(packet);
                continue;
            };
            let latency = inflight
                .as_mut()
                .and_then(|tracker| tracker.take(received.destination_port, id, Instant::now()));
            let response_class = classify_response(received.payload, id);
            match response_class {
                ResponseClass::Positive => {
                    stats.rx_dns_responses += 1;
                    stats.positive += 1;
                }
                ResponseClass::Nxdomain => {
                    stats.rx_dns_responses += 1;
                    stats.nxdomain += 1;
                }
                ResponseClass::Nodata => {
                    stats.rx_dns_responses += 1;
                    stats.nodata += 1;
                }
                ResponseClass::Servfail => {
                    stats.rx_dns_responses += 1;
                    stats.servfail += 1;
                }
                ResponseClass::Refused => {
                    stats.rx_dns_responses += 1;
                    stats.refused += 1;
                }
                ResponseClass::OtherRcode => {
                    stats.rx_dns_responses += 1;
                    stats.other_rcode += 1;
                }
                ResponseClass::Truncated => {
                    stats.rx_dns_responses += 1;
                    stats.rx_truncated += 1;
                }
                ResponseClass::Unmatched | ResponseClass::Timeout => {
                    stats.rx_dns_unmatched += 1;
                }
            }
            if inflight.is_some() {
                match latency {
                    Some(latency)
                        if !matches!(
                            response_class,
                            ResponseClass::Unmatched | ResponseClass::Timeout
                        ) =>
                    {
                        stats.latency.record(latency);
                    }
                    None => stats.rx_dns_unmatched += 1,
                    Some(_) => {}
                }
            }
        } else {
            stats.rx_dns_unmatched += 1;
        }
        umem.free_packet(packet);
    }
    // SAFETY: enqueued frame addresses come from `umem`, and the UMEM mapping
    // outlives the fill ring and AF_XDP socket.
    unsafe {
        fill_ring
            .enqueue(umem, received, true)
            .context("failed to replenish AF_XDP fill ring")?;
    }
    Ok(received)
}

#[allow(clippy::too_many_arguments)]
fn emit_xdp_record<'a>(
    config: &FileConfig,
    interface: &str,
    target: SocketAddr,
    query: &QueryTemplate,
    query_pool: &QueryPool,
    source_selector: &SourceSelector,
    stats: &Stats,
    start: Instant,
    send_duration: Option<Duration>,
    queue_stats: Option<&'a [XdpQueueOutputRecord]>,
    summary: bool,
) -> Result<()> {
    let elapsed = start.elapsed().as_secs_f64().max(0.000_001);
    let send_elapsed = send_duration.map(|duration| duration.as_secs_f64().max(0.000_001));
    let (latency_p50_us, latency_p99_us, latency_p999_us) = stats.latency.percentiles();
    let record = XdpOutputRecord {
        record_type: if summary { "summary" } else { "interval" },
        timestamp: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?,
        summary,
        backend: "xdp_af_xdp",
        xdp_mode: config.xdp.mode,
        zerocopy: config.xdp.zerocopy,
        interface,
        tx_queue: config.interface.tx_queue,
        rx_queue: config.interface.rx_queue,
        queue_count: config.interface.queue_count,
        recv_mode: config.recv.mode,
        xdp_reply_tracking: config.xdp.reply_tracking,
        xdp_rx_drain_passes: config.xdp.rx_drain_passes,
        xdp_tx_wakeup_interval: config.xdp.tx_wakeup_interval,
        drop_implementation: drop_implementation(
            config.recv.mode,
            config.xdp.drop_object.is_some(),
        ),
        target,
        source_ip: config.source.ip,
        source_port: config.source.port,
        qname: &query.qname,
        qtype: &query.qtype_name,
        query_pool_size: query_pool.len(),
        query_select: query_pool.select,
        source_strategy: source_selector.ip_description(),
        source_port_strategy: source_selector.port_description(),
        requested_qps: config.rate.target_qps,
        tx_packets_total: stats.tx_packets,
        tx_bytes_total: stats.tx_bytes,
        rx_packets_total: stats.rx_packets,
        rx_bytes_total: stats.rx_bytes,
        rx_dns_responses_total: stats.rx_dns_responses,
        rx_dns_unmatched_total: stats.rx_dns_unmatched,
        rx_truncated_total: stats.rx_truncated,
        positive_total: stats.positive,
        nxdomain_total: stats.nxdomain,
        nodata_total: stats.nodata,
        servfail_total: stats.servfail,
        refused_total: stats.refused,
        other_rcode_total: stats.other_rcode,
        queries_unanswered_total: stats.queries_unanswered,
        rx_kernel_dropped_total: stats.rx_kernel_dropped,
        errors_total: stats.errors,
        duration_seconds: elapsed,
        send_duration_seconds: send_elapsed,
        tx_qps: stats.tx_packets as f64 / send_elapsed.unwrap_or(elapsed),
        rx_qps: stats.rx_packets as f64 / send_elapsed.unwrap_or(elapsed),
        queue_stats,
        latency_p50_us,
        latency_p99_us,
        latency_p999_us,
        note: (config.recv.mode == RecvMode::Drop).then_some(if config.xdp.drop_object.is_some() {
            "drop mode attached a kernel XDP_DROP program for configured reply ports"
        } else {
            "drop mode uses TX-only AF_XDP userspace operation in this backend"
        }),
    };
    match config.log.format {
        LogFormat::Json => {
            serde_json::to_writer(io::stdout().lock(), &record)?;
            println!();
        }
        LogFormat::Human => {
            println!(
                "{} backend=xdp_af_xdp if={} tx={:.0}qps rx={:.0}qps tx_total={} rx_total={} positive={} errors={} drop={}{}",
                record.timestamp,
                record.interface,
                record.tx_qps,
                record.rx_qps,
                record.tx_packets_total,
                record.rx_packets_total,
                record.positive_total,
                record.errors_total,
                serde_plain_drop_implementation(record.drop_implementation),
                if summary { " summary=true" } else { "" }
            );
        }
    }
    io::stdout().lock().flush()?;
    Ok(())
}

#[cfg(test)]
fn build_ethernet_udp_dns_frame(
    target_mac: MacAddr,
    source_mac: MacAddr,
    source_ip: IpAddr,
    target_ip: IpAddr,
    source_port: u16,
    target_port: u16,
    dns_payload: &[u8],
) -> Result<Vec<u8>> {
    let frame_len = ethernet_udp_dns_frame_len(source_ip, target_ip, dns_payload.len())
        .map_err(|_| anyhow!("packet frame length is invalid"))?;
    let mut frame = vec![0_u8; frame_len];
    write_ethernet_udp_dns_slice(
        &mut frame,
        target_mac,
        source_mac,
        source_ip,
        target_ip,
        source_port,
        target_port,
        dns_payload,
    )
    .map_err(|_| anyhow!("failed to build packet frame"))?;
    Ok(frame)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn write_ethernet_udp_dns_packet(
    packet: &mut xdp::Packet,
    target_mac: MacAddr,
    source_mac: MacAddr,
    source_ip: IpAddr,
    target_ip: IpAddr,
    source_port: u16,
    target_port: u16,
    dns_payload: &[u8],
) -> Result<usize, xdp::packet::PacketError> {
    packet.clear();
    let frame_len = ethernet_udp_dns_frame_len(source_ip, target_ip, dns_payload.len())?;
    packet.adjust_tail(frame_len as i32)?;
    write_ethernet_udp_dns_slice(
        packet,
        target_mac,
        source_mac,
        source_ip,
        target_ip,
        source_port,
        target_port,
        dns_payload,
    )?;
    Ok(frame_len)
}

#[allow(clippy::too_many_arguments)]
fn write_ethernet_udp_dns_packet_with_query_id(
    packet: &mut xdp::Packet,
    target_mac: MacAddr,
    source_mac: MacAddr,
    source_ip: IpAddr,
    target_ip: IpAddr,
    source_port: u16,
    target_port: u16,
    dns_payload_template: &[u8],
    query_id: u16,
) -> Result<usize, xdp::packet::PacketError> {
    packet.clear();
    let frame_len = ethernet_udp_dns_frame_len(source_ip, target_ip, dns_payload_template.len())?;
    packet.adjust_tail(frame_len as i32)?;
    write_ethernet_udp_dns_slice_with_query_id(
        packet,
        target_mac,
        source_mac,
        source_ip,
        target_ip,
        source_port,
        target_port,
        dns_payload_template,
        Some(query_id),
    )?;
    Ok(frame_len)
}

fn ethernet_udp_dns_frame_len(
    source_ip: IpAddr,
    target_ip: IpAddr,
    dns_payload_len: usize,
) -> Result<usize, xdp::packet::PacketError> {
    let ip_len = match (source_ip, target_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => IPV4_HEADER_LEN,
        (IpAddr::V6(_), IpAddr::V6(_)) => IPV6_HEADER_LEN,
        _ => return Err(xdp::packet::PacketError::InvalidPacketLength {}),
    };
    ETHERNET_HEADER_LEN
        .checked_add(ip_len)
        .and_then(|len| len.checked_add(UDP_HEADER_LEN))
        .and_then(|len| len.checked_add(dns_payload_len))
        .ok_or(xdp::packet::PacketError::InvalidPacketLength {})
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn write_ethernet_udp_dns_slice(
    frame: &mut [u8],
    target_mac: MacAddr,
    source_mac: MacAddr,
    source_ip: IpAddr,
    target_ip: IpAddr,
    source_port: u16,
    target_port: u16,
    dns_payload: &[u8],
) -> Result<(), xdp::packet::PacketError> {
    write_ethernet_udp_dns_slice_with_query_id(
        frame,
        target_mac,
        source_mac,
        source_ip,
        target_ip,
        source_port,
        target_port,
        dns_payload,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_ethernet_udp_dns_slice_with_query_id(
    frame: &mut [u8],
    target_mac: MacAddr,
    source_mac: MacAddr,
    source_ip: IpAddr,
    target_ip: IpAddr,
    source_port: u16,
    target_port: u16,
    dns_payload: &[u8],
    query_id: Option<u16>,
) -> Result<(), xdp::packet::PacketError> {
    match (source_ip, target_ip) {
        (IpAddr::V4(source), IpAddr::V4(target)) => write_ipv4_frame_slice(
            frame,
            target_mac,
            source_mac,
            source,
            target,
            source_port,
            target_port,
            dns_payload,
            query_id,
        ),
        (IpAddr::V6(source), IpAddr::V6(target)) => write_ipv6_frame_slice(
            frame,
            target_mac,
            source_mac,
            source,
            target,
            source_port,
            target_port,
            dns_payload,
            query_id,
        ),
        _ => Err(xdp::packet::PacketError::InvalidPacketLength {}),
    }
}

#[allow(clippy::too_many_arguments)]
fn write_ipv4_frame_slice(
    frame: &mut [u8],
    target_mac: MacAddr,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    source_port: u16,
    target_port: u16,
    dns_payload: &[u8],
    query_id: Option<u16>,
) -> Result<(), xdp::packet::PacketError> {
    let udp_len = UDP_HEADER_LEN
        .checked_add(dns_payload.len())
        .ok_or(xdp::packet::PacketError::InvalidPacketLength {})?;
    let ip_len = IPV4_HEADER_LEN
        .checked_add(udp_len)
        .ok_or(xdp::packet::PacketError::InvalidPacketLength {})?;
    let frame_len = ETHERNET_HEADER_LEN
        .checked_add(ip_len)
        .ok_or(xdp::packet::PacketError::InvalidPacketLength {})?;
    if frame.len() != frame_len || udp_len > u16::MAX as usize || ip_len > u16::MAX as usize {
        return Err(xdp::packet::PacketError::InvalidPacketLength {});
    }

    write_ethernet_slice(frame, target_mac, source_mac, 0x0800);
    let ip_start = ETHERNET_HEADER_LEN;
    frame[ip_start..ip_start + IPV4_HEADER_LEN].copy_from_slice(&[
        0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    frame[ip_start + 2..ip_start + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[ip_start + 12..ip_start + 16].copy_from_slice(&source_ip.octets());
    frame[ip_start + 16..ip_start + 20].copy_from_slice(&target_ip.octets());
    let ip_checksum = checksum(&frame[ip_start..ip_start + IPV4_HEADER_LEN]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_start = ip_start + IPV4_HEADER_LEN;
    write_udp_slice_with_query_id(
        frame,
        udp_start,
        source_port,
        target_port,
        udp_len as u16,
        dns_payload,
        query_id,
    )?;
    let udp_checksum = udp_ipv4_checksum(source_ip, target_ip, &frame[udp_start..]);
    frame[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_ipv6_frame_slice(
    frame: &mut [u8],
    target_mac: MacAddr,
    source_mac: MacAddr,
    source_ip: Ipv6Addr,
    target_ip: Ipv6Addr,
    source_port: u16,
    target_port: u16,
    dns_payload: &[u8],
    query_id: Option<u16>,
) -> Result<(), xdp::packet::PacketError> {
    let udp_len = UDP_HEADER_LEN
        .checked_add(dns_payload.len())
        .ok_or(xdp::packet::PacketError::InvalidPacketLength {})?;
    let frame_len = ETHERNET_HEADER_LEN
        .checked_add(IPV6_HEADER_LEN)
        .and_then(|len| len.checked_add(udp_len))
        .ok_or(xdp::packet::PacketError::InvalidPacketLength {})?;
    if frame.len() != frame_len || udp_len > u16::MAX as usize {
        return Err(xdp::packet::PacketError::InvalidPacketLength {});
    }

    write_ethernet_slice(frame, target_mac, source_mac, 0x86dd);
    let ip_start = ETHERNET_HEADER_LEN;
    frame[ip_start..ip_start + 4].copy_from_slice(&[0x60, 0, 0, 0]);
    frame[ip_start + 4..ip_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    frame[ip_start + 6] = 17;
    frame[ip_start + 7] = 64;
    frame[ip_start + 8..ip_start + 24].copy_from_slice(&source_ip.octets());
    frame[ip_start + 24..ip_start + 40].copy_from_slice(&target_ip.octets());

    let udp_start = ip_start + IPV6_HEADER_LEN;
    write_udp_slice_with_query_id(
        frame,
        udp_start,
        source_port,
        target_port,
        udp_len as u16,
        dns_payload,
        query_id,
    )?;
    let udp_checksum = udp_ipv6_checksum(source_ip, target_ip, &frame[udp_start..]);
    frame[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(())
}

fn write_ethernet_slice(
    frame: &mut [u8],
    target_mac: MacAddr,
    source_mac: MacAddr,
    ether_type: u16,
) {
    frame[0..6].copy_from_slice(&target_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&ether_type.to_be_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_udp_slice_with_query_id(
    frame: &mut [u8],
    udp_start: usize,
    source_port: u16,
    target_port: u16,
    udp_len: u16,
    dns_payload: &[u8],
    query_id: Option<u16>,
) -> Result<(), xdp::packet::PacketError> {
    if query_id.is_some() && dns_payload.len() < 2 {
        return Err(xdp::packet::PacketError::InvalidPacketLength {});
    }
    frame[udp_start..udp_start + 2].copy_from_slice(&source_port.to_be_bytes());
    frame[udp_start + 2..udp_start + 4].copy_from_slice(&target_port.to_be_bytes());
    frame[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
    frame[udp_start + 6..udp_start + 8].copy_from_slice(&0_u16.to_be_bytes());
    frame[udp_start + UDP_HEADER_LEN..udp_start + UDP_HEADER_LEN + dns_payload.len()]
        .copy_from_slice(dns_payload);
    if let Some(query_id) = query_id {
        frame[udp_start + UDP_HEADER_LEN..udp_start + UDP_HEADER_LEN + 2]
            .copy_from_slice(&query_id.to_be_bytes());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReceivedDnsFrame<'a> {
    payload: &'a [u8],
    destination_port: u16,
}

fn dns_payload_from_ethernet_frame(frame: &[u8]) -> Option<ReceivedDnsFrame<'_>> {
    if frame.len() < ETHERNET_HEADER_LEN + UDP_HEADER_LEN {
        return None;
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    match ether_type {
        0x0800 => {
            if frame.len() < ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN {
                return None;
            }
            let ip_start = ETHERNET_HEADER_LEN;
            let ihl = ((frame[ip_start] & 0x0f) as usize) * 4;
            if ihl < IPV4_HEADER_LEN || frame.get(ip_start + 9).copied()? != 17 {
                return None;
            }
            let udp_start = ip_start + ihl;
            let udp_header = frame.get(udp_start..udp_start + UDP_HEADER_LEN)?;
            let destination_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);
            let udp_len = u16::from_be_bytes([udp_header[4], udp_header[5]]) as usize;
            let dns_start = udp_start + UDP_HEADER_LEN;
            let dns_end = udp_start.checked_add(udp_len)?;
            let payload = frame.get(dns_start..dns_end)?;
            Some(ReceivedDnsFrame {
                payload,
                destination_port,
            })
        }
        0x86dd => {
            if frame.len() < ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN {
                return None;
            }
            let ip_start = ETHERNET_HEADER_LEN;
            if frame.get(ip_start + 6).copied()? != 17 {
                return None;
            }
            let udp_start = ip_start + IPV6_HEADER_LEN;
            let udp_header = frame.get(udp_start..udp_start + UDP_HEADER_LEN)?;
            let destination_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);
            let udp_len = u16::from_be_bytes([udp_header[4], udp_header[5]]) as usize;
            let dns_start = udp_start + UDP_HEADER_LEN;
            let dns_end = udp_start.checked_add(udp_len)?;
            let payload = frame.get(dns_start..dns_end)?;
            Some(ReceivedDnsFrame {
                payload,
                destination_port,
            })
        }
        _ => None,
    }
}

fn udp_ipv4_checksum(source: Ipv4Addr, target: Ipv4Addr, udp_payload: &[u8]) -> u16 {
    let source = source.octets();
    let target = target.octets();
    let protocol = [0, 17];
    let len = (udp_payload.len() as u16).to_be_bytes();
    let sum = checksum_parts(&[&source, &target, &protocol, &len, udp_payload]);
    if sum == 0 { 0xffff } else { sum }
}

fn udp_ipv6_checksum(source: Ipv6Addr, target: Ipv6Addr, udp_payload: &[u8]) -> u16 {
    let source = source.octets();
    let target = target.octets();
    let len = (udp_payload.len() as u32).to_be_bytes();
    let next_header = [0, 0, 0, 17];
    checksum_parts(&[&source, &target, &len, &next_header, udp_payload])
}

fn checksum(bytes: &[u8]) -> u16 {
    checksum_parts(&[bytes])
}

fn replace_checksum_word(checksum: u16, old_word: u16, new_word: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!old_word) + u32::from(new_word);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum_parts(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    let mut pending_high_byte = None;
    for bytes in parts {
        for byte in *bytes {
            if let Some(high) = pending_high_byte.take() {
                sum = sum.wrapping_add(u32::from(u16::from_be_bytes([high, *byte])));
            } else {
                pending_high_byte = Some(*byte);
            }
        }
    }
    if let Some(high) = pending_high_byte {
        sum = sum.wrapping_add(u32::from(high) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ipv4_ethernet_udp_dns_frame_with_checksums() {
        let dns = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01";
        let frame = build_ethernet_udp_dns_frame(
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            MacAddr([0x02, 0, 0, 0, 0, 1]),
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 53)),
            53000,
            53,
            dns,
        )
        .expect("frame builds");
        assert_eq!(&frame[0..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), 0x0800);
        assert_eq!(
            checksum(&frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN]),
            0
        );
        let received = dns_payload_from_ethernet_frame(&frame).expect("DNS frame parses");
        assert_eq!(received.payload, dns.as_slice());
        assert_eq!(received.destination_port, 53);
    }

    #[test]
    fn writes_af_xdp_packet_directly_matching_vec_frame() {
        let dns = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01";
        let target_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let source_mac = MacAddr([0x02, 0, 0, 0, 0, 1]);
        let source_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        let target_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 53));
        let frame = build_ethernet_udp_dns_frame(
            target_mac, source_mac, source_ip, target_ip, 53000, 53, dns,
        )
        .expect("frame builds");

        let mut packet_buf = [0_u8; 2 * 1024];
        let mut packet = xdp::Packet::testing_new(&mut packet_buf);
        let len = write_ethernet_udp_dns_packet(
            &mut packet,
            target_mac,
            source_mac,
            source_ip,
            target_ip,
            53000,
            53,
            dns,
        )
        .expect("packet builds");

        assert_eq!(len, frame.len());
        assert_eq!(&packet[..], frame.as_slice());
    }

    #[test]
    fn prebuilt_dns_payload_matches_regular_builder_after_id_patch() {
        let config = FileConfig::default();
        let pool = query_pool(&config).expect("query pool builds");
        let encoded = encoded_query_pool(&pool).expect("query payloads prebuild");
        let mut patched = Vec::new();
        write_query_id_into_dns_payload(&mut patched, &encoded[0], 0x1234);

        let expected = build_dns_query(pool.first(), 0x1234).expect("query builds");
        assert_eq!(patched, expected);
    }

    #[test]
    fn packet_writer_patches_prebuilt_dns_id_before_checksum() {
        let config = FileConfig::default();
        let pool = query_pool(&config).expect("query pool builds");
        let encoded = encoded_query_pool(&pool).expect("query payloads prebuild");
        let expected_dns = build_dns_query(pool.first(), 0x1234).expect("query builds");
        let target_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let source_mac = MacAddr([0x02, 0, 0, 0, 0, 1]);
        let source_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        let target_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 53));
        let expected_frame = build_ethernet_udp_dns_frame(
            target_mac,
            source_mac,
            source_ip,
            target_ip,
            53000,
            53,
            &expected_dns,
        )
        .expect("expected frame builds");

        let mut packet_buf = [0_u8; 2 * 1024];
        let mut packet = xdp::Packet::testing_new(&mut packet_buf);
        let len = write_ethernet_udp_dns_packet_with_query_id(
            &mut packet,
            target_mac,
            source_mac,
            source_ip,
            target_ip,
            53000,
            53,
            &encoded[0],
            0x1234,
        )
        .expect("packet builds");

        assert_eq!(len, expected_frame.len());
        assert_eq!(&packet[..], expected_frame.as_slice());
        assert_eq!(
            checksum(&packet[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN]),
            0
        );
    }

    #[test]
    fn packet_template_patches_ipv4_dns_id_and_checksum() {
        let config = FileConfig::default();
        let pool = query_pool(&config).expect("query pool builds");
        let encoded = encoded_query_pool(&pool).expect("query payloads prebuild");
        let expected_dns = build_dns_query(pool.first(), 0x1234).expect("query builds");
        let target_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let source_mac = MacAddr([0x02, 0, 0, 0, 0, 1]);
        let source = SourceEndpoint {
            ip: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            port: 53000,
        };
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 53)), 53);
        let expected_frame = build_ethernet_udp_dns_frame(
            target_mac,
            source_mac,
            source.ip,
            target.ip(),
            source.port,
            target.port(),
            &expected_dns,
        )
        .expect("expected frame builds");
        let template = XdpPacketTemplate::new(target_mac, source_mac, source, target, &encoded[0])
            .expect("template builds");

        let mut packet_buf = [0_u8; 2 * 1024];
        let mut packet = xdp::Packet::testing_new(&mut packet_buf);
        let len = template
            .write_packet(&mut packet, 0x1234)
            .expect("packet builds from template");

        assert_eq!(len, expected_frame.len());
        assert_eq!(&packet[..], expected_frame.as_slice());
    }

    #[test]
    fn packet_template_patches_ipv6_dns_id_and_checksum() {
        let config = FileConfig::default();
        let pool = query_pool(&config).expect("query pool builds");
        let encoded = encoded_query_pool(&pool).expect("query payloads prebuild");
        let expected_dns = build_dns_query(pool.first(), 0x4321).expect("query builds");
        let target_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let source_mac = MacAddr([0x02, 0, 0, 0, 0, 1]);
        let source = SourceEndpoint {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 53000,
        };
        let target = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);
        let expected_frame = build_ethernet_udp_dns_frame(
            target_mac,
            source_mac,
            source.ip,
            target.ip(),
            source.port,
            target.port(),
            &expected_dns,
        )
        .expect("expected frame builds");
        let template = XdpPacketTemplate::new(target_mac, source_mac, source, target, &encoded[0])
            .expect("template builds");

        let mut packet_buf = [0_u8; 2 * 1024];
        let mut packet = xdp::Packet::testing_new(&mut packet_buf);
        let len = template
            .write_packet(&mut packet, 0x4321)
            .expect("packet builds from template");

        assert_eq!(len, expected_frame.len());
        assert_eq!(&packet[..], expected_frame.as_slice());
    }

    #[test]
    fn checksum_parts_matches_contiguous_bytes_across_odd_boundaries() {
        let bytes = [1_u8, 2, 3, 4, 5, 6, 7];
        assert_eq!(
            checksum_parts(&[&bytes[..1], &bytes[1..4], &bytes[4..]]),
            checksum(&bytes)
        );
    }

    #[test]
    fn shared_inflight_distinguishes_same_id_on_different_ports() {
        let first = Instant::now();
        let inflight = SharedInflight::new(53000, 53001, first);
        let second = first + Duration::from_micros(10);
        inflight.insert(53000, 7, first);
        inflight.insert(53001, 7, second);

        assert_eq!(
            inflight.take(53001, 7, second + Duration::from_micros(5)),
            Some(Duration::from_micros(5))
        );
        assert_eq!(
            inflight.take(53000, 7, second + Duration::from_micros(5)),
            Some(Duration::from_micros(15))
        );
        assert_eq!(inflight.take(53000, 7, second), None);
    }

    #[test]
    fn active_queue_count_does_not_create_zero_limit_workers() {
        let mut config = FileConfig::default();
        config.interface.queue_count = 8;
        config.run.max_packets = 3;
        config.rate.target_qps = Some(2);

        assert_eq!(active_queue_count(&config), 2);
    }

    #[test]
    fn worker_config_pins_auto_source_port_per_queue() {
        let mut config = FileConfig::default();
        config.interface.tx_queue = 10;
        config.interface.rx_queue = 10;
        config.interface.queue_count = 4;
        config.source.port = 53000;
        config.source.port_range = Some("53000-53003".to_owned());
        config.source.port_select = PortSelect::Sequential;

        let worker = worker_config(&config, 2, 4, true).expect("worker config builds");

        assert_eq!(worker.interface.tx_queue, 12);
        assert_eq!(worker.interface.rx_queue, 12);
        assert_eq!(worker.interface.queue_count, 1);
        assert_eq!(worker.source.port, 53002);
        assert_eq!(worker.source.port_range, None);
    }

    #[test]
    fn worker_config_preserves_explicit_source_port_range() {
        let mut config = FileConfig::default();
        config.interface.queue_count = 4;
        config.source.port = 53000;
        config.source.port_range = Some("53000-53003".to_owned());
        config.source.port_select = PortSelect::Random;

        let worker = worker_config(&config, 2, 4, false).expect("worker config builds");

        assert_eq!(worker.source.port, 53000);
        assert_eq!(worker.source.port_range.as_deref(), Some("53000-53003"));
        assert_eq!(worker.source.port_select, PortSelect::Random);
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
        assert!(!should_wakeup_tx(0, 4));
    }

    #[test]
    fn builds_ipv6_ethernet_udp_dns_frame() {
        let dns = b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x01";
        let frame = build_ethernet_udp_dns_frame(
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            MacAddr([0x02, 0, 0, 0, 0, 1]),
            IpAddr::V6("2001:db8::1".parse().expect("valid IPv6")),
            IpAddr::V6("2001:db8::53".parse().expect("valid IPv6")),
            53000,
            53,
            dns,
        )
        .expect("frame builds");
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), 0x86dd);
        let received = dns_payload_from_ethernet_frame(&frame).expect("DNS frame parses");
        assert_eq!(received.payload, dns.as_slice());
        assert_eq!(received.destination_port, 53);
    }

    #[test]
    fn drop_scope_selects_fixed_and_cidr_sources() {
        let target = "198.18.0.53:53".parse().expect("valid target");
        let fixed = FileConfig::default();
        let fixed_scope = drop_scope(&fixed, target).expect("fixed scope");
        assert_eq!(fixed_scope.target, Ipv4Addr::new(198, 18, 0, 53));
        assert_eq!(fixed_scope.source_network, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(fixed_scope.source_mask, u32::MAX);

        let mut cidr = FileConfig::default();
        cidr.source.cidr = Some("198.18.10.0/24".to_owned());
        let cidr_scope = drop_scope(&cidr, target).expect("cidr scope");
        assert_eq!(cidr_scope.source_network, Ipv4Addr::new(198, 18, 10, 0));
        assert_eq!(cidr_scope.source_mask, 0xffff_ff00);
    }

    #[test]
    fn drop_scope_wildcards_uncompact_source_sets() {
        let mut config = FileConfig::default();
        config.source.range_start = Some(IpAddr::V4(Ipv4Addr::new(198, 18, 10, 1)));
        config.source.range_count = Some(4);
        let scope = drop_scope(&config, "198.18.0.53:53".parse().expect("valid target"))
            .expect("range scope");
        assert_eq!(scope.source_network, Ipv4Addr::UNSPECIFIED);
        assert_eq!(scope.source_mask, 0);
    }
}
