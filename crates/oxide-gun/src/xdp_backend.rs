#![allow(unsafe_code)]

use std::ffi::CString;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use time::OffsetDateTime;
use xdp::slab::{HeapSlab, Slab};
use xdp::socket::{BindFlags, PollTimeout, XdpSocketBuilder};

use super::{
    DEFAULT_TARGET, FileConfig, LogFormat, MacAddr, QueryTemplate, RecvMode, ResponseClass, Stats,
    XdpMode, XdpZeroCopyMode, build_dns_query, classify_response, query_template,
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
    recv_mode: RecvMode,
    target: SocketAddr,
    source_ip: IpAddr,
    source_port: u16,
    qname: &'a str,
    qtype: &'a str,
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
    errors_total: u64,
    duration_seconds: f64,
    tx_qps: f64,
    rx_qps: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
}

pub(super) fn run(config: &FileConfig) -> Result<()> {
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
    let query = query_template(config)?;
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

    if config.recv.mode == RecvMode::Process {
        // SAFETY: all RX frame addresses come from `umem`, and both the UMEM
        // mapping and AF_XDP socket outlive the fill/RX rings in this function.
        unsafe {
            rings
                .fill_ring
                .enqueue(&mut umem, config.xdp.fill_ring_size as usize, true)
                .context("failed to populate AF_XDP fill ring")?;
        }
    }

    let mut tx_ring = rings
        .tx_ring
        .take()
        .ok_or_else(|| anyhow!("AF_XDP TX ring was not configured"))?;
    let mut rx_ring = rings.rx_ring.take();
    let mut stats = Stats::default();
    let mut send_slab = HeapSlab::with_capacity(1);
    let mut recv_slab = HeapSlab::with_capacity(64);
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

    while stats.tx_packets < max_packets {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
        query_id = query_id.wrapping_add(1);
        let dns = build_dns_query(&query, query_id)?;
        let frame = build_ethernet_udp_dns_frame(
            target_mac,
            source_mac,
            config.source.ip,
            target.ip(),
            config.source.port,
            target.port(),
            &dns,
        )?;
        // SAFETY: returned packet stays within this function, is either handed
        // to the TX ring while `umem` and `socket` remain alive, or immediately
        // freed back to the same UMEM on error.
        let Some(mut packet) = (unsafe { umem.alloc() }) else {
            stats.errors += 1;
            rings.completion_ring.dequeue(&mut umem, 64);
            continue;
        };
        if let Err(error) = packet.append(&frame) {
            umem.free_packet(packet);
            return Err(error).context("failed to write packet into AF_XDP frame");
        }
        if send_slab.push_front(packet).is_some() {
            bail!("internal AF_XDP send slab overflow");
        }
        // SAFETY: every packet in `send_slab` was allocated from `umem`, and
        // `umem` outlives the socket and TX ring for the entire send loop.
        let sent = unsafe { tx_ring.send(&mut send_slab, true) }
            .context("failed to enqueue AF_XDP packet")?;
        if sent == 0 {
            stats.errors += 1;
            while let Some(packet) = send_slab.pop_back() {
                umem.free_packet(packet);
            }
        } else {
            stats.tx_packets += sent as u64;
            stats.tx_bytes += frame.len() as u64 * sent as u64;
        }
        rings.completion_ring.dequeue(&mut umem, 64);

        if config.recv.mode == RecvMode::Process {
            receive_available_xdp(
                &socket,
                rx_ring.as_mut(),
                &mut rings.fill_ring,
                &mut umem,
                &mut recv_slab,
                query_id,
                &mut stats,
            )?;
        }

        if config.log.flush_interval_ms > 0
            && last_flush.elapsed() >= Duration::from_millis(config.log.flush_interval_ms)
        {
            emit_xdp_record(config, interface, target, &query, &stats, start, false)?;
            last_flush = Instant::now();
        }

        if let Some(delay) = per_packet_delay {
            std::thread::sleep(delay);
        }
    }

    emit_xdp_record(config, interface, target, &query, &stats, start, true)
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

fn receive_available_xdp(
    socket: &xdp::socket::XdpSocket,
    rx_ring: Option<&mut xdp::RxRing>,
    fill_ring: &mut xdp::WakableFillRing,
    umem: &mut xdp::Umem,
    recv_slab: &mut HeapSlab,
    expected_id: u16,
    stats: &mut Stats,
) -> Result<()> {
    let Some(rx_ring) = rx_ring else {
        return Ok(());
    };
    if !socket
        .poll_read(PollTimeout::new(Some(Duration::from_millis(0))))
        .context("failed to poll AF_XDP RX ring")?
    {
        return Ok(());
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
        if let Some(dns_payload) = dns_payload_from_ethernet_frame(&packet) {
            match classify_response(dns_payload, expected_id) {
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
    Ok(())
}

fn emit_xdp_record(
    config: &FileConfig,
    interface: &str,
    target: SocketAddr,
    query: &QueryTemplate,
    stats: &Stats,
    start: Instant,
    summary: bool,
) -> Result<()> {
    let elapsed = start.elapsed().as_secs_f64().max(0.000_001);
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
        recv_mode: config.recv.mode,
        target,
        source_ip: config.source.ip,
        source_port: config.source.port,
        qname: &query.qname,
        qtype: &query.qtype_name,
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
        errors_total: stats.errors,
        duration_seconds: elapsed,
        tx_qps: stats.tx_packets as f64 / elapsed,
        rx_qps: stats.rx_packets as f64 / elapsed,
        note: (config.recv.mode == RecvMode::Drop)
            .then_some("drop mode uses TX-only AF_XDP userspace operation in this backend"),
    };
    match config.log.format {
        LogFormat::Json => {
            serde_json::to_writer(io::stdout().lock(), &record)?;
            println!();
        }
        LogFormat::Human => {
            println!(
                "{} backend=xdp_af_xdp if={} tx={:.0}qps rx={:.0}qps tx_total={} rx_total={} positive={} errors={}{}",
                record.timestamp,
                record.interface,
                record.tx_qps,
                record.rx_qps,
                record.tx_packets_total,
                record.rx_packets_total,
                record.positive_total,
                record.errors_total,
                if summary { " summary=true" } else { "" }
            );
        }
    }
    io::stdout().lock().flush()?;
    Ok(())
}

fn build_ethernet_udp_dns_frame(
    target_mac: MacAddr,
    source_mac: MacAddr,
    source_ip: IpAddr,
    target_ip: IpAddr,
    source_port: u16,
    target_port: u16,
    dns_payload: &[u8],
) -> Result<Vec<u8>> {
    match (source_ip, target_ip) {
        (IpAddr::V4(source), IpAddr::V4(target)) => build_ipv4_frame(
            target_mac,
            source_mac,
            source,
            target,
            source_port,
            target_port,
            dns_payload,
        ),
        (IpAddr::V6(source), IpAddr::V6(target)) => build_ipv6_frame(
            target_mac,
            source_mac,
            source,
            target,
            source_port,
            target_port,
            dns_payload,
        ),
        _ => bail!("source and target IP versions must match"),
    }
}

fn build_ipv4_frame(
    target_mac: MacAddr,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    source_port: u16,
    target_port: u16,
    dns_payload: &[u8],
) -> Result<Vec<u8>> {
    let udp_len = checked_u16(UDP_HEADER_LEN + dns_payload.len(), "UDP payload")?;
    let ip_len = checked_u16(IPV4_HEADER_LEN + udp_len as usize, "IPv4 packet")?;
    let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + ip_len as usize);
    append_ethernet(&mut frame, target_mac, source_mac, 0x0800);
    let ip_start = frame.len();
    frame.extend_from_slice(&[
        0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    frame[ip_start + 2..ip_start + 4].copy_from_slice(&ip_len.to_be_bytes());
    frame[ip_start + 12..ip_start + 16].copy_from_slice(&source_ip.octets());
    frame[ip_start + 16..ip_start + 20].copy_from_slice(&target_ip.octets());
    let ip_checksum = checksum(&frame[ip_start..ip_start + IPV4_HEADER_LEN]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());
    let udp_start = frame.len();
    append_udp(&mut frame, source_port, target_port, udp_len, dns_payload);
    let udp_checksum = udp_ipv4_checksum(source_ip, target_ip, &frame[udp_start..]);
    frame[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(frame)
}

fn build_ipv6_frame(
    target_mac: MacAddr,
    source_mac: MacAddr,
    source_ip: Ipv6Addr,
    target_ip: Ipv6Addr,
    source_port: u16,
    target_port: u16,
    dns_payload: &[u8],
) -> Result<Vec<u8>> {
    let udp_len = checked_u16(UDP_HEADER_LEN + dns_payload.len(), "UDP payload")?;
    let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + udp_len as usize);
    append_ethernet(&mut frame, target_mac, source_mac, 0x86dd);
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.push(17);
    frame.push(64);
    frame.extend_from_slice(&source_ip.octets());
    frame.extend_from_slice(&target_ip.octets());
    let udp_start = frame.len();
    append_udp(&mut frame, source_port, target_port, udp_len, dns_payload);
    let udp_checksum = udp_ipv6_checksum(source_ip, target_ip, &frame[udp_start..]);
    frame[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(frame)
}

fn append_ethernet(frame: &mut Vec<u8>, target_mac: MacAddr, source_mac: MacAddr, ether_type: u16) {
    frame.extend_from_slice(&target_mac.0);
    frame.extend_from_slice(&source_mac.0);
    frame.extend_from_slice(&ether_type.to_be_bytes());
}

fn append_udp(
    frame: &mut Vec<u8>,
    source_port: u16,
    target_port: u16,
    udp_len: u16,
    dns_payload: &[u8],
) {
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&target_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(dns_payload);
}

fn dns_payload_from_ethernet_frame(frame: &[u8]) -> Option<&[u8]> {
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
            let udp_len = u16::from_be_bytes([frame[udp_start + 4], frame[udp_start + 5]]) as usize;
            let dns_start = udp_start + UDP_HEADER_LEN;
            let dns_end = udp_start.checked_add(udp_len)?;
            frame.get(dns_start..dns_end)
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
            let udp_len = u16::from_be_bytes([frame[udp_start + 4], frame[udp_start + 5]]) as usize;
            let dns_start = udp_start + UDP_HEADER_LEN;
            let dns_end = udp_start.checked_add(udp_len)?;
            frame.get(dns_start..dns_end)
        }
        _ => None,
    }
}

fn checked_u16(value: usize, field: &str) -> Result<u16> {
    u16::try_from(value).with_context(|| format!("{field} exceeds 65535 octets"))
}

fn udp_ipv4_checksum(source: Ipv4Addr, target: Ipv4Addr, udp_payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_payload.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&target.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_payload.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_payload);
    let sum = checksum(&pseudo);
    if sum == 0 { 0xffff } else { sum }
}

fn udp_ipv6_checksum(source: Ipv6Addr, target: Ipv6Addr, udp_payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp_payload.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&target.octets());
    pseudo.extend_from_slice(&(udp_payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(udp_payload);
    checksum(&pseudo)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
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
        assert_eq!(
            dns_payload_from_ethernet_frame(&frame),
            Some(dns.as_slice())
        );
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
        assert_eq!(
            dns_payload_from_ethernet_frame(&frame),
            Some(dns.as_slice())
        );
    }
}
