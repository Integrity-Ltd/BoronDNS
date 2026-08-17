#![no_std]
#![no_main]
#![allow(unsafe_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, XskMap},
    programs::XdpContext,
};
use core::{mem, ptr};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RedirectConfig {
    pub udp_dest_port_be: u16,
    pub address_family: u8,
    pub wildcard_address: u8,
    pub destination_addr: [u8; 16],
}

#[map]
static REDIRECT_CONFIG: Array<RedirectConfig> = Array::with_max_entries(1, 0);

#[map]
static BORONDNS_XSKS: XskMap = XskMap::with_max_entries(XDP_REDIRECT_MAP_CAPACITY, 0);

// Keep equal to borondns_core::config::XDP_REDIRECT_MAP_CAPACITY. The host
// configuration tests assert this source contract so the independently built
// eBPF artifact cannot silently diverge.
const XDP_REDIRECT_MAP_CAPACITY: u32 = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    eth_proto: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    total_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: [u8; 4],
    dst: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ipv6Hdr {
    version_tc_flow: u32,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UdpHdr {
    source: u16,
    dest: u16,
    len: u16,
    check: u16,
}

// SAFETY: implementors are repr(C) packet headers containing only integer or
// byte-array fields, so every input bit pattern is a valid Rust value.
// SAFETY-ID: UNSAFE-BORONDNS-SERVER-EBPF-LIB-001
unsafe trait PacketPod: Copy {}
// SAFETY: EthHdr is repr(C), Copy, has no padding read by the program, and any
// bit pattern is valid for its byte-array fields.
// SAFETY-ID: UNSAFE-BORONDNS-SERVER-EBPF-LIB-002
unsafe impl PacketPod for EthHdr {}
// SAFETY: Ipv4Hdr is repr(C), Copy, and every field accepts every bit pattern.
// SAFETY-ID: UNSAFE-BORONDNS-SERVER-EBPF-LIB-003
unsafe impl PacketPod for Ipv4Hdr {}
// SAFETY: Ipv6Hdr is repr(C), Copy, and every field accepts every bit pattern.
// SAFETY-ID: UNSAFE-BORONDNS-SERVER-EBPF-LIB-004
unsafe impl PacketPod for Ipv6Hdr {}
// SAFETY: UdpHdr is repr(C), Copy, and every field accepts every bit pattern.
// SAFETY-ID: UNSAFE-BORONDNS-SERVER-EBPF-LIB-005
unsafe impl PacketPod for UdpHdr {}

#[xdp]
pub fn borondns_xdp_redirect(ctx: XdpContext) -> u32 {
    match try_borondns_xdp_redirect(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_borondns_xdp_redirect(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = read_at::<EthHdr>(ctx, 0)?;
    let eth_proto = u16::from_be(eth.eth_proto);
    let Some(config) = REDIRECT_CONFIG.get(0) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let udp_offset = match eth_proto {
        0x0800 => {
            let (udp_offset, destination) = ipv4_udp_info(ctx)?;
            if config.address_family != 4
                || (config.wildcard_address == 0
                    && !ipv4_address_matches(destination, &config.destination_addr))
            {
                return Ok(xdp_action::XDP_PASS);
            }
            udp_offset
        }
        0x86dd => {
            let (udp_offset, destination) = ipv6_udp_info(ctx)?;
            if config.address_family != 6
                || (config.wildcard_address == 0
                    && !ipv6_address_matches(&destination, &config.destination_addr))
            {
                return Ok(xdp_action::XDP_PASS);
            }
            udp_offset
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let udp = read_at::<UdpHdr>(ctx, udp_offset)?;
    if config.udp_dest_port_be != 0 && udp.dest != config.udp_dest_port_be {
        return Ok(xdp_action::XDP_PASS);
    }

    let queue_id = rx_queue_index(ctx);
    Ok(BORONDNS_XSKS
        .redirect(queue_id, xdp_action::XDP_PASS as u64)
        .unwrap_or(xdp_action::XDP_PASS))
}

fn ipv4_udp_info(ctx: &XdpContext) -> Result<(usize, [u8; 4]), ()> {
    let ip_offset = mem::size_of::<EthHdr>();
    let ip = read_at::<Ipv4Hdr>(ctx, ip_offset)?;
    if ip.version_ihl >> 4 != 4 {
        return Err(());
    }
    if ip.protocol != 17 {
        return Err(());
    }
    let ihl = usize::from(ip.version_ihl & 0x0f) * 4;
    if ihl < mem::size_of::<Ipv4Hdr>() {
        return Err(());
    }
    if (u16::from_be(ip.frag_off) & 0x3fff) != 0 {
        return Err(());
    }

    Ok((ip_offset + ihl, ip.dst))
}

fn ipv6_udp_info(ctx: &XdpContext) -> Result<(usize, [u8; 16]), ()> {
    let ip_offset = mem::size_of::<EthHdr>();
    let ip = read_at::<Ipv6Hdr>(ctx, ip_offset)?;
    if u32::from_be(ip.version_tc_flow) >> 28 != 6 {
        return Err(());
    }
    if ip.next_header != 17 {
        // Extension-header parsing is deliberately deferred; pass those packets
        // to the ordinary stack instead of redirecting them to userspace.
        return Err(());
    }
    if u16::from_be(ip.payload_len) < mem::size_of::<UdpHdr>() as u16 {
        return Err(());
    }

    Ok((ip_offset + mem::size_of::<Ipv6Hdr>(), ip.dst))
}

#[inline(always)]
fn ipv4_address_matches(packet: [u8; 4], configured: &[u8; 16]) -> bool {
    packet[0] == configured[0]
        && packet[1] == configured[1]
        && packet[2] == configured[2]
        && packet[3] == configured[3]
}

#[inline(always)]
fn ipv6_address_matches(packet: &[u8; 16], configured: &[u8; 16]) -> bool {
    packet[0] == configured[0]
        && packet[1] == configured[1]
        && packet[2] == configured[2]
        && packet[3] == configured[3]
        && packet[4] == configured[4]
        && packet[5] == configured[5]
        && packet[6] == configured[6]
        && packet[7] == configured[7]
        && packet[8] == configured[8]
        && packet[9] == configured[9]
        && packet[10] == configured[10]
        && packet[11] == configured[11]
        && packet[12] == configured[12]
        && packet[13] == configured[13]
        && packet[14] == configured[14]
        && packet[15] == configured[15]
}

fn read_at<T: PacketPod>(ctx: &XdpContext, offset: usize) -> Result<T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let size = mem::size_of::<T>();
    let location = start.checked_add(offset).ok_or(())?;
    let limit = location.checked_add(size).ok_or(())?;
    if limit > end {
        return Err(());
    }
    let ptr = location as *const T;
    // SAFETY: bounds are checked against data_end above, PacketPod guarantees
    // all input bit patterns are valid T values, and unaligned access is
    // required because packet headers are byte streams.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-EBPF-LIB-006
    Ok(unsafe { ptr::read_unaligned(ptr) })
}

fn rx_queue_index(ctx: &XdpContext) -> u32 {
    // SAFETY: `ctx.ctx` is the kernel-provided xdp_md pointer for this program
    // invocation and remains valid for the duration of the call.
    // SAFETY-ID: UNSAFE-BORONDNS-SERVER-EBPF-LIB-007
    unsafe { (*ctx.ctx).rx_queue_index }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
