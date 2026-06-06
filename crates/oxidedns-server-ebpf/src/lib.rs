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
}

#[map]
static REDIRECT_CONFIG: Array<RedirectConfig> = Array::with_max_entries(1, 0);

#[map]
static OXIDEDNS_XSKS: XskMap = XskMap::with_max_entries(64, 0);

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
    src: u32,
    dst: u32,
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

#[xdp]
pub fn oxidedns_xdp_redirect(ctx: XdpContext) -> u32 {
    match try_oxidedns_xdp_redirect(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_oxidedns_xdp_redirect(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = read_at::<EthHdr>(ctx, 0)?;
    let eth_proto = u16::from_be(eth.eth_proto);
    let udp_offset = match eth_proto {
        0x0800 => ipv4_udp_offset(ctx)?,
        0x86dd => ipv6_udp_offset(ctx)?,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let udp = read_at::<UdpHdr>(ctx, udp_offset)?;
    let Some(config) = REDIRECT_CONFIG.get(0) else {
        return Ok(xdp_action::XDP_PASS);
    };
    if config.udp_dest_port_be != 0 && udp.dest != config.udp_dest_port_be {
        return Ok(xdp_action::XDP_PASS);
    }

    let queue_id = rx_queue_index(ctx);
    Ok(OXIDEDNS_XSKS
        .redirect(queue_id, xdp_action::XDP_PASS as u64)
        .unwrap_or(xdp_action::XDP_PASS))
}

fn ipv4_udp_offset(ctx: &XdpContext) -> Result<usize, ()> {
    let ip_offset = mem::size_of::<EthHdr>();
    let ip = read_at::<Ipv4Hdr>(ctx, ip_offset)?;
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

    Ok(ip_offset + ihl)
}

fn ipv6_udp_offset(ctx: &XdpContext) -> Result<usize, ()> {
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

    Ok(ip_offset + mem::size_of::<Ipv6Hdr>())
}

fn read_at<T: Copy>(ctx: &XdpContext, offset: usize) -> Result<T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let size = mem::size_of::<T>();
    if start + offset + size > end {
        return Err(());
    }
    let ptr = (start + offset) as *const T;
    // SAFETY: bounds are checked against data_end above; unaligned access is
    // required because packet headers are byte streams, not Rust-aligned structs.
    Ok(unsafe { ptr::read_unaligned(ptr) })
}

fn rx_queue_index(ctx: &XdpContext) -> u32 {
    // SAFETY: `ctx.ctx` is the kernel-provided xdp_md pointer for this program
    // invocation and remains valid for the duration of the call.
    unsafe { (*ctx.ctx).rx_queue_index }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
