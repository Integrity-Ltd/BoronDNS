#![no_std]
#![no_main]
#![allow(unsafe_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, PerCpuArray, XskMap},
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

#[map]
static REDIRECTED_PACKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PASSED_PACKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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
        Err(()) => {
            increment_counter(&PASSED_PACKETS);
            xdp_action::XDP_PASS
        }
    }
}

fn try_oxidedns_xdp_redirect(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = read_at::<EthHdr>(ctx, 0)?;
    if u16::from_be(eth.eth_proto) != 0x0800 {
        increment_counter(&PASSED_PACKETS);
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_offset = mem::size_of::<EthHdr>();
    let ip = read_at::<Ipv4Hdr>(ctx, ip_offset)?;
    if ip.protocol != 17 {
        increment_counter(&PASSED_PACKETS);
        return Ok(xdp_action::XDP_PASS);
    }
    let ihl = usize::from(ip.version_ihl & 0x0f) * 4;
    if ihl < mem::size_of::<Ipv4Hdr>() {
        increment_counter(&PASSED_PACKETS);
        return Ok(xdp_action::XDP_PASS);
    }
    if (u16::from_be(ip.frag_off) & 0x3fff) != 0 {
        increment_counter(&PASSED_PACKETS);
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = read_at::<UdpHdr>(ctx, ip_offset + ihl)?;
    let Some(config) = REDIRECT_CONFIG.get(0) else {
        increment_counter(&PASSED_PACKETS);
        return Ok(xdp_action::XDP_PASS);
    };
    if config.udp_dest_port_be != 0 && udp.dest != config.udp_dest_port_be {
        increment_counter(&PASSED_PACKETS);
        return Ok(xdp_action::XDP_PASS);
    }

    let queue_id = rx_queue_index(ctx);
    let action = OXIDEDNS_XSKS
        .redirect(queue_id, xdp_action::XDP_PASS as u64)
        .unwrap_or(xdp_action::XDP_PASS);
    if action == xdp_action::XDP_REDIRECT {
        increment_counter(&REDIRECTED_PACKETS);
    } else {
        increment_counter(&PASSED_PACKETS);
    }
    Ok(action)
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

fn increment_counter(counter: &PerCpuArray<u64>) {
    let Some(value) = counter.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: the pointer comes from a valid per-CPU Array map entry for the
    // current CPU, so a plain increment is sufficient.
    unsafe {
        *value += 1;
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
