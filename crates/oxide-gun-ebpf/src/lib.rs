#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, PerCpuArray},
    programs::XdpContext,
};
use core::{mem, ptr};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DropConfig {
    pub port_start_be: u16,
    pub port_end_be: u16,
    pub target_ipv4_be: u32,
    pub source_ipv4_be: u32,
    pub source_mask_be: u32,
}

#[map]
static DROP_CONFIG: Array<DropConfig> = Array::with_max_entries(1, 0);

#[map]
static DROPPED_PACKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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
pub fn oxide_gun_drop(ctx: XdpContext) -> u32 {
    match try_oxide_gun_drop(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_oxide_gun_drop(ctx: &XdpContext) -> Result<u32, ()> {
    let eth = read_at::<EthHdr>(ctx, 0)?;
    if u16::from_be(eth.eth_proto) != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_offset = mem::size_of::<EthHdr>();
    let ip = read_at::<Ipv4Hdr>(ctx, ip_offset)?;
    if ip.protocol != 17 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ihl = usize::from(ip.version_ihl & 0x0f) * 4;
    if ihl < mem::size_of::<Ipv4Hdr>() {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = read_at::<UdpHdr>(ctx, ip_offset + ihl)?;
    let Some(config) = DROP_CONFIG.get(0) else {
        return Ok(xdp_action::XDP_PASS);
    };
    if config.target_ipv4_be != 0 && ip.src != config.target_ipv4_be {
        return Ok(xdp_action::XDP_PASS);
    }
    if config.source_mask_be != 0
        && (ip.dst & config.source_mask_be) != (config.source_ipv4_be & config.source_mask_be)
    {
        return Ok(xdp_action::XDP_PASS);
    }

    let dst_port = udp.dest;
    if port_in_range(dst_port, config.port_start_be, config.port_end_be) {
        increment_drop_counter();
        Ok(xdp_action::XDP_DROP)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
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

fn port_in_range(port_be: u16, start_be: u16, end_be: u16) -> bool {
    let port = u16::from_be(port_be);
    let start = u16::from_be(start_be);
    let end = u16::from_be(end_be);
    port >= start && port <= end
}

fn increment_drop_counter() {
    let Some(counter) = DROPPED_PACKETS.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: the pointer comes from a valid per-CPU Array map entry for the
    // current CPU, so a plain increment is sufficient.
    unsafe {
        *counter += 1;
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
