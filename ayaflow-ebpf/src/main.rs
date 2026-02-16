#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use ayaflow_common::PacketEvent;
use core::ptr;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[no_mangle]
#[link_section = "license"]
pub static _license: [u8; 4] = *b"GPL\0";

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[classifier]
pub fn ayaflow(ctx: TcContext) -> i32 {
    match try_ayaflow(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline(always)]
fn try_ayaflow(ctx: &TcContext) -> Result<i32, ()> {
    // --- Ethernet ---
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    let ether_type = unsafe { ptr::read_unaligned(ptr::addr_of!(ethhdr.ether_type)) };
    if ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_PIPE);
    }

    // --- IPv4 ---
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let proto = unsafe { ptr::read_unaligned(ptr::addr_of!(ipv4hdr.proto)) };

    let src_addr = u32::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!(ipv4hdr.src_addr)) });
    let dst_addr = u32::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!(ipv4hdr.dst_addr)) });
    let pkt_len = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!(ipv4hdr.tot_len)) }) as u32;

    let ip_hdr_len = EthHdr::LEN + Ipv4Hdr::LEN;

    // --- Transport ---
    let (src_port, dst_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx.load(ip_hdr_len).map_err(|_| ())?;
            (
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!(tcphdr.source)) }),
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!(tcphdr.dest)) }),
            )
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(ip_hdr_len).map_err(|_| ())?;
            (
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!(udphdr.source)) }),
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!(udphdr.dest)) }),
            )
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    // --- Emit event ---
    let event = PacketEvent {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol: proto as u8,
        _pad: [0u8; 3],
        pkt_len,
    };

    if let Some(mut buf) = EVENTS.reserve::<PacketEvent>(0) {
        unsafe {
            core::ptr::write_unaligned(buf.as_mut_ptr() as *mut PacketEvent, event);
        }
        buf.submit(0);
    }

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
