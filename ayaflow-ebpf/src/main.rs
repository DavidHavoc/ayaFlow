#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]

use aya_ebpf::{
    bindings::{__sk_buff, TC_ACT_PIPE},
    macros::map,
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

/// TC classifier entry point.
///
/// We set `#[link_section = "classifier/ayaflow"]` manually instead of using
/// the `#[classifier]` proc-macro.  aya-ebpf-macros 0.1.x generates a bare
/// `classifier` section, but aya 0.13.x requires the `prefix/name` format
/// to properly resolve map relocations.  Without the suffix, aya loads the
/// program with 0 instructions and the kernel verifier rejects it.
#[no_mangle]
#[link_section = "classifier/ayaflow"]
pub fn ayaflow(ctx: *mut __sk_buff) -> i32 {
    let ctx = unsafe { TcContext::new(ctx) };
    try_classify(&ctx)
}

#[inline(always)]
fn try_classify(ctx: &TcContext) -> i32 {
    // -- Ethernet ----------------------------------------------------------
    let data = ctx.data();
    let data_end = ctx.data_end();

    let eth_end = data + EthHdr::LEN;
    if eth_end > data_end {
        return TC_ACT_PIPE;
    }
    let eth_hdr = data as *const EthHdr;
    let ether_type = unsafe { ptr::read_unaligned(ptr::addr_of!((*eth_hdr).ether_type)) };
    if ether_type != EtherType::Ipv4 {
        return TC_ACT_PIPE;
    }

    // -- IPv4 --------------------------------------------------------------
    let ip_start = eth_end;
    let ip_end = ip_start + Ipv4Hdr::LEN;
    if ip_end > data_end {
        return TC_ACT_PIPE;
    }
    let ip_hdr = ip_start as *const Ipv4Hdr;
    let proto = unsafe { ptr::read_unaligned(ptr::addr_of!((*ip_hdr).proto)) };
    let src_addr = u32::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*ip_hdr).src_addr)) });
    let dst_addr = u32::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*ip_hdr).dst_addr)) });
    let pkt_len =
        u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*ip_hdr).tot_len)) }) as u32;

    // -- Transport ---------------------------------------------------------
    let transport_start = ip_end;
    let (src_port, dst_port) = match proto {
        IpProto::Tcp => {
            let tcp_end = transport_start + TcpHdr::LEN;
            if tcp_end > data_end {
                return TC_ACT_PIPE;
            }
            let tcp_hdr = transport_start as *const TcpHdr;
            (
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*tcp_hdr).source)) }),
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*tcp_hdr).dest)) }),
            )
        }
        IpProto::Udp => {
            let udp_end = transport_start + UdpHdr::LEN;
            if udp_end > data_end {
                return TC_ACT_PIPE;
            }
            let udp_hdr = transport_start as *const UdpHdr;
            (
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*udp_hdr).source)) }),
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*udp_hdr).dest)) }),
            )
        }
        _ => return TC_ACT_PIPE,
    };

    // -- Emit event --------------------------------------------------------
    if let Some(mut buf) = EVENTS.reserve::<PacketEvent>(0) {
        let p = buf.as_mut_ptr() as *mut PacketEvent;
        unsafe {
            ptr::write(ptr::addr_of_mut!((*p).src_addr), src_addr);
            ptr::write(ptr::addr_of_mut!((*p).dst_addr), dst_addr);
            ptr::write(ptr::addr_of_mut!((*p).src_port), src_port);
            ptr::write(ptr::addr_of_mut!((*p).dst_port), dst_port);
            ptr::write(ptr::addr_of_mut!((*p).protocol), proto as u8);
            ptr::write(ptr::addr_of_mut!((*p).pkt_len), pkt_len);
        }
        buf.submit(0);
    }

    TC_ACT_PIPE
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
