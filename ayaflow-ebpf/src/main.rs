#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]

use aya_ebpf::{
    bindings::{__sk_buff, TC_ACT_PIPE},
    macros::map,
    maps::{Array, RingBuf},
    programs::TcContext,
};
use ayaflow_common::{PacketEvent, PayloadEvent, MAX_PAYLOAD_LEN};
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

/// Existing ring buffer for lightweight L3/L4 PacketEvent -- always active.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Second ring buffer for L7 payload events -- only written to when deep
/// inspection is enabled via CONFIG[0].
#[map]
static PAYLOAD_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Runtime configuration flag.  Index 0: deep_inspect (0 = off, 1 = on).
/// Userspace writes this at program load time.
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

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
    let (src_port, dst_port, payload_offset) = match proto {
        IpProto::Tcp => {
            let tcp_end = transport_start + TcpHdr::LEN;
            if tcp_end > data_end {
                return TC_ACT_PIPE;
            }
            let tcp_hdr = transport_start as *const TcpHdr;
            let sport =
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*tcp_hdr).source)) });
            let dport =
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*tcp_hdr).dest)) });
            // TCP data offset is in the upper 4 bits of the 13th byte (doff field),
            // measured in 32-bit words.
            let doff = unsafe { ptr::read_unaligned(ptr::addr_of!((*tcp_hdr).doff)) };
            let tcp_header_len = ((doff >> 4) & 0x0F) as usize * 4;
            (sport, dport, transport_start + tcp_header_len)
        }
        IpProto::Udp => {
            let udp_end = transport_start + UdpHdr::LEN;
            if udp_end > data_end {
                return TC_ACT_PIPE;
            }
            let udp_hdr = transport_start as *const UdpHdr;
            let sport =
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*udp_hdr).source)) });
            let dport =
                u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*udp_hdr).dest)) });
            (sport, dport, udp_end)
        }
        _ => return TC_ACT_PIPE,
    };

    // -- Emit L3/L4 event (always) -----------------------------------------
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

    // -- Conditionally emit L7 payload event -------------------------------
    // Only fire for DNS (port 53) or TLS (port 443) when deep_inspect is on.
    let wants_payload = (proto == IpProto::Tcp && dst_port == 443)
        || (proto == IpProto::Udp && (dst_port == 53 || src_port == 53));

    if wants_payload {
        if let Some(flag) = unsafe { CONFIG.get(0) } {
            if *flag == 1 {
                emit_payload(ctx, src_addr, dst_addr, src_port, dst_port, proto as u8, pkt_len, payload_offset, data_end);
            }
        }
    }

    TC_ACT_PIPE
}

/// Copy up to MAX_PAYLOAD_LEN bytes of L7 payload into the PAYLOAD_EVENTS
/// ring buffer.  All bounds are checked against `data_end` to satisfy the
/// eBPF verifier.
#[inline(always)]
fn emit_payload(
    _ctx: &TcContext,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    pkt_len: u32,
    payload_offset: usize,
    data_end: usize,
) {
    // Verify there is at least 1 byte of payload.
    if payload_offset >= data_end {
        return;
    }

    let available = data_end - payload_offset;
    let copy_len = if available > MAX_PAYLOAD_LEN {
        MAX_PAYLOAD_LEN
    } else {
        available
    };

    // Bounds-check the range we are about to read.
    if payload_offset + copy_len > data_end {
        return;
    }

    if let Some(mut buf) = PAYLOAD_EVENTS.reserve::<PayloadEvent>(0) {
        let p = buf.as_mut_ptr() as *mut PayloadEvent;
        unsafe {
            ptr::write(ptr::addr_of_mut!((*p).src_addr), src_addr);
            ptr::write(ptr::addr_of_mut!((*p).dst_addr), dst_addr);
            ptr::write(ptr::addr_of_mut!((*p).src_port), src_port);
            ptr::write(ptr::addr_of_mut!((*p).dst_port), dst_port);
            ptr::write(ptr::addr_of_mut!((*p).protocol), protocol);
            ptr::write(ptr::addr_of_mut!((*p)._pad), [0u8; 3]);
            ptr::write(ptr::addr_of_mut!((*p).pkt_len), pkt_len);
            ptr::write(ptr::addr_of_mut!((*p).payload_len), copy_len as u16);
            ptr::write(ptr::addr_of_mut!((*p)._pad2), [0u8; 2]);

            // Zero the payload buffer first, then copy actual bytes.
            // Using a bounded loop that the verifier can unroll/verify.
            let payload_dst = ptr::addr_of_mut!((*p).payload) as *mut u8;
            let payload_src = payload_offset as *const u8;

            // Zero the full buffer.
            let mut i: usize = 0;
            while i < MAX_PAYLOAD_LEN {
                *payload_dst.add(i) = 0;
                i += 1;
            }

            // Copy the actual payload bytes.  The verifier needs the
            // copy_len bound to be provably <= MAX_PAYLOAD_LEN.
            i = 0;
            while i < copy_len && i < MAX_PAYLOAD_LEN {
                // Re-verify pointer is within packet bounds on each iteration
                // to satisfy the eBPF verifier.
                let src_ptr = payload_src.add(i);
                if (src_ptr as usize) + 1 > data_end {
                    break;
                }
                *payload_dst.add(i) = ptr::read_unaligned(src_ptr);
                i += 1;
            }
        }
        buf.submit(0);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
