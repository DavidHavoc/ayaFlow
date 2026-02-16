#![no_std]

/// Packet metadata passed from the eBPF TC hook to userspace via a RingBuf.
///
/// Kept intentionally small: eBPF has a 512-byte stack limit and the verifier
/// is strict about memory access.  Timestamps are assigned in userspace where
/// `chrono` is available.
///
/// IPv6 support is deferred -- addresses are stored as 32-bit IPv4 for now.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct PacketEvent {
    /// Source IPv4 address in network byte order.
    pub src_addr: u32,
    /// Destination IPv4 address in network byte order.
    pub dst_addr: u32,
    /// Source port (host byte order after conversion in eBPF).
    pub src_port: u16,
    /// Destination port (host byte order after conversion in eBPF).
    pub dst_port: u16,
    /// IP protocol number: 6 = TCP, 17 = UDP.
    pub protocol: u8,
    /// Padding to maintain alignment.
    pub _pad: [u8; 3],
    /// Total packet length from the IP header.
    pub pkt_len: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}
