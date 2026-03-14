#![no_std]

/// Packet metadata passed from the eBPF TC hook to userspace via a RingBuf.
///
/// Kept intentionally small: eBPF has a 512-byte stack limit and the verifier
/// is strict about memory access.  Timestamps are assigned in userspace where
/// `chrono` is available.
///
/// IPv6 support is not here-- addresses are stored as 32-bit IPv4 for now.
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
    /// Packet direction: 0 = ingress, 1 = egress.
    pub direction: u8,
    /// Padding to maintain alignment.
    pub _pad: [u8; 2],
    /// Total packet length from the IP header.
    pub pkt_len: u32,
}

/// Maximum bytes of L7 payload forwarded from eBPF to userspace.
///
/// 256 bytes is enough for virtually all DNS queries and TLS ClientHello
/// SNI extensions while staying comfortably within eBPF stack/verifier limits.
pub const MAX_PAYLOAD_LEN: usize = 256;

/// Payload event passed from eBPF to userspace via a **separate** RingBuf.
///
/// Only emitted for packets that qualify for L7 inspection (DNS on port 53,
/// TLS on port 443) and only when deep inspection is enabled at runtime.
/// The existing `PacketEvent` path is completely unaffected.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PayloadEvent {
    /// Source IPv4 address (host byte order).
    pub src_addr: u32,
    /// Destination IPv4 address (host byte order).
    pub dst_addr: u32,
    /// Source port (host byte order).
    pub src_port: u16,
    /// Destination port (host byte order).
    pub dst_port: u16,
    /// IP protocol number: 6 = TCP, 17 = UDP.
    pub protocol: u8,
    /// Packet direction: 0 = ingress, 1 = egress.
    pub direction: u8,
    /// Padding to maintain alignment.
    pub _pad: [u8; 2],
    /// Total packet length from the IP header.
    pub pkt_len: u32,
    /// Actual number of payload bytes copied (may be < MAX_PAYLOAD_LEN).
    pub payload_len: u16,
    /// Padding for alignment.
    pub _pad2: [u8; 2],
    /// Raw L7 payload bytes (DNS query or TLS ClientHello).
    pub payload: [u8; MAX_PAYLOAD_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PayloadEvent {}
