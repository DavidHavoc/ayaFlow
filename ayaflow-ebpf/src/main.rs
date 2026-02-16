#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::classifier,
    programs::TcContext,
};

#[no_mangle]
#[link_section = "license"]
pub static _license: [u8; 4] = *b"GPL\0";

#[classifier]
pub fn ayaflow(_ctx: TcContext) -> i32 {
    TC_ACT_PIPE
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
