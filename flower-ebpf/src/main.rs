#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn flower(ctx: ProbeContext) -> u32 {
    match try_flower(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_flower(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function __arm64_sys_futex called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
