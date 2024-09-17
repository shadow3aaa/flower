#![no_std]
#![no_main]
mod futex;

use core::ffi::{c_int, c_long};

use aya_ebpf::{
    helpers::{bpf_probe_read, bpf_probe_read_user}, macros::{kprobe, kretprobe, map}, maps::{self, RingBuf}, programs::{ProbeContext, RetProbeContext}, EbpfContext
};
use aya_log_ebpf::{debug, error, info};
use flower_common::{
    error_codes::{ERR_CODE_ARG_NOT_INITED, ERR_CODE_NOT_TARGET_PROCESS},
    futex_args::FutexArgs,
    Args, FutexEvent,
};
use futex::parse_futex;

#[map]
static ARG: maps::Array<Args> = maps::Array::<Args>::with_max_entries(1, 0);
#[map]
static CHANNEL: RingBuf = RingBuf::with_byte_size(0x1000, 0);

#[kprobe]
pub fn flower(ctx: ProbeContext) -> u32 {
    match try_flower(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_flower(ctx: ProbeContext) -> Result<u32, u32> {
    let Some(arg) = ARG.get(0) else {
        return Err(ERR_CODE_ARG_NOT_INITED);
    };
    if ctx.tgid() != arg.target_pid {
        return Err(ERR_CODE_NOT_TARGET_PROCESS);
    }

    let futex_args = FutexArgs {
        uaddr: ctx.arg(4).unwrap(),
        futex_op: ctx.arg(3).unwrap(),
        val: ctx.arg(0).unwrap(),
        timeout: ctx.arg(5).unwrap(),
        uaddr2: ctx.arg(2).unwrap(),
        val3: ctx.arg(1).unwrap(),
    };

    debug!(&ctx, "uaddr: 0x{}", futex_args.uaddr as usize);
    debug!(&ctx, "futex op: {}", futex_args.futex_op);
    debug!(&ctx, "val: {}", futex_args.val);
    debug!(&ctx, "timeout: {}", futex_args.timeout as usize);
    debug!(&ctx, "uaddr2: 0x{}", futex_args.uaddr2 as usize);
    debug!(&ctx, "val3: {}", futex_args.val3);

    // Do Null Check *Here* To Make eBPF verifier Happy 
    let Some(event) = parse_futex(&ctx, futex_args, ctx.pid() as i32) else {
        return Ok(0);
    };

    if let Some(mut entry) = CHANNEL.reserve::<FutexEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
