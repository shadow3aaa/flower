#![no_std]
#![no_main]
use aya_ebpf::{
    macros::{map, tracepoint}, maps::{self, HashMap, RingBuf}, programs::TracePointContext, EbpfContext
};
use aya_log_ebpf::debug;
use flower_common::{
    error_codes::{ERR_CODE_ARG_NOT_INITED, ERR_CODE_NOT_TARGET_PROCESS},
    futex_args::FutexArgs,
    Args, FutexEvent,
};

#[map]
static ARG: maps::Array<Args> = maps::Array::<Args>::with_max_entries(1, 0);
#[map]
static CHANNEL: RingBuf = RingBuf::with_byte_size(0x1000, 0);
#[map]
static mut CONTEXT: HashMap<u32, FutexArgs> = HashMap::with_max_entries(64, 0);

const FUTEX_ID_AARCH64: u64 = 98;
const FUTEX_ID_X86_64: u64 = 240;

#[tracepoint]
pub fn flower_futex_enter(ctx: TracePointContext) {
    let _ = try_flower_enter(ctx);
}

fn try_flower_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let Some(arg) = ARG.get(0) else {
        return Err(ERR_CODE_ARG_NOT_INITED);
    };

    if ctx.tgid() != arg.target_pid {
        return Err(ERR_CODE_NOT_TARGET_PROCESS);
    }

    let syscall_id = unsafe { ctx.read_at::<u64>(8).unwrap() };
    // todo: apply for x86_64
    if syscall_id != FUTEX_ID_AARCH64 {
        return Ok(0);
    }

    let args: [usize; 6] = unsafe { ctx.read_at(16) }.unwrap();

    let futex_args = FutexArgs {
        uaddr: args[0],
        futex_op: args[1] as i32,
        val: args[2] as u32,
        uaddr2: args[4],
        val3: args[5] as u32,
    };

    unsafe {
        let _ = CONTEXT.insert(&ctx.pid(), &futex_args, 0);
    }

    Ok(0)
}

#[tracepoint]
pub fn flower_futex_exit(ctx: TracePointContext) {
    let _ = try_flower_exit(ctx);
}

fn try_flower_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let Some(arg) = ARG.get(0) else {
        return Err(ERR_CODE_ARG_NOT_INITED);
    };

    if ctx.tgid() != arg.target_pid {
        return Err(ERR_CODE_NOT_TARGET_PROCESS);
    }

    let syscall_id = unsafe { ctx.read_at::<u64>(8).unwrap() };
    // todo: apply for x86_64
    if syscall_id != FUTEX_ID_AARCH64 {
        return Ok(0);
    }

    let Some(futex_args) = (unsafe {
        CONTEXT.get(&ctx.pid()).copied()
    }) else {
        return Ok(0);
    };

    let ret = unsafe { ctx.read_at::<i64>(16)? };

    if ret < 0 {
        return Ok(0);
    }

    let event = FutexEvent {
        tid: ctx.pid(),
        args: futex_args,
        ret,
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
