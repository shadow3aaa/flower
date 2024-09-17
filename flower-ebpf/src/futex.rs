#![allow(unused)]

use aya_ebpf::programs::ProbeContext;
use aya_log_ebpf::{debug, error};
use flower_common::{futex_args::FutexArgs, FutexEvent};

pub fn parse_futex(ctx: &ProbeContext, futex_args: FutexArgs, tid: i32) -> Option<FutexEvent> {
    let cmd = futex_args.futex_op & FUTEX_CMD_MASK;
    debug!(ctx, "cmd: {}", cmd);
    // todo: apply for FUTEX_WAKE_OP, FUTEX_REQUEUE, FUTEX_CMP_REQUEUE
    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => Some(FutexEvent::Wait(tid, futex_args.uaddr as usize)),
        FUTEX_WAKE | FUTEX_WAKE_BITSET => Some(FutexEvent::Wake(tid, futex_args.uaddr as usize)),
        _ => None
    }
}

// Futex Operation Codes
pub const FUTEX_WAIT: i32 = 0;
pub const FUTEX_WAKE: i32 = 1;
pub const FUTEX_FD: i32 = 2;
pub const FUTEX_REQUEUE: i32 = 3;
pub const FUTEX_CMP_REQUEUE: i32 = 4;
pub const FUTEX_WAKE_OP: i32 = 5;
pub const FUTEX_LOCK_PI: i32 = 6;
pub const FUTEX_UNLOCK_PI: i32 = 7;
pub const FUTEX_TRYLOCK_PI: i32 = 8;
pub const FUTEX_WAIT_BITSET: i32 = 9;
pub const FUTEX_WAKE_BITSET: i32 = 10;
pub const FUTEX_WAIT_REQUEUE_PI: i32 = 11;
pub const FUTEX_CMP_REQUEUE_PI: i32 = 12;
pub const FUTEX_LOCK_PI2: i32 = 13;

// Futex Flags
pub const FUTEX_PRIVATE_FLAG: i32 = 128;
pub const FUTEX_CLOCK_REALTIME: i32 = 256;

// Mask for command extraction
pub const FUTEX_CMD_MASK: i32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

// Futex Operation Codes with PRIVATE Flag
pub const FUTEX_WAIT_PRIVATE: i32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
pub const FUTEX_WAKE_PRIVATE: i32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
pub const FUTEX_REQUEUE_PRIVATE: i32 = FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG;
pub const FUTEX_CMP_REQUEUE_PRIVATE: i32 = FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG;
pub const FUTEX_WAKE_OP_PRIVATE: i32 = FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG;
pub const FUTEX_LOCK_PI_PRIVATE: i32 = FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG;
pub const FUTEX_LOCK_PI2_PRIVATE: i32 = FUTEX_LOCK_PI2 | FUTEX_PRIVATE_FLAG;
pub const FUTEX_UNLOCK_PI_PRIVATE: i32 = FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG;
pub const FUTEX_TRYLOCK_PI_PRIVATE: i32 = FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG;
pub const FUTEX_WAIT_BITSET_PRIVATE: i32 = FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG;
pub const FUTEX_WAKE_BITSET_PRIVATE: i32 = FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG;
pub const FUTEX_WAIT_REQUEUE_PI_PRIVATE: i32 = FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG;
pub const FUTEX_CMP_REQUEUE_PI_PRIVATE: i32 = FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG;
