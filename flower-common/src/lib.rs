#![no_std]
pub mod error_codes;
pub mod futex_args;

#[cfg(feature = "user")]
use aya::Pod;
use futex_args::FutexArgs;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Args {
    pub target_pid: u32,
}

#[cfg(feature = "user")]
unsafe impl Pod for Args {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FutexEvent {
    pub tid: u32,
    pub args: FutexArgs,
    pub timestamp_ns: u64,
    pub ret: i64,
}
