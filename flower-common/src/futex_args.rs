#[derive(Debug, Clone, Copy)]
pub struct FutexArgs {
    pub uaddr: usize,
    pub futex_op: i32,
    pub val: u32,
    pub uaddr2: usize,
    pub val3: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
