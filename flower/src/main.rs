use std::collections::HashMap;
use std::{env, ptr};

use aya::maps::{MapData, RingBuf};
use aya::programs::KProbe;
use aya::{include_bytes_aligned, maps, Ebpf};
use aya_log::EbpfLogger;
use flower_common::{Args, FutexEvent};
use log::{debug, error, info, warn};
use mio::Poll;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/flower"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/flower"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("flower").unwrap().try_into()?;
    program.load()?;

    program.attach("__arm64_sys_futex", 0)?;

    let mut map = maps::Array::<_, Args>::try_from(bpf.map_mut("ARG").unwrap())?;
    map.set(
        0,
        Args {
            target_pid: env::args().nth(1).unwrap().parse()?,
        },
        0,
    )?;

    let channel = RingBuf::try_from(bpf.take_map("CHANNEL").unwrap())?;
    receiver(channel).await;

    Ok(())
}

async fn receiver(mut channel: RingBuf<MapData>) {
    // let poll = Poll::new().unwrap();
    let mut wake_op_map = HashMap::new();
    loop {
        if let Some(event) = channel.next() {
            let event: FutexEvent = unsafe { trans(&event) };
            debug!("{event:?}");
            match event {
                FutexEvent::Wake(tid, addr) => {
                    wake_op_map.insert(addr, tid);
                }
                FutexEvent::Wait(tid, addr) => {
                    if let Some(waker_tid) = wake_op_map.get(&addr) {
                        info!("{tid} is waken by {waker_tid}");
                    } else {
                        debug!("Can't find waker for {tid}");
                    }
                }
            }
        }
    }
}

const unsafe fn trans<T>(buf: &[u8]) -> T {
    ptr::read_unaligned(buf.as_ptr().cast::<T>())
}
