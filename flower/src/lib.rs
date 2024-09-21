pub mod flow_web;

use std::fs;
use std::path::Path;
use std::time::Duration;
use std::{env, os::fd::AsRawFd, ptr};

use aya::maps::{MapData, RingBuf};
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, maps, Ebpf};
use flow_web::FlowWeb;
use flower_common::{Args, FutexEvent};
use log::error;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

pub struct Flower {
    channel: RingBuf<MapData>,
    poll: Poll,
    web: FlowWeb,
    bpf: Ebpf,
}

impl Flower {
    pub fn new(target_pid: u32) -> anyhow::Result<Self> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            error!("remove limit on locked memory failed, ret is: {}", ret);
        }

        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        #[cfg(debug_assertions)]
        let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/ebpf_target/bpfel-unknown-none/debug/flower"
        )))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/ebpf_target/bpfel-unknown-none/release/flower"
        )))?;

        let program_enter: &mut TracePoint =
            bpf.program_mut("flower_futex_enter").unwrap().try_into()?;
        program_enter.load()?;
        program_enter.attach("raw_syscalls", "sys_enter")?;
        let program_exit: &mut TracePoint =
            bpf.program_mut("flower_futex_exit").unwrap().try_into()?;
        program_exit.load()?;
        program_exit.attach("raw_syscalls", "sys_exit")?;

        let mut map = maps::Array::<_, Args>::try_from(bpf.map_mut("ARG").unwrap())?;
        map.set(0, Args { target_pid }, 0)?;

        let channel = RingBuf::try_from(bpf.take_map("CHANNEL").unwrap())?;
        let mut web = FlowWeb::new(target_pid);
        web.init_thread_data()?;

        Ok(Self {
            channel,
            poll: Poll::new().unwrap(),
            web,
            bpf,
        })
    }

    pub fn try_update(&mut self) {
        loop {
            if let Some(event) = self.channel.next() {
                let event: FutexEvent = unsafe { trans(&event) };
                self.web.process_event(event);
            } else {
                break;
            }
        }
    }

    pub fn update_timeout(&mut self, timeout: Option<Duration>) -> anyhow::Result<()> {
        let _ = self
            .poll
            .registry()
            .deregister(&mut SourceFd(&self.channel.as_raw_fd()));
        self.poll
            .registry()
            .register(
                &mut SourceFd(&self.channel.as_raw_fd()),
                Token(0),
                Interest::READABLE,
            )
            .unwrap();
        let mut events = Events::with_capacity(1);
        let _ = self.poll.poll(&mut events, timeout);

        loop {
            if let Some(event) = self.channel.next() {
                let event: FutexEvent = unsafe { trans(&event) };
                self.web.process_event(event);
            } else {
                break;
            }
        }

        Ok(())
    }

    pub fn analyze(&self) -> Option<Vec<flow_web::AnalyzeData>> {
        self.web.analyze()
    }

    pub fn clear(&mut self) {
        self.web.clear();
    }
}

pub fn list_threads(pid: u32) -> anyhow::Result<Vec<u32>> {
    let path = Path::new("/proc").join(pid.to_string()).join("task");
    let mut tids = Vec::new();
    for entry in fs::read_dir(path)? {
        if let Ok(entry) = entry {
            let tid: u32 = entry.file_name().to_str().unwrap().parse()?;
            tids.push(tid);
        }
    }

    Ok(tids)
}

const unsafe fn trans<T>(buf: &[u8]) -> T {
    ptr::read_unaligned(buf.as_ptr().cast::<T>())
}
