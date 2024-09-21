use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    time::{Duration, Instant},
};

use cpu_instructions_reader::{
    InstructionNumber, InstructionNumberInstant, InstructionNumberReader,
};
use flower_common::FutexEvent;
use libc::{FUTEX_CMD_MASK, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAKE, FUTEX_WAKE_BITSET};

use crate::list_threads;

type FlowWebNodeWarpper = Rc<RefCell<FlowWebNode>>;

#[derive(Debug)]
pub struct FlowWeb {
    pid: u32,
    time_instant: Instant,
    childs: Vec<FlowWebNodeWarpper>,
    threads_pos: HashMap<u32, FlowWebNodeWarpper>,
    threads_data: HashMap<u32, ThreadData>,
    addr_node: HashMap<usize, FlowWebNodeWarpper>,
}

#[derive(Debug)]
struct ThreadData {
    pub reader: InstructionNumberReader,
    pub instants: Vec<InstructionNumberInstant>,
}

#[derive(Debug)]
pub struct FlowWebNode {
    pub owner: u32,
    pub timestamp: Duration,
    pub max_wake_count: i64,
    pub len: InstructionNumber,
    pub childs: Vec<FlowWebNodeWarpper>,
}

impl FlowWeb {
    pub(super) fn new(pid: u32) -> Self {
        Self {
            pid,
            time_instant: Instant::now(),
            childs: Vec::new(),
            threads_pos: HashMap::new(),
            threads_data: HashMap::new(),
            addr_node: HashMap::new(),
        }
    }

    pub(super) fn init_thread_data(&mut self) -> anyhow::Result<()> {
        self.threads_data.clear();
        let tids = list_threads(self.pid)?;
        for tid in tids {
            self.threads_data.insert(tid, ThreadData::new(tid)?);
        }
        Ok(())
    }

    pub fn process_event(&mut self, event: FutexEvent) {
        let cmd = event.args.futex_op & FUTEX_CMD_MASK;
        match cmd {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                self.process_wait_event(event);
            }
            FUTEX_WAKE | FUTEX_WAKE_BITSET => {
                self.process_wake_event(event);
            }
            _ => (),
        }
    }

    fn process_wake_event(&mut self, event: FutexEvent) {
        let mut node = FlowWebNode {
            owner: event.tid,
            timestamp: Instant::now() - self.time_instant,
            max_wake_count: event.ret,
            len: InstructionNumber::ZERO,
            childs: Vec::new(),
        };
        let num_cpus = num_cpus::get();

        // find target thread data, or add a new one
        let thread_data = if let Some(data) = self.threads_data.get_mut(&event.tid) {
            data
        } else {
            let data = ThreadData::new(event.tid).unwrap();
            self.threads_data.insert(event.tid, data);
            self.threads_data.get_mut(&event.tid).unwrap()
        };

        if let Some(parent_node) = self.threads_pos.get_mut(&event.tid) {
            // update instants & create new node(add as parent node's child), move waker thread to new node
            let new_instants: Vec<_> = (0..num_cpus)
                .map(|cpu| thread_data.reader.instant(cpu as i32).unwrap())
                .collect();
            node.len = new_instants
                .iter()
                .zip(thread_data.instants.iter())
                .map(|(new_instant, old_instant)| *new_instant - *old_instant)
                .sum();
            thread_data.instants = new_instants;

            let node = Rc::new(RefCell::new(node));

            self.addr_node.insert(event.args.uaddr, node.clone());
            parent_node.borrow_mut().childs.push(node);
        } else {
            // create new node, move waker thread to new node
            let node = Rc::new(RefCell::new(node));

            self.threads_pos
                .insert(event.tid, node.clone());
            self.addr_node.insert(event.args.uaddr, node.clone());
            self.childs.push(node);
        }
    }

    fn process_wait_event(&mut self, event: FutexEvent) {
        if let Some(node) = self.addr_node.get(&event.args.uaddr) {
            if node.borrow().max_wake_count > 0 {
                let num_cpus = num_cpus::get();
                node.borrow_mut().max_wake_count -= 1;

                if let Some(mut thread_data) = self.threads_data.remove(&event.tid) {
                    // update instant & move thread to target node
                    thread_data.instants = (0..num_cpus)
                        .map(|cpu| thread_data.reader.instant(cpu as i32).unwrap())
                        .collect();
                    self.threads_pos
                        .insert(event.tid, node.clone());
                } else {
                    // create new thread data & move to target node
                    let thread_data = ThreadData::new(event.tid).unwrap();
                    self.threads_pos
                        .insert(event.tid, node.clone());
                    self.threads_data.insert(event.tid, thread_data);
                }
            }
        }
    }

    pub fn clear(&mut self) {
        self.time_instant = Instant::now();
        self.addr_node.clear();
        self.childs.clear();
        self.threads_pos.clear();
        let _ = self.init_thread_data();
    }

    pub fn analyze(&self) -> Option<Vec<AnalyzeData>> {
        let mut cache = Vec::new();
        self.analyze_inner(Vec::new(), None, &mut cache);
        cache
            .into_iter()
            .max_by_key(|datas| datas.iter().map(|data| data.len).sum::<InstructionNumber>())
    }

    fn analyze_inner(
        &self,
        mut history: Vec<AnalyzeData>,
        node: Option<FlowWebNodeWarpper>,
        cache: &mut Vec<Vec<AnalyzeData>>,
    ) {
        if let Some(node) = node {
            let data = AnalyzeData {
                timestamp: node.borrow().timestamp,
                tid: node.borrow().owner,
                len: node.borrow().len,
            };
            history.push(data);

            if node.borrow().childs.is_empty() {
                cache.push(history);
            } else {
                for child in &node.borrow().childs {
                    self.analyze_inner(history.clone(), Some(child.clone()), cache);
                }
            }
        } else {
            for child in &self.childs {
                self.analyze_inner(history.clone(), Some(child.clone()), cache);
            }
        }
    }
}

impl ThreadData {
    pub(self) fn new(tid: u32) -> anyhow::Result<Self> {
        let num_cpus = num_cpus::get();
        let reader = InstructionNumberReader::new(Some(tid as i32))?;
        Ok(ThreadData {
            instants: (0..num_cpus)
                .map(|cpu| reader.instant(cpu as i32).unwrap())
                .collect(),
            reader,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AnalyzeData {
    pub timestamp: Duration,
    pub tid: u32,
    pub len: InstructionNumber,
}
