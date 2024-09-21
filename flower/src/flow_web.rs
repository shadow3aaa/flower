use std::{cell::RefCell, collections::HashMap, rc::Rc};

use flower_common::FutexEvent;
use libc::{FUTEX_CMD_MASK, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAKE, FUTEX_WAKE_BITSET};

type FlowWebNodeWarpper = Rc<RefCell<FlowWebNode>>;

#[derive(Debug)]
pub struct FlowWeb {
    pid: u32,
    childs: Vec<FlowWebNodeWarpper>,
    threads_pos: HashMap<u32, FlowWebNodeWarpper>,
    addr_node: HashMap<usize, FlowWebNodeWarpper>,
}

#[derive(Debug)]
pub struct FlowWebNode {
    pub parent: Option<FlowWebNodeWarpper>,
    pub owner: u32,
    pub timestamp: u64,
    pub max_wake_count: i64,
    pub childs: Vec<FlowWebNodeWarpper>,
}

#[derive(Debug, Clone, Copy)]
pub struct AnalyzeData {
    pub tid: u32,
    pub timestamp_ns: u64,
}

impl FlowWeb {
    pub(super) fn new(pid: u32) -> Self {
        Self {
            pid,
            childs: Vec::new(),
            threads_pos: HashMap::new(),
            addr_node: HashMap::new(),
        }
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
        let node = FlowWebNode {
            parent: None,
            owner: event.tid,
            timestamp: event.timestamp_ns,
            max_wake_count: event.ret,
            childs: Vec::new(),
        };
        let node = Rc::new(RefCell::new(node));

        if let Some(parent_node) = self.threads_pos.get_mut(&event.tid) {
            // add new node as parent node's child
            node.borrow_mut().parent = Some(parent_node.clone());
            parent_node.borrow_mut().childs.push(node.clone());
        } else {
            // add new node as root's child
            self.childs.push(node.clone());
        }

        self.addr_node.insert(event.args.uaddr, node.clone());
        self.threads_pos.insert(event.tid, node);
    }

    fn process_wait_event(&mut self, event: FutexEvent) {
        if let Some(node) = self.addr_node.get(&event.args.uaddr) {
            if node.borrow().max_wake_count > 0 {
                node.borrow_mut().max_wake_count -= 1;
                self.threads_pos.insert(event.tid, node.clone());
            }
        }
    }

    pub fn clear(&mut self) {
        self.addr_node.clear();
        self.childs.clear();
        self.threads_pos.clear();
    }

    pub fn analyze(&self) -> Option<Vec<AnalyzeData>> {
        let mut cache = Vec::new();
        self.analyze_inner(Vec::new(), None, &mut cache);
        cache.into_iter().max_by_key(|datas| {
            datas
                .windows(2)
                .map(|arr| arr[1].timestamp_ns.saturating_sub(arr[0].timestamp_ns))
                .sum::<u64>()
        })
    }

    fn analyze_inner(
        &self,
        mut datas: Vec<AnalyzeData>,
        node: Option<FlowWebNodeWarpper>,
        cache: &mut Vec<Vec<AnalyzeData>>,
    ) {
        if let Some(node) = node {
            let data = AnalyzeData {
                timestamp_ns: node.borrow().timestamp,
                tid: node.borrow().owner,
            };
            datas.push(data);

            if node.borrow().childs.is_empty() {
                cache.push(datas);
            } else {
                for child in &node.borrow().childs {
                    self.analyze_inner(datas.clone(), Some(child.clone()), cache);
                }
            }
        } else {
            for child in &self.childs {
                self.analyze_inner(datas.clone(), Some(child.clone()), cache);
            }
        }
    }
}
