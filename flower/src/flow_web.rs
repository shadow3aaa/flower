use std::{
    cell::RefCell,
    collections::HashMap,
    rc::{Rc, Weak},
    time::Duration,
};

use flower_common::FutexEvent;
use libc::{FUTEX_CMD_MASK, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAKE, FUTEX_WAKE_BITSET};

type FlowWebNodeWarpper = Rc<RefCell<FlowWebNode>>;
type FlowWebNodeWeakWarpper = Weak<RefCell<FlowWebNode>>;

#[derive(Debug)]
pub struct FlowWeb {
    len: u64,
    last_update_timestamp: Option<u64>,
    pid: u32,
    childs: Vec<FlowWebNodeWarpper>,
    threads_pos: HashMap<u32, FlowWebNodeWeakWarpper>,
    addr_node: HashMap<usize, FlowWebNodeWeakWarpper>,
}

#[derive(Debug)]
pub struct FlowWebNode {
    pub last_update_timestamp: u64,
    pub parent: Option<FlowWebNodeWeakWarpper>,
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
    pub(super) fn new(pid: u32, len: Duration) -> Self {
        Self {
            len: len.as_nanos() as u64,
            last_update_timestamp: None,
            pid,
            childs: Vec::new(),
            threads_pos: HashMap::new(),
            addr_node: HashMap::new(),
        }
    }

    fn retain_timeout_nodes(&mut self) {
        if self.last_update_timestamp.is_none() {
            return;
        }

        let mut childs = Vec::new();
        self.search_new_childs(&mut childs, None);
        self.childs = childs;
    }

    fn search_new_childs(
        &self,
        childs: &mut Vec<FlowWebNodeWarpper>,
        node: Option<FlowWebNodeWarpper>,
    ) {
        if let Some(node) = node {
            if self.last_update_timestamp.unwrap() - node.borrow().last_update_timestamp <= self.len
            {
                childs.push(node);
            } else {
                for child in &node.borrow().childs {
                    self.search_new_childs(childs, Some(child.clone()));
                }
            }
        } else {
            for child in &self.childs {
                self.search_new_childs(childs, Some(child.clone()));
            }
        }
    }

    pub fn process_event(&mut self, event: FutexEvent) {
        let cmd = event.args.futex_op & FUTEX_CMD_MASK;
        match cmd {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                self.last_update_timestamp = Some(event.timestamp_ns);
                self.process_wait_event(event);
                self.retain_timeout_nodes();
            }
            FUTEX_WAKE | FUTEX_WAKE_BITSET => {
                self.last_update_timestamp = Some(event.timestamp_ns);
                self.process_wake_event(event);
                self.retain_timeout_nodes();
            }
            _ => (),
        }
    }

    fn process_wake_event(&mut self, event: FutexEvent) {
        let node = FlowWebNode {
            last_update_timestamp: event.timestamp_ns,
            parent: None,
            owner: event.tid,
            timestamp: event.timestamp_ns,
            max_wake_count: event.ret,
            childs: Vec::new(),
        };
        let node = Rc::new(RefCell::new(node));

        if let Some(parent_node) = self
            .threads_pos
            .get_mut(&event.tid)
            .and_then(|node| node.upgrade())
        {
            // add new node as parent node's child
            parent_node.borrow_mut().childs.push(node.clone());
            node.borrow_mut().parent = Some(Rc::downgrade(&parent_node));
        } else {
            // add new node as root's child
            self.childs.push(node.clone());
        }

        self.addr_node
            .insert(event.args.uaddr, Rc::downgrade(&node));
        self.threads_pos.insert(event.tid, Rc::downgrade(&node));
    }

    fn process_wait_event(&mut self, event: FutexEvent) {
        if let Some(node) = self
            .addr_node
            .get(&event.args.uaddr)
            .and_then(|node| node.upgrade())
        {
            if node.borrow().max_wake_count > 0 {
                node.borrow_mut().max_wake_count -= 1;
                node.borrow_mut().last_update_timestamp = event.timestamp_ns;
                self.threads_pos.insert(event.tid, Rc::downgrade(&node));
            }
        } else {
            self.addr_node.remove(&event.args.uaddr);
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
