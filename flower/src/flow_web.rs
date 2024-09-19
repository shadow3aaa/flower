use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
};

use cpu_instructions_reader::{
    InstructionNumber, InstructionNumberInstant, InstructionNumberReader,
};
use flower_common::FutexEvent;
use libc::{FUTEX_CMD_MASK, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAKE, FUTEX_WAKE_BITSET};
use smallvec::SmallVec;

type FlowWebNodeWarpper = Rc<RefCell<Box<FlowWebNode>>>;

#[derive(Debug)]
pub struct FlowWeb {
    childs: SmallVec<[FlowWebNodeWarpper; 10]>,
    threads_pos: HashMap<u32, (FlowWebNodeWarpper, ThreadData)>,
    addr_node: HashMap<usize, FlowWebNodeWarpper>,
}

#[derive(Debug)]
struct ThreadData {
    pub reader: InstructionNumberReader,
    pub instant: InstructionNumberInstant,
}

#[derive(Debug)]
struct FlowWebNode {
    pub max_wake_count: i64,
    pub len: InstructionNumber,
    pub childs: SmallVec<[FlowWebNodeWarpper; 10]>,
}

impl FlowWeb {
    pub fn new() -> Self {
        Self {
            childs: SmallVec::new(),
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
        let mut node = FlowWebNode {
            max_wake_count: event.ret,
            len: InstructionNumber::ZERO,
            childs: SmallVec::new(),
        };
        if let Some((parent_node, thread_data)) = self.threads_pos.get(&event.tid) {
            node.len = thread_data.reader.instant_of_all().unwrap() - thread_data.instant;
            let node = Rc::new(RefCell::new(Box::new(node)));
            self.addr_node.insert(event.args.uaddr, node.clone());
            parent_node.borrow_mut().childs.push(node);
        } else {
            let node = Rc::new(RefCell::new(Box::new(node)));
            self.addr_node.insert(event.args.uaddr, node.clone());
            self.childs.push(node);
        }
    }

    fn process_wait_event(&mut self, event: FutexEvent) {
        if let Some(node) = self.addr_node.get(&event.args.uaddr) {
            if node.borrow().max_wake_count > 0 {
                node.borrow_mut().max_wake_count -= 1;
                if let Some((_, mut thread_data)) = self.threads_pos.remove(&event.tid) {
                    // update instant & move thread to new node
                    thread_data.instant = thread_data.reader.instant_of_all().unwrap();
                    self.threads_pos
                        .insert(event.tid, (node.clone(), thread_data));
                } else {
                    let reader = InstructionNumberReader::new(Some(event.tid as i32)).unwrap();
                    let thread_data = ThreadData {
                        instant: reader.instant_of_all().unwrap(),
                        reader,
                    };
                    self.threads_pos
                        .insert(event.tid, (node.clone(), thread_data));
                }
            }
        }
    }

    pub fn clear(&mut self) {
        self.childs.clear();
        self.threads_pos.clear();
    }
}
