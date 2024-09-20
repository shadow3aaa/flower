use std::{cell::RefCell, collections::HashMap, rc::Rc};

use cpu_instructions_reader::{
    InstructionNumber, InstructionNumberInstant, InstructionNumberReader,
};
use flower_common::FutexEvent;
use libc::{FUTEX_CMD_MASK, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAKE, FUTEX_WAKE_BITSET};

type FlowWebNodeWarpper = Rc<RefCell<Box<FlowWebNode>>>;

#[derive(Debug)]
pub struct FlowWeb {
    childs: Vec<FlowWebNodeWarpper>,
    threads_pos: HashMap<u32, (FlowWebNodeWarpper, ThreadData)>,
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
    pub max_wake_count: i64,
    pub len: InstructionNumber,
    pub childs: Vec<FlowWebNodeWarpper>,
}

impl FlowWeb {
    pub fn new() -> Self {
        Self {
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
        let mut node = FlowWebNode {
            owner: event.tid,
            max_wake_count: event.ret,
            len: InstructionNumber::ZERO,
            childs: Vec::new(),
        };
        let num_cpus = num_cpus::get();

        if let Some((parent_node, thread_data)) = self.threads_pos.get_mut(&event.tid) {
            // update instants & create new node(add as parent node's child), move waker thread to new node
            let new_instants: Vec<_> = (0..num_cpus)
                .map(|cpu| thread_data.reader.instant_of_spec(cpu as i32).unwrap())
                .collect();
            node.len = new_instants
                .iter()
                .zip(thread_data.instants.iter())
                .map(|(new_instant, old_instant)| *new_instant - *old_instant)
                .sum();
            thread_data.instants = new_instants;

            let node = Rc::new(RefCell::new(Box::new(node)));

            self.addr_node.insert(event.args.uaddr, node.clone());
            parent_node.borrow_mut().childs.push(node);
        } else {
            // create new thread data & new node, move waker thread to new node
            let reader = InstructionNumberReader::new(Some(event.tid as i32)).unwrap();
            let thread_data = ThreadData {
                instants: (0..num_cpus)
                    .map(|cpu| reader.instant_of_spec(cpu as i32).unwrap())
                    .collect(),
                reader,
            };

            let node = Rc::new(RefCell::new(Box::new(node)));

            self.threads_pos
                .insert(event.tid, (node.clone(), thread_data));
            self.addr_node.insert(event.args.uaddr, node.clone());
            self.childs.push(node);
        }
    }

    fn process_wait_event(&mut self, event: FutexEvent) {
        if let Some(node) = self.addr_node.get(&event.args.uaddr) {
            if node.borrow().max_wake_count > 0 {
                let num_cpus = num_cpus::get();
                node.borrow_mut().max_wake_count -= 1;

                if let Some((_, mut thread_data)) = self.threads_pos.remove(&event.tid) {
                    // update instant & move thread to target node
                    thread_data.instants = (0..num_cpus)
                        .map(|cpu| thread_data.reader.instant_of_spec(cpu as i32).unwrap())
                        .collect();
                    self.threads_pos
                        .insert(event.tid, (node.clone(), thread_data));
                } else {
                    // create new thread data & move to target node
                    let reader = InstructionNumberReader::new(Some(event.tid as i32)).unwrap();
                    let thread_data = ThreadData {
                        instants: (0..num_cpus)
                            .map(|cpu| reader.instant_of_spec(cpu as i32).unwrap())
                            .collect(),
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

    pub fn analyze(&self) {
        let mut cache = Vec::new();
        self.analyze_inner(Vec::new(), None, &mut cache);
        if let Some(crital_path) = cache
            .into_iter()
            .max_by_key(|datas| datas.iter().map(|data| data.len).sum::<InstructionNumber>())
        {
            println!("{:?}", crital_path);
        }
    }

    fn analyze_inner(
        &self,
        mut history: Vec<AnalyzeData>,
        node: Option<FlowWebNodeWarpper>,
        cache: &mut Vec<Vec<AnalyzeData>>,
    ) {
        if let Some(node) = node {
            let data = AnalyzeData {
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

#[derive(Debug, Clone, Copy)]
pub struct AnalyzeData {
    pub tid: u32,
    pub len: InstructionNumber,
}
