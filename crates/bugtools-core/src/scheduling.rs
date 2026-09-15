use std::cmp::Ordering;
use std::collections::BinaryHeap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestFamily {
    BooleanDifferential,
    SyntaxPerturbation,
    ErrorBehavior,
    TimingDifferential,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestJob {
    pub endpoint_id: String,
    pub parameter_id: String,
    pub family: TestFamily,
    pub priority: u32,
    pub estimated_cost: u32,
}

impl PartialEq for TestJob {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
            && self.endpoint_id == other.endpoint_id
            && self.parameter_id == other.parameter_id
    }
}

impl Eq for TestJob {}

impl PartialOrd for TestJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TestJob {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority value means it gets popped first
        self.priority.cmp(&other.priority)
    }
}

pub struct PriorityScheduler {
    queue: BinaryHeap<TestJob>,
}

impl Default for PriorityScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl PriorityScheduler {
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
        }
    }

    pub fn push(&mut self, job: TestJob) {
        self.queue.push(job);
    }

    pub fn pop(&mut self) -> Option<TestJob> {
        self.queue.pop()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}
