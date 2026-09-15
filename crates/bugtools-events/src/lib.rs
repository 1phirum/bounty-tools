use bugtools_core::events::BugToolsEvent;
use tokio::sync::broadcast;

pub mod grpc;

#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<BugToolsEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: BugToolsEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BugToolsEvent> {
        self.sender.subscribe()
    }
}
