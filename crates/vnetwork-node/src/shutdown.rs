use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct ShutdownSignal {
    tx: watch::Sender<bool>,
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownSignal {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self { tx }
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }
}
