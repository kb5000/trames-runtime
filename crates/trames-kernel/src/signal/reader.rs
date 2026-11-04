// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-reader signalfd authority; shared masks never capture their creator.
use super::*;
use std::sync::Arc;
pub struct TaskReader {
    pub task: Arc<IoTask>,
    pub namespace: trames_vfs::PidNamespace,
}
impl trames_vfs::SignalReader for TaskReader {
    fn task_signal(&self) -> Option<Arc<dyn trames_vfs::TaskSignal>> {
        Some(self.task.clone())
    }
    fn poll(&self, mask: u64) -> (u16, [u64; 2]) {
        (
            u16::from(self.task.pending_bits() & mask != 0),
            [self.task.inbox.epoch(), self.task.process().epoch()],
        )
    }
    fn take(&self, mask: u64) -> Option<[u8; 128]> {
        let (sig, mut info) = self.task.dequeue(mask & !UNBLOCKABLE)?;
        if info.fault.is_none() && info.poll.is_none() {
            info.sender = self.namespace.local(info.sender);
        }
        Some(write_signalfd(sig, info))
    }
    fn subscribe(&self, signal: &Arc<trames_vfs::IoSignal>) -> Vec<trames_vfs::IoSubscription> {
        self.task.subscribe(signal)
    }
}
impl Signals {
    pub fn reader(
        &self,
        namespace: &trames_vfs::PidNamespace,
    ) -> Arc<dyn trames_vfs::SignalReader> {
        self.reader
            .get_or_init(|| {
                Arc::new(TaskReader {
                    task: self.io.clone(),
                    namespace: namespace.clone(),
                })
            })
            .clone()
    }
}
