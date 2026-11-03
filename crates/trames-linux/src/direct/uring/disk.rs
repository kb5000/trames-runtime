// SPDX-License-Identifier: GPL-3.0-or-later
//! Durability jobs use the session's existing bounded disk workers. Completion
//! wakes the source task; it sends no coordinator request or completion RPC.
use super::*;
use std::sync::Mutex;
pub trait UringDiskExecutor: Send + Sync {
    fn submit(&self, job: trames_vfs::DiskSyncJob, result: Arc<UringDiskResult>);
}
#[derive(Default)]
pub struct UringDiskResult {
    result: Mutex<Option<Result<()>>>,
    readiness: Arc<trames_vfs::Readiness>,
    _file: Option<UringFile>,
}
impl UringDiskResult {
    pub(super) fn with_file(file: UringFile) -> Self {
        Self {
            _file: Some(file),
            ..Default::default()
        }
    }
    pub fn complete(&self, result: Result<()>) {
        *self.result.lock().unwrap() = Some(result);
        self.readiness.notify_locked();
    }
    pub(super) fn result(&self) -> Option<Result<()>> {
        *self.result.lock().unwrap()
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> trames_vfs::IoSubscription {
        self.readiness.subscribe(signal)
    }
}
