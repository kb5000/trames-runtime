// SPDX-License-Identifier: GPL-3.0-or-later
//! Last-mm AIO teardown participates in existing memory close completions.
use super::*;
use trames_memory::{MemoryError, SyncCompletion, SyncResource};
#[cfg(test)]
#[path = "retire_tests.rs"]
mod tests;

pub(super) struct FinalClose {
    aio: Aio,
    waits: Mutex<Waits>,
}
#[derive(Default)]
struct Waits {
    failed: Option<MemoryError>,
    live: Vec<Weak<CloseWait>>,
}
impl FinalClose {
    pub(super) fn new(aio: Aio) -> Self {
        Self {
            aio,
            waits: Mutex::default(),
        }
    }
}
pub(super) struct CloseWait {
    state: Mutex<(usize, Option<Box<dyn SyncCompletion>>)>,
}
impl CloseWait {
    fn failed(&self, error: MemoryError) {
        let completion = self.state.lock().unwrap().1.take();
        if let Some(completion) = completion {
            completion.complete(Err(error));
        }
    }
    fn add(&self) {
        self.state.lock().unwrap().0 += 1;
    }
    pub(super) fn done(&self) {
        let completion = {
            let mut state = self.state.lock().unwrap();
            state.0 -= 1;
            if state.0 == 0 {
                state.1.take()
            } else {
                None
            }
        };
        if let Some(completion) = completion {
            completion.complete(Ok(()));
        }
    }
}
impl Context {
    pub(super) fn notify(&self) {
        let closing = {
            let mut state = self.state.lock().unwrap();
            if state.active.is_empty()
                && state.users == 0
                && state.destroyers == 0
                && !state.reaping
                && self
                    .mapping_close
                    .get()
                    .is_none_or(|close| close.finished())
            {
                std::mem::take(&mut state.closing)
            } else {
                Vec::new()
            }
        };
        self.readiness.notify_locked();
        for closing in closing {
            closing.done();
        }
    }
}
impl SyncResource for FinalClose {
    fn failed(&self, error: MemoryError) {
        let waits = {
            let mut state = self.waits.lock().unwrap();
            state.failed = Some(error.clone());
            std::mem::take(&mut state.live)
        };
        for wait in waits.into_iter().filter_map(|wait| wait.upgrade()) {
            wait.failed(error.clone());
        }
    }
    fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        None
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Err(MemoryError::BackingIo(95))
    }
    fn sync_async(
        &self,
        completion: Box<dyn SyncCompletion>,
    ) -> Result<(), Box<dyn SyncCompletion>> {
        let wait = Arc::new(CloseWait {
            state: Mutex::new((1, Some(completion))),
        });
        let error = {
            let mut waits = self.waits.lock().unwrap();
            if waits.failed.is_none() {
                waits.live.retain(|wait| wait.strong_count() != 0);
                waits.live.push(Arc::downgrade(&wait));
            }
            waits.failed.clone()
        };
        if let Some(error) = error {
            wait.failed(error);
            return Ok(());
        }
        let (contexts, registered) = {
            let mut contexts = self.aio.0.contexts.lock().unwrap();
            self.aio
                .0
                .closed
                .store(true, std::sync::atomic::Ordering::Relaxed);
            let mut retiring = self.aio.0.retiring.lock().unwrap();
            retiring.retain(|context| context.strong_count() != 0);
            retiring.extend(contexts.values().map(Arc::downgrade));
            let active = retiring
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            (active, std::mem::take(&mut *contexts))
        };
        drop(registered);
        for context in contexts {
            {
                let mut state = context.state.lock().unwrap();
                state.dead = true;
                if !state.active.is_empty()
                    || state.users != 0
                    || state.destroyers != 0
                    || state.reaping
                    || context
                        .mapping_close
                        .get()
                        .is_some_and(|close| !close.finished())
                {
                    wait.add();
                    state.closing.push(wait.clone());
                }
            }
            // Wake original pipe/layout/copy users to cancel their own calls.
            // An abandoned native request keeps its Context until FileResult
            // completion; notification below never waits on a CPU slot.
            context.notify();
        }
        wait.done();
        Ok(())
    }
}
