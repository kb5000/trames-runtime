// SPDX-License-Identifier: GPL-3.0-or-later
//! Namespace-group protocol readiness, consumed by existing executors.
use crate::shared_state::State;
use crate::*;
use std::{ops::Deref, sync::Weak};
#[derive(Default)]
pub(crate) struct Group {
    state: State<Option<Fabric>>,
    pub changed: Arc<trames_shared::Readiness>,
}
impl Deref for Group {
    type Target = State<Option<Fabric>>;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        self.changed.notify_atomic();
    }
}
pub struct Driver {
    group: Weak<Group>,
    changed: Arc<trames_shared::Readiness>,
}
impl Driver {
    pub(crate) fn new(group: &Arc<Group>) -> Self {
        Self {
            group: Arc::downgrade(group),
            changed: group.changed.clone(),
        }
    }
    fn fabric(&self) -> Option<Fabric> {
        self.group.upgrade()?.borrow().clone()
    }
}
impl trames_shared::HostProtocol for Driver {
    fn identity(&self) -> usize {
        self.group.as_ptr() as usize
    }
    fn alive(&self) -> bool {
        self.group.strong_count() != 0
    }
    fn changed(&self) -> Arc<trames_shared::Readiness> {
        self.changed.clone()
    }
    fn progress(&self, _signal: &Arc<trames_shared::IoSignal>) -> std::io::Result<()> {
        if let Some(f) = self.fabric() {
            f.protocol_tick();
        }
        Ok(())
    }
    fn interests(&self) -> std::io::Result<trames_shared::ProtocolInterests> {
        let Some(fabric) = self.fabric() else {
            return Ok((vec![], None));
        };
        let mut sources = Vec::new();
        if let Some(link) = fabric.external_waiter() {
            let source = WaitSource::Link(link);
            sources.push((source.identity(), source.open()?));
        }
        for (socket, _) in fabric.native_waiters() {
            for source in socket.wait_interests() {
                sources.push((source.identity(), source.open()?));
            }
        }
        sources.sort_unstable_by_key(|s| s.0);
        sources.dedup_by_key(|s| s.0);
        Ok((
            sources,
            fabric
                .protocol_delay()
                .and_then(|d| std::time::Instant::now().checked_add(d)),
        ))
    }
}
