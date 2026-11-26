// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold file faults use the task executing this worker assignment.
use crate::CredentialState;
use std::{cell::RefCell, marker::PhantomData, rc::Rc, sync::Arc};

thread_local! {
    static CURRENT: RefCell<Option<(Arc<CredentialState>, u32)>> = const { RefCell::new(None) };
    static SYNC: RefCell<Option<Arc<dyn trames_memory::SyncExecutor>>> = const { RefCell::new(None) };
}

/// Bind once at the existing worker boundary, without retaining a ProcessView
/// or copying credentials on ordinary guest accesses. Nested embeddings restore
/// their caller; the guard cannot migrate to a different host thread.
pub struct FileActorScope {
    previous: Option<(Arc<CredentialState>, u32)>,
    previous_sync: Option<Arc<dyn trames_memory::SyncExecutor>>,
    _memory: Option<trames_memory::CgroupMemoryScope>,
    _io: Option<crate::cgroup::IoScope>,
    _thread: PhantomData<Rc<()>>,
}
#[derive(Clone)]
pub struct FileActorSnapshot {
    credentials: Arc<CredentialState>,
    tid: u32,
    executor: Option<Arc<dyn trames_memory::SyncExecutor>>,
    memory: trames_memory::CgroupMemoryContext,
    io: crate::cgroup::IoContext,
}
impl FileActorSnapshot {
    pub fn enter(&self) -> FileActorScope {
        let mut scope = FileActorScope::enter_with_sync(
            self.credentials.clone(),
            self.tid,
            self.executor.clone(),
        );
        scope._memory = Some(self.memory.enter());
        scope._io = Some(self.io.enter());
        scope
    }
}
impl FileActorScope {
    /// A lifecycle/host acceptance already owns the actual task's credentials
    /// and has explicitly bound its resource context, without a CPU actor TLS.
    pub fn frozen_for(credentials: &crate::Credentials, tid: u32) -> FileActorSnapshot {
        FileActorSnapshot {
            credentials: Arc::new(CredentialState::new(credentials.clone())),
            tid,
            executor: sync_executor(),
            memory: trames_memory::CgroupMemoryContext::capture(),
            io: crate::cgroup::IoContext::capture(),
        }
    }
    /// AIO fsync uses prepare_creds semantics, rather than a later live task
    /// credential update. Capture only at this asynchronous acceptance point.
    pub fn frozen() -> Option<FileActorSnapshot> {
        let (credentials, tid) = current()?;
        let credentials = Arc::new(CredentialState::new(credentials.read().clone()));
        Some(FileActorSnapshot {
            credentials,
            tid,
            executor: sync_executor(),
            memory: trames_memory::CgroupMemoryContext::capture(),
            io: crate::cgroup::IoContext::capture(),
        })
    }
    pub fn enter_if_absent(
        credentials: impl FnOnce() -> crate::Credentials,
        tid: u32,
        executor: Option<Arc<dyn trames_memory::SyncExecutor>>,
    ) -> Option<Self> {
        if CURRENT.with(|current| current.borrow().is_some()) {
            return None;
        }
        Some(Self::enter_with_sync(
            Arc::new(CredentialState::new(credentials())),
            tid,
            executor,
        ))
    }
    pub fn enter(credentials: Arc<CredentialState>, tid: u32) -> Self {
        Self::enter_with_sync(credentials, tid, None)
    }
    pub fn enter_with_sync(
        credentials: Arc<CredentialState>,
        tid: u32,
        executor: Option<Arc<dyn trames_memory::SyncExecutor>>,
    ) -> Self {
        let previous = CURRENT.with(|current| current.replace(Some((credentials, tid))));
        Self {
            previous,
            previous_sync: SYNC.with(|current| current.replace(executor)),
            _memory: None,
            _io: None,
            _thread: PhantomData,
        }
    }
}
impl Drop for FileActorScope {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            current.replace(self.previous.take());
        });
        SYNC.with(|current| {
            current.replace(self.previous_sync.take());
        });
    }
}
pub(crate) fn current() -> Option<(Arc<CredentialState>, u32)> {
    CURRENT.with(|current| current.borrow().clone())
}
pub(crate) fn sync_executor() -> Option<Arc<dyn trames_memory::SyncExecutor>> {
    SYNC.with(|current| current.borrow().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_async_actor_keeps_original_credentials_and_restores_the_executing_thread() {
        let state = Arc::new(CredentialState::new(crate::Credentials::user(1000, 1001)));
        let scope = FileActorScope::enter(state.clone(), 71);
        let frozen = FileActorScope::frozen().unwrap();
        state.publish(&crate::Credentials::user(2000, 2001));
        drop(scope);
        let other = Arc::new(CredentialState::new(crate::Credentials::user(3000, 3001)));
        let _other = FileActorScope::enter(other, 99);
        {
            let _frozen = frozen.enter();
            let (credentials, tid) = current().unwrap();
            assert_eq!(tid, 71);
            assert_eq!(credentials.read().uid, 1000);
        }
        let (credentials, tid) = current().unwrap();
        assert_eq!(tid, 99);
        assert_eq!(credentials.read().uid, 3000);
    }
    #[test]
    fn scopes_restore_original_actor_and_observe_live_credentials() {
        assert!(current().is_none());
        let first = Arc::new(CredentialState::default());
        let second = Arc::new(CredentialState::default());
        let outer = FileActorScope::enter(first.clone(), 31);
        assert!(FileActorScope::enter_if_absent(
            || panic!("existing actor supplies the original live credentials"),
            99,
            None
        )
        .is_none());
        {
            let _inner = FileActorScope::enter(second.clone(), 47);
            let (state, tid) = current().unwrap();
            assert!(Arc::ptr_eq(&state, &second));
            assert_eq!(tid, 47);
        }
        let (state, tid) = current().unwrap();
        assert!(Arc::ptr_eq(&state, &first));
        assert_eq!(tid, 31);
        let mut credentials = state.read().clone();
        credentials.fsuid = 1234;
        first.publish(&credentials);
        assert_eq!(current().unwrap().0.read().fsuid, 1234);
        drop(outer);
        assert!(current().is_none());
        let fallback =
            FileActorScope::enter_if_absent(crate::Credentials::default, 47, None).unwrap();
        assert_eq!(current().unwrap().1, 47);
        drop(fallback);
        assert!(current().is_none());
    }
}
