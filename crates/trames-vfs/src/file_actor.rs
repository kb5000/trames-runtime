// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold file faults use the task executing this worker assignment.
use crate::CredentialState;
use std::{cell::RefCell, marker::PhantomData, rc::Rc, sync::Arc};

thread_local! {
    static CURRENT: RefCell<Option<(Arc<CredentialState>, u32)>> = const { RefCell::new(None) };
}

/// Bind once at the existing worker boundary, without retaining a ProcessView
/// or copying credentials on ordinary guest accesses. Nested embeddings restore
/// their caller; the guard cannot migrate to a different host thread.
pub struct FileActorScope {
    previous: Option<(Arc<CredentialState>, u32)>,
    _thread: PhantomData<Rc<()>>,
}
impl FileActorScope {
    pub fn enter(credentials: Arc<CredentialState>, tid: u32) -> Self {
        let previous = CURRENT.with(|current| current.replace(Some((credentials, tid))));
        Self {
            previous,
            _thread: PhantomData,
        }
    }
}
impl Drop for FileActorScope {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            current.replace(self.previous.take());
        });
    }
}
pub(crate) fn current() -> Option<(Arc<CredentialState>, u32)> {
    CURRENT.with(|current| current.borrow().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scopes_restore_original_actor_and_observe_live_credentials() {
        assert!(current().is_none());
        let first = Arc::new(CredentialState::default());
        let second = Arc::new(CredentialState::default());
        let outer = FileActorScope::enter(first.clone(), 31);
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
    }
}
