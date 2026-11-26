// SPDX-License-Identifier: GPL-3.0-or-later
//! Original task IO ownership, captured before an asynchronous request moves.
use super::{Group, Permit};
use crate::SharedCell;
use std::{cell::RefCell, io, marker::PhantomData, rc::Rc, sync::Arc, time::Instant};

#[derive(Default)]
pub(crate) struct Target(SharedCell<Option<Arc<Group>>>);
#[derive(Clone)]
enum Binding {
    Live(Arc<Target>),
    Frozen(Option<Arc<Group>>),
}
impl Binding {
    fn group(&self) -> Option<Arc<Group>> {
        match self {
            Self::Live(target) => target.0.borrow().as_ref().and_then(Group::online),
            Self::Frozen(group) => group.as_ref().and_then(Group::online),
        }
    }
    fn limited(&self) -> bool {
        match self {
            Self::Live(target) => target
                .0
                .borrow()
                .as_ref()
                .is_some_and(|group| group.limited()),
            Self::Frozen(group) => group.as_ref().is_some_and(|group| group.limited()),
        }
    }
}
thread_local! { static CURRENT: RefCell<Option<Binding>> = const { RefCell::new(None) }; }

#[derive(Clone, Default)]
pub(crate) struct Context(Option<Arc<Group>>);
pub(crate) struct Scope {
    previous: Option<Binding>,
    _thread: PhantomData<Rc<()>>,
}
impl Scope {
    fn enter(binding: Binding) -> Self {
        Self {
            previous: CURRENT.with(|current| current.replace(Some(binding))),
            _thread: PhantomData,
        }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|current| current.replace(self.previous.take()));
    }
}
impl Target {
    pub fn set(&self, group: Arc<Group>) -> bool {
        let mut current = self.0.borrow_mut();
        if current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &group))
        {
            return false;
        }
        *current = Some(group);
        true
    }
    pub fn scope(self: &Arc<Self>) -> Scope {
        Scope::enter(Binding::Live(self.clone()))
    }
}
impl Context {
    pub fn capture() -> Self {
        Self(CURRENT.with(|current| current.borrow().as_ref().and_then(Binding::group)))
    }
    pub fn enter(&self) -> Scope {
        // Explicit absence is also an accepted context. A root/native job must
        // not inherit the unrelated guest which happened to run on this worker.
        Scope::enter(Binding::Frozen(self.0.clone()))
    }
}

/// Call immediately before a real private-disk request, after resolving its
/// original FD and range. Cache hits and non-disk providers never call here.
pub(crate) fn admit(bytes: u64, write: bool) -> io::Result<Option<Permit>> {
    if bytes == 0 {
        return Ok(None);
    }
    let group = CURRENT.with(|current| current.borrow().as_ref().and_then(Binding::group));
    group
        .map(|group| {
            group
                .admit(bytes, write, Instant::now())
                .map_err(|wait| trames_shared::ResourcePending::io_error(Arc::new(wait)))
        })
        .transpose()
}
pub(crate) fn limited() -> bool {
    CURRENT.with(|current| current.borrow().as_ref().is_some_and(Binding::limited))
}
pub(crate) fn complete(permit: Option<Permit>, result: io::Result<usize>) -> io::Result<usize> {
    if let Some(permit) = permit {
        // An issued backend error is an actual operation with no delivered
        // bytes. Dropping before the backend instead refunds the whole permit.
        permit.complete(result.as_ref().map_or(0, |bytes| *bytes as u64));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transferred(bytes: u64) {
        admit(bytes, false).unwrap().unwrap().complete(bytes);
    }
    #[test]
    fn accepted_io_keeps_its_group_across_worker_and_task_migration_then_normalizes_offline() {
        let native = Context::capture();
        let root = Group::new(None);
        let original = Group::new(Some(&root));
        let next = Group::new(Some(&root));
        let target = Arc::new(Target::default());
        target.set(original.clone());
        let _live = target.scope();
        let accepted = Context::capture();
        transferred(10);
        target.set(next.clone());
        {
            let _native = native.enter();
            assert!(
                admit(100, false).unwrap().is_none(),
                "an explicit native context does not inherit a guest worker"
            );
        }
        let worker_target = target.clone();
        let worker_context = accepted.clone();
        std::thread::spawn(move || {
            let _other_task = worker_target.scope();
            {
                let _original = worker_context.enter();
                transferred(20);
            }
            transferred(30);
        })
        .join()
        .unwrap();
        assert!(original.format_stat().contains("rbytes=30 "));
        assert!(next.format_stat().contains("rbytes=30 "));
        assert!(root.format_stat().contains("rbytes=60 "));
        let issued = {
            let _original = accepted.enter();
            admit(7, false).unwrap().unwrap()
        };
        original.retire_state();
        original.notify();
        assert_eq!(original.set_max("253:1 rbps=1"), Err(crate::Errno(19)));
        {
            let _retired = accepted.enter();
            transferred(40);
        }
        issued.complete(5);
        assert!(original.format_stat().contains("rbytes=35 "));
        assert!(root.format_stat().contains("rbytes=105 "));
        next.set_max("253:1 wbps=1").unwrap();
        assert!(limited());
        {
            let _native = native.enter();
            assert!(!limited());
        }
        assert!(limited());
    }
}
