// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed internal waits cross legacy errno helpers only within one request.
use crate::Errno;
use std::{cell::RefCell, marker::PhantomData, rc::Rc, sync::Arc};
use trames_memory::{MemoryError, PageWait};

/// The accepted caller's wait owns cold resource progress. The resource keeps
/// only a Weak lookup; cancellation drops unpublished bytes with the last wait.
pub(super) fn holding<T: Send + Sync + 'static>(
    wait: Arc<PageWait>,
    owner: Arc<T>,
) -> Arc<PageWait> {
    struct Held<T> {
        wait: Arc<PageWait>,
        _owner: Arc<T>,
    }
    impl<T: Send + Sync> trames_shared::ResourceWait for Held<T> {
        fn ready(&self) -> bool {
            self.wait.ready()
        }
        fn subscribe(
            &self,
            signal: &Arc<trames_shared::IoSignal>,
        ) -> Vec<trames_shared::IoSubscription> {
            self.wait.subscribe(signal)
        }
        fn deadline(&self) -> Option<std::time::Instant> {
            self.wait.deadline()
        }
    }
    PageWait::resource(Arc::new(Held {
        wait,
        _owner: owner,
    }))
}

pub(super) struct Pending {
    pub wait: Arc<PageWait>,
    pub progress: usize,
}
struct Frame {
    pending: Option<Pending>,
}
thread_local! { static CURRENT: RefCell<Option<Frame>> = const { RefCell::new(None) }; }
pub(super) struct Scope {
    previous: Option<Frame>,
    _thread: PhantomData<Rc<()>>,
}
impl Scope {
    pub fn enter() -> Self {
        Self {
            previous: CURRENT.with(|current| current.replace(Some(Frame { pending: None }))),
            _thread: PhantomData,
        }
    }
    pub fn finish(self) -> Option<Pending> {
        CURRENT
            .with(|current| current.borrow_mut().take())
            .and_then(|frame| frame.pending)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let retired = CURRENT.with(|current| current.replace(self.previous.take()));
        drop(retired);
    }
}
pub(super) fn waiting() -> bool {
    CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .is_some_and(|frame| frame.pending.is_some())
    })
}
fn remember(pending: Pending) -> Errno {
    let mut pending = Some(pending);
    CURRENT.with(|current| {
        if let Some(frame) = &mut *current.borrow_mut() {
            if frame.pending.is_none() {
                frame.pending = pending.take();
            }
        }
    });
    drop(pending);
    Errno(11)
}
pub(super) fn host_error(error: &std::io::Error) -> Option<Errno> {
    let pending = trames_shared::ResourcePending::detail(error)?;
    Some(remember(Pending {
        wait: PageWait::resource(pending.wait.clone()),
        progress: pending.progress,
    }))
}
pub(super) fn memory_error(error: MemoryError) -> Errno {
    match error {
        MemoryError::Pending(fault) => remember(Pending {
            wait: fault.wait,
            progress: 0,
        }),
        MemoryError::BackingIo(code) => Errno(code),
        _ => Errno(12),
    }
}
/// Publish a backend's committed prefix through the original metadata and
/// position code. The enclosing request still owns the typed continuation;
/// this count does not mean the accepted syscall has finished.
pub(super) fn write_result(result: std::io::Result<usize>) -> crate::Result<usize> {
    result.map_or_else(
        |error| {
            let progress = trames_shared::ResourcePending::detail(&error)
                .map_or(0, |pending| pending.progress);
            let error = crate::storage::host_errno(error);
            if progress != 0 {
                Ok(progress)
            } else {
                Err(error)
            }
        },
        Ok,
    )
}
pub(super) fn memory_result<T>(
    pending: Option<Pending>,
    result: crate::Result<T>,
) -> Result<T, MemoryError> {
    if let Some(pending) = pending {
        Err(pending.wait.fault(0))
    } else {
        result.map_err(|error| {
            if error.0 == 12 {
                MemoryError::Limit
            } else {
                MemoryError::BackingIo(error.0)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_requests_keep_their_original_waits_and_cancel_without_a_stale_slot() {
        let first = Arc::new(PageWait::default());
        let second = Arc::new(PageWait::default());
        let outer = Scope::enter();
        assert_eq!(memory_error(first.fault(7)), Errno(11));
        let inner = Scope::enter();
        assert_eq!(memory_error(second.fault(9)), Errno(11));
        assert!(Arc::ptr_eq(&inner.finish().unwrap().wait, &second));
        let pending = outer.finish().unwrap();
        assert!(Arc::ptr_eq(&pending.wait, &first));
        assert!(matches!(
            memory_result::<()>(Some(pending), Err(Errno(11))),
            Err(MemoryError::Pending(_))
        ));
        {
            let _cancelled = Scope::enter();
            memory_error(second.fault(11));
        }
        assert!(Scope::enter().finish().is_none());
    }
    #[test]
    fn io_progress_survives_the_errno_boundary_only_as_an_owned_typed_wait() {
        let wait = Arc::new(PageWait::default());
        let original = trames_shared::ResourcePending::io_error(wait.clone());
        let original = trames_shared::ResourcePending::add_progress(original, 19);
        let scope = Scope::enter();
        assert_eq!(crate::storage::host_errno(original), Errno(11));
        let pending = scope.finish().unwrap();
        assert_eq!(pending.progress, 19);
        assert!(!pending.wait.ready());
        wait.finish();
        assert!(pending.wait.ready());
        let scope = Scope::enter();
        let error = trames_shared::ResourcePending::add_progress(
            trames_shared::ResourcePending::io_error(wait.clone()),
            7,
        );
        assert_eq!(write_result(Err(error)), Ok(7));
        assert_eq!(scope.finish().unwrap().progress, 7);
        let scope = Scope::enter();
        assert_eq!(
            crate::storage::host_errno(std::io::Error::from_raw_os_error(11)),
            Errno(5)
        );
        assert!(
            scope.finish().is_none(),
            "an equal numeric errno is not a resource continuation"
        );
    }
}
