// SPDX-License-Identifier: GPL-3.0-or-later
//! Extend one file's existing data transaction across resource suspension.
use crate::{IoSignal, IoSubscription, Readiness, ResourcePending, ResourceWait};
use std::{
    cell::RefCell,
    io,
    marker::PhantomData,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
};

#[derive(Default)]
pub struct FileTransaction {
    owner: AtomicU64,
    next: AtomicU64,
    changed: Arc<Readiness>,
}
#[derive(Clone)]
enum Binding {
    Owner(Arc<FileTransaction>, u64),
    Writeback,
}
thread_local! { static CURRENT: RefCell<Option<Binding>> = const { RefCell::new(None) }; }
pub struct FileTransactionLease {
    resource: Arc<FileTransaction>,
    owner: u64,
}
pub struct FileTransactionScope {
    previous: Option<Binding>,
    _thread: PhantomData<Rc<()>>,
}
struct Wait(Arc<FileTransaction>);
impl FileTransaction {
    fn admitted(&self, owner: u64) -> bool {
        owner == 0
            || CURRENT.with(|current| match current.borrow().as_ref() {
                Some(Binding::Owner(resource, admitted)) => {
                    std::ptr::eq(Arc::as_ptr(resource), self) && *admitted == owner
                }
                Some(Binding::Writeback) => true,
                None => false,
            })
    }
    /// The caller holds the original data mutation lock. Ordinary operations
    /// check admission inside that same lock, so an older queued writer cannot
    /// pass a suspended transaction after observing an unlocked scalar earlier.
    pub fn try_acquire(
        self: &Arc<Self>,
    ) -> Result<Option<FileTransactionLease>, Arc<dyn ResourceWait>> {
        let current = self.owner.load(Relaxed);
        if current != 0 && self.admitted(current) {
            return Ok(None);
        }
        if CURRENT.with(|current| matches!(current.borrow().as_ref(), Some(Binding::Writeback))) {
            return Ok(None);
        }
        let mut owner = self.next.fetch_add(1, Relaxed).wrapping_add(1);
        if owner == 0 {
            owner = self.next.fetch_add(1, Relaxed).wrapping_add(1);
        }
        if self
            .owner
            .compare_exchange(0, owner, Relaxed, Relaxed)
            .is_err()
        {
            return Err(Arc::new(Wait(self.clone())));
        }
        Ok(Some(FileTransactionLease {
            resource: self.clone(),
            owner,
        }))
    }
    pub fn check(self: &Arc<Self>) -> io::Result<()> {
        if self.admitted(self.owner.load(Relaxed)) {
            Ok(())
        } else {
            Err(ResourcePending::io_error(Arc::new(Wait(self.clone()))))
        }
    }
    pub fn available(&self) -> bool {
        self.admitted(self.owner.load(Relaxed))
    }
}
impl FileTransactionLease {
    pub fn enter(&self) -> FileTransactionScope {
        FileTransactionScope::enter(Binding::Owner(self.resource.clone(), self.owner))
    }
}
impl Drop for FileTransactionLease {
    fn drop(&mut self) {
        self.resource.owner.store(0, Relaxed);
        self.resource.changed.notify_atomic();
    }
}
impl FileTransactionScope {
    fn enter(binding: Binding) -> Self {
        Self {
            previous: CURRENT.with(|current| current.replace(Some(binding))),
            _thread: PhantomData,
        }
    }
    /// Original kernel writeback may make progress while a foreground writer
    /// is waiting for reclaim. This scope must never run guest callbacks.
    pub fn writeback() -> Self {
        Self::enter(Binding::Writeback)
    }
}
impl Drop for FileTransactionScope {
    fn drop(&mut self) {
        CURRENT.with(|current| current.replace(self.previous.take()));
    }
}
impl ResourceWait for Wait {
    fn ready(&self) -> bool {
        self.0.owner.load(Relaxed) == 0
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        vec![self.0.changed.subscribe(signal)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_aliases_keep_transaction_ownership_across_threads_and_writeback_can_progress() {
        let file = crate::SharedFile::anonymous().unwrap();
        file.write_at(0, b"base").unwrap();
        let lease = file.begin_transaction().unwrap().unwrap();
        let error = file.write_at(0, b"late").unwrap_err();
        let wait = ResourcePending::from_io(&error).unwrap();
        assert!(!wait.ready());
        assert_eq!(file.read_at(0, 4).unwrap(), b"base");
        assert!(ResourcePending::from_io(&file.set_len(0).unwrap_err()).is_some());
        {
            let _scope = lease.enter();
            assert!(file.begin_transaction().unwrap().is_none());
            file.write_at(0, b"part").unwrap();
        }
        let alias = file.clone();
        std::thread::spawn(move || {
            let pending = alias.write_at(0, b"late").unwrap_err();
            assert_eq!(ResourcePending::detail(&pending).unwrap().progress, 0);
            assert!(ResourcePending::from_io(&pending).is_some());
        })
        .join()
        .unwrap();
        let unrelated = crate::SharedFile::anonymous().unwrap();
        unrelated.write_at(0, b"independent").unwrap();
        // Existing byte mappings keep their own CPU/protocol synchronization;
        // this lease does not impose a second memory-access policy on them.
        let mapping = file.map(0, 4).unwrap();
        drop(mapping);
        {
            let _writeback = FileTransactionScope::writeback();
            file.write_at(0, b"page").unwrap();
            assert_eq!(file.read_at(0, 4).unwrap(), b"page");
        }
        assert!(
            !wait.ready(),
            "background progress does not release foreground ownership"
        );
        drop(lease);
        assert!(wait.ready());
        assert_eq!(file.read_at(0, 4).unwrap(), b"page");
    }
    #[test]
    fn a_writer_queued_before_publication_rechecks_inside_the_original_data_lock() {
        let transaction = Arc::new(FileTransaction::default());
        let data = Arc::new(std::sync::Mutex::new(Vec::new()));
        let held = data.lock().unwrap();
        let (observed, ready) = std::sync::mpsc::channel();
        let other = transaction.clone();
        let bytes = data.clone();
        let writer = std::thread::spawn(move || {
            assert!(other.available());
            observed.send(()).unwrap();
            let mut bytes = bytes.lock().unwrap();
            other.check()?;
            bytes.push(1u8);
            Ok::<_, io::Error>(())
        });
        ready.recv().unwrap();
        let lease = transaction.try_acquire().unwrap().unwrap();
        drop(held);
        let error = writer.join().unwrap().unwrap_err();
        assert!(data.lock().unwrap().is_empty());
        let wait = ResourcePending::from_io(&error).unwrap();
        assert!(!wait.ready());
        drop(lease);
        assert!(wait.ready());
    }
}
