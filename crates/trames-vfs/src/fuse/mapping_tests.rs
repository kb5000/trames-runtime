// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::fuse::tests::{answer, mounted, open_file, receive, reply};
use std::collections::VecDeque;
use std::sync::{Mutex, Weak};
use trames_memory::{SyncCompletion, SyncExecutor};
#[path = "buffered_tests.rs"]
mod buffered_tests;

struct Executor {
    this: Weak<Self>,
    jobs: Mutex<VecDeque<Box<Job>>>,
    closed: std::sync::atomic::AtomicBool,
}
struct Job {
    executor: Weak<Executor>,
    resource: Arc<dyn SyncResource>,
    completion: Option<Box<dyn SyncCompletion>>,
}
impl Drop for Job {
    fn drop(&mut self) {
        if let Some(completion) = self.completion.take() {
            self.resource.failed(MemoryError::BackingIo(5));
            completion.complete(Err(MemoryError::BackingIo(5)));
        }
    }
}
impl SyncCompletion for Job {
    fn complete(mut self: Box<Self>, result: std::result::Result<(), MemoryError>) {
        self.completion.take().unwrap().complete(result);
    }
    fn retry(self: Box<Self>) {
        if let Some(executor) = self.executor.upgrade() {
            executor.enqueue(self);
        }
    }
}
impl SyncExecutor for Executor {
    fn submit(&self, resource: Arc<dyn SyncResource>, completion: Box<dyn SyncCompletion>) {
        self.enqueue(Box::new(Job {
            executor: self.this.clone(),
            resource,
            completion: Some(completion),
        }));
    }
}
impl Executor {
    fn new() -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            jobs: Mutex::default(),
            closed: Default::default(),
        })
    }
    fn enqueue(&self, job: Box<Job>) {
        if self.closed.load(Ordering::Relaxed) {
            drop(job);
        } else {
            self.jobs.lock().unwrap().push_back(job);
        }
    }
    fn step(&self) {
        let job = self.jobs.lock().unwrap().pop_front();
        let job = job.expect("original resource continuation");
        let resource = job.resource.clone();
        if let Err(completion) = resource.sync_async(job) {
            completion.complete(resource.sync());
        }
    }
    fn resume(&self) {
        if !self.jobs.lock().unwrap().is_empty() {
            self.step();
        }
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let jobs = std::mem::take(&mut *self.jobs.lock().unwrap());
        drop(jobs);
    }
}
struct Done(Arc<Mutex<Option<std::result::Result<(), MemoryError>>>>);
impl SyncCompletion for Done {
    fn complete(self: Box<Self>, result: std::result::Result<(), MemoryError>) {
        *self.0.lock().unwrap() = Some(result);
    }
}
fn mapped(v: &Vfs, c: &Connection) -> (Arc<File>, Vec<Arc<dyn PageBacking>>) {
    let (_, fd) = open_file(v, c, 2);
    let original = v.shared_files().lookup(fd).unwrap().unwrap();
    let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
        panic!("original FUSE OFD")
    };
    let file = file.clone();
    file.attr.lock().unwrap()[8..16].copy_from_slice(&(2 * PAGE_SIZE).to_le_bytes());
    let pages = file
        .mapping_pages(original, 0, 2 * PAGE_SIZE, true, true)
        .unwrap();
    (file, pages)
}
fn load(c: &Connection, executor: &Executor, page: &Arc<dyn PageBacking>, fill: u8) {
    assert!(matches!(
        page.read(0, &mut [0]),
        Err(MemoryError::Pending(_))
    ));
    let read = receive(c, 15, 10);
    answer(c, &read, &vec![fill; PAGE_SIZE as usize]);
    assert!(
        !page.native_resident(),
        "reply thread does not invalidate a live native residency check"
    );
    executor.step();
    assert_eq!(page.read(0, &mut [0]), Ok(()));
    assert!(page.native_resident());
}
fn ack(c: &Connection, write: &[u8]) {
    let count = u32::from_le_bytes(write[56..60].try_into().unwrap());
    let mut response = [0; 8];
    response[..4].copy_from_slice(&count.to_le_bytes());
    answer(c, write, &response);
}

#[test]
fn cgroup_pressure_flushes_original_dirty_owners_and_executor_failure_is_bounded() {
    use trames_memory::{CgroupMemoryTarget, MemoryCgroup};
    let (v, device) = mounted();
    let c = device.connection().unwrap();
    let executor = Executor::new();
    let _actor = FileActorScope::enter_with_sync(
        Arc::new(CredentialState::new(v.credentials.clone())),
        v.pid,
        Some(executor.clone()),
    );
    let first = MemoryCgroup::new(None);
    let second = MemoryCgroup::new(None);
    let target = Arc::new(CgroupMemoryTarget::default());
    target.set(Some(first.clone()));
    let _scope = target.scope();
    let (file, pages) = mapped(&v, c);
    load(c, &executor, &pages[0], b'a');
    pages[0].write(0, b"first").unwrap();
    let pin = pages[0].shared_page().unwrap();
    target.set(Some(second.clone()));
    load(c, &executor, &pages[1], b'b');
    pages[1].write(0, b"second").unwrap();
    let wait = first.writeback(PAGE_SIZE as usize).unwrap();
    let other = first.writeback(PAGE_SIZE as usize).unwrap();
    assert_eq!(executor.jobs.lock().unwrap().len(), 1);
    executor.step();
    let write = receive(c, 16, 10);
    assert_eq!(&write[48..56], &0u64.to_le_bytes());
    assert_eq!(&write[80..85], b"first");
    assert!(!wait.ready());
    ack(c, &write);
    executor.resume();
    assert!(wait.ready() && other.ready());
    assert!(!pages[0].proc_dirty() && pages[1].proc_dirty());
    assert_eq!(
        first.current(),
        PAGE_SIZE as usize,
        "a mapped physical pin is still allocated"
    );
    assert!(first.writeback(PAGE_SIZE as usize).is_none());
    assert!(!pages[0].native_resident());
    assert_eq!(first.reclaimed_bytes(), 0);
    drop(pin);
    assert_eq!(first.current(), 0);
    assert_eq!(first.reclaimed_bytes(), PAGE_SIZE as usize);
    let cancelled = second.writeback(PAGE_SIZE as usize).unwrap();
    executor.close();
    assert!(cancelled.ready());
    assert!(pages[1].proc_dirty());
    assert_eq!(second.current(), PAGE_SIZE as usize);
    assert!(second.writeback(PAGE_SIZE as usize).is_none());
    assert!(file.attr.cache.dirty());
}

#[test]
fn mapped_writeback_waits_for_each_original_reply_and_fsync_under_layout_admission() {
    let (v, device) = mounted();
    let c = device.connection().unwrap();
    let executor = Executor::new();
    let _actor = FileActorScope::enter_with_sync(
        Arc::new(CredentialState::new(v.credentials.clone())),
        v.pid,
        Some(executor.clone()),
    );
    let (file, pages) = mapped(&v, c);
    for (page, fill) in pages.iter().zip(*b"ab") {
        load(c, &executor, page, fill);
        page.write(0, &[fill + 1]).unwrap();
    }
    let done = Arc::new(Mutex::new(None));
    executor.submit(
        pages[0].sync_resource().unwrap().unwrap(),
        Box::new(Done(done.clone())),
    );
    executor.step();
    let first = receive(c, 16, 10);
    assert_eq!(
        &first[24..40],
        &[0; 16],
        "writeback has no task credentials"
    );
    assert_eq!(&first[40..48], &9876u64.to_le_bytes());
    assert_eq!(&first[60..64], &1u32.to_le_bytes());
    ack(c, &first);
    assert!(
        pages[0].proc_dirty(),
        "daemon ACK still requires source layout admission"
    );
    assert!(
        executor.jobs.lock().unwrap().is_empty(),
        "an intermediate ACK only advances owned bytes"
    );
    let second = receive(c, 16, 10);
    assert_eq!(&second[48..56], &PAGE_SIZE.to_le_bytes());
    let memory = trames_memory::Memory::default();
    let reader = file.attr.layout.try_read(memory.memory_report()).unwrap();
    ack(c, &second);
    assert!(pages[0].proc_dirty());
    drop(reader);
    executor.step();
    let sync = receive(c, 20, 10);
    assert!(done.lock().unwrap().is_none());
    answer(c, &sync, &[]);
    executor.resume();
    assert!(matches!(done.lock().unwrap().take(), Some(Ok(()))));
    assert!(!file.attr.cache.dirty());
    executor.close();
}

#[test]
fn stores_after_a_write_snapshot_survive_its_ack_and_close_error_reaches_original_ofd() {
    let (v, device) = mounted();
    let c = device.connection().unwrap();
    let executor = Executor::new();
    let _actor = FileActorScope::enter_with_sync(
        Arc::new(CredentialState::new(v.credentials.clone())),
        v.pid,
        Some(executor.clone()),
    );
    let (file, pages) = mapped(&v, c);
    load(c, &executor, &pages[0], b'a');
    pages[0].write(0, b"first").unwrap();
    let done = Arc::new(Mutex::new(None));
    executor.submit(
        pages[0].close_resource().unwrap(),
        Box::new(Done(done.clone())),
    );
    executor.step();
    let write = receive(c, 16, 10);
    pages[0].write(0, b"later").unwrap();
    ack(c, &write);
    executor.resume();
    assert!(matches!(done.lock().unwrap().take(), Some(Ok(()))));
    assert!(
        pages[0].proc_dirty(),
        "a late generation is not cleared by an earlier ACK"
    );
    let done = Arc::new(Mutex::new(None));
    executor.submit(
        pages[0].close_resource().unwrap(),
        Box::new(Done(done.clone())),
    );
    executor.step();
    let write = receive(c, 16, 10);
    assert_eq!(&write[80..85], b"later");
    c.write(&reply(crate::fuse::tests::id(&write), -5, &[]))
        .unwrap();
    executor.resume();
    assert!(matches!(
        done.lock().unwrap().take(),
        Some(Err(MemoryError::BackingIo(5)))
    ));
    assert_eq!(
        file.attr.cache.check_error(&file.writeback_seen),
        Err(Errno(5))
    );
    assert_eq!(file.attr.cache.check_error(&file.writeback_seen), Ok(()));
    assert!(!pages[0].proc_dirty());
    executor.close();
}

#[test]
fn truncate_keeps_physical_identity_zeroes_tail_and_makes_removed_pages_bus_faults() {
    let (v, device) = mounted();
    let c = device.connection().unwrap();
    let executor = Executor::new();
    let _actor = FileActorScope::enter_with_sync(
        Arc::new(CredentialState::new(v.credentials.clone())),
        v.pid,
        Some(executor.clone()),
    );
    let (file, pages) = mapped(&v, c);
    load(c, &executor, &pages[0], b'x');
    let original = pages[0].shared_page().unwrap();
    pages[0].write(0, b"keep").unwrap();
    file.attr.lock().unwrap()[8..16].copy_from_slice(&4u64.to_le_bytes());
    file.attr.cache.resize(2 * PAGE_SIZE, 4);
    assert!(Arc::ptr_eq(&original, &pages[0].shared_page().unwrap()));
    let mut bytes = [1; 8];
    pages[0].read(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"keep\0\0\0\0");
    assert!(matches!(
        pages[1].check(0x9000),
        Err(MemoryError::Bus(0x9000))
    ));
    executor.close();
}
