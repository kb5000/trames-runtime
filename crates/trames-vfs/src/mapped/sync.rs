// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted writeback keeps each page and backend phase across suspension.
use super::*;
use std::sync::Mutex;
use trames_memory::{CgroupMemoryContext, PageWait, SyncResource};
use trames_shared::ResourceWait;

#[derive(Default)]
pub(super) struct Ticket {
    done: AtomicBool,
    changed: Arc<Readiness>,
}
impl Ticket {
    pub(super) fn ready(&self) -> bool {
        self.done.load(Ordering::Relaxed)
    }
    fn finish(&self) {
        self.done.store(true, Ordering::Relaxed);
        self.changed.notify_atomic();
    }
}
impl ResourceWait for Ticket {
    fn ready(&self) -> bool {
        self.ready()
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        vec![self.changed.subscribe(signal)]
    }
}
struct Page {
    offset: u64,
    page: Arc<FilePage>,
    ticket: Option<Arc<Ticket>>,
    generation: u64,
    written: usize,
    done: bool,
    write: bool,
    resources: Option<CgroupResourceContext>,
}
impl Page {
    fn new(offset: u64, page: Arc<FilePage>, write: bool) -> Self {
        Self {
            offset,
            page,
            ticket: None,
            generation: 0,
            written: 0,
            done: false,
            write,
            resources: None,
        }
    }
    fn complete(&mut self) {
        self.done = true;
        if let Some(ticket) = &self.ticket {
            ticket.done.store(true, Ordering::Relaxed);
        }
    }
    fn step(&mut self, data: &SharedCell<Box<FileData>>, state: &MappingState) -> Result<()> {
        let _resources = self.resources.as_ref().map(CgroupResourceContext::enter);
        if self.ticket.is_none() {
            let mut owner = self.page.writeback.lock().unwrap();
            if let Some(ticket) = owner.upgrade().filter(|ticket| !ticket.ready()) {
                return Err(resource_io::memory_error(
                    PageWait::resource(ticket).fault(0),
                ));
            }
            if !self.write {
                drop(owner);
                self.complete();
                return Ok(());
            }
            let dirty = self.page.dirty.swap(false, Ordering::Relaxed);
            let skip =
                !dirty || self.page.deferred() || self.page.bytes.read().unwrap().is_shared();
            if skip {
                drop(owner);
                self.complete();
                return Ok(());
            }
            let ticket = Arc::new(Ticket::default());
            *owner = Arc::downgrade(&ticket);
            self.ticket = Some(ticket);
            self.generation = self
                .page
                .invalidation_generation
                .load(Ordering::Relaxed)
                .wrapping_add(self.page.external_version());
            drop(owner);
        }
        if self.generation
            != self
                .page
                .invalidation_generation
                .load(Ordering::Relaxed)
                .wrapping_add(self.page.external_version())
        {
            self.complete();
            return Ok(());
        }
        let count = state.len().saturating_sub(self.offset).min(PAGE_SIZE) as usize;
        if self.written < count {
            // Recopy only the unfinished bytes. Concurrent mapped stores keep
            // their dirty publication; an older parked snapshot must not be
            // copied back into the canonical page after a newer write.
            let mut bytes = [0; PAGE_SIZE as usize];
            self.page
                .bytes
                .read()
                .unwrap()
                .copy_read(self.written, &mut bytes[self.written..count]);
            let scope = resource_io::Scope::enter();
            let result = data.borrow_mut().write_at(
                self.offset + self.written as u64,
                &bytes[self.written..count],
            );
            let pending = scope.finish();
            let progress = match &result {
                Ok(count) => *count,
                Err(_) => pending.as_ref().map_or(0, |pending| pending.progress),
            };
            assert!(
                progress <= count - self.written,
                "backend writeback progress exceeds its input"
            );
            self.written += progress;
            if let Some(pending) = pending {
                // Backend progress belongs to writeback, never to the guest's
                // original write or copy operation which happened to need it.
                return Err(resource_io::memory_error(pending.wait.fault(0)));
            }
            result?;
            if self.written != count {
                return Err(Errno(5));
            }
        }
        self.complete();
        Ok(())
    }
}
impl Drop for Page {
    fn drop(&mut self) {
        if !self.done && self.ticket.is_some() {
            self.page.dirty.store(true, Ordering::Relaxed);
        }
        let retired = if self.done {
            let mut origin = self.page.dirty_resources.lock().unwrap();
            (!self.page.dirty.load(Ordering::Relaxed))
                .then(|| origin.take())
                .flatten()
        } else {
            None
        };
        drop(retired);
        if let Some(ticket) = self.ticket.take() {
            ticket.finish();
        }
    }
}

/// The tree contains original data capabilities, including every mapped layer.
/// Capturing once prevents a resumed sync from marking finished pages dirty.
pub(crate) struct DataSync {
    operation: Operation,
    step: Step,
    done: bool,
    retired: Vec<Page>,
}
/// Callers can release these tickets outside their own resource-state locks.
pub(crate) struct Notifications(Vec<Page>);
#[derive(Clone, Copy)]
pub(crate) enum Operation {
    File(bool),
    Range {
        offset: u64,
        length: u64,
        flags: u32,
    },
}
enum Step {
    Plain(Arc<file_data::PlainFile>),
    Layer {
        node: NodeRef,
        backing: Box<DataSync>,
    },
    Mapped {
        data: Arc<SharedCell<Box<FileData>>>,
        state: Arc<MappingState>,
        pages: VecDeque<Page>,
        backing: Box<DataSync>,
    },
    Done,
}
impl DataSync {
    /// Setting file capabilities implicitly syncs mapped providers, including
    /// mapped data below an overlay layer. Plain providers retain their own
    /// capability transaction and its original durability barrier.
    pub(crate) fn before_capabilities(data: &FileData) -> Result<Option<Self>> {
        match data {
            FileData::Mapped(_) => Self::capture(data, false).map(Some),
            FileData::Layer(layer) => layer.read(Self::before_capabilities).map(|plan| {
                plan.map(|plan| Self {
                    operation: Operation::File(false),
                    step: Step::Layer {
                        node: layer.node.clone(),
                        backing: Box::new(plan),
                    },
                    done: false,
                    retired: Vec::new(),
                })
            }),
            _ => Ok(None),
        }
    }
    pub(crate) fn before_truncate(data: &FileData, length: u64) -> Result<Option<Self>> {
        match data {
            FileData::Mapped(mapped)
                if length == mapped.len() && !mapped.has_allocated_after(length) =>
            {
                Ok(None)
            }
            FileData::Mapped(_) => Self::capture(data, false).map(Some),
            FileData::Layer(layer) => {
                layer
                    .read(|data| Self::before_truncate(data, length))
                    .map(|plan| {
                        plan.map(|plan| Self {
                            operation: Operation::File(false),
                            step: Step::Layer {
                                node: layer.node.clone(),
                                backing: Box::new(plan),
                            },
                            done: false,
                            retired: Vec::new(),
                        })
                    })
            }
            _ => Ok(None),
        }
    }
    pub(crate) fn capture(data: &FileData, data_only: bool) -> Result<Self> {
        Self::capture_operation(data, Operation::File(data_only), true)
    }
    pub(crate) fn capture_operation(
        data: &FileData,
        operation: Operation,
        backend: bool,
    ) -> Result<Self> {
        if matches!(operation, Operation::Range { flags: 0, .. }) {
            return Ok(Self {
                operation,
                step: Step::Done,
                done: true,
                retired: Vec::new(),
            });
        }
        let step = match data {
            FileData::Plain(data) if backend => Step::Plain(data.clone()),
            FileData::Plain(_) => Step::Done,
            FileData::Mapped(mapped) => Step::Mapped {
                data: mapped.data.clone(),
                state: mapped.state.clone(),
                pages: mapped
                    .prepare_sync_operation(operation)
                    .into_iter()
                    .map(|(offset, page)| {
                        Page::new(
                            offset,
                            page,
                            match operation {
                                Operation::File(_) => true,
                                Operation::Range { flags, .. } => flags & 2 != 0,
                            },
                        )
                    })
                    .collect(),
                backing: Box::new(Self::capture_operation(
                    &mapped.data.borrow(),
                    operation,
                    backend,
                )?),
            },
            FileData::Layer(layer) => Step::Layer {
                node: layer.node.clone(),
                backing: Box::new(
                    layer.read(|data| Self::capture_operation(data, operation, backend))?,
                ),
            },
            FileData::Lower(_) if matches!(operation, Operation::Range { .. }) => Step::Done,
            FileData::Lower(source) => {
                let node = source.borrow();
                let Content::File(data) = &node.content else {
                    return Err(Errno(5));
                };
                Step::Layer {
                    node: source.clone(),
                    backing: Box::new(Self::capture_operation(data, operation, backend)?),
                }
            }
            FileData::Shared(_) => Step::Done,
        };
        Ok(Self {
            operation,
            step,
            done: false,
            retired: Vec::new(),
        })
    }
    pub(crate) fn run(&mut self) -> Result<()> {
        if self.done {
            return Ok(());
        }
        match &mut self.step {
            Step::Plain(data) => match self.operation {
                Operation::File(data_only) => data.sync(data_only)?,
                Operation::Range {
                    offset,
                    length,
                    flags,
                } => data.sync_range(offset, length, flags)?,
            },
            Step::Layer { node, backing } => {
                let _node = node.borrow();
                backing.run()?;
            }
            Step::Mapped {
                data,
                state,
                pages,
                backing,
            } => {
                while let Some(page) = pages.front_mut() {
                    page.step(data, state)?;
                    self.retired.push(pages.pop_front().unwrap());
                }
                backing.run()?;
            }
            Step::Done => {}
        }
        self.done = true;
        Ok(())
    }
    /// Release bytes and wake followers only after inode/data guards are gone.
    pub(crate) fn notify(&mut self) {
        drop(std::mem::take(&mut self.retired));
        if let Step::Mapped { backing, .. } | Step::Layer { backing, .. } = &mut self.step {
            backing.notify();
        }
    }
    pub(crate) fn take_notifications(&mut self) -> Notifications {
        let mut retired = std::mem::take(&mut self.retired);
        if let Step::Mapped { backing, .. } | Step::Layer { backing, .. } = &mut self.step {
            retired.append(&mut backing.take_notifications().0);
        }
        Notifications(retired)
    }
}

pub(super) struct Resource {
    node: NodeRef,
    _open: Arc<SharedOpenDescription>,
    layout: Option<Arc<trames_memory::layout::Layout>>,
    actor: Option<crate::FileActorSnapshot>,
    memory: CgroupMemoryContext,
    io: cgroup::IoContext,
    state: Mutex<State>,
    reclaim: Option<(Arc<trames_memory::MemoryCgroup>, Vec<Arc<FilePage>>)>,
}
enum State {
    Ready(DataSync),
    Running(Arc<PageWait>),
    Complete(std::result::Result<(), MemoryError>),
}
impl Resource {
    pub(super) fn capture(mapping: &FileMapping) -> Result<Self> {
        let node = mapping.node.borrow();
        let Content::File(data) = &node.content else {
            return Err(Errno(5));
        };
        let plan = DataSync::capture(data, false)?;
        Ok(Self {
            node: mapping.node.clone(),
            _open: mapping.open.clone(),
            layout: mapping.layout(),
            actor: crate::FileActorScope::frozen(),
            memory: CgroupMemoryContext::capture(),
            io: cgroup::IoContext::capture(),
            state: Mutex::new(State::Ready(plan)),
            reclaim: None,
        })
    }
    pub(super) fn pressure(
        node: NodeRef,
        open: Arc<SharedOpenDescription>,
        data: Arc<SharedCell<Box<FileData>>>,
        state: Arc<MappingState>,
        selected: Vec<(u64, Arc<FilePage>)>,
        group: Arc<trames_memory::MemoryCgroup>,
    ) -> Option<Self> {
        let plain = match &**data.try_borrow()? {
            FileData::Plain(file) if file.private_disk() => file.clone(),
            _ => return None,
        };
        let pages: Option<VecDeque<_>> = selected
            .iter()
            .map(|(offset, page)| {
                let mut work = Page::new(*offset, page.clone(), true);
                work.resources = page.dirty_resources.try_lock().ok()?.clone();
                Some(work)
            })
            .collect();
        let pages = pages?;
        let backing = DataSync {
            operation: Operation::File(false),
            step: Step::Plain(plain),
            done: false,
            retired: Vec::new(),
        };
        let plan = DataSync {
            operation: Operation::File(false),
            step: Step::Mapped {
                data,
                state,
                pages,
                backing: Box::new(backing),
            },
            done: false,
            retired: Vec::new(),
        };
        let layout = Some(node.layout.get_or_init(Default::default).clone());
        Some(Self {
            node,
            _open: open,
            layout,
            actor: None,
            memory: CgroupMemoryContext::default(),
            io: cgroup::IoContext::default(),
            state: Mutex::new(State::Ready(plan)),
            reclaim: Some((group, selected.into_iter().map(|(_, page)| page).collect())),
        })
    }
}
impl SyncResource for Resource {
    fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        self.layout.clone()
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        let (plan, wait) = {
            let mut state = self.state.lock().unwrap();
            match &*state {
                State::Running(wait) => return Err(wait.fault(0)),
                State::Complete(result) => return result.clone(),
                State::Ready(_) => {}
            }
            let wait = Arc::new(PageWait::default());
            let State::Ready(plan) = std::mem::replace(&mut *state, State::Running(wait.clone()))
            else {
                unreachable!()
            };
            (plan, wait)
        };
        let mut plan = Some(plan);
        let _memory = self.memory.enter();
        let _io = self.io.enter();
        let _actor = self.actor.as_ref().map(crate::FileActorSnapshot::enter);
        let _writeback = trames_shared::FileTransactionScope::writeback();
        let scope = resource_io::Scope::enter();
        let result = {
            let _node = self.node.borrow();
            plan.as_mut().unwrap().run()
        };
        if result.is_ok() {
            if let Some((group, pages)) = &self.reclaim {
                for page in pages {
                    page.discard_clean(group);
                }
            }
        }
        plan.as_mut().unwrap().notify();
        let result = resource_io::memory_result(scope.finish(), result);
        let retired = {
            let mut state = self.state.lock().unwrap();
            if matches!(&*state, State::Running(current) if Arc::ptr_eq(current, &wait)) {
                let next = if matches!(result, Err(MemoryError::Pending(_))) {
                    State::Ready(plan.take().unwrap())
                } else {
                    State::Complete(result.clone())
                };
                Some(std::mem::replace(&mut *state, next))
            } else {
                None
            }
        };
        drop(retired);
        drop(plan);
        wait.finish();
        match &*self.state.lock().unwrap() {
            State::Complete(result) => result.clone(),
            _ => result,
        }
    }
    fn failed(&self, error: MemoryError) {
        let old = {
            let mut state = self.state.lock().unwrap();
            if matches!(*state, State::Complete(_)) {
                return;
            }
            std::mem::replace(&mut *state, State::Complete(Err(error)))
        };
        if let State::Running(wait) = &old {
            wait.finish();
        }
        drop(old);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_shared::{SharedFile, SharedFileAccess, SharedFileAccounting, SharedFileCharge};

    struct Account {
        wait: Arc<PageWait>,
        commits: Arc<Mutex<Vec<(usize, usize)>>>,
    }
    struct Loan {
        offset: usize,
        commits: Arc<Mutex<Vec<(usize, usize)>>>,
    }
    impl SharedFileCharge for Loan {
        fn changed(&self) -> bool {
            true
        }
        fn commit(self: Box<Self>, count: usize) -> Arc<dyn Send + Sync> {
            self.commits.lock().unwrap().push((self.offset, count));
            Arc::new(())
        }
    }
    impl SharedFileAccounting for Account {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn reserve(
            &self,
            offset: usize,
            _: usize,
            _: SharedFileAccess,
        ) -> std::io::Result<Box<dyn SharedFileCharge>> {
            if offset >= PAGE_SIZE as usize + 2 && !self.wait.ready() {
                return Err(trames_shared::ResourcePending::io_error(self.wait.clone()));
            }
            Ok(Box::new(Loan {
                offset,
                commits: self.commits.clone(),
            }))
        }
        fn truncate(&self, _: usize) {}
        fn write_chunk(&self, offset: usize, length: usize) -> usize {
            let boundary = PAGE_SIZE as usize + 2;
            if offset < boundary {
                length.min(boundary - offset)
            } else {
                length
            }
        }
    }
    fn fixture(nested: bool) -> (FileData, [Arc<FilePage>; 2], SharedFile, Arc<Account>) {
        let file = SharedFile::anonymous().unwrap();
        file.set_len(PAGE_SIZE as usize * 2).unwrap();
        let account = Arc::new(Account {
            wait: Arc::default(),
            commits: Arc::default(),
        });
        file.set_accounting(account.clone()).unwrap();
        let mut data = FileData::Shared(file.clone());
        if nested {
            data = FileData::Mapped(Box::new(MappedData::new(data, true)));
        }
        let mapped = MappedData::new(data, true);
        // A controlled backend supplies deterministic suspension after real
        // writes. The pages exercise the ordinary copied-page writeback path.
        let pages = [
            FilePage::new(PageStorage::heap(Box::new([1; PAGE_SIZE as usize]))),
            FilePage::new(PageStorage::heap(Box::new([2; PAGE_SIZE as usize]))),
        ];
        for (index, page) in pages.iter().enumerate() {
            page.dirty.store(true, Ordering::Relaxed);
            mapped
                .pages
                .borrow_mut()
                .insert(index as u64 * PAGE_SIZE, Arc::downgrade(page));
        }
        (FileData::Mapped(Box::new(mapped)), pages, file, account)
    }
    fn run(plan: &mut DataSync) -> (Result<()>, Option<resource_io::Pending>) {
        let scope = resource_io::Scope::enter();
        let result = plan.run();
        plan.notify();
        (result, scope.finish())
    }
    #[test]
    fn nested_sync_resumes_the_unfinished_page_without_rewriting_an_earlier_page_or_prefix() {
        for (nested, implicit) in [(false, false), (true, false), (false, true), (true, true)] {
            let (data, pages, file, account) = fixture(nested);
            let mut plan = if implicit {
                DataSync::before_capabilities(&data).unwrap().unwrap()
            } else {
                DataSync::capture(&data, false).unwrap()
            };
            let (result, pending) = run(&mut plan);
            assert_eq!(result, Err(Errno(11)));
            let pending = pending.unwrap();
            assert_eq!(
                pending.progress, 0,
                "writeback bytes are not original syscall progress"
            );
            assert!(!pending.wait.ready());
            assert_eq!(
                *account.commits.lock().unwrap(),
                [(0, PAGE_SIZE as usize), (PAGE_SIZE as usize, 2)]
            );
            // These stores happened after the first page and the second-page
            // prefix were written. Only the unfinished suffix belongs to the
            // resumed wave; newly dirty data remains for the next one.
            pages[0].bytes.read().unwrap().copy_write(0, &[3]);
            pages[0].dirty.store(true, Ordering::Relaxed);
            pages[1]
                .bytes
                .read()
                .unwrap()
                .copy_write(2, &vec![4; PAGE_SIZE as usize - 2]);
            pages[1].dirty.store(true, Ordering::Relaxed);
            account.wait.finish();
            assert!(pending.wait.ready());
            let (result, pending) = run(&mut plan);
            assert_eq!(result, Ok(()));
            assert!(pending.is_none());
            assert_eq!(
                *account.commits.lock().unwrap(),
                [
                    (0, PAGE_SIZE as usize),
                    (PAGE_SIZE as usize, 2),
                    (PAGE_SIZE as usize + 2, PAGE_SIZE as usize - 2)
                ]
            );
            assert_eq!(
                file.read_at(0, 1).unwrap(),
                [1],
                "the finished first page was not replayed"
            );
            let suffix = file.read_at(PAGE_SIZE, PAGE_SIZE as usize).unwrap();
            assert_eq!(&suffix[..2], &[2, 2]);
            assert!(suffix[2..].iter().all(|byte| *byte == 4));
            assert!(pages.iter().all(|page| page.dirty.load(Ordering::Relaxed)));
            let before = account.commits.lock().unwrap().len();
            assert_eq!(run(&mut plan).0, Ok(()));
            assert_eq!(
                account.commits.lock().unwrap().len(),
                before,
                "a completed plan is terminal"
            );
        }
    }
    #[test]
    fn a_following_sync_waits_for_the_original_page_and_cancellation_restores_dirty_data() {
        let (data, pages, _, account) = fixture(false);
        let mut first = DataSync::capture(&data, false).unwrap();
        assert!(run(&mut first).1.is_some());
        assert!(!pages[1].dirty.load(Ordering::Relaxed));
        let mut next = DataSync::capture(&data, false).unwrap();
        let (result, pending) = run(&mut next);
        assert_eq!(result, Err(Errno(11)));
        let pending = pending.unwrap();
        assert!(!pending.wait.ready());
        drop(first);
        assert!(pending.wait.ready());
        assert!(pages[1].dirty.load(Ordering::Relaxed));
        account.wait.finish();
        assert_eq!(run(&mut next).0, Ok(()));
    }
    #[test]
    fn ranged_writeback_keeps_other_pages_dirty_and_resumes_only_its_selected_page() {
        let (data, pages, file, account) = fixture(false);
        let mut plan = DataSync::capture_operation(
            &data,
            Operation::Range {
                offset: PAGE_SIZE + 1,
                length: 1,
                flags: 2,
            },
            true,
        )
        .unwrap();
        assert!(run(&mut plan).1.is_some());
        assert_eq!(*account.commits.lock().unwrap(), [(PAGE_SIZE as usize, 2)]);
        assert!(pages[0].dirty.load(Ordering::Relaxed));
        account.wait.finish();
        assert_eq!(run(&mut plan).0, Ok(()));
        assert_eq!(
            *account.commits.lock().unwrap(),
            [
                (PAGE_SIZE as usize, 2),
                (PAGE_SIZE as usize + 2, PAGE_SIZE as usize - 2)
            ]
        );
        assert_eq!(file.read_at(0, 1).unwrap(), [0]);
        assert_eq!(file.read_at(PAGE_SIZE, 1).unwrap(), [2]);
        assert!(pages[0].dirty.load(Ordering::Relaxed));
    }
    #[test]
    fn ranged_wait_only_and_zero_flags_do_not_start_new_dirty_writes() {
        let (data, pages, _, account) = fixture(false);
        let mut zero = DataSync::capture_operation(
            &data,
            Operation::Range {
                offset: 0,
                length: 0,
                flags: 0,
            },
            true,
        )
        .unwrap();
        assert_eq!(run(&mut zero).0, Ok(()));
        assert!(account.commits.lock().unwrap().is_empty());
        let mut first = DataSync::capture(&data, false).unwrap();
        assert!(run(&mut first).1.is_some());
        let before = account.commits.lock().unwrap().len();
        let mut wait = DataSync::capture_operation(
            &data,
            Operation::Range {
                offset: PAGE_SIZE,
                length: PAGE_SIZE,
                flags: 5,
            },
            true,
        )
        .unwrap();
        let pending = run(&mut wait).1.unwrap();
        assert!(!pending.wait.ready());
        drop(first);
        assert!(pending.wait.ready());
        assert_eq!(run(&mut wait).0, Ok(()));
        assert_eq!(account.commits.lock().unwrap().len(), before);
        assert!(pages[1].dirty.load(Ordering::Relaxed));
    }
    #[test]
    fn retired_sync_resource_releases_the_original_page_and_keeps_its_terminal_error() {
        let (data, pages, _, _) = fixture(false);
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/sync", 0x42, 0o600).unwrap();
        let target = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let node = target.0.open.node.as_ref().unwrap().clone();
        let plan = DataSync::capture(&data, false).unwrap();
        node.borrow_mut().content = Content::File(data);
        let resource = Resource {
            node,
            _open: target.0.open.clone(),
            layout: None,
            actor: None,
            memory: CgroupMemoryContext::default(),
            io: crate::cgroup::IoContext::default(),
            reclaim: None,
            state: Mutex::new(State::Ready(plan)),
        };
        assert!(matches!(resource.sync(), Err(MemoryError::Pending(_))));
        let ticket = pages[1].writeback.lock().unwrap().upgrade().unwrap();
        assert!(!ticket.ready());
        resource.failed(MemoryError::BackingIo(5));
        assert!(ticket.ready());
        assert!(pages[1].dirty.load(Ordering::Relaxed));
        assert_eq!(resource.sync(), Err(MemoryError::BackingIo(5)));
        resource.failed(MemoryError::BackingIo(12));
        assert_eq!(resource.sync(), Err(MemoryError::BackingIo(5)));
    }
    #[test]
    fn filesystem_sync_resumes_at_the_original_file_instead_of_replaying_finished_files() {
        let (first, pages, _, first_account) = fixture(false);
        first_account.wait.finish();
        let (second, second_pages, _, second_account) = fixture(false);
        let mut v = Vfs::default();
        for (path, data) in [
            (b"/first".as_slice(), first),
            (b"/second".as_slice(), second),
        ] {
            let fd = v.open_at(AT_FDCWD, path, 0x42, 0o600).unwrap();
            let target = v
                .shared_files()
                .lookup(fd)
                .unwrap()
                .unwrap()
                .file_target()
                .unwrap();
            target.0.open.node.as_ref().unwrap().borrow_mut().content = Content::File(data);
        }
        let mut work = storage::FilesystemSync::new(v.fs.clone());
        let scope = resource_io::Scope::enter();
        assert_eq!(work.run(), Err(Errno(11)));
        assert!(scope.finish().is_some());
        let completed = first_account.commits.lock().unwrap().len();
        pages[0].bytes.read().unwrap().copy_write(0, &[7]);
        pages[0].dirty.store(true, Ordering::Relaxed);
        second_account.wait.finish();
        let scope = resource_io::Scope::enter();
        assert_eq!(work.run(), Ok(()));
        assert!(scope.finish().is_none());
        assert_eq!(first_account.commits.lock().unwrap().len(), completed);
        assert!(pages[0].dirty.load(Ordering::Relaxed));
        drop(second_pages);
    }
    #[test]
    fn retained_truncate_reacquires_layout_preserves_new_dirty_prefix_and_keeps_the_original_fd() {
        for nested in [false, true] {
            let (data, pages, file, account) = fixture(nested);
            let mut v = Vfs::default();
            let fd = v.open_at(AT_FDCWD, b"/resize", 0x42, 0o600).unwrap();
            v.seek(fd, 5, 0).unwrap();
            let original = v.shared_files().lookup(fd).unwrap().unwrap();
            let target = original.clone().file_target().unwrap();
            target.0.open.node.as_ref().unwrap().borrow_mut().content = Content::File(data);
            let FileOutcome::Waiting(work) =
                FileWork::run_owned(&mut v, target, FileCommand::Truncate(PAGE_SIZE / 2))
            else {
                panic!("original truncate must retain its writeback");
            };
            assert!(!work.interruptible_wait());
            assert_eq!(file.len(), PAGE_SIZE as usize * 2);
            assert_eq!(original.open.file_position.snapshot(), 5);
            pages[0].bytes.read().unwrap().copy_write(0, &[7]);
            pages[0].dirty.store(true, Ordering::Relaxed);
            v.close(fd).unwrap();
            assert_eq!(v.eventfd(11, 0).unwrap(), fd);
            account.wait.finish();
            let FileOutcome::Layout(work) = work.run() else {
                panic!("a parked resize must reacquire original layout authority");
            };
            assert_eq!(file.len(), PAGE_SIZE as usize * 2);
            let FileOutcome::Complete(reply) = work.exclusive().run() else {
                panic!("original resize must complete after writeback");
            };
            assert!(matches!(reply.result, Ok(FileValue::Count(0))));
            assert_eq!(file.len(), PAGE_SIZE as usize / 2);
            assert_eq!(original.open.file_position.snapshot(), 5);
            assert_eq!(v.read(fd, 8).unwrap(), 11u64.to_le_bytes());
            assert!(
                pages[0].dirty.load(Ordering::Relaxed),
                "a newer surviving prefix stays dirty"
            );
            let mut prefix = [0];
            pages[0].bytes.read().unwrap().copy_read(0, &mut prefix);
            assert_eq!(prefix, [7]);
            assert_eq!(
                account
                    .commits
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(offset, _)| *offset == 0)
                    .count(),
                1,
                "the accepted sync did not repeat its finished page"
            );
            let descriptor = Descriptor {
                open: OpenHandle::Shared(original.open.clone()),
                cloexec: false.into(),
            };
            v.sync_description(&descriptor, false).unwrap();
            assert_eq!(file.read_at(0, 1).unwrap(), [7]);
            assert!(!pages[0].dirty.load(Ordering::Relaxed));
        }
    }
    #[test]
    fn cancelling_a_parked_truncate_preserves_eof_and_releases_its_original_mutation() {
        let (data, pages, file, _) = fixture(false);
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/resize", 0x42, 0o600).unwrap();
        let target = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        target.0.open.node.as_ref().unwrap().borrow_mut().content = Content::File(data);
        let FileOutcome::Waiting(work) =
            FileWork::run_owned(&mut v, target.clone(), FileCommand::Truncate(1))
        else {
            panic!("truncate writeback wait");
        };
        let FileOutcome::Waiting(contender) = FileWork::run_inline(
            &v.path_queries(),
            target,
            FileCommand::Write {
                bytes: vec![3],
                offset: Some(0),
            },
        ) else {
            panic!("the original data mutation is retained");
        };
        assert!(!contender.ready());
        drop(work);
        assert_eq!(file.len(), PAGE_SIZE as usize * 2);
        assert!(pages[1].dirty.load(Ordering::Relaxed));
        assert!(contender.ready());
    }
    #[test]
    fn a_new_seal_waits_for_the_original_resize_and_does_not_change_its_admission() {
        let (data, _pages, _, _) = fixture(false);
        let mut v = Vfs::default();
        let fd = v.memfd_create(b"seal-after-resize", 2).unwrap();
        let target = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        target.0.open.node.as_ref().unwrap().borrow_mut().content = Content::File(data);
        let FileOutcome::Waiting(resize) =
            FileWork::run_owned(&mut v, target.clone(), FileCommand::Truncate(1))
        else {
            panic!("retained resize");
        };
        let FileOutcome::Waiting(seal) =
            FileWork::run_inline(&v.path_queries(), target, FileCommand::Seals(Some(4)))
        else {
            panic!("seal must wait for the original mutation");
        };
        assert_eq!(v.seals(fd, None), Ok(0));
        assert!(!seal.ready());
        drop(resize);
        assert!(seal.ready());
        let FileOutcome::Complete(reply) = seal.run() else {
            panic!("seal proceeds after cancelled resize");
        };
        assert!(matches!(reply.result, Ok(FileValue::Count(0))));
        assert_eq!(v.seals(fd, None), Ok(4));
    }
    #[test]
    fn write_seal_retains_its_sync_progress_and_publishes_before_releasing_new_writers() {
        let (data, _pages, _, account) = fixture(true);
        let mut v = Vfs::default();
        let fd = v.memfd_create(b"seal-sync", 2).unwrap();
        let target = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        target.0.open.node.as_ref().unwrap().borrow_mut().content = Content::File(data);
        let FileOutcome::Waiting(seal) =
            FileWork::run_owned(&mut v, target.clone(), FileCommand::Seals(Some(8)))
        else {
            panic!("write seal must retain original writeback");
        };
        let FileOutcome::Waiting(writer) = FileWork::run_inline(
            &v.path_queries(),
            target,
            FileCommand::Write {
                bytes: vec![9],
                offset: Some(0),
            },
        ) else {
            panic!("writer waits for accepted seal");
        };
        assert_eq!(v.seals(fd, None), Ok(0));
        assert!(!writer.ready());
        account.wait.finish();
        let FileOutcome::Complete(reply) = seal.run() else {
            panic!("write seal resumes original sync");
        };
        assert!(matches!(reply.result, Ok(FileValue::Count(0))));
        assert_eq!(v.seals(fd, None), Ok(8));
        assert_eq!(
            account
                .commits
                .lock()
                .unwrap()
                .iter()
                .filter(|(offset, _)| *offset == 0)
                .count(),
            1
        );
        assert!(writer.ready());
        let FileOutcome::Complete(reply) = writer.run() else {
            panic!("writer observes the published seal");
        };
        assert!(matches!(reply.result, Err(Errno(1))));
    }
}
