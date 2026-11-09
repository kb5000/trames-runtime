// SPDX-License-Identifier: GPL-3.0-or-later
//! Original mapped-file mutations, driven by existing execution slots. This
//! resource owns accepted work across executor changes; it runs no thread.
use crate::{FileExecutor, FileResult, HostFileTask};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};
use trames_memory::layout::{Layout, LayoutWrite};
use trames_shared::{IoSignal, IoSubscription, IoWake};
use trames_vfs::FileWork;

pub struct FileLayouts {
    state: Mutex<State>,
    executor: Arc<dyn FileExecutor>,
    driver: Mutex<Option<Weak<IoSignal>>>,
    owner: std::sync::OnceLock<Arc<IoSignal>>,
}
#[derive(Default)]
struct State {
    next: u64,
    live: BTreeSet<u64>,
    ready: BTreeSet<u64>,
    pending: BTreeMap<u64, FileLayoutRequest>,
}
struct Wake {
    owner: Weak<FileLayouts>,
    id: u64,
}
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        if let Some(owner) = self.owner.upgrade() {
            let mut state = owner.state.lock().unwrap();
            if !state.live.contains(&self.id) {
                return;
            }
            state.ready.insert(self.id);
            drop(state);
            owner.notify();
        }
    }
}
pub struct FileLayoutRequest {
    id: u64,
    work: LayoutWork,
    ticket: Option<LayoutWrite>,
    pub signal: Arc<IoSignal>,
    _wake: Arc<Wake>,
    _layout: IoSubscription,
    waits: Vec<IoSubscription>,
}
#[allow(clippy::large_enum_variant)] // Preserve inline ordinary file jobs; only cold host work allocates.
enum LayoutWork {
    File(FileWork, Arc<FileResult>),
    Host(Box<dyn HostFileTask>),
}
impl LayoutWork {
    fn fail(self, errno: u32) {
        match self {
            Self::File(_, result) => result.fail(errno),
            Self::Host(work) => work.fail(),
        }
    }
}
impl FileLayoutRequest {
    pub fn layout(&self) -> &Arc<Layout> {
        self.ticket.as_ref().expect("accepted layout").layout()
    }
    /// Resource subscriptions survive epoch cancellation. Subscribe before
    /// retrying original task/mm admission, then retain here if still busy.
    pub fn retain_wait(&mut self, subscription: IoSubscription) {
        self.waits.push(subscription);
    }
}
pub struct FileLayoutDriver {
    layouts: Arc<FileLayouts>,
    pub signal: Arc<IoSignal>,
}
impl FileLayoutDriver {
    pub fn take_ready(&self) -> Vec<FileLayoutRequest> {
        let current = self.layouts.driver.lock().unwrap();
        if !current
            .as_ref()
            .is_some_and(|weak| weak.ptr_eq(&Arc::downgrade(&self.signal)))
        {
            return Vec::new();
        }
        self.signal.reset();
        let requests = self.layouts.take_ready();
        drop(current);
        requests
    }
}
impl Drop for FileLayoutDriver {
    fn drop(&mut self) {
        let mut driver = self.layouts.driver.lock().unwrap();
        if driver
            .as_ref()
            .is_some_and(|weak| weak.ptr_eq(&Arc::downgrade(&self.signal)))
        {
            *driver = None;
            drop(driver);
            if self.layouts.has_ready() {
                self.layouts.notify();
            }
        }
    }
}
impl FileLayouts {
    pub fn new(executor: Arc<dyn FileExecutor>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::default(),
            executor,
            driver: Mutex::default(),
            owner: Default::default(),
        })
    }
    pub fn bind_owner(&self, signal: Arc<IoSignal>) {
        let _ = self.owner.set(signal);
    }
    pub fn bind_reader(self: &Arc<Self>, signal: Arc<IoSignal>) -> FileLayoutDriver {
        *self.driver.lock().unwrap() = Some(Arc::downgrade(&signal));
        if self.has_ready() {
            signal.notify();
        }
        FileLayoutDriver {
            layouts: self.clone(),
            signal,
        }
    }
    fn notify(&self) {
        let driver = self.driver.lock().unwrap().as_ref().and_then(Weak::upgrade);
        if let Some(signal) = driver.or_else(|| self.owner.get().cloned()) {
            signal.notify();
        }
    }
    fn has_ready(&self) -> bool {
        !self.state.lock().unwrap().ready.is_empty()
    }
    pub fn pending(&self) -> bool {
        !self.state.lock().unwrap().live.is_empty()
    }
    /// Enqueue only an already-accepted layout boundary. Neither FD lookup nor
    /// guest input import is repeated. A non-file fallback retains its work.
    #[allow(clippy::result_large_err)] // Return ownership without a fallback-only allocation.
    pub fn submit(
        self: &Arc<Self>,
        work: FileWork,
        result: Arc<FileResult>,
    ) -> Result<(), FileWork> {
        let Some(ticket) = work.begin_layout() else {
            return Err(work);
        };
        result.begin();
        self.enqueue(ticket, LayoutWork::File(work, result));
        Ok(())
    }
    /// Host byte consumers share original mapped-backing admission. Ordinary
    /// imports/timezone updates have no layout dependency and use the pool
    /// directly. No execution slot is retained by either kind of host job.
    pub fn submit_host(self: &Arc<Self>, work: Box<dyn HostFileTask>) {
        if let Some(layout) = work.layout() {
            self.enqueue(layout.write(), LayoutWork::Host(work));
        } else {
            self.executor.submit_host(work, None);
        }
    }
    fn enqueue(self: &Arc<Self>, ticket: LayoutWrite, work: LayoutWork) {
        let id = {
            let mut state = self.state.lock().unwrap();
            let id = state.next;
            state.next = state.next.wrapping_add(1);
            assert!(state.live.insert(id));
            id
        };
        let wake = Arc::new(Wake {
            owner: Arc::downgrade(self),
            id,
        });
        let target: Arc<dyn IoWake> = wake.clone();
        let signal = IoSignal::new(0, Arc::downgrade(&target));
        let subscription = ticket.layout().subscribe(&signal);
        let request = FileLayoutRequest {
            id,
            work,
            ticket: Some(ticket),
            signal,
            _wake: wake,
            _layout: subscription,
            waits: Vec::new(),
        };
        let mut state = self.state.lock().unwrap();
        assert!(state.pending.insert(id, request).is_none());
        state.ready.insert(id);
        drop(state);
        self.notify();
    }
    pub fn take_owner(&self) -> Vec<FileLayoutRequest> {
        let driver = self.driver.lock().unwrap();
        if driver.as_ref().and_then(Weak::upgrade).is_some() {
            return Vec::new();
        }
        if let Some(signal) = self.owner.get() {
            signal.reset();
        }
        let requests = self.take_ready();
        drop(driver);
        requests
    }
    fn take_ready(&self) -> Vec<FileLayoutRequest> {
        let mut state = self.state.lock().unwrap();
        let mut requests = Vec::new();
        for id in std::mem::take(&mut state.ready) {
            if let Some(request) = state.pending.remove(&id) {
                request.signal.reset();
                requests.push(request);
            }
        }
        drop(state);
        for request in &mut requests {
            request.waits.clear();
        }
        requests
    }
    pub fn restore(&self, request: FileLayoutRequest) {
        let id = request.id;
        let mut state = self.state.lock().unwrap();
        assert!(state.live.contains(&id));
        let ready = request.signal.ready() || state.ready.contains(&id);
        assert!(state.pending.insert(id, request).is_none());
        if ready {
            state.ready.insert(id);
        }
        drop(state);
        if ready {
            self.notify();
        }
    }
    /// Success transfers the original ticket through native completion. While
    /// waiting, the caller parks the request and gives its CPU slot back.
    #[allow(clippy::result_large_err)] // The pending map owns this request by value on every retry.
    pub fn try_submit(&self, mut request: FileLayoutRequest) -> Result<(), FileLayoutRequest> {
        let ticket = request.ticket.take().expect("one accepted mutation");
        let exclusive = match ticket.try_enter() {
            Ok(exclusive) => exclusive,
            Err(ticket) => {
                request.ticket = Some(ticket);
                return Err(request);
            }
        };
        self.finish(request.id);
        match request.work {
            LayoutWork::File(work, result) => {
                result.begin();
                self.executor
                    .submit_file(work.enter_layout(exclusive), result);
            }
            LayoutWork::Host(work) => self.executor.submit_host(work, Some(exclusive)),
        }
        Ok(())
    }
    pub fn fail(&self, request: FileLayoutRequest, errno: u32) {
        self.finish(request.id);
        request.work.fail(errno);
    }
    fn finish(&self, id: u64) {
        let mut state = self.state.lock().unwrap();
        assert!(state.live.remove(&id));
        state.ready.remove(&id);
    }
}
