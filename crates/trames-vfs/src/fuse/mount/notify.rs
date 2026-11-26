// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted reverse notifications, executed under the original inode layout.
use super::*;
use std::sync::Mutex;
use trames_memory::{MemoryError, SyncCompletion, SyncResource};
#[cfg(test)]
#[path = "../notification_tests.rs"]
mod tests;

enum Change {
    Inode(i64, i64),
    Entry {
        name: Vec<u8>,
        child: u64,
        expire_only: bool,
    },
    Store(u64, Vec<u8>),
    Retrieve(u64, u64, usize),
}
pub(super) struct Notification {
    _usage: Option<Arc<ConnectionUse>>,
    fs: Arc<Mounted>,
    node: NodeRef,
    id: u64,
    caller: Caller,
    change: Change,
    detach: Option<mounts::Invalidate>,
    state: Arc<Mutex<State>>,
}
#[derive(Default)]
struct State {
    started: bool,
    flushed: Option<Result<()>>,
    selected: Option<(Arc<Entry>, NodeRef)>,
    detached: bool,
    result: Option<Result<()>>,
    child: Option<inode::Write>,
    child_wait: Option<inode::WriteWait>,
    parent: Option<inode::Write>,
    parent_wait: Option<inode::WriteWait>,
    waiting: Option<Waiting>,
    retry: Option<RetryWait>,
}
#[derive(Clone)]
enum Waiting {
    Namespace(Arc<mounts::admin::Admin>),
    Inode(Arc<inode::Attr>),
}
impl Waiting {
    fn ready(&self) -> bool {
        match self {
            Self::Namespace(admin) => admin.ready(),
            Self::Inode(attr) => attr.write_ready(),
        }
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        match self {
            Self::Namespace(admin) => admin.subscribe(signal),
            Self::Inode(attr) => attr.subscribe_write(signal),
        }
    }
}
struct RetryWait {
    retry: Arc<Retry>,
    _signal: Arc<IoSignal>,
    _subscription: IoSubscription,
}
struct Retry(Mutex<Option<Box<dyn SyncCompletion>>>);
impl IoWake for Retry {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        let completion = self.0.lock().unwrap().take();
        if let Some(completion) = completion {
            completion.retry();
        }
    }
}
struct Flushed {
    state: Arc<Mutex<State>>,
    completion: Box<dyn SyncCompletion>,
}
impl SyncCompletion for Flushed {
    fn complete(self: Box<Self>, result: std::result::Result<(), MemoryError>) {
        self.state.lock().unwrap().flushed = Some(result.map_err(|error| match error {
            MemoryError::BackingIo(code) => Errno(code),
            _ => Errno(5),
        }));
        self.completion.retry();
    }
}
impl SyncResource for Notification {
    fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        Some(inode::attr(&self.node).layout.clone())
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        Err(MemoryError::BackingIo(95))
    }
    fn failed(&self, error: MemoryError) {
        let (retry, child, parent, child_wait, parent_wait) = {
            let mut state = self.state.lock().unwrap();
            if state.result.is_some() {
                return;
            }
            state.result = Some(Err(match error {
                MemoryError::BackingIo(code) => Errno(code),
                _ => Errno(5),
            }));
            state.waiting = None;
            (
                state.retry.take(),
                state.child.take(),
                state.parent.take(),
                state.child_wait.take(),
                state.parent_wait.take(),
            )
        };
        if let Some(retry) = retry {
            let completion = retry.retry.0.lock().unwrap().take();
            if let Some(completion) = completion {
                completion.complete(Err(error));
            }
        }
        drop(child_wait);
        drop(child);
        drop(parent_wait);
        drop(parent);
    }
    fn sync_async(
        &self,
        completion: Box<dyn SyncCompletion>,
    ) -> std::result::Result<(), Box<dyn SyncCompletion>> {
        let attr = inode::attr(&self.node);
        let mut state = self.state.lock().unwrap();
        let old_retry = state.retry.take();
        drop(state);
        drop(old_retry);
        let mut state = self.state.lock().unwrap();
        if let Some(result) = state.result {
            drop(state);
            completion.complete(result.map_err(|error| MemoryError::BackingIo(error.0)));
            return Ok(());
        }
        if !state.started {
            state.started = true;
            if matches!(self.change, Change::Inode(offset, _) if offset >= 0) && attr.cache.dirty()
            {
                let writer = attr.cache.writer();
                drop(state);
                if let Some(writer) = writer {
                    writer.flush_with(
                        self.caller,
                        Box::new(Flushed {
                            state: self.state.clone(),
                            completion,
                        }),
                    );
                } else {
                    completion.complete(Err(MemoryError::BackingIo(5)));
                }
                return Ok(());
            }
        }
        let flushed = state.flushed.take();
        drop(state);
        if matches!(self.change, Change::Entry { .. }) {
            match self.progress_entry() {
                Some(result) => {
                    completion.complete(result.map_err(|error| MemoryError::BackingIo(error.0)))
                }
                None => self.park(completion),
            }
            return Ok(());
        }
        let result = self.apply().and(flushed.unwrap_or(Ok(())));
        self.state.lock().unwrap().result = Some(result);
        completion.complete(result.map_err(|error| MemoryError::BackingIo(error.0)));
        Ok(())
    }
}
impl Notification {
    pub(super) fn ready(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .waiting
            .as_ref()
            .is_none_or(Waiting::ready)
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> Option<IoSubscription> {
        self.state
            .lock()
            .unwrap()
            .waiting
            .as_ref()
            .map(|waiting| waiting.subscribe(signal))
    }
    fn park(&self, completion: Box<dyn SyncCompletion>) {
        let waiting = self
            .state
            .lock()
            .unwrap()
            .waiting
            .as_ref()
            .expect("original inode or namespace admission")
            .clone();
        let retry = Arc::new(Retry(Mutex::new(Some(completion))));
        let target: Arc<dyn IoWake> = retry.clone();
        let signal = IoSignal::new(0, Arc::downgrade(&target));
        let subscription = waiting.subscribe(&signal);
        self.state.lock().unwrap().retry = Some(RetryWait {
            retry,
            _signal: signal.clone(),
            _subscription: subscription,
        });
        if waiting.ready() {
            signal.notify();
        }
    }
    pub(super) fn progress_entry(&self) -> Option<Result<()>> {
        let result = self.entry_attempt()?;
        let (child, parent, child_wait, parent_wait) = {
            let mut state = self.state.lock().unwrap();
            state.result = Some(result);
            state.waiting = None;
            (
                state.child.take(),
                state.parent.take(),
                state.child_wait.take(),
                state.parent_wait.take(),
            )
        };
        drop(child_wait);
        drop(child);
        drop(parent_wait);
        drop(parent);
        Some(result)
    }
    fn entry_attempt(&self) -> Option<Result<()>> {
        let Change::Entry {
            name,
            child,
            expire_only,
        } = &self.change
        else {
            unreachable!()
        };
        {
            let state = self.state.lock().unwrap();
            if let Some(result) = state.result {
                return Some(result);
            }
        }
        if let Err(error) = self
            .fs
            .connection
            .init_result()
            .and_then(|()| inode::attr(&self.node).check())
        {
            return Some(Err(error));
        }
        {
            let mut state = self.state.lock().unwrap();
            if state.parent.is_none() {
                let attr = inode::attr(&self.node);
                let Some(parent) = attr.enter_write(&mut state.parent_wait) else {
                    state.waiting = Some(Waiting::Inode(attr.clone()));
                    return None;
                };
                state.parent = Some(parent);
                state.waiting = None;
            }
        }
        if !self.node.directory {
            return Some(Err(Errno(20)));
        }
        let selected = self.state.lock().unwrap().selected.clone();
        let (entry, node) = match selected {
            Some(selected) => selected,
            None => {
                let selected = match self.fs.entries.notification(&self.node, name, *expire_only) {
                    Ok(selected) => selected,
                    Err(error) => return Some(Err(error)),
                };
                self.fs.inode_changed(&self.node);
                self.state.lock().unwrap().selected = Some(selected.clone());
                selected
            }
        };
        let detached = self.state.lock().unwrap().detached;
        if !*expire_only && !detached {
            let detach = self
                .detach
                .as_ref()
                .expect("original mount namespace resources");
            if let Err(admin) = detach.run(&entry) {
                self.state.lock().unwrap().waiting = Some(Waiting::Namespace(admin));
                return None;
            }
            detach.reap();
            let mut state = self.state.lock().unwrap();
            state.detached = true;
            state.waiting = None;
        }
        if *child == 0 {
            return Some(Ok(()));
        }
        {
            let mut state = self.state.lock().unwrap();
            if state.child.is_none() {
                let attr = inode::attr(&node);
                let Some(child) = attr.enter_write(&mut state.child_wait) else {
                    state.waiting = Some(Waiting::Inode(attr.clone()));
                    return None;
                };
                state.child = Some(child);
                state.waiting = None;
            }
        }
        let id = node
            .fuse_directory
            .get()
            .map(|directory| directory.node)
            .or_else(|| node.fuse_leaf.get().map(|leaf| leaf.node));
        if id != Some(*child) {
            return Some(Err(Errno(2)));
        }
        if let Some(directory) = node.fuse_directory.get() {
            if self.fs.entries.has_children(&node) {
                return Some(Err(Errno(39)));
            }
            let _ = node.removed_directory_parent.set(self.node.clone());
            directory.unlink();
        }
        node.borrow_mut().links = 0;
        let attr = inode::attr(&node);
        let mut data = attr.lock().unwrap();
        data[64..68].copy_from_slice(&0u32.to_le_bytes());
        data.version = self.fs.connection.next_attr_version();
        drop(data);
        attr.validity.set(0, 0);
        Some(Ok(()))
    }
    fn apply(&self) -> Result<()> {
        self.fs.connection.init_result()?;
        let attr = inode::attr(&self.node);
        attr.check()?;
        match &self.change {
            Change::Inode(offset, length) => {
                self.fs.notify_original_inode(&self.node, *offset, *length)
            }
            Change::Entry { .. } => unreachable!("retained entry notification"),
            Change::Store(offset, bytes) => {
                let mut data = attr.lock().unwrap();
                let size = u64::from_le_bytes(data[8..16].try_into().unwrap())
                    .max(*offset + bytes.len() as u64);
                data[8..16].copy_from_slice(&size.to_le_bytes());
                data.version = self.fs.connection.next_attr_version();
                drop(data);
                attr.validity.set(0, 0);
                attr.cache.store(*offset, bytes, size);
                Ok(())
            }
            Change::Retrieve(cookie, offset, count) => {
                let size = u64::from_le_bytes(attr.lock().unwrap()[8..16].try_into().unwrap());
                let page_limit = 32 * trames_memory::PAGE_SIZE as usize
                    - (*offset % trames_memory::PAGE_SIZE) as usize;
                let count = (*count)
                    .min(self.fs.connection.data_limit())
                    .min(page_limit)
                    .min(size.saturating_sub(*offset) as usize);
                let bytes = attr.cache.retrieve(*offset, count);
                let mut body = vec![0; 40];
                body[8..16].copy_from_slice(&offset.to_le_bytes());
                body[16..20].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
                body.extend_from_slice(&bytes);
                self.fs
                    .connection
                    .notify_reply(*cookie, self.id, self.caller, &body)
            }
        }
    }
}
pub(crate) fn prepare(
    v: &Vfs,
    connection: &Arc<Connection>,
    bytes: &[u8],
) -> Result<Option<Metadata>> {
    if bytes.len() < 16 || bytes[8..16] != [0; 8] {
        return Ok(None);
    }
    if u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize != bytes.len() {
        return Err(Errno(22));
    }
    let fs = connection.mounted().ok_or(Errno(2))?;
    let body = &bytes[16..];
    let code = i32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let u64_at = |at| u64::from_le_bytes(body[at..at + 8].try_into().unwrap());
    let (id, change) = match code {
        2 if body.len() == 24 => (
            u64_at(0),
            Change::Inode(u64_at(8) as i64, u64_at(16) as i64),
        ),
        3 | 6 if body.len() >= if code == 3 { 16 } else { 24 } => {
            let at = if code == 3 { 8 } else { 16 };
            let len = u32::from_le_bytes(body[at..at + 4].try_into().unwrap()) as usize;
            let header = at + 8;
            // FUSE_NAME_MAX is 1024, distinct from a filesystem's NAME_MAX.
            // Native checks this limit before checking the full packet size.
            if len > 1024 {
                return Err(Errno(36));
            }
            if body.len() != header + len + 1 {
                return Err(Errno(22));
            }
            let name = &body[header..header + len];
            (
                u64_at(0),
                Change::Entry {
                    name: name.to_vec(),
                    child: if code == 6 { u64_at(8) } else { 0 },
                    expire_only: code == 3
                        && u32::from_le_bytes(body[12..16].try_into().unwrap()) & 1 != 0,
                },
            )
        }
        4 if body.len() >= 24 => {
            let len = u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize;
            let offset = u64_at(8);
            if body.len() != 24 + len
                || offset
                    .checked_add(len as u64)
                    .is_none_or(|end| end > i64::MAX as u64)
            {
                return Err(Errno(22));
            }
            (u64_at(0), Change::Store(offset, body[24..].to_vec()))
        }
        5 if body.len() == 32 => (
            u64_at(8),
            Change::Retrieve(
                u64_at(0),
                u64_at(16),
                u32::from_le_bytes(body[24..28].try_into().unwrap()) as usize,
            ),
        ),
        _ => return Err(Errno(22)),
    };
    let node = fs.attribute_target(id).ok_or(Errno(2))?;
    if let Change::Store(offset, bytes) = &change {
        let attr = inode::attr(&node);
        attr.cache.reserve_store(attr, *offset, bytes.len())?;
    }
    let is_entry = matches!(change, Change::Entry { .. });
    let resource = Arc::new(Notification {
        _usage: fs.usage(),
        node,
        id,
        caller: fs.caller(v),
        fs: fs.clone(),
        change,
        detach: is_entry.then(|| mounts::Invalidate::capture(v)),
        state: Arc::default(),
    });
    let executor =
        crate::file_actor::sync_executor().or_else(|| inode::attr(&resource.node).cache.executor());
    let kind = if let Some(executor) = executor {
        ResultKind::Device(
            writeback::submit(resource.clone(), &executor),
            bytes.len() as u64,
        )
    } else {
        // Synchronous embeddings can update an unmapped cache inline. Live
        // mappings require the original layout executor before any mutation.
        let cache = &inode::attr(&resource.node).cache;
        if cache.mapped() || cache.dirty() {
            return Err(Errno(95));
        }
        if is_entry {
            ResultKind::Notification(resource, bytes.len() as u64)
        } else {
            ResultKind::Device(
                writeback::Pending::completed(resource.apply()),
                bytes.len() as u64,
            )
        }
    };
    Ok(Some(Metadata {
        request: None,
        kind,
        _usage: None,
        resolved: None,
        resolved_entry: None,
        reference: None,
        open: None,
        mount: StatMount {
            id: 0,
            is_root: false,
            mounted: false,
        },
        dev: 0,
        owner_ns: fs.namespace.clone(),
        reader_ns: v.credentials.user_namespace.clone(),
        retry: None,
    }))
}
