// SPDX-License-Identifier: GPL-3.0-or-later
//! One bounded READ for adjacent cold pages, with independently retained users.
use super::*;

pub(super) struct Batch {
    this: Weak<Self>,
    file: Arc<File>,
    members: Vec<Weak<ReadWave>>,
    offset: u64,
    count: usize,
    executor: Option<Arc<dyn trames_memory::SyncExecutor>>,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    request: Option<Request>,
    done: bool,
    output: Option<Vec<u8>>,
}
impl Cache {
    pub(in crate::fuse::mount) fn read_pages_as(
        &self,
        file: &Arc<File>,
        original: &SharedFd,
        offset: u64,
        count: usize,
        caller: Caller,
    ) -> std::result::Result<Vec<Read>, MemoryError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        file.attr
            .check()
            .map_err(|error| MemoryError::BackingIo(error.0))?;
        let first = offset / PAGE_SIZE;
        let last = (offset + count as u64 - 1) / PAGE_SIZE;
        let pages: Vec<_> = {
            let mut cache = self.pages.lock().unwrap();
            (first..=last)
                .map(|index| (index, Self::page_locked(&mut cache, index)))
                .collect()
        };
        let mut reads = Vec::with_capacity(pages.len());
        let mut groups: Vec<Vec<Arc<ReadWave>>> = Vec::new();
        let limit = (file.reference.fs.connection.data_limit() / PAGE_SIZE as usize).max(1);
        for (index, page) in pages {
            let mut state = page.state.lock().unwrap();
            if state.valid {
                reads.push(Read::Ready(page.clone()));
                continue;
            }
            if let Some(read) = state.reading.upgrade().filter(|read| !read.wait.ready()) {
                reads.push(Read::Pending(read));
                continue;
            }
            page.owners.reserve_cache()?;
            let read = Arc::new_cyclic(|this| ReadWave {
                this: this.clone(),
                executor: crate::file_actor::sync_executor().or_else(|| self.executor()),
                page: page.clone(),
                _original: original.clone(),
                file: file.clone(),
                offset: index * PAGE_SIZE,
                count: (PAGE_SIZE.min(i64::MAX as u64 - index * PAGE_SIZE)) as usize,
                attr_version: file.reference.fs.connection.current_attr_version(),
                page_generation: state.generation,
                wait: Arc::default(),
                state: Mutex::default(),
            });
            state.reading = Arc::downgrade(&read);
            if groups.last().is_none_or(|group| {
                group.len() == limit || group.last().unwrap().offset + PAGE_SIZE != read.offset
            }) {
                groups.push(Vec::new());
            }
            groups.last_mut().unwrap().push(read.clone());
            reads.push(Read::Pending(read));
        }
        // All page ownership is published before any daemon can reply. No
        // cache/page lock is held while requests or reply callbacks run.
        for group in groups {
            Batch::start(group, caller);
        }
        Ok(reads)
    }
}
impl Batch {
    pub(super) fn take_reply(
        &self,
        first: u64,
        pages: usize,
        offset: u64,
        count: usize,
    ) -> Option<Vec<u8>> {
        if first != self.offset || pages != self.members.len() || offset < self.offset {
            return None;
        }
        let start = (offset - self.offset) as usize;
        if start.checked_add(count)? > self.count {
            return None;
        }
        let mut bytes = self.state.lock().unwrap().output.take()?;
        if start != 0 {
            bytes.copy_within(start..start + count, 0);
        }
        bytes.truncate(count);
        Some(bytes)
    }
    fn start(members: Vec<Arc<ReadWave>>, caller: Caller) {
        let first = &members[0];
        let batch = Arc::new_cyclic(|this| Self {
            this: this.clone(),
            file: first.file.clone(),
            offset: first.offset,
            count: (members.len() * PAGE_SIZE as usize)
                .min((i64::MAX as u64 - first.offset) as usize),
            executor: first.executor.clone(),
            members: members.iter().map(Arc::downgrade).collect(),
            state: Mutex::default(),
        });
        for member in &members {
            member.state.lock().unwrap()._batch = Some(batch.clone());
        }
        let mut body = [0; 40];
        body[..8].copy_from_slice(&batch.file.fh.unwrap_or(0).to_le_bytes());
        body[8..16].copy_from_slice(&batch.offset.to_le_bytes());
        body[16..20].copy_from_slice(&(batch.count as u32).to_le_bytes());
        body[32..36].copy_from_slice(&batch.file.current_flags().to_le_bytes());
        let receiver: Arc<dyn transport::ReplyReceiver> = batch.clone();
        let request = batch.file.reference.fs.connection.request_received(
            15,
            batch.file.reference.node,
            caller,
            &body,
            Arc::downgrade(&receiver),
        );
        match request {
            Ok(request) => {
                let mut state = batch.state.lock().unwrap();
                if !state.done {
                    state.request = Some(request);
                } else {
                    drop(state);
                    drop(request);
                }
            }
            Err(error) => receiver.complete(Err(error)),
        }
    }
    fn publish(&self, result: Result<Vec<u8>>) {
        let request = {
            let mut state = self.state.lock().unwrap();
            if state.done {
                return;
            }
            state.done = true;
            state.request.take()
        };
        let result = result.and_then(|bytes| {
            if bytes.len() <= self.count {
                Ok(bytes)
            } else {
                Err(Errno(5))
            }
        });
        let mut compatible = true;
        let mut published = 0;
        for member in self.members.iter().filter_map(Weak::upgrade) {
            let start = (member.offset - self.offset) as usize;
            let reply = result
                .as_ref()
                .map(|bytes| {
                    let start = start.min(bytes.len());
                    &bytes[start..(start + PAGE_SIZE as usize).min(bytes.len())]
                })
                .map_err(|error| *error);
            compatible &= member.publish_bytes(reply);
            published += 1;
        }
        if compatible && published == self.members.len() {
            if let Ok(mut bytes) = result {
                bytes.resize(self.count, 0);
                self.state.lock().unwrap().output = Some(bytes);
            }
        }
        drop(request);
    }
}
impl Drop for Batch {
    fn drop(&mut self) {
        // Cancel the original request before retiring the last retained FH.
        let request = self.state.get_mut().unwrap().request.take();
        drop(request);
    }
}
struct Publish {
    batch: Arc<Batch>,
    result: Mutex<Option<Result<Vec<u8>>>>,
}
impl trames_memory::SyncResource for Publish {
    fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        Some(self.batch.file.attr.layout.clone())
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        if let Some(result) = self.result.lock().unwrap().take() {
            self.batch.publish(result);
        }
        Ok(())
    }
}
struct Published(Arc<Batch>);
impl trames_memory::SyncCompletion for Published {
    fn complete(self: Box<Self>, result: std::result::Result<(), MemoryError>) {
        if result.is_err() {
            self.0.publish(Err(Errno(5)));
        }
    }
}
impl transport::ReplyReceiver for Batch {
    fn complete(&self, result: Result<Vec<u8>>) {
        if let Some(executor) = self
            .executor
            .as_ref()
            .filter(|_| self.file.attr.cache.mapped())
        {
            if let Some(batch) = self.this.upgrade() {
                executor.submit(
                    Arc::new(Publish {
                        batch: batch.clone(),
                        result: Mutex::new(Some(result)),
                    }),
                    Box::new(Published(batch)),
                );
                return;
            }
        }
        self.publish(result);
    }
}
