// SPDX-License-Identifier: GPL-3.0-or-later
//! Negotiated buffered IO retains original inode pages across daemon waits.
use super::*;
use trames_memory::{MemoryError, PAGE_SIZE};

pub(super) struct Io {
    pub(super) result: FileResult,
    reads: Vec<cache::Read>,
    prepared: bool,
    caller: Caller,
    count: usize,
}
impl Io {
    pub(super) fn enabled(result: &FileResult) -> bool {
        matches!(
            result,
            FileResult::Read {
                buffered: Some(_),
                ..
            } | FileResult::Write {
                buffered: Some(_),
                ..
            }
        )
    }
    pub(super) fn wrap(result: FileResult, caller: Caller) -> ResultKind {
        // A full resident hit is already an accepted, bounded output snapshot.
        // Retain it rather than allocate and read those pages a second time.
        if matches!(
            &result,
            FileResult::Read {
                cached: Some(_),
                ..
            }
        ) {
            ResultKind::File(result)
        } else if Self::enabled(&result) {
            ResultKind::Buffered(Box::new(Self {
                result,
                reads: Vec::new(),
                prepared: false,
                caller,
                count: 0,
            }))
        } else {
            ResultKind::File(result)
        }
    }
    pub(super) fn ready(&self) -> bool {
        self.reads.iter().all(|read| read.result().is_some())
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> Option<IoSubscription> {
        self.reads.iter().find_map(|read| match read {
            cache::Read::Pending(read) if !read.wait.ready() => {
                Some(read.wait.subscribe_completion(signal))
            }
            _ => None,
        })
    }
    fn prepare(&mut self) -> Result<()> {
        let (file, original, start, count, write) = match &self.result {
            FileResult::Write {
                file,
                buffered: Some(writer),
                start,
                max,
                ..
            } => (file, writer.original(), *start, *max, true),
            FileResult::Read {
                file,
                buffered: Some(original),
                start,
                max,
                ..
            } => (file, original, *start, *max, false),
            _ => unreachable!("negotiated buffered IO"),
        };
        let size = u64::from_le_bytes(file.attr.lock().unwrap()[8..16].try_into().unwrap());
        let count = if write {
            count
        } else {
            count.min(size.saturating_sub(start) as usize)
        };
        if count != 0 && !write {
            self.reads = file
                .attr
                .cache
                .read_pages_as(file, original, start, count, self.caller)
                .map_err(|error| match error {
                    MemoryError::BackingIo(code) => Errno(code),
                    _ => Errno(12),
                })?;
        } else if count != 0 {
            for index in start / PAGE_SIZE..=(start + count as u64 - 1) / PAGE_SIZE {
                let read = file.attr.cache.prepare_write(
                    file,
                    original,
                    index,
                    (start, start + count as u64),
                    size,
                    self.caller,
                );
                self.reads.push(read.map_err(|error| match error {
                    MemoryError::BackingIo(code) => Errno(code),
                    _ => Errno(12),
                })?);
            }
        }
        self.prepared = true;
        self.count = count;
        Ok(())
    }
    pub(super) fn take(&mut self) -> Option<Result<FileValue>> {
        if !self.prepared {
            if let Err(error) = self.prepare() {
                return Some(Err(error));
            }
        }
        for read in &self.reads {
            if let Err(error) = read.result()? {
                return Some(Err(error));
            }
        }
        let reply = match &self.result {
            FileResult::Read {
                file, start, max, ..
            } => {
                let size = u64::from_le_bytes(file.attr.lock().unwrap()[8..16].try_into().unwrap());
                let count = (*max)
                    .min(self.count)
                    .min(size.saturating_sub(*start) as usize);
                // Read from the accepted pages even if a notification retired
                // their current cache identities while the daemon was replying.
                if let Some(bytes) = cache::Read::take_reply(&self.reads, *start, count) {
                    bytes
                } else {
                    let mut bytes = vec![0; count];
                    let mut done = 0;
                    for read in &self.reads {
                        let at = ((*start + done as u64) % PAGE_SIZE) as usize;
                        let n = (count - done).min(PAGE_SIZE as usize - at);
                        if let Err(error) = read.copy_to(at, &mut bytes[done..done + n]) {
                            return Some(Err(error));
                        }
                        done += n;
                        if done == count {
                            break;
                        }
                    }
                    bytes
                }
            }
            FileResult::Write {
                file,
                input,
                start,
                max,
                ..
            } => {
                file.attr.cache.buffered_write(*start, &input[..*max]);
                file.attr.modified(&file.reference.fs);
                let mut reply = vec![0; 8];
                reply[..4].copy_from_slice(&(*max as u32).to_le_bytes());
                reply
            }
            _ => unreachable!(),
        };
        if let FileResult::Read { max, .. } = &mut self.result {
            // The common mmap overlay must obey this accepted read's bound;
            // a later extension cannot turn its zero-filled tail into output.
            *max = reply.len();
        }
        let result = self.result.finish(Ok(reply));
        if let FileResult::Write {
            file,
            buffered: Some(writer),
            _transaction,
            sync,
            start,
            max,
            ..
        } = &mut self.result
        {
            let pressure = ((*start % PAGE_SIZE + *max as u64).div_ceil(PAGE_SIZE)) * PAGE_SIZE;
            let accumulated = file
                .attr
                .cache
                .buffered_pressure
                .fetch_add(pressure, Ordering::Relaxed)
                + pressure;
            let limit = (file.reference.fs.connection.data_limit() as u64 * 8).min(1024 * 1024);
            // Publication is complete. Background work uses the existing
            // executor and reacquires inode/layout admission independently.
            _transaction.take();
            if sync.is_none() && result.is_ok() && accumulated >= limit {
                writeback::background_data(writer);
            }
        }
        Some(result)
    }
}
