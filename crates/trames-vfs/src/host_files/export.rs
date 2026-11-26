// SPDX-License-Identifier: GPL-3.0-or-later
//! One accepted export, retaining both sides and their actual byte progress.
use super::*;

pub struct HostExportWork<W> {
    original: HostExport,
    writer: W,
    resources: CgroupResourceContext,
    offset: u64,
    buffer: Vec<u8>,
    written: usize,
    wait: Option<Arc<trames_memory::PageWait>>,
    eof: bool,
    done: bool,
}

#[cfg(test)]
#[path = "export_tests.rs"]
mod tests;
impl HostExport {
    pub fn into_work<W: Write>(self, writer: W) -> HostExportWork<W> {
        HostExportWork {
            original: self,
            writer,
            resources: CgroupResourceContext::capture(),
            offset: 0,
            buffer: Vec::new(),
            written: 0,
            wait: None,
            eof: false,
            done: false,
        }
    }
}
impl<W: Write> HostExportWork<W> {
    pub fn layout(&self) -> Arc<trames_memory::layout::Layout> {
        self.original.layout()
    }
    pub fn wait(&self) -> Option<&Arc<trames_memory::PageWait>> {
        self.wait.as_ref()
    }
    pub(super) fn writer(&self) -> &W {
        &self.writer
    }
    pub fn into_writer(self) -> W {
        assert!(self.done, "export writer is complete");
        self.writer
    }
    /// The original backing is admitted anew after each resource wait. The
    /// request retains no node/data/layout guard while the executor is parked.
    pub fn run(
        &mut self,
        admission: &trames_memory::layout::LayoutExclusive,
        cancelled: impl Fn() -> bool,
    ) -> Result<Option<u64>> {
        assert!(!self.done, "completed export");
        assert!(
            Arc::ptr_eq(&self.layout(), admission.layout()),
            "original export admission"
        );
        if cancelled() {
            return Err(Errno(4));
        }
        if self.wait.as_ref().is_some_and(|wait| !wait.ready()) {
            return Ok(None);
        }
        let _resumed = self.wait.take();
        let _resources = self.resources.enter();
        loop {
            if cancelled() {
                return Err(Errno(4));
            }
            if self.written == self.buffer.len() {
                self.buffer.clear();
                self.written = 0;
                if self.eof {
                    break;
                }
                let scope = resource_io::Scope::enter();
                let result = {
                    let node = self.original.node.borrow();
                    let Content::File(data) = &node.content else {
                        return Err(Errno(21));
                    };
                    if self.offset >= data.len() {
                        self.eof = true;
                        Ok(Vec::new())
                    } else {
                        // At most one page per legacy read: a later cache miss
                        // cannot discard an earlier, already-issued IO prefix.
                        let count = trames_memory::PAGE_SIZE as usize
                            - (self.offset % trames_memory::PAGE_SIZE) as usize;
                        data.read_at(self.offset, count)
                    }
                };
                let pending = scope.finish();
                match result {
                    Ok(bytes) => self.buffer = bytes,
                    Err(_) if pending.is_some() => {}
                    Err(error) => return Err(error),
                }
                if let Some(pending) = pending {
                    self.wait = Some(pending.wait);
                    return Ok(None);
                }
                if self.buffer.is_empty() {
                    if self.eof {
                        break;
                    }
                    return Err(Errno(5));
                }
            }
            let scope = resource_io::Scope::enter();
            let result = self
                .writer
                .write(&self.buffer[self.written..])
                .map_err(storage::host_errno);
            let pending = scope.finish();
            let count = match result {
                Ok(count) => count,
                Err(_) if pending.is_some() => pending.as_ref().unwrap().progress,
                Err(error) => return Err(error),
            };
            if count > self.buffer.len() - self.written {
                return Err(Errno(5));
            }
            self.written += count;
            self.offset = self.offset.checked_add(count as u64).ok_or(Errno(27))?;
            if let Some(pending) = pending {
                self.wait = Some(pending.wait);
                return Ok(None);
            }
            if count == 0 {
                return Err(Errno(5));
            }
        }
        let scope = resource_io::Scope::enter();
        let result = self.writer.flush().map_err(storage::host_errno);
        if let Some(pending) = scope.finish() {
            self.wait = Some(pending.wait);
            return Ok(None);
        }
        result?;
        self.done = true;
        Ok(Some(self.offset))
    }
}
