// SPDX-License-Identifier: GPL-3.0-or-later
//! One unpublished import object, also used by conditional compare-and-save.
use super::*;

pub(crate) struct StagedImport<R> {
    reader: R,
    data: Option<Stage>,
    wait: Option<Arc<trames_memory::PageWait>>,
}
impl<R: Read> StagedImport<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            data: None,
            wait: None,
        }
    }
    pub(crate) fn wait(&self) -> Option<&Arc<trames_memory::PageWait>> {
        self.wait.as_ref()
    }
    pub(crate) fn file(&self) -> storage::FileData {
        storage::FileData::Plain(self.data.as_ref().unwrap().data.clone())
    }
    pub(crate) fn bytes(&self) -> u64 {
        self.data.as_ref().unwrap().total
    }
    pub(crate) fn discard(&mut self) {
        self.data = None;
        self.wait = None;
    }
    pub(crate) fn run(&mut self, view: &Vfs, cancelled: &impl Fn() -> bool) -> Result<bool> {
        if cancelled() {
            return Err(Errno(4));
        }
        if self.wait.as_ref().is_some_and(|wait| !wait.ready()) {
            return Ok(false);
        }
        let _resumed = self.wait.take();
        if self.data.is_none() {
            let scope = resource_io::Scope::enter();
            let data = view.empty_data();
            let pending = scope.finish();
            match data {
                Ok(storage::FileData::Plain(data)) => {
                    self.data = Some(Stage {
                        data,
                        buffer: Box::new([0; 65536]),
                        used: 0,
                        written: 0,
                        total: 0,
                        eof: false,
                        synced: false,
                    });
                }
                Ok(_) => return Err(Errno(5)),
                Err(_) if pending.is_some() => {}
                Err(error) => return Err(error),
            }
            if let Some(pending) = pending {
                self.wait = Some(pending.wait);
                return Ok(false);
            }
        }
        let stage = self.data.as_mut().unwrap();
        while !stage.eof || stage.written < stage.used {
            if cancelled() {
                return Err(Errno(4));
            }
            if stage.written == stage.used {
                let scope = resource_io::Scope::enter();
                let result = self
                    .reader
                    .read(stage.buffer.as_mut())
                    .map_err(storage::host_errno);
                let pending = scope.finish();
                stage.used = match result {
                    Ok(count) => count,
                    Err(_) if pending.is_some() => pending.as_ref().unwrap().progress,
                    Err(error) => return Err(error),
                };
                stage.written = 0;
                if stage.used > stage.buffer.len() {
                    return Err(Errno(5));
                }
                stage
                    .total
                    .checked_add(stage.used as u64)
                    .ok_or(Errno(27))?;
                if let Some(pending) = pending {
                    self.wait = Some(pending.wait);
                    return Ok(false);
                }
                if stage.used == 0 {
                    stage.eof = true;
                    break;
                }
            }
            let scope = resource_io::Scope::enter();
            let result = stage
                .data
                .write_at(stage.total, &stage.buffer[stage.written..stage.used]);
            let pending = scope.finish();
            let written = match result {
                Ok(count) => count,
                Err(_) if pending.is_some() => pending.as_ref().unwrap().progress,
                Err(error) => return Err(error),
            };
            if written > stage.used - stage.written {
                return Err(Errno(5));
            }
            stage.written += written;
            stage.total += written as u64;
            if let Some(pending) = pending {
                self.wait = Some(pending.wait);
                return Ok(false);
            }
            if written == 0 {
                return Err(Errno(5));
            }
        }
        if !stage.synced {
            if cancelled() {
                return Err(Errno(4));
            }
            let scope = resource_io::Scope::enter();
            let result = stage.data.sync(false);
            if let Some(pending) = scope.finish() {
                self.wait = Some(pending.wait);
                return Ok(false);
            }
            result?;
            stage.synced = true;
        }
        Ok(true)
    }
}
