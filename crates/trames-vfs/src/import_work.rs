// SPDX-License-Identifier: GPL-3.0-or-later
//! An original host stream and unpublished inode survive resource waits.
use super::*;
use std::io::Read;
mod stage;
pub(super) use stage::StagedImport;

#[derive(Clone, Copy, Debug)]
pub struct ImportedFile {
    pub bytes: u64,
    pub inode: u64,
}
enum Destination {
    Create,
    Replace(HostEdit),
}
struct Stage {
    data: Arc<file_data::PlainFile>,
    buffer: Box<[u8; 65536]>,
    used: usize,
    written: usize,
    total: u64,
    eof: bool,
    synced: bool,
}
/// Owns its reader; restoring work must not reopen a host pathname or ask an
/// already-advanced stream to reproduce data. Dropping cancels unpublished IO.
pub struct HostImport<R> {
    view: Vfs,
    path: Vec<u8>,
    replace: bool,
    executable: bool,
    destination: Option<Destination>,
    stage: Option<StagedImport<R>>,
    wait: Option<Arc<trames_memory::PageWait>>,
    resources: CgroupResourceContext,
    result: Option<ImportedFile>,
    done: bool,
}
impl Vfs {
    /// Acceptance performs no host IO. The existing worker initializes its
    /// anonymous object after validating this original filesystem view.
    pub fn host_import<R: Read>(
        &self,
        path: &[u8],
        reader: R,
        replace: bool,
        executable: bool,
    ) -> HostImport<R> {
        HostImport {
            view: self.host_files_context(),
            path: path.to_vec(),
            replace,
            executable,
            destination: None,
            stage: Some(StagedImport::new(reader)),
            wait: None,
            resources: CgroupResourceContext::capture(),
            result: None,
            done: false,
        }
    }
}
impl<R: Read> HostImport<R> {
    pub fn wait(&self) -> Option<&Arc<trames_memory::PageWait>> {
        self.wait
            .as_ref()
            .or_else(|| self.stage.as_ref().and_then(StagedImport::wait))
    }
    pub fn run(&mut self) -> Result<Option<ImportedFile>> {
        self.run_checked(|| false)
    }
    /// Cancellation checks run between effects, outside all byte/node guards.
    pub fn run_checked(&mut self, cancelled: impl Fn() -> bool) -> Result<Option<ImportedFile>> {
        assert!(!self.done, "completed host import");
        if cancelled() {
            return Err(Errno(4));
        }
        if self.wait.as_ref().is_some_and(|wait| !wait.ready()) {
            return Ok(None);
        }
        let _resumed = self.wait.take();
        let _resources = self.resources.enter();
        if let Some(result) = self.result.take() {
            self.done = true;
            self.stage = None;
            return Ok(Some(result));
        }
        if self.destination.is_none() {
            self.destination = Some(match self.view.import_plan(&self.path) {
                Ok(_) => Destination::Create,
                Err(Errno(17)) if self.replace => {
                    Destination::Replace(self.view.host_edit(&self.path)?)
                }
                Err(error) => return Err(error),
            });
        }
        let stage = self.stage.as_mut().unwrap();
        if !stage.run(&self.view, &cancelled)? {
            return Ok(None);
        }
        if cancelled() {
            return Err(Errno(4));
        }
        let scope = resource_io::Scope::enter();
        let data = stage.file();
        let result = match self.destination.as_ref().unwrap() {
            Destination::Create => self
                .view
                .import_data_node(&self.path, data, self.executable, false)
                .map(|node| node.borrow().inode),
            Destination::Replace(edit) => {
                edit.commit(&self.view, Some(data), false, |_, _| Ok(false))
            }
        };
        let pending = scope.finish();
        if let Ok(inode) = &result {
            self.result = Some(ImportedFile {
                bytes: stage.bytes(),
                inode: *inode,
            });
        }
        if let Some(pending) = pending {
            self.wait = Some(pending.wait);
            return Ok(None);
        }
        result?;
        self.done = true;
        self.stage = None;
        Ok(self.result.take())
    }
}

#[cfg(test)]
#[path = "import_work_tests.rs"]
mod tests;
