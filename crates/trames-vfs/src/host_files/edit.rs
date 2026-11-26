// SPDX-License-Identifier: GPL-3.0-or-later
//! Conditional saves retain staging and checksum state through typed waits.
use super::*;
use crate::import_work::StagedImport;

#[cfg(test)]
#[path = "edit_tests.rs"]
mod tests;

pub struct HostEditWork<R, W> {
    original: HostEdit,
    view: Vfs,
    staged: StagedImport<R>,
    staged_ready: bool,
    no_space: bool,
    validation: Option<storage::Validation>,
    read: Option<HostExportWork<W>>,
    read_done: bool,
    wait: Option<Arc<trames_memory::PageWait>>,
    resources: CgroupResourceContext,
    done: bool,
}
impl HostEdit {
    /// W is an incremental checksum sink. A fresh default sink is needed only
    /// if the original mapped/provider generation actually changed while the
    /// request relinquished layout custody; the replacement is never restaged.
    pub fn into_work<R: Read, W: Write + Default>(
        self,
        vfs: &Vfs,
        reader: R,
    ) -> HostEditWork<R, W> {
        HostEditWork {
            original: self,
            view: vfs.host_files_context(),
            staged: StagedImport::new(reader),
            staged_ready: false,
            no_space: false,
            validation: None,
            read: None,
            read_done: false,
            wait: None,
            resources: CgroupResourceContext::capture(),
            done: false,
        }
    }
}
impl<R: Read, W: Write + Default> HostEditWork<R, W> {
    pub fn layout(&self) -> Arc<trames_memory::layout::Layout> {
        self.original.layout()
    }
    pub fn wait(&self) -> Option<&Arc<trames_memory::PageWait>> {
        self.wait.as_ref()
    }
    /// validate is a pure comparison of the original inode/checksum: true for
    /// an already-saved retry, false to publish, or an error to keep the copy.
    pub fn run(
        &mut self,
        admission: &trames_memory::layout::LayoutExclusive,
        cancelled: impl Fn() -> bool,
        mut validate: impl FnMut(u64, &W) -> Result<bool>,
    ) -> Result<Option<u64>> {
        assert!(!self.done, "completed conditional edit");
        assert!(
            Arc::ptr_eq(&self.layout(), admission.layout()),
            "original edit admission"
        );
        if cancelled() {
            return Err(Errno(4));
        }
        if self.wait.as_ref().is_some_and(|wait| !wait.ready()) {
            return Ok(None);
        }
        let _resumed = self.wait.take();
        let _resources = self.resources.enter();
        if !self.staged_ready && !self.no_space {
            match self.staged.run(&self.view, &cancelled) {
                Ok(true) => self.staged_ready = true,
                Ok(false) => {
                    self.wait = self.staged.wait().cloned();
                    return Ok(None);
                }
                // Preserve the original idempotent-save fallback: a completed
                // prior save can be recognized without allocating a new copy.
                Err(Errno(28)) => {
                    self.staged.discard();
                    self.no_space = true;
                }
                Err(error) => return Err(error),
            }
        }
        loop {
            if cancelled() {
                return Err(Errno(4));
            }
            let current = {
                let node = self.original.node.borrow();
                let Content::File(data) = &node.content else {
                    return Err(Errno(21));
                };
                match &self.validation {
                    Some(validation) => validation.version.matches(data)?,
                    None => false,
                }
            };
            if !current {
                // Retire outside node/data custody: lease drop notifies writers.
                self.read = None;
                self.read_done = false;
                self.validation = None;
                let validation = {
                    let node = self.original.node.borrow();
                    let Content::File(data) = &node.content else {
                        return Err(Errno(21));
                    };
                    data.begin_validation()?
                };
                match validation {
                    Ok(validation) => self.validation = Some(validation),
                    Err(wait) => {
                        self.wait = Some(trames_memory::PageWait::resource(wait));
                        return Ok(None);
                    }
                }
                self.read = Some(
                    HostExport {
                        node: self.original.node.clone(),
                    }
                    .into_work(W::default()),
                );
            }
            let _transaction = self
                .validation
                .as_ref()
                .unwrap()
                .lease
                .as_ref()
                .map(trames_shared::FileTransactionLease::enter);
            if !self.read_done {
                let read = self.read.as_mut().unwrap();
                if read.run(admission, &cancelled)?.is_none() {
                    self.wait = read.wait().cloned();
                    return Ok(None);
                }
                self.read_done = true;
            }
            if cancelled() {
                return Err(Errno(4));
            }
            let inode = self.original.node.borrow().inode;
            let decision = validate(inode, self.read.as_ref().unwrap().writer());
            let already_applied = match decision {
                Ok(decision) => decision,
                Err(error) => {
                    let unchanged = {
                        let node = self.original.node.borrow();
                        let Content::File(data) = &node.content else {
                            return Err(Errno(21));
                        };
                        self.validation.as_ref().unwrap().version.matches(data)?
                    };
                    if unchanged {
                        return Err(error);
                    }
                    // A provider change makes the old comparison obsolete too;
                    // do not report a stale conflict from the prior checksum.
                    drop(_transaction);
                    self.read = None;
                    self.read_done = false;
                    self.validation = None;
                    continue;
                }
            };
            let scope = resource_io::Scope::enter();
            let result = self.original.commit_versioned(
                &self.view,
                self.staged_ready.then(|| self.staged.file()),
                &self.validation.as_ref().unwrap().version,
                already_applied,
            );
            let pending = scope.finish();
            match result {
                Ok(Some(inode)) => {
                    drop(_transaction);
                    self.read = None;
                    self.validation = None;
                    self.staged.discard();
                    self.done = true;
                    return Ok(Some(inode));
                }
                Ok(None) => {
                    // The provider changed between the last read and commit.
                    // Retry validation against that actual change, keeping the
                    // already-synced anonymous replacement and original reader.
                    drop(_transaction);
                    self.read = None;
                    self.read_done = false;
                    self.validation = None;
                }
                Err(_) if pending.is_some() => {
                    self.wait = Some(pending.unwrap().wait);
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
    }
}
