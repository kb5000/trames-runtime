// SPDX-License-Identifier: GPL-3.0-or-later
//! Original resources retained through guest output, without a Files backref.
use super::*;
use std::{marker::PhantomData, rc::Rc};
#[cfg(test)]
#[path = "output_resources_tests.rs"]
mod tests;

type Leases = Vec<Box<dyn Send>>;
thread_local! {
    static OUTPUT: RefCell<Option<Leases>> = const { RefCell::new(None) };
}
/// The existing caller collects only the resources it actually resolves. The
/// frame never crosses a suspension; completed leases themselves are movable.
pub(crate) struct OutputScope {
    previous: Option<Leases>,
    _thread: PhantomData<Rc<()>>,
}
impl OutputScope {
    pub fn enter() -> Self {
        Self {
            previous: OUTPUT.with(|output| output.replace(Some(Vec::new()))),
            _thread: PhantomData,
        }
    }
    pub fn finish(self) -> FileResources {
        let leases = OUTPUT.with(|output| output.borrow_mut().take()).unwrap();
        if leases.is_empty() {
            FileResources::default()
        } else {
            FileResources::default().context(leases)
        }
    }
    pub fn retain<T: Send + 'static>(resource: impl FnOnce() -> T) {
        OUTPUT.with(|output| {
            if let Some(leases) = &mut *output.borrow_mut() {
                leases.push(Box::new(resource()));
            }
        });
    }
    pub fn path(path: &ResolvedPath) {
        Self::retain(|| {
            (
                path.clone(),
                path.mount
                    .as_ref()
                    .map(|mount| mounts::MountUse::new(mount.identity.clone())),
            )
        });
    }
}
impl Drop for OutputScope {
    fn drop(&mut self) {
        let retired = OUTPUT.with(|output| output.replace(self.previous.take()));
        // Resource destructors may enter file operations, so no TLS borrow
        // remains while releasing a cancelled or failed operation's graph.
        drop(retired);
    }
}

/// Returning read/link/xattr bytes does not finish a syscall whose destination
/// page is waiting. Hold its OFD/path until copyout finishes or drops. stat and
/// statfs have already released their source after taking a metadata snapshot.
/// The common FD case is inline; cold pathname calls may retain their accepted
/// graph, without retaining the whole VFS, Files, active work or layout lock.
#[derive(Default)]
pub struct FileResources {
    file: Option<SharedFd>,
    context: Option<Box<dyn Send>>,
}
impl FileResources {
    pub(crate) fn append(mut self, other: Self) -> Self {
        self.retain_file(other.file);
        if let Some(context) = other.context {
            self = self.context(context);
        }
        self
    }
    pub fn file(target: &FileTarget) -> Self {
        Self {
            file: Some(target.0.clone()),
            context: None,
        }
    }
    pub(crate) fn context<T: Send + 'static>(self, context: T) -> Self {
        let context: Box<dyn Send> = match self.context {
            Some(previous) => Box::new((previous, context)),
            None => Box::new(context),
        };
        Self {
            context: Some(context),
            ..self
        }
    }
    pub(crate) fn retain_file(&mut self, original: Option<SharedFd>) {
        if self.file.is_none() {
            self.file = original;
        }
    }
    pub(crate) fn needed(result: &Result<FileValue>) -> bool {
        matches!(result, Ok(FileValue::Bytes(bytes)) if !bytes.is_empty())
            || matches!(result, Ok(FileValue::Transfer { .. }))
    }
}
impl FileReply {
    /// Owner fallbacks use the same resolved-resource collection as FileWork.
    pub fn capture(operation: impl FnOnce() -> Result<FileValue>) -> Self {
        Self::capture_optional(|| Some(operation())).unwrap()
    }
    pub fn capture_optional(operation: impl FnOnce() -> Option<Result<FileValue>>) -> Option<Self> {
        let scope = OutputScope::enter();
        let result = operation()?;
        Some(
            Self {
                result,
                resources: FileResources::default(),
                file_size_signal: false,
                scratch: None,
            }
            .retain_output(scope.finish()),
        )
    }
    pub(crate) fn retain_output(mut self, resources: FileResources) -> Self {
        if FileResources::needed(&self.result) {
            self.resources = self.resources.append(resources);
        }
        self
    }
    pub(crate) fn retain_file(mut self, file: Option<SharedFd>) -> Self {
        if FileResources::needed(&self.result) {
            self.resources.retain_file(file);
        }
        self
    }
}
impl FileOutcome {
    pub(crate) fn retain_output(self, resources: FileResources) -> Self {
        match self {
            Self::Complete(reply) => Self::Complete(reply.retain_output(resources)),
            outcome => outcome,
        }
    }
    pub(crate) fn retain_file(self, file: Option<SharedFd>) -> Self {
        match self {
            Self::Complete(reply) => Self::Complete(reply.retain_file(file)),
            outcome => outcome,
        }
    }
}
