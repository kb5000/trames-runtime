// SPDX-License-Identifier: GPL-3.0-or-later
//! Original inode mutations retain their admission and writeback stages.
use super::*;
pub(super) enum Mutation {
    Resize(memfd::ResizeState),
    Seals(memfd::SealState),
}
impl Mutation {
    fn notify(&mut self) {
        match self {
            Self::Resize(state) => state.notify(),
            Self::Seals(state) => state.notify(),
        }
    }
}

impl FileWork {
    pub(super) fn cursor_resize(&self) -> bool {
        matches!(
            self.command,
            FileCommand::Truncate(_)
                | FileCommand::TruncateOpen
                | FileCommand::Allocate { .. }
                | FileCommand::Seals(Some(_))
        ) && self
            .target
            .as_ref()
            .is_some_and(|target| target.regular_file() && !target.daemon_backed())
    }
    pub(super) fn run_resize(mut self) -> FileOutcome {
        let state = self.mutation.get_or_insert_with(|| {
            Box::new(if matches!(self.command, FileCommand::Seals(_)) {
                Mutation::Seals(Default::default())
            } else {
                Mutation::Resize(Default::default())
            })
        });
        let scope = resource_io::Scope::enter();
        let reply = self.paths.file_operation(self.exclusive, |v| {
            let descriptor = Descriptor {
                open: OpenHandle::Shared(self.target.as_ref().unwrap().0.open.clone()),
                cloexec: false.into(),
            };
            let Mutation::Resize(state) = state.as_mut() else {
                let Mutation::Seals(state) = state.as_mut() else {
                    unreachable!()
                };
                let FileCommand::Seals(add) = self.command else {
                    unreachable!()
                };
                return Vfs::seals_description_inner(&descriptor, add, state)
                    .map(|count| FileValue::Count(count as u64));
            };
            let (request, opening) = match self.command {
                FileCommand::Truncate(length) => (memfd::FileResize::Truncate(length), false),
                FileCommand::TruncateOpen => (memfd::FileResize::Truncate(0), true),
                FileCommand::Allocate {
                    mode,
                    offset,
                    length,
                } => {
                    let end = Vfs::allocation_end(offset, length)?;
                    (
                        Vfs::allocation_request(&descriptor, mode, offset, length, end)?,
                        false,
                    )
                }
                _ => unreachable!("accepted file resize"),
            };
            v.resize_description_inner(&descriptor, request, opening, state)
                .map(|()| FileValue::Count(0))
        });
        let pending = scope.finish();
        // Page completion and quota wake callbacks cannot run under original
        // inode/provider guards or the sealed VFS operation's mutable borrow.
        state.notify();
        if let Some(pending) = pending {
            self.resource_wait = Some(pending.wait);
            return FileOutcome::Waiting(self);
        }
        match reply {
            Some((result, signal)) => {
                let result = self.publish_open(result);
                let mut reply = Self::descriptor_result(result, &mut self.command);
                reply.file_size_signal = signal;
                FileOutcome::Complete(reply)
            }
            None => self.defer_operation(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use trames_memory::PageWait;
    use trames_shared::{SharedFile, SharedFileAccess, SharedFileAccounting, SharedFileCharge};
    struct Account {
        wait: Arc<PageWait>,
        commits: Arc<AtomicUsize>,
    }
    struct Loan(Arc<AtomicUsize>);
    impl SharedFileCharge for Loan {
        fn changed(&self) -> bool {
            true
        }
        fn commit(self: Box<Self>, _: usize) -> Arc<dyn Send + Sync> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Arc::new(())
        }
    }
    impl SharedFileAccounting for Account {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn reserve(
            &self,
            _: usize,
            _: usize,
            _: SharedFileAccess,
        ) -> std::io::Result<Box<dyn SharedFileCharge>> {
            if !self.wait.ready() {
                return Err(trames_shared::ResourcePending::io_error(self.wait.clone()));
            }
            Ok(Box::new(Loan(self.commits.clone())))
        }
        fn truncate(&self, _: usize) {}
    }
    fn fixture() -> (Vfs, u32, FileTarget, SharedFile, Arc<Account>) {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/allocate", 0x42, 0o600).unwrap();
        v.seek(fd, 3, 0).unwrap();
        let target = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let file = SharedFile::anonymous().unwrap();
        file.write_at(0, b"base").unwrap();
        let account = Arc::new(Account {
            wait: Arc::default(),
            commits: Arc::default(),
        });
        file.set_accounting(account.clone()).unwrap();
        target.0.open.node.as_ref().unwrap().borrow_mut().content =
            Content::File(storage::FileData::Shared(file.clone()));
        (v, fd, target, file, account)
    }
    #[test]
    fn allocation_wait_retains_the_original_inode_and_commits_one_reservation() {
        for mode in [0, 1] {
            let (mut v, fd, original, file, account) = fixture();
            let FileOutcome::Waiting(work) = FileWork::run_owned(
                &mut v,
                original.clone(),
                FileCommand::Allocate {
                    mode,
                    offset: 4096,
                    length: 4096,
                },
            ) else {
                panic!("allocation admission wait");
            };
            assert_eq!(file.len(), 4);
            assert_eq!(account.commits.load(Ordering::Relaxed), 0);
            assert!(!work.interruptible_wait());
            v.close(fd).unwrap();
            assert_eq!(v.eventfd(13, 0).unwrap(), fd);
            account.wait.finish();
            let FileOutcome::Complete(reply) = work.run() else {
                panic!("allocation resumes original resource");
            };
            assert!(matches!(reply.result, Ok(FileValue::Count(0))));
            assert_eq!(file.len(), if mode == 0 { 8192 } else { 4 });
            assert_eq!(file.read_at(0, 4).unwrap(), b"base");
            assert_eq!(original.0.open.file_position.snapshot(), 3);
            assert_eq!(account.commits.load(Ordering::Relaxed), 1);
            assert_eq!(v.read(fd, 8).unwrap(), 13u64.to_le_bytes());
        }
    }
    #[test]
    fn cancelled_allocation_releases_mutation_ownership_without_committing_a_reservation() {
        let (mut v, _, original, file, account) = fixture();
        let FileOutcome::Waiting(work) = FileWork::run_owned(
            &mut v,
            original,
            FileCommand::Allocate {
                mode: 0,
                offset: 4096,
                length: 4096,
            },
        ) else {
            panic!("allocation admission wait");
        };
        drop(work);
        assert_eq!(file.len(), 4);
        assert_eq!(account.commits.load(Ordering::Relaxed), 0);
        assert!(file.begin_transaction().unwrap().is_some());
        account.wait.finish();
        file.reserve_range(4096, 4096).unwrap();
        assert_eq!(account.commits.load(Ordering::Relaxed), 1);
    }
}
