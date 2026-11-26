// SPDX-License-Identifier: GPL-3.0-or-later
//! Synchronous embedding adapters wait on their original calling thread.
//! Guest execution uses retained FileWork/HostFileTask instead of this adapter.
use super::*;

#[derive(Default)]
pub(super) struct Wait(Option<trames_shared::HostWait>);
impl Wait {
    pub fn operation<T>(&mut self, mut run: impl FnMut() -> Result<T>) -> Result<T> {
        let mut receipt = None;
        loop {
            let _resumed = receipt.take();
            let scope = resource_io::Scope::enter();
            let result = run();
            if let Some(pending) = scope.finish() {
                self.page(&pending.wait)?;
                receipt = Some(pending.wait);
            } else {
                return result;
            }
        }
    }
    fn armed(&mut self) -> Result<&mut trames_shared::HostWait> {
        if self.0.is_none() {
            self.0 = Some(trames_shared::HostWait::new().map_err(storage::host_errno)?);
        }
        let wait = self.0.as_mut().unwrap();
        wait.begin();
        Ok(wait)
    }
    pub fn page(&mut self, page: &Arc<trames_memory::PageWait>) -> Result<()> {
        while !page.ready() {
            let wait = self.armed()?;
            wait.retain(page.subscribe(wait.signal()));
            if let Some(deadline) = page.deadline() {
                wait.until(deadline);
            }
            if !page.ready() {
                wait.wait().map_err(storage::host_errno)?;
            }
        }
        Ok(())
    }
    pub fn layout(
        &mut self,
        layout: &Arc<trames_memory::layout::Layout>,
    ) -> Result<trames_memory::layout::LayoutExclusive> {
        let mut writer = layout.write();
        loop {
            writer = match writer.try_enter() {
                Ok(admission) => return Ok(admission),
                Err(writer) => writer,
            };
            let wait = self.armed()?;
            wait.retain([layout.subscribe(wait.signal())]);
            if !writer.ready() {
                wait.wait().map_err(storage::host_errno)?;
            }
        }
    }
    pub fn file(&mut self, vfs: &mut Vfs, mut outcome: FileOutcome) -> Result<FileValue> {
        loop {
            outcome = match outcome {
                FileOutcome::Complete(reply) => {
                    if reply.file_size_signal {
                        vfs.file_size_signal.set(true);
                    }
                    return reply.result;
                }
                FileOutcome::Owner(work) => work.resume_owner(vfs),
                FileOutcome::Layout(work) => {
                    let layout = work.admission_layout().ok_or(Errno(95))?;
                    work.enter_layout(self.layout(&layout)?).run()
                }
                FileOutcome::Waiting(work) => {
                    if !work.ready() {
                        // This compatibility API historically returns ordinary
                        // would-block on pipes/sockets. Only internal resource
                        // pressure sleeps on the original host caller.
                        if !work.resource_pending() {
                            return Err(Errno(11));
                        }
                        let wait = self.armed()?;
                        let sources = work
                            .wait_sources(wait.signal())
                            .map_err(storage::host_errno)?;
                        wait.retain(sources.subscriptions);
                        for (fd, writing) in sources.native {
                            wait.watch_owned(fd, writing).map_err(storage::host_errno)?;
                        }
                        if let Some(deadline) = sources.deadline {
                            wait.until(deadline);
                        }
                        if !work.ready() {
                            wait.wait().map_err(storage::host_errno)?;
                        }
                    }
                    work.run()
                }
            };
        }
    }
}

impl Vfs {
    pub(super) fn host_resources(&self) -> bool {
        self.query.is_none()
            && (trames_memory::CgroupMemoryTarget::active() || cgroup::io_limited())
    }
    pub(super) fn host_namespace_work(&mut self, call: NamespaceCall) -> Result<()> {
        let work = self.path_queries().namespace_work(call);
        Wait::default().file(self, work.run()).map(|_| ())
    }
}
