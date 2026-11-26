// SPDX-License-Identifier: GPL-3.0-or-later
//! IOCB fsync owns no guest buffer and completes on existing file executors.
use super::*;

pub(super) struct Fsync {
    context: Arc<Context>,
    inner: Mutex<Inner>,
    executor: Weak<dyn FileExecutor>,
    layouts: Weak<crate::FileLayouts>,
    actor: Option<Arc<trames_vfs::FileActorSnapshot>>,
    signal: std::sync::OnceLock<Arc<IoSignal>>,
    me: Weak<Self>,
}
struct Inner {
    request: Option<Request>,
    waiting: Option<trames_vfs::FileWork>,
    subscriptions: Vec<IoSubscription>,
}
struct Task {
    work: Option<trames_vfs::FileWork>,
    result: Option<Arc<FileResult>>,
    actor: Option<Arc<trames_vfs::FileActorSnapshot>>,
    layout: bool,
}
impl Drop for Task {
    fn drop(&mut self) {
        if let Some(result) = self.result.take() {
            drop(self.work.take());
            result.fail(5);
        }
    }
}
impl crate::HostFileTask for Task {
    fn layout(&self) -> Option<Arc<crate::HostFileLayout>> {
        self.layout
            .then(|| self.work.as_ref().unwrap().admission_layout())
            .flatten()
    }
    fn run(mut self: Box<Self>, admission: Option<crate::HostFileAdmission>) {
        let _actor = self.actor.as_ref().map(|actor| actor.enter());
        let work = self.work.take().unwrap();
        let work = if let Some(admission) = admission {
            work.enter_layout(admission)
        } else {
            work
        };
        let outcome = work.run();
        self.result.take().unwrap().complete(outcome);
    }
    fn fail(self: Box<Self>) {
        drop(self);
    }
}
#[allow(clippy::result_large_err)]
pub(super) fn start(
    source: &DirectSyscalls,
    context: Arc<Context>,
    request: Request,
    work: Work,
) -> Result<(), (Request, Work)> {
    let (Some(executor), Some(layouts)) = (&source.file_executor, &source.file_layouts) else {
        return Err((request, work));
    };
    let Work::Disk(work) = work else {
        unreachable!("only files accept asynchronous fsync");
    };
    let actor = request.actor.clone();
    let pending = Arc::new_cyclic(|me| Fsync {
        context: context.clone(),
        inner: Mutex::new(Inner {
            request: Some(request),
            waiting: None,
            subscriptions: Vec::new(),
        }),
        executor: Arc::downgrade(executor),
        layouts: Arc::downgrade(layouts),
        actor,
        signal: Default::default(),
        me: me.clone(),
    });
    let target: Arc<dyn IoWake> = pending.clone();
    assert!(pending
        .signal
        .set(IoSignal::new(0, Arc::downgrade(&target)))
        .is_ok());
    context
        .state
        .lock()
        .unwrap()
        .owned
        .insert(Arc::as_ptr(&pending) as usize, pending.clone());
    pending.issue(work, false);
    Ok(())
}
impl IoWake for Fsync {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        if let Some(original) = self.me.upgrade() {
            original.ready();
        }
    }
}
impl Fsync {
    fn issue(self: &Arc<Self>, work: trames_vfs::FileWork, layout: bool) {
        let Some(executor) = self.executor.upgrade() else {
            drop(work);
            self.finish(Err(Errno(5)), Default::default());
            return;
        };
        let layouts = if layout {
            let Some(layouts) = self.layouts.upgrade() else {
                drop(work);
                self.finish(Err(Errno(5)), Default::default());
                return;
            };
            Some(layouts)
        } else {
            None
        };
        let result = self
            .inner
            .lock()
            .unwrap()
            .request
            .as_ref()
            .expect("one original fsync")
            .result
            .clone();
        result.begin();
        let original = Arc::downgrade(self);
        result.on_finished(Box::new(move || {
            if let Some(original) = original.upgrade() {
                original.completed();
            }
        }));
        let task = Box::new(Task {
            work: Some(work.queued()),
            result: Some(result),
            actor: self.actor.clone(),
            layout,
        });
        if let Some(layouts) = layouts {
            layouts.submit_host(task);
        } else {
            executor.submit_host(task, None);
        }
    }
    fn completed(self: &Arc<Self>) {
        let result = {
            let inner = self.inner.lock().unwrap();
            let Some(request) = &inner.request else {
                return;
            };
            request.result.clone()
        };
        let Some(outcome) = result.take() else {
            return;
        };
        match outcome {
            trames_vfs::FileOutcome::Complete(reply) => {
                let result = reply.result.and_then(|value| match value {
                    trames_vfs::FileValue::Count(count) => Ok(count),
                    _ => Err(Errno(5)),
                });
                self.finish(result, reply.resources);
            }
            trames_vfs::FileOutcome::Layout(work) => self.issue(work, true),
            trames_vfs::FileOutcome::Owner(work) => {
                drop(work);
                self.finish(Err(Errno(95)), Default::default());
            }
            trames_vfs::FileOutcome::Waiting(work) => self.wait(work),
        }
    }
    fn wait(self: &Arc<Self>, work: trames_vfs::FileWork) {
        let signal = self.signal.get().unwrap();
        signal.reset();
        let sources = match work.wait_sources(signal) {
            Ok(sources) if sources.native.is_empty() && sources.deadline.is_none() => sources,
            _ => {
                drop(work);
                self.finish(Err(Errno(5)), Default::default());
                return;
            }
        };
        {
            let mut inner = self.inner.lock().unwrap();
            inner.waiting = Some(work);
            inner.subscriptions = sources.subscriptions;
        }
        self.ready();
    }
    fn ready(self: &Arc<Self>) {
        self.signal.get().unwrap().reset();
        let accepted = {
            let mut inner = self.inner.lock().unwrap();
            if !inner.waiting.as_ref().is_some_and(|work| work.ready()) {
                return;
            }
            (
                inner.waiting.take().unwrap(),
                std::mem::take(&mut inner.subscriptions),
            )
        };
        drop(accepted.1);
        self.issue(accepted.0, false);
    }
    fn finish(self: &Arc<Self>, result: Result<u64, Errno>, resources: trames_vfs::FileResources) {
        let (request, waiting, subscriptions) = {
            let mut inner = self.inner.lock().unwrap();
            (
                inner.request.take(),
                inner.waiting.take(),
                std::mem::take(&mut inner.subscriptions),
            )
        };
        drop(waiting);
        drop(subscriptions);
        let retired = self
            .context
            .state
            .lock()
            .unwrap()
            .owned
            .remove(&(Arc::as_ptr(self) as usize));
        drop(retired);
        if let Some(request) = request {
            self.context.complete(request, result, resources);
        }
    }
}
