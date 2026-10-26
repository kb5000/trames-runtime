// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned native work. No guest pointer, memory guard or coordinator Rc crosses.
use std::{
    sync::{mpsc, Arc},
    thread,
};
use trames_shared::{IoSignal, IoSubscription, Readiness};

pub(super) struct Task<T> {
    result: mpsc::Receiver<T>,
    worker: Option<thread::JoinHandle<()>>,
    readiness: Arc<Readiness>,
}
struct Completed(Arc<Readiness>);
impl Drop for Completed {
    fn drop(&mut self) {
        self.0.notify_atomic();
    }
}
impl<T: Send + 'static> Task<T> {
    pub fn spawn(work: impl FnOnce() -> T + Send + 'static) -> std::io::Result<Self> {
        let (sender, result) = mpsc::channel();
        let readiness = Arc::new(Readiness::default());
        let completed = readiness.clone();
        let worker = thread::Builder::new()
            .name("trames-gpu-compile".into())
            .spawn(move || {
                let _completed = Completed(completed);
                // This local sender drops BEFORE the completion guard, even
                // when work panics. A wake must observe result or disconnect.
                let sender = sender;
                // If the owner has gone away, dropping the result frees its native
                // object on this worker while the owned driver remains alive.
                let _ = sender.send(work());
            })?;
        Ok(Self {
            result,
            worker: Some(worker),
            readiness,
        })
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.readiness.subscribe(signal)
    }
    pub fn poll(&mut self) -> Result<Option<T>, ()> {
        match self.result.try_recv() {
            Ok(value) => Ok(Some(value)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(()),
        }
    }
}
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        // Final context teardown joins before coordinator-held dependencies
        // disappear. Ordinary polling never joins unfinished native work.
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Wake(mpsc::Sender<()>);
    impl trames_shared::IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.send(()).unwrap();
        }
    }
    #[test]
    fn completion_or_panic_publishes_result_before_notification() {
        for panic in [false, true] {
            let (release, gate) = mpsc::channel();
            let mut task = Task::spawn(move || {
                gate.recv().unwrap();
                assert!(!panic, "test compiler panic");
                37
            })
            .unwrap();
            let (wake, woken) = mpsc::channel();
            let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake(wake));
            let signal = IoSignal::new(7, Arc::downgrade(&target));
            let _subscription = task.subscribe(&signal);
            assert_eq!(task.poll(), Ok(None));
            release.send(()).unwrap();
            woken
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
            if panic {
                assert_eq!(task.poll(), Err(()));
            } else {
                assert_eq!(task.poll(), Ok(Some(37)));
            }
        }
    }
    #[test]
    fn slow_tasks_do_not_block_the_caller_or_an_unrelated_task() {
        let (release, gate) = mpsc::channel();
        let mut slow = Task::spawn(move || gate.recv().unwrap()).unwrap();
        assert_eq!(slow.poll(), Ok(None));
        let (done, completed) = mpsc::channel();
        let mut fast = Task::spawn(move || {
            done.send(()).unwrap();
            7
        })
        .unwrap();
        completed
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        // Receipt of the test marker precedes delivery of the task result.
        release.send(3).unwrap();
        for task in [&mut slow, &mut fast] {
            while task.poll().unwrap().is_none() {
                thread::yield_now();
            }
        }
    }
    #[test]
    fn teardown_joins_before_owned_dependency_destruction() {
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peer = finished.clone();
        let task =
            Task::spawn(move || peer.store(true, std::sync::atomic::Ordering::Release)).unwrap();
        drop(task);
        assert!(finished.load(std::sync::atomic::Ordering::Acquire));
    }
}
