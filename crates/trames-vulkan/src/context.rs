// SPDX-License-Identifier: GPL-3.0-or-later
//! Exclusive transport of a complete GPU object graph between CPU workers.
use crate::{Backend, Invocation, TransferMetrics};
use std::sync::{Arc, Mutex};
use trames_memory::{CpuMemory, MemoryError};

// Backend deliberately remains !Send/!Sync. Its private Rc/RefCell graph never
// escapes through its public interface. Only this consuming envelope may move
// that whole graph, and all entry/teardown access is behind the context mutex.
struct OwnedBackend(Backend);
// SAFETY: no Rc<Object>/Weak/Object borrow leaves Backend or its private child
// modules. Pending compilers retain Rc dependencies inside Backend; their host
// threads receive only Send-owned arrays, raw Vulkan handles and Arc<Device>.
// UI frames contain Arc native image/device/fence leases, never a backend Rc.
// Display/Wayland/Budget are already Send + Sync. No TLS, CPU View, guest page
// borrow or native stack pointer is retained by the graph. Moving the complete
// graph under this exclusive lease is equivalent to moving an isolated arena;
// this does NOT make Backend, Rc, RefCell or any individual Object Send/Sync.
unsafe impl Send for OwnedBackend {}

struct Inner {
    backend: Mutex<OwnedBackend>,
    available: Arc<trames_shared::Readiness>,
}
#[derive(Clone)]
pub struct Context(Arc<Inner>);
pub type Call = (Result<Invocation, MemoryError>, TransferMetrics);
/// A synchronous exclusive lease; neither Backend nor its Rc graph escapes.
pub struct Lease<'a> {
    backend: Option<std::sync::MutexGuard<'a, OwnedBackend>>,
    available: &'a trames_shared::Readiness,
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        drop(self.backend.take());
        // Unlock before entering a scheduler callback. This RMW pairs with the
        // subscribe/retry handshake, including a failed try_lock on weak ARM.
        self.available.notify_atomic();
    }
}
impl Lease<'_> {
    pub fn invoke(
        &mut self,
        memory: &mut impl CpuMemory,
        operation: u64,
        address: u64,
        size: u64,
        authenticated: Option<(trames_wayland::Server, u64)>,
    ) -> Call {
        let backend = &mut self.backend.as_mut().unwrap().0;
        if matches!(operation, 110 | 111) {
            backend.authenticate_wayland(authenticated);
        }
        let before = backend.transfers;
        let result = backend.invoke(memory, operation, address, size);
        let after = backend.transfers;
        (result, after.since(before))
    }
    pub fn poll(
        &mut self,
        memory: &mut impl CpuMemory,
        job: u64,
    ) -> Result<Option<u64>, MemoryError> {
        self.backend.as_mut().unwrap().0.poll(memory, job)
    }
    pub fn subscribe_compile(
        &self,
        job: u64,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Option<trames_shared::IoSubscription> {
        self.backend
            .as_ref()
            .unwrap()
            .0
            .subscribe_compile(job, signal)
    }
}
impl Context {
    pub fn new(backend: Backend) -> Self {
        Self(Arc::new(Inner {
            backend: Mutex::new(OwnedBackend(backend)),
            available: Arc::default(),
        }))
    }
    /// Device/instance teardown can drain native work and remains joined.
    pub fn worker_operation(operation: u64) -> bool {
        !matches!(operation, 2 | 9)
    }
    pub fn try_lock(&self) -> Option<Lease<'_>> {
        match self.0.backend.try_lock() {
            Ok(backend) => Some(Lease {
                backend: Some(backend),
                available: &self.0.available,
            }),
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(_)) => panic!("GPU context poisoned"),
        }
    }
    fn lock(&self) -> Lease<'_> {
        Lease {
            backend: Some(self.0.backend.lock().expect("GPU context poisoned")),
            available: &self.0.available,
        }
    }
    pub fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.0.available.subscribe(signal)
    }
    pub fn invoke(
        &self,
        memory: &mut impl CpuMemory,
        operation: u64,
        address: u64,
        size: u64,
        authenticated: Option<(trames_wayland::Server, u64)>,
    ) -> Call {
        self.lock()
            .invoke(memory, operation, address, size, authenticated)
    }
    pub fn poll(&self, memory: &mut impl CpuMemory, job: u64) -> Result<Option<u64>, MemoryError> {
        self.lock().poll(memory, job)
    }
    pub fn abandon(&self, job: u64) {
        self.lock().backend.as_mut().unwrap().0.abandon(job);
    }
    pub fn reap_abandoned(&self) {
        self.lock().backend.as_mut().unwrap().0.reap_abandoned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    struct Unlocked(Context, mpsc::Sender<()>);
    impl trames_shared::IoWake for Unlocked {
        fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
            assert!(
                self.0.try_lock().is_some(),
                "callback must run after unlock"
            );
            self.1.send(()).unwrap();
        }
    }
    #[test]
    fn nonblocking_lease_and_subscribe_retry_notify_only_after_unlock() {
        let context = Context::new(Backend::new());
        let lease = context.try_lock().unwrap();
        assert!(context.try_lock().is_none());
        let (wake, woken) = mpsc::channel();
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Unlocked(context.clone(), wake));
        let signal = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
        let sub = context.subscribe(&signal);
        assert!(context.try_lock().is_none());
        drop(lease);
        woken.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(signal.ready());
        drop(sub);
        signal.reset();
        drop(context.try_lock().unwrap());
        assert!(!signal.ready());
    }
    fn view() -> (Memory, trames_memory::parallel::View) {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        memory.write_array(0x1000, 0x2000u64.to_le_bytes()).unwrap();
        memory.write(0x2000, &[0xa5; 32]).unwrap();
        let view = memory.parallel_view(&mut Default::default()).unwrap();
        (memory, view)
    }
    #[test]
    fn a_complete_graph_moves_between_workers_without_guest_or_rc_aliases_escaping() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Context>();
        let context = Context::new(Backend::new());
        let views: Vec<_> = (0..4).map(|_| view()).collect();
        let (mut roots, views): (Vec<_>, Vec<_>) = views.into_iter().unzip();
        let jobs: Vec<_> = views
            .into_iter()
            .map(|mut view| {
                let context = context.clone();
                thread::spawn(move || {
                    for _ in 0..64 {
                        let (r, t) = context.invoke(&mut view, 79, 0x1000, 128, None);
                        assert_eq!(r, Ok(Invocation::Complete(0)));
                        assert_eq!(t.direct_bytes, 0);
                    }
                    assert_eq!(view.read_array::<24>(0x2000).unwrap(), [0; 24]);
                    assert_eq!(view.read_array::<8>(0x2018).unwrap(), [0xa5; 8]);
                })
            })
            .collect();
        for job in jobs {
            job.join().unwrap();
        }
        for root in &mut roots {
            root.commit_parallel().unwrap();
            assert_eq!(root.read_array::<24>(0x2000).unwrap(), [0; 24]);
        }
    }
    #[test]
    fn an_occupied_context_does_not_serialize_an_independent_context() {
        let slow = Context::new(Backend::new());
        let guard = slow.lock();
        let peer = slow.clone();
        let (mut root, mut memory) = view();
        let (began, starting) = mpsc::channel();
        let (done, completed) = mpsc::channel();
        let worker = thread::spawn(move || {
            began.send(()).unwrap();
            let r = peer.invoke(&mut memory, 79, 0x1000, 128, None).0;
            done.send(r).unwrap();
        });
        starting.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(completed.try_recv().is_err());
        let fast = Context::new(Backend::new());
        let (_fast_root, mut memory) = view();
        assert_eq!(
            fast.invoke(&mut memory, 79, 0x1000, 128, None).0,
            Ok(Invocation::Complete(0))
        );
        drop(guard);
        assert_eq!(
            completed.recv_timeout(Duration::from_secs(2)).unwrap(),
            Ok(Invocation::Complete(0))
        );
        worker.join().unwrap();
        root.commit_parallel().unwrap();
    }
    #[test]
    fn only_device_teardown_stays_out_of_worker_admission() {
        for op in [2, 9] {
            assert!(!Context::worker_operation(op));
        }
        for op in [
            1, 3, 8, 17, 19, 20, 27, 38, 47, 51, 70, 79, 87, 91, 109, 110, 111, 150,
        ] {
            assert!(Context::worker_operation(op));
        }
        let context = Context::new(Backend::new());
        let (_root, mut memory) = view();
        assert!(context.invoke(&mut memory, 79, 0, 128, None).0.is_err());
        assert_eq!(memory.read_array::<32>(0x2000).unwrap(), [0xa5; 32]);
    }
}
