// SPDX-License-Identifier: GPL-3.0-or-later
//! Exclusive transport of a complete GPU object graph between CPU workers.
use crate::{Backend, Invocation, TransferMetrics};
use std::sync::{Arc, Mutex};
use trames_memory::{CpuMemory, MemoryError};
mod retirement;

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
    display: crate::Display,
    retirement: Mutex<Option<Arc<retirement::Retirement>>>,
}
#[derive(Clone)]
pub struct Context(Arc<Inner>);
/// Non-owning observation of an original native device graph.
pub struct WeakContext(std::sync::Weak<Inner>);
impl WeakContext {
    pub fn upgrade(&self) -> Option<Context> {
        self.0.upgrade().map(Context)
    }
}
pub type Call = (Result<Invocation, MemoryError>, TransferMetrics);
/// A synchronous exclusive lease; neither Backend nor its Rc graph escapes.
pub struct Lease<'a> {
    backend: Option<std::sync::MutexGuard<'a, OwnedBackend>>,
    available: &'a trames_shared::Readiness,
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let completion = self
            .backend
            .as_mut()
            .and_then(|backend| backend.0.take_completion_notice());
        drop(self.backend.take());
        if let Some(completion) = completion {
            completion.notify_atomic();
        }
        // Unlock before entering a scheduler callback. This RMW pairs with the
        // subscribe/retry handshake, including a failed try_lock on weak ARM.
        self.available.notify_atomic();
    }
}
impl Lease<'_> {
    pub fn job_deadline(&self, job: u64) -> Option<std::time::Instant> {
        self.backend.as_ref().unwrap().0.job_deadline(job)
    }
    pub fn is_compile(&self, job: u64) -> bool {
        self.backend.as_ref().unwrap().0.is_compile(job)
    }
    pub fn invoke(
        &mut self,
        memory: &mut impl CpuMemory,
        operation: u64,
        address: u64,
        size: u64,
        authenticated: Option<(trames_wayland::Server, u64)>,
    ) -> Call {
        self.invoke_with_images(memory, operation, address, size, authenticated, None)
    }
    pub fn invoke_with_images(
        &mut self,
        memory: &mut impl CpuMemory,
        operation: u64,
        address: u64,
        size: u64,
        authenticated: Option<(trames_wayland::Server, u64)>,
        images: Option<&Arc<dyn trames_graphics::ImageFds>>,
    ) -> Call {
        let backend = &mut self.backend.as_mut().unwrap().0;
        if matches!(operation, 110 | 111) {
            backend.authenticate_wayland(authenticated);
        }
        let image_call = matches!(operation, 14 | 240..=242);
        if image_call {
            backend.authenticate_images(images.cloned());
        }
        let before = backend.transfers;
        let result = backend.invoke(memory, operation, address, size);
        if image_call {
            backend.authenticate_images(None);
        }
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
    ) -> Option<crate::JobSubscription> {
        self.backend.as_ref().unwrap().0.subscribe_job(job, signal)
    }
}
impl crate::display::SuspensionFence for Inner {
    fn quiesce(&self) {
        drop(self.backend.lock().expect("GPU context poisoned"));
    }
    fn resume(&self) {
        self.available.notify_atomic();
    }
}
impl Context {
    pub fn downgrade(&self) -> WeakContext {
        WeakContext(Arc::downgrade(&self.0))
    }
    pub fn new(backend: Backend) -> Self {
        let display = backend.host_display();
        let inner = Arc::new(Inner {
            backend: Mutex::new(OwnedBackend(backend)),
            available: Arc::default(),
            display: display.clone(),
            retirement: Mutex::default(),
        });
        display.register_context(&(inner.clone() as Arc<dyn crate::display::SuspensionFence>));
        Self(inner)
    }
    pub fn try_lock(&self) -> Option<Lease<'_>> {
        match self.0.backend.try_lock() {
            Ok(backend) if !self.0.display.suspended() => Some(Lease {
                backend: Some(backend),
                available: &self.0.available,
            }),
            Ok(_) | Err(std::sync::TryLockError::WouldBlock) => None,
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
    pub fn invoke_with_images(
        &self,
        memory: &mut impl CpuMemory,
        operation: u64,
        address: u64,
        size: u64,
        authenticated: Option<(trames_wayland::Server, u64)>,
        images: Option<&Arc<dyn trames_graphics::ImageFds>>,
    ) -> Call {
        self.lock()
            .invoke_with_images(memory, operation, address, size, authenticated, images)
    }
    pub fn poll(&self, memory: &mut impl CpuMemory, job: u64) -> Result<Option<u64>, MemoryError> {
        self.lock().poll(memory, job)
    }
    pub fn abandon(&self, job: u64) {
        let mut lease = self.lock();
        let backend = lease.backend.as_mut().unwrap();
        backend.0.abandon(job);
        if backend.0.has_abandoned() {
            retirement::Retirement::arm(&self.0, backend, false);
        }
    }
    /// End an original mm's authority. Accepted native work retains the graph
    /// through its completion; no guest View or task slot waits for destruction.
    pub fn retire(&self) {
        retirement::Retirement::close(&self.0);
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
    fn retiring_a_busy_original_context_defers_to_its_lease_unlock_without_a_service_thread() {
        let context = Context::new(Backend::new());
        let lease = context.try_lock().unwrap();
        let closing = context.clone();
        let (send, receive) = mpsc::channel();
        let closer = thread::spawn(move || {
            closing.retire();
            send.send(()).unwrap();
        });
        let result = receive.recv_timeout(Duration::from_secs(1));
        assert!(context.0.retirement.lock().unwrap().is_some());
        drop(lease);
        closer.join().unwrap();
        assert!(
            result.is_ok(),
            "retirement waited for another native caller"
        );
        assert!(context.0.retirement.lock().unwrap().is_none());
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
    #[test]
    fn host_background_fences_entries_and_foreground_wakes_the_original_waiter() {
        let display = crate::Display::default();
        let context = Context::new(Backend::new().with_display(display.clone()));
        let lease = context.try_lock().unwrap();
        let (entered, started) = mpsc::channel();
        let (done, completed) = mpsc::channel();
        let host = display.clone();
        let thread = thread::spawn(move || {
            entered.send(()).unwrap();
            host.set_suspended(true);
            done.send(()).unwrap();
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(completed.recv_timeout(Duration::from_millis(20)).is_err());
        drop(lease);
        completed.recv_timeout(Duration::from_secs(2)).unwrap();
        thread.join().unwrap();
        assert!(context.try_lock().is_none());
        let (wake, woken) = mpsc::channel();
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Unlocked(context.clone(), wake));
        let signal = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
        let _subscription = context.subscribe(&signal);
        assert!(context.try_lock().is_none());
        display.set_suspended(false);
        woken.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(signal.ready());
        assert!(context.try_lock().is_some());
        display.set_suspended(true);
        let later = Context::new(Backend::new().with_display(display.clone()));
        assert!(later.try_lock().is_none());
        display.set_suspended(false);
        assert!(later.try_lock().is_some());
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
    fn device_calls_keep_original_wire_faults_on_worker_views() {
        let context = Context::new(Backend::new());
        let (_root, mut memory) = view();
        assert!(context.invoke(&mut memory, 79, 0, 128, None).0.is_err());
        assert_eq!(memory.read_array::<32>(0x2000).unwrap(), [0xa5; 32]);
    }
}
