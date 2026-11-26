// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::{atomic::AtomicUsize, Mutex};
use trames_shared::{IoSignal, IoWake};

struct Deferred {
    wait: Arc<PageWait>,
    result: Mutex<Option<Result<Arc<SharedPage>, MemoryError>>>,
    identity: u64,
}
impl Deferred {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            wait: Arc::default(),
            result: Mutex::default(),
            identity: new_backing_identity(),
        })
    }
    fn complete(&self, result: Result<Arc<SharedPage>, MemoryError>) {
        *self.result.lock().unwrap() = Some(result);
        self.wait.finish();
    }
}
impl PageSource for Deferred {
    fn load(&self) -> Result<Arc<SharedPage>, MemoryError> {
        self.result
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Err(self.wait.fault(0)))
    }
}
struct Backing(Arc<Deferred>);
impl PageBacking for Backing {
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn native_resident(&self) -> bool {
        self.0
            .result
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|result| result.is_ok())
    }
    fn page_source(&self) -> Option<Arc<dyn PageSource>> {
        Some(self.0.clone())
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.0.identity, 0))
    }
    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.0.load()?.copy_read(offset, bytes);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        self.0.load()?.copy_write(offset, bytes);
        Ok(())
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn publish_write(&self, _: usize, _: usize) -> Result<(), MemoryError> {
        Ok(())
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn version(&self) -> u64 {
        0
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}
fn mapping(page: &Arc<Deferred>) -> Memory {
    let mut memory = Memory::default();
    memory
        .map_backed(
            0x10000,
            vec![Arc::new(Backing(page.clone()))],
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    memory
}
fn pending(error: MemoryError, page: &Arc<Deferred>, address: u64) {
    let MemoryError::Pending(fault) = error else {
        panic!("expected accepted page wait: {error:?}")
    };
    assert_eq!(fault.address, address);
    assert!(Arc::ptr_eq(&fault.wait, &page.wait));
}
#[test]
fn deferred_pages_retry_the_same_resource_through_root_and_retained_worker_views() {
    let page = Deferred::new();
    let mut memory = mapping(&page);
    let mut view = memory.parallel_view(&mut Default::default()).unwrap();
    pending(view.read_array::<1>(0x10017).unwrap_err(), &page, 0x10017);
    pending(view.write(0x10025, &[3]).unwrap_err(), &page, 0x10025);
    assert_eq!(
        memory.resident_bytes(),
        0,
        "waiting does not allocate a shadow page"
    );
    page.complete(Ok(Arc::new(SharedPage::new([7; PAGE_SIZE as usize]))));
    assert_eq!(view.read_array::<1>(0x10017).unwrap(), [7]);
    view.write(0x10025, &[3]).unwrap();
    drop(view);
    memory.commit_parallel().unwrap();
    assert_eq!(memory.read_array::<1>(0x10025).unwrap(), [3]);
}
#[test]
fn root_and_native_preflight_preserve_precise_pending_addresses_and_terminal_errors() {
    let page = Deferred::new();
    let mut memory = mapping(&page);
    pending(memory.read_array::<1>(0x10017).unwrap_err(), &page, 0x10017);
    pending(
        memory.with_read_chunk(0x10035, 1, |_| ()).unwrap_err(),
        &page,
        0x10035,
    );
    pending(memory.write(0x10055, &[1]).unwrap_err(), &page, 0x10055);
    page.complete(Err(MemoryError::Bus(0)));
    assert_eq!(
        memory.read_array::<1>(0x10017),
        Err(MemoryError::Bus(0x10017))
    );
    assert_eq!(memory.resident_bytes(), 0);
}
#[test]
fn a_pending_hardware_export_never_allocates_or_imports_a_shadow_page() {
    let page = Deferred::new();
    let mut memory = mapping(&page);
    let mut view = memory.parallel_view(&mut Default::default()).unwrap();
    view.enable_hardware();
    // SAFETY: the isolated View has no byte aliases or active hardware actor.
    let result = unsafe {
        view.export_hardware_page_with_mapping(
            0x10000,
            Access::Read,
            |_| panic!("pending page cannot allocate a hardware shadow"),
            |_| panic!("pending page has no physical mapping to import"),
        )
    };
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("page is not ready"),
    };
    pending(error, &page, 0x10000);
    assert_eq!(memory.resident_bytes(), 0);
}
#[test]
fn independent_waiters_and_cancellation_cannot_steal_another_actors_notification() {
    struct Wake(AtomicUsize);
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let target = Arc::new(Wake(AtomicUsize::new(0)));
    let erased: Arc<dyn IoWake> = target.clone();
    let a = IoSignal::new(1, Arc::downgrade(&erased));
    let b = IoSignal::new(2, Arc::downgrade(&erased));
    let wait = Arc::new(PageWait::default());
    let subscription = wait.subscribe(&a);
    let _other = wait.subscribe(&b);
    drop(subscription);
    wait.finish();
    assert!(!a.ready());
    assert!(b.ready() && wait.ready());
    wait.finish();
    assert_eq!(target.0.load(Ordering::Relaxed), 1);
}

#[test]
fn resource_faults_keep_all_ancestor_notifications_and_a_live_deadline() {
    use trames_shared::{Readiness, ResourcePending, ResourceWait};
    struct Resource {
        changed: [Arc<Readiness>; 2],
        deadline: Mutex<std::time::Instant>,
        ready: std::sync::atomic::AtomicBool,
    }
    impl ResourceWait for Resource {
        fn ready(&self) -> bool {
            self.ready.load(Ordering::Relaxed)
        }
        fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<trames_shared::IoSubscription> {
            self.changed
                .iter()
                .map(|changed| changed.subscribe(signal))
                .collect()
        }
        fn deadline(&self) -> Option<std::time::Instant> {
            Some(*self.deadline.lock().unwrap())
        }
    }
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let first = IoSignal::new(1, Arc::downgrade(&target));
    let second = IoSignal::new(2, Arc::downgrade(&target));
    let now = std::time::Instant::now();
    let resource = Arc::new(Resource {
        changed: std::array::from_fn(|_| Arc::default()),
        deadline: Mutex::new(now + std::time::Duration::from_secs(600)),
        ready: Default::default(),
    });
    let wait = PageWait::resource(resource.clone());
    let cancelled = wait.subscribe(&first);
    let active = wait.subscribe(&second);
    drop(cancelled);
    assert_eq!(
        active
            .iter()
            .filter_map(trames_shared::IoSubscription::deadline)
            .min(),
        wait.deadline()
    );
    let earlier = now + std::time::Duration::from_secs(60);
    *resource.deadline.lock().unwrap() = earlier;
    resource.changed[1].notify_atomic();
    assert!(second.ready() && !first.ready() && !wait.ready());
    assert_eq!(
        active
            .iter()
            .filter_map(trames_shared::IoSubscription::deadline)
            .min(),
        Some(earlier)
    );
    assert!(active.iter().all(|subscription| !subscription.external()));
    for subscription in &active {
        subscription.rearm_host().unwrap();
    }
    second.reset();
    resource.ready.store(true, Ordering::Relaxed);
    resource.changed[0].notify_atomic();
    assert!(second.ready() && wait.ready());
    let original: Arc<dyn ResourceWait> = wait.clone();
    let error = ResourcePending::io_error(original.clone());
    assert!(Arc::ptr_eq(
        &ResourcePending::from_io(&error).unwrap(),
        &original
    ));
    assert!(ResourcePending::from_io(&std::io::Error::from_raw_os_error(11)).is_none());
}
