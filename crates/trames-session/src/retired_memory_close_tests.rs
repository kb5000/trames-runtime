// SPDX-License-Identifier: GPL-3.0-or-later
//! Exercise actual mapping cancellation and accepted close jobs across handoff.
use super::*;
use trames_memory::{CpuMemory, PageBacking, Permissions, SyncResource, PAGE_SIZE};

type Host = (
    Box<dyn trames_linux::HostFileTask>,
    Option<trames_linux::HostFileAdmission>,
);
#[derive(Default)]
struct Queue {
    jobs: Mutex<Vec<Host>>,
    on_submit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl trames_linux::FileExecutor for Queue {
    fn submit_file(&self, _: trames_vfs::FileWork, _: Arc<trames_linux::FileResult>) {
        panic!("mapping close does not replay a guest file syscall");
    }
    fn submit_host(
        &self,
        work: Box<dyn trames_linux::HostFileTask>,
        admission: Option<trames_linux::HostFileAdmission>,
    ) {
        self.jobs.lock().unwrap().push((work, admission));
        let hook = self.on_submit.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }
}
impl Queue {
    fn finish(&self) {
        let (job, admission) = self.jobs.lock().unwrap().pop().expect("original close job");
        job.run(admission);
    }
    fn len(&self) -> usize {
        self.jobs.lock().unwrap().len()
    }
}
#[derive(Default)]
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn driver(retired: &Arc<RetiredMemory>) -> (Arc<dyn IoWake>, Driver) {
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(0, Arc::downgrade(&target));
    (target, retired.bind_reader(signal))
}
struct Data {
    bytes: Mutex<Vec<u8>>,
    saved: Mutex<Vec<u8>>,
}
struct Close(Arc<Data>);
impl SyncResource for Close {
    fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        None
    }
    fn sync(&self) -> Result<(), MemoryError> {
        self.0
            .saved
            .lock()
            .unwrap()
            .push(self.0.bytes.lock().unwrap()[0]);
        Ok(())
    }
}
struct Backing {
    id: u64,
    data: Arc<Data>,
    close: Arc<Close>,
}
impl Backing {
    fn new() -> Arc<Self> {
        let data = Arc::new(Data {
            bytes: Mutex::new(vec![0; PAGE_SIZE as usize]),
            saved: Mutex::default(),
        });
        Arc::new(Self {
            id: trames_memory::new_backing_identity(),
            close: Arc::new(Close(data.clone())),
            data,
        })
    }
    fn map(self: &Arc<Self>, memory: &mut Memory, address: u64) -> trames_memory::MappingLease {
        let objects: Vec<Arc<dyn PageBacking>> = vec![self.clone()];
        memory
            .map_backed(address, objects.clone(), true, Permissions::RW, false)
            .unwrap();
        memory.mapping_lease(objects)
    }
}
impl PageBacking for Backing {
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.id, 0))
    }
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        out.copy_from_slice(&self.data.bytes.lock().unwrap()[offset..offset + out.len()]);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        self.data.bytes.lock().unwrap()[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn version(&self) -> u64 {
        0
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn writable(&self) -> bool {
        true
    }
    fn sync_key(&self) -> Option<u64> {
        Some(self.id)
    }
    fn close_resource(&self) -> Option<Arc<dyn SyncResource>> {
        Some(self.close.clone())
    }
    fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}
fn resources() -> (
    Arc<RetiredMemory>,
    Arc<Queue>,
    Arc<trames_linux::FileLayouts>,
) {
    let retired = Arc::new(RetiredMemory::default());
    let queue = Arc::new(Queue::default());
    let layouts = trames_linux::FileLayouts::new(queue.clone());
    retired.bind_layouts(&layouts);
    (retired, queue, layouts)
}

#[test]
fn a_new_cancellation_during_close_submission_preserves_both_original_waves() {
    let (retired, queue, _layouts) = resources();
    let (_target, current) = driver(&retired);
    let mut memory = Memory::default();
    let first = Backing::new();
    let second = Backing::new();
    let lease = first.map(&mut memory, 0x1000);
    let next = second.map(&mut memory, 0x2000);
    memory.write_array(0x1000, [11]).unwrap();
    memory.write_array(0x2000, [22]).unwrap();
    let alias = memory.share();
    let next_alias = memory.share();
    let owner = retired.clone();
    *queue.on_submit.lock().unwrap() = Some(Box::new(move || {
        // The first mm pass has finished, but its close state is still owned
        // by the pump. Publish another real cancellation at that boundary.
        drop(next);
        owner.retire(next_alias).unwrap();
        owner.pump().unwrap();
    }));
    drop(lease);
    retired.retire(alias).unwrap();
    retired.pump().unwrap();
    assert_eq!(queue.len(), 1);
    assert!(current.signal.ready());
    retired.pump().unwrap();
    assert!(memory.validate_mapped(0x1000, 2 * PAGE_SIZE).is_err());
    assert!(!retired.is_empty());
    assert_eq!(
        queue.len(),
        1,
        "second wave retains its resources behind the first close"
    );
    queue.finish();
    assert_eq!(*first.data.saved.lock().unwrap(), vec![11]);
    retired.pump().unwrap();
    assert_eq!(queue.len(), 1);
    assert!(!retired.is_empty());
    queue.finish();
    retired.pump().unwrap();
    assert!(retired.is_empty());
    assert_eq!(*second.data.saved.lock().unwrap(), vec![22]);
    assert!(memory.take_closed_resources().is_empty());
    assert_eq!(
        memory.coordinator_ownership().1,
        1,
        "weak cleanup is never an extra mm owner"
    );
}

#[test]
fn original_close_survives_driver_replacement_and_mm_destruction() {
    let (retired, queue, _layouts) = resources();
    let (_old_target, old) = driver(&retired);
    let mut memory = Memory::default();
    let backing = Backing::new();
    let original = Arc::downgrade(&backing);
    let data = backing.data.clone();
    let lease = backing.map(&mut memory, 0x1000);
    let alias = memory.share();
    drop((lease, backing));
    retired.retire(alias).unwrap();
    retired.pump().unwrap();
    assert_eq!(queue.len(), 1);
    drop(memory);
    assert!(
        original.upgrade().is_some(),
        "accepted close retains its detached backing"
    );
    let (_new_target, next) = driver(&retired);
    drop(old);
    // Consume any work advertised during handoff before clearing the new
    // reader's latch; a reader cannot discard an undrained ready notification.
    retired.pump().unwrap();
    next.signal.reset();
    queue.finish();
    assert!(next.signal.ready());
    retired.pump().unwrap();
    assert!(retired.is_empty());
    assert!(original.upgrade().is_none());
    assert_eq!(*data.saved.lock().unwrap(), vec![0]);
}

#[test]
fn missing_close_capability_keeps_original_resources_until_it_is_bound() {
    let retired = Arc::new(RetiredMemory::default());
    let mut memory = Memory::default();
    let backing = Backing::new();
    let lease = backing.map(&mut memory, 0x1000);
    let alias = memory.share();
    drop(lease);
    retired.retire(alias).unwrap();
    assert!(matches!(retired.pump(), Err(MemoryError::BackingIo(95))));
    assert!(!retired.is_empty());
    assert!(
        memory.take_closed_resources().is_empty(),
        "the original request owns the close"
    );
    let queue = Arc::new(Queue::default());
    let layouts = trames_linux::FileLayouts::new(queue.clone());
    retired.bind_layouts(&layouts);
    retired.pump().unwrap();
    queue.finish();
    retired.pump().unwrap();
    assert!(retired.is_empty());
    assert_eq!(*backing.data.saved.lock().unwrap(), vec![0]);
}

#[test]
fn last_view_publication_gets_a_final_close_before_the_original_mm_is_released() {
    let (retired, queue, _layouts) = resources();
    let mut memory = Memory::default();
    let backing = Backing::new();
    backing.map(&mut memory, 0x1000).commit();
    let mut view = memory.parallel_view(&mut Default::default()).unwrap();
    retired.retire(memory).unwrap();
    retired.pump().unwrap();
    assert_eq!(queue.len(), 0);
    view.write_array(0x1000, [93]).unwrap();
    drop(view);
    retired.pump().unwrap();
    assert_eq!(queue.len(), 1);
    assert!(
        !retired.is_empty(),
        "original mm survives its accepted final writeback"
    );
    queue.finish();
    retired.pump().unwrap();
    assert!(retired.is_empty());
    assert_eq!(*backing.data.saved.lock().unwrap(), vec![93]);
}
