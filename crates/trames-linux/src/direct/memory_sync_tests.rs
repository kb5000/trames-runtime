// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use trames_memory::{Memory, MemoryError, Permissions, SharedPage, PAGE_SIZE};

struct Probe {
    id: u64,
    layout: Option<Arc<trames_memory::layout::Layout>>,
    page: Arc<SharedPage>,
    calls: AtomicUsize,
    result: i32,
}
impl Probe {
    fn new(result: i32) -> Arc<Self> {
        Arc::new(Self {
            id: trames_memory::new_backing_identity(),
            layout: Some(Arc::default()),
            page: Arc::new(SharedPage::zero()),
            calls: AtomicUsize::new(0),
            result,
        })
    }
    fn map(self: &Arc<Self>, memory: &mut Memory, base: u64) {
        memory
            .map_backed(base, vec![self.clone()], true, Permissions::RW, false)
            .unwrap();
    }
}
impl PageBacking for Probe {
    fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        self.layout.clone()
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.id, 0))
    }
    fn shared_page(&self) -> Option<Arc<SharedPage>> {
        Some(self.page.clone())
    }
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        self.page.copy_read(offset, out);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        self.page.copy_write(offset, bytes);
        Ok(())
    }
    fn sync(&self) -> Result<(), MemoryError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match self.result {
            0 => Ok(()),
            -1 => panic!("injected backing failure"),
            code => Err(MemoryError::BackingIo(code as u32)),
        }
    }
    fn sync_key(&self) -> Option<u64> {
        Some(self.id)
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
type Host = (
    Box<dyn crate::HostFileTask>,
    Option<crate::HostFileAdmission>,
);
#[derive(Default)]
struct Queue(Mutex<Vec<Host>>);
impl FileExecutor for Queue {
    fn submit_file(&self, _: trames_vfs::FileWork, _: Arc<FileResult>) {
        panic!("not a file replay")
    }
    fn submit_host(
        &self,
        work: Box<dyn crate::HostFileTask>,
        admission: Option<crate::HostFileAdmission>,
    ) {
        self.0.lock().unwrap().push((work, admission));
    }
}
impl Queue {
    fn take(&self, layouts: &crate::FileLayouts) -> Host {
        for request in layouts.take_owner() {
            assert!(
                layouts.try_submit(request).is_ok(),
                "original backing is quiescent"
            );
        }
        let mut pending = self.0.lock().unwrap();
        assert_eq!(pending.len(), 1);
        pending.pop().unwrap()
    }
}
#[derive(Default)]
struct Target(AtomicUsize);
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn target() -> Arc<dyn IoWake> {
    Arc::new(Target::default())
}

#[test]
fn mapped_sync_retains_original_resources_and_completion_across_unmap_and_handoff() {
    let first = Probe::new(0);
    let second = Probe::new(0);
    let replacement = Probe::new(0);
    let mut memory = Memory::default();
    first.map(&mut memory, 0x1000);
    first.map(&mut memory, 0x2000);
    second.map(&mut memory, 0x3000);
    let queue = Arc::new(Queue::default());
    let layouts = crate::FileLayouts::new(queue.clone());
    let source = DirectSyscalls::default().with_file_layouts(layouts.clone());
    let old_target = target();
    let mut registry = trames_memory::parallel::Registry::default();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    let args = [0x1000, 3 * PAGE_SIZE, 4, 0, 0, 0];
    let Some(IoAttempt::Blocked(wait)) =
        source.start_file_call(227, args, &mut view, 1, &Arc::downgrade(&old_target))
    else {
        panic!("return execution slot")
    };
    assert!(wait.external_wait() && wait.notification_external());
    let pending = wait.file_pending().unwrap();
    assert!(!pending.interruptible());
    assert_eq!(first.calls.load(Ordering::Relaxed), 0);
    drop((wait, source, old_target, view));
    memory.commit_parallel().unwrap();
    memory.unmap(0x1000, 3 * PAGE_SIZE).unwrap();
    replacement.map(&mut memory, 0x1000);
    let new_target = target();
    let IoAttempt::Blocked(wait) = DirectSyscalls::default().start_retained_file(
        pending,
        227,
        args,
        &mut memory,
        9,
        &Arc::downgrade(&new_target),
    ) else {
        panic!("retain original accepted sync")
    };
    let pending = wait.file_pending().unwrap();
    let (work, admission) = queue.take(&layouts);
    work.run(admission);
    assert_eq!(
        first.calls.load(Ordering::Relaxed),
        1,
        "aliases deduplicate by original sync key"
    );
    assert!(
        !wait.signal.ready(),
        "multi-backing completion waits for the last original resource"
    );
    let (work, admission) = queue.take(&layouts);
    work.run(admission);
    assert!(wait.signal.ready());
    drop(wait);
    assert!(matches!(
        DirectSyscalls::default().start_retained_file(
            pending,
            227,
            args,
            &mut memory,
            9,
            &Arc::downgrade(&new_target)
        ),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(second.calls.load(Ordering::Relaxed), 1);
    assert_eq!(replacement.calls.load(Ordering::Relaxed), 0);
    assert!(!layouts.pending());
}

#[test]
fn mapped_sync_error_unwind_and_closed_pool_release_admissions_and_stop_the_suffix() {
    for mode in [13, -1, -2] {
        let first = Probe::new(mode);
        let second = Probe::new(0);
        let mut memory = Memory::default();
        first.map(&mut memory, 0x1000);
        second.map(&mut memory, 0x2000);
        let queue = Arc::new(Queue::default());
        let layouts = crate::FileLayouts::new(queue.clone());
        let source = DirectSyscalls::default().with_file_layouts(layouts.clone());
        let wake = target();
        let Some(IoAttempt::Blocked(wait)) = source.start_file_call(
            227,
            [0x1000, 2 * PAGE_SIZE, 4, 0, 0, 0],
            &mut memory,
            1,
            &Arc::downgrade(&wake),
        ) else {
            panic!("native work")
        };
        let pending = wait.file_pending().unwrap();
        let (work, admission) = queue.take(&layouts);
        if mode == -2 {
            work.fail();
            drop(admission);
        } else {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work.run(admission)));
            assert_eq!(result.is_err(), mode == -1);
        }
        assert!(wait.signal.ready());
        let result = source.start_retained_file(
            pending,
            227,
            wait.args,
            &mut memory,
            1,
            &Arc::downgrade(&wake),
        );
        assert!(
            matches!(result, IoAttempt::Complete(Err(Errno(code))) if code == if mode == 13 {13} else {5})
        );
        assert_eq!(second.calls.load(Ordering::Relaxed), 0);
        assert!(!layouts.pending());
        assert!(!first.layout.as_ref().unwrap().pending());
        assert!(queue.0.lock().unwrap().is_empty());
    }
}

#[test]
fn mapped_sync_cancelled_wait_and_dropped_layout_owner_do_not_form_a_resource_cycle() {
    for admitted in [false, true] {
        let first = Probe::new(0);
        let second = Probe::new(0);
        let mut memory = Memory::default();
        first.map(&mut memory, 0x1000);
        second.map(&mut memory, 0x2000);
        let queue = Arc::new(Queue::default());
        let layouts = crate::FileLayouts::new(queue.clone());
        let weak = Arc::downgrade(&layouts);
        let source = DirectSyscalls::default().with_file_layouts(layouts.clone());
        let wake = target();
        let args = [0x1000, 2 * PAGE_SIZE, 4, 0, 0, 0];
        let Some(IoAttempt::Blocked(wait)) =
            source.start_file_call(227, args, &mut memory, 1, &Arc::downgrade(&wake))
        else {
            panic!("native work")
        };
        let pending = wait.file_pending().unwrap();
        let host = admitted.then(|| queue.take(&layouts));
        drop((wait, source, layouts, wake));
        assert!(
            weak.upgrade().is_none(),
            "pending work must not retain its enclosing queue"
        );
        if let Some((work, admission)) = host {
            work.run(admission);
        }
        assert_eq!(first.calls.load(Ordering::Relaxed), usize::from(admitted));
        assert_eq!(second.calls.load(Ordering::Relaxed), 0);
        assert!(pending.result.ready());
        let wake = target();
        assert!(matches!(
            DirectSyscalls::default().start_retained_file(
                pending,
                227,
                args,
                &mut memory,
                1,
                &Arc::downgrade(&wake)
            ),
            IoAttempt::Complete(Err(Errno(5)))
        ));
        assert!(!first.layout.as_ref().unwrap().pending());
        assert!(!second.layout.as_ref().unwrap().pending());
    }
}

#[test]
fn msync_source_solo_errors_and_noop_ranges_share_one_import_without_native_work() {
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::NONE).unwrap();
    let mut registry = trames_memory::parallel::Registry::default();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    let wake = target();
    let direct = DirectSyscalls::default();
    for (args, expected) in [
        ([0x1000, 1, 0, 0, 0, 0], Ok(0)),
        ([0x1000, 1, 1, 0, 0, 0], Ok(0)),
        ([0x1000, 1, 2, 0, 0, 0], Ok(0)),
        ([0x1000, 1, 4, 0, 0, 0], Ok(0)),
        ([0x1000, 1, 6, 0, 0, 0], Ok(0)),
        ([0x1000, 1, 5, 0, 0, 0], Err(Errno(22))),
        ([0x1000, 1, 8, 0, 0, 0], Err(Errno(22))),
        ([0x1001, 0, 0, 0, 0, 0], Err(Errno(22))),
        ([!4095, 0, 0, 0, 0, 0], Ok(0)),
        ([0x1000, u64::MAX, 4, 0, 0, 0], Err(Errno(22))),
        ([0x1000, 2 * PAGE_SIZE, 4, 0, 0, 0], Err(Errno(12))),
    ] {
        let solo = crate::memory_sync::prepare(&memory, args)
            .unwrap()
            .and_then(|work| work.run().map(|()| 0).map_err(Linux::memory_errno));
        assert_eq!(solo, expected, "solo args {args:?}");
        let Some(IoAttempt::Complete(value)) =
            direct.start_file_call(227, args, &mut view, 1, &Arc::downgrade(&wake))
        else {
            panic!("no backing work for {args:?}")
        };
        assert_eq!(value, expected, "source args {args:?}");
    }
}

#[test]
fn msync_missing_original_layout_capability_defers_before_callback_effects() {
    let probe = Arc::new(Probe {
        id: trames_memory::new_backing_identity(),
        layout: None,
        page: Arc::new(SharedPage::zero()),
        calls: AtomicUsize::new(0),
        result: 0,
    });
    let mut memory = Memory::default();
    probe.map(&mut memory, 0x1000);
    let mut view = memory
        .parallel_view(&mut trames_memory::parallel::Registry::default())
        .unwrap();
    let direct = DirectSyscalls::default();
    let wake = target();
    assert!(direct
        .start_file_call(
            227,
            [0x1000, PAGE_SIZE, 4, 0, 0, 0],
            &mut view,
            1,
            &Arc::downgrade(&wake)
        )
        .is_none());
    assert_eq!(probe.calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        direct.start_file_call(
            227,
            [0x1001, 0, 0, 0, 0, 0],
            &mut view,
            1,
            &Arc::downgrade(&wake)
        ),
        Some(IoAttempt::Complete(Err(Errno(22))))
    ));
}
