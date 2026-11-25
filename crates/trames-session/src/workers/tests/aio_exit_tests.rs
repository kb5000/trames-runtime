// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
#[derive(Default)]
struct Disk(Mutex<Option<(trames_vfs::FileWork, Arc<trames_linux::FileResult>)>>);
impl trames_linux::FileExecutor for Disk {
    fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<trames_linux::FileResult>) {
        result.begin();
        *self.0.lock().unwrap() = Some((work, result));
    }
}
#[test]
fn fatal_aio_wait_releases_the_only_slot_without_requeueing_exit_or_discarding_original_request() {
    let mut vfs = trames_vfs::Vfs::default();
    vfs.import_file(b"/data", b"data".to_vec()).unwrap();
    let fd = vfs.open_at(-100, b"/data", 0, 0).unwrap();
    let disk = Arc::new(Disk::default());
    let aio = trames_linux::Aio::default();
    let mut snapshot = syscall_snapshot();
    snapshot.direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors())
        .with_aio(aio.clone(), vfs.native_events())
        .with_paths(vfs.path_queries())
        .with_file_executor(disk.clone());
    let control = Arc::new(Control::new(1));
    let epoch = crate::run_queue::Epoch::new(control.clone());
    let mut memory = Memory::default();
    memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
    let trames_linux::IoAttempt::Complete(Ok(0)) = snapshot
        .direct
        .start(
            0,
            [8, 0x1000, 0, 0, 0, 0],
            &mut memory,
            1,
            &epoch.io_target,
            None,
        )
        .unwrap()
    else {
        panic!("original setup");
    };
    let id = memory.read_u64(0x1000).unwrap();
    let mut cb = [0; 64];
    cb[20..24].copy_from_slice(&fd.to_le_bytes());
    cb[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
    cb[32..40].copy_from_slice(&4u64.to_le_bytes());
    memory.write_array(0x2000, cb).unwrap();
    memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
    let trames_linux::IoAttempt::Blocked(wait) = snapshot
        .direct
        .start(
            2,
            [id, 1, 0x1800, 0, 0, 0],
            &mut memory,
            1,
            &epoch.io_target,
            None,
        )
        .unwrap()
    else {
        panic!("native request must queue");
    };
    let original_wake = wait.signal.clone();
    snapshot.io_signals.lifecycle().request_exit(9);
    let mut cpu = Cpu::new(0x5000, 0);
    cpu.set_x(8, 2);
    cpu.set_x(0, id);
    cpu.set_x(1, 1);
    cpu.set_x(2, 0x1800);
    let source = Work {
        task: None,
        audio: None,
        gpu: None,
        pid: 1,
        cpu,
        memory: Some(Box::new(
            memory.parallel_view(&mut Default::default()).unwrap(),
        )),
        control: control.clone(),
        trace: Default::default(),
        syscalls: Some(snapshot),
    };
    let mut source = crate::run_queue::Job::new(source, 1, 0, None);
    source.io = Some(wait);
    epoch.add(source);
    epoch.add(crate::run_queue::Job::new(
        work(2, &[0xd4000001], 0, control),
        1,
        0,
        None,
    ));
    let mut pool = Pool::new(1);
    pool.ensure(0).unwrap();
    pool.launch(0, epoch.clone()).unwrap();
    assert!(matches!(
        pool.event_timeout(Duration::from_secs(5)).unwrap(),
        Some(Event::EpochStopped(0))
    ));
    let mut done = epoch.drain();
    let source = done.remove(done.iter().position(|done| done.pid == 1).unwrap());
    assert_eq!(done[0].instructions, 1);
    assert_eq!(source.instructions, 0);
    assert_eq!(source.syscalls, 0);
    assert_eq!(source.serviced_syscalls, 0);
    assert_eq!(
        source.resumes, 0,
        "fatal exit alone cannot requeue a native wait"
    );
    let wait = source
        .io
        .expect("original request remains attached to the exiting task");
    assert!(wait.aio.as_ref().unwrap().exit_waiting());
    assert!(!original_wake.ready());
    let (work, result) = disk.0.lock().unwrap().take().unwrap();
    result.complete(work.run());
    memory.commit_parallel().unwrap();
    let direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors())
        .with_aio(aio, vfs.native_events());
    assert!(matches!(
        direct.drain_aio_exit(wait.aio.unwrap(), &mut memory, 1, &epoch.io_target),
        trames_linux::IoAttempt::Complete(Ok(1))
    ));
    assert_eq!(memory.read_array::<4>(0x3000).unwrap(), *b"data");
}
