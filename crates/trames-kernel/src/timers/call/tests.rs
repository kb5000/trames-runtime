// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::signal::frame_copy_tests::Faults;
use trames_memory::PAGE_SIZE;
fn fixture() -> (Arc<Timers>, Arc<IoDirectory>, Arc<IoTask>, Faults) {
    let (timers, directory, task, _) = super::super::tests::setup();
    (Arc::new(timers), directory, task, Faults::new(0x2000))
}
fn request(
    timers: &Arc<Timers>,
    directory: &Arc<IoDirectory>,
    task: &Arc<IoTask>,
    number: u32,
    args: [u64; 6],
) -> Call {
    Call::new(
        timers.clone(),
        number,
        args,
        Instant::now(),
        task.clone(),
        directory.clone(),
        PidNamespace::default(),
    )
}
fn invoke(
    timers: &Timers,
    directory: &IoDirectory,
    task: &IoTask,
    memory: &mut impl CpuMemory,
    number: u32,
    args: [u64; 6],
) -> Result<u64, Errno> {
    timers.call(
        number,
        args,
        memory,
        Instant::now(),
        task,
        directory,
        &PidNamespace::default(),
    )
}
fn spec(memory: &mut impl CpuMemory, address: u64, interval: u64, value: u64) {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&interval.to_le_bytes());
    bytes[16..24].copy_from_slice(&value.to_le_bytes());
    memory.write_array(address, bytes).unwrap();
}
fn create(
    timers: &Timers,
    directory: &IoDirectory,
    task: &IoTask,
    memory: &mut impl CpuMemory,
) -> i32 {
    invoke(
        timers,
        directory,
        task,
        memory,
        107,
        [1, 0, 0x1100, 0, 0, 0],
    )
    .unwrap();
    i32::from_le_bytes(memory.read_array::<4>(0x1100).unwrap())
}
#[test]
fn posix_set_exchanges_once_before_output_wait_and_keeps_original_predecessor() {
    let (timers, directory, task, mut memory) = fixture();
    let id = create(&timers, &directory, &task, &mut memory.memory);
    spec(&mut memory.memory, 0x1200, 7, 3600);
    invoke(
        &timers,
        &directory,
        &task,
        &mut memory.memory,
        110,
        [id as u64, 0, 0x1200, 0, 0, 0],
    )
    .unwrap();
    spec(&mut memory.memory, 0x1200, 11, 7200);
    let mut call = request(
        &timers,
        &directory,
        &task,
        110,
        [id as u64, 0, 0x1200, 0x1ff0, 0, 0],
    );
    assert_eq!(call.check(&mut memory), None);
    assert_eq!(
        timers
            .lookup(42, id)
            .unwrap()
            .state
            .lock()
            .unwrap()
            .interval,
        Duration::from_secs(11)
    );
    assert_eq!(memory.memory.read_u64(0x1ff0).unwrap(), 7);
    memory
        .memory
        .write_array(0x1ff0, 99u64.to_le_bytes())
        .unwrap();
    spec(&mut memory.memory, 0x1200, 23, 0);
    invoke(
        &timers,
        &directory,
        &task,
        &mut memory.memory,
        110,
        [id as u64, 0, 0x1200, 0, 0, 0],
    )
    .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(memory.memory.read_u64(0x1ff0).unwrap(), 99);
    assert!(memory.memory.read_u64(0x2000).unwrap() >= 3599);
    assert_eq!(
        timers
            .lookup(42, id)
            .unwrap()
            .state
            .lock()
            .unwrap()
            .interval,
        Duration::from_secs(23)
    );
    assert!(timers.next_deadline().is_none());
}
#[test]
fn posix_input_is_complete_before_lookup_and_keeps_copied_fragments() {
    for deleted in [false, true] {
        let (timers, directory, task, mut memory) = fixture();
        let id = create(&timers, &directory, &task, &mut memory.memory);
        spec(&mut memory.memory, 0x1ff0, 5, 3600);
        let mut call = request(
            &timers,
            &directory,
            &task,
            110,
            [id as u64, 0, 0x1ff0, 0, 0, 0],
        );
        assert_eq!(call.check(&mut memory), None);
        assert!(timers
            .lookup(42, id)
            .unwrap()
            .state
            .lock()
            .unwrap()
            .deadline
            .is_none());
        memory
            .memory
            .write_array(0x1ff0, 99u64.to_le_bytes())
            .unwrap();
        if deleted {
            invoke(
                &timers,
                &directory,
                &task,
                &mut memory.memory,
                111,
                [id as u64, 0, 0, 0, 0, 0],
            )
            .unwrap();
        }
        memory.wait.finish();
        assert_eq!(
            call.check(&mut memory),
            Some(if deleted { Err(Errno(22)) } else { Ok(0) })
        );
        if !deleted {
            assert_eq!(
                timers
                    .lookup(42, id)
                    .unwrap()
                    .state
                    .lock()
                    .unwrap()
                    .interval,
                Duration::from_secs(5)
            );
        }
    }
}
#[test]
fn create_reserves_id_but_publishes_only_after_its_original_output_completes() {
    let (timers, directory, task, mut memory) = fixture();
    let mut call = request(&timers, &directory, &task, 107, [1, 0, 0x1ffe, 0, 0, 0]);
    assert_eq!(call.check(&mut memory), None);
    assert!(!call.ready());
    assert_eq!(timers.registry.read().unwrap().reserved.len(), 1);
    assert!(timers.lookup(42, 1).is_err());
    let other = create(&timers, &directory, &task, &mut memory.memory);
    assert_ne!(other, 1);
    memory.memory.write_array(0x1ffe, [0x77; 2]).unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert!(timers.lookup(42, 1).is_ok());
    assert!(timers.registry.read().unwrap().reserved.is_empty());
    assert_eq!(memory.memory.read_array::<2>(0x1ffe).unwrap(), [0x77; 2]);
    assert_eq!(timers.registry.read().unwrap().timers.len(), 2);
}
#[test]
fn create_output_failure_and_cancellation_release_unpublished_original_reservation() {
    for cancelled in [false, true] {
        let (timers, directory, task, mut memory) = fixture();
        let mut call = request(&timers, &directory, &task, 107, [1, 0, 0x1ffe, 0, 0, 0]);
        assert_eq!(call.check(&mut memory), None);
        assert_eq!(timers.registry.read().unwrap().reserved.len(), 1);
        if cancelled {
            call.cancel();
        } else {
            memory.memory.unmap(0x2000, PAGE_SIZE).unwrap();
        }
        memory.wait.finish();
        assert_eq!(
            call.check(&mut memory),
            Some(Err(Errno(if cancelled { 4 } else { 14 })))
        );
        assert!(timers.registry.read().unwrap().reserved.is_empty());
        assert!(timers.registry.read().unwrap().timers.is_empty());
    }
}
#[test]
fn create_event_import_precedes_clock_validation_and_keeps_original_event_bytes() {
    let (timers, directory, task, mut memory) = fixture();
    assert_eq!(
        invoke(
            &timers,
            &directory,
            &task,
            &mut memory.memory,
            107,
            [999, 0x90000, 0x1100, 0, 0, 0]
        ),
        Err(Errno(14))
    );
    let mut event = [0; 64];
    event[..8].copy_from_slice(&0x1234u64.to_le_bytes());
    event[8..12].copy_from_slice(&12u32.to_le_bytes());
    memory.memory.write_array(0x1ff0, event).unwrap();
    let mut call = request(
        &timers,
        &directory,
        &task,
        107,
        [1, 0x1ff0, 0x1100, 0, 0, 0],
    );
    assert_eq!(call.check(&mut memory), None);
    assert!(timers.registry.read().unwrap().reserved.is_empty());
    memory
        .memory
        .write_array(0x1ff8, 10u32.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    let id = i32::from_le_bytes(memory.memory.read_array::<4>(0x1100).unwrap());
    let timer = timers.lookup(42, id).unwrap();
    assert_eq!(timer.signal, 12);
    assert_eq!(timer.value, 0x1234);
}
#[test]
fn interval_real_virtual_and_prof_effects_are_not_repeated_after_output_wait() {
    for which in 0..=2 {
        let (timers, directory, task, mut memory) = fixture();
        spec(&mut memory.memory, 0x1200, 7, 3600);
        invoke(
            &timers,
            &directory,
            &task,
            &mut memory.memory,
            103,
            [which, 0x1200, 0, 0, 0, 0],
        )
        .unwrap();
        spec(&mut memory.memory, 0x1200, 11, 7200);
        let mut call = request(
            &timers,
            &directory,
            &task,
            103,
            [which, 0x1200, 0x1ff0, 0, 0, 0],
        );
        assert_eq!(call.check(&mut memory), None);
        invoke(
            &timers,
            &directory,
            &task,
            &mut memory.memory,
            102,
            [which, 0x1300, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(memory.memory.read_u64(0x1300).unwrap(), 11);
        invoke(
            &timers,
            &directory,
            &task,
            &mut memory.memory,
            103,
            [which, 0, 0, 0, 0, 0],
        )
        .unwrap();
        memory.wait.finish();
        assert_eq!(call.check(&mut memory), Some(Ok(0)));
        assert_eq!(memory.memory.read_u64(0x1ff0).unwrap(), 7);
        invoke(
            &timers,
            &directory,
            &task,
            &mut memory.memory,
            102,
            [which, 0x1300, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(memory.memory.read_array::<32>(0x1300).unwrap(), [0; 32]);
    }
}
#[test]
fn timer_get_snapshot_is_owned_before_concurrent_delete_and_input_errors_keep_native_order() {
    let (timers, directory, task, mut memory) = fixture();
    let id = create(&timers, &directory, &task, &mut memory.memory);
    spec(&mut memory.memory, 0x1200, 7, 3600);
    invoke(
        &timers,
        &directory,
        &task,
        &mut memory.memory,
        110,
        [id as u64, 0, 0x1200, 0, 0, 0],
    )
    .unwrap();
    let mut call = request(
        &timers,
        &directory,
        &task,
        108,
        [id as u64, 0x1ff0, 0, 0, 0, 0],
    );
    assert_eq!(call.check(&mut memory), None);
    invoke(
        &timers,
        &directory,
        &task,
        &mut memory.memory,
        111,
        [id as u64, 0, 0, 0, 0, 0],
    )
    .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(memory.memory.read_u64(0x1ff0).unwrap(), 7);
    assert!(memory.memory.read_u64(0x2000).unwrap() >= 3599);
    assert_eq!(
        invoke(
            &timers,
            &directory,
            &task,
            &mut memory.memory,
            110,
            [999, 0, 0, 0, 0, 0]
        ),
        Err(Errno(22))
    );
    assert_eq!(
        invoke(
            &timers,
            &directory,
            &task,
            &mut memory.memory,
            110,
            [999, 0, 0x90000, 0, 0, 0]
        ),
        Err(Errno(14))
    );
    assert_eq!(
        invoke(
            &timers,
            &directory,
            &task,
            &mut memory.memory,
            103,
            [999, 0x90000, 0, 0, 0, 0]
        ),
        Err(Errno(14))
    );
}
#[test]
fn clock_specific_create_failure_happens_after_id_copy_and_retires_reservation() {
    let (timers, directory, _task, mut memory) = fixture();
    let task = Arc::new(IoTask::default());
    let mut event = [0; 64];
    event[12..16].copy_from_slice(&1u32.to_le_bytes());
    memory.memory.write_array(0x1200, event).unwrap();
    let mut call = request(
        &timers,
        &directory,
        &task,
        107,
        [3, 0x1200, 0x1100, 0, 0, 0],
    );
    assert_eq!(call.check(&mut memory), Some(Err(Errno(3))));
    assert_eq!(
        memory.memory.read_array::<4>(0x1100).unwrap(),
        1i32.to_le_bytes()
    );
    assert!(timers.registry.read().unwrap().reserved.is_empty());
    assert!(timers.registry.read().unwrap().timers.is_empty());
}
