// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions};
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn complete(attempt: IoAttempt) -> Result<u64, Errno> {
    match attempt {
        IoAttempt::Complete(result) => result,
        _ => panic!("completion"),
    }
}
fn blocked(attempt: IoAttempt) -> PendingIo {
    match attempt {
        IoAttempt::Blocked(wait) => wait,
        _ => panic!("retained original queue"),
    }
}
fn memory() -> Memory {
    let mut m = Memory::default();
    m.map(0x1000, 4096, Permissions::RW).unwrap();
    m
}
#[test]
fn blocking_receive_rearms_the_original_queue_after_namespace_change_and_id_collision() {
    let mut vfs = trames_vfs::Vfs::default();
    let old = vfs.descriptor_factory();
    let id = old.message_get(0, 0o600).unwrap();
    let direct = DirectSyscalls::default().with_resources(old.clone());
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let target = Arc::downgrade(&wake);
    let mut memory = memory();
    assert!(direct.supports_call(188, [0; 6]));
    let pending = blocked(
        direct
            .start(
                188,
                [id as u64, 0x1000, 64, 1, 0, 0],
                &mut memory,
                1,
                &target,
                None,
            )
            .unwrap(),
    );
    assert!(!pending.signal.ready());
    vfs.unshare_ipc().unwrap();
    let next = vfs.descriptor_factory();
    assert_eq!(next.message_get(0, 0o600).unwrap(), id);
    old.message_send(id, 1, b"accepted".to_vec(), 1)
        .unwrap()
        .attempt()
        .unwrap();
    assert!(pending.signal.ready());
    pending.signal.reset();
    assert!(old
        .message_receive(id, 0, 8, 0x4800, 1)
        .unwrap()
        .attempt()
        .is_ok());
    assert!(
        !pending.signal.ready(),
        "MSG_COPY changes no data or capacity"
    );
    let retained = pending.message.clone().unwrap();
    drop(pending);
    let next = DirectSyscalls::default().with_resources(next);
    assert_eq!(
        complete(next.start_retained_message(retained, &mut memory, 1, &target)),
        Ok(8)
    );
    assert_eq!(memory.read_array::<8>(0x1000).unwrap(), 1i64.to_le_bytes());
    assert_eq!(memory.read_array::<8>(0x1008).unwrap(), *b"accepted");
}
#[test]
fn removal_wakes_blocked_sender_without_reimporting_a_changed_buffer() {
    let vfs = trames_vfs::Vfs::default();
    let factory = vfs.descriptor_factory();
    let id = factory.message_get(0, 0o600).unwrap();
    for _ in 0..2 {
        factory
            .message_send(id, 1, vec![0; MSGMAX], 1)
            .unwrap()
            .attempt()
            .unwrap();
    }
    let mut memory = memory();
    memory.write_array(0x1000, 2i64.to_le_bytes()).unwrap();
    memory.write(0x1008, b"old").unwrap();
    let direct = DirectSyscalls::default().with_resources(factory.clone());
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let target = Arc::downgrade(&wake);
    let pending = blocked(
        direct
            .start(
                189,
                [id as u64, 0x1000, 3, 0, 0, 0],
                &mut memory,
                1,
                &target,
                None,
            )
            .unwrap(),
    );
    memory.unmap(0x1000, 4096).unwrap();
    factory.message_control(id, 0, None).unwrap();
    assert!(pending.signal.ready());
    assert_eq!(
        complete(direct.resume(pending, &mut memory)),
        Err(Errno(43))
    );
}
#[test]
fn receive_copyout_fault_consumes_message_but_msg_copy_does_not() {
    let factory = trames_vfs::Vfs::default().descriptor_factory();
    let id = factory.message_get(0, 0o600).unwrap();
    factory
        .message_send(id, 1, b"one".to_vec(), 1)
        .unwrap()
        .attempt()
        .unwrap();
    let mut memory = memory();
    assert_eq!(
        call(
            &factory,
            188,
            [id as u64, 0, 64, 0, 0x4800, 0],
            &mut memory,
            1
        ),
        Err(Errno(14))
    );
    assert_eq!(
        call(
            &factory,
            188,
            [id as u64, 0, 64, 0, 0x800, 0],
            &mut memory,
            1
        ),
        Err(Errno(14))
    );
    assert_eq!(
        call(
            &factory,
            188,
            [id as u64, 0x1000, 64, 0, 0x800, 0],
            &mut memory,
            1
        ),
        Err(Errno(42))
    );
}
