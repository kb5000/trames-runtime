// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions};
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn flock(kind: u16) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..2].copy_from_slice(&kind.to_le_bytes());
    bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
    bytes[16..24].copy_from_slice(&8u64.to_le_bytes());
    bytes
}
fn direct(v: &trames_vfs::Vfs) -> DirectSyscalls {
    DirectSyscalls::default()
        .with_resources(v.descriptor_factory())
        .with_lock_context(v.record_lock_context(2))
}
#[test]
fn accepted_record_wait_keeps_its_original_range_file_and_owner_across_handoff() {
    for ofd in [false, true] {
        let mut v = trames_vfs::Vfs::default();
        v.set_lock_owner(1);
        let a = v.open_at(-100, b"/original", 0x42, 0o600).unwrap();
        let b = v.open_at(-100, b"/original", 2, 0).unwrap();
        v.seek(a, 3, 0).unwrap();
        v.seek(b, 3, 0).unwrap();
        let locked = if ofd {
            v.normalize_ofd_lock(a, 1, 1, 0, 8)
        } else {
            v.normalize_lock(a, 1, 1, 0, 8)
        }
        .unwrap();
        v.record_lock_set(a, locked).unwrap();
        let mut peer = v.clone_with_files(false);
        peer.set_lock_owner(2);
        let mut memory = Memory::default();
        memory.map(0x1000, 4096, Permissions::RW).unwrap();
        memory.write_array(0x1000, flock(1)).unwrap();
        let target: Arc<dyn IoWake> = Arc::new(Wake);
        let args = [b as u64, if ofd { 38 } else { 7 }, 0x1000, 0, 0, 0];
        let Some(IoAttempt::Blocked(pending)) =
            direct(&peer).start(25, args, &mut memory, 2, &Arc::downgrade(&target), None)
        else {
            panic!("original record wait must release the execution slot")
        };
        let request = pending.record.as_ref().unwrap().clone();
        peer.close(b).unwrap();
        assert_eq!(peer.open_at(-100, b"/replacement", 0x42, 0o600).unwrap(), b);
        memory.write_array(0x1000, flock(2)).unwrap();
        v.seek(a, 100, 0).unwrap();
        drop(pending);
        let mut unlock = locked;
        unlock.kind = 2;
        v.record_lock_set(a, unlock).unwrap();
        assert!(matches!(
            DirectSyscalls::default().start_record_wait(
                request,
                args,
                &mut memory,
                2,
                &Arc::downgrade(&target)
            ),
            IoAttempt::Complete(Ok(0))
        ));
        let requested = v.normalize_lock(a, 1, 0, 3, 8).unwrap();
        assert!(v.record_lock_conflict(a, requested).unwrap().is_some());
        let replacement = peer.normalize_lock(b, 1, 0, 3, 8).unwrap();
        assert_eq!(peer.record_lock_conflict(b, replacement), Ok(None));
    }
}
#[test]
fn original_source_and_solo_waits_share_one_deadlock_graph() {
    let mut linux = Linux::new(0x100000);
    linux.vfs.set_lock_owner(2);
    let a = linux.vfs.open_at(-100, b"/a", 0x42, 0o600).unwrap();
    let b = linux.vfs.open_at(-100, b"/b", 0x42, 0o600).unwrap();
    let mut peer = Linux::new(0x100000);
    peer.vfs = linux.vfs.clone_with_files(false);
    peer.vfs.set_lock_owner(3);
    for (v, fd) in [(&linux.vfs, a), (&peer.vfs, b)] {
        let lock = v.normalize_lock(fd, 1, 0, 0, 8).unwrap();
        v.record_lock_set(fd, lock).unwrap();
    }
    let mut memory = Memory::default();
    memory.map(0x1000, 4096, Permissions::RW).unwrap();
    memory.write_array(0x1000, flock(1)).unwrap();
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let Some(IoAttempt::Blocked(pending)) = direct(&linux.vfs).start(
        25,
        [b as u64, 7, 0x1000, 0, 0, 0],
        &mut memory,
        2,
        &Arc::downgrade(&target),
        None,
    ) else {
        panic!("source locks wait on original inode")
    };
    let request = peer
        .prepare_record_lock(&mut memory, [a as u64, 7, 0x1000, 0, 0, 0])
        .unwrap();
    assert!(matches!(request.wait(), Err(Errno(35))));
    drop(pending);
    let request = peer
        .prepare_record_lock(&mut memory, [a as u64, 7, 0x1000, 0, 0, 0])
        .unwrap();
    assert!(request.wait().is_ok());
}
#[test]
fn all_range_lock_commands_preserve_source_solo_error_and_pointer_precedence() {
    let mut linux = Linux::new(0x100000);
    let file = linux.vfs.open_at(-100, b"/file", 0x42, 0o600).unwrap();
    let path = linux
        .vfs
        .open_at(-100, b"/", trames_vfs::O_PATH, 0)
        .unwrap();
    let directory = linux.vfs.open_at(-100, b"/", 0, 0).unwrap();
    let pipe = linux.vfs.pipe(0).unwrap()[0];
    let mut memory = Memory::default();
    memory.map(0x1000, 4096, Permissions::RW).unwrap();
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let d = direct(&linux.vfs);
    for command in [5, 6, 7, 36, 37, 38] {
        for (fd, address, kind, expected) in [
            (u32::MAX, 0x9000, 1, 9),
            (path, 0x9000, 1, 9),
            (pipe, 0x9000, 1, 14),
            (directory, 0x1000, 3, 22),
            (directory, 0x1000, 1, 9),
            (file, 0x9000, 1, 14),
        ] {
            memory.write_array(0x1000, flock(kind)).unwrap();
            let args = [fd as u64, command, address, 0, 0, 0];
            assert_eq!(
                linux.syscall(25, args, &mut memory, &mut crate::CapturedOutput::default()),
                Err(Errno(expected))
            );
            if matches!(command, 7 | 38) {
                assert!(
                    matches!(d.start(25,args,&mut memory,2,&Arc::downgrade(&target),None),Some(IoAttempt::Complete(Err(Errno(e)))) if e==expected)
                );
            } else {
                assert_eq!(
                    d.invoke_file(25, args, &mut memory),
                    Some(Err(Errno(expected)))
                );
            }
        }
    }
}
