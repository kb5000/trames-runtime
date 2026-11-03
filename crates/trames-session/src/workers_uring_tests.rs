// SPDX-License-Identifier: GPL-3.0-or-later
//! Whole-subsystem scheduling: the source task makes async progress while its
//! guest CPU remains asleep and a peer uses the same existing execution slot.
use super::*;
use trames_cpu::Cpu;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
fn snapshot(direct: trames_linux::DirectSyscalls) -> crate::worker_syscalls::Snapshot {
    crate::worker_syscalls::Snapshot {
        io_signals: Default::default(),
        io_routes: Default::default(),
        io_wake: None,
        futex: Default::default(),
        seccomp: Default::default(),
        identities: [1; 7],
        started: Instant::now(),
        processor: 0,
        profile: false,
        streams: Default::default(),

        fd_flags: Default::default(),
        umask: Default::default(),
        actions: Default::default(),
        program_break: Default::default(),
        uts: None,
        direct,
    }
}
#[test]
fn uring_background_does_not_retire_sleep_futex_or_lifecycle_waits_on_one_cpu_slot() {
    for mode in 0..3 {
        let mut linux = trames_linux::Linux::new(0x100000);
        let [reader, writer] = linux.vfs.pipe(0).unwrap();
        let (fd, ring) = linux.vfs.uring_create(4, 8).unwrap();
        let mut memory = Memory::default();
        memory.map(0x1000, 4 * PAGE_SIZE, Permissions::RW).unwrap();
        for (address, offset, len) in [
            (0x10000, 0, ring.ring_bytes),
            (0x20000, 0x10000000, ring.sqe_bytes),
        ] {
            memory
                .map_backed(
                    address,
                    linux
                        .vfs
                        .mapping_pages(fd, offset, len, true, true)
                        .unwrap(),
                    true,
                    Permissions::RW,
                    false,
                )
                .unwrap();
        }
        let mut sqe = [0u8; 64];
        sqe[0] = 22;
        sqe[4..8].copy_from_slice(&reader.to_le_bytes());
        sqe[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        sqe[24..28].copy_from_slice(&1u32.to_le_bytes());
        sqe[32..40].copy_from_slice(&17u64.to_le_bytes());
        memory.write(0x20000, &sqe).unwrap();
        memory.write_array(0x10004, 1u32.to_le_bytes()).unwrap();
        memory.write(0x1100, b"q").unwrap();
        for (index, word) in [
            0xd4000001u32,
            0xd2800f88,
            0xd4000001,
            0xd2800ba8,
            0xd4000001,
        ]
        .into_iter()
        .enumerate()
        {
            memory
                .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        memory.protect(0x4000, PAGE_SIZE, Permissions::RX).unwrap();
        let control = Arc::new(Control::new(1000));
        let epoch = crate::run_queue::Epoch::<Cpu>::new(control.clone());
        let mut uring_epoch = trames_linux::UringEpoch::default();
        let direct = trames_linux::DirectSyscalls::new(linux.vfs.direct_descriptors()).with_urings(
            uring_epoch
                .capture(&linux.vfs, memory.instruction_identity().0, 1)
                .with_actor(linux.uring_actor_root()),
        );
        assert!(matches!(
            direct.start(
                426,
                [fd as u64, 1, 0, 0, 0, 0],
                &mut memory,
                1,
                &epoch.io_target,
                None
            ),
            Some(trames_linux::IoAttempt::Complete(Ok(1)))
        ));
        linux.vfs.close(fd).unwrap();
        linux.vfs.close(reader).unwrap();
        let source = memory.parallel_view(&mut Default::default()).unwrap();
        let peer = source.clone();
        let mut cpu = Cpu::default();
        cpu.set_x(0, 0x7788);
        let futexes = crate::futex::Futexes::default();
        let deadline = Instant::now() + Duration::from_secs(3600);
        let waiting = match mode {
            0 => crate::run_queue::WaitState::Sleep {
                deadline,
                remaining: 0x1234,
            },
            1 => crate::run_queue::WaitState::Futex {
                wait: futexes
                    .wait((0, 1, 0x1000), 1, 1, || Ok::<_, ()>(()))
                    .unwrap(),
                deadline: None,
            },
            _ => crate::run_queue::WaitState::OwnerEvent,
        };
        epoch.add(crate::run_queue::Job::new(
            Work {
                audio: None,
                gpu: None,
                pid: 1,
                cpu,
                memory: Some(Box::new(source)),
                control: control.clone(),
                syscalls: Some(snapshot(direct)),
            },
            1,
            0,
            Some(waiting),
        ));
        let mut cpu = Cpu::new(0x4000, 0);
        cpu.set_x(8, 64);
        cpu.set_x(0, writer as u64);
        cpu.set_x(1, 0x1100);
        cpu.set_x(2, 1);
        let direct = trames_linux::DirectSyscalls::new(linux.vfs.direct_descriptors());
        epoch.add(crate::run_queue::Job::new(
            Work {
                audio: None,
                gpu: None,
                pid: 2,
                cpu,
                memory: Some(Box::new(peer)),
                control,
                syscalls: Some(snapshot(direct)),
            },
            1,
            0,
            None,
        ));
        epoch.assign(&[(1, 0)]);
        let mut pool = Pool::<Cpu>::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain();
        let source = done.iter().find(|task| task.pid == 1).unwrap();
        assert_eq!(source.cpu.x(0), 0x7788);
        assert_eq!(source.instructions, 0);
        assert!(matches!(
            source.outcome,
            Some(SliceOutcome::Yield { instructions: 0 })
        ));
        assert!(source.waiting.is_some());
        assert!(source.assignments >= 2);
        assert_eq!(source.serviced_syscalls, 0);
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<1>(0x1000).unwrap(), *b"q");
        assert_eq!(ring.cq_ready(), 1);
        assert_eq!(
            ring.read_queue::<8>(trames_vfs::URING_CQES),
            17u64.to_le_bytes()
        );
        assert!(uring_epoch.finish().is_empty());
    }
}
