// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions};
use trames_vfs::{CapturedConsole, Vfs, O_NONBLOCK};

fn memory() -> Memory {
    let mut memory = Memory::default();
    memory.map(0x1000, 4096, Permissions::RW).unwrap();
    memory
}
fn direct(v: &Vfs) -> DirectSyscalls {
    DirectSyscalls::new(v.direct_descriptors())
        .with_membership(v.shared_files())
        .with_resources(v.descriptor_factory())
        .with_paths(v.path_queries())
}
#[test]
fn console_scalar_vector_alias_and_fork_keep_original_bytes_after_fd_reuse() {
    let mut v = Vfs::default();
    let console = Arc::new(CapturedConsole {
        input: b"input!".to_vec().into(),
        ..Default::default()
    });
    v.bind_console(console.clone());
    let input = v.dup(0, 20, false).unwrap();
    let output = v.dup(1, 21, false).unwrap();
    let child = v.clone();
    let d = direct(&child);
    let mut m = memory();
    v.close(0).unwrap();
    assert_eq!(v.eventfd(88, O_NONBLOCK).unwrap(), 0);
    v.close(1).unwrap();
    assert_eq!(v.eventfd(99, O_NONBLOCK).unwrap(), 1);
    assert_eq!(
        d.invoke(63, [input as u64, 0x1100, 3, 0, 0, 0], &mut m),
        Some(Ok(3))
    );
    assert_eq!(m.read_array::<3>(0x1100).unwrap(), *b"inp");
    m.write_array(0x1000, 0x1200u64.to_le_bytes()).unwrap();
    m.write_array(0x1008, 3u64.to_le_bytes()).unwrap();
    assert_eq!(
        d.invoke(65, [input as u64, 0x1000, 1, 0, 0, 0], &mut m),
        Some(Ok(3))
    );
    assert_eq!(m.read_array::<3>(0x1200).unwrap(), *b"ut!");
    assert_eq!(
        d.invoke(64, [output as u64, 0x1100, 3, 0, 0, 0], &mut m),
        Some(Ok(3))
    );
    assert_eq!(
        d.invoke(66, [output as u64, 0x1000, 1, 0, 0, 0], &mut m),
        Some(Ok(3))
    );
    assert_eq!(console.output.snapshot(), b"input!");
    assert_eq!(v.read(0, 8).unwrap(), 88u64.to_le_bytes());
    assert_eq!(v.read(1, 8).unwrap(), 99u64.to_le_bytes());
    // Output preflight remains before consumption; EOF and zero-length reads
    // preserve the original resource contract.
    assert_eq!(
        d.invoke(63, [input as u64, 0x9000, 1, 0, 0, 0], &mut m),
        Some(Err(Errno(14)))
    );
    assert_eq!(
        d.invoke(63, [input as u64, 0x1100, 1, 0, 0, 0], &mut m),
        Some(Ok(0))
    );
}
#[test]
fn all_fd_observations_and_epoll_creation_match_solo_without_compatibility_service() {
    let mut linux = Linux::new(0x10000);
    let mut m = memory();
    linux.vfs.set_runtime_info(
        1,
        trames_vfs::RuntimeInfo {
            processes: vec![trames_vfs::ProcessInfo {
                pid: 1,
                tgid: 1,
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let ep = linux.vfs.epoll_create(0).unwrap();
    let event = linux.vfs.eventfd(1, 0).unwrap();
    let [pipe, _writer] = linux.vfs.pipe(0).unwrap();
    let namespace = linux.vfs.open_at(-100, b"/proc/self/ns/uts", 0, 0).unwrap();
    let d = direct(&linux.vfs);
    for fd in [0, 1, 2, ep, event, pipe, namespace, u32::MAX] {
        for (number, args) in [
            (62, [fd as u64, 0, 0, 0, 0, 0]),
            (80, [fd as u64, 0x1400, 0, 0, 0, 0]),
        ] {
            let worker = d
                .invoke_path(number, args, &mut m)
                .expect("FD observations cannot request owner service");
            let bytes = m.read_array::<128>(0x1400).unwrap();
            m.write(0x1400, &[0; 128]).unwrap();
            let solo = linux.syscall(
                number as u64,
                args,
                &mut m,
                &mut crate::CapturedOutput::default(),
            );
            assert_eq!(worker, solo, "number={number} fd={fd}");
            if number == 80 && worker.is_ok() {
                assert_eq!(m.read_array::<128>(0x1400).unwrap(), bytes);
            }
        }
    }
    assert_eq!(
        d.invoke_creation(20, [1, 0, 0, 0, 0, 0], &mut m),
        Some(Err(Errno(22)))
    );
    let created = d
        .invoke_creation(20, [trames_vfs::O_CLOEXEC as u64, 0, 0, 0, 0, 0], &mut m)
        .unwrap()
        .unwrap() as u32;
    linux.vfs.epoll_ctl(created, 1, event, 1, 42).unwrap();
    let alias = linux.vfs.dup(created, 100, false).unwrap();
    linux.vfs.close(created).unwrap();
    assert_eq!(
        linux.vfs.epoll_wait(alias, 1, |_, _| Ok(None)).unwrap(),
        vec![(1, 42)]
    );
}

#[test]
fn parked_console_input_wakes_and_finishes_against_original_resource_after_close_reuse() {
    struct Wake;
    impl trames_vfs::IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let input = Arc::new(std::sync::Mutex::new(Vec::new()));
    let read = input.clone();
    let poll = input.clone();
    let readiness = Arc::new(trames_vfs::Readiness::default());
    let console = Arc::new(
        trames_vfs::ConsoleCallbacks::new(
            move |count| {
                let mut bytes = read.lock().unwrap();
                if bytes.is_empty() {
                    Err(Errno(11))
                } else {
                    let n = count.min(bytes.len());
                    Ok(bytes.drain(..n).collect())
                }
            },
            |_, _| Err(Errno(32)),
            move |stream, events| {
                (
                    events
                        & if stream == trames_vfs::ConsoleStream::Input
                            && !poll.lock().unwrap().is_empty()
                        {
                            1
                        } else {
                            0
                        },
                    [0; 2],
                )
            },
        )
        .readiness(readiness.clone()),
    );
    let mut v = Vfs::default();
    v.bind_console(console);
    let d = direct(&v);
    let mut m = memory();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let target = Arc::downgrade(&wake);
    let pending = match d
        .start(63, [0, 0x1100, 4, 0, 0, 0], &mut m, 1, &target, None)
        .unwrap()
    {
        IoAttempt::Blocked(pending) => pending,
        _ => panic!("stdin must park"),
    };
    v.close(0).unwrap();
    assert_eq!(v.eventfd(99, 0).unwrap(), 0);
    input.lock().unwrap().extend(b"real");
    readiness.notify_locked();
    assert!(pending.signal.ready());
    assert!(matches!(
        d.resume(pending, &mut m),
        IoAttempt::Complete(Ok(4))
    ));
    assert_eq!(m.read_array::<4>(0x1100).unwrap(), *b"real");
    assert_eq!(v.read(0, 8).unwrap(), 99u64.to_le_bytes());
}

#[test]
fn source_pipe_errors_signal_exactly_once_and_nosignal_keeps_the_errno() {
    #[derive(Default)]
    struct Signals(std::sync::Mutex<Vec<u32>>);
    impl trames_vfs::TaskSignal for Signals {
        fn raise(&self, signal: u32) {
            self.0.lock().unwrap().push(signal);
        }
    }
    let mut v = Vfs::default();
    let [read, write] = v.pipe(0).unwrap();
    let signals = Arc::new(Signals::default());
    let d = direct(&v).with_task_signal(signals.clone());
    let mut m = memory();
    m.write(0x1100, b"x").unwrap();
    v.close(read).unwrap();
    assert_eq!(
        d.invoke(64, [write as u64, 0x1100, 1, 0, 0, 0], &mut m),
        Some(Err(Errno(32)))
    );
    assert_eq!(*signals.0.lock().unwrap(), [13]);
    let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
    v.close(rx).unwrap();
    let d = direct(&v).with_task_signal(signals.clone());
    assert_eq!(
        d.invoke(206, [tx as u64, 0x1100, 1, 0x4000, 0, 0], &mut m),
        Some(Err(Errno(32)))
    );
    assert_eq!(*signals.0.lock().unwrap(), [13]);
    assert_eq!(
        d.invoke(206, [tx as u64, 0x1100, 1, 0, 0, 0], &mut m),
        Some(Err(Errno(32)))
    );
    assert_eq!(*signals.0.lock().unwrap(), [13, 13]);
}
