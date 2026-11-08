// SPDX-License-Identifier: GPL-3.0-or-later
//! Real source SVC/parking tests for the complete guest job-control subsystem.
use super::socket_wait_tests::{filter, mov, program};
use super::*;
use trames_cpu::Cpu as Interpreter;
use trames_linux::CapturedOutput;

fn routes(p: &Process<Interpreter>) -> trames_kernel::signal::IoRoutes {
    trames_kernel::signal::IoRoutes {
        directory: p.signals.io_directory.clone(),
        namespace: p.linux.vfs.pid_namespace().clone(),
        uid: p.linux.vfs.credentials.uid,
        euid: p.linux.vfs.credentials.euid,
    }
}
fn pair(p: &mut Process<Interpreter>) -> (u32, u32, Arc<trames_vfs::Pty>) {
    pair_kind(p, true)
}
fn pair_kind(p: &mut Process<Interpreter>, private: bool) -> (u32, u32, Arc<trames_vfs::Pty>) {
    p.linux.vfs.set_runtime_info(1, Default::default());
    p.linux.vfs.enable_terminal().unwrap();
    p.linux.vfs.set_controlling_terminal(None).unwrap();
    if private {
        p.linux.vfs.mkdir_at(AT_FDCWD, b"/pts", 0o755).unwrap();
        p.linux
            .vfs
            .mount(
                Some(b"devpts"),
                b"/pts",
                Some(b"devpts"),
                0,
                Some(b"newinstance,ptmxmode=0666,max=4"),
            )
            .unwrap();
    }
    let master = p
        .linux
        .vfs
        .open_at(
            AT_FDCWD,
            if private { b"/pts/ptmx" } else { b"/dev/ptmx" },
            2,
            0,
        )
        .unwrap();
    let pair = p.linux.vfs.pty(master).unwrap().unwrap().pair.clone();
    pair.locked
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let slave = p.linux.vfs.open_pty_peer(master, 2 | 0x100).unwrap();
    (master, slave, pair)
}
fn call(code: &mut Vec<u32>, number: u32, args: &[u32], index: u32) {
    for (r, &value) in args.iter().enumerate() {
        code.push(mov(r as u32, value & 0xffff));
        if value > 0xffff {
            code.push(0xf2a00000 | ((value >> 16) << 5) | r as u32);
        }
    }
    code.extend([
        mov(8, number),
        0xd4000001,
        mov(10, 0x1800 + index * 8),
        0xf9000140,
    ]);
}
fn park(code: &mut Vec<u32>) {
    code.extend([
        mov(0, 0x1040),
        mov(1, 128),
        mov(2, 0),
        mov(3, 0),
        mov(8, 98),
        0xd4000001,
        0x14000000,
    ]);
}
fn run(
    k: &mut Kernel<Interpreter>,
    root: Box<Process<Interpreter>>,
    mut child: Box<Process<Interpreter>>,
    slots: usize,
    code: Vec<u32>,
    parent: Vec<u32>,
) {
    let mut root = root;
    program(&mut root, parent);
    program(&mut child, code);
    if slots == 2 {
        root.signals.io.scheduling.set_affinity(2);
    }
    k.cpu_count = 2;
    k.workers = crate::workers::Pool::new(slots);
    k.per_cpu = vec![Duration::ZERO; 2];
    k.processes.insert(1, root);
    k.processes.insert(2, child);
    assert!(k
        .parallel_epoch(&mut CapturedOutput::default(), 100_000, true)
        .unwrap());
    assert_eq!(k.service_requests, 0);
    assert!(
        k.cohort_return_syscalls
            .iter()
            .all(|(number, _)| !matches!(*number,29 | 56 | 63..=66 | 154..=157)),
        "{:?}",
        k.cohort_return_syscalls
    );
}
#[test]
fn source_session_controls_signal_input_and_automatic_slave_opens_need_no_owner() {
    for (slots, private) in [1, 2]
        .into_iter()
        .flat_map(|slots| [true, false].map(move |private| (slots, private)))
    {
        let mut k = super::tests::kernel();
        let mut root = super::tests::process();
        let (master, slave, pair) = pair_kind(&mut root, private);
        let path = if private {
            format!("/pts/{}\0", pair.number)
        } else {
            format!("/dev/pts/{}\0", pair.id)
        };
        root.memory.write(0x1000, path.as_bytes()).unwrap();
        root.memory.write(0x1020, b"/dev/tty\0").unwrap();
        root.memory.write(0x1080, b"\x03").unwrap();
        root.memory
            .write_array(0x1100, ((1u64 << 1) | (1 << 27) | (1 << 0)).to_le_bytes())
            .unwrap();
        root.memory.write_array(0x1120, 2u32.to_le_bytes()).unwrap();
        root.memory
            .write(0x1140, &[40, 0, 120, 0, 0, 0, 0, 0])
            .unwrap();
        root.signals.mask = (1 << 1) | (1 << 27) | (1 << 0);
        filter(&mut k, &mut root, 0x7fff0000);
        let mut child = root.fork();
        child.tgid = 2;
        child.family.set_parent(1);
        let mut code = Vec::new();
        call(&mut code, 157, &[], 0);
        call(&mut code, 155, &[0], 1);
        call(&mut code, 156, &[0], 2);
        // No O_NOCTTY: source open must acquire the terminal itself.
        call(&mut code, 56, &[0, 0x1000, 2, 0], 3);
        call(&mut code, 56, &[0, 0x1020, 2, 0], 4);
        for (index, request, address) in [
            (5, 0x540f, 0x1200),
            (6, 0x5429, 0x1204),
            (7, 0x5401, 0x1300),
            (8, 0x5402, 0x1300),
            (9, 0x5403, 0x1300),
            (10, 0x5404, 0x1300),
            (11, 0x5410, 0x1120),
            (12, 0x5413, 0x1210),
            (13, 0x540b, 2),
        ] {
            call(&mut code, 29, &[slave, request, address], index);
        }
        // signalfd consumes process-directed terminal events on the same worker.
        call(
            &mut code,
            74,
            &[u32::MAX, 0x1100, 8, trames_vfs::O_NONBLOCK],
            14,
        );
        code.push(0xaa0003f3); // saved signalfd in x19
        call(&mut code, 64, &[master, 0x1080, 1], 15);
        code.extend([
            0xaa1303e0,
            mov(1, 0x1400),
            mov(2, 128),
            mov(8, 63),
            0xd4000001,
            mov(10, 0x1880),
            0xf9000140,
        ]);
        call(&mut code, 29, &[slave, 0x5414, 0x1140], 17);
        code.extend([
            0xaa1303e0,
            mov(1, 0x1500),
            mov(2, 128),
            mov(8, 63),
            0xd4000001,
            mov(10, 0x1890),
            0xf9000140,
        ]);
        call(&mut code, 29, &[slave, 0x5422, 0], 19);
        call(&mut code, 29, &[slave, 0x5429, 0x1208], 20);
        call(&mut code, 56, &[0, 0x1020, 2, 0], 21);
        call(&mut code, 29, &[slave, 0xdead, 0], 22);
        park(&mut code);
        let mut parent = Vec::new();
        park(&mut parent);
        run(&mut k, root, child, slots, code, parent);
        let p = k.processes.read(&2);
        let expected = [
            2,
            2,
            2,
            5,
            6,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            7,
            1,
            128,
            0,
            128,
            0,
            error(Errno(25)),
            error(Errno(6)),
            error(Errno(25)),
        ];
        for (i, value) in expected.into_iter().enumerate() {
            assert_eq!(
                p.memory.read_u64(0x1800 + i as u64 * 8).unwrap(),
                value,
                "slots={slots} call={i} pc={:#x} x0={:#x} returns={:?}",
                p.cpu.pc,
                p.cpu.x(0),
                k.cohort_return_syscalls
            );
        }
        assert_eq!(read_u32(&p.memory, 0x1200).unwrap(), 2);
        assert_eq!(read_u32(&p.memory, 0x1204).unwrap(), 2);
        assert_eq!(read_u32(&p.memory, 0x1400).unwrap(), 2);
        assert_eq!(read_u32(&p.memory, 0x1500).unwrap(), 28);
        assert_eq!(p.linux.vfs.controlling_terminal(), None);
        assert_eq!(pair.terminal.borrow().session, 0);
    }
}
#[test]
fn background_nonblocking_read_stops_and_resumes_on_the_only_slot_without_owner() {
    for (slots, operation) in [1, 2]
        .into_iter()
        .flat_map(|slots| (0..3).map(move |operation| (slots, operation)))
    {
        let mut k = super::tests::kernel();
        let mut root = super::tests::process();
        let (master, slave, pair) = pair(&mut root);
        root.linux
            .vfs
            .set_controlling_terminal(Some(pair.id))
            .unwrap();
        {
            let mut tty = pair.terminal.borrow_mut();
            tty.session = 1;
            tty.foreground = 1;
            if operation == 1 {
                let flags = tty.lflag() | 256;
                tty.attributes[12..16].copy_from_slice(&flags.to_le_bytes());
            }
            root.memory.write(0x1380, &tty.attributes).unwrap();
        }
        root.linux
            .vfs
            .set_status_flags(slave, trames_vfs::O_NONBLOCK)
            .unwrap();
        root.memory.write(0x1080, b"ok\n").unwrap();
        root.memory.write_array(0x1120, 2u32.to_le_bytes()).unwrap();
        filter(&mut k, &mut root, 0x7fff0000);
        let mut child = root.fork();
        child.tgid = 2;
        child.family.set_parent(1);
        child.set_group(2);
        let mut code = Vec::new();
        let (number, args) = match operation {
            0 => (63, [slave, 0x1300, 3]),
            1 => (64, [slave, 0x1080, 1]),
            _ => (29, [slave, 0x5402, 0x1380]),
        };
        call(&mut code, number, &args, 0);
        park(&mut code);
        let mut parent = Vec::new();
        // Negative process-group wait verifies live family wait indexing too.
        call(&mut parent, 260, &[(-2i32) as u32, 0x1200, 2, 0], 0);
        call(&mut parent, 29, &[slave, 0x5410, 0x1120], 1);
        call(&mut parent, 64, &[master, 0x1080, 3], 2);
        call(&mut parent, 129, &[2, 18], 3);
        call(&mut parent, 260, &[2, 0x1204, 8, 0], 4);
        park(&mut parent);
        run(&mut k, root, child, slots, code, parent);
        let p = k.processes.read(&2);
        assert_eq!(
            p.memory.read_u64(0x1800).unwrap(),
            [3, 1, 0][operation],
            "slots={slots} operation={operation}, never EAGAIN for the job stop"
        );
        if operation == 0 {
            assert_eq!(p.memory.read_array::<3>(0x1300).unwrap(), *b"ok\n");
        }
        assert!(!p.stopped());
        drop(p);
        let p = k.processes.read(&1);
        for (i, value) in [2, 0, 3, 0, 2].into_iter().enumerate() {
            assert_eq!(
                p.memory.read_u64(0x1800 + i as u64 * 8).unwrap(),
                value,
                "slots={slots} call={i}"
            );
        }
        assert_eq!(
            read_u32(&p.memory, 0x1200).unwrap(),
            ((if operation == 0 { 21 } else { 22 }) << 8) | 0x7f
        );
        assert_eq!(read_u32(&p.memory, 0x1204).unwrap(), 0xffff);
    }
}

#[test]
fn original_job_ids_threads_wait_selection_and_refresh_survive_source_changes() {
    let k = super::tests::kernel();
    let root = super::tests::process();
    k.publish_task(1, &root);
    let mut child = root.fork();
    child.tgid = 2;
    child.family.set_parent(1);
    let mut thread = child.fork();
    thread.tgid = 2;
    thread.family = child.family.clone();
    thread.children = child.children.clone();
    thread.wait_event = child.wait_event.clone();
    thread.share_process_context(&child);
    k.publish_task(2, &child);
    k.publish_task(3, &thread);
    let source = routes(&child);
    let parent = routes(&root);
    assert_eq!(
        source.job_call(&thread.signals.io, 154, [0, 0, 0, 0, 0, 0]),
        Some(Ok(0))
    );
    assert_eq!((child.group(), thread.group(), thread.session()), (2, 2, 1));
    // A stale observer refresh must only reindex the committed originals.
    source.directory.publish(&child.signals.io, 2, 2, 1, 0, 0);
    assert_eq!(child.group(), 2);
    assert_eq!(
        parent.send(
            &root.signals.io,
            129,
            [(-2i32) as u32 as u64, 10, 0, 0, 0, 0]
        ),
        Some(Ok(0))
    );
    assert!(child.signals.io.process().contains_key(&10));
    child.wait_event.stopped(21);
    let request =
        trames_kernel::children::Wait::prepare(260, [(-2i32) as u32 as u64, 0x1200, 3, 0, 0, 0])
            .unwrap();
    let mut memory = super::tests::process().memory;
    assert_eq!(
        root.children.wait(
            request,
            root.linux.vfs.pid_namespace(),
            root.group(),
            &mut memory
        ),
        Ok(Some(2))
    );
    assert_eq!(
        parent.job_call(&root.signals.io, 154, [2, 1, 0, 0, 0, 0]),
        Some(Ok(0))
    );
    assert_eq!(
        source.job_call(&thread.signals.io, 157, [0; 6]),
        Some(Ok(2))
    );
    assert_eq!(
        (
            child.group(),
            thread.group(),
            child.session(),
            thread.session()
        ),
        (2, 2, 2, 2)
    );
    assert_eq!(
        source.job_call(&thread.signals.io, 155, [0x1_0000_0000, 0, 0, 0, 0, 0]),
        Some(Ok(2))
    );
    assert_eq!(
        source.job_call(&child.signals.io, 154, [0, 0xffff_ffff, 0, 0, 0, 0]),
        Some(Err(Errno(22)))
    );
    child.signals.actions.set_handler(28, 1);
    thread.signals.actions.set_handler(28, 1);
    thread.signals.set_mask(1 << 27);
    child.linux.vfs.terminal_task().unwrap().signal(2, 2, 28);
    assert!(
        child.signals.io.process().contains_key(&28),
        "a blocked sibling retains a process signal even when the first thread ignores it"
    );
    // A parent's setpgid must preserve the post-exec EACCES distinction.
    let mut other = root.fork();
    other.tgid = 4;
    other.family.set_parent(1);
    k.publish_task(4, &other);
    other.family.mark_exec();
    assert_eq!(
        parent.job_call(&root.signals.io, 154, [4, 4, 0, 0, 0, 0]),
        Some(Err(Errno(13)))
    );
    other.set_session(4);
    assert_eq!(
        parent.job_call(&root.signals.io, 154, [4, 4, 0, 0, 0, 0]),
        Some(Err(Errno(1)))
    );
}

#[test]
fn tty_detach_steal_hangup_and_last_nonleader_exit_use_original_resources() {
    let k = super::tests::kernel();
    let mut root = super::tests::process();
    let (master, _, pair) = pair(&mut root);
    k.publish_task(1, &root);
    let owner = root.linux.vfs.terminal_task().unwrap();
    owner.acquire(&pair, false, true, false).unwrap();
    let mut child = root.fork();
    child.tgid = 2;
    child.family.set_parent(1);
    let mut thread = child.fork();
    thread.tgid = 2;
    thread.family = child.family.clone();
    thread.share_process_context(&child);
    k.publish_task(2, &child);
    k.publish_task(3, &thread);
    child
        .linux
        .vfs
        .terminal_task()
        .unwrap()
        .detach(&pair, false)
        .unwrap();
    assert_eq!(child.linux.vfs.controlling_terminal(), None);
    assert_eq!(thread.linux.vfs.controlling_terminal(), None);
    assert_eq!(root.linux.vfs.controlling_terminal(), Some(pair.id));
    assert_eq!(pair.terminal.borrow().session, 1);
    assert_eq!(
        routes(&child).job_call(&child.signals.io, 157, [0; 6]),
        Some(Ok(2))
    );
    let claimant = thread.linux.vfs.terminal_task().unwrap();
    assert_eq!(claimant.acquire(&pair, false, true, false), Err(Errno(1)));
    claimant.acquire(&pair, true, true, false).unwrap();
    assert_eq!(root.linux.vfs.controlling_terminal(), None);
    assert_eq!(child.linux.vfs.controlling_terminal(), Some(pair.id));
    assert_eq!(thread.linux.vfs.controlling_terminal(), Some(pair.id));
    let mut descendant = child.fork();
    descendant.tgid = 4;
    descendant.family.set_parent(2);
    k.publish_task(4, &descendant);
    assert_eq!(child.signals.io.try_exit(2, 0), Some(false));
    assert_eq!(child.signals.io.finish_exit(2), None);
    assert_eq!(descendant.linux.vfs.controlling_terminal(), Some(pair.id));
    assert_eq!(thread.signals.io.try_exit(3, 0), Some(true));
    assert_eq!(thread.signals.io.finish_exit(3), Some(0));
    assert_eq!(descendant.linux.vfs.controlling_terminal(), None);
    assert_eq!(pair.terminal.borrow().session, 0);
    // Reattach a different original session, then make actual final master close
    // produce HUP/CONT without running Kernel::pump_guest_ptys.
    assert_eq!(
        routes(&descendant).job_call(&descendant.signals.io, 157, [0; 6]),
        Some(Ok(4))
    );
    descendant
        .linux
        .vfs
        .terminal_task()
        .unwrap()
        .acquire(&pair, false, true, false)
        .unwrap();
    descendant.signals.set_mask(1);
    root.linux.vfs.close(master).unwrap();
    child.linux.vfs.close(master).unwrap();
    thread.linux.vfs.close(master).unwrap();
    assert!(pair.master_alive.load(std::sync::atomic::Ordering::Relaxed));
    descendant.linux.vfs.close(master).unwrap();
    assert!(!pair.master_alive.load(std::sync::atomic::Ordering::Relaxed));
    assert_eq!(descendant.linux.vfs.controlling_terminal(), None);
    assert!(descendant.signals.io.process().contains_key(&1));
}

#[test]
fn filtered_tty_control_adoption_retains_original_fd_after_close_and_reuse() {
    let mut k = super::tests::kernel();
    let mut root = super::tests::process();
    let (_, slave, pair) = pair(&mut root);
    root.linux
        .vfs
        .set_controlling_terminal(Some(pair.id))
        .unwrap();
    {
        let mut tty = pair.terminal.borrow_mut();
        tty.session = 1;
        tty.foreground = 1;
        root.memory.write(0x1300, &tty.attributes).unwrap();
    }
    filter(&mut k, &mut root, 0x7fff0000);
    let mut child = root.fork();
    child.tgid = 2;
    child.family.set_parent(1);
    child.set_group(2);
    k.publish_task(1, &root);
    k.publish_task(2, &child);
    k.call(
        2,
        &mut child,
        29,
        [slave as u64, 0x5402, 0x1300, 0, 0, 0],
        &mut CapturedOutput::default(),
    );
    assert!(child.byte_wait.is_some());
    child.linux.vfs.close(slave).unwrap();
    assert_eq!(child.linux.vfs.eventfd(99, 0).unwrap(), slave);
    pair.terminal.borrow_mut().foreground = 2;
    assert_eq!(
        routes(&root).send(&root.signals.io, 129, [2, 18, 0, 0, 0, 0]),
        Some(Ok(0))
    );
    let mut code = vec![mov(10, 0x1800), 0xf9000140];
    park(&mut code);
    let mut parent = Vec::new();
    park(&mut parent);
    run(&mut k, root, child, 1, code, parent);
    let child = k.processes.read(&2);
    assert_eq!(child.memory.read_u64(0x1800).unwrap(), 0);
    assert_eq!(
        child.seccomp.evaluations(),
        3,
        "one original ioctl decision, then two final futex waits"
    );
}

#[test]
fn serial_background_write_and_ioctl_waits_wake_on_ignored_continue() {
    for number in [64, 29] {
        let mut k = super::tests::kernel();
        let mut root = super::tests::process();
        let (_, slave, pair) = pair(&mut root);
        root.linux
            .vfs
            .set_controlling_terminal(Some(pair.id))
            .unwrap();
        {
            let mut tty = pair.terminal.borrow_mut();
            tty.session = 1;
            tty.foreground = 1;
            let flags = tty.lflag() | 256;
            tty.attributes[12..16].copy_from_slice(&flags.to_le_bytes());
            root.memory.write(0x1300, &tty.attributes).unwrap();
        }
        root.memory.write(0x1100, b"x").unwrap();
        let mut child = root.fork();
        child.tgid = 2;
        child.family.set_parent(1);
        child.set_group(2);
        k.publish_task(1, &root);
        k.publish_task(2, &child);
        let args = if number == 64 {
            [slave as u64, 0x1100, 1, 0, 0, 0]
        } else {
            [slave as u64, 0x5402, 0x1300, 0, 0, 0]
        };
        k.call(2, &mut child, number, args, &mut CapturedOutput::default());
        assert!(child.byte_wait.is_some());
        assert!(!child.byte_wait.as_ref().unwrap().signal.ready());
        assert!(child.signals.io.lifecycle().consume_stop(22, || child
            .signals
            .io
            .take(22, true)
            .is_some()));
        pair.terminal.borrow_mut().foreground = 2;
        // SIGCONT's default disposition need not enqueue a user signal; the
        // original control event must still wake this serial resource wait.
        assert_eq!(
            routes(&root).send(&root.signals.io, 129, [2, 18, 0, 0, 0, 0]),
            Some(Ok(0))
        );
        assert!(child.byte_wait.as_ref().unwrap().signal.ready());
        k.call(2, &mut child, number, args, &mut CapturedOutput::default());
        assert_eq!(child.cpu.x(0), u64::from(number == 64));
        assert!(child.byte_wait.is_none());
    }
}
