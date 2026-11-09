// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

fn words<C: Cpu>(p: &mut Process<C>, at: u64, code: &[u32]) {
    p.memory
        .write(
            at,
            &code
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    p.memory.protect(at, PAGE_SIZE, Permissions::RX).unwrap();
}
fn mov(code: &mut Vec<u32>, r: u32, value: u32) {
    code.push(0xd2800000 | ((value & 0xffff) << 5) | r);
    if value > 0xffff {
        code.push(0xf2a00000 | ((value >> 16) << 5) | r);
    }
}
fn wait() -> [u32; 7] {
    [
        0xd2860000, 0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
    ]
}
fn name<C: Cpu>(p: &mut Process<C>, value: &[u8]) {
    p.memory.write(0x1800, value).unwrap();
    p.memory.write(0x1800 + value.len() as u64, &[0]).unwrap();
    for (i, value) in [15, 0x1800, 0, 0, 0, 0].into_iter().enumerate() {
        p.cpu.set_x(i, value);
    }
    p.cpu.set_x(8, 167);
    p.linux.dispatch_untraced(
        &mut p.cpu,
        &mut p.memory,
        &mut trames_linux::CapturedOutput::default(),
    );
    assert_eq!(p.cpu.x(0), 0);
}

#[test]
fn residual_prctl_family_runs_without_join_and_proc_observes_name_before_drain() {
    struct Observe {
        task: Arc<dyn trames_vfs::ProcTask>,
        seen: bool,
    }
    impl GuestOutput for Observe {
        fn write(&mut self, _: trames_linux::OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn source_console(&mut self) -> Arc<dyn trames_vfs::ConsoleIo> {
            Arc::new(trames_vfs::CapturedConsole::default())
        }
        fn poll_control(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<bool> {
            self.seen |= self
                .task
                .observe(trames_vfs::ProcRefresh::Metadata, None)
                .is_some_and(|p| p.command == b"worker-comm-len");
            Ok(false)
        }
    }
    for (cpus, slots, filtered) in [(4, 4, false), (12, 12, false), (4, 1, false), (4, 1, true)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = process();
        name(&mut root, b"before");
        if filtered {
            root.memory
                .write_array(0x1300, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0, 0, 0, 0, 0, 0])
                .unwrap();
            root.memory
                .write_array(0x1400, [6, 0, 0, 0, 0, 0, 0xff, 0x7f])
                .unwrap();
            root.linux.vfs.credentials.caps.no_new_privs.set();
            assert_eq!(k.seccomp(&mut root, [1, 0, 0x1300, 0, 0, 0]), Ok(0));
        }
        root.memory
            .write(0x1000, b"worker-comm-length-extra\0")
            .unwrap();
        let mut code = Vec::new();
        for (option, arg, result) in [
            (15, 0x1000, 19),
            (16, 0x1100, 20),
            (5, 0, 21),
            (64, 0, 22),
            (1, 10, 23),
            (2, 0x1500, 24),
            (36, 7, 25),
            (37, 0x1504, 26),
            (38, 1, 27),
            (39, 0, 28),
            (21, 0, 29),
        ] {
            mov(&mut code, 0, option);
            mov(&mut code, 1, arg);
            mov(&mut code, 2, 0);
            mov(&mut code, 3, 0);
            mov(&mut code, 4, 0);
            mov(&mut code, 8, 167);
            code.push(0xd4000001);
            code.push(0xaa0003e0 | result);
        }
        mov(&mut code, 0, 0x2800);
        mov(&mut code, 1, 1);
        code.push(0xb9000001);
        code.extend(wait());
        words(&mut root, 0x4000, &code);
        words(&mut root, 0x5000, &wait());
        k.install_proc_source(&root, None);
        k.publish_task(1, &root);
        let task = k
            .proc_source
            .as_ref()
            .unwrap()
            .directory
            .proc_identity(1)
            .unwrap();
        let mut output = Observe { task, seen: false };
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 2;
        peer.cpu.set_pc(0x5000);
        for p in [&root, &peer] {
            p.signals.io.scheduling.set_affinity((1 << slots) - 1);
        }
        k.processes.insert(1, root);
        k.processes.insert(2, peer);
        assert!(k.parallel_epoch(&mut output, 1_000_000, true).unwrap());
        let root = k.processes.read(&1);
        eprintln!("prctl CPUs={cpus} slots={slots} filtered={filtered} marker={:?} cohorts={} returned={:?} live_name={}",root.memory.read_array::<4>(0x2800).unwrap(),k.parallel_rounds,k.cohort_return_syscalls,output.seen);
        assert_eq!(
            root.memory.read_array::<4>(0x2800).unwrap(),
            1u32.to_le_bytes()
        );
        assert!(
            output.seen,
            "proc must observe the original name while the cohort is live"
        );
        assert_eq!(
            root.memory.read_array::<16>(0x1100).unwrap(),
            *b"worker-comm-len\0"
        );
        for r in [19, 20, 23, 24, 25, 26, 27] {
            assert_eq!(root.cpu.x(r), 0, "r={r}");
        }
        assert_eq!(root.cpu.x(21), 0u64.wrapping_sub(22));
        assert_eq!(root.cpu.x(22), 0u64.wrapping_sub(22));
        assert_eq!(root.cpu.x(28), 1);
        assert_eq!(root.cpu.x(29), if filtered { 2 } else { 0 });
        assert_eq!(
            root.memory.read_array::<4>(0x1500).unwrap(),
            10u32.to_le_bytes()
        );
        assert_eq!(
            root.memory.read_array::<4>(0x1504).unwrap(),
            1u32.to_le_bytes()
        );
        assert!(k.cohort_return_syscalls.is_empty());
        assert_eq!(k.parallel_rounds, 1);
        assert_eq!(k.vm_checkpoint_spaces, 0);
        assert_eq!(k.service_requests, 0);
    }
}

#[test]
fn faulting_source_setname_keeps_the_original_comm_and_completes_once() {
    let mut k = kernel();
    k.cpu_count = 4;
    k.workers = crate::workers::Pool::new(1);
    k.per_cpu = vec![Duration::ZERO; 4];
    k.profile_syscalls = true;
    let mut root = process();
    name(&mut root, b"before");
    root.memory.write(0x8ff8, b"nonzero!").unwrap();
    let mut code = Vec::new();
    for (option, pointer, result) in [(15, 0x8ff8, 19), (16, 0x1100, 20)] {
        mov(&mut code, 0, option);
        mov(&mut code, 1, pointer);
        mov(&mut code, 8, 167);
        code.push(0xd4000001);
        code.push(0xaa0003e0 | result);
    }
    code.extend(wait());
    words(&mut root, 0x4000, &code);
    words(&mut root, 0x5000, &wait());
    let mut peer = root.fork();
    peer.vm_id = 2;
    peer.tgid = 2;
    peer.cpu.set_pc(0x5000);
    for p in [&root, &peer] {
        p.signals.io.scheduling.set_affinity(1);
    }
    k.processes.insert(1, root);
    k.processes.insert(2, peer);
    assert!(k
        .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
        .unwrap());
    let root = k.processes.read(&1);
    assert_eq!(root.cpu.x(19), 0u64.wrapping_sub(14));
    assert_eq!(root.cpu.x(20), 0);
    assert_eq!(
        &root.memory.read_array::<16>(0x1100).unwrap()[..7],
        b"before\0"
    );
    assert!(k.cohort_return_syscalls.is_empty());
    assert_eq!(k.parallel_rounds, 1);
    assert_eq!(k.service_requests, 0);
}

#[test]
fn task_comm_forks_by_value_and_proc_namespace_rebinding_preserves_live_name() {
    let mut k = kernel();
    let mut root = process();
    name(&mut root, b"parent");
    k.install_proc_source(&root, None);
    k.publish_task(1, &root);
    let original = k
        .proc_source
        .as_ref()
        .unwrap()
        .directory
        .proc_identity(1)
        .unwrap();
    assert_eq!(
        k.syscall(
            1,
            &mut root,
            220,
            [0x10f00, 0, 0, 0, 0, 0],
            &mut trames_linux::CapturedOutput::default()
        ),
        Ok(Some(2))
    );
    let child = k
        .proc_source
        .as_ref()
        .unwrap()
        .directory
        .proc_identity(2)
        .unwrap();
    {
        let mut peer = k.processes.get_mut(&2).unwrap();
        name(&mut peer, b"child");
    }
    name(&mut root, b"renamed-parent");
    assert_eq!(
        original
            .observe(trames_vfs::ProcRefresh::Metadata, None)
            .unwrap()
            .command,
        b"renamed-parent"
    );
    assert_eq!(
        child
            .observe(trames_vfs::ProcRefresh::Metadata, None)
            .unwrap()
            .command,
        b"child"
    );
    root.signals
        .io
        .proc_view
        .replace_resources(root.linux.vfs.proc_resources());
    name(&mut root, b"after-rebind");
    assert_eq!(
        original
            .observe(trames_vfs::ProcRefresh::Metadata, None)
            .unwrap()
            .command,
        b"after-rebind"
    );
}
