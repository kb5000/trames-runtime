// SPDX-License-Identifier: GPL-3.0-or-later
//! Original statistics remain observable while the owner and CPUs are occupied.
use super::tests::{kernel, process};
use super::*;
use trames_linux::SystemStatistics;
use trames_memory::{Permissions, PAGE_SIZE};
use trames_vfs::{ProcQuery, ProcRefresh, ProcSource};

#[test]
fn task_proc_observations_use_original_mm_without_sampling_host_global_memory() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let paths: &[&[u8]] = &[
        b"/proc/1/status",
        b"/proc/1/stat",
        b"/proc/1/statm",
        b"/proc/1/smaps",
        b"/proc/1/smaps_rollup",
        b"/proc/1/maps",
        b"/proc/1/comm",
        b"/proc/1/limits",
        b"/proc/1/fdinfo/0",
        b"/proc/1/mountinfo",
    ];
    for limits in [
        crate::MemoryLimits::default(),
        crate::MemoryLimits::host_managed(),
    ] {
        let mut k = kernel();
        k.memory_limits = limits;
        let mut p = process();
        p.memory.write(0x1000, b"resident").unwrap();
        k.install_proc_source(&p, None);
        k.publish_task(1, &p);
        let absent = k.proc_source.as_ref().unwrap();
        for path in paths {
            assert!(absent.available(ProcRefresh::for_path(path)), "{path:?}");
        }
        assert_eq!(
            absent.available(ProcRefresh::for_path(b"/proc/meminfo")),
            !limits.is_host_managed()
        );
        let samples = Arc::new(AtomicUsize::new(0));
        let calls = samples.clone();
        k.install_proc_source(
            &p,
            Some(Arc::new(move || {
                calls.fetch_add(1, Ordering::Relaxed);
                trames_linux::HostMemoryInfo {
                    total: 1000,
                    free: 600,
                    available: 800,
                }
            })),
        );
        k.publish_task(1, &p);
        let source = k.proc_source.as_ref().unwrap();
        for path in paths {
            let info = ProcSource::observe(
                &**source,
                ProcQuery::new(
                    path,
                    ProcRefresh::for_path(path),
                    p.linux.vfs.pid_namespace(),
                    1,
                ),
            );
            assert!(info.processes.iter().any(|task| task.pid == 1), "{path:?}");
        }
        assert_eq!(samples.load(Ordering::Relaxed), 0);
        let global = ProcSource::observe(
            &**source,
            ProcQuery::new(
                b"/proc/meminfo",
                ProcRefresh::HostMemory,
                p.linux.vfs.pid_namespace(),
                1,
            ),
        );
        assert_eq!(
            samples.load(Ordering::Relaxed),
            usize::from(limits.is_host_managed())
        );
        if limits.is_host_managed() {
            assert_eq!(
                (
                    global.memory_limit,
                    global.used_memory,
                    global.available_memory
                ),
                (1000, 400, Some(800))
            );
        } else {
            assert_eq!(global.memory_limit, limits.total);
        }
    }
}

#[test]
fn system_statistics_deduplicate_original_mm_and_follow_live_task_membership() {
    let mut k = kernel();
    let mut p = process();
    k.install_proc_source(&p, None);
    k.publish_task(1, &p);
    let source = k.proc_source.as_ref().unwrap().clone();
    let original = SystemStatistics::observe(&*source).unwrap();
    assert_eq!(original.tasks, 1);
    let used = original.total - original.free;
    p.memory.map(0x100000, 64 << 20, Permissions::RW).unwrap();
    let reserved = SystemStatistics::observe(&*source).unwrap();
    assert_eq!(
        reserved.free, original.free,
        "unused VA is not resident RAM"
    );
    p.memory.write(0x100000, &[42]).unwrap();
    let touched = SystemStatistics::observe(&*source).unwrap();
    assert_eq!(touched.total - touched.free, used + PAGE_SIZE as usize);
    let mut peer = process();
    peer.tgid = 2;
    peer.memory = p.memory.share();
    peer.signals.io_directory = source.directory.clone();
    k.publish_task(2, &peer);
    let shared = SystemStatistics::observe(&*source).unwrap();
    assert_eq!(shared.tasks, 2);
    assert_eq!(
        shared.free, touched.free,
        "CLONE_VM counts the original mm once"
    );
    let info = ProcSource::observe(
        &*source,
        ProcQuery::new(
            b"/proc/meminfo",
            ProcRefresh::HostMemory,
            p.linux.vfs.pid_namespace(),
            1,
        ),
    );
    assert_eq!(info.used_memory, touched.total - touched.free);
    peer.signals.io.exit();
    assert_eq!(
        SystemStatistics::observe(&*source).unwrap().free,
        touched.free
    );
    p.signals.io.exit();
    assert_eq!(
        SystemStatistics::observe(&*source).unwrap().free,
        original.total
    );
    drop(peer);
    assert_eq!(SystemStatistics::observe(&*source).unwrap().tasks, 1);
    drop(p);
    assert_eq!(SystemStatistics::observe(&*source).unwrap().tasks, 0);
}

#[test]
fn system_statistics_share_host_reports_and_preflight_before_host_sampling() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut k = kernel();
    k.memory_limits = crate::MemoryLimits::host_managed();
    let mut p = process();
    k.install_proc_source(&p, None);
    k.publish_task(1, &p);
    let absent = k.proc_source.as_ref().unwrap().clone();
    let direct = trames_linux::DirectSyscalls::default().with_statistics(Some(absent));
    assert_eq!(
        direct.invoke_system(179, [0x1000, 0, 0, 0, 0, 0], &mut p.memory),
        None
    );
    assert_eq!(
        direct.invoke_system(179, [0, 0, 0, 0, 0, 0], &mut p.memory),
        Some(Err(Errno(14)))
    );
    let samples = Arc::new(AtomicUsize::new(0));
    let host_free = Arc::new(AtomicUsize::new(700));
    let s = samples.clone();
    let f = host_free.clone();
    k.install_proc_source(
        &p,
        Some(Arc::new(move || {
            s.fetch_add(1, Ordering::Relaxed);
            trames_linux::HostMemoryInfo {
                total: 1000,
                free: f.load(Ordering::Relaxed),
                available: 800,
            }
        })),
    );
    k.publish_task(1, &p);
    let source = k.proc_source.as_ref().unwrap().clone();
    let direct = trames_linux::DirectSyscalls::default().with_statistics(Some(source.clone()));
    assert_eq!(
        direct.invoke_system(179, [0x8fff, 0, 0, 0, 0, 0], &mut p.memory),
        Some(Err(Errno(14)))
    );
    assert_eq!(samples.load(Ordering::Relaxed), 0);
    for free in [700, 500] {
        host_free.store(free, Ordering::Relaxed);
        assert_eq!(
            direct.invoke_system(179, [0x1000, 0, 0, 0, 0, 0], &mut p.memory),
            Some(Ok(0))
        );
        assert_eq!(p.memory.read_u64(0x1020).unwrap(), 1000);
        assert_eq!(p.memory.read_u64(0x1028).unwrap(), free as u64);
    }
    assert_eq!(samples.load(Ordering::Relaxed), 2);
    let proc = ProcSource::observe(
        &*source,
        ProcQuery::new(
            b"/proc/meminfo",
            ProcRefresh::HostMemory,
            p.linux.vfs.pid_namespace(),
            1,
        ),
    );
    assert_eq!(
        (proc.memory_limit, proc.used_memory, proc.available_memory),
        (1000, 500, Some(800))
    );
}

#[test]
fn standalone_sysinfo_binds_original_statistics_before_admission_without_a_host_return() {
    for cpus in [1, 4, 12] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut p = process();
        for (i, word) in [0xd4000001u32, 0xd28000e0, 0xd2800ba8, 0xd4000001]
            .into_iter()
            .enumerate()
        {
            p.memory
                .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        p.cpu.set_x(0, 0x1000);
        p.cpu.set_x(8, 179);
        k.publish_task(1, &p);
        k.processes.insert(1, p);
        assert!(k.proc_source.is_none());
        assert_eq!(
            k.drive(&mut trames_linux::CapturedOutput::default(), 100000)
                .unwrap()
                .code,
            7
        );
        let p = k.processes.read(&1);
        let total = p.memory.read_u64(0x1020).unwrap();
        let free = p.memory.read_u64(0x1028).unwrap();
        assert!(total > 0 && free <= total);
        assert_eq!(
            u16::from_le_bytes(p.memory.read_array::<2>(0x1050).unwrap()),
            1
        );
        assert_eq!(k.parallel_rounds, 1);
        assert!(k.cohort_return_syscalls.is_empty());
        assert_eq!(k.service_requests, 0);
    }
}

#[test]
fn sysinfo_and_live_cpu_statistics_keep_four_twelve_and_one_slot_cohorts() {
    struct Host {
        source: Arc<crate::proc_views::Source>,
        namespace: trames_vfs::PidNamespace,
        started: Instant,
        first: Option<u64>,
        last: u64,
        done: bool,
    }
    impl GuestOutput for Host {
        fn write(&mut self, _: trames_linux::OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn source_console(&mut self) -> Arc<dyn trames_vfs::ConsoleIo> {
            Arc::new(trames_vfs::CapturedConsole::default())
        }
        fn host_interest(&mut self, wait: &mut trames_linux::HostWait) -> std::io::Result<()> {
            wait.until(std::time::Instant::now() + Duration::from_millis(1));
            Ok(())
        }
        fn poll_host(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<trames_linux::HostState> {
            let info = ProcSource::observe(
                &*self.source,
                ProcQuery::new(b"/proc/stat", ProcRefresh::Metadata, &self.namespace, 1),
            );
            assert!(info.idle <= info.uptime.saturating_mul(info.cpu_count as u32));
            if self.started.elapsed() >= Duration::from_millis(20) {
                self.first.get_or_insert(info.cpu_user_ticks);
            }
            self.last = info.cpu_user_ticks;
            self.done = self.started.elapsed() >= Duration::from_millis(200);
            Ok(trames_linux::HostState::from_cancelled(self.done))
        }
    }
    for (cpus, slots) in [(4, 4), (12, 12), (4, 1)] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let root = process();
        let namespace = root.linux.vfs.pid_namespace().clone();
        k.install_proc_source(&root, None);
        let source = k.proc_source.as_ref().unwrap().clone();
        for id in 1..=cpus {
            let mut p = if id == 1 { root.fork() } else { process() };
            p.tgid = id as u32;
            p.vm_id = id as u64;
            p.signals.io_directory = source.directory.clone();
            p.signals.io.scheduling.set_affinity((1 << slots) - 1);
            // Reset the output pointer on every call; count completed entries
            // in x19 without consuming any host-observed guest byte lease.
            let words = [
                0xd2820000u32,
                0xd2801668,
                0xd4000001,
                0x91000673,
                0x17fffffc,
            ];
            p.memory
                .write(
                    0x4000,
                    &words
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            p.memory
                .protect(0x4000, PAGE_SIZE, Permissions::RX)
                .unwrap();
            k.processes.insert(id as u32, p);
        }
        let mut host = Host {
            source,
            namespace,
            started: Instant::now(),
            first: None,
            last: 0,
            done: false,
        };
        assert!(matches!(
            k.drive(&mut host, u64::MAX),
            Err(RuntimeError::Cancelled)
        ));
        assert!(
            host.last > host.first.unwrap(),
            "live time did not advance: cpus={cpus} slots={slots}"
        );
        assert_eq!(k.parallel_rounds, 1);
        assert!(
            k.cohort_return_syscalls.is_empty(),
            "{:?}",
            k.cohort_return_syscalls
        );
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.serviced_syscalls, 0);
        for (_, p) in k.processes.iter() {
            assert!(p.cpu.x(19) > 0, "every admitted task must execute");
        }
        // Terminal cancellation retires children; inspect the surviving root's
        // bytes, and each completed CPU's counter above.
        let root = k.processes.read(&1);
        assert_eq!(
            root.memory.read_u64(0x1020).unwrap(),
            k.memory_limits.total as u64
        );
        assert_eq!(
            root.memory.read_array::<2>(0x1050).unwrap(),
            (cpus as u16).to_le_bytes()
        );
    }
}
