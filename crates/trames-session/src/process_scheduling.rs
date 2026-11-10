// SPDX-License-Identifier: GPL-3.0-or-later
//! Virtual scheduling metadata and a single NUMA-node view. Host thread
//! priorities are deliberately independent from guest permissions and policy.
use super::*;
impl<C: Cpu> Kernel<C> {
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn scheduling(
        &self,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let c = &p.linux.vfs.credentials;
        trames_kernel::signal::IoRoutes {
            directory: p.signals.io_directory.clone(),
            namespace: p.linux.vfs.pid_namespace().clone(),
            uid: c.uid,
            euid: c.euid,
        }
        .scheduling(&p.signals.io, self.cpu_count, number, a, &mut p.memory)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn mempolicy(p: &mut Process<C>, a: [u64; 6]) -> Result<Option<u64>, Errno> {
        trames_linux::memory_query(&mut p.memory, 236, a)
            .expect("memory policy ABI")
            .map(Some)
    }
}
#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Kernel = crate::process::Kernel<Cpu>;

    use super::super::tests::{kernel, process};
    use super::*;
    #[test]
    fn scheduling_subsystem_completes_on_sources_with_one_filter_decision_per_entry() {
        for cpus in [2, 4] {
            for decision in [None, Some(0x7fff_0000u32), Some(0x0005_007b)] {
                for (number, args, expected) in [
                    (118, [0, 0x1200, 0, 0, 0, 0], 0),
                    (119, [0, 3, 0x1200, 0, 0, 0], 0),
                    (120, [0; 6], 0),
                    (121, [0, 0x1200, 0, 0, 0, 0], 0),
                    (122, [0, 8, 0x1210, 0, 0, 0], 0),
                    (123, [0, 8, 0x1220, 0, 0, 0], 8),
                    (125, [1, 0, 0, 0, 0, 0], 99),
                    (126, [1, 0, 0, 0, 0, 0], 1),
                    (127, [0; 6], 0u64.wrapping_sub(38)),
                    (140, [0, 0, 7, 0, 0, 0], 0),
                    (141, [0; 6], 20),
                    (274, [0; 6], 0u64.wrapping_sub(38)),
                    (275, [0; 6], 0u64.wrapping_sub(38)),
                ] {
                    let mut p = process();
                    let mut k = kernel();
                    k.cpu_count = cpus;
                    k.workers = crate::workers::Pool::new(cpus);
                    k.per_cpu = vec![Duration::ZERO; cpus];
                    p.signals.io.scheduling.set_affinity((1 << cpus) - 1);
                    p.memory
                        .write_array(0x1210, ((1u64 << cpus) - 1).to_le_bytes())
                        .unwrap();
                    if let Some(value) = decision {
                        let mut instruction = [0; 8];
                        instruction[..2].copy_from_slice(&6u16.to_le_bytes());
                        instruction[4..].copy_from_slice(&value.to_le_bytes());
                        p.memory.write(0x1100, &instruction).unwrap();
                        p.memory.write_array(0x1000, 1u64.to_le_bytes()).unwrap();
                        p.memory
                            .write_array(0x1008, 0x1100u64.to_le_bytes())
                            .unwrap();
                        assert_eq!(k.seccomp(&mut p, [1, 0, 0x1000, 0, 0, 0]), Ok(0));
                    }
                    let mut code: Vec<u32> = args
                        .into_iter()
                        .enumerate()
                        .map(|(r, value)| 0xd2800000 | ((value as u32) << 5) | r as u32)
                        .collect();
                    code.extend([0xd2800008 | (number << 5), 0xd4000001, 0xaa0003e6]);
                    code.push(0x14000000 | ((-(code.len() as i32)) as u32 & 0x03ff_ffff));
                    for (i, word) in code.into_iter().enumerate() {
                        p.memory
                            .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                            .unwrap();
                    }
                    p.memory
                        .protect(
                            0x4000,
                            trames_memory::PAGE_SIZE,
                            trames_memory::Permissions::RX,
                        )
                        .unwrap();
                    p.cpu = Cpu::new(0x4000, 0);
                    for id in 2..=4 {
                        k.processes.insert(id, p.fork());
                    }
                    k.processes.insert(1, p);
                    let expected = if decision == Some(0x0005_007b) {
                        0u64.wrapping_sub(123)
                    } else {
                        expected
                    };
                    for _ in 0..4 {
                        assert!(
                            k.parallel_round(
                                &mut trames_linux::CapturedOutput::default(),
                                k.instructions + 30_000
                            )
                            .unwrap(),
                            "{number} {cpus} {decision:?}"
                        );
                        if k.worker_syscalls > 0
                            && k.processes.values().any(|p| p.cpu.x(6) == expected)
                        {
                            break;
                        }
                    }
                    assert!(
                        k.worker_syscalls > 0,
                        "{number} {cpus} {decision:?}: worker={} all={} returns={:?}",
                        k.worker_syscalls,
                        k.syscalls,
                        k.cohort_return_syscalls
                    );
                    assert_eq!(
                        k.syscalls, k.worker_syscalls,
                        "{number} must not join peers"
                    );
                    assert_eq!(k.service_requests, 0);
                    assert!(
                        k.processes.values().any(|p| p.cpu.x(6) == expected),
                        "{number} result {expected}"
                    );
                    if decision.is_some() {
                        assert_eq!(
                            k.processes.read(&1).seccomp.evaluations(),
                            k.syscalls,
                            "{number}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn desktop_priorities_and_batch_idle_policy_roundtrip_and_inherit() {
        let mut k = kernel();
        let mut p = process();
        k.publish_task(1, &p);
        let mut io = trames_linux::CapturedOutput::default();
        for policy in [0, 3, 5] {
            write_u32(&mut p.memory, 0x1000, 0).unwrap();
            assert_eq!(
                k.syscall(1, &mut p, 119, [0, policy, 0x1000, 0, 0, 0], &mut io),
                Ok(Some(0))
            );
            assert_eq!(k.syscall(1, &mut p, 120, [0; 6], &mut io), Ok(Some(policy)));
        }
        assert_eq!(
            k.syscall(1, &mut p, 140, [0, 0, 19, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert_eq!(k.syscall(1, &mut p, 141, [0; 6], &mut io), Ok(Some(1)));
        let child = p.fork();
        assert_eq!(child.signals.io.scheduling.nice(), 19);
        assert_eq!(child.signals.io.scheduling.policy(), 5);
        k.processes.insert(2, p.fork());
        k.publish_io_tasks(Some((1, &p)));
        assert_eq!(
            k.syscall(1, &mut p, 119, [2, 3, 0x1000, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert_eq!(
            k.syscall(1, &mut p, 120, [2, 0, 0, 0, 0, 0], &mut io),
            Ok(Some(3))
        );
        assert_eq!(p.signals.io.scheduling.policy(), 5);
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        k.publish_task(1, &p);
        assert_eq!(
            k.syscall(1, &mut p, 140, [0, 0, 0, 0, 0, 0], &mut io),
            Err(Errno(13))
        );
        assert_eq!(
            k.syscall(1, &mut p, 140, [3, 0, 0, 0, 0, 0], &mut io),
            Err(Errno(22))
        );
        assert_eq!(
            k.syscall(1, &mut p, 140, [0, 999, 0, 0, 0, 0], &mut io),
            Err(Errno(3))
        );
    }
    #[test]
    fn structural_group_and_capability_changes_publish_at_their_actual_write_boundary() {
        let mut k = kernel();
        let mut p = process();
        let mut child = p.fork();
        child.tgid = 2;
        child.family.set_parent(1);
        k.publish_task(1, &p);
        k.publish_task(2, &child);
        k.processes.insert(2, child);
        let mut io = trames_linux::CapturedOutput::default();
        assert_eq!(
            k.syscall(1, &mut p, 154, [2, 0, 0, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert_eq!(
            k.syscall(1, &mut p, 140, [1, 2, 7, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert_eq!(p.signals.io.scheduling.nice(), 0);
        assert_eq!(k.processes.read(&2).signals.io.scheduling.nice(), 7);
        assert_eq!(
            k.syscall(1, &mut p, 141, [1, 0, 0, 0, 0, 0], &mut io),
            Ok(Some(20))
        );
        write_u32(&mut p.memory, 0x1000, 0x2008_0522).unwrap();
        write_u32(&mut p.memory, 0x1004, 0).unwrap();
        p.memory.write(0x1100, &[0; 24]).unwrap();
        assert_eq!(
            k.syscall(1, &mut p, 91, [0x1000, 0x1100, 0, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert_eq!(
            k.syscall(1, &mut p, 140, [0, 0, 7, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert_eq!(k.syscall(1, &mut p, 140, [0; 6], &mut io), Err(Errno(13)));
    }
    #[test]
    fn numa_default_allowed_mask_and_address_queries_are_consistent() {
        let mut p = process();
        for flags in [0, 4, 3] {
            p.memory.write(0x1100, &[0xff; 8]).unwrap();
            assert_eq!(
                Kernel::mempolicy(
                    &mut p,
                    [
                        0x1000,
                        0x1100,
                        33,
                        if flags == 3 { 0x1000 } else { 0 },
                        flags,
                        0
                    ]
                ),
                Ok(Some(0))
            );
            assert_eq!(read_u32(&p.memory, 0x1000).unwrap(), 0);
            assert_eq!(read_u64(&p.memory, 0x1100).unwrap(), u64::from(flags == 4));
        }
        assert_eq!(Kernel::mempolicy(&mut p, [0; 6]), Ok(Some(0)));
        assert_eq!(
            Kernel::mempolicy(&mut p, [0x1000, 0, 0, 0, 8, 0]),
            Err(Errno(22))
        );
        assert_eq!(
            Kernel::mempolicy(&mut p, [0x1000, 0, 0, 0x1000000, 3, 0]),
            Err(Errno(14))
        );
    }
}
