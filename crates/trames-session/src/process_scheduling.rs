// SPDX-License-Identifier: GPL-3.0-or-later
//! Virtual scheduling metadata and a single NUMA-node view. Host thread
//! priorities are deliberately independent from guest permissions and policy.
use super::*;
impl<C: Cpu> Kernel<C> {
    pub(super) fn priority(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
    ) -> Result<Option<u64>, Errno> {
        let which = a[0] as u32;
        if which > 2 {
            return Err(Errno(22));
        }
        let who = a[1] as u32;
        let uid = if who == 0 {
            p.linux.vfs.credentials.uid
        } else {
            who
        };
        let group = if who == 0 {
            p.linux.vfs.visible_pid(p.group)
        } else {
            who
        };
        let matches = |id: u32, target: &Process<C>| {
            let visible = p.linux.vfs.visible_pid(id);
            visible != 0
                && !matches!(target.state, State::Zombie(_))
                && match which {
                    0 => {
                        visible
                            == if who == 0 {
                                p.linux.vfs.visible_pid(pid)
                            } else {
                                who
                            }
                    }
                    1 => p.linux.vfs.visible_pid(target.group) == group,
                    _ => target.linux.vfs.credentials.uid == uid,
                }
        };
        let mut targets = self
            .processes
            .iter()
            .filter(|(id, t)| matches(**id, t))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        if matches(pid, p) {
            targets.push(pid);
        }
        if targets.is_empty() {
            return Err(Errno(3));
        }
        if number == 141 {
            let nice = targets
                .iter()
                .map(|id| {
                    if *id == pid {
                        p.nice
                    } else {
                        self.processes[id].nice
                    }
                })
                .min()
                .unwrap();
            return Ok(Some((20 - nice) as u64)); // raw Linux ABI, not libc's -20..19
        }
        let nice = (a[2] as u32 as i32).clamp(-20, 19);
        let privileged = p.linux.vfs.credentials.has_cap(capabilities::SYS_NICE);
        let caller = p.linux.vfs.credentials.euid;
        let mut error = None;
        for id in targets {
            let target = if id == pid {
                &mut *p
            } else {
                self.processes.get_mut(&id).unwrap()
            };
            if !privileged
                && caller != target.linux.vfs.credentials.uid
                && caller != target.linux.vfs.credentials.euid
            {
                error = Some(Errno(1));
            } else if !privileged && nice < target.nice {
                error = Some(Errno(13));
            } else {
                target.nice = nice;
            }
        }
        if let Some(error) = error {
            Err(error)
        } else {
            Ok(Some(0))
        }
    }
    pub(super) fn mempolicy(p: &mut Process<C>, a: [u64; 6]) -> Result<Option<u64>, Errno> {
        let flags = a[4];
        if flags & !7 != 0
            || flags & 4 != 0 && flags & 3 != 0
            || flags == 1
            || a[3] != 0 && flags & 2 == 0
        {
            return Err(Errno(22));
        }
        if flags & 2 != 0
            && !p
                .memory
                .regions()
                .iter()
                .any(|(start, end, _)| a[3] >= *start && a[3] < *end)
        {
            return Err(Errno(14));
        }
        if a[0] != 0 {
            Linux::check(&p.memory, a[0], 4, Access::Write)?;
        }
        let length = if a[1] != 0 {
            if a[2] == 0 || a[2] > 65536 {
                return Err(Errno(22));
            }
            let length = a[2].div_ceil(64) as usize * 8;
            Linux::check(&p.memory, a[1], length, Access::Write)?;
            length
        } else {
            0
        };
        if a[0] != 0 {
            write_u32(&mut p.memory, a[0], 0)?;
        } // MPOL_DEFAULT, or node 0 with F_NODE
        if length != 0 {
            let mut mask = vec![0; length];
            if flags & 4 != 0 {
                mask[0] = 1;
            } // allowed node mask; default policy mask is empty
            p.memory.write(a[1], &mask).map_err(|_| Errno(14))?;
        }
        Ok(Some(0))
    }
}
#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Kernel = crate::process::Kernel<Cpu>;

    use super::super::tests::{kernel, process};
    use super::*;
    #[test]
    fn desktop_priorities_and_batch_idle_policy_roundtrip_and_inherit() {
        let mut k = kernel();
        let mut p = process();
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
        assert_eq!(child.nice, 19);
        assert_eq!(child.scheduler, 5);
        k.processes.insert(2, p.fork());
        assert_eq!(
            k.syscall(1, &mut p, 119, [2, 3, 0x1000, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert_eq!(
            k.syscall(1, &mut p, 120, [2, 0, 0, 0, 0, 0], &mut io),
            Ok(Some(3))
        );
        assert_eq!(p.scheduler, 5);
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
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
