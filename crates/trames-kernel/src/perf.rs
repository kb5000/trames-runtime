// SPDX-License-Identifier: GPL-3.0-or-later
//! Task-scoped software perf admission; accepted events retain the actual clock.
use crate::signal::{IoRoutes, IoTask};
use trames_memory::CpuMemory;
use trames_vfs::{perf::Attr, DescriptorFactory, Errno, FdFlags};

impl IoRoutes {
    pub fn perf_event_open(
        &self,
        caller: &IoTask,
        files: &FdFlags,
        factory: &DescriptorFactory,
        a: [u64; 6],
        cpus: usize,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        if a[4] & !15 != 0 {
            return Err(Errno(22));
        }
        let attr = Attr::read(memory, a[0])?;
        factory.check_perf_attr(&attr)?;
        let pid = a[1] as i32;
        let cpu = a[2] as i32;
        if cpu < -1 || cpu >= cpus as i32 || pid < -1 || pid == -1 && cpu == -1 {
            return Err(Errno(22));
        }
        // CPU-wide and cgroup scopes need their original producers.
        if cpu != -1 || pid == -1 || a[4] & 4 != 0 {
            return Err(Errno(95));
        }
        let group = a[3] as i32;
        let named = if group == -1 {
            None
        } else {
            Some(files.perf_event(group as u32)?.ok_or(Errno(9))?)
        };
        let retained = if pid == 0 {
            None
        } else {
            let global = self.namespace.global(pid as u32).ok_or(Errno(3))?;
            Some(
                self.directory
                    .proc_task(global)
                    .filter(|task| task.live())
                    .ok_or(Errno(3))?,
            )
        };
        let target = retained.as_deref().unwrap_or(caller);
        target
            .credentials()
            .check_perf(&caller.credentials().read(), target.tgid() == caller.tgid())?;
        let leader = if a[4] & 1 == 0 { named.as_ref() } else { None };
        let output = if a[4] & 2 != 0 { named.as_ref() } else { None };
        factory
            .perf_event_configured(
                attr,
                target.proc_view.perf_clock(),
                leader,
                output,
                a[4] & 8 != 0,
                cpus,
            )
            .map(u64::from)
    }
}
