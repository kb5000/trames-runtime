// SPDX-License-Identifier: GPL-3.0-or-later
//! Pollable proc pressure OFDs retain their original session resource.
use super::*;
use std::sync::Mutex;
use trames_memory::{pressure::PressureMonitor, MemoryPressure};
#[derive(Clone, Copy)]
enum Kind {
    Memory,
    Zones,
    Vmstat,
}
pub(super) struct PressureFile {
    domain: Arc<MemoryPressure>,
    kind: Kind,
    privileged: bool,
    monitor: Mutex<Option<Arc<PressureMonitor>>>,
}
impl PressureFile {
    pub(super) fn epoch(&self) -> [u64; 2] {
        self.monitor
            .lock()
            .unwrap()
            .as_ref()
            .map_or([0; 2], |monitor| monitor.epoch())
    }
    pub(super) fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        if !matches!(self.kind, Kind::Memory) {
            return (events & 0x145, [0; 2]);
        }
        self.monitor
            .lock()
            .unwrap()
            .as_ref()
            .map_or((events & 0x147 | 8, [0; 2]), |monitor| monitor.poll(events))
    }
    pub(super) fn acknowledge(&self, epoch: [u64; 2]) {
        if let Some(monitor) = self.monitor.lock().unwrap().as_ref() {
            monitor.acknowledge(epoch);
        }
    }
    pub(super) fn peek(&self, events: u16) -> (u16, [u64; 2]) {
        if !matches!(self.kind, Kind::Memory) {
            return (events & 0x145, [0; 2]);
        }
        self.monitor
            .lock()
            .unwrap()
            .as_ref()
            .map_or((events & 0x147 | 8, [0; 2]), |monitor| monitor.peek(events))
    }
    pub(super) fn deadline(&self) -> Option<std::time::Instant> {
        self.monitor
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|monitor| monitor.deadline())
    }
    pub(super) fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.domain.subscribe(signal)
    }
    pub(super) fn read(&self, offset: u64, count: usize) -> Vec<u8> {
        let bytes = match self.kind {
            Kind::Memory => self.domain.format(),
            Kind::Zones => {
                let m = self.domain.memory();
                let [min, low, high] = self.domain.watermarks();
                format!("Node 0, zone Normal\n  nr_inactive_file 0\n  nr_active_file 0\n  nr_free_pages {}\n        min {}\n        low {}\n        high {}\n        present {}\n  nr_free_cma 0\n  protection: (0)\n  pagesets\n",m.free/4096,min/4096,low/4096,high/4096,m.total/4096).into_bytes()
            }
            Kind::Vmstat => {
                let m = self.domain.memory();
                format!("nr_free_pages {}\nnr_inactive_file 0\nnr_active_file 0\nworkingset_refault 0\nworkingset_refault_file 0\nworkingset_refault_anon {}\npgscan_kswapd 0\npgscan_direct {}\npgsteal_direct {}\npgscan_direct_throttle 0\n",m.free/4096,self.domain.anonymous_refaults(),self.domain.scanned_pages(),self.domain.reclaimed()).into_bytes()
            }
        };
        let start = offset.min(bytes.len() as u64) as usize;
        bytes[start..bytes.len().min(start.saturating_add(count))].to_vec()
    }
    pub(super) fn write(&self, bytes: &[u8]) -> Result<usize> {
        if !matches!(self.kind, Kind::Memory) {
            return Err(Errno(5));
        }
        if bytes.is_empty() {
            return Err(Errno(22));
        }
        let mut monitor = self.monitor.lock().unwrap();
        if monitor.is_some() {
            return Err(Errno(16));
        }
        // proc PSI imports at most 32 bytes and replaces the final imported
        // byte with NUL, including when the caller omitted a terminator.
        let imported = bytes.len().min(32);
        *monitor = Some(
            self.domain
                .monitor(&bytes[..imported - 1], self.privileged)
                .map_err(Errno)?,
        );
        Ok(bytes.len())
    }
}
impl Vfs {
    pub fn bind_memory_pressure(&self, domain: Arc<MemoryPressure>) {
        *self.pseudo.borrow().memory_pressure.write().unwrap() = Some(domain);
    }
    pub fn memory_pressure(&self) -> Option<Arc<MemoryPressure>> {
        self.pseudo.borrow().memory_pressure.read().unwrap().clone()
    }
    pub(super) fn pressure_file(
        &self,
        path: &ResolvedPath,
        flags: u32,
    ) -> Option<Arc<PressureFile>> {
        if flags & O_PATH != 0 {
            return None;
        }
        let kind = match path.key.as_slice() {
            b"/proc/pressure/memory" => Kind::Memory,
            b"/proc/zoneinfo" => Kind::Zones,
            b"/proc/vmstat" => Kind::Vmstat,
            _ => return None,
        };
        Some(Arc::new(PressureFile {
            domain: self.memory_pressure()?,
            kind,
            privileged: self.credentials.has_local_cap(capabilities::SYS_RESOURCE),
            monitor: Default::default(),
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_projection_created_before_session_binding_sees_original_pressure_resource() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let paths = v.path_queries();
        let domain = MemoryPressure::host(Arc::new(Default::default));
        v.bind_memory_pressure(domain.clone());
        let files = FileEpoch::default().capture(&v, true);
        let fd = paths
            .open_at_resolve(AT_FDCWD, b"/proc/pressure/memory", 2, 0, 0, &files)
            .unwrap()
            .unwrap();
        let accepted = v.direct_descriptors().get(fd).unwrap();
        accepted.write(b"some 1 2000000\0").unwrap();
        assert!(domain.monitored());
        v.close(fd).unwrap();
        drop(accepted);
        assert!(!domain.monitored());
    }
    #[test]
    fn lmkd_status_contract_includes_real_rss_and_zero_guest_swap() {
        let mut v = Vfs::default();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    state: 'R',
                    mapped_bytes: 64 << 20,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let fd = v.open_at(AT_FDCWD, b"/proc/1/status", 0, 0).unwrap();
        let status = String::from_utf8(v.read(fd, 4096).unwrap()).unwrap();
        for field in ["Tgid:\t1\n", "VmRSS:\t65536 kB\n", "VmSwap:\t0 kB\n"] {
            assert!(status.contains(field), "original lmkd requires {field}");
        }
    }
    #[test]
    fn concurrent_pollers_consume_one_original_psi_event() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let domain = MemoryPressure::host(Arc::new(Default::default));
        v.bind_memory_pressure(domain.clone());
        let fd = v.open_at(AT_FDCWD, b"/proc/pressure/memory", 2, 0).unwrap();
        v.write(fd, b"full 1000 1000000\0").unwrap();
        let file = match &v.descriptor(fd).unwrap().open.borrow().control {
            Some(events::SharedControl::Pressure(file)) => file.clone(),
            _ => panic!("original pressure resource"),
        };
        let task = domain.task();
        let _stall = task.stall();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(file.peek(2).0, 2);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut pollers = Vec::new();
        for _ in 0..2 {
            let file = file.clone();
            let barrier = barrier.clone();
            pollers.push(std::thread::spawn(move || {
                barrier.wait();
                file.poll(2).0
            }));
        }
        barrier.wait();
        assert_eq!(
            pollers.into_iter().map(|p| p.join().unwrap()).sum::<u16>(),
            2
        );
    }
    #[test]
    fn psi_epoll_previews_and_cancelled_copyout_preserve_the_original_event() {
        for direct in [false, true] {
            let mut v = Vfs::default();
            v.set_runtime_info(1, Default::default());
            let domain = MemoryPressure::host(Arc::new(Default::default));
            v.bind_memory_pressure(domain.clone());
            let fd = v.open_at(AT_FDCWD, b"/proc/pressure/memory", 2, 0).unwrap();
            v.write(fd, b"full 1000 1000000\0").unwrap();
            let ep = v.epoll_create(0).unwrap();
            v.epoll_ctl(ep, 1, fd, 2, 77).unwrap();
            let task = domain.task();
            let _stall = task.stall();
            std::thread::sleep(std::time::Duration::from_millis(2));
            for _ in 0..2 {
                assert!(v.epoll_ready_signals(ep, 0, |_, _| Ok(None)).unwrap());
            }
            let original = v.direct_descriptors().get(ep).unwrap();
            let mut cancelled = original.epoll_delivery().unwrap();
            assert!(cancelled.prepare(1).is_ok());
            assert_eq!(cancelled.events().collect::<Vec<_>>(), [(2, 77)]);
            drop(cancelled);
            if direct {
                let mut accepted = original.epoll_delivery().unwrap();
                assert!(accepted.prepare(1).is_ok());
                assert_eq!(accepted.events().collect::<Vec<_>>(), [(2, 77)]);
                accepted.commit(1);
            } else {
                assert_eq!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(), [(2, 77)]);
            }
            assert!(!v.epoll_ready_signals(ep, 0, |_, _| Ok(None)).unwrap());
            assert!(original.epoll_wait(1).unwrap().is_empty());
        }
    }
    #[test]
    fn proc_pressure_ofds_preserve_trigger_credentials_positions_and_shared_identity() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let domain = MemoryPressure::new(Arc::new(|| trames_memory::PressureMemory {
            total: 1 << 20,
            free: 1 << 19,
            available: 1 << 19,
        }));
        v.bind_memory_pressure(domain.clone());
        let fd = v
            .open_at(AT_FDCWD, b"/proc/pressure/memory", 2 | O_NONBLOCK, 0)
            .unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let separate = v.open_at(AT_FDCWD, b"/proc/pressure/memory", 2, 0).unwrap();
        assert!(String::from_utf8(v.read(fd, 4096).unwrap())
            .unwrap()
            .starts_with("some avg10="));
        assert!(v.read(alias, 4096).unwrap().is_empty());
        let descriptors = v.direct_descriptors();
        let original = descriptors.get(alias).unwrap();
        let peer = descriptors.get(separate).unwrap();
        original.byte_seek(0, 0).unwrap();
        assert!(original.read(4096).unwrap().starts_with(b"some "));
        assert_eq!(original.write(b"some 2000000 2000000"), Err(Errno(22)));
        original.write(b"some 1000 1000000\0").unwrap();
        assert_eq!(peer.write(b"full 1 1000000\n"), Ok(15));
        assert_eq!(original.write(b"full 1 1000000\n"), Err(Errno(16)));
        v.close(fd).unwrap();
        assert!(domain.monitored());
        let task = domain.task();
        let guard = task.stall();
        assert!(original.poll_deadline(2).is_some());
        drop(guard);
        drop(task);
        // Closing one numeric alias retains the original monitor through both
        // the other alias and an accepted resource snapshot.
        v.close(alias).unwrap();
        v.close(separate).unwrap();
        drop(descriptors);
        drop(original);
        drop(peer);
        assert!(!domain.monitored());
    }
}
