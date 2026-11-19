// SPDX-License-Identifier: GPL-3.0-or-later
//! Original process limits, callable by any executor. No CPU/VFS owner crosses.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock, Weak},
};
use trames_memory::{Access, CpuMemory};
use trames_vfs::{
    capabilities, Credentials, DescriptorLimit, Errno, FileSizeLimit, PidNamespace, Vfs,
};
type Pair = (u64, u64);
pub struct Limits {
    values: Mutex<[Pair; 8]>, // FSIZE, CORE, NOFILE, NICE, DATA, AS, MEMLOCK, MSGQUEUE.
    file_size: FileSizeLimit,
    nofile: DescriptorLimit,
    nr_open: trames_vfs::DescriptorCeiling,
    vm: trames_vfs::MemoryResourceLimits,
}
impl Limits {
    pub fn new(vfs: &Vfs) -> Arc<Self> {
        Arc::new(Self {
            values: Mutex::new([
                (vfs.file_size_limit_handle().get(), u64::MAX),
                (0, u64::MAX),
                (
                    vfs.descriptor_limit() as u64,
                    vfs.descriptor_ceiling().get() as u64,
                ),
                (0, 0),
                (vfs.memory_resource_limits().data(), u64::MAX),
                (vfs.memory_resource_limits().address_space(), u64::MAX),
                (
                    vfs.memory_resource_limits().locked(),
                    vfs.memory_resource_limits().locked(),
                ),
                (
                    vfs.memory_resource_limits().message_queue(),
                    trames_vfs::posix_mq::DEFAULT_BYTES,
                ),
            ]),
            file_size: vfs.file_size_limit_handle(),
            nofile: vfs.descriptor_limit_handle(),
            nr_open: vfs.descriptor_ceiling(),
            vm: vfs.memory_resource_limits().clone(),
        })
    }
    pub fn fork(&self, vfs: &Vfs) -> Arc<Self> {
        let values = *self.values.lock().unwrap();
        let child = Self::new(vfs);
        for (resource, value) in [1, 4, 7, 13, 2, 9, 8, 12].into_iter().zip(values) {
            child.set(resource, value);
        }
        child
    }
    pub fn bind(&self, vfs: &mut Vfs) {
        vfs.bind_resource_limits(self.file_size.clone(), self.nofile.clone());
        vfs.bind_memory_resource_limits(self.vm.clone());
    }
    pub fn snapshot(&self) -> trames_vfs::MutableLimits {
        trames_vfs::MutableLimits(*self.values.lock().unwrap())
    }
    pub fn get(&self, resource: u64) -> Pair {
        self.values.lock().unwrap()
            [trames_vfs::MutableLimits::index(resource).expect("mutable resource")]
    }
    pub fn set(&self, resource: u64, value: Pair) {
        let mut values = self.values.lock().unwrap();
        values[trames_vfs::MutableLimits::index(resource).expect("mutable resource")] = value;
        self.enforce(resource, value.0);
    }
    fn enforce(&self, resource: u64, soft: u64) {
        match resource {
            1 => self.file_size.set(soft),
            7 => self.nofile.set(soft as u32),
            2 | 8 | 9 | 12 => self.vm.set(resource, soft),
            _ => {}
        }
    }
    /// Decode an already authorized target. Callers keep guest identity checks outside.
    pub fn call(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        fixed: Fixed,
        privileged: bool,
    ) -> Result<u64, Errno> {
        let (resource, new, old) = if number == 261 {
            (a[1], a[2], a[3])
        } else {
            (
                a[0],
                if number == 164 { a[1] } else { 0 },
                if number == 163 { a[1] } else { 0 },
            )
        };
        let ceiling = if resource == 7 {
            self.nr_open.get() as u64
        } else {
            fixed.value(resource)?
        };
        if old != 0 {
            memory
                .check(old, 16, Access::Write)
                .map_err(|_| Errno(14))?;
        }
        // Import before copyout: new and old may alias, including raw SVC callers.
        let next = if new != 0 {
            let bytes = memory.read_array::<16>(new).map_err(|_| Errno(14))?;
            let value = (
                u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                u64::from_le_bytes(bytes[8..].try_into().unwrap()),
            );
            if value.0 > value.1 {
                return Err(Errno(22));
            }
            Some(value)
        } else {
            None
        };
        let mut values = self.values.lock().unwrap();
        let previous =
            trames_vfs::MutableLimits::index(resource).map_or((ceiling, ceiling), |i| values[i]);
        if let Some(value) = next {
            if value.1 > previous.1 && !privileged
                || !matches!(resource, 1 | 2 | 4 | 9 | 12) && value.1 > ceiling
            {
                return Err(Errno(1));
            }
            if trames_vfs::MutableLimits::index(resource).is_none() && value != previous {
                return Err(Errno(95));
            }
        }
        if old != 0 {
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&previous.0.to_le_bytes());
            bytes[8..].copy_from_slice(&previous.1.to_le_bytes());
            memory.write_array(old, bytes).map_err(|_| Errno(14))?;
        }
        if let Some(value) = next {
            if let Some(i) = trames_vfs::MutableLimits::index(resource) {
                values[i] = value;
                self.enforce(resource, value.0);
            }
        }
        Ok(0)
    }
}
pub use trames_vfs::FixedLimits as Fixed;
struct Target {
    presence: crate::task::Visibility,
    limits: Weak<Limits>,
    identity: Arc<trames_vfs::CredentialState>,
}
#[derive(Default)]
pub struct Directory(RwLock<BTreeMap<u32, Target>>);
impl Directory {
    pub fn retire(&self, pid: u32, original: &crate::task::Visibility) {
        let removed = {
            let mut entries = self.0.write().unwrap();
            if !entries
                .get(&pid)
                .is_some_and(|t| t.presence.identity() == original.identity())
            {
                return;
            }
            entries.remove(&pid)
        };
        drop(removed);
    }
    pub fn prune(&self) {
        self.0.write().unwrap().retain(|_, t| t.presence.present());
    }
    pub fn publish(
        &self,
        pid: u32,
        presence: &Arc<crate::task::Presence>,
        limits: &Arc<Limits>,
        credentials: &Arc<trames_vfs::CredentialState>,
    ) {
        let mut entries = self.0.write().unwrap();
        // Publication is a lifecycle/authority boundary, never a syscall hot path.
        entries.insert(
            pid,
            Target {
                presence: presence.visibility(),
                limits: Arc::downgrade(limits),
                identity: credentials.clone(),
            },
        );
    }
}
#[derive(Clone)]
pub struct Authority {
    pub directory: Arc<Directory>,
    pub limits: Arc<Limits>,
    pub namespace: PidNamespace,
    pub pid: u32,
    pub credentials: Credentials,
    pub fixed: Fixed,
}
impl Authority {
    pub fn call(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        let pid = if number == 261 && a[0] as u32 != 0 {
            self.namespace.global(a[0] as u32).ok_or(Errno(3))?
        } else {
            self.pid
        };
        self.call_resolved(pid, number, a, memory)
    }
    /// The trusted owner has already resolved this global target in its namespace.
    pub fn call_resolved(
        &self,
        pid: u32,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        let privileged = self.credentials.has_cap(capabilities::SYS_RESOURCE);
        if pid == self.pid {
            return self.limits.call(number, a, memory, self.fixed, privileged);
        }
        let target = {
            let entries = self.directory.0.read().unwrap();
            let target = entries
                .get(&pid)
                .filter(|t| t.presence.present())
                .ok_or(Errno(3))?;
            let credentials = target.identity.read();
            if !privileged
                && !([credentials.uid, credentials.euid, credentials.suid]
                    .iter()
                    .all(|id| *id == self.credentials.uid)
                    && [credentials.gid, credentials.egid, credentials.sgid]
                        .iter()
                        .all(|id| *id == self.credentials.gid))
            {
                return Err(Errno(1));
            }
            target.limits.upgrade().ok_or(Errno(3))?
        };
        target.call(number, a, memory, self.fixed, privileged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m
    }
    fn fixed() -> Fixed {
        Fixed {
            address_space: u64::MAX,
            stack: 8 << 20,
            tasks: 1024,
        }
    }
    fn pair(m: &mut Memory, v: Pair) {
        let mut b = [0; 16];
        b[..8].copy_from_slice(&v.0.to_le_bytes());
        b[8..].copy_from_slice(&v.1.to_le_bytes());
        m.write_array(0x1000, b).unwrap();
    }
    #[test]
    fn concurrent_alias_transactions_keep_pairs_and_original_fd_enforcement_together() {
        let v = Vfs::default();
        let limits = Limits::new(&v);
        limits.set(7, (64, 128));
        std::thread::scope(|scope| {
            for worker in 0..4 {
                let limits = &limits;
                scope.spawn(move || {
                    let mut m = memory();
                    for i in 0..1000 {
                        let n = 64 + ((i + worker) % 16);
                        pair(&mut m, (n, n * 2));
                        assert_eq!(
                            limits.call(261, [0, 7, 0x1000, 0x1000, 0, 0], &mut m, fixed(), true),
                            Ok(0)
                        );
                        let b = m.read_array::<16>(0x1000).unwrap();
                        let soft = u64::from_le_bytes(b[..8].try_into().unwrap());
                        let hard = u64::from_le_bytes(b[8..].try_into().unwrap());
                        assert_eq!(hard, soft * 2);
                    }
                });
            }
        });
        assert_eq!(v.descriptor_limit() as u64, limits.get(7).0);
    }
    #[test]
    fn shared_thread_limits_update_live_handles_but_forks_remain_independent() {
        let v = Vfs::default();
        let limits = Limits::new(&v);
        let mut thread = v.clone_with_files(false);
        limits.bind(&mut thread);
        thread.unshare_descriptors();
        let fork = v.clone_with_files(true);
        let child = limits.fork(&fork);
        limits.set(1, (9, 18));
        limits.set(7, (8, 16));
        assert_eq!(thread.file_size_limit_handle().get(), 9);
        assert_eq!(thread.descriptor_limit(), 8);
        assert_eq!(fork.file_size_limit_handle().get(), u64::MAX);
        assert_eq!(child.get(7).0, trames_vfs::DEFAULT_MAX_FDS as u64);
        child.set(1, (3, 6));
        assert_eq!(v.file_size_limit_handle().get(), 9);
    }
    #[test]
    fn retained_old_limit_object_cannot_keep_a_reaped_pid_visible_or_retarget_reuse() {
        let v = Vfs::default();
        let directory = Arc::new(Directory::default());
        let own = Limits::new(&v);
        let old = Limits::new(&v);
        let life = Arc::new(crate::task::Presence::default());
        directory.publish(42, &life, &old, &Arc::default());
        let a = Authority {
            directory: directory.clone(),
            limits: own,
            namespace: v.pid_namespace().clone(),
            pid: 1,
            credentials: Credentials::default(),
            fixed: fixed(),
        };
        let mut m = memory();
        assert_eq!(a.call(261, [42, 7, 0, 0x1000, 0, 0], &mut m), Ok(0));
        drop(life);
        assert_eq!(a.call(261, [42, 7, 0, 0x1000, 0, 0], &mut m), Err(Errno(3)));
        let replacement = Limits::new(&v);
        let life = Arc::new(crate::task::Presence::default());
        directory.publish(42, &life, &replacement, &Arc::default());
        pair(&mut m, (8, 16));
        assert_eq!(a.call(261, [42, 7, 0x1000, 0, 0, 0], &mut m), Ok(0));
        assert_eq!(replacement.get(7), (8, 16));
        assert_eq!(old.get(7).0, trames_vfs::DEFAULT_MAX_FDS as u64);
    }
}

#[cfg(test)]
mod gvisor_regressions {
    use super::*;
    #[test]
    fn source_sysctl_write_updates_preexisting_limits_and_fresh_path_captures() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let limits = Limits::new(&v);
        let paths = v.path_queries();
        let mut epoch = trames_vfs::FileEpoch::default();
        let files = epoch.capture(&v, true);
        let fd = paths
            .open_at_resolve(
                trames_vfs::AT_FDCWD,
                b"/proc/sys/fs/nr_open",
                1,
                0,
                0,
                &files,
            )
            .unwrap()
            .unwrap();
        assert_eq!(v.write(fd, b"4194304"), Ok(7));
        let mut memory = trames_memory::Memory::default();
        memory
            .map(0x1000, 4096, trames_memory::Permissions::RW)
            .unwrap();
        memory
            .write_array(0x1000, 4194304u64.to_le_bytes())
            .unwrap();
        memory
            .write_array(0x1008, 4194304u64.to_le_bytes())
            .unwrap();
        assert_eq!(
            limits.call(
                164,
                [7, 0x1000, 0, 0, 0, 0],
                &mut memory,
                Fixed {
                    address_space: 8192,
                    stack: 4096,
                    tasks: 8192
                },
                true
            ),
            Ok(0)
        );
        assert_eq!(v.descriptor_limit(), 4194304);
        let other = v.clone();
        assert_eq!(other.descriptor_ceiling().get(), 4194304);
        assert_eq!(limits.nr_open.get(), 4194304);
    }
}
