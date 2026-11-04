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
    values: Mutex<[Pair; 3]>, // FSIZE, CORE, NOFILE; updated with their enforcement fields.
    file_size: FileSizeLimit,
    nofile: DescriptorLimit,
}
impl Limits {
    pub fn new(vfs: &Vfs) -> Arc<Self> {
        Arc::new(Self {
            values: Mutex::new([
                (vfs.file_size_limit_handle().get(), u64::MAX),
                (0, u64::MAX),
                (vfs.descriptor_limit() as u64, trames_vfs::MAX_FDS as u64),
            ]),
            file_size: vfs.file_size_limit_handle(),
            nofile: vfs.descriptor_limit_handle(),
        })
    }
    pub fn fork(&self, vfs: &Vfs) -> Arc<Self> {
        let values = *self.values.lock().unwrap();
        let child = Self::new(vfs);
        for (resource, value) in [1, 4, 7].into_iter().zip(values) {
            child.set(resource, value);
        }
        child
    }
    pub fn bind(&self, vfs: &mut Vfs) {
        vfs.bind_resource_limits(self.file_size.clone(), self.nofile.clone());
    }
    fn index(resource: u64) -> Option<usize> {
        match resource {
            1 => Some(0),
            4 => Some(1),
            7 => Some(2),
            _ => None,
        }
    }
    pub fn get(&self, resource: u64) -> Pair {
        self.values.lock().unwrap()[Self::index(resource).expect("mutable resource")]
    }
    pub fn set(&self, resource: u64, value: Pair) {
        let mut values = self.values.lock().unwrap();
        values[Self::index(resource).expect("mutable resource")] = value;
        self.enforce(resource, value.0);
    }
    fn enforce(&self, resource: u64, soft: u64) {
        match resource {
            1 => self.file_size.set(soft),
            7 => self.nofile.set(soft as u32),
            _ => {}
        }
    }
    fn call(
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
        let ceiling = fixed.value(resource)?;
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
        let previous = Self::index(resource).map_or((ceiling, ceiling), |i| values[i]);
        if let Some(value) = next {
            if value.1 > previous.1 && !privileged
                || !matches!(resource, 1 | 4) && value.1 > ceiling
            {
                return Err(Errno(1));
            }
            if Self::index(resource).is_none() && value != previous {
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
            if let Some(i) = Self::index(resource) {
                values[i] = value;
                self.enforce(resource, value.0);
            }
        }
        Ok(0)
    }
}
#[derive(Clone, Copy)]
pub struct Fixed {
    pub address_space: u64,
    pub stack: u64,
    pub tasks: u64,
}
impl Fixed {
    fn value(self, resource: u64) -> Result<u64, Errno> {
        Ok(match resource {
            0 | 1 | 10 | 15 => u64::MAX,
            2 | 5 | 9 => self.address_space,
            3 => self.stack,
            4 | 8 | 12 | 13 | 14 => 0,
            6 => self.tasks,
            7 => trames_vfs::MAX_FDS as u64,
            11 => 64,
            _ => return Err(Errno(22)),
        })
    }
}
#[derive(Clone)]
struct Identity {
    uid: [u32; 3],
    gid: [u32; 3],
}
impl From<&Credentials> for Identity {
    fn from(c: &Credentials) -> Self {
        Self {
            uid: [c.uid, c.euid, c.suid],
            gid: [c.gid, c.egid, c.sgid],
        }
    }
}
struct Target {
    presence: Weak<()>,
    limits: Weak<Limits>,
    identity: Identity,
}
#[derive(Default)]
pub struct Directory(RwLock<BTreeMap<u32, Target>>);
impl Directory {
    pub fn prune(&self) {
        self.0
            .write()
            .unwrap()
            .retain(|_, t| t.presence.strong_count() != 0);
    }
    pub fn publish(
        &self,
        pid: u32,
        presence: &Arc<()>,
        limits: &Arc<Limits>,
        credentials: &Credentials,
    ) {
        let mut entries = self.0.write().unwrap();
        // Publication is a lifecycle/authority boundary, never a syscall hot path.
        entries.insert(
            pid,
            Target {
                presence: Arc::downgrade(presence),
                limits: Arc::downgrade(limits),
                identity: credentials.into(),
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
        let privileged = self.credentials.has_cap(capabilities::SYS_RESOURCE);
        if pid == self.pid {
            return self.limits.call(number, a, memory, self.fixed, privileged);
        }
        let target = {
            let entries = self.directory.0.read().unwrap();
            let target = entries
                .get(&pid)
                .filter(|t| t.presence.strong_count() != 0)
                .ok_or(Errno(3))?;
            if !privileged
                && !(target
                    .identity
                    .uid
                    .iter()
                    .all(|id| *id == self.credentials.uid)
                    && target
                        .identity
                        .gid
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
        assert_eq!(child.get(7).0, trames_vfs::MAX_FDS as u64);
        child.set(1, (3, 6));
        assert_eq!(v.file_size_limit_handle().get(), 9);
    }
    #[test]
    fn retained_old_limit_object_cannot_keep_a_reaped_pid_visible_or_retarget_reuse() {
        let v = Vfs::default();
        let directory = Arc::new(Directory::default());
        let own = Limits::new(&v);
        let old = Limits::new(&v);
        let life = Arc::new(());
        directory.publish(42, &life, &old, &Credentials::default());
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
        let life = Arc::new(());
        directory.publish(42, &life, &replacement, &Credentials::default());
        pair(&mut m, (8, 16));
        assert_eq!(a.call(261, [42, 7, 0x1000, 0, 0, 0], &mut m), Ok(0));
        assert_eq!(replacement.get(7), (8, 16));
        assert_eq!(old.get(7).0, trames_vfs::MAX_FDS as u64);
    }
}
