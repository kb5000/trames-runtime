// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest OOM preferences. Allocation limits still return ENOMEM; there is no
//! guest OOM victim selector. Never changes the host process's OOM policy.
use crate::*;
use std::sync::atomic::AtomicU32;

/// Task lifetime and signal-group preference are distinct: an open proc file
/// must not keep a dead task alive, even while another thread survives.
#[derive(Default)]
pub struct OomTask {
    // Score and the privileged floor form one invariant. Both fit in i16;
    // update the pair atomically, without a task/global lock or byte barriers.
    score: Arc<AtomicU32>,
}
fn pack(value: i32, minimum: i32) -> u32 {
    u32::from(value as i16 as u16) | (u32::from(minimum as i16 as u16) << 16)
}
fn unpack(pair: u32) -> (i32, i32) {
    (pair as u16 as i16 as i32, (pair >> 16) as u16 as i16 as i32)
}
impl OomTask {
    pub fn fork(&self) -> Self {
        Self {
            score: Arc::new(AtomicU32::new(self.score.load(Ordering::Relaxed))),
        }
    }
    pub fn thread(&self) -> Self {
        Self {
            score: self.score.clone(),
        }
    }
    fn read(&self, offset: u64, count: usize) -> Vec<u8> {
        let value = format!("{}\n", unpack(self.score.load(Ordering::Relaxed)).0).into_bytes();
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(value.len());
        value[start..start + count.min(value.len() - start)].to_vec()
    }
    fn write(&self, bytes: &[u8], privileged: bool) -> Result<usize> {
        // Linux fs/proc/base.c uses PROC_NUMBUF (13), strstrip and kstrtoint(0).
        let count = bytes.len().min(12);
        let input = &bytes[..count];
        let input = input.split(|b| *b == 0).next().unwrap_or_default();
        let input = std::str::from_utf8(input)
            .map_err(|_| Errno(22))?
            .trim_ascii();
        let (negative, digits) = if let Some(s) = input.strip_prefix('-') {
            (true, s)
        } else {
            (false, input.strip_prefix('+').unwrap_or(input))
        };
        let (radix, digits) = if let Some(s) = digits
            .strip_prefix("0x")
            .or_else(|| digits.strip_prefix("0X"))
        {
            (16, s)
        } else if digits.starts_with('0') && digits.len() > 1 {
            (8, digits)
        } else {
            (10, digits)
        };
        if digits.is_empty() || !digits.bytes().all(|b| (b as char).is_digit(radix)) {
            return Err(Errno(22));
        }
        let magnitude = i64::from_str_radix(digits, radix).map_err(|_| Errno(34))?;
        let value =
            i32::try_from(if negative { -magnitude } else { magnitude }).map_err(|_| Errno(34))?;
        if !(-1000..=1000).contains(&value) {
            return Err(Errno(22));
        }
        if privileged {
            self.score.store(pack(value, value), Ordering::Relaxed);
        } else {
            // Retest the floor if another writer changes it before commit.
            // A stale permission check must not overwrite a newer floor.
            self.score
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |pair| {
                    let (_, minimum) = unpack(pair);
                    (value >= minimum).then(|| pack(value, minimum))
                })
                .map_err(|_| Errno(13))?;
        }
        Ok(count)
    }
}

impl Vfs {
    pub(super) fn oom_for_path(&self, at: &ResolvedPath) -> Option<std::sync::Weak<OomTask>> {
        if !self.uses_pseudo(at) || !self.pseudo.borrow().enabled {
            return None;
        }
        let rest = at.key.strip_prefix(b"/proc/")?;
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let number = |s: &[u8]| std::str::from_utf8(s).ok()?.parse::<u32>().ok();
        let pid = number(parts[0])?;
        let pseudo = self.pseudo.borrow();
        let runtime = self.proc_runtime(at, &pseudo.runtime);
        let mut task = runtime.processes.iter().find(|p| p.pid == pid)?;
        match parts.as_slice() {
            [_, b"oom_score_adj"] => {}
            [_, b"task", tid, b"oom_score_adj"] => {
                let tid = number(tid)?;
                task = runtime
                    .processes
                    .iter()
                    .find(|p| p.pid == tid && p.tgid == task.tgid)?;
            }
            _ => return None,
        }
        Some(task.oom.clone())
    }
    pub(super) fn oom_read(
        o: &OpenDescription,
        offset: u64,
        count: usize,
    ) -> Result<Option<Vec<u8>>> {
        o.oom
            .as_ref()
            .map(|task| Ok(task.upgrade().ok_or(Errno(3))?.read(offset, count)))
            .transpose()
    }
    pub(super) fn oom_write(&self, o: &OpenDescription, bytes: &[u8]) -> Result<Option<usize>> {
        o.oom
            .as_ref()
            .map(|task| {
                task.upgrade()
                    .ok_or(Errno(3))?
                    .write(bytes, self.credentials.has_cap(capabilities::SYS_RESOURCE))
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_score_and_privilege_floor_updates_remain_one_atomic_state() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<OomTask>();
        let task = OomTask::default();
        let gate = Arc::new(std::sync::Barrier::new(4));
        std::thread::scope(|scope| {
            for rank in 0..4 {
                let task = task.thread();
                let gate = gate.clone();
                scope.spawn(move || {
                    gate.wait();
                    for i in 0..4096 {
                        if rank == 0 {
                            let values: [&[u8]; 3] = [b"500", b"-300", b"100"];
                            task.write(values[i % 3], true).unwrap();
                        } else {
                            let values: [&[u8]; 3] = [b"-299", b"499", b"1000"];
                            let result = task.write(values[(i + rank) % 3], false);
                            assert!(result.is_ok() || result == Err(Errno(13)));
                        }
                        let (score, minimum) = unpack(task.score.load(Ordering::Relaxed));
                        assert!(score >= minimum);
                        assert!((-1000..=1000).contains(&score));
                        // Fork snapshots the pair, not two racing scalar loads.
                        let child = task.fork();
                        let (score, minimum) = unpack(child.score.load(Ordering::Relaxed));
                        assert!(score >= minimum);
                    }
                });
            }
        });
        task.write(b"500", true).unwrap();
        assert_eq!(task.thread().write(b"499", false), Err(Errno(13)));
        assert_eq!(task.read(0, 32), b"500\n");
    }
    #[test]
    fn worker_final_task_release_does_not_wait_for_surviving_group_member() {
        let task = Arc::new(OomTask::default());
        let observer = Arc::downgrade(&task);
        let sibling = task.thread();
        std::thread::spawn(move || {
            task.write(b"-100", true).unwrap();
            // Actual final task identity dies on this worker; shared group
            // preference remains independently usable by another live task.
            drop(task);
        })
        .join()
        .unwrap();
        assert!(observer.upgrade().is_none());
        assert_eq!(sibling.read(0, 32), b"-100\n");
        assert_eq!(sibling.write(b"-101", false), Err(Errno(13)));
    }
    #[test]
    fn privilege_floor_fork_sharing_and_invalid_writes_are_atomic() {
        let parent = OomTask::default();
        assert_eq!(parent.write(b"-400", true), Ok(4));
        assert_eq!(parent.write(b"600", false), Ok(3));
        assert_eq!(parent.write(b"-400", false), Ok(4));
        assert_eq!(parent.write(b"-401", false), Err(Errno(13)));
        let child = parent.fork();
        let thread = parent.thread();
        thread.write(b"100", true).unwrap();
        assert_eq!(parent.read(0, 32), b"100\n");
        assert_eq!(child.read(0, 32), b"-400\n");
        assert_eq!(parent.write(b"99", false), Err(Errno(13)));
        for (input, errno) in [(b"1001".as_slice(), 22), (b"1x", 22), (b"2147483648", 34)] {
            assert_eq!(parent.write(input, true), Err(Errno(errno)));
            assert_eq!(parent.read(0, 32), b"100\n");
        }
    }
    #[test]
    fn proc_control_checks_dac_mount_and_retains_only_weak_task_identity() {
        let mut v = Vfs::default();
        let task = Arc::new(OomTask::default());
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    oom: Arc::downgrade(&task),
                    credentials: Credentials::user(1000, 1000),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        v.credentials = Credentials::user(2000, 2000);
        assert_eq!(
            v.open_at(AT_FDCWD, b"/proc/1/oom_score_adj", 1, 0),
            Err(Errno(13))
        );
        v.credentials = Credentials::user(1000, 1000);
        let fd = v
            .open_at(AT_FDCWD, b"/proc/1/oom_score_adj", 2 | 0x200, 0)
            .unwrap();
        assert_eq!(v.write(fd, b"500"), Ok(3));
        assert_eq!(v.read(fd, 32).unwrap(), b"500\n");
        assert_eq!(
            v.mapping_pages(fd, 0, 4096, false, false).err(),
            Some(Errno(19))
        );
        v.credentials = Credentials::default();
        let mount = v
            .descriptor(fd)
            .unwrap()
            .open
            .borrow()
            .mount
            .clone()
            .unwrap();
        mount.flags.set(mount.flags.get() | mounts::MS_RDONLY);
        assert_eq!(v.write(fd, b"600"), Err(Errno(30)));
        assert_eq!(
            v.open_at(AT_FDCWD, b"/proc/1/oom_score_adj", 1, 0),
            Err(Errno(30))
        );
        mount.flags.set(mount.flags.get() & !mounts::MS_RDONLY);
        assert_eq!(v.open_at(AT_FDCWD, b"/proc/stat", 1, 0), Err(Errno(30)));
        assert_eq!(
            v.open_at(AT_FDCWD, b"/proc/1/new", 0x41, 0o644),
            Err(Errno(30))
        );
        drop(task);
        assert_eq!(v.pread(fd, 32, 0), Err(Errno(3)));
        assert_eq!(v.write(fd, b"600"), Err(Errno(3)));
    }
    #[test]
    fn task_paths_use_thread_credentials_and_thread_lifetime() {
        let mut v = Vfs::default();
        let leader = Arc::new(OomTask::default());
        let thread = Arc::new(leader.thread());
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![
                    ProcessInfo {
                        pid: 1,
                        tgid: 1,
                        oom: Arc::downgrade(&leader),
                        credentials: Credentials::user(1000, 1000),
                        ..Default::default()
                    },
                    ProcessInfo {
                        pid: 2,
                        tgid: 1,
                        oom: Arc::downgrade(&thread),
                        credentials: Credentials::user(2000, 2000),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );
        v.credentials = Credentials::user(1000, 1000);
        assert_eq!(
            v.open_at(AT_FDCWD, b"/proc/1/task/2/oom_score_adj", 1, 0),
            Err(Errno(13))
        );
        v.credentials = Credentials::user(2000, 2000);
        let fd = v
            .open_at(AT_FDCWD, b"/proc/1/task/2/oom_score_adj", 2, 0)
            .unwrap();
        v.write(fd, b"500").unwrap();
        assert_eq!(leader.read(0, 32), b"500\n");
        drop(thread);
        assert_eq!(v.pread(fd, 32, 0), Err(Errno(3)));
        assert_eq!(leader.read(0, 32), b"500\n");
    }
}
