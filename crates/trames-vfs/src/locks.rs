// SPDX-License-Identifier: GPL-3.0-or-later
//! POSIX byte-range advisory locks. Process ownership survives exec, not fork.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordLock {
    pub kind: u16,
    pub start: u64,
    pub end: u64,
    pub owner: u32,
}

impl Vfs {
    pub fn set_lock_owner(&mut self, owner: u32) {
        self.lock_owner = owner;
    }
    pub fn release_process_locks(&self) {
        self.fs.borrow_mut().record_locks.retain(|_, locks| {
            locks.retain(|lock| lock.owner != self.lock_owner);
            !locks.is_empty()
        });
    }
    pub(super) fn release_record_locks(&self, descriptor: &Descriptor) {
        if let Some(node) = &descriptor.open.borrow().node {
            let inode = node.borrow().inode;
            let mut fs = self.fs.borrow_mut();
            if let Some(locks) = fs.record_locks.get_mut(&inode) {
                locks.retain(|lock| lock.owner != self.lock_owner);
                if locks.is_empty() {
                    fs.record_locks.remove(&inode);
                }
            }
        }
    }
    pub fn normalize_lock(
        &self,
        fd: u32,
        kind: u16,
        whence: u16,
        start: i64,
        length: i64,
    ) -> Result<RecordLock> {
        if kind > 2 {
            return Err(Errno(22));
        }
        let d = self.descriptor(fd)?;
        let o = d.open.borrow();
        let n = o.node.as_ref().ok_or(Errno(9))?.borrow();
        let Content::File(data) = &n.content else {
            return Err(Errno(9));
        };
        let base = match whence {
            0 => 0,
            1 => o.position,
            2 => data.len(),
            _ => return Err(Errno(22)),
        };
        let mut low = base as i128 + start as i128;
        let high = if length == 0 {
            u64::MAX
        } else {
            let other = low + length as i128;
            if length < 0 {
                let previous = low;
                low = other;
                previous
            } else {
                other
            }
            .try_into()
            .map_err(|_| Errno(75))?
        };
        if low < 0 {
            return Err(Errno(22));
        }
        if low > i64::MAX as i128 || (high != u64::MAX && high - 1 > i64::MAX as u64) {
            return Err(Errno(75));
        }
        Ok(RecordLock {
            kind,
            start: low as u64,
            end: high,
            owner: self.lock_owner,
        })
    }
    pub fn record_lock_conflict(
        &self,
        fd: u32,
        requested: RecordLock,
    ) -> Result<Option<RecordLock>> {
        let d = self.descriptor(fd)?;
        let o = d.open.borrow();
        let inode = o.node.as_ref().ok_or(Errno(9))?.borrow().inode;
        let fs = self.fs.borrow();
        Ok(fs.record_locks.get(&inode).and_then(|locks| {
            locks
                .iter()
                .filter(|lock| {
                    lock.owner != requested.owner
                        && requested.kind != 2
                        && (requested.kind == 1 || lock.kind == 1)
                        && requested.start < lock.end
                        && lock.start < requested.end
                })
                .min_by_key(|lock| lock.start)
                .copied()
        }))
    }
    pub fn record_lock_set(&self, fd: u32, requested: RecordLock) -> Result<()> {
        let d = self.descriptor(fd)?;
        let o = d.open.borrow();
        if (requested.kind == 0 && o.flags & 3 == 1) || (requested.kind == 1 && o.flags & 3 == 0) {
            return Err(Errno(9));
        }
        let inode = o.node.as_ref().ok_or(Errno(9))?.borrow().inode;
        if self.record_lock_conflict(fd, requested)?.is_some() {
            return Err(Errno(11));
        }
        let mut fs = self.fs.borrow_mut();
        let locks = fs.record_locks.entry(inode).or_default();
        let mut next = Vec::new();
        for &lock in locks.iter() {
            if lock.owner != requested.owner
                || requested.start >= lock.end
                || lock.start >= requested.end
            {
                next.push(lock);
            } else {
                if lock.start < requested.start {
                    next.push(RecordLock {
                        end: requested.start,
                        ..lock
                    });
                }
                if lock.end > requested.end {
                    next.push(RecordLock {
                        start: requested.end,
                        ..lock
                    });
                }
            }
        }
        if requested.kind != 2 {
            next.push(requested);
        }
        next.sort_by_key(|l| (l.owner, l.kind, l.start));
        let mut merged: Vec<RecordLock> = Vec::new();
        for lock in next {
            if let Some(last) = merged
                .last_mut()
                .filter(|l| l.owner == lock.owner && l.kind == lock.kind && l.end >= lock.start)
            {
                last.end = last.end.max(lock.end);
            } else {
                merged.push(lock);
            }
        }
        if merged.len() > 1024 {
            return Err(Errno(37));
        }
        *locks = merged;
        if locks.is_empty() {
            fs.record_locks.remove(&inode);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backward_ranges_readers_and_overflow_are_checked() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/locks", 0x42, 0o600).unwrap();
        v.write(fd, &[0; 24]).unwrap();
        let lock = v.normalize_lock(fd, 0, 2, -4, -8).unwrap();
        assert_eq!((lock.start, lock.end), (12, 20));
        v.record_lock_set(fd, lock).unwrap();
        let mut child = v.clone();
        child.set_lock_owner(2);
        let reader = child.normalize_lock(fd, 0, 0, 12, 8).unwrap();
        assert_eq!(child.record_lock_conflict(fd, reader).unwrap(), None);
        child.record_lock_set(fd, reader).unwrap();
        let writer = child.normalize_lock(fd, 1, 0, 12, 8).unwrap();
        assert_eq!(
            child
                .record_lock_conflict(fd, writer)
                .unwrap()
                .unwrap()
                .owner,
            1
        );
        assert_eq!(child.record_lock_set(fd, writer), Err(Errno(11)));
        assert_eq!(v.normalize_lock(fd, 1, 0, -1, 0), Err(Errno(22)));
        assert_eq!(v.normalize_lock(fd, 1, 0, i64::MAX, 2), Err(Errno(75)));
        child.close(fd).unwrap();
        assert_eq!(v.fs.borrow().record_locks.values().flatten().count(), 1);
        v.close(fd).unwrap();
        assert_eq!(v.fs.borrow().record_locks.values().flatten().count(), 0);
    }
}
