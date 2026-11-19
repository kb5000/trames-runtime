// SPDX-License-Identifier: GPL-3.0-or-later
//! System V attachment lifetime belongs to the address space. Exported CPU
//! views retain byte providers only; they cannot keep a deleted segment alive.
use super::*;
pub trait SegmentAttachment: Send + Sync {
    fn fork(&self, pid: u32) -> Arc<dyn SegmentAttachment>;
    fn detached_by(&self, pid: u32);
    fn page(&self, offset: u64) -> Result<Arc<dyn PageBacking>, MemoryError>;
}

#[derive(Clone)]
pub(super) struct Piece {
    start: u64,
    end: u64,
    offset: u64,
    maximum: Permissions,
    owner: Arc<dyn SegmentAttachment>,
}
impl Piece {
    fn slice(&self, start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            offset: self.offset + (start - self.start),
            ..self.clone()
        }
    }
}
#[derive(Default)]
pub(super) struct Mappings(pub(super) Vec<Piece>);
impl Mappings {
    pub fn remove(&mut self, start: u64, end: u64) {
        if self.0.is_empty() {
            return;
        }
        let mut tail = None;
        self.0.retain_mut(|p| {
            if start >= p.end || end <= p.start {
                return true;
            }
            if start > p.start {
                if end < p.end {
                    tail = Some(p.slice(end, p.end));
                }
                p.end = start;
            } else if end < p.end {
                p.offset += end - p.start;
                p.start = end;
            } else {
                return false;
            }
            true
        });
        self.0.extend(tail);
    }
    pub fn moved(&self, old: u64, len: u64, new: u64, new_len: u64) -> Vec<Piece> {
        let mut result = Vec::new();
        for p in &self.0 {
            let start = p.start.max(old);
            let end = p.end.min(old + len.min(new_len));
            if start >= end {
                continue;
            }
            let mut part = p.slice(start, end);
            part.start = new + (start - old);
            part.end = new + (end - old);
            if end == old + len && new_len > len {
                part.end = new + new_len
            }
            result.push(part);
        }
        result
    }
    pub fn extension(
        &self,
        end: u64,
        pages: u64,
    ) -> Option<Result<Arc<dyn PageBacking>, MemoryError>> {
        let p = self.0.iter().find(|p| p.start < end && p.end >= end)?;
        Some(
            p.owner
                .page(p.offset + (end - p.start) + (pages - 1) * PAGE_SIZE),
        )
    }
    pub fn check_protect(
        &self,
        start: u64,
        end: u64,
        perm: Permissions,
    ) -> Result<(), MemoryError> {
        for p in &self.0 {
            if start < p.end && end > p.start {
                let access = if perm.write && !p.maximum.write {
                    Access::Write
                } else if perm.execute && !p.maximum.execute {
                    Access::Execute
                } else {
                    continue;
                };
                return Err(MemoryError::Permission {
                    address: start.max(p.start),
                    access,
                });
            }
        }
        Ok(())
    }
    pub fn fork(&self, excluded: &vma_policy::Ranges, pid: u32) -> Self {
        if self.0.is_empty() {
            return Self::default();
        }
        let mut copy = Self(self.0.clone());
        for (&a, &b) in &excluded.0 {
            copy.remove(a, b)
        }
        let mut owners: BTreeMap<usize, Arc<dyn SegmentAttachment>> = BTreeMap::new();
        for p in &mut copy.0 {
            let key = Arc::as_ptr(&p.owner) as *const () as usize;
            p.owner = owners
                .entry(key)
                .or_insert_with(|| p.owner.fork(pid))
                .clone();
        }
        copy
    }
}
impl Memory {
    pub fn track_attachment(
        &mut self,
        address: u64,
        length: u64,
        maximum: Permissions,
        owner: Arc<dyn SegmentAttachment>,
    ) {
        if let Some(root) = &self.shared {
            return root
                .borrow_mut()
                .track_attachment(address, length, maximum, owner);
        }
        self.attachments.0.push(Piece {
            start: address,
            end: address + length,
            offset: 0,
            maximum,
            owner,
        });
    }
    pub fn detach_segment(&mut self, address: u64, pid: u32) -> Result<(), MemoryError> {
        if let Some(root) = &self.shared {
            return root.borrow_mut().detach_segment(address, pid);
        }
        let matches = |p: &Piece| p.start.checked_sub(p.offset) == Some(address);
        let first = self
            .attachments
            .0
            .iter()
            .filter(|p| matches(p))
            .min_by_key(|p| p.start)
            .ok_or(MemoryError::InvalidRange)?;
        let owner = first.owner.clone();
        let spans: Vec<_> = self
            .attachments
            .0
            .iter()
            .filter(|p| matches(p) && Arc::ptr_eq(&p.owner, &owner))
            .map(|p| (p.start, p.end))
            .collect();
        for (a, b) in spans {
            self.unmap(a, b - a)?;
        }
        owner.detached_by(pid);
        Ok(())
    }
}
