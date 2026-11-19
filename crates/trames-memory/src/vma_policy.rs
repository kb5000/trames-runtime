// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold VMA policy. Ordinary loads, stores and native calls never consult it.
use super::*;
#[cfg(test)]
#[path = "vma_policy_tests.rs"]
mod tests;

#[derive(Clone, Default)]
pub(super) struct Ranges(pub(super) BTreeMap<u64, u64>);
impl Ranges {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn contains(&self, address: u64) -> bool {
        self.0
            .range(..=address)
            .next_back()
            .is_some_and(|(_, end)| address < *end)
    }
    pub fn remove(&mut self, start: u64, end: u64) {
        let overlaps: Vec<_> = self
            .0
            .range(..end)
            .filter(|(_, b)| **b > start)
            .map(|(&a, &b)| (a, b))
            .collect();
        for (a, b) in overlaps {
            self.0.remove(&a);
            if a < start {
                self.0.insert(a, start);
            }
            if end < b {
                self.0.insert(end, b);
            }
        }
    }
    pub fn insert(&mut self, mut start: u64, mut end: u64) {
        if let Some((&a, &b)) = self.0.range(..=start).next_back() {
            if b >= start {
                start = a;
                end = end.max(b);
            }
        }
        let overlaps: Vec<_> = self.0.range(start..=end).map(|(&a, &b)| (a, b)).collect();
        for (a, b) in overlaps {
            self.0.remove(&a);
            end = end.max(b);
        }
        self.0.insert(start, end);
    }
}
#[derive(Clone, Default)]
pub(super) struct Policy {
    pub nofork: Ranges,
    pub wipe: Ranges,
}
impl Policy {
    pub fn remove(&mut self, start: u64, end: u64) {
        self.nofork.remove(start, end);
        self.wipe.remove(start, end);
    }
    pub fn moved(&self, old: u64, old_len: u64, new: u64, new_len: u64) -> Self {
        let mut out = Self::default();
        for (source, target) in [(&self.nofork, &mut out.nofork), (&self.wipe, &mut out.wipe)] {
            for (&a, &b) in source.0.range(..old + old_len) {
                let start = a.max(old);
                let end = b.min(old + old_len.min(new_len));
                if start < end {
                    target.insert(new + start - old, new + end - old);
                }
            }
            if new_len > old_len && source.contains(old + old_len - PAGE_SIZE) {
                target.insert(new + old_len, new + new_len);
            }
        }
        out
    }
    pub fn extend(&mut self, other: Self) {
        for (a, b) in other.nofork.0 {
            self.nofork.insert(a, b);
        }
        for (a, b) in other.wipe.0 {
            self.wipe.insert(a, b);
        }
    }
}
impl Memory {
    pub fn advise_fork(&mut self, address: u64, len: u64, advice: u32) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().advise_fork(address, len, advice);
        }
        let end = Self::mapping_end(address, len)?;
        self.check_mapped_range(address, end)?;
        if advice == 18
            && self
                .pages
                .range(address..end)
                .any(|(_, i)| self.frames[*i].as_ref().unwrap().backing.is_some())
        {
            return Err(MemoryError::InvalidRange);
        }
        match advice {
            10 => self.vma_policy.nofork.insert(address, end),
            11 => self.vma_policy.nofork.remove(address, end),
            18 => self.vma_policy.wipe.insert(address, end),
            19 => self.vma_policy.wipe.remove(address, end),
            _ => return Err(MemoryError::InvalidRange),
        }
        Ok(())
    }
    pub(super) fn apply_fork_policy(&mut self, source: &Policy) -> Result<(), MemoryError> {
        for (&a, &b) in &source.nofork.0 {
            self.unmap(a, b - a)?;
        }
        // DONTFORK takes precedence, so wipe only the surviving mapped pieces.
        let mut wipe = source.wipe.clone();
        for (&a, &b) in &source.nofork.0 {
            wipe.remove(a, b);
        }
        for (a, b) in wipe.0 {
            self.discard(a, b - a)?;
        }
        Ok(())
    }
}
