// SPDX-License-Identifier: GPL-3.0-or-later
//! Free numeric intervals, under the existing files_struct membership lock.
use std::collections::BTreeMap;

#[derive(Clone)]
pub(super) struct FreeFds {
    limit: u32,
    ranges: BTreeMap<u32, u32>,
}
impl Default for FreeFds {
    fn default() -> Self {
        Self::new(super::MAX_FDS)
    }
}
impl FreeFds {
    pub fn new(limit: u32) -> Self {
        let mut ranges = BTreeMap::new();
        if limit != 0 {
            ranges.insert(0, limit);
        }
        Self { limit, ranges }
    }
    pub fn next(&self, min: u32) -> Option<u32> {
        if self
            .ranges
            .range(..=min)
            .next_back()
            .is_some_and(|(_, &end)| min < end)
        {
            return Some(min);
        }
        self.ranges.range(min..).next().map(|(&start, _)| start)
    }
    pub fn first(&self, count: usize) -> Vec<u32> {
        self.ranges
            .iter()
            .flat_map(|(&start, &end)| start..end)
            .take(count)
            .collect()
    }
    pub fn reserve(&mut self, fd: u32) {
        let Some((start, end)) = self.ranges.range(..=fd).next_back().map(|(&a, &b)| (a, b)) else {
            return;
        };
        if fd >= end {
            return;
        }
        self.ranges.remove(&start);
        if start < fd {
            self.ranges.insert(start, fd);
        }
        if fd + 1 < end {
            self.ranges.insert(fd + 1, end);
        }
    }
    pub fn release(&mut self, fd: u32) {
        // Internal retained-OFD aliases can lie outside the guest number space.
        if fd >= self.limit {
            return;
        }
        let (mut start, mut end) = (fd, fd + 1);
        if let Some((left, stop)) = self.ranges.range(..fd).next_back().map(|(&a, &b)| (a, b)) {
            if stop == fd {
                start = left;
                self.ranges.remove(&left);
            }
        }
        if let Some(&stop) = self.ranges.get(&end) {
            self.ranges.remove(&end);
            end = stop;
        }
        self.ranges.insert(start, end);
    }
    pub fn clear(&mut self) {
        self.ranges.clear();
        if self.limit != 0 {
            self.ranges.insert(0, self.limit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_merge_replacement_and_minimum_follow_numeric_membership() {
        let mut free = FreeFds::new(32);
        let mut occupied = [false; 32];
        let mut random = 7u64;
        for _ in 0..1000 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let fd = (random >> 32) as usize % 32;
            if occupied[fd] {
                free.release(fd as u32);
            } else {
                free.reserve(fd as u32);
                free.reserve(fd as u32);
            }
            occupied[fd] = !occupied[fd];
            for min in 0..=32 {
                assert_eq!(
                    free.next(min as u32),
                    (min..32).find(|&n| !occupied[n]).map(|n| n as u32)
                );
            }
            assert_eq!(
                free.first(5),
                (0..32)
                    .filter(|&n| !occupied[n])
                    .take(5)
                    .map(|n| n as u32)
                    .collect::<Vec<_>>()
            );
        }
        let snapshot = free.clone();
        free.clear();
        assert_eq!(free.first(100), (0..32).collect::<Vec<_>>());
        assert_eq!(
            snapshot.first(32),
            (0..32)
                .filter(|&n| !occupied[n])
                .map(|n| n as u32)
                .collect::<Vec<_>>()
        );
    }
    #[test]
    fn large_ceiling_uses_intervals_and_internal_aliases_do_not_expand_it() {
        let mut free = FreeFds::default();
        let last = super::super::MAX_FDS - 1;
        assert_eq!(free.ranges.len(), 1);
        assert_eq!(free.first(2), [0, 1]);
        free.reserve(last);
        assert_eq!(free.next(last), None);
        free.release(last);
        assert_eq!(free.next(last), Some(last));
        free.release(last + 1);
        assert_eq!(free.next(last + 1), None);
        assert_eq!(free.ranges.len(), 1);
    }
}
