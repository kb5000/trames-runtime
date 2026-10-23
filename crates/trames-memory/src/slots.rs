// SPDX-License-Identifier: GPL-3.0-or-later
//! Indexed metadata in small allocations, independent of host VA contiguity.
use std::ops::{Index, IndexMut};

const CHUNK: usize = 256;

#[derive(Clone)]
pub(super) struct Slots<T> {
    chunks: Vec<Vec<T>>,
    len: usize,
}

impl<T> Slots<T> {
    pub(super) fn new() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }
    pub(super) fn len(&self) -> usize {
        self.len
    }
    pub(super) fn push(&mut self, value: T) {
        if self.len.is_multiple_of(CHUNK) {
            self.chunks.push(Vec::with_capacity(CHUNK));
        }
        self.chunks.last_mut().unwrap().push(value);
        self.len += 1;
    }
    pub(super) fn pop(&mut self) -> Option<T> {
        let chunk = self.chunks.last_mut()?;
        let value = chunk.pop();
        self.len -= 1;
        if chunk.is_empty() {
            self.chunks.pop();
        }
        value
    }
    pub(super) fn swap_remove(&mut self, index: usize) -> T {
        assert!(index < self.len);
        let last = self.pop().unwrap();
        if index == self.len {
            last
        } else {
            std::mem::replace(&mut self[index], last)
        }
    }
    pub(super) fn get(&self, index: usize) -> Option<&T> {
        self.chunks.get(index / CHUNK)?.get(index % CHUNK)
    }
    pub(super) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.chunks.get_mut(index / CHUNK)?.get_mut(index % CHUNK)
    }
    /// # Safety
    /// `index` must be below len, as established by the caller's live TLB.
    #[inline]
    pub(super) unsafe fn get_unchecked(&self, index: usize) -> &T {
        unsafe {
            self.chunks
                .get_unchecked(index / CHUNK)
                .get_unchecked(index % CHUNK)
        }
    }
    /// # Safety
    /// Same index contract as get_unchecked, with exclusive metadata ownership.
    #[inline]
    pub(super) unsafe fn get_unchecked_mut(&mut self, index: usize) -> &mut T {
        unsafe {
            self.chunks
                .get_unchecked_mut(index / CHUNK)
                .get_unchecked_mut(index % CHUNK)
        }
    }
    pub(super) fn pair_mut(&mut self, first: usize, second: usize) -> (&mut T, &mut T) {
        let a = first / CHUNK;
        let b = second / CHUNK;
        if a == b {
            let [first, second] = self.chunks[a]
                .get_disjoint_mut([first % CHUNK, second % CHUNK])
                .unwrap();
            (first, second)
        } else {
            let [left, right] = self.chunks.get_disjoint_mut([a, b]).unwrap();
            (&mut left[first % CHUNK], &mut right[second % CHUNK])
        }
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
        self.chunks.iter().flatten()
    }
    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.chunks.iter_mut().flatten()
    }
}

impl<T: Clone> Slots<T> {
    pub(super) fn resize(&mut self, len: usize, value: T) {
        while self.len > len {
            self.pop();
        }
        while self.len < len {
            self.push(value.clone());
        }
    }
}
impl<T> Index<usize> for Slots<T> {
    type Output = T;
    #[inline]
    fn index(&self, index: usize) -> &T {
        self.get(index).expect("slot index")
    }
}
impl<T> IndexMut<usize> for Slots<T> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut T {
        self.get_mut(index).expect("slot index")
    }
}
impl<T> FromIterator<T> for Slots<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut slots = Self::new();
        for value in iter {
            slots.push(value);
        }
        slots
    }
}
impl<T> IntoIterator for Slots<T> {
    type Item = T;
    type IntoIter = std::iter::Flatten<std::vec::IntoIter<Vec<T>>>;
    fn into_iter(self) -> Self::IntoIter {
        self.chunks.into_iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_keeps_existing_slots_in_place_and_pairs_cross_chunks() {
        let mut slots: Slots<_> = (0..CHUNK).collect();
        let first = &slots[0] as *const usize;
        for value in CHUNK..CHUNK * 3 {
            slots.push(value);
        }
        assert_eq!(first, &slots[0] as *const usize);
        for (a, b) in [(0, 1), (CHUNK - 1, CHUNK), (CHUNK * 2, 0)] {
            let (left, right) = slots.pair_mut(a, b);
            std::mem::swap(left, right);
            assert_eq!(slots[a], b);
            assert_eq!(slots[b], a);
            let (left, right) = slots.pair_mut(a, b);
            std::mem::swap(left, right);
        }
        let mut clone = slots.clone();
        assert_eq!(clone.swap_remove(CHUNK - 1), CHUNK - 1);
        assert_eq!(clone[CHUNK - 1], CHUNK * 3 - 1);
        assert_eq!(clone.swap_remove(CHUNK * 3 - 2), CHUNK * 3 - 2);
        clone.resize(1, 0);
        clone.resize(CHUNK + 1, 7);
        assert_eq!(clone[CHUNK], 7);
        assert_eq!(slots.iter().copied().sum::<usize>(), (0..CHUNK * 3).sum());
    }
}
