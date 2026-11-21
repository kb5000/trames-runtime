use std::collections::BTreeMap;

/// Changes of timestamp along the receive sequence, relative to the first byte
/// after enabling the option. Absolute offsets survive ring wrap and reassembly.
#[derive(Debug, Default)]
pub(super) struct Stamps {
    head: u64,
    changes: BTreeMap<u64, Option<u64>>,
}

impl Stamps {
    pub(super) fn record(&mut self, offset: usize, size: usize, ns: u64) {
        let start = self.head + offset as u64;
        let end = start + size as u64;
        let tail = self.at(end);
        while let Some((&key, _)) = self.changes.range(start..end).next() {
            self.changes.remove(&key);
        }
        self.changes.insert(start, Some(ns));
        self.changes.insert(end, tail);
    }

    fn at(&self, position: u64) -> Option<u64> {
        *self.changes.range(..=position).next_back()?.1
    }

    pub(super) fn last(&self, count: usize) -> Option<u64> {
        self.at(self.head + count.checked_sub(1)? as u64)
    }

    pub(super) fn consume(&mut self, size: usize) {
        self.head += size as u64;
        let remaining = self.at(self.head);
        while self.changes.first_key_value().is_some_and(|(key, _)| *key <= self.head) {
            self.changes.pop_first();
        }
        if remaining.is_some() {
            self.changes.insert(self.head, remaining);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reordered_and_overlapping_segments_keep_the_last_read_byte_stamp() {
        let mut stamps = Stamps::default();
        stamps.record(4, 4, 100);
        stamps.record(0, 4, 200);
        stamps.record(2, 4, 300);
        assert_eq!(stamps.last(2), Some(200));
        assert_eq!(stamps.last(5), Some(300));
        assert_eq!(stamps.last(8), Some(100));
        stamps.consume(5);
        assert_eq!(stamps.last(1), Some(300));
        assert_eq!(stamps.last(2), Some(100));
        stamps.consume(3);
        assert!(stamps.changes.is_empty());
        assert_eq!(stamps.last(0), None);
    }
}
