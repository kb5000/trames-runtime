// SPDX-License-Identifier: GPL-3.0-or-later
//! Scoped host slices over checked guest pages. No guest address is a host pointer.
use super::*;

/// Bytes supplied to native operations directly or through coherent staging.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub direct_read: u64,
    pub direct_write: u64,
    pub buffered_read: u64,
    pub buffered_write: u64,
}

impl Memory {
    /// Borrow one readable page fragment for the duration of a pure callback.
    /// Live backing objects use a bounded snapshot; private COW pages can borrow.
    /// The bool reports whether the supplied slice directly refers to guest bytes.
    pub fn with_read_chunk<T>(
        &self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&[u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        let address = address & 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared.borrow().with_read_chunk(address, len, operation);
        }
        if len == 0 {
            return Ok((operation(&[]), true));
        }
        let offset = (address % PAGE_SIZE) as usize;
        if len > PAGE_SIZE as usize - offset {
            return Err(MemoryError::InvalidRange);
        }
        let page = self.page_for_access(address, len, Access::Read)?;
        if page
            .backing
            .as_ref()
            .is_none_or(|b| !b.shared && b.private_copy)
        {
            return Ok((operation(&page.bytes[offset..offset + len]), true));
        }
        let mut snapshot = [0; PAGE_SIZE as usize];
        page.read_bytes(offset, &mut snapshot[..len])?;
        Ok((operation(&snapshot[..len]), false))
    }

    /// Borrow a checked writable fragment, making a private COW copy as needed.
    /// Shared backings retain their write-through/versioning implementation.
    pub fn with_write_chunk<T>(
        &mut self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&mut [u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        let address = address & 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared
                .borrow_mut()
                .with_write_chunk(address, len, operation);
        }
        if len == 0 {
            return Ok((operation(&mut []), true));
        }
        let offset = (address % PAGE_SIZE) as usize;
        if len > PAGE_SIZE as usize - offset {
            return Err(MemoryError::InvalidRange);
        }
        self.check(address, len, Access::Write)?;
        let frame = self
            .frame(address & !(PAGE_SIZE - 1))
            .expect("checked frame");
        // Materialize MAP_PRIVATE before borrowing it. check_backing above still
        // enforces live EOF/SIGBUS even after a private copy has been made.
        let page = self.frames[frame].as_mut().expect("checked page");
        if let Some(b) = &mut page.backing {
            if !b.shared && !b.private_copy {
                let mut bytes = [0; PAGE_SIZE as usize];
                b.object.read(0, &mut bytes)?;
                page.bytes = Arc::new(bytes);
                b.private_copy = true;
            }
        }
        self.mark_native_write(frame);
        let page = self.frames[frame].as_mut().expect("checked page");
        if page.backing.as_ref().is_some_and(|b| b.shared) {
            let mut bytes = [0; PAGE_SIZE as usize];
            page.read_bytes(offset, &mut bytes[..len])?;
            let result = operation(&mut bytes[..len]);
            page.write_bytes(offset, &bytes[..len])?;
            return Ok((result, false));
        }
        Ok((
            operation(&mut Arc::make_mut(&mut page.bytes)[offset..offset + len]),
            true,
        ))
    }

    fn mark_native_write(&mut self, frame: usize) {
        self.revision = self.revision.wrapping_add(1);
        if self.frames[frame]
            .as_ref()
            .expect("page")
            .permissions
            .execute
        {
            self.advance_code_revision();
            self.frames[frame]
                .as_mut()
                .expect("page")
                .instruction_revision = self.code_revision;
        }
    }

    /// Fill validated guest pages with the supplied native slice operation.
    pub fn fill_with(
        &mut self,
        address: u64,
        len: usize,
        mut fill: impl FnMut(&mut [u8]),
    ) -> Result<Transfer, MemoryError> {
        let address = address & 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().fill_with(address, len, fill);
        }
        self.check(address, len, Access::Write)?;
        let mut stats = Transfer::default();
        let mut offset = 0;
        while offset < len {
            let at = address + offset as u64;
            let count = (len - offset).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
            let (_, direct) = self.with_write_chunk(at, count, &mut fill)?;
            if direct {
                stats.direct_write += count as u64;
            } else {
                stats.buffered_write += count as u64;
            }
            offset += count;
        }
        Ok(stats)
    }

    /// Copy/move checked ranges. Anonymous pages use direct native slices, with
    /// directional iteration and host memmove for within-page overlap. Any live
    /// backing uses a complete source snapshot to preserve non-virtual aliases.
    pub fn copy_with(
        &mut self,
        destination: u64,
        source: u64,
        len: usize,
        mut copy: impl FnMut(&mut [u8], &[u8]),
    ) -> Result<Transfer, MemoryError> {
        let destination = destination & 0x00ffffffffffffff;
        let source = source & 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared
                .borrow_mut()
                .copy_with(destination, source, len, copy);
        }
        self.check(source, len, Access::Read)?;
        self.check(destination, len, Access::Write)?;
        let mut stats = Transfer::default();
        if len == 0 {
            return Ok(stats);
        }
        let backed = [source, destination].into_iter().any(|start| {
            (start & !(PAGE_SIZE - 1)..start + len as u64)
                .step_by(PAGE_SIZE as usize)
                .any(|base| {
                    self.frames[self.pages[&base]]
                        .as_ref()
                        .expect("page")
                        .backing
                        .is_some()
                })
        });
        if backed {
            let mut input = vec![0; len];
            self.read(source, &mut input)?;
            stats.buffered_read = len as u64;
            let mut offset = 0;
            while offset < len {
                let at = destination + offset as u64;
                let count = (len - offset).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
                let (_, direct) = self
                    .with_write_chunk(at, count, |out| copy(out, &input[offset..offset + count]))?;
                if direct {
                    stats.direct_write += count as u64;
                } else {
                    stats.buffered_write += count as u64;
                }
                offset += count;
            }
            return Ok(stats);
        }
        let backwards = destination > source && destination < source + len as u64;
        let mut remaining = len;
        while remaining != 0 {
            let (dst, src, count) = if backwards {
                let de = destination + remaining as u64;
                let se = source + remaining as u64;
                let count = remaining
                    .min(((de - 1) % PAGE_SIZE + 1) as usize)
                    .min(((se - 1) % PAGE_SIZE + 1) as usize);
                (de - count as u64, se - count as u64, count)
            } else {
                let dst = destination + (len - remaining) as u64;
                let src = source + (len - remaining) as u64;
                let count = remaining
                    .min((PAGE_SIZE - dst % PAGE_SIZE) as usize)
                    .min((PAGE_SIZE - src % PAGE_SIZE) as usize);
                (dst, src, count)
            };
            let df = self
                .frame(dst & !(PAGE_SIZE - 1))
                .expect("checked destination");
            let sf = self.frame(src & !(PAGE_SIZE - 1)).expect("checked source");
            self.mark_native_write(df);
            let di = (dst % PAGE_SIZE) as usize;
            let si = (src % PAGE_SIZE) as usize;
            if df == sf {
                let page = self.frames[df].as_mut().expect("page");
                Arc::make_mut(&mut page.bytes).copy_within(si..si + count, di);
            } else {
                let (d, s) = if df < sf {
                    let (left, right) = self.frames.split_at_mut(sf);
                    (
                        left[df].as_mut().expect("destination"),
                        right[0].as_ref().expect("source"),
                    )
                } else {
                    let (left, right) = self.frames.split_at_mut(df);
                    (
                        right[0].as_mut().expect("destination"),
                        left[sf].as_ref().expect("source"),
                    )
                };
                copy(
                    &mut Arc::make_mut(&mut d.bytes)[di..di + count],
                    &s.bytes[si..si + count],
                );
            }
            stats.direct_read += count as u64;
            stats.direct_write += count as u64;
            remaining -= count;
        }
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_borrows_reach_real_pages_and_preserve_cow_shared_vm_and_code_tokens() {
        let mut memory = Memory::default();
        memory
            .map(
                0x1000,
                PAGE_SIZE * 2,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        memory.write(0x1000, b"original").unwrap();
        let pointer = memory.frames[memory.pages[&0x1000]]
            .as_ref()
            .unwrap()
            .bytes
            .as_ptr();
        let (borrowed, direct) = memory
            .with_read_chunk(0x1000, 8, |bytes| bytes.as_ptr())
            .unwrap();
        assert!(direct);
        assert_eq!(pointer, borrowed);
        let parent = memory.clone();
        let before = memory.instruction_page_identity(0x1000).unwrap();
        let other = memory.instruction_page_identity(0x2000).unwrap();
        let transfer = memory.fill_with(0x1000, 8, |bytes| bytes.fill(7)).unwrap();
        assert_eq!(transfer.direct_write, 8);
        assert_eq!(parent.read_array::<8>(0x1000).unwrap(), *b"original");
        assert_ne!(before, memory.instruction_page_identity(0x1000).unwrap());
        assert_eq!(other, memory.instruction_page_identity(0x2000).unwrap());
        let mut thread = memory.share();
        thread.fill_with(0x1000, 8, |bytes| bytes.fill(9)).unwrap();
        assert_eq!(memory.read_array::<8>(0x1000).unwrap(), [9; 8]);
        assert_eq!(
            thread.with_read_chunk(0x1000, 8, |bytes| bytes[0]).unwrap(),
            (9, true)
        );
        let before = memory.instruction_revision();
        assert!(thread.with_write_chunk(0x1fff, 2, |_| ()).is_err());
        assert_eq!(before, memory.instruction_revision());
        thread.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert!(thread.fill_with(0x1000, 8, |bytes| bytes.fill(0)).is_err());
    }

    #[test]
    fn direct_moves_match_a_snapshot_for_overlapping_and_unaligned_page_ranges() {
        let initial: Vec<_> = (0..PAGE_SIZE as usize * 4)
            .map(|i| (i * 73) as u8)
            .collect();
        for src in [0, 1, 4094, 4095, 4096, 4101] {
            for dst in [0, 1, 4094, 4095, 4096, 4101] {
                for len in [0, 1, 7, 129, 4095, 4096, 8191] {
                    let mut memory = Memory::default();
                    memory.map(0x1000, PAGE_SIZE * 4, Permissions::RW).unwrap();
                    memory.write(0x1000, &initial).unwrap();
                    let parent = memory.clone();
                    let mut expected = initial.clone();
                    expected[dst..dst + len].copy_from_slice(&initial[src..src + len]);
                    let stats = memory
                        .copy_with(0x1000 + dst as u64, 0x1000 + src as u64, len, |d, s| {
                            d.copy_from_slice(s)
                        })
                        .unwrap();
                    assert_eq!(stats.direct_read, len as u64);
                    assert_eq!(stats.buffered_read, 0);
                    let mut actual = vec![0; initial.len()];
                    memory.read(0x1000, &mut actual).unwrap();
                    assert_eq!(actual, expected, "src={src} dst={dst} len={len}");
                    parent.read(0x1000, &mut actual).unwrap();
                    assert_eq!(actual, initial);
                }
            }
        }
    }

    #[test]
    fn backing_aliases_snapshot_source_and_private_pages_detach_on_write() {
        let mut memory = Memory::default();
        memory
            .map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        let object = memory.frames[memory.pages[&0x1000]]
            .as_ref()
            .unwrap()
            .backing
            .as_ref()
            .unwrap()
            .object
            .clone();
        memory
            .map_backed(0x3000, vec![object.clone()], true, Permissions::RW, false)
            .unwrap();
        memory
            .map_backed(0x5000, vec![object], false, Permissions::RW, false)
            .unwrap();
        let initial: Vec<_> = (0..4096).map(|i| (i * 73) as u8).collect();
        memory.write(0x1000, &initial).unwrap();
        assert!(
            !memory
                .with_read_chunk(0x3000, 4096, |bytes| assert_eq!(bytes, initial))
                .unwrap()
                .1
        );
        let stats = memory
            .copy_with(0x3001, 0x1000, 4095, |d, s| d.copy_from_slice(s))
            .unwrap();
        assert_eq!(stats.buffered_read, 4095);
        assert_eq!(stats.buffered_write, 4095);
        let mut expected = initial.clone();
        expected[1..].copy_from_slice(&initial[..4095]);
        let mut actual = vec![0; 4096];
        memory.read(0x1000, &mut actual).unwrap();
        assert_eq!(actual, expected);
        let stats = memory
            .fill_with(0x5000, 4096, |bytes| bytes.fill(7))
            .unwrap();
        assert_eq!(stats.direct_write, 4096);
        assert_eq!(
            memory
                .with_read_chunk(0x5000, 4096, |bytes| bytes[4095])
                .unwrap(),
            (7, true)
        );
        memory.read(0x3000, &mut actual).unwrap();
        assert_eq!(actual, expected);
        let before = memory.revision();
        assert!(memory
            .copy_with(0x1000, 0x3fff, 2, |d, s| d.copy_from_slice(s))
            .is_err());
        assert_eq!(memory.revision(), before);
        assert!(memory.fill_with(0x1fff, 2, |bytes| bytes.fill(0)).is_err());
        assert_eq!(memory.read_array::<1>(0x1fff).unwrap(), [expected[4095]]);
    }
}
