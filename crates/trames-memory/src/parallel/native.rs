// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure native access to resident worker pages; no backing objects cross threads.
use super::*;

#[derive(Clone, Copy)]
enum Gate {
    Read,
    Write,
    Output,
    Retryable,
}
impl View {
    #[inline]
    fn native_range(
        &self,
        address: u64,
        len: usize,
        access: Access,
        gate: Gate,
    ) -> Result<bool, NativeAccessError> {
        let address = address & 0x00ffffffffffffff;
        Memory::end(address, len as u64)?;
        if len == 0 {
            return Ok(true);
        }
        let mut defer = false;
        let mut eligible = true;
        for base in (address & !(PAGE_SIZE - 1)..address + len as u64).step_by(PAGE_SIZE as usize) {
            // Validate all permissions/EOF before returning a typed defer, with
            // the exact first fault address, in one mapping traversal.
            let frame = self.frame(base.max(address), access)?;
            if access == Access::Write {
                self.ensure_resident(frame)?;
            }
            defer |= frame.native_live_private.load(Ordering::Relaxed);
            match gate {
                Gate::Write => defer |= !frame.native_one_shot.load(Ordering::Relaxed),
                Gate::Output => eligible &= frame.native_one_shot.load(Ordering::Relaxed),
                Gate::Retryable => eligible &= frame.native_retryable.load(Ordering::Relaxed),
                Gate::Read => {}
            }
        }
        if defer {
            Err(NativeAccessError::Checkpoint)
        } else {
            Ok(eligible)
        }
    }
    fn write_chunk<T>(
        &self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&mut [u8]) -> T,
    ) -> Result<T, MemoryError> {
        let (frame, offset) = self.reached(address, len, Access::Write)?;
        self.ensure_resident(frame)?;
        let mut guard = frame
            .bytes
            .bytes
            .as_ref()
            .expect("writable page")
            .lock(offset, len);
        // Invalidate reservations/code before exposing a mutable slice, including
        // an internal panic. Dirty-fragment commit uses the existing CPU hooks.
        self.changed(frame, &mut guard, offset, len);
        Ok(operation(guard.write(offset, len)))
    }
}

impl NativeMemory for View {
    fn native_writable_range(&self, address: u64, len: usize) -> Result<bool, NativeAccessError> {
        self.native_range(address, len, Access::Read, Gate::Retryable)
    }
    fn native_output_range(&self, address: u64, len: usize) -> Result<bool, NativeAccessError> {
        self.native_range(address, len, Access::Write, Gate::Output)
    }
    #[inline]
    fn native_read(&self, address: u64, out: &mut [u8]) -> Result<(), NativeAccessError> {
        self.read_checked(address, out, |frame| {
            if frame.native_live_private.load(Ordering::Relaxed) {
                Err(NativeAccessError::Checkpoint)
            } else {
                Ok(())
            }
        })
    }
    #[inline]
    fn native_read_array<const N: usize>(
        &self,
        address: u64,
    ) -> Result<[u8; N], NativeAccessError> {
        // Hardware views contain only ordinary anonymous pages, which cannot
        // require native live-backing admission.
        if let Some(bytes) = self.mmu_read::<N>(address) {
            return Ok(bytes);
        }
        let mut bytes = [0; N];
        self.native_read(address, &mut bytes)?;
        Ok(bytes)
    }
    fn with_read_chunk<T>(
        &self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&[u8]) -> T,
    ) -> Result<(T, bool), NativeAccessError> {
        if len == 0 {
            return Ok((operation(&[]), true));
        }
        let address = address & 0x00ffffffffffffff;
        let (frame, offset) = self.reached(address, len, Access::Read)?;
        if frame.native_live_private.load(Ordering::Relaxed) {
            return Err(NativeAccessError::Checkpoint);
        }
        let result = if let Some(bytes) = &frame.bytes.constant {
            operation(&bytes[offset..offset + len])
        } else {
            let guard = frame
                .bytes
                .bytes
                .as_ref()
                .expect("mutable page")
                .lock(offset, len);
            operation(guard.read(offset, len))
        };
        Ok((result, true))
    }
    fn with_read_pair<T>(
        &self,
        left: u64,
        right: u64,
        len: usize,
        operation: impl FnOnce(&[u8], &[u8]) -> T,
    ) -> Result<(T, bool, bool), NativeAccessError> {
        if len == 0 {
            return Ok((operation(&[], &[]), true, true));
        }
        let (a, ai) = self.reached(left & 0x00ffffffffffffff, len, Access::Read)?;
        let (b, bi) = self.reached(right & 0x00ffffffffffffff, len, Access::Read)?;
        if a.native_live_private.load(Ordering::Relaxed)
            || b.native_live_private.load(Ordering::Relaxed)
        {
            return Err(NativeAccessError::Checkpoint);
        }
        let a = &a.bytes;
        let b = &b.bytes;
        let result = match (&a.constant, &b.constant) {
            (Some(a), Some(b)) => operation(&a[ai..ai + len], &b[bi..bi + len]),
            (Some(a), None) => {
                let bg = b.bytes.as_ref().unwrap().lock(bi, len);
                operation(&a[ai..ai + len], bg.read(bi, len))
            }
            (None, Some(b)) => {
                let ag = a.bytes.as_ref().unwrap().lock(ai, len);
                operation(ag.read(ai, len), &b[bi..bi + len])
            }
            (None, None) if Arc::ptr_eq(a, b) => {
                let guard = a.bytes.as_ref().unwrap().lock_pair(ai, bi, len);
                operation(guard.read(ai, len), guard.read(bi, len))
            }
            (None, None) => {
                // Physical identity order applies equally to aliases and opposite
                // direction comparisons; no AB/BA lock inversion is possible.
                let (ag, bg) = if a.identity < b.identity {
                    let ag = a.bytes.as_ref().unwrap().lock(ai, len);
                    let bg = b.bytes.as_ref().unwrap().lock(bi, len);
                    (ag, bg)
                } else {
                    let bg = b.bytes.as_ref().unwrap().lock(bi, len);
                    let ag = a.bytes.as_ref().unwrap().lock(ai, len);
                    (ag, bg)
                };
                operation(ag.read(ai, len), bg.read(bi, len))
            }
        };
        Ok((result, true, true))
    }
    fn fill_with(
        &mut self,
        address: u64,
        len: usize,
        mut fill: impl FnMut(&mut [u8]),
    ) -> Result<Transfer, NativeAccessError> {
        let address = address & 0x00ffffffffffffff;
        self.native_range(address, len, Access::Write, Gate::Write)?;
        let mut offset = 0;
        while offset < len {
            let at = address + offset as u64;
            let count = (len - offset).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
            self.write_chunk(at, count, &mut fill)?;
            offset += count;
        }
        Ok(Transfer {
            direct_write: len as u64,
            ..Transfer::default()
        })
    }
    fn copy_with(
        &mut self,
        destination: u64,
        source: u64,
        len: usize,
        mut copy: impl FnMut(&mut [u8], &[u8]),
    ) -> Result<Transfer, NativeAccessError> {
        let destination = destination & 0x00ffffffffffffff;
        let source = source & 0x00ffffffffffffff;
        self.native_range(source, len, Access::Read, Gate::Read)?;
        self.native_range(destination, len, Access::Write, Gate::Write)?;
        if len == 0 {
            return Ok(Transfer::default());
        }
        // Virtual overlap is directional. A repeated backing identity at another
        // virtual address instead needs a source snapshot, preserving alias moves.
        let mut identities = BTreeMap::new();
        let mut aliased = false;
        if self.snapshot.has_aliases {
            for base in (source & !(PAGE_SIZE - 1)..source + len as u64).step_by(PAGE_SIZE as usize)
            {
                let id = self.frame(base, Access::Read)?.bytes.identity;
                if identities.insert(id, base).is_some() {
                    aliased = true;
                }
            }
            for base in (destination & !(PAGE_SIZE - 1)..destination + len as u64)
                .step_by(PAGE_SIZE as usize)
            {
                let id = self.frame(base, Access::Write)?.bytes.identity;
                if identities.get(&id).is_some_and(|s| *s != base) {
                    aliased = true;
                }
            }
        }
        if aliased {
            let mut input = vec![0; len];
            self.read(source, &mut input)?;
            let mut offset = 0;
            while offset < len {
                let at = destination + offset as u64;
                let count = (len - offset).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
                self.write_chunk(at, count, |out| copy(out, &input[offset..offset + count]))?;
                offset += count;
            }
            return Ok(Transfer {
                buffered_read: len as u64,
                direct_write: len as u64,
                ..Transfer::default()
            });
        }
        let backwards = destination > source && destination < source + len as u64;
        let mut remaining = len;
        while remaining != 0 {
            let (d, s, count) = if backwards {
                let de = destination + remaining as u64;
                let se = source + remaining as u64;
                let count = remaining
                    .min(((de - 1) % PAGE_SIZE + 1) as usize)
                    .min(((se - 1) % PAGE_SIZE + 1) as usize);
                (de - count as u64, se - count as u64, count)
            } else {
                let d = destination + (len - remaining) as u64;
                let s = source + (len - remaining) as u64;
                let count = remaining
                    .min((PAGE_SIZE - d % PAGE_SIZE) as usize)
                    .min((PAGE_SIZE - s % PAGE_SIZE) as usize);
                (d, s, count)
            };
            let (df, di) = self.reached(d, count, Access::Write)?;
            self.ensure_resident(df)?;
            let (sf, si) = self.reached(s, count, Access::Read)?;
            let dst = &df.bytes;
            let src = &sf.bytes;
            if Arc::ptr_eq(dst, src) {
                let mut guard = dst
                    .bytes
                    .as_ref()
                    .expect("writable page")
                    .lock_pair(si, di, count);
                self.changed(df, &mut guard, di, count);
                guard.copy_within(si, di, count);
            } else if let Some(bytes) = &src.constant {
                self.write_chunk(d, count, |out| copy(out, &bytes[si..si + count]))?;
            } else {
                let (mut dg, sg) = if dst.identity < src.identity {
                    let dg = dst.bytes.as_ref().unwrap().lock(di, count);
                    let sg = src.bytes.as_ref().unwrap().lock(si, count);
                    (dg, sg)
                } else {
                    let sg = src.bytes.as_ref().unwrap().lock(si, count);
                    let dg = dst.bytes.as_ref().unwrap().lock(di, count);
                    (dg, sg)
                };
                self.changed(df, &mut dg, di, count);
                copy(dg.write(di, count), sg.read(si, count));
            }
            remaining -= count;
        }
        Ok(Transfer {
            direct_read: len as u64,
            direct_write: len as u64,
            ..Transfer::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn native_and_cpu_scalar_reads_share_permissions_tags_and_cross_page_faults() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        let input: Vec<_> = (0..PAGE_SIZE as usize * 2).map(|i| i as u8).collect();
        memory.write(0x1000, &input).unwrap();
        memory.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
        memory
            .map(
                0x3000,
                PAGE_SIZE,
                Permissions {
                    read: false,
                    write: false,
                    execute: true,
                },
            )
            .unwrap();
        let view = memory.parallel_view(&mut Registry::default()).unwrap();
        fn compare<const N: usize>(view: &View, address: u64) {
            let expected = view
                .read_array::<N>(address)
                .map_err(NativeAccessError::from);
            assert_eq!(view.native_read_array::<N>(address), expected);
            let mut bytes = [0x55; N];
            let result = view.native_read(address, &mut bytes);
            match expected {
                Ok(value) => {
                    assert_eq!(result, Ok(()));
                    assert_eq!(bytes, value);
                }
                Err(error) => {
                    assert_eq!(result, Err(error));
                    assert_eq!(bytes, [0x55; N]);
                }
            }
        }
        for address in [
            0xffc,
            0x1001,
            0x1ff9,
            0x1fff,
            0x2ffc,
            0x3000,
            0x3fff,
            0x4000,
            ADDRESS_LIMIT - 4,
            ADDRESS_LIMIT,
        ] {
            for tagged in [address, address | 0xab00_0000_0000_0000] {
                compare::<1>(&view, tagged);
                compare::<2>(&view, tagged);
                compare::<4>(&view, tagged);
                compare::<8>(&view, tagged);
                compare::<16>(&view, tagged);
            }
        }
    }

    #[test]
    fn independent_atomic_pairs_share_one_page_without_torn_reads() {
        use std::sync::{atomic::AtomicUsize, Arc, Barrier};
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        for rank in 0..4 {
            memory
                .write(0x1000 + rank * 64 + 8, &u64::MAX.to_le_bytes())
                .unwrap();
        }
        let view = memory.parallel_view(&mut Registry::default()).unwrap();
        let barrier = Arc::new(Barrier::new(5));
        let active = Arc::new(AtomicUsize::new(4));
        let mut joins = Vec::new();
        for rank in 0..4 {
            let mut worker = view.clone();
            let barrier = barrier.clone();
            let active = active.clone();
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..2000 {
                    worker
                        .atomic_update(0x1000 + rank * 64, 16, |bytes| {
                            let value = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                            assert_eq!(u64::from_le_bytes(bytes[8..].try_into().unwrap()), !value);
                            let value = value + 1;
                            bytes[..8].copy_from_slice(&value.to_le_bytes());
                            bytes[8..].copy_from_slice(&(!value).to_le_bytes());
                            ((), true)
                        })
                        .unwrap();
                }
                active.fetch_sub(1, Ordering::Release);
            }));
        }
        barrier.wait();
        while active.load(Ordering::Acquire) != 0 {
            for rank in 0..4 {
                let bytes = view.read_array::<16>(0x1000 + rank * 64).unwrap();
                assert_eq!(
                    u64::from_le_bytes(bytes[8..].try_into().unwrap()),
                    !u64::from_le_bytes(bytes[..8].try_into().unwrap())
                );
            }
        }
        for join in joins {
            join.join().unwrap();
        }
        drop(view);
        memory.commit_parallel().unwrap();
        for rank in 0..4 {
            assert_eq!(memory.read_u64(0x1000 + rank * 64).unwrap(), 2000);
        }
    }

    #[test]
    fn a_new_coordinator_registry_rejoins_cached_fork_shared_aliases() {
        let mut memory = Memory::default();
        memory
            .map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        let mut first = Registry::default();
        let mut view = memory.parallel_view(&mut first).unwrap();
        view.fill_with(0x1000, 4096, |b| b.fill(7)).unwrap();
        drop(view);
        memory.commit_parallel().unwrap();
        let mut child = memory.clone();
        let mut next = Registry::default();
        let parent = memory.parallel_view(&mut next).unwrap();
        let mut fork = child.parallel_view(&mut next).unwrap();
        fork.fill_with(0x1000, 4096, |b| b.fill(9)).unwrap();
        assert_eq!(parent.read_array::<8>(0x1000).unwrap(), [9; 8]);
    }

    #[test]
    fn directional_moves_code_tokens_and_fork_cow_match_owned_memory() {
        let mut memory = Memory::default();
        memory
            .map(
                0x1000,
                PAGE_SIZE * 6,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        let initial: Vec<_> = (0..PAGE_SIZE as usize * 6)
            .map(|i| (i * 73) as u8)
            .collect();
        memory.write(0x1000, &initial).unwrap();
        let parent = memory.clone();
        let mut registry = Registry::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        let before = view.instruction_page_identity(0x1000).unwrap();
        let len = PAGE_SIZE as usize * 4 + 11;
        let transfer = view
            .copy_with(0xab00_0000_0000_1001, 0x1000, len, |d, s| {
                d.copy_from_slice(s)
            })
            .unwrap();
        assert_eq!(transfer.direct_read, len as u64);
        assert_eq!(transfer.buffered_read, 0);
        assert_ne!(before, view.instruction_page_identity(0x1000).unwrap());
        let mut expected = initial.clone();
        expected.copy_within(0..len, 1);
        let mut output = vec![0; initial.len()];
        view.read(0x1000, &mut output).unwrap();
        assert_eq!(output, expected);
        view.copy_with(0x1000, 0x1001, len, |d, s| d.copy_from_slice(s))
            .unwrap();
        expected.copy_within(1..len + 1, 0);
        drop(view);
        memory.commit_parallel().unwrap();
        memory.read(0x1000, &mut output).unwrap();
        assert_eq!(output, expected);
        parent.read(0x1000, &mut output).unwrap();
        assert_eq!(output, initial);
    }

    #[test]
    fn backing_alias_moves_snapshot_source_and_pair_reads_lock_once() {
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
        let mut registry = Registry::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(
            view.native_output_range(0x5000, 4096),
            Err(NativeAccessError::Checkpoint)
        );
        assert_eq!(
            view.native_read_array::<8>(0x5000),
            Err(NativeAccessError::Checkpoint)
        );
        assert_eq!(view.read_array::<8>(0x5000).unwrap(), initial[..8]);
        let mut untouched = [0x55; 16];
        assert_eq!(
            view.native_read(0x5ff8, &mut untouched),
            Err(NativeAccessError::Memory(MemoryError::Unmapped(0x6000)))
        );
        assert_eq!(untouched, [0x55; 16]);
        assert_eq!(
            view.native_writable_range(0x5000, 4096),
            Err(NativeAccessError::Checkpoint)
        );
        let transfer = view
            .copy_with(0x3001, 0x1000, 4095, |d, s| d.copy_from_slice(s))
            .unwrap();
        assert_eq!(transfer.buffered_read, 4095);
        assert_eq!(transfer.direct_write, 4095);
        assert_eq!(
            view.with_read_pair(0x1000, 0x3000, 4096, |a, b| a == b)
                .unwrap(),
            (true, true, true)
        );
        let mut expected = initial.clone();
        expected.copy_within(0..4095, 1);
        let mut actual = vec![0; 4096];
        view.read(0x1000, &mut actual).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            view.fill_with(0x5000, 4096, |b| b.fill(17)),
            Err(NativeAccessError::Checkpoint)
        );
        view.write(0x5000, &[17; 4096]).unwrap();
        drop(view);
        memory.commit_parallel().unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert!(view.native_writable_range(0x5000, 4096).unwrap());
        assert_eq!(
            view.with_read_chunk(0x5000, 4096, |b| b.to_vec())
                .unwrap()
                .0,
            vec![17; 4096]
        );
        assert_eq!(
            view.with_read_chunk(0x1000, 4096, |b| b.to_vec())
                .unwrap()
                .0,
            expected
        );
    }

    #[test]
    fn disjoint_native_page_guards_overlap_and_opposite_pair_orders_finish() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let (ready_tx, ready_rx) = mpsc::channel();
        let mut starts = Vec::new();
        let mut joins = Vec::new();
        let views: Vec<_> = (0..2)
            .map(|_| memory.parallel_view(&mut registry).unwrap())
            .collect();
        for (rank, mut view) in views.into_iter().enumerate() {
            let ready = ready_tx.clone();
            let (start_tx, start_rx) = mpsc::channel();
            starts.push(start_tx);
            joins.push(std::thread::spawn(move || {
                view.fill_with(0x1000 + rank as u64 * PAGE_SIZE, 4096, |b| {
                    ready.send(rank).unwrap();
                    start_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    b.fill(73 + rank as u8);
                })
                .unwrap();
            }));
        }
        // Both messages are sent with their write guard held. A global lock
        // would prevent the second message; timeout bounds a locking regression.
        let a = ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let b = ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_ne!(a, b);
        for start in starts {
            start.send(()).unwrap();
        }
        for join in joins {
            join.join().unwrap();
        }
        memory.commit_parallel().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let mut joins = Vec::new();
        let views: Vec<_> = (0..2)
            .map(|_| memory.parallel_view(&mut registry).unwrap())
            .collect();
        for (rank, view) in views.into_iter().enumerate() {
            let done = done_tx.clone();
            joins.push(std::thread::spawn(move || {
                for _ in 0..512 {
                    let (a, b, expected) = if rank == 0 {
                        (0x1000, 0x2000, -1)
                    } else {
                        (0x2000, 0x1000, 1)
                    };
                    assert_eq!(
                        view.with_read_pair(a, b, 4096, |l, r| i32::from(l[0]) - i32::from(r[0]))
                            .unwrap()
                            .0,
                        expected
                    );
                }
                done.send(()).unwrap();
            }));
        }
        for _ in 0..2 {
            done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        for join in joins {
            join.join().unwrap();
        }
    }

    #[test]
    fn full_page_reservation_epochs_preserve_partial_granules_and_wrap() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut view = memory.parallel_view(&mut Registry::default()).unwrap();
        let mut bytes = [0; 8];
        let old = view.exclusive_read(0x1000, &mut bytes).unwrap();
        view.fill_with(0x1000, 4096, |b| b.fill(7)).unwrap();
        assert!(!view.exclusive_write(0x1000, &[9; 8], Some(old)).unwrap());
        for offset in [16, 32, 48] {
            let token = view.exclusive_read(0x1000 + offset, &mut bytes).unwrap();
            view.fill_with(0x1000, 8, |b| b.fill(6)).unwrap();
            assert!(view
                .exclusive_write(0x1000 + offset, &[5; 8], Some(token))
                .unwrap());
        }
        let first = view.exclusive_read(0x1000, &mut bytes).unwrap();
        view.fill_with(0x1100, 8, |b| b.fill(8)).unwrap();
        assert!(view.exclusive_write(0x1000, &[9; 8], Some(first)).unwrap());
        {
            let frame = view.frame(0x1000, Access::Write).unwrap();
            let _guard = frame.bytes.bytes.as_ref().unwrap().lock(0, 4096);
            frame.bytes.version.store(u64::MAX - 1, Ordering::Relaxed);
        }
        view.fill_with(0x1000, 4096, |b| b.fill(1)).unwrap();
        let old = view.exclusive_read(0x1000, &mut bytes).unwrap();
        let other = view.exclusive_read(0x1100, &mut bytes).unwrap();
        view.fill_with(0x1000, 8, |b| b.fill(2)).unwrap();
        assert!(!view.exclusive_write(0x1000, &[9; 8], Some(old)).unwrap());
        assert!(view.exclusive_write(0x1100, &[9; 8], Some(other)).unwrap());
    }
}
