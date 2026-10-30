// SPDX-License-Identifier: GPL-3.0-or-later
//! NativeCall v1 catalog: bounded guest-memory operations and versioned musl
//! adapters. Matching guest code never grants host pointers or kernel authority.
use serde::Serialize;
use std::time::Instant;
#[cfg(test)]
use trames_memory::Memory;
use trames_memory::{MemoryError, NativeAccessError, NativeMemory, Transfer, PAGE_SIZE};
pub const AUXV_KEY: u64 = 0x5452_0001;
/// Optional function bitmap: bit (id - 1). Absent on old hosts.
pub const FEATURES_AUXV_KEY: u64 = 0x5452_0002;
pub const FUNCTION_COUNT: usize = 19;
pub const FEATURES: u64 = (1 << FUNCTION_COUNT) - 1;
pub const PROFILE: u64 = 0x0001_0001; // protocol 1, pure module 1
pub const INSTRUCTION: u32 = 0xd44a8a40; // HLT #0x5452, opt-in virtual encoding
pub const VULKAN_PROFILE: u64 = 0x0001_0006;
pub const VIDEO_PROFILE: u64 = 0x0001_0007;
pub const MAX_BYTES: usize = 64 * 1024;
/// Bulk operations remain bounded inside a joined NativeCall checkpoint.
/// Larger operations fall back before any effects; no partial replay.
pub const MAX_BULK_BYTES: usize = 1024 * 1024;
pub const MAX_STRING_BYTES: usize = 1024 * 1024;
#[derive(Default, Debug, Serialize)]
pub struct Metrics {
    pub calls: u64,
    pub worker_calls: u64,
    pub checkpoint_retries: u64,
    pub function_calls: [u64; FUNCTION_COUNT],
    pub function_fallbacks: [u64; FUNCTION_COUNT],
    pub integer_calls: u64,
    pub integer_conversions: u64,
    pub allocator_calls: u64,
    pub allocator_load_callbacks: u64,
    pub allocator_page_callbacks: u64,
    pub allocator_direct_loads: u64,
    pub allocator_journal_writes: u64,
    pub allocator_allocations: u64,
    pub allocator_slot_reservations: u64,
    pub allocator_frees: u64,
    pub allocator_free_resumes: u64,
    pub callback_calls: u64,
    pub callback_requests: u64,
    pub callback_yields: u64,
    pub callback_sorts: u64,
    pub callback_searches: u64,
    pub callback_state_bytes: u64,
    pub numeric_calls: u64,
    pub numeric_conversions: u64,
    pub numeric_replays: u64,
    pub numeric_input_bytes: u64,
    pub numeric_result_bytes: u64,
    pub fallbacks: u64,
    pub rejected: u64,
    pub validation_hits: u64,
    pub validation_misses: u64,
    pub faults: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub direct_bytes_read: u64,
    pub direct_bytes_written: u64,
    pub buffered_bytes_read: u64,
    pub buffered_bytes_written: u64,
    pub nanoseconds: u64,
}
impl Metrics {
    /// Worker-local counters join here after every view user has stopped.
    pub fn merge(&mut self, other: Self) {
        self.allocator_calls = self.allocator_calls.saturating_add(other.allocator_calls);
        self.allocator_load_callbacks = self
            .allocator_load_callbacks
            .saturating_add(other.allocator_load_callbacks);
        self.allocator_page_callbacks = self
            .allocator_page_callbacks
            .saturating_add(other.allocator_page_callbacks);
        self.allocator_direct_loads = self
            .allocator_direct_loads
            .saturating_add(other.allocator_direct_loads);
        self.allocator_journal_writes = self
            .allocator_journal_writes
            .saturating_add(other.allocator_journal_writes);
        self.allocator_allocations = self
            .allocator_allocations
            .saturating_add(other.allocator_allocations);
        self.allocator_slot_reservations = self
            .allocator_slot_reservations
            .saturating_add(other.allocator_slot_reservations);
        self.allocator_frees = self.allocator_frees.saturating_add(other.allocator_frees);
        self.allocator_free_resumes = self
            .allocator_free_resumes
            .saturating_add(other.allocator_free_resumes);
        self.calls = self.calls.saturating_add(other.calls);
        self.worker_calls = self.worker_calls.saturating_add(other.worker_calls);
        self.checkpoint_retries = self
            .checkpoint_retries
            .saturating_add(other.checkpoint_retries);
        self.integer_calls = self.integer_calls.saturating_add(other.integer_calls);
        self.integer_conversions = self
            .integer_conversions
            .saturating_add(other.integer_conversions);
        self.callback_calls = self.callback_calls.saturating_add(other.callback_calls);
        self.callback_requests = self
            .callback_requests
            .saturating_add(other.callback_requests);
        self.callback_yields = self.callback_yields.saturating_add(other.callback_yields);
        self.callback_sorts = self.callback_sorts.saturating_add(other.callback_sorts);
        self.callback_searches = self
            .callback_searches
            .saturating_add(other.callback_searches);
        self.callback_state_bytes = self
            .callback_state_bytes
            .saturating_add(other.callback_state_bytes);
        self.numeric_calls = self.numeric_calls.saturating_add(other.numeric_calls);
        self.numeric_conversions = self
            .numeric_conversions
            .saturating_add(other.numeric_conversions);
        self.numeric_replays = self.numeric_replays.saturating_add(other.numeric_replays);
        self.numeric_input_bytes = self
            .numeric_input_bytes
            .saturating_add(other.numeric_input_bytes);
        self.numeric_result_bytes = self
            .numeric_result_bytes
            .saturating_add(other.numeric_result_bytes);
        self.fallbacks = self.fallbacks.saturating_add(other.fallbacks);
        self.rejected = self.rejected.saturating_add(other.rejected);
        self.validation_hits = self.validation_hits.saturating_add(other.validation_hits);
        self.validation_misses = self
            .validation_misses
            .saturating_add(other.validation_misses);
        self.faults = self.faults.saturating_add(other.faults);
        self.bytes_read = self.bytes_read.saturating_add(other.bytes_read);
        self.bytes_written = self.bytes_written.saturating_add(other.bytes_written);
        self.direct_bytes_read = self
            .direct_bytes_read
            .saturating_add(other.direct_bytes_read);
        self.direct_bytes_written = self
            .direct_bytes_written
            .saturating_add(other.direct_bytes_written);
        self.buffered_bytes_read = self
            .buffered_bytes_read
            .saturating_add(other.buffered_bytes_read);
        self.buffered_bytes_written = self
            .buffered_bytes_written
            .saturating_add(other.buffered_bytes_written);
        self.nanoseconds = self.nanoseconds.saturating_add(other.nanoseconds);
        for (a, b) in self.function_calls.iter_mut().zip(other.function_calls) {
            *a = a.saturating_add(b);
        }
        for (a, b) in self
            .function_fallbacks
            .iter_mut()
            .zip(other.function_fallbacks)
        {
            *a = a.saturating_add(b);
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidEntry,
    /// No body effects: revalidate at a joined checkpoint or perform backing I/O.
    Checkpoint,
    Memory(MemoryError),
}
impl From<NativeAccessError> for Error {
    fn from(error: NativeAccessError) -> Self {
        match error {
            NativeAccessError::Memory(error) => Self::Memory(error),
            NativeAccessError::Checkpoint => Self::Checkpoint,
        }
    }
}
impl From<MemoryError> for Error {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Return {
    pub value: u64,
    pub fallback: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CheckedStub {
    pc: u64,
    module: u64,
    function: u64,
    first: (u64, u64, u64),
    last: (u64, u64, u64),
}
const VALIDATION_SLOTS: usize = 64;
#[derive(Debug)]
pub struct Registry {
    pub metrics: Metrics,
    checked: [Option<CheckedStub>; VALIDATION_SLOTS],
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            metrics: Metrics::default(),
            checked: [None; VALIDATION_SLOTS],
        }
    }
}
impl Registry {
    /// Recheck executable page permissions, identity, code revision and live
    /// backing version on every entry. Only identical page tokens can reuse the
    /// exact five-word check; no host pointers or borrows are cached.
    fn valid(
        &mut self,
        memory: &impl NativeMemory,
        pc: u64,
        module: u64,
        function: u64,
    ) -> Result<bool, Error> {
        let allowed = (module == PROFILE && (1..=FUNCTION_COUNT as u64).contains(&function))
            || (module == crate::callbacks::PROFILE && function == 1)
            || (module == crate::numeric::PROFILE && function == 1)
            || (module == crate::integer::PROFILE && function == 1)
            || (module == crate::allocator::PROFILE && (1..=3).contains(&function))
            || (matches!(module, VULKAN_PROFILE | VIDEO_PROFILE) && function == 1);
        if !allowed || pc < 12 {
            return Ok(false);
        }
        let start = pc - 12;
        let Some(end) = pc.checked_add(4) else {
            return Ok(false);
        };
        let Ok(first) = memory.instruction_page_identity(start) else {
            return Ok(false);
        };
        let last = if start / PAGE_SIZE == end / PAGE_SIZE {
            first
        } else {
            let Ok(last) = memory.instruction_page_identity(end) else {
                return Ok(false);
            };
            last
        };
        let key = CheckedStub {
            pc,
            module,
            function,
            first,
            last,
        };
        let slot = ((pc / 4) as usize) & (VALIDATION_SLOTS - 1);
        if self.checked[slot] == Some(key) {
            self.metrics.validation_hits = self.metrics.validation_hits.saturating_add(1);
            return Ok(true);
        }
        self.metrics.validation_misses = self.metrics.validation_misses.saturating_add(1);
        let words = [
            0xd2800010 | ((module as u32 & 0xffff) << 5),
            0xf2a00030,
            0xd2800011 | (function as u32) << 5,
            INSTRUCTION,
            0xd65f03c0,
        ];
        let valid = words
            .into_iter()
            .enumerate()
            .all(|(i, word)| memory.fetch_u32(start + i as u64 * 4) == Ok(word));
        // Read-through backing versions may change during a fetch. Store only
        // a coherent observation; the next entry still checks the live tokens.
        if memory.instruction_page_identity(start) != Ok(first)
            || (start / PAGE_SIZE != end / PAGE_SIZE
                && memory.instruction_page_identity(end) != Ok(last))
        {
            return Err(Error::Checkpoint);
        }
        if valid {
            self.checked[slot] = Some(key);
        }
        Ok(valid)
    }
    /// Authorize stateful transport against the calling CPU's memory. The GPU
    /// context owns resource synchronization; this grants no resource access.
    pub fn authorize_stateful(
        &mut self,
        memory: &impl NativeMemory,
        pc: u64,
        module: u64,
        function: u64,
    ) -> Result<(), Error> {
        if !matches!(module, VULKAN_PROFILE | VIDEO_PROFILE)
            || function != 1
            || !self.valid(memory, pc, module, function)?
        {
            self.metrics.rejected = self.metrics.rejected.saturating_add(1);
            return Err(Error::InvalidEntry);
        }
        self.metrics.calls = self.metrics.calls.saturating_add(1);
        Ok(())
    }
    pub fn invoke(
        &mut self,
        memory: &mut impl NativeMemory,
        pc: u64,
        module: u64,
        function: u64,
        a: [u64; 3],
    ) -> Result<Return, Error> {
        if matches!(module, VULKAN_PROFILE | VIDEO_PROFILE) {
            return Err(Error::Checkpoint);
        }
        self.invoke_scoped(memory, pc, module, function, a, || ())
    }
    /// Enter a worker-local tracking scope only after authorization. The scope
    /// may hold timing/counter guards, never guest memory or kernel authority.
    pub fn invoke_scoped<T>(
        &mut self,
        memory: &mut impl NativeMemory,
        pc: u64,
        module: u64,
        function: u64,
        a: [u64; 3],
        scope: impl FnOnce() -> T,
    ) -> Result<Return, Error> {
        if matches!(module, VULKAN_PROFILE | VIDEO_PROFILE) {
            self.metrics.checkpoint_retries = self.metrics.checkpoint_retries.saturating_add(1);
            return Err(Error::Checkpoint);
        }
        // Reuse the interpreter's slice-scoped shared-address-space borrow.
        // Live/reentrant backings keep cpu_slice's original conservative path.
        // Neither this borrow nor the tracking scope survives a guest callback
        // or a scheduler/mapping checkpoint.
        let mut slice = memory.cpu_slice();
        let memory = &mut *slice;
        let valid = match self.valid(memory, pc, module, function) {
            Ok(valid) => valid,
            Err(error) => {
                self.metrics.checkpoint_retries = self.metrics.checkpoint_retries.saturating_add(1);
                return Err(error);
            }
        };
        if !valid {
            self.metrics.rejected = self.metrics.rejected.saturating_add(1);
            return Err(Error::InvalidEntry);
        }
        self.metrics.calls = self.metrics.calls.saturating_add(1);
        let _scope = scope();
        let began = Instant::now();
        let result = if module == crate::callbacks::PROFILE {
            self.metrics.callback_calls = self.metrics.callback_calls.saturating_add(1);
            crate::callbacks::step(memory, a, &mut self.metrics)
        } else if module == crate::allocator::PROFILE {
            self.metrics.allocator_calls = self.metrics.allocator_calls.saturating_add(1);
            crate::allocator::step(memory, function, a, &mut self.metrics)
        } else if module == crate::integer::PROFILE {
            self.metrics.integer_calls = self.metrics.integer_calls.saturating_add(1);
            crate::integer::parse(memory, a, &mut self.metrics)
        } else if module == crate::numeric::PROFILE {
            self.metrics.numeric_calls = self.metrics.numeric_calls.saturating_add(1);
            crate::numeric::parse(memory, a, &mut self.metrics)
        } else {
            let count = &mut self.metrics.function_calls[function as usize - 1];
            *count = count.saturating_add(1);
            self.execute(memory, function, a)
        };
        self.metrics.nanoseconds = self
            .metrics
            .nanoseconds
            .saturating_add(began.elapsed().as_nanos().min(u64::MAX as u128) as u64);
        match &result {
            Ok(Return { fallback: true, .. }) => {
                self.metrics.fallbacks = self.metrics.fallbacks.saturating_add(1);
                if module == PROFILE {
                    let counter = &mut self.metrics.function_fallbacks[function as usize - 1];
                    *counter = counter.saturating_add(1);
                }
            }
            Err(Error::Checkpoint) => {
                self.metrics.checkpoint_retries = self.metrics.checkpoint_retries.saturating_add(1)
            }
            Err(_) => self.metrics.faults = self.metrics.faults.saturating_add(1),
            _ => {}
        }
        result
    }
    pub(crate) fn record_transfer(&mut self, transfer: Transfer) {
        self.metrics.bytes_read = self
            .metrics
            .bytes_read
            .saturating_add(transfer.direct_read + transfer.buffered_read);
        self.metrics.bytes_written = self
            .metrics
            .bytes_written
            .saturating_add(transfer.direct_write + transfer.buffered_write);
        self.metrics.direct_bytes_read = self
            .metrics
            .direct_bytes_read
            .saturating_add(transfer.direct_read);
        self.metrics.direct_bytes_written = self
            .metrics
            .direct_bytes_written
            .saturating_add(transfer.direct_write);
        self.metrics.buffered_bytes_read = self
            .metrics
            .buffered_bytes_read
            .saturating_add(transfer.buffered_read);
        self.metrics.buffered_bytes_written = self
            .metrics
            .buffered_bytes_written
            .saturating_add(transfer.buffered_write);
    }
    pub(crate) fn record_read(&mut self, count: usize, direct: bool) {
        self.record_transfer(Transfer {
            direct_read: if direct { count as u64 } else { 0 },
            buffered_read: if direct { 0 } else { count as u64 },
            ..Transfer::default()
        });
    }
    fn execute(
        &mut self,
        memory: &mut impl NativeMemory,
        function: u64,
        a: [u64; 3],
    ) -> Result<Return, Error> {
        let (dst, src, length) = (a[0], a[1], a[2]);
        let fallback = || {
            Ok(Return {
                value: dst,
                fallback: true,
            })
        };
        let done = |value| {
            Ok(Return {
                value,
                fallback: false,
            })
        };
        let ceiling = if matches!(function, 1..=4 | 6 | 7) {
            MAX_BULK_BYTES
        } else {
            MAX_STRING_BYTES
        };
        if matches!(function, 1..=3 | 7) && length > ceiling as u64 {
            return fallback();
        }
        let len = length.min(ceiling as u64) as usize;
        match function {
            1 | 2 => {
                if len == 0 || (function == 2 && dst == src) {
                    return done(dst);
                }
                let transfer = memory.copy_with(dst, src, len, trames_native::copy)?;
                self.record_transfer(transfer);
                done(dst)
            }
            3 => {
                let transfer =
                    memory.fill_with(dst, len, |bytes| trames_native::fill(bytes, src as u8))?;
                self.record_transfer(transfer);
                done(dst)
            }
            4 | 9 | 10 => {
                // Compare only reached page fragments; mismatch/NUL ends the scan.
                let limit = if function == 9 { MAX_STRING_BYTES } else { len };
                let mut offset = 0;
                while offset < limit {
                    let la = (dst & 0x00ffffffffffffff) + offset as u64;
                    let ra = (src & 0x00ffffffffffffff) + offset as u64;
                    let count = (limit - offset)
                        .min((PAGE_SIZE - la % PAGE_SIZE) as usize)
                        .min((PAGE_SIZE - ra % PAGE_SIZE) as usize);
                    let (value, ld, rd) = memory.with_read_pair(la, ra, count, |left, right| {
                        if function == 4 {
                            let value = trames_native::compare(left, right);
                            (value != 0).then_some(value)
                        } else {
                            trames_native::compare_strings(left, right)
                        }
                    })?;
                    self.record_read(count, ld);
                    self.record_read(count, rd);
                    if let Some(value) = value {
                        return done(value as u32 as u64);
                    }
                    offset += count;
                }
                if function == 9 || length > ceiling as u64 {
                    fallback()
                } else {
                    done(0)
                }
            }
            5 | 8 => {
                // strnlen may stop before a huge bound. Only a scan exhausted at
                // the native limit requests the untouched original implementation.
                let limit = if function == 8 {
                    src.min(MAX_STRING_BYTES as u64) as usize
                } else {
                    MAX_STRING_BYTES
                };
                let mut offset = 0;
                while offset < limit {
                    let address = (dst & 0x00ffffffffffffff) + offset as u64;
                    let count = (limit - offset).min((PAGE_SIZE - address % PAGE_SIZE) as usize);
                    let (index, direct) =
                        memory.with_read_chunk(address, count, trames_native::first_zero)?;
                    self.record_read(count, direct);
                    if let Some(index) = index {
                        return done((offset + index) as u64);
                    }
                    offset += count;
                }
                if function == 8 && src <= MAX_STRING_BYTES as u64 {
                    done(src)
                } else {
                    fallback()
                }
            }
            6 | 7 => {
                let mut remaining = len;
                while remaining != 0 {
                    let (offset, count) = if function == 7 {
                        let end = (dst & 0x00ffffffffffffff) + remaining as u64;
                        let count = remaining.min(((end - 1) % PAGE_SIZE + 1) as usize);
                        (remaining - count, count)
                    } else {
                        let offset = len - remaining;
                        let at = (dst & 0x00ffffffffffffff) + offset as u64;
                        (offset, remaining.min((PAGE_SIZE - at % PAGE_SIZE) as usize))
                    };
                    let (index, direct) = memory.with_read_chunk(
                        (dst & 0x00ffffffffffffff) + offset as u64,
                        count,
                        |bytes| {
                            if function == 6 {
                                trames_native::first_byte(bytes, src as u8)
                            } else {
                                trames_native::last_byte(bytes, src as u8)
                            }
                        },
                    )?;
                    self.record_read(count, direct);
                    if let Some(index) = index {
                        return done(dst.wrapping_add((offset + index) as u64));
                    }
                    remaining -= count;
                }
                if length > ceiling as u64 {
                    fallback()
                } else {
                    done(0)
                }
            }
            11..=19 => crate::strings::execute(self, memory, function, a),
            _ => unreachable!("signed-in pure profile"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::Permissions;
    fn memory(function: u64) -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.map(0x2000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        let words = [
            0xd2800030u32,
            0xf2a00030,
            0xd2800011 | (function as u32) << 5,
            INSTRUCTION,
            0xd65f03c0,
        ];
        for (i, word) in words.into_iter().enumerate() {
            m.write(0x1000 + i as u64 * 4, &word.to_le_bytes()).unwrap();
        }
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        m
    }
    #[test]
    fn device_transport_defers_without_effects_and_rechecks_code_before_authorization() {
        let mut m = memory(1);
        let mut registry = Registry::default();
        m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, &0xd28000d0u32.to_le_bytes()).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        assert!(matches!(
            registry.invoke(&mut m, 0x100c, VULKAN_PROFILE, 1, [0, 0, 0]),
            Err(Error::Checkpoint)
        ));
        assert_eq!(registry.metrics.calls, 0);
        registry
            .authorize_stateful(&m, 0x100c, VULKAN_PROFILE, 1)
            .unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, &0xd28000f0u32.to_le_bytes()).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        assert!(matches!(
            registry.authorize_stateful(&m, 0x100c, VULKAN_PROFILE, 1),
            Err(Error::InvalidEntry)
        ));
        registry
            .authorize_stateful(&m, 0x100c, VIDEO_PROFILE, 1)
            .unwrap();
    }
    #[test]
    fn all_pure_entries_match_coordinator_on_parallel_views() {
        let mut seed = Memory::default();
        seed.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        seed.map(0x4000, PAGE_SIZE * 4, Permissions::RW).unwrap();
        for function in 1..=FUNCTION_COUNT as u64 {
            let base = 0x1000 + (function - 1) * 32;
            for (i, word) in [
                0xd2800030u32,
                0xf2a00030,
                0xd2800011 | (function as u32) << 5,
                INSTRUCTION,
                0xd65f03c0,
            ]
            .iter()
            .enumerate()
            {
                seed.write(base + i as u64 * 4, &word.to_le_bytes())
                    .unwrap();
            }
        }
        seed.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        seed.write(0x5ff0, &[b'a'; 300]).unwrap();
        seed.write(0x5ff0 + 150, &[0]).unwrap();
        seed.write(0x4100, &[b'p'; 300]).unwrap();
        seed.write(0x4100 + 128, &[0]).unwrap();
        for function in 1..=FUNCTION_COUNT as u64 {
            let args = match function {
                1 | 4 | 9 | 10 | 14..=19 => [0x4100, 0x5ff0, 256],
                2 => [0x5ff1, 0x5ff0, 256],
                3 => [0x4100, 255, 256],
                5 => [0x5ff0, 0, 0],
                6 | 7 => [0x5ff0, b'a' as u64, 256],
                8 => [0x5ff0, u64::MAX, 0],
                11..=13 => [0x5ff0, b'z' as u64, 0],
                _ => unreachable!(),
            };
            let pc = 0x100c + (function - 1) * 32;
            let mut owned = seed.clone();
            let mut parallel = seed.clone();
            let mut view = parallel.parallel_view(&mut Default::default()).unwrap();
            let reference = Registry::default()
                .invoke(&mut owned, pc, PROFILE, function, args)
                .unwrap();
            let actual = Registry::default()
                .invoke(&mut view, pc, PROFILE, function, args)
                .unwrap();
            assert_eq!(actual, reference, "function {function}");
            drop(view);
            parallel.commit_parallel().unwrap();
            let mut a = vec![0; PAGE_SIZE as usize * 4];
            let mut b = a.clone();
            owned.read(0x4000, &mut a).unwrap();
            parallel.read(0x4000, &mut b).unwrap();
            assert_eq!(a, b, "function {function}");
        }
    }

    #[test]
    fn huge_compare_search_bounds_stop_early_or_fall_back_only_at_ceiling() {
        let mut m = memory(10);
        let mut r = Registry::default();
        m.write(0x2ffe, b"x\0").unwrap();
        m.write(0x3ffe, b"x\0").unwrap();
        let result = r
            .invoke(&mut m, 0x100c, PROFILE, 10, [0x2ffe, 0x3ffe, u64::MAX])
            .unwrap();
        assert!(!result.fallback);
        assert_eq!(result.value, 0);
        m.write(0x3ffe, b"y").unwrap();
        assert_eq!(
            r.execute(&mut m, 4, [0x2ffe, 0x3ffe, u64::MAX])
                .unwrap()
                .value as u32 as i32,
            -1
        );
        assert_eq!(
            r.execute(&mut m, 6, [0x2ffe, b'x' as u64, u64::MAX])
                .unwrap()
                .value,
            0x2ffe
        );
        m.map(0x10000, MAX_STRING_BYTES as u64 * 2, Permissions::RW)
            .unwrap();
        m.fill_with(0x10000, MAX_STRING_BYTES * 2, |b| b.fill(1))
            .unwrap();
        let result = r
            .invoke(&mut m, 0x100c, PROFILE, 10, [0x10000, 0x110000, u64::MAX])
            .unwrap();
        assert!(result.fallback);
        assert_eq!(r.metrics.function_fallbacks[9], 1);
    }

    #[test]
    fn bulk_ceiling_copy_move_fill_search_and_first_invalid_page() {
        let mut m = memory(1);
        let mut r = Registry::default();
        m.map(0x10000, MAX_BULK_BYTES as u64 * 2, Permissions::RW)
            .unwrap();
        let data: Vec<_> = (0..MAX_BULK_BYTES).map(|i| (i * 73) as u8).collect();
        m.write(0x10000, &data).unwrap();
        assert!(
            !r.invoke(
                &mut m,
                0x100c,
                PROFILE,
                1,
                [0x110000, 0x10000, MAX_BULK_BYTES as u64]
            )
            .unwrap()
            .fallback
        );
        let mut out = vec![0; MAX_BULK_BYTES];
        m.read(0x110000, &mut out).unwrap();
        assert_eq!(out, data);
        assert!(
            !r.execute(&mut m, 2, [0x10001, 0x10000, MAX_BULK_BYTES as u64 - 1])
                .unwrap()
                .fallback
        );
        m.read(0x10001, &mut out[..MAX_BULK_BYTES - 1]).unwrap();
        assert_eq!(&out[..MAX_BULK_BYTES - 1], &data[..MAX_BULK_BYTES - 1]);
        assert!(
            !r.execute(&mut m, 3, [0x110000, 7, MAX_BULK_BYTES as u64])
                .unwrap()
                .fallback
        );
        assert_eq!(
            r.execute(&mut m, 6, [0x110000, 7, MAX_BULK_BYTES as u64])
                .unwrap()
                .value,
            0x110000
        );
        assert_eq!(
            r.execute(&mut m, 7, [0x110000, 7, MAX_BULK_BYTES as u64])
                .unwrap()
                .value,
            0x20ffff
        );
        assert!(
            r.execute(&mut m, 1, [1, 1, MAX_BULK_BYTES as u64 + 1])
                .unwrap()
                .fallback
        );
        m.unmap(0x200000, PAGE_SIZE).unwrap();
        assert!(r
            .execute(&mut m, 3, [0x110000, 0, MAX_BULK_BYTES as u64])
            .is_err());
        assert_eq!(m.read_array::<1>(0x110000).unwrap(), [7]);
    }

    #[test]
    fn rejection_and_limit_fallback_have_no_memory_effects() {
        let mut m = memory(1);
        let mut r = Registry::default();
        m.write(0x2000, b"before").unwrap();
        for (module, function) in [
            (PROFILE + 1, 1),
            (PROFILE, FUNCTION_COUNT as u64 + 1),
            (PROFILE, 0),
        ] {
            assert!(matches!(
                r.invoke(&mut m, 0x100c, module, function, [0x2000, 1, 6]),
                Err(Error::InvalidEntry)
            ));
        }
        assert!(
            r.invoke(
                &mut m,
                0x100c,
                PROFILE,
                1,
                [1, 2, MAX_BULK_BYTES as u64 + 1]
            )
            .unwrap()
            .fallback
        );
        assert_eq!(m.read_array::<6>(0x2000).unwrap(), *b"before");
        // Caller bytes are revalidated after executable mutation, not just once.
        m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, &0xd503201fu32.to_le_bytes()).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        assert!(matches!(
            r.invoke(&mut m, 0x100c, PROFILE, 1, [0x2000, 0x3000, 6]),
            Err(Error::InvalidEntry)
        ));
        assert_eq!(r.metrics.fallbacks, 1);
        assert_eq!(r.metrics.rejected, 4);
    }
    #[test]
    fn early_stops_and_precise_fault_leave_destination_untouched() {
        let mut m = memory(5);
        let mut r = Registry::default();
        m.write(0x3fff, &[0]).unwrap();
        assert_eq!(
            r.invoke(&mut m, 0x100c, PROFILE, 5, [0x3fff, 0, 0])
                .unwrap()
                .value,
            0
        );
        m.write(0x3fff, &[1]).unwrap();
        assert!(matches!(
            r.invoke(&mut m, 0x100c, PROFILE, 5, [0x3fff, 0, 0]),
            Err(Error::Memory(MemoryError::Unmapped(0x4000)))
        ));
        let mut m = memory(4);
        m.write(0x3fff, &[1]).unwrap();
        m.write(0x2fff, &[255]).unwrap();
        assert_eq!(
            r.invoke(&mut m, 0x100c, PROFILE, 4, [0x3fff, 0x2fff, 512])
                .unwrap()
                .value as u32 as i32,
            -254
        );
        let mut m = memory(1);
        m.write(0x2000, b"before").unwrap();
        assert!(matches!(
            r.invoke(&mut m, 0x100c, PROFILE, 1, [0x2000, 0x3fff, 6]),
            Err(Error::Memory(MemoryError::Unmapped(0x4000)))
        ));
        assert_eq!(m.read_array::<6>(0x2000).unwrap(), *b"before");
    }
    #[test]
    fn cached_stubs_recheck_pages_across_fork_remap_protection_and_cross_page_mutation() {
        let mut registry = Registry::default();
        let mut m = memory(3);
        let call =
            |r: &mut Registry, m: &mut Memory, pc| r.invoke(m, pc, PROFILE, 3, [0x3800, 7, 128]);
        call(&mut registry, &mut m, 0x100c).unwrap();
        call(&mut registry, &mut m, 0x100c).unwrap();
        assert_eq!(
            (
                registry.metrics.validation_hits,
                registry.metrics.validation_misses
            ),
            (1, 1)
        );
        m.map(0x9000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x9000, &[8]).unwrap();
        call(&mut registry, &mut m, 0x100c).unwrap();
        assert_eq!(registry.metrics.validation_hits, 2);
        let mut child = m.clone();
        call(&mut registry, &mut child, 0x100c).unwrap();
        assert_eq!(registry.metrics.validation_misses, 2);
        m.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert!(call(&mut registry, &mut m, 0x100c).is_err());
        m.map_fixed(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        assert!(call(&mut registry, &mut m, 0x100c).is_err());
        let mut crossing = Memory::default();
        crossing
            .map(0x1000, PAGE_SIZE * 3, Permissions::RW)
            .unwrap();
        let code = [
            0xd2800030u32,
            0xf2a00030,
            0xd2800071,
            INSTRUCTION,
            0xd65f03c0,
        ];
        for (i, word) in code.iter().enumerate() {
            crossing
                .write(0x1ff4 + i as u64 * 4, &word.to_le_bytes())
                .unwrap();
        }
        crossing
            .protect(0x1000, PAGE_SIZE * 2, Permissions::RX)
            .unwrap();
        call(&mut registry, &mut crossing, 0x2000).unwrap();
        call(&mut registry, &mut crossing, 0x2000).unwrap();
        crossing
            .protect(
                0x2000,
                PAGE_SIZE,
                Permissions {
                    execute: true,
                    ..Permissions::RW
                },
            )
            .unwrap();
        call(&mut registry, &mut crossing, 0x2000).unwrap();
        crossing
            .fill_with(0x2004, 4, |bytes| {
                bytes.copy_from_slice(&0xd503201fu32.to_le_bytes())
            })
            .unwrap();
        assert!(matches!(
            call(&mut registry, &mut crossing, 0x2000),
            Err(Error::InvalidEntry)
        ));
    }
    #[test]
    fn cached_stub_tokens_follow_live_backing_aliases_and_eof_checks() {
        use std::{
            cell::{Cell, RefCell},
            rc::Rc,
        };
        use trames_memory::{backing_changed, PageBacking};
        struct Backing {
            bytes: RefCell<[u8; PAGE_SIZE as usize]>,
            version: Cell<u64>,
            valid: Cell<bool>,
        }
        impl PageBacking for Backing {
            fn check(&self, address: u64) -> Result<(), MemoryError> {
                if self.valid.get() {
                    Ok(())
                } else {
                    Err(MemoryError::Bus(address))
                }
            }
            fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
                out.copy_from_slice(&self.bytes.borrow()[offset..offset + out.len()]);
                Ok(())
            }
            fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
                self.bytes.borrow_mut()[offset..offset + bytes.len()].copy_from_slice(bytes);
                self.version.set(self.version.get() + 1);
                backing_changed();
                Ok(())
            }
            fn sync(&self) -> Result<(), MemoryError> {
                Ok(())
            }
            fn version(&self) -> u64 {
                self.version.get()
            }
            fn writable(&self) -> bool {
                true
            }
            fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
                Err(MemoryError::InvalidRange)
            }
        }
        let backing = Rc::new(Backing {
            bytes: RefCell::new([0; PAGE_SIZE as usize]),
            version: Cell::new(1),
            valid: Cell::new(true),
        });
        for (i, word) in [
            0xd2800030u32,
            0xf2a00030,
            0xd2800071,
            INSTRUCTION,
            0xd65f03c0,
        ]
        .iter()
        .enumerate()
        {
            backing.write(i * 4, &word.to_le_bytes()).unwrap();
        }
        let mut m = Memory::default();
        m.map_backed(0x1000, vec![backing.clone()], true, Permissions::RX, false)
            .unwrap();
        m.map_backed(0x3000, vec![backing.clone()], true, Permissions::RW, false)
            .unwrap();
        m.map(0x5000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut r = Registry::default();
        for _ in 0..2 {
            r.invoke(&mut m, 0x100c, PROFILE, 3, [0x5000, 1, 128])
                .unwrap();
        }
        assert_eq!(r.metrics.validation_hits, 1);
        backing.valid.set(false);
        assert!(matches!(
            r.invoke(&mut m, 0x100c, PROFILE, 3, [0x5000, 1, 128]),
            Err(Error::InvalidEntry)
        ));
        backing.valid.set(true);
        m.fill_with(0x3000, 4, |bytes| {
            bytes.copy_from_slice(&0xd503201fu32.to_le_bytes())
        })
        .unwrap();
        assert!(matches!(
            r.invoke(&mut m, 0x100c, PROFILE, 3, [0x5000, 1, 128]),
            Err(Error::InvalidEntry)
        ));
        assert_eq!(r.metrics.validation_hits, 1);
    }
    #[test]
    fn copy_overlap_cow_and_tagged_return_are_preserved() {
        let mut m = memory(2);
        let mut r = Registry::default();
        m.write(0x2ffc, b"abcdefgh").unwrap();
        let parent = m.clone();
        let tagged = 0xab00_0000_0000_2ffe;
        assert_eq!(
            r.invoke(&mut m, 0x100c, PROFILE, 2, [tagged, 0x2ffc, 6])
                .unwrap()
                .value,
            tagged
        );
        assert_eq!(m.read_array::<8>(0x2ffc).unwrap(), *b"ababcdef");
        assert_eq!(parent.read_array::<8>(0x2ffc).unwrap(), *b"abcdefgh");
        assert_eq!(r.metrics.buffered_bytes_read, 0);
        assert_eq!(r.metrics.buffered_bytes_written, 0);
        assert_eq!(r.metrics.direct_bytes_written, 6);
    }
    #[test]
    fn searches_stop_at_reached_pages_preserve_tags_and_large_bounds_fall_back() {
        let mut r = Registry::default();
        for function in [6, 7] {
            let mut m = memory(function);
            m.write(0x3fff, &[0xff]).unwrap();
            let tagged = 0xab00_0000_0000_3fff;
            assert_eq!(
                r.invoke(&mut m, 0x100c, PROFILE, function, [tagged, 0x1ff, 1])
                    .unwrap()
                    .value,
                tagged
            );
            assert_eq!(
                r.invoke(&mut m, 0x100c, PROFILE, function, [1, 1, 0])
                    .unwrap()
                    .value,
                0
            );
            if function == 7 {
                assert!(
                    r.invoke(
                        &mut m,
                        0x100c,
                        PROFILE,
                        function,
                        [1, 1, MAX_BULK_BYTES as u64 + 1]
                    )
                    .unwrap()
                    .fallback
                );
            }
        }
        let mut m = memory(6);
        m.write(0x3fff, &[17]).unwrap();
        assert_eq!(
            r.invoke(&mut m, 0x100c, PROFILE, 6, [0x3fff, 17, 1024])
                .unwrap()
                .value,
            0x3fff
        );
        assert!(matches!(
            r.invoke(&mut m, 0x100c, PROFILE, 6, [0x3fff, 18, 1024]),
            Err(Error::Memory(MemoryError::Unmapped(0x4000)))
        ));
        let mut m = memory(8);
        m.write(0x3ffe, &[1, 0]).unwrap();
        assert_eq!(
            r.invoke(&mut m, 0x100c, PROFILE, 8, [0x3ffe, u64::MAX, 0])
                .unwrap()
                .value,
            1
        );
        assert_eq!(
            r.invoke(&mut m, 0x100c, PROFILE, 8, [1, 0, 0])
                .unwrap()
                .value,
            0
        );
        m.write(0x3fff, &[1]).unwrap();
        assert_eq!(
            r.invoke(&mut m, 0x100c, PROFILE, 8, [0x3fff, 1, 0])
                .unwrap()
                .value,
            1
        );
        for function in [9, 10] {
            let mut m = memory(function);
            m.write(0x3fff, &[0]).unwrap();
            m.write(0x2fff, &[0]).unwrap();
            assert_eq!(
                r.invoke(&mut m, 0x100c, PROFILE, function, [0x3fff, 0x2fff, 1024])
                    .unwrap()
                    .value,
                0
            );
            m.write(0x3fff, &[255]).unwrap();
            m.write(0x2fff, &[1]).unwrap();
            assert_eq!(
                r.invoke(&mut m, 0x100c, PROFILE, function, [0x3fff, 0x2fff, 1024])
                    .unwrap()
                    .value as u32 as i32,
                254
            );
        }
        assert_eq!(r.metrics.buffered_bytes_read, 0);
    }
}
