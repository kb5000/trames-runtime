// SPDX-License-Identifier: GPL-3.0-or-later
//! Original CQ records survive output faults. One context-local consumption
//! lease protects the whole copied batch without retaining its mutex or a CPU.
use super::*;
use trames_memory::{MemoryError, PageFault, PAGE_SIZE};
pub(super) struct Events {
    context: Arc<Context>,
    head: u32,
    records: VecDeque<[u8; 32]>,
    offset: usize,
    copied: u32,
    owns: bool,
    result: Option<Result<u64, Errno>>,
}
impl Drop for Events {
    fn drop(&mut self) {
        self.release();
    }
}
impl Events {
    pub(super) fn begin(
        context: Arc<Context>,
        minimum: u64,
        maximum: u64,
        expired: bool,
    ) -> Result<Option<Self>, Errno> {
        let mut state = context.state.lock().unwrap();
        if state.dead {
            return Err(Errno(22));
        }
        if state.reaping {
            return Ok(None);
        }
        let mut head = context.head();
        let available = context.pending(head, state.tail);
        if available == 0 && minimum != 0 && !expired {
            return Ok(None);
        }
        let count = available.min(maximum as usize);
        let original = head;
        let mut records = VecDeque::with_capacity(count);
        for _ in 0..count {
            let (page, offset) = context.event(head);
            let mut bytes = [0; 32];
            page.copy_read(offset, &mut bytes);
            records.push_back(bytes);
            head = (head + 1) % context.slots;
        }
        state.reaping = count != 0;
        drop(state);
        Ok(Some(Self {
            context,
            head: original,
            records,
            offset: 0,
            copied: 0,
            owns: count != 0,
            result: None,
        }))
    }
    fn release(&mut self) {
        if !self.owns {
            return;
        }
        {
            let mut state = self.context.state.lock().unwrap();
            // Linux aio_read_events_ring publishes its head only after the
            // entire captured batch copy succeeds. A failed later fragment
            // leaves even previously copied records in this batch unconsumed.
            if matches!(self.result, Some(Ok(_))) {
                let head = (self.head + self.copied) % self.context.slots;
                unsafe {
                    self.context.ring[0].store_release_u32(8, head);
                }
            }
            state.reaping = false;
        }
        self.owns = false;
        self.context.notify();
    }
    pub(super) fn cancel(&mut self) {
        if self.result.is_none() {
            self.result = Some(Err(Errno(4)));
        }
        self.records.clear();
        self.release();
    }
    pub(super) fn progress(
        &mut self,
        memory: &mut impl CpuMemory,
        address: u64,
    ) -> std::result::Result<Result<u64, Errno>, PageFault> {
        if let Some(result) = self.result {
            return Ok(result);
        }
        while let Some(record) = self.records.front() {
            let at = address.checked_add(u64::from(self.copied) * 32 + self.offset as u64);
            let result = match at {
                Some(at) => {
                    let count = (32 - self.offset).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
                    memory
                        .write(at, &record[self.offset..self.offset + count])
                        .map(|()| count)
                }
                None => Err(MemoryError::InvalidRange),
            };
            match result {
                Ok(count) => {
                    self.offset += count;
                    if self.offset == 32 {
                        self.records.pop_front();
                        self.offset = 0;
                        self.copied += 1;
                    }
                }
                Err(MemoryError::Pending(fault)) => return Err(fault),
                Err(_) => {
                    let result = Err(Errno(14));
                    self.result = Some(result);
                    self.release();
                    return Ok(result);
                }
            }
        }
        let result = Ok(u64::from(self.copied));
        self.result = Some(result);
        self.release();
        Ok(result)
    }
}
