// SPDX-License-Identifier: GPL-3.0-or-later
//! Perf control/data pages retain their original event and shared byte domain.
use super::*;
use trames_memory::{MemoryError, PageBacking, SharedPage, PAGE_SIZE};

const PAGE: usize = PAGE_SIZE as usize;
struct Producer {
    head: u64,
    lost: u64,
    samples: u64,
    wakeup: u64,
    paused: bool,
}
pub(super) struct Ring {
    pub(super) event: Arc<Event>,
    pages: Vec<Arc<SharedPage>>,
    owners: Vec<trames_memory::MappedResidents>,
    writable: bool,
    pub(super) identity: u64,
    producer: parking_lot::Mutex<Producer>,
    pending: std::sync::atomic::AtomicU32,
    epoch: AtomicU64,
    maps: std::sync::atomic::AtomicUsize,
    attached: parking_lot::Mutex<Vec<std::sync::Weak<output::Output>>>,
}
struct Mapping {
    ring: Arc<Ring>,
    _open: Arc<SharedOpenDescription>,
    _charge: accounting::Charge,
}
struct Page {
    ring: Arc<Ring>,
    index: usize,
    // A VMA retains the exact OFD, including flock and final-release lifetime.
    _mapping: Arc<Mapping>,
}
impl Ring {
    pub(super) fn mapped(&self) -> bool {
        self.maps.load(Ordering::Relaxed) != 0
    }
    pub(super) fn attach(
        self: &Arc<Self>,
        output: &Arc<output::Output>,
        state: &mut std::sync::Weak<Self>,
    ) -> Result<()> {
        let mut attached = self.attached.lock();
        if !self.mapped() {
            return Err(Errno(22));
        }
        attached.retain(|weak| weak.strong_count() != 0);
        if !attached
            .iter()
            .any(|weak| weak.ptr_eq(&Arc::downgrade(output)))
        {
            attached.push(Arc::downgrade(output));
        }
        *state = Arc::downgrade(self);
        output.buffer.store(self.identity, Ordering::Relaxed);
        Ok(())
    }
    pub(super) fn waiters(&self) -> Vec<Arc<Readiness>> {
        self.attached
            .lock()
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .filter(|output| output.buffer.load(Ordering::Relaxed) == self.identity)
            .map(|output| output.changed.clone())
            .collect()
    }
    fn alias(&self, output: &output::Output, count: usize) -> Result<bool> {
        let _mapping = self.attached.lock();
        if !self.mapped() {
            return Ok(false);
        }
        if self.pages.len() != count {
            return Err(Errno(22));
        }
        if output.owned.load(Ordering::Relaxed) != self.identity {
            return Err(Errno(16));
        }
        self.maps.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }
    pub(super) fn size(&self) -> usize {
        (self.pages.len() - 1) * PAGE
    }
    fn write(&self, mut at: u64, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let offset = at as usize & (self.size() - 1);
            let n = bytes.len().min(PAGE - offset % PAGE);
            self.pages[1 + offset / PAGE].copy_write(offset % PAGE, &bytes[..n]);
            bytes = &bytes[n..];
            at = at.wrapping_add(n as u64);
        }
    }
    pub(super) fn userpage(&self, value: u64, time: u64) {
        let page = &self.pages[0];
        let mut sequence = [0; 4];
        page.copy_read(8, &mut sequence);
        let sequence = u32::from_le_bytes(sequence).wrapping_add(1) | 1;
        page.copy_write(8, &sequence.to_le_bytes());
        // The mmap ABI's actual sequence publication: odd precedes data,
        // final even releases it. Ordinary guest memory accesses add no fence.
        std::sync::atomic::fence(Ordering::Release);
        page.copy_write(16, &value.to_le_bytes());
        page.copy_write(24, &time.to_le_bytes());
        page.copy_write(32, &time.to_le_bytes());
        unsafe {
            page.store_release_u32(8, sequence.wrapping_add(1));
        }
    }
    pub(super) fn pause(&self, paused: bool) {
        self.producer.lock().paused = paused;
    }
    pub(super) fn output(
        &self,
        record: &[u8],
        context: &Sample,
        is_sample: bool,
        source: &sample::Identity<'_>,
        lost: &AtomicU64,
    ) -> bool {
        let mut state = self.producer.lock();
        if self.size() == 0 || !self.mapped() {
            return false;
        }
        if state.paused {
            state.lost = state.lost.saturating_add(1);
            lost.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let mut prefix = Vec::new();
        if state.lost != 0 {
            prefix.extend([0; 8]);
            prefix.extend(source.id.to_le_bytes());
            prefix.extend(state.lost.to_le_bytes());
            source.sample_id(context, &mut prefix);
            sample::header(&mut prefix, 2, 0);
        }
        let needed = prefix.len() + record.len();
        if self.writable {
            // SAFETY: data_tail is the fixed aligned guest publication word;
            // its value never chooses a host pointer or allocation geometry.
            let tail = unsafe { self.pages[0].load_acquire_u64(1032) };
            let room = tail.wrapping_sub(state.head).wrapping_sub(1) as usize & (self.size() - 1);
            if needed > room {
                state.lost = state.lost.saturating_add(1);
                lost.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        if needed > self.size() {
            state.lost = state.lost.saturating_add(1);
            lost.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.write(state.head, &prefix);
        state.head = state.head.wrapping_add(prefix.len() as u64);
        self.write(state.head, record);
        state.head = state.head.wrapping_add(record.len() as u64);
        state.lost = 0;
        // SAFETY: the control page's fixed publication word. Release orders
        // preceding writes to every original data page before the new head.
        unsafe {
            self.pages[0].store_release_u64(1024, state.head);
        }
        let watermark = if self.event.attr.watermark && self.event.attr.wakeup != 0 {
            u64::from(self.event.attr.wakeup).min(self.size() as u64)
        } else {
            self.size() as u64 / 2
        };
        let mut wake = state.head.wrapping_sub(state.wakeup) > watermark;
        if wake {
            state.wakeup = state.wakeup.wrapping_add(watermark);
        }
        if is_sample && !source.attr.watermark && source.attr.wakeup != 0 {
            state.samples = state.samples.saturating_add(1);
            if state.samples >= u64::from(source.attr.wakeup) {
                state.samples -= u64::from(source.attr.wakeup);
                wake = true;
            }
        }
        if wake {
            self.pending.store(1, Ordering::Relaxed);
            self.epoch.fetch_add(1, Ordering::Relaxed);
        }
        wake
    }
    pub(super) fn poll(&self, events: u16, consume: bool) -> (u16, [u64; 2]) {
        let pending = if consume {
            self.pending.swap(0, Ordering::Relaxed)
        } else {
            self.pending.load(Ordering::Relaxed)
        };
        (
            pending as u16 & (events & 1 | 16),
            [self.epoch.load(Ordering::Relaxed), 0],
        )
    }
}
impl Event {
    pub(crate) fn pages(
        self: &Arc<Self>,
        open: Arc<SharedOpenDescription>,
        range: (u64, u64),
        shared: bool,
        writable: bool,
        policy: &Policy,
        mm: u64,
    ) -> Result<Vec<Arc<dyn PageBacking>>> {
        let (offset, len) = range;
        if self.attr.inherit || !shared || offset != 0 || len == 0 || !len.is_multiple_of(PAGE_SIZE)
        {
            return Err(Errno(22));
        }
        let count = usize::try_from(len / PAGE_SIZE).map_err(|_| Errno(12))?;
        if count > i32::MAX as usize {
            return Err(Errno(12));
        }
        if count != 1 && !(count - 1).is_power_of_two() {
            return Err(Errno(22));
        }
        let mut destination = self.output.ring.lock();
        let existing = match destination.upgrade() {
            Some(ring) if ring.alias(&self.output, count)? => Some(ring),
            _ => None,
        };
        let (ring, charge) = if let Some(ring) = existing {
            (ring, policy.alias(mm, len))
        } else {
            let charge = policy.reserve(mm, len, self.cpus)?;
            let mut pages = Vec::new();
            pages.try_reserve_exact(count).map_err(|_| Errno(12))?;
            for _ in 0..count {
                pages.push(Arc::new(SharedPage::zero()));
            }
            pages[0].copy_write(40, &2u64.to_le_bytes()); // deprecated cap bit 0 is clear
            pages[0].copy_write(1040, &PAGE_SIZE.to_le_bytes());
            pages[0].copy_write(1048, &((count as u64 - 1) * PAGE_SIZE).to_le_bytes());
            let ring = Arc::new(Ring {
                event: self.clone(),
                pages,
                owners: (0..count).map(|_| Default::default()).collect(),
                writable,
                identity: trames_memory::new_backing_identity(),
                producer: parking_lot::Mutex::new(Producer {
                    head: 0,
                    lost: 0,
                    samples: 0,
                    wakeup: 0,
                    paused: false,
                }),
                pending: Default::default(),
                epoch: Default::default(),
                maps: std::sync::atomic::AtomicUsize::new(1),
                attached: Default::default(),
            });
            ring.attach(&self.output, &mut destination)?;
            self.output.owned.store(ring.identity, Ordering::Relaxed);
            (ring, charge)
        };
        let mapping = Arc::new(Mapping {
            ring: ring.clone(),
            _open: open,
            _charge: charge,
        });
        drop(destination);
        {
            let mut state = self.group.lock();
            state.settle(self.clock.read());
            ring.userpage(state.members[&self.id].value, state.members[&self.id].time);
        }
        Ok((0..count)
            .map(|index| {
                Arc::new(Page {
                    ring: ring.clone(),
                    index,
                    _mapping: mapping.clone(),
                }) as Arc<dyn PageBacking>
            })
            .collect())
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        let mut changes = Vec::new();
        {
            let mut attached = self.ring.attached.lock();
            if self.ring.maps.fetch_sub(1, Ordering::Relaxed) != 1 {
                return;
            }
            for output in attached.drain(..).filter_map(|weak| weak.upgrade()) {
                output
                    .owned
                    .compare_exchange(self.ring.identity, 0, Ordering::Relaxed, Ordering::Relaxed)
                    .ok();
                if output
                    .buffer
                    .compare_exchange(self.ring.identity, 0, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    changes.push(output.changed.clone());
                }
            }
        }
        for changed in changes {
            changed.notify_atomic();
        }
    }
}
impl PageBacking for Page {
    fn mapped_residents(&self) -> Option<&trames_memory::MappedResidents> {
        Some(&self.ring.owners[self.index])
    }
    fn inherit_on_fork(&self) -> bool {
        false
    }
    fn expandable(&self) -> bool {
        false
    }
    fn retain_in_view(&self) -> bool {
        true
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.ring.identity, self.index as u64))
    }
    fn shared_page(&self) -> Option<Arc<SharedPage>> {
        Some(self.ring.pages[self.index].clone())
    }
    fn parallel_versioned(&self) -> bool {
        true
    }
    fn parallel_metadata_domain(&self) -> Option<(u64, u64)> {
        Some((self.ring.identity, 0))
    }
    fn check(&self, _: u64) -> std::result::Result<(), MemoryError> {
        Ok(())
    }
    fn write_fault(&self, address: u64) -> Option<MemoryError> {
        (self.index != 0).then_some(MemoryError::Bus(address))
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> std::result::Result<(), MemoryError> {
        self.ring.pages[self.index].copy_read(offset, out);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> std::result::Result<(), MemoryError> {
        if self.index != 0 {
            return Err(MemoryError::Bus(0));
        }
        self.ring.pages[0].copy_write(offset, bytes);
        Ok(())
    }
    fn with_read(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> std::result::Result<bool, MemoryError> {
        self.ring.pages[self.index].with_read(offset, len, f);
        Ok(true)
    }
    fn with_write(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&mut [u8]),
    ) -> std::result::Result<bool, MemoryError> {
        if self.index != 0 {
            return Err(MemoryError::Bus(0));
        }
        self.ring.pages[0].with_write(offset, len, f);
        Ok(true)
    }
    fn publish_write(&self, _: usize, _: usize) -> std::result::Result<(), MemoryError> {
        Ok(())
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        Ok(())
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn native_resident(&self) -> bool {
        true
    }
    fn executable(&self) -> bool {
        false
    } // anon_inodefs SB_I_NOEXEC
    fn writable(&self) -> bool {
        true
    }
    fn version(&self) -> u64 {
        self.ring.pages[self.index].revision()
    }
    fn next_page(&self, _: u64) -> std::result::Result<Arc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::BackingIo(14))
    }
}
