// SPDX-License-Identifier: GPL-3.0-or-later
//! Hierarchical resident-page accounting on the original page lease.
use crate::{MemoryError, PAGE_SIZE};
use parking_lot::RwLock;
use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
        Arc,
    },
};

#[derive(Default)]
struct Events {
    high: AtomicUsize,
    max: AtomicUsize,
    oom: AtomicUsize,
    oom_kill: AtomicUsize,
    oom_group_kill: AtomicUsize,
}

pub struct MemoryCgroup {
    parent: Option<Arc<Self>>,
    current: AtomicUsize,
    high: AtomicUsize,
    limit: AtomicUsize,
    oom_group: AtomicBool,
    local: Events,
    events: Events,
}

impl MemoryCgroup {
    pub fn new(parent: Option<Arc<Self>>) -> Arc<Self> {
        Arc::new(Self {
            parent,
            current: AtomicUsize::new(0),
            high: AtomicUsize::new(usize::MAX),
            limit: AtomicUsize::new(usize::MAX),
            oom_group: AtomicBool::new(false),
            local: Events::default(),
            events: Events::default(),
        })
    }
    pub fn current(&self) -> usize {
        self.current.load(Relaxed)
    }
    pub fn limit(&self) -> usize {
        self.limit.load(Relaxed)
    }
    pub fn set_limit(&self, bytes: usize) {
        self.limit.store(bytes, Relaxed);
    }
    pub fn high(&self) -> usize {
        self.high.load(Relaxed)
    }
    pub fn set_high(&self, bytes: usize) {
        self.high.store(bytes, Relaxed);
    }
    pub fn oom_group(&self) -> bool {
        self.oom_group.load(Relaxed)
    }
    pub fn set_oom_group(&self, enabled: bool) {
        self.oom_group.store(enabled, Relaxed);
    }
    pub fn format_events(&self, local: bool) -> String {
        let ev = if local { &self.local } else { &self.events };
        format!(
            "low 0\nhigh {}\nmax {}\noom {}\noom_kill {}\noom_group_kill {}\n",
            ev.high.load(Relaxed),
            ev.max.load(Relaxed),
            ev.oom.load(Relaxed),
            ev.oom_kill.load(Relaxed),
            ev.oom_group_kill.load(Relaxed),
        )
    }
    fn event(&self, select: impl Fn(&Events) -> &AtomicUsize) {
        select(&self.local).fetch_add(1, Relaxed);
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            select(&group.events).fetch_add(1, Relaxed);
            cursor = group.parent.as_deref();
        }
    }
    pub fn is_within(&self, ancestor: &Self) -> bool {
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            if std::ptr::eq(group, ancestor) {
                return true;
            }
            cursor = group.parent.as_deref();
        }
        false
    }
    pub fn oom_group_within(self: &Arc<Self>, limit: &Self) -> Option<Arc<Self>> {
        if !self.is_within(limit) {
            return None;
        }
        let mut victim = None;
        let mut current = Some(self);
        while let Some(group) = current {
            if group.oom_group() {
                victim = Some(group.clone());
            }
            if std::ptr::eq(group.as_ref(), limit) {
                break;
            }
            current = group.parent.as_ref();
        }
        victim
    }
    pub fn record_oom_kill(&self) {
        self.event(|ev| &ev.oom_kill);
    }
    pub fn record_group_kill(&self) {
        self.event(|ev| &ev.oom_group_kill);
    }
    fn take(self: &Arc<Self>) -> Result<bool, Arc<Self>> {
        let parent_high = self
            .parent
            .as_ref()
            .map_or(Ok(false), |parent| parent.take())?;
        let page = PAGE_SIZE as usize;
        let limit = self.limit();
        let update = self.current.try_update(Relaxed, Relaxed, |used| {
            used.checked_add(page).filter(|&next| next <= limit)
        });
        let Ok(before) = update else {
            if let Some(parent) = &self.parent {
                parent.release();
            }
            self.event(|ev| &ev.max);
            self.event(|ev| &ev.oom);
            return Err(self.clone());
        };
        let high = before + page > self.high();
        if high {
            self.event(|ev| &ev.high);
        }
        Ok(high || parent_high)
    }
    pub(super) fn release(&self) {
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            group.current.fetch_sub(PAGE_SIZE as usize, Relaxed);
            cursor = group.parent.as_deref();
        }
    }
}

#[derive(Default)]
pub struct CgroupMemoryTarget {
    current: RwLock<Option<Arc<MemoryCgroup>>>,
    oom: parking_lot::Mutex<Option<(Arc<MemoryCgroup>, Arc<MemoryCgroup>)>>,
    high_pages: AtomicUsize,
}

thread_local! {
    static SOURCE: RefCell<Option<Arc<CgroupMemoryTarget>>> = const { RefCell::new(None) };
}
pub struct CgroupMemoryScope {
    previous: Option<Arc<CgroupMemoryTarget>>,
    _executor: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Drop for CgroupMemoryScope {
    fn drop(&mut self) {
        SOURCE.with(|source| {
            source.replace(self.previous.take());
        });
    }
}

impl CgroupMemoryTarget {
    pub fn set(&self, group: Option<Arc<MemoryCgroup>>) {
        *self.current.write() = group;
    }
    pub fn scope(self: &Arc<Self>) -> CgroupMemoryScope {
        CgroupMemoryScope {
            previous: SOURCE.with(|slot| slot.replace(Some(self.clone()))),
            _executor: std::marker::PhantomData,
        }
    }
    pub fn take_oom(&self) -> Option<(Arc<MemoryCgroup>, Arc<MemoryCgroup>)> {
        self.oom.lock().take()
    }
    pub fn above_high(&self) -> bool {
        self.high_pages.load(Relaxed) != 0
    }
    pub fn high_delay(&self) -> std::time::Duration {
        // Bound a single delay while the guest is over its configured high mark.
        // The executor releases its slot between bursts of page admissions.
        std::time::Duration::from_micros(self.high_pages.swap(0, Relaxed).min(500) as u64 * 100)
    }
    pub(super) fn active() -> bool {
        SOURCE.with(|s| {
            s.borrow()
                .as_ref()
                .is_some_and(|target| target.current.read().is_some())
        })
    }
    pub(super) fn charge_page() -> Result<Option<Arc<MemoryCgroup>>, MemoryError> {
        SOURCE.with(|s| {
            let source = s.borrow();
            let Some(target) = source.as_ref() else {
                return Ok(None);
            };
            let Some(group) = target.current.read().clone() else {
                return Ok(None);
            };
            match group.take() {
                Ok(high) => {
                    if high {
                        target.high_pages.fetch_add(1, Relaxed);
                    }
                    Ok(Some(group))
                }
                Err(failed) => {
                    *target.oom.lock() = Some((group, failed));
                    Err(MemoryError::Limit)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Memory, Permissions};

    #[test]
    fn resident_pages_keep_the_controller_that_accepted_them() {
        let parent = MemoryCgroup::new(None);
        let child = MemoryCgroup::new(Some(parent.clone()));
        let other = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(child.clone()));
        let _scope = target.scope();
        let mut memory = Memory::default();
        let start = PAGE_SIZE;
        memory.map(start, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(child.current(), 0);
        memory.write_array(start, [1]).unwrap();
        target.set(Some(other.clone()));
        memory.write_array(start + PAGE_SIZE, [2]).unwrap();
        assert_eq!(child.current(), PAGE_SIZE as usize);
        assert_eq!(parent.current(), PAGE_SIZE as usize);
        assert_eq!(other.current(), PAGE_SIZE as usize);
        memory.unmap(start, PAGE_SIZE).unwrap();
        assert_eq!(child.current(), 0);
        assert_eq!(parent.current(), 0);
        assert_eq!(other.current(), PAGE_SIZE as usize);
    }

    #[test]
    fn a_failed_hierarchical_charge_rolls_back_and_reports_its_limit() {
        let parent = MemoryCgroup::new(None);
        let child = MemoryCgroup::new(Some(parent.clone()));
        child.set_limit(PAGE_SIZE as usize);
        child.set_high(0);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(child.clone()));
        let _scope = target.scope();
        let mut memory = Memory::default();
        memory
            .map(PAGE_SIZE, 2 * PAGE_SIZE, Permissions::RW)
            .unwrap();
        memory.write_array(PAGE_SIZE, [1]).unwrap();
        assert!(!target.high_delay().is_zero());
        assert_eq!(
            memory.write_array(2 * PAGE_SIZE, [1]),
            Err(MemoryError::Limit)
        );
        assert_eq!(parent.current(), PAGE_SIZE as usize);
        let (origin, limit) = target.take_oom().unwrap();
        assert!(Arc::ptr_eq(&origin, &child) && Arc::ptr_eq(&limit, &child));
        memory.unmap(PAGE_SIZE, PAGE_SIZE).unwrap();
        memory.write_array(2 * PAGE_SIZE, [1]).unwrap();
        assert_eq!(parent.current(), PAGE_SIZE as usize);
    }
}
