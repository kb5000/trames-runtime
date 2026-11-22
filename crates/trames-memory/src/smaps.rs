// SPDX-License-Identifier: GPL-3.0-or-later
//! On-demand physical accounting. A proc descriptor retains formatted bytes,
//! never an execution view, a guest page, or a second reference to a COW owner.
use super::*;
use std::io::Write;
use std::sync::{Mutex, OnceLock, Weak};
use trames_shared::{IoSignal, IoSubscription, Readiness};

#[derive(Default)]
struct Totals {
    pages: [u64; 4],
    pss: u64,
    anonymous: u64,
    locked: u64,
}
impl Totals {
    fn page(&mut self, owners: usize, dirty: bool, anon: bool, locked: bool) {
        self.pages[2 * usize::from(owners == 1) + usize::from(dirty)] += 1;
        let proportional = (PAGE_SIZE << 12) / owners as u64;
        self.pss += proportional;
        self.anonymous += u64::from(anon);
        self.locked += if locked { proportional } else { 0 };
    }
    fn add(&mut self, other: &Self) {
        for (a, b) in self.pages.iter_mut().zip(other.pages) {
            *a += b;
        }
        self.pss += other.pss;
        self.anonymous += other.anonymous;
        self.locked += other.locked;
    }
    fn write(&self, out: &mut Vec<u8>) {
        let kb = PAGE_SIZE / 1024;
        for (name, n) in [
            ("Rss", self.pages.iter().sum::<u64>() * kb),
            ("Pss", self.pss >> 22),
            ("Shared_Clean", self.pages[0] * kb),
            ("Shared_Dirty", self.pages[1] * kb),
            ("Private_Clean", self.pages[2] * kb),
            ("Private_Dirty", self.pages[3] * kb),
            ("Anonymous", self.anonymous * kb),
            ("Swap", 0),
            ("Locked", self.locked >> 22),
        ] {
            writeln!(out, "{name}: {n} kB").unwrap();
        }
    }
}
impl Memory {
    /// Call while the original structural owner is admitted. Scanning page-table
    /// metadata and atomic residency does not require execution views to return.
    pub fn serve_mapping_statistics(&self, report: &MemoryReport) -> bool {
        if !report.requested_smaps() || !self.has_memory_report(report) {
            return false;
        }
        report.finish_smaps(Some(self));
        !report.has_requested_reads()
    }
    pub fn smaps(&self, rollup: bool) -> Result<Arc<[u8]>, MemoryError> {
        self.smaps_at_root(rollup, None)
    }
    fn smaps_at_root(
        &self,
        rollup: bool,
        root: Option<&MappingRoot>,
    ) -> Result<Arc<[u8]>, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().smaps_at_root(rollup, root);
        }
        let mut total = Totals::default();
        let mut result = Ok(());
        let stack = self.image_ranges.map(|r| r.start_stack);
        let text = self.region_layout.describe_maps(
            stack,
            !rollup,
            root,
            |out, start, end, perm, mapping| {
                if result.is_err() {
                    return;
                }
                let mut area = Totals::default();
                let locked = self.locks.overlaps(start, end);
                for (a, r) in self.anonymous.overlapping(start, end) {
                    let lo = a.max(start);
                    let hi = r.end.min(end);
                    result = r.store.visit_resident(lo, hi, |base| {
                        let owners = self
                            .sparse_pages
                            .borrow()
                            .get(&base)
                            .map_or(1, |p| Arc::strong_count(&p.bytes));
                        area.page(
                            owners,
                            true,
                            true,
                            locked && self.locks.overlaps(base, base + PAGE_SIZE),
                        );
                    });
                    if result.is_err() {
                        return;
                    }
                }
                for (&base, &index) in self.pages.range(start..end) {
                    let p = self.frames[index].as_ref().expect("mapped frame");
                    if p.check_backing(base).is_err() {
                        continue;
                    }
                    match p.charge.page_resident(p.bytes.shared().map(Arc::as_ref)) {
                        Ok(0) => continue,
                        Err(e) => {
                            result = Err(e);
                            return;
                        }
                        _ => {}
                    }
                    let (owners, dirty, anon) = match &p.backing {
                        Some(b) if !b.private_copy => {
                            let pending = self.worker_dirty_backing(base);
                            if pending == Some(true) && !b.shared {
                                (1, true, true)
                            } else {
                                (
                                    b.object
                                        .mapped_residents()
                                        .map_or(1, |m| m.resident_count().max(1)),
                                    b.object.proc_dirty() || pending == Some(false),
                                    false,
                                )
                            }
                        }
                        _ => (Arc::strong_count(&p.bytes), true, true),
                    };
                    area.page(
                        owners,
                        dirty,
                        anon,
                        locked && self.locks.overlaps(base, base + PAGE_SIZE),
                    );
                }
                if rollup {
                    total.add(&area);
                } else {
                    writeln!(
                        out,
                        "Size: {} kB\nKernelPageSize: {} kB\nMMUPageSize: {} kB",
                        (end - start) / 1024,
                        PAGE_SIZE / 1024,
                        PAGE_SIZE / 1024
                    )
                    .unwrap();
                    area.write(out);
                    let shared = mapping.is_some_and(|m| m.shared);
                    let may_write = mapping.is_none_or(|m| m.may_write);
                    out.extend_from_slice(b"VmFlags:");
                    for (flag, on) in [
                        ("rd", perm.read && !mapping.is_some_and(|m| m.write_only)),
                        ("wr", perm.write),
                        ("ex", perm.execute),
                        ("sh", shared && may_write),
                        ("mr", true),
                        ("mw", may_write),
                        ("me", mapping.is_none_or(|m| m.may_execute)),
                        ("ms", shared),
                        ("lo", locked),
                    ] {
                        if on {
                            write!(out, " {flag}").unwrap();
                        }
                    }
                    out.push(b'\n');
                }
            },
        );
        result?;
        if !rollup {
            return Ok(text);
        }
        let Some(first) = self.region_layout.ranges.first() else {
            return Ok(text);
        };
        let end = self.region_layout.ranges.last().unwrap().1;
        let mut out = Vec::new();
        writeln!(
            out,
            "{:08x}-{end:08x} ---p 00000000 00:00 0 [rollup]",
            first.0
        )
        .unwrap();
        total.write(&mut out);
        Ok(out.into())
    }
}

pub type SmapsResult = Result<Arc<[u8]>, MemoryError>;
pub struct SmapsRead {
    rollup: bool,
    root: Option<MappingRoot>,
    body: OnceLock<SmapsResult>,
    event: Arc<Readiness>,
}
impl SmapsRead {
    pub fn result(&self) -> Option<&SmapsResult> {
        self.body.get()
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.event.subscribe(signal)
    }
}
pub(super) type Requests = Mutex<Vec<Weak<SmapsRead>>>;
impl MemoryReport {
    pub fn request_smaps(&self, rollup: bool) -> Arc<SmapsRead> {
        self.request_smaps_at_root(rollup, None)
    }
    pub fn request_smaps_at_root(&self, rollup: bool, root: Option<MappingRoot>) -> Arc<SmapsRead> {
        let r = Arc::new(SmapsRead {
            root,
            rollup,
            body: Default::default(),
            event: Default::default(),
        });
        let mut requests = self.0.smaps.get_or_init(Default::default).lock().unwrap();
        if self.alive() {
            requests.retain(|w| w.strong_count() != 0);
            requests.push(Arc::downgrade(&r));
            drop(requests);
            self.wake_reads();
        } else {
            let _ = r.body.set(Ok(Arc::from([])));
        }
        r
    }
    pub(super) fn requested_smaps(&self) -> bool {
        self.0
            .smaps
            .get()
            .is_some_and(|q| !q.lock().unwrap().is_empty())
    }
    pub(super) fn finish_smaps(&self, mm: Option<&Memory>) {
        let Some(q) = self.0.smaps.get() else {
            return;
        };
        let requests = std::mem::take(&mut *q.lock().unwrap());
        let mut texts = [None, None];
        for r in requests.into_iter().filter_map(|w| w.upgrade()) {
            let render = || {
                mm.map_or_else(
                    || Ok(Arc::from([])),
                    |m| m.smaps_at_root(r.rollup, r.root.as_ref()),
                )
            };
            // Rollups have no file labels. Only unrooted headers can share the default sample.
            let text = if r.rollup || r.root.is_none() {
                texts[usize::from(r.rollup)]
                    .get_or_insert_with(render)
                    .clone()
            } else {
                render()
            };
            let _ = r.body.set(text);
            r.event.notify_locked();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fields(mm: &Memory, rollup: bool) -> BTreeMap<String, u64> {
        let body = mm.smaps(rollup).unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        let mut fields = BTreeMap::new();
        for line in text.lines() {
            if let Some((name, value)) = line.split_once(": ") {
                if let Some(value) = value.strip_suffix(" kB") {
                    *fields.entry(name.to_string()).or_default() += value.parse::<u64>().unwrap();
                }
            }
        }
        fields
    }
    #[test]
    fn sparse_census_never_populates_or_pins_pages_and_tracks_fork_and_cow() {
        let mut parent = Memory::default();
        parent.map(PAGE_SIZE, 1 << 38, Permissions::RW).unwrap();
        assert_eq!(fields(&parent, false)["Rss"], 0);
        assert_eq!(parent.resident_bytes(), 0);
        assert!(parent.sparse_pages.borrow().is_empty());
        parent.write(PAGE_SIZE, &[1]).unwrap();
        parent.write(1 << 36, &[1]).unwrap();
        let mut child = parent.try_fork().unwrap();
        for mm in [&child, &parent] {
            let stats = fields(mm, true);
            assert_eq!(
                (stats["Rss"], stats["Pss"], stats["Shared_Dirty"]),
                (8, 4, 8)
            );
            assert_eq!(stats["Anonymous"], 8);
        }
        child.write(PAGE_SIZE, &[2]).unwrap();
        for mm in [&child, &parent] {
            let stats = fields(mm, false);
            assert_eq!(
                (stats["Rss"], stats["Pss"], stats["Private_Dirty"]),
                (8, 6, 4)
            );
            assert_eq!(fields(mm, true)["Pss"], stats["Pss"]);
        }
        drop(child);
        assert_eq!(fields(&parent, true)["Private_Dirty"], 8);
    }

    #[test]
    fn shmem_proportional_residency_follows_mapping_lifetimes() {
        let mut mm = Memory::default();
        mm.map_shared_anonymous(PAGE_SIZE, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        mm.write(PAGE_SIZE, &[1]).unwrap();
        let mut child = mm.try_fork().unwrap();
        for m in [&mm, &child] {
            let stats = fields(m, true);
            assert_eq!(
                (
                    stats["Rss"],
                    stats["Pss"],
                    stats["Shared_Dirty"],
                    stats["Anonymous"]
                ),
                (4, 2, 4, 0)
            );
        }
        child.unmap(PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(fields(&mm, true)["Private_Dirty"], 4);
        assert_eq!(fields(&mm, true)["Pss"], 4);
    }
}
