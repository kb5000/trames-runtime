// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold VMA metadata. Ordinary unnamed private mappings need no extra entry.
use super::*;
use std::io::Write;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingFileInfo {
    pub device: u64,
    pub inode: u64,
    pub path: Arc<[u8]>,
    /// Original mount for a filesystem-relative path. Executable image labels
    /// may already have been rendered relative to the executing task.
    pub path_mount: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct MappingRoot {
    pub mount: u64,
    pub path: Arc<[u8]>,
}
impl MappingRoot {
    fn visible<'a>(&self, file: &'a MappingFileInfo) -> &'a [u8] {
        if file.path_mount != Some(self.mount) || self.path.as_ref() == b"/" {
            return &file.path;
        }
        file.path
            .strip_prefix(self.path.as_ref())
            .filter(|relative| relative.starts_with(b"/"))
            .unwrap_or(&file.path)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum Origin {
    Private,
    Stack,
    SharedAnon(u64),
    File(MappingFileInfo),
    Other,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Mapping {
    pub end: u64,
    pub offset: u64,
    pub origin: Origin,
    pub shared: bool,
    pub write_only: bool,
    pub may_write: bool,
    pub may_execute: bool,
    pub name: Option<Arc<[u8]>>,
}
impl Mapping {
    fn private(end: u64) -> Self {
        Self {
            end,
            offset: 0,
            origin: Origin::Private,
            shared: false,
            write_only: false,
            may_write: true,
            may_execute: true,
            name: None,
        }
    }
    fn redundant(&self) -> bool {
        matches!(self.origin, Origin::Private) && self.name.is_none() && !self.write_only
    }
    fn joins(&self, base: u64, next: &Self) -> bool {
        self.origin == next.origin
            && !matches!(self.origin, Origin::Other)
            && self.name == next.name
            && self.shared == next.shared
            && self.write_only == next.write_only
            && self.may_write == next.may_write
            && self.may_execute == next.may_execute
            && (matches!(self.origin, Origin::Private)
                || self.offset.checked_add(self.end - base) == Some(next.offset))
    }
    fn slice(&self, base: u64, start: u64, end: u64) -> Self {
        Self {
            end,
            offset: self.offset + (start - base),
            ..self.clone()
        }
    }
}

#[derive(Default, Clone)]
pub(super) struct Mappings(Option<Arc<Vec<(u64, Mapping)>>>);
impl Mappings {
    fn spans(&self) -> &[(u64, Mapping)] {
        self.0.as_deref().map_or(&[], Vec::as_slice)
    }
    fn overlap(&self, start: u64, end: u64) -> std::ops::Range<usize> {
        let spans = self.spans();
        if spans.last().is_none_or(|(_, m)| m.end <= start) {
            return spans.len()..spans.len();
        }
        let first = spans.partition_point(|(_, m)| m.end <= start);
        let count = spans[first..].partition_point(|(a, _)| *a < end);
        first..first + count
    }
    pub fn remove(&mut self, start: u64, end: u64) {
        let overlap = self.overlap(start, end);
        if overlap.is_empty() {
            return;
        }
        let spans = Arc::make_mut(self.0.as_mut().unwrap());
        let (base, first) = &spans[overlap.start];
        let left = (*base < start).then(|| (*base, first.slice(*base, *base, start)));
        let (base, last) = &spans[overlap.end - 1];
        let right = (last.end > end).then(|| (end, last.slice(*base, end, last.end)));
        spans.splice(overlap, left.into_iter().chain(right));
        if spans.is_empty() {
            self.0 = None;
        }
    }
    pub fn insert(&mut self, mut start: u64, mut mapping: Mapping) {
        self.remove(start, mapping.end);
        if mapping.redundant() {
            return;
        }
        let spans = Arc::make_mut(self.0.get_or_insert_with(Arc::default));
        let index = spans.partition_point(|(a, _)| *a < start);
        let mut first = index;
        let mut last = index;
        if let Some((base, prev)) = index.checked_sub(1).and_then(|i| spans.get(i)) {
            if prev.end == start && prev.joins(*base, &mapping) {
                start = *base;
                mapping.offset = prev.offset;
                first -= 1;
            }
        }
        if let Some((_, next)) = spans
            .get(index)
            .filter(|(a, m)| *a == mapping.end && mapping.joins(start, m))
        {
            mapping.end = next.end;
            last += 1;
        }
        spans.splice(first..last, [(start, mapping)]);
    }
    pub fn moved(&self, old: u64, len: u64, new: u64, new_len: u64) -> Vec<(u64, Mapping)> {
        self.spans()[self.overlap(old, old + len.min(new_len))]
            .iter()
            .map(|(base, m)| {
                let start = (*base).max(old);
                let end = m.end.min(old + len.min(new_len));
                let mut part = m.slice(*base, start, end);
                part.end = if end == old + len && new_len > len {
                    new + new_len
                } else {
                    new + (end - old)
                };
                (new + (start - old), part)
            })
            .collect()
    }
    pub fn extend(&mut self, other: Vec<(u64, Mapping)>) {
        for (a, m) in other {
            self.insert(a, m);
        }
    }
    fn pieces(&self, start: u64, end: u64, mut f: impl FnMut(u64, u64, Option<(u64, &Mapping)>)) {
        let mut cursor = start;
        for &(base, ref m) in &self.spans()[self.overlap(start, end)] {
            if base > cursor {
                f(cursor, base, None);
            }
            let stop = m.end.min(end);
            f(cursor.max(base), stop, Some((base, m)));
            cursor = stop;
        }
        if cursor < end {
            f(cursor, end, None);
        }
    }
}

impl Memory {
    /// ARM permits loads through writable mappings. Procfs reports the requested VMA flags.
    pub fn report_write_only(&mut self, start: u64, len: u64, enabled: bool) {
        if let Some(mm) = &self.shared {
            return mm.borrow_mut().report_write_only(start, len, enabled);
        }
        if !enabled && self.region_layout.origins.0.is_none() {
            return;
        }
        let end = start + len;
        let mut edits = Vec::new();
        self.region_layout
            .origins
            .pieces(start, end, |lo, hi, entry| {
                if entry.is_some_and(|(_, m)| m.write_only) != enabled {
                    let mut m = entry
                        .map_or_else(|| Mapping::private(hi), |(base, m)| m.slice(base, lo, hi));
                    m.write_only = enabled;
                    edits.push((lo, m));
                }
            });
        self.apply_proc_edits(edits);
    }
    fn apply_proc_edits(&mut self, edits: Vec<(u64, Mapping)>) {
        if !edits.is_empty() {
            let origins = &mut Arc::make_mut(&mut self.region_layout).origins;
            for (a, m) in edits {
                origins.insert(a, m);
            }
            self.advance_layout_revision();
        }
    }
    /// The initial Linux stack is a distinct VMA even next to another private RW map.
    pub fn map_initial_stack(&mut self, start: u64, length: u64) -> Result<(), MemoryError> {
        if let Some(mm) = &self.shared {
            return mm.borrow_mut().map_initial_stack(start, length);
        }
        self.map(start, length, Permissions::RW)?;
        Arc::make_mut(&mut self.region_layout).origins.insert(
            start,
            Mapping {
                origin: Origin::Stack,
                ..Mapping::private(start + length)
            },
        );
        self.advance_layout_revision();
        Ok(())
    }
    /// Records file provenance for private pages populated by the ELF loader.
    pub fn record_image_file(
        &mut self,
        start: u64,
        length: u64,
        offset: u64,
        file: MappingFileInfo,
    ) {
        if let Some(mm) = &self.shared {
            return mm
                .borrow_mut()
                .record_image_file(start, length, offset, file);
        }
        let end = start.checked_add(length).expect("validated image range");
        Arc::make_mut(&mut self.region_layout).origins.insert(
            start,
            Mapping {
                offset,
                origin: Origin::File(file),
                ..Mapping::private(end)
            },
        );
        self.advance_layout_revision();
    }
    /// PR_SET_VMA_ANON_NAME operates on mapping metadata only.
    pub fn name_anonymous(
        &mut self,
        start: u64,
        len: u64,
        name: Option<Arc<[u8]>>,
    ) -> Result<(), MemoryError> {
        if let Some(mm) = &self.shared {
            return mm.borrow_mut().name_anonymous(start, len, name);
        }
        let end = Self::mapping_end(start, len)?;
        let mut cursor = start;
        let mut result = Ok(());
        let mut hole = None;
        let mut edits = Vec::new();
        let layout = &self.region_layout;
        let first = layout.ranges.partition_point(|r| r.1 <= start);
        for &(a, b, _) in &layout.ranges[first..] {
            if a >= end {
                break;
            }
            if a > cursor {
                hole.get_or_insert(cursor);
                cursor = a;
            }
            layout.origins.pieces(cursor, b.min(end), |lo, hi, entry| {
                if result.is_err() {
                    return;
                }
                let mut m = match entry {
                    Some((base, m))
                        if matches!(
                            m.origin,
                            Origin::Private | Origin::Stack | Origin::SharedAnon(_)
                        ) =>
                    {
                        m.slice(base, lo, hi)
                    }
                    Some(_) => {
                        result = Err(MemoryError::BackingIo(9));
                        return;
                    }
                    None => Mapping::private(hi),
                };
                if m.name != name {
                    m.name = name.clone();
                    edits.push((lo, m));
                }
            });
            cursor = b.min(end);
            if result.is_err() || cursor == end {
                break;
            }
        }
        self.apply_proc_edits(edits);
        result?;
        if let Some(missing) = hole.or_else(|| (cursor != end).then_some(cursor)) {
            return Err(MemoryError::Unmapped(missing));
        }
        Ok(())
    }
}
impl super::report::RegionLayout {
    pub(super) fn vm_sizes(&self) -> super::report::VmSizes {
        let mut sizes = super::report::VmSizes::default();
        for &(a, b, perm) in &self.ranges {
            self.origins.pieces(a, b, |start, end, entry| {
                let mapping = entry.map(|(_, m)| m);
                if mapping.is_some_and(|m| matches!(m.origin, Origin::Stack)) {
                    sizes.stack += end - start;
                } else if perm.execute && !perm.write {
                    sizes.executable += end - start;
                } else if perm.write && !mapping.is_some_and(|m| m.shared) {
                    sizes.data += end - start;
                }
            });
        }
        sizes
    }
    pub(super) fn maps(&self, stack: Option<u64>) -> Arc<[u8]> {
        self.describe_maps(stack, true, None, |_, _, _, _, _| {})
    }
    pub(super) fn describe_maps(
        &self,
        stack: Option<u64>,
        headers: bool,
        root: Option<&MappingRoot>,
        mut visit: impl FnMut(&mut Vec<u8>, u64, u64, Permissions, Option<&Mapping>),
    ) -> Arc<[u8]> {
        let mut text = Vec::new();
        for &(a, b, perm) in &self.ranges {
            self.origins.pieces(a, b, |start, end, entry| {
                let m = entry.map(|(_, m)| m);
                if headers {
                    let (dev, inode, offset) = match entry {
                        Some((base, m)) => match &m.origin {
                            Origin::File(f) => (f.device, f.inode, m.offset + (start - base)),
                            Origin::SharedAnon(id) => (1, *id, m.offset + (start - base)),
                            _ => (0, 0, 0),
                        },
                        None => (0, 0, 0),
                    };
                    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
                    let minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
                    let line = text.len();
                    write!(
                    text,
                    "{start:08x}-{end:08x} {}{}{}{} {offset:08x} {major:02x}:{minor:02x} {inode} ",
                    if perm.read && !m.is_some_and(|m| m.write_only) {
                        'r'
                    } else {
                        '-'
                    },
                    if perm.write { 'w' } else { '-' },
                    if perm.execute { 'x' } else { '-' },
                    if m.is_some_and(|m| m.shared) {
                        's'
                    } else {
                        'p'
                    }
                )
                    .unwrap();
                    let label: &[u8] = match m {
                        Some(Mapping {
                            origin: Origin::File(f),
                            ..
                        }) => root.map_or(f.path.as_ref(), |r| r.visible(f)),
                        Some(Mapping {
                            origin: Origin::SharedAnon(_),
                            name: None,
                            ..
                        }) => b"/dev/zero (deleted)",
                        Some(Mapping {
                            origin: Origin::SharedAnon(_),
                            name: Some(_),
                            ..
                        }) => b"[anon_shmem:",
                        Some(Mapping { name: Some(_), .. }) => b"[anon:",
                        _ if stack.is_some_and(|sp| start <= sp && sp < end) => b"[stack]",
                        _ => b"",
                    };
                    if !label.is_empty() {
                        text.resize(text.len().max(line + 73), b' ');
                        for &byte in label {
                            if byte == b'\n' {
                                text.extend_from_slice(b"\\012");
                            } else {
                                text.push(byte);
                            }
                        }
                        if let Some(name) = m.and_then(|m| m.name.as_ref()) {
                            text.extend_from_slice(name);
                            text.push(b']');
                        }
                    }
                    text.push(b'\n');
                }
                visit(&mut text, start, end, perm, m);
            });
        }
        text.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maps(mm: &Memory) -> String {
        String::from_utf8(mm.memory_report().maps().to_vec()).unwrap()
    }

    #[test]
    fn virtual_data_and_stack_follow_mapping_changes_without_faulting_pages() {
        let mut mm = Memory::default();
        let p = PAGE_SIZE;
        mm.map_initial_stack(p, 2 * p).unwrap();
        mm.map(3 * p, 2 * p, Permissions::RW).unwrap();
        mm.map_shared_anonymous(5 * p, p, Permissions::RW, false)
            .unwrap();
        let report = mm.memory_report();
        let resident = report.resident_bytes();
        assert_eq!(
            report.vm_sizes(),
            VmSizes {
                executable: 0,
                data: 2 * p,
                stack: 2 * p
            }
        );
        assert_eq!(report.resident_bytes(), resident);
        let mut child = mm.clone();
        child.protect(3 * p, p, Permissions::RX).unwrap();
        child.map_fixed(p, p, Permissions::RW).unwrap();
        assert_eq!(
            child.memory_report().vm_sizes(),
            VmSizes {
                executable: p,
                data: 2 * p,
                stack: p
            }
        );
        child.unmap(2 * p, p).unwrap();
        assert_eq!(
            child.memory_report().vm_sizes(),
            VmSizes {
                executable: p,
                data: 2 * p,
                stack: 0
            }
        );
        assert_eq!(
            report.vm_sizes(),
            VmSizes {
                executable: 0,
                data: 2 * p,
                stack: 2 * p
            }
        );
    }

    #[test]
    fn names_follow_aliases_remaps_and_fork_without_changing_memory_access() {
        let mut mm = Memory::default();
        let p = PAGE_SIZE;
        mm.map_shared_anonymous(p, 3 * p, Permissions::RW, false)
            .unwrap();
        mm.name_anonymous(p, p, Some(Arc::from(&b"video"[..])))
            .unwrap();
        mm.report_write_only(p, p, true);
        mm.write_array(p, [8u8]).unwrap();
        assert_eq!(mm.read_array::<1>(p).unwrap(), [8]);
        mm.alias_shared_mapping(p, 8 * p, p).unwrap();
        let mut child = mm.clone();
        child.remap(8 * p, p, 12 * p, p, false).unwrap();
        child.name_anonymous(12 * p, p, None).unwrap();
        assert!(maps(&mm)
            .lines()
            .any(|s| s.starts_with("00008000-00009000 -w-s") && s.ends_with("[anon_shmem:video]")));
        assert!(
            maps(&child)
                .lines()
                .any(|s| s.starts_with("0000c000-0000d000 -w-s")
                    && s.ends_with("/dev/zero (deleted)"))
        );
        mm.map_fixed(p, p, Permissions::R).unwrap();
        assert!(maps(&mm).contains("00001000-00002000 r--p 00000000 00:00 0 \n"));
        assert!(maps(&mm).contains("00002000-00004000 rw-s 00001000"));
    }

    #[test]
    fn names_cross_protection_boundaries_and_apply_on_both_sides_of_a_hole() {
        let mut mm = Memory::default();
        let p = PAGE_SIZE;
        mm.map(p, 5 * p, Permissions::RW).unwrap();
        mm.protect(2 * p, p, Permissions::R).unwrap();
        mm.unmap(3 * p, p).unwrap();
        let name: Arc<[u8]> = Arc::from(&b"buffer"[..]);
        assert_eq!(
            mm.name_anonymous(p, 5 * p, Some(name)),
            Err(MemoryError::Unmapped(3 * p))
        );
        assert_eq!(maps(&mm).matches("[anon:buffer]").count(), 3);
        mm.protect(2 * p, p, Permissions::RW).unwrap();
        assert_eq!(maps(&mm).matches("[anon:buffer]").count(), 2);
        mm.name_anonymous(p, 2 * p, None).unwrap();
        assert_eq!(maps(&mm).matches("[anon:buffer]").count(), 1);
    }
}
