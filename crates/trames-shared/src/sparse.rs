// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned memfds have a Linux file offset space even when a single host inode
//! cannot extend that far. Keep the original descriptor for native consumers.
//! Allocate additional unlinked inodes only when a distant window is touched.
use super::*;
use std::ops::Range;

pub(super) const WINDOW: usize = 1 << 40;
#[derive(Default)]
pub(super) struct Windows(Mutex<BTreeMap<usize, Arc<File>>>);

impl Windows {
    pub(super) fn get(&self, base: usize, create: bool) -> io::Result<Option<Arc<File>>> {
        let mut files = self.0.lock().map_err(lock_error)?;
        if let Some(file) = files.get(&base) {
            return Ok(Some(file.clone()));
        }
        if !create {
            return Ok(None);
        }
        let file = anonymous_file()?;
        file.set_len(WINDOW as u64)?;
        let file = Arc::new(file);
        files.insert(base, file.clone());
        Ok(Some(file))
    }

    pub(super) fn clear(&self, start: usize, end: usize) -> io::Result<()> {
        let files = self.0.lock().map_err(lock_error)?;
        for (&base, file) in files.range((start & !(WINDOW - 1))..end) {
            let from = start.saturating_sub(base);
            SharedFile::clear_file_range(file, from, (end - base).min(WINDOW) - from)?;
        }
        Ok(())
    }
}

/// Page charges in byte-offset order. Reserving a sparse range costs time
/// proportional to its overlapping extents, including when quota rejects it.
#[derive(Default)]
pub(super) struct Charges(BTreeMap<usize, usize>);
impl Charges {
    pub(super) fn extension(&self, range: Range<usize>) -> Option<(Range<usize>, usize)> {
        let first = self.0.range(..=range.start).next_back();
        if first.is_some_and(|(_, &end)| end >= range.end) {
            return None;
        }
        let start = first
            .filter(|(_, &end)| end >= range.start)
            .map_or(range.start, |(&start, _)| start);
        let mut end = range.end;
        let mut covered = 0;
        for (&from, &to) in self.0.range(start..=range.end) {
            covered += to - from;
            end = end.max(to);
        }
        let extra = (end - start) - covered;
        Some((start..end, extra))
    }
    pub(super) fn insert(&mut self, range: Range<usize>) {
        while let Some((&key, _)) = self.0.range(range.clone()).next() {
            self.0.remove(&key);
        }
        self.0.insert(range.start, range.end);
    }
}

impl SharedFile {
    fn visit_windows(
        &self,
        offset: usize,
        length: usize,
        create: bool,
        mut visit: impl FnMut(Option<&File>, usize, usize, usize) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut done = 0;
        while done < length {
            let at = offset + done;
            let base = at & !(WINDOW - 1);
            let local = at - base;
            let n = (length - done).min(WINDOW - local);
            if base == 0 {
                visit(Some(&self.0.file), local, done, n)?;
            } else {
                let file = self.0.windows.get(base, create)?;
                visit(file.as_deref(), local, done, n)?;
            }
            done += n;
        }
        Ok(())
    }
    pub(super) fn read_windows(&self, offset: usize, out: &mut [u8]) -> io::Result<()> {
        self.visit_windows(offset, out.len(), false, |file, local, done, n| {
            if let Some(file) = file {
                file.read_exact_at(&mut out[done..done + n], local as u64)?;
            }
            Ok(()) // The caller supplied a zeroed buffer for holes.
        })
    }
    pub(super) fn map_region(&self, start: usize, len: usize) -> io::Result<Region> {
        if len > isize::MAX as usize {
            return Err(invalid());
        }
        let across = self.0.owned && (start / WINDOW != (start + len - 1) / WINDOW);
        let backing = if across {
            None
        } else if self.0.owned && start >= WINDOW {
            self.0.windows.get(start & !(WINDOW - 1), true)?
        } else {
            None
        };
        let (prot, flags, fd, at) = if across {
            (libc::PROT_NONE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0)
        } else {
            let file = backing.as_deref().unwrap_or(&self.0.file);
            (
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                if backing.is_some() {
                    start % WINDOW
                } else {
                    start
                },
            )
        };
        // SAFETY: the OS chooses a fresh range. Native offsets are page aligned
        // inside a backing file that outlives the complete mapping.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                flags,
                fd,
                at as libc::off_t,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let region = Region {
            pointer: NonNull::new(ptr.cast()).expect("non-null mmap"),
            length: len,
            _owner: self.0.clone(),
        };
        if across {
            self.visit_windows(start, len, true, |file, local, done, n| {
                // SAFETY: MAP_FIXED replaces only page-aligned subranges of our
                // own unpublished reservation. Region unmaps it all on any error.
                let mapped = unsafe {
                    libc::mmap(
                        region.pointer.as_ptr().add(done).cast(),
                        n,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_FIXED | libc::MAP_SHARED,
                        file.unwrap().as_raw_fd(),
                        local as libc::off_t,
                    )
                };
                if mapped == libc::MAP_FAILED {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            })?;
        }
        Ok(region)
    }
}
