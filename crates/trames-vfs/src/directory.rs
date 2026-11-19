// SPDX-License-Identifier: GPL-3.0-or-later
//! Enumerate immediate children without walking every descendant in a flat map.
use std::collections::{btree_map::Range, BTreeMap};

/// Serialize parent mtime/ctime with explicit metadata changes. Acquire before
/// taking the filesystem write guard, and never hold an inode data borrow
/// while the store serializes its manifest. Atime is independent.
pub(super) struct EntryTimes<'a> {
    parents: [Option<&'a super::Inode>; 2],
    _guards: [Option<std::sync::MutexGuard<'a, ()>>; 2],
}
impl<'a> EntryTimes<'a> {
    pub fn lock(first: Option<&'a super::Inode>, second: Option<&'a super::Inode>) -> Self {
        let mut parents = [first, second];
        if let (Some(a), Some(b)) = (first, second) {
            if std::ptr::eq(a, b) {
                parents[1] = None;
            } else if a.identity > b.identity {
                parents.swap(0, 1);
            }
        }
        let guards = parents.map(|p| p.map(|n| n.metadata.lock().unwrap()));
        Self {
            parents,
            _guards: guards,
        }
    }
    pub fn commit(
        &self,
        now: super::storage::Timestamp,
        persist: impl FnOnce() -> super::Result<()>,
    ) -> super::Result<()> {
        let previous = self.parents.map(|parent| {
            parent.map(|p| {
                // A parent is a directory. Updating its own timestamps has no
                // file data, length or quota change to publish.
                let mut n = p.state.borrow_mut();
                let old = [n.times[1], n.times[2]];
                n.times[1..].fill(now);
                old
            })
        });
        if let Err(error) = persist() {
            for (parent, old) in self.parents.into_iter().zip(previous) {
                if let (Some(parent), Some(old)) = (parent, old) {
                    parent.state.borrow_mut().times[1..].copy_from_slice(&old);
                }
            }
            return Err(error);
        }
        Ok(())
    }
}

/// Return owned child metadata before the caller resolves any parent/mount
/// paths. A resolver can acquire this same namespace lock again; keeping its
/// calls outside this scope avoids recursive reads behind a queued writer.
pub(super) fn metadata(filesystem: &super::FsHandle, key: &[u8]) -> BTreeMap<Vec<u8>, (u64, u8)> {
    let fs = filesystem.borrow();
    children(&fs.paths, key)
        .map(|(name, node)| {
            let node = node.borrow();
            (
                name.to_vec(),
                (node.inode, ((node.mode & 0o170000) >> 12) as u8),
            )
        })
        .collect()
}

pub(super) type CopyDirents<'a> = dyn FnMut(usize, &[u8]) -> super::Result<()> + 'a;

/// File descriptor numbers are stable readdir cookies even when an application
/// closes each fd as it enumerates procfs.
pub(super) fn proc_fds(path: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(b"/proc/") else {
        return false;
    };
    let mut parts = rest.split(|&b| b == b'/');
    parts.next();
    let mut leaf = parts.next();
    if leaf == Some(b"task") {
        parts.next();
        leaf = parts.next();
    }
    matches!(leaf, Some(b"fd" | b"fdinfo")) && parts.next().is_none()
}

/// Commit the shared description's position only through the last record the
/// guest received. The normal case copies the assembled output in one call.
pub(super) fn encode(
    position: &super::file_data::FilePosition,
    count: usize,
    dots: (u64, u64),
    children: BTreeMap<Vec<u8>, (u64, u8)>,
    numbered: bool,
    copy: &mut CopyDirents<'_>,
) -> super::Result<Vec<u8>> {
    let mut entries = Vec::with_capacity(children.len() + 2);
    entries.push((0, b".".to_vec(), dots.0, 4u8));
    entries.push((1, b"..".to_vec(), dots.1, 4));
    for (i, (name, (inode, kind))) in children.into_iter().enumerate() {
        let index = if numbered {
            let Ok(fd) = std::str::from_utf8(&name).unwrap_or("").parse::<u32>() else {
                continue;
            };
            u64::from(fd)
        } else {
            i as u64
        };
        entries.push((index + 2, name, inode, kind));
    }
    if numbered {
        entries[2..].sort_unstable_by_key(|e| e.0);
    }
    let mut cursor = position.lock().unwrap();
    let first = if numbered {
        entries.partition_point(|e| e.0 < cursor.value)
    } else {
        (cursor.value as usize).min(entries.len())
    };
    let mut out = Vec::new();
    let mut next = cursor.value;
    for (cookie, name, inode, kind) in &entries[first..] {
        let size = (19 + name.len() + 1 + 7) & !7;
        if out.len() + size > count {
            if out.is_empty() {
                return Err(super::Errno(22));
            }
            break;
        }
        next = cookie + 1;
        let start = out.len();
        out.resize(start + size, 0);
        out[start..start + 8].copy_from_slice(&inode.to_le_bytes());
        out[start + 8..start + 16].copy_from_slice(&next.to_le_bytes());
        out[start + 16..start + 18].copy_from_slice(&(size as u16).to_le_bytes());
        out[start + 18] = *kind;
        out[start + 19..start + 19 + name.len()].copy_from_slice(name);
    }
    if !out.is_empty() && copy(0, &out).is_err() {
        let mut start = 0;
        while start < out.len() {
            let size = u16::from_le_bytes(out[start + 16..start + 18].try_into().unwrap());
            let end = start + usize::from(size);
            if let Err(error) = copy(start, &out[start..end]) {
                if start == 0 {
                    return Err(error);
                }
                out.truncate(start);
                break;
            }
            next = u64::from_le_bytes(out[start + 8..start + 16].try_into().unwrap());
            start = end;
        }
    }
    cursor.value = next;
    Ok(out)
}

pub(super) struct Children<'a, T> {
    paths: &'a BTreeMap<Vec<u8>, T>,
    range: Range<'a, Vec<u8>, T>,
    prefix: Vec<u8>,
    #[cfg(test)]
    visited: usize,
}
pub(super) fn children<'a, T>(
    paths: &'a BTreeMap<Vec<u8>, T>,
    directory: &[u8],
) -> Children<'a, T> {
    let mut prefix = directory.to_vec();
    if prefix != b"/" {
        prefix.push(b'/');
    }
    Children {
        paths,
        range: paths.range(prefix.clone()..),
        prefix,
        #[cfg(test)]
        visited: 0,
    }
}
impl<'a, T> Iterator for Children<'a, T> {
    type Item = (&'a [u8], &'a T);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (path, value) = self.range.next()?;
            #[cfg(test)]
            {
                self.visited += 1;
            }
            if !path.starts_with(&self.prefix) {
                return None;
            }
            let name = &path[self.prefix.len()..];
            if let Some(slash) = name.iter().position(|&b| b == b'/') {
                // Skip precisely "prefix/component/" and its descendants.
                // Siblings like component-, component. sort before this subtree
                // and have already been visited; component0 remains included.
                let mut after = path[..self.prefix.len() + slash].to_vec();
                after.push(b'0');
                self.range = self.paths.range(after..);
                continue;
            }
            if !name.is_empty() {
                return Some((name, value));
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immediate_children_preserve_byte_order_and_prefix_siblings() {
        let names = [
            b"/a".as_slice(),
            b"/a-",
            b"/a.",
            b"/a/x/deep",
            b"/a/y",
            b"/a0",
            b"/a\xff",
            b"/other/item",
            b"/other/item/deep",
            b"/other/item0",
            b"/",
        ];
        let paths: BTreeMap<_, _> = names
            .into_iter()
            .enumerate()
            .map(|(n, p)| (p.to_vec(), n))
            .collect();
        for directory in [b"/".as_slice(), b"/a", b"/other", b"/missing"] {
            let prefix = if directory == b"/" {
                directory.to_vec()
            } else {
                [directory, b"/"].concat()
            };
            let expected: Vec<_> = paths
                .iter()
                .filter_map(|(path, n)| {
                    let name = path.strip_prefix(prefix.as_slice())?;
                    (!name.is_empty() && !name.contains(&b'/')).then_some((name, n))
                })
                .collect();
            assert_eq!(children(&paths, directory).collect::<Vec<_>>(), expected);
        }
    }
    #[test]
    fn root_enumeration_skips_a_large_nested_tree() {
        let mut paths = BTreeMap::from([
            (b"/".to_vec(), 0),
            (b"/tree".to_vec(), 0),
            (b"/tree0".to_vec(), 0),
        ]);
        for n in 0..10000 {
            paths.insert(format!("/tree/deep/{n:05}").into_bytes(), n);
        }
        let mut list = children(&paths, b"/");
        assert_eq!(
            list.by_ref()
                .map(|(name, _)| name.to_vec())
                .collect::<Vec<_>>(),
            [b"tree".to_vec(), b"tree0".to_vec()]
        );
        assert!(
            list.visited < 10,
            "must skip descendants, visited {}",
            list.visited
        );
    }
}
