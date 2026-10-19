// SPDX-License-Identifier: GPL-3.0-or-later
//! Enumerate immediate children without walking every descendant in a flat map.
use std::collections::{btree_map::Range, BTreeMap};

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
