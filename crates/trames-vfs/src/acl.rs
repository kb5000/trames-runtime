// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux POSIX ACL xattrs, original inode permissions and creation inheritance.
//! ACL bytes live in existing persistent inode metadata. Ordinary mode-only
//! files need no ACL allocation, lock, service or separate authority ledger.
use super::*;
pub(super) const ACCESS: &[u8] = b"system.posix_acl_access";
pub(super) const DEFAULT: &[u8] = b"system.posix_acl_default";
pub(super) fn name(name: &[u8]) -> bool {
    name == ACCESS || name == DEFAULT
}
fn entries(bytes: &[u8]) -> impl Iterator<Item = (u16, u32, u32)> + '_ {
    bytes[4..].chunks_exact(8).map(|e| {
        (
            u16::from_le_bytes(e[..2].try_into().unwrap()),
            u16::from_le_bytes(e[2..4].try_into().unwrap()) as u32,
            u32::from_le_bytes(e[4..8].try_into().unwrap()),
        )
    })
}
pub(super) fn validate(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 4 || (bytes.len() - 4) % 8 != 0 || bytes[..4] != 2u32.to_le_bytes() {
        return Err(Errno(22));
    }
    if bytes.len() == 4 {
        return Ok(());
    }
    let (mut state, mut named, mut mask) = (0, false, false);
    for (tag, perm, id) in entries(bytes) {
        if perm > 7 {
            return Err(Errno(22));
        }
        match tag {
            1 if state == 0 => state = 1,
            2 if state == 1 && id != u32::MAX => named = true,
            4 if state == 1 => state = 2,
            8 if state == 2 && id != u32::MAX => named = true,
            16 if state == 2 => {
                state = 3;
                mask = true;
            }
            32 if state == 3 || state == 2 && !named => state = 4,
            _ => return Err(Errno(22)),
        }
    }
    if state != 4 || named && !mask {
        return Err(Errno(22));
    }
    Ok(())
}
pub(super) fn normalize(bytes: &mut [u8]) {
    for e in bytes[4..].chunks_exact_mut(8) {
        if !matches!(u16::from_le_bytes(e[..2].try_into().unwrap()), 2 | 8) {
            e[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        }
    }
}
pub(super) fn mode(bytes: &[u8], mode: u32) -> u32 {
    let mut bits = 0;
    for (tag, p, _) in entries(bytes) {
        match tag {
            1 => bits |= p << 6,
            4 => bits |= p << 3,
            16 => bits = (bits & !0o70) | (p << 3),
            32 => bits |= p,
            _ => {}
        }
    }
    (mode & !0o777) | bits
}
pub(super) fn extended(bytes: &[u8]) -> bool {
    entries(bytes).any(|(tag, _, _)| matches!(tag, 2 | 8 | 16))
}
pub(super) fn chmod(bytes: &mut [u8], mode: u32, intersect: bool) {
    let has_mask = entries(bytes).any(|(tag, _, _)| tag == 16);
    for e in bytes[4..].chunks_exact_mut(8) {
        let tag = u16::from_le_bytes(e[..2].try_into().unwrap());
        let p = match tag {
            1 => mode >> 6,
            4 if !has_mask => mode >> 3,
            16 => mode >> 3,
            32 => mode,
            _ => continue,
        } & 7;
        let old = u16::from_le_bytes(e[2..4].try_into().unwrap()) as u32;
        e[2..4].copy_from_slice(&(if intersect { old & p } else { p } as u16).to_le_bytes());
    }
}
pub(super) fn inherit(
    parent: Option<&Node>,
    content: &Content,
    mode: &mut u32,
    umask: u32,
    create: bool,
) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut attrs = BTreeMap::new();
    if !create || matches!(content, Content::Symlink(_)) {
        return attrs;
    }
    if let Some(default) = parent.and_then(|p| p.xattrs.get(DEFAULT)) {
        let mut access = default.clone();
        chmod(&mut access, *mode, true);
        *mode = self::mode(&access, *mode);
        if extended(&access) {
            attrs.insert(ACCESS.to_vec(), access);
        }
        if matches!(content, Content::Directory) {
            attrs.insert(DEFAULT.to_vec(), default.clone());
        }
    } else {
        *mode &= !umask;
    }
    attrs
}
pub(super) fn allows(bytes: &[u8], node: &Node, c: &Credentials, want: u32) -> bool {
    let mask = entries(bytes)
        .find(|(tag, _, _)| *tag == 16)
        .map_or(7, |(_, p, _)| p);
    let mut group = false;
    for (tag, p, id) in entries(bytes) {
        match tag {
            1 if c.fsuid == node.uid => return p & want == want,
            2 if c.fsuid == id => return p & mask & want == want,
            4 | 8 if c.in_group(if tag == 4 { node.gid } else { id }) => {
                group = true;
                // Linux requires one matching group entry to cover the request;
                // a denied group class never falls through to OTHER permissions.
                if p & want == want {
                    return p & mask & want == want;
                }
            }
            32 => return !group && p & want == want,
            _ => {}
        }
    }
    false
}
#[cfg(test)]
mod tests;
