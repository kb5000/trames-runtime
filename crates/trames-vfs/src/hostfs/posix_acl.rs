// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux retains native POSIX ACL enforcement and inheritance. Only ABI IDs
//! cross the host grant's owner mapping and the calling guest user namespace.
use super::*;

fn map_ids(bytes: &mut [u8], mut map: impl FnMut(bool, u32) -> Result<u32>) -> Result<()> {
    acl::decode(bytes)?;
    acl::normalize(bytes);
    for entry in bytes[4..].chunks_exact_mut(8) {
        let tag = u16::from_le_bytes(entry[..2].try_into().unwrap());
        if matches!(tag, 2 | 8) {
            let id = u32::from_le_bytes(entry[4..8].try_into().unwrap());
            entry[4..8].copy_from_slice(&map(tag == 8, id)?.to_le_bytes());
        }
    }
    Ok(())
}
fn from_native(file: &OpenFile, bytes: &mut [u8]) -> Result<()> {
    map_ids(bytes, |group, id| {
        let (native, guest) = if group { file.root.gid } else { file.root.uid };
        // A separately existing native principal at the substituted guest
        // number has no distinct guest identity in this single-owner grant.
        // Do not merge its ACL permission with that of the mapped owner.
        if native != guest && id == guest {
            return Err(Errno(75));
        }
        Ok(file.root.guest_id(group, id))
    })
}
fn to_native(file: &OpenFile, ns: &UserNamespace, bytes: &mut [u8]) -> Result<()> {
    map_ids(bytes, |group, id| ns.to_global(group, id).ok_or(Errno(22)))?;
    // Validate named-entry ordering in guest kernel IDs before the grant's
    // potentially nonmonotonic owner substitution changes their native order.
    let mut previous = [None, None];
    for entry in bytes[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes(entry[..2].try_into().unwrap());
        if matches!(tag, 2 | 8) {
            let id = u32::from_le_bytes(entry[4..8].try_into().unwrap());
            let previous = &mut previous[(tag == 8) as usize];
            if previous.is_some_and(|old| old >= id) {
                return Err(Errno(22));
            }
            *previous = Some(id);
        }
    }
    map_ids(bytes, |group, id| file.root.native_id(group, id))?;
    let mut entries: Vec<[u8; 8]> = bytes[4..]
        .chunks_exact(8)
        .map(|entry| entry.try_into().unwrap())
        .collect();
    entries.sort_by_key(|entry| {
        (
            u16::from_le_bytes(entry[..2].try_into().unwrap()),
            u32::from_le_bytes(entry[4..8].try_into().unwrap()),
        )
    });
    for (out, entry) in bytes[4..].chunks_exact_mut(8).zip(entries) {
        out.copy_from_slice(&entry);
    }
    Ok(())
}
fn bytes(file: &OpenFile, name: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = vec![0; 65536];
    let count = xattr::Native::new(file)?.read(Some(&CString::new(name).unwrap()), &mut bytes)?;
    if count > bytes.len() {
        return Err(Errno(5));
    }
    bytes.truncate(count);
    from_native(file, &mut bytes)?;
    Ok(bytes)
}
pub(super) fn refresh(file: &OpenFile, node: &NodeRef, stat: &libc::stat) -> Result<()> {
    if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Ok(());
    }
    // ctime can remain equal across independent host ACL mutations on a
    // coarse-timestamp kernel. Refresh the native ACL rather than treating
    // that scalar observation as a permission-cache invalidation guarantee.
    let access = match bytes(file, acl::ACCESS) {
        Ok(bytes) => Some(bytes),
        Err(Errno(61 | 95)) => None,
        Err(error) => return Err(error),
    };
    {
        let mut state = node.borrow_mut();
        if let Some(access) = access {
            state.xattrs.insert(acl::ACCESS.to_vec(), access);
        } else {
            state.xattrs.remove(acl::ACCESS);
        }
    }
    Ok(())
}
pub(super) fn read(file: &OpenFile, v: &Vfs, name: &[u8], capacity: u64) -> Result<FileValue> {
    let mut bytes = bytes(file, name)?;
    map_ids(&mut bytes, |group, id| {
        Ok(v.credentials
            .user_namespace
            .from_global(group, id)
            .unwrap_or(u32::MAX))
    })?;
    if capacity == 0 {
        Ok(FileValue::Count(bytes.len() as u64))
    } else if bytes.len() as u64 > capacity {
        Err(Errno(34))
    } else {
        Ok(FileValue::Bytes(bytes))
    }
}
pub(super) fn write(
    file: &OpenFile,
    node: &NodeRef,
    v: &Vfs,
    name: &[u8],
    value: Option<&[u8]>,
) -> Result<()> {
    let mut value = value.map(<[u8]>::to_vec);
    if let Some(bytes) = &mut value {
        if !bytes.is_empty() {
            acl::validate(bytes)?;
            to_native(file, &v.credentials.user_namespace, bytes)?;
        }
    }
    // POSIX ACL setters deliberately ignore CREATE/REPLACE. The native kernel
    // updates mode, canonicalizes equivalent ACLs, and performs inheritance.
    xattr::Native::new(file)?.write(&CString::new(name).unwrap(), value.as_deref(), 0)?;
    if name == acl::ACCESS {
        let state = node.borrow();
        let clear = !v.credentials.in_group(state.gid)
            && !v
                .credentials
                .inode_cap(capabilities::FSETID, state.uid, state.gid);
        drop(state);
        if clear {
            let mode = file.native_stat()?.st_mode;
            if mode & 0o2000 != 0 {
                file.chmod(mode & !0o2000)?;
            }
        }
    }
    file.refresh_permissions(node)
}

#[cfg(test)]
mod tests;
