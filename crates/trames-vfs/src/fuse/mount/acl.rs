// SPDX-License-Identifier: GPL-3.0-or-later
//! Negotiated inode ACL observations. No inode guard crosses a daemon wait.
use super::*;
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Access = 0,
    Default = 1,
}
/// A request may return its own observation without owning a cache fill.
pub(super) struct Claim {
    kind: Kind,
    version: u64,
    owner: bool,
}
pub(super) enum Read {
    Cached(Option<Arc<Vec<u8>>>),
    Pending(Claim),
}
#[derive(Default)]
struct Cached {
    version: u64,
    uncached: bool,
    values: [Option<Option<Arc<Vec<u8>>>>; 2],
    filling: [bool; 2],
}
#[derive(Default)]
pub(super) struct Cache(std::sync::Mutex<Cached>);
impl Cache {
    pub(super) fn uncached() -> Self {
        Self(std::sync::Mutex::new(Cached {
            uncached: true,
            ..Cached::default()
        }))
    }
    pub(super) fn get(&self, kind: Kind) -> Option<Option<Arc<Vec<u8>>>> {
        let c = self.0.lock().unwrap();
        if c.uncached {
            None
        } else {
            c.values[kind as usize].clone()
        }
    }
    pub(super) fn begin(&self, kind: Kind) -> Read {
        let mut c = self.0.lock().unwrap();
        if !c.uncached {
            if let Some(value) = &c.values[kind as usize] {
                return Read::Cached(value.clone());
            }
        }
        let owner = !c.uncached && !c.filling[kind as usize];
        c.filling[kind as usize] |= owner;
        Read::Pending(Claim {
            kind,
            version: c.version,
            owner,
        })
    }
    pub(super) fn complete(&self, claim: Claim, value: &Result<Option<Arc<Vec<u8>>>>) {
        let mut c = self.0.lock().unwrap();
        if claim.owner && c.version == claim.version {
            c.filling[claim.kind as usize] = false;
            if let Ok(value) = value {
                c.values[claim.kind as usize] = Some(value.clone());
            }
        }
    }
    pub(super) fn cancel(&self, claim: Claim) {
        self.complete(claim, &Err(Errno(4)));
    }
    fn invalidate(&self) {
        let mut c = self.0.lock().unwrap();
        c.version = c.version.wrapping_add(1);
        c.values = Default::default();
        c.filling = [false; 2];
    }
}
impl Mounted {
    pub(super) fn acl_cache<'a>(&self, node: &'a NodeRef) -> &'a Cache {
        inode_cache(node)
    }
    pub(super) fn invalidate_acl(&self, node: &NodeRef) {
        if self.posix_acl() {
            self.acl_cache(node).invalidate();
        }
    }
    pub(super) fn permission_result(
        &self,
        node: &NodeRef,
        c: &Credentials,
        mask: u32,
    ) -> Result<Option<bool>> {
        if !self.local_permissions() {
            return Ok(Some(true));
        }
        let n = node.borrow();
        if self.posix_acl() && mask != 0 && c.fsuid != n.uid && n.mode & 0o70 != 0 {
            self.acl_cache(node)
                .get(Kind::Access)
                .map(|a| c.allows_acl(&n, mask, a.as_deref().map(Vec::as_slice)))
                .transpose()
        } else {
            Ok(Some(c.allows_mode(
                n.uid,
                n.gid,
                n.mode,
                node.directory,
                mask,
            )))
        }
    }
    pub(super) fn decode_acl(&self, result: Result<Vec<u8>>) -> Result<Option<Arc<Vec<u8>>>> {
        let mut bytes = match result {
            Ok(bytes) if bytes.is_empty() => return Ok(None),
            Ok(bytes) if bytes.len() <= 4096 => bytes,
            Ok(_) | Err(Errno(34)) => return Err(Errno(7)),
            Err(Errno(61)) => return Ok(None),
            Err(Errno(38)) => {
                self.xattr_unsupported.fetch_or(2, Ordering::Relaxed);
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        crate::acl::decode(&bytes)?;
        crate::acl::normalize(&mut bytes);
        if bytes.len() == 4 {
            return Ok(None);
        }
        for e in bytes[4..].chunks_exact_mut(8) {
            let tag = u16::from_le_bytes(e[..2].try_into().unwrap());
            if matches!(tag, 2 | 8) {
                let id = u32::from_le_bytes(e[4..8].try_into().unwrap());
                let global = self.namespace.to_global(tag == 8, id).ok_or(Errno(22))?;
                e[4..8].copy_from_slice(&global.to_le_bytes());
            }
        }
        Ok(Some(Arc::new(bytes)))
    }
}
enum Phase {
    Attr(u64),
    Acl(Claim),
}
pub(super) struct Check {
    pub(super) node: NodeRef,
    credentials: Credentials,
    mask: u32,
    owner_bypass: bool,
    refreshed: bool,
    observed: Option<Option<Arc<Vec<u8>>>>,
    phase: Option<Phase>,
}
fn inode_cache(node: &NodeRef) -> &Cache {
    node.fuse_leaf
        .get()
        .map(|n| &n.acl)
        .or_else(|| node.fuse_directory.get().map(|n| &n.acl))
        .expect("FUSE inode")
}
impl Drop for Check {
    fn drop(&mut self) {
        if let Some(Phase::Acl(claim)) = self.phase.take() {
            inode_cache(&self.node).cancel(claim);
        }
    }
}
impl Check {
    pub(super) fn new(node: NodeRef, credentials: Credentials, mask: u32) -> Self {
        Self {
            node,
            credentials,
            mask,
            owner_bypass: false,
            refreshed: false,
            observed: None,
            phase: None,
        }
    }
    pub(super) fn times(mut self) -> Self {
        self.owner_bypass = true;
        self
    }
    pub(super) fn refreshed(mut self) -> Self {
        self.refreshed = true;
        self
    }
    pub(super) fn attributes_refreshed(&self) -> bool {
        self.refreshed
    }
    pub(super) fn next(&mut self, fs: &Mounted, caller: Caller) -> Result<Option<Arc<Request>>> {
        fs.check_inode(&self.node)?;
        if !fs.local_permissions() {
            return Ok(None);
        }
        let mut attr = !self.refreshed && !fs.permission_attr_fresh(&self.node);
        if !attr {
            let allowed = self.allowed(fs)?;
            match allowed {
                Some(true) => return Ok(None),
                Some(false) if self.refreshed => return Err(Errno(13)),
                Some(false) => attr = true,
                None => {
                    if fs.xattr_unsupported.load(Ordering::Relaxed) & 2 != 0 {
                        self.observed = Some(None);
                        return self.next(fs, caller);
                    }
                    match fs.acl_cache(&self.node).begin(Kind::Access) {
                        Read::Cached(value) => {
                            self.observed = Some(value);
                            return self.next(fs, caller);
                        }
                        Read::Pending(claim) => self.phase = Some(Phase::Acl(claim)),
                    }
                    let mut body = 4096u32.to_le_bytes().to_vec();
                    body.extend([0; 4]);
                    body.extend(crate::acl::ACCESS);
                    body.push(0);
                    return Ok(Some(Arc::new(fs.connection.request(
                        22,
                        self.id(),
                        caller,
                        &body,
                    )?)));
                }
            }
        }
        debug_assert!(attr);
        fs.invalidate_acl(&self.node);
        self.observed = None;
        let request = Arc::new(fs.connection.request(3, self.id(), caller, &[0; 16])?);
        self.phase = Some(Phase::Attr(request.attr_version));
        Ok(Some(request))
    }

    fn allowed(&self, fs: &Mounted) -> Result<Option<bool>> {
        let n = self.node.borrow();
        let mask = if self.owner_bypass
            && (self.credentials.fsuid == n.uid
                || self
                    .credentials
                    .inode_cap(capabilities::FOWNER, n.uid, n.gid))
        {
            0
        } else {
            self.mask
        };
        let allowed = if let Some(acl) = &self.observed {
            Ok(Some(self.credentials.allows_acl(
                &n,
                mask,
                acl.as_deref().map(Vec::as_slice),
            )?))
        } else {
            drop(n);
            fs.permission_result(&self.node, &self.credentials, mask)
        };
        allowed
    }
    fn id(&self) -> u64 {
        self.node
            .fuse_leaf
            .get()
            .map(|n| n.node)
            .or_else(|| self.node.fuse_directory.get().map(|n| n.node))
            .unwrap()
    }
    pub(super) fn accept(&mut self, fs: &Mounted, result: Result<Vec<u8>>) -> Result<()> {
        match self.phase.take().expect("pending permission check") {
            Phase::Attr(version) => {
                fs.refresh_permission_attr(&self.node, &mut result?, version, false)?;
                self.refreshed = true;
            }
            Phase::Acl(claim) => {
                let value = fs.decode_acl(result);
                fs.acl_cache(&self.node).complete(claim, &value);
                self.observed = Some(value?);
            }
        }
        Ok(())
    }
}
