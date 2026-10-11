// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest identities only. They never change the containing app's host identity.
use super::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Credentials {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub groups: Vec<u32>,
}
impl Credentials {
    pub fn user(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            euid: uid,
            suid: uid,
            gid,
            egid: gid,
            sgid: gid,
            fsuid: uid,
            fsgid: gid,
            groups: Vec::new(),
        }
    }
    pub fn in_group(&self, gid: u32) -> bool {
        self.fsgid == gid || self.groups.contains(&gid)
    }
    pub fn set_res_ids(&mut self, group: bool, values: [u32; 3]) -> Result<()> {
        let current = if group {
            [self.gid, self.egid, self.sgid]
        } else {
            [self.uid, self.euid, self.suid]
        };
        if self.euid != 0
            && values
                .iter()
                .any(|v| *v != u32::MAX && !current.contains(v))
        {
            return Err(Errno(1));
        }
        let mut next = current;
        for i in 0..3 {
            if values[i] != u32::MAX {
                next[i] = values[i];
            }
        }
        if group {
            [self.gid, self.egid, self.sgid] = next;
            self.fsgid = self.egid;
        } else {
            [self.uid, self.euid, self.suid] = next;
            self.fsuid = self.euid;
        }
        Ok(())
    }
    pub fn set_id(&mut self, group: bool, value: u32) -> Result<()> {
        if value == u32::MAX {
            return Err(Errno(22));
        }
        if self.euid == 0 {
            self.set_res_ids(group, [value; 3])
        } else {
            self.set_res_ids(group, [u32::MAX, value, u32::MAX])
        }
    }
}
impl Vfs {
    pub fn apply_exec_credentials(&mut self, path: &[u8]) -> Result<()> {
        let n = self.node(&self.resolve(AT_FDCWD, path)?)?;
        let n = n.borrow();
        if n.mode & 0o4000 != 0 {
            self.credentials.euid = n.uid;
            self.credentials.fsuid = n.uid;
        }
        if n.mode & 0o2000 != 0 {
            self.credentials.egid = n.gid;
            self.credentials.fsgid = n.gid;
        }
        self.credentials.suid = self.credentials.euid;
        self.credentials.sgid = self.credentials.egid;
        Ok(())
    }
    pub fn access_at(
        &self,
        dirfd: i32,
        path: &[u8],
        mode: u32,
        effective: bool,
        nofollow: bool,
    ) -> Result<()> {
        if mode & !7 != 0 {
            return Err(Errno(22));
        }
        let mut view = self.clone();
        if !effective {
            view.credentials.fsuid = self.credentials.uid;
            view.credentials.fsgid = self.credentials.gid;
        }
        let node = view.node(&view.resolve_final(dirfd, path, !nofollow)?)?;
        if view.allowed(&node.borrow(), mode) {
            Ok(())
        } else {
            Err(Errno(13))
        }
    }
    pub(super) fn check_remove(&self, path: &[u8]) -> Result<()> {
        let end = path
            .iter()
            .rposition(|b| *b == b'/')
            .ok_or(Errno(22))?
            .max(1);
        let parent = self.node(&path[..end])?;
        let p = parent.borrow();
        let uid = self.credentials.fsuid;
        if p.mode & 0o1000 != 0 && uid != 0 && uid != p.uid && uid != self.node(path)?.borrow().uid
        {
            return Err(Errno(1));
        }
        Ok(())
    }
    pub(super) fn allowed(&self, node: &Node, bits: u32) -> bool {
        let c = &self.credentials;
        if c.fsuid == 0 {
            return bits & 1 == 0
                || matches!(node.content, Content::Directory)
                || node.mode & 0o111 != 0;
        }
        let shift = if c.fsuid == node.uid {
            6
        } else if c.in_group(node.gid) {
            3
        } else {
            0
        };
        (node.mode >> shift) & bits == bits
    }
    fn chown_node(&self, node: Rc<RefCell<Node>>, uid: u32, gid: u32) -> Result<()> {
        self.pseudo_immutable(&node)?;
        let mut n = node.borrow_mut();
        let c = &self.credentials;
        if c.fsuid != 0
            && (c.fsuid != n.uid
                || (uid != u32::MAX && uid != n.uid)
                || (gid != u32::MAX && gid != n.gid && !c.in_group(gid)))
        {
            return Err(Errno(1));
        }
        let old = (n.uid, n.gid, n.mode, n.times[2]);
        if uid != u32::MAX {
            n.uid = uid;
        }
        if gid != u32::MAX {
            n.gid = gid;
        }
        if matches!(n.content, Content::File(_)) && (uid != u32::MAX || gid != u32::MAX) {
            n.mode &= !0o6000;
        }
        n.times[2] = storage::Timestamp::now();
        drop(n);
        if let Err(error) = self.checkpoint() {
            let mut n = node.borrow_mut();
            (n.uid, n.gid, n.mode, n.times[2]) = old;
            return Err(error);
        }
        Ok(())
    }
    pub fn chown_at(
        &mut self,
        dirfd: i32,
        path: &[u8],
        uid: u32,
        gid: u32,
        nofollow: bool,
    ) -> Result<()> {
        let node = self.node(&self.resolve_final(dirfd, path, !nofollow)?)?;
        self.chown_node(node, uid, gid)
    }
    pub fn chown_fd(&mut self, fd: u32, uid: u32, gid: u32) -> Result<()> {
        let node = self
            .descriptor(fd)?
            .open
            .borrow()
            .node
            .clone()
            .ok_or(Errno(22))?;
        self.chown_node(node, uid, gid)
    }
}
