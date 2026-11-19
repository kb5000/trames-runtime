// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
pub(super) struct Permissions {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) cuid: u32,
    pub(super) cgid: u32,
    pub(super) mode: u32,
}
pub(super) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl Permissions {
    pub(super) fn allowed(&self, c: &Credentials, bits: u32, owner: &UserNamespace) -> bool {
        let shift = if c.euid == self.uid || c.euid == self.cuid {
            6
        } else if c.egid == self.gid
            || c.egid == self.cgid
            || c.groups.contains(&self.gid)
            || c.groups.contains(&self.cgid)
        {
            3
        } else {
            0
        };
        self.mode >> shift & bits == bits || c.has_ns_cap(owner, capabilities::IPC_OWNER)
    }
    pub(super) fn controls(&self, c: &Credentials, owner: &UserNamespace) -> bool {
        c.euid == self.uid || c.euid == self.cuid || c.has_ns_cap(owner, capabilities::SYS_ADMIN)
    }
}

impl Permissions {
    pub(super) fn new(c: &Credentials, flags: u32) -> Self {
        Self {
            uid: c.euid,
            gid: c.egid,
            cuid: c.euid,
            cgid: c.egid,
            mode: flags & 0o777,
        }
    }
}
