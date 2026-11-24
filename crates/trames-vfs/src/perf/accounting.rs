// SPDX-License-Identifier: GPL-3.0-or-later
//! Original environment/UID allowance and original-mm pinned perf pages.
use super::*;

#[derive(Default)]
pub(crate) struct Accounts {
    usage: parking_lot::Mutex<Usage>,
    pub(super) settings: Arc<Settings>,
}
#[derive(Default)]
struct Usage {
    user: BTreeMap<u32, u64>,
    pinned: BTreeMap<u64, u64>,
}
#[derive(Clone)]
pub(crate) struct Policy {
    accounts: Arc<Accounts>,
    uid: u32,
    limits: MemoryResourceLimits,
    privileged: bool,
}
pub(super) struct Charge {
    accounts: Arc<Accounts>,
    uid: u32,
    mm: u64,
    user: u64,
    pinned: u64,
}
impl Policy {
    pub(crate) fn new(vfs: &Vfs) -> Self {
        Self {
            accounts: vfs.credentials.user_namespace.overflow().1.clone(),
            uid: vfs.credentials.uid,
            limits: vfs.memory_resource_limits.clone(),
            privileged: vfs.credentials.has_cap(capabilities::IPC_LOCK),
        }
    }
    pub(super) fn alias(&self, mm: u64, bytes: u64) -> Charge {
        let mut state = self.accounts.usage.lock();
        *state.user.entry(self.uid).or_default() += bytes;
        Charge {
            accounts: self.accounts.clone(),
            uid: self.uid,
            mm,
            user: bytes,
            pinned: 0,
        }
    }
    pub(super) fn reserve(&self, mm: u64, bytes: u64, cpus: usize) -> Result<Charge> {
        let mut state = self.accounts.usage.lock();
        let used = state.user.get(&self.uid).copied().unwrap_or(0);
        let allowance = self.accounts.settings.allowance(cpus);
        let user = bytes.min(allowance.saturating_sub(used));
        let extra = bytes - user;
        let pinned = state.pinned.get(&mm).copied().unwrap_or(0);
        let next = pinned.checked_add(extra).ok_or(Errno(12))?;
        if !self.privileged
            && self.accounts.settings.get(Setting::Paranoid) >= 0
            && next > self.limits.locked()
        {
            return Err(Errno(1));
        }
        if user != 0 {
            state.user.insert(self.uid, used + user);
        }
        if extra != 0 {
            state.pinned.insert(mm, next);
        }
        Ok(Charge {
            accounts: self.accounts.clone(),
            uid: self.uid,
            mm,
            user,
            pinned: extra,
        })
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        let mut state = self.accounts.usage.lock();
        if self.user != 0 {
            let used = state.user.get_mut(&self.uid).unwrap();
            *used -= self.user;
            if *used == 0 {
                state.user.remove(&self.uid);
            }
        }
        if self.pinned != 0 {
            let pinned = state.pinned.get_mut(&self.mm).unwrap();
            *pinned -= self.pinned;
            if *pinned == 0 {
                state.pinned.remove(&self.mm);
            }
        }
    }
}
