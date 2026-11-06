// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest affinity and ready-queue policy; no execution engine or host threads.
use std::sync::{
    atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering},
    Arc,
};

#[derive(Clone, Copy, Default)]
pub(crate) struct Authority {
    pub uid: u32,
    pub euid: u32,
    pub permitted: u64,
    pub privileged: bool,
}
/// The original task's scheduling attributes, shared by its CPU job and owner.
/// Single-field guest updates use relaxed atomics; there is no host priority change.
pub struct Attributes {
    affinity: AtomicU64,
    nice: AtomicI32,
    policy: AtomicU32,
    credentials: Arc<trames_vfs::CredentialState>,
}
impl Default for Attributes {
    fn default() -> Self {
        Self {
            affinity: AtomicU64::new(u64::MAX),
            nice: AtomicI32::new(0),
            policy: AtomicU32::new(0),
            credentials: Arc::default(),
        }
    }
}
impl Attributes {
    pub fn affinity(&self) -> u64 {
        self.affinity.load(Ordering::Relaxed)
    }
    pub fn set_affinity(&self, mask: u64) {
        self.affinity.store(mask, Ordering::Relaxed);
    }
    pub fn replace_affinity(&self, mask: u64) -> bool {
        self.affinity.swap(mask, Ordering::Relaxed) != mask
    }
    pub fn nice(&self) -> i32 {
        self.nice.load(Ordering::Relaxed)
    }
    pub fn set_nice(&self, nice: i32) {
        self.nice.store(nice, Ordering::Relaxed);
    }
    pub fn policy(&self) -> u32 {
        self.policy.load(Ordering::Relaxed)
    }
    pub fn set_policy(&self, policy: u32) {
        self.policy.store(policy, Ordering::Relaxed);
    }
    pub fn inherit(&self, parent: &Self) {
        self.set_affinity(parent.affinity());
        self.set_nice(parent.nice());
        self.set_policy(parent.policy());
    }
    pub fn credentials(&self) -> &Arc<trames_vfs::CredentialState> {
        &self.credentials
    }
    pub fn publish_credentials(&self, credentials: &trames_vfs::Credentials) {
        self.credentials.publish(credentials);
    }
    pub(crate) fn authority(&self) -> Authority {
        let credentials = self.credentials.read();
        Authority {
            uid: credentials.uid,
            euid: credentials.euid,
            permitted: credentials.caps.permitted,
            privileged: credentials.has_cap(trames_vfs::capabilities::SYS_NICE),
        }
    }
}

pub fn call(number: u32) -> bool {
    matches!(number, 118..=123 | 125..=127 | 140 | 141 | 274 | 275)
}

/// Preserve round-robin queue priority while relocating an earlier flexible
/// task when a later pinned task needs its slot. Mask width is at most 32 CPUs.
pub fn assign_cpus(ready: impl IntoIterator<Item = (u32, u64)>, count: usize) -> Vec<(u32, usize)> {
    fn place(pid: u32, mask: u64, slots: &mut [Option<(u32, u64)>], visited: &mut u64) -> bool {
        let eligible = mask & !*visited;
        // Equal/full masks take the same lowest-free-slot fast path as before.
        if let Some(slot) = slots
            .iter()
            .enumerate()
            .find_map(|(i, p)| (eligible & (1 << i) != 0 && p.is_none()).then_some(i))
        {
            slots[slot] = Some((pid, mask));
            return true;
        }
        for slot in 0..slots.len() {
            if eligible & (1 << slot) == 0 {
                continue;
            }
            *visited |= 1 << slot;
            let (previous, previous_mask) = slots[slot].expect("occupied eligible slot");
            if place(previous, previous_mask, slots, visited) {
                slots[slot] = Some((pid, mask));
                return true;
            }
        }
        false
    }
    let mut slots = vec![None; count];
    let mut selected = Vec::new();
    for (pid, mask) in ready {
        if place(pid, mask, &mut slots, &mut 0) {
            selected.push(pid);
            if selected.len() == count {
                break;
            }
        }
    }
    selected
        .into_iter()
        .map(|pid| {
            let slot = slots
                .iter()
                .position(|p| p.is_some_and(|p| p.0 == pid))
                .expect("assigned task");
            (pid, slot)
        })
        .collect()
}
