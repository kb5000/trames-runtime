// SPDX-License-Identifier: GPL-3.0-or-later
//! Parked jobs and their actual scheduling deadlines are one queue invariant.
//! Read-only map access cannot silently bypass the deadline index. Resources
//! still wake their original job through its existing subscription/ticket.
use super::{Cpu, Job};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

pub(super) struct Parked<C: Cpu> {
    jobs: BTreeMap<u32, Box<Job<C>>>,
    deadlines: BTreeSet<(Instant, u32)>,
    indexed: BTreeMap<u32, Instant>,
    external: BTreeSet<u32>,
    gpu: BTreeSet<u32>,
    compiles: BTreeSet<u32>,
}
impl<C: Cpu> Default for Parked<C> {
    fn default() -> Self {
        Self {
            jobs: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            indexed: BTreeMap::new(),
            external: BTreeSet::new(),
            gpu: BTreeSet::new(),
            compiles: BTreeSet::new(),
        }
    }
}
impl<C: Cpu> std::ops::Deref for Parked<C> {
    type Target = BTreeMap<u32, Box<Job<C>>>;
    fn deref(&self) -> &Self::Target {
        &self.jobs
    }
}
impl<C: Cpu> Parked<C> {
    pub fn insert(&mut self, pid: u32, job: Box<Job<C>>) -> Option<Box<Job<C>>> {
        let previous = self.remove(&pid);
        if let Some(deadline) = job.wake_deadline() {
            self.deadlines.insert((deadline, pid));
            self.indexed.insert(pid, deadline);
        }
        // Producer/interest changes notify the original job signal, remove it
        // from parked and rearm it before re-insertion. Never cache native fd
        // handles or substitute a queue timer/polling service for that protocol.
        if job.io.as_ref().is_some_and(|io| io.external_wait())
            || job.uring.as_ref().is_some_and(|ring| ring.external())
        {
            self.external.insert(pid);
        }
        if let Some(pending) = &job.gpu_pending {
            self.gpu.insert(pid);
            if pending.compile.is_some() {
                self.compiles.insert(pid);
            }
        }
        self.jobs.insert(pid, job);
        previous
    }
    pub fn remove(&mut self, pid: &u32) -> Option<Box<Job<C>>> {
        if let Some(deadline) = self.indexed.remove(pid) {
            self.deadlines.remove(&(deadline, *pid));
        }
        self.external.remove(pid);
        self.gpu.remove(pid);
        self.compiles.remove(pid);
        self.jobs.remove(pid)
    }
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.first().map(|&(deadline, _)| deadline)
    }
    pub fn external(&self) -> bool {
        !self.external.is_empty()
    }
    pub fn gpu_pending(&self) -> bool {
        !self.gpu.is_empty()
    }
    pub fn compile_count(&self) -> usize {
        self.compiles.len()
    }
    pub fn expired(&mut self, now: Instant) -> Vec<u32> {
        let mut expired = Vec::new();
        while let Some(&(deadline, pid)) = self.deadlines.first() {
            if deadline > now {
                break;
            }
            self.deadlines.pop_first();
            self.indexed.remove(&pid);
            // Stop/continue and resource readiness retain their original rules.
            // Only due entries need this observation, never unrelated sleepers.
            if let Some(current) = self.jobs.get(&pid).and_then(|job| job.wake_deadline()) {
                if current <= now {
                    expired.push(pid);
                } else {
                    self.deadlines.insert((current, pid));
                    self.indexed.insert(pid, current);
                }
            }
        }
        expired
    }
    pub fn into_values(self) -> std::collections::btree_map::IntoValues<u32, Box<Job<C>>> {
        self.jobs.into_values()
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn update(&mut self, pid: u32, operation: impl FnOnce(&mut Job<C>)) {
        let mut job = self.remove(&pid).unwrap();
        operation(&mut job);
        self.insert(pid, job);
    }
}
impl<C: Cpu> IntoIterator for Parked<C> {
    type Item = (u32, Box<Job<C>>);
    type IntoIter = std::collections::btree_map::IntoIter<u32, Box<Job<C>>>;
    fn into_iter(self) -> Self::IntoIter {
        self.jobs.into_iter()
    }
}
