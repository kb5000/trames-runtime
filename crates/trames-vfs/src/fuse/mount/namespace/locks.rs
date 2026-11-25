// SPDX-License-Identifier: GPL-3.0-or-later
//! Native directory transactions, retained across the original daemon request.
use super::*;

#[derive(Default)]
pub(in super::super) struct Rename {
    busy: std::sync::atomic::AtomicBool,
    changed: Arc<Readiness>,
}
pub(in super::super) struct RenameLease(Arc<Rename>);
impl Rename {
    pub(in super::super) fn try_enter(self: &Arc<Self>) -> Option<RenameLease> {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| RenameLease(self.clone()))
    }
}
impl Drop for RenameLease {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
        self.0.changed.notify_atomic();
    }
}
enum Wait {
    Rename(Arc<Rename>),
    Inode(Arc<inode::Attr>),
}
#[derive(Default)]
pub(super) struct Locks {
    parents: Option<Vec<NodeRef>>,
    held: Vec<inode::Write>,
    rename: Option<RenameLease>,
    waiting: Option<Wait>,
    pending: Option<inode::WriteWait>,
}
impl Drop for Locks {
    fn drop(&mut self) {
        drop(self.pending.take());
        while self.held.pop().is_some() {}
        drop(self.rename.take());
    }
}
fn ancestors(node: &NodeRef) -> Vec<NodeRef> {
    let mut chain = Vec::new();
    let mut next = Some(node.clone());
    for _ in 0..MAX_PATH {
        let Some(node) = next else { break };
        next = node
            .fuse_directory
            .get()
            .and_then(|directory| directory.parent());
        chain.push(node);
    }
    chain
}
impl Locks {
    pub(super) fn ready(&self) -> bool {
        match &self.waiting {
            Some(Wait::Rename(rename)) => !rename.busy.load(Ordering::Acquire),
            Some(Wait::Inode(attr)) => attr.write_ready(),
            None => true,
        }
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> Option<IoSubscription> {
        match &self.waiting {
            Some(Wait::Rename(rename)) => Some(rename.changed.subscribe(signal)),
            Some(Wait::Inode(attr)) => Some(attr.subscribe_write(signal)),
            None => None,
        }
    }
    pub(super) fn parents(
        &mut self,
        fs: &Mounted,
        source: &NodeRef,
        dest: Option<&NodeRef>,
    ) -> Result<bool> {
        if self.parents.is_none() {
            let different = dest.filter(|dest| !Arc::ptr_eq(source, dest));
            if different.is_some() && self.rename.is_none() {
                let Some(lease) = fs.rename.try_enter() else {
                    self.waiting = Some(Wait::Rename(fs.rename.clone()));
                    return Ok(false);
                };
                self.rename = Some(lease);
            }
            self.parents = Some(if let Some(dest) = different {
                let source_chain = ancestors(source);
                let dest_chain = ancestors(dest);
                if !source_chain
                    .iter()
                    .any(|a| dest_chain.iter().any(|b| Arc::ptr_eq(a, b)))
                {
                    return Err(Errno(18));
                }
                if source_chain.iter().any(|node| Arc::ptr_eq(node, dest)) {
                    vec![dest.clone(), source.clone()]
                } else {
                    vec![source.clone(), dest.clone()]
                }
            } else {
                vec![source.clone()]
            });
        }
        // Parent order is fixed under the original filesystem rename lease.
        // Keep earlier admissions while waiting, as native inode_lock does.
        for index in 0..self.parents.as_ref().unwrap().len() {
            let parent = self.parents.as_ref().unwrap()[index].clone();
            if !self.child(&parent) {
                return Ok(false);
            }
            if !parent.fuse_directory.get().ok_or(Errno(20))?.linked() {
                return Err(Errno(2));
            }
        }
        Ok(true)
    }
    pub(super) fn child(&mut self, node: &NodeRef) -> bool {
        let attr = inode::attr(node);
        if self.held.iter().any(|lease| lease.is_for(attr)) {
            return true;
        }
        let Some(lease) = attr.enter_write(&mut self.pending) else {
            self.waiting = Some(Wait::Inode(attr.clone()));
            return false;
        };
        self.held.push(lease);
        self.waiting = None;
        true
    }
}
