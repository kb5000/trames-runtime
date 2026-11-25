// SPDX-License-Identifier: GPL-3.0-or-later
//! Filesystem-wide writeback retains each original inode before parking.
use super::*;
use std::collections::VecDeque;

pub(super) struct Batch {
    groups: VecDeque<(Arc<Mounted>, Caller, Vec<writeback::Pending>)>,
    request: Option<(Arc<Mounted>, Arc<Request>)>,
    all: bool,
    error: Option<Errno>,
    _usage: Vec<Arc<ConnectionUse>>,
}
impl Batch {
    pub(super) fn ready(&self) -> bool {
        if let Some((_, request)) = &self.request {
            return request.ready();
        }
        self.groups
            .front()
            .is_none_or(|(_, _, pending)| pending.iter().all(writeback::Pending::ready))
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> Option<IoSubscription> {
        if let Some((_, request)) = &self.request {
            return Some(request.subscribe(signal));
        }
        self.groups
            .front()?
            .2
            .iter()
            .find(|pending| !pending.ready())
            .map(|pending| pending.subscribe(signal))
    }
    pub(super) fn take(&mut self) -> Option<Result<FileValue>> {
        loop {
            if let Some((fs, request)) = &self.request {
                let result = request.take()?;
                match result {
                    Ok(bytes) if bytes.is_empty() => {}
                    Err(Errno(38)) => {
                        fs.syncfs_unsupported.store(true, Ordering::Relaxed);
                    }
                    Ok(_) => {
                        self.error.get_or_insert(Errno(5));
                    }
                    Err(error) => {
                        self.error.get_or_insert(error);
                    }
                }
                self.request = None;
            }
            let Some((fs, caller, pending)) = self.groups.front() else {
                return Some(if self.all {
                    Ok(FileValue::Count(0))
                } else {
                    self.error.map_or(Ok(FileValue::Count(0)), Err)
                });
            };
            if pending.iter().any(|pending| !pending.ready()) {
                return None;
            }
            for pending in pending {
                if let Some(Err(error)) = pending.result() {
                    self.error.get_or_insert(error);
                }
            }
            let fs = fs.clone();
            let caller = *caller;
            self.groups.pop_front();
            if fs.connection.minor() < 34 || fs.syncfs_unsupported.load(Ordering::Relaxed) {
                continue;
            }
            let mut body = [0; 8];
            body[..4].copy_from_slice(&1u32.to_le_bytes());
            match fs.connection.request(50, 0, caller, &body) {
                Ok(request) => {
                    self.request = Some((fs, Arc::new(request)));
                    return None;
                }
                Err(error) => {
                    self.error.get_or_insert(error);
                }
            }
        }
    }
}
impl Mounted {
    fn writers(&self) -> Vec<Arc<writeback::OpenWriter>> {
        let nodes: Vec<_> = self
            .directories
            .lock()
            .unwrap()
            .values()
            .filter_map(std::sync::Weak::upgrade)
            .collect();
        nodes
            .into_iter()
            .filter_map(|node| inode::attr(&node).cache.writer())
            .collect()
    }
}
impl Metadata {
    pub(crate) fn sync_filesystems(
        v: &Vfs,
        filesystems: Vec<Arc<Mounted>>,
        all: bool,
    ) -> Option<Self> {
        let fs = filesystems.first()?.clone();
        let usage = filesystems.iter().filter_map(|fs| fs.usage()).collect();
        let groups = filesystems
            .into_iter()
            .map(|fs| {
                let caller = fs.caller(v);
                let pending = fs
                    .writers()
                    .into_iter()
                    .map(|writer| writer.flush(caller))
                    .collect();
                (fs, caller, pending)
            })
            .collect();
        Some(Self {
            request: None,
            kind: ResultKind::Filesystems(Box::new(Batch {
                groups,
                request: None,
                all,
                error: None,
                _usage: usage,
            })),
            _usage: None,
            resolved: None,
            resolved_entry: None,
            reference: None,
            open: None,
            mount: StatMount {
                id: 0,
                is_root: false,
                mounted: false,
            },
            dev: 0,
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
            retry: None,
        })
    }
}
