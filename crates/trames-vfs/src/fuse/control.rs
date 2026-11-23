// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::{Mutex, Weak};

#[derive(Default)]
pub(crate) struct Controller(Mutex<Option<FsHandle>>);

#[derive(Clone)]
pub(crate) struct Abort {
    target: Weak<Connection>,
    owner: u32,
}
impl Abort {
    pub(crate) fn authorized(&self, credentials: &Credentials) -> bool {
        credentials.fsuid == self.owner || credentials.has_cap(capabilities::DAC_OVERRIDE)
    }
    pub(crate) fn write(&self, count: usize) -> usize {
        if count != 0 {
            if let Some(connection) = self.target.upgrade() {
                connection.abort();
            }
        }
        count
    }
}

impl Controller {
    pub(crate) fn filesystem(&self) -> Result<FsHandle> {
        let mut state = self.0.lock().unwrap();
        if let Some(fs) = &*state {
            return Ok(fs.clone());
        }
        let fs = mounts::ram_filesystem(0, usize::MAX, 0o555, 0, 0, false)?;
        *state = Some(fs.clone());
        Ok(fs)
    }
    pub(super) fn add(
        &self,
        id: u64,
        uid: u32,
        gid: u32,
        connection: &Arc<Connection>,
    ) -> Result<()> {
        let files = self.filesystem()?;
        let mut fs = files.borrow_mut();
        let root = fs.paths[b"/".as_slice()].clone();
        let device = root.borrow().device;
        let mut node = |mode, content| {
            let inode = fs.next_inode;
            fs.next_inode = inode.checked_add(1).ok_or(Errno(28))?;
            Ok(Arc::new(Inode::new(Node {
                identity: 0,
                record_locks: Default::default(),
                whole_locks: Default::default(),
                notifications: Default::default(),
                path_hint: Default::default(),
                inode,
                device,
                mode,
                uid,
                gid,
                content,
                volatile: false,
                links: 1,
                times: [storage::Timestamp::now(); 3],
                xattrs: Default::default(),
                seals: None,
            })))
        };
        let dir = node(0o40500, Content::Directory)?;
        let abort = node(
            0o100200,
            Content::File(storage::FileData::memory(Vec::new())),
        )?;
        let _ = abort.fuse_abort.set(Abort {
            target: Arc::downgrade(connection),
            owner: uid,
        });
        let name = id.to_string();
        inotify::link(&dir, &root, name.as_bytes());
        inotify::link(&abort, &dir, b"abort");
        fs.paths.insert(format!("/{name}").into_bytes(), dir);
        fs.paths
            .insert(format!("/{name}/abort").into_bytes(), abort);
        Ok(())
    }
    pub(super) fn remove(&self, id: u64) {
        let state = self.0.lock().unwrap();
        if let Some(files) = &*state {
            let mut fs = files.borrow_mut();
            fs.paths.remove(format!("/{id}/abort").as_bytes());
            fs.paths.remove(format!("/{id}").as_bytes());
        }
    }
}
