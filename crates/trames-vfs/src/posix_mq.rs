// SPDX-License-Identifier: GPL-3.0-or-later
//! A namespace's mqueue mount and mq_open use one directory. Open descriptions
//! keep the original queue after unlink, namespace changes and FD reuse.
use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;

const CREATE: u32 = 0x40;
const EXCLUSIVE: u32 = 0x80;
pub const DEFAULT_BYTES: u64 = 819_200;
// The real UID's reservation survives unlink and is shared across IPC namespaces.
// Linux accounts for the ARM64 msg_msg and priority tree headers as well as payload.
#[derive(Default)]
pub(super) struct Accounts(Mutex<BTreeMap<u32, u64>>);
struct Charge {
    accounts: Arc<Accounts>,
    uid: u32,
    bytes: u64,
}
impl Accounts {
    fn reserve(self: &Arc<Self>, uid: u32, bytes: u64, limit: u64) -> Result<Charge> {
        let mut users = self.0.lock().unwrap();
        let total = users
            .get(&uid)
            .copied()
            .unwrap_or(0)
            .checked_add(bytes)
            .filter(|v| *v <= limit)
            .ok_or(Errno(24))?;
        users.insert(uid, total);
        Ok(Charge {
            accounts: self.clone(),
            uid,
            bytes,
        })
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        let mut users = self.accounts.0.lock().unwrap();
        let used = users
            .get_mut(&self.uid)
            .expect("live message queue reservation");
        *used -= self.bytes;
        if *used == 0 {
            users.remove(&self.uid);
        }
    }
}
pub struct Queue {
    _charge: Charge,
    maximum: usize,
    message_size: usize,
    state: Mutex<State>,
    ready: Arc<Readiness>,
}
#[derive(Default)]
struct State {
    messages: BTreeMap<u32, VecDeque<Arc<[u8]>>>,
    count: usize,
    bytes: usize,
    epochs: [u64; 2],
}
impl Queue {
    fn new(attr: Option<[i64; 2]>, vfs: &Vfs) -> Result<Self> {
        let [count, size] = attr.unwrap_or([10, 8192]);
        let (max_count, max_size) = if vfs.credentials.has_cap(capabilities::SYS_RESOURCE) {
            (65536, 16 * 1024 * 1024)
        } else {
            (10, 8192)
        };
        if !(1..=max_count).contains(&count) || !(1..=max_size).contains(&size) {
            return Err(Errno(22));
        }
        let bytes = count as u64 * (size as u64 + 48) + count.min(32768) as u64 * 48;
        let charge = vfs.ipc_namespace.queue_accounts.reserve(
            vfs.credentials.uid,
            bytes,
            vfs.memory_resource_limits.message_queue(),
        )?;
        Ok(Self {
            _charge: charge,
            maximum: count as usize,
            message_size: size as usize,
            state: Default::default(),
            ready: Default::default(),
        })
    }
    pub fn message_size(&self) -> usize {
        self.message_size
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.ready.subscribe(signal)
    }
    pub fn send(&self, data: &Arc<[u8]>, priority: u32) -> Result<()> {
        if priority >= 32768 {
            return Err(Errno(22));
        }
        if data.len() > self.message_size {
            return Err(Errno(90));
        }
        let mut s = self.state.lock().unwrap();
        if s.count == self.maximum {
            return Err(Errno(11));
        }
        if s.count == 0 {
            s.epochs[0] = s.epochs[0].wrapping_add(1);
        }
        s.count += 1;
        s.bytes += data.len();
        s.messages
            .entry(priority)
            .or_default()
            .push_back(data.clone());
        drop(s);
        self.ready.notify_locked();
        Ok(())
    }
    pub fn receive(&self, capacity: u64) -> Result<(u32, Arc<[u8]>)> {
        if capacity < self.message_size as u64 {
            return Err(Errno(90));
        }
        let mut s = self.state.lock().unwrap();
        let mut entry = s.messages.last_entry().ok_or(Errno(11))?;
        let priority = *entry.key();
        let data = entry.get_mut().pop_front().unwrap();
        if entry.get().is_empty() {
            entry.remove();
        }
        if s.count == self.maximum {
            s.epochs[1] = s.epochs[1].wrapping_add(1);
        }
        s.count -= 1;
        s.bytes -= data.len();
        drop(s);
        self.ready.notify_locked();
        Ok((priority, data))
    }
    pub(super) fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let s = self.state.lock().unwrap();
        let mut ready = 0;
        if s.count > 0 {
            ready |= 0x41
        }
        if s.count < self.maximum {
            ready |= 0x104
        }
        (ready & events, s.epochs)
    }
    pub(super) fn status(&self, offset: u64, count: usize) -> Vec<u8> {
        let bytes = self.state.lock().unwrap().bytes;
        let line = format!("QSIZE:{bytes:<10} NOTIFY:0     SIGNO:0     NOTIFY_PID:0     \n");
        let start = (offset as usize).min(line.len());
        line.as_bytes()[start..start + count.min(line.len() - start)].to_vec()
    }
    pub(super) fn read(&self, position: &file_data::FilePosition, count: usize) -> Result<Vec<u8>> {
        let mut p = position.lock().unwrap();
        if p.pending != 0 {
            return Err(Errno(11));
        }
        let data = self.status(p.value, count);
        p.value += data.len() as u64;
        Ok(data)
    }
}

pub struct QueueFd {
    pub queue: Arc<Queue>,
    flags: StatusFlags,
}
impl QueueFd {
    pub fn flags(&self) -> u32 {
        self.flags.get()
    }
    pub fn attributes(&self, update: Option<u64>) -> Result<[u64; 4]> {
        if update.is_some_and(|f| f & !u64::from(O_NONBLOCK) != 0) {
            return Err(Errno(22));
        }
        let flags = match update {
            Some(f) => self.flags.swap_nonblocking(f != 0)?,
            None => self.flags.get(),
        };
        let s = self.queue.state.lock().unwrap();
        Ok([
            u64::from(flags & O_NONBLOCK),
            self.queue.maximum as u64,
            self.queue.message_size as u64,
            s.count as u64,
        ])
    }
}
impl DescriptorFactory {
    pub fn mq_descriptor(&self, fd: u32) -> Result<QueueFd> {
        let f = self.files.lookup(fd).ok_or(Errno(9))??;
        let Some(events::SharedControl::MessageQueue(queue)) = &f.open.control else {
            return Err(Errno(9));
        };
        Ok(QueueFd {
            queue: queue.clone(),
            flags: f.open.flags.clone(),
        })
    }
}
fn key(name: &[u8], unlink: bool) -> Result<Vec<u8>> {
    if name.len() > 255 {
        return Err(Errno(36));
    }
    if name.is_empty() {
        return Err(Errno(2));
    }
    if name.contains(&b'/') {
        return Err(Errno(13));
    }
    if matches!(name, b"." | b"..") {
        return Err(Errno(if unlink { 21 } else { 13 }));
    }
    Ok([b"/", name].concat())
}
impl Vfs {
    pub(super) fn mqueue_fs(&self) -> Result<FsHandle> {
        let cell = &self.ipc_namespace.mqueue;
        if let Some(fs) = cell.get() {
            return Ok(fs.clone());
        }
        let owner = &self.ipc_namespace.user_namespace;
        let mut fs = mounts::ram_filesystem(
            0,
            257,
            0o1777,
            owner.to_global(false, 0).unwrap_or(0),
            owner.to_global(true, 0).unwrap_or(0),
            false,
        )?;
        fs.owner = owner.clone();
        Ok(cell.get_or_init(|| fs).clone())
    }
    pub fn mq_open(
        &mut self,
        name: &[u8],
        flags: u32,
        mode: u32,
        attr: Option<[i64; 2]>,
    ) -> Result<u32> {
        let key = key(name, false)?;
        let access = flags & 3;
        if access == 3 {
            return Err(Errno(22));
        }
        let fs = self.mqueue_fs()?;
        let reserved = self.shared_files().reserve()?;
        let _namespace = fs.namespace.lock().unwrap();
        let mut data = fs.borrow_mut();
        let node = if let Some(node) = data.paths.get(&key) {
            if flags & (CREATE | EXCLUSIVE) == (CREATE | EXCLUSIVE) {
                return Err(Errno(17));
            }
            if !self.allowed(&node.borrow(), [4, 2, 6][access as usize]) {
                return Err(Errno(13));
            }
            node.clone()
        } else {
            if flags & CREATE == 0 {
                return Err(Errno(2));
            }
            let queue = Queue::new(attr, self)?;
            data.admit_inode()?;
            let inode = data.next_inode;
            let root = data.paths[b"/".as_slice()].borrow();
            let device = root.device;
            if !self.allowed(&root, 3) {
                return Err(Errno(13));
            }
            drop(root);
            let node = Arc::new(Inode::new(Node {
                identity: 0,
                record_locks: Default::default(),
                whole_locks: Default::default(),
                notifications: Default::default(),
                path_hint: Default::default(),
                device,
                content: Content::MessageQueue(Arc::new(queue)),
                mode: 0o100000 | (mode & 0o777 & !self.umask()),
                uid: self.credentials.fsuid,
                gid: self.credentials.fsgid,
                volatile: false,
                inode,
                links: 1,
                times: [storage::Timestamp::now(); 3],
                xattrs: Default::default(),
                seals: None,
            }));
            data.next_inode = inode.checked_add(1).ok_or(Errno(28))?;
            data.track_inode(&node)?;
            data.paths.insert(key.clone(), node.clone());
            node
        };
        drop(data);
        let q = match &node.borrow().content {
            Content::MessageQueue(q) => q.clone(),
            _ => return Err(Errno(22)),
        };
        let desc = events::resource_descriptor(
            self.open_id(),
            access | (flags & O_NONBLOCK) | O_CLOEXEC,
            FdKind::Node(key),
            Some(node),
            Some(events::SharedControl::MessageQueue(q)),
            None,
        );
        reserved.publish(desc, self.query.is_none().then_some(&self.fds))
    }
    pub fn mq_unlink(&self, name: &[u8]) -> Result<()> {
        let key = key(name, true)?;
        let fs = self.mqueue_fs()?;
        let _namespace = fs.namespace.lock().unwrap();
        let mut data = fs.borrow_mut();
        let node = data.paths.get(&key).ok_or(Errno(2))?;
        let root = data.paths[b"/".as_slice()].borrow();
        let uid = self.credentials.fsuid;
        if !self.allowed(&root, 3)
            || root.mode & 0o1000 != 0
                && uid != root.uid
                && uid != node.borrow().uid
                && !self.credentials.has_cap(capabilities::FOWNER)
        {
            return Err(Errno(13));
        }
        drop(root);
        node.borrow_mut().links -= 1;
        data.paths.remove(&key);
        Ok(())
    }
}
