// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-owned PTYs. Descriptor aliases share an endpoint; the last close hangs up.
use super::*;
use terminal::Terminal;

pub struct Pty {
    pub id: u32,
    pub terminal: RefCell<Terminal>,
    pub locked: Cell<bool>,
    pub master_alive: Cell<bool>,
    pub slaves: Cell<u32>,
    slave_opened: Cell<bool>,
    pub packet: Cell<bool>,
    pub packet_status: Cell<u8>,
    pub hangup_notified: Cell<bool>,
}
pub struct PtyEnd {
    pub pair: Rc<Pty>,
    pub master: bool,
}
impl PtyEnd {
    pub(super) fn new(pair: Rc<Pty>, master: bool) -> Rc<Self> {
        if !master {
            pair.slaves.set(pair.slaves.get() + 1);
            pair.slave_opened.set(true);
        }
        Rc::new(Self { pair, master })
    }
}
impl Drop for PtyEnd {
    fn drop(&mut self) {
        if self.master {
            self.pair.master_alive.set(false);
        } else {
            self.pair.slaves.set(self.pair.slaves.get() - 1);
        }
    }
}
impl Pty {
    pub fn master_read(&self, count: usize) -> Result<Vec<u8>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        if self.packet.get() && self.packet_status.get() != 0 {
            return Ok(vec![self.packet_status.replace(0)]);
        }
        let mut tty = self.terminal.borrow_mut();
        if tty.output_queue.is_empty() {
            return Err(Errno(
                if self.slave_opened.get() && self.slaves.get() == 0 {
                    5
                } else {
                    11
                },
            ));
        }
        let mut bytes = Vec::new();
        if self.packet.get() {
            bytes.push(0);
        }
        let take = (count - bytes.len()).min(tty.output_queue.len());
        bytes.extend(tty.output_queue.drain(..take));
        Ok(bytes)
    }
    pub fn poll(&self, master: bool, events: u16) -> u16 {
        let tty = self.terminal.borrow();
        if master {
            let read = !tty.output_queue.is_empty()
                || (self.packet.get() && self.packet_status.get() != 0);
            let hungup = self.slave_opened.get() && self.slaves.get() == 0;
            (if read { events & 1 } else { 0 })
                | (if self.packet.get() && self.packet_status.get() != 0 {
                    events & 2
                } else {
                    0
                })
                | (if tty.input_capacity() != 0 {
                    events & 4
                } else {
                    0
                })
                | (if hungup { 16 } else { 0 })
        } else {
            (if tty.readable() || !self.master_alive.get() {
                events & 1
            } else {
                0
            }) | (if tty.output_queue.len() < PIPE_CAPACITY && self.master_alive.get() {
                events & 4
            } else {
                0
            }) | (if !self.master_alive.get() { 16 | 8 } else { 0 })
        }
    }
    pub fn flush_echo(&self) {
        let mut tty = self.terminal.borrow_mut();
        let echo = std::mem::take(&mut tty.echo);
        let count = tty.queue_output(&echo).unwrap_or(0);
        tty.echo = echo[count..].to_vec();
    }
}
impl Vfs {
    pub fn set_controlling_terminal(&mut self, id: Option<u32>) -> Result<()> {
        self.controlling_pair = match id {
            Some(id) if id != 0 => Some(self.pty_by_id(id).ok_or(Errno(6))?),
            _ => None,
        };
        self.controlling_terminal = id;
        Ok(())
    }
    pub fn pty(&self, fd: u32) -> Result<Option<Rc<PtyEnd>>> {
        Ok(self.descriptor(fd)?.open.borrow().pty.clone())
    }
    pub fn pty_by_id(&self, id: u32) -> Option<Rc<Pty>> {
        self.ptys.borrow().get(&id).and_then(Weak::upgrade)
    }
    pub fn live_ptys(&self) -> Vec<Rc<Pty>> {
        self.ptys
            .borrow()
            .values()
            .filter_map(Weak::upgrade)
            .collect()
    }
    pub(super) fn allocate_pty(&mut self) -> Result<Rc<PtyEnd>> {
        let id = (1..4096)
            .find(|id| self.pty_by_id(*id).is_none())
            .ok_or(Errno(28))?;
        let mut tty = Terminal::default();
        tty.session = 0;
        tty.foreground = 0;
        let pair = Rc::new(Pty {
            id,
            terminal: RefCell::new(tty),
            locked: Cell::new(true),
            master_alive: Cell::new(true),
            slaves: Cell::new(0),
            slave_opened: Cell::new(false),
            packet: Cell::new(false),
            packet_status: Cell::new(0),
            hangup_notified: Cell::new(false),
        });
        self.ptys.borrow_mut().insert(id, Rc::downgrade(&pair));
        let path = format!("/dev/pts/{id}").into_bytes();
        self.pseudo.borrow_mut().nodes.remove(&(0, path.clone()));
        let node = self.node(&path)?;
        node.borrow_mut().uid = self.credentials.fsuid;
        node.borrow_mut().gid = 5; // Linux's tty group; grantpt/chown may change it.
        Ok(PtyEnd::new(pair, true))
    }
}
