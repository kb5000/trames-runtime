// SPDX-License-Identifier: GPL-3.0-or-later
//! ICCCM text selections, bounded INCR reception, and lazy native paste reads.
use super::*;
use std::{
    io::Read,
    time::{Duration, Instant},
};
use trames_shared::NativePipe;
use x11rb::protocol::xfixes;
const LIMIT: usize = 16384;
struct Atoms {
    clipboard: u32,
    targets: u32,
    timestamp: u32,
    utf8: u32,
    text: u32,
    incr: u32,
    property: u32,
}
struct Incoming {
    window: u32,
    bytes: Vec<u8>,
    incr: bool,
    latin1: bool,
    deadline: Instant,
}
struct Outgoing {
    request: SelectionRequestEvent,
    pipe: NativePipe,
    bytes: Vec<u8>,
    deadline: Instant,
}
pub(super) struct Clipboard {
    atoms: Atoms,
    owner: u32,
    proxy: bool,
    timestamp: u32,
    incoming: Option<Incoming>,
    outgoing: Vec<Outgoing>,
}
impl Clipboard {
    pub fn new(c: &RustConnection, owner: u32) -> Result<Self> {
        let atom = |name: &[u8]| -> Result<u32> { Ok(c.intern_atom(false, name)?.reply()?.atom) };
        let atoms = Atoms {
            clipboard: atom(b"CLIPBOARD")?,
            targets: atom(b"TARGETS")?,
            timestamp: atom(b"TIMESTAMP")?,
            utf8: atom(b"UTF8_STRING")?,
            text: atom(b"TEXT")?,
            incr: atom(b"INCR")?,
            property: atom(b"TRAMES_SELECTION")?,
        };
        xfixes::query_version(c, 5, 0)?.reply()?;
        xfixes::select_selection_input(
            c,
            owner,
            atoms.clipboard,
            xfixes::SelectionEventMask::SET_SELECTION_OWNER
                | xfixes::SelectionEventMask::SELECTION_WINDOW_DESTROY
                | xfixes::SelectionEventMask::SELECTION_CLIENT_CLOSE,
        )?;
        Ok(Self {
            atoms,
            owner,
            proxy: false,
            timestamp: CURRENT_TIME,
            incoming: None,
            outgoing: Vec::new(),
        })
    }
    pub fn proxy(&mut self, c: &RustConnection, enabled: bool) -> Result<()> {
        if self.proxy == enabled {
            return Ok(());
        }
        self.proxy = enabled;
        if enabled {
            c.set_selection_owner(self.owner, self.atoms.clipboard, CURRENT_TIME)?;
        } else if c.get_selection_owner(self.atoms.clipboard)?.reply()?.owner == self.owner {
            c.set_selection_owner(NONE, self.atoms.clipboard, CURRENT_TIME)?;
        }
        Ok(())
    }
    fn notify(c: &RustConnection, r: &SelectionRequestEvent, property: u32) -> Result<()> {
        c.send_event(
            false,
            r.requestor,
            EventMask::NO_EVENT,
            SelectionNotifyEvent {
                response_type: SELECTION_NOTIFY_EVENT,
                sequence: 0,
                time: r.time,
                requestor: r.requestor,
                selection: r.selection,
                target: r.target,
                property,
            },
        )?;
        Ok(())
    }
    fn finish(&mut self, c: &RustConnection, updates: &mpsc::SyncSender<Update>) -> Result<()> {
        if let Some(i) = self.incoming.take() {
            c.destroy_window(i.window)?;
            let text = if i.latin1 {
                i.bytes.into_iter().map(char::from).collect::<String>()
            } else {
                match String::from_utf8(i.bytes) {
                    Ok(s) => s,
                    Err(_) => return Ok(()),
                }
            };
            if text.len() <= LIMIT && !text.contains('\0') {
                updates.try_send(Update::Clipboard(text))?;
            }
        }
        Ok(())
    }
    fn read_property(
        &mut self,
        c: &RustConnection,
        updates: &mpsc::SyncSender<Update>,
    ) -> Result<()> {
        let Some(i) = &mut self.incoming else {
            return Ok(());
        };
        let p = c
            .get_property(
                true,
                i.window,
                self.atoms.property,
                AtomEnum::ANY,
                0,
                (LIMIT / 4 + 1) as u32,
            )?
            .reply()?;
        if p.type_ == self.atoms.incr && !i.incr {
            i.incr = true;
            return Ok(());
        }
        if p.type_ == NONE {
            return Ok(());
        }
        if p.format != 8 || p.bytes_after != 0 || i.bytes.len() + p.value.len() > LIMIT {
            let i = self.incoming.take().unwrap();
            c.destroy_window(i.window)?;
            return Ok(());
        }
        i.latin1 = p.type_ == u32::from(AtomEnum::STRING);
        let complete = !i.incr || p.value.is_empty();
        i.bytes.extend(p.value);
        if complete {
            self.finish(c, updates)?
        }
        Ok(())
    }
    pub fn filter(
        &mut self,
        c: &RustConnection,
        e: &Event,
        updates: &mpsc::SyncSender<Update>,
    ) -> Result<bool> {
        match e {
            Event::XfixesSelectionNotify(e) if e.selection == self.atoms.clipboard => {
                self.timestamp = e.selection_timestamp;
                if e.owner == self.owner {
                    return Ok(true);
                }
                self.proxy = false;
                if let Some(i) = self.incoming.take() {
                    c.destroy_window(i.window)?;
                }
                if e.owner == NONE {
                    return Ok(true);
                }
                let window = c.generate_id()?;
                c.create_window(
                    0,
                    window,
                    c.setup().roots[0].root,
                    0,
                    0,
                    1,
                    1,
                    0,
                    WindowClass::INPUT_ONLY,
                    0,
                    &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
                )?;
                self.incoming = Some(Incoming {
                    window,
                    bytes: Vec::new(),
                    incr: false,
                    latin1: false,
                    deadline: Instant::now() + Duration::from_secs(5),
                });
                c.convert_selection(
                    window,
                    self.atoms.clipboard,
                    self.atoms.utf8,
                    self.atoms.property,
                    e.timestamp,
                )?;
                Ok(true)
            }
            Event::SelectionNotify(e)
                if self
                    .incoming
                    .as_ref()
                    .is_some_and(|i| i.window == e.requestor) =>
            {
                if e.property == NONE {
                    if e.target == self.atoms.utf8 {
                        c.convert_selection(
                            e.requestor,
                            self.atoms.clipboard,
                            AtomEnum::STRING.into(),
                            self.atoms.property,
                            e.time,
                        )?;
                    } else if let Some(i) = self.incoming.take() {
                        c.destroy_window(i.window)?;
                    }
                } else {
                    self.read_property(c, updates)?
                }
                Ok(true)
            }
            Event::PropertyNotify(e)
                if self.incoming.as_ref().is_some_and(|i| i.window == e.window)
                    && e.atom == self.atoms.property
                    && e.state == Property::NEW_VALUE =>
            {
                if self.incoming.as_ref().is_some_and(|i| i.incr) {
                    self.read_property(c, updates)?
                }
                Ok(true)
            }
            Event::SelectionRequest(r)
                if r.owner == self.owner && r.selection == self.atoms.clipboard =>
            {
                let property = if r.property == NONE {
                    r.target
                } else {
                    r.property
                };
                if r.target == self.atoms.targets {
                    c.change_property32(
                        PropMode::REPLACE,
                        r.requestor,
                        property,
                        AtomEnum::ATOM,
                        &[
                            self.atoms.targets,
                            self.atoms.timestamp,
                            self.atoms.utf8,
                            self.atoms.text,
                            AtomEnum::STRING.into(),
                        ],
                    )?;
                    Self::notify(c, r, property)?;
                } else if r.target == self.atoms.timestamp {
                    c.change_property32(
                        PropMode::REPLACE,
                        r.requestor,
                        property,
                        AtomEnum::INTEGER,
                        &[self.timestamp],
                    )?;
                    Self::notify(c, r, property)?;
                } else if self.proxy
                    && self.outgoing.len() < 4
                    && [self.atoms.utf8, self.atoms.text, AtomEnum::STRING.into()]
                        .contains(&r.target)
                {
                    let (read, write) = NativePipe::pair()?;
                    if updates
                        .try_send(Update::ReadClipboard(write.into_fd()))
                        .is_ok()
                    {
                        self.outgoing.push(Outgoing {
                            request: *r,
                            pipe: read,
                            bytes: Vec::new(),
                            deadline: Instant::now() + Duration::from_secs(120),
                        });
                    } else {
                        Self::notify(c, r, NONE)?
                    }
                } else {
                    Self::notify(c, r, NONE)?
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    pub fn tick(&mut self, c: &RustConnection) -> Result<()> {
        if self
            .incoming
            .as_ref()
            .is_some_and(|i| Instant::now() > i.deadline)
        {
            let i = self.incoming.take().unwrap();
            c.destroy_window(i.window)?;
        }
        let mut n = 0;
        while n < self.outgoing.len() {
            let o = &mut self.outgoing[n];
            let mut buf = [0; 4096];
            let mut complete = false;
            let mut failed = false;
            loop {
                match o.pipe.read(&mut buf) {
                    Ok(0) => {
                        complete = true;
                        break;
                    }
                    Ok(len) if o.bytes.len() + len <= LIMIT => {
                        o.bytes.extend_from_slice(&buf[..len])
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    _ => {
                        failed = true;
                        break;
                    }
                }
            }
            failed |= Instant::now() > o.deadline;
            if !complete && !failed {
                n += 1;
                continue;
            }
            let o = self.outgoing.swap_remove(n);
            let text = String::from_utf8(o.bytes);
            if failed || text.is_err() {
                Self::notify(c, &o.request, NONE)?;
                continue;
            }
            let text = text.unwrap();
            let bytes = if o.request.target == u32::from(AtomEnum::STRING) {
                text.chars()
                    .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
                    .collect()
            } else {
                text.into_bytes()
            };
            let property = if o.request.property == NONE {
                o.request.target
            } else {
                o.request.property
            };
            let ty = if o.request.target == u32::from(AtomEnum::STRING) {
                o.request.target
            } else {
                self.atoms.utf8
            };
            c.change_property8(PropMode::REPLACE, o.request.requestor, property, ty, &bytes)?;
            Self::notify(c, &o.request, property)?;
        }
        Ok(())
    }
}
