// SPDX-License-Identifier: GPL-3.0-or-later
//! Native, non-reparenting XWM. Only X11 bytes and owned sockets cross threads.
//! Xwayland itself remains the original guest program. Blocking X11 replies
//! never run on the compositor, CPU workers, or UIKit's main thread.
use std::{
    collections::BTreeMap,
    io,
    net::Shutdown,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::mpsc,
    thread,
};
use x11rb::{
    connection::Connection,
    protocol::{composite, xproto::*, Event},
    rust_connection::{DefaultStream, RustConnection},
    wrapper::ConnectionExt as _,
    CURRENT_TIME, NONE,
};
mod clipboard;
mod ime;
mod keys;
pub(crate) use ime::Text;

pub(crate) type Identity = (u32, u32, u32);
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct Window {
    pub id: u32,
    pub serial: u64,
    pub title: String,
    pub class: String,
    pub transient: Option<u32>,
    pub geometry: (i16, i16, u16, u16),
    pub override_redirect: bool,
    pub min: (u32, u32),
    pub max: (u32, u32),
    pub(super) delete: bool,
    pub(super) take_focus: bool,
}
pub(crate) enum Update {
    Window(Window),
    Remove(u32),
    Focus(u64, u32),
    Clipboard(String),
    ReadClipboard(std::os::fd::OwnedFd),
    Text(Option<Text>),
}
pub(crate) enum Command {
    Resize(u32, u32, u32),
    Focus(u64, Option<u32>),
    Close(u32),
    ClipboardProxy(bool),
    Text(u64, String),
    Key(u32, bool, u32),
}
pub(crate) struct Manager {
    pub commands: mpsc::SyncSender<Command>,
    pub updates: mpsc::Receiver<Update>,
    socket: UnixStream,
    worker: Option<thread::JoinHandle<()>>,
}
impl Manager {
    pub fn new(socket: UnixStream) -> io::Result<Self> {
        let stop = socket.try_clone()?;
        let (commands, rx) = mpsc::sync_channel(256);
        let (tx, updates) = mpsc::sync_channel(256);
        let worker = thread::Builder::new()
            .name("trames-xwm".into())
            .spawn(move || {
                // Closing our retained socket interrupts handshake/reply waits too.
                if let Err(error) = run(socket, rx, tx) {
                    eprintln!("trames-xwm: {error}");
                }
            })?;
        Ok(Self {
            commands,
            updates,
            socket: stop,
            worker: Some(worker),
        })
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Atoms {
    serial: u32,
    name: u32,
    utf8: u32,
    protocols: u32,
    delete: u32,
    take_focus: u32,
    active: u32,
    supported: u32,
    check: u32,
    wm: u32,
    cm: u32,
}
impl Atoms {
    fn new(c: &RustConnection) -> Result<Self> {
        let atom = |name: &[u8]| -> Result<u32> { Ok(c.intern_atom(false, name)?.reply()?.atom) };
        Ok(Self {
            serial: atom(b"WL_SURFACE_SERIAL")?,
            name: atom(b"_NET_WM_NAME")?,
            utf8: atom(b"UTF8_STRING")?,
            protocols: atom(b"WM_PROTOCOLS")?,
            delete: atom(b"WM_DELETE_WINDOW")?,
            take_focus: atom(b"WM_TAKE_FOCUS")?,
            active: atom(b"_NET_ACTIVE_WINDOW")?,
            supported: atom(b"_NET_SUPPORTED")?,
            check: atom(b"_NET_SUPPORTING_WM_CHECK")?,
            wm: atom(b"WM_S0")?,
            cm: atom(b"_NET_WM_CM_S0")?,
        })
    }
}
fn property(c: &RustConnection, window: u32, atom: u32) -> Result<GetPropertyReply> {
    // Bound untrusted property replies (4 KiB); never ask X11 for an entire blob.
    Ok(c.get_property(false, window, atom, AtomEnum::ANY, 0, 1024)?
        .reply()?)
}
fn metadata(c: &RustConnection, a: &Atoms, id: u32, serial: u64) -> Result<Window> {
    let g = c.get_geometry(id)?.reply()?;
    let attrs = c.get_window_attributes(id)?.reply()?;
    let name = property(c, id, a.name)?;
    let name = if name.value.is_empty() {
        property(c, id, AtomEnum::WM_NAME.into())?
    } else {
        name
    };
    let class = property(c, id, AtomEnum::WM_CLASS.into())?;
    let transient = property(c, id, AtomEnum::WM_TRANSIENT_FOR.into())?
        .value32()
        .and_then(|mut v| v.next());
    let hints = property(c, id, AtomEnum::WM_NORMAL_HINTS.into())?;
    let hints = hints
        .value32()
        .map(|v| v.collect::<Vec<_>>())
        .unwrap_or_default();
    let flags = hints.first().copied().unwrap_or(0);
    let size = |i: usize, bit: u32| {
        if flags & bit != 0 && hints.len() > i + 1 {
            (hints[i].min(4096), hints[i + 1].min(4096))
        } else {
            (0, 0)
        }
    };
    let protocols = property(c, id, a.protocols)?;
    let has_protocol = |atom| {
        protocols
            .value32()
            .is_some_and(|mut v| v.any(|p| p == atom))
    };
    Ok(Window {
        id,
        serial,
        title: String::from_utf8_lossy(&name.value)
            .chars()
            .take(256)
            .collect(),
        class: String::from_utf8_lossy(&class.value)
            .split('\0')
            .rfind(|s| !s.is_empty())
            .unwrap_or("")
            .chars()
            .take(128)
            .collect(),
        transient,
        geometry: (g.x, g.y, g.width, g.height),
        override_redirect: attrs.override_redirect,
        min: size(5, 1 << 4),
        max: size(7, 1 << 5),
        delete: has_protocol(a.delete),
        take_focus: has_protocol(a.take_focus),
    })
}
fn run(
    socket: UnixStream,
    commands: mpsc::Receiver<Command>,
    updates: mpsc::SyncSender<Update>,
) -> Result<()> {
    let (stream, _) = DefaultStream::from_unix_stream(socket)?;
    let c = RustConnection::connect_to_stream(stream, 0)?;
    let root = c.setup().roots[0].root;
    let a = Atoms::new(&c)?;
    composite::query_version(&c, 0, 4)?.reply()?;
    c.change_window_attributes(
        root,
        &ChangeWindowAttributesAux::new()
            .event_mask(EventMask::SUBSTRUCTURE_REDIRECT | EventMask::SUBSTRUCTURE_NOTIFY),
    )?
    .check()?;
    composite::redirect_subwindows(&c, root, composite::Redirect::MANUAL)?.check()?;
    let owner = c.generate_id()?;
    c.create_window(
        0,
        owner,
        root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_ONLY,
        0,
        &CreateWindowAux::new(),
    )?;
    c.set_selection_owner(owner, a.wm, CURRENT_TIME)?;
    c.set_selection_owner(owner, a.cm, CURRENT_TIME)?;
    c.change_property32(PropMode::REPLACE, root, a.check, AtomEnum::WINDOW, &[owner])?;
    c.change_property32(
        PropMode::REPLACE,
        owner,
        a.check,
        AtomEnum::WINDOW,
        &[owner],
    )?;
    c.change_property8(PropMode::REPLACE, owner, a.name, a.utf8, b"Trames")?;
    c.change_property32(
        PropMode::REPLACE,
        root,
        a.supported,
        AtomEnum::ATOM,
        &[a.name, a.active, a.check],
    )?;
    c.flush()?;
    let mut clipboard = clipboard::Clipboard::new(&c, owner)?;
    let mut ime = ime::Ime::new(&c, updates.clone())?;
    x11rb::protocol::xtest::get_version(&c, 2, 2)?.reply()?;
    let mut keys = keys::Keys::default();
    let mut windows: BTreeMap<u32, Window> = BTreeMap::new();
    // A full bounded queue disconnects this XWM, never blocks compositor teardown.
    let publish = |u| {
        updates
            .try_send(u)
            .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })
    };
    // Clients may connect as soon as the X socket exists, before XWM setup.
    // Redirect and adopt already-mapped windows as well as future MapRequests.
    for id in c
        .query_tree(root)?
        .reply()?
        .children
        .into_iter()
        .filter(|id| *id != owner)
        .take(256)
    {
        if c.get_window_attributes(id)?
            .reply()
            .is_ok_and(|a| a.map_state == MapState::VIEWABLE)
        {
            c.change_window_attributes(
                id,
                &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE),
            )?;
            if let Ok(w) = metadata(&c, &a, id, 0) {
                publish(Update::Window(w.clone()))?;
                windows.insert(id, w);
            }
        }
    }
    loop {
        while let Ok(command) = commands.try_recv() {
            match command {
                Command::ClipboardProxy(enabled) => clipboard.proxy(&c, enabled)?,
                Command::Text(token, text) => ime.commit(token, &text)?,
                Command::Key(key, pressed, modifiers) => keys.key(&c, key, pressed, modifiers)?,
                Command::Resize(id, w, h) => {
                    c.configure_window(
                        id,
                        &ConfigureWindowAux::new().width(w).height(h).border_width(0),
                    )?;
                }
                Command::Focus(serial, id) => {
                    keys.release(&c)?;
                    let id = id.unwrap_or(NONE);
                    c.set_input_focus(InputFocus::POINTER_ROOT, id, CURRENT_TIME)?;
                    c.change_property32(
                        PropMode::REPLACE,
                        root,
                        a.active,
                        AtomEnum::WINDOW,
                        &[id],
                    )?;
                    if id != NONE {
                        c.configure_window(
                            id,
                            &ConfigureWindowAux::new().stack_mode(StackMode::ABOVE),
                        )?;
                        if windows.get(&id).is_some_and(|w| w.take_focus) {
                            c.send_event(
                                false,
                                id,
                                EventMask::NO_EVENT,
                                ClientMessageEvent::new(
                                    32,
                                    id,
                                    a.protocols,
                                    [a.take_focus, CURRENT_TIME, 0, 0, 0],
                                ),
                            )?;
                        }
                    }
                    // The compositor gates keys on this reply. Wayland and X11
                    // have independent byte streams: sending focus first is
                    // insufficient to order a subsequent batch of key events.
                    let focused = c.get_input_focus()?.reply()?.focus;
                    publish(Update::Focus(serial, focused))?;
                }
                Command::Close(id) => {
                    if windows.get(&id).is_some_and(|w| w.delete) {
                        c.send_event(
                            false,
                            id,
                            EventMask::NO_EVENT,
                            ClientMessageEvent::new(
                                32,
                                id,
                                a.protocols,
                                [a.delete, CURRENT_TIME, 0, 0, 0],
                            ),
                        )?;
                    } else {
                        c.kill_client(id)?;
                    }
                }
            }
        }
        // Limit each turn so a noisy X11 client cannot starve UI commands.
        for _ in 0..256 {
            let Some(event) = c.poll_for_event()? else {
                break;
            };
            if clipboard.filter(&c, &event, &updates)? || ime.filter(&event)? {
                continue;
            }
            match event {
                Event::MapRequest(e) => {
                    if windows.len() >= 256 && !windows.contains_key(&e.window) {
                        continue;
                    }
                    c.change_window_attributes(
                        e.window,
                        &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE),
                    )?;
                    c.configure_window(e.window, &ConfigureWindowAux::new().border_width(0))?;
                    c.map_window(e.window)?;
                }
                Event::MapNotify(e) if e.window != owner => {
                    if windows.len() >= 256 && !windows.contains_key(&e.window) {
                        continue;
                    }
                    c.change_window_attributes(
                        e.window,
                        &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE),
                    )?;
                    if let Ok(w) = metadata(&c, &a, e.window, 0) {
                        publish(Update::Window(w.clone()))?;
                        windows.insert(w.id, w);
                    }
                }
                Event::ConfigureRequest(e) => {
                    let mut aux = ConfigureWindowAux::from_configure_request(&e).border_width(0);
                    if let Some(w) = aux.width {
                        aux.width = Some(w.clamp(1, 4096));
                    }
                    if let Some(h) = aux.height {
                        aux.height = Some(h.clamp(1, 4096));
                    }
                    c.configure_window(e.window, &aux)?;
                }
                Event::PropertyNotify(e) if windows.contains_key(&e.window) => {
                    let serial = windows[&e.window].serial;
                    if let Ok(w) = metadata(&c, &a, e.window, serial) {
                        publish(Update::Window(w.clone()))?;
                        windows.insert(w.id, w);
                    }
                }
                Event::ConfigureNotify(e) => {
                    if let Some(w) = windows.get_mut(&e.window) {
                        w.geometry = (e.x, e.y, e.width, e.height);
                        publish(Update::Window(w.clone()))?;
                    }
                }
                Event::ClientMessage(e) if e.type_ == a.serial && e.format == 32 => {
                    let v = e.data.as_data32();
                    let serial = u64::from(v[0]) | u64::from(v[1]) << 32;
                    if let Ok(w) = metadata(&c, &a, e.window, serial) {
                        publish(Update::Window(w.clone()))?;
                        windows.insert(w.id, w);
                    }
                }
                Event::ClientMessage(e)
                    if e.type_ == a.active && windows.contains_key(&e.window) =>
                {
                    c.set_input_focus(InputFocus::POINTER_ROOT, e.window, CURRENT_TIME)?;
                }
                Event::DestroyNotify(DestroyNotifyEvent { window, .. })
                | Event::UnmapNotify(UnmapNotifyEvent { window, .. }) => {
                    if windows.remove(&window).is_some() {
                        publish(Update::Remove(window))?;
                    }
                }
                _ => {}
            }
        }
        clipboard.tick(&c)?;
        c.flush()?;
        let mut fd = libc::pollfd {
            fd: c.stream().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the connection owns a live descriptor; one initialized pollfd.
        if unsafe { libc::poll(&mut fd, 1, 4) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn teardown_interrupts_an_unanswered_x11_handshake() {
        let (_silent, socket) = UnixStream::pair().unwrap();
        let manager = Manager::new(socket).unwrap();
        let start = std::time::Instant::now();
        drop(manager);
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
}
